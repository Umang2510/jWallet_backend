import argon2 from 'argon2';
import { v7 as uuidv7 } from 'uuid';

import {
  ForbiddenError,
  TooManyRequestsError,
  UnauthorizedError,
} from '#src/common/classes/route-errors.ts';
import { Env } from '#src/common/constants/env.constants.ts';
import { randomToken, sha256Hex } from '#src/common/utils/crypto.utils.ts';
import db from '#src/db/client.ts';
import type { LoginInput } from '#src/entities/Auth/index.ts';
import AuditRepo, { AuditActions } from '#src/repos/AuditRepo.ts';
import DeviceRepo from '#src/repos/DeviceRepo.ts';
import SessionRepo from '#src/repos/SessionRepo.ts';
import UserRepo from '#src/repos/UserRepo.ts';

import TokenService, { DEFAULT_SCOPES } from './TokenService.ts';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

export const AuthErrors = {
  INVALID_CREDENTIALS: 'Invalid email or password',
  ACCOUNT_LOCKED: (minutes: number) =>
    `Too many failed attempts. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`,
  ACCOUNT_INACTIVE: 'This account is not active. Please contact support.',
} as const;

/**
 * Hash of a random throwaway password. Verifying against it when the email is
 * unknown keeps response times the same, so timing can't reveal which emails exist.
 */
const DUMMY_HASH = await argon2.hash(randomToken(), { type: argon2.argon2id });

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface RequestContext {
  ip: string | null;
  userAgent: string | null;
  requestId: string | null;
}

export interface LoginResult {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  refreshToken: string;
  refreshExpiresIn: number;
  user: { id: string; name: string; email: string };
  security: { pinSet: boolean; biometricEnrolled: boolean };
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

function minutesUntil(iso: string, now: Date): number {
  return Math.max(1, Math.ceil((Date.parse(iso) - now.getTime()) / 60_000));
}

/**
 * Verify credentials and open a new session.
 *
 * - Same 401 for unknown email and wrong password (no account enumeration).
 * - Per-account lockout after MAX_FAILED_LOGINS failures (429).
 * - Refresh token is returned once and stored only as a SHA-256 hash.
 * - Session, device registration, failure reset and audit entry are written atomically.
 */
async function login(
  input: LoginInput,
  ctx: RequestContext,
): Promise<LoginResult> {
  const now = new Date();
  const nowIso = now.toISOString();
  const deviceId = input.deviceId ?? null;
  const audit = { ip: ctx.ip, deviceId, requestId: ctx.requestId };

  const user = await UserRepo.findByEmail(input.email);

  // Locked accounts are rejected before the password is even checked.
  if (
    user?.loginLockedUntil &&
    Date.parse(user.loginLockedUntil) > now.getTime()
  ) {
    await AuditRepo.record({
      ...audit,
      userId: user.id,
      action: AuditActions.LOGIN_BLOCKED,
    });
    throw new TooManyRequestsError(
      AuthErrors.ACCOUNT_LOCKED(minutesUntil(user.loginLockedUntil, now)),
      'ACCOUNT_TEMPORARILY_LOCKED',
    );
  }

  const passwordOk = await argon2.verify(
    user?.passwordHash ?? DUMMY_HASH,
    input.password,
  );

  if (!user) {
    await AuditRepo.record({
      ...audit,
      userId: null,
      action: AuditActions.LOGIN_FAIL,
      metadata: { reason: 'UNKNOWN_EMAIL', emailHash: sha256Hex(input.email) },
    });
    throw new UnauthorizedError(
      AuthErrors.INVALID_CREDENTIALS,
      'INVALID_CREDENTIALS',
    );
  }

  if (!passwordOk) {
    const failed = user.failedLoginCount + 1;
    if (failed >= Env.MAX_FAILED_LOGINS) {
      const lockedUntil = new Date(
        now.getTime() + Env.LOGIN_LOCK_MINUTES * 60_000,
      ).toISOString();
      await UserRepo.recordFailedLogin(user.id, 0, lockedUntil);
      await AuditRepo.record({
        ...audit,
        userId: user.id,
        action: AuditActions.LOGIN_LOCKED,
      });
      throw new TooManyRequestsError(
        AuthErrors.ACCOUNT_LOCKED(Env.LOGIN_LOCK_MINUTES),
        'ACCOUNT_TEMPORARILY_LOCKED',
      );
    }
    await UserRepo.recordFailedLogin(user.id, failed, null);
    await AuditRepo.record({
      ...audit,
      userId: user.id,
      action: AuditActions.LOGIN_FAIL,
      metadata: { reason: 'WRONG_PASSWORD', failedCount: failed },
    });
    throw new UnauthorizedError(
      AuthErrors.INVALID_CREDENTIALS,
      'INVALID_CREDENTIALS',
    );
  }

  // Only reveal account status after the password is proven.
  if (user.status !== 'ACTIVE') {
    await AuditRepo.record({
      ...audit,
      userId: user.id,
      action: AuditActions.LOGIN_INACTIVE,
    });
    throw new ForbiddenError(AuthErrors.ACCOUNT_INACTIVE, 'ACCOUNT_INACTIVE');
  }

  // ---- Open the session
  const sessionId = uuidv7();
  const refreshToken = randomToken('rt_');
  const refreshExpiresIn = Env.REFRESH_TOKEN_TTL_SEC;

  await db.batch(
    [
      UserRepo.resetLoginFailuresStmt(user.id, nowIso),
      ...(deviceId
        ? [
            DeviceRepo.upsertOnLoginStmt(
              user.id,
              deviceId,
              input.devicePublicKey ?? null,
              nowIso,
            ),
          ]
        : []),
      SessionRepo.insertStmt({
        id: sessionId,
        userId: user.id,
        deviceId,
        refreshTokenHash: sha256Hex(refreshToken),
        familyId: uuidv7(),
        passwordAuthAt: nowIso,
        expiresAt: new Date(
          now.getTime() + refreshExpiresIn * 1000,
        ).toISOString(),
        ip: ctx.ip,
        userAgent: ctx.userAgent?.slice(0, 255) ?? null,
        createdAt: nowIso,
      }),
      AuditRepo.insertStmt(
        {
          ...audit,
          userId: user.id,
          action: AuditActions.LOGIN_OK,
          metadata: { sessionId },
        },
        nowIso,
      ),
    ],
    'write',
  );

  const [{ token, expiresIn }, pinSet, biometricEnrolled] = await Promise.all([
    TokenService.issueAccessToken({
      userId: user.id,
      sessionId,
      deviceId,
      scopes: DEFAULT_SCOPES,
    }),
    UserRepo.hasTransactionPin(user.id),
    deviceId
      ? DeviceRepo.isBiometricEnrolled(user.id, deviceId)
      : Promise.resolve(false),
  ]);

  return {
    accessToken: token,
    tokenType: 'Bearer',
    expiresIn,
    refreshToken,
    refreshExpiresIn,
    user: { id: user.publicId, name: user.name, email: user.email },
    security: { pinSet, biometricEnrolled },
  };
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  Errors: AuthErrors,
  login,
} as const;
