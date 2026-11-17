import argon2 from 'argon2';
import { v7 as uuidv7 } from 'uuid';

import {
  ForbiddenError,
  TooManyRequestsError,
  UnauthorizedError,
} from '#src/common/classes/route-errors.ts';
import { Env } from '#src/common/constants/env.constants.ts';
import { randomToken, sha256Hex } from '#src/common/utils/crypto.utils.ts';
import { verifyP256Signature } from '#src/common/utils/crypto.utils.ts';
import db from '#src/db/client.ts';
import {
  type LoginInput,
  type LogoutInput,
  type RefreshInput,
  refreshProofMessage,
} from '#src/entities/Auth/index.ts';
import type { AuthContext } from '#src/middleware/auth.ts';
import AuditRepo, { AuditActions } from '#src/repos/AuditRepo.ts';
import DeviceRepo from '#src/repos/DeviceRepo.ts';
import SessionRepo, {
  RevokeReasons,
  type SessionRow,
} from '#src/repos/SessionRepo.ts';
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
  INVALID_REFRESH: 'Invalid refresh token',
  REFRESH_REUSED:
    'This refresh token was already used. For your safety you have been logged out.',
  SESSION_ENDED: 'Session has ended. Please log in again.',
  REFRESH_EXPIRED: 'Session has expired. Please log in again.',
  DEVICE_PROOF: 'Device verification failed',
} as const;

/** Allowed clock difference between the phone and the server for refresh proofs. */
const PROOF_MAX_SKEW_MS = 5 * 60_000;

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

export type RefreshResult = Pick<
  LoginResult,
  | 'accessToken'
  | 'tokenType'
  | 'expiresIn'
  | 'refreshToken'
  | 'refreshExpiresIn'
>;

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

/**
 * Check the device-binding of a session: same deviceId, device not revoked,
 * and — if the device registered a key — a fresh signature proving the caller
 * holds that key (so a refresh token copied off the phone is useless).
 */
async function verifyDeviceBinding(
  session: SessionRow,
  input: RefreshInput,
  now: Date,
): Promise<string | null> {
  if (!session.deviceId) return null; // session wasn't device-bound
  if (input.deviceId !== session.deviceId) return 'DEVICE_MISMATCH';

  const device = await DeviceRepo.find(session.userId, session.deviceId);
  if (!device || device.revokedAt) return 'DEVICE_REVOKED';
  if (!device.devicePublicKey) return null; // bound by id only

  if (!input.signature || input.timestamp === undefined) {
    return 'PROOF_MISSING';
  }
  if (Math.abs(now.getTime() - input.timestamp) > PROOF_MAX_SKEW_MS) {
    return 'PROOF_STALE';
  }
  const ok = verifyP256Signature(
    device.devicePublicKey,
    refreshProofMessage(input.refreshToken, input.timestamp),
    input.signature,
  );
  return ok ? null : 'PROOF_INVALID';
}

/**
 * Exchange a refresh token for a new access + refresh token pair (rotation).
 *
 * - Every refresh token works exactly once. The used row is marked ROTATED and
 *   a new row is added to the same family.
 * - Presenting an already-rotated token means it was stolen (or replayed):
 *   the whole family is revoked and the user must log in again.
 * - Device-bound sessions require deviceId (+ key signature when registered).
 */
async function refresh(
  input: RefreshInput,
  ctx: RequestContext,
): Promise<RefreshResult> {
  const now = new Date();
  const nowIso = now.toISOString();
  const audit = {
    ip: ctx.ip,
    deviceId: input.deviceId ?? null,
    requestId: ctx.requestId,
  };

  const session = await SessionRepo.findByRefreshHash(
    sha256Hex(input.refreshToken),
  );
  if (!session) {
    throw new UnauthorizedError(
      AuthErrors.INVALID_REFRESH,
      'INVALID_REFRESH_TOKEN',
    );
  }

  const reuse = async () => {
    await db.batch(
      [
        SessionRepo.revokeFamilyStmt(
          session.familyId,
          RevokeReasons.REUSE_DETECTED,
          nowIso,
        ),
        AuditRepo.insertStmt(
          {
            ...audit,
            userId: session.userId,
            action: AuditActions.TOKEN_REUSE_DETECTED,
            metadata: { familyId: session.familyId },
          },
          nowIso,
        ),
      ],
      'write',
    );
    return new UnauthorizedError(
      AuthErrors.REFRESH_REUSED,
      'REFRESH_TOKEN_REUSED',
    );
  };

  if (session.revokeReason === RevokeReasons.ROTATED) throw await reuse();
  if (session.revokedAt) {
    throw new UnauthorizedError(AuthErrors.SESSION_ENDED, 'SESSION_REVOKED');
  }
  if (Date.parse(session.expiresAt) <= now.getTime()) {
    throw new UnauthorizedError(
      AuthErrors.REFRESH_EXPIRED,
      'REFRESH_TOKEN_EXPIRED',
    );
  }

  const deviceProblem = await verifyDeviceBinding(session, input, now);
  if (deviceProblem) {
    await AuditRepo.record({
      ...audit,
      userId: session.userId,
      action: AuditActions.TOKEN_REFRESH_FAIL,
      metadata: { reason: deviceProblem },
    });
    throw new UnauthorizedError(
      AuthErrors.DEVICE_PROOF,
      'DEVICE_VERIFICATION_FAILED',
    );
  }

  const user = await UserRepo.findById(session.userId);
  if (user?.status !== 'ACTIVE') {
    throw new ForbiddenError(AuthErrors.ACCOUNT_INACTIVE, 'ACCOUNT_INACTIVE');
  }

  // ---- Rotate atomically: consume the old row, add the new one.
  const newSessionId = uuidv7();
  const newRefreshToken = randomToken('rt_');
  const refreshExpiresIn = Env.REFRESH_TOKEN_TTL_SEC;

  const tx = await db.transaction('write');
  try {
    const rotated = await tx.execute(
      SessionRepo.rotateStmt(session.id, nowIso),
    );
    if (rotated.rowsAffected === 0) {
      // Another request consumed this token a moment ago: treat as reuse.
      await tx.rollback();
      throw await reuse();
    }
    await tx.execute(
      SessionRepo.insertStmt({
        id: newSessionId,
        userId: session.userId,
        deviceId: session.deviceId,
        refreshTokenHash: sha256Hex(newRefreshToken),
        familyId: session.familyId,
        passwordAuthAt: session.passwordAuthAt,
        expiresAt: new Date(
          now.getTime() + refreshExpiresIn * 1000,
        ).toISOString(),
        ip: ctx.ip,
        userAgent: ctx.userAgent?.slice(0, 255) ?? null,
        createdAt: nowIso,
      }),
    );
    await tx.execute(
      AuditRepo.insertStmt(
        {
          ...audit,
          userId: session.userId,
          action: AuditActions.TOKEN_REFRESH,
          metadata: { fromSessionId: session.id, sessionId: newSessionId },
        },
        nowIso,
      ),
    );
    await tx.commit();
  } finally {
    tx.close();
  }

  const { token, expiresIn } = await TokenService.issueAccessToken({
    userId: session.userId,
    sessionId: newSessionId,
    deviceId: session.deviceId,
    scopes: DEFAULT_SCOPES,
  });

  return {
    accessToken: token,
    tokenType: 'Bearer',
    expiresIn,
    refreshToken: newRefreshToken,
    refreshExpiresIn,
  };
}

/**
 * End the caller's session (this login on this device), or every session of
 * the user when `allDevices` is true. Takes effect immediately: requireAuth
 * rejects the revoked session's access tokens on the next request.
 */
async function logout(
  auth: AuthContext,
  input: LogoutInput,
  ctx: RequestContext,
): Promise<{ allDevices: boolean }> {
  const nowIso = new Date().toISOString();
  await db.batch(
    [
      input.allDevices
        ? SessionRepo.revokeAllForUserStmt(
            auth.userId,
            RevokeReasons.LOGOUT_ALL,
            nowIso,
          )
        : SessionRepo.revokeFamilyStmt(
            auth.familyId,
            RevokeReasons.LOGOUT,
            nowIso,
          ),
      AuditRepo.insertStmt(
        {
          userId: auth.userId,
          action: input.allDevices
            ? AuditActions.LOGOUT_ALL
            : AuditActions.LOGOUT,
          ip: ctx.ip,
          deviceId: auth.deviceId,
          requestId: ctx.requestId,
          metadata: { sessionId: auth.sessionId },
        },
        nowIso,
      ),
    ],
    'write',
  );
  return { allDevices: input.allDevices };
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  Errors: AuthErrors,
  login,
  refresh,
  logout,
} as const;
