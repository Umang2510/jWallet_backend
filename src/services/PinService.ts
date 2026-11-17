import argon2 from 'argon2';

import {
  ForbiddenError,
  RouteError,
} from '#src/common/classes/route-errors.ts';
import { Env } from '#src/common/constants/env.constants.ts';
import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import type { AuthContext } from '#src/middleware/auth.ts';
import AuditRepo, { AuditActions } from '#src/repos/AuditRepo.ts';
import PinRepo from '#src/repos/PinRepo.ts';
import SessionRepo from '#src/repos/SessionRepo.ts';

import type { RequestContext } from './AuthService.ts';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

export const PinErrors = {
  NOT_SET: 'Please set your transaction PIN first.',
  ALREADY_SET: 'A transaction PIN is already set. Use change PIN instead.',
  REAUTH: 'For your security, please log in again to set your PIN.',
  INCORRECT: 'Incorrect PIN',
  LOCKED: (hours: number) =>
    `Too many incorrect PIN attempts. PIN is locked for ${hours} hour${hours === 1 ? '' : 's'}.`,
} as const;

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

function hoursUntil(iso: string, now: number): number {
  return Math.max(1, Math.ceil((Date.parse(iso) - now) / 3_600_000));
}

function hashPin(pin: string): Promise<string> {
  return argon2.hash(pin, { type: argon2.argon2id });
}

/**
 * Check the user's PIN, enforcing the UPI-style lockout:
 * PIN_MAX_ATTEMPTS wrong tries lock PIN use for PIN_LOCK_HOURS.
 * The counter lives on the server, so reinstalling the app doesn't reset it.
 *
 * Errors: 403 PIN_NOT_SET, 423 PIN_LOCKED, 403 INVALID_PIN (with attempts left).
 * Used by change-PIN, biometric enrollment and money transfer.
 */
async function verifyPin(
  userId: string,
  pin: string,
  ctx: RequestContext & { deviceId?: string | null },
): Promise<void> {
  const now = Date.now();
  const audit = {
    userId,
    ip: ctx.ip,
    deviceId: ctx.deviceId ?? null,
    requestId: ctx.requestId,
  };

  const row = await PinRepo.find(userId);
  if (!row) throw new ForbiddenError(PinErrors.NOT_SET, 'PIN_NOT_SET');

  if (row.lockedUntil && Date.parse(row.lockedUntil) > now) {
    await AuditRepo.record({ ...audit, action: AuditActions.PIN_BLOCKED });
    throw new RouteError(
      HttpStatusCodes.LOCKED,
      PinErrors.LOCKED(hoursUntil(row.lockedUntil, now)),
      'PIN_LOCKED',
    );
  }

  if (await argon2.verify(row.pinHash, pin)) {
    await PinRepo.resetFailures(userId);
    return;
  }

  const failed = await PinRepo.incrementFailures(userId);
  if (failed >= Env.PIN_MAX_ATTEMPTS) {
    await PinRepo.lock(
      userId,
      new Date(now + Env.PIN_LOCK_HOURS * 3_600_000).toISOString(),
    );
    await AuditRepo.record({ ...audit, action: AuditActions.PIN_LOCKED });
    throw new RouteError(
      HttpStatusCodes.LOCKED,
      PinErrors.LOCKED(Env.PIN_LOCK_HOURS),
      'PIN_LOCKED',
    );
  }

  const left = Env.PIN_MAX_ATTEMPTS - failed;
  await AuditRepo.record({
    ...audit,
    action: AuditActions.PIN_FAIL,
    metadata: { failedCount: failed },
  });
  // 403 (not 401): a wrong PIN must not look like an expired session to the app.
  throw new RouteError(
    HttpStatusCodes.FORBIDDEN,
    `${PinErrors.INCORRECT}. ${left} attempt${left === 1 ? '' : 's'} left.`,
    'INVALID_PIN',
    [{ field: 'pin', message: `${left} attempt${left === 1 ? '' : 's'} left` }],
  );
}

/**
 * Set the first PIN. Allowed only within FRESH_AUTH_MINUTES of a password
 * login, so a stolen access/refresh token can't be used to set a PIN.
 */
async function setPin(
  auth: AuthContext,
  pin: string,
  ctx: RequestContext,
): Promise<{ pinSet: true }> {
  const session = await SessionRepo.findById(auth.sessionId);
  const freshUntil = session
    ? Date.parse(session.passwordAuthAt) + Env.FRESH_AUTH_MINUTES * 60_000
    : 0;
  if (Date.now() > freshUntil) {
    throw new ForbiddenError(PinErrors.REAUTH, 'REAUTH_REQUIRED');
  }

  const nowIso = new Date().toISOString();
  const created = await PinRepo.insert(auth.userId, await hashPin(pin), nowIso);
  if (!created) {
    throw new RouteError(
      HttpStatusCodes.CONFLICT,
      PinErrors.ALREADY_SET,
      'PIN_ALREADY_SET',
    );
  }
  await AuditRepo.record({
    userId: auth.userId,
    action: AuditActions.PIN_SET,
    ip: ctx.ip,
    deviceId: auth.deviceId,
    requestId: ctx.requestId,
  });
  return { pinSet: true };
}

/** Change the PIN; the current PIN must be correct (counts toward lockout). */
async function changePin(
  auth: AuthContext,
  currentPin: string,
  newPin: string,
  ctx: RequestContext,
): Promise<{ pinChanged: true }> {
  await verifyPin(auth.userId, currentPin, { ...ctx, deviceId: auth.deviceId });
  await PinRepo.updateHash(
    auth.userId,
    await hashPin(newPin),
    new Date().toISOString(),
  );
  await AuditRepo.record({
    userId: auth.userId,
    action: AuditActions.PIN_CHANGED,
    ip: ctx.ip,
    deviceId: auth.deviceId,
    requestId: ctx.requestId,
  });
  return { pinChanged: true };
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  Errors: PinErrors,
  verifyPin,
  setPin,
  changePin,
} as const;
