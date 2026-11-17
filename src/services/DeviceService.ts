import {
  ForbiddenError,
  RouteError,
} from '#src/common/classes/route-errors.ts';
import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import type { AuthContext } from '#src/middleware/auth.ts';
import AuditRepo, { AuditActions } from '#src/repos/AuditRepo.ts';
import DeviceRepo from '#src/repos/DeviceRepo.ts';

import type { RequestContext } from './AuthService.ts';
import PinService from './PinService.ts';

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/** Biometrics are per phone, so the session must be bound to a device. */
function requireDevice(auth: AuthContext): string {
  if (!auth.deviceId) {
    throw new RouteError(
      HttpStatusCodes.BAD_REQUEST,
      'This session is not linked to a device. Log in from the app to use biometrics.',
      'DEVICE_REQUIRED',
    );
  }
  return auth.deviceId;
}

/**
 * Register the biometric-bound Keystore public key for this device, after the
 * user proves who they are with their transaction PIN. Re-enrolling replaces
 * the old key (e.g. after the user adds a new fingerprint).
 */
async function enrollBiometric(
  auth: AuthContext,
  publicKey: string,
  pin: string,
  ctx: RequestContext,
): Promise<{ biometricEnrolled: true; enrolledAt: string }> {
  const deviceId = requireDevice(auth);
  await PinService.verifyPin(auth.userId, pin, { ...ctx, deviceId });

  const now = new Date().toISOString();
  const ok = await DeviceRepo.setBiometricKey(
    auth.userId,
    deviceId,
    publicKey,
    now,
  );
  if (!ok) {
    throw new ForbiddenError(
      'This device is no longer active. Please log in again.',
      'DEVICE_REVOKED',
    );
  }
  await AuditRepo.record({
    userId: auth.userId,
    action: AuditActions.BIOMETRIC_ENROLLED,
    ip: ctx.ip,
    deviceId,
    requestId: ctx.requestId,
  });
  return { biometricEnrolled: true, enrolledAt: now };
}

/** Turn biometric approval off for this device (PIN is still required). */
async function removeBiometric(
  auth: AuthContext,
  ctx: RequestContext,
): Promise<{ biometricEnrolled: false }> {
  const deviceId = requireDevice(auth);
  await DeviceRepo.clearBiometricKey(auth.userId, deviceId);
  await AuditRepo.record({
    userId: auth.userId,
    action: AuditActions.BIOMETRIC_REMOVED,
    ip: ctx.ip,
    deviceId,
    requestId: ctx.requestId,
  });
  return { biometricEnrolled: false };
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  enrollBiometric,
  removeBiometric,
} as const;
