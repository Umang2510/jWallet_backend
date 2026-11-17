import type { InStatement } from '@libsql/client';
import { v7 as uuidv7 } from 'uuid';

import db, { asTextOrNull } from '#src/db/client.ts';

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/** The device row for (user, device), or null if unknown. */
async function find(
  userId: string,
  deviceId: string,
): Promise<{
  devicePublicKey: string | null;
  revokedAt: string | null;
} | null> {
  const res = await db.execute({
    sql: `SELECT device_public_key, revoked_at FROM devices
          WHERE user_id = ? AND device_id = ?`,
    args: [userId, deviceId],
  });
  const r = res.rows[0];
  if (!r) return null;
  return {
    devicePublicKey: asTextOrNull(r.device_public_key),
    revokedAt: asTextOrNull(r.revoked_at),
  };
}

async function isBiometricEnrolled(
  userId: string,
  deviceId: string,
): Promise<boolean> {
  const res = await db.execute({
    sql: `SELECT 1 FROM devices
          WHERE user_id = ? AND device_id = ? AND revoked_at IS NULL
            AND biometric_public_key IS NOT NULL`,
    args: [userId, deviceId],
  });
  return res.rows.length > 0;
}

/**
 * Register the device on login (or refresh its key / last-seen time).
 * A newly supplied device key replaces the old one; omitting it keeps the old one.
 */
function upsertOnLoginStmt(
  userId: string,
  deviceId: string,
  devicePublicKey: string | null,
  now: string,
): InStatement {
  return {
    sql: `INSERT INTO devices (id, user_id, device_id, device_public_key, created_at, last_seen_at)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT (user_id, device_id) DO UPDATE SET
            device_public_key = COALESCE(excluded.device_public_key, devices.device_public_key),
            last_seen_at = excluded.last_seen_at,
            revoked_at = NULL`,
    args: [uuidv7(), userId, deviceId, devicePublicKey, now, now],
  };
}

/** Store (or replace) the biometric-bound public key for an active device. */
async function setBiometricKey(
  userId: string,
  deviceId: string,
  publicKey: string,
  now: string,
): Promise<boolean> {
  const res = await db.execute({
    sql: `UPDATE devices
          SET biometric_public_key = ?, biometric_enrolled_at = ?, last_seen_at = ?
          WHERE user_id = ? AND device_id = ? AND revoked_at IS NULL`,
    args: [publicKey, now, now, userId, deviceId],
  });
  return res.rowsAffected > 0;
}

/** Remove the biometric key from a device (biometric approval turned off). */
async function clearBiometricKey(
  userId: string,
  deviceId: string,
): Promise<void> {
  await db.execute({
    sql: `UPDATE devices SET biometric_public_key = NULL, biometric_enrolled_at = NULL
          WHERE user_id = ? AND device_id = ?`,
    args: [userId, deviceId],
  });
}

/** The biometric public key for an active device, or null. */
async function getBiometricKey(
  userId: string,
  deviceId: string,
): Promise<string | null> {
  const res = await db.execute({
    sql: `SELECT biometric_public_key FROM devices
          WHERE user_id = ? AND device_id = ? AND revoked_at IS NULL`,
    args: [userId, deviceId],
  });
  return asTextOrNull(res.rows[0]?.biometric_public_key);
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  find,
  setBiometricKey,
  clearBiometricKey,
  getBiometricKey,
  isBiometricEnrolled,
  upsertOnLoginStmt,
} as const;
