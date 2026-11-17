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

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  find,
  isBiometricEnrolled,
  upsertOnLoginStmt,
} as const;
