import type { InStatement } from '@libsql/client';

import db, { asText, asTextOrNull } from '#src/db/client.ts';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

/**
 * Why a session row was revoked. ROTATED rows are superseded by a newer row in
 * the same family: their access tokens stay valid until expiry, but their
 * refresh token must never be used again (doing so = token theft).
 */
export const RevokeReasons = {
  ROTATED: 'ROTATED',
  LOGOUT: 'LOGOUT',
  LOGOUT_ALL: 'LOGOUT_ALL',
  REUSE_DETECTED: 'REUSE_DETECTED',
} as const;
export type RevokeReason = (typeof RevokeReasons)[keyof typeof RevokeReasons];

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface NewSession {
  id: string;
  userId: string;
  deviceId: string | null;
  refreshTokenHash: string;
  familyId: string;
  passwordAuthAt: string;
  expiresAt: string;
  ip: string | null;
  userAgent: string | null;
  createdAt: string;
}

export interface SessionRow {
  id: string;
  userId: string;
  deviceId: string | null;
  familyId: string;
  passwordAuthAt: string;
  expiresAt: string;
  revokedAt: string | null;
  revokeReason: string | null;
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

const SELECT_COLUMNS = `id, user_id, device_id, family_id, password_auth_at,
                        expires_at, revoked_at, revoke_reason`;

function toRow(r: Record<string, unknown>): SessionRow {
  const v = r as Record<string, Parameters<typeof asText>[0]>;
  return {
    id: asText(v.id),
    userId: asText(v.user_id),
    deviceId: asTextOrNull(v.device_id),
    familyId: asText(v.family_id),
    passwordAuthAt: asText(v.password_auth_at),
    expiresAt: asText(v.expires_at),
    revokedAt: asTextOrNull(v.revoked_at),
    revokeReason: asTextOrNull(v.revoke_reason),
  };
}

async function findByRefreshHash(hash: string): Promise<SessionRow | null> {
  const res = await db.execute({
    sql: `SELECT ${SELECT_COLUMNS} FROM sessions WHERE refresh_token_hash = ?`,
    args: [hash],
  });
  return res.rows[0] ? toRow(res.rows[0]) : null;
}

async function findById(id: string): Promise<SessionRow | null> {
  const res = await db.execute({
    sql: `SELECT ${SELECT_COLUMNS} FROM sessions WHERE id = ?`,
    args: [id],
  });
  return res.rows[0] ? toRow(res.rows[0]) : null;
}

function insertStmt(s: NewSession): InStatement {
  return {
    sql: `INSERT INTO sessions (id, user_id, device_id, refresh_token_hash, family_id,
                                password_auth_at, expires_at, ip, user_agent, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      s.id,
      s.userId,
      s.deviceId,
      s.refreshTokenHash,
      s.familyId,
      s.passwordAuthAt,
      s.expiresAt,
      s.ip,
      s.userAgent,
      s.createdAt,
    ],
  };
}

/** Mark one live row as rotated. Affects 0 rows if it was already used. */
function rotateStmt(sessionId: string, now: string): InStatement {
  return {
    sql: `UPDATE sessions SET revoked_at = ?, revoke_reason = '${RevokeReasons.ROTATED}'
          WHERE id = ? AND revoked_at IS NULL`,
    args: [now, sessionId],
  };
}

/**
 * Kill every row of a login chain (live and rotated), so neither its refresh
 * tokens nor its still-unexpired access tokens work any more.
 */
function revokeFamilyStmt(
  familyId: string,
  reason: RevokeReason,
  now: string,
): InStatement {
  return {
    sql: `UPDATE sessions
          SET revoked_at = COALESCE(revoked_at, ?), revoke_reason = ?
          WHERE family_id = ?
            AND (revoked_at IS NULL OR revoke_reason = '${RevokeReasons.ROTATED}')`,
    args: [now, reason, familyId],
  };
}

/** Same as revokeFamilyStmt, for every session of the user (all devices). */
function revokeAllForUserStmt(
  userId: string,
  reason: RevokeReason,
  now: string,
): InStatement {
  return {
    sql: `UPDATE sessions
          SET revoked_at = COALESCE(revoked_at, ?), revoke_reason = ?
          WHERE user_id = ?
            AND (revoked_at IS NULL OR revoke_reason = '${RevokeReasons.ROTATED}')`,
    args: [now, reason, userId],
  };
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  findByRefreshHash,
  findById,
  insertStmt,
  rotateStmt,
  revokeFamilyStmt,
  revokeAllForUserStmt,
} as const;
