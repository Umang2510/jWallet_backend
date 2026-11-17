import type { InStatement } from '@libsql/client';

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

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

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

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  insertStmt,
} as const;
