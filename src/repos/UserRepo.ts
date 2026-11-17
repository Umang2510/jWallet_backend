import type { InStatement } from '@libsql/client';

import db, { asText, asTextOrNull } from '#src/db/client.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface UserRow {
  id: string;
  publicId: string;
  name: string;
  email: string;
  passwordHash: string;
  status: 'ACTIVE' | 'LOCKED' | 'FROZEN';
  failedLoginCount: number;
  loginLockedUntil: string | null;
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

async function findByEmail(email: string): Promise<UserRow | null> {
  const res = await db.execute({
    sql: `SELECT id, public_id, name, email, password_hash, status,
                 failed_login_count, login_locked_until
          FROM users WHERE email = ?`,
    args: [email],
  });
  const r = res.rows[0];
  if (!r) return null;
  return {
    id: asText(r.id),
    publicId: asText(r.public_id),
    name: asText(r.name),
    email: asText(r.email),
    passwordHash: asText(r.password_hash),
    status: asText(r.status) as UserRow['status'],
    failedLoginCount: Number(r.failed_login_count),
    loginLockedUntil: asTextOrNull(r.login_locked_until),
  };
}

async function findById(
  id: string,
): Promise<{ id: string; status: UserRow['status'] } | null> {
  const res = await db.execute({
    sql: 'SELECT id, status FROM users WHERE id = ?',
    args: [id],
  });
  const r = res.rows[0];
  if (!r) return null;
  return { id: asText(r.id), status: asText(r.status) as UserRow['status'] };
}

/** Record a failed login; `lockedUntil` is set when the threshold is hit. */
async function recordFailedLogin(
  userId: string,
  failedCount: number,
  lockedUntil: string | null,
): Promise<void> {
  await db.execute({
    sql: `UPDATE users
          SET failed_login_count = ?, login_locked_until = ?, updated_at = ?
          WHERE id = ?`,
    args: [failedCount, lockedUntil, new Date().toISOString(), userId],
  });
}

/** Statement (for a batch) that clears failed-login state after a success. */
function resetLoginFailuresStmt(userId: string, now: string): InStatement {
  return {
    sql: `UPDATE users
          SET failed_login_count = 0, login_locked_until = NULL, updated_at = ?
          WHERE id = ?`,
    args: [now, userId],
  };
}

async function hasTransactionPin(userId: string): Promise<boolean> {
  const res = await db.execute({
    sql: 'SELECT 1 FROM transaction_pins WHERE user_id = ?',
    args: [userId],
  });
  return res.rows.length > 0;
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  findByEmail,
  findById,
  recordFailedLogin,
  resetLoginFailuresStmt,
  hasTransactionPin,
} as const;
