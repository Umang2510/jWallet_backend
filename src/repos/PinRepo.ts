import db, { asText, asTextOrNull } from '#src/db/client.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface PinRow {
  pinHash: string;
  failedCount: number;
  lockedUntil: string | null;
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

async function find(userId: string): Promise<PinRow | null> {
  const res = await db.execute({
    sql: `SELECT pin_hash, failed_count, locked_until
          FROM transaction_pins WHERE user_id = ?`,
    args: [userId],
  });
  const r = res.rows[0];
  if (!r) return null;
  return {
    pinHash: asText(r.pin_hash),
    failedCount: Number(r.failed_count),
    lockedUntil: asTextOrNull(r.locked_until),
  };
}

/** Create the first PIN. Returns false if one already exists. */
async function insert(
  userId: string,
  pinHash: string,
  now: string,
): Promise<boolean> {
  const res = await db.execute({
    sql: `INSERT INTO transaction_pins (user_id, pin_hash, set_at, updated_at)
          VALUES (?, ?, ?, ?)
          ON CONFLICT (user_id) DO NOTHING`,
    args: [userId, pinHash, now, now],
  });
  return res.rowsAffected > 0;
}

async function updateHash(
  userId: string,
  pinHash: string,
  now: string,
): Promise<void> {
  await db.execute({
    sql: `UPDATE transaction_pins
          SET pin_hash = ?, failed_count = 0, locked_until = NULL, updated_at = ?
          WHERE user_id = ?`,
    args: [pinHash, now, userId],
  });
}

/**
 * Atomically count one wrong attempt and return the new count. Using a single
 * UPDATE ... RETURNING means parallel guesses can't all read the same count.
 */
async function incrementFailures(userId: string): Promise<number> {
  const res = await db.execute({
    sql: `UPDATE transaction_pins SET failed_count = failed_count + 1
          WHERE user_id = ? RETURNING failed_count`,
    args: [userId],
  });
  return Number(res.rows[0]?.failed_count ?? 0);
}

async function lock(userId: string, until: string): Promise<void> {
  await db.execute({
    sql: `UPDATE transaction_pins SET failed_count = 0, locked_until = ?
          WHERE user_id = ?`,
    args: [until, userId],
  });
}

async function resetFailures(userId: string): Promise<void> {
  await db.execute({
    sql: `UPDATE transaction_pins SET failed_count = 0, locked_until = NULL
          WHERE user_id = ? AND (failed_count > 0 OR locked_until IS NOT NULL)`,
    args: [userId],
  });
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  find,
  insert,
  updateHash,
  incrementFailures,
  lock,
  resetFailures,
} as const;
