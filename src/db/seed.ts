import argon2 from 'argon2';
import logger from 'jet-logger';
import { v7 as uuidv7 } from 'uuid';

import db from './client.ts';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

/** Public demo credentials from the assignment brief — not a secret. */
export const DEMO_USER = {
  publicId: 'USR10001',
  name: 'Demo User',
  email: 'demo@jstack.co',
  password: 'Demo@123',
} as const;

export const DEMO_WALLET = {
  publicId: 'WALLET10001',
  balancePaise: 2545075, // ₹25,450.75
  currency: 'INR',
  accountLast4: '4589',
} as const;

// Child tables first so foreign keys never point at deleted rows.
const ALL_TABLES = [
  'audit_log',
  'request_nonces',
  'idempotency_keys',
  'transfer_challenges',
  'sessions',
  'devices',
  'transaction_pins',
  'transactions',
  'wallets',
  'users',
] as const;

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/**
 * Insert the demo user and wallet if they don't exist. Safe to run repeatedly.
 */
export async function seedDemoData(): Promise<void> {
  const now = new Date().toISOString();
  const existing = await db.execute({
    sql: 'SELECT id FROM users WHERE email = ?',
    args: [DEMO_USER.email],
  });

  let userId = existing.rows[0]?.id as string | undefined;
  if (!userId) {
    userId = uuidv7();
    const passwordHash = await argon2.hash(DEMO_USER.password, {
      type: argon2.argon2id,
    });
    await db.execute({
      sql: `INSERT INTO users (id, public_id, name, email, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
      args: [
        userId,
        DEMO_USER.publicId,
        DEMO_USER.name,
        DEMO_USER.email,
        passwordHash,
        now,
        now,
      ],
    });
    logger.info(`Seeded demo user ${DEMO_USER.email}`);
  }

  await db.execute({
    sql: `INSERT INTO wallets (id, public_id, user_id, currency, balance_paise, account_last4, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT (user_id) DO NOTHING`,
    args: [
      uuidv7(),
      DEMO_WALLET.publicId,
      userId,
      DEMO_WALLET.currency,
      DEMO_WALLET.balancePaise,
      DEMO_WALLET.accountLast4,
      now,
      now,
    ],
  });
}

/** Seed only when the database has no users yet (used by AUTO_SEED). */
export async function seedIfEmpty(): Promise<void> {
  const res = await db.execute('SELECT COUNT(*) AS n FROM users');
  if (Number(res.rows[0]?.n ?? 0) === 0) await seedDemoData();
}

/**
 * Delete all rows from every table, then re-seed.
 *
 * @testOnly
 */
export async function resetAllData(): Promise<void> {
  await db.batch(
    ALL_TABLES.map((t) => `DELETE FROM ${t}`),
    'write',
  );
  await seedDemoData();
}
