import argon2 from 'argon2';
import logger from 'jet-logger';
import { randomInt } from 'node:crypto';
import { parseArgs } from 'node:util';
import { v7 as uuidv7 } from 'uuid';
import { z } from 'zod';

import db, { asText } from './client.ts';

// Usage:
//   npm run user:create -- --name "Rahul Sharma" --email rahul@example.com --password "Rahul@1234" [--balance 10000.50]
// Creates the user (argon2id-hashed password) and their INR wallet in one atomic batch.

// ========================================================================= //
//                                  SCHEMAS                                  //
// ========================================================================= //

const ArgsSchema = z.object({
  name: z.string().trim().min(1, 'name is required').max(100),
  email: z.string().trim().toLowerCase().pipe(z.email('invalid email')),
  password: z
    .string()
    .min(8, 'password must be at least 8 characters')
    .max(128)
    .regex(/[a-z]/, 'password needs a lowercase letter')
    .regex(/[A-Z]/, 'password needs an uppercase letter')
    .regex(/\d/, 'password needs a digit')
    .regex(/[^A-Za-z0-9]/, 'password needs a special character'),
  balance: z.coerce
    .number()
    .min(0, 'balance cannot be negative')
    .max(10_000_000)
    .refine(
      (v) =>
        Number.isInteger(Math.round(v * 100)) &&
        /^\d+(\.\d{1,2})?$/.test(String(v)),
      'balance can have at most 2 decimals',
    )
    .default(0),
});

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/** Next sequential public id, e.g. USR10001 -> USR10002. */
async function nextPublicId(table: 'users' | 'wallets', prefix: string) {
  const res = await db.execute(
    `SELECT public_id FROM ${table} WHERE public_id LIKE '${prefix}%'
     ORDER BY CAST(substr(public_id, ${prefix.length + 1}) AS INTEGER) DESC LIMIT 1`,
  );
  const last = res.rows[0] ? asText(res.rows[0].public_id) : `${prefix}10000`;
  return `${prefix}${Number(last.slice(prefix.length)) + 1}`;
}

async function main() {
  const { values } = parseArgs({
    options: {
      name: { type: 'string' },
      email: { type: 'string' },
      password: { type: 'string' },
      balance: { type: 'string' },
    },
  });

  const parsed = ArgsSchema.safeParse(values);
  if (!parsed.success) {
    logger.err(z.prettifyError(parsed.error));
    process.exitCode = 1;
    return;
  }
  const { name, email, password, balance } = parsed.data;

  const exists = await db.execute({
    sql: 'SELECT 1 FROM users WHERE email = ?',
    args: [email],
  });
  if (exists.rows.length) {
    logger.err(`A user with email ${email} already exists`);
    process.exitCode = 1;
    return;
  }

  const now = new Date().toISOString();
  const userId = uuidv7();
  const userPublicId = await nextPublicId('users', 'USR');
  const walletPublicId = await nextPublicId('wallets', 'WALLET');
  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
  const accountLast4 = String(randomInt(0, 10_000)).padStart(4, '0');

  await db.batch(
    [
      {
        sql: `INSERT INTO users (id, public_id, name, email, password_hash, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?)`,
        args: [userId, userPublicId, name, email, passwordHash, now, now],
      },
      {
        sql: `INSERT INTO wallets (id, public_id, user_id, currency, balance_paise, account_last4, created_at, updated_at)
              VALUES (?, ?, ?, 'INR', ?, ?, ?, ?)`,
        args: [
          uuidv7(),
          walletPublicId,
          userId,
          Math.round(balance * 100),
          accountLast4,
          now,
          now,
        ],
      },
    ],
    'write',
  );

  logger.info(
    `Created ${userPublicId} (${email}) with wallet ${walletPublicId}, ` +
      `balance ₹${balance.toFixed(2)}, account XXXX XXXX ${accountLast4}`,
  );
}

try {
  await main();
} catch (err) {
  logger.err(err, true);
  process.exitCode = 1;
} finally {
  db.close();
}
