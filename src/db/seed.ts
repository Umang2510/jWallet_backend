import type { InStatement } from '@libsql/client';
import argon2 from 'argon2';
import logger from 'jet-logger';
import { v7 as uuidv7 } from 'uuid';

import { encryptField } from '#src/common/utils/crypto.utils.ts';
import {
  generateTxnReference,
  maskMobile,
} from '#src/common/utils/money.utils.ts';

import db, { asText } from './client.ts';

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

interface SampleTxn {
  type: 'CREDIT' | 'DEBIT';
  paise: number;
  name: string;
  mobile: string;
  status: 'SUCCESS' | 'FAILED' | 'PENDING';
  remarks: string | null;
  hoursAgo: number;
}

/**
 * Sample history (newest first). Fictional names and numbers only.
 * Only SUCCESS entries move the balance; FAILED/PENDING leave it unchanged.
 */
export const SAMPLE_TRANSACTIONS: readonly SampleTxn[] = [
  {
    type: 'DEBIT',
    paise: 150000,
    name: 'Rahul Sharma',
    mobile: '9876543210',
    status: 'SUCCESS',
    remarks: 'Payment for services',
    hoursAgo: 2,
  },
  {
    type: 'CREDIT',
    paise: 500000,
    name: 'Amit Kumar',
    mobile: '9123456780',
    status: 'SUCCESS',
    remarks: 'Rent share',
    hoursAgo: 20,
  },
  {
    type: 'DEBIT',
    paise: 25000,
    name: 'Priya Verma',
    mobile: '9988776655',
    status: 'SUCCESS',
    remarks: 'Lunch',
    hoursAgo: 30,
  },
  {
    type: 'DEBIT',
    paise: 79900,
    name: 'Neha Gupta',
    mobile: '9012345678',
    status: 'FAILED',
    remarks: 'Movie tickets',
    hoursAgo: 52,
  },
  {
    type: 'CREDIT',
    paise: 120050,
    name: 'Vikram Singh',
    mobile: '9898989898',
    status: 'SUCCESS',
    remarks: 'Refund',
    hoursAgo: 75,
  },
  {
    type: 'DEBIT',
    paise: 320000,
    name: 'Sanjay Patel',
    mobile: '9765432109',
    status: 'SUCCESS',
    remarks: 'Electricity bill',
    hoursAgo: 100,
  },
  {
    type: 'DEBIT',
    paise: 45025,
    name: 'Anjali Mehta',
    mobile: '9345678901',
    status: 'PENDING',
    remarks: 'Groceries',
    hoursAgo: 130,
  },
  {
    type: 'CREDIT',
    paise: 1000000,
    name: 'Rohit Jain',
    mobile: '9456789012',
    status: 'SUCCESS',
    remarks: 'Salary advance',
    hoursAgo: 170,
  },
  {
    type: 'DEBIT',
    paise: 210000,
    name: 'Kavita Rao',
    mobile: '9567890123',
    status: 'SUCCESS',
    remarks: null,
    hoursAgo: 220,
  },
  {
    type: 'DEBIT',
    paise: 89999,
    name: 'Arjun Nair',
    mobile: '9678901234',
    status: 'SUCCESS',
    remarks: 'Mobile recharge',
    hoursAgo: 280,
  },
  {
    type: 'CREDIT',
    paise: 75000,
    name: 'Deepak Joshi',
    mobile: '9789012345',
    status: 'SUCCESS',
    remarks: 'Split bill',
    hoursAgo: 350,
  },
  {
    type: 'DEBIT',
    paise: 135000,
    name: 'Sneha Iyer',
    mobile: '9890123456',
    status: 'SUCCESS',
    remarks: 'Books',
    hoursAgo: 430,
  },
];

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

  let userId = existing.rows[0] ? asText(existing.rows[0].id) : undefined;
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

/**
 * Give every wallet that has no history the sample transactions. The history
 * is built backwards from the wallet's current balance, so each entry's
 * `balance_after` is consistent with the real balance. Wallets too small for
 * the sample history (it would go negative) are skipped.
 */
export async function seedSampleTransactions(): Promise<void> {
  const wallets = await db.execute(
    `SELECT w.id, w.user_id, w.balance_paise, u.email
     FROM wallets w JOIN users u ON u.id = w.user_id
     WHERE NOT EXISTS (SELECT 1 FROM transactions t WHERE t.wallet_id = w.id)`,
  );

  for (const w of wallets.rows) {
    const walletId = asText(w.id);
    const userId = asText(w.user_id);
    const email = asText(w.email);

    let running = Number(w.balance_paise);
    const stmts: InStatement[] = [];
    let ok = true;

    for (const t of SAMPLE_TRANSACTIONS) {
      const createdAt = new Date(Date.now() - t.hoursAgo * 3_600_000);
      stmts.push({
        sql: `INSERT INTO transactions (id, reference, wallet_id, user_id, type, amount_paise,
                currency, counterparty_name, counterparty_mobile_enc, counterparty_mobile_masked,
                remarks, status, balance_after_paise, created_at)
              VALUES (?, ?, ?, ?, ?, ?, 'INR', ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          uuidv7(),
          generateTxnReference(createdAt),
          walletId,
          userId,
          t.type,
          t.paise,
          t.name,
          encryptField(t.mobile),
          maskMobile(t.mobile),
          t.remarks,
          t.status,
          running,
          createdAt.toISOString(),
        ],
      });
      // Walk back in time: undo this entry's effect to get the earlier balance.
      if (t.status === 'SUCCESS') {
        running += t.type === 'CREDIT' ? -t.paise : t.paise;
      }
      if (running < 0) {
        ok = false;
        break;
      }
    }

    if (!ok) {
      logger.warn(`Skipped sample history for ${email}: balance too low`);
      continue;
    }
    await db.batch(stmts, 'write');
    logger.info(
      `Seeded ${SAMPLE_TRANSACTIONS.length} sample transactions for ${email}`,
    );
  }
}

/** Seed only when the database has no users yet (used by AUTO_SEED). */
export async function seedIfEmpty(): Promise<void> {
  const res = await db.execute('SELECT COUNT(*) AS n FROM users');
  if (Number(res.rows[0]?.n ?? 0) === 0) {
    await seedDemoData();
    await seedSampleTransactions();
  }
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
  await seedSampleTransactions();
}
