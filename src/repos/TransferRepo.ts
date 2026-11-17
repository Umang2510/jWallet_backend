import type { InStatement, Transaction } from '@libsql/client';

import db, { asText, asTextOrNull } from '#src/db/client.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface ChallengeRow {
  id: string;
  userId: string;
  familyId: string | null;
  nonce: string;
  payloadHash: string;
  expiresAt: string;
  usedAt: string | null;
}

export interface IdempotencyRow {
  requestHash: string;
  responseStatus: number;
  responseBody: string;
}

type Executor = Pick<Transaction, 'execute'> | typeof db;

// ========================================================================= //
//                                CHALLENGES                                 //
// ========================================================================= //

async function insertChallenge(c: {
  id: string;
  userId: string;
  sessionId: string;
  nonce: string;
  payloadHash: string;
  expiresAt: string;
  createdAt: string;
}): Promise<void> {
  await db.execute({
    sql: `INSERT INTO transfer_challenges (id, user_id, session_id, nonce, payload_hash, expires_at, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    args: [
      c.id,
      c.userId,
      c.sessionId,
      c.nonce,
      c.payloadHash,
      c.expiresAt,
      c.createdAt,
    ],
  });
}

/** Challenge plus the login family it was issued to (survives token refresh). */
async function findChallenge(id: string): Promise<ChallengeRow | null> {
  const res = await db.execute({
    sql: `SELECT c.id, c.user_id, s.family_id, c.nonce, c.payload_hash,
                 c.expires_at, c.used_at
          FROM transfer_challenges c
          LEFT JOIN sessions s ON s.id = c.session_id
          WHERE c.id = ?`,
    args: [id],
  });
  const r = res.rows[0];
  if (!r) return null;
  return {
    id: asText(r.id),
    userId: asText(r.user_id),
    familyId: asTextOrNull(r.family_id),
    nonce: asText(r.nonce),
    payloadHash: asText(r.payload_hash),
    expiresAt: asText(r.expires_at),
    usedAt: asTextOrNull(r.used_at),
  };
}

/** Mark the challenge used. 0 rows affected = already used or expired. */
function consumeChallengeStmt(id: string, now: string): InStatement {
  return {
    sql: `UPDATE transfer_challenges SET used_at = ?
          WHERE id = ? AND used_at IS NULL AND expires_at > ?`,
    args: [now, id, now],
  };
}

// ========================================================================= //
//                                IDEMPOTENCY                                //
// ========================================================================= //

async function findIdempotency(
  exec: Executor,
  userId: string,
  key: string,
): Promise<IdempotencyRow | null> {
  const res = await exec.execute({
    sql: `SELECT request_hash, response_status, response_body
          FROM idempotency_keys WHERE user_id = ? AND key = ?`,
    args: [userId, key],
  });
  const r = res.rows[0];
  if (!r) return null;
  return {
    requestHash: asText(r.request_hash),
    responseStatus: Number(r.response_status),
    responseBody: asText(r.response_body),
  };
}

function insertIdempotencyStmt(i: {
  userId: string;
  key: string;
  requestHash: string;
  responseStatus: number;
  responseBody: string;
  createdAt: string;
}): InStatement {
  return {
    sql: `INSERT INTO idempotency_keys (user_id, key, request_hash, response_status, response_body, created_at)
          VALUES (?, ?, ?, ?, ?, ?)`,
    args: [
      i.userId,
      i.key,
      i.requestHash,
      i.responseStatus,
      i.responseBody,
      i.createdAt,
    ],
  };
}

// ========================================================================= //
//                                  MONEY                                    //
// ========================================================================= //

/** Sum of today's successful debits (paise) since `sinceIso`. */
async function sumDebitsSince(
  exec: Executor,
  userId: string,
  sinceIso: string,
): Promise<number> {
  const res = await exec.execute({
    sql: `SELECT COALESCE(SUM(amount_paise), 0) AS total FROM transactions
          WHERE user_id = ? AND type = 'DEBIT' AND status = 'SUCCESS'
            AND created_at >= ?`,
    args: [userId, sinceIso],
  });
  return Number(res.rows[0]?.total ?? 0);
}

/**
 * The atomic debit: only succeeds if the wallet is ACTIVE and has enough
 * money *at this moment*. Returns the new balance, or null if refused.
 */
async function debitWallet(
  tx: Transaction,
  userId: string,
  amountPaise: number,
  now: string,
): Promise<{ walletId: string; balancePaise: number } | null> {
  const res = await tx.execute({
    sql: `UPDATE wallets
          SET balance_paise = balance_paise - ?, updated_at = ?
          WHERE user_id = ? AND status = 'ACTIVE' AND balance_paise >= ?
          RETURNING id, balance_paise`,
    args: [amountPaise, now, userId, amountPaise],
  });
  const r = res.rows[0];
  if (!r) return null;
  return { walletId: asText(r.id), balancePaise: Number(r.balance_paise) };
}

function insertTransactionStmt(t: {
  id: string;
  reference: string;
  walletId: string;
  userId: string;
  amountPaise: number;
  counterpartyName: string;
  mobileEnc: string;
  mobileMasked: string;
  remarks: string | null;
  balanceAfterPaise: number;
  approvalMethod: 'BIOMETRIC' | 'PIN';
  idempotencyKey: string;
  createdAt: string;
}): InStatement {
  return {
    sql: `INSERT INTO transactions (id, reference, wallet_id, user_id, type, amount_paise,
            currency, counterparty_name, counterparty_mobile_enc, counterparty_mobile_masked,
            remarks, status, balance_after_paise, approval_method, idempotency_key, created_at)
          VALUES (?, ?, ?, ?, 'DEBIT', ?, 'INR', ?, ?, ?, ?, 'SUCCESS', ?, ?, ?, ?)`,
    args: [
      t.id,
      t.reference,
      t.walletId,
      t.userId,
      t.amountPaise,
      t.counterpartyName,
      t.mobileEnc,
      t.mobileMasked,
      t.remarks,
      t.balanceAfterPaise,
      t.approvalMethod,
      t.idempotencyKey,
      t.createdAt,
    ],
  };
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  insertChallenge,
  findChallenge,
  consumeChallengeStmt,
  findIdempotency,
  insertIdempotencyStmt,
  sumDebitsSince,
  debitWallet,
  insertTransactionStmt,
} as const;
