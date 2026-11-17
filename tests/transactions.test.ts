import argon2 from 'argon2';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { before, describe, it } from 'node:test';

import Paths from '#src/common/constants/Paths/index.ts';
import { decryptField, encryptField } from '#src/common/utils/crypto.utils.ts';
import {
  generateTxnReference,
  maskMobile,
} from '#src/common/utils/money.utils.ts';
import db, { asText } from '#src/db/client.ts';
import { DEMO_USER, DEMO_WALLET, SAMPLE_TRANSACTIONS } from '#src/db/seed.ts';
import type { LoginResult } from '#src/services/AuthService.ts';
import type {
  TransactionDetails,
  TransactionListResult,
} from '#src/services/TransactionService.ts';

import { agent, dbReady } from './support/agent.ts';
import type { TypedErrRes, TypedRes } from './support/utils.ts';

// ========================================================================= //
//                                  HELPERS                                  //
// ========================================================================= //

const LIST = '/api/v1/transactions';
const details = (id: string) => Paths.Transactions.Details.format(id);
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

const OTHER = { email: 'other@jwallet.co', password: 'Other@1234' };

async function login(email: string, password: string): Promise<LoginResult> {
  const res: TypedRes<LoginResult> = await agent
    .post(Paths.Auth.Login.FULL_PATH)
    .send({ email, password });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body.body;
}

async function list(
  token: string,
  query = '',
): Promise<TypedRes<TransactionListResult>> {
  return agent.get(`${LIST}${query}`).set(bearer(token));
}

let demo: LoginResult;
let other: LoginResult;
let otherRef: string;

before(async () => {
  await dbReady;
  // A second user with one transaction of their own.
  const now = new Date().toISOString();
  const userId = randomUUID();
  const walletId = randomUUID();
  await db.batch(
    [
      {
        sql: `INSERT INTO users (id, public_id, name, email, password_hash, created_at, updated_at)
              VALUES (?, 'USR30001', 'Other User', ?, ?, ?, ?)`,
        args: [
          userId,
          OTHER.email,
          await argon2.hash(OTHER.password),
          now,
          now,
        ],
      },
      {
        sql: `INSERT INTO wallets (id, public_id, user_id, balance_paise, account_last4, created_at, updated_at)
              VALUES (?, 'WALLET30001', ?, 100, '1111', ?, ?)`,
        args: [walletId, userId, now, now],
      },
    ],
    'write',
  );
  otherRef = generateTxnReference();
  await db.execute({
    sql: `INSERT INTO transactions (id, reference, wallet_id, user_id, type, amount_paise,
            counterparty_name, status, created_at)
          VALUES (?, ?, ?, ?, 'CREDIT', 100, 'Secret Sender', 'SUCCESS', ?)`,
    args: [randomUUID(), otherRef, walletId, userId, now],
  });

  demo = await login(DEMO_USER.email, DEMO_USER.password);
  other = await login(OTHER.email, OTHER.password);
});

// ========================================================================= //
//                                   TESTS                                   //
// ========================================================================= //

describe('seeded sample data', () => {
  it('has at least 10 transactions for the demo user', async () => {
    const res = await list(demo.accessToken, '?limit=50');
    assert.ok(res.body.body.pagination.totalItems >= 10);
    assert.equal(
      res.body.body.pagination.totalItems,
      SAMPLE_TRANSACTIONS.length,
    );
  });

  it("is consistent with the wallet's real balance", async () => {
    const latest = await db.execute(
      `SELECT t.balance_after_paise FROM transactions t
       JOIN wallets w ON w.id = t.wallet_id
       WHERE w.public_id = '${DEMO_WALLET.publicId}'
       ORDER BY t.created_at DESC LIMIT 1`,
    );
    assert.equal(
      Number(latest.rows[0]?.balance_after_paise),
      DEMO_WALLET.balancePaise,
    );
  });

  it('stores mobile numbers encrypted, never in plain text', async () => {
    const res = await db.execute(
      "SELECT counterparty_mobile_enc, counterparty_mobile_masked FROM transactions WHERE counterparty_name = 'Rahul Sharma'",
    );
    const enc = asText(res.rows[0]?.counterparty_mobile_enc);
    assert.ok(!enc.includes('9876543210'));
    assert.equal(decryptField(enc), '9876543210');
    assert.equal(asText(res.rows[0]?.counterparty_mobile_masked), 'XXXXXX3210');
  });
});

describe('GET /api/v1/transactions', () => {
  it('returns items + pagination in the meta/body envelope, newest first', async () => {
    const res = await list(demo.accessToken);
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.meta, {
      statusCode: 200,
      message: 'Transactions fetched successfully',
    });
    const { items, pagination } = res.body.body;
    assert.deepEqual(pagination, {
      page: 1,
      limit: 20,
      totalItems: SAMPLE_TRANSACTIONS.length,
      totalPages: 1,
      hasNextPage: false,
    });
    const times = items.map((i) => Date.parse(i.createdAt));
    assert.deepEqual(
      times,
      [...times].sort((a, b) => b - a),
    );

    const first = items[0];
    assert.equal(first.beneficiaryName, 'Rahul Sharma');
    assert.equal(first.type, 'DEBIT');
    assert.equal(first.amount, 1500);
    assert.equal(first.currency, 'INR');
    assert.equal(first.status, 'SUCCESS');
    assert.match(first.id, /^TXN\d{8}[2-9A-HJ-NP-Z]{6}$/);
    assert.deepEqual(Object.keys(first).sort(), [
      'amount',
      'beneficiaryName',
      'createdAt',
      'currency',
      'id',
      'status',
      'type',
    ]);
  });

  it('supports the dashboard "latest five" call', async () => {
    const res = await list(demo.accessToken, '?limit=5');
    assert.equal(res.body.body.items.length, 5);
    assert.equal(res.body.body.pagination.hasNextPage, true);
  });

  it('paginates without overlap or gaps', async () => {
    const p1 = await list(demo.accessToken, '?limit=5&page=1');
    const p2 = await list(demo.accessToken, '?limit=5&page=2');
    const p3 = await list(demo.accessToken, '?limit=5&page=3');
    const ids = [p1, p2, p3].flatMap((r) => r.body.body.items.map((i) => i.id));
    assert.equal(ids.length, SAMPLE_TRANSACTIONS.length);
    assert.equal(new Set(ids).size, ids.length);
    assert.equal(p3.body.body.pagination.hasNextPage, false);
  });

  it('returns an empty page (200) past the last page', async () => {
    const res = await list(demo.accessToken, '?page=99');
    assert.equal(res.status, 200);
    assert.equal(res.body.meta.message, 'No transactions found');
    assert.deepEqual(res.body.body.items, []);
  });

  it('filters by type (case-insensitive)', async () => {
    const credit = await list(demo.accessToken, '?type=credit');
    assert.ok(credit.body.body.items.length > 0);
    assert.ok(credit.body.body.items.every((i) => i.type === 'CREDIT'));
    const debit = await list(demo.accessToken, '?type=DEBIT');
    assert.ok(debit.body.body.items.every((i) => i.type === 'DEBIT'));
    assert.equal(
      credit.body.body.pagination.totalItems +
        debit.body.body.pagination.totalItems,
      SAMPLE_TRANSACTIONS.length,
    );
  });

  it('filters by status', async () => {
    const res = await list(demo.accessToken, '?status=FAILED');
    assert.equal(res.body.body.items.length, 1);
    assert.equal(res.body.body.items[0]?.beneficiaryName, 'Neha Gupta');
  });

  it('searches beneficiary name case-insensitively and partially', async () => {
    const res = await list(demo.accessToken, '?q=rahul');
    assert.equal(res.body.body.items.length, 1);
    assert.equal(res.body.body.items[0]?.beneficiaryName, 'Rahul Sharma');
  });

  it('searches by transaction reference', async () => {
    const all = await list(demo.accessToken, '?limit=50');
    const ref = all.body.body.items[3].id;
    const res = await list(demo.accessToken, `?q=${ref.toLowerCase()}`);
    assert.equal(res.body.body.items.length, 1);
    assert.equal(res.body.body.items[0]?.id, ref);
  });

  it('combines search and type filters', async () => {
    const res = await list(demo.accessToken, '?q=rahul&type=CREDIT');
    assert.equal(res.body.body.items.length, 0);
    assert.equal(res.body.meta.message, 'No transactions found');
  });

  it('treats SQL wildcards and quotes in search literally', async () => {
    for (const q of ['%', '_', "' OR 1=1 --", '%25']) {
      const res = await list(demo.accessToken, `?q=${encodeURIComponent(q)}`);
      assert.equal(res.status, 200);
      assert.equal(res.body.body.items.length, 0, `query ${q}`);
    }
  });

  it('filters by IST date range (inclusive)', async () => {
    const today = new Date(Date.now() + 5.5 * 3_600_000)
      .toISOString()
      .slice(0, 10);
    const res = await list(demo.accessToken, `?from=2000-01-01&to=${today}`);
    assert.equal(
      res.body.body.pagination.totalItems,
      SAMPLE_TRANSACTIONS.length,
    );
    const none = await list(demo.accessToken, '?from=2000-01-01&to=2000-01-02');
    assert.equal(none.body.body.pagination.totalItems, 0);
  });

  it("never returns another user's transactions", async () => {
    const res = await list(other.accessToken, '?limit=50');
    assert.equal(res.body.body.pagination.totalItems, 1);
    assert.equal(res.body.body.items[0]?.id, otherRef);
    const demoSearch = await list(demo.accessToken, '?q=Secret');
    assert.equal(demoSearch.body.body.items.length, 0);
  });

  describe('invalid query (400)', () => {
    const cases: [string, string][] = [
      ['?type=TRANSFER', 'type'],
      ['?status=DONE', 'status'],
      ['?page=0', 'page'],
      ['?page=-1', 'page'],
      ['?page=abc', 'page'],
      ['?page=1.5', 'page'],
      ['?limit=0', 'limit'],
      ['?limit=51', 'limit'],
      ['?limit=1000000', 'limit'],
      ['?from=2026-13-01', 'from'],
      ['?from=yesterday', 'from'],
      ['?from=2026-11-10&to=2026-11-01', 'from'],
      [`?q=${'a'.repeat(51)}`, 'q'],
      ['?type=CREDIT&type=DEBIT', 'type'],
      ['?userId=USR10001', 'query'],
    ];
    for (const [query, field] of cases) {
      it(`rejects ${query.slice(0, 40)}`, async () => {
        const res: TypedErrRes = await agent
          .get(`${LIST}${query}`)
          .set(bearer(demo.accessToken));
        assert.equal(res.status, 400);
        assert.equal(res.body.body.errorCode, 'VALIDATION_ERROR');
        assert.ok(
          res.body.body.details?.some((d) => d.field === field),
          JSON.stringify(res.body.body.details),
        );
      });
    }
  });

  it('accepts empty optional params as "not set"', async () => {
    const res = await list(demo.accessToken, '?q=&type=&page=&limit=');
    assert.equal(res.status, 200);
    assert.equal(res.body.body.pagination.page, 1);
  });

  it('requires authentication', async () => {
    const res: TypedErrRes = await agent.get(LIST);
    assert.equal(res.status, 401);
  });
});

describe('GET /api/v1/transactions/:id', () => {
  it('returns full details in the meta/body envelope', async () => {
    const all = await list(demo.accessToken);
    const ref = all.body.body.items[0].id;
    const res: TypedRes<TransactionDetails> = await agent
      .get(details(ref))
      .set(bearer(demo.accessToken));
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.meta, {
      statusCode: 200,
      message: 'Transaction details fetched successfully',
    });
    const d = res.body.body;
    assert.equal(d.id, ref);
    assert.equal(d.type, 'DEBIT');
    assert.equal(d.amount, 1500);
    assert.equal(d.beneficiaryName, 'Rahul Sharma');
    assert.equal(d.mobileNumber, 'XXXXXX3210');
    assert.equal(d.remarks, 'Payment for services');
    assert.equal(d.status, 'SUCCESS');
    assert.ok(!JSON.stringify(res.body).includes('9876543210'));
  });

  it('returns remarks: null when there are none', async () => {
    const res = await list(demo.accessToken, '?q=Kavita');
    const ref = res.body.body.items[0].id;
    const d: TypedRes<TransactionDetails> = await agent
      .get(details(ref))
      .set(bearer(demo.accessToken));
    assert.equal(d.body.body.remarks, null);
  });

  it('accepts the reference in lower case', async () => {
    const all = await list(demo.accessToken);
    const ref = all.body.body.items[0].id;
    const res = await agent
      .get(details(ref.toLowerCase()))
      .set(bearer(demo.accessToken));
    assert.equal(res.status, 200);
  });

  it('404 for an unknown reference', async () => {
    const res: TypedErrRes = await agent
      .get(details('TXN10001'))
      .set(bearer(demo.accessToken));
    assert.equal(res.status, 404);
    assert.deepEqual(res.body, {
      meta: { statusCode: 404, message: 'Transaction not found' },
      body: { errorCode: 'TRANSACTION_NOT_FOUND' },
    });
  });

  it("404 (not 403) for another user's transaction", async () => {
    const res: TypedErrRes = await agent
      .get(details(otherRef))
      .set(bearer(demo.accessToken));
    assert.equal(res.status, 404);
    assert.equal(res.body.body.errorCode, 'TRANSACTION_NOT_FOUND');
  });

  it('400 for a malformed id', async () => {
    for (const bad of ["TXN' OR '1'='1", 'a'.repeat(41), 'TXN%00']) {
      const res: TypedErrRes = await agent
        .get(details(bad))
        .set(bearer(demo.accessToken));
      assert.equal(res.status, 400, bad);
      assert.equal(res.body.body.errorCode, 'VALIDATION_ERROR');
    }
  });

  it('requires authentication', async () => {
    const res: TypedErrRes = await agent.get(details(otherRef));
    assert.equal(res.status, 401);
  });
});

describe('field encryption helpers', () => {
  it('round-trips and uses a fresh IV each time', () => {
    const a = encryptField('9876543210');
    const b = encryptField('9876543210');
    assert.notEqual(a, b);
    assert.equal(decryptField(a), '9876543210');
  });

  it('detects tampering', () => {
    const enc = encryptField('9876543210');
    const parts = enc.split('.');
    const ct = Buffer.from(parts[3], 'base64url');
    ct[0] = ct[0] ^ 1;
    parts[3] = ct.toString('base64url');
    assert.throws(() => decryptField(parts.join('.')));
  });

  it('masks mobile numbers', () => {
    assert.equal(maskMobile('9876543210'), 'XXXXXX3210');
  });
});
