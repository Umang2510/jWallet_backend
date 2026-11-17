import argon2 from 'argon2';
import assert from 'node:assert/strict';
import {
  generateKeyPairSync,
  type KeyObject,
  randomUUID,
  sign,
} from 'node:crypto';
import { beforeEach, describe, it } from 'node:test';

import { Env } from '#src/common/constants/env.constants.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import { decryptField } from '#src/common/utils/crypto.utils.ts';
import db, { asText } from '#src/db/client.ts';
import { DEMO_USER, DEMO_WALLET } from '#src/db/seed.ts';
import { rupeesToPaise } from '#src/entities/Transfer/index.ts';
import type { LoginResult } from '#src/services/AuthService.ts';
import type { TransactionDetails } from '#src/services/TransactionService.ts';
import type {
  ChallengeResult,
  TransferResult,
} from '#src/services/TransferService.ts';
import type { BalanceResult } from '#src/services/WalletService.ts';

import { agent, dbReady } from './support/agent.ts';
import type { TypedErrRes, TypedRes } from './support/utils.ts';

// ========================================================================= //
//                                  HELPERS                                  //
// ========================================================================= //

const CHALLENGE = Paths.Transactions.TransferChallenge.FULL_PATH;
const TRANSFER = Paths.Transactions.Transfer.FULL_PATH;
const PIN = '2580';
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

const BODY = {
  beneficiaryName: 'Rahul Sharma',
  mobileNumber: '9876543210',
  amount: 1500,
  remarks: 'Payment for services',
};

async function login(extra: object = {}): Promise<LoginResult> {
  const res: TypedRes<LoginResult> = await agent
    .post(Paths.Auth.Login.FULL_PATH)
    .send({ email: DEMO_USER.email, password: DEMO_USER.password, ...extra });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body.body;
}

/** Logged-in device with a biometric key enrolled (written directly). */
async function biometricLogin() {
  const deviceId = randomUUID();
  const session = await login({ deviceId });
  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  await db.execute({
    sql: `UPDATE devices SET biometric_public_key = ?, biometric_enrolled_at = ?
          WHERE device_id = ?`,
    args: [
      publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
      new Date().toISOString(),
      deviceId,
    ],
  });
  return { session, privateKey, deviceId };
}

const signWith = (key: KeyObject, text: string) =>
  sign('sha256', Buffer.from(text), { key, dsaEncoding: 'der' }).toString(
    'base64',
  );

/** T defaults to the success shape; annotate with TypedErrRes for errors. */
async function challenge<T = ChallengeResult>(
  token: string,
  body: object = BODY,
): Promise<TypedRes<T>> {
  return agent.post(CHALLENGE).set(bearer(token)).send(body);
}

function transfer(
  token: string,
  body: object,
  key: string | null = randomUUID(),
) {
  const req = agent.post(TRANSFER).set(bearer(token));
  if (key !== null) req.set('Idempotency-Key', key);
  return req.send(body);
}

/** Full happy-path PIN transfer; returns the response. */
async function payWithPin<T = TransferResult>(
  token: string,
  body: object = BODY,
  key = randomUUID(),
): Promise<TypedRes<T>> {
  const c = await challenge<ChallengeResult>(token, body);
  assert.equal(c.status, 201, JSON.stringify(c.body));
  return transfer(
    token,
    {
      ...body,
      challengeId: c.body.body.challengeId,
      approval: { method: 'PIN', pin: PIN },
    },
    key,
  );
}

async function balancePaise(): Promise<number> {
  const r = await db.execute(
    `SELECT balance_paise FROM wallets WHERE public_id = '${DEMO_WALLET.publicId}'`,
  );
  return Number(r.rows[0]?.balance_paise);
}

async function setBalance(paise: number) {
  await db.execute(
    `UPDATE wallets SET balance_paise = ${paise}, status = 'ACTIVE' WHERE public_id = '${DEMO_WALLET.publicId}'`,
  );
}

async function transferCount(): Promise<number> {
  const r = await db.execute(
    'SELECT COUNT(*) AS n FROM transactions WHERE idempotency_key IS NOT NULL',
  );
  return Number(r.rows[0]?.n);
}

beforeEach(async () => {
  await dbReady;
  const now = new Date().toISOString();
  await db.batch(
    [
      'DELETE FROM transactions WHERE idempotency_key IS NOT NULL',
      'DELETE FROM idempotency_keys',
      'DELETE FROM transfer_challenges',
      'DELETE FROM transaction_pins',
      'UPDATE users SET failed_login_count = 0, login_locked_until = NULL',
      `UPDATE wallets SET balance_paise = ${DEMO_WALLET.balancePaise}, status = 'ACTIVE'`,
    ],
    'write',
  );
  await db.execute({
    sql: `INSERT INTO transaction_pins (user_id, pin_hash, set_at, updated_at)
          SELECT id, ?, ?, ? FROM users WHERE email = ?`,
    args: [await argon2.hash(PIN), now, now, DEMO_USER.email],
  });
});

// ========================================================================= //
//                                   TESTS                                   //
// ========================================================================= //

describe('POST /api/v1/transactions/transfer/challenge', () => {
  it('returns a challenge with summary and approval methods (201)', async () => {
    const s = await login();
    const res = await challenge(s.accessToken);
    assert.equal(res.status, 201);
    assert.deepEqual(res.body.meta, {
      statusCode: 201,
      message: 'Approve this transfer with your fingerprint or PIN',
    });
    const b = res.body.body;
    assert.match(b.challengeId, /^[0-9a-f-]{36}$/);
    assert.ok(b.nonce.length >= 43);
    assert.deepEqual(b.approvalMethods, ['PIN']);
    assert.match(b.signingPayload, /^JWALLET-TRANSFER\n/);
    assert.deepEqual(b.summary, {
      beneficiaryName: 'Rahul Sharma',
      mobileNumber: 'XXXXXX3210',
      amount: 1500,
      currency: 'INR',
      remarks: 'Payment for services',
    });
    const ttl = (Date.parse(b.expiresAt) - Date.now()) / 1000;
    assert.ok(ttl > Env.CHALLENGE_TTL_SEC - 5 && ttl <= Env.CHALLENGE_TTL_SEC);
  });

  it('offers BIOMETRIC on an enrolled device', async () => {
    const { session } = await biometricLogin();
    const res = await challenge(session.accessToken);
    assert.deepEqual(res.body.body.approvalMethods, ['BIOMETRIC', 'PIN']);
  });

  it('409 INSUFFICIENT_BALANCE up front', async () => {
    const s = await login();
    const res: TypedErrRes = await challenge(s.accessToken, {
      ...BODY,
      amount: 25450.76,
    });
    assert.equal(res.status, 409);
    assert.deepEqual(res.body, {
      meta: { statusCode: 409, message: 'Insufficient wallet balance' },
      body: { errorCode: 'INSUFFICIENT_BALANCE' },
    });
  });

  it('403 PIN_NOT_SET before a PIN exists', async () => {
    await db.execute('DELETE FROM transaction_pins');
    const s = await login();
    const res: TypedErrRes = await challenge(s.accessToken);
    assert.equal(res.status, 403);
    assert.equal(res.body.body.errorCode, 'PIN_NOT_SET');
  });

  it('423 PIN_LOCKED while the PIN is locked', async () => {
    await db.execute(
      `UPDATE transaction_pins SET locked_until = '${new Date(Date.now() + 3_600_000).toISOString()}'`,
    );
    const s = await login();
    const res: TypedErrRes = await challenge(s.accessToken);
    assert.equal(res.status, 423);
  });

  it('403 WALLET_FROZEN for a frozen wallet', async () => {
    await db.execute("UPDATE wallets SET status = 'FROZEN'");
    const s = await login();
    const res: TypedErrRes = await challenge(s.accessToken);
    assert.equal(res.status, 403);
    assert.equal(res.body.body.errorCode, 'WALLET_FROZEN');
  });

  it('400 above the per-transfer maximum', async () => {
    await setBalance(1_000_000_00);
    const s = await login();
    const res: TypedErrRes = await challenge(s.accessToken, {
      ...BODY,
      amount: Env.MAX_TRANSFER_AMOUNT + 0.01,
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.body.details?.some((d) => d.field === 'amount'));
  });

  describe('validation (400)', () => {
    const cases: [string, Record<string, unknown>, string][] = [
      ['empty name', { beneficiaryName: '   ' }, 'beneficiaryName'],
      ['missing name', { beneficiaryName: undefined }, 'beneficiaryName'],
      ['name with digits', { beneficiaryName: 'R2D2' }, 'beneficiaryName'],
      ['name with HTML', { beneficiaryName: '<script>x' }, 'beneficiaryName'],
      [
        'name too long',
        { beneficiaryName: 'A'.repeat(101) },
        'beneficiaryName',
      ],
      ['9-digit mobile', { mobileNumber: '987654321' }, 'mobileNumber'],
      ['11-digit mobile', { mobileNumber: '98765432101' }, 'mobileNumber'],
      [
        'mobile starting with 5',
        { mobileNumber: '5876543210' },
        'mobileNumber',
      ],
      ['mobile with +91', { mobileNumber: '+919876543210' }, 'mobileNumber'],
      ['mobile with letters', { mobileNumber: '98765abcde' }, 'mobileNumber'],
      ['mobile as number', { mobileNumber: 9876543210 }, 'mobileNumber'],
      ['zero amount', { amount: 0 }, 'amount'],
      ['negative amount', { amount: -100 }, 'amount'],
      ['3 decimals', { amount: 10.005 }, 'amount'],
      ['amount as string', { amount: '1500' }, 'amount'],
      ['missing amount', { amount: undefined }, 'amount'],
      ['remarks too long', { remarks: 'x'.repeat(101) }, 'remarks'],
      ['remarks with control chars', { remarks: 'hi\u0000there' }, 'remarks'],
      ['unknown field', { walletId: 'WALLET20001' }, 'body'],
    ];
    for (const [name, override, field] of cases) {
      it(name, async () => {
        const s = await login();
        const res: TypedErrRes = await challenge(s.accessToken, {
          ...BODY,
          ...override,
        });
        assert.equal(res.status, 400, JSON.stringify(res.body));
        assert.ok(
          res.body.body.details?.some((d) => d.field === field),
          JSON.stringify(res.body.body.details),
        );
      });
    }

    it('rejects NaN / Infinity sent as JSON', async () => {
      const s = await login();
      const res = await agent
        .post(CHALLENGE)
        .set(bearer(s.accessToken))
        .set('Content-Type', 'application/json')
        .send(
          '{"beneficiaryName":"A","mobileNumber":"9876543210","amount":1e999}',
        );
      assert.equal(res.status, 400);
    });
  });

  it('normalises name spaces and empty remarks', async () => {
    const s = await login();
    const res = await challenge(s.accessToken, {
      ...BODY,
      beneficiaryName: '  Rahul    Sharma ',
      remarks: '   ',
    });
    assert.equal(res.body.body.summary.beneficiaryName, 'Rahul Sharma');
    assert.equal(res.body.body.summary.remarks, null);
  });
});

describe('POST /api/v1/transactions/transfer', () => {
  describe('success', () => {
    it('PIN approval: debits exactly once and returns the receipt', async () => {
      const s = await login();
      const res = await payWithPin(s.accessToken);
      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.deepEqual(res.body.meta, {
        statusCode: 200,
        message: 'Transfer successful',
      });
      const b = res.body.body;
      assert.match(b.transactionId, /^TXN\d{8}[2-9A-HJ-NP-Z]{6}$/);
      assert.equal(b.status, 'SUCCESS');
      assert.equal(b.amount, 1500);
      assert.equal(b.currency, 'INR');
      assert.equal(b.availableBalance, 23950.75);
      assert.equal(b.beneficiaryName, 'Rahul Sharma');
      assert.equal(b.mobileNumber, 'XXXXXX3210');
      assert.equal(b.remarks, 'Payment for services');
      assert.equal(b.approvalMethod, 'PIN');
      assert.equal(await balancePaise(), 2395075);
    });

    it('updates balance API, history (top item) and details', async () => {
      const s = await login();
      const paid = await payWithPin(s.accessToken);
      const ref = paid.body.body.transactionId;

      const bal: TypedRes<BalanceResult> = await agent
        .get(Paths.Wallet.Balance.FULL_PATH)
        .set(bearer(s.accessToken));
      assert.equal(bal.body.body.availableBalance, 23950.75);

      const hist: TypedRes<{ items: { id: string }[] }> = await agent
        .get('/api/v1/transactions?limit=1')
        .set(bearer(s.accessToken));
      assert.equal(hist.body.body.items[0]?.id, ref);

      const d: TypedRes<TransactionDetails> = await agent
        .get(Paths.Transactions.Details.format(ref))
        .set(bearer(s.accessToken));
      assert.equal(d.body.body.type, 'DEBIT');
      assert.equal(d.body.body.remarks, 'Payment for services');
    });

    it('stores the mobile number encrypted with the transaction', async () => {
      const s = await login();
      const paid = await payWithPin(s.accessToken);
      const row = await db.execute({
        sql: 'SELECT counterparty_mobile_enc, balance_after_paise, approval_method FROM transactions WHERE reference = ?',
        args: [paid.body.body.transactionId],
      });
      assert.equal(
        decryptField(asText(row.rows[0]?.counterparty_mobile_enc)),
        '9876543210',
      );
      assert.equal(Number(row.rows[0]?.balance_after_paise), 2395075);
      assert.equal(row.rows[0]?.approval_method, 'PIN');
    });

    it('BIOMETRIC approval with a valid Keystore signature', async () => {
      const { session, privateKey } = await biometricLogin();
      const c = await challenge(session.accessToken);
      const res: TypedRes<TransferResult> = await transfer(
        session.accessToken,
        {
          ...BODY,
          challengeId: c.body.body.challengeId,
          approval: {
            method: 'BIOMETRIC',
            signature: signWith(privateKey, c.body.body.signingPayload),
          },
        },
      );
      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.equal(res.body.body.approvalMethod, 'BIOMETRIC');
    });

    it('can spend the entire balance down to exactly zero', async () => {
      const s = await login();
      const res = await payWithPin(s.accessToken, {
        ...BODY,
        amount: 25450.75,
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.body.availableBalance, 0);
      assert.equal(await balancePaise(), 0);
    });

    it('handles float-unfriendly amounts exactly (0.1 + 0.2)', async () => {
      const s = await login();
      const res = await payWithPin(s.accessToken, { ...BODY, amount: 0.3 });
      assert.equal(res.status, 200);
      assert.equal(await balancePaise(), DEMO_WALLET.balancePaise - 30);
      assert.equal(rupeesToPaise(0.1 + 0.2), 30);
    });

    it('allows the smallest amount (₹0.01)', async () => {
      const s = await login();
      const res = await payWithPin(s.accessToken, { ...BODY, amount: 0.01 });
      assert.equal(res.status, 200);
      assert.equal(res.body.body.availableBalance, 25450.74);
    });

    it('works after the access token is refreshed (same login)', async () => {
      const s = await login();
      const c = await challenge(s.accessToken);
      const r: TypedRes<{ accessToken: string }> = await agent
        .post(Paths.Auth.Refresh.FULL_PATH)
        .send({ refreshToken: s.refreshToken });
      const res = await transfer(r.body.body.accessToken, {
        ...BODY,
        challengeId: c.body.body.challengeId,
        approval: { method: 'PIN', pin: PIN },
      });
      assert.equal(res.status, 200, JSON.stringify(res.body));
    });
  });

  describe('idempotency', () => {
    it('same key + same body: returns the original result, no second debit', async () => {
      const s = await login();
      const key = randomUUID();
      const first = await payWithPin(s.accessToken, BODY, key);
      // Retry (e.g. response lost) with the same key and body.
      const again: TypedRes<TransferResult> = await transfer(
        s.accessToken,
        {
          ...BODY,
          challengeId: randomUUID(),
          approval: { method: 'PIN', pin: PIN },
        },
        key,
      );
      assert.equal(again.status, 200);
      assert.equal(again.headers['idempotent-replayed'], 'true');
      assert.deepEqual(again.body, first.body);
      assert.equal(await balancePaise(), 2395075);
      assert.equal(await transferCount(), 1);
    });

    it('same key + different body: 409 IDEMPOTENCY_KEY_REUSED', async () => {
      const s = await login();
      const key = randomUUID();
      await payWithPin(s.accessToken, BODY, key);
      const res: TypedErrRes = await payWithPin(
        s.accessToken,
        { ...BODY, amount: 1 },
        key,
      );
      assert.equal(res.status, 409);
      assert.equal(res.body.body.errorCode, 'IDEMPOTENCY_KEY_REUSED');
      assert.equal(await transferCount(), 1);
    });

    it('5 parallel submissions with one key debit once', async () => {
      const s = await login();
      const c = await challenge(s.accessToken);
      const key = randomUUID();
      const body = {
        ...BODY,
        challengeId: c.body.body.challengeId,
        approval: { method: 'PIN', pin: PIN },
      };
      const results = await Promise.all(
        Array.from({ length: 5 }, () => transfer(s.accessToken, body, key)),
      );
      const ok = results.filter((r) => r.status === 200);
      assert.ok(ok.length >= 1);
      assert.ok(
        results.every((r) => r.status === 200 || r.status === 409),
        results.map((r) => r.status).join(','),
      );
      assert.equal(await transferCount(), 1);
      assert.equal(await balancePaise(), 2395075);
    });

    it('400 when the Idempotency-Key header is missing or malformed', async () => {
      const s = await login();
      const c = await challenge(s.accessToken);
      const body = {
        ...BODY,
        challengeId: c.body.body.challengeId,
        approval: { method: 'PIN', pin: PIN },
      };
      for (const key of [null, 'short', 'has spaces in it', 'x'.repeat(65)]) {
        const res: TypedErrRes = await transfer(s.accessToken, body, key);
        assert.equal(res.status, 400, String(key));
        assert.equal(res.body.body.details?.[0]?.field, 'Idempotency-Key');
      }
      assert.equal(await transferCount(), 0);
    });
  });

  describe('challenge checks', () => {
    it('409 CHALLENGE_USED when reusing a challenge with a new key', async () => {
      const s = await login();
      const c = await challenge(s.accessToken);
      const body = {
        ...BODY,
        challengeId: c.body.body.challengeId,
        approval: { method: 'PIN', pin: PIN },
      };
      assert.equal((await transfer(s.accessToken, body)).status, 200);
      const res: TypedErrRes = await transfer(s.accessToken, body);
      assert.equal(res.status, 409);
      assert.equal(res.body.body.errorCode, 'CHALLENGE_USED');
      assert.equal(await transferCount(), 1);
    });

    it('400 CHALLENGE_MISMATCH when details change after approval', async () => {
      const s = await login();
      const c = await challenge(s.accessToken);
      for (const change of [
        { amount: 15000 },
        { mobileNumber: '9123456780' },
        { beneficiaryName: 'Someone Else' },
        { remarks: 'changed' },
      ]) {
        const res: TypedErrRes = await transfer(s.accessToken, {
          ...BODY,
          ...change,
          challengeId: c.body.body.challengeId,
          approval: { method: 'PIN', pin: PIN },
        });
        assert.equal(res.status, 400, JSON.stringify(change));
        assert.equal(res.body.body.errorCode, 'CHALLENGE_MISMATCH');
      }
      assert.equal(await balancePaise(), DEMO_WALLET.balancePaise);
    });

    it('400 CHALLENGE_EXPIRED after the time limit', async () => {
      const s = await login();
      const c = await challenge(s.accessToken);
      await db.execute(
        "UPDATE transfer_challenges SET expires_at = '2000-01-01T00:00:00.000Z'",
      );
      const res: TypedErrRes = await transfer(s.accessToken, {
        ...BODY,
        challengeId: c.body.body.challengeId,
        approval: { method: 'PIN', pin: PIN },
      });
      assert.equal(res.status, 400);
      assert.equal(res.body.body.errorCode, 'CHALLENGE_EXPIRED');
    });

    it("400 INVALID_CHALLENGE for unknown or another login's challenge", async () => {
      const a = await login();
      const b = await login();
      const c = await challenge(a.accessToken);
      for (const [token, id] of [
        [a.accessToken, randomUUID()],
        [b.accessToken, c.body.body.challengeId],
      ] as const) {
        const res: TypedErrRes = await transfer(token, {
          ...BODY,
          challengeId: id,
          approval: { method: 'PIN', pin: PIN },
        });
        assert.equal(res.status, 400);
        assert.equal(res.body.body.errorCode, 'INVALID_CHALLENGE');
      }
    });
  });

  describe('approval checks', () => {
    it('403 INVALID_PIN: no debit, challenge still usable with the right PIN', async () => {
      const s = await login();
      const c = await challenge(s.accessToken);
      const base = { ...BODY, challengeId: c.body.body.challengeId };
      const wrong: TypedErrRes = await transfer(s.accessToken, {
        ...base,
        approval: { method: 'PIN', pin: '9999' },
      });
      assert.equal(wrong.status, 403);
      assert.equal(wrong.body.body.errorCode, 'INVALID_PIN');
      assert.equal(await balancePaise(), DEMO_WALLET.balancePaise);

      const right = await transfer(s.accessToken, {
        ...base,
        approval: { method: 'PIN', pin: PIN },
      });
      assert.equal(right.status, 200);
    });

    it('3 wrong PINs lock transfers (423), including biometric approval', async () => {
      const { session, privateKey } = await biometricLogin();
      const c = await challenge(session.accessToken);
      const base = { ...BODY, challengeId: c.body.body.challengeId };
      for (const pin of ['9999', '9998']) {
        await transfer(session.accessToken, {
          ...base,
          approval: { method: 'PIN', pin },
        });
      }
      const locked: TypedErrRes = await transfer(session.accessToken, {
        ...base,
        approval: { method: 'PIN', pin: '9997' },
      });
      assert.equal(locked.status, 423);

      const bio: TypedErrRes = await transfer(session.accessToken, {
        ...base,
        approval: {
          method: 'BIOMETRIC',
          signature: signWith(privateKey, c.body.body.signingPayload),
        },
      });
      assert.equal(bio.status, 423);
      assert.equal(await balancePaise(), DEMO_WALLET.balancePaise);
    });

    it('403 BIOMETRIC_NOT_ENROLLED on a device without a key', async () => {
      const s = await login({ deviceId: randomUUID() });
      const c = await challenge(s.accessToken);
      const res: TypedErrRes = await transfer(s.accessToken, {
        ...BODY,
        challengeId: c.body.body.challengeId,
        approval: { method: 'BIOMETRIC', signature: 'AAAA' },
      });
      assert.equal(res.status, 403);
      assert.equal(res.body.body.errorCode, 'BIOMETRIC_NOT_ENROLLED');
    });

    it('403 INVALID_SIGNATURE for wrong key, wrong challenge, or garbage', async () => {
      const { session, privateKey } = await biometricLogin();
      const c1 = await challenge(session.accessToken);
      const c2 = await challenge(session.accessToken);
      const otherKey = generateKeyPairSync('ec', {
        namedCurve: 'P-256',
      }).privateKey;
      for (const signature of [
        signWith(otherKey, c1.body.body.signingPayload),
        signWith(privateKey, c2.body.body.signingPayload),
        'AAAA',
      ]) {
        const res: TypedErrRes = await transfer(session.accessToken, {
          ...BODY,
          challengeId: c1.body.body.challengeId,
          approval: { method: 'BIOMETRIC', signature },
        });
        assert.equal(res.status, 403);
        assert.equal(res.body.body.errorCode, 'INVALID_SIGNATURE');
      }
      assert.equal(await balancePaise(), DEMO_WALLET.balancePaise);
    });

    it('400 for an unknown or malformed approval', async () => {
      const s = await login();
      const c = await challenge(s.accessToken);
      for (const approval of [
        { method: 'OTP', code: '123456' },
        { method: 'PIN' },
        { method: 'PIN', pin: '12' },
        { method: 'BIOMETRIC', signature: 'not base64!' },
        undefined,
      ]) {
        const res = await transfer(s.accessToken, {
          ...BODY,
          challengeId: c.body.body.challengeId,
          approval,
        });
        assert.equal(res.status, 400, JSON.stringify(approval));
      }
    });
  });

  describe('balance and limits', () => {
    it('409 INSUFFICIENT_BALANCE if money left between challenge and transfer', async () => {
      const s = await login();
      const c = await challenge(s.accessToken);
      await setBalance(100); // ₹1 left
      const res: TypedErrRes = await transfer(s.accessToken, {
        ...BODY,
        challengeId: c.body.body.challengeId,
        approval: { method: 'PIN', pin: PIN },
      });
      assert.equal(res.status, 409);
      assert.equal(res.body.body.errorCode, 'INSUFFICIENT_BALANCE');
      assert.equal(await balancePaise(), 100);
      assert.equal(await transferCount(), 0);
    });

    it('parallel transfers can never overdraw the wallet', async () => {
      await setBalance(500000); // ₹5,000
      const s = await login();
      const body = { ...BODY, amount: 2000 };
      const challenges = await Promise.all(
        Array.from({ length: 5 }, () => challenge(s.accessToken, body)),
      );
      const results = await Promise.all(
        challenges.map((c) =>
          transfer(s.accessToken, {
            ...body,
            challengeId: c.body.body.challengeId,
            approval: { method: 'PIN', pin: PIN },
          }),
        ),
      );
      const ok = results.filter((r) => r.status === 200).length;
      const rejected = results.filter((r) => r.status === 409).length;
      assert.equal(ok, 2, results.map((r) => r.status).join(','));
      assert.equal(rejected, 3);
      assert.equal(await balancePaise(), 100000);
      assert.equal(await transferCount(), 2);
    });

    it('403 DAILY_LIMIT_EXCEEDED across transfers in one IST day', async () => {
      await setBalance(Env.DAILY_TRANSFER_LIMIT * 100 * 2);
      // Start the day clean: seeded history includes a debit from ~2h ago,
      // which (correctly) counts toward today's limit.
      await db.execute("DELETE FROM transactions WHERE type = 'DEBIT'");
      const s = await login();
      const big = { ...BODY, amount: Env.MAX_TRANSFER_AMOUNT };
      const transfersAllowed = Math.floor(
        Env.DAILY_TRANSFER_LIMIT / Env.MAX_TRANSFER_AMOUNT,
      );
      for (let i = 0; i < transfersAllowed; i++) {
        assert.equal((await payWithPin(s.accessToken, big)).status, 200);
      }
      const res: TypedErrRes = await challenge(s.accessToken, {
        ...BODY,
        amount: 1,
      });
      assert.equal(res.status, 403);
      assert.equal(res.body.body.errorCode, 'DAILY_LIMIT_EXCEEDED');
    });

    it('403 WALLET_FROZEN if frozen after the challenge', async () => {
      const s = await login();
      const c = await challenge(s.accessToken);
      await db.execute("UPDATE wallets SET status = 'FROZEN'");
      const res: TypedErrRes = await transfer(s.accessToken, {
        ...BODY,
        challengeId: c.body.body.challengeId,
        approval: { method: 'PIN', pin: PIN },
      });
      assert.equal(res.status, 403);
      assert.equal(res.body.body.errorCode, 'WALLET_FROZEN');
    });
  });

  describe('authorization', () => {
    it('401 without a token', async () => {
      assert.equal((await agent.post(CHALLENGE).send(BODY)).status, 401);
      assert.equal((await agent.post(TRANSFER).send(BODY)).status, 401);
    });

    it('401 after logout, even with a valid challenge', async () => {
      const s = await login();
      const c = await challenge(s.accessToken);
      await agent.post(Paths.Auth.Logout.FULL_PATH).set(bearer(s.accessToken));
      const res: TypedErrRes = await transfer(s.accessToken, {
        ...BODY,
        challengeId: c.body.body.challengeId,
        approval: { method: 'PIN', pin: PIN },
      });
      assert.equal(res.status, 401);
      assert.equal(res.body.body.errorCode, 'SESSION_REVOKED');
      assert.equal(await balancePaise(), DEMO_WALLET.balancePaise);
    });
  });
});
