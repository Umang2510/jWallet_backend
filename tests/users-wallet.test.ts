import argon2 from 'argon2';
import { SignJWT } from 'jose';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { before, describe, it } from 'node:test';

import { Env } from '#src/common/constants/env.constants.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import db from '#src/db/client.ts';
import { DEMO_USER } from '#src/db/seed.ts';
import type { LoginResult } from '#src/services/AuthService.ts';
import { initialsOf, type ProfileResult } from '#src/services/UserService.ts';
import type { BalanceResult } from '#src/services/WalletService.ts';

import { agent, dbReady } from './support/agent.ts';
import type { TypedErrRes, TypedRes } from './support/utils.ts';

// ========================================================================= //
//                                  HELPERS                                  //
// ========================================================================= //

const PROFILE = Paths.Users.Profile.FULL_PATH;
const BALANCE = Paths.Wallet.Balance.FULL_PATH;
const LOGIN = Paths.Auth.Login.FULL_PATH;

const SECOND = {
  email: 'second@jwallet.co',
  password: 'Second@123',
  name: 'Second Person',
};
const NO_WALLET = {
  email: 'nowallet@jwallet.co',
  password: 'NoWallet@123',
  name: 'No Wallet',
};

async function insertUser(
  u: typeof SECOND,
  publicId: string,
  wallet?: { publicId: string; paise: number; last4: string },
) {
  const now = new Date().toISOString();
  const id = randomUUID();
  await db.execute({
    sql: `INSERT INTO users (id, public_id, name, email, password_hash, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    args: [
      id,
      publicId,
      u.name,
      u.email,
      await argon2.hash(u.password),
      now,
      now,
    ],
  });
  if (wallet) {
    await db.execute({
      sql: `INSERT INTO wallets (id, public_id, user_id, balance_paise, account_last4, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
      args: [
        randomUUID(),
        wallet.publicId,
        id,
        wallet.paise,
        wallet.last4,
        now,
        now,
      ],
    });
  }
  return id;
}

async function login(email: string, password: string): Promise<LoginResult> {
  const res: TypedRes<LoginResult> = await agent
    .post(LOGIN)
    .send({ email, password });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body.body;
}

const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

/** Re-sign the caller's own token with different scopes (same live session). */
async function withScopes(accessToken: string, scope: string) {
  const claims = JSON.parse(
    Buffer.from(accessToken.split('.')[1], 'base64url').toString(),
  ) as Record<string, unknown>;
  return new SignJWT({ ...claims, scope })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .sign(new TextEncoder().encode(Env.JWT_SECRET));
}

// ========================================================================= //
//                                   TESTS                                   //
// ========================================================================= //

let demo: LoginResult;
let second: LoginResult;

before(async () => {
  await dbReady;
  await insertUser(SECOND, 'USR20001', {
    publicId: 'WALLET20001',
    paise: 100001, // ₹1,000.01
    last4: '0042',
  });
  await insertUser(NO_WALLET, 'USR20002');
  demo = await login(DEMO_USER.email, DEMO_USER.password);
  second = await login(SECOND.email, SECOND.password);
});

describe('GET /api/v1/users/profile', () => {
  it('returns the caller profile in the meta/body envelope', async () => {
    const res: TypedRes<ProfileResult> = await agent
      .get(PROFILE)
      .set(bearer(demo.accessToken));
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.meta, {
      statusCode: 200,
      message: 'Profile fetched successfully',
    });
    const b = res.body.body;
    assert.equal(b.id, 'USR10001');
    assert.equal(b.name, 'Demo User');
    assert.equal(b.email, 'demo@jstack.co');
    assert.equal(b.initials, 'DU');
    assert.ok(!Number.isNaN(Date.parse(b.memberSince)));
    assert.deepEqual(b.security, { pinSet: false, biometricEnrolled: false });
    assert.equal(res.headers['cache-control'], 'no-store');
  });

  it('never exposes internal or secret fields', async () => {
    const res = await agent.get(PROFILE).set(bearer(demo.accessToken));
    const raw = JSON.stringify(res.body);
    for (const leak of [
      'password',
      'hash',
      'failed_login',
      'locked',
      'argon2',
    ]) {
      assert.ok(!raw.toLowerCase().includes(leak), `leaked "${leak}"`);
    }
  });

  it('each user only sees their own profile', async () => {
    const res: TypedRes<ProfileResult> = await agent
      .get(PROFILE)
      .set(bearer(second.accessToken));
    assert.equal(res.body.body.id, 'USR20001');
    assert.equal(res.body.body.email, SECOND.email);
  });

  it('ignores attempts to pick another user via query string', async () => {
    const res: TypedRes<ProfileResult> = await agent
      .get(`${PROFILE}?userId=USR10001&id=USR10001`)
      .set(bearer(second.accessToken));
    assert.equal(res.body.body.id, 'USR20001');
  });
});

describe('GET /api/v1/wallet/balance', () => {
  it('returns the authoritative balance in the spec format', async () => {
    const res: TypedRes<BalanceResult> = await agent
      .get(BALANCE)
      .set(bearer(demo.accessToken));
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.meta, {
      statusCode: 200,
      message: 'Wallet balance fetched successfully',
    });
    const b = res.body.body;
    assert.equal(b.walletId, 'WALLET10001');
    assert.equal(b.currency, 'INR');
    assert.equal(b.availableBalance, 25450.75);
    assert.equal(b.maskedAccountNumber, 'XXXX XXXX 4589');
    assert.equal(b.status, 'ACTIVE');
  });

  it('returns exact paise amounts without float drift', async () => {
    const res: TypedRes<BalanceResult> = await agent
      .get(BALANCE)
      .set(bearer(second.accessToken));
    assert.equal(res.body.body.availableBalance, 1000.01);
    assert.equal(res.body.body.walletId, 'WALLET20001');
    assert.equal(res.body.body.maskedAccountNumber, 'XXXX XXXX 0042');
  });

  it('reads fresh from the database (no stale cache)', async () => {
    await db.execute(
      "UPDATE wallets SET balance_paise = 5 WHERE public_id = 'WALLET20001'",
    );
    const res: TypedRes<BalanceResult> = await agent
      .get(BALANCE)
      .set(bearer(second.accessToken));
    assert.equal(res.body.body.availableBalance, 0.05);
    await db.execute(
      "UPDATE wallets SET balance_paise = 100001 WHERE public_id = 'WALLET20001'",
    );
  });

  it('handles a zero balance', async () => {
    await db.execute(
      "UPDATE wallets SET balance_paise = 0 WHERE public_id = 'WALLET20001'",
    );
    const res: TypedRes<BalanceResult> = await agent
      .get(BALANCE)
      .set(bearer(second.accessToken));
    assert.equal(res.body.body.availableBalance, 0);
    await db.execute(
      "UPDATE wallets SET balance_paise = 100001 WHERE public_id = 'WALLET20001'",
    );
  });

  it('reports a frozen wallet status', async () => {
    await db.execute(
      "UPDATE wallets SET status = 'FROZEN' WHERE public_id = 'WALLET20001'",
    );
    const res: TypedRes<BalanceResult> = await agent
      .get(BALANCE)
      .set(bearer(second.accessToken));
    assert.equal(res.body.body.status, 'FROZEN');
    await db.execute(
      "UPDATE wallets SET status = 'ACTIVE' WHERE public_id = 'WALLET20001'",
    );
  });

  it('returns 404 when the user has no wallet', async () => {
    const s = await login(NO_WALLET.email, NO_WALLET.password);
    const res: TypedErrRes = await agent
      .get(BALANCE)
      .set(bearer(s.accessToken));
    assert.equal(res.status, 404);
    assert.deepEqual(res.body, {
      meta: { statusCode: 404, message: 'Wallet not found' },
      body: { errorCode: 'WALLET_NOT_FOUND' },
    });
  });

  it('is never cached', async () => {
    const res = await agent.get(BALANCE).set(bearer(demo.accessToken));
    assert.equal(res.headers['cache-control'], 'no-store');
  });
});

describe('authorization on protected routes', () => {
  for (const path of [PROFILE, BALANCE]) {
    describe(path, () => {
      it('401 AUTH_REQUIRED without a token', async () => {
        const res: TypedErrRes = await agent.get(path);
        assert.equal(res.status, 401);
        assert.equal(res.body.body.errorCode, 'AUTH_REQUIRED');
      });

      it('401 AUTH_REQUIRED for a non-Bearer scheme', async () => {
        const res: TypedErrRes = await agent
          .get(path)
          .set('Authorization', `Basic ${demo.accessToken}`);
        assert.equal(res.status, 401);
        assert.equal(res.body.body.errorCode, 'AUTH_REQUIRED');
      });

      it('401 INVALID_TOKEN for a token signed with another secret', async () => {
        const forged = await new SignJWT({ sid: 'x', scope: 'wallet:read' })
          .setProtectedHeader({ alg: 'HS256' })
          .setSubject('x')
          .setIssuer(Env.JWT_ISSUER)
          .setAudience(Env.JWT_AUDIENCE)
          .setIssuedAt()
          .setJti('j')
          .setExpirationTime('5m')
          .sign(new TextEncoder().encode('another-secret-another-secret-xx'));
        const res: TypedErrRes = await agent.get(path).set(bearer(forged));
        assert.equal(res.status, 401);
        assert.equal(res.body.body.errorCode, 'INVALID_TOKEN');
      });

      it('401 INVALID_TOKEN for an unsigned (alg: none) token', async () => {
        const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString(
          'base64url',
        );
        const [, payload] = demo.accessToken.split('.');
        const res: TypedErrRes = await agent
          .get(path)
          .set(bearer(`${header}.${payload}.x`));
        assert.equal(res.status, 401);
        assert.equal(res.body.body.errorCode, 'INVALID_TOKEN');
      });

      it('401 INVALID_TOKEN when the token claims another user', async () => {
        const claims = JSON.parse(
          Buffer.from(second.accessToken.split('.')[1], 'base64url').toString(),
        ) as Record<string, unknown>;
        const demoClaims = JSON.parse(
          Buffer.from(demo.accessToken.split('.')[1], 'base64url').toString(),
        ) as Record<string, unknown>;
        // Valid signature, but session belongs to "second" while sub says demo.
        const mixed = await new SignJWT({
          ...claims,
          sub: String(demoClaims.sub),
        })
          .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
          .sign(new TextEncoder().encode(Env.JWT_SECRET));
        const res: TypedErrRes = await agent.get(path).set(bearer(mixed));
        assert.equal(res.status, 401);
        assert.equal(res.body.body.errorCode, 'INVALID_TOKEN');
      });

      it('403 INSUFFICIENT_SCOPE without the required permission', async () => {
        const limited = await withScopes(demo.accessToken, 'txn:read');
        const res: TypedErrRes = await agent.get(path).set(bearer(limited));
        assert.equal(res.status, 403);
        assert.equal(res.body.body.errorCode, 'INSUFFICIENT_SCOPE');
      });
    });
  }

  it('403 ACCOUNT_INACTIVE when the account is frozen mid-session', async () => {
    const s = await login(SECOND.email, SECOND.password);
    await db.execute({
      sql: "UPDATE users SET status = 'FROZEN' WHERE email = ?",
      args: [SECOND.email],
    });
    const res: TypedErrRes = await agent
      .get(BALANCE)
      .set(bearer(s.accessToken));
    assert.equal(res.status, 403);
    assert.equal(res.body.body.errorCode, 'ACCOUNT_INACTIVE');
    await db.execute({
      sql: "UPDATE users SET status = 'ACTIVE' WHERE email = ?",
      args: [SECOND.email],
    });
  });

  it('401 SESSION_REVOKED after logout', async () => {
    const s = await login(SECOND.email, SECOND.password);
    await agent.post(Paths.Auth.Logout.FULL_PATH).set(bearer(s.accessToken));
    const res: TypedErrRes = await agent
      .get(PROFILE)
      .set(bearer(s.accessToken));
    assert.equal(res.status, 401);
    assert.equal(res.body.body.errorCode, 'SESSION_REVOKED');
  });

  it('protected routers hide unknown sub-routes behind auth', async () => {
    const res: TypedErrRes = await agent.get('/api/v1/wallet/secret');
    assert.equal(res.status, 401);
  });
});

describe('initialsOf', () => {
  it('handles one, two and many names and extra spaces', () => {
    assert.equal(initialsOf('Demo User'), 'DU');
    assert.equal(initialsOf('harshil'), 'H');
    assert.equal(initialsOf('  umang   kumar  chovatiya '), 'UC');
  });
});
