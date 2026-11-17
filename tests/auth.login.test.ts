import { jwtVerify } from 'jose';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { beforeEach, describe, it } from 'node:test';

import { Env } from '#src/common/constants/env.constants.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import { sha256Hex } from '#src/common/utils/crypto.utils.ts';
import db, { asText } from '#src/db/client.ts';
import { DEMO_USER } from '#src/db/seed.ts';
import type { LoginResult } from '#src/services/AuthService.ts';

import { agent } from './support/agent.ts';
import type { TypedErrRes, TypedRes } from './support/utils.ts';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

const LOGIN = Paths.Auth.Login.FULL_PATH;
const VALID = { email: DEMO_USER.email, password: DEMO_USER.password };

function p256PublicKeyBase64(): string {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
}

async function resetLoginState() {
  await db.execute(
    'UPDATE users SET failed_login_count = 0, login_locked_until = NULL',
  );
}

// ========================================================================= //
//                                   TESTS                                   //
// ========================================================================= //

describe('POST /api/v1/auth/login', () => {
  beforeEach(resetLoginState);

  describe('success', () => {
    it('returns 200 with tokens, user and security flags in the meta/body envelope', async () => {
      const res: TypedRes<LoginResult> = await agent.post(LOGIN).send(VALID);

      assert.equal(res.status, 200);
      assert.deepEqual(res.body.meta, {
        statusCode: 200,
        message: 'Login successful',
      });
      const b = res.body.body;
      assert.equal(b.tokenType, 'Bearer');
      assert.equal(b.expiresIn, Env.ACCESS_TOKEN_TTL_SEC);
      assert.equal(b.refreshExpiresIn, Env.REFRESH_TOKEN_TTL_SEC);
      assert.match(b.refreshToken, /^rt_[A-Za-z0-9_-]{43}$/);
      assert.deepEqual(b.user, {
        id: 'USR10001',
        name: 'Demo User',
        email: 'demo@jstack.co',
      });
      assert.deepEqual(b.security, { pinSet: false, biometricEnrolled: false });
      assert.equal(res.headers['cache-control'], 'no-store');
    });

    it('issues a signed JWT with session and scope claims', async () => {
      const res: TypedRes<LoginResult> = await agent.post(LOGIN).send(VALID);
      const { payload, protectedHeader } = await jwtVerify(
        res.body.body.accessToken,
        new TextEncoder().encode(Env.JWT_SECRET),
        { issuer: Env.JWT_ISSUER, audience: Env.JWT_AUDIENCE },
      );
      assert.equal(protectedHeader.alg, 'HS256');
      assert.ok(payload.sub);
      assert.ok(payload.sid);
      assert.ok(payload.jti);
      assert.equal(payload.exp! - payload.iat!, Env.ACCESS_TOKEN_TTL_SEC);
      assert.match(String(payload.scope), /txn:transfer/);
    });

    it('stores only a hash of the refresh token', async () => {
      const res: TypedRes<LoginResult> = await agent.post(LOGIN).send(VALID);
      const { refreshToken } = res.body.body;
      const plain = await db.execute({
        sql: 'SELECT 1 FROM sessions WHERE refresh_token_hash = ?',
        args: [refreshToken],
      });
      const hashed = await db.execute({
        sql: 'SELECT 1 FROM sessions WHERE refresh_token_hash = ?',
        args: [sha256Hex(refreshToken)],
      });
      assert.equal(plain.rows.length, 0);
      assert.equal(hashed.rows.length, 1);
    });

    it('accepts email with different case and surrounding spaces', async () => {
      const res = await agent
        .post(LOGIN)
        .send({ email: '  DEMO@JStack.co ', password: DEMO_USER.password });
      assert.equal(res.status, 200);
    });

    it('binds the session to the device when deviceId + key are sent', async () => {
      const deviceId = randomUUID();
      const devicePublicKey = p256PublicKeyBase64();
      const res: TypedRes<LoginResult> = await agent
        .post(LOGIN)
        .send({ ...VALID, deviceId, devicePublicKey });

      assert.equal(res.status, 200);
      const { payload } = await jwtVerify(
        res.body.body.accessToken,
        new TextEncoder().encode(Env.JWT_SECRET),
      );
      assert.equal(payload.did, deviceId);

      const device = await db.execute({
        sql: 'SELECT device_public_key FROM devices WHERE device_id = ?',
        args: [deviceId],
      });
      assert.equal(device.rows[0]?.device_public_key, devicePublicKey);
    });

    it('never stores the password in plain text', async () => {
      const row = await db.execute({
        sql: 'SELECT password_hash FROM users WHERE email = ?',
        args: [DEMO_USER.email],
      });
      const hash = asText(row.rows[0]?.password_hash);
      assert.notEqual(hash, DEMO_USER.password);
      assert.match(hash, /^\$argon2id\$/);
    });
  });

  describe('invalid credentials', () => {
    it('returns 401 for a wrong password', async () => {
      const res: TypedErrRes = await agent
        .post(LOGIN)
        .send({ ...VALID, password: 'Wrong@123' });
      assert.equal(res.status, 401);
      assert.deepEqual(res.body, {
        meta: { statusCode: 401, message: 'Invalid email or password' },
        body: { errorCode: 'INVALID_CREDENTIALS' },
      });
    });

    it('returns the identical 401 for an unknown email (no enumeration)', async () => {
      const res: TypedErrRes = await agent
        .post(LOGIN)
        .send({ email: 'nobody@jstack.co', password: 'Whatever@1' });
      assert.equal(res.status, 401);
      assert.deepEqual(res.body, {
        meta: { statusCode: 401, message: 'Invalid email or password' },
        body: { errorCode: 'INVALID_CREDENTIALS' },
      });
    });

    it('locks the account with 429 after too many failures, even for the right password', async () => {
      const wrong = { ...VALID, password: 'Wrong@123' };
      for (let i = 1; i < Env.MAX_FAILED_LOGINS; i++) {
        const r = await agent.post(LOGIN).send(wrong);
        assert.equal(r.status, 401);
      }
      const locking: TypedErrRes = await agent.post(LOGIN).send(wrong);
      assert.equal(locking.status, 429);
      assert.equal(locking.body.body.errorCode, 'ACCOUNT_TEMPORARILY_LOCKED');

      const correct: TypedErrRes = await agent.post(LOGIN).send(VALID);
      assert.equal(correct.status, 429);
      assert.equal(correct.body.meta.statusCode, 429);
    });

    it('resets the failure counter after a successful login', async () => {
      const wrong = { ...VALID, password: 'Wrong@123' };
      for (let i = 1; i < Env.MAX_FAILED_LOGINS; i++) {
        await agent.post(LOGIN).send(wrong);
      }
      assert.equal((await agent.post(LOGIN).send(VALID)).status, 200);
      assert.equal((await agent.post(LOGIN).send(wrong)).status, 401);
    });
  });

  describe('validation (400)', () => {
    const cases: [string, unknown, string][] = [
      ['missing body fields', {}, 'email'],
      ['invalid email', { email: 'not-an-email', password: 'x' }, 'email'],
      ['empty password', { email: DEMO_USER.email, password: '' }, 'password'],
      ['unknown field', { ...VALID, role: 'admin' }, 'body'],
      ['non-UUID deviceId', { ...VALID, deviceId: '123' }, 'deviceId'],
      [
        'invalid device key',
        { ...VALID, deviceId: randomUUID(), devicePublicKey: 'abc' },
        'devicePublicKey',
      ],
      [
        'device key without deviceId',
        { ...VALID, devicePublicKey: p256PublicKeyBase64() },
        'deviceId',
      ],
    ];

    for (const [name, payload, field] of cases) {
      it(`rejects ${name}`, async () => {
        const res: TypedErrRes = await agent
          .post(LOGIN)
          .send(payload as object);
        assert.equal(res.status, 400);
        assert.equal(res.body.meta.statusCode, 400);
        assert.equal(res.body.body.errorCode, 'VALIDATION_ERROR');
        assert.ok(
          res.body.body.details?.some((d) => d.field === field),
          `expected an error for "${field}", got ${JSON.stringify(res.body.body.details)}`,
        );
      });
    }

    it('rejects malformed JSON', async () => {
      const res: TypedErrRes = await agent
        .post(LOGIN)
        .set('Content-Type', 'application/json')
        .send('{"email": ');
      assert.equal(res.status, 400);
      assert.equal(res.body.body.errorCode, 'INVALID_JSON');
    });
  });

  it('returns 404 in the same envelope for unknown routes', async () => {
    const res: TypedErrRes = await agent.get('/api/v1/nope');
    assert.equal(res.status, 404);
    assert.deepEqual(res.body, {
      meta: { statusCode: 404, message: 'Route not found' },
      body: { errorCode: 'ROUTE_NOT_FOUND' },
    });
  });
});
