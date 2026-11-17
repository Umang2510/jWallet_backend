import { SignJWT } from 'jose';
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
import db from '#src/db/client.ts';
import { DEMO_USER } from '#src/db/seed.ts';
import { refreshProofMessage } from '#src/entities/Auth/index.ts';
import type { LoginResult, RefreshResult } from '#src/services/AuthService.ts';

import { agent } from './support/agent.ts';
import type { TypedErrRes, TypedRes } from './support/utils.ts';

// ========================================================================= //
//                                  HELPERS                                  //
// ========================================================================= //

const LOGIN = Paths.Auth.Login.FULL_PATH;
const REFRESH = Paths.Auth.Refresh.FULL_PATH;
const LOGOUT = Paths.Auth.Logout.FULL_PATH;
const CREDS = { email: DEMO_USER.email, password: DEMO_USER.password };

async function login(extra: object = {}): Promise<LoginResult> {
  const res: TypedRes<LoginResult> = await agent
    .post(LOGIN)
    .send({ ...CREDS, ...extra });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body.body;
}

function deviceKeys() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  return {
    privateKey,
    publicKeyB64: publicKey
      .export({ format: 'der', type: 'spki' })
      .toString('base64'),
  };
}

/** Sign the refresh proof exactly like the app's Keystore key will. */
function proof(privateKey: KeyObject, refreshToken: string, timestamp: number) {
  return sign(
    'sha256',
    Buffer.from(refreshProofMessage(refreshToken, timestamp)),
    { key: privateKey, dsaEncoding: 'der' },
  ).toString('base64');
}

const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

// ========================================================================= //
//                                   TESTS                                   //
// ========================================================================= //

describe('POST /api/v1/auth/refresh', () => {
  beforeEach(async () => {
    await db.execute(
      'UPDATE users SET failed_login_count = 0, login_locked_until = NULL',
    );
  });

  it('rotates: returns a new token pair in the meta/body envelope', async () => {
    const first = await login();
    const res: TypedRes<RefreshResult> = await agent
      .post(REFRESH)
      .send({ refreshToken: first.refreshToken });

    assert.equal(res.status, 200);
    assert.deepEqual(res.body.meta, {
      statusCode: 200,
      message: 'Token refreshed',
    });
    const b = res.body.body;
    assert.equal(b.tokenType, 'Bearer');
    assert.equal(b.expiresIn, Env.ACCESS_TOKEN_TTL_SEC);
    assert.match(b.refreshToken, /^rt_/);
    assert.notEqual(b.refreshToken, first.refreshToken);
    assert.notEqual(b.accessToken, first.accessToken);

    // The new access token works on a protected route.
    const out = await agent.post(LOGOUT).set(bearer(b.accessToken));
    assert.equal(out.status, 200);
  });

  it('detects reuse of an old refresh token and revokes the whole login', async () => {
    const first = await login();
    const second: TypedRes<RefreshResult> = await agent
      .post(REFRESH)
      .send({ refreshToken: first.refreshToken });
    assert.equal(second.status, 200);

    // Attacker (or replay) uses the already-rotated token.
    const reused: TypedErrRes = await agent
      .post(REFRESH)
      .send({ refreshToken: first.refreshToken });
    assert.equal(reused.status, 401);
    assert.equal(reused.body.body.errorCode, 'REFRESH_TOKEN_REUSED');

    // The legitimate newer token is now dead too...
    const newer: TypedErrRes = await agent
      .post(REFRESH)
      .send({ refreshToken: second.body.body.refreshToken });
    assert.equal(newer.status, 401);
    assert.equal(newer.body.body.errorCode, 'SESSION_REVOKED');

    // ...and so is its access token.
    const access: TypedErrRes = await agent
      .post(LOGOUT)
      .set(bearer(second.body.body.accessToken));
    assert.equal(access.status, 401);
    assert.equal(access.body.body.errorCode, 'SESSION_REVOKED');
  });

  it('rejects an unknown refresh token', async () => {
    const res: TypedErrRes = await agent
      .post(REFRESH)
      .send({ refreshToken: 'rt_' + 'A'.repeat(43) });
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, {
      meta: { statusCode: 401, message: 'Invalid refresh token' },
      body: { errorCode: 'INVALID_REFRESH_TOKEN' },
    });
  });

  it('rejects an expired refresh token', async () => {
    const first = await login();
    await db.execute({
      sql: `UPDATE sessions SET expires_at = '2000-01-01T00:00:00.000Z'
            WHERE revoked_at IS NULL`,
    });
    const res: TypedErrRes = await agent
      .post(REFRESH)
      .send({ refreshToken: first.refreshToken });
    assert.equal(res.status, 401);
    assert.equal(res.body.body.errorCode, 'REFRESH_TOKEN_EXPIRED');
  });

  it('rejects a malformed body with 400', async () => {
    const res: TypedErrRes = await agent
      .post(REFRESH)
      .send({ refreshToken: 'abc', extra: 1 });
    assert.equal(res.status, 400);
    assert.equal(res.body.body.errorCode, 'VALIDATION_ERROR');
  });

  describe('device-bound sessions', () => {
    it('accepts a valid device signature', async () => {
      const deviceId = randomUUID();
      const keys = deviceKeys();
      const first = await login({
        deviceId,
        devicePublicKey: keys.publicKeyB64,
      });
      const timestamp = Date.now();
      const res: TypedRes<RefreshResult> = await agent.post(REFRESH).send({
        refreshToken: first.refreshToken,
        deviceId,
        timestamp,
        signature: proof(keys.privateKey, first.refreshToken, timestamp),
      });
      assert.equal(res.status, 200, JSON.stringify(res.body));
    });

    const failCases: [
      string,
      (
        t: string,
        id: string,
        k: ReturnType<typeof deviceKeys>,
      ) => Record<string, unknown>,
    ][] = [
      ['missing signature', (t, id) => ({ refreshToken: t, deviceId: id })],
      [
        'wrong deviceId',
        (t, _id, k) => {
          const ts = Date.now();
          return {
            refreshToken: t,
            deviceId: randomUUID(),
            timestamp: ts,
            signature: proof(k.privateKey, t, ts),
          };
        },
      ],
      [
        'signature from another key (token copied to another phone)',
        (t, id) => {
          const ts = Date.now();
          return {
            refreshToken: t,
            deviceId: id,
            timestamp: ts,
            signature: proof(deviceKeys().privateKey, t, ts),
          };
        },
      ],
      [
        'stale timestamp',
        (t, id, k) => {
          const ts = Date.now() - 10 * 60_000;
          return {
            refreshToken: t,
            deviceId: id,
            timestamp: ts,
            signature: proof(k.privateKey, t, ts),
          };
        },
      ],
    ];

    for (const [name, build] of failCases) {
      it(`rejects ${name}`, async () => {
        const deviceId = randomUUID();
        const keys = deviceKeys();
        const first = await login({
          deviceId,
          devicePublicKey: keys.publicKeyB64,
        });
        const res: TypedErrRes = await agent
          .post(REFRESH)
          .send(build(first.refreshToken, deviceId, keys));
        assert.equal(res.status, 401);
        assert.equal(res.body.body.errorCode, 'DEVICE_VERIFICATION_FAILED');
      });
    }
  });
});

describe('POST /api/v1/auth/logout', () => {
  it('requires an access token', async () => {
    const res: TypedErrRes = await agent.post(LOGOUT);
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, {
      meta: { statusCode: 401, message: 'Authentication required' },
      body: { errorCode: 'AUTH_REQUIRED' },
    });
  });

  it('rejects a tampered token', async () => {
    const { accessToken } = await login();
    const tampered = accessToken.slice(0, -2) + 'xx';
    const res: TypedErrRes = await agent.post(LOGOUT).set(bearer(tampered));
    assert.equal(res.status, 401);
    assert.equal(res.body.body.errorCode, 'INVALID_TOKEN');
  });

  it('returns TOKEN_EXPIRED for an expired access token', async () => {
    const { accessToken } = await login();
    const [, payloadB64] = accessToken.split('.');
    const claims = JSON.parse(
      Buffer.from(payloadB64, 'base64url').toString(),
    ) as Record<string, unknown>;
    const expired = await new SignJWT({ ...claims })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(new TextEncoder().encode(Env.JWT_SECRET));
    const res: TypedErrRes = await agent.post(LOGOUT).set(bearer(expired));
    assert.equal(res.status, 401);
    assert.equal(res.body.body.errorCode, 'TOKEN_EXPIRED');
  });

  it('ends the session immediately: access and refresh tokens stop working', async () => {
    const s = await login();
    const res: TypedRes<{ allDevices: boolean }> = await agent
      .post(LOGOUT)
      .set(bearer(s.accessToken));
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, {
      meta: { statusCode: 200, message: 'Logged out successfully' },
      body: { allDevices: false },
    });

    const again: TypedErrRes = await agent
      .post(LOGOUT)
      .set(bearer(s.accessToken));
    assert.equal(again.status, 401);
    assert.equal(again.body.body.errorCode, 'SESSION_REVOKED');

    const refresh: TypedErrRes = await agent
      .post(REFRESH)
      .send({ refreshToken: s.refreshToken });
    assert.equal(refresh.status, 401);
    assert.equal(refresh.body.body.errorCode, 'SESSION_REVOKED');
  });

  it('only ends the current session by default', async () => {
    const phoneA = await login();
    const phoneB = await login();
    await agent.post(LOGOUT).set(bearer(phoneA.accessToken));
    const stillIn = await agent
      .post(REFRESH)
      .send({ refreshToken: phoneB.refreshToken });
    assert.equal(stillIn.status, 200);
  });

  it('ends every session with { allDevices: true }', async () => {
    const phoneA = await login();
    const phoneB = await login();
    const res: TypedRes<{ allDevices: boolean }> = await agent
      .post(LOGOUT)
      .set(bearer(phoneA.accessToken))
      .send({ allDevices: true });
    assert.equal(res.status, 200);
    assert.equal(res.body.meta.message, 'Logged out from all devices');

    const other: TypedErrRes = await agent
      .post(REFRESH)
      .send({ refreshToken: phoneB.refreshToken });
    assert.equal(other.status, 401);
    assert.equal(other.body.body.errorCode, 'SESSION_REVOKED');
  });

  it('rejects unknown body fields', async () => {
    const { accessToken } = await login();
    const res: TypedErrRes = await agent
      .post(LOGOUT)
      .set(bearer(accessToken))
      .send({ everything: true });
    assert.equal(res.status, 400);
  });
});
