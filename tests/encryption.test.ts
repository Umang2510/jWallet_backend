import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { before, describe, it } from 'node:test';

import { Env } from '#src/common/constants/env.constants.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import { sealRequest } from '#src/common/utils/e2e-client.ts';
import { open, responseAad, seal } from '#src/common/utils/e2e.utils.ts';
import db from '#src/db/client.ts';
import { purgeExpired } from '#src/db/maintenance.ts';
import { DEMO_USER } from '#src/db/seed.ts';
import { SERVER_ENC_PUBLIC_KEY } from '#src/middleware/e2e-encryption.ts';

import { agent, dbReady } from './support/agent.ts';
import type { TypedErrRes } from './support/utils.ts';

// ========================================================================= //
//                                  HELPERS                                  //
// ========================================================================= //

const LOGIN = Paths.Auth.Login.FULL_PATH;
const BALANCE = Paths.Wallet.Balance.FULL_PATH;
const CREDS = { email: DEMO_USER.email, password: DEMO_USER.password };

interface Envelope<T = Record<string, unknown>> {
  meta: { statusCode: number; message: string };
  body: T;
}

function seal_(method: string, url: string, body?: unknown, extra = {}) {
  return sealRequest({
    serverPublicKeyBase64: SERVER_ENC_PUBLIC_KEY.publicKey,
    kid: SERVER_ENC_PUBLIC_KEY.kid,
    method,
    originalUrl: url,
    body,
    ...extra,
  });
}

/** Send an encrypted request and decrypt the response. */
async function call<T = Record<string, unknown>>(
  method: 'get' | 'post',
  url: string,
  body?: unknown,
  headers: Record<string, string> = {},
) {
  const s = seal_(method.toUpperCase(), url, body);
  const req = agent[method](url).set({ ...s.headers, ...headers });
  const res = s.body ? await req.send(s.body) : await req;
  return {
    res,
    data: s.openResponse(res.status, res.body) as Envelope<T>,
  };
}

let accessToken: string;

before(async () => {
  await dbReady;
  const { data } = await call<{ accessToken: string }>('post', LOGIN, CREDS);
  accessToken = data.body.accessToken;
});

// ========================================================================= //
//                                   TESTS                                   //
// ========================================================================= //

describe('GET /api/v1/security/encryption-key', () => {
  it('is public and returns the server public key', async () => {
    const res = await agent.get(Paths.Security.EncryptionKey.FULL_PATH);
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, {
      meta: { statusCode: 200, message: 'Encryption key fetched successfully' },
      body: {
        kid: Env.SERVER_ENC_KEY_ID,
        alg: 'ECDH-P256+HKDF-SHA256+A256GCM',
        publicKey: SERVER_ENC_PUBLIC_KEY.publicKey,
      },
    });
    assert.equal(
      Buffer.from(SERVER_ENC_PUBLIC_KEY.publicKey, 'base64').length,
      65,
    );
  });
});

describe('encrypted requests', () => {
  it('login: body and response are both encrypted on the wire', async () => {
    const s = seal_('POST', LOGIN, CREDS);
    const res = await agent.post(LOGIN).set(s.headers).send(s.body);
    assert.equal(res.status, 200);
    assert.equal(res.headers['x-encrypted'], '1');
    // Nothing readable on the wire.
    const wire = JSON.stringify(res.body);
    assert.deepEqual(Object.keys(res.body as object), ['payload']);
    assert.ok(!wire.includes('accessToken') && !wire.includes('Demo User'));
    assert.ok(!JSON.stringify(s.body).includes(DEMO_USER.password));

    const data = s.openResponse(res.status, res.body) as Envelope;
    assert.deepEqual(data.meta, {
      statusCode: 200,
      message: 'Login successful',
    });
    assert.ok(data.body.accessToken);
  });

  it('GET with no body: response is encrypted', async () => {
    const { res, data } = await call<{ availableBalance: number }>(
      'get',
      BALANCE,
      undefined,
      { Authorization: `Bearer ${accessToken}` },
    );
    assert.equal(res.status, 200);
    assert.equal(data.body.availableBalance, 25450.75);
  });

  it('GET with a query string is bound to that exact URL', async () => {
    const url = '/api/v1/transactions?limit=2&type=DEBIT';
    const { data } = await call<{ items: unknown[] }>('get', url, undefined, {
      Authorization: `Bearer ${accessToken}`,
    });
    assert.equal(data.body.items.length, 2);
  });

  it('error responses are encrypted too', async () => {
    const { res, data } = await call('post', LOGIN, {
      ...CREDS,
      password: 'Wrong@123',
    });
    assert.equal(res.status, 401);
    assert.equal(res.headers['x-encrypted'], '1');
    assert.deepEqual(data, {
      meta: { statusCode: 401, message: 'Invalid email or password' },
      body: { errorCode: 'INVALID_CREDENTIALS' },
    });
  });

  it('auth/validation/404 errors after decryption are encrypted', async () => {
    const noAuth = await call('get', BALANCE);
    assert.equal(noAuth.res.status, 401);
    assert.equal(noAuth.data.body.errorCode, 'AUTH_REQUIRED');

    const invalid = await call('post', LOGIN, { email: 'x' });
    assert.equal(invalid.res.status, 400);
    assert.equal(invalid.data.body.errorCode, 'VALIDATION_ERROR');

    const missing = await call('get', '/api/v1/nope');
    assert.equal(missing.res.status, 404);
    assert.equal(missing.data.body.errorCode, 'ROUTE_NOT_FOUND');
  });

  it('plain JSON still works when X-Encrypted is not sent', async () => {
    const res = await agent.post(LOGIN).send(CREDS);
    assert.equal(res.status, 200);
    assert.equal(res.headers['x-encrypted'], undefined);
    assert.ok((res.body as Envelope).body.accessToken);
  });

  it("the response can only be opened with this request's key", async () => {
    const s = seal_('POST', LOGIN, CREDS);
    const res = await agent.post(LOGIN).set(s.headers).send(s.body);
    const other = seal_('POST', LOGIN, CREDS);
    assert.throws(() => other.openResponse(res.status, res.body));
    // ...and is bound to the HTTP status.
    assert.throws(() => s.openResponse(500, res.body));
  });
});

describe('rejected encrypted requests (400, plain error)', () => {
  async function expect400(
    send: () => Promise<TypedErrRes>,
    code: string,
  ): Promise<void> {
    const res = await send();
    assert.equal(res.status, 400, JSON.stringify(res.body));
    assert.equal(res.body.body.errorCode, code);
  }

  it('tampered ciphertext', async () => {
    const s = seal_('POST', LOGIN, CREDS);
    const raw = Buffer.from(s.body!.payload, 'base64');
    raw[20] = raw[20] ^ 1;
    await expect400(
      () =>
        agent
          .post(LOGIN)
          .set(s.headers)
          .send({ payload: raw.toString('base64') }),
      'DECRYPTION_FAILED',
    );
  });

  it('a body encrypted for another endpoint (AAD mismatch)', async () => {
    const s = seal_('POST', Paths.Auth.Refresh.FULL_PATH, CREDS);
    await expect400(
      () => agent.post(LOGIN).set(s.headers).send(s.body),
      'DECRYPTION_FAILED',
    );
  });

  it('a changed query string (AAD mismatch)', async () => {
    const s = seal_('GET', '/api/v1/transactions?limit=1');
    const res = await agent
      .get('/api/v1/transactions?limit=50')
      .set(s.headers)
      .send({ payload: seal(Buffer.alloc(32), '{}', 'x') });
    assert.equal(res.status, 400);
  });

  it('a replayed request (same nonce twice)', async () => {
    const s = seal_('POST', LOGIN, CREDS);
    const first = await agent.post(LOGIN).set(s.headers).send(s.body);
    assert.equal(first.status, 200);
    await expect400(
      () => agent.post(LOGIN).set(s.headers).send(s.body),
      'REPLAYED_REQUEST',
    );
  });

  it('a stale or future timestamp', async () => {
    for (const offset of [-1, 1]) {
      const s = seal_('POST', LOGIN, CREDS, {
        ts: Date.now() + offset * (Env.ENC_MAX_SKEW_SEC + 30) * 1000,
      });
      await expect400(
        () => agent.post(LOGIN).set(s.headers).send(s.body),
        'REQUEST_EXPIRED',
      );
    }
  });

  it('an unknown key id', async () => {
    const s = seal_('POST', LOGIN, CREDS);
    await expect400(
      () =>
        agent
          .post(LOGIN)
          .set({ ...s.headers, 'x-enc-kid': 'old-key' })
          .send(s.body),
      'ENCRYPTION_KEY_UNKNOWN',
    );
  });

  it('missing or malformed headers', async () => {
    const s = seal_('POST', LOGIN, CREDS);
    for (const [h, v] of [
      ['x-enc-nonce', ''],
      ['x-enc-nonce', 'short'],
      ['x-enc-ts', 'yesterday'],
      ['x-enc-epk', 'abc'],
    ]) {
      const headers = { ...s.headers, [h]: v };
      if (v === '') delete (headers as Record<string, string>)[h];
      await expect400(
        () => agent.post(LOGIN).set(headers).send(s.body),
        'ENCRYPTION_HEADERS_INVALID',
      );
    }
  });

  it('an ephemeral key that is not on the curve', async () => {
    const s = seal_('POST', LOGIN, CREDS);
    const bogus = Buffer.alloc(65, 7);
    bogus[0] = 4;
    await expect400(
      () =>
        agent
          .post(LOGIN)
          .set({ ...s.headers, 'x-enc-epk': bogus.toString('base64') })
          .send(s.body),
      'ENCRYPTION_HEADERS_INVALID',
    );
  });

  it('a plain body sent with X-Encrypted: 1', async () => {
    const s = seal_('POST', LOGIN, CREDS);
    await expect400(
      () => agent.post(LOGIN).set(s.headers).send(CREDS),
      'DECRYPTION_FAILED',
    );
  });

  it('extra fields next to payload', async () => {
    const s = seal_('POST', LOGIN, CREDS);
    await expect400(
      () =>
        agent
          .post(LOGIN)
          .set(s.headers)
          .send({ ...s.body, email: 'x' }),
      'DECRYPTION_FAILED',
    );
  });
});

describe('maintenance', () => {
  it('purges expired nonces', async () => {
    await db.execute(
      "INSERT INTO request_nonces (nonce, expires_at) VALUES ('old-nonce-for-test-0000', '2000-01-01T00:00:00.000Z')",
    );
    await purgeExpired();
    const r = await db.execute(
      "SELECT 1 FROM request_nonces WHERE nonce = 'old-nonce-for-test-0000'",
    );
    assert.equal(r.rows.length, 0);
  });
});

describe('e2e primitives', () => {
  it('round-trips and rejects a wrong AAD', () => {
    const key = crypto.randomBytes(32);
    const sealed = seal(key, 'hello', 'aad-1');
    assert.equal(open(key, sealed, 'aad-1'), 'hello');
    assert.throws(() => open(key, sealed, 'aad-2'));
    assert.throws(() => open(key, 'AAAA', 'aad-1'));
    assert.ok(responseAad('n', 200).includes('RES'));
  });
});
