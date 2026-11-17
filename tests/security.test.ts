import argon2 from 'argon2';
import { SignJWT } from 'jose';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { beforeEach, describe, it } from 'node:test';

import { Env } from '#src/common/constants/env.constants.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import db, { asText, asTextOrNull } from '#src/db/client.ts';
import { DEMO_USER } from '#src/db/seed.ts';
import { isWeakPin } from '#src/entities/Security/index.ts';
import type { LoginResult } from '#src/services/AuthService.ts';
import type { ProfileResult } from '#src/services/UserService.ts';

import { agent, dbReady } from './support/agent.ts';
import type { TypedErrRes, TypedRes } from './support/utils.ts';

// ========================================================================= //
//                                  HELPERS                                  //
// ========================================================================= //

const PIN = Paths.Security.SetPin.FULL_PATH;
const BIO = Paths.Devices.Biometric.FULL_PATH;
const GOOD_PIN = '2580';
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

async function login(extra: object = {}): Promise<LoginResult> {
  const res: TypedRes<LoginResult> = await agent
    .post(Paths.Auth.Login.FULL_PATH)
    .send({ email: DEMO_USER.email, password: DEMO_USER.password, ...extra });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body.body;
}

async function deviceLogin() {
  const deviceId = randomUUID();
  return { deviceId, session: await login({ deviceId }) };
}

/** Put a PIN in place directly (faster than the API, used for setup). */
async function givePin(pin = GOOD_PIN) {
  const now = new Date().toISOString();
  await db.execute({
    sql: `INSERT INTO transaction_pins (user_id, pin_hash, set_at, updated_at)
          SELECT id, ?, ?, ? FROM users WHERE email = ?`,
    args: [await argon2.hash(pin), now, now, DEMO_USER.email],
  });
}

function p256Key(): string {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
}

async function profile(token: string) {
  const res: TypedRes<ProfileResult> = await agent
    .get(Paths.Users.Profile.FULL_PATH)
    .set(bearer(token));
  return res.body.body.security;
}

async function pinRow() {
  const res = await db.execute({
    sql: `SELECT p.pin_hash, p.failed_count, p.locked_until FROM transaction_pins p
          JOIN users u ON u.id = p.user_id WHERE u.email = ?`,
    args: [DEMO_USER.email],
  });
  return res.rows[0];
}

beforeEach(async () => {
  await dbReady;
  await db.batch(
    [
      'DELETE FROM transaction_pins',
      'UPDATE devices SET biometric_public_key = NULL, biometric_enrolled_at = NULL',
      'UPDATE users SET failed_login_count = 0, login_locked_until = NULL',
    ],
    'write',
  );
});

// ========================================================================= //
//                                   TESTS                                   //
// ========================================================================= //

describe('POST /api/v1/security/pin (set PIN)', () => {
  it('sets the PIN (201) and the profile reports it', async () => {
    const s = await login();
    const res: TypedRes<{ pinSet: boolean }> = await agent
      .post(PIN)
      .set(bearer(s.accessToken))
      .send({ pin: GOOD_PIN });
    assert.equal(res.status, 201);
    assert.deepEqual(res.body, {
      meta: { statusCode: 201, message: 'Transaction PIN set' },
      body: { pinSet: true },
    });
    assert.equal((await profile(s.accessToken)).pinSet, true);
    assert.equal((await login()).security.pinSet, true);
  });

  it('stores only an argon2id hash of the PIN', async () => {
    const s = await login();
    await agent.post(PIN).set(bearer(s.accessToken)).send({ pin: GOOD_PIN });
    const hash = asText((await pinRow())?.pin_hash);
    assert.notEqual(hash, GOOD_PIN);
    assert.match(hash, /^\$argon2id\$/);
  });

  it('accepts a 6-digit PIN', async () => {
    const s = await login();
    const res = await agent
      .post(PIN)
      .set(bearer(s.accessToken))
      .send({ pin: '258014' });
    assert.equal(res.status, 201);
  });

  it('409 PIN_ALREADY_SET on a second attempt', async () => {
    const s = await login();
    await agent.post(PIN).set(bearer(s.accessToken)).send({ pin: GOOD_PIN });
    const res: TypedErrRes = await agent
      .post(PIN)
      .set(bearer(s.accessToken))
      .send({ pin: '3691' });
    assert.equal(res.status, 409);
    assert.equal(res.body.body.errorCode, 'PIN_ALREADY_SET');
  });

  it('403 REAUTH_REQUIRED when the password login is not recent', async () => {
    const s = await login();
    await db.execute(
      "UPDATE sessions SET password_auth_at = '2000-01-01T00:00:00.000Z'",
    );
    const res: TypedErrRes = await agent
      .post(PIN)
      .set(bearer(s.accessToken))
      .send({ pin: GOOD_PIN });
    assert.equal(res.status, 403);
    assert.equal(res.body.body.errorCode, 'REAUTH_REQUIRED');
    assert.equal(await pinRow(), undefined);
  });

  describe('rejects bad PINs (400)', () => {
    const bad: [string, unknown][] = [
      ['all same digit', '0000'],
      ['all same digit (6)', '111111'],
      ['ascending', '1234'],
      ['descending', '4321'],
      ['ascending (6)', '123456'],
      ['descending (6)', '987654'],
      ['repeated pair', '1212'],
      ['repeated pair (6)', '121212'],
      ['too short', '123'],
      ['5 digits', '25801'],
      ['too long', '2580147'],
      ['letters', 'abcd'],
      ['spaces', ' 2580'],
      ['number instead of string', 2580],
      ['missing', undefined],
    ];
    for (const [name, pin] of bad) {
      it(name, async () => {
        const s = await login();
        const res: TypedErrRes = await agent
          .post(PIN)
          .set(bearer(s.accessToken))
          .send(pin === undefined ? {} : { pin });
        assert.equal(res.status, 400, JSON.stringify(res.body));
        assert.equal(res.body.body.errorCode, 'VALIDATION_ERROR');
      });
    }
  });

  it('401 without a token', async () => {
    const res = await agent.post(PIN).send({ pin: GOOD_PIN });
    assert.equal(res.status, 401);
  });

  it('403 INSUFFICIENT_SCOPE for a token without security:manage', async () => {
    const s = await login();
    const claims = JSON.parse(
      Buffer.from(s.accessToken.split('.')[1], 'base64url').toString(),
    ) as Record<string, unknown>;
    const limited = await new SignJWT({ ...claims, scope: 'wallet:read' })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .sign(new TextEncoder().encode(Env.JWT_SECRET));
    const res: TypedErrRes = await agent
      .post(PIN)
      .set(bearer(limited))
      .send({ pin: GOOD_PIN });
    assert.equal(res.status, 403);
    assert.equal(res.body.body.errorCode, 'INSUFFICIENT_SCOPE');
  });
});

describe('PUT /api/v1/security/pin (change PIN)', () => {
  const change = (token: string, currentPin: string, newPin = '3691') =>
    agent.put(PIN).set(bearer(token)).send({ currentPin, newPin });

  it('changes the PIN; the old one stops working', async () => {
    await givePin();
    const s = await login();
    const res = await change(s.accessToken, GOOD_PIN);
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, {
      meta: { statusCode: 200, message: 'Transaction PIN changed' },
      body: { pinChanged: true },
    });
    const old: TypedErrRes = await change(s.accessToken, GOOD_PIN, '1470');
    assert.equal(old.body.body.errorCode, 'INVALID_PIN');
    const now = await change(s.accessToken, '3691', '1470');
    assert.equal(now.status, 200);
  });

  it('403 INVALID_PIN with attempts left (not 401, so the app keeps the session)', async () => {
    await givePin();
    const s = await login();
    const res: TypedErrRes = await change(s.accessToken, '9999');
    assert.equal(res.status, 403);
    assert.deepEqual(res.body, {
      meta: { statusCode: 403, message: 'Incorrect PIN. 2 attempts left.' },
      body: {
        errorCode: 'INVALID_PIN',
        details: [{ field: 'pin', message: '2 attempts left' }],
      },
    });
  });

  it('locks for 24h after 3 wrong PINs (423), even for the right PIN', async () => {
    await givePin();
    const s = await login();
    assert.equal((await change(s.accessToken, '9999')).status, 403);
    assert.equal((await change(s.accessToken, '9998')).status, 403);
    const third: TypedErrRes = await change(s.accessToken, '9997');
    assert.equal(third.status, 423);
    assert.equal(third.body.body.errorCode, 'PIN_LOCKED');
    assert.match(third.body.meta.message, /locked for 24 hours/);

    const right: TypedErrRes = await change(s.accessToken, GOOD_PIN);
    assert.equal(right.status, 423);

    const until = Date.parse(asText((await pinRow())?.locked_until));
    const hours = (until - Date.now()) / 3_600_000;
    assert.ok(hours > 23.9 && hours <= 24, `locked for ${hours}h`);
  });

  it('the lockout survives logging in again (server-side counter)', async () => {
    await givePin();
    const a = await login();
    for (const p of ['9999', '9998', '9997']) await change(a.accessToken, p);
    const b = await login();
    const res: TypedErrRes = await change(b.accessToken, GOOD_PIN);
    assert.equal(res.status, 423);
  });

  it('a correct PIN resets the failure counter', async () => {
    await givePin();
    const s = await login();
    await change(s.accessToken, '9999');
    await change(s.accessToken, '9998');
    assert.equal(
      (
        await change(
          s.accessToken,
          GOOD_PIN,
          GOOD_PIN.split('').reverse().join(''),
        )
      ).status,
      200,
    );
    assert.equal(Number((await pinRow())?.failed_count), 0);
  });

  it('parallel wrong guesses cannot exceed the attempt limit', async () => {
    await givePin();
    const s = await login();
    const results = await Promise.all(
      ['1111', '2222', '3333', '4444', '5555', '6666'].map((p) =>
        change(s.accessToken, p.replace(/^(\d)\1+$/, '9$1$1$1').slice(0, 4)),
      ),
    );
    assert.ok(results.every((r) => r.status === 403 || r.status === 423));
    assert.ok(asTextOrNull((await pinRow())?.locked_until));
    const right: TypedErrRes = await change(s.accessToken, GOOD_PIN);
    assert.equal(right.status, 423);
  });

  it('400 when the new PIN equals the current one', async () => {
    await givePin();
    const s = await login();
    const res: TypedErrRes = await change(s.accessToken, GOOD_PIN, GOOD_PIN);
    assert.equal(res.status, 400);
    assert.ok(res.body.body.details?.some((d) => d.field === 'newPin'));
  });

  it('400 when the new PIN is weak', async () => {
    await givePin();
    const s = await login();
    const res = await change(s.accessToken, GOOD_PIN, '1111');
    assert.equal(res.status, 400);
  });

  it('403 PIN_NOT_SET when there is no PIN yet', async () => {
    const s = await login();
    const res: TypedErrRes = await change(s.accessToken, GOOD_PIN);
    assert.equal(res.status, 403);
    assert.equal(res.body.body.errorCode, 'PIN_NOT_SET');
  });
});

describe('POST/DELETE /api/v1/devices/biometric', () => {
  it('enrolls with the PIN; profile and next login report it', async () => {
    await givePin();
    const { deviceId, session } = await deviceLogin();
    const res: TypedRes<{ biometricEnrolled: boolean; enrolledAt: string }> =
      await agent
        .post(BIO)
        .set(bearer(session.accessToken))
        .send({ publicKey: p256Key(), pin: GOOD_PIN });
    assert.equal(res.status, 200);
    assert.equal(res.body.meta.message, 'Biometric approval enabled');
    assert.equal(res.body.body.biometricEnrolled, true);
    assert.ok(!Number.isNaN(Date.parse(res.body.body.enrolledAt)));

    assert.equal((await profile(session.accessToken)).biometricEnrolled, true);
    assert.equal((await login({ deviceId })).security.biometricEnrolled, true);
    // Another device is not enrolled.
    assert.equal(
      (await deviceLogin()).session.security.biometricEnrolled,
      false,
    );
  });

  it('re-enrolling replaces the key', async () => {
    await givePin();
    const { deviceId, session } = await deviceLogin();
    const k1 = p256Key();
    const k2 = p256Key();
    for (const publicKey of [k1, k2]) {
      await agent
        .post(BIO)
        .set(bearer(session.accessToken))
        .send({ publicKey, pin: GOOD_PIN });
    }
    const row = await db.execute({
      sql: 'SELECT biometric_public_key FROM devices WHERE device_id = ?',
      args: [deviceId],
    });
    assert.equal(row.rows[0]?.biometric_public_key, k2);
  });

  it('403 INVALID_PIN and nothing enrolled for a wrong PIN', async () => {
    await givePin();
    const { session } = await deviceLogin();
    const res: TypedErrRes = await agent
      .post(BIO)
      .set(bearer(session.accessToken))
      .send({ publicKey: p256Key(), pin: '9999' });
    assert.equal(res.status, 403);
    assert.equal(res.body.body.errorCode, 'INVALID_PIN');
    assert.equal((await profile(session.accessToken)).biometricEnrolled, false);
  });

  it('423 while the PIN is locked', async () => {
    await givePin();
    await db.execute(
      `UPDATE transaction_pins SET locked_until = '${new Date(Date.now() + 3_600_000).toISOString()}'`,
    );
    const { session } = await deviceLogin();
    const res: TypedErrRes = await agent
      .post(BIO)
      .set(bearer(session.accessToken))
      .send({ publicKey: p256Key(), pin: GOOD_PIN });
    assert.equal(res.status, 423);
  });

  it('403 PIN_NOT_SET before a PIN exists', async () => {
    const { session } = await deviceLogin();
    const res: TypedErrRes = await agent
      .post(BIO)
      .set(bearer(session.accessToken))
      .send({ publicKey: p256Key(), pin: GOOD_PIN });
    assert.equal(res.status, 403);
    assert.equal(res.body.body.errorCode, 'PIN_NOT_SET');
  });

  it('400 DEVICE_REQUIRED for a session without a device', async () => {
    await givePin();
    const s = await login();
    const res: TypedErrRes = await agent
      .post(BIO)
      .set(bearer(s.accessToken))
      .send({ publicKey: p256Key(), pin: GOOD_PIN });
    assert.equal(res.status, 400);
    assert.equal(res.body.body.errorCode, 'DEVICE_REQUIRED');
  });

  it('400 for an invalid public key (RSA, garbage, missing)', async () => {
    await givePin();
    const { session } = await deviceLogin();
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
      .publicKey.export({ format: 'der', type: 'spki' })
      .toString('base64');
    for (const publicKey of [rsa, 'not-a-key', undefined]) {
      const res: TypedErrRes = await agent
        .post(BIO)
        .set(bearer(session.accessToken))
        .send({ publicKey, pin: GOOD_PIN });
      assert.equal(res.status, 400);
    }
  });

  it('DELETE turns biometric approval off', async () => {
    await givePin();
    const { session } = await deviceLogin();
    await agent
      .post(BIO)
      .set(bearer(session.accessToken))
      .send({ publicKey: p256Key(), pin: GOOD_PIN });
    const res: TypedRes<{ biometricEnrolled: boolean }> = await agent
      .delete(BIO)
      .set(bearer(session.accessToken));
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, {
      meta: { statusCode: 200, message: 'Biometric approval disabled' },
      body: { biometricEnrolled: false },
    });
    assert.equal((await profile(session.accessToken)).biometricEnrolled, false);
  });

  it('401 without a token', async () => {
    assert.equal((await agent.post(BIO).send({})).status, 401);
    assert.equal((await agent.delete(BIO)).status, 401);
  });
});

describe('isWeakPin', () => {
  it('flags guessable PINs and allows normal ones', () => {
    for (const p of [
      '0000',
      '9999',
      '1234',
      '6789',
      '9876',
      '1212',
      '123456',
      '654321',
      '454545',
      '777777',
    ]) {
      assert.equal(isWeakPin(p), true, p);
    }
    for (const p of [
      '2580',
      '1470',
      '3691',
      '1357',
      '258014',
      '193746',
      '1122',
    ]) {
      assert.equal(isWeakPin(p), false, p);
    }
  });
});
