import type { RequestHandler, Response } from 'express';

import { RouteError } from '#src/common/classes/route-errors.ts';
import { Env } from '#src/common/constants/env.constants.ts';
import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import {
  deriveKey,
  E2E_ALG,
  E2E_HEADERS,
  ecdhFromPrivateKey,
  open,
  requestAad,
  responseAad,
  seal,
} from '#src/common/utils/e2e.utils.ts';
import db from '#src/db/client.ts';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

const SERVER_ECDH = ecdhFromPrivateKey(Env.SERVER_ENC_PRIVATE_KEY);

/** Public part the app needs (also bundled in the app at build time). */
export const SERVER_ENC_PUBLIC_KEY = {
  kid: Env.SERVER_ENC_KEY_ID,
  alg: E2E_ALG,
  publicKey: SERVER_ECDH.getPublicKey('base64'), // uncompressed point
} as const;

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

const bad = (message: string, code: string) =>
  new RouteError(HttpStatusCodes.BAD_REQUEST, message, code);

/** Record the nonce; false if it was seen before (replayed request). */
async function rememberNonce(nonce: string): Promise<boolean> {
  const expiresAt = new Date(
    Date.now() + 2 * Env.ENC_MAX_SKEW_SEC * 1000,
  ).toISOString();
  const res = await db.execute({
    sql: `INSERT INTO request_nonces (nonce, expires_at) VALUES (?, ?)
          ON CONFLICT (nonce) DO NOTHING`,
    args: [nonce, expiresAt],
  });
  return res.rowsAffected > 0;
}

/** From now on, every JSON response on this request is sealed with `key`. */
function encryptResponses(res: Response, key: Buffer, nonce: string): void {
  const json = res.json.bind(res);
  res.json = (data: unknown) => {
    res.setHeader('X-Encrypted', '1');
    return json({
      payload: seal(
        key,
        JSON.stringify(data),
        responseAad(nonce, res.statusCode),
      ),
    });
  };
}

/**
 * Optional end-to-end encryption (see e2e.utils.ts for the protocol).
 * - No `X-Encrypted` header: plain JSON (Postman, cURL).
 * - `X-Encrypted: 1`: headers + body must be valid, fresh and unseen; the body
 *   `{ "payload": "..." }` is decrypted into `req.body` and every response
 *   (success or error) is encrypted back to the caller.
 */
export const e2eEncryption: RequestHandler = async (req, res, next) => {
  if (req.get(E2E_HEADERS.ENCRYPTED) !== '1') return next();

  const kid = req.get(E2E_HEADERS.KID);
  const epk = req.get(E2E_HEADERS.EPK);
  const ts = req.get(E2E_HEADERS.TS);
  const nonce = req.get(E2E_HEADERS.NONCE);

  if (!kid || !epk || !ts || !nonce) {
    return next(
      bad(
        'Encrypted request is missing X-Enc-Kid, X-Enc-Epk, X-Enc-Ts or X-Enc-Nonce',
        'ENCRYPTION_HEADERS_INVALID',
      ),
    );
  }
  if (kid !== Env.SERVER_ENC_KEY_ID) {
    return next(
      bad(
        'Unknown encryption key. Please update the app.',
        'ENCRYPTION_KEY_UNKNOWN',
      ),
    );
  }
  if (
    !/^\d{10,16}$/.test(ts) ||
    !/^[A-Za-z0-9_-]{22,43}$/.test(nonce) ||
    !/^[A-Za-z0-9+/]{86,88}={0,2}$/.test(epk)
  ) {
    return next(
      bad('Malformed encryption headers', 'ENCRYPTION_HEADERS_INVALID'),
    );
  }
  if (Math.abs(Date.now() - Number(ts)) > Env.ENC_MAX_SKEW_SEC * 1000) {
    return next(
      bad(
        'Request has expired. Check the device date and time.',
        'REQUEST_EXPIRED',
      ),
    );
  }

  let key: Buffer;
  try {
    key = deriveKey(SERVER_ECDH, Buffer.from(epk, 'base64'), nonce, kid);
  } catch {
    return next(bad('Invalid client key', 'ENCRYPTION_HEADERS_INVALID'));
  }

  // Decrypt the body (if any) before anything else reads it.
  const aad = requestAad(req.method, req.originalUrl, ts, nonce);
  const body = req.body as unknown;
  if (body !== undefined) {
    const payload =
      body && typeof body === 'object' && !Array.isArray(body)
        ? (body as Record<string, unknown>).payload
        : undefined;
    if (
      typeof payload !== 'string' ||
      Object.keys(body as object).length !== 1
    ) {
      return next(
        bad(
          'Encrypted body must be { "payload": "<base64>" }',
          'DECRYPTION_FAILED',
        ),
      );
    }
    try {
      req.body = JSON.parse(open(key, payload, aad)) as unknown;
    } catch {
      return next(bad('Could not decrypt the request', 'DECRYPTION_FAILED'));
    }
  }

  // Each nonce works once (checked after decryption so junk can't fill the table).
  if (!(await rememberNonce(nonce))) {
    return next(bad('This request was already processed', 'REPLAYED_REQUEST'));
  }

  encryptResponses(res, key, nonce);
  next();
};
