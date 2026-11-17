import crypto from 'node:crypto';

import {
  deriveKey,
  E2E_HEADERS,
  open,
  requestAad,
  responseAad,
  seal,
} from './e2e.utils.ts';

// ========================================================================= //
//                     REFERENCE CLIENT FOR E2E ENCRYPTION                   //
// ========================================================================= //
//
// What the mobile app does for every call. Used by the tests and by
// scripts/encrypted-client.ts; mirrors the Dart implementation step by step.

export interface SealedRequest {
  headers: Record<string, string>;
  /** JSON body to send (undefined for GET / no body). */
  body: { payload: string } | undefined;
  /** Decrypt the server's `{ payload }` response for this request. */
  openResponse: (status: number, responseBody: unknown) => unknown;
}

export function sealRequest(opts: {
  serverPublicKeyBase64: string;
  kid: string;
  method: string;
  originalUrl: string;
  body?: unknown;
  ts?: number;
  nonce?: string;
}): SealedRequest {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const nonce = opts.nonce ?? crypto.randomBytes(16).toString('base64url');
  const ts = String(opts.ts ?? Date.now());
  const key = deriveKey(
    ecdh,
    Buffer.from(opts.serverPublicKeyBase64, 'base64'),
    nonce,
    opts.kid,
  );
  const aad = requestAad(opts.method, opts.originalUrl, ts, nonce);

  return {
    headers: {
      [E2E_HEADERS.ENCRYPTED]: '1',
      [E2E_HEADERS.KID]: opts.kid,
      [E2E_HEADERS.EPK]: ecdh.getPublicKey('base64'),
      [E2E_HEADERS.TS]: ts,
      [E2E_HEADERS.NONCE]: nonce,
    },
    body:
      opts.body === undefined
        ? undefined
        : { payload: seal(key, JSON.stringify(opts.body), aad) },
    openResponse: (status, responseBody) => {
      const payload = (responseBody as { payload?: unknown } | null)?.payload;
      if (typeof payload !== 'string') {
        throw new Error('Response is not encrypted');
      }
      return JSON.parse(
        open(key, payload, responseAad(nonce, status)),
      ) as unknown;
    },
  };
}
