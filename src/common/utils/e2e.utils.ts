import crypto from 'node:crypto';

// ========================================================================= //
//                     END-TO-END PAYLOAD ENCRYPTION (v1)                    //
// ========================================================================= //
//
// On top of TLS, request and response bodies can be encrypted so that only
// this server (request) and only the calling app instance (response) can read
// them — even if TLS is intercepted (user-installed CA, debugging proxy, ...).
//
// Per request, the client:
//   1. creates a fresh (ephemeral) P-256 key pair,
//   2. ECDH(ephemeral private, server public) -> shared secret,
//   3. HKDF-SHA256(shared, salt = nonce, info = "JWALLET-E2E-v1|<kid>") -> 32-byte key,
//   4. AES-256-GCM encrypts the JSON body with AAD = requestAad(...).
// The server derives the same key from (server private, ephemeral public) and
// encrypts its response with it (AAD = responseAad(...)).
//
// Wire format of an encrypted payload: base64( iv[12] || ciphertext || tag[16] ).

export const E2E_VERSION = 'JWALLET-E2E-v1';
export const E2E_ALG = 'ECDH-P256+HKDF-SHA256+A256GCM';

export const E2E_HEADERS = {
  ENCRYPTED: 'x-encrypted', // "1"
  KID: 'x-enc-kid', // server key id the client used
  EPK: 'x-enc-epk', // client ephemeral public key, base64 uncompressed point (65 bytes)
  TS: 'x-enc-ts', // client time, epoch ms
  NONCE: 'x-enc-nonce', // base64url, 16-32 random bytes, never reused
} as const;

/** Bytes the request ciphertext is bound to: it can't be moved to another call. */
export function requestAad(
  method: string,
  originalUrl: string,
  ts: string,
  nonce: string,
): string {
  return `${E2E_VERSION}\nREQ\n${method.toUpperCase()}\n${originalUrl}\n${ts}\n${nonce}`;
}

/** Bytes the response ciphertext is bound to (incl. the HTTP status). */
export function responseAad(nonce: string, status: number): string {
  return `${E2E_VERSION}\nRES\n${nonce}\n${status}`;
}

/** Shared AES key from our private key and the peer's public point. */
export function deriveKey(
  ecdh: crypto.ECDH,
  peerPublicKey: Buffer,
  nonce: string,
  kid: string,
): Buffer {
  const shared = ecdh.computeSecret(peerPublicKey);
  return Buffer.from(
    crypto.hkdfSync(
      'sha256',
      shared,
      Buffer.from(nonce, 'base64url'),
      Buffer.from(`${E2E_VERSION}|${kid}`),
      32,
    ),
  );
}

export function seal(key: Buffer, plaintext: string, aad: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, ct, cipher.getAuthTag()]).toString('base64');
}

/** Throws if the payload was tampered with or the key/AAD don't match. */
export function open(key: Buffer, payload: string, aad: string): string {
  const raw = Buffer.from(payload, 'base64');
  if (raw.length < 12 + 16) throw new Error('Payload too short');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(raw.length - 16);
  const ct = raw.subarray(12, raw.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString(
    'utf8',
  );
}

/** Server ECDH object from a base64 raw 32-byte private key. */
export function ecdhFromPrivateKey(privateKeyBase64: string): crypto.ECDH {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(privateKeyBase64, 'base64'));
  return ecdh;
}
