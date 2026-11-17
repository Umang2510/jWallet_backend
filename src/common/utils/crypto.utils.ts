import crypto from 'node:crypto';

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/** Hex SHA-256 — used to store tokens so a DB leak doesn't expose them. */
export function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

/** URL-safe random token with 256 bits of entropy. */
export function randomToken(prefix = ''): string {
  return prefix + crypto.randomBytes(32).toString('base64url');
}

/**
 * Verify an ECDSA P-256 / SHA-256 signature (DER-encoded, base64) — the format
 * Android Keystore `SHA256withECDSA` produces — against a base64 DER SPKI key.
 * Returns false (never throws) for malformed input.
 */
export function verifyP256Signature(
  publicKeyBase64: string,
  message: string,
  signatureBase64: string,
): boolean {
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(publicKeyBase64, 'base64'),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(
      'sha256',
      Buffer.from(message, 'utf8'),
      { key, dsaEncoding: 'der' },
      Buffer.from(signatureBase64, 'base64'),
    );
  } catch {
    return false;
  }
}

/**
 * True if `value` is a base64-encoded DER SPKI public key on curve P-256
 * (the format Android Keystore / iOS Secure Enclave keys export to).
 */
export function isP256PublicKeyBase64(value: string): boolean {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(value, 'base64'),
      format: 'der',
      type: 'spki',
    });
    return (
      key.asymmetricKeyType === 'ec' &&
      key.asymmetricKeyDetails?.namedCurve === 'prime256v1'
    );
  } catch {
    return false;
  }
}
