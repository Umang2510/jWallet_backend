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
