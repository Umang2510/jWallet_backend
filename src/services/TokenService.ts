import { SignJWT } from 'jose';
import { randomUUID } from 'node:crypto';

import { Env } from '#src/common/constants/env.constants.ts';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

const SECRET = new TextEncoder().encode(Env.JWT_SECRET);

/** Permissions granted to a normal password-authenticated session. */
export const DEFAULT_SCOPES = [
  'profile:read',
  'wallet:read',
  'txn:read',
  'txn:transfer',
] as const;

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface AccessTokenClaims {
  userId: string;
  sessionId: string;
  deviceId: string | null;
  scopes: readonly string[];
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/**
 * Sign a short-lived access token (HS256).
 * Claims: sub = user id, sid = session id, did = device id, scope = permissions.
 */
async function issueAccessToken(
  claims: AccessTokenClaims,
): Promise<{ token: string; expiresIn: number }> {
  const expiresIn = Env.ACCESS_TOKEN_TTL_SEC;
  const token = await new SignJWT({
    sid: claims.sessionId,
    ...(claims.deviceId ? { did: claims.deviceId } : {}),
    scope: claims.scopes.join(' '),
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(claims.userId)
    .setIssuer(Env.JWT_ISSUER)
    .setAudience(Env.JWT_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(`${expiresIn}s`)
    .setJti(randomUUID())
    .sign(SECRET);
  return { token, expiresIn };
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  issueAccessToken,
} as const;
