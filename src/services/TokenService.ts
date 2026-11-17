import { errors, jwtVerify, SignJWT } from 'jose';
import { randomUUID } from 'node:crypto';

import { UnauthorizedError } from '#src/common/classes/route-errors.ts';
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

/**
 * Verify signature, algorithm, issuer, audience and expiry of an access token.
 * Throws 401 TOKEN_EXPIRED (app should refresh) or 401 INVALID_TOKEN.
 */
async function verifyAccessToken(token: string): Promise<AccessTokenClaims> {
  try {
    const { payload } = await jwtVerify(token, SECRET, {
      algorithms: ['HS256'],
      issuer: Env.JWT_ISSUER,
      audience: Env.JWT_AUDIENCE,
      requiredClaims: ['sub', 'sid', 'exp', 'iat', 'jti'],
    });
    if (typeof payload.sid !== 'string' || typeof payload.sub !== 'string') {
      throw new UnauthorizedError('Invalid access token', 'INVALID_TOKEN');
    }
    return {
      userId: payload.sub,
      sessionId: payload.sid,
      deviceId: typeof payload.did === 'string' ? payload.did : null,
      scopes: typeof payload.scope === 'string' ? payload.scope.split(' ') : [],
    };
  } catch (err) {
    if (err instanceof errors.JWTExpired) {
      throw new UnauthorizedError('Access token has expired', 'TOKEN_EXPIRED');
    }
    if (err instanceof UnauthorizedError) throw err;
    throw new UnauthorizedError('Invalid access token', 'INVALID_TOKEN');
  }
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  issueAccessToken,
  verifyAccessToken,
} as const;
