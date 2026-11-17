import type { RequestHandler, Response } from 'express';

import {
  ForbiddenError,
  UnauthorizedError,
} from '#src/common/classes/route-errors.ts';
import db, { asText, asTextOrNull } from '#src/db/client.ts';
import { RevokeReasons } from '#src/repos/SessionRepo.ts';
import TokenService from '#src/services/TokenService.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

/** Identity of the caller, set by requireAuth on `res.locals.auth`. */
export interface AuthContext {
  userId: string;
  sessionId: string;
  familyId: string;
  deviceId: string | null;
  scopes: readonly string[];
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;

/**
 * Authenticate every protected request:
 * 1. valid `Authorization: Bearer <jwt>` (signature, alg, iss, aud, exp)
 * 2. its session still exists and isn't logged out / revoked (instant logout)
 * 3. the token's device matches the session's device
 * 4. the account is ACTIVE
 */
export const requireAuth: RequestHandler = async (req, res, next) => {
  const match = BEARER.exec(req.get('authorization') ?? '');
  if (!match?.[1]) {
    return next(
      new UnauthorizedError('Authentication required', 'AUTH_REQUIRED'),
    );
  }

  const claims = await TokenService.verifyAccessToken(match[1]);

  const res1 = await db.execute({
    sql: `SELECT s.user_id, s.device_id, s.family_id, s.revoked_at, s.revoke_reason,
                 u.status
          FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.id = ?`,
    args: [claims.sessionId],
  });
  const row = res1.rows[0];
  if (!row || asText(row.user_id) !== claims.userId) {
    return next(new UnauthorizedError('Invalid access token', 'INVALID_TOKEN'));
  }

  // A ROTATED row only means a newer refresh token exists; its access tokens
  // stay valid until they expire. Any other revocation ends access immediately.
  const revokedAt = asTextOrNull(row.revoked_at);
  if (revokedAt && asTextOrNull(row.revoke_reason) !== RevokeReasons.ROTATED) {
    return next(
      new UnauthorizedError(
        'Session has ended. Please log in again.',
        'SESSION_REVOKED',
      ),
    );
  }

  if (asTextOrNull(row.device_id) !== claims.deviceId) {
    return next(new UnauthorizedError('Invalid access token', 'INVALID_TOKEN'));
  }

  if (asText(row.status) !== 'ACTIVE') {
    return next(
      new ForbiddenError(
        'This account is not active. Please contact support.',
        'ACCOUNT_INACTIVE',
      ),
    );
  }

  const auth: AuthContext = {
    userId: claims.userId,
    sessionId: claims.sessionId,
    familyId: asText(row.family_id),
    deviceId: claims.deviceId,
    scopes: claims.scopes,
  };
  res.locals.auth = auth;
  next();
};

/** Allow the request only if the access token carries every listed scope. */
export function requireScope(...scopes: string[]): RequestHandler {
  return (_req, res, next) => {
    const auth = getAuth(res);
    const missing = scopes.filter((s) => !auth.scopes.includes(s));
    if (missing.length) {
      return next(
        new ForbiddenError(
          'You are not allowed to perform this action',
          'INSUFFICIENT_SCOPE',
        ),
      );
    }
    next();
  };
}

/** Typed access to the caller identity inside a route after requireAuth. */
export function getAuth(res: Response): AuthContext {
  const auth = res.locals.auth as AuthContext | undefined;
  if (!auth) throw new Error('getAuth() used on a route without requireAuth');
  return auth;
}
