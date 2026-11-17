import { rateLimit } from 'express-rate-limit';

import { TooManyRequestsError } from '#src/common/classes/route-errors.ts';
import { Env } from '#src/common/constants/env.constants.ts';

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

/**
 * Per-IP limit on login attempts (brute-force / credential-stuffing guard).
 * Works alongside the per-account lockout in AuthService.
 */
export const loginRateLimiter = rateLimit({
  windowMs: Env.LOGIN_RATE_LIMIT_WINDOW_SEC * 1000,
  limit: Env.LOGIN_RATE_LIMIT_MAX,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: (_req, _res, next) => {
    next(
      new TooManyRequestsError(
        'Too many login attempts. Please try again later.',
        'RATE_LIMITED',
      ),
    );
  },
});

/** Per-IP limit on transfer calls (challenge + transfer). */
export const transferRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: Env.TRANSFER_RATE_LIMIT_MAX,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: (_req, _res, next) => {
    next(
      new TooManyRequestsError(
        'Too many transfer requests. Please wait a minute.',
        'RATE_LIMITED',
      ),
    );
  },
});

/** Per-IP limit on token refreshes (stops refresh-token guessing/flooding). */
export const refreshRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Env.REFRESH_RATE_LIMIT_MAX,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: (_req, _res, next) => {
    next(
      new TooManyRequestsError(
        'Too many requests. Please try again later.',
        'RATE_LIMITED',
      ),
    );
  },
});
