import { Router } from 'express';

import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import { requestContext } from '#src/common/utils/request.utils.ts';
import { sendSuccess } from '#src/common/utils/response.utils.ts';
import Auth, {
  type LoginInput,
  type LogoutInput,
  type RefreshInput,
} from '#src/entities/Auth/index.ts';
import { getAuth, requireAuth } from '#src/middleware/auth.ts';
import {
  loginRateLimiter,
  refreshRateLimiter,
} from '#src/middleware/rate-limiters.ts';
import { validateBody } from '#src/middleware/validate.ts';
import AuthService from '#src/services/AuthService.ts';

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

const router = Router();

// Public: email + password -> access token + refresh token.
router.post(
  Paths.Auth.Login.PATH,
  loginRateLimiter,
  validateBody(Auth.Schemas.Login),
  async (req, res) => {
    const result = await AuthService.login(
      req.body as LoginInput,
      requestContext(req, res),
    );
    sendSuccess(res, HttpStatusCodes.OK, 'Login successful', result);
  },
);

// Public (authenticated by the refresh token itself): rotate token pair.
router.post(
  Paths.Auth.Refresh.PATH,
  refreshRateLimiter,
  validateBody(Auth.Schemas.Refresh),
  async (req, res) => {
    const result = await AuthService.refresh(
      req.body as RefreshInput,
      requestContext(req, res),
    );
    sendSuccess(res, HttpStatusCodes.OK, 'Token refreshed', result);
  },
);

// Protected: end this session (or all sessions with { allDevices: true }).
router.post(
  Paths.Auth.Logout.PATH,
  requireAuth,
  validateBody(Auth.Schemas.Logout),
  async (req, res) => {
    const result = await AuthService.logout(
      getAuth(res),
      req.body as LogoutInput,
      requestContext(req, res),
    );
    sendSuccess(
      res,
      HttpStatusCodes.OK,
      result.allDevices
        ? 'Logged out from all devices'
        : 'Logged out successfully',
      result,
    );
  },
);

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default router;
