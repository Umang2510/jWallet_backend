import { Router } from 'express';

import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import { sendSuccess } from '#src/common/utils/response.utils.ts';
import Auth, { type LoginInput } from '#src/entities/Auth/index.ts';
import { loginRateLimiter } from '#src/middleware/rate-limiters.ts';
import { validateBody } from '#src/middleware/validate.ts';
import AuthService from '#src/services/AuthService.ts';

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

const router = Router();

// Public route: no access token required.
router.post(
  Paths.Auth.Login.PATH,
  loginRateLimiter,
  validateBody(Auth.Schemas.Login),
  async (req, res) => {
    const result = await AuthService.login(req.body as LoginInput, {
      ip: req.ip ?? null,
      userAgent: req.get('user-agent') ?? null,
      requestId: (res.locals.requestId as string | undefined) ?? null,
    });
    sendSuccess(res, HttpStatusCodes.OK, 'Login successful', result);
  },
);

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default router;
