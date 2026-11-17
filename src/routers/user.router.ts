import { Router } from 'express';

import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import { sendSuccess } from '#src/common/utils/response.utils.ts';
import { getAuth, requireAuth, requireScope } from '#src/middleware/auth.ts';
import UserService from '#src/services/UserService.ts';

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

const router = Router();

// Every route in this router requires a valid session.
router.use(requireAuth);

router.get(
  Paths.Users.Profile.PATH,
  requireScope('profile:read'),
  async (_req, res) => {
    const profile = await UserService.getProfile(getAuth(res));
    sendSuccess(
      res,
      HttpStatusCodes.OK,
      'Profile fetched successfully',
      profile,
    );
  },
);

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default router;
