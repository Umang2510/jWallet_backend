import { Router } from 'express';

import Paths from '#src/common/constants/Paths/index.ts';

import authRouter from './auth.router.ts';

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

const apiRouter = Router();

apiRouter.use(Paths.Auth.PATH, authRouter);

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default apiRouter;
