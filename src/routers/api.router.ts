import { Router } from 'express';

import Paths from '#src/common/constants/Paths/index.ts';

import authRouter from './auth.router.ts';
import deviceRouter from './device.router.ts';
import securityRouter from './security.router.ts';
import transactionRouter from './transaction.router.ts';
import userRouter from './user.router.ts';
import walletRouter from './wallet.router.ts';

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

const apiRouter = Router();

apiRouter.use(Paths.Auth.PATH, authRouter);
apiRouter.use(Paths.Users.PATH, userRouter);
apiRouter.use(Paths.Wallet.PATH, walletRouter);
apiRouter.use(Paths.Transactions.PATH, transactionRouter);
apiRouter.use(Paths.Security.PATH, securityRouter);
apiRouter.use(Paths.Devices.PATH, deviceRouter);

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default apiRouter;
