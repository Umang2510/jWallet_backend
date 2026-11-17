import { Router } from 'express';

import Paths from '#src/common/constants/Paths/index.ts';

import authRouter from './auth.router.ts';
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

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default apiRouter;
