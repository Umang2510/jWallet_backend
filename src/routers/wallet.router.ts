import { Router } from 'express';

import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import { sendSuccess } from '#src/common/utils/response.utils.ts';
import { getAuth, requireAuth, requireScope } from '#src/middleware/auth.ts';
import WalletService from '#src/services/WalletService.ts';

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

const router = Router();

// Every route in this router requires a valid session.
router.use(requireAuth);

router.get(
  Paths.Wallet.Balance.PATH,
  requireScope('wallet:read'),
  async (_req, res) => {
    const balance = await WalletService.getBalance(getAuth(res));
    sendSuccess(
      res,
      HttpStatusCodes.OK,
      'Wallet balance fetched successfully',
      balance,
    );
  },
);

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default router;
