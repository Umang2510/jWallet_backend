import { Router } from 'express';

import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import { sendSuccess } from '#src/common/utils/response.utils.ts';
import Transaction, {
  type IdParam,
  type ListQuery,
} from '#src/entities/Transaction/index.ts';
import { getAuth, requireAuth, requireScope } from '#src/middleware/auth.ts';
import {
  getValidated,
  validateParams,
  validateQuery,
} from '#src/middleware/validate.ts';
import TransactionService from '#src/services/TransactionService.ts';

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

const router = Router();

// Every route in this router requires a valid session.
router.use(requireAuth);

// History: ?type=CREDIT|DEBIT&status=&q=&from=YYYY-MM-DD&to=YYYY-MM-DD&page=1&limit=20
router.get(
  Paths.Transactions.List.PATH,
  requireScope('txn:read'),
  validateQuery(Transaction.Schemas.ListQuery),
  async (_req, res) => {
    const result = await TransactionService.list(
      getAuth(res),
      getValidated<ListQuery>(res, 'query'),
    );
    sendSuccess(
      res,
      HttpStatusCodes.OK,
      result.items.length
        ? 'Transactions fetched successfully'
        : 'No transactions found',
      result,
    );
  },
);

// Details by public reference.
router.get(
  Paths.Transactions.Details.PATH,
  requireScope('txn:read'),
  validateParams(Transaction.Schemas.IdParam),
  async (_req, res) => {
    const { id } = getValidated<IdParam>(res, 'params');
    const details = await TransactionService.getDetails(getAuth(res), id);
    sendSuccess(
      res,
      HttpStatusCodes.OK,
      'Transaction details fetched successfully',
      details,
    );
  },
);

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default router;
