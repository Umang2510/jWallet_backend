import { Router } from 'express';

import { ValidationError } from '#src/common/classes/route-errors.ts';
import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import { requestContext } from '#src/common/utils/request.utils.ts';
import { sendSuccess } from '#src/common/utils/response.utils.ts';
import Transaction, {
  type IdParam,
  type ListQuery,
} from '#src/entities/Transaction/index.ts';
import Transfer, {
  type ChallengeInput,
  type TransferInput,
} from '#src/entities/Transfer/index.ts';
import { getAuth, requireAuth, requireScope } from '#src/middleware/auth.ts';
import { transferRateLimiter } from '#src/middleware/rate-limiters.ts';
import {
  getValidated,
  validateBody,
  validateParams,
  validateQuery,
} from '#src/middleware/validate.ts';
import TransactionService from '#src/services/TransactionService.ts';
import TransferService from '#src/services/TransferService.ts';

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

// Transfer step 1: validate and get a one-time approval challenge.
router.post(
  Paths.Transactions.TransferChallenge.PATH,
  requireScope('txn:transfer'),
  transferRateLimiter,
  validateBody(Transfer.Schemas.Challenge),
  async (req, res) => {
    const result = await TransferService.createChallenge(
      getAuth(res),
      req.body as ChallengeInput,
      requestContext(req, res),
    );
    sendSuccess(
      res,
      HttpStatusCodes.CREATED,
      'Approve this transfer with your fingerprint or PIN',
      result,
    );
  },
);

// Transfer step 2: approved transfer (Idempotency-Key header required).
router.post(
  Paths.Transactions.Transfer.PATH,
  requireScope('txn:transfer'),
  transferRateLimiter,
  (req, res, next) => {
    const key = Transfer.Schemas.IdempotencyKey.safeParse(
      req.get('idempotency-key'),
    );
    if (!key.success) {
      return next(
        new ValidationError(
          [
            {
              field: 'Idempotency-Key',
              message: key.error.issues[0]?.message ?? 'Invalid',
            },
          ],
          'Idempotency-Key header is missing or invalid',
        ),
      );
    }
    res.locals.idempotencyKey = key.data;
    next();
  },
  validateBody(Transfer.Schemas.Transfer),
  async (req, res) => {
    const outcome = await TransferService.transfer(
      getAuth(res),
      req.body as TransferInput,
      res.locals.idempotencyKey as string,
      requestContext(req, res),
    );
    if (outcome.replayed) res.setHeader('Idempotent-Replayed', 'true');
    res.status(outcome.statusCode).json(outcome.response);
  },
);

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default router;
