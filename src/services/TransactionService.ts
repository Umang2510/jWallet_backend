import { NotFoundError } from '#src/common/classes/route-errors.ts';
import {
  istDayStartIso,
  istNextDayStartIso,
} from '#src/common/utils/date.utils.ts';
import { paiseToRupees } from '#src/common/utils/money.utils.ts';
import type { ListQuery } from '#src/entities/Transaction/index.ts';
import type { AuthContext } from '#src/middleware/auth.ts';
import TransactionRepo, {
  type TransactionRow,
} from '#src/repos/TransactionRepo.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface TransactionListItem {
  id: string;
  type: 'CREDIT' | 'DEBIT';
  amount: number;
  currency: string;
  beneficiaryName: string;
  status: 'SUCCESS' | 'FAILED' | 'PENDING';
  createdAt: string;
}

export interface TransactionDetails extends TransactionListItem {
  mobileNumber: string | null;
  remarks: string | null;
}

export interface TransactionListResult {
  items: TransactionListItem[];
  pagination: {
    page: number;
    limit: number;
    totalItems: number;
    totalPages: number;
    hasNextPage: boolean;
  };
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

function toListItem(t: TransactionRow): TransactionListItem {
  return {
    id: t.reference,
    type: t.type,
    amount: paiseToRupees(t.amountPaise),
    currency: t.currency,
    beneficiaryName: t.counterpartyName,
    status: t.status,
    createdAt: t.createdAt,
  };
}

/** The caller's transactions, newest first, filtered and paginated. */
async function list(
  auth: AuthContext,
  q: ListQuery,
): Promise<TransactionListResult> {
  const { rows, total } = await TransactionRepo.list(
    auth.userId,
    {
      type: q.type,
      status: q.status,
      search: q.q,
      fromIso: q.from ? istDayStartIso(q.from) : undefined,
      toIsoExclusive: q.to ? istNextDayStartIso(q.to) : undefined,
    },
    q.page,
    q.limit,
  );
  const totalPages = Math.ceil(total / q.limit);
  return {
    items: rows.map(toListItem),
    pagination: {
      page: q.page,
      limit: q.limit,
      totalItems: total,
      totalPages,
      hasNextPage: q.page < totalPages,
    },
  };
}

/**
 * One of the caller's transactions. Someone else's transaction gives the same
 * 404 as a non-existent one, so references can't be probed.
 */
async function getDetails(
  auth: AuthContext,
  reference: string,
): Promise<TransactionDetails> {
  const t = await TransactionRepo.findByReference(auth.userId, reference);
  if (!t) {
    throw new NotFoundError('Transaction not found', 'TRANSACTION_NOT_FOUND');
  }
  return {
    ...toListItem(t),
    mobileNumber: t.counterpartyMobileMasked,
    remarks: t.remarks,
  };
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  list,
  getDetails,
} as const;
