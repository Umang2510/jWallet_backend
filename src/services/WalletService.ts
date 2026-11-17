import { NotFoundError } from '#src/common/classes/route-errors.ts';
import {
  maskAccountNumber,
  paiseToRupees,
} from '#src/common/utils/money.utils.ts';
import type { AuthContext } from '#src/middleware/auth.ts';
import WalletRepo from '#src/repos/WalletRepo.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface BalanceResult {
  walletId: string;
  currency: string;
  availableBalance: number;
  maskedAccountNumber: string;
  status: 'ACTIVE' | 'FROZEN';
  updatedAt: string;
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/**
 * The caller's authoritative balance, read fresh from the database on every
 * call (never cached). Only the last 4 digits of the account ever leave the server.
 */
async function getBalance(auth: AuthContext): Promise<BalanceResult> {
  const wallet = await WalletRepo.findByUserId(auth.userId);
  if (!wallet) throw new NotFoundError('Wallet not found', 'WALLET_NOT_FOUND');

  return {
    walletId: wallet.publicId,
    currency: wallet.currency,
    availableBalance: paiseToRupees(wallet.balancePaise),
    maskedAccountNumber: maskAccountNumber(wallet.accountLast4),
    status: wallet.status,
    updatedAt: wallet.updatedAt,
  };
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  getBalance,
} as const;
