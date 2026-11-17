import db, { asText } from '#src/db/client.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface WalletRow {
  id: string;
  publicId: string;
  userId: string;
  currency: string;
  balancePaise: number;
  accountLast4: string;
  status: 'ACTIVE' | 'FROZEN';
  updatedAt: string;
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/** The caller's own wallet. Always looked up by the authenticated user id. */
async function findByUserId(userId: string): Promise<WalletRow | null> {
  const res = await db.execute({
    sql: `SELECT id, public_id, user_id, currency, balance_paise, account_last4,
                 status, updated_at
          FROM wallets WHERE user_id = ?`,
    args: [userId],
  });
  const r = res.rows[0];
  if (!r) return null;
  return {
    id: asText(r.id),
    publicId: asText(r.public_id),
    userId: asText(r.user_id),
    currency: asText(r.currency),
    balancePaise: Number(r.balance_paise),
    accountLast4: asText(r.account_last4),
    status: asText(r.status) as WalletRow['status'],
    updatedAt: asText(r.updated_at),
  };
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  findByUserId,
} as const;
