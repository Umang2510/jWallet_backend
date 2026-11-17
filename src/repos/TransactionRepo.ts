import type { InArgs, Row } from '@libsql/client';

import db, { asText, asTextOrNull } from '#src/db/client.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface TransactionRow {
  reference: string;
  type: 'CREDIT' | 'DEBIT';
  amountPaise: number;
  currency: string;
  counterpartyName: string;
  counterpartyMobileMasked: string | null;
  remarks: string | null;
  status: 'SUCCESS' | 'FAILED' | 'PENDING';
  createdAt: string;
}

export interface ListFilters {
  type?: 'CREDIT' | 'DEBIT' | undefined;
  status?: 'SUCCESS' | 'FAILED' | 'PENDING' | undefined;
  search?: string | undefined;
  fromIso?: string | undefined; // inclusive
  toIsoExclusive?: string | undefined;
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

const COLUMNS = `reference, type, amount_paise, currency, counterparty_name,
                 counterparty_mobile_masked, remarks, status, created_at`;

function toRow(r: Row): TransactionRow {
  return {
    reference: asText(r.reference),
    type: asText(r.type) as TransactionRow['type'],
    amountPaise: Number(r.amount_paise),
    currency: asText(r.currency),
    counterpartyName: asText(r.counterparty_name),
    counterpartyMobileMasked: asTextOrNull(r.counterparty_mobile_masked),
    remarks: asTextOrNull(r.remarks),
    status: asText(r.status) as TransactionRow['status'],
    createdAt: asText(r.created_at),
  };
}

/** Escape LIKE wildcards so user search text is matched literally. */
function likePattern(text: string): string {
  return `%${text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
}

/**
 * One page of the user's transactions, newest first, plus the total count.
 * Always scoped to `userId`; filters are bound parameters (no SQL injection).
 */
async function list(
  userId: string,
  f: ListFilters,
  page: number,
  limit: number,
): Promise<{ rows: TransactionRow[]; total: number }> {
  const where = ['user_id = ?'];
  const args: InArgs = [userId];

  if (f.type) {
    where.push('type = ?');
    args.push(f.type);
  }
  if (f.status) {
    where.push('status = ?');
    args.push(f.status);
  }
  if (f.search) {
    // SQLite LIKE is case-insensitive for ASCII.
    where.push(
      "(reference LIKE ? ESCAPE '\\' OR counterparty_name LIKE ? ESCAPE '\\')",
    );
    const p = likePattern(f.search);
    args.push(p, p);
  }
  if (f.fromIso) {
    where.push('created_at >= ?');
    args.push(f.fromIso);
  }
  if (f.toIsoExclusive) {
    where.push('created_at < ?');
    args.push(f.toIsoExclusive);
  }

  const whereSql = where.join(' AND ');
  const [count, page_] = await Promise.all([
    db.execute({
      sql: `SELECT COUNT(*) AS n FROM transactions WHERE ${whereSql}`,
      args,
    }),
    db.execute({
      sql: `SELECT ${COLUMNS} FROM transactions WHERE ${whereSql}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?`,
      args: [...args, limit, (page - 1) * limit],
    }),
  ]);

  return {
    rows: page_.rows.map(toRow),
    total: Number(count.rows[0]?.n ?? 0),
  };
}

/** One transaction by public reference — only if it belongs to `userId`. */
async function findByReference(
  userId: string,
  reference: string,
): Promise<TransactionRow | null> {
  const res = await db.execute({
    sql: `SELECT ${COLUMNS} FROM transactions WHERE reference = ? AND user_id = ?`,
    args: [reference, userId],
  });
  return res.rows[0] ? toRow(res.rows[0]) : null;
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  list,
  findByReference,
} as const;
