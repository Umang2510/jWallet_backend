import type { InStatement } from '@libsql/client';
import logger from 'jet-logger';
import { v7 as uuidv7 } from 'uuid';

import db from '#src/db/client.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export const AuditActions = {
  LOGIN_OK: 'LOGIN_OK',
  LOGIN_FAIL: 'LOGIN_FAIL',
  LOGIN_LOCKED: 'LOGIN_LOCKED',
  LOGIN_BLOCKED: 'LOGIN_BLOCKED',
  LOGIN_INACTIVE: 'LOGIN_INACTIVE',
  TOKEN_REFRESH: 'TOKEN_REFRESH',
  TOKEN_REFRESH_FAIL: 'TOKEN_REFRESH_FAIL',
  TOKEN_REUSE_DETECTED: 'TOKEN_REUSE_DETECTED',
  LOGOUT: 'LOGOUT',
  LOGOUT_ALL: 'LOGOUT_ALL',
  PIN_SET: 'PIN_SET',
  PIN_CHANGED: 'PIN_CHANGED',
  PIN_FAIL: 'PIN_FAIL',
  PIN_LOCKED: 'PIN_LOCKED',
  PIN_BLOCKED: 'PIN_BLOCKED',
  BIOMETRIC_ENROLLED: 'BIOMETRIC_ENROLLED',
  BIOMETRIC_REMOVED: 'BIOMETRIC_REMOVED',
  TRANSFER_CHALLENGE: 'TRANSFER_CHALLENGE',
  TRANSFER_OK: 'TRANSFER_OK',
  TRANSFER_REJECTED: 'TRANSFER_REJECTED',
  TRANSFER_REPLAYED: 'TRANSFER_REPLAYED',
} as const;
export type AuditAction = (typeof AuditActions)[keyof typeof AuditActions];

export interface AuditEntry {
  userId: string | null;
  action: AuditAction;
  ip?: string | null;
  deviceId?: string | null;
  requestId?: string | null;
  /** Never put passwords, PINs, tokens or keys in here. */
  metadata?: Record<string, unknown>;
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

function insertStmt(
  e: AuditEntry,
  now = new Date().toISOString(),
): InStatement {
  return {
    sql: `INSERT INTO audit_log (id, user_id, action, ip, device_id, request_id, metadata, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      uuidv7(),
      e.userId,
      e.action,
      e.ip ?? null,
      e.deviceId ?? null,
      e.requestId ?? null,
      e.metadata ? JSON.stringify(e.metadata) : null,
      now,
    ],
  };
}

/** Write an audit entry outside a batch. Failures are logged, never thrown. */
async function record(e: AuditEntry): Promise<void> {
  try {
    await db.execute(insertStmt(e));
  } catch (err) {
    logger.err(err, true);
  }
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  insertStmt,
  record,
} as const;
