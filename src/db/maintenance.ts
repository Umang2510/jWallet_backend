import logger from 'jet-logger';

import db from './client.ts';

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

const DAY_MS = 86_400_000;

/**
 * Delete short-lived security records that are no longer needed:
 * replay nonces, old transfer challenges, idempotency results older than 24h
 * (clients only retry within minutes), and sessions dead for 30+ days.
 */
export async function purgeExpired(now = Date.now()): Promise<void> {
  const iso = (ms: number) => new Date(ms).toISOString();
  await db.batch(
    [
      {
        sql: 'DELETE FROM request_nonces WHERE expires_at < ?',
        args: [iso(now)],
      },
      {
        sql: 'DELETE FROM transfer_challenges WHERE expires_at < ?',
        args: [iso(now - DAY_MS)],
      },
      {
        sql: 'DELETE FROM idempotency_keys WHERE created_at < ?',
        args: [iso(now - DAY_MS)],
      },
      {
        sql: `DELETE FROM sessions
              WHERE expires_at < ? AND id NOT IN (SELECT session_id FROM transfer_challenges)`,
        args: [iso(now - 30 * DAY_MS)],
      },
    ],
    'write',
  );
}

/** Run purgeExpired now and every `intervalMs` (doesn't keep the process alive). */
export function startMaintenance(intervalMs = 10 * 60_000): void {
  const run = (): void => {
    purgeExpired().catch((err: unknown) => logger.err(err, true));
  };
  run();
  setInterval(run, intervalMs).unref();
}
