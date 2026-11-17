import logger from 'jet-logger';
import fs from 'node:fs/promises';
import path from 'node:path';

import db, { asText } from './client.ts';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

const MIGRATIONS_DIR = path.join(import.meta.dirname, 'migrations');

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/**
 * Apply every `migrations/NNN_*.sql` file that hasn't run yet, in order.
 * Each file runs inside its own transaction together with its bookkeeping row,
 * so a failed migration leaves no partial schema behind.
 */
export async function runMigrations(): Promise<string[]> {
  await db.execute(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       id TEXT PRIMARY KEY,
       applied_at TEXT NOT NULL
     )`,
  );

  const applied = new Set(
    (await db.execute('SELECT id FROM schema_migrations')).rows.map((r) =>
      asText(r.id),
    ),
  );

  const files = (await fs.readdir(MIGRATIONS_DIR))
    .filter((f) => /^\d+_.+\.sql$/.test(f))
    .sort();

  const ran: string[] = [];
  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = await fs.readFile(path.join(MIGRATIONS_DIR, file), 'utf8');
    const now = new Date().toISOString();
    await db.executeMultiple(
      `BEGIN;\n${sql}\nINSERT INTO schema_migrations (id, applied_at) VALUES ('${file}', '${now}');\nCOMMIT;`,
    );
    logger.info(`Applied migration ${file}`);
    ran.push(file);
  }
  return ran;
}
