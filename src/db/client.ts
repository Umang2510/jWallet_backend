import { type Client, createClient, type Value } from '@libsql/client';
import fs from 'node:fs';
import path from 'node:path';

import { Env } from '#src/common/constants/env.constants.ts';

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/**
 * Local `file:` URLs need their directory to exist before libSQL opens them.
 */
function ensureLocalDir(url: string): void {
  if (!url.startsWith('file:')) return;
  const filePath = url.slice('file:'.length);
  if (!filePath || filePath === ':memory:') return;
  fs.mkdirSync(path.dirname(path.resolve(filePath)), { recursive: true });
}

function createDb(): Client {
  ensureLocalDir(Env.DATABASE_URL);
  return createClient({
    url: Env.DATABASE_URL,
    ...(Env.DATABASE_AUTH_TOKEN ? { authToken: Env.DATABASE_AUTH_TOKEN } : {}),
  });
}

/** Read a TEXT column; throws if the column holds something unexpected. */
export function asText(v: Value | undefined): string {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'bigint') return v.toString();
  throw new TypeError(`Expected a text column, got ${typeof v}`);
}

/** Read a nullable TEXT column. */
export function asTextOrNull(v: Value | undefined): string | null {
  return v === null || v === undefined ? null : asText(v);
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

/** Shared libSQL client: a local SQLite file in dev/test, Turso when hosted. */
const db = createDb();

export default db;
