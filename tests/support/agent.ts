import { before } from 'node:test';
import supertest from 'supertest';

import { runMigrations } from '#src/db/migrate.ts';
import { resetAllData } from '#src/db/seed.ts';
import app from '#src/server.ts';

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

const agent = supertest.agent(app);

/**
 * Fresh schema + seed data, started once when this module is imported.
 * node:test does not wait for one root `before` hook to finish before running
 * the next, so any test file with its own `before` must `await dbReady` first.
 */
const dbReady: Promise<void> = (async () => {
  await runMigrations();
  await resetAllData();
})();

before(() => dbReady);

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export { agent, dbReady };
