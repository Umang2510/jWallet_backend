import { before } from 'node:test';
import supertest, { type Test } from 'supertest';
import type TestAgent from 'supertest/lib/agent.js';

import { runMigrations } from '#src/db/migrate.ts';
import { resetAllData } from '#src/db/seed.ts';
import app from '#src/server.ts';

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

let agent: TestAgent<Test>;

before(async () => {
  agent = supertest.agent(app);
  await runMigrations();
  await resetAllData();
});

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export { agent };
