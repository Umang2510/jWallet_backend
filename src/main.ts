import logger from 'jet-logger';

import { Env } from './common/constants/env.constants.ts';
import { startMaintenance } from './db/maintenance.ts';
import { runMigrations } from './db/migrate.ts';
import { seedIfEmpty } from './db/seed.ts';
import server from './server.ts';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

const SERVER_START_MESSAGE = `Express server started on port: ${Env.PORT}`;

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

// Bring the schema up to date (and seed demo data if enabled) before serving.
await runMigrations();
if (Env.AUTO_SEED) {
  await seedIfEmpty();
}

// Periodically delete expired nonces, challenges and idempotency records.
startMaintenance();

// Start the server
server.listen(Env.PORT, (err) => {
  if (!!err) {
    logger.err(err.message);
  } else {
    logger.info(SERVER_START_MESSAGE);
  }
});
