import logger from 'jet-logger';

import db from './client.ts';
import { runMigrations } from './migrate.ts';
import { seedDemoData } from './seed.ts';

// Usage: node --env-file=<env> src/db/cli.ts <migrate|seed|setup>

const command = process.argv[2];

try {
  switch (command) {
    case 'migrate': {
      const ran = await runMigrations();
      logger.info(ran.length ? `Done (${ran.length} applied)` : 'Up to date');
      break;
    }
    case 'seed':
      await seedDemoData();
      logger.info('Seed complete');
      break;
    case 'setup':
      await runMigrations();
      await seedDemoData();
      logger.info('Database ready');
      break;
    default:
      logger.err('Usage: src/db/cli.ts <migrate|seed|setup>');
      process.exitCode = 1;
  }
} catch (err) {
  logger.err(err, true);
  process.exitCode = 1;
} finally {
  db.close();
}
