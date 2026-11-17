/* eslint-disable no-process-env */
import logger from 'jet-logger';
import { z } from 'zod';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

// NOTE: These need to match the names of your ".env" files
export const NodeEnvs = {
  DEVELOPMENT: 'development',
  TEST: 'test',
  PRODUCTION: 'production',
} as const;
export type NodeEnvs = z.infer<typeof NodeEnvsEnum>;

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

const NodeEnvsEnum = z.enum(NodeEnvs, 'Not a valid node environment');

const emptyToUndefined = (v: unknown) => (v === '' ? undefined : v);

const EnvSchema = z.object({
  NODE_ENV: z
    .string()
    .transform((v) => v.toLowerCase())
    .pipe(NodeEnvsEnum),
  PORT: z.coerce.number().int().min(1).max(65535),
  TRUST_PROXY: z.coerce.number().int().min(0).default(0),

  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  DATABASE_AUTH_TOKEN: z.preprocess(emptyToUndefined, z.string().optional()),
  AUTO_SEED: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),

  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_ISSUER: z.string().default('jwallet-api'),
  JWT_AUDIENCE: z.string().default('jwallet-app'),
  ACCESS_TOKEN_TTL_SEC: z.coerce.number().int().min(60).default(900),
  REFRESH_TOKEN_TTL_SEC: z.coerce.number().int().min(300).default(604800),
  MAX_FAILED_LOGINS: z.coerce.number().int().min(1).default(5),
  LOGIN_LOCK_MINUTES: z.coerce.number().int().min(1).default(15),
  LOGIN_RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(10),
  LOGIN_RATE_LIMIT_WINDOW_SEC: z.coerce.number().int().min(1).default(900),
  REFRESH_RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(30),
});

// ===================== Validate Environment Variables ==================== //

function loadEnv() {
  const parsed = EnvSchema.safeParse(process.env);
  if (!parsed.success) {
    logger.err(
      'Invalid environment configuration:\n' + z.prettifyError(parsed.error),
    );
    throw parsed.error;
  }
  return parsed.data;
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export const Env = loadEnv();
