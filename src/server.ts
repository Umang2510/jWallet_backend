import express, {
  type NextFunction,
  type Request,
  type Response,
} from 'express';
import helmet from 'helmet';
import logger from 'jet-logger';
import morgan from 'morgan';
import { randomUUID } from 'node:crypto';

import { RouteError } from '#src/common/classes/route-errors.ts';
import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import { sendError, sendSuccess } from '#src/common/utils/response.utils.ts';
import { e2eEncryption } from '#src/middleware/e2e-encryption.ts';
import BaseRouter from '#src/routers/api.router.ts';

import { Env, NodeEnvs } from './common/constants/env.constants.ts';

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

const app = express();

// Correct client IPs (rate limiting, audit log) behind Render's proxy.
app.set('trust proxy', Env.TRUST_PROXY);

// =============================== Middleware ============================== //

// Security headers (HSTS, no sniffing, frame denial, no X-Powered-By, ...)
app.use(helmet());

// Request ID: echoed back and stored in the audit log for tracing.
app.use((req, res, next) => {
  const incoming = req.get('x-request-id');
  const id =
    incoming && /^[A-Za-z0-9-]{8,64}$/.test(incoming) ? incoming : randomUUID();
  res.locals.requestId = id;
  res.setHeader('X-Request-Id', id);
  next();
});

// JSON only, small bodies.
app.use(express.json({ limit: '10kb' }));

// Show routes called in console during development
if (Env.NODE_ENV === NodeEnvs.DEVELOPMENT) {
  app.use(morgan('dev'));
}

// Financial data must never be cached by clients or proxies.
app.use(Paths.PATH, (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// Optional end-to-end payload encryption (the mobile app always uses it).
app.use(Paths.PATH, e2eEncryption);

// ================================= Routes ================================ //

app.get('/health', (_req, res) => {
  sendSuccess(res, HttpStatusCodes.OK, 'OK', { status: 'up' });
});

// Add APIs, must be after middleware
app.use(Paths.PATH, BaseRouter);

// Unknown routes
app.use((_req, _res, next) => {
  next(
    new RouteError(
      HttpStatusCodes.NOT_FOUND,
      'Route not found',
      'ROUTE_NOT_FOUND',
    ),
  );
});

// ============================== Error handler ============================ //

// `_next` must stay: Express only treats 4-arg middleware as an error handler.
app.use((err: Error, _: Request, res: Response, _next: NextFunction) => {
  if (err instanceof RouteError) {
    return sendError(res, err.status, err.message, err.errorCode, err.details);
  }
  // Body-parser errors are client errors; don't expose the rejected body.
  if ('type' in err) {
    if (err.type === 'entity.parse.failed') {
      return sendError(
        res,
        HttpStatusCodes.BAD_REQUEST,
        'Invalid JSON',
        'INVALID_JSON',
      );
    }
    if (err.type === 'entity.too.large') {
      return sendError(
        res,
        HttpStatusCodes.PAYLOAD_TOO_LARGE,
        'Request body too large',
        'PAYLOAD_TOO_LARGE',
      );
    }
  }
  if (Env.NODE_ENV !== NodeEnvs.TEST) {
    logger.err(err, true);
  }
  // Never leak internals (stack traces, SQL) to the client.
  return sendError(
    res,
    HttpStatusCodes.INTERNAL_SERVER_ERROR,
    'Something went wrong. Please try again.',
    'INTERNAL_ERROR',
  );
});

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default app;
