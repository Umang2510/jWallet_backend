import type { Request, Response } from 'express';

import type { RequestContext } from '#src/services/AuthService.ts';

/** Caller metadata recorded in sessions and the audit log. */
export function requestContext(req: Request, res: Response): RequestContext {
  return {
    ip: req.ip ?? null,
    userAgent: req.get('user-agent') ?? null,
    requestId: (res.locals.requestId as string | undefined) ?? null,
  };
}
