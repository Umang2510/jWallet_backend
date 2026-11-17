import type { RequestHandler } from 'express';
import type { z } from 'zod';

import { ValidationError } from '#src/common/classes/route-errors.ts';

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/**
 * Validate (and normalise) `req.body` with a zod schema. On failure, responds
 * 400 with one `{ field, message }` entry per problem.
 */
export function validateBody(schema: z.ZodType): RequestHandler {
  return (req, _res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      const details = result.error.issues.map((issue) => ({
        field: issue.path.join('.') || 'body',
        message: issue.message,
      }));
      return next(new ValidationError(details));
    }
    req.body = result.data;
    next();
  };
}
