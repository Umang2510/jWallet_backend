import type { RequestHandler, Response } from 'express';
import type { z } from 'zod';

import { ValidationError } from '#src/common/classes/route-errors.ts';

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

function toDetails(error: z.ZodError, fallback: string) {
  return error.issues.map((issue) => ({
    field: issue.path.join('.') || fallback,
    message: issue.message,
  }));
}

/**
 * Validate (and normalise) `req.body` with a zod schema. On failure, responds
 * 400 with one `{ field, message }` entry per problem.
 */
export function validateBody(schema: z.ZodType): RequestHandler {
  return (req, _res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      return next(new ValidationError(toDetails(result.error, 'body')));
    }
    req.body = result.data;
    next();
  };
}

/**
 * Validate the query string. Express 5's `req.query` is read-only, so the
 * parsed value is stored on `res.locals.query` (read it with getValidated).
 */
export function validateQuery(schema: z.ZodType): RequestHandler {
  return (req, res, next) => {
    const result = schema.safeParse(req.query);
    if (!result.success) {
      return next(new ValidationError(toDetails(result.error, 'query')));
    }
    res.locals.query = result.data;
    next();
  };
}

/** Validate route params; parsed value goes to `res.locals.params`. */
export function validateParams(schema: z.ZodType): RequestHandler {
  return (req, res, next) => {
    const result = schema.safeParse(req.params);
    if (!result.success) {
      return next(new ValidationError(toDetails(result.error, 'params')));
    }
    res.locals.params = result.data;
    next();
  };
}

/** Read a value stored by validateQuery / validateParams. */
export function getValidated<T>(res: Response, key: 'query' | 'params'): T {
  return res.locals[key] as T;
}
