import type { Response } from 'express';

import type { FieldError } from '#src/common/classes/route-errors.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

/**
 * Every API response — success or error — uses this envelope:
 * `{ meta: { statusCode, message }, body: { ... } }`
 */
export interface ApiResponse<T> {
  meta: { statusCode: number; message: string };
  body: T;
}

export interface ErrorBody {
  errorCode: string;
  details?: FieldError[];
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

export function sendSuccess<T>(
  res: Response,
  statusCode: number,
  message: string,
  body: T,
): void {
  const payload: ApiResponse<T> = { meta: { statusCode, message }, body };
  res.status(statusCode).json(payload);
}

export function sendError(
  res: Response,
  statusCode: number,
  message: string,
  errorCode: string,
  details?: FieldError[],
): void {
  const body: ErrorBody = details?.length
    ? { errorCode, details }
    : { errorCode };
  const payload: ApiResponse<ErrorBody> = {
    meta: { statusCode, message },
    body,
  };
  res.status(statusCode).json(payload);
}
