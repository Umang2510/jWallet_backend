import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface FieldError {
  field: string;
  message: string;
}

// ========================================================================= //
//                                  CLASSES                                  //
// ========================================================================= //

/**
 * Error with an HTTP status, a client-safe message and a stable machine-readable
 * `errorCode` the app can branch on. `details` (optional) is sent to the client.
 */
export class RouteError extends Error {
  public status: HttpStatusCodes;
  public errorCode: string;
  public details?: FieldError[];

  public constructor(
    status: HttpStatusCodes,
    message: string,
    errorCode: string,
    details?: FieldError[],
  ) {
    super(message);
    this.status = status;
    this.errorCode = errorCode;
    this.details = details;
  }
}

export class ValidationError extends RouteError {
  public constructor(details: FieldError[], message = 'Invalid request data') {
    super(HttpStatusCodes.BAD_REQUEST, message, 'VALIDATION_ERROR', details);
  }
}

export class UnauthorizedError extends RouteError {
  public constructor(message: string, errorCode = 'UNAUTHORIZED') {
    super(HttpStatusCodes.UNAUTHORIZED, message, errorCode);
  }
}

export class ForbiddenError extends RouteError {
  public constructor(message: string, errorCode = 'FORBIDDEN') {
    super(HttpStatusCodes.FORBIDDEN, message, errorCode);
  }
}

export class NotFoundError extends RouteError {
  public constructor(message: string, errorCode = 'NOT_FOUND') {
    super(HttpStatusCodes.NOT_FOUND, message, errorCode);
  }
}

export class TooManyRequestsError extends RouteError {
  public constructor(message: string, errorCode = 'TOO_MANY_REQUESTS') {
    super(HttpStatusCodes.TOO_MANY_REQUESTS, message, errorCode);
  }
}
