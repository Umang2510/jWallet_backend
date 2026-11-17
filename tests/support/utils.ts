import type { Response } from 'supertest';

import type {
  ApiResponse,
  ErrorBody,
} from '#src/common/utils/response.utils.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export type TypedRes<T> = Omit<Response, 'body'> & { body: ApiResponse<T> };
export type TypedErrRes = TypedRes<ErrorBody>;
