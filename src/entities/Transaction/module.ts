import { z } from 'zod';

// ========================================================================= //
//                                  SCHEMAS                                  //
// ========================================================================= //

const emptyToUndefined = (v: unknown) => (v === '' ? undefined : v);
const upper = (v: unknown) => (typeof v === 'string' ? v.toUpperCase() : v);

/**
 * GET /api/v1/transactions query string. Every value must appear at most once
 * (repeated keys arrive as arrays and are rejected). Unknown keys are rejected.
 * Dates are calendar days in India time (IST); `to` is inclusive.
 */
const ListQuerySchema = z
  .strictObject({
    type: z.preprocess(
      (v) => upper(emptyToUndefined(v)),
      z.enum(['CREDIT', 'DEBIT'], 'type must be CREDIT or DEBIT').optional(),
    ),
    status: z.preprocess(
      (v) => upper(emptyToUndefined(v)),
      z
        .enum(
          ['SUCCESS', 'FAILED', 'PENDING'],
          'status must be SUCCESS, FAILED or PENDING',
        )
        .optional(),
    ),
    q: z.preprocess(
      emptyToUndefined,
      z
        .string('q must be a single value')
        .trim()
        .min(1)
        .max(50, 'Search text is too long (max 50 characters)')
        .optional(),
    ),
    from: z.preprocess(
      emptyToUndefined,
      z.iso.date('from must be a date (YYYY-MM-DD)').optional(),
    ),
    to: z.preprocess(
      emptyToUndefined,
      z.iso.date('to must be a date (YYYY-MM-DD)').optional(),
    ),
    page: z.preprocess(
      emptyToUndefined,
      z.coerce
        .number('page must be a number')
        .int('page must be a whole number')
        .min(1, 'page must be at least 1')
        .max(10_000, 'page is too large')
        .default(1),
    ),
    limit: z.preprocess(
      emptyToUndefined,
      z.coerce
        .number('limit must be a number')
        .int('limit must be a whole number')
        .min(1, 'limit must be at least 1')
        .max(50, 'limit can be at most 50')
        .default(20),
    ),
  })
  .refine((d) => !d.from || !d.to || d.from <= d.to, {
    message: 'from must be on or before to',
    path: ['from'],
  });

/** :id route param — the public transaction reference (case-insensitive). */
const IdParamSchema = z.object({
  id: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9-]{1,40}$/, 'Invalid transaction id')
    .transform((v) => v.toUpperCase()),
});

export type ListQuery = z.infer<typeof ListQuerySchema>;
export type IdParam = z.infer<typeof IdParamSchema>;

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  Schemas: {
    ListQuery: ListQuerySchema,
    IdParam: IdParamSchema,
  },
} as const;
