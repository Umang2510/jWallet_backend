import { z } from 'zod';

import { sha256Hex } from '#src/common/utils/crypto.utils.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

/** A transfer request after validation and normalisation. */
export interface TransferPayload {
  beneficiaryName: string;
  mobileNumber: string;
  amountPaise: number;
  remarks: string | null;
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/** Rupees (max 2 decimals) -> integer paise, or null if not representable. */
export function rupeesToPaise(amount: number): number | null {
  if (!Number.isFinite(amount)) return null;
  const paise = Math.round(amount * 100);
  // Reject amounts with more than 2 decimals (e.g. 10.005).
  if (Math.abs(amount * 100 - paise) > 1e-6) return null;
  return Number.isSafeInteger(paise) ? paise : null;
}

/**
 * Stable SHA-256 of the money-relevant fields. Binds a challenge to exactly
 * what the user approved, and identifies the request for idempotency.
 */
export function transferHash(p: TransferPayload): string {
  return sha256Hex(
    JSON.stringify([
      p.beneficiaryName,
      p.mobileNumber,
      p.amountPaise,
      p.remarks ?? '',
    ]),
  );
}

/** Exact text the device's biometric key must sign to approve a transfer. */
export function transferSigningPayload(
  challengeId: string,
  nonce: string,
  payloadHash: string,
): string {
  return `JWALLET-TRANSFER\n${challengeId}\n${nonce}\n${payloadHash}`;
}

// ========================================================================= //
//                                  SCHEMAS                                  //
// ========================================================================= //

const TransferFields = {
  beneficiaryName: z
    .string('Beneficiary name is required')
    .trim()
    .transform((v) => v.replace(/\s+/g, ' '))
    .pipe(
      z
        .string()
        .min(1, 'Beneficiary name is required')
        .max(100, 'Beneficiary name is too long')
        .regex(
          /^[\p{L}][\p{L} .'-]*$/u,
          "Beneficiary name can only contain letters, spaces, . ' and -",
        ),
    ),
  mobileNumber: z
    .string('Mobile number is required')
    .trim()
    .regex(/^[6-9]\d{9}$/, 'Enter a valid 10-digit mobile number'),
  amount: z
    .number('Amount must be a number')
    .positive('Amount must be greater than zero'),
  remarks: z
    .string('Remarks must be text')
    .trim()
    .max(100, 'Remarks can be at most 100 characters')
    // eslint-disable-next-line no-control-regex
    .regex(/^[^\u0000-\u001f\u007f]*$/, 'Remarks contain invalid characters')
    .nullish()
    .transform((v) => (v ? v : null)),
};

/** Turn the validated amount into paise, rejecting > 2 decimals. */
function withPaise<T extends { amount: number }>(
  d: T,
  ctx: z.RefinementCtx,
): Omit<T, 'amount'> & { amountPaise: number } {
  const amountPaise = rupeesToPaise(d.amount);
  if (amountPaise === null) {
    ctx.addIssue({
      code: 'custom',
      path: ['amount'],
      message: 'Amount can have at most 2 decimal places',
    });
    return z.NEVER;
  }
  const { amount: _amount, ...rest } = d;
  return { ...rest, amountPaise };
}

/** POST /api/v1/transactions/transfer/challenge */
const ChallengeSchema = z.strictObject(TransferFields).transform(withPaise);

const ApprovalSchema = z.discriminatedUnion(
  'method',
  [
    z.strictObject({
      method: z.literal('BIOMETRIC'),
      signature: z
        .string('signature is required')
        .max(200, 'signature is too long')
        .regex(/^[A-Za-z0-9+/]+={0,2}$/, 'signature must be base64'),
    }),
    z.strictObject({
      method: z.literal('PIN'),
      pin: z
        .string('PIN is required')
        .regex(/^(\d{4}|\d{6})$/, 'PIN must be 4 or 6 digits'),
    }),
  ],
  'approval.method must be BIOMETRIC or PIN',
);

/** POST /api/v1/transactions/transfer */
const TransferSchema = z
  .strictObject({
    ...TransferFields,
    challengeId: z.uuid('challengeId is required'),
    approval: ApprovalSchema,
  })
  .transform(withPaise);

/** Idempotency-Key header. */
const IdempotencyKeySchema = z
  .string('Idempotency-Key header is required')
  .regex(
    /^[A-Za-z0-9_-]{8,64}$/,
    'Idempotency-Key must be 8-64 characters (letters, digits, - or _)',
  );

export type ChallengeInput = z.infer<typeof ChallengeSchema>;
export type TransferInput = z.infer<typeof TransferSchema>;
export type Approval = z.infer<typeof ApprovalSchema>;

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  Schemas: {
    Challenge: ChallengeSchema,
    Transfer: TransferSchema,
    IdempotencyKey: IdempotencyKeySchema,
  },
} as const;
