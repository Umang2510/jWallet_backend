import { z } from 'zod';

import { isP256PublicKeyBase64 } from '#src/common/utils/crypto.utils.ts';

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/**
 * Reject PINs that are trivially guessable: all one digit (0000, 111111),
 * straight runs up or down (1234, 987654), or two repeated pairs (1212).
 */
export function isWeakPin(pin: string): boolean {
  if (/^(\d)\1+$/.test(pin)) return true;
  const digits = [...pin].map(Number);
  const steps = digits.slice(1).map((d, i) => d - digits[i]);
  if (steps.every((s) => s === 1) || steps.every((s) => s === -1)) return true;
  if (pin.length === 4 && pin.slice(0, 2) === pin.slice(2)) return true;
  if (pin.length === 6 && /^(\d\d)\1\1$/.test(pin)) return true;
  return false;
}

// ========================================================================= //
//                                  SCHEMAS                                  //
// ========================================================================= //

/** Any PIN being checked (format only — weak old PINs must still verify). */
const PinSchema = z
  .string('PIN is required')
  .regex(/^(\d{4}|\d{6})$/, 'PIN must be 4 or 6 digits');

/** A PIN being created: format + strength. */
const NewPinSchema = PinSchema.refine(
  (p) => !isWeakPin(p),
  'PIN is too easy to guess. Avoid repeated or sequential digits.',
);

/** POST /api/v1/security/pin */
const SetPinSchema = z.strictObject({ pin: NewPinSchema });

/** PUT /api/v1/security/pin */
const ChangePinSchema = z
  .strictObject({ currentPin: PinSchema, newPin: NewPinSchema })
  .refine((d) => d.currentPin !== d.newPin, {
    message: 'New PIN must be different from the current PIN',
    path: ['newPin'],
  });

/** POST /api/v1/devices/biometric */
const EnrollBiometricSchema = z.strictObject({
  publicKey: z
    .string('publicKey is required')
    .max(512, 'publicKey is too long')
    .refine(
      isP256PublicKeyBase64,
      'publicKey must be a base64 DER (SPKI) P-256 public key',
    ),
  pin: PinSchema,
});

export type SetPinInput = z.infer<typeof SetPinSchema>;
export type ChangePinInput = z.infer<typeof ChangePinSchema>;
export type EnrollBiometricInput = z.infer<typeof EnrollBiometricSchema>;

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  Schemas: {
    Pin: PinSchema,
    SetPin: SetPinSchema,
    ChangePin: ChangePinSchema,
    EnrollBiometric: EnrollBiometricSchema,
  },
} as const;
