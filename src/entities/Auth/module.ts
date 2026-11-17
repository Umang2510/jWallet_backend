import { z } from 'zod';

import { isP256PublicKeyBase64 } from '#src/common/utils/crypto.utils.ts';

// ========================================================================= //
//                                  SCHEMAS                                  //
// ========================================================================= //

/**
 * POST /api/v1/auth/login body. Unknown fields are rejected.
 * `deviceId` / `devicePublicKey` are optional so plain clients (Postman, cURL)
 * can log in; the mobile app always sends them to bind the session to the device.
 */
const LoginSchema = z
  .strictObject({
    email: z
      .string('Email is required')
      .trim()
      .toLowerCase()
      .max(254, 'Email is too long')
      .pipe(z.email('Enter a valid email address')),
    password: z
      .string('Password is required')
      .min(1, 'Password is required')
      .max(128, 'Password is too long'),
    deviceId: z.uuid('deviceId must be a UUID').optional(),
    devicePublicKey: z
      .string()
      .max(512, 'devicePublicKey is too long')
      .refine(
        isP256PublicKeyBase64,
        'devicePublicKey must be a base64 DER (SPKI) P-256 public key',
      )
      .optional(),
  })
  .refine((d) => !d.devicePublicKey || d.deviceId, {
    message: 'deviceId is required when devicePublicKey is provided',
    path: ['deviceId'],
  });

export type LoginInput = z.infer<typeof LoginSchema>;

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  Schemas: {
    Login: LoginSchema,
  },
} as const;
