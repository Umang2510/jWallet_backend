import { z } from 'zod';

import { isP256PublicKeyBase64 } from '#src/common/utils/crypto.utils.ts';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

/**
 * Message a device-bound client signs (with its Keystore device key) to prove
 * possession when refreshing: `JWALLET-REFRESH\n<refreshToken>\n<timestamp>`.
 */
export function refreshProofMessage(refreshToken: string, timestamp: number) {
  return `JWALLET-REFRESH\n${refreshToken}\n${timestamp}`;
}

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

/**
 * POST /api/v1/auth/refresh body.
 * Sessions bound to a device key must also send `timestamp` (epoch ms) and
 * `signature` (base64 DER ECDSA-SHA256 over refreshProofMessage()).
 */
const RefreshSchema = z
  .strictObject({
    refreshToken: z
      .string('refreshToken is required')
      .regex(/^rt_[A-Za-z0-9_-]{43}$/, 'refreshToken is malformed'),
    deviceId: z.uuid('deviceId must be a UUID').optional(),
    timestamp: z
      .number('timestamp must be epoch milliseconds')
      .int('timestamp must be epoch milliseconds')
      .positive()
      .optional(),
    signature: z
      .string()
      .max(200, 'signature is too long')
      .regex(/^[A-Za-z0-9+/]+={0,2}$/, 'signature must be base64')
      .optional(),
  })
  .refine((d) => !d.signature || d.timestamp !== undefined, {
    message: 'timestamp is required when signature is provided',
    path: ['timestamp'],
  });

/** POST /api/v1/auth/logout body (optional — an empty/missing body is fine). */
const LogoutSchema = z.preprocess(
  (v) => v ?? {},
  z.strictObject({
    allDevices: z.boolean('allDevices must be true or false').default(false),
  }),
);

export type LoginInput = z.infer<typeof LoginSchema>;
export type RefreshInput = z.infer<typeof RefreshSchema>;
export type LogoutInput = z.infer<typeof LogoutSchema>;

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  Schemas: {
    Login: LoginSchema,
    Refresh: RefreshSchema,
    Logout: LogoutSchema,
  },
} as const;
