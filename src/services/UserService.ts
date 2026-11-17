import { NotFoundError } from '#src/common/classes/route-errors.ts';
import type { AuthContext } from '#src/middleware/auth.ts';
import DeviceRepo from '#src/repos/DeviceRepo.ts';
import UserRepo from '#src/repos/UserRepo.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface ProfileResult {
  id: string;
  name: string;
  email: string;
  initials: string;
  memberSince: string;
  security: { pinSet: boolean; biometricEnrolled: boolean };
}

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/** "Demo User" -> "DU", "harshil" -> "H" */
export function initialsOf(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  const letters = parts.length > 1 ? [parts[0], parts.at(-1)] : [parts[0]];
  return letters
    .map((p) => p?.[0] ?? '')
    .join('')
    .toUpperCase();
}

/**
 * The caller's own profile. The user id comes only from the verified access
 * token, never from the request, so one user can't read another's profile.
 */
async function getProfile(auth: AuthContext): Promise<ProfileResult> {
  const [profile, pinSet, biometricEnrolled] = await Promise.all([
    UserRepo.findProfile(auth.userId),
    UserRepo.hasTransactionPin(auth.userId),
    auth.deviceId
      ? DeviceRepo.isBiometricEnrolled(auth.userId, auth.deviceId)
      : Promise.resolve(false),
  ]);
  if (!profile) throw new NotFoundError('User not found', 'USER_NOT_FOUND');

  return {
    id: profile.publicId,
    name: profile.name,
    email: profile.email,
    initials: initialsOf(profile.name),
    memberSince: profile.createdAt,
    security: { pinSet, biometricEnrolled },
  };
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  getProfile,
} as const;
