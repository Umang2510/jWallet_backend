import { ep } from './helpers.ts';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

const BASE = '/api/v1';
const AUTH_BASE = '/auth';
const AUTH = BASE + AUTH_BASE;

const Paths = {
  PATH: BASE,
  Auth: {
    PATH: AUTH_BASE,
    Login: ep(AUTH, '/login', 'POST'),
  },
} as const;

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default Paths;
