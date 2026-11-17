import { ep } from './helpers.ts';

// ========================================================================= //
//                                 CONSTANTS                                 //
// ========================================================================= //

const BASE = '/api/v1';

const AUTH_BASE = '/auth';
const AUTH = BASE + AUTH_BASE;

const USERS_BASE = '/users';
const USERS = BASE + USERS_BASE;

const WALLET_BASE = '/wallet';
const WALLET = BASE + WALLET_BASE;

const TXN_BASE = '/transactions';
const TXN = BASE + TXN_BASE;

const SECURITY_BASE = '/security';
const SECURITY = BASE + SECURITY_BASE;

const DEVICES_BASE = '/devices';
const DEVICES = BASE + DEVICES_BASE;

const Paths = {
  PATH: BASE,
  Auth: {
    PATH: AUTH_BASE,
    Login: ep(AUTH, '/login', 'POST'),
    Refresh: ep(AUTH, '/refresh', 'POST'),
    Logout: ep(AUTH, '/logout', 'POST'),
  },
  Users: {
    PATH: USERS_BASE,
    Profile: ep(USERS, '/profile', 'GET'),
  },
  Wallet: {
    PATH: WALLET_BASE,
    Balance: ep(WALLET, '/balance', 'GET'),
  },
  Security: {
    PATH: SECURITY_BASE,
    SetPin: ep(SECURITY, '/pin', 'POST'),
    ChangePin: ep(SECURITY, '/pin', 'PUT'),
  },
  Devices: {
    PATH: DEVICES_BASE,
    Biometric: ep(DEVICES, '/biometric', 'POST'),
  },
  Transactions: {
    PATH: TXN_BASE,
    List: ep(TXN, '/', 'GET'),
    Details: {
      ...ep(TXN, '/:id', 'GET'),
      format: (id: string) => `${TXN}/${encodeURIComponent(id)}`,
    },
  },
} as const;

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default Paths;
