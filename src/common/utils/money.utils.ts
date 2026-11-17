import { randomInt } from 'node:crypto';

// Money is stored and computed as integer paise. Conversion to rupees happens
// only at the API boundary.

/** 2545075 -> 25450.75 */
export function paiseToRupees(paise: number): number {
  if (!Number.isSafeInteger(paise)) {
    throw new TypeError(`Invalid paise amount: ${paise}`);
  }
  return paise / 100;
}

/** "4589" -> "XXXX XXXX 4589" */
export function maskAccountNumber(last4: string): string {
  return `XXXX XXXX ${last4}`;
}

/** "9876543210" -> "XXXXXX3210" */
export function maskMobile(mobile: string): string {
  return 'X'.repeat(Math.max(0, mobile.length - 4)) + mobile.slice(-4);
}

// No 0/O or 1/I so references are easy to read out on a support call.
const REF_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

/**
 * Public transaction reference: TXN + yyyymmdd (UTC) + 6 random characters,
 * e.g. TXN20261117K7Q2MX. Not sequential, so references can't be guessed or
 * used to estimate transaction volume.
 */
export function generateTxnReference(date = new Date()): string {
  const ymd = date.toISOString().slice(0, 10).replaceAll('-', '');
  let suffix = '';
  for (let i = 0; i < 6; i++) {
    suffix += REF_ALPHABET[randomInt(REF_ALPHABET.length)];
  }
  return `TXN${ymd}${suffix}`;
}
