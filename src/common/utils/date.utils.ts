import { z } from 'zod';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export type ISOString =
  `${number}-${number}-${number}T${number}:${number}:${number}${string}`;

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

export const ISOStringSchema = z.iso
  .datetime()
  .transform((value) => value as ISOString);

// ========================================================================= //
//                                 FUNCTIONS                                 //
// ========================================================================= //

/**
 * Return the current-date (or a provided date) as an ISOString.
 */
export function getISOString(date = new Date()): ISOString {
  return date.toISOString() as ISOString;
}

/** Business days are calendar days in India time. */
const IST_OFFSET = '+05:30';
const IST_OFFSET_MS = 5.5 * 3_600_000;

/** Start of a calendar day (YYYY-MM-DD) in IST, as a UTC ISO string. */
export function istDayStartIso(ymd: string): string {
  return new Date(`${ymd}T00:00:00${IST_OFFSET}`).toISOString();
}

/** Start of the day after `ymd` in IST (exclusive upper bound). */
export function istNextDayStartIso(ymd: string): string {
  const d = new Date(`${ymd}T00:00:00${IST_OFFSET}`);
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString();
}

/** Today's date in IST as YYYY-MM-DD. */
export function istToday(now = Date.now()): string {
  return new Date(now + IST_OFFSET_MS).toISOString().slice(0, 10);
}
