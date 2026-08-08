/**
 * earnmore — Expiry date generation (PCI-DSS v4.0 compliant)
 *
 * Derives a card expiry (MM/YY) that is:
 *  - Domain-separated from PAN generation via HmacDrbg context "earnmore:expiry"
 *    (no longer shares LCG state with PAN — cleaner and more secure)
 *  - Seeded from the same combinedHash produced during PAN generation
 *  - Month: 01-12  (unbiased, rejection-sampled)
 *  - Year:  currentYear + 4  to  currentYear + 7  (inclusive, unbiased)
 *
 * "Current date" is the moment generate() is called (card issuance time).
 */

import { HmacDrbg } from "./hash";

// Inclusive → range size = 4 (4,5,6,7)
const MIN_YEARS_AHEAD = 4;
const MAX_YEARS_AHEAD = 7;

/**
 * Generates a card expiry date in "MM/YY" format.
 *
 * Uses a fresh HmacDrbg seeded from combinedHash with context "earnmore:expiry",
 * fully independent from the PAN generation stream. No step-skipping needed.
 *
 * @param seedBuffer  The 32-byte SHA-256 combinedHash from PAN generation.
 */
export function generateExpiry(seedBuffer: Buffer): string {
  const drbg = new HmacDrbg(seedBuffer, "earnmore:expiry");
  const currentYear = new Date().getFullYear();
  const yearsRange = MAX_YEARS_AHEAD - MIN_YEARS_AHEAD + 1; // = 4
  const year = currentYear + MIN_YEARS_AHEAD + drbg.nextInt(yearsRange);
  const month = drbg.nextInt(12) + 1;

  const mm = String(month).padStart(2, "0");
  const yy = String(year).slice(-2);

  return `${mm}/${yy}`;
}

/**
 * Parses a "MM/YY" expiry string into its numeric components.
 * Throws if the format is invalid.
 */
export function parseExpiry(expiry: string): { month: number; year: number } {
  const match = /^(\d{2})\/(\d{2})$/.exec(expiry);
  if (!match) {
    throw new Error(`Invalid expiry format "${expiry}": expected "MM/YY".`);
  }
  const month = parseInt(match[1], 10);
  const year = 2000 + parseInt(match[2], 10);

  if (month < 1 || month > 12) {
    throw new Error(`Invalid expiry month "${match[1]}": must be 01-12.`);
  }

  return { month, year };
}
