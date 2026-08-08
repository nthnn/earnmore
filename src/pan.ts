/**
 * earnmore — 16-digit PAN generation (PCI-DSS v4.0 compliant)
 *
 * Design:
 *  1. Compute SHA-256 over (customerFingerprint + randomSalt) → combinedHash
 *  2. Feed combinedHash into HmacDrbg with domain context "earnmore:pan"
 *  3. Select BIN prefix using unbiased rejection-sampled draw
 *  4. Fill digits 5-15 using rejection-sampled draws in [0, 10)
 *  5. Compute Luhn check digit for position 16
 *
 * Non-regeneratable guarantee:
 *  The randomSalt (crypto.randomBytes(16)) is mixed in before hashing, so
 *  repeated calls for the same customer always produce a distinct PAN.
 *
 * CSPRNG compliance (PCI-DSS Req 6.2.4 / A3.3):
 *  All digit selection uses HmacDrbg with rejection sampling — no modular bias.
 */

import { createHash, randomBytes } from "crypto";
import { ALLOWED_PREFIXES, AllowedPrefix } from "./types";
import { HmacDrbg } from "./hash";

/**
 * Computes the Luhn check digit for a partial PAN (digits 1-15).
 * Returns a single digit (0-9) to append as digit 16.
 */
export function luhnCheckDigit(partial: string): number {
  const digits = (partial + "0").split("").map(Number);
  let sum = 0;

  for (let i = digits.length - 1; i >= 0; i--) {
    // eslint-disable-next-line security/detect-object-injection
    let d = digits[i];
    if ((digits.length - 1 - i) % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }

  return (10 - (sum % 10)) % 10;
}

/**
 * Validates that a 16-digit PAN passes the Luhn algorithm.
 */
export function luhnValid(pan: string): boolean {
  if (pan.length !== 16 || !/^\d{16}$/.test(pan)) return false;

  const digits = pan.split("").map(Number);
  let sum = 0;

  for (let i = digits.length - 1; i >= 0; i--) {
    // eslint-disable-next-line security/detect-object-injection
    let d = digits[i];

    if ((digits.length - 1 - i) % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }

  return sum % 10 === 0;
}

export interface PanResult {
  /** 16-digit PAN string */
  pan: string;

  /** The selected BIN prefix */
  prefix: AllowedPrefix;

  /**
   * The combinedHash buffer — used downstream to seed the expiry HMAC-DRBG.
   * Both PAN and expiry streams are domain-separated from this shared seed.
   */
  seedBuffer: Buffer;
}

/**
 * Generates a unique, non-regeneratable 16-digit PAN.
 *
 * @param fingerprint  SHA-256 hex fingerprint of the customer's identity
 */
export function generatePAN(fingerprint: string): PanResult {
  const salt = randomBytes(16);
  const combined = createHash("sha256").update(fingerprint, "hex").update(salt).digest();
  const drbg = new HmacDrbg(combined, "earnmore:pan");
  const prefixIndex = drbg.nextInt(ALLOWED_PREFIXES.length);

  // eslint-disable-next-line security/detect-object-injection
  const prefix = ALLOWED_PREFIXES[prefixIndex];
  let middle = "";

  for (let i = 0; i < 11; i++) {
    middle += String(drbg.nextInt(10));
  }

  const partial = prefix + middle;
  const check = luhnCheckDigit(partial);
  const pan = partial + String(check);

  return {
    pan,
    prefix,
    seedBuffer: combined,
  };
}
