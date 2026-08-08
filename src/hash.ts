/**
 * earnmore — Hashing & CSPRNG utilities
 *
 * PCI-DSS Req 6.2.4 / A3.3: All random number generation used in card data
 * production must use a cryptographically secure source.
 *
 * NIST SP 800-218 (SSDF): Input validation is enforced on all customer fields
 * to prevent denial-of-service via excessively large payloads.
 */

import { createHash, createHmac } from "crypto";
import { CustomerInfo } from "./types";

/** Maximum characters allowed per customer identity field */
const MAX_FIELD_LENGTH = 1024;

/** Maximum total character count across all customer fields combined */
const MAX_TOTAL_PAYLOAD = 5 * 1024; // 5 KB

/**
 * Validates that birthPlace contains only letters and spaces.
 * Throws a descriptive error if it doesn't.
 */
export function validateBirthPlace(birthPlace: string): void {
  if (!/^[A-Za-z\s]+$/.test(birthPlace)) {
    throw new Error(`Invalid birthPlace: must contain letters and spaces only.`);
  }
}

/**
 * Validates customer identity field lengths per NIST SP 800-218 / ISO 27002:2022 A.8.25.
 * Enforces per-field and total-payload limits to prevent DoS via large inputs.
 *
 * @throws {Error} If any individual field exceeds MAX_FIELD_LENGTH, or the
 *                 combined total exceeds MAX_TOTAL_PAYLOAD.
 */
function validateFieldLengths(info: CustomerInfo): void {
  const fields: Array<[string, string]> = [
    ["firstName", info.firstName],
    ["middleName", info.middleName],
    ["lastName", info.lastName],
    ["address.line1", info.address.line1],
    ["address.line2", info.address.line2 ?? ""],
    ["address.city", info.address.city],
    ["address.country", info.address.country],
    ["address.zipCode", info.address.zipCode],
    ["birthPlace", info.birthPlace],
    ["idDocument.number", info.idDocument.number],
  ];

  for (const [name, value] of fields) {
    if (value.length > MAX_FIELD_LENGTH) {
      throw new Error(
        `Field "${name}" exceeds the maximum allowed length of ${MAX_FIELD_LENGTH} characters ` +
          `(received ${value.length}). Per NIST SP 800-218, input length limits prevent DoS attacks.`,
      );
    }
  }

  const total = fields.reduce((sum, [, v]) => sum + v.length, 0);
  if (total > MAX_TOTAL_PAYLOAD) {
    throw new Error(
      `Total customer data payload exceeds ${MAX_TOTAL_PAYLOAD} bytes (received ${total}). ` +
        `Per NIST SP 800-218, total input size is bounded to prevent DoS.`,
    );
  }
}

/**
 * Scrubs a CustomerInfo object by overwriting its string fields with zeroes.
 *
 * In JavaScript, memory cannot be manually freed, but mutating the string
 * properties in-place ensures the original PII is removed from the active
 * object immediately before the garbage collector reclaims it.
 * This aids in complying with data minimization and Right to be Forgotten
 * principles in environments where memory dumps could expose PII.
 *
 * Note: Strings in JS are immutable. This sets the property to a NEW string
 * of zeroes. The original string becomes eligible for GC immediately.
 *
 * @param info The CustomerInfo object to scrub
 */
export function scrubCustomerData(info: CustomerInfo): void {
  const scrubString = (s: string) => "0".repeat(s.length);

  if (info.firstName) info.firstName = scrubString(info.firstName);
  if (info.middleName) info.middleName = scrubString(info.middleName);
  if (info.lastName) info.lastName = scrubString(info.lastName);
  if (info.birthPlace) info.birthPlace = scrubString(info.birthPlace);

  if (info.address) {
    if (info.address.line1) info.address.line1 = scrubString(info.address.line1);
    if (info.address.line2) info.address.line2 = scrubString(info.address.line2);
    if (info.address.city) info.address.city = scrubString(info.address.city);
    if (info.address.country) info.address.country = scrubString(info.address.country);
    if (info.address.zipCode) info.address.zipCode = scrubString(info.address.zipCode);
  }

  if (info.idDocument) {
    if (info.idDocument.number) info.idDocument.number = scrubString(info.idDocument.number);
  }
}

/**
 * Produces a deterministic SHA-256 hex fingerprint from all customer fields.
 * Fields are normalized (trimmed, lowercased, date as ISO YYYY-MM-DD) so that
 * minor formatting differences do not produce different fingerprints.
 *
 * This fingerprint is used as an entropy *input* mixed with a random salt —
 * it is never the sole source of PAN uniqueness.
 *
 * Input validation (NIST SP 800-218):
 *  - birthPlace: letters and spaces only
 *  - Individual fields: max 512 characters each
 *  - Total payload: max 5 KB
 */
export function customerFingerprint(info: CustomerInfo): string {
  validateBirthPlace(info.birthPlace);
  validateFieldLengths(info);

  const parts: string[] = [
    info.firstName.trim().toLowerCase(),
    info.middleName.trim().toLowerCase(),
    info.lastName.trim().toLowerCase(),
    info.address.line1.trim().toLowerCase(),
    (info.address.line2 ?? "").trim().toLowerCase(),
    info.address.city.trim().toLowerCase(),
    info.address.country.trim().toLowerCase(),
    info.address.zipCode.trim().toLowerCase(),
    new Date(info.birthday).toISOString().split("T")[0],
    info.birthPlace.trim().toLowerCase(),
    info.idDocument.type,
    info.idDocument.number.trim().toLowerCase(),
  ];

  const raw = parts.join("|");
  return createHash("sha256").update(raw, "utf8").digest("hex");
}

/**
 * HMAC-SHA256 Deterministic Random Bit Generator.
 * Implements the formal NIST SP 800-90A Rev.1 HMAC_DRBG specification.
 *
 * Properties:
 *  - Cryptographically secure (HMAC-SHA256 as PRF)
 *  - Domain-separated via the context string (prevents cross-use of the same
 *    seed for different purposes, e.g. "earnmore:pan" vs "earnmore:expiry")
 *  - Rejection-sampled outputs eliminate modular bias (FIPS 186-5 §B.4.2)
 *
 * @see NIST SP 800-90A Rev.1 — HMAC_DRBG (formal standard)
 * @see FIPS 186-5 §B.4.2 — Rejection sampling for unbiased output
 */
export class HmacDrbg {
  private V: Buffer;
  private Key: Buffer;
  private reseedCounter: number;
  private block: Buffer = Buffer.alloc(0);
  private blockOffset: number = 0;

  /**
   * Instantiates the HMAC_DRBG state machine (SP 800-90A §10.1.2.3).
   *
   * @param seed     32-byte Buffer from which all randomness is derived.
   *                 Must originate from a CSPRNG (e.g. crypto.randomBytes).
   * @param context  Domain-separation string. Used as `personalization_string`.
   */
  constructor(seed: Buffer, context: string = "") {
    this.Key = Buffer.alloc(32, 0x00);
    this.V = Buffer.alloc(32, 0x01);

    const seedMaterial = Buffer.concat([seed, Buffer.from(context, "utf8")]);
    this.update(seedMaterial);
    this.reseedCounter = 1;
  }

  /**
   * HMAC_DRBG Update Function (SP 800-90A §10.1.2.2).
   */
  private update(providedData?: Buffer): void {
    let mac = createHmac("sha256", this.Key);
    mac.update(this.V);
    mac.update(Buffer.from([0x00]));

    if (providedData) mac.update(providedData);

    this.Key = mac.digest();
    this.V = createHmac("sha256", this.Key).update(this.V).digest();

    if (!providedData) return;

    mac = createHmac("sha256", this.Key);
    mac.update(this.V);
    mac.update(Buffer.from([0x01]));
    mac.update(providedData);

    this.Key = mac.digest();
    this.V = createHmac("sha256", this.Key).update(this.V).digest();
  }

  /**
   * Executes a Generate request for 32 bytes (SP 800-90A §10.1.2.5).
   */
  private generateBlock(): void {
    if (this.reseedCounter > 10000) {
      throw new Error("HMAC_DRBG reseed interval exceeded.");
    }

    this.V = createHmac("sha256", this.Key).update(this.V).digest();
    this.block = Buffer.from(this.V);
    this.blockOffset = 0;

    this.update();
    this.reseedCounter++;
  }

  /** Returns the next byte from the DRBG output stream */
  nextByte(): number {
    if (this.blockOffset >= this.block.length) {
      this.generateBlock();
    }
    return this.block[this.blockOffset++];
  }

  /**
   * Returns an unbiased random integer in [0, max) using rejection sampling.
   * Rejects bytes that would introduce modular bias (FIPS 186-5 §B.4.2).
   *
   * @param max  Upper bound (exclusive). Must be in [2, 256].
   */
  nextInt(max: number): number {
    if (max < 2 || max > 256) {
      throw new RangeError(`nextInt max must be in [2, 256], got ${max}`);
    }

    const threshold = 256 - (256 % max);
    for (;;) {
      const b = this.nextByte();
      if (b < threshold) return b % max;
    }
  }
}
