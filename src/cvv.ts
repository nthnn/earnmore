/**
 * earnmore — CVV/CVC generation, validation, and Key Check Value (KCV)
 *
 * CVV algorithm (NIST SP 800-57 / ISO 11568-1 — key versioning):
 *   message    = keyId + "|" + pan + "|" + expiry
 *   derivedKey = PBKDF2-SHA256(passkey, "earnmore:cvv:v1", iterations, 32 bytes)
 *   hmac       = HMAC-SHA256(derivedKey, message)
 *   cvv        = parseInt(hmac_hex[0..7], 16) % 10000  → zero-padded to 4 digits
 *
 * The `keyId` in the message enables key rotation without full card reissuance:
 *   - Issue cards under keyId "k1" with passkey A
 *   - Rotate to keyId "k2" with passkey B
 *   - Validate old cards: EarnmoreClient(passkeyA, { keyId: "k1" }).validateCvv(...)
 *   - Validate new cards: EarnmoreClient(passkeyB, { keyId: "k2" }).validateCvv(...)
 *
 * Key Check Value (ISO 11568-2):
 *   KCV = HMAC-SHA256(derivedKey, "earnmore:kcv:check")[0..2]  →  6 hex chars
 *
 * Security notes:
 *  - PCI-DSS Req 3.3.1: CVV is SAD — never store it after authorization.
 *  - PCI-DSS Req 3.7.5: The passkey (HMAC key) must be separate from any
 *    PAN encryption key.
 *  - PCI-DSS Req 8: Rate-limit CVV validation — only 10,000 possible values.
 *  - Rotate the passkey if compromised; increment keyId on rotation.
 */

import { createHmac, pbkdf2Sync, timingSafeEqual } from "crypto";
import { ComplianceConfig, PCI_DSS_PBKDF2_ITERATIONS, isValidUUID } from "./types";

const HMAC_KEY_SALT = "earnmore:cvv:v1";
const KCV_CHECK_DATA = "earnmore:kcv:check";
const MIN_PBKDF2_ITERATIONS = 1_000;
const MIN_PASSKEY_LENGTH = 16;

// ISO 11568-2: 3-byte (6 hex char) KCV
const KCV_BYTES = 3;

/**
 * Derives a 256-bit HMAC key from a passkey string using PBKDF2-SHA256.
 *
 * @param passkey    Secret passkey string. Minimum 16 characters.
 * @param iterations PBKDF2 iteration count. Use PCI_DSS_PBKDF2_ITERATIONS
 *                   (310,000) in production.
 */
export function deriveHmacKey(
  passkey: string,
  iterations: number = PCI_DSS_PBKDF2_ITERATIONS,
): Buffer {
  if (!passkey || passkey.length < MIN_PASSKEY_LENGTH) {
    throw new Error(`passkey must be at least ${MIN_PASSKEY_LENGTH} characters long.`);
  }
  if (iterations < MIN_PBKDF2_ITERATIONS) {
    throw new Error(
      `pbkdf2Iterations must be at least ${MIN_PBKDF2_ITERATIONS}. ` +
        `Received ${iterations}. Use PCI_DSS_PBKDF2_ITERATIONS (310,000) in production.`,
    );
  }
  return pbkdf2Sync(passkey, HMAC_KEY_SALT, iterations, 32, "sha256");
}

/**
 * Generates a Key Check Value (KCV) for a derived HMAC key.
 *
 * The KCV is a non-secret 6-character hex fingerprint that allows verifying
 * the correct passkey was loaded at startup, without exposing the key itself.
 * Store the KCV alongside your key configuration and compare on initialization.
 *
 * Algorithm: HMAC-SHA256(derivedKey, "earnmore:kcv:check")[0..2] as hex
 *
 * @param derivedKey  32-byte key Buffer from deriveHmacKey()
 * @returns           6-character hex string (e.g. "a3f2c1")
 */
export function generateKCV(derivedKey: Buffer): string {
  if (!Buffer.isBuffer(derivedKey) || derivedKey.length !== 32) {
    throw new Error(`derivedKey must be a 32-byte Buffer. Use deriveHmacKey().`);
  }
  const mac = createHmac("sha256", derivedKey).update(KCV_CHECK_DATA, "utf8").digest();
  return mac.subarray(0, KCV_BYTES).toString("hex");
}

/**
 * Builds the HMAC message including the key identifier.
 * Per NIST SP 800-57 / ISO 11568-1: keyId inclusion enables key rotation
 * without full card reissuance.
 */
function buildMessage(pan: string, expiry: string, keyId: string, atc?: number): string {
  if (atc !== undefined) {
    return `${keyId}|${pan}|${expiry}|${atc}`;
  }
  return `${keyId}|${pan}|${expiry}`;
}

function computeHmac(derivedKey: Buffer, message: string): string {
  return createHmac("sha256", derivedKey).update(message, "utf8").digest("hex");
}

function hmacToCvv(hmacHex: string): string {
  const value = parseInt(hmacHex.substring(0, 8), 16) % 10_000;
  return String(value).padStart(4, "0");
}

/** Inlines PAN masking to avoid a circular dependency with masking.ts */
function safeMaskPan(pan: string): string {
  return pan.substring(0, 6) + "xxxxxx" + pan.substring(12);
}

/**
 * Generates a 4-digit CVV using a pre-derived HMAC key.
 *
 * Prefer this overload for repeated calls — derive the key once with
 * deriveHmacKey() and reuse the Buffer (e.g. inside EarnmoreClient).
 *
 * @param pan         16-digit PAN string
 * @param expiry      "MM/YY" formatted expiry string
 * @param derivedKey  32-byte key from deriveHmacKey()
 * @param keyId       Key identifier (NIST SP 800-57 / ISO 11568-1).
 *                    Must match the keyId used during validation.
 *                    Default: DEFAULT_KEY_ID ("default")
 */
export function generateCvvFromKey(
  pan: string,
  expiry: string,
  derivedKey: Buffer,
  keyId: string,
): string {
  if (!isValidUUID(keyId)) {
    throw new Error(`keyId must be a valid UUID.`);
  }
  if (!/^\d{16}$/.test(pan)) {
    throw new Error(`Invalid PAN: must be exactly 16 digits.`);
  }
  if (derivedKey.length !== 32) {
    throw new Error(`derivedKey must be 32 bytes (256-bit). Use deriveHmacKey().`);
  }
  return hmacToCvv(computeHmac(derivedKey, buildMessage(pan, expiry, keyId)));
}

/**
 * Validates a 4-digit CVV using a pre-derived HMAC key.
 * Uses constant-time comparison (timingSafeEqual) to prevent timing attacks.
 *
 * @param pan         16-digit PAN string
 * @param expiry      "MM/YY" formatted expiry string
 * @param derivedKey  32-byte key from deriveHmacKey()
 * @param cvv         The 4-digit CVV to validate
 * @param keyId       Key identifier — must match the keyId used during issuance.
 *                    Default: DEFAULT_KEY_ID ("default")
 */
export function validateCvvFromKey(
  pan: string,
  expiry: string,
  derivedKey: Buffer,
  cvv: string,
  keyId: string,
): boolean {
  if (!isValidUUID(keyId)) return false;
  try {
    const expected = generateCvvFromKey(pan, expiry, derivedKey, keyId);
    const a = Buffer.from(expected, "utf8");
    const b = Buffer.from((cvv ?? "").padStart(4, "0").substring(0, 4), "utf8");
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Generates an EMVCo-style dynamic CVV using a pre-derived HMAC key.
 * Binds an Application Transaction Counter (ATC) to the cryptogram.
 *
 * @param pan         16-digit PAN string
 * @param expiry      "MM/YY" formatted expiry string
 * @param atc         Application Transaction Counter (integer)
 * @param derivedKey  32-byte key from deriveHmacKey()
 * @param keyId       Key identifier. Default: DEFAULT_KEY_ID
 */
export function generateDynamicCvvFromKey(
  pan: string,
  expiry: string,
  atc: number,
  derivedKey: Buffer,
  keyId: string,
): string {
  if (!isValidUUID(keyId)) {
    throw new Error(`keyId must be a valid UUID.`);
  }
  if (!/^\d{16}$/.test(pan)) {
    throw new Error(`Invalid PAN: must be exactly 16 digits.`);
  }
  if (derivedKey.length !== 32) {
    throw new Error(`derivedKey must be 32 bytes (256-bit). Use deriveHmacKey().`);
  }
  if (!Number.isInteger(atc) || atc < 0) {
    throw new Error(`atc must be a positive integer.`);
  }
  return hmacToCvv(computeHmac(derivedKey, buildMessage(pan, expiry, keyId, atc)));
}

/**
 * Validates a dynamic CVV (dCVV) using a pre-derived HMAC key.
 */
export function validateDynamicCvvFromKey(
  pan: string,
  expiry: string,
  atc: number,
  derivedKey: Buffer,
  dcvv: string,
  keyId: string,
): boolean {
  if (!isValidUUID(keyId)) return false;
  try {
    const expected = generateDynamicCvvFromKey(pan, expiry, atc, derivedKey, keyId);
    const a = Buffer.from(expected, "utf8");
    const b = Buffer.from((dcvv ?? "").padStart(4, "0").substring(0, 4), "utf8");
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Generates a 4-digit CVV, deriving the HMAC key inline.
 * Use generateCvvFromKey() + a cached derivedKey for repeated calls.
 *
 * @param pan     16-digit PAN string
 * @param expiry  "MM/YY" formatted expiry string
 * @param passkey Secret passkey (≥16 chars)
 * @param config  Optional compliance config (pbkdf2Iterations, keyId, onEvent)
 */
export function generateCvv(
  pan: string,
  expiry: string,
  passkey: string,
  config: ComplianceConfig,
): string {
  const iterations = config.pbkdf2Iterations ?? PCI_DSS_PBKDF2_ITERATIONS;
  const keyId = config.keyId;
  const key = deriveHmacKey(passkey, iterations);
  try {
    const cvv = generateCvvFromKey(pan, expiry, key, keyId);
    config?.onEvent?.({
      type: "card_generated",
      timestamp: new Date(),
      keyId,
      maskedPan: safeMaskPan(pan),
    });
    return cvv;
  } finally {
    key.fill(0);
  }
}

/**
 * Validates a 4-digit CVV, deriving the HMAC key inline.
 * Uses PBKDF2 on each call — use validateCvvFromKey() for frequent validation.
 *
 * @param pan     16-digit PAN string
 * @param expiry  "MM/YY" formatted expiry string
 * @param passkey The same passkey used to generate the CVV
 * @param cvv     The 4-digit CVV to validate
 * @param config  Optional compliance config (pbkdf2Iterations, keyId, onEvent)
 */
export function validateCvv(
  pan: string,
  expiry: string,
  passkey: string,
  cvv: string,
  config: ComplianceConfig,
): boolean {
  try {
    const iterations = config.pbkdf2Iterations ?? PCI_DSS_PBKDF2_ITERATIONS;
    const keyId = config.keyId;
    const key = deriveHmacKey(passkey, iterations);
    try {
      const isValid = validateCvvFromKey(pan, expiry, key, cvv, keyId);
      config?.onEvent?.({
        type: isValid ? "cvv_valid" : "cvv_invalid",
        timestamp: new Date(),
        keyId,
        maskedPan: safeMaskPan(pan),
      });
      return isValid;
    } finally {
      key.fill(0);
    }
  } catch {
    return false;
  }
}

/**
 * Generates a dynamic CVV (dCVV), deriving the HMAC key inline.
 */
export function generateDynamicCvv(
  pan: string,
  expiry: string,
  atc: number,
  passkey: string,
  config: ComplianceConfig,
): string {
  const iterations = config.pbkdf2Iterations ?? PCI_DSS_PBKDF2_ITERATIONS;
  const keyId = config.keyId;
  const key = deriveHmacKey(passkey, iterations);
  try {
    const dcvv = generateDynamicCvvFromKey(pan, expiry, atc, key, keyId);
    config?.onEvent?.({
      type: "card_generated",
      timestamp: new Date(),
      keyId,
      maskedPan: safeMaskPan(pan),
    });
    return dcvv;
  } finally {
    key.fill(0);
  }
}

/**
 * Validates a dynamic CVV (dCVV), deriving the HMAC key inline.
 */
export function validateDynamicCvv(
  pan: string,
  expiry: string,
  atc: number,
  passkey: string,
  dcvv: string,
  config: ComplianceConfig,
): boolean {
  try {
    const iterations = config.pbkdf2Iterations ?? PCI_DSS_PBKDF2_ITERATIONS;
    const keyId = config.keyId;
    const key = deriveHmacKey(passkey, iterations);
    try {
      const isValid = validateDynamicCvvFromKey(pan, expiry, atc, key, dcvv, keyId);
      config?.onEvent?.({
        type: isValid ? "cvv_valid" : "cvv_invalid",
        timestamp: new Date(),
        keyId,
        maskedPan: safeMaskPan(pan),
      });
      return isValid;
    } finally {
      key.fill(0);
    }
  } catch {
    return false;
  }
}
