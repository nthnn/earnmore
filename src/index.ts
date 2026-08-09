/**
 * earnmore — Public API (PCI-DSS v4.0 / NIST / ISO / CSF 2.0 compliant)
 *
 * ## Key Rotation (NIST SP 800-57 / ISO 11568-1)
 *
 * Every generated card records a `keyId`. When rotating passphrases:
 *
 * ```typescript
 * // Old cards were issued under keyId "k1"
 * const oldClient = new EarnmoreClient(oldPasskey, { keyId: "k1" });
 *
 * // New cards are issued under keyId "k2"
 * const newClient = new EarnmoreClient(newPasskey, { keyId: "k2" });
 *
 * // Validate old card: look up stored keyId, pick the right client
 * oldClient.validateCvv(pan, expiry, cvv); // uses keyId "k1"
 * newClient.validateCvv(pan, expiry, cvv); // uses keyId "k2"
 * ```
 *
 * ## Key Check Value (ISO 11568-2)
 *
 * Verify the correct passkey is loaded at startup:
 * ```typescript
 * const client = new EarnmoreClient(passkey, { keyId: "k1" });
 * const kcv = client.getKCV(); // e.g. "a3f2c1"
 * // Compare kcv to the expected value stored in your configuration.
 * ```
 *
 * ## Cryptoperiod (NIST SP 800-57 §5.3.6)
 *
 * ```typescript
 * const client = new EarnmoreClient(passkey, {
 *   keyCreatedAt: new Date("2025-01-01"),
 * });
 * if (client.isKeyExpired()) { // checks 2-year NIST limit
 *   // Rotate passkey and reissue with new keyId
 * }
 * ```
 *
 * ## Audit Events (CSF 2.0 DE.AE-02 / ISO 27001:2022 A.8.15)
 *
 * ```typescript
 * const client = new EarnmoreClient(passkey, {
 *   onEvent: (event) => myAuditLogger.log(event),
 * });
 * // Fires: key_initialized, card_generated, cvv_valid/invalid, pan_encrypted/decrypted, key_destroyed
 * ```
 *
 * ## PCI-DSS compliance reminders
 *
 * - DO NOT store card.cvv — it is SAD (PCI-DSS Req 3.3.1).
 *   Call redactCardResult(card) before saving to any persistent store.
 * - DO store card.keyId — required for CVV validation after key rotation.
 * - DO NOT store the PAN in plaintext — use encryptPAN() (Req 3.4.1).
 * - The CVV passkey and the PAN encryption key MUST be different secrets
 *   (PCI-DSS Req 3.7.5).
 */

export type {
  CustomerInfo,
  CustomerAddress,
  IdDocument,
  IdType,
  CardResult,
  StorableCardData,
  EncryptedPAN,
  ComplianceConfig,
  EarnmoreEvent,
  EarnmoreEventType,
  AllowedPrefix,
} from "./types";

export {
  ALLOWED_PREFIXES,
  PCI_DSS_PBKDF2_ITERATIONS,
  isValidUUID,
  NIST_HMAC_KEY_MAX_YEARS,
} from "./types";

export { luhnValid } from "./pan";
export { parseExpiry } from "./expiry";
export {
  deriveHmacKey,
  generateCvvFromKey,
  validateCvvFromKey,
  generateDynamicCvvFromKey,
  validateDynamicCvvFromKey,
  generateKCV,
} from "./cvv";
export { maskPAN, redactCardResult } from "./masking";
export { encryptPAN, decryptPAN, generateEncryptionKey } from "./storage";

import { customerFingerprint } from "./hash";
import { generatePAN } from "./pan";
import { generateExpiry } from "./expiry";
import {
  generateCvv,
  deriveHmacKey,
  generateCvvFromKey,
  validateCvvFromKey,
  generateDynamicCvvFromKey,
  validateDynamicCvvFromKey,
  generateKCV,
} from "./cvv";
import { maskPAN, redactCardResult } from "./masking";
import { encryptPAN, decryptPAN } from "./storage";
import {
  CustomerInfo,
  CardResult,
  ComplianceConfig,
  StorableCardData,
  EncryptedPAN,
  EarnmoreEvent,
  PCI_DSS_PBKDF2_ITERATIONS,
  isValidUUID,
  NIST_HMAC_KEY_MAX_YEARS,
} from "./types";

/**
 * Generates a unique closed-loop reward card (PAN + expiry + CVV + keyId)
 * from customer identity data.
 *
 * Every call produces a **different** PAN even for the same customer,
 * because a CSPRNG salt is mixed into the hash before digit generation.
 *
 * ⚠️ The returned `cvv` is SAD — do not persist it.
 *    Store `keyId` alongside the card record for future validation.
 *    Call `redactCardResult()` before saving.
 *
 * @param customer  Full customer identity information
 * @param passkey   Secret passkey (≥16 chars) for CVV HMAC key derivation.
 *                  Must be distinct from any PAN encryption key.
 * @param config    Optional compliance config (pbkdf2Iterations, keyId, onEvent)
 */
export function generate(
  customer: CustomerInfo,
  passkey: string,
  config: ComplianceConfig,
): CardResult {
  const fingerprint = customerFingerprint(customer);
  const { pan, seedBuffer } = generatePAN(fingerprint);
  const expiry = generateExpiry(seedBuffer);
  const keyId = config.keyId;

  if (!isValidUUID(keyId)) {
    throw new Error(`keyId must be a valid UUID.`);
  }

  const cvv = generateCvv(pan, expiry, passkey, config);
  return { pan, expiry, cvv, keyId };
}

/** Re-export validateCvv and EMVCo dynamic CVV functions from cvv module */
export { validateCvv, generateDynamicCvv, validateDynamicCvv } from "./cvv";

/** Re-export GDPR scrubCustomerData from hash module */
export { scrubCustomerData } from "./hash";

/**
 * A stateful client that derives the PBKDF2 HMAC key once at construction
 * and caches it for fast repeated operations.
 *
 * Implements:
 *  - Key versioning (NIST SP 800-57 / ISO 11568-1): `keyId` in constructor
 *  - Key Check Value (ISO 11568-2): `getKCV()`
 *  - Cryptoperiod enforcement (NIST SP 800-57 §5.3.6): `isKeyExpired()`
 *  - Audit event hooks (CSF 2.0 DE.AE-02 / ISO 27001:2022 A.8.15): `onEvent`
 *  - Secure key zeroing on decommission: `destroy()`
 */
export class EarnmoreClient {
  private derivedKey: Buffer;
  private destroyed: boolean = false;
  private readonly keyId: string;
  private readonly keyCreatedAt: Date;
  private readonly onEvent?: (event: EarnmoreEvent) => void;

  /**
   * @param passkey  Secret passkey string (≥16 chars)
   * @param config   Optional compliance config:
   *   - `pbkdf2Iterations`: PBKDF2 rounds (default: PCI_DSS_PBKDF2_ITERATIONS)
   *   - `keyId`: Key identifier for HMAC message (default: DEFAULT_KEY_ID)
   *   - `keyCreatedAt`: Key provisioning date (default: now; used by isKeyExpired())
   *   - `onEvent`: Audit event callback (CSF 2.0 / ISO 27001 A.8.15)
   */
  constructor(passkey: string, config: ComplianceConfig) {
    const iterations = config.pbkdf2Iterations ?? PCI_DSS_PBKDF2_ITERATIONS;
    this.keyId = config.keyId;

    if (!isValidUUID(this.keyId)) {
      throw new Error(`keyId must be a valid UUID.`);
    }

    this.keyCreatedAt = config.keyCreatedAt ?? new Date();
    this.onEvent = config.onEvent;

    this.derivedKey = deriveHmacKey(passkey, iterations);
    this.emit({ type: "key_initialized", timestamp: new Date(), keyId: this.keyId });
  }

  private assertNotDestroyed(): void {
    if (this.destroyed) {
      throw new Error("EarnmoreClient has been destroyed. Create a new instance.");
    }
  }

  private emit(event: EarnmoreEvent): void {
    try {
      this.onEvent?.(event);
    } catch {}
  }

  /**
   * Generates a unique card from customer identity data.
   * CVV is derived using the cached HMAC key and this client's keyId.
   *
   * ⚠️ Store card.keyId alongside the card record — required for validation
   *    after key rotation (NIST SP 800-57 / ISO 11568-1).
   */
  generate(customer: CustomerInfo): CardResult {
    this.assertNotDestroyed();
    const fingerprint = customerFingerprint(customer);
    const { pan, seedBuffer } = generatePAN(fingerprint);
    const expiry = generateExpiry(seedBuffer);
    const cvv = generateCvvFromKey(pan, expiry, this.derivedKey, this.keyId);
    this.emit({
      type: "card_generated",
      timestamp: new Date(),
      keyId: this.keyId,
      maskedPan: maskPAN(pan),
    });
    return { pan, expiry, cvv, keyId: this.keyId };
  }

  /**
   * Validates a CVV using this client's cached HMAC key and keyId.
   * Uses constant-time comparison — no PBKDF2 per call.
   *
   * For cards issued under a different keyId, use the corresponding
   * EarnmoreClient instance (with the matching passkey and keyId).
   */
  validateCvv(pan: string, expiry: string, cvv: string): boolean {
    this.assertNotDestroyed();
    const isValid = validateCvvFromKey(pan, expiry, this.derivedKey, cvv, this.keyId);
    this.emit({
      type: isValid ? "cvv_valid" : "cvv_invalid",
      timestamp: new Date(),
      keyId: this.keyId,
      maskedPan: maskPAN(pan),
    });
    return isValid;
  }

  /**
   * Generates a dynamic CVV (dCVV) using this client's cached HMAC key.
   * EMVCo cryptograms bind an Application Transaction Counter (ATC) to the message.
   */
  generateDynamicCvv(pan: string, expiry: string, atc: number): string {
    this.assertNotDestroyed();
    const dcvv = generateDynamicCvvFromKey(pan, expiry, atc, this.derivedKey, this.keyId);
    this.emit({
      type: "card_generated",
      timestamp: new Date(),
      keyId: this.keyId,
      maskedPan: maskPAN(pan),
    });
    return dcvv;
  }

  /**
   * Validates a dynamic CVV (dCVV) using this client's cached HMAC key.
   */
  validateDynamicCvv(pan: string, expiry: string, atc: number, dcvv: string): boolean {
    this.assertNotDestroyed();
    const isValid = validateDynamicCvvFromKey(pan, expiry, atc, this.derivedKey, dcvv, this.keyId);
    this.emit({
      type: isValid ? "cvv_valid" : "cvv_invalid",
      timestamp: new Date(),
      keyId: this.keyId,
      maskedPan: maskPAN(pan),
    });
    return isValid;
  }

  /**
   * Returns the Key Check Value (KCV) for this client's derived key.
   *
   * The KCV is a non-secret 6-character hex fingerprint (ISO 11568-2).
   * Store it alongside your key configuration and verify on startup to
   * confirm the correct passkey was loaded.
   *
   * @returns 6-character hex KCV (e.g. "a3f2c1")
   */
  getKCV(): string {
    this.assertNotDestroyed();
    return generateKCV(this.derivedKey);
  }

  /**
   * Returns the key identifier this client was initialized with.
   * Store alongside card records for key rotation support.
   */
  getKeyId(): string {
    return this.keyId;
  }

  /**
   * Checks whether this key has exceeded its recommended cryptoperiod.
   *
   * Per NIST SP 800-57 Part 1 Rev.5 §5.3.6, HMAC authentication keys
   * should not be used beyond 2 years (NIST_HMAC_KEY_MAX_YEARS).
   *
   * @param maxAgeYears  Maximum key age in years. Default: NIST_HMAC_KEY_MAX_YEARS (2)
   * @returns            true if the key age exceeds maxAgeYears
   */
  isKeyExpired(maxAgeYears: number = NIST_HMAC_KEY_MAX_YEARS): boolean {
    const maxMs = maxAgeYears * 365.25 * 24 * 60 * 60 * 1000;
    return Date.now() - this.keyCreatedAt.getTime() > maxMs;
  }

  /**
   * Encrypts a PAN for at-rest storage (AES-256-GCM).
   *
   * @param pan            16-digit PAN
   * @param encryptionKey  32-byte key — MUST be different from the CVV passkey
   *                       (PCI-DSS Req 3.7.5)
   */
  encryptPAN(pan: string, encryptionKey: Buffer): EncryptedPAN {
    this.assertNotDestroyed();
    const result = encryptPAN(pan, encryptionKey);
    this.emit({
      type: "pan_encrypted",
      timestamp: new Date(),
      keyId: this.keyId,
      maskedPan: maskPAN(pan),
    });
    return result;
  }

  /**
   * Decrypts an EncryptedPAN.
   *
   * @param encrypted      Result from encryptPAN()
   * @param encryptionKey  The same 32-byte key used for encryption
   */
  decryptPAN(encrypted: EncryptedPAN, encryptionKey: Buffer): string {
    this.assertNotDestroyed();
    const pan = decryptPAN(encrypted, encryptionKey);
    this.emit({
      type: "pan_decrypted",
      timestamp: new Date(),
      keyId: this.keyId,
      maskedPan: maskPAN(pan),
    });
    return pan;
  }

  /**
   * Masks a PAN per PCI-DSS Req 3.5.
   * Returns first 6 + 6 masked chars + last 4.
   */
  maskPAN(pan: string): string {
    return maskPAN(pan);
  }

  /**
   * Strips CVV (SAD) from a CardResult, returning a StorableCardData object
   * safe to persist per PCI-DSS Req 3.3.1.
   * The keyId is preserved in StorableCardData for future validation.
   */
  redactCardResult(result: CardResult): StorableCardData {
    return redactCardResult(result);
  }

  /**
   * Zeros the cached derived key and marks this client as destroyed.
   * Call this when the client will no longer be used to clear key material
   * from process memory.
   */
  destroy(): void {
    if (!this.destroyed) {
      this.derivedKey.fill(0);
      this.destroyed = true;
      this.emit({ type: "key_destroyed", timestamp: new Date(), keyId: this.keyId });
    }
  }
}
