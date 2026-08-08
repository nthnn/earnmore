/**
 * earnmore — Type definitions
 * Closed-loop reward card network library (PCI-DSS v4.0 / NIST / ISO compliant)
 */

/**
 * PBKDF2 iteration count meeting NIST SP 800-132 and PCI-DSS v4.0 requirements.
 * Use this value in production environments.
 */
export const PCI_DSS_PBKDF2_ITERATIONS = 310_000;

/**
 * NIST SP 800-57 Part 1 Rev.5 §5.3.6 recommended maximum cryptoperiod for
 * HMAC authentication keys: 2 years.
 */
export const NIST_HMAC_KEY_MAX_YEARS = 2;

export interface ComplianceConfig {
  /**
   * PBKDF2-SHA256 iteration count for CVV key derivation.
   * Default: `PCI_DSS_PBKDF2_ITERATIONS` (310,000) — satisfies NIST SP 800-132
   * and PCI-DSS Req 3.7.1.
   * Minimum enforced by the library: 1,000.
   *
   * Pass a lower value only in non-production contexts (e.g. unit tests).
   *
   * @see PCI_DSS_PBKDF2_ITERATIONS
   */
  pbkdf2Iterations?: number;

  /**
   * Key identifier for CVV generation/validation (must be a valid UUID).
   *
   * Per NIST SP 800-57 / ISO 11568-1, embedding a key ID in the authenticated
   * message enables key rotation without reissuing all cards. Store the keyId
   * alongside each card record and pass it back during CVV validation.
   */
  keyId: string;

  /**
   * Timestamp when this key/passkey was provisioned.
   * Used by `EarnmoreClient.isKeyExpired()` to enforce NIST SP 800-57 §5.3.6
   * cryptoperiod recommendations.
   * Defaults to the time the EarnmoreClient was constructed.
   */
  keyCreatedAt?: Date;

  /**
   * Audit event callback (CSF 2.0 DE.AE-02 / ISO 27001:2022 A.8.15).
   *
   * Called for every significant cryptographic operation. Events never contain
   * a full PAN, CVV, or raw key material — only masked PAN and metadata.
   * Feed these events into your SIEM, anomaly detection, or audit log.
   */
  onEvent?: (event: EarnmoreEvent) => void;
}

export type EarnmoreEventType =
  | "card_generated"
  | "cvv_valid"
  | "cvv_invalid"
  | "pan_encrypted"
  | "pan_decrypted"
  | "key_initialized"
  | "key_destroyed";

/**
 * Audit event emitted by the library for significant cryptographic operations.
 * Safe to log — never contains a full PAN, raw CVV, or key material.
 */
export interface EarnmoreEvent {
  /** Operation that triggered this event */
  type: EarnmoreEventType;

  /** UTC timestamp of the operation */
  timestamp: Date;

  /** Key identifier active at the time of the operation */
  keyId: string;

  /**
   * Masked PAN when the operation involved a specific card.
   * Format: first 6 (BIN) + "xxxxxx" + last 4.
   * Absent for key lifecycle events.
   */
  maskedPan?: string;
}

export type IdType = "passport" | "drivers_license" | "national_id";

export interface IdDocument {
  /** Type of identification document */
  type: IdType;

  /** The document number (alphanumeric) */
  number: string;
}

export interface CustomerAddress {
  line1: string;

  /** Optional second address line */
  line2?: string;
  city: string;
  country: string;
  zipCode: string;
}

export interface CustomerInfo {
  firstName: string;
  lastName: string;

  /** Pass an empty string if the customer has no middle name */
  middleName: string;

  /** Date of birth */
  birthday: Date;

  /**
   * Place of birth — letters and spaces only (e.g. "New York", "Manila").
   * The library will throw if this contains digits or special characters.
   */
  birthPlace: string;

  /** Primary identification document */
  idDocument: IdDocument;

  address: CustomerAddress;
}

/**
 * Full card issuance result.
 *
 * ⚠️ PCI-DSS Req 3.3.1: The `cvv` field is Sensitive Authentication Data (SAD)
 * and MUST NOT be stored after authorization. Use `redactCardResult()` to obtain
 * a storable representation that excludes the CVV.
 *
 * Store `keyId` alongside the card record — it is required for CVV validation
 * after a key rotation (NIST SP 800-57 / ISO 11568-1).
 */
export interface CardResult {
  /** 16-digit Primary Account Number */
  pan: string;

  /** Card expiry in MM/YY format */
  expiry: string;

  /**
   * 4-digit Card Verification Value.
   * SAD — do not persist this field after card issuance / authorization.
   */
  cvv: string;

  /**
   * Key identifier used to generate this CVV.
   * Persist this alongside the card record for future CVV validation.
   * Per NIST SP 800-57 / ISO 11568-1.
   */
  keyId: string;
}

/**
 * Cardholder Data (CHD) safe for storage after authorization.
 * The CVV/CVC is intentionally absent — per PCI-DSS Req 3.3.1,
 * SAD must not be retained once issuance/authorization is complete.
 */
export interface StorableCardData {
  /**
   * Masked PAN: first 6 digits (BIN) + 6 masked characters + last 4 digits.
   * Example: "001138xxxxxx1836"
   * Per PCI-DSS Req 3.5, full PANs must not be stored in plaintext.
   * Use encryptPAN() if the full PAN must be recoverable.
   */
  maskedPan: string;

  /** Card expiry in MM/YY format */
  expiry: string;

  /**
   * Key identifier — required for CVV validation after key rotation.
   * Per NIST SP 800-57 / ISO 11568-1.
   */
  keyId: string;
}

/**
 * AES-256-GCM encrypted PAN for compliant storage (PCI-DSS Req 3.4.1).
 * All fields are hex-encoded strings.
 */
export interface EncryptedPAN {
  /** 12-byte random IV (hex) — unique per encryption operation */
  iv: string;

  /** AES-256-GCM ciphertext (hex) */
  ciphertext: string;

  /** 16-byte GCM authentication tag (hex) — verifies integrity */
  authTag: string;
}

export const ALLOWED_PREFIXES = ["0011", "9212", "0513", "8989", "7312", "9876"] as const;

export type AllowedPrefix = (typeof ALLOWED_PREFIXES)[number];

export const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidUUID(uuid: string): boolean {
  return typeof uuid === "string" && UUID_REGEX.test(uuid);
}
