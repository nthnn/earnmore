/**
 * earnmore — PAN encryption for secure at-rest storage (PCI-DSS Req 3.4.1)
 *
 * PCI-DSS Req 3.4.1 requires that PANs stored anywhere (database, log, backup)
 * be rendered unreadable using strong cryptography.
 *
 * This module provides AES-256-GCM encryption for PAN storage:
 *  - AES-256-GCM: authenticated encryption (confidentiality + integrity)
 *  - 12-byte random IV per operation (NIST SP 800-38D recommendation)
 *  - 128-bit GCM auth tag validates integrity on decryption
 *
 * Key management (PCI-DSS Req 3.7):
 *  - The encryption key (32 bytes / 256 bits) is the caller's responsibility.
 *  - It MUST be different from the CVV HMAC passkey (Req 3.7.5 key separation).
 *  - Rotate and re-encrypt stored PANs when the key is rotated.
 *  - Store the key separately from the encrypted PAN data.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { EncryptedPAN } from "./types";

const ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

/**
 * Encrypts a 16-digit PAN using AES-256-GCM.
 *
 * @param pan            16-digit PAN string
 * @param encryptionKey  32-byte (256-bit) encryption key Buffer.
 *                       Must be distinct from the CVV HMAC passkey.
 * @returns              EncryptedPAN with iv, ciphertext, and authTag (all hex)
 *
 * @throws {Error}  If PAN is not 16 digits or key is not 32 bytes.
 */
export function encryptPAN(pan: string, encryptionKey: Buffer): EncryptedPAN {
  if (!/^\d{16}$/.test(pan)) {
    throw new Error(`Invalid PAN: must be exactly 16 digits.`);
  }

  if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== KEY_BYTES) {
    throw new Error(
      `encryptionKey must be a ${KEY_BYTES}-byte Buffer (256-bit). ` +
        `Received ${encryptionKey?.length ?? "unknown"} bytes.`,
    );
  }

  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, encryptionKey, iv, {
    authTagLength: TAG_BYTES,
  });

  const ciphertext = Buffer.concat([cipher.update(pan, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    iv: iv.toString("hex"),
    ciphertext: ciphertext.toString("hex"),
    authTag: authTag.toString("hex"),
  };
}

/**
 * Decrypts an EncryptedPAN using AES-256-GCM.
 * GCM authentication tag is verified before any plaintext is returned —
 * if the tag fails, an error is thrown and no plaintext is exposed.
 *
 * @param encrypted      EncryptedPAN object from encryptPAN()
 * @param encryptionKey  The same 32-byte key used during encryption
 * @returns              The original 16-digit PAN string
 *
 * @throws {Error}  If key is wrong, data is tampered, or input is malformed.
 */
export function decryptPAN(encrypted: EncryptedPAN, encryptionKey: Buffer): string {
  if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== KEY_BYTES) {
    throw new Error(`encryptionKey must be a ${KEY_BYTES}-byte Buffer (256-bit).`);
  }

  const iv = Buffer.from(encrypted.iv, "hex");
  const ciphertext = Buffer.from(encrypted.ciphertext, "hex");
  const authTag = Buffer.from(encrypted.authTag, "hex");

  if (iv.length !== IV_BYTES) {
    throw new Error(`Invalid IV length: expected ${IV_BYTES} bytes.`);
  }
  if (authTag.length !== TAG_BYTES) {
    throw new Error(`Invalid auth tag length: expected ${TAG_BYTES} bytes.`);
  }

  const decipher = createDecipheriv(ALGORITHM, encryptionKey, iv, {
    authTagLength: TAG_BYTES,
  });
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf8");
}

/**
 * Generates a random 32-byte AES-256 encryption key.
 * Use this to create a key for encryptPAN() / decryptPAN().
 *
 * ⚠️ Store the returned key securely (HSM, secret manager, KMS).
 *    This key must be kept separate from the CVV passkey.
 */
export function generateEncryptionKey(): Buffer {
  return randomBytes(KEY_BYTES);
}
