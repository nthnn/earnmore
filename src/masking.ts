/**
 * earnmore — PAN masking and SAD redaction utilities (PCI-DSS Req 3.3.1 / 3.5)
 *
 * PCI-DSS Req 3.5:
 *   Primary Account Numbers (PANs) must be masked when displayed so that only
 *   personnel with a legitimate business need can see more than the first six
 *   or last four digits.
 *
 *   Compliant mask format: first 6 digits (BIN) + masked middle + last 4 digits.
 *   Example: "0011382910471836" → "001138xxxxxx1836"
 *
 * PCI-DSS Req 3.3.1:
 *   Sensitive Authentication Data (SAD) — including CVV/CVC — must not be
 *   stored after authorization is complete, even if encrypted.
 *   Use redactCardResult() to strip the CVV before persisting a card record.
 */

import { CardResult, StorableCardData } from "./types";

/**
 * Masks a 16-digit PAN per PCI-DSS Req 3.5.
 *
 * Format: first 6 digits (BIN/IIN) + 6 masked chars + last 4 digits.
 * The 6 masked characters in the middle are shown as lowercase 'x'.
 *
 * Example: "0011382910471836" → "001138xxxxxx1836"
 *
 * @param pan  16-digit PAN string (digits only)
 * @returns    Masked PAN string
 * @throws {Error} If PAN is not exactly 16 digits
 */
export function maskPAN(pan: string): string {
  if (!/^\d{16}$/.test(pan)) {
    throw new Error(`Invalid PAN: must be exactly 16 digits.`);
  }
  // first 6 (BIN) + 6 masked + last 4
  return pan.substring(0, 6) + "xxxxxx" + pan.substring(12);
}

/**
 * Strips Sensitive Authentication Data (SAD) from a CardResult, returning
 * only Cardholder Data (CHD) that is safe to store per PCI-DSS Req 3.3.1.
 *
 * The CVV is intentionally excluded. The PAN is automatically masked.
 * If you need the full PAN for storage, use encryptPAN() from storage.ts.
 *
 * @param result  Full CardResult from generate()
 * @returns       StorableCardData with maskedPan and expiry only (no CVV)
 */
export function redactCardResult(result: CardResult): StorableCardData {
  return {
    maskedPan: maskPAN(result.pan),
    expiry: result.expiry,
    keyId: result.keyId,
  };
}
