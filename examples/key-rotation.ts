/**
 * Key Rotation (NIST SP 800-57)
 * 
 * Demonstrates rotating the HMAC passkey while continuing to validate
 * previously issued cards using the `keyId` stored with the card record.
 */
import { EarnmoreClient, CustomerInfo } from "../src";

function run() {
  console.log("=== NIST SP 800-57 Key Rotation Example ===\n");

  const customer: CustomerInfo = {
    firstName: "Maria",
    middleName: "Clara",
    lastName: "Santos",
    address: { line1: "123 Rizal Street", city: "Manila", country: "PH", zipCode: "1000" },
    birthday: new Date("1990-05-15"),
    birthPlace: "Manila",
    idDocument: { type: "national_id", number: "123-456-789" },
  };

  const passkeyV1 = "super-secret-passkey-v1-2024";
  const clientV1 = new EarnmoreClient(passkeyV1, { keyId: "123e4567-e89b-12d3-a456-426614174000" });
  console.log("[2024] Generating card under keyId '123e4567-...'...");

  const oldCard = clientV1.generate(customer);
  console.log(`[2024] Card generated: ${oldCard.pan}`);
  console.log(`[2024] Saved to DB with keyId: ${oldCard.keyId}\n`);

  const passkeyV2 = "super-secret-passkey-v2-2026";
  const clientV2 = new EarnmoreClient(passkeyV2, { keyId: "223e4567-e89b-12d3-a456-426614174000" });
  console.log("[2026] Key rotated. Generating new card under keyId '223e4567-...'...");

  const newCard = clientV2.generate(customer);
  console.log(`[2026] New card generated: ${newCard.pan}`);
  console.log(`[2026] Saved to DB with keyId: ${newCard.keyId}\n`);

  console.log("--- Processing incoming transactions ---\n");
  console.log("Incoming Txn: Old Card CVV submitted.");
  console.log("System looks up keyId from DB... it is 'v1'. Routes to Client V1.");

  const isValidOld = clientV1.validateCvv(oldCard.pan, oldCard.expiry, oldCard.cvv);
  console.log(`Validation result: ${isValidOld ? "Success" : "Fail"}\n`);
  console.log("Incoming Txn: New Card CVV submitted.");
  console.log("System looks up keyId from DB... it is 'v2'. Routes to Client V2.");

  const isValidNew = clientV2.validateCvv(newCard.pan, newCard.expiry, newCard.cvv);
  console.log(`Validation result: ${isValidNew ? "Success" : "Fail"}\n`);
  console.log("Simulating misconfiguration: validating old card CVV against Client V2...");

  const isBadRouting = clientV2.validateCvv(oldCard.pan, oldCard.expiry, oldCard.cvv);
  console.log(`Validation result: ${isBadRouting ? "Success (Bad!)" : "Fail (Proper isolation!)"}\n`);

  clientV1.destroy();
  clientV2.destroy();
}

run();
