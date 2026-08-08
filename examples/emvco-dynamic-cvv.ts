/**
 * EMVCo Dynamic CVV
 * 
 * Demonstrates generating and validating counter-based dynamic cryptograms
 * which rotate every transaction to prevent replay attacks.
 */
import { EarnmoreClient, CustomerInfo } from "../src";

function run() {
  console.log("=== EMVCo Dynamic CVV (dCVV) Example ===\n");

  const client = new EarnmoreClient("super-secret-passkey-1234567890", {
    keyId: "123e4567-e89b-12d3-a456-426614174000",
  });

  const customer: CustomerInfo = {
    firstName: "Maria",
    middleName: "Clara",
    lastName: "Santos",
    address: { line1: "123 Rizal Street", city: "Manila", country: "PH", zipCode: "1000" },
    birthday: new Date("1990-05-15"),
    birthPlace: "Manila",
    idDocument: { type: "national_id", number: "123-456-789" },
  };

  const card = client.generate(customer);
  console.log(`Generated Card: ${card.pan}\n`);

  let atc = 1;
  const dcvv1 = client.generateDynamicCvv(card.pan, card.expiry, atc);
  console.log(`[Txn 1] ATC: ${atc}, Generated dCVV: ${dcvv1}`);

  const isValid1 = client.validateDynamicCvv(card.pan, card.expiry, atc, dcvv1);
  console.log(`[Txn 1] Validation result: ${isValid1 ? "Success" : "Fail"}\n`);

  atc++;

  const dcvv2 = client.generateDynamicCvv(card.pan, card.expiry, atc);
  console.log(`[Txn 2] ATC: ${atc}, Generated dCVV: ${dcvv2}`);

  const isValid2 = client.validateDynamicCvv(card.pan, card.expiry, atc, dcvv2);
  console.log(`[Txn 2] Validation result: ${isValid2 ? "Success" : "Fail"}\n`);

  console.log(`[Replay Attack] Interceptor tries to use Txn 1's dCVV (${dcvv1}) for Txn 3 (ATC: ${atc + 1})...`);
  atc++;

  const isValid3 = client.validateDynamicCvv(card.pan, card.expiry, atc, dcvv1);
  console.log(`[Replay Attack] Validation result: ${isValid3 ? "Success (Bad!)" : "Fail (Attack thwarted!)"}\n`);

  client.destroy();
}

run();
