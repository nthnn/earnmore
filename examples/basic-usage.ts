/**
 * Basic Usage
 * 
 * Demonstrates generating a card and validating a CVV using EarnmoreClient.
 */
import { EarnmoreClient, CustomerInfo } from "../src";

function run() {
  console.log("=== Basic Usage Example ===\n");

  const passkey = "super-secret-passkey-1234567890";
  const client = new EarnmoreClient(passkey, {
    keyId: "123e4567-e89b-12d3-a456-426614174000",
  });

  const customer: CustomerInfo = {
    firstName: "Maria",
    middleName: "Clara",
    lastName: "Santos",
    address: {
      line1: "123 Rizal Street",
      city: "Manila",
      country: "Philippines",
      zipCode: "1000",
    },
    birthday: new Date("1990-05-15"),
    birthPlace: "Manila",
    idDocument: { type: "national_id", number: "123-456-789" },
  };
  console.log("Generating card for Maria...");

  const card = client.generate(customer);
  console.log("Card generated successfully!");
  console.log(`PAN:    ${card.pan}`);
  console.log(`Expiry: ${card.expiry}`);
  console.log(`CVV:    ${card.cvv}`);
  console.log(`Key ID: ${card.keyId}`);
  console.log();

  const submittedCvv = card.cvv;
  console.log(`Validating submitted CVV (${submittedCvv})...`);

  const isValid = client.validateCvv(card.pan, card.expiry, submittedCvv);
  console.log(`Is Valid? ${isValid ? "Yes" : "No"}`);

  client.destroy();
}

run();
