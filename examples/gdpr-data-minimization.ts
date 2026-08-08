/**
 * GDPR Data Minimization
 * 
 * Demonstrates generating a card and immediately scrubbing the sensitive
 * PII from memory to prevent data leakage in heap dumps.
 */
import { EarnmoreClient, CustomerInfo, scrubCustomerData } from "../src";

function run() {
  console.log("=== GDPR Data Minimization Example ===\n");

  const client = new EarnmoreClient("super-secret-passkey-1234567890", {
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

  console.log("Before scrubbing:");
  console.log(`  Name: ${customer.firstName} ${customer.lastName}`);
  console.log(`  Address: ${customer.address.line1}`);
  console.log();

  const card = client.generate(customer);

  console.log(`Card successfully generated! PAN: ${card.pan}`);
  scrubCustomerData(customer);

  console.log("\nAfter scrubbing:");
  console.log(`  Name: ${customer.firstName} ${customer.lastName}`);
  console.log(`  Address: ${customer.address.line1}`);
  console.log();
  console.log("Data successfully scrubbed from memory.");

  client.destroy();
}

run();
