/**
 * earnmore — Comprehensive test suite
 * PCI-DSS v4.0 / NIST SP 800-57 / ISO 11568 / NIST CSF 2.0 compliant build
 */

import {
  generate,
  validateCvv,
  luhnValid,
  parseExpiry,
  maskPAN,
  redactCardResult,
  encryptPAN,
  decryptPAN,
  generateEncryptionKey,
  deriveHmacKey,
  generateCvvFromKey,
  validateCvvFromKey,
  generateKCV,
  generateDynamicCvv,
  validateDynamicCvv,
  generateDynamicCvvFromKey,
  EarnmoreClient,
  PCI_DSS_PBKDF2_ITERATIONS,
  NIST_HMAC_KEY_MAX_YEARS,
} from "../src/index";
import { CustomerInfo, ALLOWED_PREFIXES, CardResult, EarnmoreEvent } from "../src/types";
import { customerFingerprint, HmacDrbg, scrubCustomerData } from "../src/hash";
import { generatePAN, luhnCheckDigit } from "../src/pan";
import { generateExpiry } from "../src/expiry";
import { generateCvv } from "../src/cvv";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SAMPLE_CUSTOMER: CustomerInfo = {
  firstName: "Maria",
  middleName: "Clara",
  lastName: "Santos",
  address: {
    line1: "123 Rizal Street",
    line2: "Barangay 7",
    city: "Manila",
    country: "Philippines",
    zipCode: "1000",
  },
  birthday: new Date("1990-05-15"),
  birthPlace: "Quezon City",
  idDocument: { type: "national_id", number: "PH-1234-5678-9" },
};

const PASSKEY = "super-secret-passkey-12345"; // 26 chars — satisfies ≥16 char minimum

/**
 * Low-iteration ComplianceConfig used throughout tests to keep the suite fast.
 * Pass { pbkdf2Iterations: <n> } directly to any generate(), validateCvv(),
 * deriveHmacKey(), or EarnmoreClient() call that needs a non-default count.
 */
const COMPLIANCE: ComplianceConfig = {
  pbkdf2Iterations: 1_000,
  keyId: "123e4567-e89b-12d3-a456-426614174000",
};
type ComplianceConfig = Parameters<typeof generate>[2];

// ---------------------------------------------------------------------------
// PCI-DSS / NIST constants
// ---------------------------------------------------------------------------

describe("Compliance constants", () => {
  it("PCI_DSS_PBKDF2_ITERATIONS is at least 310,000 (NIST SP 800-132)", () => {
    expect(PCI_DSS_PBKDF2_ITERATIONS).toBeGreaterThanOrEqual(310_000);
  });

  it("1,000 is less than PCI_DSS_PBKDF2_ITERATIONS", () => {
    expect(1_000).toBeLessThan(PCI_DSS_PBKDF2_ITERATIONS);
  });

  it("NIST_HMAC_KEY_MAX_YEARS is 2 (NIST SP 800-57 §5.3.6)", () => {
    expect(NIST_HMAC_KEY_MAX_YEARS).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// customerFingerprint
// ---------------------------------------------------------------------------

describe("customerFingerprint", () => {
  it("returns a 64-character hex string (SHA-256)", () => {
    const fp = customerFingerprint(SAMPLE_CUSTOMER);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic — same input always yields same fingerprint", () => {
    expect(customerFingerprint(SAMPLE_CUSTOMER)).toBe(customerFingerprint(SAMPLE_CUSTOMER));
  });

  it("changes when any customer field changes", () => {
    const fp1 = customerFingerprint(SAMPLE_CUSTOMER);
    const fp2 = customerFingerprint({ ...SAMPLE_CUSTOMER, firstName: "Ana" });
    expect(fp1).not.toBe(fp2);
  });

  it("throws if birthPlace contains digits", () => {
    expect(() => customerFingerprint({ ...SAMPLE_CUSTOMER, birthPlace: "Manila1" })).toThrow(
      /birthPlace/,
    );
  });

  it("throws if birthPlace contains special characters", () => {
    expect(() => customerFingerprint({ ...SAMPLE_CUSTOMER, birthPlace: "New@York" })).toThrow(
      /birthPlace/,
    );
  });

  it("accepts birthPlace with letters and spaces", () => {
    expect(() => customerFingerprint({ ...SAMPLE_CUSTOMER, birthPlace: "New York" })).not.toThrow();
  });

  it("normalizes case and whitespace", () => {
    const upper: CustomerInfo = { ...SAMPLE_CUSTOMER, firstName: "  MARIA  ", lastName: "SANTOS" };
    const lower: CustomerInfo = { ...SAMPLE_CUSTOMER, firstName: "maria", lastName: "santos" };
    expect(customerFingerprint(upper)).toBe(customerFingerprint(lower));
  });

  // Input length limits — NIST SP 800-218 / ISO 27002 A.8.25
  it("throws if any field exceeds 1024 characters", () => {
    const tooLong = "A".repeat(1025);
    expect(() => customerFingerprint({ ...SAMPLE_CUSTOMER, firstName: tooLong })).toThrow(
      /exceeds the maximum allowed length/,
    );
  });

  it("accepts a field of exactly 1024 characters", () => {
    const maxLen = "A".repeat(1024);
    expect(() => customerFingerprint({ ...SAMPLE_CUSTOMER, firstName: maxLen })).not.toThrow();
  });

  it("throws if total payload exceeds 5,120 bytes", () => {
    // With 1024 char per-field limit, 6 fields of 1000 chars will trigger total limit
    const big = "B".repeat(1000); // 1000 is < 1024, so passes individual field test
    const customer: CustomerInfo = {
      ...SAMPLE_CUSTOMER,
      firstName: big,
      middleName: big,
      lastName: big,
      address: {
        line1: big,
        line2: big,
        city: big,
        country: "Philippines",
        zipCode: "1000",
      },
      birthPlace: "Cebu",
      idDocument: { type: "passport", number: "123" },
    };
    // Total is 6000+ bytes, which exceeds 5120
    // Total is 6000+ bytes, which exceeds 5120
    expect(() => customerFingerprint(customer)).toThrow(/payload exceeds/);
  });
});

describe("scrubCustomerData (GDPR Data Minimization)", () => {
  it("scrubs string fields by overwriting with zeroes", () => {
    const customer = JSON.parse(JSON.stringify(SAMPLE_CUSTOMER)); // clone
    scrubCustomerData(customer);

    // Check that PII is removed
    expect(customer.firstName).not.toBe(SAMPLE_CUSTOMER.firstName);
    expect(customer.firstName).toBe("00000"); // "Maria" is 5 chars
    expect(customer.middleName).toBe("00000"); // "Clara" is 5 chars
    expect(customer.lastName).toBe("000000"); // "Santos" is 6 chars
    expect(customer.address.line1).toBe("0000000000000000"); // "123 Rizal Street"

    // Ensure non-string or unscrubbed fields remain intact (like birthday Date object)
    expect(customer.birthday).toEqual(SAMPLE_CUSTOMER.birthday.toISOString());

    // Doesn't throw on missing optional fields
    const minimal: CustomerInfo = {
      firstName: "A",
      middleName: "",
      lastName: "B",
      address: { line1: "X", city: "Y", country: "Z", zipCode: "1" },
      birthday: new Date(),
      birthPlace: "W",
      idDocument: { type: "national_id", number: "123" },
    };
    expect(() => scrubCustomerData(minimal)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// HmacDrbg (CSPRNG)
// ---------------------------------------------------------------------------

describe("HmacDrbg (CSPRNG)", () => {
  it("produces deterministic output for the same seed and context", () => {
    const seed = Buffer.from("test-seed-32bytes-for-hmac-drbg!", "utf8");
    const drbg1 = new HmacDrbg(seed, "test:ctx");
    const drbg2 = new HmacDrbg(seed, "test:ctx");
    const seq1 = Array.from({ length: 50 }, () => drbg1.nextByte());
    const seq2 = Array.from({ length: 50 }, () => drbg2.nextByte());
    expect(seq1).toEqual(seq2);
  });

  it("different contexts produce different output (domain separation)", () => {
    const seed = Buffer.from("test-seed-32bytes-for-hmac-drbg!", "utf8");
    const s1 = Array.from({ length: 20 }, () => new HmacDrbg(seed, "earnmore:pan").nextByte());
    const s2 = Array.from({ length: 20 }, () => new HmacDrbg(seed, "earnmore:expiry").nextByte());
    expect(s1).not.toEqual(s2);
  });

  it("different seeds produce different output", () => {
    const s1 = Array.from({ length: 20 }, () =>
      new HmacDrbg(Buffer.from("seed-A-pad-32bytesxxxxxxxxxx"), "ctx").nextByte(),
    );
    const s2 = Array.from({ length: 20 }, () =>
      new HmacDrbg(Buffer.from("seed-B-pad-32bytesxxxxxxxxxx"), "ctx").nextByte(),
    );
    expect(s1).not.toEqual(s2);
  });

  it("nextInt produces values in [0, max) — no out-of-range values", () => {
    const drbg = new HmacDrbg(Buffer.alloc(32, 0xab), "test");
    for (let i = 0; i < 200; i++) {
      const v = drbg.nextInt(10);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(10);
    }
  });

  it("nextInt is statistically uniform across 0-9 (no modular bias)", () => {
    const drbg = new HmacDrbg(Buffer.alloc(32, 0xcd), "bias-test");
    const counts = new Array(10).fill(0);
    for (let i = 0; i < 10_000; i++) counts[drbg.nextInt(10)]++;
    counts.forEach((c) => {
      expect(c).toBeGreaterThan(700);
      expect(c).toBeLessThan(1300);
    });
  });

  it("nextInt throws for max out of [2, 256]", () => {
    const drbg = new HmacDrbg(Buffer.alloc(32), "ctx");
    expect(() => drbg.nextInt(1)).toThrow(/max/);
    expect(() => drbg.nextInt(257)).toThrow(/max/);
  });

  it("produces more than 32 bytes without throwing (crosses block boundary)", () => {
    const drbg = new HmacDrbg(Buffer.alloc(32, 0xff), "ctx");
    const bytes = Array.from({ length: 100 }, () => drbg.nextByte());
    expect(bytes).toHaveLength(100);
    bytes.forEach((b) => {
      expect(b).toBeGreaterThanOrEqual(0);
      expect(b).toBeLessThan(256);
    });
  });
});

// ---------------------------------------------------------------------------
// Luhn algorithm
// ---------------------------------------------------------------------------

describe("Luhn algorithm", () => {
  it("luhnCheckDigit produces correct check digit", () => {
    expect(luhnCheckDigit("453201511283036")).toBe(6);
    expect(luhnCheckDigit("542523343010990")).toBe(3);
  });

  it("luhnValid passes for valid PANs", () => {
    expect(luhnValid("4532015112830366")).toBe(true);
    expect(luhnValid("5425233430109903")).toBe(true);
  });

  it("luhnValid rejects invalid PANs", () => {
    expect(luhnValid("4532015112830367")).toBe(false);
    expect(luhnValid("1234567890123456")).toBe(false);
  });

  it("luhnValid rejects non-16-digit strings", () => {
    expect(luhnValid("123456789012345")).toBe(false);
    expect(luhnValid("12345678901234567")).toBe(false);
    expect(luhnValid("45320151128303AB")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// generatePAN
// ---------------------------------------------------------------------------

describe("generatePAN", () => {
  const fingerprint = customerFingerprint(SAMPLE_CUSTOMER);

  it("returns a 16-digit string", () => {
    expect(generatePAN(fingerprint).pan).toMatch(/^\d{16}$/);
  });

  it("PAN starts with one of the 6 allowed prefixes", () => {
    for (let i = 0; i < 20; i++) {
      const { pan } = generatePAN(fingerprint);
      expect(ALLOWED_PREFIXES.some((p) => pan.startsWith(p))).toBe(true);
    }
  });

  it("PAN passes Luhn validation", () => {
    for (let i = 0; i < 20; i++) {
      expect(luhnValid(generatePAN(fingerprint).pan)).toBe(true);
    }
  });

  it("is non-regeneratable — 50 calls produce 50 unique PANs", () => {
    const pans = new Set(Array.from({ length: 50 }, () => generatePAN(fingerprint).pan));
    expect(pans.size).toBe(50);
  });

  it("different fingerprints produce different PANs", () => {
    const fp2 = customerFingerprint({ ...SAMPLE_CUSTOMER, firstName: "Jose" });
    expect(generatePAN(fingerprint).pan).not.toBe(generatePAN(fp2).pan);
  });
});

// ---------------------------------------------------------------------------
// generateExpiry
// ---------------------------------------------------------------------------

describe("generateExpiry", () => {
  const fingerprint = customerFingerprint(SAMPLE_CUSTOMER);

  it("returns a string matching MM/YY format", () => {
    const { seedBuffer } = generatePAN(fingerprint);
    expect(generateExpiry(seedBuffer)).toMatch(/^\d{2}\/\d{2}$/);
  });

  it("month is between 01 and 12", () => {
    for (let i = 0; i < 30; i++) {
      const { seedBuffer } = generatePAN(fingerprint);
      const month = parseInt(generateExpiry(seedBuffer).split("/")[0], 10);
      expect(month).toBeGreaterThanOrEqual(1);
      expect(month).toBeLessThanOrEqual(12);
    }
  });

  it("year is between currentYear+4 and currentYear+7", () => {
    const cy = new Date().getFullYear();
    for (let i = 0; i < 30; i++) {
      const { seedBuffer } = generatePAN(fingerprint);
      const year = 2000 + parseInt(generateExpiry(seedBuffer).split("/")[1], 10);
      expect(year).toBeGreaterThanOrEqual(cy + 4);
      expect(year).toBeLessThanOrEqual(cy + 7);
    }
  });

  it("covers all 4 possible year offsets across many draws", () => {
    const cy = new Date().getFullYear();
    const seen = new Set<number>();
    for (let i = 0; i < 200; i++) {
      const { seedBuffer } = generatePAN(fingerprint);
      seen.add(2000 + parseInt(generateExpiry(seedBuffer).split("/")[1], 10) - cy);
    }
    [4, 5, 6, 7].forEach((o) => expect(seen.has(o)).toBe(true));
  });

  it("PAN and expiry use different DRBG streams (domain separation)", () => {
    const { seedBuffer } = generatePAN(fingerprint);
    const panDrbg = new HmacDrbg(seedBuffer, "earnmore:pan");
    const expDrbg = new HmacDrbg(seedBuffer, "earnmore:expiry");
    expect(panDrbg.nextByte()).not.toBe(expDrbg.nextByte());
  });
});

// ---------------------------------------------------------------------------
// deriveHmacKey
// ---------------------------------------------------------------------------

describe("deriveHmacKey", () => {
  it("returns a 32-byte Buffer", () => {
    const key = deriveHmacKey(PASSKEY, 1_000);
    expect(Buffer.isBuffer(key)).toBe(true);
    expect(key.length).toBe(32);
  });

  it("is deterministic — same passkey always yields same key", () => {
    const k1 = deriveHmacKey(PASSKEY, 1_000);
    const k2 = deriveHmacKey(PASSKEY, 1_000);
    expect(k1.equals(k2)).toBe(true);
  });

  it("different passphrases yield different keys", () => {
    const k1 = deriveHmacKey(PASSKEY, 1_000);
    const k2 = deriveHmacKey("different-secret-passkey-xyz", 1_000);
    expect(k1.equals(k2)).toBe(false);
  });

  it("throws if passkey is shorter than 16 characters", () => {
    expect(() => deriveHmacKey("short-key", 1_000)).toThrow(/16/);
    expect(() => deriveHmacKey("exactly15chars!!", 1_000)).not.toThrow();
  });

  it("throws if iterations are below 1,000", () => {
    expect(() => deriveHmacKey(PASSKEY, 999)).toThrow(/1.000|1000/);
    expect(() => deriveHmacKey(PASSKEY, 1_000)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Key Check Value — ISO 11568-2
// ---------------------------------------------------------------------------

describe("generateKCV (ISO 11568-2)", () => {
  const derivedKey = deriveHmacKey(PASSKEY, 1_000);

  it("returns a 6-character hex string", () => {
    expect(generateKCV(derivedKey)).toMatch(/^[0-9a-f]{6}$/);
  });

  it("is deterministic — same key always yields same KCV", () => {
    expect(generateKCV(derivedKey)).toBe(generateKCV(derivedKey));
  });

  it("different keys produce different KCVs", () => {
    const key2 = deriveHmacKey("another-long-secret-passkey-xyz!!", 1_000);
    expect(generateKCV(derivedKey)).not.toBe(generateKCV(key2));
    key2.fill(0);
  });

  it("throws for non-32-byte key", () => {
    expect(() => generateKCV(Buffer.alloc(16))).toThrow(/32/);
  });

  afterAll(() => derivedKey.fill(0));
});

// ---------------------------------------------------------------------------
// CVV — functional API
// ---------------------------------------------------------------------------

describe("CVV — functional API", () => {
  const { pan, seedBuffer } = generatePAN(customerFingerprint(SAMPLE_CUSTOMER));
  const expiry = generateExpiry(seedBuffer);

  it("CVV is exactly 4 digits", () => {
    expect(generateCvv(pan, expiry, PASSKEY, COMPLIANCE)).toMatch(/^\d{4}$/);
  });

  it("validateCvv returns true for correct inputs", () => {
    const cvv = generateCvv(pan, expiry, PASSKEY, COMPLIANCE);
    expect(validateCvv(pan, expiry, PASSKEY, cvv, COMPLIANCE)).toBe(true);
  });

  it("validateCvv returns false for wrong passkey", () => {
    const cvv = generateCvv(pan, expiry, PASSKEY, COMPLIANCE);
    expect(validateCvv(pan, expiry, "wrong-key-that-is-long-enough!", cvv, COMPLIANCE)).toBe(false);
  });

  it("validateCvv returns false for wrong PAN", () => {
    const cvv = generateCvv(pan, expiry, PASSKEY, COMPLIANCE);
    expect(validateCvv("0011000000000001", expiry, PASSKEY, cvv, COMPLIANCE)).toBe(false);
  });

  it("validateCvv returns false for wrong expiry", () => {
    const cvv = generateCvv(pan, expiry, PASSKEY, COMPLIANCE);
    expect(validateCvv(pan, "01/99", PASSKEY, cvv, COMPLIANCE)).toBe(false);
  });

  it("validateCvv returns false for tampered CVV", () => {
    const cvv = generateCvv(pan, expiry, PASSKEY, COMPLIANCE);
    const tampered = String((parseInt(cvv, 10) + 1) % 10_000).padStart(4, "0");
    expect(validateCvv(pan, expiry, PASSKEY, tampered, COMPLIANCE)).toBe(false);
  });

  it("generateCvv is deterministic", () => {
    expect(generateCvv(pan, expiry, PASSKEY, COMPLIANCE)).toBe(
      generateCvv(pan, expiry, PASSKEY, COMPLIANCE),
    );
  });

  it("throws on passkey shorter than 16 chars", () => {
    expect(() => generateCvv(pan, expiry, "short", COMPLIANCE)).toThrow(/16/);
  });
});

// ---------------------------------------------------------------------------
// Key versioning — NIST SP 800-57 / ISO 11568-1
// ---------------------------------------------------------------------------

describe("Key versioning (NIST SP 800-57 / ISO 11568-1)", () => {
  const { pan, seedBuffer } = generatePAN(customerFingerprint(SAMPLE_CUSTOMER));
  const expiry = generateExpiry(seedBuffer);

  it("CVVs generated with different keyIds are different", () => {
    const cvv1 = generateCvv(pan, expiry, PASSKEY, {
      ...COMPLIANCE,
      keyId: "123e4567-e89b-12d3-a456-426614174000",
    });
    const cvv2 = generateCvv(pan, expiry, PASSKEY, {
      ...COMPLIANCE,
      keyId: "223e4567-e89b-12d3-a456-426614174000",
    });
    expect(cvv1).not.toBe(cvv2);
  });

  it("validates correctly with the same keyId used at generation", () => {
    const cvv = generateCvv(pan, expiry, PASSKEY, {
      ...COMPLIANCE,
      keyId: "123e4567-e89b-12d3-a456-426614174000",
    });
    expect(
      validateCvv(pan, expiry, PASSKEY, cvv, {
        ...COMPLIANCE,
        keyId: "123e4567-e89b-12d3-a456-426614174000",
      }),
    ).toBe(true);
  });

  it("fails validation with a different keyId", () => {
    const cvv = generateCvv(pan, expiry, PASSKEY, {
      ...COMPLIANCE,
      keyId: "123e4567-e89b-12d3-a456-426614174000",
    });
    expect(
      validateCvv(pan, expiry, PASSKEY, cvv, {
        ...COMPLIANCE,
        keyId: "223e4567-e89b-12d3-a456-426614174000",
      }),
    ).toBe(false);
  });

  it("CardResult includes the keyId used for generation", () => {
    const card = generate(SAMPLE_CUSTOMER, PASSKEY, {
      ...COMPLIANCE,
      keyId: "223e4567-e89b-12d3-a456-426614174000",
    });
    expect(card.keyId).toBe("223e4567-e89b-12d3-a456-426614174000");
  });

  it("StorableCardData includes keyId after redactCardResult()", () => {
    const card = generate(SAMPLE_CUSTOMER, PASSKEY, {
      ...COMPLIANCE,
      keyId: "223e4567-e89b-12d3-a456-426614174000",
    });
    const storable = redactCardResult(card);
    expect(storable.keyId).toBe("223e4567-e89b-12d3-a456-426614174000");
  });

  it("key rotation: old and new CVVs validate independently", () => {
    const oldCvv = generateCvv(pan, expiry, PASSKEY, {
      ...COMPLIANCE,
      keyId: "123e4567-e89b-12d3-a456-426614174000",
    });
    const newPasskey = "new-secret-passkey-for-rotation!!";
    const newCvv = generateCvv(pan, expiry, newPasskey, {
      ...COMPLIANCE,
      keyId: "223e4567-e89b-12d3-a456-426614174000",
    });

    // Old CVV validates with old passkey + old keyId
    expect(
      validateCvv(pan, expiry, PASSKEY, oldCvv, {
        ...COMPLIANCE,
        keyId: "123e4567-e89b-12d3-a456-426614174000",
      }),
    ).toBe(true);
    // New CVV validates with new passkey + new keyId
    expect(
      validateCvv(pan, expiry, newPasskey, newCvv, {
        ...COMPLIANCE,
        keyId: "223e4567-e89b-12d3-a456-426614174000",
      }),
    ).toBe(true);
    // Cross-validation fails
    expect(
      validateCvv(pan, expiry, PASSKEY, oldCvv, {
        ...COMPLIANCE,
        keyId: "223e4567-e89b-12d3-a456-426614174000",
      }),
    ).toBe(false);
    expect(
      validateCvv(pan, expiry, newPasskey, newCvv, {
        ...COMPLIANCE,
        keyId: "123e4567-e89b-12d3-a456-426614174000",
      }),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// EMVCo Dynamic CVV / Cryptograms
// ---------------------------------------------------------------------------

describe("EMVCo Dynamic CVV", () => {
  const { pan, seedBuffer } = generatePAN(customerFingerprint(SAMPLE_CUSTOMER));
  const expiry = generateExpiry(seedBuffer);

  it("generates different dCVVs for different ATCs", () => {
    const dcvv1 = generateDynamicCvv(pan, expiry, 1, PASSKEY, COMPLIANCE);
    const dcvv2 = generateDynamicCvv(pan, expiry, 2, PASSKEY, COMPLIANCE);
    expect(dcvv1).not.toBe(dcvv2);
  });

  it("validates successfully with the correct ATC", () => {
    const atc = 105;
    const dcvv = generateDynamicCvv(pan, expiry, atc, PASSKEY, COMPLIANCE);
    expect(validateDynamicCvv(pan, expiry, atc, PASSKEY, dcvv, COMPLIANCE)).toBe(true);
  });

  it("fails validation with the wrong ATC", () => {
    const atc = 105;
    const dcvv = generateDynamicCvv(pan, expiry, atc, PASSKEY, COMPLIANCE);
    expect(validateDynamicCvv(pan, expiry, atc + 1, PASSKEY, dcvv, COMPLIANCE)).toBe(false);
  });

  it("fails validation with the wrong keyId", () => {
    const atc = 105;
    const dcvv = generateDynamicCvv(pan, expiry, atc, PASSKEY, {
      ...COMPLIANCE,
      keyId: "123e4567-e89b-12d3-a456-426614174000",
    });
    expect(
      validateDynamicCvv(pan, expiry, atc, PASSKEY, dcvv, {
        ...COMPLIANCE,
        keyId: "223e4567-e89b-12d3-a456-426614174000",
      }),
    ).toBe(false);
  });

  it("throws on negative ATC", () => {
    const key = deriveHmacKey(PASSKEY, 1000);
    expect(() =>
      generateDynamicCvvFromKey(pan, expiry, -1, key, "123e4567-e89b-12d3-a456-426614174000"),
    ).toThrow(/positive integer/);
  });
});

// ---------------------------------------------------------------------------
// CVV — pre-derived key API
// ---------------------------------------------------------------------------

describe("CVV — pre-derived key API", () => {
  const derivedKey = deriveHmacKey(PASSKEY, 1_000);
  const { pan, seedBuffer } = generatePAN(customerFingerprint(SAMPLE_CUSTOMER));
  const expiry = generateExpiry(seedBuffer);

  it("generateCvvFromKey produces same result as generateCvv", () => {
    const cvvFromKey = generateCvvFromKey(
      pan,
      expiry,
      derivedKey,
      "123e4567-e89b-12d3-a456-426614174000",
    );
    const cvvInline = generateCvv(pan, expiry, PASSKEY, COMPLIANCE);
    expect(cvvFromKey).toBe(cvvInline);
  });

  it("validateCvvFromKey returns true for correct derived key and keyId", () => {
    const cvv = generateCvvFromKey(pan, expiry, derivedKey, "123e4567-e89b-12d3-a456-426614174000");
    expect(
      validateCvvFromKey(pan, expiry, derivedKey, cvv, "123e4567-e89b-12d3-a456-426614174000"),
    ).toBe(true);
  });

  it("validateCvvFromKey returns false for wrong key", () => {
    const wrongKey = deriveHmacKey("a-completely-different-passkey!!", 1_000);
    const cvv = generateCvvFromKey(pan, expiry, derivedKey, "123e4567-e89b-12d3-a456-426614174000");
    expect(
      validateCvvFromKey(pan, expiry, wrongKey, cvv, "123e4567-e89b-12d3-a456-426614174000"),
    ).toBe(false);
    wrongKey.fill(0);
  });

  it("validateCvvFromKey returns false for wrong keyId", () => {
    const cvv = generateCvvFromKey(pan, expiry, derivedKey, "123e4567-e89b-12d3-a456-426614174000");
    expect(
      validateCvvFromKey(pan, expiry, derivedKey, cvv, "223e4567-e89b-12d3-a456-426614174000"),
    ).toBe(false);
  });

  it("generateCvvFromKey throws for non-32-byte derived key", () => {
    expect(() =>
      generateCvvFromKey(pan, expiry, Buffer.alloc(16), "123e4567-e89b-12d3-a456-426614174000"),
    ).toThrow(/32/);
  });

  afterAll(() => derivedKey.fill(0));
});

// ---------------------------------------------------------------------------
// parseExpiry
// ---------------------------------------------------------------------------

describe("parseExpiry", () => {
  it("parses valid MM/YY strings", () => {
    const { month, year } = parseExpiry("07/32");
    expect(month).toBe(7);
    expect(year).toBe(2032);
  });

  it("throws on invalid format", () => {
    expect(() => parseExpiry("7/32")).toThrow(/format/);
    expect(() => parseExpiry("07-32")).toThrow(/format/);
    expect(() => parseExpiry("2032/07")).toThrow(/format/);
  });

  it("throws on invalid month", () => {
    expect(() => parseExpiry("00/32")).toThrow(/month/);
    expect(() => parseExpiry("13/32")).toThrow(/month/);
  });
});

// ---------------------------------------------------------------------------
// maskPAN (PCI-DSS Req 3.5)
// ---------------------------------------------------------------------------

describe("maskPAN (PCI-DSS Req 3.5)", () => {
  it("masks the middle 6 digits, keeping first 6 and last 4", () => {
    expect(maskPAN("0011382910471836")).toBe("001138xxxxxx1836");
    expect(maskPAN("9212123456789012")).toBe("921212xxxxxx9012");
  });

  it("returns a 16-character string", () => {
    expect(maskPAN("0011382910471836")).toHaveLength(16);
  });

  it("masked section is exactly 'xxxxxx'", () => {
    expect(maskPAN("0011382910471836").substring(6, 12)).toBe("xxxxxx");
  });

  it("throws for non-16-digit input", () => {
    expect(() => maskPAN("001138291047183")).toThrow(/16/);
    expect(() => maskPAN("00113829104718360")).toThrow(/16/);
    expect(() => maskPAN("001138291047183A")).toThrow(/16/);
  });
});

// ---------------------------------------------------------------------------
// redactCardResult (PCI-DSS Req 3.3.1)
// ---------------------------------------------------------------------------

describe("redactCardResult (PCI-DSS Req 3.3.1)", () => {
  const card: CardResult = {
    pan: "0011382910471836",
    expiry: "07/32",
    cvv: "2941",
    keyId: "123e4567-e89b-12d3-a456-426614174000",
  };

  it("returns maskedPan, expiry, and keyId", () => {
    const storable = redactCardResult(card);
    expect(storable.maskedPan).toBe("001138xxxxxx1836");
    expect(storable.expiry).toBe("07/32");
    expect(storable.keyId).toBe("123e4567-e89b-12d3-a456-426614174000");
  });

  it("does NOT include cvv in the result", () => {
    expect("cvv" in redactCardResult(card)).toBe(false);
  });

  it("does NOT include full PAN in the result", () => {
    expect("pan" in redactCardResult(card)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// encryptPAN / decryptPAN (PCI-DSS Req 3.4.1)
// ---------------------------------------------------------------------------

describe("encryptPAN / decryptPAN (PCI-DSS Req 3.4.1)", () => {
  const key = generateEncryptionKey();

  it("round-trips: decrypt(encrypt(pan)) === pan", () => {
    const pan = "0011382910471836";
    expect(decryptPAN(encryptPAN(pan, key), key)).toBe(pan);
  });

  it("produces different ciphertext on every call (random IV)", () => {
    const pan = "0011382910471836";
    const e1 = encryptPAN(pan, key);
    const e2 = encryptPAN(pan, key);
    expect(e1.iv).not.toBe(e2.iv);
    expect(e1.ciphertext).not.toBe(e2.ciphertext);
  });

  it("EncryptedPAN has iv, ciphertext, authTag fields (all hex)", () => {
    const enc = encryptPAN("0011382910471836", key);
    expect(enc.iv).toMatch(/^[0-9a-f]+$/);
    expect(enc.ciphertext).toMatch(/^[0-9a-f]+$/);
    expect(enc.authTag).toMatch(/^[0-9a-f]+$/);
  });

  it("IV is 24 hex chars (12 bytes)", () => {
    expect(encryptPAN("0011382910471836", key).iv).toHaveLength(24);
  });

  it("authTag is 32 hex chars (16 bytes)", () => {
    expect(encryptPAN("0011382910471836", key).authTag).toHaveLength(32);
  });

  it("decryptPAN throws with wrong key (GCM integrity failure)", () => {
    expect(() =>
      decryptPAN(encryptPAN("0011382910471836", key), generateEncryptionKey()),
    ).toThrow();
  });

  it("decryptPAN throws if ciphertext is tampered", () => {
    const enc = encryptPAN("0011382910471836", key);
    const tampered = {
      ...enc,
      ciphertext: Buffer.from(
        Array.from(Buffer.from(enc.ciphertext, "hex")).map((b) => b ^ 0xff),
      ).toString("hex"),
    };
    expect(() => decryptPAN(tampered, key)).toThrow();
  });

  it("encryptPAN throws for non-16-digit PAN", () => {
    expect(() => encryptPAN("123", key)).toThrow(/16/);
  });

  it("encryptPAN throws for wrong-length key", () => {
    expect(() => encryptPAN("0011382910471836", Buffer.alloc(16))).toThrow(/32/);
  });

  it("generateEncryptionKey returns a 32-byte Buffer", () => {
    const k = generateEncryptionKey();
    expect(Buffer.isBuffer(k)).toBe(true);
    expect(k.length).toBe(32);
  });

  it("two generateEncryptionKey calls produce different keys", () => {
    expect(generateEncryptionKey().equals(generateEncryptionKey())).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Audit event hooks — CSF 2.0 DE.AE-02 / ISO 27001:2022 A.8.15
// ---------------------------------------------------------------------------

describe("Audit event hooks (CSF 2.0 DE.AE-02 / ISO 27001 A.8.15)", () => {
  it("emits key_initialized on EarnmoreClient construction", () => {
    const events: EarnmoreEvent[] = [];
    new EarnmoreClient(PASSKEY, { ...COMPLIANCE, onEvent: (e) => events.push(e) }).destroy();
    expect(events.some((e) => e.type === "key_initialized")).toBe(true);
  });

  it("emits key_destroyed on destroy()", () => {
    const events: EarnmoreEvent[] = [];
    const c = new EarnmoreClient(PASSKEY, { ...COMPLIANCE, onEvent: (e) => events.push(e) });
    c.destroy();
    expect(events.some((e) => e.type === "key_destroyed")).toBe(true);
  });

  it("emits card_generated on generate()", () => {
    const events: EarnmoreEvent[] = [];
    const c = new EarnmoreClient(PASSKEY, { ...COMPLIANCE, onEvent: (e) => events.push(e) });
    c.generate(SAMPLE_CUSTOMER);
    c.destroy();
    const ev = events.find((e) => e.type === "card_generated");
    expect(ev).toBeDefined();
    expect(ev!.maskedPan).toMatch(/^[0-9]{6}xxxxxx[0-9]{4}$/);
  });

  it("emits cvv_valid on successful validateCvv()", () => {
    const events: EarnmoreEvent[] = [];
    const c = new EarnmoreClient(PASSKEY, { ...COMPLIANCE, onEvent: (e) => events.push(e) });
    const card = c.generate(SAMPLE_CUSTOMER);
    c.validateCvv(card.pan, card.expiry, card.cvv);
    c.destroy();
    expect(events.some((e) => e.type === "cvv_valid")).toBe(true);
  });

  it("emits cvv_invalid on failed validateCvv()", () => {
    const events: EarnmoreEvent[] = [];
    const c = new EarnmoreClient(PASSKEY, { ...COMPLIANCE, onEvent: (e) => events.push(e) });
    const card = c.generate(SAMPLE_CUSTOMER);
    c.validateCvv(card.pan, card.expiry, "0000");
    c.destroy();
    expect(events.some((e) => e.type === "cvv_invalid")).toBe(true);
  });

  it("emits pan_encrypted and pan_decrypted", () => {
    const events: EarnmoreEvent[] = [];
    const c = new EarnmoreClient(PASSKEY, { ...COMPLIANCE, onEvent: (e) => events.push(e) });
    const card = c.generate(SAMPLE_CUSTOMER);
    const encKey = generateEncryptionKey();
    const enc = c.encryptPAN(card.pan, encKey);
    c.decryptPAN(enc, encKey);
    c.destroy();
    expect(events.some((e) => e.type === "pan_encrypted")).toBe(true);
    expect(events.some((e) => e.type === "pan_decrypted")).toBe(true);
  });

  it("events include the keyId and a timestamp", () => {
    const events: EarnmoreEvent[] = [];
    const c = new EarnmoreClient(PASSKEY, {
      ...COMPLIANCE,
      keyId: "323e4567-e89b-12d3-a456-426614174000",
      onEvent: (e) => events.push(e),
    });
    c.generate(SAMPLE_CUSTOMER);
    c.destroy();
    events.forEach((e) => {
      expect(e.keyId).toBe("323e4567-e89b-12d3-a456-426614174000");
      expect(e.timestamp).toBeInstanceOf(Date);
    });
  });

  it("events never contain a full PAN", () => {
    const events: EarnmoreEvent[] = [];
    const c = new EarnmoreClient(PASSKEY, { ...COMPLIANCE, onEvent: (e) => events.push(e) });
    const card = c.generate(SAMPLE_CUSTOMER);
    c.validateCvv(card.pan, card.expiry, card.cvv);
    c.destroy();
    events.forEach((e) => {
      if (e.maskedPan) {
        // maskedPan must not be the full 16-digit PAN — must contain x's
        expect(e.maskedPan).toMatch(/x/);
        expect(e.maskedPan).not.toMatch(/^\d{16}$/);
      }
    });
  });

  it("throws in onEvent callback are silently swallowed", () => {
    const c = new EarnmoreClient(PASSKEY, {
      ...COMPLIANCE,
      onEvent: () => {
        throw new Error("audit system down");
      },
    });
    expect(() => c.generate(SAMPLE_CUSTOMER)).not.toThrow();
    c.destroy();
  });
});

// ---------------------------------------------------------------------------
// Cryptoperiod — NIST SP 800-57 §5.3.6
// ---------------------------------------------------------------------------

describe("Cryptoperiod enforcement (NIST SP 800-57 §5.3.6)", () => {
  it("isKeyExpired() returns false for a freshly created client", () => {
    const c = new EarnmoreClient(PASSKEY, COMPLIANCE);
    expect(c.isKeyExpired()).toBe(false);
    c.destroy();
  });

  it("isKeyExpired() returns true for a key created 3 years ago (default 2-year limit)", () => {
    const threeYearsAgo = new Date(Date.now() - 3 * 365.25 * 24 * 60 * 60 * 1000);
    const c = new EarnmoreClient(PASSKEY, { ...COMPLIANCE, keyCreatedAt: threeYearsAgo });
    expect(c.isKeyExpired()).toBe(true);
    c.destroy();
  });

  it("isKeyExpired() returns false for a key 1 year old with 2-year limit", () => {
    const oneYearAgo = new Date(Date.now() - 365.25 * 24 * 60 * 60 * 1000);
    const c = new EarnmoreClient(PASSKEY, { ...COMPLIANCE, keyCreatedAt: oneYearAgo });
    expect(c.isKeyExpired()).toBe(false);
    c.destroy();
  });

  it("isKeyExpired(maxAgeYears) uses the provided limit", () => {
    const thirtyOneDaysAgo = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000);
    const c = new EarnmoreClient(PASSKEY, { ...COMPLIANCE, keyCreatedAt: thirtyOneDaysAgo });
    expect(c.isKeyExpired(0.1 /* ~36 days */)).toBe(false);
    expect(c.isKeyExpired(0.08 /* ~29 days */)).toBe(true);
    c.destroy();
  });
});

// ---------------------------------------------------------------------------
// EarnmoreClient — full API
// ---------------------------------------------------------------------------

describe("EarnmoreClient (key-caching class API)", () => {
  let client: EarnmoreClient;

  beforeEach(() => {
    client = new EarnmoreClient(PASSKEY, COMPLIANCE);
  });

  afterEach(() => {
    client.destroy();
  });

  it("generate() returns CardResult with pan, expiry, cvv, keyId", () => {
    const card = client.generate(SAMPLE_CUSTOMER);
    expect(card.pan).toMatch(/^\d{16}$/);
    expect(card.expiry).toMatch(/^\d{2}\/\d{2}$/);
    expect(card.cvv).toMatch(/^\d{4}$/);
    expect(card.keyId).toBe("123e4567-e89b-12d3-a456-426614174000");
  });

  it("generate() PAN passes Luhn", () => {
    expect(luhnValid(client.generate(SAMPLE_CUSTOMER).pan)).toBe(true);
  });

  it("generate() CVV validates via validateCvv()", () => {
    const card = client.generate(SAMPLE_CUSTOMER);
    expect(client.validateCvv(card.pan, card.expiry, card.cvv)).toBe(true);
  });

  it("validateCvv() result matches functional validateCvv()", () => {
    const card = client.generate(SAMPLE_CUSTOMER);
    const funcResult = validateCvv(card.pan, card.expiry, PASSKEY, card.cvv, COMPLIANCE);
    expect(client.validateCvv(card.pan, card.expiry, card.cvv)).toBe(funcResult);
  });

  it("validateCvv() returns false for wrong CVV", () => {
    const card = client.generate(SAMPLE_CUSTOMER);
    const wrong = String((parseInt(card.cvv, 10) + 1) % 10_000).padStart(4, "0");
    expect(client.validateCvv(card.pan, card.expiry, wrong)).toBe(false);
  });

  it("generateDynamicCvv() creates valid EMVCo cryptograms", () => {
    const card = client.generate(SAMPLE_CUSTOMER);
    const atc = 42;
    const dcvv = client.generateDynamicCvv(card.pan, card.expiry, atc);
    expect(dcvv).toMatch(/^\d{4}$/);
    expect(client.validateDynamicCvv(card.pan, card.expiry, atc, dcvv)).toBe(true);
  });

  it("validateDynamicCvv() rejects wrong ATCs or dCVVs", () => {
    const card = client.generate(SAMPLE_CUSTOMER);
    const atc = 42;
    const dcvv = client.generateDynamicCvv(card.pan, card.expiry, atc);
    expect(client.validateDynamicCvv(card.pan, card.expiry, atc + 1, dcvv)).toBe(false);
    expect(client.validateDynamicCvv(card.pan, card.expiry, atc, "0000")).toBe(false);
  });

  it("getKCV() returns a 6-char hex value (ISO 11568-2)", () => {
    expect(client.getKCV()).toMatch(/^[0-9a-f]{6}$/);
  });

  it("getKCV() is stable — same client returns same KCV", () => {
    expect(client.getKCV()).toBe(client.getKCV());
  });

  it("two different passkeys produce different KCVs", () => {
    const c2 = new EarnmoreClient("another-long-different-passkey!!", COMPLIANCE);
    expect(client.getKCV()).not.toBe(c2.getKCV());
    c2.destroy();
  });

  it("getKeyId() returns the client's keyId", () => {
    const c = new EarnmoreClient(PASSKEY, {
      ...COMPLIANCE,
      keyId: "423e4567-e89b-12d3-a456-426614174000",
    });
    expect(c.getKeyId()).toBe("423e4567-e89b-12d3-a456-426614174000");
    c.destroy();
  });

  it("maskPAN() delegates to standalone maskPAN()", () => {
    expect(client.maskPAN("0011382910471836")).toBe("001138xxxxxx1836");
  });

  it("redactCardResult() returns StorableCardData with keyId, without CVV", () => {
    const card = client.generate(SAMPLE_CUSTOMER);
    const storable = client.redactCardResult(card);
    expect("cvv" in storable).toBe(false);
    expect(storable.maskedPan).toMatch(/^[0-9x]{16}$/);
    expect(storable.expiry).toBe(card.expiry);
    expect(storable.keyId).toBe(card.keyId);
  });

  it("encryptPAN/decryptPAN round-trip via client", () => {
    const card = client.generate(SAMPLE_CUSTOMER);
    const encKey = generateEncryptionKey();
    expect(client.decryptPAN(client.encryptPAN(card.pan, encKey), encKey)).toBe(card.pan);
  });

  it("throws after destroy()", () => {
    const c = new EarnmoreClient(PASSKEY, COMPLIANCE);
    c.destroy();
    expect(() => c.generate(SAMPLE_CUSTOMER)).toThrow(/destroyed/);
    expect(() => c.validateCvv("0011382910471836", "07/32", "1234")).toThrow(/destroyed/);
    expect(() => c.getKCV()).toThrow(/destroyed/);
  });

  it("destroy() is idempotent — calling twice does not throw", () => {
    const c = new EarnmoreClient(PASSKEY, COMPLIANCE);
    expect(() => {
      c.destroy();
      c.destroy();
    }).not.toThrow();
  });

  it("throws if passkey is shorter than 16 chars", () => {
    expect(() => new EarnmoreClient("short", COMPLIANCE)).toThrow(/16/);
  });
});

// ---------------------------------------------------------------------------
// generate() — full integration
// ---------------------------------------------------------------------------

describe("generate() — full integration", () => {
  it("returns CardResult with pan, expiry, cvv, keyId", () => {
    const card = generate(SAMPLE_CUSTOMER, PASSKEY, COMPLIANCE);
    expect(card.pan).toBeDefined();
    expect(card.expiry).toBeDefined();
    expect(card.cvv).toBeDefined();
    expect(card.keyId).toBe("123e4567-e89b-12d3-a456-426614174000");
  });

  it("PAN is 16 digits and passes Luhn", () => {
    const card = generate(SAMPLE_CUSTOMER, PASSKEY, COMPLIANCE);
    expect(card.pan).toMatch(/^\d{16}$/);
    expect(luhnValid(card.pan)).toBe(true);
  });

  it("PAN starts with an allowed prefix", () => {
    for (let i = 0; i < 10; i++) {
      const card = generate(SAMPLE_CUSTOMER, PASSKEY, COMPLIANCE);
      expect(ALLOWED_PREFIXES.some((p) => card.pan.startsWith(p))).toBe(true);
    }
  });

  it("expiry is in MM/YY format within 4-7 years", () => {
    const cy = new Date().getFullYear();
    const card = generate(SAMPLE_CUSTOMER, PASSKEY, COMPLIANCE);
    expect(card.expiry).toMatch(/^\d{2}\/\d{2}$/);
    const year = 2000 + parseInt(card.expiry.split("/")[1], 10);
    expect(year).toBeGreaterThanOrEqual(cy + 4);
    expect(year).toBeLessThanOrEqual(cy + 7);
  });

  it("CVV is exactly 4 digits", () => {
    expect(generate(SAMPLE_CUSTOMER, PASSKEY, COMPLIANCE).cvv).toMatch(/^\d{4}$/);
  });

  it("CVV validates successfully with same passkey and keyId", () => {
    const config = { ...COMPLIANCE, keyId: "523e4567-e89b-12d3-a456-426614174000" };
    const card = generate(SAMPLE_CUSTOMER, PASSKEY, config);
    expect(validateCvv(card.pan, card.expiry, PASSKEY, card.cvv, config)).toBe(true);
  });

  it("CVV does not validate with a different passkey", () => {
    const card = generate(SAMPLE_CUSTOMER, PASSKEY, COMPLIANCE);
    expect(
      validateCvv(card.pan, card.expiry, "another-long-passkey-xyz123", card.cvv, COMPLIANCE),
    ).toBe(false);
  });

  it("two generate() calls for the same customer produce different PANs", () => {
    const c1 = generate(SAMPLE_CUSTOMER, PASSKEY, COMPLIANCE);
    const c2 = generate(SAMPLE_CUSTOMER, PASSKEY, COMPLIANCE);
    expect(c1.pan).not.toBe(c2.pan);
  });

  it("throws when birthPlace is invalid", () => {
    expect(() =>
      generate({ ...SAMPLE_CUSTOMER, birthPlace: "M@nila1" }, PASSKEY, COMPLIANCE),
    ).toThrow(/birthPlace/);
  });

  it("throws when passkey is shorter than 16 chars", () => {
    expect(() => generate(SAMPLE_CUSTOMER, "tooshort", COMPLIANCE)).toThrow(/16/);
  });

  it("works with minimal customer (no middleName, no address line2)", () => {
    const minimal: CustomerInfo = {
      firstName: "Jose",
      middleName: "",
      lastName: "Reyes",
      address: {
        line1: "456 Mabini Avenue",
        city: "Cebu City",
        country: "Philippines",
        zipCode: "6000",
      },
      birthday: new Date("1985-11-22"),
      birthPlace: "Cebu",
      idDocument: { type: "passport", number: "EC1234567" },
    };
    const card = generate(minimal, PASSKEY, COMPLIANCE);
    expect(luhnValid(card.pan)).toBe(true);
    expect(validateCvv(card.pan, card.expiry, PASSKEY, card.cvv, COMPLIANCE)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PAN prefix distribution
// ---------------------------------------------------------------------------

describe("PAN prefix distribution", () => {
  it("all 6 allowed prefixes appear across many generated cards", () => {
    const fp = customerFingerprint(SAMPLE_CUSTOMER);
    const counts: Record<string, number> = {};
    // eslint-disable-next-line security/detect-object-injection
    ALLOWED_PREFIXES.forEach((p) => (counts[p] = 0));
    for (let i = 0; i < 300; i++) {
      const { pan } = generatePAN(fp);
      const prefix = ALLOWED_PREFIXES.find((p) => pan.startsWith(p));
      // eslint-disable-next-line security/detect-object-injection
      if (prefix) counts[prefix]++;
    }
    // eslint-disable-next-line security/detect-object-injection
    ALLOWED_PREFIXES.forEach((p) => expect(counts[p]).toBeGreaterThan(0));
  });
});
