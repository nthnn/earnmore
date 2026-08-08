---
title: earnmore
kind: index
---

# EarnMore

[![CI/CD](https://github.com/nthnn/earnmore/actions/workflows/ci.yml/badge.svg)](https://github.com/nthnn/earnmore/actions/workflows/ci.yml)

EarnMore is a zero-dependency, cryptographically secure Node.js library engineered for issuing, validating, and managing closed-loop reward and gift card networks.

It deterministically generates 16-digit Primary Account Numbers (PANs), secure Expiry Dates, and dynamic HMAC-based CVV/CVC cryptograms strictly from customer identity fingerprints.

**Compliant with:**

![PCI-DSS](/_assets/pci-dss.996cf3a5.png) ![EMVCo](/_assets/emvco.a8d2b725.png) ![HIPAA](/_assets/hipaa.477acba9.png) ![GDPR](/_assets/gdpr.04d11aa2.png) ![NIST](/_assets/nist-csf.3883380b.png)

Built from the ground up for financial-grade security, EarnMore is designed to ensure out-of-the-box compliance with enterprise standards including **PCI-DSS v4.0**, **NIST SP 800-90A/57**, **EMVCo Tokenization**, and **GDPR/HIPAA** data minimization requirements.

- **Cryptographically Secure PAN Generation**: Employs a formal NIST SP 800-90A Rev.1 `HMAC_DRBG` state machine alongside FIPS 186-5 rejection sampling to generate unbiased, mathematically unique 16-digit PANs (incorporating valid BIN prefixes and standard Luhn check digits).
- **Dynamic & Static CVV Cryptograms**: Supports standard static CVVs as well as EMVCo-compliant Application Transaction Counter (ATC) based dynamic dCVVs to cryptographically protect networks against replay attacks.
- **Robust Key Management & Versioning**: Derives keys securely via PBKDF2-SHA256 (310,000+ iterations), strictly enforces key-purpose separation (PCI Req 3.7.5), and utilizes UUID-bound message injection (`keyId`) to seamlessly enable historical key rotation lookups without requiring card reissuance.
- **Advanced At-Rest Data Protection**: Natively provides authenticated AES-256-GCM encryption with 16-byte integrity tags for secure database storage (PCI Req 3.4.1), and explicitly redacts Sensitive Authentication Data (SAD) like CVVs from returned payloads (PCI Req 3.3.1).
- **Strict PII Data Minimization**: Protects against memory heap-dump leaks by proactively providing memory-scrubbing utilities (`scrubCustomerData()`) that overwrite Personally Identifiable Information (PII) with zero-bytes in-memory, mitigating risks before V8 garbage collection occurs.
- **Zero External Dependencies**: Operates entirely utilizing Node.js's native `crypto` module, completely eliminating third-party NPM supply chain vulnerabilities (NIST SSDF compliant) and ensuring a drastically reduced attack surface.

## Standards & Compliance

EarnMore is designed to meet strict regulatory and cryptographic standards:

- **PCI-DSS v4.0**

  - Req 3.3.1: SAD (CVV) redaction via `redactCardResult()`
  - Req 3.4.1: PAN encryption at rest via AES-256-GCM (`encryptPAN()`)
  - Req 3.5: PAN masking (`maskPAN()`)
  - Req 3.7.5: Key-purpose separation (encryption key vs HMAC passkey)
  - Req 6.2.4: Cryptographically secure random number generation (CSPRNG)

- **PCI Secure Software Standard (PCI SSS) / SSF**: Automated dependency scanning and ESLint security analysis (`npm run test:security`) for continuous lifecycle validation.

- **GDPR / CCPA / HIPAA (Data Minimization)**: Provides `scrubCustomerData(customer)` to explicitly overwrite PII strings with zeroes in-memory, mitigating data leakage during heap dumps before garbage collection.

- **EMVCo Tokenization Standard**: Supports Application Transaction Counter (ATC) based Dynamic CVV / Cryptogram generation (`generateDynamicCvv()`) to protect against replay attacks.

- **NIST SP 800-57 / ISO 11568-1**: Key versioning (using `keyId` in the CVV message) to enable seamless passkey rotation without full card reissuance.

- **NIST SP 800-57 §5.3.6**: Cryptoperiod enforcement (monitoring key age via `isKeyExpired()`).

- **ISO 11568-2**: Key Check Value (`getKCV()`) for non-secret passkey verification on startup.

- **NIST CSF 2.0 (DE.AE-02) / ISO/IEC 27001:2022 (A.8.15)**: Audit event hooks (`onEvent`) for SIEM integration and anomaly detection.

- **NIST SP 800-218 (SSDF) / ISO/IEC 27002:2022 (A.8.25)**: Strict input length limits to prevent DoS attacks during SHA-256 hashing.

- **FIPS 180-4 / FIPS 198-1**: SHA-256 and HMAC-SHA256 for all hashing and MAC operations.

- **FIPS 186-5 §B.4.2**: Rejection sampling to ensure unbiased random digit selection.

- **NIST SP 800-132**: PBKDF2-SHA256 key stretching (default 310,000 iterations).

- **ISO/IEC 7812**: Luhn check digit validation.

- **NIST SP 800-90A Rev.1**: Formal `HMAC_DRBG` state machine implementation for cryptographically secure pseudo-random number generation.

## Installation

```bash
npm install earnmore

# or

yarn add earnmore
```

> Requires **Node.js ≥ 16** (uses `crypto.randomBytes`, `crypto.createHmac`, `crypto.timingSafeEqual`).

## Algorithm Details

### PAN & Expiry Generation (SP 800-90A HMAC\_DRBG)

1. **Fingerprint**: The `CustomerInfo` is normalized and hashed via SHA-256.
1. **Salted Seed**: `crypto.randomBytes(16)` is concatenated with the fingerprint and hashed again to form a 32-byte seed.
1. **CSPRNG**: The formal NIST SP 800-90A Rev.1 `HMAC_DRBG` state machine is instantiated with the seed.
1. **Domain Separation**: `HMAC_DRBG` is seeded with context `"earnmore:pan"` to draw 11 unbiased digits (via FIPS 186-5 rejection sampling), combined with a network prefix and a calculated Luhn check digit. A completely separate `HMAC_DRBG` instance is seeded with `"earnmore:expiry"` to draw the expiry month and year.

![PAN & Expiry Generation Flowchart](/_assets/pan_and_expiry_generation.b4b9388c.png)

### CVV Generation

1. **Key Derivation**: `PBKDF2-SHA256` is applied to the secret `passkey` using the domain-separated salt `"earnmore:cvv:v1"` and a minimum of `310,000` iterations to derive a secure `32-byte` HMAC key.
1. **Message Construction**: The core message payload is constructed by concatenating the `keyId`, `pan`, and `expiry` (and optionally an Application Transaction Counter, `atc`), each separated by a pipe `"|"` delimiter.
1. **HMAC Application**: An `HMAC-SHA256` signature is computed over the message payload using the derived PBKDF2 key.
1. **Truncation and Padding**: The first 4 bytes (8 hex characters) of the resulting HMAC digest are converted to an integer, a modulo of `10,000` is applied, and the output is zero-padded to generate a mathematically uniform 4-digit CVV.

![CVV Generation Flowchart](/_assets/cvv_generation.6ef9b2a8.png)

### Key Check Value (KCV)

1. **Constant Definition**: A standard deterministic check string `"earnmore:kcv:check"` is defined as the input material.
1. **HMAC Calculation**: `HMAC-SHA256` is calculated over the check string using the 32-byte derived HMAC key.
1. **Truncation**: The resulting Message Authentication Code (MAC) is truncated to exactly the first 3 bytes (6 hexadecimal characters) to formulate the KCV.
1. **Validation**: This securely allows systems to verify key rotation and parity across environments (conceptually similar to ISO 11568-2) without exposing or leaking any underlying key material.

![Key Check Value Flowchart](/_assets/key_check_value.8fbb8845.png)

### PAN Storage & Encryption (AES-256-GCM)

1. **Initialization Vector (IV)**: A cryptographically secure 12-byte (96-bit) IV is generated dynamically via `crypto.randomBytes(12)` per NIST SP 800-38D recommendations.
1. **Cipher Setup**: The `aes-256-gcm` cipher is instantiated utilizing a strict 32-byte encryption key (cryptographically separated from the CVV passkey) alongside the generated IV, enforcing a 16-byte authentication tag length.
1. **Encryption**: The plaintext PAN string is securely encrypted into ciphertext.
1. **Integrity Tagging**: The 128-bit GCM authentication tag is extracted from the cipher state to guarantee future decryption integrity.
1. **Storage Formatting**: The IV, Ciphertext, and Auth Tag are encoded as hexadecimal strings and returned for compliant at-rest storage satisfying PCI-DSS Req 3.4.1.

![PAN Storage & Encryption Flowchart](/_assets/pan_storage_and_encryption.50983b8c.png)

### PAN Masking & Redaction

1. **Format Validation**: The input PAN is strictly validated via regex to ensure it consists of exactly 16 numeric digits.
1. **Display Masking**: The PAN is spliced into three discrete segments: the first 6 digits (Bank Identification Number / BIN), a hardcoded 6-character mask (`"xxxxxx"`), and the last 4 digits. This satisfies PCI-DSS Req 3.5 display masking constraints.
1. **SAD Redaction**: During object generation, Sensitive Authentication Data (SAD)—namely the CVV—is explicitly dropped and omitted from the return payload structure. Only non-sensitive Cardholder Data (CHD) is returned, enforcing strict compliance with PCI-DSS Req 3.3.1.

![PAN Masking and Redaction Flowchart](/_assets/pan_masking_and_reduction.08cbb52c.png)

### CVV & dCVV Validation

1. **Recalculation**: The library recalculates the expected CVV dynamically utilizing the identically derived PBKDF2 HMAC key, original PAN, Expiry, and (if dynamic) the ATC.
1. **Buffer Conversion**: Both the recalculated CVV and the user-provided CVV are strictly cast into `utf8` binary Buffers.
1. **Length Parity Check**: An immediate length parity evaluation is performed to reject non-uniform inputs prior to deeper analysis.
1. **Constant-Time Comparison**: `crypto.timingSafeEqual(a, b)` enforces byte-for-byte comparison strictly in constant time, completely eliminating susceptibility to cryptographic timing side-channel attacks.

![CVV & dCVV Validation Flowchart](/_assets/cvv_and_dcvv_validation_.38c602d9.png)

### PAN Decryption & Integrity (AES-256-GCM)

1. **Parameter Reconstruction**: The stored IV, Ciphertext, and 16-byte GCM Auth Tag are decoded from their hexadecimal string representations back into raw binary Buffers.
1. **Decipher Initialization**: A `createDecipheriv` execution context is provisioned utilizing the active 32-byte encryption key alongside the retrieved IV.
1. **Tag Binding**: The expected authentication tag is explicitly bound to the decipher engine via `decipher.setAuthTag()` prior to any decryption operations.
1. **Authenticated Decryption**: During `decipher.final()`, the GCM polynomial MAC is mathematically verified. If cryptographic tampering or corruption is detected, an exception is aggressively thrown and absolutely no plaintext PAN data is exposed into memory.

![PAN Decryption and Integrity Flowchart](/_assets/pan_decryption_and_integrity.a5aca7cf.png)

### Key Rotation & Versioning

1. **UUID Binding**: All core cryptographic operations rigidly require a `keyId` parameter, fundamentally enforced as a valid UUID.
1. **Message Embedding**: The `keyId` is natively injected into the HMAC message payload (e.g., `message = keyId + "|" + pan + ...`).
1. **Implicit Versioning**: Because the `keyId` contributes heavily to the resulting HMAC digest, any generated CVV is permanently mathematically bound to the specific key version that originally issued it.
1. **Seamless Rotation**: To safely rotate keys, consuming systems merely provision a new key/keyId pair. The library consumes the `keyId` directly from the user's `StorableCardData` object to effortlessly coordinate lookups against the correct historical key for decryption or validation routines.

![Key Rotation & Versioning Flowchart](/_assets/key_rotation_and_versioning.d9a89c87.png)

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run tests with coverage
npm run test:coverage
```

## Allowed BIN Prefixes

| Prefix | Description     |
| ------ | --------------- |
| `0011` | Network range A |
| `9212` | Network range B |
| `0513` | Network range C |
| `8989` | Network range D |
| `7312` | Network range E |
| `9876` | Network range F |

## License

[GNU Affero General Public License v3.0](LICENSE)
