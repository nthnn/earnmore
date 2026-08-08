---
title: EarnmoreClient
kind: class
longname: module:index.EarnmoreClient
description: "A stateful client that derives the PBKDF2 HMAC key once at construction and caches it for fast repeated operations. Implements: Key versioning (NIST SP 800-57 / ISO 11568-1): keyId in constructor Key Check Value (ISO 11568-2): getKCV() Cryptoperiod enforcement (NIST SP 800-57 §5.3.6): isKeyExpired() Audit event hooks (CSF 2.0 DE.AE-02 / ISO 27001:2022 A.8.15): onEvent Secure key zeroing on decommission: destroy()"
---

# EarnmoreClient

<SourceLink href="/source/index-ts/#L167" label="index.ts:167" />

A stateful client that derives the PBKDF2 HMAC key once at construction and caches it for fast repeated operations.

Implements:

- Key versioning (NIST SP 800-57 / ISO 11568-1): `keyId` in constructor
- Key Check Value (ISO 11568-2): `getKCV()`
- Cryptoperiod enforcement (NIST SP 800-57 §5.3.6): `isKeyExpired()`
- Audit event hooks (CSF 2.0 DE.AE-02 / ISO 27001:2022 A.8.15): `onEvent`
- Secure key zeroing on decommission: `destroy()`

---

## Constructors

<MemberHeading
  id="constructor"
  depth="3"
  name="constructor"
  sig="new EarnmoreClient(
	passkey: string,
	config: ComplianceConfig,
): EarnmoreClient"
/>

**Parameters**

- `passkey` (string) — Secret passkey string (≥16 chars)
- `config` ([ComplianceConfig](/module/types/complianceconfig)) — Optional compliance config:

**Returns**

`EarnmoreClient`

---

## Methods

<MemberHeading
  id="decryptpan"
  depth="3"
  name="decryptPAN"
  sig="decryptPAN(
	encrypted: EncryptedPAN,
	encryptionKey: Buffer,
): string"
/>

<MemberMeta sourceHref="/source/index-ts/#L342" sourceLabel="index.ts:342" />

Decrypts an EncryptedPAN.

**Parameters**

- `encrypted` ([EncryptedPAN](/module/types/encryptedpan)) — Result from encryptPAN()
- `encryptionKey` (Buffer) — The same 32-byte key used for encryption

**Returns**

- `string`

<MemberHeading id="destroy" depth="3" name="destroy" sig="destroy(): void" />

<MemberMeta sourceHref="/source/index-ts/#L376" sourceLabel="index.ts:376" />

Zeros the cached derived key and marks this client as destroyed. Call this when the client will no longer be used to clear key material from process memory.

**Returns**

- `void`

<MemberHeading id="encryptpan" depth="3" name="encryptPAN" sig="encryptPAN(pan: string, encryptionKey: Buffer): EncryptedPAN" />

<MemberMeta sourceHref="/source/index-ts/#L324" sourceLabel="index.ts:324" />

Encrypts a PAN for at-rest storage (AES-256-GCM).

**Parameters**

- `pan` (string) — 16-digit PAN
- `encryptionKey` (Buffer) — 32-byte key — MUST be different from the CVV passkey (PCI-DSS Req 3.7.5)

**Returns**

- [`EncryptedPAN`](/module/types/encryptedpan)

<MemberHeading id="generate" depth="3" name="generate" sig="generate(customer: CustomerInfo): CardResult" />

<MemberMeta sourceHref="/source/index-ts/#L216" sourceLabel="index.ts:216" />

Generates a unique card from customer identity data. CVV is derived using the cached HMAC key and this client's keyId.

⚠️ Store card.keyId alongside the card record — required for validation after key rotation (NIST SP 800-57 / ISO 11568-1).

**Parameters**

- `customer` ([CustomerInfo](/module/types/customerinfo))

**Returns**

- [`CardResult`](/module/types/cardresult)

<MemberHeading
  id="generatedynamiccvv"
  depth="3"
  name="generateDynamicCvv"
  sig="generateDynamicCvv(
	pan: string,
	expiry: string,
	atc: number,
): string"
/>

<MemberMeta sourceHref="/source/index-ts/#L254" sourceLabel="index.ts:254" />

Generates a dynamic CVV (dCVV) using this client's cached HMAC key. EMVCo cryptograms bind an Application Transaction Counter (ATC) to the message.

**Parameters**

- `pan` (string)
- `expiry` (string)
- `atc` ([number](/module/types/iddocument#number))

**Returns**

- `string`

<MemberHeading id="getkcv" depth="3" name="getKCV" sig="getKCV(): string" />

<MemberMeta sourceHref="/source/index-ts/#L290" sourceLabel="index.ts:290" />

Returns the Key Check Value (KCV) for this client's derived key.

The KCV is a non-secret 6-character hex fingerprint (ISO 11568-2). Store it alongside your key configuration and verify on startup to confirm the correct passkey was loaded.

**Returns**

- `string` — 6-character hex KCV (e.g. "a3f2c1")

<MemberHeading id="getkeyid" depth="3" name="getKeyId" sig="getKeyId(): string" />

<MemberMeta sourceHref="/source/index-ts/#L299" sourceLabel="index.ts:299" />

Returns the key identifier this client was initialized with. Store alongside card records for key rotation support.

**Returns**

- `string`

<MemberHeading id="iskeyexpired" depth="3" name="isKeyExpired" sig="isKeyExpired(maxAgeYears: number): boolean" />

<MemberMeta sourceHref="/source/index-ts/#L312" sourceLabel="index.ts:312" />

Checks whether this key has exceeded its recommended cryptoperiod.

Per NIST SP 800-57 Part 1 Rev.5 §5.3.6, HMAC authentication keys should not be used beyond 2 years (NIST\_HMAC\_KEY\_MAX\_YEARS).

**Parameters**

- `maxAgeYears` ([number](/module/types/iddocument#number), default: "NIST\_HMAC\_KEY\_MAX\_YEARS") — Maximum key age in years. Default: NIST\_HMAC\_KEY\_MAX\_YEARS (2)

**Returns**

- `boolean` — true if the key age exceeds maxAgeYears

<MemberHeading id="maskpan" depth="3" name="maskPAN" sig="maskPAN(pan: string): string" />

<MemberMeta sourceHref="/source/index-ts/#L358" sourceLabel="index.ts:358" />

Masks a PAN per PCI-DSS Req 3.5. Returns first 6 + 6 masked chars + last 4.

**Parameters**

- `pan` (string)

**Returns**

- `string`

<MemberHeading id="redactcardresult" depth="3" name="redactCardResult" sig="redactCardResult(result: CardResult): StorableCardData" />

<MemberMeta sourceHref="/source/index-ts/#L367" sourceLabel="index.ts:367" />

Strips CVV (SAD) from a CardResult, returning a StorableCardData object safe to persist per PCI-DSS Req 3.3.1. The keyId is preserved in StorableCardData for future validation.

**Parameters**

- `result` ([CardResult](/module/types/cardresult))

**Returns**

- [`StorableCardData`](/module/types/storablecarddata)

<MemberHeading id="validatecvv" depth="3" name="validateCvv" sig="validateCvv(pan: string, expiry: string, cvv: string): boolean" />

<MemberMeta sourceHref="/source/index-ts/#L238" sourceLabel="index.ts:238" />

Validates a CVV using this client's cached HMAC key and keyId. Uses constant-time comparison — no PBKDF2 per call.

For cards issued under a different keyId, use the corresponding EarnmoreClient instance (with the matching passkey and keyId).

**Parameters**

- `pan` (string)
- `expiry` (string)
- `cvv` (string)

**Returns**

- `boolean`

<MemberHeading
  id="validatedynamiccvv"
  depth="3"
  name="validateDynamicCvv"
  sig="validateDynamicCvv(
	pan: string,
	expiry: string,
	atc: number,
	dcvv: string,
): boolean"
/>

<MemberMeta sourceHref="/source/index-ts/#L269" sourceLabel="index.ts:269" />

Validates a dynamic CVV (dCVV) using this client's cached HMAC key.

**Parameters**

- `pan` (string)
- `expiry` (string)
- `atc` ([number](/module/types/iddocument#number))
- `dcvv` (string)

**Returns**

- `boolean`
