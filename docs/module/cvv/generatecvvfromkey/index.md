---
title: generateCvvFromKey
kind: function
longname: module:cvv.generateCvvFromKey
description: Generates a 4-digit CVV using a pre-derived HMAC key. Prefer this overload for repeated calls — derive the key once with deriveHmacKey() and reuse the Buffer (e.g. inside EarnmoreClient).
---

# generateCvvFromKey

<Signature
  code="generateCvvFromKey(
	pan: string,
	expiry: string,
	derivedKey: Buffer,
	keyId: string,
): string"
/>

<SourceLink href="/source/cvv-ts/#L120" label="cvv.ts:120" />

Generates a 4-digit CVV using a pre-derived HMAC key.

Prefer this overload for repeated calls — derive the key once with deriveHmacKey() and reuse the Buffer (e.g. inside EarnmoreClient).

**Parameters**

- `pan` (string) — 16-digit PAN string
- `expiry` (string) — "MM/YY" formatted expiry string
- `derivedKey` (Buffer) — 32-byte key from deriveHmacKey()
- `keyId` (string) — Key identifier (NIST SP 800-57 / ISO 11568-1). Must match the keyId used during validation. Default: DEFAULT\_KEY\_ID ("default")

**Returns**

- `string`
