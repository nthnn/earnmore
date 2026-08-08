---
title: validateCvvFromKey
kind: function
longname: module:cvv.validateCvvFromKey
description: Validates a 4-digit CVV using a pre-derived HMAC key. Uses constant-time comparison (timingSafeEqual) to prevent timing attacks.
---

# validateCvvFromKey

<Signature
  code="validateCvvFromKey(
	pan: string,
	expiry: string,
	derivedKey: Buffer,
	cvv: string,
	keyId: string,
): boolean"
/>

<SourceLink href="/source/cvv-ts/#L149" label="cvv.ts:149" />

Validates a 4-digit CVV using a pre-derived HMAC key. Uses constant-time comparison (timingSafeEqual) to prevent timing attacks.

**Parameters**

- `pan` (string) — 16-digit PAN string
- `expiry` (string) — "MM/YY" formatted expiry string
- `derivedKey` (Buffer) — 32-byte key from deriveHmacKey()
- `cvv` (string) — The 4-digit CVV to validate
- `keyId` (string) — Key identifier — must match the keyId used during issuance. Default: DEFAULT\_KEY\_ID ("default")

**Returns**

- `boolean`
