---
title: generateDynamicCvvFromKey
kind: function
longname: module:cvv.generateDynamicCvvFromKey
description: Generates an EMVCo-style dynamic CVV using a pre-derived HMAC key. Binds an Application Transaction Counter (ATC) to the cryptogram.
---

# generateDynamicCvvFromKey

<Signature
  code="generateDynamicCvvFromKey(
	pan: string,
	expiry: string,
	atc: number,
	derivedKey: Buffer,
	keyId: string,
): string"
/>

<SourceLink href="/source/cvv-ts/#L177" label="cvv.ts:177" />

Generates an EMVCo-style dynamic CVV using a pre-derived HMAC key. Binds an Application Transaction Counter (ATC) to the cryptogram.

**Parameters**

- `pan` (string) — 16-digit PAN string
- `expiry` (string) — "MM/YY" formatted expiry string
- `atc` ([number](/module/types/iddocument#number)) — Application Transaction Counter (integer)
- `derivedKey` (Buffer) — 32-byte key from deriveHmacKey()
- `keyId` (string) — Key identifier. Default: DEFAULT\_KEY\_ID

**Returns**

- `string`
