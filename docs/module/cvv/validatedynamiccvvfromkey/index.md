---
title: validateDynamicCvvFromKey
kind: function
longname: module:cvv.validateDynamicCvvFromKey
description: Validates a dynamic CVV (dCVV) using a pre-derived HMAC key.
---

# validateDynamicCvvFromKey

<Signature
  code="validateDynamicCvvFromKey(
	pan: string,
	expiry: string,
	atc: number,
	derivedKey: Buffer,
	dcvv: string,
	keyId: string,
): boolean"
/>

<SourceLink href="/source/cvv-ts/#L202" label="cvv.ts:202" />

Validates a dynamic CVV (dCVV) using a pre-derived HMAC key.

**Parameters**

- `pan` (string)
- `expiry` (string)
- `atc` ([number](/module/types/iddocument#number))
- `derivedKey` (Buffer)
- `dcvv` (string)
- `keyId` (string)

**Returns**

- `boolean`
