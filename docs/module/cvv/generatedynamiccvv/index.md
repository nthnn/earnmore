---
title: generateDynamicCvv
kind: function
longname: module:cvv.generateDynamicCvv
description: Generates a dynamic CVV (dCVV), deriving the HMAC key inline.
---

# generateDynamicCvv

<Signature
  code="generateDynamicCvv(
	pan: string,
	expiry: string,
	atc: number,
	passkey: string,
	config: ComplianceConfig,
): string"
/>

<SourceLink href="/source/cvv-ts/#L294" label="cvv.ts:294" />

Generates a dynamic CVV (dCVV), deriving the HMAC key inline.

**Parameters**

- `pan` (string)
- `expiry` (string)
- `atc` ([number](/module/types/iddocument#number))
- `passkey` (string)
- `config` ([ComplianceConfig](/module/types/complianceconfig))

**Returns**

- `string`
