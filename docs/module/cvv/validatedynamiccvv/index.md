---
title: validateDynamicCvv
kind: function
longname: module:cvv.validateDynamicCvv
description: Validates a dynamic CVV (dCVV), deriving the HMAC key inline.
---

# validateDynamicCvv

<Signature
  code="validateDynamicCvv(
	pan: string,
	expiry: string,
	atc: number,
	passkey: string,
	dcvv: string,
	config: ComplianceConfig,
): boolean"
/>

<SourceLink href="/source/cvv-ts/#L321" label="cvv.ts:321" />

Validates a dynamic CVV (dCVV), deriving the HMAC key inline.

**Parameters**

- `pan` (string)
- `expiry` (string)
- `atc` ([number](/module/types/iddocument#number))
- `passkey` (string)
- `dcvv` (string)
- `config` ([ComplianceConfig](/module/types/complianceconfig))

**Returns**

- `boolean`
