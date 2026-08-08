---
title: validateCvv
kind: function
longname: module:cvv.validateCvv
description: Validates a 4-digit CVV, deriving the HMAC key inline. Uses PBKDF2 on each call — use validateCvvFromKey() for frequent validation.
---

# validateCvv

<Signature
  code="validateCvv(
	pan: string,
	expiry: string,
	passkey: string,
	cvv: string,
	config: ComplianceConfig,
): boolean"
/>

<SourceLink href="/source/cvv-ts/#L263" label="cvv.ts:263" />

Validates a 4-digit CVV, deriving the HMAC key inline. Uses PBKDF2 on each call — use validateCvvFromKey() for frequent validation.

**Parameters**

- `pan` (string) — 16-digit PAN string
- `expiry` (string) — "MM/YY" formatted expiry string
- `passkey` (string) — The same passkey used to generate the CVV
- `cvv` (string) — The 4-digit CVV to validate
- `config` ([ComplianceConfig](/module/types/complianceconfig)) — Optional compliance config (pbkdf2Iterations, keyId, onEvent)

**Returns**

- `boolean`
