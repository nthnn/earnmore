---
title: generateCvv
kind: function
longname: module:cvv.generateCvv
description: Generates a 4-digit CVV, deriving the HMAC key inline. Use generateCvvFromKey() + a cached derivedKey for repeated calls.
---

# generateCvv

<Signature
  code="generateCvv(
	pan: string,
	expiry: string,
	passkey: string,
	config: ComplianceConfig,
): string"
/>

<SourceLink href="/source/cvv-ts/#L230" label="cvv.ts:230" />

Generates a 4-digit CVV, deriving the HMAC key inline. Use generateCvvFromKey() + a cached derivedKey for repeated calls.

**Parameters**

- `pan` (string) — 16-digit PAN string
- `expiry` (string) — "MM/YY" formatted expiry string
- `passkey` (string) — Secret passkey (≥16 chars)
- `config` ([ComplianceConfig](/module/types/complianceconfig)) — Optional compliance config (pbkdf2Iterations, keyId, onEvent)

**Returns**

- `string`
