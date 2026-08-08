---
title: generate
kind: function
longname: module:index.generate
description: Generates a unique closed-loop reward card (PAN + expiry + CVV + keyId) from customer identity data. Every call produces a different PAN even for the same customer, because a CSPRNG salt is mixed into the hash before digit generation. ⚠️ The returned cvv is SAD — do not persist it. Store keyId alongside the card record for future validation. Call redactCardResult() before saving.
---

# generate

<Signature
  code="generate(
	customer: CustomerInfo,
	passkey: string,
	config: ComplianceConfig,
): CardResult"
/>

<SourceLink href="/source/index-ts/#L132" label="index.ts:132" />

Generates a unique closed-loop reward card (PAN + expiry + CVV + keyId) from customer identity data.

Every call produces a **different** PAN even for the same customer, because a CSPRNG salt is mixed into the hash before digit generation.

⚠️ The returned `cvv` is SAD — do not persist it. Store `keyId` alongside the card record for future validation. Call `redactCardResult()` before saving.

**Parameters**

- `customer` ([CustomerInfo](/module/types/customerinfo)) — Full customer identity information
- `passkey` (string) — Secret passkey (≥16 chars) for CVV HMAC key derivation. Must be distinct from any PAN encryption key.
- `config` ([ComplianceConfig](/module/types/complianceconfig)) — Optional compliance config (pbkdf2Iterations, keyId, onEvent)

**Returns**

- [`CardResult`](/module/types/cardresult)
