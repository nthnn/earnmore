---
title: CardResult
kind: interface
longname: module:types.CardResult
description: "Full card issuance result. ⚠️ PCI-DSS Req 3.3.1: The cvv field is Sensitive Authentication Data (SAD) and MUST NOT be stored after authorization. Use redactCardResult() to obtain a storable representation that excludes the CVV. Store keyId alongside the card record — it is required for CVV validation after a key rotation (NIST SP 800-57 / ISO 11568-1)."
---

# CardResult

<Signature
  code="interface CardResult {
	cvv: string;
	expiry: string;
	keyId: string;
	pan: string;
}"
/>

<SourceLink href="/source/types-ts/#L141" label="types.ts:141" />

Full card issuance result.

⚠️ PCI-DSS Req 3.3.1: The `cvv` field is Sensitive Authentication Data (SAD) and MUST NOT be stored after authorization. Use `redactCardResult()` to obtain a storable representation that excludes the CVV.

Store `keyId` alongside the card record — it is required for CVV validation after a key rotation (NIST SP 800-57 / ISO 11568-1).

---

## Properties

<MemberHeading id="cvv" depth="3" name="cvv" sig="cvv: string" />

<MemberMeta sourceHref="/source/types-ts/#L152" sourceLabel="types.ts:152" />

4-digit Card Verification Value. SAD — do not persist this field after card issuance / authorization.

<MemberHeading id="expiry" depth="3" name="expiry" sig="expiry: string" />

<MemberMeta sourceHref="/source/types-ts/#L146" sourceLabel="types.ts:146" />

Card expiry in MM/YY format

<MemberHeading id="keyid" depth="3" name="keyId" sig="keyId: string" />

<MemberMeta sourceHref="/source/types-ts/#L159" sourceLabel="types.ts:159" />

Key identifier used to generate this CVV. Persist this alongside the card record for future CVV validation. Per NIST SP 800-57 / ISO 11568-1.

<MemberHeading id="pan" depth="3" name="pan" sig="pan: string" />

<MemberMeta sourceHref="/source/types-ts/#L143" sourceLabel="types.ts:143" />

16-digit Primary Account Number
