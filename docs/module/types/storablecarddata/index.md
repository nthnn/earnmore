---
title: StorableCardData
kind: interface
longname: module:types.StorableCardData
description: Cardholder Data (CHD) safe for storage after authorization. The CVV/CVC is intentionally absent — per PCI-DSS Req 3.3.1, SAD must not be retained once issuance/authorization is complete.
---

# StorableCardData

<Signature
  code="interface StorableCardData {
	expiry: string;
	keyId: string;
	maskedPan: string;
}"
/>

<SourceLink href="/source/types-ts/#L167" label="types.ts:167" />

Cardholder Data (CHD) safe for storage after authorization. The CVV/CVC is intentionally absent — per PCI-DSS Req 3.3.1, SAD must not be retained once issuance/authorization is complete.

---

## Properties

<MemberHeading id="expiry" depth="3" name="expiry" sig="expiry: string" />

<MemberMeta sourceHref="/source/types-ts/#L177" sourceLabel="types.ts:177" />

Card expiry in MM/YY format

<MemberHeading id="keyid" depth="3" name="keyId" sig="keyId: string" />

<MemberMeta sourceHref="/source/types-ts/#L183" sourceLabel="types.ts:183" />

Key identifier — required for CVV validation after key rotation. Per NIST SP 800-57 / ISO 11568-1.

<MemberHeading id="maskedpan" depth="3" name="maskedPan" sig="maskedPan: string" />

<MemberMeta sourceHref="/source/types-ts/#L174" sourceLabel="types.ts:174" />

Masked PAN: first 6 digits (BIN) + 6 masked characters + last 4 digits. Example: "001138xxxxxx1836" Per PCI-DSS Req 3.5, full PANs must not be stored in plaintext. Use encryptPAN() if the full PAN must be recoverable.
