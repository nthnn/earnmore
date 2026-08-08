---
title: EncryptedPAN
kind: interface
longname: module:types.EncryptedPAN
description: AES-256-GCM encrypted PAN for compliant storage (PCI-DSS Req 3.4.1). All fields are hex-encoded strings.
---

# EncryptedPAN

<Signature
  code="interface EncryptedPAN {
	authTag: string;
	ciphertext: string;
	iv: string;
}"
/>

<SourceLink href="/source/types-ts/#L190" label="types.ts:190" />

AES-256-GCM encrypted PAN for compliant storage (PCI-DSS Req 3.4.1). All fields are hex-encoded strings.

---

## Properties

<MemberHeading id="authtag" depth="3" name="authTag" sig="authTag: string" />

<MemberMeta sourceHref="/source/types-ts/#L198" sourceLabel="types.ts:198" />

16-byte GCM authentication tag (hex) — verifies integrity

<MemberHeading id="ciphertext" depth="3" name="ciphertext" sig="ciphertext: string" />

<MemberMeta sourceHref="/source/types-ts/#L195" sourceLabel="types.ts:195" />

AES-256-GCM ciphertext (hex)

<MemberHeading id="iv" depth="3" name="iv" sig="iv: string" />

<MemberMeta sourceHref="/source/types-ts/#L192" sourceLabel="types.ts:192" />

12-byte random IV (hex) — unique per encryption operation
