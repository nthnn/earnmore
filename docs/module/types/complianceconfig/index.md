---
title: ComplianceConfig
kind: interface
longname: module:types.ComplianceConfig
---

# ComplianceConfig

<Signature
  code="interface ComplianceConfig {
	keyCreatedAt?: Date;
	keyId: string;
	onEvent?: (event: EarnmoreEvent) => void;
	pbkdf2Iterations?: number;
}"
/>

<SourceLink href="/source/types-ts/#L18" label="types.ts:18" />

---

## Properties

<MemberHeading id="keycreatedat" depth="3" name="keyCreatedAt" sig="keyCreatedAt: Date" />

<MemberMeta sourceHref="/source/types-ts/#L46" sourceLabel="types.ts:46" />

Timestamp when this key/passkey was provisioned. Used by `EarnmoreClient.isKeyExpired()` to enforce NIST SP 800-57 §5.3.6 cryptoperiod recommendations. Defaults to the time the EarnmoreClient was constructed.

<MemberHeading id="keyid" depth="3" name="keyId" sig="keyId: string" />

<MemberMeta sourceHref="/source/types-ts/#L38" sourceLabel="types.ts:38" />

Key identifier for CVV generation/validation (must be a valid UUID).

Per NIST SP 800-57 / ISO 11568-1, embedding a key ID in the authenticated message enables key rotation without reissuing all cards. Store the keyId alongside each card record and pass it back during CVV validation.

<MemberHeading id="onevent" depth="3" name="onEvent" sig="onEvent: (event: EarnmoreEvent) => void" />

<MemberMeta sourceHref="/source/types-ts/#L55" sourceLabel="types.ts:55" />

Audit event callback (CSF 2.0 DE.AE-02 / ISO 27001:2022 A.8.15).

Called for every significant cryptographic operation. Events never contain a full PAN, CVV, or raw key material — only masked PAN and metadata. Feed these events into your SIEM, anomaly detection, or audit log.

<MemberHeading id="pbkdf2iterations" depth="3" name="pbkdf2Iterations" sig="pbkdf2Iterations: number" />

<MemberMeta sourceHref="/source/types-ts/#L29" sourceLabel="types.ts:29" />

PBKDF2-SHA256 iteration count for CVV key derivation. Default: `PCI_DSS_PBKDF2_ITERATIONS` (310,000) — satisfies NIST SP 800-132 and PCI-DSS Req 3.7.1. Minimum enforced by the library: 1,000.

Pass a lower value only in non-production contexts (e.g. unit tests).

- **See:**
  - [PCI\_DSS\_PBKDF2\_ITERATIONS](/module/types/pci-dss-pbkdf2-iterations)
