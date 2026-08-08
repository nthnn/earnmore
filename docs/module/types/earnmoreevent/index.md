---
title: EarnmoreEvent
kind: interface
longname: module:types.EarnmoreEvent
description: Audit event emitted by the library for significant cryptographic operations. Safe to log — never contains a full PAN, raw CVV, or key material.
---

# EarnmoreEvent

<Signature
  code="interface EarnmoreEvent {
	keyId: string;
	maskedPan?: string;
	timestamp: Date;
	type: EarnmoreEventType;
}"
/>

<SourceLink href="/source/types-ts/#L71" label="types.ts:71" />

Audit event emitted by the library for significant cryptographic operations. Safe to log — never contains a full PAN, raw CVV, or key material.

---

## Properties

<MemberHeading id="keyid" depth="3" name="keyId" sig="keyId: string" />

<MemberMeta sourceHref="/source/types-ts/#L79" sourceLabel="types.ts:79" />

Key identifier active at the time of the operation

<MemberHeading id="maskedpan" depth="3" name="maskedPan" sig="maskedPan: string" />

<MemberMeta sourceHref="/source/types-ts/#L86" sourceLabel="types.ts:86" />

Masked PAN when the operation involved a specific card. Format: first 6 (BIN) + "xxxxxx" + last 4. Absent for key lifecycle events.

<MemberHeading id="timestamp" depth="3" name="timestamp" sig="timestamp: Date" />

<MemberMeta sourceHref="/source/types-ts/#L76" sourceLabel="types.ts:76" />

UTC timestamp of the operation

<MemberHeading id="type" depth="3" name="type" sig="type: EarnmoreEventType" />

<MemberMeta sourceHref="/source/types-ts/#L73" sourceLabel="types.ts:73" />

Operation that triggered this event
