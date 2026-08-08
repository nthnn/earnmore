---
title: PanResult
kind: interface
longname: module:pan.PanResult
---

# PanResult

<Signature
  code="interface PanResult {
	pan: string;
	prefix: '0011' | '9212' | '0513' | '8989' | '7312' | '9876';
	seedBuffer: Buffer;
}"
/>

<SourceLink href="/source/pan-ts/#L67" label="pan.ts:67" />

---

## Properties

<MemberHeading id="pan" depth="3" name="pan" sig="pan: string" />

<MemberMeta sourceHref="/source/pan-ts/#L69" sourceLabel="pan.ts:69" />

16-digit PAN string

<MemberHeading id="prefix" depth="3" name="prefix" sig="prefix: '0011' | '9212' | '0513' | '8989' | '7312' | '9876'" />

<MemberMeta sourceHref="/source/pan-ts/#L72" sourceLabel="pan.ts:72" />

The selected BIN prefix

<MemberHeading id="seedbuffer" depth="3" name="seedBuffer" sig="seedBuffer: Buffer" />

<MemberMeta sourceHref="/source/pan-ts/#L78" sourceLabel="pan.ts:78" />

The combinedHash buffer — used downstream to seed the expiry HMAC-DRBG. Both PAN and expiry streams are domain-separated from this shared seed.
