---
title: generatePAN
kind: function
longname: module:pan.generatePAN
description: Generates a unique, non-regeneratable 16-digit PAN.
---

# generatePAN

<Signature code="generatePAN(fingerprint: string): PanResult" />

<SourceLink href="/source/pan-ts/#L86" label="pan.ts:86" />

Generates a unique, non-regeneratable 16-digit PAN.

**Parameters**

- `fingerprint` (string) — SHA-256 hex fingerprint of the customer's identity

**Returns**

- [`PanResult`](/module/pan/panresult)
