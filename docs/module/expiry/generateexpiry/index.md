---
title: generateExpiry
kind: function
longname: module:expiry.generateExpiry
description: Generates a card expiry date in "MM/YY" format. Uses a fresh HmacDrbg seeded from combinedHash with context "earnmore:expiry", fully independent from the PAN generation stream. No step-skipping needed.
---

# generateExpiry

<Signature code="generateExpiry(seedBuffer: Buffer): string" />

<SourceLink href="/source/expiry-ts/#L28" label="expiry.ts:28" />

Generates a card expiry date in "MM/YY" format.

Uses a fresh HmacDrbg seeded from combinedHash with context "earnmore:expiry", fully independent from the PAN generation stream. No step-skipping needed.

**Parameters**

- `seedBuffer` (Buffer) — The 32-byte SHA-256 combinedHash from PAN generation.

**Returns**

- `string`
