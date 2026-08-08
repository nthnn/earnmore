---
title: maskPAN
kind: function
longname: module:masking.maskPAN
description: "Masks a 16-digit PAN per PCI-DSS Req 3.5. Format: first 6 digits (BIN/IIN) + 6 masked chars + last 4 digits. The 6 masked characters in the middle are shown as lowercase 'x'. Example: \"0011382910471836\" → \"001138xxxxxx1836\""
---

# maskPAN

<Signature code="maskPAN(pan: string): string" />

<SourceLink href="/source/masking-ts/#L32" label="masking.ts:32" />

Masks a 16-digit PAN per PCI-DSS Req 3.5.

Format: first 6 digits (BIN/IIN) + 6 masked chars + last 4 digits. The 6 masked characters in the middle are shown as lowercase 'x'.

Example: "0011382910471836" → "001138xxxxxx1836"

**Parameters**

- `pan` (string) — 16-digit PAN string (digits only)

**Returns**

- `string` — Masked PAN string

**Throws**

- If PAN is not exactly 16 digits
