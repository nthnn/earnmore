---
title: luhnCheckDigit
kind: function
longname: module:pan.luhnCheckDigit
description: Computes the Luhn check digit for a partial PAN (digits 1-15). Returns a single digit (0-9) to append as digit 16.
---

# luhnCheckDigit

<Signature code="luhnCheckDigit(partial: string): number" />

<SourceLink href="/source/pan-ts/#L27" label="pan.ts:27" />

Computes the Luhn check digit for a partial PAN (digits 1-15). Returns a single digit (0-9) to append as digit 16.

**Parameters**

- `partial` (string)

**Returns**

- [`number`](/module/types/iddocument#number)
