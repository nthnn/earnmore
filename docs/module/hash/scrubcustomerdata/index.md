---
title: scrubCustomerData
kind: function
longname: module:hash.scrubCustomerData
description: "Scrubs a CustomerInfo object by overwriting its string fields with zeroes. In JavaScript, memory cannot be manually freed, but mutating the string properties in-place ensures the original PII is removed from the active object immediately before the garbage collector reclaims it. This aids in complying with data minimization and Right to be Forgotten principles in environments where memory dumps could expose PII. Note: Strings in JS are immutable. This sets the property to a NEW string of zeroes. The original string becomes eligible for GC immediately."
---

# scrubCustomerData

<Signature code="scrubCustomerData(info: CustomerInfo): void" />

<SourceLink href="/source/hash-ts/#L83" label="hash.ts:83" />

Scrubs a CustomerInfo object by overwriting its string fields with zeroes.

In JavaScript, memory cannot be manually freed, but mutating the string properties in-place ensures the original PII is removed from the active object immediately before the garbage collector reclaims it. This aids in complying with data minimization and Right to be Forgotten principles in environments where memory dumps could expose PII.

Note: Strings in JS are immutable. This sets the property to a NEW string of zeroes. The original string becomes eligible for GC immediately.

**Parameters**

- `info` ([CustomerInfo](/module/types/customerinfo)) — The CustomerInfo object to scrub

**Returns**

- `void`
