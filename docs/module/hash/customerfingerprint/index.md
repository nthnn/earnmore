---
title: customerFingerprint
kind: function
longname: module:hash.customerFingerprint
description: "Produces a deterministic SHA-256 hex fingerprint from all customer fields. Fields are normalized (trimmed, lowercased, date as ISO YYYY-MM-DD) so that minor formatting differences do not produce different fingerprints. This fingerprint is used as an entropy input mixed with a random salt — it is never the sole source of PAN uniqueness. Input validation (NIST SP 800-218): birthPlace: letters and spaces only Individual fields: max 512 characters each Total payload: max 5 KB"
---

# customerFingerprint

<Signature code="customerFingerprint(info: CustomerInfo): string" />

<SourceLink href="/source/hash-ts/#L117" label="hash.ts:117" />

Produces a deterministic SHA-256 hex fingerprint from all customer fields. Fields are normalized (trimmed, lowercased, date as ISO YYYY-MM-DD) so that minor formatting differences do not produce different fingerprints.

This fingerprint is used as an entropy _input_ mixed with a random salt — it is never the sole source of PAN uniqueness.

Input validation (NIST SP 800-218):

- birthPlace: letters and spaces only
- Individual fields: max 512 characters each
- Total payload: max 5 KB

**Parameters**

- `info` ([CustomerInfo](/module/types/customerinfo))

**Returns**

- `string`
