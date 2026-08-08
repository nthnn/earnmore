---
title: deriveHmacKey
kind: function
longname: module:cvv.deriveHmacKey
description: Derives a 256-bit HMAC key from a passkey string using PBKDF2-SHA256.
---

# deriveHmacKey

<Signature code="deriveHmacKey(passkey: string, iterations: number): Buffer" />

<SourceLink href="/source/cvv-ts/#L45" label="cvv.ts:45" />

Derives a 256-bit HMAC key from a passkey string using PBKDF2-SHA256.

**Parameters**

- `passkey` (string) — Secret passkey string. Minimum 16 characters.
- `iterations` ([number](/module/types/iddocument#number), default: "PCI\_DSS\_PBKDF2\_ITERATIONS") — PBKDF2 iteration count. Use PCI\_DSS\_PBKDF2\_ITERATIONS (310,000) in production.

**Returns**

- `Buffer`
