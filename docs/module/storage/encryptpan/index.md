---
title: encryptPAN
kind: function
longname: module:storage.encryptPAN
description: Encrypts a 16-digit PAN using AES-256-GCM.
---

# encryptPAN

<Signature code="encryptPAN(pan: string, encryptionKey: Buffer): EncryptedPAN" />

<SourceLink href="/source/storage-ts/#L37" label="storage.ts:37" />

Encrypts a 16-digit PAN using AES-256-GCM.

**Parameters**

- `pan` (string) — 16-digit PAN string
- `encryptionKey` (Buffer) — 32-byte (256-bit) encryption key Buffer. Must be distinct from the CVV HMAC passkey.

**Returns**

- [`EncryptedPAN`](/module/types/encryptedpan) — EncryptedPAN with iv, ciphertext, and authTag (all hex)

**Throws**

- If PAN is not 16 digits or key is not 32 bytes.
