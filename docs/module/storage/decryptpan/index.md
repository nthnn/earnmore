---
title: decryptPAN
kind: function
longname: module:storage.decryptPAN
description: Decrypts an EncryptedPAN using AES-256-GCM. GCM authentication tag is verified before any plaintext is returned — if the tag fails, an error is thrown and no plaintext is exposed.
---

# decryptPAN

<Signature
  code="decryptPAN(
	encrypted: EncryptedPAN,
	encryptionKey: Buffer,
): string"
/>

<SourceLink href="/source/storage-ts/#L75" label="storage.ts:75" />

Decrypts an EncryptedPAN using AES-256-GCM. GCM authentication tag is verified before any plaintext is returned — if the tag fails, an error is thrown and no plaintext is exposed.

**Parameters**

- `encrypted` ([EncryptedPAN](/module/types/encryptedpan)) — EncryptedPAN object from encryptPAN()
- `encryptionKey` (Buffer) — The same 32-byte key used during encryption

**Returns**

- `string` — The original 16-digit PAN string

**Throws**

- If key is wrong, data is tampered, or input is malformed.
