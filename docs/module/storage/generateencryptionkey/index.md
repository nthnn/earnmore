---
title: generateEncryptionKey
kind: function
longname: module:storage.generateEncryptionKey
description: Generates a random 32-byte AES-256 encryption key. Use this to create a key for encryptPAN() / decryptPAN(). ⚠️ Store the returned key securely (HSM, secret manager, KMS). This key must be kept separate from the CVV passkey.
---

# generateEncryptionKey

<Signature code="generateEncryptionKey(): Buffer" />

<SourceLink href="/source/storage-ts/#L107" label="storage.ts:107" />

Generates a random 32-byte AES-256 encryption key. Use this to create a key for encryptPAN() / decryptPAN().

⚠️ Store the returned key securely (HSM, secret manager, KMS). This key must be kept separate from the CVV passkey.

**Returns**

- `Buffer`
