---
title: generateKCV
kind: function
longname: module:cvv.generateKCV
description: "Generates a Key Check Value (KCV) for a derived HMAC key. The KCV is a non-secret 6-character hex fingerprint that allows verifying the correct passkey was loaded at startup, without exposing the key itself. Store the KCV alongside your key configuration and compare on initialization. Algorithm: HMAC-SHA256(derivedKey, \"earnmore:kcv:check\")[0..2] as hex"
---

# generateKCV

<Signature code="generateKCV(derivedKey: Buffer): string" />

<SourceLink href="/source/cvv-ts/#L73" label="cvv.ts:73" />

Generates a Key Check Value (KCV) for a derived HMAC key.

The KCV is a non-secret 6-character hex fingerprint that allows verifying the correct passkey was loaded at startup, without exposing the key itself. Store the KCV alongside your key configuration and compare on initialization.

Algorithm: HMAC-SHA256(derivedKey, "earnmore:kcv:check")\[0..2] as hex

**Parameters**

- `derivedKey` (Buffer) — 32-byte key Buffer from deriveHmacKey()

**Returns**

- `string` — 6-character hex string (e.g. "a3f2c1")
