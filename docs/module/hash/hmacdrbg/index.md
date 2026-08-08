---
title: HmacDrbg
kind: class
longname: module:hash.HmacDrbg
description: "HMAC-SHA256 Deterministic Random Bit Generator. Implements the formal NIST SP 800-90A Rev.1 HMAC_DRBG specification. Properties: Cryptographically secure (HMAC-SHA256 as PRF) Domain-separated via the context string (prevents cross-use of the same seed for different purposes, e.g. \"earnmore:pan\" vs \"earnmore:expiry\") Rejection-sampled outputs eliminate modular bias (FIPS 186-5 §B.4.2)"
---

# HmacDrbg

<SourceLink href="/source/hash-ts/#L153" label="hash.ts:153" />

HMAC-SHA256 Deterministic Random Bit Generator. Implements the formal NIST SP 800-90A Rev.1 HMAC\_DRBG specification.

Properties:

- Cryptographically secure (HMAC-SHA256 as PRF)
- Domain-separated via the context string (prevents cross-use of the same seed for different purposes, e.g. "earnmore:pan" vs "earnmore:expiry")
- Rejection-sampled outputs eliminate modular bias (FIPS 186-5 §B.4.2)

* **See:**
  - \- NIST SP 800-90A Rev.1 — HMAC\_DRBG (formal standard)
    &#x20;\- FIPS 186-5 §B.4.2 — Rejection sampling for unbiased output

---

## Constructors

<MemberHeading id="constructor" depth="3" name="constructor" sig="new HmacDrbg(seed: Buffer, context: string): HmacDrbg" />

**Parameters**

- `seed` (Buffer) — 32-byte Buffer from which all randomness is derived. Must originate from a CSPRNG (e.g. crypto.randomBytes).
- `context` (string, default: "\\"\\"") — Domain-separation string. Used as `personalization_string`.

**Returns**

`HmacDrbg`

---

## Methods

<MemberHeading id="nextbyte" depth="3" name="nextByte" sig="nextByte(): number" />

<MemberMeta sourceHref="/source/hash-ts/#L217" sourceLabel="hash.ts:217" />

Returns the next byte from the DRBG output stream

**Returns**

- [`number`](/module/types/iddocument#number)

<MemberHeading id="nextint" depth="3" name="nextInt" sig="nextInt(max: number): number" />

<MemberMeta sourceHref="/source/hash-ts/#L230" sourceLabel="hash.ts:230" />

Returns an unbiased random integer in \[0, max) using rejection sampling. Rejects bytes that would introduce modular bias (FIPS 186-5 §B.4.2).

**Parameters**

- `max` ([number](/module/types/iddocument#number)) — Upper bound (exclusive). Must be in \[2, 256].

**Returns**

- [`number`](/module/types/iddocument#number)
