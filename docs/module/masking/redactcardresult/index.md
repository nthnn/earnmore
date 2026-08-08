---
title: redactCardResult
kind: function
longname: module:masking.redactCardResult
description: Strips Sensitive Authentication Data (SAD) from a CardResult, returning only Cardholder Data (CHD) that is safe to store per PCI-DSS Req 3.3.1. The CVV is intentionally excluded. The PAN is automatically masked. If you need the full PAN for storage, use encryptPAN() from storage.ts.
---

# redactCardResult

<Signature code="redactCardResult(result: CardResult): StorableCardData" />

<SourceLink href="/source/masking-ts/#L50" label="masking.ts:50" />

Strips Sensitive Authentication Data (SAD) from a CardResult, returning only Cardholder Data (CHD) that is safe to store per PCI-DSS Req 3.3.1.

The CVV is intentionally excluded. The PAN is automatically masked. If you need the full PAN for storage, use encryptPAN() from storage.ts.

**Parameters**

- `result` ([CardResult](/module/types/cardresult)) — Full CardResult from generate()

**Returns**

- [`StorableCardData`](/module/types/storablecarddata) — StorableCardData with maskedPan and expiry only (no CVV)
