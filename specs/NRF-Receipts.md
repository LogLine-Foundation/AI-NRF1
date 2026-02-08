
# NRF Receipts — WbE & Ghost (v1)

## Normative Semantics
- **Write-before-Execute (WbE):** Every act MUST append a canonical receipt *before* any effect. Failure or rejection MUST NOT delete the receipt.
- **Ghost:** A non-effectuated act MUST be recorded with `decision = "GHOST"` and `effects = null`. Ghost MUST contain no external side effects.

## Canonical Map (NRF-1.1)
Keys are UTF‑8 NFC, sorted by raw bytes; values use NRF‑1.1 types.

```
{
  "v": "receipt-v1",                  ; String
  "t": <Int64 nanos>,                 ; Int64
  "did": "did:ubl:...",               ; String
  "act": "ATTEST"|"EVALUATE"|"EXECUTE",
  "subject": "cid:blake3:...",        ; String
  "inputs_cid": "b3:...",             ; String
  "decision": "ALLOW"|"DENY"|"REQUIRE"|"GHOST",
  "effects": <Map>|null,              ; MUST be null for GHOST
  "rt": {                             ; Certified Runtime
    "binary_sha256": "...",
    "hal_ref": "hal:v1/..."
  },
  "prev_receipt_cid": "b3:..."|null,
  "sig": <Bytes 64>                   ; Ed25519 over NRF bytes without "sig"
}
```

## Invariants
- **GHO‑001:** If `decision == "GHOST"` then `effects == null`. Otherwise invalid.
- **ALW‑001:** If `decision == "ALLOW"` then `effects` MUST be present and HAL‑conformant.
- **WBE‑001:** An initial receipt (undecided) MUST be logged prior to execution; on failure it becomes a Ghost receipt.
- **CHN‑001:** If `prev_receipt_cid` is present, re-encoding the previous receipt MUST hash to that CID.

## Verification Procedure (Offline)
1. Parse NRF bytes, verify canonical constraints.
2. Remove `"sig"`, compute SHA‑256, verify Ed25519 over the digest with the signer DID key.
3. Validate invariants GHO‑001 / ALW‑001 / CHN‑001.
4. Optionally verify runtime attestation (`rt.binary_sha256` and `hal_ref`) against allowlists.
