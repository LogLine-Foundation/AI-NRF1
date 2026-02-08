# NRF-1.1 in LogLine (Informative)

## Where NRF is used
`chip_cid`, `receipt_cid`, `inputs_hash`, `canon_cid` — all computed as `Hash(NRF.encode(value))`.

## Canonical flows
```
# Value → Content ID
bytes = NRF.encode(value)
cid   = SHA-256(bytes)

# Receipt (hash-then-sign)
map_wo_sig = {..., "body": payload, ...}  # no "sig"
bytes0     = NRF.encode(map_wo_sig)
digest     = SHA-256(bytes0)
sig        = Ed25519.sign(digest)
receipt    = { ... map_wo_sig, "sig": sig }  # re-encode NRF
```
**Invariant:** the official digest is always over **NRF bytes**.

## Semantic Chip binary
All payload sections are **NRF-1.1 encoded** (PolicyBit/Composition/InputSpec/OutputSpec/HAL/Manifest). No alternatives.

## Ops & Observability
Log and surface normative rejections (NFC/BOM/varint/order/duplicate) with explicit error codes for debugging and SLOs.
