
# SIRP Compatibility (Minimal for BASE)

- We keep HTTP as the transport but **adopt SIRP capsule semantics**:
  - `capsule.payload = NRF-1.1 bytes` (or JSON✯Atomic bytes)
  - `capsule.cid = b3(payload)`
  - `capsule.sig = Ed25519(domain="sirp.cap.v1", header||payload)`
- For BASE:
  - Emit **delivery receipts** in the registry with `{ capsule_cid, outcome }`.
  - Add `sirp.receipt.delivery.v1` schema later; for now a field in receipt:`network: { capsule_cid, delivered: true }`.
