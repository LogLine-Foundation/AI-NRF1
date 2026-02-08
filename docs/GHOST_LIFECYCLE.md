
# Ghost Lifecycle (WBE → Ghost → Official)

**Goal:** Ghost is a first-class pending record. It is created at **Write-Before-Execute (WBE)**, can be **promoted** to an official receipt (ALLOW/REQUIRE/DENY), or **expired**. Ghosts are immutable evidence and carry their own identity and URL.

## State machine

```
WBE ──create──> GHOST[pending]
GHOST[pending] ──promote──> RECEIPT[final] (links ghost_id)
GHOST[pending] ──expire──> GHOST[expired]
```

- Every execution MUST start with WBE → GHOST (pending).
- Promotion MUST reference the `ghost_id` and carry a causal link.
- Expiration MUST capture cause (timeout, cancel, drift).

## Identity & URLs

- `ghost_cid = b3(nrf_bytes)` (NRF-1.1 canonical body)
- Rich URL is stable: `.../ghosts/{id}.json#cid=<ghost_cid>&did=<signer_did>&rt=<runtime_hash>`
- Promotion includes `ghost_ref = { id, cid }` and copies anchors into the final URL with `ghost=` query param for offline traceability.

## Schema (NRF logical map)

```jsonc
{
  "v": "ghost.v1",
  "t": 1738950000000000000,
  "status": "pending | expired",
  "wbe": { "who": "...", "what": "...", "when": "...", "intent": "..." },
  "cause": "timeout | canceled | drift | none",
  "nonce": "<16 bytes>",
  "sig": "<ed25519 signature>"
}
```
