# Receipt Enrichments: Ghost & Chain (Skip-List)

**Status:** Adopted • **Version:** v1 • **Scope:** BASE

## Ghost (Write-Before-Execute / Async)
- Records operational pressure of "pending" intents (Ghosts).
- Fields: `budget`, `counter`, `cost_ms`, `window_day` (0=Sun).
- Security: does **not** affect `body_cid`; purely operational evidence.

## Chain (Skip-List Links)
- Enables O(log n) interval verification without external ledger.
- Fields: `prev_cid`, optional `skips[]`, `link_hash`.
- `link_hash = b3(cid || body_cid || prev_cid? || skips*)` (canonical order).

## Invariants
1. `b3(canonical(body)) == body_cid` always.
2. `cid(receipt)` covers `ghost`/`chain` when present.
3. Verifiers MAY ignore enrichments and still validate truth of `body`.

See `schemas/receipt.v1.json` for the normative schema.