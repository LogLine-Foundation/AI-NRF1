
# Patches Applied (Step 3)

- Added unified **TASKLIST.md** consolidating Core, Receipts, Registry/Auth, Storage, CLI/CI, Security, Docs.
- Marked **✅** items already delivered (slug resolver, JWKS, RBAC, WBE, Ghost, rich URL, CLI core).
- Left **🟨/⏳** on S3 publish, bundle verify, middleware RBAC central, and threat model docs.
- README annotated with tasklist snapshot timestamp.

Bundle base: `AI-NRF1_rust_stack_step2_slug_jwks_rbac.zip`
Output: this zip (step3) with docs + tasklist.

# Patches Applied (Step 38: S3 + RBAC)

- Added **S3/MinIO** storage client (`crates/storage`) with `put_json/put_zip` and `S3_PUBLIC_BASE` URLs.
- Wired **S3 publish** docs and code snippet in receipts route (mirror canonical bytes -> public URL).
- Implemented **central RBAC middleware** (`services/registry/src/middleware/rbac.rs`) and docs.
- Updated `.env.example` with S3 settings.
- Tasklist updated: D5, F2, G2 marked ✅.

Timestamp: 2026-02-08T20:42:08.912839Z

# Step 39: Receipts publish + Offline bundles
- Implemented `services/registry/src/routes/receipts.rs` with S3 mirror and rich URLs.
- Added CLI `nrf1 bundle` and `nrf1 verify-bundle`.
- Timestamp: 2026-02-08T20:43:20.525382Z

# Step 40: Ghost prominence + Envelope + SIRP minimal
- Added Ghost lifecycle spec and routes (create/promote/expire).
- Introduced `envelope` crate (X25519+HKDF → XChaCha20-Poly1305 AEAD).
- Extended CLI with `ghost` commands (stubs for now).
- Added SIRP compatibility note for BASE.
- Timestamp: 2026-02-08T20:50:03.117827Z

# Step 41: UBL‑JSON + Transport + Policy scaffolds
- Added docs/UBL_JSON.md and schemas/ubl-json.v1.json
- Added crates: ubl-json, ubl-transport, ubl-policy
- Extended CLI skeleton for future ubl-json validation
- Timestamp: 2026-02-08T20:56:39.549226Z
