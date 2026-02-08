
# AI-NRF1 Rust Stack — UBL → App → Tenant → User

100% Rust. Sem TypeScript. Core em crates independentes + serviço Axum + CLI.

## Layout
- `crates/ubl-auth` — AuthCtx + PoP Ed25519 (X-DID/X-PUBKEY/X-Signature) e roles.
- `crates/ubl-model` — SQLx models + upsert de receipts.
- `crates/ubl-storage` — S3 client para bundles.
- `services/registry` — API HTTP: `/v1/{app}/{tenant}/receipts` etc.
- `cli/nrf1` — CLI mínima: `nrf1 publish --app --tenant --file`.

## URL Canônica
`https://passports.ubl.agency/{app}/{tenant}/receipts/{receipt_id}.json#cid=…&did=…&rt=…`

## API v1
- `POST /v1/{app}/{tenant}/receipts` (roles: signer|tenant_admin|app_owner)
- `GET  /v1/{app}/{tenant}/receipts/{id}`
- `GET  /v1/{app}/{tenant}/receipts/by-cid/{cid}`
- `GET  /v1/{app}/{tenant}/keys/{did}`

## Dev Quickstart
1) Postgres:
```
createdb ainrf1
psql ainrf1 < db/migrations/0001_init.sql
```
2) Service:
```
cd services/registry
cp .env.example .env
cargo run
```
3) CLI publish:
```
cd cli/nrf1
cargo run -- publish --app ai-nrf1 --tenant acme --file ../../examples/receipt.demo.json
```
*(Exemplo precisa de `examples/receipt.demo.json` com campos `cid`/`did`.)*

## Próximos passos
- Mapear `app_slug/tenant_slug` → IDs via DB (resolver de slugs).
- Persistir issuer/JWKS e `/keys/{did}` real.
- Publicação S3 (crates/ubl-storage) para armazenar `receipts/{id}.json` e bundles.
- Middleware de RBAC consultando `membership` no DB.


### Atualizações nesta etapa (Step 2)
- ✅ Resolver de slugs `{app, tenant}` via Postgres.
- ✅ JWKS real via tabela `issuer` em `/v1/{app}/{tenant}/keys/{did}`.
- ✅ RBAC via tabela `membership` (roles: `signer|tenant_admin|app_owner`).


## Tasklist Snapshot
- Atualizado: 2026-02-08T19:39:01.875747Z
- Ver `TASKLIST.md` para status detalhado.
