
# Divisão de Módulos (Renomeações)

- **ubl-json** → Estrutura de pensamento do LLM (slots) e ponte para NRF‑1.1
- **ubl-transport** → SIRP‑like capsules para transporte/assinatura (BASE mínimo)
- **ubl-policy** → Fachada do avaliador TDLN/Chip‑as‑Code
- **envelope** → Criptografia de tuplas (X25519 + XChaChaPoly) com AAD=cid
- **nrf1-core** → Canonical binary (NRF‑1.1)

`Chip as Code`: permanece como documento de integração e demos multi‑backend. Nesta fase BASE, fica acoplado via `ubl-policy`.
