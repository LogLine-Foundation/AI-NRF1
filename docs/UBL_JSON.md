
# UBL‑JSON (v1): Estrutura de Pensamento do LLM

**Objetivo:** padronizar a *organização mental* de um LLM sem expor "cadeia de pensamento" textual.
O formato captura *slots* de raciocínio como campos declarativos, auditáveis e estáveis,
para servir de **contexto cristalizado** ao TDLN/SIRP e ao NRF‑1.1.

## Princípios
- **Determinismo de slots**: mesmos slots → mesmo significado.
- **Sem narrativa oculta**: nada de "chain-of-thought" verborrágico. Apenas campos curtos e objetivos.
- **LLM‑friendly**: fácil de o modelo preencher; fácil de validar por máquina.

## Campos (v1)
- `space`: *namespace lógico* (ex.: `"ai-nrf1.passport"`).
- `version`: versão do schema (`"1.0.0"`).
- `id`: identificador local único (UUID4 ou slug).
- `app`: app/serviço emissor (string curta).
- `tenant`: locatário (slug/uuid).
- `subject`: quem/o quê está sendo julgado (ex.: `"model:acme/llama-8b@sha256:..."`).
- `intent`: verbo da ação (ex.: `"attest"`, `"evaluate"`).
- `scope`: escopo/limites (ex.: `"eu-ai-act/article-10"`).
- `claims`: lista de *assertivas curtas* (strings) — “o que se afirma verdade”.
- `grounds`: *fatos* (pares `name → value`) — valores que sustentam as claims.
- `rules_ref`: referências normativas (lista de IDs) — políticas/códigos aplicados.
- `decision_hint`: enum opcional (`"PASS" | "FAIL" | "NEEDS_REVIEW"`) — *sugestão* do LLM, não-veredito.
- `confidence`: `0..1` — confiança do LLM no *hint* (opcional).
- `evidence`: lista de CIDs/URLs para dados/fonte.
- `meta`: dicionário livre (limpo, curto), p/ rastros úteis (ex.: `"dataset_shasum": "..."`).

## JSON Schema (draft-07)
Veja `schemas/ubl-json.v1.json`.

## Mapeamento para NRF‑1.1
- `ubl-json` é **entrada/saída** legível; o **hash canônico** sempre é calculado sobre o **NRF‑1.1** do valor lógico correspondente.
- Conversor: `nrf1 encode --from-ubl-json file.json` → bytes NRF; `nrf1 decode --to-ubl-json bytes` → JSON.
