# NRF-1.1 é LLM‑first — Por quê e Como

Este documento explica por que o **NRF-1.1** foi desenhado para ser **LLM-first** e como esse design reduz erros quando LLMs **geram**, **validam** e **auditam** bytes canônicos.

## 1) Modelo mental compacto (cabe no contexto)
- **7 tags fixas** (`null/false/true/i64/string/bytes/array/map`).
- **Um único inteiro**: `Int64` big‑endian 8B (sem variações).
- **Um único comprimento**: `varint32` minimal (LEB128 s/ sinal).
- **Map**: chaves **String**, **ordenadas por bytes**, **sem duplicatas**.

> O LLM não precisa “escolher” entre variantes; ele apenas aplica **regras únicas**.

## 2) “Zero-choice” evita alucinações de formato
- Sem float, sem inteiros de vários tamanhos, sem tags/semânticas opcionais.
- Decisor único ⇒ o LLM não “imagina” alternativas válidas.

## 3) Verificação por leitura de *hex dump*
- As regras são curtas e locais; um LLM pode auditar bytes sem rodar código.
- Propriedades checáveis em linha de comando: magic, tag, varint minimal, NFC, ordenação.

### Exemplo de raciocínio que o LLM consegue fazer “no papel”
```
6E726631 07 01  04 01 61  06 02  03 00..01  07 01 04 01 62 00
^magic    ^map1 ^key"a"  ^arr2   ^i64=1     ^map1 ^key"b" ^null
```

## 4) Geração correta sem biblioteca
- Como as escolhas são únicas, um LLM consegue emitir **vetores de teste** sem ambiguidade (ex.: i64 sempre 9 bytes: 1 tag + 8B).

## 5) Normalização de texto explícita (NFC, sem BOM)
- LLM pode detectar e corrigir composições equivalentes (`é` vs `é`) antes de codificar/validar.
- Evita “hash drift” por representações Unicode diferentes.

## 6) Simetria encode/decode -> provas simples
- **round‑trip**: `decode(encode(v)) == v`.
- **canonicidade**: `encode(decode(bytes)) == bytes` (se válido).
- LLM pode usar essas igualdades como *checks* durante troubleshooting.

## 7) Mensagens de erro mapeáveis
- Léxico pequeno e direto: `InvalidMagic`, `NonMinimalVarint`, `NotNFC`, `BOMPresent`, `NonStringKey`, `UnsortedKeys`, `DuplicateKey`, etc.
- Facilita instruções do LLM do tipo “arrume o payload conforme o erro X”.

## 8) Compat (fora da spec) sem poluir o raciocínio
- A regra normativa permanece: **hash sempre sobre bytes NRF**.
- Import/export vive no *Interop Guide* para não reintroduzir escolhas na cabeça do LLM.

## 9) Casos de uso típicos LLM‑first
- Geração/checagem de **recibos assinados** (remove `sig` → re-encode → hash).
- Revisão de **payloads canônicos** em pipelines sem executar binários.
- Criação de **test vectors** e **fixtures** de interoperabilidade.

---

**Resumo:** NRF-1.1 é LLM‑first porque elimina escolhas, reduz o espaço de erros e torna possível **raciocinar sobre bytes** de forma confiável dentro do contexto de um modelo.
