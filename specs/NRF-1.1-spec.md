# NRF-1.1 — Canonical Binary Encoding (LLM-First, Zero-Choice)

**Versão:** 1.1 • **Status:** Draft • **Objetivo:** dado um valor lógico, produzir **um único** byte stream canônico (→ **um único hash**).
**Não-objetivos:** compressão, streaming, evolução de schema, legibilidade humana.

## 1. Princípios
1) **Canonicidade** — valores lógicos idênticos ⇒ bytes idênticos, sempre.
2) **Simplicidade** — cada construto tem **exatamente um** encoding. Zero opções.
3) **LLM-friendliness** — a especificação inteira cabe num único contexto; um LLM consegue gerar um encoder correto apenas a partir deste doc.

## 2. Estrutura do Arquivo
```
┌────────────┬───────────┐
│ Magic (4B) │ Value     │
└────────────┴───────────┘
```
- Magic **exato**: `0x6E 0x72 0x66 0x31` (`"nrf1"`).
- O stream contém **um único** valor. **Nenhum** byte a mais.

**Decoders MUST reject**: magic ausente/errado; bytes restantes após o valor-raiz; stream vazio.

## 3. Tipos e Tags
| Tag | Tipo   | Payload                                               |
|-----|--------|--------------------------------------------------------|
| 00  | Null   | —                                                      |
| 01  | False  | —                                                      |
| 02  | True   | —                                                      |
| 03  | Int64  | 8 bytes, signed, **big-endian** (two’s complement)     |
| 04  | String | **varint32** len + bytes UTF-8                         |
| 05  | Bytes  | **varint32** len + bytes brutos                        |
| 06  | Array  | **varint32** count + N valores                         |
| 07  | Map    | **varint32** count + N pares (chave String + valor)    |

Tags fora de `0x00..0x07` são inválidas (**MUST reject**).

## 4. Regras de Codificação
### 4.1 Null / False / True
Somente a tag.

### 4.2 Int64
- **Exatamente** 8 bytes, signed, big-endian.
- Sem variantes. Sem unsigned. Sem widths menores/maiores.

### 4.3 varint32 (Comprimentos)
- LEB128 **sem sinal**, até 32 bits (máx `2^32−1`). 1..5 bytes.
- Bits `[6:0]` = payload; bit 7 = continuação (1=continua, 0=último).

**Minimalidade (MUST):**
- Usar o **menor** número de bytes possível.
- Rejeitar: padding/overlong/valores > `u32`.
- Na 5ª byte, os **4 bits altos devem ser 0** (senão excede 32 bits).

### 4.4 String
`04 [varint32: byte_length] [UTF-8]`

**MUST (encoder) / MUST reject (decoder):**
1) UTF-8 válido.
2) Unicode **NFC**.
3) **Sem BOM** (`U+FEFF`) em nenhuma posição.
4) `byte_length` corresponde exatamente aos bytes subsequentes.

### 4.5 Bytes
`05 [varint32: byte_length] [bytes]`

### 4.6 Array
`06 [varint32: count] [item0] … [itemN-1]`

### 4.7 Map
`07 [varint32: count] [key0 value0] … [keyN-1 valueN-1]`

**MUST:**
1) Chaves são **Strings** (tag `04`).
2) Ordenadas por **bytes UTF-8 crus** (lexicográfica unsigned).
3) **Sem duplicatas** (byte sequence idêntica).

## 5. Canonicidade

**MUST — Hash/Assinatura Canônica:** todo digest/assinatura canônico **DEVE** ser calculado **sobre os bytes NRF-1.1 canônicos**. Entradas em outros formatos **DEVEM** ser convertidas **lossless** para NRF-1.1 **antes** de qualquer digest/assinatura.

Dois streams NRF-1.1 representam o **mesmo valor lógico** **iff** são **byte-idênticos**.

## 6. Limites
Strings/Bytes/Array/Map count ≤ `2^32−1`; profundidade e tamanho total: definidos pela implementação (RECOMENDADO ≥64 de profundidade).

## 7. Erros
InvalidMagic, InvalidTypeTag(u8), NonMinimalVarint, UnexpectedEOF, InvalidUTF8, NotNFC, BOMPresent, NonStringKey, UnsortedKeys, DuplicateKey(String), TrailingData.

## 8. Testes (amostra)
- Válidos: null, true, ints (−1/0/42), `""`, `"hello"`, bytes `[]`, array `[]`/`[true,42]`, map `{}`, `{name:"test", value:42}`, nested.
- Inválidos: magic errado; tag 0x08; varint overlong; varint 33+ bits; duplicate key; unsorted; int truncado; trailing; string com BOM; string não-NFC.

## 9. Referência (Rust) — ver crate incluso
- varint32 decode rejeita: `0x80` inicial, 5ª byte com bits altos, continuations indevidas.
- Strings: UTF-8, BOM-in-any-position, NFC.
- Map: ordenação/duplicata por bytes crus.

## 10. Receipts (Aplicação)
Map com: `"v": String`, `"t": Int64`, `"body": any`, `"nonce": Bytes(16)`, `"sig": Bytes(64 opcional)`; hash-then-sign; verificação removendo `"sig"` e re-encode.

## 11. ABNF
```
stream     = magic value
magic      = %x6E.72.66.31

value      = null / false / true / int64 / string / bytes / array / map

null       = %x00
false      = %x01
true       = %x02
int64      = %x03 8OCTET
string     = %x04 varint32 *OCTET
bytes      = %x05 varint32 *OCTET
array      = %x06 varint32 *value
map        = %x07 varint32 *(string value)

varint32   = 1*5 leb128-byte       ; minimal, unsigned, ≤32 bits
leb128-byte = OCTET                ; bit7=cont
```