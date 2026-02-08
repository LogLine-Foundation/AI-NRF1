# NRF‑1.1 Security Considerations
*Version:* 1.1 • *Updated:* 2026-02-08

This document records **normative and informative** guidance for secure usage of NRF‑1.1 across implementations, pipelines, and products.
It complements the core on‑wire specification.

---

## 1. Unicode & Text Safety

### 1.1 NFC Version Pinning (Normative)
Implementations **MUST** validate that all strings (both standalone values and map keys) are **Unicode NFC** according to **Unicode 2026** (stable normalization behavior since UAX #15).They **MUST NOT** accept strings that are not in NFC. If the platform’s normalization library is versioned, the implementation **MUST document** the Unicode version used and treat version changes as a **breaking change** for canonical byte identity.

> Rationale: canonical hashing depends on byte‑stable normalization.

### 1.2 BOM Prohibition (Normative)
Byte order mark **U+FEFF** is **forbidden** anywhere in strings. Decoders **MUST** reject on presence (`BOMPresent`).

### 1.3 Ill‑Formed UTF‑8 (Normative)
Decoders **MUST** reject ill‑formed UTF‑8 sequences (`InvalidUTF8`). Encoders **MUST** only emit legal UTF‑8 sequences.

### 1.4 Noncharacters & Confusables (Informative)
NRF‑1.1 does **not** restrict Unicode noncharacters, homoglyphs, or confusables. These are **application‑layer concerns**. Systems MAY:
- Reject or map characters in PRECIS‑style profiles for identifiers/user‑visible strings.
- Display security warnings for mixed‑script keys or suspicious code points.

---

## 2. Maps, Keys, and Collation

### 2.1 Key Type & Ordering (Normative)
Map keys are **strings only**, NFC‑validated, and encoded as NRF strings (tag `0x04`). Pairs **MUST** be sorted by **raw UTF‑8 byte sequences** (unsigned lexicographic). Duplicate keys **MUST** be rejected (`DuplicateKey`). Unsorted keys **MUST** be rejected (`UnsortedKeys`).

> Rationale: byte ordering (not locale/collation) preserves canonical hashing across locales and runtimes.

### 2.2 Identifier Policies (Informative)
If keys carry security semantics (e.g., policy fields), adopt an **allow‑list** and canonical casing policy at the schema level to avoid shadow fields (`User` vs `user`).

---

## 3. Lengths, Limits, and DoS

### 3.1 Varint32 Minimality (Normative)
All length/count fields use **unsigned LEB128 varint32** with **minimal encoding**. Non‑minimal encodings **MUST** be rejected (`NonMinimalVarint`).

### 3.2 Resource Limits (Normative)
Decoders **MUST** define **implementation limits** to resist denial‑of‑service:
- **Max string byte length** (≤ 2^32−1; recommend ≤ 64 MiB default)
- **Max bytes length** (≤ 2^32−1; recommend ≤ 64 MiB default)
- **Max array items** (≤ 2^32−1; recommend ≤ 1e6 default)
- **Max map pairs** (≤ 2^32−1; recommend ≤ 1e6 default)
- **Max nesting depth** (recommend ≥ 64; default 128)
- **Max total stream size** (implementation‑defined; set a sane cap)

Exceeding limits **MUST** fail explicitly (e.g., `ResourceLimitExceeded`).

### 3.3 Streaming & Incomplete Reads (Normative)
Decoders **MUST** treat premature EOF as `UnexpectedEOF`. No trailing bytes are allowed after the root value (`TrailingData`).

---

## 4. Hashing & Domain Separation

### 4.1 Canonical Hash Definition (Normative)
A content identifier **MUST** be computed as **BLAKE3** over the **exact NRF bytes** *(including the `nrf1` magic and one value)* or, if a project chooses to exclude the magic, it **MUST** document the convention. Recommended encoded form: `b3:<hex>`.

### 4.2 Domain Separation (Informative → Recommended)
When hashing different logical artifacts (e.g., stream vs. inner value vs. receipt envelope), prepend an ASCII context label, e.g.:
```
"nrf1.stream" || <nrf_bytes>
"nrf1.value"  || <value_bytes_without_magic>
"nrf1.receipt"|| <receipt_envelope>
```
This prevents cross‑domain collisions in multi‑artifact systems.

### 4.3 Small‑Domain Privacy (Informative)
Hashes of low‑entropy values (e.g., booleans, tiny enums) can be brute‑forced. **Do not** rely on hashing alone to hide sensitive fields. Use:
- Omission/minimization, or
- Salt/pepper outside canonical identity (not part of bytes that determine CID).

---

## 5. Signatures, Keys & Time

### 5.1 Ed25519 Signatures (Normative for Receipts)
If a receipt includes `"sig"` it **MUST** be an Ed25519 signature over the **hash of the receipt without `sig`**. Include domain separation, e.g. `"nrf1.receipt"`. Public keys **MUST** be discoverable in a trust store or pinned in the bundle.

### 5.2 Key Management (Informative → Recommended)
Define operational policy:
- Key generation in HSM/KMS where feasible.
- Rotation cadences; revocation lists.
- Provenance chain: which key signed which artifact (key IDs in receipts).

### 5.3 Timestamps (Informative → Recommended)
`Int64` timestamps reflect the **signer’s clock**. For stronger guarantees:
- Anchor the receipt hash to a trustworthy time source (e.g., public ledger anchoring, RFC 3161 TSA).
- Or scope claims: “*At time T (claimed by signer), S asserts…*”.

---

## 6. Interoperability & Import

### 6.1 Importers (Normative)
When importing from JSON/CBOR/MsgPack to NRF:
- Data **MUST** be rejected if it cannot be represented in NRF‑1.1 (e.g., floats, non‑string keys).
- Hashes/signatures **MUST ALWAYS** be computed over **NRF bytes only** after import. Never over source‑format bytes.

### 6.2 Bytes in JSON (Informative → Recommended)
Define a JSON convention for bytes (e.g., `{"$bytes":"hex"}` or base64) in mapping docs; the canonical hash **still** applies to NRF bytes.

---

## 7. Floating‑Point Policy

NRF‑1.1 core **excludes** floats. Represent real quantities as:
- **Scaled integers** (e.g., `micro` or `1e6` scale), documented per schema.
- **Strings** for display‑only numbers (not for computation).

Policies relying on floating‑point **MUST** fix rounding mode and precision in the policy runtime and confine FP usage to **non‑canonical** paths (i.e., never part of identity).

---

## 8. Implementation Guidance

- Use **constant‑time** comparisons where appropriate for signatures/MACs in higher layers.
- Avoid unbounded recursion; use iterative decoders when possible.
- Fuzz decoders with mutation + grammar‑based fuzzing.
- Cross‑test multiple independent implementations (Rust, Python) using shared vectors.

---

## 9. Threats Not Solved by NRF‑1.1

- **Authorization** and **policy semantics**: handled by higher‑level engines.
- **Transport‑layer threats**: replay, MITM, congestion — out of scope of the format.
- **End‑user phishing / visual spoofing** through confusables: mitigate in UI/policy.

---

## 10. IANA / Registries (Future Work)
If a registry of type tags or profile IDs is introduced, specify stable procedures for extension without ambiguity (NRF‑1.1 reserves no extension tags in the 0x00–0x07 range).
