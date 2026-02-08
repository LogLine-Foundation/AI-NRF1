
# AI‑NRF1 Release Notes (Template)

## Highlights
- Canonical encoding (NRF‑1.1) core crates with vectors and fuzz gates
- Golden Crashers Gate + Fix‑then‑Test workflow
- Autobundle: specs, sources, vectors, crashers (min/fixed), CLI, workflows

## Checksums
Checksums are published alongside the Autobundle in `dist/CHECKSUMS.sha256` and `dist/CHECKSUMS.sha512`.
Verify locally (Linux/macOS):
```bash
shasum -a 256 dist/ai-nrf1_autobundle_*.zip
shasum -a 512 dist/ai-nrf1_autobundle_*.zip
```

## Upgrade Notes
- No breaking changes in wire format (NRF‑1.1).
- CI introduces stricter gates: minimized crashers MUST reproduce, regressions MUST land with tests.
