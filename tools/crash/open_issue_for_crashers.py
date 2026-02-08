
#!/usr/bin/env python3
"""
Open a GitHub Issue (via gh CLI) for each minimized crasher, if GH_TOKEN is present.
Attaches hex preview and predicate reason.
"""
import os, json, subprocess, pathlib, binascii

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIN = ROOT / "impl" / "rust" / "nrf-core" / "fuzz" / "crashers_minimized"

def has_gh():
    try:
        subprocess.run(["gh", "--version"], check=True, capture_output=True)
        return True
    except Exception:
        return False

def preview_hex(p: pathlib.Path, n=64):
    b = p.read_bytes()
    return binascii.hexlify(b[:n]).decode("ascii")

def run():
    if not has_gh():
        print("gh CLI not available; skipping issue creation")
        return
    if not os.environ.get("GH_TOKEN"):
        print("GH_TOKEN not set; skipping issue creation")
        return
    for p in sorted(MIN.glob("*.nrf")):
        name = p.name
        title = f"[NRF1] Minimised crasher: {name}"
        body = f"""A minimized failing case has been produced.

**File**: `{name}`
**Size**: {p.stat().st_size} bytes
**Preview (first 64 bytes hex)**: `{preview_hex(p)}`

Reproducer:
```bash
# Requires 'nrf1' in PATH and Python ref installed
python3 tools/crash/minimize_case.py impl/rust/nrf-core/fuzz/crashers_minimized/{name} -o /tmp/verify.nrf
```

Please attach decoding logs from:
- Rust: `nrf1 decode impl/rust/nrf-core/fuzz/crashers_minimized/{name} -o -`
- Python: small script using nrf_core_ref.decode(...)
"""
        subprocess.run(["gh", "issue", "create", "-t", title, "-b", body], check=False)

if __name__ == "__main__":
    run()
