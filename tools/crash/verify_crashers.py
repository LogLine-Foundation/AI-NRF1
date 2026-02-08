
#!/usr/bin/env python3
"""
Golden Crashers Gate:
- Asserts that every minimized crasher still reproduces the defined failure predicate.
- Asserts there are no raw crashers unminimized.
- Asserts each minimized crasher has an entry in tools/crash/CRASHERS.toml.

Exit non-zero on any violation.
"""
import sys, os, json, subprocess, pathlib, re

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIN = ROOT / "impl" / "rust" / "nrf-core" / "fuzz" / "crashers_minimized"
RAW = ROOT / "impl" / "rust" / "nrf-core" / "fuzz" / "crashers"
TRACK = ROOT / "tools" / "crash" / "CRASHERS.toml"

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

def parse_toml_simple(path: pathlib.Path):
    # very small TOML subset parser for [[crasher]] blocks with 4 keys
    data = {}
    current = None
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s == "[[crasher]]":
            if current:
                if "file" in current:
                    data[current["file"]] = current
            current = {}
            continue
        m = re.match(r'(\w+)\s*=\s*"(.*)"\s*$', s)
        if m and current is not None:
            k, v = m.group(1), m.group(2)
            current[k] = v
    if current and "file" in current:
        data[current["file"]] = current
    return data

def predicate(nrf_path: pathlib.Path) -> (bool, str):
    # Uses the same oracles as the minimizer via its script (importing is fine, but we shell for isolation)
    p = run(["python3", str(ROOT / "tools" / "crash" / "minimize_case.py"), str(nrf_path), "-o", str(nrf_path) + ".tmp"])
    # The minimizer prints whether predicate holds; we detect by its stdout
    ok = ("still failing: True" in p.stdout) or ("Reason:" in p.stdout)
    reason = ""
    for line in p.stdout.splitlines():
        if line.startswith("Reason:"):
            reason = line.partition(":")[2].strip()
    # Clean temp
    try:
        os.remove(str(nrf_path) + ".tmp")
    except Exception:
        pass
    return ok, reason

def main():
    errors = []

    # 1) Ensure there are no raw, unminimized crashers
    raw = sorted([p for p in RAW.glob("*.nrf")])
    if raw:
        errors.append(f"Found raw crashers without minimization: {[p.name for p in raw]} (run tools/crash/reduce_all.sh)")

    # 2) Verify minimized crashers still fail
    minz = sorted([p for p in MIN.glob("*.nrf")])
    if not minz:
        print("No minimized crashers found; nothing to verify.")
    for p in minz:
        ok, why = predicate(p)
        if not ok:
            errors.append(f"Minimized crasher no longer fails: {p.name}. Remove it and add regression tests.")

    # 3) Ensure tracker entries exist
    reg = parse_toml_simple(TRACK)
    missing = [p.name for p in minz if p.name not in reg]
    if missing:
        errors.append(f"Missing CRASHERS.toml entries for: {missing}")

    if errors:
        print("Golden Crashers Gate FAILED:\n")
        for e in errors:
            print(" -", e)
        sys.exit(1)

    print("Golden Crashers Gate PASSED.")
    sys.exit(0)

if __name__ == "__main__":
    main()
