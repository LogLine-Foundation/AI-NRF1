
#!/usr/bin/env python3
"""
Deterministic reducer for failing NRF-1.1 cases.

Strategy:
- Treat Rust CLI ("nrf1 decode/encode") as primary oracle and Python reference as cross-oracle.
- A "failure predicate" is satisfied if any of the below is true:
  1) Rust decode fails (non-zero exit)
  2) Rust decode succeeds but Python decode fails on same bytes
  3) Both decoders succeed but their JSON values differ
  4) Python-encode(JSON_from_Rust) != original bytes (non-canonical or mismatch)
  5) Rust re-encode(JSON_from_Rust) != original bytes (non-canonical or mismatch)

Reduction:
- Decode via Python ref to a Python value (if possible). If not possible, attempt binary bisection on raw bytes.
- For structured values, attempt shrinking:
  * arrays: remove chunks, then individual elements
  * maps: remove keys (split-half + single)
  * strings: shorten by halves then by slices
  * bytes: shorten similarly
  * ints: move towards 0, try boundary values
  * booleans/null: already minimal
- Keep any change that preserves the failure predicate, until no more changes apply.

Usage:
  minimize_case.py input.nrf -o minimized.nrf
"""
import argparse, json, os, subprocess, tempfile, pathlib, sys, math, copy
from typing import Any, Tuple, Optional

# Local import (repo root):
REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "impl" / "python" / "nrf_core_ref"))
from nrf_core_ref import encode as py_encode, decode as py_decode

def run_cli(args, input_bytes=None) -> Tuple[int, bytes, bytes]:
    p = subprocess.run(args, input=input_bytes, capture_output=True)
    return p.returncode, p.stdout, p.stderr

def rust_decode_to_json(nrf_bytes: bytes) -> Tuple[bool, Optional[dict], str]:
    with tempfile.NamedTemporaryFile(suffix=".nrf", delete=False) as tf:
        tf.write(nrf_bytes); tf.flush()
        path = tf.name
    rc, out, err = run_cli(["nrf1", "decode", path, "-o", "-"])
    os.unlink(path)
    if rc != 0:
        return False, None, err.decode('utf-8', 'ignore')
    try:
        val = json.loads(out.decode("utf-8"))
        return True, val, ""
    except Exception as e:
        return False, None, f"rust decode JSON parse error: {e}"

def rust_encode_from_json(val: Any) -> Tuple[bool, Optional[bytes], str]:
    # via stdin
    js = json.dumps(val, ensure_ascii=False).encode("utf-8")
    with tempfile.NamedTemporaryFile(suffix=".nrf", delete=False) as tf:
        outp = tf.name
    rc, out, err = run_cli(["nrf1", "encode", "-", "-o", outp], input_bytes=js)
    if rc != 0:
        try:
            os.unlink(outp)
        except Exception:
            pass
        return False, None, err.decode('utf-8', 'ignore')
    b = Path(outp).read_bytes()
    os.unlink(outp)
    return True, b, ""

def predicate(nrf_bytes: bytes) -> Tuple[bool, str]:
    # 1) Rust decode must fail OR mismatch with Python OR non-canonical re-encodings
    ok_rust, rust_val, rust_err = rust_decode_to_json(nrf_bytes)
    try:
        py_val = py_decode(nrf_bytes)
        py_ok = True
    except Exception as e:
        py_ok = False
        py_val = None
        py_err = str(e)

    if not ok_rust:
        return True, f"Rust decode failed: {rust_err}"
    if not py_ok:
        return True, f"Python decode failed but Rust succeeded: {py_err}"

    # Compare values (strict JSON equality)
    if rust_val != py_val:
        return True, "Rust/Python value mismatch"

    # Check re-encodings
    ok_re, rust_re, err = rust_encode_from_json(rust_val)
    if not ok_re:
        return True, f"Rust re-encode failed: {err}"
    if rust_re != nrf_bytes:
        return True, "Rust re-encode not byte-identical"

    try:
        py_re = py_encode(py_val)
    except Exception as e:
        return True, f"Python re-encode failed: {e}"
    if py_re != nrf_bytes:
        return True, "Python re-encode not byte-identical"

    return False, ""

def shrink_value(v: Any) -> Any:
    # Primitive shrinking helpers
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        # try moving towards 0 and edge cases
        candidates = [0, 1, -1, (1<<63)-1, -(1<<63)]
        for c in candidates:
            if c == v: continue
            yield c
        # halve towards 0
        if v != 0:
            yield v // 2
    elif isinstance(v, str):
        if len(v) == 0:
            return
        # halves then slices
        yield v[: len(v)//2 ]
        yield v[: max(0, len(v)//3) ]
        yield v[: max(0, len(v)-1) ]
        # keep 1-char if long
        yield v[:1]
    elif isinstance(v, list):
        n = len(v)
        if n == 0: return
        # split halves
        yield v[: n//2 ]
        # remove each element
        for i in range(n):
            yield v[:i] + v[i+1:]
        # recurse: shrink elements in place
        for i in range(n):
            for cand in shrink_value(v[i]) or []:
                new = v[:]
                new[i] = cand
                yield new
    elif isinstance(v, dict):
        keys = list(v.keys())
        if not keys: return
        # remove half the keys
        mid = len(keys)//2
        yield {k: v[k] for k in keys[:mid]}
        # remove each key
        for k in keys:
            nv = v.copy(); nv.pop(k, None)
            yield nv
        # recurse: shrink values
        for k in keys:
            for cand in shrink_value(v[k]) or []:
                nv = v.copy(); nv[k] = cand
                yield nv
    elif isinstance(v, dict) and set(v.keys()) == {"$bytes"} and isinstance(v["$bytes"], str):
        hx = v["$bytes"]
        if len(hx) <= 2:
            return
        yield {"$bytes": hx[: len(hx)//2 ]}
        if len(hx) > 2:
            yield {"$bytes": hx[: len(hx)-2 ]}

def try_shrink(nrf_bytes: bytes) -> bytes:
    # Try decoding via Python to get structure; if fails, perform byte-level trimming
    try:
        val = py_decode(nrf_bytes)
        structured = True
    except Exception:
        structured = False

    if not structured:
        # Byte-level bisection
        b = bytearray(nrf_bytes)
        changed = True
        while changed and len(b) > 8:
            changed = False
            mid = len(b)//2
            candidate = bytes(b[:mid])
            ok, _ = predicate(candidate)
            if ok:
                b = bytearray(candidate)
                changed = True
        return bytes(b)

    best = nrf_bytes
    improved = True
    while improved:
        improved = False
        for cand_val in shrink_value(val) or []:
            try:
                cand_bytes = py_encode(cand_val)
            except Exception:
                continue
            ok, _ = predicate(cand_bytes)
            if ok and len(cand_bytes) < len(best):
                best = cand_bytes
                val = cand_val
                improved = True
                break
    return best

def main():
    import argparse
    from pathlib import Path
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help=".nrf file to minimize")
    ap.add_argument("-o", "--out", required=True, help="output minimized .nrf")
    args = ap.parse_args()

    data = Path(args.input).read_bytes()
    ok, why = predicate(data)
    if not ok:
        print("Input does not reproduce a failure; nothing to minimize.", file=sys.stderr)
        Path(args.out).write_bytes(data)
        return

    minimized = try_shrink(data)
    Path(args.out).write_bytes(minimized)
    mok, mwhy = predicate(minimized)
    print("Minimized:", len(data), "->", len(minimized), "bytes; still failing:", mok)
    if mok:
        print("Reason:", mwhy)

if __name__ == "__main__":
    from pathlib import Path
    main()
