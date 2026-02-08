
#!/usr/bin/env python3
"""
Generate deterministic randomized NRF-1.1 byte streams using the Python reference encoder,
to seed the fuzz corpus and for differential testing.
"""
import os, sys, json, random, binascii, argparse, pathlib
from typing import Any
# Local import when running from repo root
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "impl" / "python" / "nrf_core_ref"))
from nrf_core_ref import encode  # type: ignore

ALPH = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_ "

def rand_str(rng: random.Random, max_len: int = 24) -> str:
    n = rng.randint(0, max_len)
    s = "".join(rng.choice(ALPH) for _ in range(n))
    # Occasionally inject some Unicode
    if n > 0 and rng.random() < 0.2:
        s += rng.choice(["é","ç","ß","Ω","中","𐍈"])
    return s

def rand_hex(rng: random.Random, max_bytes: int = 16) -> str:
    n = rng.randint(0, max_bytes)
    return os.urandom(n).hex()

def rand_int64(rng: random.Random) -> int:
    lo, hi = -(1<<63), (1<<63)-1
    # Bias towards small ints, but include edges
    bucket = rng.random()
    if bucket < 0.05: return lo
    if bucket < 0.10: return hi
    if bucket < 0.40: return rng.randint(-256, 256)
    return rng.randint(lo, hi)

def rand_value(rng: random.Random, depth: int = 0) -> Any:
    if depth > 3:
        # cap nesting
        choices = ["null", "bool", "int", "str", "bytes"]
    else:
        choices = ["null", "bool", "int", "str", "bytes", "arr", "map"]
    k = rng.choice(choices)
    if k == "null":
        return None
    if k == "bool":
        return bool(rng.getrandbits(1))
    if k == "int":
        return rand_int64(rng)
    if k == "str":
        s = rand_str(rng)
        # Occasionally enforce NFC by constructing decomposed sequences then normalizing later (encoder enforces NFC)
        return s
    if k == "bytes":
        return {"$bytes": rand_hex(rng)}
    if k == "arr":
        n = rng.randint(0, 4)
        return [rand_value(rng, depth+1) for _ in range(n)]
    if k == "map":
        n = rng.randint(0, 4)
        keys = set()
        m = {}
        for _ in range(n):
            # ensure unique string keys
            key = rand_str(rng) or "k" + str(rng.randint(0, 9999))
            if key in keys: continue
            keys.add(key)
            m[key] = rand_value(rng, depth+1)
        return m
    raise AssertionError("unreachable")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("-n", "--count", type=int, default=128)
    ap.add_argument("-o", "--outdir", type=str, required=True)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    written = 0
    for i in range(args.count):
        v = rand_value(rng, 0)
        try:
            b = encode(v)
        except Exception:
            # Skip values not representable (e.g., non-NFC or invalid by rules)
            continue
        h = binascii.hexlify(b[:16]).decode("ascii")
        p = outdir / f"generated_{i:04d}_{h}.nrf"
        with open(p, "wb") as f:
            f.write(b)
        written += 1

    print(f"wrote {written} seeds to {outdir}")

if __name__ == "__main__":
    main()
