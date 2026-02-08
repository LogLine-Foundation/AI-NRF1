
#!/usr/bin/env python3
"""
Generate a Rust regression test for a previously-failing minimized crasher that now passes.
The test asserts decode succeeds and re-encode is byte-identical.
"""
import argparse, pathlib, re, os, textwrap

TEMPLATE = """\
// Auto-generated regression test for {seed_name}
// Source: impl/rust/nrf-core/fuzz/crashers_fixed/{seed_file}
use nrf_core::decode; // adjust module path if needed
use std::fs;

#[test]
fn regression_{fn_name}() {{
    // Load bytes at runtime to avoid include_bytes! path issues across workspaces
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/crashers_fixed/{seed_file}");
    let bytes = fs::read(&p).expect("read crasher bytes");
    let v = nrf_core::decode::decode(&bytes).expect("decode should succeed");
    let re = nrf_core::encode::encode(&v);
    assert_eq!(re, bytes, "re-encode not byte-identical");
}}
"""

def sanitize(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_]', '_', name)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("seed_file", help="filename under crashers_fixed (e.g., seed_0001.nrf)")
    ap.add_argument("-o", "--out", required=True, help="output rs test path")
    args = ap.parse_args()

    seed_file = args.seed_file
    seed_name = seed_file.rsplit('.',1)[0]
    fn_name = sanitize(seed_name)
    content = TEMPLATE.format(seed_name=seed_name, seed_file=seed_file, fn_name=fn_name)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    print(f"Wrote regression test: {out}")

if __name__ == "__main__":
    main()
