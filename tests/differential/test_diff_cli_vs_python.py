
import json, os, subprocess, tempfile, sys
from hypothesis import given, settings, strategies as st

# Value strategy: NRF-allowed JSON (no float). Bytes represented via {"$bytes":"hex"}
def hex_lower():
    return st.text(alphabet='0123456789abcdef', min_size=0).filter(lambda s: len(s)%2==0)

json_atomic = st.deferred(lambda: st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(1<<63), max_value=(1<<63)-1),
    st.text(),  # Hypothesis will generate lots of Unicode; Python side will enforce NFC/BOM
    st.lists(json_atomic, max_size=4),
    st.dictionaries(st.text(), json_atomic, max_size=4),
    st.builds(lambda h: {"$bytes": h}, hex_lower())
))

# Filter out forbidden cases pre-encode to focus on differential (Python encoder enforces NFC/BOM)
def normalize_value(v):
    # We avoid floats by construction; keep as-is and rely on encoder rules.
    return v

def run_cli(args, input_bytes=None):
    p = subprocess.run(args, input=input_bytes, capture_output=True)
    return p.returncode, p.stdout, p.stderr

@given(json_atomic.map(normalize_value))
@settings(max_examples=60, deadline=None)
def test_rust_encode_python_decode_roundtrip(v):
    import nrf_core_ref
    # 1) Write JSON for Rust CLI encode
    with tempfile.TemporaryDirectory() as td:
        jf = os.path.join(td, "in.json")
        nf = os.path.join(td, "out.nrf")
        with open(jf, "w", encoding="utf-8") as f:
            json.dump(v, f, ensure_ascii=False)

        rc, out, err = run_cli(["nrf1", "encode", jf, "-o", nf])
        if rc != 0:
            # Rust rejected input; Python should also reject when trying to encode
            # (so we check that Python encoder also fails)
            import nrf_core_ref
            try:
                nrf_core_ref.encode(v)
                assert False, "Python accepted input rejected by Rust"
            except Exception:
                return

        # 2) Python decodes the NRF and compares with Rust decode output
        with open(nf, "rb") as f:
            nrf_bytes = f.read()
        py_val = nrf_core_ref.decode(nrf_bytes)

        # 3) Rust decode
        rc2, out2, err2 = run_cli(["nrf1", "decode", nf, "-o", "-"])
        assert rc2 == 0, f"Rust decode failed: {err2}"
        rust_val = json.loads(out2.decode("utf-8"))

        assert py_val == rust_val

@given(json_atomic.map(normalize_value))
@settings(max_examples=60, deadline=None)
def test_python_encode_rust_decode_reencode_stable(v):
    import nrf_core_ref
    # Python encodes -> Rust decodes -> Rust re-encodes -> bytes identical to Python encode
    try:
        py_bytes = nrf_core_ref.encode(v)
    except Exception:
        # Invalid under NRF rules; skip as not representable
        return

    # Rust decode
    with tempfile.NamedTemporaryFile(suffix=".nrf", delete=False) as tmp:
        tmp.write(py_bytes); tmp.flush()
        nf = tmp.name

    rc, out, err = run_cli(["nrf1", "decode", nf, "-o", "-"])
    if rc != 0:
        # Rust rejected something Python accepted -> bug
        assert False, f"Rust rejected Python-encoded value: {err.decode('utf-8', 'ignore')}"

    # Rust re-encode
    with tempfile.NamedTemporaryFile(suffix=".nrf", delete=False) as tmp2:
        nf2 = tmp2.name
    rc2, out2, err2 = run_cli(["nrf1", "encode", "-", "-o", nf2], input_bytes=out)
    assert rc2 == 0, f"Rust re-encode failed: {err2}"

    # Compare bytes: must be identical (canonical)
    with open(nf2, "rb") as f2:
        rust_re = f2.read()
    assert rust_re == py_bytes
