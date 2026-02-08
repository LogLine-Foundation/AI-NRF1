
use std::fs;
use std::path::PathBuf;
use nrf_core::{decode};

fn repo_root() -> PathBuf {
    // cargo sets CARGO_MANIFEST_DIR to impl/rust/nrf-core
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // vectors are at repo_root/tests/vectors
    here.parent().unwrap().parent().unwrap().parent().unwrap().join("tests").join("vectors")
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for tok in s.split_whitespace() {
        let t = tok.trim();
        if t.is_empty() { continue; }
        let t = t.trim_start_matches("0x").trim_start_matches("0X");
        if t.len() % 2 != 0 { continue; }
        for i in (0..t.len()).step_by(2) {
            let b = u8::from_str_radix(&t[i..i+2], 16).unwrap();
            out.push(b);
        }
    }
    out
}

#[test]
fn valid_vectors_roundtrip() {
    let vdir = repo_root().join("valid");
    if !vdir.exists() { eprintln!("valid vectors dir not found, skipping"); return; }
    for entry in fs::read_dir(vdir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|x| x.to_str()) != Some("hex") { continue; }
        let txt = fs::read_to_string(&path).unwrap();
        let bytes = hex_to_bytes(&txt);
        let val = decode(&bytes).expect(&format!("decode failed for {:?}", path));
        let re = nrf_core::encode(&val);
        assert_eq!(bytes, re, "re-encode mismatch for {:?}", path);
    }
}

#[test]
fn invalid_vectors_reject() {
    let idir = repo_root().join("invalid");
    if !idir.exists() { eprintln!("invalid vectors dir not found, skipping"); return; }
    for entry in fs::read_dir(idir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|x| x.to_str()) != Some("hex") { continue; }
        let txt = fs::read_to_string(&path).unwrap();
        let bytes = hex_to_bytes(&txt);
        let res = decode(&bytes);
        assert!(res.is_err(), "expected error for {:?}", path);
    }
}
