
use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;
use std::fs;

fn write(tmp: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = tmp.join(name);
    fs::write(&p, body.as_bytes()).unwrap();
    p
}

#[test]
fn json_bytes_roundtrip_ok() {
    let tmp = tempfile::tempdir().unwrap();
    let j = r#"{"$bytes":"48656c6c6f"}"#;
    let jf = write(tmp.path(), "in.json", j);
    let nrf = tmp.path().join("out.nrf");

    // encode
    Command::cargo_bin("nrf1")
        .unwrap()
        .args(["encode", jf.to_str().unwrap(), "-o", nrf.to_str().unwrap()])
        .assert()
        .success();

    // decode
    let out = Command::cargo_bin("nrf1")
        .unwrap()
        .args(["decode", nrf.to_str().unwrap(), "-o", "-"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains(r#""$bytes":"48656c6c6f""#));
}

#[test]
fn json_bytes_reject_upper_hex() {
    let tmp = tempfile::tempdir().unwrap();
    let j = r#"{"$bytes":"DEADBEEF"}"#;
    let jf = write(tmp.path(), "bad.json", j);

    Command::cargo_bin("nrf1")
        .unwrap()
        .args(["encode", jf.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("lowercase"));
}

#[test]
fn reject_bom_in_string() {
    let tmp = tempfile::tempdir().unwrap();
    // U+FEFF at start of "Olá"
    let j = "{ \"msg\": \"\u{FEFF}Olá\" }";
    let jf = write(tmp.path(), "bom.json", j);

    Command::cargo_bin("nrf1")
        .unwrap()
        .args(["encode", jf.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("BOM (U+FEFF)"));
}
