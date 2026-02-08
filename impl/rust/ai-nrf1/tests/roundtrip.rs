use ai_ai_nrf1::{Value, encode, decode};
use std::collections::BTreeMap;

#[test]
fn test_roundtrip_primitives() {
    let cases = vec![
        Value::Null,
        Value::Bool(false),
        Value::Bool(true),
        Value::Int(0),
        Value::Int(42),
        Value::Int(-1),
        Value::String(String::new()),
        Value::Bytes(vec![]),
    ];
    for v in cases {
        let enc = encode(&v);
        let dec = decode(&enc).unwrap();
        assert_eq!(v, dec);
        assert_eq!(enc, encode(&dec));
    }
}

#[test]
fn test_array_map() {
    let arr = Value::Array(vec![Value::Bool(true), Value::Int(42)]);
    let mut m = BTreeMap::new();
    m.insert("name".into(), Value::String("test".into()));
    m.insert("value".into(), Value::Int(42));
    let map = Value::Map(m);

    for v in [arr, map] {
        let enc = encode(&v);
        let dec = decode(&enc).unwrap();
        assert_eq!(v, dec);
    }
}

#[test]
fn test_trailing_data() {
    let mut enc = encode(&Value::Null);
    enc.push(0xFF);
    assert!(matches!(decode(&enc), Err(ai_nrf1::Error::TrailingData)));
}

#[test]
fn test_bad_magic() {
    let data = b"nrf2\x00";
    assert!(matches!(decode(data), Err(ai_nrf1::Error::InvalidMagic)));
}

#[test]
fn test_unknown_tag() {
    let data = b"nrf1\x08";
    assert!(matches!(decode(data), Err(ai_nrf1::Error::InvalidTypeTag(0x08))));
}

#[test]
fn test_varint_33bits() {
    let data = vec![0x6E,0x72,0x66,0x31, 0x05, 0xFF,0xFF,0xFF,0xFF,0x1F];
    assert!(matches!(decode(&data), Err(ai_nrf1::Error::NonMinimalVarint)));
}

#[test]
fn test_duplicate_key() {
    let data = vec![
        0x6E,0x72,0x66,0x31,
        0x07,0x02,
        0x04,0x01,0x61, 0x02,
        0x04,0x01,0x61, 0x01,
    ];
    assert!(matches!(decode(&data), Err(ai_nrf1::Error::DuplicateKey(_))));
}

#[test]
fn test_unsorted_keys() {
    let data = vec![
        0x6E,0x72,0x66,0x31,
        0x07,0x02,
        0x04,0x01,0x62, 0x02,
        0x04,0x01,0x61, 0x01,
    ];
    assert!(matches!(decode(&data), Err(ai_nrf1::Error::UnsortedKeys)));
}

#[test]
fn test_bom_present() {
    let data = vec![0x6E,0x72,0x66,0x31, 0x04, 0x03, 0xEF,0xBB,0xBF];
    assert!(matches!(decode(&data), Err(ai_nrf1::Error::BOMPresent)));
}
