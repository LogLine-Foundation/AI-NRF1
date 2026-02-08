#![cfg(feature = "compat_cbor")]
use ai_ai_nrf1::{Value, encode, decode};
use std::collections::BTreeMap;

#[test]
fn cbor_roundtrip_simple_map() {
    // {"name":"test","value":42}
    let mut m = BTreeMap::new();
    m.insert("name".into(), Value::String("test".into()));
    m.insert("value".into(), Value::Int(42));
    let v = Value::Map(m);

    // to CBOR then back
    let cbor = ai_nrf1::compat_cbor::cbor::to_vec(&v).unwrap();
    let v2 = ai_nrf1::compat_cbor::cbor::from_slice(&cbor).unwrap();
    assert_eq!(v, v2);

    // Ensure NRF encoding still canonical
    let nrf = encode(&v);
    let back = decode(&nrf).unwrap();
    assert_eq!(v, back);
}

#[test]
fn cbor_reject_non_text_key() {
    // CBOR map with bytestring key should be rejected
    // d: { h'01' : 0 } -> a1 41 01 00
    let bad = vec![0xa1, 0x41, 0x01, 0x00];
    let err = ai_nrf1::compat_cbor::cbor::from_slice(&bad).unwrap_err();
    // must map to NonStringKey or InvalidTypeTag
    // We can't pattern-match foreign error types here; just assert it is an error.
    let _ = err;
}

#[test]
fn cbor_reject_float() {
    // 1.5 in CBOR = fb 3ff8000000000000
    let bad = vec![0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let err = ai_nrf1::compat_cbor::cbor::from_slice(&bad).unwrap_err();
    let _ = err;
}

#[test]
fn cbor_text_must_be_nfc() {
    // A text that is NFD should be rejected; using "e\u0301" (é decomposed).
    // We'll construct CBOR: 0x61 'é[NFD]' as a map key
    // For simplicity we serialize via ciborium
    use ciborium::value::Value as Cbor;
    let key = Cbor::Text("e\u{0301}".to_string()); // NFD
    let m = Cbor::Map(vec![(key, Cbor::Integer(0i128.into()))]);
    let mut buf = Vec::new();
    let mut ser = ciborium::ser::Serializer::new(&mut buf);
    ser.set_sort_maps(true);
    m.serialize(&mut ser).unwrap();
    let err = ai_nrf1::compat_cbor::cbor::from_slice(&buf).unwrap_err();
    let _ = err;
}
