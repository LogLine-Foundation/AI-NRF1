//! CBOR ↔ NRF-1.1 compatibility (strict subset).
//! Feature-gated with `compat_cbor`.

#[cfg(feature = "compat_cbor")]
pub mod cbor {
    use crate::{Value, Error, Result};
    use unicode_normalization::is_nfc;
    use ciborium::value::Value as Cbor;
    use std::io;

    pub fn from_slice(bytes: &[u8]) -> Result<Value> {
        let v: Cbor = ciborium::de::from_reader(bytes).map_err(|_| Error::InvalidTypeTag(0xFF))?;
        from_cbor_value(&v)
    }

    pub fn to_vec(value: &Value) -> Result<Vec<u8>> {
        let c = to_cbor_value(value)?;
        let mut buf = Vec::new();
        // sorted maps for determinism
        let mut ser = ciborium::ser::Serializer::new(&mut buf);
        ser.set_sort_maps(true);
        c.serialize(&mut ser).map_err(|_| Error::Io(io::Error::new(io::ErrorKind::Other, "cbor ser")))?;
        Ok(buf)
    }

    fn from_cbor_value(v: &Cbor) -> Result<Value> {
        Ok(match v {
            Cbor::Null => Value::Null,
            Cbor::Bool(b) => Value::Bool(*b),
            Cbor::Integer(i) => {
                let n = i128::from(*i);
                if n < i64::MIN as i128 || n > i64::MAX as i128 {
                    return Err(Error::InvalidTypeTag(0x03));
                }
                Value::Int(n as i64)
            }
            Cbor::Bytes(b) => Value::Bytes(b.clone()),
            Cbor::Text(s) => {
                if s.contains('\u{FEFF}') { return Err(Error::BOMPresent); }
                if !is_nfc(s) { return Err(Error::NotNFC); }
                Value::String(s.clone())
            }
            Cbor::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for x in arr {
                    out.push(from_cbor_value(x)?);
                }
                Value::Array(out)
            }
            Cbor::Map(entries) => {
                // keys must be text, sorted by raw UTF-8, no duplicates
                let mut kv: Vec<(String, &Cbor)> = Vec::with_capacity(entries.len());
                for (k, v) in entries {
                    match k {
                        Cbor::Text(s) => {
                            if s.contains('\u{FEFF}') { return Err(Error::BOMPresent); }
                            if !is_nfc(s) { return Err(Error::NotNFC); }
                            kv.push((s.clone(), v));
                        }
                        _ => return Err(Error::NonStringKey),
                    }
                }
                // check ordering and duplicates
                let mut prev: Option<Vec<u8>> = None;
                for (k, _) in &kv {
                    let kb = k.as_bytes().to_vec();
                    if let Some(p) = &prev {
                        use std::cmp::Ordering::*;
                        match p.cmp(&kb) {
                            Less => {}
                            Equal => return Err(Error::DuplicateKey(k.clone())),
                            Greater => return Err(Error::UnsortedKeys),
                        }
                    }
                    prev = Some(kb);
                }
                let mut map = std::collections::BTreeMap::new();
                for (k, v) in kv {
                    map.insert(k, from_cbor_value(v)?);
                }
                Value::Map(map)
            }
            // Disallow: Float, Tag, Simple, Break etc.
            _ => return Err(Error::InvalidTypeTag(0xFF)),
        })
    }

    fn to_cbor_value(v: &Value) -> Result<Cbor> {
        Ok(match v {
            Value::Null => Cbor::Null,
            Value::Bool(b) => Cbor::Bool(*b),
            Value::Int(n) => Cbor::Integer((*n).into()),
            Value::String(s) => {
                if s.contains('\u{FEFF}') { return Err(Error::BOMPresent); }
                if !is_nfc(s) { return Err(Error::NotNFC); }
                Cbor::Text(s.clone())
            }
            Value::Bytes(b) => Cbor::Bytes(b.clone()),
            Value::Array(a) => Cbor::Array(a.iter().map(|x| to_cbor_value(x)).collect::<Result<Vec<_>>>()?),
            Value::Map(m) => {
                // ensure sorted by raw bytes already by BTreeMap key ordering (String byte order == Rust lex order on UTF-8 bytes)
                let mut v = Vec::with_capacity(m.len());
                for (k, val) in m {
                    v.push((Cbor::Text(k.clone()), to_cbor_value(val)?));
                }
                Cbor::Map(v)
            }
        })
    }
}
