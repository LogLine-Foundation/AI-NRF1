use std::collections::BTreeMap;
use std::io::{self, Read};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

#[derive(Debug)]
pub enum Error {
    InvalidMagic,
    InvalidTypeTag(u8),
    NonMinimalVarint,
    UnexpectedEOF,
    InvalidUTF8,
    NotNFC,
    BOMPresent,
    NonStringKey,
    UnsortedKeys,
    DuplicateKey(String),
    TrailingData,
    Io(io::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Error::UnexpectedEOF
        } else {
            Error::Io(e)
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

const MAGIC: &[u8; 4] = b"nrf1";

pub fn encode(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    encode_value(&mut buf, value);
    buf
}

fn encode_value(buf: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Null => buf.push(0x00),
        Value::Bool(false) => buf.push(0x01),
        Value::Bool(true) => buf.push(0x02),
        Value::Int(n) => {
            buf.push(0x03);
            buf.extend_from_slice(&n.to_be_bytes());
        }
        Value::String(s) => {
            buf.push(0x04);
            encode_varint32(buf, s.as_bytes().len() as u32);
            buf.extend_from_slice(s.as_bytes());
        }
        Value::Bytes(b) => {
            buf.push(0x05);
            encode_varint32(buf, b.len() as u32);
            buf.extend_from_slice(b);
        }
        Value::Array(items) => {
            buf.push(0x06);
            encode_varint32(buf, items.len() as u32);
            for it in items {
                encode_value(buf, it);
            }
        }
        Value::Map(map) => {
            buf.push(0x07);
            encode_varint32(buf, map.len() as u32);
            for (k, v) in map {
                buf.push(0x04);
                encode_varint32(buf, k.as_bytes().len() as u32);
                buf.extend_from_slice(k.as_bytes());
                encode_value(buf, v);
            }
        }
    }
}

fn encode_varint32(buf: &mut Vec<u8>, mut v: u32) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(b);
            break;
        }
        buf.push(b | 0x80);
    }
}

pub fn decode(data: &[u8]) -> Result<Value> {
    let mut cur = io::Cursor::new(data);
    let mut magic = [0u8; 4];
    cur.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(Error::InvalidMagic);
    }
    let v = decode_value(&mut cur)?;
    let mut trailing = [0u8; 1];
    if cur.read(&mut trailing)? > 0 {
        return Err(Error::TrailingData);
    }
    Ok(v)
}

fn decode_value<R: Read>(r: &mut R) -> Result<Value> {
    let tag = read_u8(r)?;
    match tag {
        0x00 => Ok(Value::Null),
        0x01 => Ok(Value::Bool(false)),
        0x02 => Ok(Value::Bool(true)),
        0x03 => {
            let mut b = [0u8; 8];
            r.read_exact(&mut b)?;
            Ok(Value::Int(i64::from_be_bytes(b)))
        }
        0x04 => {
            let len = decode_varint32(r)? as usize;
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf)?;
            let s = validate_string_bytes(buf)?;
            Ok(Value::String(s))
        }
        0x05 => {
            let len = decode_varint32(r)? as usize;
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf)?;
            Ok(Value::Bytes(buf))
        }
        0x06 => {
            let count = decode_varint32(r)? as usize;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(decode_value(r)?);
            }
            Ok(Value::Array(items))
        }
        0x07 => {
            let count = decode_varint32(r)? as usize;
            let mut map = BTreeMap::new();
            let mut prev_key_bytes: Option<Vec<u8>> = None;

            for _ in 0..count {
                let key_tag = read_u8(r)?;
                if key_tag != 0x04 {
                    return Err(Error::NonStringKey);
                }
                let key_len = decode_varint32(r)? as usize;
                let mut key_buf = vec![0u8; key_len];
                r.read_exact(&mut key_buf)?;
                let key = validate_string_bytes(key_buf.clone())?;

                if let Some(prev) = &prev_key_bytes {
                    use std::cmp::Ordering::*;
                    match prev.cmp(&key_buf) {
                        Less => {}
                        Equal => return Err(Error::DuplicateKey(key)),
                        Greater => return Err(Error::UnsortedKeys),
                    }
                }
                prev_key_bytes = Some(key_buf);
                let val = decode_value(r)?;
                map.insert(key, val);
            }
            Ok(Value::Map(map))
        }
        _ => Err(Error::InvalidTypeTag(tag)),
    }
}

fn read_u8<R: Read>(r: &mut R) -> Result<u8> {
    let mut b = [0u8;1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

fn decode_varint32<R: Read>(r: &mut R) -> Result<u32> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    for i in 0..5 {
        let byte = read_u8(r)?;
        let payload = (byte & 0x7F) as u32;

        if i == 0 && byte == 0x80 {
            return Err(Error::NonMinimalVarint);
        }

        result |= payload << shift;
        shift += 7;

        let cont = (byte & 0x80) != 0;

        if !cont {
            return Ok(result);
        }

        if i == 4 {
            if (byte & 0x80) != 0 || (byte & 0xF0) != 0 {
                return Err(Error::NonMinimalVarint);
            }
            return Ok(result);
        }
    }
    Err(Error::NonMinimalVarint)
}

fn validate_string_bytes(bytes: Vec<u8>) -> Result<String> {
    let s = String::from_utf8(bytes).map_err(|_| Error::InvalidUTF8)?;
    if s.contains('\u{FEFF}') {
        return Err(Error::BOMPresent);
    }
    if !unicode_normalization::is_nfc(&s) {
        return Err(Error::NotNFC);
    }
    Ok(s)
}

#[cfg(feature = "compat_cbor")]
pub mod compat_cbor;
