
// Minimal NRF-1.1 encoder/decoder (no decisions). Intended for BASE.
// Covers: tags, varint32 minimal, UTF-8, NFC, map key order, duplicate keys.
// Hashing helper over full stream bytes.
use std::collections::BTreeMap;
use thiserror::Error;
use unicode_normalization::is_nfc;

pub const MAGIC: [u8;4] = *b"nrf1";

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

#[derive(Debug, Error)]
pub enum NrfError {
    #[error("Invalid magic")]
    InvalidMagic,
    #[error("Invalid type tag {0:#x}")]
    InvalidTypeTag(u8),
    #[error("Non-minimal varint32")]
    NonMinimalVarint,
    #[error("Unexpected EOF")]
    UnexpectedEOF,
    #[error("Invalid UTF-8")]
    InvalidUTF8,
    #[error("Not NFC")]
    NotNFC,
    #[error("BOM present")]
    BOMPresent,
    #[error("Non-string map key")]
    NonStringKey,
    #[error("Unsorted keys")]
    UnsortedKeys,
    #[error("Duplicate key: {0}")]
    DuplicateKey(String),
    #[error("Trailing data")]
    TrailingData,
}

pub type Result<T> = std::result::Result<T, NrfError>;

pub fn encode_stream(value: &Value) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&MAGIC);
    encode_value(&mut buf, value);
    buf
}

pub fn blake3_cid(value: &Value) -> String {
    let bytes = encode_stream(value);
    let hash = blake3::hash(&bytes);
    format!("b3:{:x}", hash)
}

fn encode_value(buf: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => buf.push(0x00),
        Value::Bool(false)=> buf.push(0x01),
        Value::Bool(true) => buf.push(0x02),
        Value::Int(n) => { buf.push(0x03); buf.extend_from_slice(&n.to_be_bytes()); }
        Value::String(s) => {
            buf.push(0x04);
            let b = s.as_bytes();
            encode_varint32(buf, b.len() as u32);
            buf.extend_from_slice(b);
        }
        Value::Bytes(b) => {
            buf.push(0x05);
            encode_varint32(buf, b.len() as u32);
            buf.extend_from_slice(b);
        }
        Value::Array(xs) => {
            buf.push(0x06);
            encode_varint32(buf, xs.len() as u32);
            for it in xs { encode_value(buf, it); }
        }
        Value::Map(m) => {
            buf.push(0x07);
            encode_varint32(buf, m.len() as u32);
            for (k, val) in m {
                buf.push(0x04);
                let kb = k.as_bytes();
                encode_varint32(buf, kb.len() as u32);
                buf.extend_from_slice(kb);
                encode_value(buf, val);
            }
        }
    }
}

fn encode_varint32(buf: &mut Vec<u8>, mut x: u32) {
    loop {
        let b = (x & 0x7F) as u8;
        x >>= 7;
        if x == 0 { buf.push(b); break; }
        buf.push(b | 0x80);
    }
}

// Decoder (minimal implementation adequate for BASE check)
pub fn decode_stream(bytes: &[u8]) -> Result<Value> {
    if bytes.len() < 4 { return Err(NrfError::InvalidMagic); }
    if &bytes[0..4] != MAGIC { return Err(NrfError::InvalidMagic); }
    let mut i = 4usize;
    let (val, n) = decode_value(&bytes[i..])?;
    i += n;
    if i != bytes.len() { return Err(NrfError::TrailingData); }
    Ok(val)
}

fn decode_value(input: &[u8]) -> Result<(Value, usize)> {
    if input.is_empty() { return Err(NrfError::UnexpectedEOF); }
    let tag = input[0];
    let mut idx = 1usize;
    match tag {
        0x00 => Ok((Value::Null, idx)),
        0x01 => Ok((Value::Bool(false), idx)),
        0x02 => Ok((Value::Bool(true), idx)),
        0x03 => {
            if input.len() < idx+8 { return Err(NrfError::UnexpectedEOF); }
            let mut buf = [0u8;8];
            buf.copy_from_slice(&input[idx..idx+8]);
            idx += 8;
            Ok((Value::Int(i64::from_be_bytes(buf)), idx))
        }
        0x04 => {
            let (len, used) = decode_varint32(&input[idx..])?; idx += used;
            let end = idx + (len as usize);
            if input.len() < end { return Err(NrfError::UnexpectedEOF); }
            let bytes = &input[idx..end]; idx = end;
            let s = std::str::from_utf8(bytes).map_err(|_| NrfError::InvalidUTF8)?.to_string();
            if s.contains('\u{FEFF}') { return Err(NrfError::BOMPresent); }
            if !is_nfc(&s) { return Err(NrfError::NotNFC); }
            Ok((Value::String(s), idx))
        }
        0x05 => {
            let (len, used) = decode_varint32(&input[idx..])?; idx += used;
            let end = idx + (len as usize);
            if input.len() < end { return Err(NrfError::UnexpectedEOF); }
            let b = input[idx..end].to_vec(); idx = end;
            Ok((Value::Bytes(b), idx))
        }
        0x06 => {
            let (count, used) = decode_varint32(&input[idx..])?; idx += used;
            let mut items = Vec::with_capacity(count as usize);
            let mut used_total = idx;
            for _ in 0..count {
                let (v, u) = decode_value(&input[used_total..])?;
                used_total += u;
                items.push(v);
            }
            Ok((Value::Array(items), used_total))
        }
        0x07 => {
            let (pairs, used) = decode_varint32(&input[idx..])?; idx += used;
            let mut map = BTreeMap::new();
            let mut used_total = idx;
            let mut prev: Option<Vec<u8>> = None;
            for _ in 0..pairs {
                // key must be a string
                if input.len() <= used_total { return Err(NrfError::UnexpectedEOF); }
                if input[used_total] != 0x04 { return Err(NrfError::NonStringKey); }
                let (k, ku) = decode_value(&input[used_total..])?;
                used_total += ku;
                let key = match k { Value::String(s) => s, _ => return Err(NrfError::NonStringKey) };
                // order & duplicates (byte order)
                let kb = key.clone().into_bytes();
                if let Some(p) = prev.as_ref() {
                    match p.as_slice().cmp(&kb) {
                        std::cmp::Ordering::Greater => return Err(NrfError::UnsortedKeys),
                        std::cmp::Ordering::Equal => return Err(NrfError::DuplicateKey(String::from_utf8(kb).unwrap_or_default())),
                        _ => {}
                    }
                }
                prev = Some(kb);
                let (val, vu) = decode_value(&input[used_total..])?;
                used_total += vu;
                map.insert(key, val);
            }
            Ok((Value::Map(map), used_total))
        }
        _ => Err(NrfError::InvalidTypeTag(tag)),
    }
}

fn decode_varint32(input: &[u8]) -> Result<(u32, usize)> {
    let mut res: u32 = 0;
    let mut shift = 0;
    for i in 0..5 {
        if i >= input.len() { return Err(NrfError::UnexpectedEOF); }
        let byte = input[i];
        let payload = (byte & 0x7F) as u32;
        if i == 0 && byte == 0x80 { return Err(NrfError::NonMinimalVarint); }
        if i > 0 && byte == 0x00 { return Err(NrfError::NonMinimalVarint); }
        res |= payload << shift;
        shift += 7;
        if (byte & 0x80) == 0 { return Ok((res, i+1)); }
    }
    Err(NrfError::NonMinimalVarint)
}
