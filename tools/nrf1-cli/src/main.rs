
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use nrf_core::{Value, encode, decode, hash_bytes};
use serde_json::Value as J;
use unicode_normalization::is_nfc;

/// NRF-1.1 CLI: encode/decode/hash
#[derive(Parser)]
#[command(name="nrf1", version, about="NRF-1.1 CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Encode JSON -> NRF-1.1 bytes
    Encode {
        /// Input JSON file (or - for stdin)
        input: String,
        /// Output file (or - for stdout). Writes raw bytes.
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Decode NRF-1.1 bytes -> JSON
    Decode {
        /// Input NRF file (or - for stdin)
        input: String,
        /// Output file (or - for stdout). Writes pretty-printed JSON.
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Compute BLAKE3 of raw bytes (NRF or any file)
    Hash {
        /// Input file (or - for stdin)
        input: String,
        /// print as 'b3:<hex>'
        #[arg(short, long)]
        tag: bool,
    },
}

// JSON <-> NRF mapping (canonical, zero-choice)
use serde_json::Value as J;
use unicode_normalization::is_nfc;

fn parse_hex_lower(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.len() % 2 != 0 || s.is_empty() { anyhow::bail!("bytes hex must be even length and non-empty"); }
    let mut out = Vec::with_capacity(s.len()/2);
    for ch in s.chars() {
        if !ch.is_ascii_hexdigit() { anyhow::bail!("bytes hex must be [0-9a-f]"); }
        if ch.is_ascii_uppercase() { anyhow::bail!("bytes hex must be lowercase"); }
    }
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i+2], 16)?;
        out.push(b);
    }
    Ok(out)
}

fn to_hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len()*2);
    for b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn json_to_nrf(v: &J) -> anyhow::Result<nrf_core::Value> {
    use nrf_core::Value as V;
    Ok(match v {
        J::Null => V::Null,
        J::Bool(b) => V::Bool(*b),
        J::Number(n) => {
            if !n.is_i64() { anyhow::bail!("floats not allowed; numbers must be i64"); }
            V::Int(n.as_i64().unwrap())
        }
        J::String(s) => { if s.contains('\u{FEFF}') { anyhow::bail!("BOM (U+FEFF) forbidden"); } if !is_nfc(s) { anyhow::bail!("String must be NFC"); } V::String(s.clone()) },
        J::Array(arr) => V::Array(arr.iter().map(|x| json_to_nrf(x)).collect::<anyhow::Result<Vec<_>>>()?),
        J::Object(map) => {
            if map.len() == 1 {
                if let Some(J::String(hex)) = map.get("$bytes") {
                    return Ok(V::Bytes(parse_hex_lower(hex)?));
                }
            }
            let mut out = std::collections::BTreeMap::new();
            for (k, val) in map {
                out.insert(k.clone(), json_to_nrf(val)?);
            }
            V::Map(out)
        }
    })
}

fn nrf_to_json(v: &nrf_core::Value) -> J {
    use nrf_core::Value as V;
    match v {
        V::Null => J::Null,
        V::Bool(b) => J::Bool(*b),
        V::Int(i) => serde_json::Number::from(*i).into(),
        V::String(s) => J::String(s.clone()),
        V::Bytes(b) => {
            let mut o = serde_json::Map::new();
            o.insert("$bytes".to_string(), J::String(to_hex_lower(b)));
            J::Object(o)
        }
        V::Array(items) => J::Array(items.iter().map(nrf_to_json).collect()),
        V::Map(m) => {
            let mut o = serde_json::Map::new();
            for (k, val) in m {
                o.insert(k.clone(), nrf_to_json(val));
            }
            J::Object(o)
        }
    }
}


fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Encode { input, out } => {
            let j = read_to_string_maybe_stdin(&input)?;
            let vj: J = serde_json::from_str(&j)?;
            let v = json_to_nrf(&vj)?;
            let bytes = encode(&v);
            write_bytes_maybe_stdout(out.as_deref(), &bytes)?;
        }
        Cmd::Decode { input, out } => {
            let bytes = read_to_bytes_maybe_stdin(&input)?;
            let v = decode(&bytes).map_err(|e| anyhow::anyhow!(format!("{e:?}")))?;
            let j = nrf_to_json(&v);
            let s = serde_json::to_string_pretty(&j)? + "\n";
            write_string_maybe_stdout(out.as_deref(), &s)?;
        }
        Cmd::Hash { input, tag } => {
            let bytes = read_to_bytes_maybe_stdin(&input)?;
            let h = hash_bytes(&bytes);
            let hex = hex::encode(h);
            if tag { println!("b3:{hex}"); } else { println!("{hex}"); }
        }
    }
    Ok(())
}

fn read_to_string_maybe_stdin(path: &str) -> anyhow::Result<String> {
    if path == "-" {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        Ok(std::fs::read_to_string(path)?)
    }
}

fn read_to_bytes_maybe_stdin(path: &str) -> anyhow::Result<Vec<u8>> {
    if path == "-" {
        let mut v = Vec::new();
        io::stdin().read_to_end(&mut v)?;
        Ok(v)
    } else {
        Ok(std::fs::read(path)?)
    }
}

fn write_bytes_maybe_stdout(path: Option<&str>, bytes: &[u8]) -> anyhow::Result<()> {
    match path {
        Some("-") | None if path.is_none() => {
            let mut stdout = io::stdout();
            stdout.write_all(bytes)?;
        }
        Some(p) if p == "-" => {
            let mut stdout = io::stdout();
            stdout.write_all(bytes)?;
        }
        Some(p) => {
            std::fs::write(p, bytes)?;
        }
        None => {}
    }
    Ok(())
}

fn write_string_maybe_stdout(path: Option<&str>, s: &str) -> anyhow::Result<()> {
    match path {
        Some("-") | None if path.is_none() => {
            print!("{s}");
        }
        Some(p) if p == "-" => {
            print!("{s}");
        }
        Some(p) => {
            std::fs::write(p, s)?;
        }
        None => {}
    }
    Ok(())
}

/// JSON -> NRF Value (no floats; bytes unsupported in JSON mapping)
fn json_to_nrf(j: &J) -> anyhow::Result<Value> {
    Ok(match j {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else {
                anyhow::bail!("Non-integer or out-of-range number is not supported by NRF-1.1 core");
            }
        }
        J::String(s) => Value::String(s.clone()),
        J::Array(a) => {
            let mut v = Vec::with_capacity(a.len());
            for it in a { v.push(json_to_nrf(it)?); }
            Value::Array(v)
        }
        J::Object(m) => {
            let mut map = std::collections::BTreeMap::new();
            for (k, vj) in m {
                map.insert(k.clone(), json_to_nrf(vj)?);
            }
            Value::Map(map)
        }
    })
}

fn nrf_to_json(v: &Value) -> J {
    match v {
        Value::Null => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::Int(i) => serde_json::json!(*i),
        Value::String(s) => J::String(s.clone()),
        Value::Bytes(b) => {
            // Represent bytes as hex string for now
            J::String(format!("0x{}", hex::encode(b)))
        }
        Value::Array(a) => {
            J::Array(a.iter().map(nrf_to_json).collect())
        }
        Value::Map(m) => {
            let mut obj = serde_json::Map::new();
            for (k, val) in m {
                obj.insert(k.clone(), nrf_to_json(val));
            }
            J::Object(obj)
        }
    }
}
