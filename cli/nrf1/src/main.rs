use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::io::{Read, Write};
use unicode_normalization::is_nfc;

#[derive(Parser)]
#[command(name = "nrf1", version = "0.4.0", about = "NRF-1.1 CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Encode JSON to NRF-1.1 bytes
    Encode(EncodeCmd),
    /// Decode NRF-1.1 bytes to JSON
    Decode(DecodeCmd),
    Bundle {
        #[arg(long)]
        receipt: String,
        #[arg(long)]
        context: Option<String>,
        #[arg(long, default_value = "bundle.zip")]
        out: String,
    },
    VerifyBundle {
        #[arg(long)]
        bundle: String,
    },
    Ghost(GhostCmd),
}

#[derive(Args)]
struct EncodeCmd {
    /// Input JSON file (or "-" for stdin)
    #[arg(value_name = "INPUT", default_value = "-")]
    input: String,
    /// Output NRF file (or "-" for stdout)
    #[arg(short = 'o', long = "out", value_name = "OUT", default_value = "-")]
    out: String,
}

#[derive(Args)]
struct DecodeCmd {
    /// Input NRF file (or "-" for stdin)
    #[arg(value_name = "INPUT", default_value = "-")]
    input: String,
    /// Output JSON file (or "-" for stdout)
    #[arg(short = 'o', long = "out", value_name = "OUT", default_value = "-")]
    out: String,
}

#[derive(Args)]
struct GhostCmd {
    #[command(subcommand)]
    action: GhostAction,
}

#[derive(Subcommand)]
enum GhostAction {
    New {
        #[arg(long)]
        body_hex: String,
        #[arg(long)]
        cid: String,
        #[arg(long)]
        did: String,
        #[arg(long)]
        rt: String,
    },
    Promote {
        #[arg(long)]
        ghost_id: String,
        #[arg(long)]
        receipt_id: String,
    },
    Expire {
        #[arg(long)]
        ghost_id: String,
        #[arg(long)]
        cause: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Encode(args) => cmd_encode(args),
        Cmd::Decode(args) => cmd_decode(args),
        Cmd::Bundle {
            receipt,
            context,
            out,
        } => {
            println!("(stub) would bundle receipt={receipt} context={context:?} out={out}");
            Ok(())
        }
        Cmd::VerifyBundle { bundle } => {
            println!("(stub) would verify bundle={bundle}");
            Ok(())
        }
        Cmd::Ghost(g) => {
            match g.action {
                GhostAction::New {
                    body_hex,
                    cid,
                    did,
                    rt,
                } => {
                    println!("(stub) would POST /ghosts with cid={cid} did={did} rt={rt} body_hex.len={}", body_hex.len());
                    Ok(())
                }
                GhostAction::Promote {
                    ghost_id,
                    receipt_id,
                } => {
                    println!(
                        "(stub) would POST /ghosts/{ghost_id}/promote with receipt_id={receipt_id}"
                    );
                    Ok(())
                }
                GhostAction::Expire { ghost_id, cause } => {
                    println!("(stub) would POST /ghosts/{ghost_id}/expire cause={cause}");
                    Ok(())
                }
            }
        }
    }
}

fn read_all(path: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    if path == "-" {
        std::io::stdin().read_to_end(&mut buf)?;
    } else {
        buf = std::fs::read(path)?;
    }
    Ok(buf)
}

fn write_all(path: &str, bytes: &[u8]) -> Result<()> {
    if path == "-" {
        let mut out = std::io::stdout().lock();
        out.write_all(bytes)?;
        out.flush()?;
    } else {
        std::fs::write(path, bytes)?;
    }
    Ok(())
}

fn parse_hex_lower(s: &str) -> Result<Vec<u8>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.len() % 2 != 0 {
        anyhow::bail!("bytes hex must be even length");
    }
    for ch in s.chars() {
        if !ch.is_ascii_hexdigit() {
            anyhow::bail!("bytes hex must be [0-9a-f]");
        }
        if ch.is_ascii_uppercase() {
            anyhow::bail!("bytes hex must be lowercase");
        }
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i + 2], 16)?;
        out.push(b);
    }
    Ok(out)
}

fn to_hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

fn json_to_nrf(v: &serde_json::Value) -> Result<nrf_core::Value> {
    use nrf_core::Value as V;
    use serde_json::Value as J;
    Ok(match v {
        J::Null => V::Null,
        J::Bool(b) => V::Bool(*b),
        J::Number(n) => {
            if !n.is_i64() {
                anyhow::bail!("floats not allowed; numbers must be i64");
            }
            V::Int(n.as_i64().unwrap())
        }
        J::String(s) => {
            if s.contains('\u{FEFF}') {
                anyhow::bail!("BOM (U+FEFF) forbidden");
            }
            if !is_nfc(s) {
                anyhow::bail!("String must be NFC");
            }
            V::String(s.clone())
        }
        J::Array(arr) => V::Array(arr.iter().map(json_to_nrf).collect::<Result<Vec<_>>>()?),
        J::Object(map) => {
            if map.len() == 1 {
                if let Some(J::String(hex)) = map.get("$bytes") {
                    return Ok(V::Bytes(parse_hex_lower(hex)?));
                }
            }
            let mut out = std::collections::BTreeMap::new();
            for (k, val) in map {
                // Validate key is NFC and BOM-free
                if k.contains('\u{FEFF}') {
                    anyhow::bail!("BOM (U+FEFF) forbidden in map key");
                }
                if !is_nfc(k) {
                    anyhow::bail!("Map key must be NFC");
                }
                out.insert(k.clone(), json_to_nrf(val)?);
            }
            V::Map(out)
        }
    })
}

fn nrf_to_json(v: &nrf_core::Value) -> serde_json::Value {
    use nrf_core::Value as V;
    use serde_json::Value as J;
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

fn cmd_encode(args: EncodeCmd) -> Result<()> {
    let data = read_all(&args.input).context("reading input")?;
    let json: serde_json::Value = serde_json::from_slice(&data).context("parsing JSON")?;
    let v = json_to_nrf(&json).context("converting JSON to NRF value")?;
    let bytes = nrf_core::encode(&v);
    write_all(&args.out, &bytes).context("writing output")?;
    Ok(())
}

fn cmd_decode(args: DecodeCmd) -> Result<()> {
    let bytes = read_all(&args.input).context("reading input")?;
    let v = nrf_core::decode(&bytes).map_err(|e| anyhow::anyhow!("NRF decode error: {e:?}"))?;
    let json = nrf_to_json(&v);
    let out = serde_json::to_vec_pretty(&json).context("serializing JSON")?;
    write_all(&args.out, &out).context("writing output")?;
    Ok(())
}
