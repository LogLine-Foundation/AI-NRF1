
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(clap::Parser)]
#[command(name="nrf1")]

#[derive(clap::Parser)]
#[command(name="nrf1")]
enum Cmd {
        /// Unpack an audit bundle (.zip) into a directory
        ReceiptUnpack { #[arg(long)] bundle: std::path::PathBuf, #[arg(long)] out: std::path::PathBuf },
        /// Produce a static HTML report from an audit bundle
        ReceiptReport { #[arg(long)] bundle: std::path::PathBuf, #[arg(long)] out: std::path::PathBuf },

        /// Compute sha256 and blake3 of a .nrf file (writes .sha256 and .b3)
        Hash { #[arg(long)] r#in: std::path::PathBuf },
        /// Build an index.json for an audit bundle (zip)
        ReceiptIndex { #[arg(long)] bundle: std::path::PathBuf, #[arg(long)] out: std::path::PathBuf },

        /// Verify that a .nrf canonical bytes file matches the signed JSON receipt and its signature
        ReceiptVerifyNrf { #[arg(long)] nrf: std::path::PathBuf, #[arg(long)] signed: std::path::PathBuf, #[arg(long)] pubkey: std::path::PathBuf },
        /// Pack {nrf, signed.json, pubkey} into a deterministic audit bundle (.zip)
        ReceiptPack { #[arg(long)] nrf: std::path::PathBuf, #[arg(long)] signed: std::path::PathBuf, #[arg(long)] pubkey: std::path::PathBuf, #[arg(long)] out: std::path::PathBuf },
    /// Generate Ed25519 keypair (raw 32-byte files)
    Keygen { #[arg(long)] outdir: std::path::PathBuf },
    /// Emit a signed receipt (ALLOW/GHOST) to stdout
    Judge {
        #[arg(long)] allow: bool,
        #[arg(long)] ghost: bool,
        #[arg(long)] sign: bool,
    },
    /// Verify a signed receipt against a public key
    Verify { #[arg()] input: std::path::PathBuf, #[arg(long)] pubkey: std::path::PathBuf },
    /// Dump canonical NRF-1.1 bytes (without sig) from a JSON receipt
    ReceiptBytes { #[arg(long)] r#in: std::path::PathBuf, #[arg(long)] out: std::path::PathBuf },
    /// Print a human-readable dump of the canonical NRF bytes tree
    ReceiptDump { #[arg(long)] r#in: std::path::PathBuf },
    /// Sign a JSON receipt and emit .nrf canonical bytes to a file
    Sign { #[arg(long)] r#in: std::path::PathBuf, #[arg(long)] out: std::path::PathBuf },
}
,
    /// Emit a signed receipt (ALLOW/GHOST) to stdout
    Judge {
        #[arg(long)] allow: bool,
        #[arg(long)] ghost: bool,
        #[arg(long)] sign: bool,
    },
    /// Verify a signed receipt against a public key
    Verify { #[arg()] input: PathBuf, #[arg(long)] pubkey: PathBuf },
    /// Dump canonical NRF-1.1 bytes (without sig) from a JSON receipt
    ReceiptBytes { #[arg(long)] r#in: PathBuf, #[arg(long)] out: PathBuf },
}


// HELPER: cid_from_json_stable
fn cid_from_json_stable(v: &serde_json::Value) -> anyhow::Result<String> {
    // NOTE: Placeholder for NRF-1.1 canonical bytes; here we use a stable JSON sort to keep demo deterministic.
    fn sort_value(val: &serde_json::Value) -> serde_json::Value {
        match val {
            serde_json::Value::Object(m) => {
                let mut keys: Vec<_> = m.keys().cloned().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), sort_value(&m[&k]));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(a) => {
                serde_json::Value::Array(a.iter().map(sort_value).collect())
            }
            _ => val.clone()
        }
    }
    let sorted = sort_value(v);
    let bytes = serde_json::to_vec(&sorted)?;
    let hash = blake3::hash(&bytes);
    Ok(format!("b3:{:x}", hash))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use clap::Parser;
    let cmd = Cmd::parse();
    match cmd {

            Cmd::ReceiptUnpack { bundle, out } => {
                std::fs::create_dir_all(&out)?;
                let file = std::fs::File::open(&bundle)?;
                let mut z = zip::ZipArchive::new(file)?;
                for i in 0..z.len() {
                    let mut f = z.by_index(i)?;
                    let name = f.name().to_string();
                    let dest = out.join(&name);
                    if let Some(parent) = dest.parent() { std::fs::create_dir_all(parent)?; }
                    let mut buf = Vec::new();
                    use std::io::Read;
                    f.read_to_end(&mut buf)?;
                    std::fs::write(&dest, &buf)?;
                }
                eprintln!("unpacked -> {}", out.display());
            }
            Cmd::ReceiptReport { bundle, out } => {
                // build an index on the fly (reuse the index code by calling the command would be nicer, but inline here)
                let file = std::fs::File::open(&bundle)?;
                let mut z = zip::ZipArchive::new(file)?;
                use std::io::Read;
                let mut rows = Vec::new();
                for i in 0..z.len() {
                    let mut f = z.by_index(i)?;
                    let name = f.name().to_string();
                    let mut buf = Vec::new();
                    f.read_to_end(&mut buf)?;
                    use sha2::Digest;
                    let sha_hex = hex::encode(sha2::Sha256::digest(&buf));
                    let b3_hex = blake3::hash(&buf).to_hex().to_string();
                    rows.push((name, buf.len(), sha_hex, format!("b3:{}", b3_hex)));
                }
                rows.sort_by(|a,b| a.0.cmp(&b.0));
                let mut html = String::new();
                html.push_str(r#"<!doctype html><meta charset="utf-8"><title>AI-NRF1 Audit Report</title>
<style>body{font-family:system-ui, -apple-system, Segoe UI, Roboto, sans-serif;padding:24px} h1{margin:0 0 12px} table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:8px;font-size:14px} th{background:#f6f6f6;text-align:left}</style>
<h1>AI‑NRF1 Audit Report</h1><p>Deterministic bundle listing with hashes.</p><table><thead><tr><th>Name</th><th>Bytes</th><th>sha256</th><th>blake3</th></tr></thead><tbody>"#);
                for (name, bytes, sha, b3) in rows {
                    html.push_str(&format!(r#"<tr><td>{}</td><td>{}</td><td style="font-family:monospace">{}</td><td style="font-family:monospace">{}</td></tr>"#, name, bytes, sha, b3));
                }
                html.push_str("</tbody></table>");
                std::fs::write(&out, html)?;
                eprintln!("report -> {}", out.display());
            }


Cmd::Hash { r#in } => {
    use blake3::Hasher as B3;
    let bytes = std::fs::read(&r#in)?;
    // sha256
    use sha2::Digest;
    let mut sh = sha2::Sha256::new();
    sh.update(&bytes);
    let sha = sh.finalize();
    // b3
    let b3 = B3::new().update(&bytes).finalize();
    let p = r#in.display().to_string();
    let sha_hex = hex::encode(sha);
    let b3_hex  = b3.to_hex().to_string();
    println!("sha256({}): {}", p, sha_hex);
    println!("b3({}): {}", p, b3_hex);
    std::fs::write(format!("{}.sha256", p), format("{}  {}
", sha_hex, p))?;
    std::fs::write(format!("{}.b3", p),      format("b3:{}  {}
", b3_hex, p))?;
}
Cmd::ReceiptIndex { bundle, out } => {
    // open zip, compute sha256 & b3 of each entry
    let file = std::fs::File::open(&bundle)?;
    let mut z = zip::ZipArchive::new(file)?;
    use std::io::Read;
    let mut entries = Vec::new();
    for i in 0..z.len() {
        let mut f = z.by_index(i)?;
        let name = f.name().to_string();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        // sha256
        use sha2::Digest;
        let mut sh = sha2::Sha256::new();
        sh.update(&buf);
        let sha_hex = hex::encode(sh.finalize());
        // b3
        let b3_hex = blake3::hash(&buf).to_hex().to_string();
        entries.push(serde_json::json!({
            "name": name,
            "bytes": buf.len(),
            "sha256": sha_hex,
            "b3": f"b3:{b3_hex}"
        }));
    }
    let idx = serde_json::json!({
        "bundle": bundle.display().to_string(),
        "entries": entries
    });
    std::fs::write(&out, serde_json::to_string_pretty(&idx)?)?;
    eprintln!("index -> {}", out.display());
}


Cmd::ReceiptVerifyNrf { nrf, signed, pubkey } => {
    let nrf_bytes = std::fs::read(&nrf)?;
    assert!(nrf_bytes.len() >= 4 && &nrf_bytes[0..4] == b"nrf1", "bad magic in .nrf");
    let signed_data = std::fs::read(&signed)?;
    let r: ai_nrf1_receipts::Receipt = serde_json::from_slice(&signed_data)?;
    // bytes equivalence
    let canon = r.canonical_bytes_without_sig();
    if canon != nrf_bytes {
        return Err("NRF bytes do not match canonical receipt body".into());
    }
    // signature verify
    let pk = std::fs::read(&pubkey)?;
    let pk: [u8;32] = pk[..32].try_into().unwrap();
    r.verify_with_vk(&pk)?;
    eprintln!("✔ .nrf matches signed JSON; signature valid");
}
Cmd::ReceiptPack { nrf, signed, pubkey, out } => {
    // write deterministic zip: fixed filenames
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&out)?);
    use zip::write::FileOptions;
    let opts = FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    // 1) receipt.nrf
    zip.start_file("receipt.nrf", opts)?;
    let b = std::fs::read(&nrf)?; zip.write_all(&b)?;
    // 2) receipt.signed.json
    zip.start_file("receipt.signed.json", opts)?;
    let s = std::fs::read(&signed)?; zip.write_all(&s)?;
    // 3) pubkey.pk
    zip.start_file("pubkey.pk", opts)?;
    let k = std::fs::read(&pubkey)?; zip.write_all(&k)?;
    zip.finish()?;
    eprintln!("packed -> {}", out.display());
}

        Cmd::Keygen { outdir 
Cmd::ReceiptDump { r#in } => {
    let data = std::fs::read(&r#in)?;
    let r: ai_nrf1_receipts::Receipt = serde_json::from_slice(&data)?;
    let bytes = r.canonical_bytes_without_sig();
    dump_tree(&bytes);
}
Cmd::Sign { r#in, out } => {
    let data = std::fs::read(&r#in)?;
    let mut r: ai_nrf1_receipts::Receipt = serde_json::from_slice(&data)?;
    let sk_path = std::env::var("NRF1_SK_PATH")
        .map_err(|_| "NRF1_SK_PATH missing; export secret key path")?;
    let sk = std::fs::read(sk_path)?;
    let sk: [u8;32] = sk[..32].try_into().unwrap();
    r.sign_with_sk(&sk)?; // mutates r.sig
    // write NRF canonical bytes (without sig) for the signed content
    let bytes = r.canonical_bytes_without_sig();
    std::fs::write(&out, &bytes)?;
    eprintln!("signed; canonical bytes -> {}", out.display());
    // also echo JSON to stdout (signed form), useful in pipelines
    println!("{}", serde_json::to_string_pretty(&r)?);
}
} => {
            fs::create_dir_all(&outdir)?;
            let sk = ed25519_dalek::SecretKey::generate(&mut rand::rngs::OsRng);
            let pk: ed25519_dalek::PublicKey = (&sk).into();
            fs::write(outdir.join("ed25519.sk"), sk.to_bytes())?;
            fs::write(outdir.join("ed25519.pk"), pk.to_bytes())?;
        }
        Cmd::Judge { allow, ghost, sign } => {
            // Simplified demo receipt structure
            let did = "did:demo:issuer".to_string();
            let act = if allow { "ALLOW" } else if ghost { "GHOST" } else { "DENY" }.to_string();
            let subject = "subject:demo".to_string();
            let inputs_cid = "b3:democtx".to_string();
            let decision = act.clone();
            let now = 1_736_980_000i64; // placeholder
            let rt = ai_nrf1_receipts::RuntimeMeta { binary_sha256: "sha256:demo".into(), hal_ref: "hal:v1".into() };
            let mut r = ai_nrf1_receipts::Receipt {
                v: "receipt-v1".into(),
                t: now as i128,
                did, act, subject,
                prev_receipt_cid: None,
                inputs_cid,
                decision,
                effects: None,
                rt,
                sig: None,
            };
            if sign {
                let sk_path = std::env::var("NRF1_SK_PATH")?;
                let sk = fs::read(sk_path)?;
                let sk: [u8;32] = sk[..32].try_into().unwrap();
                r.sign_with_sk(&sk)?;
            }
            let out = serde_json::to_string_pretty(&r)?;
            println!("{}", out);
        }
        Cmd::Verify { input, pubkey } => {
            let data = fs::read(&input)?;
            let r: ai_nrf1_receipts::Receipt = serde_json::from_slice(&data)?;
            let pk = fs::read(pubkey)?;
            let pk: [u8;32] = pk[..32].try_into().unwrap();
            r.verify_with_vk(&pk)?;
            r.verify_invariants()?;
            Ok(())
        }
        Cmd::ReceiptBytes { r#in, out } => {
            let data = fs::read(&r#in)?;
            let r: ai_nrf1_receipts::Receipt = serde_json::from_slice(&data)?;
            let bytes = r.canonical_bytes_without_sig();
            let mut f = fs::File::create(&out)?;
            f.write_all(&bytes)?;
            eprintln!("wrote {} bytes to {}", bytes.len(), out.display());
        }
    }
    Ok(())
}

fn make_signer(cfg: &ReceiptSign) -> anyhow::Result<Box<dyn signers::Signer>> {
    match cfg.signer.as_str() {
        "local" => {
            let pem_path = cfg.pem.as_ref().ok_or_else(|| anyhow::anyhow!("--pem required for local signer"))?;
            let pem = std::fs::read_to_string(pem_path)?;
            let s = signers::LocalEd25519Signer::from_pkcs8_pem(&pem)?;
            Ok(Box::new(s))
        }
        "http" => {
            let ep = cfg.endpoint.clone().ok_or_else(|| anyhow::anyhow!("--endpoint required for http signer"))?;
            Ok(Box::new(signers::HttpSigner { endpoint: ep, kid: cfg.kid.clone(), auth_header: cfg.auth_header.clone() }))
        }
        "cloudflare" => {
            let ep = cfg.endpoint.clone().ok_or_else(|| anyhow::anyhow!("--endpoint required for cloudflare signer"))?;
            Ok(Box::new(signers::CloudflareSigner { endpoint: ep, kid: cfg.kid.clone(), auth_header: cfg.auth_header.clone() }))
        }
        other => Err(anyhow::anyhow!(format!("unknown signer kind: {}", other))),
    }
}
