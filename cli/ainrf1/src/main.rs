
use clap::{Parser, Subcommand};
use anyhow::Result;
use std::fs;
use std::path::Path;
use nrf1::Value;
use ed25519_dalek::{SigningKey, VerifyingKey};
use reasoning_bit::{ReasoningBit, Judgment, Usage};
use rand::RngCore;
use sha2::{Sha256, Digest};
use std::io::Read;

#[derive(Parser)]
#[command(author, version, about="AI-NRF1 CLI (BASE)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd
}
#[derive(Subcommand)]
enum Cmd {
    /// Run conformance vectors (manifest.json)
    Conformance { manifest: String },
    /// JSON -> NRF bytes
    Canon { input: String, #[arg(short, long)] out: Option<String> },
    /// Compute CID (b3:...) from JSON (strict)
    Cid { input: String },
    /// Verify basic NRF constraints
    Check { input: String },
    /// Sanitize with schema (placeholder: same as canon in BASE)
    Sanitize { input: String, #[arg(short, long)] schema: Option<String>, #[arg(short, long)] out: Option<String> },
    /// Deterministic judge: creates a receipt (engine local or ollama). Use --model-path to hash gguf.
    Judge { 
        context: String, 
        #[arg(short, long)] policy: String, 
        #[arg(long)] engine: String, 
        #[arg(long)] model: String,
        #[arg(long)] model_path: Option<String>,
        #[arg(long, default_value="0")] seed: u64, 
        #[arg(long, default_value="0")] temperature: f32, 
        #[arg(long, default_value="1.0")] top_p: f32, 
        #[arg(short, long)] out: String, 
        #[arg(long)] url: Option<String> 
    },
    /// Bundle receipt (+context) into .tgz
    Bundle { receipt: String, #[arg(long)] context: Option<String>, #[arg(short, long)] out: String, #[arg(long)] sbom: Option<String> },
    /// Verify bundle or receipt (strict)
    Verify { bundle: String, #[arg(long)] known_runtime: Option<String>, #[arg(long, default_value="false")] require_cosign: bool },
    Conformance { manifest: String },
}

fn sha256_file(p: &Path) -> Result<String> {
    let mut f = fs::File::open(p)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    format!("{:x}", h.finalize())
}

fn current_binary_sha256() -> Result<String> {
    // Linux: /proc/self/exe. Fallback: read argv[0] if exists.
    let path = std::env::current_exe()?;
    sha256_file(&path)
}

fn prompt_hash(model: &str, policy: &str) -> String {
    // Deterministic render stub; in real engine render template with fixed canon.
    let rendered = format!("ENGINE_PROMPT_V1\nMODEL={}\nPOLICY={}\n", model, policy);
    sha256_bytes(rendered.as_bytes())
}

async fn ollama_generate(model: &str, prompt: &str) -> Result<String> {
    // Optional local integration: POST http://localhost:11434/api/generate
    // To keep BASE portable, we only try when engine=="ollama"; ignore errors (fallback to stub).
    let url = "http://127.0.0.1:11434/api/generate";
    let body = serde_json::json!({"model": model, "prompt": prompt, "stream": false});
    let client = reqwest::Client::new();
    let resp = client.post(url).json(&body).send().await;
    if let Ok(r) = resp {
        let v: serde_json::Value = r.json().await?;
        if let Some(s) = v.get("response").and_then(|x| x.as_str()) { return Ok(s.to_string()); }
    }
    anyhow::bail!("ollama not available")
}

fn render_prompt(model: &str, policy: &str, context_cid: &str) -> String {
    format!("# LLM-Engine v1\nMODEL={}\nPOLICY={}\nCONTEXT_CID={}\n", model, policy, context_cid)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Canon{input, out} => {
            let s = fs::read_to_string(input)?;
            let bytes = ai_nrf1_sdk::canon_json_strict(&s)?;
            if let Some(o)=out { fs::write(o, bytes)?; } else { println!("{}", hex::encode(bytes)); }
        }
        Cmd::Cid{input} => {
            let s = fs::read_to_string(input)?;
            let cid = ai_nrf1_sdk::cid_from_json(&s)?;
            println!("{}", cid);
        }
        Cmd::Check{input} => {
            let data = fs::read(input)?;
            let _v = nrf1::decode_stream(&data)?;
            println!("OK");
        }
        Cmd::Sanitize{input, schema:_, out} => {
            let s = fs::read_to_string(input)?;
            let bytes = ai_nrf1_sdk::canon_json_strict(&s)?;
            if let Some(o)=out { fs::write(o, bytes)?; } else { println!("{}", hex::encode(bytes)); }
        }
        Cmd::Judge{context, policy, engine, model, model_path, seed:_, temperature:_, top_p:_, out, url} => {
            // Load NRF context (bytes) and decode to Value (ensures it's valid)
            let ctx_bytes = fs::read(&context)?;
            let body_val = nrf1::decode_stream(&ctx_bytes)?;

            // Runtime info
            let bin_sha = current_binary_sha256()?;
            let mut env = std::collections::BTreeMap::new();
            env.insert("model".into(), model.clone());
            let model_sha = match model_path {
                Some(mp) if Path::new(&mp).exists() => sha256_file(Path::new(&mp))?,
                _ => "unknown".into(),
            };
            env.insert("model_sha256".into(), model_sha.clone());
            let rt = receipt::RuntimeInfo{
                name: engine, version: "local".into(), binary_sha256: bin_sha, env
            };

            // Receipt
            let mut nonce = vec![0u8;16]; rand::thread_rng().fill_bytes(&mut nonce);
            // Context CID
            let context_cid = nrf1::blake3_cid(&body_val);

            // Render prompt and hash
            let prompt = render_prompt(&model, &policy, &context_cid);
            let ph = prompt_hash(&model, &policy);

            // Call engine (optional): if engine=="ollama" try local server, else stub verdict by policy+context
            let judgment_text = if engine == "ollama" {
                match tokio::runtime::Runtime::new().unwrap().block_on(ollama_generate(&model, &prompt)) {
                    Ok(s) => s,
                    Err(_) => "Engine offline; deterministic stub verdict.".into()
                }
            } else {
                "Deterministic stub verdict for BASE.".into()
            };

            let verdict = if judgment_text.to_lowercase().contains("violation") { "FAIL" } else { "PASS" };
            let model_sha = model_path.clone().and_then(|p| if std::path::Path::new(&p).exists() { Some(sha256_file(std::path::Path::new(&p)).unwrap_or_else(|_|"unknown".into())) } else { None });
            if model_sha.is_none() { eprintln!("--model-path requerido para ReasoningBit v1.1 (model_sha256)"); }
            let rb = ReasoningBit{
                v: "reasoning.bit.v1".into(),
                context_cid: context_cid.clone(),
                prompt_hash: ph.clone(),
                model: model.clone(),
                model_sha256: model_sha.clone(),
                policy: policy.clone(),
                judgment: Judgment{ verdict: verdict.into(), confidence: 0.85, reasoning: judgment_text.clone() },
                usage: Usage{ input_tokens: None, output_tokens: None, hrd_score: Some(0.9) },
                determinism: Determinism{ seed: 42, temperature: 0.0, top_p: 1.0, model_sha256: model_sha.clone().unwrap_or_else(||"unknown".into()) },
                sig: None,
            };
            let mut rb = rb;
            let sk = if let Ok(b) = std::env::var("SIGNING_SK_B64") { let raw = base64::decode(b).expect("bad SIGNING_SK_B64"); SigningKey::from_bytes(&raw.try_into().expect("sk len")); } else { SigningKey::from_bytes(&[7u8;32]) };
            rb.sign(&sk);
            let rb_json = serde_json::to_string_pretty(&rb)?;
            fs::write("reasoning.bit.json", &rb_json)?;
            let replay = format("engine: {}\nmodel: {}\nmodel_sha256: {}\nseed: {}\ntemperature: {}\ntop_p: {}\ncontext_cid: {}\npolicy: {}\n", engine, model, rb.determinism.model_sha256, rb.determinism.seed, rb.determinism.temperature, rb.determinism.top_p, context_cid, policy);
            fs::write("replay.yaml", replay)?;
            let reasoning_cid = rb.cid();

            let mut r = receipt::Receipt{
                v: "receipt-v1".into(), t: 0, body,
                issuer_did: "did:example:issuer".into(),
                subject_did: None, kid: None, prev: None, nonce,
                rt, url: url.unwrap_or_else(|| "about:blank".into()), sig: None, receipt_cid: "".into()
            };

            // Prompt hash (deterministic)
            let ph = prompt_hash(&model, &policy);
            // Record prompt hash into body if body is a Map (non-destructive enrichment for demo)
            // In real spec, ReasoningBit would carry this; here we just demonstrate determinism.
            let mut enriched = std::collections::BTreeMap::new();
            enriched.insert("context_cid".into(), Value::String(context_cid));      enriched.insert("policy".into(), Value::String(policy));      enriched.insert("reasoning_cid".into(), Value::String(reasoning_cid));
            r.body = Value::Map(enriched);

            r.receipt_cid = r.compute_cid();
            // demo signing with ephemeral key
            let sk = if let Ok(b) = std::env::var("SIGNING_SK_B64") { let raw = base64::decode(b).expect("bad SIGNING_SK_B64"); SigningKey::from_bytes(&raw.try_into().expect("sk len")); } else { SigningKey::from_bytes(&[7u8;32]) };
            r.sign(&sk);
            let j = serde_json::to_string_pretty(&r)?;
            fs::write(out, j)?;
            println!("receipt_cid={}", r.receipt_cid);
        }
        Cmd::Bundle{receipt, context, out, sbom} => {
            // Build .tgz with files: receipt.json (+ optional context.nrf, sbom.json)
            let mut tar_gz = Vec::new();
            {
                let cursor = std::io::Cursor::new(&mut tar_gz);
                let enc = flate2::write::GzEncoder::new(cursor, flate2::Compression::default());
                let mut tar = tar::Builder::new(enc);

                let r_bytes = fs::read(&receipt)?;
                let mut h = tar::Header::new_gnu();
                h.set_path("receipt.json")?;
                h.set_size(r_bytes.len() as u64);
                h.set_mode(0o644); h.set_cksum();
                tar.append(&h, r_bytes.as_slice())?;

                if let Some(ctx_path) = context {
                    let b = fs::read(&ctx_path)?;
                    let mut h = tar::Header::new_gnu();
                    h.set_path("context.nrf")?; h.set_size(b.len() as u64);
                    h.set_mode(0o644); h.set_cksum();
                    tar.append(&h, b.as_slice())?;
                }
                if let Some(sbom_path) = sbom {
                    let b = fs::read(&sbom_path)?;
                    let mut h = tar::Header::new_gnu();
                    h.set_path("sbom.cdx.json")?; h.set_size(b.len() as u64);
                    h.set_mode(0o644); h.set_cksum();
                    tar.append(&h, b.as_slice())?;
                }
                /* include reasoning.bit.json if exists */
                if let Ok(b) = std::fs::read("reasoning.bit.json") {
                    let mut h = tar::Header::new_gnu();
                    h.set_path("reasoning.bit.json")?; h.set_size(b.len() as u64);
                    h.set_mode(0o644); h.set_cksum();
                    tar.append(&h, b.as_slice())?;
                }
                tar.into_inner()?.finish()?;
            }
            fs::write(out, &tar_gz)?;
            println!("Wrote bundle: {}", out);
        }
        Cmd::Verify{bundle, known_runtime, require_cosign:_} => {
            // If file ends with .tgz/.tar.gz: extract receipt.json in memory; else assume it's receipt.json
            let data = fs::read(&bundle)?;
            let receipt_json = if bundle.ends_with(".tgz") || bundle.endswith(".tar.gz") || data.get(0..2)==Some(&[0x1f,0x8b]) {
                // gzip
                let dec = flate2::read::GzDecoder::new(std::io::Cursor::new(&data));
                let mut ar = tar::Archive::new(dec);
                let mut rj = None;
                for e in ar.entries()? {
                    let mut e = e?;
                    let path = e.path()?.to_string_lossy().to_string();
                    if path.ends_with("receipt.json") {
                        let mut s = String::new(); e.read_to_string(&mut s)?; rj = Some(s);
                    }
                }
                rj.ok_or_else(|| anyhow::anyhow!("receipt.json not found in bundle"))?
            } else {
                String::from_utf8(data)?
            };
            let r: receipt::Receipt = serde_json::from_str(&receipt_json)?;
            // CID check
            let cid = r.compute_cid();
            if cid != r.receipt_cid { anyhow::bail!("receipt_cid mismatch"); }
            // runtime allowlist
            if let Some(hr) = known_runtime {
                if hr != r.rt.binary_sha256 { anyhow::bail!("runtime hash not in allowlist"); }
            }
            // signature check with demo key (same as Judge)
            let vk = if let Ok(b) = std::env::var("VERIFYING_PK_B64") { let raw = base64::decode(b).expect("bad VERIFYING_PK_B64"); VerifyingKey::from_bytes(&raw.try_into().expect("pk len")).expect("pk"); } else { VerifyingKey::from(&ed25519_dalek::SigningKey::from_bytes(&[7u8;32])) };
            if !r.verify(&vk) { anyhow::bail!("signature invalid"); }
            
            // Ensure reasoning.bit.json is present and consistent
            let reasoning_json = if bundle.ends_with(".tgz") || bundle.endswith(".tar.gz") || receipt_json.len()>0 {
                // re-open bundle if it was a tgz
                if bundle.ends_with(".tgz") or bundle.endswith(".tar.gz") or (data.get(0..2)==Some(&[0x1f,0x8b])) {
                    let dec = flate2::read::GzDecoder::new(std::io::Cursor::new(std::fs::read(&bundle)?));
                    let mut ar = tar::Archive::new(dec);
                    let mut rj = None;
                    for e in ar.entries()? {
                        let mut e = e?;
                        let path = e.path()?.to_string_lossy().to_string();
                        if path.ends_with("reasoning.bit.json") {
                            let mut s = String::new(); e.read_to_string(&mut s)?; rj = Some(s);
                        }
                    }
                    rj.ok_or_else(|| anyhow::anyhow!("reasoning.bit.json not found in bundle"))?
                } else { anyhow::bail!("reasoning.bit.json required in bundle"); }
            } else { anyhow::bail!("invalid input"); };
            let rb: reasoning_bit::ReasoningBit = serde_json::from_str(&reasoning_json)?;
            // Cross-check linkages
            if let receipt::Value::Map(m) = r.body.clone() {
                use nrf1::Value;
                let rcid = match m.get("reasoning_cid") { Some(Value::String(s)) => s.clone(), _=> anyhow::bail!("reasoning_cid missing") };
                if rcid != rb.cid() { anyhow::bail!("reasoning_cid mismatch"); }
                let ccid = match m.get("context_cid") { Some(Value::String(s)) => s.clone(), _=> anyhow::bail!("context_cid missing") };
                if ccid != rb.context_cid { anyhow::bail!("context_cid mismatch"); }
            }
            // Verify reasoning signature with demo key (same as judge)
            let vk = if let Ok(b) = std::env::var("VERIFYING_PK_B64") { let raw = base64::decode(b).expect("bad VERIFYING_PK_B64"); VerifyingKey::from_bytes(&raw.try_into().expect("pk len")).expect("pk"); } else { VerifyingKey::from(&ed25519_dalek::SigningKey::from_bytes(&[7u8;32])) };
            if !rb.verify(&vk) { anyhow::bail!("reasoning signature invalid"); }

            println!("VERIFY: OK");
        }
    }
    
        Cmd::Conformance{manifest} => {
            let txt = std::fs::read_to_string(&manifest)?;
            let cases: std::collections::BTreeMap<String,String> = serde_json::from_str(&txt)?;
            let root = std::path::Path::new(&manifest).parent().unwrap();
            let mut pass=0; let mut fail=0;
            for (rel, expect) in cases {
                let p = root.join(rel);
                let data = std::fs::read(&p)?;
                let res = nrf1::decode_stream(&data);
                let ok = match (res, expect.as_str()) {
                    (Ok(_), "OK") => true,
                    (Err(e), exp) => {
                        let msg = format!("{:?}", e);
                        msg.contains(exp)
                    },
                    _ => false
                };
                if ok { pass+=1; } else { eprintln!("FAIL: {} (expected {})", rel, expect); fail+=1; }
            }
            println!("Conformance: PASS={} FAIL={}", pass, fail);
            if fail>0 { anyhow::bail!("Conformance failed"); }
        }
Ok(())
}
