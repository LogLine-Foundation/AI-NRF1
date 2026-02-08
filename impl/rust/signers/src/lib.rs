
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum SignerKind {
    Local,
    Http,
    Cloudflare,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest<'a> {
    /// hex-encoded sha256 digest (32 bytes)
    pub sha256_hex: &'a str,
    /// optional key id / label
    pub kid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    /// base64 of raw Ed25519 signature (64 bytes)
    pub sig_b64: String,
}

pub trait Signer {
    fn sign(&self, sha256_hex: &str) -> Result<Vec<u8>>;
}

/// Local Ed25519 signer from PKCS#8-encoded private key bytes
pub struct LocalEd25519Signer {
    key: ed25519_dalek::SigningKey,
}

impl LocalEd25519Signer {
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let key = ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| anyhow!("pkcs8 parse: {e}"))?;
        Ok(Self { key })
    }
    pub fn public_key_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.key.verifying_key().to_bytes())
    }
}

impl Signer for LocalEd25519Signer {
    fn sign(&self, sha256_hex: &str) -> Result<Vec<u8>> {
        let bytes = hex::decode(sha256_hex)?;
        if bytes.len() != 32 { return Err(anyhow!("sha256 digest must be 32 bytes")); }
        Ok(self.key.sign(&bytes).to_bytes().to_vec())
    }
}

/// Generic HTTP signer (POST endpoint) with JSON request/response
pub struct HttpSigner {
    pub endpoint: String,
    pub kid: Option<String>,
    pub auth_header: Option<String>,
}

impl Signer for HttpSigner {
    fn sign(&self, sha256_hex: &str) -> Result<Vec<u8>> {
        let client = reqwest::blocking::Client::new();
        let req = SignRequest { sha256_hex, kid: self.kid.clone() };
        let mut rb = client.post(&self.endpoint).json(&req);
        if let Some(h) = &self.auth_header {
            rb = rb.header("Authorization", h);
        }
        let resp = rb.send()?;
        if !resp.status().is_success() {
            return Err(anyhow!("signer http status {}", resp.status()));
        }
        let sr: SignResponse = resp.json()?;
        let sig = base64::engine::general_purpose::STANDARD.decode(sr.sig_b64)?;
        if sig.len() != 64 { return Err(anyhow!("expected 64-byte ed25519 signature")); }
        Ok(sig)
    }
}

/// Cloudflare Workers convenience alias (same as HttpSigner)
pub type CloudflareSigner = HttpSigner;
