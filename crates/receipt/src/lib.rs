
use serde::{Serialize, Deserialize};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use nrf1::Value;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuntimeInfo {
    pub name: String,
    pub version: String,
    pub binary_sha256: String,
    #[serde(default)]
    pub env: std::collections::BTreeMap<String,String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Receipt {
    pub v: String,                    // "receipt-v1"
    pub t: i64,                       // nanos
    pub body: Value,                  // any NRF value (encoded when hashing)
    pub issuer_did: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub subject_did: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub prev: Option<String>,
    pub nonce: Vec<u8>,               // 16 bytes
    pub rt: RuntimeInfo,
    pub url: String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub sig: Option<Vec<u8>>,
    pub receipt_cid: String,          // computed over NRF without sig
}

impl Receipt {
    pub fn nrf_without_sig(&self) -> nrf1::Value {
        use nrf1::Value::*;
        // Map with deterministic sorted keys
        let mut m = std::collections::BTreeMap::new();
        m.insert("v".into(), String(self.v.clone()));
        m.insert("t".into(), Int(self.t));
        m.insert("body".into(), self.body.clone());
        m.insert("issuer_did".into(), String(self.issuer_did.clone()));
        if let Some(sd)=&self.subject_did { m.insert("subject_did".into(), String(sd.clone())); }
        if let Some(k)=&self.kid { m.insert("kid".into(), String(k.clone())); }
        if let Some(p)=&self.prev { m.insert("prev".into(), String(p.clone())); }
        m.insert("nonce".into(), nrf1::Value::Bytes(self.nonce.clone()));
        // runtime
        let mut rt = std::collections::BTreeMap::new();
        rt.insert("name".into(), String(self.rt.name.clone()));
        rt.insert("version".into(), String(self.rt.version.clone()));
        rt.insert("binary_sha256".into(), String(self.rt.binary_sha256.clone()));
        if !self.rt.env.is_empty() {
            let mut env_map = std::collections::BTreeMap::new();
            for (k,v) in &self.rt.env {
                env_map.insert(k.clone(), String(v.clone()));
            }
            rt.insert("env".into(), Map(env_map));
        }
        m.insert("rt".into(), Map(rt));
        m.insert("url".into(), String(self.url.clone()));
        // sig deliberately omitted
        Map(m)
    }
    pub fn compute_cid(&self) -> String {
        nrf1::blake3_cid(&self.nrf_without_sig())
    }
    pub fn sign(&mut self, sk: &SigningKey) {
        let bytes = nrf1::encode_stream(&self.nrf_without_sig());
        let digest = blake3::hash(&bytes);
        let sig = sk.sign(digest.as_bytes());
        self.sig = Some(sig.to_bytes().to_vec());
    }
    pub fn verify(&self, vk: &VerifyingKey) -> bool {
        let bytes = nrf1::encode_stream(&self.nrf_without_sig());
        let digest = blake3::hash(&bytes);
        if let Some(sig) = &self.sig {
            let sig = Signature::from_slice(sig).ok();
            if let Some(s) = sig {
                return vk.verify(digest.as_bytes(), &s).is_ok();
            }
        }
        false
    }
}
