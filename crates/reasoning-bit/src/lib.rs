
use serde::{Serialize, Deserialize};
use nrf1::Value;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature};
use blake3;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Judgment {
    pub verdict: String,          // PASS | FAIL | NEEDS_REVIEW
    pub confidence: f32,          // 0..1
    pub reasoning: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Usage {
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub hrd_score: Option<f32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Determinism { pub seed: i64, pub temperature: f32, pub top_p: f32, pub model_sha256: String }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReasoningBit {
    pub v: String,                // "reasoning.bit.v1"
    pub context_cid: String,      // b3:...
    pub prompt_hash: String,      // sha256(rendered_prompt)
    pub model: String,            // identifier
    pub model_sha256: Option<String>,
    pub policy: String,           // policy ref (e.g., eu-ai-act@1)
    pub judgment: Judgment,
    pub usage: Usage,
    pub determinism: Determinism,
    #[serde(skip_serializing_if="Option::is_none")]
    pub sig: Option<Vec<u8>>,     // wrapper signature (optional here)
}

impl ReasoningBit {
    pub fn sign_bytes(&self) -> Vec<u8> {
        // Canonical NRF bytes of the ReasoningBit (without sig)
        nrf1::encode_stream(&self.to_nrf())
    }
    pub fn sign(&mut self, sk: &SigningKey) {
        let sig = sk.sign(&self.sign_bytes());
        self.sig = Some(sig.to_bytes().to_vec());
    }
    pub fn verify(&self, vk: &VerifyingKey) -> bool {
        if let Some(ref s) = self.sig {
            let sig = Signature::from_bytes(&s[..]).ok();
            if let Some(sig) = sig {
                return vk.verify_strict(&self.sign_bytes(), &sig).is_ok();
            }
        }
        false
    }
    pub fn to_nrf(&self) -> Value {
        use Value::*;
        let mut m = std::collections::BTreeMap::new();
        m.insert("v".into(), String(self.v.clone()));
        m.insert("context_cid".into(), String(self.context_cid.clone()));
        m.insert("prompt_hash".into(), String(self.prompt_hash.clone()));
        m.insert("model".into(), String(self.model.clone()));
        if let Some(ms) = &self.model_sha256 { m.insert("model_sha256".into(), String(ms.clone())); }
        m.insert("policy".into(), String(self.policy.clone()));
        // judgment
        let mut jm = std::collections::BTreeMap::new();
        jm.insert("verdict".into(), String(self.judgment.verdict.clone()));
        jm.insert("confidence".into(), Value::Int((self.judgment.confidence * 1_000_000.0) as i64)); // fixed-point µ
        jm.insert("reasoning".into(), String(self.judgment.reasoning.clone()));
        m.insert("judgment".into(), Map(jm));
        // usage
        let mut um = std::collections::BTreeMap::new();
        if let Some(x)=self.usage.input_tokens { um.insert("input_tokens".into(), Value::Int(x as i64)); }
        if let Some(x)=self.usage.output_tokens { um.insert("output_tokens".into(), Value::Int(x as i64)); }
        if let Some(x)=self.usage.hrd_score { um.insert("hrd_score".into(), Value::Int((x*1_000_000.0) as i64)); }
        m.insert("usage".into(), Map(um));
        Map(m)
    }
    pub fn cid(&self) -> String {
        nrf1::blake3_cid(&self.to_nrf())
    }
}
