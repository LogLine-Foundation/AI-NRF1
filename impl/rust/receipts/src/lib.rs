use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostInfo {
    pub budget: u64,
    pub counter: u64,
    pub cost_ms: u64,
    pub window_day: u8, // 0..=6
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub prev_cid: String,          // "b3:<hex>"
    #[serde(default)]
    pub skips: Vec<Option<String>>, // "b3:<hex>" or null
    pub link_hash: String,         // "b3:<hex>"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptV1 {
    pub cid: String,               // "b3:<hex>"
    pub body_cid: String,          // "b3:<hex>"
    pub ts_ns: u128,
    pub signer: String,            // did/kid
    pub claims: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ghost: Option<GhostInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<ChainInfo>,
}

/// Compute a simple link hash (BLAKE3 over concatenated fields in canonical order).
pub fn link_hash(cid: &str, body_cid: &str, prev: Option<&str>, skips: &[Option<String>]) -> String {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(cid.as_bytes());
    h.update(body_cid.as_bytes());
    if let Some(p) = prev { h.update(p.as_bytes()); } else { h.update(b""); }
    for s in skips {
        match s {
            Some(x) => h.update(x.as_bytes()),
            None => h.update(b"\x00"),
        }
    }
    format!("b3:{}", h.finalize().to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn link_hash_stable() {
        let lh = link_hash("b3:aa","b3:bb",Some("b3:cc"),&[None, Some("b3:dd".to_string())]);
        assert!(lh.starts_with("b3:"));
        assert_eq!(lh.len(), 2 + 1 + 64); // "b3:" + 64 hex
    }
}