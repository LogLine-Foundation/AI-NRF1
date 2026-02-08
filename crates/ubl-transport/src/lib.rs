
use serde::{Serialize, Deserialize};
use blake3::Hasher;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Capsule {
    pub header: CapsuleHeader,
    pub payload: Vec<u8>, // NRF-1.1 or JSON bytes
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CapsuleHeader {
    pub sender_did: String,
    pub content_type: String, // "application/nrf1" | "application/json"
    pub ttl: u32,
    pub created_ns: i128,
}

impl Capsule {
    pub fn cid(&self) -> String {
        let mut h = Hasher::new();
        h.update(&self.payload);
        format!("b3:{}", h.finalize().to_hex())
    }
}
