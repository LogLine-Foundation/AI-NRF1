
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EvalRequest {
    pub policy_id: String,
    pub context_cid: String,
    pub ubl_json: serde_json::Value, // optional helper view
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EvalResponse {
    pub decision: String, // ALLOW | DENY | REQUIRE
    pub reasoning_hint: Option<String>,
}

pub trait PolicyEngine {
    fn evaluate(&self, req: &EvalRequest) -> anyhow::Result<EvalResponse>;
}
