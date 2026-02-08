
use ai_nrf1_receipts::{Receipt, RuntimeMeta, Decision};
use ai_nrf1_core::hash::b3_hex;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run_judge(context_bytes: &[u8], policy_ref: &str, allow: bool) -> Receipt {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as i64;
    let inputs_cid = b3_hex(context_bytes);
    let rt = RuntimeMeta { binary_sha256: "deadbeef".repeat(8), hal_ref: "hal:v1/cpu-guard".into() };
    let pre = Receipt::pre("receipt-v1".into(), t, "did:ubl:demo".into(), "EVALUATE".into(), "cid:blake3:subject".into(), inputs_cid, rt, None);

    if allow {
        pre.finalize_allow(json!({"decision":"ok","notes":"demo"}))
    } else {
        pre.finalize_ghost()
    }
}
