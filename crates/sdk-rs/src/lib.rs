
use nrf1::Value;
pub fn canon_json_strict(s: &str) -> anyhow::Result<Vec<u8>> {
    // Strict minimal: parse via serde_json (loses ordering); for BASE we map deterministically.
    let v: serde_json::Value = serde_json::from_str(s)?;
    let nv = to_nrf(&v)?;
    Ok(nrf1::encode_stream(&nv))
}
pub fn cid_from_json(s: &str) -> anyhow::Result<String> {
    let v: serde_json::Value = serde_json::from_str(s)?;
    let nv = to_nrf(&v)?;
    Ok(nrf1::blake3_cid(&nv))
}
pub fn to_nrf(v: &serde_json::Value) -> anyhow::Result<Value> {
    Ok(match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            // BASE: accept integers only; reject floats.
            if let Some(i) = n.as_i64() { Value::Int(i) }
            else { anyhow::bail!("floats not allowed"); }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(xs) => {
            Value::Array(xs.iter().map(|x| to_nrf(x)).collect::<anyhow::Result<Vec<_>>>()?)
        }
        serde_json::Value::Object(m) => {
            let mut bm = std::collections::BTreeMap::new();
            // BTreeMap ensures key order by UTF-8 bytes (serde gives valid UTF-8 keys)
            for (k,v) in m.iter() {
                bm.insert(k.clone(), to_nrf(v)?);
            }
            Value::Map(bm)
        }
    })
}
pub mod fxp {
    pub fn to_fixed(value: f64, scale: u32) -> i64 {
        let m = 10f64.powi(scale as i32);
        (value * m).round() as i64
    }
}
