
use axum::{extract::{State, Path}, routing::post, Json, Router};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::state::AppState;
use crate::middleware::rbac::{AuthCtx, require_any};

#[derive(Deserialize)]
pub struct NewReceiptReq {
    // canonical NRF bytes as hex (produced by CLI), or base64 in real-world
    pub canonical_hex: String,
    pub cid: String,
    pub did: String,
    pub rt: String,        // runtime hash
    pub app: String,       // slug for resolver
    pub tenant: String,    // slug for resolver
}

#[derive(Serialize)]
pub struct NewReceiptResp {
    pub id: Uuid,
    pub url: String,      // rich url with anchors
    pub cid: String,
    pub did: String,
    pub rt: String,
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/receipts", post(create_receipt))
}

pub async fn create_receipt(
    State(state): State<Arc<AppState>>,
    axum::Extension(ctx): axum::Extension<AuthCtx>,
    Json(req): Json<NewReceiptReq>,
) -> Result<Json<NewReceiptResp>, axum::http::StatusCode> {

    if !require_any(&ctx, &["signer","tenant_admin","app_owner"]) {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }

    // decode hex -> bytes
    let bytes = hex::decode(&req.canonical_hex).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

    // persist DB row (id + canonical bytes + cid/did/rt + app/tenant)
    let id = Uuid::new_v4();
    state.db.insert_receipt(id, &bytes, &req.cid, &req.did, &req.rt, &req.app, &req.tenant)
        .await.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    // optional S3 mirror
    let mut public_url_opt = None;
    if let Some(s3) = state.s3.clone() {
        let key = format!("receipts/{id}.json");
        match s3.put_json(&key, &bytes).await {
            Ok(u) => { public_url_opt = Some(u); },
            Err(_) => {} // non-fatal; DB remains source of truth
        }
    }

    // build rich URL (prefer S3 public if exists, else registry URL)
    let base_url = public_url_opt.unwrap_or_else(|| {
        // derive local URL
        format!("{}/apps/{}/tenants/{}/receipts/{}.json",
            state.cfg.public_base.trim_end_matches('/'),
            req.app, req.tenant, id)
    });

    let rich = format!("{base}#cid={}&did={}&rt={}", req.cid, req.did, req.rt, base=base_url);
    // update DB url
    state.db.update_receipt_url(id, &rich).await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(NewReceiptResp { id, url: rich, cid: req.cid, did: req.did, rt: req.rt }))
}
