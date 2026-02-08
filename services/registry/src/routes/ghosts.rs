
use axum::{routing::post, Router, extract::{State, Path}, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::state::AppState;
use crate::middleware::rbac::{AuthCtx, require_any};

#[derive(Deserialize)]
pub struct NewGhostReq {
    pub canonical_hex: String,
    pub cid: String,
    pub did: String,
    pub rt: String,
    pub app: String,
    pub tenant: String,
}

#[derive(Serialize)]
pub struct NewGhostResp {
    pub id: Uuid,
    pub url: String,
    pub cid: String,
    pub did: String,
    pub rt: String,
}

#[derive(Deserialize)]
pub struct PromoteReq {
    pub receipt_id: String, // final receipt UUID (string) or external ref
}

#[derive(Deserialize)]
pub struct ExpireReq {
    pub cause: String, // timeout | canceled | drift
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ghosts", post(create_ghost))
        .route("/ghosts/:id/promote", post(promote_ghost))
        .route("/ghosts/:id/expire", post(expire_ghost))
}

pub async fn create_ghost(
    State(state): State<Arc<AppState>>,
    axum::Extension(ctx): axum::Extension<AuthCtx>,
    Json(req): Json<NewGhostReq>,
) -> Result<Json<NewGhostResp>, axum::http::StatusCode> {
    if !require_any(&ctx, &["signer","tenant_admin","app_owner"]) {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }
    let bytes = hex::decode(&req.canonical_hex).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    let id = Uuid::new_v4();
    state.db.insert_ghost(id, &bytes, &req.cid, &req.did, &req.rt, &req.app, &req.tenant)
        .await.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    // optional S3 mirror
    let mut public_url_opt = None;
    if let Some(s3) = state.s3.clone() {
        let key = format!("ghosts/{id}.json");
        if let Ok(u) = s3.put_json(&key, &bytes).await {
            public_url_opt = Some(u);
        }
    }
    let base = public_url_opt.unwrap_or_else(|| {
        format!("{}/apps/{}/tenants/{}/ghosts/{}.json",
            state.cfg.public_base.trim_end_matches('/'),
            req.app, req.tenant, id)
    });
    let rich = format!("{base}#cid={}&did={}&rt={}", req.cid, req.did, req.rt);
    state.db.update_ghost_url(id, &rich).await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(NewGhostResp{ id, url: rich, cid: req.cid, did: req.did, rt: req.rt }))
}

pub async fn promote_ghost(
    State(state): State<Arc<AppState>>,
    axum::Extension(ctx): axum::Extension<AuthCtx>,
    Path(id): Path<Uuid>,
    Json(req): Json<PromoteReq>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    if !require_any(&ctx, &["signer","tenant_admin","app_owner"]) {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }
    state.db.mark_ghost_promoted(id, &req.receipt_id)
        .await.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"ok":true,"ghost_id":id,"receipt_id":req.receipt_id})))
}

pub async fn expire_ghost(
    State(state): State<Arc<AppState>>,
    axum::Extension(ctx): axum::Extension<AuthCtx>,
    Path(id): Path<Uuid>,
    Json(req): Json<ExpireReq>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    if !require_any(&ctx, &["signer","tenant_admin","app_owner"]) {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }
    state.db.mark_ghost_expired(id, &req.cause)
        .await.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"ok":true,"ghost_id":id,"cause":req.cause})))
}
