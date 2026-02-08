
use axum::{routing::{get, post}, Router, extract::{Path, State}, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use sqlx::{PgPool};
use ubl_auth::AuthCtx;
use ubl_model::{ReceiptNew, upsert_receipt};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
  pool: PgPool,
  cdn_base: String,
}

#[derive(Serialize)]
struct Health { status: &'static str }

#[derive(Serialize, Deserialize)]
struct ReceiptIngest {
    cid: String,
    did: String,
    locators: serde_json::Value,
    body: serde_json::Value,
    decision: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ReceiptOut {
    id: uuid::Uuid,
    cid: String,
    did: String,
    url: String,
    decision: Option<String>,
    created_at: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "registry=info,axum=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let pool = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    let cdn_base = std::env::var("CDN_BASE").unwrap_or_else(|_| "https://passports.ubl.agency".into());
    let state = Arc::new(AppState { pool, cdn_base });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/:app/:tenant/receipts", post(receipts_post))
        .route("/v1/:app/:tenant/receipts/:id", get(receipts_get))
        .route("/v1/:app/:tenant/receipts/by-cid/:cid", get(receipts_get_by_cid))
        .route("/v1/:app/:tenant/keys/:did", get(keys_get))
        .with_state(state);

    let addr = "0.0.0.0:8080";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

// POST /v1/{app}/{tenant}/receipts
async fn receipts_post(
    Path((app, tenant)): Path<(String, String)>,
    State(st): State<Arc<AppState>>,
    auth: AuthCtx,
    Json(input): Json<ReceiptIngest>,
) -> Result<Json<ReceiptOut>, (axum::http::StatusCode, String)> {
    // RBAC mínimo: precisa de role signer/tenant_admin/app_owner
    auth.require_any_role(&["signer","tenant_admin","app_owner"]).map_err(|e| (axum::http::StatusCode::FORBIDDEN, e.to_string()))?;


// Resolver slugs -> UUIDs
let app_id: Uuid = sqlx::query_scalar("SELECT id FROM app WHERE slug = $1")
    .bind(&app)
    .fetch_optional(&st.pool).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((axum::http::StatusCode::NOT_FOUND, format!("app '{}' not found", app)))?;

let tenant_id: Uuid = sqlx::query_scalar("SELECT id FROM tenant WHERE app_id = $1 AND slug = $2")
    .bind(app_id)
    .bind(&tenant)
    .fetch_optional(&st.pool).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((axum::http::StatusCode::NOT_FOUND, format!("tenant '{}/{}' not found", app, tenant)))?;

// Enforce RBAC via membership (if user present)
if let Some(user_str) = auth.user_id.as_ref() {
    // allow UUIDv4/7, else reject
    let user_id = Uuid::parse_str(user_str).map_err(|_| (axum::http::StatusCode::UNAUTHORIZED, "x-user-id must be UUID".into()))?;
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM membership WHERE user_id = $1 AND tenant_id = $2")
        .bind(user_id).bind(tenant_id)
        .fetch_optional(&st.pool).await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let role_ok = role.as_deref().map(|r| matches!(r, "signer" | "tenant_admin" | "app_owner")).unwrap_or(false);
    if !role_ok {
        return Err((axum::http::StatusCode::FORBIDDEN, "membership role insufficient".into()));
    }
} else {
    return Err((axum::http::StatusCode::UNAUTHORIZED, "missing x-user-id".into()));
}

    let receipt_id = Uuid::now_v7();
    let url = format!("{}/{}/{}/receipts/{}.json", st.cdn_base, app, tenant, receipt_id);

    let rec_new = ReceiptNew {
        app_id,
        tenant_id,
        issuer_id: None,
        created_by_user_id: auth.user_id.as_ref().and_then(|_| Some(Uuid::new_v4())),
        cid: input.cid,
        did: input.did,
        url: url.clone(),
        locators: input.locators,
        body: input.body,
        decision: input.decision.clone(),
    };

    let rec = upsert_receipt(&st.pool, rec_new).await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let out = ReceiptOut {
        id: rec.id,
        cid: rec.cid,
        did: rec.did,
        url,
        decision: rec.decision,
        created_at: rec.created_at.to_rfc3339(),
    };
    Ok(Json(out))
}

// GET /v1/{app}/{tenant}/receipts/:id

async fn receipts_get(
    Path((app, tenant, id)): Path<(String, String, String)>,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let app_id: Uuid = sqlx::query_scalar("SELECT id FROM app WHERE slug = $1")
        .bind(&app).fetch_one(&st.pool).await
        .map_err(|e| (axum::http::StatusCode::NOT_FOUND, e.to_string()))?;
    let tenant_id: Uuid = sqlx::query_scalar("SELECT id FROM tenant WHERE app_id = $1 AND slug = $2")
        .bind(app_id).bind(&tenant).fetch_one(&st.pool).await
        .map_err(|e| (axum::http::StatusCode::NOT_FOUND, e.to_string()))?;
    let rid = Uuid::parse_str(&id).map_err(|_| (axum::http::StatusCode::BAD_REQUEST, "invalid id".into()))?;
    let row = sqlx::query_as::<_, (String, String, String, serde_json::Value, Option<String>)>(
        "SELECT cid, did, url, body, decision FROM receipt WHERE id = $1 AND tenant_id = $2")
        .bind(rid).bind(tenant_id).fetch_optional(&st.pool).await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some((cid, did, url, body, decision)) = row {
        Ok(Json(serde_json::json!({ "id": id, "cid": cid, "did": did, "url": url, "body": body, "decision": decision })))
    } else {
        Err((axum::http::StatusCode::NOT_FOUND, "not found".into()))
    }
}

// GET /v1/{app}/{tenant}/receipts/by-cid/:cid

async fn receipts_get_by_cid(
    Path((app, tenant, cid)): Path<(String, String, String)>,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let app_id: Uuid = sqlx::query_scalar("SELECT id FROM app WHERE slug = $1")
        .bind(&app).fetch_one(&st.pool).await
        .map_err(|e| (axum::http::StatusCode::NOT_FOUND, e.to_string()))?;
    let tenant_id: Uuid = sqlx::query_scalar("SELECT id FROM tenant WHERE app_id = $1 AND slug = $2")
        .bind(app_id).bind(&tenant).fetch_one(&st.pool).await
        .map_err(|e| (axum::http::StatusCode::NOT_FOUND, e.to_string()))?;
    let row = sqlx::query_as::<_, (uuid::Uuid, String, String, String, serde_json::Value, Option<String>)>(
        "SELECT id, cid, did, url, body, decision FROM receipt WHERE tenant_id = $1 AND cid = $2")
        .bind(tenant_id).bind(&cid).fetch_optional(&st.pool).await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some((id, cid, did, url, body, decision)) = row {
        Ok(Json(serde_json::json!({ "id": id, "cid": cid, "did": did, "url": url, "body": body, "decision": decision })))
    } else {
        Err((axum::http::StatusCode::NOT_FOUND, "not found".into()))
    }
}

// GET /v1/{app}/{tenant}/keys/:did

async fn keys_get(
    Path((app, tenant, did)): Path<(String, String, String)>,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let app_id: Uuid = sqlx::query_scalar("SELECT id FROM app WHERE slug = $1")
        .bind(&app).fetch_one(&st.pool).await
        .map_err(|e| (axum::http::StatusCode::NOT_FOUND, e.to_string()))?;
    let tenant_id: Uuid = sqlx::query_scalar("SELECT id FROM tenant WHERE app_id = $1 AND slug = $2")
        .bind(app_id).bind(&tenant).fetch_one(&st.pool).await
        .map_err(|e| (axum::http::StatusCode::NOT_FOUND, e.to_string()))?;
    let jwks: Option<serde_json::Value> = sqlx::query_scalar("SELECT jwks FROM issuer WHERE tenant_id = $1 AND did = $2 AND active = TRUE")
        .bind(tenant_id).bind(&did).fetch_optional(&st.pool).await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some(j) = jwks {
        Ok(Json(serde_json::json!({ "did": did, "jwks": j })))
    } else {
        Err((axum::http::StatusCode::NOT_FOUND, "issuer not found".into()))
    }
}
