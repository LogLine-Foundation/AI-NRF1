
use axum::http::Request;
use axum::response::Response;
use axum::middleware::Next;
use axum::extract::State;
use tower::Layer;
use uuid::Uuid;
use std::sync::Arc;

use crate::state::AppState;

// Simple role set
#[derive(Clone, Debug)]
pub struct AuthCtx {
    pub user_id: Uuid,
    pub roles: Vec<String>,
}

pub async fn rbac_middleware<B>(State(state): State<Arc<AppState>>, mut req: Request<B>, next: Next<B>) -> Result<Response, axum::http::StatusCode> {
    let Some(user_id_hdr) = req.headers().get("x-user-id") else {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    };
    let Ok(user_id) = user_id_hdr.to_str().ok().and_then(|s| Uuid::parse_str(s).ok()) else {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    };

    // Resolve app/tenant from request extensions set by slug resolver
    let (app_id, tenant_id) = {
        let ext = req.extensions();
        let Some(app) = ext.get::<Uuid>() else { return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR); };
        let Some(tenant) = ext.get::<(String, Uuid)>().map(|t| t.1) else { return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR); };
        (*app, tenant)
    };

    // Query DB for membership roles
    let roles = match state.db.fetch_membership_roles(user_id, tenant_id).await {
        Ok(rs) => rs,
        Err(_) => return Err(axum::http::StatusCode::UNAUTHORIZED),
    };

    req.extensions_mut().insert(AuthCtx { user_id, roles });
    Ok(next.run(req).await)
}

// Helper guard
pub fn require_any<'a>(ctx: &'a AuthCtx, allowed: &[&str]) -> bool {
    for a in allowed {
        if ctx.roles.iter().any(|r| r == a) {
            return true;
        }
    }
    false
}
