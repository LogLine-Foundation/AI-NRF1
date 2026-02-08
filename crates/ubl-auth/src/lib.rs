
use axum::{async_trait, extract::{FromRequestParts}, http::{request::Parts, HeaderMap, StatusCode}};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCtx {
  pub app: String,
  pub tenant: String,
  pub user_id: Option<String>,
  pub did: Option<String>,
  pub roles: Vec<String>,
}

#[derive(Debug, Error)]
pub enum AuthError {
  #[error("unauthorized")]
  Unauthorized,
  #[error("forbidden")]
  Forbidden,
  #[error("bad header: {0}")]
  BadHeader(&'static str),
  #[error("invalid signature")]
  InvalidSignature,
}

fn header_s(h: &HeaderMap, name: &str) -> Option<String> {
  h.get(name).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

/// Very small PoP: X-DID, X-Signature (base64) over method|path
fn verify_pop(headers: &HeaderMap) -> Result<Option<String>, AuthError> {
  if let (Some(did), Some(sig_b64), Some(pk_b64)) = (
      header_s(headers, "x-did"),
      header_s(headers, "x-signature"),
      header_s(headers, "x-pubkey"),
  ) {
      let method = header_s(headers, "x-method").unwrap_or_else(|| "GET".into());
      let path = header_s(headers, "x-path").ok_or(AuthError::BadHeader("x-path"))?;
      let msg = format!("{}|{}", method, path);

      let pk_bytes = general_purpose::STANDARD
        .decode(pk_b64).map_err(|_| AuthError::InvalidSignature)?;
      let sig_bytes = general_purpose::STANDARD
        .decode(sig_b64).map_err(|_| AuthError::InvalidSignature)?;

      let vk = VerifyingKey::from_bytes(pk_bytes.as_slice().try_into()
        .map_err(|_| AuthError::InvalidSignature)?).map_err(|_| AuthError::InvalidSignature)?;
      let sig = Signature::from_slice(&sig_bytes).map_err(|_| AuthError::InvalidSignature)?;
      vk.verify(msg.as_bytes(), &sig).map_err(|_| AuthError::InvalidSignature)?;
      return Ok(Some(did));
  }
  Ok(None)
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthCtx
where S: Send + Sync
{
  type Rejection = (StatusCode, String);

  async fn from_request_parts(parts: &mut Parts, _state: &S)
    -> Result<Self, Self::Rejection> {
    let headers = &parts.headers;

    let app = parts.extensions.get::<String>()
      .cloned()
      .or_else(|| header_s(headers, "x-app")).unwrap_or_default();
    let tenant = parts.extensions.get::<String>()
      .cloned()
      .or_else(|| header_s(headers, "x-tenant")).unwrap_or_default();

    if app.is_empty() || tenant.is_empty() {
      return Err((StatusCode::UNAUTHORIZED, "missing app/tenant".into()));
    }

    let user = header_s(headers, "x-user-id");
    let roles = header_s(headers, "x-roles").map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
      .unwrap_or_else(|| vec![]);

    match verify_pop(headers) {
      Ok(did) => Ok(AuthCtx { app, tenant, user_id: user, did, roles }),
      Err(e) => {
        warn!("PoP error: {}", e);
        Err((StatusCode::UNAUTHORIZED, e.to_string()))
      }
    }
  }
}

impl AuthCtx {
  pub fn require_any_role(&self, needed: &[&str]) -> Result<(), AuthError> {
    let ok = self.roles.iter().any(|r| needed.iter().any(|n| r == n));
    if ok { Ok(()) } else { Err(AuthError::Forbidden) }
  }
}
