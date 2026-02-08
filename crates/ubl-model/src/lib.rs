
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, FromRow};
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Receipt {
  pub id: Uuid,
  pub app_id: uuid::Uuid,
  pub tenant_id: uuid::Uuid,
  pub issuer_id: Option<uuid::Uuid>,
  pub created_by_user_id: Option<uuid::Uuid>,
  pub cid: String,
  pub did: String,
  pub url: String,
  pub locators: serde_json::Value,
  pub body: serde_json::Value,
  pub decision: Option<String>,
  pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiptNew {
  pub app_id: uuid::Uuid,
  pub tenant_id: uuid::Uuid,
  pub issuer_id: Option<uuid::Uuid>,
  pub created_by_user_id: Option<uuid::Uuid>,
  pub cid: String,
  pub did: String,
  pub url: String,
  pub locators: serde_json::Value,
  pub body: serde_json::Value,
  pub decision: Option<String>,
}

pub async fn upsert_receipt(pool: &PgPool, r: ReceiptNew) -> Result<Receipt> {
  let rec = sqlx::query_as::<_, Receipt>(r#"
    INSERT INTO receipt (id, app_id, tenant_id, issuer_id, created_by_user_id, cid, did, url, locators, body, decision)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    ON CONFLICT (tenant_id, cid) DO UPDATE SET
      url = EXCLUDED.url,
      locators = EXCLUDED.locators,
      body = EXCLUDED.body,
      decision = EXCLUDED.decision
    RETURNING *
  "#)
  .bind(Uuid::now_v7())
  .bind(r.app_id)
  .bind(r.tenant_id)
  .bind(r.issuer_id)
  .bind(r.created_by_user_id)
  .bind(r.cid)
  .bind(r.did)
  .bind(r.url)
  .bind(r.locators)
  .bind(r.body)
  .bind(r.decision)
  .fetch_one(pool).await?;
  Ok(rec)
}
