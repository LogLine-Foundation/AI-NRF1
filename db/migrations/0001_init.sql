
-- App -> Tenant -> User (+membership) + issuer/receipt/bundle
BEGIN;
CREATE TABLE app (
  id UUID PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  display_name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE tenant (
  id UUID PRIMARY KEY,
  app_id UUID NOT NULL REFERENCES app(id),
  slug TEXT NOT NULL,
  display_name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (app_id, slug)
);
CREATE TABLE "user" (
  id UUID PRIMARY KEY,
  app_id UUID NOT NULL REFERENCES app(id),
  external_sub TEXT,
  email TEXT,
  display_name TEXT,
  did TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (app_id, external_sub)
);
CREATE TABLE membership (
  user_id UUID NOT NULL REFERENCES "user"(id),
  tenant_id UUID NOT NULL REFERENCES tenant(id),
  role TEXT NOT NULL,
  PRIMARY KEY (user_id, tenant_id)
);
CREATE TABLE issuer (
  id UUID PRIMARY KEY,
  app_id UUID NOT NULL REFERENCES app(id),
  tenant_id UUID NOT NULL REFERENCES tenant(id),
  did TEXT NOT NULL,
  jwks JSONB NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (tenant_id, did)
);
CREATE TABLE receipt (
  id UUID PRIMARY KEY,
  app_id UUID NOT NULL REFERENCES app(id),
  tenant_id UUID NOT NULL REFERENCES tenant(id),
  issuer_id UUID REFERENCES issuer(id),
  created_by_user_id UUID REFERENCES "user"(id),
  cid TEXT NOT NULL,
  did TEXT NOT NULL,
  url TEXT NOT NULL,
  locators JSONB NOT NULL,
  body JSONB NOT NULL,
  decision TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, cid)
);
CREATE TABLE bundle (
  id UUID PRIMARY KEY,
  app_id UUID NOT NULL REFERENCES app(id),
  tenant_id UUID NOT NULL REFERENCES tenant(id),
  receipt_id UUID NOT NULL REFERENCES receipt(id),
  s3_key TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_receipt_app_tenant_created ON receipt(app_id, tenant_id, created_at);
COMMIT;
