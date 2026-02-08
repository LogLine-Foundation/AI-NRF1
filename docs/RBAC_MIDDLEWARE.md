
# RBAC Middleware (Registry)

Centralizes membership role resolution:
- Extracts `x-user-id` (UUID)
- Resolves `app/tenant` from slug resolver
- Loads roles from `membership` and attaches `AuthCtx` into request extensions
- Route handlers then call `require_any(&ctx, &["signer","tenant_admin","app_owner"])`

This replaces the per-route RBAC checks.
