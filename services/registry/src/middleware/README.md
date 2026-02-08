// RBAC middleware is applied in router build:
// .route_layer(axum::middleware::from_fn_with_state(state.clone(), rbac::rbac_middleware))
