//! Production middleware for the OpenFang API server.
//!
//! Provides:
//! - Request ID generation and propagation
//! - Per-endpoint structured request logging
//! - Multi-method authentication (legacy api_key + new web auth tokens/sessions)
//! - Security headers

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

use crate::web_auth::{self, SessionStore};
use openfang_types::config::{WebAuthConfig, WebAuthMode};

/// Request ID header name (standard).
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Shared auth state passed to the middleware.
#[derive(Clone)]
pub struct AuthState {
    /// New multi-method auth configuration.
    pub auth_config: WebAuthConfig,
    /// Legacy single api_key (for backwards compatibility).
    pub legacy_api_key: String,
    /// Session store for password-based login.
    pub session_store: Arc<SessionStore>,
}

/// Middleware: inject a unique request ID and log the request/response.
pub async fn request_logging(request: Request<Body>, next: Next) -> Response<Body> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let method = request.method().clone();
    let uri = request.uri().path().to_string();
    let start = Instant::now();

    let mut response = next.run(request).await;

    let elapsed = start.elapsed();
    let status = response.status().as_u16();

    info!(
        request_id = %request_id,
        method = %method,
        path = %uri,
        status = status,
        latency_ms = elapsed.as_millis() as u64,
        "API request"
    );

    // Inject the request ID into the response
    if let Ok(header_val) = request_id.parse() {
        response.headers_mut().insert(REQUEST_ID_HEADER, header_val);
    }

    response
}

/// Endpoints that never require authentication.
fn is_always_public(path: &str) -> bool {
    path == "/logo.png"
        || path == "/favicon.ico"
        || path == "/.well-known/agent.json"
        || path == "/api/health"
        || path == "/api/version"
        // Auth endpoints must be public so users can log in
        || path == "/api/auth/login"
        || path == "/api/auth/status"
        || path == "/api/auth/mode"
}

/// Endpoints public when dashboard protection is disabled.
fn is_dashboard_public(path: &str) -> bool {
    path == "/"
        || path == "/api/health/detail"
        || path == "/api/status"
        || path == "/api/agents"
        || path == "/api/profiles"
        || path == "/api/config"
        || path.starts_with("/api/uploads/")
        || path == "/api/models"
        || path == "/api/models/aliases"
        || path == "/api/providers"
        || path == "/api/budget"
        || path == "/api/budget/agents"
        || path.starts_with("/api/budget/agents/")
        || path == "/api/network/status"
        || path == "/api/a2a/agents"
        || path == "/api/approvals"
        || path.starts_with("/api/approvals/")
        || path == "/api/channels"
        || path == "/api/hands"
        || path == "/api/hands/active"
        || path.starts_with("/api/hands/")
        || path == "/api/skills"
        || path == "/api/sessions"
        || path == "/api/integrations"
        || path == "/api/integrations/available"
        || path == "/api/integrations/health"
        || path == "/api/workflows"
        || path == "/api/logs/stream"
        || path.starts_with("/api/cron/")
        || path.starts_with("/api/providers/github-copilot/oauth/")
}

/// A2A protocol endpoints are always public (they have their own auth).
fn is_a2a_endpoint(path: &str) -> bool {
    path.starts_with("/a2a/")
}

/// Multi-method authentication middleware.
///
/// Supports (in order of priority):
/// 1. Legacy `api_key` from config (Bearer header, X-API-Key, ?token=)
/// 2. New multi-token auth (from [auth] config section)
/// 3. Session cookies (from password login)
/// 4. Localhost-only fallback when no auth is configured
pub async fn auth(
    axum::extract::State(state): axum::extract::State<AuthState>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let effective_mode =
        web_auth::effective_auth_mode(&state.auth_config, &state.legacy_api_key);

    // Mode::None (no [auth] config and no legacy api_key) → loopback only.
    if effective_mode == WebAuthMode::None {
        let client_ip = web_auth::extract_client_ip(
            request.headers(),
            request.extensions(),
            state.auth_config.trust_proxy_headers,
        );

        if !client_ip.is_loopback() {
            tracing::warn!(
                client_ip = %client_ip,
                "Rejected non-localhost request: no auth configured. \
                 Set api_key or [auth] mode in config.toml for remote access."
            );
            return json_error(
                StatusCode::FORBIDDEN,
                "No authentication configured. Remote access denied. \
                 Configure api_key or [auth] section in ~/.openfang/config.toml",
            );
        }
        return next.run(request).await;
    }

    // Always-public endpoints
    let path = request.uri().path();
    if is_always_public(path) || is_a2a_endpoint(path) {
        return next.run(request).await;
    }

    // Dashboard-public endpoints (when protect_dashboard is false)
    if !state.auth_config.protect_dashboard && is_dashboard_public(path) {
        return next.run(request).await;
    }

    // --- Attempt authentication ---

    // 1. Check session cookie (from password login)
    if let Some(session_id) = web_auth::extract_session_cookie(request.headers()) {
        if state.session_store.validate(&session_id) {
            return next.run(request).await;
        }
    }

    // 2. Extract token from headers or query parameter
    let token = web_auth::extract_bearer_token(request.headers())
        .or_else(|| web_auth::extract_api_key_header(request.headers()))
        .or_else(|| web_auth::extract_query_token(request.uri()));

    if let Some(token) = token {
        // 2a. Check against legacy api_key (backwards compatible — existing behavior)
        if !state.legacy_api_key.is_empty() && web_auth::constant_time_eq(token, &state.legacy_api_key) {
            return next.run(request).await;
        }

        // 2b. Check against new multi-token config
        if web_auth::validate_token(token, &state.auth_config).is_some() {
            return next.run(request).await;
        }

        // Token was provided but invalid
        return json_error(StatusCode::UNAUTHORIZED, "Invalid API token");
    }

    // No credentials provided
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("www-authenticate", "Bearer")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "error": "Authentication required. Provide Authorization: Bearer <token> header, or log in with password.",
                "auth_mode": effective_mode.to_string()
            })
            .to_string(),
        ))
        .unwrap_or_default()
}

/// Helper to build a JSON error response.
fn json_error(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"error": message}).to_string(),
        ))
        .unwrap_or_default()
}

/// Security headers middleware — applied to ALL API responses.
pub async fn security_headers(request: Request<Body>, next: Next) -> Response<Body> {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("x-xss-protection", "1; mode=block".parse().unwrap());
    headers.insert(
        "content-security-policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' ws://localhost:* ws://127.0.0.1:* wss://localhost:* wss://127.0.0.1:*; font-src 'self' https://fonts.gstatic.com; media-src 'self' blob:; frame-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'self'"
            .parse()
            .unwrap(),
    );
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "cache-control",
        "no-store, no-cache, must-revalidate".parse().unwrap(),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_id_header_constant() {
        assert_eq!(REQUEST_ID_HEADER, "x-request-id");
    }

    #[test]
    fn test_always_public_endpoints() {
        assert!(is_always_public("/api/health"));
        assert!(is_always_public("/api/version"));
        assert!(is_always_public("/api/auth/login"));
        assert!(!is_always_public("/api/agents"));
    }

    #[test]
    fn test_a2a_endpoints() {
        assert!(is_a2a_endpoint("/a2a/tasks/send"));
        assert!(!is_a2a_endpoint("/api/a2a/agents"));
    }
}
