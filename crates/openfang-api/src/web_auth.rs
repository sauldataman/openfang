//! Web authentication module — multi-token, password login, and session management.
//!
//! Adds OpenClaw-style web auth on top of the existing `api_key` mechanism.
//! Supports:
//! - Multiple named API tokens (bearer or X-API-Key)
//! - Password-based login with Argon2 hashing and session cookies
//! - Auto-generation of tokens on first startup
//! - In-memory session store with configurable timeout
//! - Login brute-force protection

use dashmap::DashMap;
use openfang_types::config::{WebAuthConfig, WebAuthMode, WebAuthToken};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Prefix for auto-generated tokens.
const TOKEN_PREFIX: &str = "of-";

/// Session cookie name.
pub const SESSION_COOKIE: &str = "openfang_session";

// ── Session Store ──

/// An active web session (from password login).
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub created_at: Instant,
    pub last_used: Instant,
    pub created_from: String,
    pub timeout: Duration,
}

impl Session {
    pub fn is_expired(&self) -> bool {
        self.last_used.elapsed() > self.timeout
    }
    pub fn touch(&mut self) {
        self.last_used = Instant::now();
    }
}

/// In-memory session store.
#[derive(Debug, Clone)]
pub struct SessionStore {
    sessions: Arc<DashMap<String, Session>>,
    timeout: Duration,
}

impl SessionStore {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    pub fn create_session(&self, remote_ip: &str) -> String {
        let session_id = generate_session_id();
        let session = Session {
            id: session_id.clone(),
            created_at: Instant::now(),
            last_used: Instant::now(),
            created_from: remote_ip.to_string(),
            timeout: self.timeout,
        };
        self.sessions.insert(session_id.clone(), session);
        session_id
    }

    pub fn validate(&self, session_id: &str) -> bool {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            if session.is_expired() {
                drop(session);
                self.sessions.remove(session_id);
                return false;
            }
            session.touch();
            true
        } else {
            false
        }
    }

    pub fn remove(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn active_sessions(&self) -> Vec<SessionInfo> {
        let mut result = Vec::new();
        let mut expired = Vec::new();
        for entry in self.sessions.iter() {
            if entry.value().is_expired() {
                expired.push(entry.key().clone());
            } else {
                result.push(SessionInfo {
                    id_prefix: entry.key()[..8.min(entry.key().len())].to_string(),
                    created_from: entry.value().created_from.clone(),
                    age_secs: entry.value().created_at.elapsed().as_secs(),
                    idle_secs: entry.value().last_used.elapsed().as_secs(),
                });
            }
        }
        for id in expired {
            self.sessions.remove(&id);
        }
        result
    }

    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    pub fn clear_all(&self) -> usize {
        let count = self.sessions.len();
        self.sessions.clear();
        count
    }
}

/// Public session info (for API responses).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionInfo {
    pub id_prefix: String,
    pub created_from: String,
    pub age_secs: u64,
    pub idle_secs: u64,
}

// ── Login Rate Limiter ──

#[derive(Debug, Clone)]
struct LoginAttemptRecord {
    failed_count: u32,
    #[allow(dead_code)]
    first_failure: Instant,
    locked_until: Option<Instant>,
}

/// Tracks failed login attempts per IP for brute-force protection.
#[derive(Debug, Clone)]
pub struct LoginRateLimiter {
    attempts: Arc<DashMap<String, LoginAttemptRecord>>,
    max_attempts: u32,
    lockout_duration: Duration,
}

impl LoginRateLimiter {
    pub fn new(max_attempts: u32, lockout_secs: u64) -> Self {
        Self {
            attempts: Arc::new(DashMap::new()),
            max_attempts,
            lockout_duration: Duration::from_secs(lockout_secs),
        }
    }

    /// Returns remaining lockout seconds if locked, None otherwise.
    pub fn is_locked_out(&self, ip: &str) -> Option<u64> {
        if self.max_attempts == 0 {
            return None;
        }
        if let Some(record) = self.attempts.get(ip) {
            if let Some(locked_until) = record.locked_until {
                if Instant::now() < locked_until {
                    let remaining = locked_until.duration_since(Instant::now());
                    return Some(remaining.as_secs() + 1);
                }
            }
        }
        None
    }

    /// Record failure. Returns true if now locked out.
    pub fn record_failure(&self, ip: &str) -> bool {
        if self.max_attempts == 0 {
            return false;
        }
        let mut entry = self.attempts.entry(ip.to_string()).or_insert(LoginAttemptRecord {
            failed_count: 0,
            first_failure: Instant::now(),
            locked_until: None,
        });
        entry.failed_count += 1;
        if entry.failed_count >= self.max_attempts {
            entry.locked_until = Some(Instant::now() + self.lockout_duration);
            tracing::warn!(ip = %ip, attempts = entry.failed_count, "Login rate limit triggered");
            return true;
        }
        false
    }

    pub fn clear(&self, ip: &str) {
        self.attempts.remove(ip);
    }
}

// ── Token & Password Helpers ──

fn generate_session_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Generate a new API token with the `of-` prefix.
pub fn generate_api_token() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill(&mut bytes);
    format!("{}{}", TOKEN_PREFIX, hex::encode(bytes))
}

/// Hash a password using Argon2id.
pub fn hash_password(password: &str) -> Result<String, String> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Password hashing failed: {e}"))
}

/// Verify a password against an Argon2 hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// SECURITY: Constant-time token comparison to prevent timing attacks.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Check if a request token matches any configured web auth token.
pub fn validate_token(request_token: &str, config: &WebAuthConfig) -> Option<String> {
    for t in &config.tokens {
        if constant_time_eq(request_token, &t.token) {
            return Some(t.name.clone());
        }
    }
    None
}

/// Resolve the effective auth mode considering both `[auth]` config
/// and legacy `api_key` for backwards compatibility.
pub fn effective_auth_mode(config: &WebAuthConfig, legacy_api_key: &str) -> WebAuthMode {
    if config.mode != WebAuthMode::None {
        return config.mode;
    }
    // Backwards compat: if legacy api_key is set, treat as token mode.
    if !legacy_api_key.is_empty() {
        return WebAuthMode::Token;
    }
    WebAuthMode::None
}

/// Auto-generate a token on startup if configured and no tokens exist.
pub fn maybe_auto_generate_token(config: &mut WebAuthConfig) -> Option<WebAuthToken> {
    if !config.auto_generate_token || !config.tokens.is_empty() || config.mode == WebAuthMode::None
    {
        return None;
    }
    let token = generate_api_token();
    let auth_token = WebAuthToken {
        name: "auto-generated".to_string(),
        token: token.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    config.tokens.push(auth_token.clone());
    tracing::info!(
        "Auto-generated API token '{}'. Token: {}",
        auth_token.name,
        mask_token(&token)
    );
    Some(auth_token)
}

/// Mask a token for logging (show first 6 and last 4 chars).
pub fn mask_token(token: &str) -> String {
    if token.len() <= 10 {
        return "***".to_string();
    }
    format!("{}...{}", &token[..6], &token[token.len() - 4..])
}

/// Hash a token with SHA-256 for safe storage.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

// ── Header extraction helpers ──

pub fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

pub fn extract_api_key_header(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers.get("x-api-key").and_then(|v| v.to_str().ok())
}

pub fn extract_query_token(uri: &axum::http::Uri) -> Option<&str> {
    uri.query()
        .and_then(|q| q.split('&').find_map(|pair| pair.strip_prefix("token=")))
}

pub fn extract_session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let cookie = cookie.trim();
                cookie
                    .strip_prefix(&format!("{SESSION_COOKIE}="))
                    .map(|v| v.to_string())
            })
        })
}

/// Extract the real client IP, respecting proxy headers when configured.
pub fn extract_client_ip(
    headers: &axum::http::HeaderMap,
    extensions: &axum::http::Extensions,
    trust_proxy: bool,
) -> std::net::IpAddr {
    if trust_proxy {
        // Cloudflare-specific
        if let Some(ip) = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<std::net::IpAddr>().ok())
        {
            return ip;
        }
        // X-Real-IP
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<std::net::IpAddr>().ok())
        {
            return ip;
        }
        // X-Forwarded-For (first IP)
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.split(',')
                    .next()
                    .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
            })
        {
            return ip;
        }
    }
    extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_token() {
        let token = generate_api_token();
        assert!(token.starts_with("of-"));
        assert_eq!(token.len(), 3 + 48);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("hello", "hello"));
        assert!(!constant_time_eq("hello", "world"));
        assert!(!constant_time_eq("hello", "hell"));
    }

    #[test]
    fn test_password_hash_verify() {
        let hash = hash_password("test-password-123").unwrap();
        assert!(verify_password("test-password-123", &hash));
        assert!(!verify_password("wrong-password", &hash));
    }

    #[test]
    fn test_validate_token() {
        let config = WebAuthConfig {
            mode: WebAuthMode::Token,
            tokens: vec![
                WebAuthToken {
                    name: "test".to_string(),
                    token: "of-abc123".to_string(),
                    created_at: String::new(),
                },
                WebAuthToken {
                    name: "ci".to_string(),
                    token: "of-xyz789".to_string(),
                    created_at: String::new(),
                },
            ],
            ..Default::default()
        };
        assert_eq!(validate_token("of-abc123", &config), Some("test".to_string()));
        assert_eq!(validate_token("of-xyz789", &config), Some("ci".to_string()));
        assert_eq!(validate_token("of-wrong", &config), None);
    }

    #[test]
    fn test_session_store() {
        let store = SessionStore::new(3600);
        let session_id = store.create_session("127.0.0.1");
        assert!(store.validate(&session_id));
        assert!(!store.validate("nonexistent"));
        assert_eq!(store.count(), 1);
        store.remove(&session_id);
        assert!(!store.validate(&session_id));
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_effective_auth_mode() {
        let config = WebAuthConfig::default();
        assert_eq!(effective_auth_mode(&config, ""), WebAuthMode::None);
        assert_eq!(effective_auth_mode(&config, "some-key"), WebAuthMode::Token);
        let config = WebAuthConfig {
            mode: WebAuthMode::Full,
            ..Default::default()
        };
        assert_eq!(effective_auth_mode(&config, ""), WebAuthMode::Full);
    }

    #[test]
    fn test_login_rate_limiter() {
        let limiter = LoginRateLimiter::new(3, 300);
        assert!(limiter.is_locked_out("1.2.3.4").is_none());
        assert!(!limiter.record_failure("1.2.3.4"));
        assert!(!limiter.record_failure("1.2.3.4"));
        assert!(limiter.record_failure("1.2.3.4"));
        assert!(limiter.is_locked_out("1.2.3.4").is_some());
        assert!(limiter.is_locked_out("5.6.7.8").is_none());
        limiter.clear("1.2.3.4");
        assert!(limiter.is_locked_out("1.2.3.4").is_none());
    }

    #[test]
    fn test_login_rate_limiter_disabled() {
        let limiter = LoginRateLimiter::new(0, 300);
        for _ in 0..100 {
            assert!(!limiter.record_failure("1.2.3.4"));
        }
        assert!(limiter.is_locked_out("1.2.3.4").is_none());
    }

    #[test]
    fn test_mask_token() {
        assert_eq!(mask_token("of-abcdef1234567890abcdef"), "of-abc...cdef");
        assert_eq!(mask_token("short"), "***");
    }

    #[test]
    fn test_auto_generate_token() {
        let mut config = WebAuthConfig::default();
        assert!(maybe_auto_generate_token(&mut config).is_none());

        let mut config = WebAuthConfig {
            mode: WebAuthMode::Token,
            auto_generate_token: true,
            ..Default::default()
        };
        let token = maybe_auto_generate_token(&mut config);
        assert!(token.is_some());
        assert_eq!(config.tokens.len(), 1);
        assert!(maybe_auto_generate_token(&mut config).is_none());
    }
}
