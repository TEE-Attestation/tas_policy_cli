// TEE Attestation Service Policy Library - Error types
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module defines error types for the tas_policy_lib crate.

use thiserror::Error;

/// Result type for tas_policy_lib operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for tas_policy_lib.
#[derive(Debug, Error)]
pub enum Error {
    #[error("policy already exists: {0}")]
    AlreadyExists(String),

    #[error("policy not found: {0}")]
    NotFound(String),

    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("signing error: {0}")]
    SigningError(String),

    #[error("failed to read key file {path}")]
    KeyFileError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("API error ({status}): {message}")]
    ApiError { status: u16, message: String },

    #[error("configuration error: {0}")]
    Configuration(String),

    #[error("invalid hex: {0}")]
    InvalidHex(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization / deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Non-JSON serialization error (TOML, YAML, etc.).
    #[error("serialization error: {0}")]
    Serialization(String),
}

impl Error {
    /// Convert a ureq transport error into a library error, enriched with URL context.
    ///
    /// This is intentionally *not* a `From<ureq::Error>` impl because we need
    /// the target URL to produce useful diagnostics.
    pub(crate) fn from_ureq(err: ureq::Error, url: &str) -> Self {
        match err {
            ureq::Error::StatusCode(code) => Error::ApiError {
                status: code,
                message: format!("HTTP {code} from {url}"),
            },
            ureq::Error::HostNotFound => {
                let msg = [
                    &format!("DNS lookup failed for {url}"),
                    "",
                    "  \u{2022} check the hostname spelling",
                    "  \u{2022} verify DNS/network connectivity",
                ]
                .join("\n");
                Error::NetworkError(msg)
            }
            ureq::Error::ConnectionFailed => {
                let msg = [
                    &format!("connection to {url} refused"),
                    "",
                    "  \u{2022} is the TAS server running at that address?",
                    "  \u{2022} if the server uses plain HTTP, try --no-tls",
                ]
                .join("\n");
                Error::NetworkError(msg)
            }
            ureq::Error::BadUri(ref s) => Error::NetworkError(format!("invalid URL: {url} ({s})")),
            ureq::Error::Timeout(_) => Error::NetworkError(format!("request to {url} timed out")),
            other => Error::NetworkError(format!("{url}: {other}")),
        }
    }

    /// Whether this error is transient and worth retrying.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::NetworkError(_) => true,
            Error::ApiError { status, .. } => matches!(status, 408 | 429 | 500 | 502 | 503 | 504),
            _ => false,
        }
    }

    /// Convert an HTTP response with an error status into an ApiError.
    ///
    /// Called from the HTTP helpers when `http_status_as_error` is `false`
    /// and the response carries a 4xx/5xx status.
    pub(crate) fn from_http_status(status: u16, body: &str, url: &str) -> Self {
        let message = body.trim().to_string();

        // "Bad request version" — HTTPS client talking to HTTP server.
        if status == 400 && message.to_lowercase().contains("bad request version") {
            return Error::ApiError {
                status,
                message: format!(
                    "{url}: {message} — the server likely expects \
                     plain HTTP, not HTTPS (try --no-tls)"
                ),
            };
        }

        Error::ApiError { status, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Display / error message tests
    // =========================================================================

    #[test]
    fn already_exists_display() {
        let e = Error::AlreadyExists("policy:TDX:key-1".into());
        assert_eq!(e.to_string(), "policy already exists: policy:TDX:key-1");
    }

    #[test]
    fn not_found_display() {
        let e = Error::NotFound("policy:SEV:key-2".into());
        assert_eq!(e.to_string(), "policy not found: policy:SEV:key-2");
    }

    #[test]
    fn api_error_display() {
        let e = Error::ApiError {
            status: 403,
            message: "forbidden".into(),
        };
        assert_eq!(e.to_string(), "API error (403): forbidden");
    }

    // =========================================================================
    // is_retryable tests
    // =========================================================================

    #[test]
    fn network_error_is_retryable() {
        let e = Error::NetworkError("timeout".into());
        assert!(e.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        let e = Error::ApiError {
            status: 500,
            message: "internal".into(),
        };
        assert!(e.is_retryable());
    }

    #[test]
    fn api_502_is_retryable() {
        let e = Error::ApiError {
            status: 502,
            message: "bad gateway".into(),
        };
        assert!(e.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        let e = Error::ApiError {
            status: 503,
            message: "unavailable".into(),
        };
        assert!(e.is_retryable());
    }

    #[test]
    fn api_429_is_retryable() {
        let e = Error::ApiError {
            status: 429,
            message: "rate limit".into(),
        };
        assert!(e.is_retryable());
    }

    #[test]
    fn api_404_not_retryable() {
        let e = Error::ApiError {
            status: 404,
            message: "not found".into(),
        };
        assert!(!e.is_retryable());
    }

    #[test]
    fn api_401_not_retryable() {
        let e = Error::ApiError {
            status: 401,
            message: "unauthorized".into(),
        };
        assert!(!e.is_retryable());
    }

    #[test]
    fn already_exists_not_retryable() {
        let e = Error::AlreadyExists("key".into());
        assert!(!e.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        let e = Error::NotFound("key".into());
        assert!(!e.is_retryable());
    }

    #[test]
    fn signing_error_not_retryable() {
        let e = Error::SigningError("bad key".into());
        assert!(!e.is_retryable());
    }

    // =========================================================================
    // from_http_status tests
    // =========================================================================

    #[test]
    fn from_http_status_normal() {
        let e = Error::from_http_status(404, "not found", "https://host/api");
        match e {
            Error::ApiError { status, message } => {
                assert_eq!(status, 404);
                assert_eq!(message, "not found");
            }
            _ => panic!("expected ApiError"),
        }
    }

    #[test]
    fn from_http_status_bad_request_version_suggests_no_tls() {
        let e = Error::from_http_status(400, "Bad request version", "https://host/api");
        match e {
            Error::ApiError { status, message } => {
                assert_eq!(status, 400);
                assert!(
                    message.contains("--no-tls"),
                    "should suggest --no-tls, got: {message}"
                );
            }
            _ => panic!("expected ApiError"),
        }
    }
}
