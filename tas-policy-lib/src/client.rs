// TEE Attestation Service Policy Library - TAS API client
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides TAS API client for policy operations

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::policy::Policy;
use crate::policy::signed::{PolicySignature, SignedPolicyEnvelope};
use crate::signing::{SigningKey, sign_envelope};
//use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};

/// Base path for the TAS management policy API.
const POLICY_API_BASE: &str = "/management/policy/v0";

/// TAS API client for policy operations.
pub struct TasClient {
    host: String,
    port: u16,
    api_key: String,
    tls_enabled: bool,
    agent: ureq::Agent,
    max_retries: u32,
    initial_backoff: Duration,
}

impl TasClient {
    /// Create a new client builder.
    pub fn builder() -> TasClientBuilder {
        TasClientBuilder::new()
    }

    // =========================================================================
    // HTTP helpers (private)
    // =========================================================================

    /// Build the full URL for a TAS API endpoint path.
    fn url(&self, path: &str) -> String {
        let scheme = if self.tls_enabled { "https" } else { "http" };
        format!("{scheme}://{}:{}{}", self.host, self.port, path)
    }

    /// Execute a closure with exponential backoff retry on transient errors.
    fn with_retry<F, T>(&self, op: F) -> Result<T>
    where
        F: FnMut() -> Result<T>,
    {
        retry_with_backoff(self.max_retries, self.initial_backoff, op)
    }

    /// Send a POST request with a JSON body to the given API path.
    fn post<T: serde::Serialize>(&self, path: &str, body: &T) -> Result<(String, DeprecationInfo)> {
        let url = self.url(path);
        self.with_retry(|| {
            let mut resp = self
                .agent
                .post(&url)
                .header("X-MANAGEMENT-API-KEY", &self.api_key)
                .send_json(body)
                .map_err(|e| Error::from_ureq(e, &url))?;
            let status = resp.status().as_u16();
            let text = resp
                .body_mut()
                .read_to_string()
                .map_err(|e| Error::from_ureq(e, &url))?;
            if status >= 400 {
                return Err(Error::from_http_status(status, &text, &url));
            }
            let deprecation = extract_deprecation(&resp);
            Ok((text, deprecation))
        })
    }

    /// Send a GET request to the given API path.
    fn get(&self, path: &str) -> Result<(String, DeprecationInfo)> {
        let url = self.url(path);
        self.with_retry(|| {
            let mut resp = self
                .agent
                .get(&url)
                .header("X-MANAGEMENT-API-KEY", &self.api_key)
                .call()
                .map_err(|e| Error::from_ureq(e, &url))?;
            let status = resp.status().as_u16();
            let text = resp
                .body_mut()
                .read_to_string()
                .map_err(|e| Error::from_ureq(e, &url))?;
            if status >= 400 {
                return Err(Error::from_http_status(status, &text, &url));
            }
            let deprecation = extract_deprecation(&resp);
            Ok((text, deprecation))
        })
    }

    /// Send a DELETE request to the given API path.
    fn delete_request(&self, path: &str) -> Result<(String, DeprecationInfo)> {
        let url = self.url(path);
        self.with_retry(|| {
            let mut resp = self
                .agent
                .delete(&url)
                .header("X-MANAGEMENT-API-KEY", &self.api_key)
                .call()
                .map_err(|e| Error::from_ureq(e, &url))?;
            let status = resp.status().as_u16();
            let text = resp
                .body_mut()
                .read_to_string()
                .map_err(|e| Error::from_ureq(e, &url))?;
            if status >= 400 {
                return Err(Error::from_http_status(status, &text, &url));
            }
            let deprecation = extract_deprecation(&resp);
            Ok((text, deprecation))
        })
    }

    /// Build a signed policy envelope from a Policy (internal helper).
    fn build_envelope(policy: &Policy) -> Result<SignedPolicyEnvelope> {
        let envelope = match policy {
            Policy::Tdx(tdx) => SignedPolicyEnvelope::from_tdx(tdx, PolicySignature::placeholder()),
            Policy::Sev(sev) => SignedPolicyEnvelope::from_sev(sev, PolicySignature::placeholder()),
        };
        Ok(envelope)
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /// Create and upload a new policy.
    ///
    /// Builds the signed envelope (RSA-SHA384-PSS over canonical validation_rules),
    /// then POSTs it to `POST /management/policy/v0/store`.
    /// Returns `Error::AlreadyExists` if a policy with the same key already exists on the server.
    ///
    /// # Upcoming Tasks
    /// * Investigate if CIPHERTEXT_HIDING_DRAM can be set to true for SEV, whne Ubuntu 26.04 arrives, and update the SEV policy builder accordingly.
    /// * Investigate  if RAPL_DIS can be set by default to true for SEV.
    pub fn create_policy<P: Into<Policy>>(
        &self,
        policy: P,
        signing_key: &SigningKey,
    ) -> Result<ApiResponse<CreateResult>> {
        let policy = policy.into();

        let mut envelope = Self::build_envelope(&policy)?;
        sign_envelope(signing_key, &mut envelope)?;

        let policy_key = format!("policy:{}:{}", policy.cvm_type(), policy.key_id());
        let (_body, deprecation) = self
            .post(&format!("{}/store", POLICY_API_BASE), &envelope)
            .map_err(|e| match e {
                Error::ApiError { status: 409, .. } => Error::AlreadyExists(policy_key.clone()),
                other => other,
            })?;

        Ok(ApiResponse::new(
            CreateResult {
                policy_key: format!(
                    "policy:{}:{}",
                    envelope.metadata.policy_type,
                    envelope.metadata.key_id
                ),
                cvm_type: policy.cvm_type(),
            },
            Some(deprecation),
        ))
    }

    /// Delete a policy by key.
    ///
    /// Sends `DELETE /management/policy/v0/delete/{policy_key}`.
    /// Returns `Error::NotFound` if the policy does not exist on the server.
    pub fn delete_policy(&self, policy_key: &str) -> Result<ApiResponse<()>> {
        let path = format!("{}/delete/{}", POLICY_API_BASE, policy_key);
        let (_body, deprecation) = self.delete_request(&path).map_err(|e| match e {
            Error::ApiError { status: 404, .. } => {
                Error::NotFound(format!("policy '{}' does not exist", policy_key))
            }
            other => other,
        })?;
        Ok(ApiResponse::new((), Some(deprecation)))
    }

    /// List all policies, optionally filtered.
    ///
    /// Sends `GET /management/policy/v0/list`. The API returns all policies;
    /// client-side filtering is applied when a `ListFilter` is provided.
    pub fn list_policies(
        &self,
        filter: Option<ListFilter>,
    ) -> Result<ApiResponse<Vec<PolicySummary>>> {
        let (response, deprecation) = self.get(&format!("{}/list", POLICY_API_BASE))?;
        let wrapper: ListResponse = serde_json::from_str(&response)?;
        let mut summaries = wrapper.policies;

        if let Some(ref f) = filter {
            filter_summaries(&mut summaries, f);
        }

        Ok(ApiResponse::new(summaries, Some(deprecation)))
    }

    /// Get a specific policy by key.
    ///
    /// Sends `GET /management/policy/v0/get/{policy_key}`.
    /// The server returns a JSON object with `policy_key` and `policy` fields.
    /// The CVM type is extracted from the `policy_key` (e.g. `"policy:TDX:my-id"`).
    pub fn get_policy(&self, policy_key: &str) -> Result<ApiResponse<GetPolicyResponse>> {
        let path = format!("{}/get/{}", POLICY_API_BASE, policy_key);
        let (response, deprecation) = self.get(&path)?;
        let get_resp: GetPolicyResponse = serde_json::from_str(&response)?;
        Ok(ApiResponse::new(get_resp, Some(deprecation)))
    }

    /// Check connectivity and authentication.
    ///
    /// Sends `GET /` and checks for a successful response.
    pub fn health_check(&self) -> Result<HealthStatus> {
        match self.get("/") {
            Ok(_) => Ok(HealthStatus {
                reachable: true,
                authenticated: true,
            }),
            Err(Error::ApiError { status: 401, .. }) => Ok(HealthStatus {
                reachable: true,
                authenticated: false,
            }),
            Err(Error::NetworkError(_)) => Ok(HealthStatus {
                reachable: false,
                authenticated: false,
            }),
            Err(e) => Err(e),
        }
    }

    /// Validate a policy without uploading (dry-run).
    pub fn validate_policy<P: Into<Policy>>(&self, policy: P) -> Result<ValidationReport> {
        let _ = policy.into();
        todo!("Implement policy validation")
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for TasClient with fluent API.
pub struct TasClientBuilder {
    host: Option<String>,
    port: u16,
    api_key_file: Option<PathBuf>,
    tls_enabled: bool,
    tls_ca_cert: Option<PathBuf>,
    timeout: Duration,
    retry_config: RetryConfig,
}

impl TasClientBuilder {
    pub fn new() -> Self {
        Self {
            host: None,
            port: 5001,
            api_key_file: None,
            tls_enabled: true,
            tls_ca_cert: None,
            timeout: Duration::from_secs(30),
            retry_config: RetryConfig::default(),
        }
    }

    /// Set TAS server hostname or IP.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Set TAS server port (default: 5001).
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set path to API key file.
    pub fn api_key_file(mut self, path: impl AsRef<Path>) -> Self {
        self.api_key_file = Some(path.as_ref().to_path_buf());
        self
    }

    /// Enable/disable TLS (default: true).
    pub fn tls(mut self, enabled: bool) -> Self {
        self.tls_enabled = enabled;
        self
    }

    /// Set custom CA certificate for TLS verification.
    pub fn tls_ca_cert(mut self, path: impl AsRef<Path>) -> Self {
        self.tls_ca_cert = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set request timeout (default: 30s).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Configure retry behavior.
    pub fn retry(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<TasClient> {
        let host = self
            .host
            .ok_or(Error::Configuration("host is required".into()))?;
        let api_key_file = self
            .api_key_file
            .ok_or(Error::Configuration("api_key_file is required".into()))?;
        let api_key = std::fs::read_to_string(&api_key_file).map_err(|e| {
            Error::Configuration(format!(
                "failed to read API key from {}: {}",
                api_key_file.display(),
                e
            ))
        })?;

        let agent = {
            let mut config_builder = ureq::Agent::config_builder()
                .timeout_global(Some(self.timeout))
                .http_status_as_error(false);

            if self.tls_enabled {
                let ca_cert_path = self.tls_ca_cert.as_ref().ok_or_else(|| {
                    Error::Configuration(
                        "TLS is enabled but no CA certificate path was provided. \
                         Use --tls-ca-cert or set TAS_TLS_CA_CERT, \
                         or disable TLS with --no-tls"
                            .into(),
                    )
                })?;

                let pem_data = std::fs::read(ca_cert_path).map_err(|e| {
                    Error::Configuration(format!(
                        "failed to read CA cert file {}: {}",
                        ca_cert_path.display(),
                        e
                    ))
                })?;

                let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(&pem_data)
                    .filter_map(|item| match item {
                        Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                        _ => None,
                    })
                    .collect();

                if certs.is_empty() {
                    return Err(Error::Configuration(format!(
                        "no valid certificates found in {}",
                        ca_cert_path.display()
                    )));
                }

                let tls_config = ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::Specific(Arc::new(certs)))
                    .build();

                config_builder = config_builder.tls_config(tls_config);
            }

            ureq::Agent::new_with_config(config_builder.build())
        };

        Ok(TasClient {
            host,
            port: self.port,
            api_key: api_key.trim().to_string(),
            tls_enabled: self.tls_enabled,
            agent,
            max_retries: self.retry_config.max_retries,
            initial_backoff: self.retry_config.initial_backoff,
        })
    }

    /// Build from a Config object.
    pub fn from_config(config: &crate::config::Config) -> Result<TasClient> {
        let mut builder = Self::new();
        if let Some(ref host) = config.tas_host {
            builder = builder.host(host.clone());
        }
        if let Some(port) = config.tas_port {
            builder = builder.port(port);
        }
        if let Some(ref path) = config.api_key_file {
            builder = builder.api_key_file(path);
        }
        builder.build()
    }
}

impl Default for TasClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Free helper functions
// =============================================================================

/// Execute a closure with exponential backoff retry on transient errors.
///
/// Extracted as a free function for testability — `TasClient::with_retry`
/// delegates here.
fn retry_with_backoff<F, T>(max_retries: u32, initial_backoff: Duration, mut op: F) -> Result<T>
where
    F: FnMut() -> Result<T>,
{
    let mut attempt = 0u32;
    loop {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) if e.is_retryable() && attempt < max_retries => {
                attempt += 1;
                let backoff = initial_backoff * 2u32.saturating_pow(attempt - 1);
                std::thread::sleep(backoff);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Extract deprecation metadata from an HTTP response's headers.
///
/// Centralises the header-reading logic that was previously duplicated
/// across `post()`, `get()`, and `delete_request()`.
fn extract_deprecation<B>(resp: &ureq::http::Response<B>) -> DeprecationInfo {
    DeprecationInfo::from_headers(
        resp.headers()
            .get("Deprecation")
            .and_then(|v| v.to_str().ok()),
        resp.headers().get("Sunset").and_then(|v| v.to_str().ok()),
        resp.headers().get("Link").and_then(|v| v.to_str().ok()),
        resp.headers().get("Warning").and_then(|v| v.to_str().ok()),
    )
}

// =============================================================================
// Deprecation types
// =============================================================================

/// A parsed Link header entry (RFC 8288).
#[derive(Debug, Clone, Serialize)]
pub struct LinkEntry {
    pub url: String,
    pub rel: String,
}

/// Deprecation metadata extracted from HTTP response headers.
///
/// Captures the standard deprecation-related headers:
/// - `Deprecation` (RFC 8594) — indicates the API is or will be deprecated
/// - `Sunset` (RFC 8594) — date when the endpoint will be removed
/// - `Link` (RFC 8288) — URLs to successor API or migration docs
/// - `Warning` — human-readable server warning text
#[derive(Debug, Clone, Default, Serialize)]
pub struct DeprecationInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sunset: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<LinkEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

impl DeprecationInfo {
    /// Returns `true` if any deprecation header was present.
    pub fn has_any(&self) -> bool {
        self.deprecated.is_some()
            || self.sunset.is_some()
            || !self.links.is_empty()
            || self.warning.is_some()
    }

    /// Build from individual header values.
    fn from_headers(
        deprecated: Option<&str>,
        sunset: Option<&str>,
        link: Option<&str>,
        warning: Option<&str>,
    ) -> Self {
        Self {
            deprecated: deprecated.map(String::from),
            sunset: sunset.map(String::from),
            links: Self::parse_link_header(link),
            warning: warning.map(String::from),
        }
    }

    /// Parse a `Link` header value into a list of `LinkEntry`.
    ///
    /// Handles the format: `<url>; rel="relationship", <url2>; rel="other"`
    fn parse_link_header(value: Option<&str>) -> Vec<LinkEntry> {
        let Some(value) = value else { return vec![] };
        value
            .split(',')
            .filter_map(|part| {
                let part = part.trim();
                let url = part.split('>').next()?.trim_start_matches('<').to_string();
                let rel = part.split("rel=\"").nth(1)?.split('"').next()?.to_string();
                if url.is_empty() || rel.is_empty() {
                    return None;
                }
                Some(LinkEntry { url, rel })
            })
            .collect()
    }
}

/// Wraps an API result with optional deprecation metadata.
///
/// Every CRUD method on `TasClient` returns `ApiResponse<T>` so callers
/// can inspect server-sent deprecation headers when verbose mode is enabled.
#[derive(Debug, Clone)]
pub struct ApiResponse<T> {
    pub data: T,
    pub deprecation: Option<DeprecationInfo>,
}

impl<T> ApiResponse<T> {
    fn new(data: T, deprecation: Option<DeprecationInfo>) -> Self {
        let deprecation = match deprecation {
            Some(d) if d.has_any() => Some(d),
            _ => None,
        };
        Self { data, deprecation }
    }
}

// =============================================================================
// Response / result types
// =============================================================================

/// Result of a successful policy creation.
#[derive(Debug, Clone)]
pub struct CreateResult {
    pub policy_key: String,
    pub cvm_type: crate::policy::CvmType,
}

/// Summary of a policy for list operations.
///
/// Matches the shape returned by `GET /management/policy/v0/list`:
/// ```json
/// { "policy_key": "...", "name": "...", "version": "...", "description": "...", "signed": false }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySummary {
    pub policy_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub signed: bool,
}

impl PolicySummary {
    /// Extract the CVM type from the policy_key (format: `policy:TYPE:key_id`).
    pub fn cvm_type(&self) -> Option<crate::policy::CvmType> {
        let parts: Vec<&str> = self.policy_key.splitn(3, ':').collect();
        if parts.len() >= 2 {
            parts[1].parse().ok()
        } else {
            None
        }
    }

    /// Extract the key_id from the policy_key (format: `policy:TYPE:key_id`).
    pub fn key_id(&self) -> &str {
        let parts: Vec<&str> = self.policy_key.splitn(3, ':').collect();
        if parts.len() == 3 {
            parts[2]
        } else {
            &self.policy_key
        }
    }
}

/// Filter for list operations.
#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    pub cvm_type: Option<crate::policy::CvmType>,
    pub key_id_prefix: Option<String>,
}

/// Health check status.
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub reachable: bool,
    pub authenticated: bool,
}

/// Status of a single diagnostic check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Fail,
    Skip,
}

/// Result of a single diagnostic check.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Comprehensive health report from `diagnose_connection`.
#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    pub healthy: bool,
    pub checks: Vec<CheckResult>,
}

/// Configuration for `diagnose_connection`.
pub struct HealthCheckConfig {
    pub host: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub tls_ca_cert: Option<PathBuf>,
    pub api_key: Option<String>,
}

/// Run layered connectivity diagnostics: DNS → TCP → TLS → HTTP → Auth.
///
/// Each layer short-circuits on failure so the user sees the first broken layer.
/// Returns a `HealthReport` (never fails — failures are captured as check results).
pub fn diagnose_connection(config: &HealthCheckConfig) -> HealthReport {
    let mut checks = Vec::new();

    // --- 1. DNS Resolution ---
    let start = Instant::now();
    let addrs: Vec<SocketAddr> = match (config.host.as_str(), config.port).to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(e) => {
            checks.push(CheckResult {
                name: "DNS Resolution".into(),
                status: CheckStatus::Fail,
                latency_ms: start.elapsed().as_millis() as u64,
                detail: Some(format!("failed to resolve '{}': {}", config.host, e)),
            });
            return HealthReport {
                healthy: false,
                checks,
            };
        }
    };
    let addr_list: String = addrs
        .iter()
        .map(|a| a.ip().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    checks.push(CheckResult {
        name: "DNS Resolution".into(),
        status: CheckStatus::Pass,
        latency_ms: start.elapsed().as_millis() as u64,
        detail: Some(format!("resolved to: {}", addr_list)),
    });

    // --- 2. TCP Connection ---
    let addr = addrs[0];
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(_) => {
            checks.push(CheckResult {
                name: "TCP Connection".into(),
                status: CheckStatus::Pass,
                latency_ms: start.elapsed().as_millis() as u64,
                detail: Some(format!("connected to {}", addr)),
            });
        }
        Err(e) => {
            checks.push(CheckResult {
                name: "TCP Connection".into(),
                status: CheckStatus::Fail,
                latency_ms: start.elapsed().as_millis() as u64,
                detail: Some(format!("failed to connect to {}: {}", addr, e)),
            });
            return HealthReport {
                healthy: false,
                checks,
            };
        }
    }

    // --- 3. TLS + HTTP + Auth (via ureq request) ---
    let scheme = if config.tls_enabled { "https" } else { "http" };
    let url = format!(
        "{}://{}:{}{}/list",
        scheme, config.host, config.port, POLICY_API_BASE
    );

    let agent = match build_diagnostic_agent(config) {
        Ok(a) => a,
        Err(detail) => {
            checks.push(CheckResult {
                name: "TLS Configuration".into(),
                status: CheckStatus::Fail,
                latency_ms: 0,
                detail: Some(detail),
            });
            return HealthReport {
                healthy: false,
                checks,
            };
        }
    };

    let start = Instant::now();
    let mut request = agent.get(&url);
    if let Some(ref key) = config.api_key {
        request = request.header("X-MANAGEMENT-API-KEY", key);
    }

    match request.call() {
        Ok(mut response) => {
            let latency = start.elapsed().as_millis() as u64;
            let status = response.status().as_u16();
            let body = response.body_mut().read_to_string().unwrap_or_default();

            if config.tls_enabled {
                checks.push(CheckResult {
                    name: "TLS Handshake".into(),
                    status: CheckStatus::Pass,
                    latency_ms: latency,
                    detail: Some("TLS connection established".into()),
                });
            }

            checks.push(CheckResult {
                name: "HTTP Request".into(),
                status: CheckStatus::Pass,
                latency_ms: latency,
                detail: Some(format!("HTTP {}", status)),
            });

            // Auth check
            if config.api_key.is_some() {
                if status == 401 || status == 403 {
                    checks.push(CheckResult {
                        name: "API Authentication".into(),
                        status: CheckStatus::Fail,
                        latency_ms: 0,
                        detail: Some(format!("HTTP {} — check your API key", status)),
                    });
                } else {
                    checks.push(CheckResult {
                        name: "API Authentication".into(),
                        status: CheckStatus::Pass,
                        latency_ms: 0,
                        detail: Some(format!("API key accepted (HTTP {})", status)),
                    });
                }
            } else {
                checks.push(CheckResult {
                    name: "API Authentication".into(),
                    status: CheckStatus::Skip,
                    latency_ms: 0,
                    detail: Some("no API key provided — skipped".into()),
                });
            }

            if status >= 400 && !body.is_empty() {
                log::debug!("server response body: {}", body.trim());
            }
        }
        Err(err) => {
            let latency = start.elapsed().as_millis() as u64;
            classify_ureq_error(&mut checks, err, latency, config.tls_enabled);
            return HealthReport {
                healthy: false,
                checks,
            };
        }
    }

    let healthy = checks
        .iter()
        .all(|c| matches!(c.status, CheckStatus::Pass | CheckStatus::Skip));
    HealthReport { healthy, checks }
}

/// Build a ureq Agent for the diagnostic checks.
fn build_diagnostic_agent(config: &HealthCheckConfig) -> std::result::Result<ureq::Agent, String> {
    let mut config_builder = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .http_status_as_error(false);

    if config.tls_enabled {
        let ca_cert_path = config.tls_ca_cert.as_ref().ok_or_else(|| {
            "TLS is enabled but no CA certificate was provided. \
             Use --tls-ca-cert or disable TLS with --no-tls"
                .to_string()
        })?;

        let pem_data = std::fs::read(ca_cert_path)
            .map_err(|e| format!("failed to read CA cert {}: {}", ca_cert_path.display(), e))?;

        let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(&pem_data)
            .filter_map(|item| match item {
                Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                _ => None,
            })
            .collect();

        if certs.is_empty() {
            return Err(format!(
                "no valid certificates found in {}",
                ca_cert_path.display()
            ));
        }

        let tls_config = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::Specific(Arc::new(certs)))
            .build();

        config_builder = config_builder.tls_config(tls_config);
    }

    Ok(ureq::Agent::new_with_config(config_builder.build()))
}

/// Classify a ureq error into the appropriate TLS / HTTP / Auth check results.
fn classify_ureq_error(
    checks: &mut Vec<CheckResult>,
    err: ureq::Error,
    latency: u64,
    tls_enabled: bool,
) {
    match err {
        ureq::Error::Tls(msg) => {
            checks.push(CheckResult {
                name: "TLS Handshake".into(),
                status: CheckStatus::Fail,
                latency_ms: latency,
                detail: Some(format!("TLS error: {}", msg)),
            });
        }
        #[cfg(feature = "rustls")]
        ureq::Error::Rustls(ref rustls_err) => {
            checks.push(CheckResult {
                name: "TLS Handshake".into(),
                status: CheckStatus::Fail,
                latency_ms: latency,
                detail: Some(format!("TLS error: {}", rustls_err)),
            });
        }
        ureq::Error::Timeout(_) => {
            if tls_enabled {
                checks.push(CheckResult {
                    name: "TLS Handshake".into(),
                    status: CheckStatus::Fail,
                    latency_ms: latency,
                    detail: Some("connection timed out during TLS/HTTP".into()),
                });
            } else {
                checks.push(CheckResult {
                    name: "HTTP Request".into(),
                    status: CheckStatus::Fail,
                    latency_ms: latency,
                    detail: Some("request timed out".into()),
                });
            }
        }
        ureq::Error::Io(ref io_err) => {
            let detail = format!("I/O error: {}", io_err);
            if tls_enabled {
                checks.push(CheckResult {
                    name: "TLS Handshake".into(),
                    status: CheckStatus::Fail,
                    latency_ms: latency,
                    detail: Some(detail),
                });
            } else {
                checks.push(CheckResult {
                    name: "HTTP Request".into(),
                    status: CheckStatus::Fail,
                    latency_ms: latency,
                    detail: Some(detail),
                });
            }
        }
        other => {
            checks.push(CheckResult {
                name: "HTTP Request".into(),
                status: CheckStatus::Fail,
                latency_ms: latency,
                detail: Some(format!("error: {}", other)),
            });
        }
    }
}

/// Validation report from dry-run.
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Response from the `GET /policy/v0/get/{policy_key}` endpoint.
///
/// The server returns this format:
/// ```json
/// {
///   "policy_key": "policy:TDX:my-id",
///   "policy": { "metadata": {...}, "validation_rules": {...}, "signature": {...} }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPolicyResponse {
    pub policy_key: String,
    pub policy: crate::policy::signed::SignedPolicyEnvelope,
}

impl GetPolicyResponse {
    /// Convert the server GET response into a `Policy`.
    ///
    /// The CVM type is determined from the `policy_key` (e.g. `"policy:TDX:my-id"`)
    /// and the `validation_rules` variant within the body.
    pub fn to_policy(&self) -> Result<Policy> {
        // Extract key_id from policy_key format "policy:TYPE:key_id"
        let parts: Vec<&str> = self.policy_key.splitn(3, ':').collect();
        let key_id = if parts.len() == 3 {
            parts[2].to_string()
        } else {
            self.policy_key.clone()
        };

        let policy_type = if parts.len() >= 2 {
            parts[1].to_string()
        } else {
            // Infer from validation_rules variant
            match &self.policy.validation_rules {
                crate::policy::signed::ValidationRules::Tdx(_) => "TDX".to_string(),
                crate::policy::signed::ValidationRules::Sev(_) => "SEV".to_string(),
            }
        };

        // Build an envelope with policy_type/key_id in metadata for to_policy()
        let mut envelope = self.policy.clone();
        envelope.metadata.policy_type = policy_type;
        envelope.metadata.key_id = key_id;
        envelope.to_policy()
    }
}

/// Apply client-side filtering to a list of policy summaries.
///
/// Filters in-place by CVM type and/or key-id prefix when the
/// corresponding fields on `ListFilter` are `Some`.
/// Apply client-side filtering to a list of policy summaries.
///
/// Filters in-place by CVM type and/or key-id prefix when the
/// corresponding fields on `ListFilter` are `Some`.
pub fn filter_summaries(summaries: &mut Vec<PolicySummary>, filter: &ListFilter) {
    if let Some(cvm) = filter.cvm_type {
        summaries.retain(|s| s.cvm_type() == Some(cvm));
    }
    if let Some(ref prefix) = filter.key_id_prefix {
        summaries.retain(|s| s.key_id().starts_with(prefix.as_str()));
    }
}

/// Retry configuration.
/// Response wrapper for `GET /management/policy/v0/list`.
#[derive(Debug, Clone, Deserialize)]
struct ListResponse {
    policies: Vec<PolicySummary>,
    #[serde(default)]
    #[allow(dead_code)]
    count: usize,
}

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_backoff: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(500),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::CvmType;

    /// Helper: build a `PolicySummary` with the given policy_key, name, and signed flag.
    fn make_summary(policy_key: &str, name: Option<&str>, signed: bool) -> PolicySummary {
        PolicySummary {
            policy_key: policy_key.to_string(),
            name: name.map(String::from),
            version: None,
            description: None,
            signed,
        }
    }

    /// Helper: build a vec of mixed TDX/SEV summaries for filter tests.
    fn sample_summaries() -> Vec<PolicySummary> {
        vec![
            make_summary("policy:TDX:tdx-prod-001", Some("TDX Production"), true),
            make_summary("policy:TDX:tdx-staging-002", Some("TDX Staging"), false),
            make_summary("policy:SEV:sev-prod-001", Some("SEV Production"), true),
            make_summary("policy:SEV:sev-staging-002", Some("SEV Staging"), false),
            make_summary("policy:SEV:test-sev-003", Some("SEV Test"), true),
        ]
    }

    // =========================================================================
    // PolicySummary::cvm_type() tests
    // =========================================================================

    #[test]
    fn cvm_type_tdx() {
        let s = make_summary("policy:TDX:my-key", None, false);
        assert_eq!(s.cvm_type(), Some(CvmType::TDX));
    }

    #[test]
    fn cvm_type_sev() {
        let s = make_summary("policy:SEV:my-key", None, false);
        assert_eq!(s.cvm_type(), Some(CvmType::SEV));
    }

    #[test]
    fn cvm_type_unknown_returns_none() {
        let s = make_summary("policy:UNKNOWN:key", None, false);
        assert_eq!(
            s.cvm_type(),
            None,
            "unrecognised type segment should yield None"
        );
    }

    #[test]
    fn cvm_type_no_colons_returns_none() {
        let s = make_summary("no-colons", None, false);
        assert_eq!(s.cvm_type(), None);
    }

    #[test]
    fn cvm_type_empty_key_id_still_parses() {
        let s = make_summary("policy:TDX:", None, false);
        assert_eq!(s.cvm_type(), Some(CvmType::TDX));
    }

    // =========================================================================
    // PolicySummary::key_id() tests
    // =========================================================================

    #[test]
    fn key_id_normal() {
        let s = make_summary("policy:TDX:my-key", None, false);
        assert_eq!(s.key_id(), "my-key");
    }

    #[test]
    fn key_id_preserves_colons_in_key() {
        let s = make_summary("policy:SEV:compound:key:value", None, false);
        assert_eq!(
            s.key_id(),
            "compound:key:value",
            "splitn(3,':') should keep colons in key_id"
        );
    }

    #[test]
    fn key_id_no_colons_fallback() {
        let s = make_summary("no-colons", None, false);
        assert_eq!(
            s.key_id(),
            "no-colons",
            "should fall back to full policy_key"
        );
    }

    #[test]
    fn key_id_empty_segment() {
        let s = make_summary("policy:TDX:", None, false);
        assert_eq!(s.key_id(), "");
    }

    // =========================================================================
    // filter_summaries() tests
    // =========================================================================

    #[test]
    fn filter_no_criteria_retains_all() {
        let mut summaries = sample_summaries();
        let filter = ListFilter::default();
        filter_summaries(&mut summaries, &filter);
        assert_eq!(summaries.len(), 5, "empty filter should keep all items");
    }

    #[test]
    fn filter_by_cvm_type_tdx() {
        let mut summaries = sample_summaries();
        let filter = ListFilter {
            cvm_type: Some(CvmType::TDX),
            key_id_prefix: None,
        };
        filter_summaries(&mut summaries, &filter);
        assert_eq!(summaries.len(), 2);
        assert!(summaries.iter().all(|s| s.cvm_type() == Some(CvmType::TDX)));
    }

    #[test]
    fn filter_by_cvm_type_sev() {
        let mut summaries = sample_summaries();
        let filter = ListFilter {
            cvm_type: Some(CvmType::SEV),
            key_id_prefix: None,
        };
        filter_summaries(&mut summaries, &filter);
        assert_eq!(summaries.len(), 3);
        assert!(summaries.iter().all(|s| s.cvm_type() == Some(CvmType::SEV)));
    }

    #[test]
    fn filter_by_key_id_prefix() {
        let mut summaries = sample_summaries();
        let filter = ListFilter {
            cvm_type: None,
            key_id_prefix: Some("sev-prod".to_string()),
        };
        filter_summaries(&mut summaries, &filter);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].policy_key, "policy:SEV:sev-prod-001");
    }

    #[test]
    fn filter_by_type_and_prefix() {
        let mut summaries = sample_summaries();
        let filter = ListFilter {
            cvm_type: Some(CvmType::SEV),
            key_id_prefix: Some("sev-".to_string()),
        };
        filter_summaries(&mut summaries, &filter);
        assert_eq!(
            summaries.len(),
            2,
            "should match SEV items with key starting 'sev-'"
        );
        assert!(summaries.iter().all(|s| s.key_id().starts_with("sev-")));
    }

    #[test]
    fn filter_matches_nothing() {
        let mut summaries = sample_summaries();
        let filter = ListFilter {
            cvm_type: Some(CvmType::TDX),
            key_id_prefix: Some("nonexistent-".to_string()),
        };
        filter_summaries(&mut summaries, &filter);
        assert!(
            summaries.is_empty(),
            "no item matches both TDX + 'nonexistent-' prefix"
        );
    }

    // =========================================================================
    // PolicySummary serde round-trip tests
    // =========================================================================

    #[test]
    fn summary_serde_full() {
        let json = r#"{
            "policy_key": "policy:TDX:my-key",
            "name": "My Policy",
            "version": "1.0",
            "description": "A test policy",
            "signed": true
        }"#;
        let s: PolicySummary = serde_json::from_str(json).expect("deserialize");
        assert_eq!(s.policy_key, "policy:TDX:my-key");
        assert_eq!(s.name.as_deref(), Some("My Policy"));
        assert_eq!(s.version.as_deref(), Some("1.0"));
        assert_eq!(s.description.as_deref(), Some("A test policy"));
        assert!(s.signed);

        // Round-trip
        let out = serde_json::to_string(&s).expect("serialize");
        let s2: PolicySummary = serde_json::from_str(&out).expect("re-deserialize");
        assert_eq!(s.policy_key, s2.policy_key);
        assert_eq!(s.signed, s2.signed);
    }

    #[test]
    fn summary_serde_minimal() {
        let json = r#"{ "policy_key": "policy:SEV:k", "signed": false }"#;
        let s: PolicySummary = serde_json::from_str(json).expect("deserialize minimal");
        assert_eq!(s.policy_key, "policy:SEV:k");
        assert!(s.name.is_none());
        assert!(s.version.is_none());
        assert!(s.description.is_none());
        assert!(!s.signed);
    }

    // =========================================================================
    // ListResponse deserialization test
    // =========================================================================

    #[test]
    fn list_response_deserializes() {
        let json = r#"{
            "policies": [
                { "policy_key": "policy:TDX:a", "signed": true },
                { "policy_key": "policy:SEV:b", "signed": false }
            ],
            "count": 2
        }"#;
        let resp: ListResponse = serde_json::from_str(json).expect("deserialize ListResponse");
        assert_eq!(resp.policies.len(), 2);
        assert_eq!(resp.count, 2);
        assert_eq!(resp.policies[0].policy_key, "policy:TDX:a");
        assert_eq!(resp.policies[1].policy_key, "policy:SEV:b");
    }

    #[test]
    fn list_response_missing_count_defaults_to_zero() {
        let json = r#"{ "policies": [] }"#;
        let resp: ListResponse = serde_json::from_str(json).expect("deserialize empty");
        assert_eq!(resp.policies.len(), 0);
        assert_eq!(resp.count, 0);
    }
}

#[cfg(test)]
mod healthcheck_tests {
    use super::*;

    // =========================================================================
    // CheckStatus serialization tests
    // =========================================================================

    #[test]
    fn check_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&CheckStatus::Pass).unwrap(),
            r#""pass""#
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Fail).unwrap(),
            r#""fail""#
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Skip).unwrap(),
            r#""skip""#
        );
    }

    #[test]
    fn check_status_equality() {
        assert_eq!(CheckStatus::Pass, CheckStatus::Pass);
        assert_ne!(CheckStatus::Pass, CheckStatus::Fail);
        assert_ne!(CheckStatus::Fail, CheckStatus::Skip);
    }

    // =========================================================================
    // HealthReport serialization tests
    // =========================================================================

    #[test]
    fn health_report_serializes_to_json() {
        let report = HealthReport {
            healthy: true,
            checks: vec![
                CheckResult {
                    name: "DNS Resolution".into(),
                    status: CheckStatus::Pass,
                    latency_ms: 5,
                    detail: Some("resolved to: 127.0.0.1".into()),
                },
                CheckResult {
                    name: "API Authentication".into(),
                    status: CheckStatus::Skip,
                    latency_ms: 0,
                    detail: None,
                },
            ],
        };

        let json = serde_json::to_string_pretty(&report).expect("serialize HealthReport");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse back");

        assert_eq!(parsed["healthy"], true);
        assert_eq!(parsed["checks"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["checks"][0]["name"], "DNS Resolution");
        assert_eq!(parsed["checks"][0]["status"], "pass");
        assert_eq!(parsed["checks"][0]["latency_ms"], 5);
        assert_eq!(parsed["checks"][0]["detail"], "resolved to: 127.0.0.1");
        // detail: None should be omitted via skip_serializing_if
        assert!(parsed["checks"][1]["detail"].is_null());
    }

    #[test]
    fn health_report_unhealthy_flag() {
        let report = HealthReport {
            healthy: false,
            checks: vec![CheckResult {
                name: "TCP Connection".into(),
                status: CheckStatus::Fail,
                latency_ms: 50,
                detail: Some("connection refused".into()),
            }],
        };

        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["healthy"], false);
        assert_eq!(parsed["checks"][0]["status"], "fail");
    }

    // =========================================================================
    // diagnose_connection tests
    // =========================================================================

    #[test]
    fn diagnose_connection_dns_fail() {
        let config = HealthCheckConfig {
            host: "this-host-does-not-exist.invalid".into(),
            port: 9999,
            tls_enabled: false,
            tls_ca_cert: None,
            api_key: None,
        };

        let report = diagnose_connection(&config);
        assert!(!report.healthy);
        assert!(!report.checks.is_empty());
        assert_eq!(report.checks[0].name, "DNS Resolution");
        assert_eq!(report.checks[0].status, CheckStatus::Fail);
    }

    #[test]
    fn diagnose_connection_unreachable_tcp() {
        // localhost DNS resolves but nothing listens on this port
        let config = HealthCheckConfig {
            host: "127.0.0.1".into(),
            port: 1, // privileged port, almost certainly closed
            tls_enabled: false,
            tls_ca_cert: None,
            api_key: None,
        };

        let report = diagnose_connection(&config);
        assert!(!report.healthy);
        // DNS should pass (it's an IP literal)
        assert_eq!(report.checks[0].name, "DNS Resolution");
        assert_eq!(report.checks[0].status, CheckStatus::Pass);
        // TCP should fail
        assert!(report.checks.len() >= 2);
        assert_eq!(report.checks[1].name, "TCP Connection");
        assert_eq!(report.checks[1].status, CheckStatus::Fail);
    }
}

#[cfg(test)]
mod classify_error_tests {
    use super::*;

    #[test]
    fn classify_timeout_without_tls_yields_http_fail() {
        let mut checks = Vec::new();
        classify_ureq_error(
            &mut checks,
            ureq::Error::Timeout(ureq::Timeout::Global),
            100,
            false,
        );
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "HTTP Request");
        assert_eq!(checks[0].status, CheckStatus::Fail);
        assert!(checks[0].detail.as_ref().unwrap().contains("timed out"));
    }

    #[test]
    fn classify_timeout_with_tls_yields_tls_fail() {
        let mut checks = Vec::new();
        classify_ureq_error(
            &mut checks,
            ureq::Error::Timeout(ureq::Timeout::Global),
            200,
            true,
        );
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "TLS Handshake");
        assert_eq!(checks[0].status, CheckStatus::Fail);
        assert!(checks[0].detail.as_ref().unwrap().contains("timed out"));
    }

    #[test]
    fn classify_io_error_without_tls_yields_http_fail() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let mut checks = Vec::new();
        classify_ureq_error(&mut checks, ureq::Error::Io(io_err), 50, false);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "HTTP Request");
        assert_eq!(checks[0].status, CheckStatus::Fail);
        assert!(checks[0].detail.as_ref().unwrap().contains("I/O error"));
    }

    #[test]
    fn classify_io_error_with_tls_yields_tls_fail() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let mut checks = Vec::new();
        classify_ureq_error(&mut checks, ureq::Error::Io(io_err), 75, true);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "TLS Handshake");
        assert_eq!(checks[0].status, CheckStatus::Fail);
    }

    #[test]
    fn classify_tls_error() {
        let mut checks = Vec::new();
        classify_ureq_error(
            &mut checks,
            ureq::Error::Tls("certificate verify failed"),
            30,
            true,
        );
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "TLS Handshake");
        assert_eq!(checks[0].status, CheckStatus::Fail);
        assert!(checks[0].detail.as_ref().unwrap().contains("TLS error"));
    }

    #[test]
    fn classify_unknown_error_yields_http_fail() {
        let mut checks = Vec::new();
        classify_ureq_error(&mut checks, ureq::Error::ConnectionFailed, 10, false);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "HTTP Request");
        assert_eq!(checks[0].status, CheckStatus::Fail);
    }

    #[test]
    fn classify_preserves_latency() {
        let mut checks = Vec::new();
        classify_ureq_error(&mut checks, ureq::Error::ConnectionFailed, 42, false);
        assert_eq!(checks[0].latency_ms, 42);
    }
}

#[cfg(test)]
mod deprecation_tests {
    use super::*;

    // =========================================================================
    // DeprecationInfo::has_any() tests (B1)
    // =========================================================================

    #[test]
    fn deprecation_info_empty_has_any_false() {
        assert!(!DeprecationInfo::default().has_any());
    }

    #[test]
    fn deprecation_info_deprecated_only() {
        let info = DeprecationInfo {
            deprecated: Some("true".into()),
            ..Default::default()
        };
        assert!(info.has_any());
    }

    #[test]
    fn deprecation_info_sunset_only() {
        let info = DeprecationInfo {
            sunset: Some("2026-12-31".into()),
            ..Default::default()
        };
        assert!(info.has_any());
    }

    #[test]
    fn deprecation_info_warning_only() {
        let info = DeprecationInfo {
            warning: Some("This API is deprecated".into()),
            ..Default::default()
        };
        assert!(info.has_any());
    }

    #[test]
    fn deprecation_info_links_only() {
        let info = DeprecationInfo {
            links: vec![LinkEntry {
                url: "https://api.example.com/v2".into(),
                rel: "successor".into(),
            }],
            ..Default::default()
        };
        assert!(info.has_any());
    }

    #[test]
    fn deprecation_info_all_fields() {
        let info = DeprecationInfo {
            deprecated: Some("true".into()),
            sunset: Some("2026-12-31".into()),
            links: vec![LinkEntry {
                url: "https://api.example.com/v2".into(),
                rel: "successor".into(),
            }],
            warning: Some("Migrate soon".into()),
        };
        assert!(info.has_any());
        assert_eq!(info.deprecated.as_deref(), Some("true"));
        assert_eq!(info.sunset.as_deref(), Some("2026-12-31"));
        assert_eq!(info.links.len(), 1);
        assert_eq!(info.warning.as_deref(), Some("Migrate soon"));
    }

    // =========================================================================
    // DeprecationInfo::from_headers() tests (B1)
    // =========================================================================

    #[test]
    fn deprecation_info_from_headers_none() {
        let info = DeprecationInfo::from_headers(None, None, None, None);
        assert!(!info.has_any());
        assert!(info.deprecated.is_none());
        assert!(info.sunset.is_none());
        assert!(info.links.is_empty());
        assert!(info.warning.is_none());
    }

    #[test]
    fn deprecation_info_from_headers_full() {
        let info = DeprecationInfo::from_headers(
            Some("true"),
            Some("2026-12-31"),
            Some(r#"<https://api.example.com/v2>; rel="successor""#),
            Some("299 - API will be removed"),
        );
        assert!(info.has_any());
        assert_eq!(info.deprecated.as_deref(), Some("true"));
        assert_eq!(info.sunset.as_deref(), Some("2026-12-31"));
        assert_eq!(info.links.len(), 1);
        assert_eq!(info.links[0].url, "https://api.example.com/v2");
        assert_eq!(info.links[0].rel, "successor");
        assert_eq!(info.warning.as_deref(), Some("299 - API will be removed"));
    }

    // =========================================================================
    // parse_link_header() tests (B2)
    // =========================================================================

    #[test]
    fn parse_link_none() {
        let links = DeprecationInfo::parse_link_header(None);
        assert!(links.is_empty());
    }

    #[test]
    fn parse_link_single() {
        let links = DeprecationInfo::parse_link_header(Some(
            r#"<https://api.example.com/v2>; rel="successor""#,
        ));
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].url, "https://api.example.com/v2");
        assert_eq!(links[0].rel, "successor");
    }

    #[test]
    fn parse_link_multiple() {
        let links = DeprecationInfo::parse_link_header(Some(
            r#"<https://api.example.com/v2>; rel="successor", <https://docs.example.com/migration>; rel="help""#,
        ));
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].url, "https://api.example.com/v2");
        assert_eq!(links[0].rel, "successor");
        assert_eq!(links[1].url, "https://docs.example.com/migration");
        assert_eq!(links[1].rel, "help");
    }

    #[test]
    fn parse_link_empty_url_skipped() {
        let links = DeprecationInfo::parse_link_header(Some(r#"<>; rel="foo""#));
        assert!(links.is_empty(), "empty URL should be skipped");
    }

    #[test]
    fn parse_link_empty_rel_skipped() {
        let links = DeprecationInfo::parse_link_header(Some(r#"<https://x.com>; rel="""#));
        assert!(links.is_empty(), "empty rel should be skipped");
    }

    #[test]
    fn parse_link_malformed_no_rel() {
        let links =
            DeprecationInfo::parse_link_header(Some(r#"<https://x.com>; type="text/html""#));
        assert!(links.is_empty(), "missing rel= should be skipped");
    }

    #[test]
    fn parse_link_whitespace_handling() {
        let links = DeprecationInfo::parse_link_header(Some(
            r#"  <https://a.com>; rel="x"  ,  <https://b.com>; rel="y"  "#,
        ));
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].url, "https://a.com");
        assert_eq!(links[1].url, "https://b.com");
    }

    // =========================================================================
    // ApiResponse::new() tests (B3)
    // =========================================================================

    #[test]
    fn api_response_strips_empty_deprecation() {
        let resp = ApiResponse::new(42, Some(DeprecationInfo::default()));
        assert!(
            resp.deprecation.is_none(),
            "empty DeprecationInfo should be stripped to None"
        );
    }

    #[test]
    fn api_response_preserves_real_deprecation() {
        let info = DeprecationInfo {
            sunset: Some("2026-12-31".into()),
            ..Default::default()
        };
        let resp = ApiResponse::new(42, Some(info));
        assert!(resp.deprecation.is_some());
        assert_eq!(
            resp.deprecation.unwrap().sunset.as_deref(),
            Some("2026-12-31")
        );
    }

    #[test]
    fn api_response_none_deprecation_stays_none() {
        let resp: ApiResponse<i32> = ApiResponse::new(42, None);
        assert!(resp.deprecation.is_none());
    }

    #[test]
    fn api_response_data_accessible() {
        let resp = ApiResponse::new("hello", None);
        assert_eq!(resp.data, "hello");
    }

    // =========================================================================
    // DeprecationInfo serialization tests (B4)
    // =========================================================================

    #[test]
    fn deprecation_info_serializes_only_present_fields() {
        let info = DeprecationInfo::default();
        let json = serde_json::to_string(&info).expect("serialize");
        assert_eq!(json, "{}");
    }

    #[test]
    fn deprecation_info_serializes_all_fields() {
        let info = DeprecationInfo {
            deprecated: Some("true".into()),
            sunset: Some("2026-12-31".into()),
            links: vec![LinkEntry {
                url: "https://x.com".into(),
                rel: "successor".into(),
            }],
            warning: Some("deprecated".into()),
        };
        let json = serde_json::to_string(&info).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["deprecated"], "true");
        assert_eq!(v["sunset"], "2026-12-31");
        assert_eq!(v["links"][0]["url"], "https://x.com");
        assert_eq!(v["links"][0]["rel"], "successor");
        assert_eq!(v["warning"], "deprecated");
    }

    #[test]
    fn link_entry_serializes() {
        let entry = LinkEntry {
            url: "https://api.example.com/v2".into(),
            rel: "successor".into(),
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["url"], "https://api.example.com/v2");
        assert_eq!(v["rel"], "successor");
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use std::cell::Cell;
    use std::time::Duration;

    #[test]
    fn retry_returns_ok_on_first_success() {
        let count = Cell::new(0u32);
        let result: Result<(String, DeprecationInfo)> =
            retry_with_backoff(3, Duration::from_millis(1), || {
                count.set(count.get() + 1);
                Ok(("ok".into(), DeprecationInfo::default()))
            });
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, "ok");
        assert_eq!(count.get(), 1, "should only be called once");
    }

    #[test]
    fn retry_retries_on_transient_error() {
        let count = Cell::new(0u32);
        let result: Result<String> = retry_with_backoff(3, Duration::from_millis(1), || {
            let n = count.get() + 1;
            count.set(n);
            if n < 3 {
                Err(Error::NetworkError("transient".into()))
            } else {
                Ok("recovered".into())
            }
        });
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "recovered");
        assert_eq!(count.get(), 3, "should have retried twice then succeeded");
    }

    #[test]
    fn retry_gives_up_after_max_retries() {
        let count = Cell::new(0u32);
        let result: Result<String> = retry_with_backoff(2, Duration::from_millis(1), || {
            count.set(count.get() + 1);
            Err(Error::NetworkError("persistent".into()))
        });
        assert!(result.is_err());
        // max_retries=2 means: attempt 0, retry 1, retry 2 = 3 total calls
        assert_eq!(count.get(), 3, "should attempt 1 + 2 retries = 3 total");
    }

    #[test]
    fn retry_does_not_retry_non_retryable() {
        let count = Cell::new(0u32);
        let result: Result<String> = retry_with_backoff(3, Duration::from_millis(1), || {
            count.set(count.get() + 1);
            Err(Error::InvalidPolicy("bad".into()))
        });
        assert!(result.is_err());
        assert_eq!(
            count.get(),
            1,
            "non-retryable errors should not trigger retries"
        );
    }

    #[test]
    fn retry_zero_max_retries_no_retry() {
        let count = Cell::new(0u32);
        let result: Result<String> = retry_with_backoff(0, Duration::from_millis(1), || {
            count.set(count.get() + 1);
            Err(Error::NetworkError("fail".into()))
        });
        assert!(result.is_err());
        assert_eq!(count.get(), 1, "max_retries=0 should not retry at all");
    }

    #[test]
    fn retry_api_503_is_retried() {
        let count = Cell::new(0u32);
        let result: Result<String> = retry_with_backoff(2, Duration::from_millis(1), || {
            let n = count.get() + 1;
            count.set(n);
            if n <= 2 {
                Err(Error::ApiError {
                    status: 503,
                    message: "service unavailable".into(),
                })
            } else {
                Ok("ok".into())
            }
        });
        assert!(result.is_ok());
        assert_eq!(count.get(), 3);
    }

    #[test]
    fn retry_api_404_is_not_retried() {
        let count = Cell::new(0u32);
        let result: Result<String> = retry_with_backoff(3, Duration::from_millis(1), || {
            count.set(count.get() + 1);
            Err(Error::ApiError {
                status: 404,
                message: "not found".into(),
            })
        });
        assert!(result.is_err());
        assert_eq!(count.get(), 1, "404 is not retryable");
    }
}
