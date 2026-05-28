// TEE Attestation Service Policy Library - Configuration types
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the Config struct for TAS connection and TLS settings.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub tas_host: Option<String>,
    pub tas_port: Option<u16>,
    pub api_key_file: Option<PathBuf>,
    pub signing_key: Option<PathBuf>,
    pub tls_enabled: Option<bool>,
    pub tls_ca_cert: Option<PathBuf>,
}

impl Config {
    pub fn from_file(path: impl AsRef<std::path::Path>) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        toml::from_str(&content).map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }
}
