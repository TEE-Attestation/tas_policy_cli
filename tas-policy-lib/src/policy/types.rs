// TEE Attestation Service Policy Library - Policy types
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides shared policy types including CvmType, Policy, and PolicyMetadata.

use super::sev::SevPolicy;
use super::tdx::TdxPolicy;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// CVM (Confidential Virtual Machine) type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CvmType {
    TDX,
    SEV,
}

impl std::fmt::Display for CvmType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CvmType::TDX => write!(f, "TDX"),
            CvmType::SEV => write!(f, "SEV"),
        }
    }
}

impl std::str::FromStr for CvmType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "TDX" => Ok(CvmType::TDX),
            "SEV" => Ok(CvmType::SEV),
            other => Err(Error::Configuration(format!(
                "unknown CVM type '{}', expected 'TDX' or 'SEV'",
                other
            ))),
        }
    }
}

/// A unified policy enum supporting both TDX and SEV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Policy {
    Tdx(Box<TdxPolicy>),
    Sev(Box<SevPolicy>),
}

impl Policy {
    pub fn cvm_type(&self) -> CvmType {
        match self {
            Policy::Tdx(_) => CvmType::TDX,
            Policy::Sev(_) => CvmType::SEV,
        }
    }

    pub fn key_id(&self) -> &str {
        match self {
            Policy::Tdx(p) => &p.key_id,
            Policy::Sev(p) => &p.key_id,
        }
    }

    pub fn policy_id(&self) -> &str {
        match self {
            Policy::Tdx(p) => &p.policy_id,
            Policy::Sev(p) => &p.policy_id,
        }
    }
}

impl From<TdxPolicy> for Policy {
    fn from(tdx: TdxPolicy) -> Policy {
        Policy::Tdx(Box::new(tdx))
    }
}

impl From<SevPolicy> for Policy {
    fn from(sev: SevPolicy) -> Policy {
        Policy::Sev(Box::new(sev))
    }
}

/// Policy metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyMetadata {
    #[serde(default)]
    pub policy_type: String,
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
}

/// A validated 48-byte measurement hash (384 bits).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MeasurementHash([u8; 48]);

impl MeasurementHash {
    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.trim();
        if hex.len() != 96 {
            return Err(Error::InvalidHex(format!(
                "expected 96 hex characters (48 bytes), got {}",
                hex.len()
            )));
        }
        let mut bytes = [0u8; 48];
        for i in 0..48 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| {
                Error::InvalidHex(format!("invalid hex at position {}: {}", i * 2, e))
            })?;
        }
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

impl TryFrom<String> for MeasurementHash {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::from_hex(&s)
    }
}

impl From<MeasurementHash> for String {
    fn from(h: MeasurementHash) -> String {
        h.to_hex()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvm_type_from_str_tdx() {
        assert_eq!("TDX".parse::<CvmType>().unwrap(), CvmType::TDX);
    }

    #[test]
    fn cvm_type_from_str_sev() {
        assert_eq!("SEV".parse::<CvmType>().unwrap(), CvmType::SEV);
    }

    #[test]
    fn cvm_type_from_str_case_insensitive() {
        assert_eq!("tdx".parse::<CvmType>().unwrap(), CvmType::TDX);
        assert_eq!("sev".parse::<CvmType>().unwrap(), CvmType::SEV);
        assert_eq!("Tdx".parse::<CvmType>().unwrap(), CvmType::TDX);
        assert_eq!("Sev".parse::<CvmType>().unwrap(), CvmType::SEV);
    }

    #[test]
    fn cvm_type_from_str_invalid() {
        assert!("INVALID".parse::<CvmType>().is_err());
    }

    #[test]
    fn cvm_type_from_str_empty() {
        assert!("".parse::<CvmType>().is_err());
    }
}
