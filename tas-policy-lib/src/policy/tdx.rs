// TEE Attestation Service Policy Library - TDX policy
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides TDX-specific policy types, builders, and configuration.

use super::types::{MeasurementHash, PolicyMetadata};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// TDX-specific policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxPolicy {
    pub key_id: String,
    pub metadata: PolicyMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurements: Option<TdxMeasurements>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcb: Option<TcbConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_tee_tcb_svn: Option<u16>,
}

impl TdxPolicy {
    pub fn tcb_only(key_id: impl Into<String>, tcb: TcbConfig) -> Self {
        Self {
            key_id: key_id.into(),
            metadata: PolicyMetadata::default(),
            measurements: None,
            tcb: Some(tcb),
            min_tee_tcb_svn: None,
        }
    }

    pub fn with_mrtd(key_id: impl Into<String>, mrtd_hex: &str) -> Result<Self> {
        Ok(Self {
            key_id: key_id.into(),
            metadata: PolicyMetadata::default(),
            measurements: Some(TdxMeasurements {
                mrtd: Some(MeasurementHash::from_hex(mrtd_hex)?),
                ..Default::default()
            }),
            tcb: Some(TcbConfig::all_up_to_date()),
            min_tee_tcb_svn: None,
        })
    }

    pub fn from_config(config: TdxConfig) -> Result<Self> {
        let measurements = if config.tcb_only {
            None
        } else {
            let mut m = TdxMeasurements::default();
            if let Some(ref h) = config.mrtd {
                m.mrtd = Some(MeasurementHash::from_hex(h)?);
            }
            if let Some(ref h) = config.rtmr0 {
                m.rtmr0 = Some(MeasurementHash::from_hex(h)?);
            }
            if let Some(ref h) = config.rtmr1 {
                m.rtmr1 = Some(MeasurementHash::from_hex(h)?);
            }
            if let Some(ref h) = config.rtmr2 {
                m.rtmr2 = Some(MeasurementHash::from_hex(h)?);
            }
            if let Some(ref h) = config.rtmr3 {
                m.rtmr3 = Some(MeasurementHash::from_hex(h)?);
            }
            if let Some(ref h) = config.mrconfigid {
                m.mrconfigid = Some(MeasurementHash::from_hex(h)?);
            }
            if let Some(ref h) = config.mrowner {
                m.mrowner = Some(MeasurementHash::from_hex(h)?);
            }
            if let Some(ref h) = config.mrownerconfig {
                m.mrownerconfig = Some(MeasurementHash::from_hex(h)?);
            }
            if m.has_any() { Some(m) } else { None }
        };
        Ok(Self {
            key_id: config.key_id,
            metadata: PolicyMetadata {
                name: config.name,
                version: config.version,
                description: config.description,
                ..Default::default()
            },
            measurements,
            tcb: Some(TcbConfig::new(
                config.tcb_update,
                config.platform_tcb,
                config.tdx_module_tcb,
                config.qe_tcb,
            )),
            min_tee_tcb_svn: config.min_tee_tcb_svn,
        })
    }

    pub fn builder(key_id: impl Into<String>) -> TdxPolicyBuilder {
        TdxPolicyBuilder::new(key_id)
    }

    /// Merge overrides into this policy, replacing only the fields that are `Some`.
    ///
    /// Measurement hex strings are validated. TCB fields update the existing
    /// `TcbConfig` in place (creating one if absent).
    pub fn merge(&mut self, ov: TdxOverrides) -> Result<()> {
        // Metadata
        if let Some(n) = ov.name {
            self.metadata.name = n;
        }
        if let Some(d) = ov.description {
            self.metadata.description = Some(d);
        }

        // Measurements — apply each provided override
        let m = self
            .measurements
            .get_or_insert_with(TdxMeasurements::default);
        macro_rules! merge_hash {
            ($field:ident) => {
                if let Some(ref hex) = ov.$field {
                    m.$field = Some(MeasurementHash::from_hex(hex)?);
                }
            };
        }
        merge_hash!(mrtd);
        merge_hash!(rtmr0);
        merge_hash!(rtmr1);
        merge_hash!(rtmr2);
        merge_hash!(rtmr3);
        merge_hash!(mrconfigid);
        merge_hash!(mrowner);
        merge_hash!(mrownerconfig);

        // If no measurements remain after merge, set to None
        if !m.has_any() {
            self.measurements = None;
        }

        // TCB
        if ov.tcb_update.is_some()
            || ov.platform_tcb.is_some()
            || ov.tdx_module_tcb.is_some()
            || ov.qe_tcb.is_some()
        {
            let tcb = self.tcb.get_or_insert_with(TcbConfig::all_up_to_date);
            if let Some(u) = ov.tcb_update {
                tcb.update = u;
            }
            if let Some(s) = ov.platform_tcb {
                tcb.platform_tcb = s;
            }
            if let Some(s) = ov.tdx_module_tcb {
                tcb.tdx_module_tcb = s;
            }
            if let Some(s) = ov.qe_tcb {
                tcb.qe_tcb = s;
            }
        }

        if let Some(svn) = ov.min_tee_tcb_svn {
            self.min_tee_tcb_svn = Some(svn);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TdxConfig {
    pub key_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub mrtd: Option<String>,
    #[serde(default)]
    pub rtmr0: Option<String>,
    #[serde(default)]
    pub rtmr1: Option<String>,
    #[serde(default)]
    pub rtmr2: Option<String>,
    #[serde(default)]
    pub rtmr3: Option<String>,
    #[serde(default)]
    pub mrconfigid: Option<String>,
    #[serde(default)]
    pub mrowner: Option<String>,
    #[serde(default)]
    pub mrownerconfig: Option<String>,
    #[serde(default)]
    pub tcb_only: bool,
    #[serde(default)]
    pub tcb_update: TcbUpdate,
    #[serde(default)]
    pub platform_tcb: TcbStatus,
    #[serde(default)]
    pub tdx_module_tcb: TcbStatus,
    #[serde(default)]
    pub qe_tcb: TcbStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_tee_tcb_svn: Option<u16>,
}

impl TdxConfig {
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        serde_json::from_str(&content).map_err(|e| Error::Serialization(e.to_string()))
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TcbUpdate {
    #[default]
    Standard,
    Early,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum TcbStatus {
    #[default]
    UpToDate,
    OutOfDate,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TcbConfig {
    #[serde(default)]
    pub update: TcbUpdate,
    #[serde(default)]
    pub platform_tcb: TcbStatus,
    #[serde(default)]
    pub tdx_module_tcb: TcbStatus,
    #[serde(default)]
    pub qe_tcb: TcbStatus,
}

impl TcbConfig {
    pub fn all_up_to_date() -> Self {
        Self {
            update: TcbUpdate::Standard,
            platform_tcb: TcbStatus::UpToDate,
            tdx_module_tcb: TcbStatus::UpToDate,
            qe_tcb: TcbStatus::UpToDate,
        }
    }
    pub fn new(
        update: TcbUpdate,
        platform_tcb: TcbStatus,
        tdx_module_tcb: TcbStatus,
        qe_tcb: TcbStatus,
    ) -> Self {
        Self {
            update,
            platform_tcb,
            tdx_module_tcb,
            qe_tcb,
        }
    }
}

pub struct TdxPolicyBuilder {
    key_id: String,
    metadata: PolicyMetadata,
    measurements: TdxMeasurements,
    tcb: TcbConfig,
    min_tee_tcb_svn: Option<u16>,
    tcb_only: bool,
}

impl TdxPolicyBuilder {
    pub fn new(key_id: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            metadata: PolicyMetadata::default(),
            measurements: TdxMeasurements::default(),
            tcb: TcbConfig::all_up_to_date(),
            min_tee_tcb_svn: None,
            tcb_only: false,
        }
    }
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.metadata.name = name.into();
        self
    }
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.metadata.version = Some(version.into());
        self
    }
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.metadata.description = Some(desc.into());
        self
    }
    pub fn mrtd(mut self, hex: &str) -> Result<Self> {
        self.measurements.mrtd = Some(MeasurementHash::from_hex(hex)?);
        Ok(self)
    }
    pub fn rtmr0(mut self, hex: &str) -> Result<Self> {
        self.measurements.rtmr0 = Some(MeasurementHash::from_hex(hex)?);
        Ok(self)
    }
    pub fn rtmr1(mut self, hex: &str) -> Result<Self> {
        self.measurements.rtmr1 = Some(MeasurementHash::from_hex(hex)?);
        Ok(self)
    }
    pub fn rtmr2(mut self, hex: &str) -> Result<Self> {
        self.measurements.rtmr2 = Some(MeasurementHash::from_hex(hex)?);
        Ok(self)
    }
    pub fn rtmr3(mut self, hex: &str) -> Result<Self> {
        self.measurements.rtmr3 = Some(MeasurementHash::from_hex(hex)?);
        Ok(self)
    }
    pub fn mrconfigid(mut self, hex: &str) -> Result<Self> {
        self.measurements.mrconfigid = Some(MeasurementHash::from_hex(hex)?);
        Ok(self)
    }
    pub fn mrowner(mut self, hex: &str) -> Result<Self> {
        self.measurements.mrowner = Some(MeasurementHash::from_hex(hex)?);
        Ok(self)
    }
    pub fn mrownerconfig(mut self, hex: &str) -> Result<Self> {
        self.measurements.mrownerconfig = Some(MeasurementHash::from_hex(hex)?);
        Ok(self)
    }
    pub fn tcb_update(mut self, update: TcbUpdate) -> Self {
        self.tcb.update = update;
        self
    }
    pub fn platform_tcb(mut self, status: TcbStatus) -> Self {
        self.tcb.platform_tcb = status;
        self
    }
    pub fn tdx_module_tcb(mut self, status: TcbStatus) -> Self {
        self.tcb.tdx_module_tcb = status;
        self
    }
    pub fn qe_tcb(mut self, status: TcbStatus) -> Self {
        self.tcb.qe_tcb = status;
        self
    }
    pub fn tcb(mut self, tcb: TcbConfig) -> Self {
        self.tcb = tcb;
        self
    }
    pub fn min_tee_tcb_svn(mut self, svn: u16) -> Self {
        self.min_tee_tcb_svn = Some(svn);
        self
    }
    pub fn tcb_only(mut self) -> Self {
        self.tcb_only = true;
        self
    }

    pub fn build(self) -> Result<TdxPolicy> {
        let measurements = if self.tcb_only {
            None
        } else if self.measurements.has_any() {
            Some(self.measurements)
        } else {
            return Err(Error::InvalidPolicy(
                "at least one measurement is required unless --tcb-only is specified".into(),
            ));
        };

        Ok(TdxPolicy {
            key_id: self.key_id,
            metadata: self.metadata,
            measurements,
            tcb: Some(self.tcb),
            min_tee_tcb_svn: self.min_tee_tcb_svn,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TdxMeasurements {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mrtd: Option<MeasurementHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtmr0: Option<MeasurementHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtmr1: Option<MeasurementHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtmr2: Option<MeasurementHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtmr3: Option<MeasurementHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mrconfigid: Option<MeasurementHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mrowner: Option<MeasurementHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mrownerconfig: Option<MeasurementHash>,
}

impl TdxMeasurements {
    pub fn has_any(&self) -> bool {
        self.mrtd.is_some()
            || self.rtmr0.is_some()
            || self.rtmr1.is_some()
            || self.rtmr2.is_some()
            || self.rtmr3.is_some()
            || self.mrconfigid.is_some()
            || self.mrowner.is_some()
            || self.mrownerconfig.is_some()
    }
}

/// Overrides for selectively updating fields of an existing TdxPolicy.
///
/// Every field is `Option`: `None` means "keep existing", `Some(...)` means "replace".
#[derive(Debug, Clone, Default)]
pub struct TdxOverrides {
    pub name: Option<String>,
    pub description: Option<String>,
    // Measurements
    pub mrtd: Option<String>,
    pub rtmr0: Option<String>,
    pub rtmr1: Option<String>,
    pub rtmr2: Option<String>,
    pub rtmr3: Option<String>,
    pub mrconfigid: Option<String>,
    pub mrowner: Option<String>,
    pub mrownerconfig: Option<String>,
    // TCB
    pub tcb_update: Option<TcbUpdate>,
    pub platform_tcb: Option<TcbStatus>,
    pub tdx_module_tcb: Option<TcbStatus>,
    pub qe_tcb: Option<TcbStatus>,
    pub min_tee_tcb_svn: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_sample_tdx_config() {
        let config = TdxConfig::from_json_file("../samples/tdx_measurement.json")
            .expect("should parse sample TDX measurement file");
        assert_eq!(config.key_id, "test-tdx-policy-001");
        assert!(config.mrtd.is_some());
        assert_eq!(config.mrtd.as_ref().unwrap().len(), 96);

        // Verify it converts to a TdxPolicy
        let policy = TdxPolicy::from_config(config).expect("should build TdxPolicy from config");
        assert!(policy.measurements.is_some());
    }
    #[test]
    fn test_bad_config_mrtd_wrong_length() {
        // mrtd in bad file is 109 chars, not 96
        let config = TdxConfig::from_json_file("../samples/tdx_measurement_bad.json")
            .expect("JSON should parse (structure is valid)");
        let result = TdxPolicy::from_config(config);
        assert!(result.is_err(), "should reject mrtd with wrong length");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid hex") || err.contains("96"),
            "error should mention hex validation, got: {}",
            err
        );
    }

    #[test]
    fn test_bad_config_rtmr0_too_short() {
        // rtmr0 is only 10 chars
        let config = TdxConfig {
            key_id: "test-key".into(),
            rtmr0: Some("0001020304".into()), // 10 chars, need 96
            ..Default::default()
        };
        let result = TdxPolicy::from_config(config);
        assert!(result.is_err(), "should reject rtmr0 with wrong length");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("96") || err.contains("got 10"),
            "error should mention expected length, got: {}",
            err
        );
    }

    #[test]
    fn test_bad_config_non_hex_characters() {
        let config = TdxConfig {
            key_id: "test-key".into(),
            // 96 chars but contains non-hex 'Z' characters
            mrtd: Some("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".into()),
            ..Default::default()
        };
        let result = TdxPolicy::from_config(config);
        assert!(result.is_err(), "should reject non-hex characters");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid hex"),
            "error should mention invalid hex, got: {}",
            err
        );
    }

    #[test]
    fn test_bad_config_empty_key_id_validation() {
        // Empty key_id passes from_config but fails validate_policy
        let config = TdxConfig {
            key_id: "".into(),
            tcb_only: true, // skip measurements to isolate key_id check
            ..Default::default()
        };
        let policy = TdxPolicy::from_config(config)
            .expect("from_config should succeed (no measurement parsing)");

        use crate::policy::types::Policy;
        use crate::policy::validation::validate_policy;
        let errors = validate_policy(&Policy::Tdx(Box::new(policy))).unwrap();
        assert!(!errors.is_empty(), "validator should catch empty key_id");
        assert!(
            errors.iter().any(|e| e.field == "key_id"),
            "should have key_id error, got: {:?}",
            errors
        );
    }

    #[test]
    fn test_bad_config_no_measurements_no_tcb() {
        // A policy with no measurements AND no TCB should fail validation
        let policy = TdxPolicy {
            key_id: "some-key".into(),
            metadata: PolicyMetadata::default(),
            measurements: None,
            tcb: None,
            min_tee_tcb_svn: None,
        };

        use crate::policy::types::Policy;
        use crate::policy::validation::validate_policy;
        let errors = validate_policy(&Policy::Tdx(Box::new(policy))).unwrap();
        assert!(
            !errors.is_empty(),
            "validator should catch missing TCB and measurements"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("TCB") || e.message.contains("measurements")),
            "should mention TCB or measurements, got: {:?}",
            errors
        );
    }

    #[test]
    fn test_bad_config_empty_rtmr1() {
        let config = TdxConfig {
            key_id: "test-key".into(),
            rtmr1: Some("".into()), // empty string
            ..Default::default()
        };
        let result = TdxPolicy::from_config(config);
        assert!(result.is_err(), "should reject empty measurement hash");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("96") || err.contains("got 0"),
            "error should mention expected length, got: {}",
            err
        );
    }

    #[test]
    fn test_bad_json_structure() {
        // Completely invalid JSON should fail at deserialization
        let result = TdxConfig::from_json_file("../samples/tdx_measurement.json");
        assert!(result.is_ok(), "valid file should parse");

        // Non-existent file should fail with IO error
        let result = TdxConfig::from_json_file("../samples/nonexistent.json");
        assert!(result.is_err(), "missing file should fail");
    }
}
