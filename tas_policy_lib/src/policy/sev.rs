// TEE Attestation Service Policy Library - SEV policy
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides SEV-SNP specific policy types, builders, and configuration.

use super::types::{MeasurementHash, PolicyMetadata};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SevPlatformInfo {
    pub ecc_enabled: bool,
    pub tsme_enabled: bool,
    pub alias_check_complete: bool,
    pub smt_enabled: bool,
}

impl Default for SevPlatformInfo {
    fn default() -> Self {
        Self {
            ecc_enabled: true,
            tsme_enabled: true,
            alias_check_complete: true,
            smt_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SevPolicy {
    #[serde(default)]
    pub policy_id: String,
    pub key_id: String,
    pub metadata: PolicyMetadata,
    pub measurement: Option<MeasurementHash>,
    pub tcb: Option<SevTcbConfig>,
    pub policy_flags: Option<SevSecurityFlags>,
    pub vmpl: Option<u8>,
    pub host_data: Option<MeasurementHash>,
    pub platform_info: Option<SevPlatformInfo>,
}

impl SevPolicy {
    pub fn with_measurement(
        policy_id: impl Into<String>,
        key_id: impl Into<String>,
        measurement_hex: &str,
    ) -> Result<Self> {
        Ok(Self {
            policy_id: policy_id.into(),
            key_id: key_id.into(),
            metadata: PolicyMetadata::default(),
            measurement: Some(MeasurementHash::from_hex(measurement_hex)?),
            tcb: None,
            policy_flags: None,
            vmpl: Some(0),
            host_data: None,
            platform_info: Some(SevPlatformInfo::default()),
        })
    }

    pub fn svn_only(
        policy_id: impl Into<String>,
        key_id: impl Into<String>,
        tcb: SevTcbConfig,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            key_id: key_id.into(),
            metadata: PolicyMetadata::default(),
            measurement: None,
            tcb: Some(tcb),
            policy_flags: None,
            vmpl: None,
            host_data: None,
            platform_info: Some(SevPlatformInfo::default()),
        }
    }

    pub fn production(
        policy_id: impl Into<String>,
        key_id: impl Into<String>,
        measurement_hex: &str,
    ) -> Result<Self> {
        Ok(Self {
            policy_id: policy_id.into(),
            key_id: key_id.into(),
            metadata: PolicyMetadata::default(),
            measurement: Some(MeasurementHash::from_hex(measurement_hex)?),
            tcb: None,
            policy_flags: Some(SevSecurityFlags {
                debug_allowed: false,
                migrate_ma_allowed: false,
                smt_allowed: None,
            }),
            vmpl: Some(0),
            host_data: None,
            platform_info: Some(SevPlatformInfo::default()),
        })
    }

    pub fn from_config(config: SevConfig) -> Result<Self> {
        let measurement = config
            .measurement
            .as_deref()
            .map(MeasurementHash::from_hex)
            .transpose()?;
        let host_data = config
            .host_data
            .as_deref()
            .map(MeasurementHash::from_hex)
            .transpose()?;
        let tcb = SevTcbConfig {
            processor_family: config.processor_family,
            min_boot_loader_svn: config.min_boot_loader_svn,
            min_tee_svn: config.min_tee_svn,
            min_snp_svn: config.min_snp_svn,
            min_microcode_svn: config.min_microcode_svn,
            min_ucode_svn: config.min_ucode_svn,
            min_snp_iface_ver: config.min_snp_iface_ver,
        };
        let policy_flags = Some(SevSecurityFlags {
            debug_allowed: config.debug_allowed.unwrap_or(false),
            migrate_ma_allowed: config.migrate_ma_allowed.unwrap_or(false),
            smt_allowed: config.smt_allowed,
        });
        let platform_info = Some(SevPlatformInfo {
            ecc_enabled: config.ecc_enabled.unwrap_or(true),
            tsme_enabled: config.tsme_enabled.unwrap_or(true),
            alias_check_complete: config.alias_check_complete.unwrap_or(true),
            smt_enabled: config.smt_enabled.unwrap_or(true),
        });
        Ok(Self {
            policy_id: config.policy_id,
            key_id: config.key_id,
            metadata: PolicyMetadata {
                name: config.name,
                description: config.description,
                ..Default::default()
            },
            measurement,
            tcb: Some(tcb),
            policy_flags,
            vmpl: config.vmpl,
            host_data,
            platform_info,
        })
    }

    pub fn builder(policy_id: impl Into<String>, key_id: impl Into<String>) -> SevPolicyBuilder {
        SevPolicyBuilder::new(policy_id, key_id)
    }

    /// Merge overrides into this policy, replacing only the fields that are `Some`.
    pub fn merge(&mut self, ov: SevOverrides) -> Result<()> {
        // Metadata
        if let Some(n) = ov.name {
            self.metadata.name = n;
        }
        if let Some(d) = ov.description {
            self.metadata.description = Some(d);
        }

        // Measurement
        if let Some(ref hex) = ov.measurement {
            self.measurement = Some(MeasurementHash::from_hex(hex)?);
        }
        if let Some(ref hex) = ov.host_data {
            self.host_data = Some(MeasurementHash::from_hex(hex)?);
        }

        // TCB overrides
        if ov.processor_family.is_some()
            || ov.min_boot_loader_svn.is_some()
            || ov.min_tee_svn.is_some()
            || ov.min_snp_svn.is_some()
            || ov.min_microcode_svn.is_some()
            || ov.min_ucode_svn.is_some()
            || ov.min_snp_iface_ver.is_some()
        {
            let tcb = self.tcb.get_or_insert_with(SevTcbConfig::default);
            if let Some(f) = ov.processor_family {
                tcb.processor_family = f;
            }
            if let Some(v) = ov.min_boot_loader_svn {
                tcb.min_boot_loader_svn = v;
            }
            if let Some(v) = ov.min_tee_svn {
                tcb.min_tee_svn = v;
            }
            if let Some(v) = ov.min_snp_svn {
                tcb.min_snp_svn = v;
            }
            if let Some(v) = ov.min_microcode_svn {
                tcb.min_microcode_svn = v;
            }
            if let Some(v) = ov.min_ucode_svn {
                tcb.min_ucode_svn = Some(v);
            }
            if let Some(v) = ov.min_snp_iface_ver {
                tcb.min_snp_iface_ver = Some(v);
            }
        }

        // Security flags
        if ov.debug_allowed.is_some() || ov.migrate_ma_allowed.is_some() || ov.smt_allowed.is_some()
        {
            let flags = self
                .policy_flags
                .get_or_insert_with(SevSecurityFlags::default);
            if let Some(v) = ov.debug_allowed {
                flags.debug_allowed = v;
            }
            if let Some(v) = ov.migrate_ma_allowed {
                flags.migrate_ma_allowed = v;
            }
            if let Some(v) = ov.smt_allowed {
                flags.smt_allowed = Some(v);
            }
        }

        // Platform info
        if ov.ecc_enabled.is_some()
            || ov.tsme_enabled.is_some()
            || ov.alias_check_complete.is_some()
            || ov.smt_enabled.is_some()
        {
            let pi = self
                .platform_info
                .get_or_insert_with(SevPlatformInfo::default);
            if let Some(v) = ov.ecc_enabled {
                pi.ecc_enabled = v;
            }
            if let Some(v) = ov.tsme_enabled {
                pi.tsme_enabled = v;
            }
            if let Some(v) = ov.alias_check_complete {
                pi.alias_check_complete = v;
            }
            if let Some(v) = ov.smt_enabled {
                pi.smt_enabled = v;
            }
        }

        if let Some(v) = ov.vmpl {
            self.vmpl = Some(v);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SevConfig {
    #[serde(default)]
    pub policy_id: String,
    pub key_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub measurement: Option<String>,
    #[serde(default)]
    pub host_data: Option<String>,
    #[serde(default)]
    pub svn_only: bool,
    pub processor_family: ProcessorFamily,
    pub min_boot_loader_svn: u8,
    pub min_tee_svn: u8,
    pub min_snp_svn: u8,
    pub min_microcode_svn: u8,
    #[serde(default)]
    pub min_ucode_svn: Option<u8>,
    #[serde(default)]
    pub min_snp_iface_ver: Option<u8>,
    #[serde(default)]
    pub vmpl: Option<u8>,
    #[serde(default)]
    pub debug_allowed: Option<bool>,
    #[serde(default)]
    pub migrate_ma_allowed: Option<bool>,
    #[serde(default)]
    pub smt_allowed: Option<bool>,
    #[serde(default)]
    pub ecc_enabled: Option<bool>,
    #[serde(default)]
    pub tsme_enabled: Option<bool>,
    #[serde(default)]
    pub alias_check_complete: Option<bool>,
    #[serde(default)]
    pub smt_enabled: Option<bool>,
}

impl SevConfig {
    /// Load config from JSON file.
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        serde_json::from_str(&content).map_err(|e| Error::Serialization(e.to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessorFamily {
    Milan,
    #[default]
    Genoa,
    Turin,
}

impl ProcessorFamily {
    pub fn has_extended_tcb(&self) -> bool {
        matches!(self, Self::Turin)
    }

    /// Returns family-specific default TCB values.
    ///
    /// These are used when the user omits `--min-*-svn` flags on the CLI.
    /// Turin includes the extended fields (`min_ucode_svn`, `min_snp_iface_ver`).
    pub fn default_tcb(&self) -> SevTcbConfig {
        match self {
            Self::Milan => SevTcbConfig::new(*self, 1, 1, 1, 1),
            Self::Genoa => SevTcbConfig::new(*self, 12, 0, 28, 88),
            Self::Turin => SevTcbConfig::new(*self, 1, 1, 1, 1)
                .min_ucode_svn(1)
                .min_snp_iface_ver(1),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SevTcbConfig {
    #[serde(default)]
    pub processor_family: ProcessorFamily,
    pub min_boot_loader_svn: u8,
    pub min_tee_svn: u8,
    pub min_snp_svn: u8,
    pub min_microcode_svn: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_ucode_svn: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_snp_iface_ver: Option<u8>,
}

impl SevTcbConfig {
    pub fn new(family: ProcessorFamily, bl: u8, tee: u8, snp: u8, mc: u8) -> Self {
        Self {
            processor_family: family,
            min_boot_loader_svn: bl,
            min_tee_svn: tee,
            min_snp_svn: snp,
            min_microcode_svn: mc,
            min_ucode_svn: None,
            min_snp_iface_ver: None,
        }
    }
    pub fn min_ucode_svn(mut self, v: u8) -> Self {
        self.min_ucode_svn = Some(v);
        self
    }
    pub fn min_snp_iface_ver(mut self, v: u8) -> Self {
        self.min_snp_iface_ver = Some(v);
        self
    }
    pub fn for_milan(bl: u8, tee: u8, snp: u8, mc: u8) -> Self {
        Self::new(ProcessorFamily::Milan, bl, tee, snp, mc)
    }
    pub fn for_genoa(bl: u8, tee: u8, snp: u8, mc: u8) -> Self {
        Self::new(ProcessorFamily::Genoa, bl, tee, snp, mc)
    }
    pub fn for_turin(bl: u8, tee: u8, snp: u8, mc: u8) -> Self {
        Self::new(ProcessorFamily::Turin, bl, tee, snp, mc)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SevSecurityFlags {
    pub debug_allowed: bool,
    pub migrate_ma_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smt_allowed: Option<bool>,
}

pub struct SevPolicyBuilder {
    policy_id: String,
    key_id: String,
    metadata: PolicyMetadata,
    measurement: Option<MeasurementHash>,
    tcb: Option<SevTcbConfig>,
    policy_flags: Option<SevSecurityFlags>,
    vmpl: Option<u8>,
    host_data: Option<MeasurementHash>,
    platform_info: Option<SevPlatformInfo>,
    svn_only: bool,
}

impl SevPolicyBuilder {
    pub fn new(policy_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self {
            policy_id: policy_id.into(),
            key_id: key_id.into(),
            metadata: PolicyMetadata::default(),
            measurement: None,
            tcb: None,
            policy_flags: None,
            vmpl: None,
            host_data: None,
            platform_info: None,
            svn_only: false,
        }
    }
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.metadata.name = name.into();
        self
    }
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.metadata.description = Some(desc.into());
        self
    }
    pub fn measurement(mut self, hex: &str) -> Result<Self> {
        self.measurement = Some(MeasurementHash::from_hex(hex)?);
        Ok(self)
    }
    pub fn host_data(mut self, hex: &str) -> Result<Self> {
        self.host_data = Some(MeasurementHash::from_hex(hex)?);
        Ok(self)
    }
    pub fn tcb(mut self, tcb: SevTcbConfig) -> Self {
        self.tcb = Some(tcb);
        self
    }
    pub fn debug_allowed(mut self, allowed: bool) -> Self {
        self.policy_flags
            .get_or_insert_with(SevSecurityFlags::default)
            .debug_allowed = allowed;
        self
    }
    pub fn migrate_ma_allowed(mut self, allowed: bool) -> Self {
        self.policy_flags
            .get_or_insert_with(SevSecurityFlags::default)
            .migrate_ma_allowed = allowed;
        self
    }
    pub fn smt_allowed(mut self, allowed: bool) -> Self {
        self.policy_flags
            .get_or_insert_with(SevSecurityFlags::default)
            .smt_allowed = Some(allowed);
        self
    }
    pub fn vmpl(mut self, vmpl: u8) -> Self {
        self.vmpl = Some(vmpl);
        self
    }
    pub fn svn_only(mut self) -> Self {
        self.svn_only = true;
        self
    }

    pub fn build(self) -> Result<SevPolicy> {
        if !self.svn_only && self.measurement.is_none() {
            return Err(Error::InvalidPolicy(
                "measurement is required unless --svn-only is specified".into(),
            ));
        }
        Ok(SevPolicy {
            policy_id: self.policy_id,
            key_id: self.key_id,
            metadata: self.metadata,
            measurement: self.measurement,
            tcb: self.tcb,
            policy_flags: self.policy_flags,
            vmpl: self.vmpl,
            host_data: self.host_data,
            platform_info: self.platform_info,
        })
    }
}

/// Overrides for selectively updating fields of an existing SevPolicy.
///
/// Every field is `Option`: `None` means "keep existing", `Some(...)` means "replace".
#[derive(Debug, Clone, Default)]
pub struct SevOverrides {
    pub name: Option<String>,
    pub description: Option<String>,
    // Measurement
    pub measurement: Option<String>,
    pub host_data: Option<String>,
    // TCB
    pub processor_family: Option<ProcessorFamily>,
    pub min_boot_loader_svn: Option<u8>,
    pub min_tee_svn: Option<u8>,
    pub min_snp_svn: Option<u8>,
    pub min_microcode_svn: Option<u8>,
    pub min_ucode_svn: Option<u8>,
    pub min_snp_iface_ver: Option<u8>,
    // Security flags
    pub debug_allowed: Option<bool>,
    pub migrate_ma_allowed: Option<bool>,
    pub smt_allowed: Option<bool>,
    // Other
    pub vmpl: Option<u8>,
    // Platform info
    pub ecc_enabled: Option<bool>,
    pub tsme_enabled: Option<bool>,
    pub alias_check_complete: Option<bool>,
    pub smt_enabled: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Sample file tests (SEV equivalents of TDX sample file tests)
    // =========================================================================

    #[test]
    fn test_load_sample_sev_config() {
        let config = SevConfig::from_json_file("../samples/sev_measurement.json")
            .expect("should parse sample SEV measurement file");
        assert_eq!(config.key_id, "test-sev-policy-001");
        assert!(config.measurement.is_some());
        assert_eq!(config.measurement.as_ref().unwrap().len(), 96);

        // Verify it converts to a SevPolicy
        let policy = SevPolicy::from_config(config).expect("should build SevPolicy from config");
        assert!(policy.measurement.is_some());
    }

    #[test]
    fn test_bad_config_measurement_wrong_length() {
        // measurement in bad file is 109 chars, not 96
        let config = SevConfig::from_json_file("../samples/sev_measurement_bad.json")
            .expect("JSON should parse (structure is valid)");
        let result = SevPolicy::from_config(config);
        assert!(
            result.is_err(),
            "should reject measurement with wrong length"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid hex") || err.contains("96"),
            "error should mention hex validation, got: {}",
            err
        );
    }

    #[test]
    fn test_bad_config_measurement_too_short() {
        // measurement with only 10 characters (should be 96)
        let config = SevConfig {
            key_id: "test-key".into(),
            measurement: Some("0001020304".into()), // 10 chars, need 96
            ..Default::default()
        };
        let result = SevPolicy::from_config(config);
        assert!(
            result.is_err(),
            "should reject measurement with wrong length"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("96") || err.contains("got 10"),
            "error should mention expected length, got: {}",
            err
        );
    }

    #[test]
    fn test_bad_config_non_hex_characters() {
        let config = SevConfig {
            key_id: "test-key".into(),
            // 96 chars but contains non-hex 'Z' characters
            measurement: Some("Z".repeat(96)),
            ..Default::default()
        };
        let result = SevPolicy::from_config(config);
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
        let config = SevConfig {
            key_id: "".into(),
            svn_only: true, // skip measurement to isolate key_id check
            ..Default::default()
        };
        let policy = SevPolicy::from_config(config)
            .expect("from_config should succeed (no measurement parsing)");

        use crate::policy::types::Policy;
        use crate::policy::validation::validate_policy;
        let errors = validate_policy(&Policy::Sev(Box::new(policy))).unwrap();
        assert!(!errors.is_empty(), "validator should catch empty key_id");
        assert!(
            errors.iter().any(|e| e.field == "key_id"),
            "should have key_id error, got: {:?}",
            errors
        );
    }

    #[test]
    fn test_bad_config_no_measurement_no_tcb() {
        // A policy with no measurement AND no TCB should fail validation
        let policy = SevPolicy {
            policy_id: "test-policy".into(),
            key_id: "some-key".into(),
            metadata: PolicyMetadata::default(),
            measurement: None,
            tcb: None,
            policy_flags: None,
            vmpl: None,
            host_data: None,
            platform_info: None,
        };

        use crate::policy::types::Policy;
        use crate::policy::validation::validate_policy;
        let errors = validate_policy(&Policy::Sev(Box::new(policy))).unwrap();
        assert!(
            !errors.is_empty(),
            "validator should catch missing TCB and measurement"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("TCB") || e.message.contains("measurement")),
            "should mention TCB or measurement, got: {:?}",
            errors
        );
    }

    #[test]
    fn test_bad_config_empty_measurement() {
        let config = SevConfig {
            key_id: "test-key".into(),
            measurement: Some("".into()), // empty string
            ..Default::default()
        };
        let result = SevPolicy::from_config(config);
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
        // Valid file parses OK
        let result = SevConfig::from_json_file("../samples/sev_measurement.json");
        assert!(result.is_ok(), "valid file should parse");

        // Non-existent file should fail with IO error
        let result = SevConfig::from_json_file("../samples/nonexistent.json");
        assert!(result.is_err(), "missing file should fail");
    }

    // =========================================================================
    // SEV-specific negative tests (host_data, vmpl)
    // =========================================================================

    #[test]
    fn test_bad_config_host_data_too_short() {
        let config = SevConfig {
            key_id: "test-key".into(),
            measurement: Some("a".repeat(96)),
            host_data: Some("0001020304".into()), // 10 chars, need 96
            ..Default::default()
        };
        let result = SevPolicy::from_config(config);
        assert!(result.is_err(), "should reject host_data with wrong length");
    }

    #[test]
    fn test_bad_config_invalid_vmpl() {
        // VMPL > 3 should be caught by validation
        let m = "a".repeat(96);
        let policy = SevPolicy {
            policy_id: "test-policy".into(),
            key_id: "test-key".into(),
            metadata: PolicyMetadata::default(),
            measurement: Some(MeasurementHash::from_hex(&m).unwrap()),
            tcb: None,
            policy_flags: None,
            vmpl: Some(5),
            host_data: None,
            platform_info: None,
        };

        use crate::policy::types::Policy;
        use crate::policy::validation::validate_policy;
        let errors = validate_policy(&Policy::Sev(Box::new(policy))).unwrap();
        assert!(
            errors.iter().any(|e| e.field == "vmpl"),
            "expected 'vmpl' field error for value 5, got: {:?}",
            errors
        );
    }

    // =========================================================================
    // Default / struct tests (smt_allowed)
    // =========================================================================

    #[test]
    fn default_security_flags_omit_smt_allowed() {
        let flags = SevSecurityFlags::default();
        assert!(!flags.debug_allowed);
        assert!(!flags.migrate_ma_allowed);
        assert!(
            flags.smt_allowed.is_none(),
            "smt_allowed should be None by default"
        );
    }

    #[test]
    fn default_serialization_omits_smt_allowed() {
        let flags = SevSecurityFlags::default();
        let json = serde_json::to_string(&flags).expect("serialize");
        assert!(
            !json.contains("smt_allowed"),
            "default JSON should not contain smt_allowed, got: {json}"
        );
    }

    #[test]
    fn explicit_smt_allowed_serializes() {
        let flags = SevSecurityFlags {
            debug_allowed: false,
            migrate_ma_allowed: false,
            smt_allowed: Some(true),
        };
        let json = serde_json::to_string(&flags).expect("serialize");
        assert!(
            json.contains("\"smt_allowed\":true"),
            "JSON should contain smt_allowed when set, got: {json}"
        );
    }

    #[test]
    fn deserialize_without_smt_allowed() {
        let json = r#"{"debug_allowed":false,"migrate_ma_allowed":false}"#;
        let flags: SevSecurityFlags = serde_json::from_str(json).expect("deserialize");
        assert!(flags.smt_allowed.is_none());
    }

    #[test]
    fn deserialize_with_smt_allowed() {
        let json = r#"{"debug_allowed":false,"migrate_ma_allowed":false,"smt_allowed":true}"#;
        let flags: SevSecurityFlags = serde_json::from_str(json).expect("deserialize");
        assert_eq!(flags.smt_allowed, Some(true));
    }

    // =========================================================================
    // production() tests
    // =========================================================================

    #[test]
    fn production_policy_omits_smt_allowed() {
        let measurement = "a".repeat(96);
        let policy = SevPolicy::production("pol1", "key1", &measurement).expect("production");
        let flags = policy.policy_flags.expect("should have policy_flags");
        assert!(
            flags.smt_allowed.is_none(),
            "production default should not set smt_allowed"
        );
    }

    // =========================================================================
    // from_config() tests
    // =========================================================================

    #[test]
    fn from_config_without_smt_allowed() {
        let config = SevConfig {
            key_id: "test".into(),
            measurement: Some("a".repeat(96)),
            processor_family: ProcessorFamily::Genoa,
            ..Default::default()
        };
        let policy = SevPolicy::from_config(config).expect("from_config");
        let flags = policy.policy_flags.expect("should have policy_flags");
        assert!(
            flags.smt_allowed.is_none(),
            "smt_allowed should be None when not in config"
        );
    }

    #[test]
    fn from_config_with_smt_allowed_true() {
        let config = SevConfig {
            key_id: "test".into(),
            measurement: Some("a".repeat(96)),
            processor_family: ProcessorFamily::Genoa,
            smt_allowed: Some(true),
            ..Default::default()
        };
        let policy = SevPolicy::from_config(config).expect("from_config");
        let flags = policy.policy_flags.expect("should have policy_flags");
        assert_eq!(flags.smt_allowed, Some(true));
    }

    #[test]
    fn from_config_with_smt_allowed_false() {
        let config = SevConfig {
            key_id: "test".into(),
            measurement: Some("a".repeat(96)),
            processor_family: ProcessorFamily::Genoa,
            smt_allowed: Some(false),
            ..Default::default()
        };
        let policy = SevPolicy::from_config(config).expect("from_config");
        let flags = policy.policy_flags.expect("should have policy_flags");
        assert_eq!(flags.smt_allowed, Some(false));
    }

    // =========================================================================
    // Builder tests
    // =========================================================================

    #[test]
    fn builder_without_smt_allowed() {
        let policy = SevPolicy::builder("pol1", "key1")
            .svn_only()
            .build()
            .expect("build");
        assert!(policy.policy_flags.is_none(), "no flags set means None");
    }

    #[test]
    fn builder_sets_smt_allowed() {
        let policy = SevPolicy::builder("pol1", "key1")
            .svn_only()
            .smt_allowed(false)
            .build()
            .expect("build");
        let flags = policy.policy_flags.expect("should have policy_flags");
        assert_eq!(flags.smt_allowed, Some(false));
    }

    // =========================================================================
    // Merge tests
    // =========================================================================

    #[test]
    fn merge_applies_smt_allowed_override() {
        let measurement = "a".repeat(96);
        let mut policy = SevPolicy::production("pol1", "key1", &measurement).expect("production");
        assert!(policy.policy_flags.as_ref().unwrap().smt_allowed.is_none());

        let overrides = SevOverrides {
            smt_allowed: Some(false),
            ..Default::default()
        };
        policy.merge(overrides).expect("merge");
        assert_eq!(
            policy.policy_flags.as_ref().unwrap().smt_allowed,
            Some(false),
            "merge should set smt_allowed to Some(false)"
        );
    }

    #[test]
    fn merge_without_smt_override_preserves_none() {
        let measurement = "a".repeat(96);
        let mut policy = SevPolicy::production("pol1", "key1", &measurement).expect("production");
        assert!(policy.policy_flags.as_ref().unwrap().smt_allowed.is_none());

        let overrides = SevOverrides {
            debug_allowed: Some(true),
            ..Default::default()
        };
        policy.merge(overrides).expect("merge");
        assert!(
            policy.policy_flags.as_ref().unwrap().smt_allowed.is_none(),
            "merge without smt_allowed override should preserve None"
        );
    }
}
