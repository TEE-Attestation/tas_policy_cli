// TEE Attestation Service Policy Library - Signed policy envelope
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module defines the SignedPolicyEnvelope struct for TAS API policy registration.

// TEE Attestation Service Policy Library - Signed policy envelope
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module defines the SignedPolicyEnvelope struct for TAS API policy registration.

use serde::{Deserialize, Serialize};

use super::sev::{SevPlatformInfo, SevPolicy, SevSecurityFlags, SevTcbConfig};
use super::tdx::{TcbConfig, TcbStatus, TcbUpdate, TdxMeasurements, TdxPolicy};
use super::types::{MeasurementHash, PolicyMetadata};
use crate::error::Result;
use crate::signing::Signature;

// =============================================================================
// Envelope — the top-level registration payload sent to TAS
// =============================================================================

/// Signed policy envelope — the registration payload for the TAS API.
///
/// ```json
/// {
///   "metadata": { "policy_type": "SEV", "key_id": "my-secret-id", ... },
///   "validation_rules": {...},
///   "signature": {...}
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicyEnvelope {
    pub metadata: PolicyMetadata,
    pub validation_rules: ValidationRules,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<PolicySignature>,
}

// =============================================================================
// Validation rules — CVM-specific, untagged for clean JSON
// =============================================================================

/// Validation rules — either TDX or SEV flavored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ValidationRules {
    Tdx(Box<TdxValidationRules>),
    Sev(SevValidationRules),
}

// ---- TDX validation rules (matches tdx_example_policy.json) ----------------

/// TDX validation rules.
///
/// Spec uses `body` (not `measurements`) for register matching,
/// and `tcb` for TCB level requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TdxValidationRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcb: Option<TdxTcbRules>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<TdxBodyRules>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_tee_tcb_svn: Option<u16>,
}

/// TDX TCB rules — require specific TCB levels.
///
/// ```json
/// "tcb": { "update": "standard", "platform_tcb": "UpToDate", ... }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TdxTcbRules {
    #[serde(default)]
    pub update: String,
    #[serde(default)]
    pub platform_tcb: String,
    #[serde(default)]
    pub tdx_module_tcb: String,
    #[serde(default)]
    pub qe_tcb: String,
}

/// TDX body rules — measurement registers as `exact_match` rules.
///
/// ```json
/// "body": {
///   "mr_td": { "exact_match": "abcd1234" },
///   "rtmr0": { "exact_match": "efab5678" }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TdxBodyRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mr_td: Option<ExactMatchString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtmr0: Option<ExactMatchString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtmr1: Option<ExactMatchString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtmr2: Option<ExactMatchString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtmr3: Option<ExactMatchString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mrconfigid: Option<ExactMatchString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mrowner: Option<ExactMatchString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mrownerconfig: Option<ExactMatchString>,
}

// ---- SEV validation rules (matches sev_example_policy.json) ----------------

/// SEV validation rules.
///
/// Spec uses `current_tcb` (not `tcb`) with `min_value` wrappers per field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SevValidationRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement: Option<ExactMatchString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vmpl: Option<ExactMatchU8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<SevSecurityFlags>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_tcb: Option<SevCurrentTcb>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_tcb: Option<SevCurrentTcb>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_tcb: Option<SevCurrentTcb>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_data: Option<ExactMatchString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_info: Option<SevPlatformInfoRules>,
}

/// SEV current_tcb — uses `min_value` wrappers matching the spec.
///
/// ```json
/// "current_tcb": {
///   "bootloader": { "min_value": 9 },
///   "tee": { "min_value": 0 },
///   "snp": { "min_value": 15 },
///   "microcode": { "min_value": 72 }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SevCurrentTcb {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootloader: Option<MinValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tee: Option<MinValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snp: Option<MinValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub microcode: Option<MinValue>,
}

/// SEV platform info — uses `boolean` wrappers matching the TAS spec.
///
/// ```json
/// "platform_info": {
///   "ecc_enabled": { "boolean": true },
///   "tsme_enabled": { "boolean": true }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SevPlatformInfoRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_enabled: Option<BooleanMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsme_enabled: Option<BooleanMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias_check_complete: Option<BooleanMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smt_enabled: Option<BooleanMatch>,
}

// =============================================================================
// Validation rule wrappers (matching TAS spec § Validation Rule Types)
// =============================================================================

/// String exact match: `{ "exact_match": "hex..." }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExactMatchString {
    pub exact_match: String,
}

/// Numeric exact match: `{ "exact_match": N }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExactMatchU8 {
    pub exact_match: u8,
}

/// Numeric minimum value: `{ "min_value": N }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinValue {
    pub min_value: u8,
}

/// Boolean match wrapper for platform_info fields.
/// Serializes as `{ "boolean": true }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BooleanMatch {
    pub boolean: bool,
}

// =============================================================================
// Signature block
// =============================================================================

/// Cryptographic signature (POLICY.md § Signature Fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySignature {
    pub algorithm: String,
    pub padding: String,
    pub value: String,
}

impl PolicySignature {
    /// Create from a raw `Signature` (RSA-SHA384-PSS).
    pub fn from_signature(sig: &Signature) -> Self {
        Self {
            algorithm: "SHA384".to_string(),
            padding: "PSS".to_string(),
            value: sig.to_base64(),
        }
    }

    /// Create a placeholder for dry-run / preview.
    pub fn placeholder() -> Self {
        Self {
            algorithm: "SHA384".to_string(),
            padding: "PSS".to_string(),
            value: "<not-yet-signed>".to_string(),
        }
    }
}

// =============================================================================
// Conversions: TdxPolicy / SevPolicy → SignedPolicyEnvelope
// =============================================================================

impl SignedPolicyEnvelope {
    /// Wrap a TDX policy with a signature into the API envelope.
    pub fn from_tdx(policy: &TdxPolicy, signature: Option<PolicySignature>) -> Self {
        // Convert internal TdxMeasurements → TdxBodyRules (exact_match wrappers)
        let body = policy.measurements.as_ref().map(|m| {
            let to_em = |h: &super::types::MeasurementHash| ExactMatchString {
                exact_match: h.to_hex(),
            };
            TdxBodyRules {
                mr_td: m.mrtd.as_ref().map(to_em),
                rtmr0: m.rtmr0.as_ref().map(to_em),
                rtmr1: m.rtmr1.as_ref().map(to_em),
                rtmr2: m.rtmr2.as_ref().map(to_em),
                rtmr3: m.rtmr3.as_ref().map(to_em),
                mrconfigid: m.mrconfigid.as_ref().map(to_em),
                mrowner: m.mrowner.as_ref().map(to_em),
                mrownerconfig: m.mrownerconfig.as_ref().map(to_em),
            }
        });

        // Convert internal TcbConfig → TdxTcbRules (string values)
        let tcb = policy.tcb.as_ref().map(|t| TdxTcbRules {
            update: serde_json::to_value(t.update)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            platform_tcb: serde_json::to_value(t.platform_tcb)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            tdx_module_tcb: serde_json::to_value(t.tdx_module_tcb)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            qe_tcb: serde_json::to_value(t.qe_tcb)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
        });

        Self {
            metadata: PolicyMetadata {
                policy_type: "TDX".to_string(),
                key_id: policy.key_id.clone(),
                ..policy.metadata.clone()
            },
            validation_rules: ValidationRules::Tdx(Box::new(TdxValidationRules {
                tcb,
                body,
                min_tee_tcb_svn: policy.min_tee_tcb_svn,
            })),
            signature,
        }
    }

    /// Wrap a SEV policy with a signature into the API envelope.
    pub fn from_sev(policy: &SevPolicy, signature: Option<PolicySignature>) -> Self {
        // Convert internal SevTcbConfig → SevCurrentTcb (min_value wrappers)
        let current_tcb = policy.tcb.as_ref().map(|t| SevCurrentTcb {
            bootloader: Some(MinValue {
                min_value: t.min_boot_loader_svn,
            }),
            tee: Some(MinValue {
                min_value: t.min_tee_svn,
            }),
            snp: Some(MinValue {
                min_value: t.min_snp_svn,
            }),
            microcode: Some(MinValue {
                min_value: t.min_microcode_svn,
            }),
        });

        Self {
            metadata: PolicyMetadata {
                policy_type: "SEV".to_string(),
                key_id: policy.key_id.clone(),
                ..policy.metadata.clone()
            },
            validation_rules: ValidationRules::Sev(SevValidationRules {
                measurement: policy.measurement.as_ref().map(|m| ExactMatchString {
                    exact_match: m.to_hex(),
                }),
                vmpl: policy.vmpl.map(|v| ExactMatchU8 { exact_match: v }),
                policy: policy.policy_flags.clone(),
                committed_tcb: current_tcb.clone(),
                launch_tcb: current_tcb.clone(),
                current_tcb,
                host_data: policy.host_data.as_ref().map(|m| ExactMatchString {
                    exact_match: m.to_hex(),
                }),
                platform_info: policy
                    .platform_info
                    .as_ref()
                    .map(|pi| SevPlatformInfoRules {
                        ecc_enabled: Some(BooleanMatch {
                            boolean: pi.ecc_enabled,
                        }),
                        tsme_enabled: Some(BooleanMatch {
                            boolean: pi.tsme_enabled,
                        }),
                        alias_check_complete: Some(BooleanMatch {
                            boolean: pi.alias_check_complete,
                        }),
                        smt_enabled: Some(BooleanMatch {
                            boolean: pi.smt_enabled,
                        }),
                    }),
            }),
            signature,
        }
    }

    /// Create a preview envelope (unsigned) for dry-run.
    pub fn preview_tdx(policy: &TdxPolicy) -> Self {
        Self::from_tdx(policy, Some(PolicySignature::placeholder()))
    }

    /// Create a preview envelope (unsigned) for dry-run.
    pub fn preview_sev(policy: &SevPolicy) -> Self {
        Self::from_sev(policy, Some(PolicySignature::placeholder()))
    }

    /// Convert a signed policy envelope back into a `Policy`.
    ///
    /// This is the reverse of `from_tdx` / `from_sev`, used when fetching
    /// a policy from the TAS server (which returns the envelope format).
    pub fn to_policy(&self) -> Result<super::types::Policy> {
        let key_id = self.metadata.key_id.clone();
        match &self.validation_rules {
            ValidationRules::Tdx(tdx_rules) => {
                // Convert TdxBodyRules -> TdxMeasurements
                let measurements = tdx_rules.body.as_ref().and_then(|body| {
                    let parse = |em: &Option<ExactMatchString>| -> Option<MeasurementHash> {
                        em.as_ref()
                            .and_then(|e| MeasurementHash::from_hex(&e.exact_match).ok())
                    };
                    let m = TdxMeasurements {
                        mrtd: parse(&body.mr_td),
                        rtmr0: parse(&body.rtmr0),
                        rtmr1: parse(&body.rtmr1),
                        rtmr2: parse(&body.rtmr2),
                        rtmr3: parse(&body.rtmr3),
                        mrconfigid: parse(&body.mrconfigid),
                        mrowner: parse(&body.mrowner),
                        mrownerconfig: parse(&body.mrownerconfig),
                    };
                    if m.has_any() { Some(m) } else { None }
                });

                // Convert TdxTcbRules -> TcbConfig
                let tcb = tdx_rules.tcb.as_ref().map(|t| {
                    let update: TcbUpdate =
                        serde_json::from_value(serde_json::Value::String(t.update.clone()))
                            .unwrap_or_default();
                    let platform_tcb: TcbStatus =
                        serde_json::from_value(serde_json::Value::String(t.platform_tcb.clone()))
                            .unwrap_or_default();
                    let tdx_module_tcb: TcbStatus =
                        serde_json::from_value(serde_json::Value::String(t.tdx_module_tcb.clone()))
                            .unwrap_or_default();
                    let qe_tcb: TcbStatus =
                        serde_json::from_value(serde_json::Value::String(t.qe_tcb.clone()))
                            .unwrap_or_default();
                    TcbConfig::new(update, platform_tcb, tdx_module_tcb, qe_tcb)
                });

                Ok(super::types::Policy::Tdx(Box::new(TdxPolicy {
                    key_id,
                    metadata: self.metadata.clone(),
                    measurements,
                    tcb,
                    min_tee_tcb_svn: tdx_rules.min_tee_tcb_svn,
                })))
            }
            ValidationRules::Sev(sev_rules) => {
                // Convert ExactMatchString -> MeasurementHash
                let measurement = sev_rules
                    .measurement
                    .as_ref()
                    .and_then(|em| MeasurementHash::from_hex(&em.exact_match).ok());
                let host_data = sev_rules
                    .host_data
                    .as_ref()
                    .and_then(|em| MeasurementHash::from_hex(&em.exact_match).ok());

                // Convert SevCurrentTcb -> SevTcbConfig (prefer committed_tcb, fall back to launch_tcb/current_tcb)
                let tcb = sev_rules
                    .committed_tcb
                    .as_ref()
                    .or(sev_rules.launch_tcb.as_ref())
                    .or(sev_rules.current_tcb.as_ref())
                    .map(|t| SevTcbConfig {
                        processor_family: Default::default(),
                        min_boot_loader_svn: t.bootloader.as_ref().map_or(0, |v| v.min_value),
                        min_tee_svn: t.tee.as_ref().map_or(0, |v| v.min_value),
                        min_snp_svn: t.snp.as_ref().map_or(0, |v| v.min_value),
                        min_microcode_svn: t.microcode.as_ref().map_or(0, |v| v.min_value),
                        min_ucode_svn: None,
                        min_snp_iface_ver: None,
                    });

                Ok(super::types::Policy::Sev(Box::new(SevPolicy {
                    key_id,
                    metadata: self.metadata.clone(),
                    measurement,
                    tcb,
                    policy_flags: sev_rules.policy.clone(),
                    vmpl: sev_rules.vmpl.as_ref().map(|v| v.exact_match),
                    host_data,
                    platform_info: sev_rules.platform_info.as_ref().map(|pi| SevPlatformInfo {
                        ecc_enabled: pi.ecc_enabled.as_ref().is_none_or(|b| b.boolean),
                        tsme_enabled: pi.tsme_enabled.as_ref().is_none_or(|b| b.boolean),
                        alias_check_complete: pi
                            .alias_check_complete
                            .as_ref()
                            .is_some_and(|b| b.boolean),
                        smt_enabled: pi.smt_enabled.as_ref().is_none_or(|b| b.boolean),
                    }),
                })))
            }
        }
    }
}
