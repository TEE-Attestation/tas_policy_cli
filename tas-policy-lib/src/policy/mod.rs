// TEE Attestation Service Policy Library - Policy module
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides policy types and builders for TDX and SEV attestation policies.

pub mod sev;
pub mod signed;
pub mod tdx;
pub mod types;
pub mod validation;

pub use sev::{
    ProcessorFamily, SevConfig, SevOverrides, SevPlatformInfo, SevPolicy, SevPolicyBuilder,
    SevSecurityFlags, SevTcbConfig,
};
pub use tdx::{
    TcbConfig, TcbStatus, TcbUpdate, TdxConfig, TdxMeasurements, TdxOverrides, TdxPolicy,
    TdxPolicyBuilder,
};
pub use types::{CvmType, MeasurementHash, Policy, PolicyMetadata};
pub use validation::ValidationError;

pub use signed::{
    ExactMatchString, ExactMatchU8, MinValue, PolicySignature, SevCurrentTcb, SevValidationRules,
    SignedPolicyEnvelope, TdxBodyRules, TdxTcbRules, TdxValidationRules, ValidationRules,
};
