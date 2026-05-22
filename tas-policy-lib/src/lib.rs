// TEE Attestation Service (TAS) Policy Management Library
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//

//! # tas-policy-lib - TAS Policy Management Library
//!
//! This library provides types and client for creating, signing, and managing TEE attestation
//! policies for the [TEE Attestation Service (TAS)](https://github.com/TEE-Attestation/tas).
//! It includes support for various TEE technologies such as Intel TDX, AMD SEV, and general TCB
//! configurations. The library allows users to define policies, sign them with cryptographic keys,
//! and interact with the TAS Server API to manage these policies.
//!
//! The library uses a Hybrid Factory + Builder pattern for maximum ergonomics and safety:
//! Factory functions for common use cases (concise, hard to misuse)
//! Builder for complex/custom configurations (flexible, discoverable)
//! Config structs for serialization and bulk configuration
//!
//! # Quick Start - Factory Functions (Common Cases)
//! ```rust
//! use tas_policy_lib::{TasClient, TdxPolicy, SevPolicy, SigningKey, TcbConfig, SevTcbConfig};
//!
//! # fn main() -> Result<(), tas_policy_lib::Error> {
//! // TDX: TCB-only policy (no measurements) - using default TCB settings
//! let policy = TdxPolicy::tcb_only("my-key", TcbConfig::all_up_to_date());
//!
//! // TDX: With MRTD measurement (uses default TCB: all UpToDate, standard update)
//! let policy = TdxPolicy::with_mrtd("my-key", "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c700000000")?;
//!
//! // SEV: With measurement
//! let policy = SevPolicy::with_measurement("my-key", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2000000000000")?;
//!
//! // SEV: SVN-only (no measurement, all TCB_VERSION fields required)
//! let policy = SevPolicy::svn_only("my-key", SevTcbConfig::for_genoa(
//!     4,    // boot_loader_svn
//!     0,    // tee_svn
//!     20,   // snp_svn
//!     209,  // microcode_svn
//! ));
//!
//! // SEV: Turin processor (requires additional fields)
//! let policy = SevPolicy::svn_only("my-key", SevTcbConfig::for_turin(4, 0, 25, 215)
//!     .min_ucode_svn(10)
//!     .min_snp_iface_ver(2));
//! # Ok(())
//! # }
//! ```
//!
//! # Custom Policies - Builder Pattern
//! ```rust
//! use tas_policy_lib::{TdxPolicy, TcbStatus, TcbUpdate};
//!
//! # fn main() -> Result<(), tas_policy_lib::Error> {
//! // Complex TDX policy with multiple measurements and custom TCB
//! let policy = TdxPolicy::builder("my-key")
//!     .mrtd("b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c700000000")?
//!     .rtmr0("112233445566778899001122334455667788990011223344556677889900112233445566778899001122334400000000")?
//!     .rtmr1("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445500000000")?
//!     .platform_tcb(TcbStatus::UpToDate)
//!     .tdx_module_tcb(TcbStatus::UpToDate)
//!     .qe_tcb(TcbStatus::UpToDate)
//!     .tcb_update(TcbUpdate::Standard)
//!     .min_tee_tcb_svn(3)   // Optional: additional version check
//!     .name("Production TDX Policy")
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Full Example with Client
//! ```rust,no_run
//! use tas_policy_lib::{TasClient, TdxPolicy, SigningKey};
//!
//! fn main() -> Result<(), tas_policy_lib::Error> {
//!     let client = TasClient::builder()
//!         .host("tas.example.com")
//!         .api_key_file("/run/secrets/api_key")
//!         .build()?;
//!     
//!     let policy = TdxPolicy::with_mrtd("vm-123-key", "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c700000000")?;
//!     let key = SigningKey::from_file("/etc/tas/key.pem", None)?;
//!     
//!     let result = client.create_policy(policy, Some(&key))?;
//!     println!("Created: {}", result.data.policy_key);
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod config;
pub mod error;
pub mod policy;
pub mod signing;

pub use client::{
    ApiResponse, CheckResult, CheckStatus, DeprecationInfo, GetPolicyResponse, HealthCheckConfig,
    HealthReport, LinkEntry, TasClient, TasClientBuilder, diagnose_connection,
};
pub use config::Config;
pub use error::{Error, Result};
pub use policy::{
    CvmType, ExactMatchString, ExactMatchU8, MeasurementHash, MinValue, Policy, PolicyMetadata,
    PolicySignature, ProcessorFamily, SevConfig, SevCurrentTcb, SevOverrides, SevPlatformInfo,
    SevPolicy, SevPolicyBuilder, SevSecurityFlags, SevTcbConfig, SevValidationRules,
    SignedPolicyEnvelope, TcbConfig, TcbStatus, TcbUpdate, TdxBodyRules, TdxConfig,
    TdxMeasurements, TdxOverrides, TdxPolicy, TdxPolicyBuilder, TdxTcbRules, TdxValidationRules,
    ValidationError, ValidationRules,
};
pub use signing::{Signature, SigningKey, sign_envelope};
