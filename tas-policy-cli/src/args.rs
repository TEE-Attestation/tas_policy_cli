// TEE Attestation Service Policy CLI - Argument definitions
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This file defines the CLI argument structs for the TEE Attestation Service Policy CLI.

use clap::{Args, ValueEnum};
use std::path::PathBuf;

/// Global options shared across all commands.
///
/// These are flattened into the top-level CLI struct and passed
/// to every command handler, avoiding duplication of connection
/// and output arguments in each subcommand.
#[derive(Args, Debug, Clone)]
pub struct GlobalOpts {
    /// Increase logging verbosity (-v info, -vv debug).
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// TAS server hostname or IP address.
    #[arg(long, global = true, env = "TAS_HOST")]
    pub tas_host: Option<String>,

    /// TAS server port (default: 5001).
    #[arg(long, global = true, env = "TAS_PORT")]
    pub tas_port: Option<u16>,

    /// Path to API key file.
    #[arg(long, global = true, env = "TAS_API_KEY_FILE")]
    pub api_key_file: Option<PathBuf>,

    /// Output format.
    #[arg(long, global = true, default_value = "human")]
    pub output_format: crate::output::OutputFormat,

    /// Disable TLS (use plain HTTP). Use when the TAS server does not support HTTPS.
    #[arg(long, global = true, env = "TAS_NO_TLS")]
    pub no_tls: bool,

    /// Path to a PEM-encoded CA certificate bundle for TLS.
    #[arg(long, global = true, env = "TAS_TLS_CA_CERT")]
    pub tls_ca_cert: Option<PathBuf>,

    /// Non-interactive mode (no prompts).
    #[arg(long, global = true)]
    pub non_interactive: bool,
}

/// Arguments for the `create` command (unified TDX + SEV).
///
/// Use `--cvm-type` to select the CVM type. TDX-specific and SEV-specific
/// flags are validated at runtime based on the selected CVM type.
#[derive(Args, Debug)]
pub struct CreateArgs {
    // =========================================================================
    // Common (required for both TDX and SEV)
    // =========================================================================
    /// Unique key identifier for this policy.
    #[arg(long)]
    pub key_id: String,

    /// CVM type: TDX or SEV.
    #[arg(long, value_enum)]
    pub cvm_type: CvmTypeArg,

    /// Path to signing key (PEM format). Required unless --unsigned is specified.
    #[arg(
        long,
        required_unless_present = "unsigned",
        conflicts_with = "unsigned"
    )]
    pub signing_key: Option<PathBuf>,

    /// Path to file containing signing key passphrase.
    #[arg(long, conflicts_with = "unsigned")]
    pub signing_key_pass_file: Option<PathBuf>,

    /// Create an unsigned policy (no signature field).
    #[arg(long, conflicts_with = "signing_key")]
    pub unsigned: bool,

    /// Human-readable policy name (required).
    #[arg(long)]
    pub name: String,

    /// Policy description.
    #[arg(long)]
    pub description: Option<String>,

    /// Preview policy without uploading.
    #[arg(long)]
    pub dry_run: bool,

    // =========================================================================
    // TDX: Measurements (96 hex characters each = 48 bytes)
    // =========================================================================
    /// MRTD: Build-time measurement of TD (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub mrtd: Option<String>,

    /// RTMR0: Firmware measurement register (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub rtmr0: Option<String>,

    /// RTMR1: OS/bootloader measurement register (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub rtmr1: Option<String>,

    /// RTMR2: Application measurement register (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub rtmr2: Option<String>,

    /// RTMR3: Runtime measurement register (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub rtmr3: Option<String>,

    /// Configuration ID measurement (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub mrconfigid: Option<String>,

    /// Owner measurement (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub mrowner: Option<String>,

    /// Owner configuration measurement (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub mrownerconfig: Option<String>,

    // =========================================================================
    // TDX: TCB Configuration
    // =========================================================================
    /// TCB-only mode (no measurements, fleet-wide policy). [TDX only]
    #[arg(long)]
    pub tcb_only: bool,

    /// TCB update policy. [TDX only] [default: standard]
    #[arg(long, value_enum, default_value = "standard")]
    pub tcb_update: TcbUpdateArg,

    /// Platform TCB status requirement. [TDX only] [default: up-to-date]
    #[arg(long, value_enum, default_value = "up-to-date")]
    pub platform_tcb: TcbStatusArg,

    /// TDX Module TCB status requirement. [TDX only] [default: up-to-date]
    #[arg(long, value_enum, default_value = "up-to-date")]
    pub tdx_module_tcb: TcbStatusArg,

    /// QE (Quoting Enclave) TCB status requirement. [TDX only] [default: up-to-date]
    #[arg(long, value_enum, default_value = "up-to-date")]
    pub qe_tcb: TcbStatusArg,

    /// Minimum TEE TCB SVN (optional additional version check). [TDX only]
    #[arg(long)]
    pub min_tee_tcb_svn: Option<u16>,

    // =========================================================================
    // SEV: Processor Family & TCB_VERSION
    // =========================================================================
    /// AMD processor family. [SEV only, REQUIRED for SEV]
    #[arg(long, value_enum)]
    pub processor_family: Option<ProcessorFamilyArg>,

    /// SVN-only mode (no measurement required). [SEV only]
    #[arg(long)]
    pub svn_only: bool,

    /// Minimum PSP Bootloader SVN - bits 7:0 of TCB_VERSION. [SEV only, REQUIRED]
    #[arg(long)]
    pub min_boot_loader_svn: Option<u8>,

    /// Minimum PSP OS (TEE) SVN - bits 15:8 of TCB_VERSION. [SEV only, REQUIRED]
    #[arg(long)]
    pub min_tee_svn: Option<u8>,

    /// Minimum SNP firmware SVN - bits 31:24 of TCB_VERSION. [SEV only, REQUIRED]
    #[arg(long)]
    pub min_snp_svn: Option<u8>,

    /// Minimum CPU microcode SVN - bits 39:32 of TCB_VERSION. [SEV only, REQUIRED]
    #[arg(long)]
    pub min_microcode_svn: Option<u8>,

    /// Minimum UCODE_SVN - bits 47:40 (REQUIRED for Turin/Zen5). [SEV only]
    #[arg(long)]
    pub min_ucode_svn: Option<u8>,

    /// Minimum SNP_IFACE_VER - bits 55:48 (REQUIRED for Turin/Zen5). [SEV only]
    #[arg(long)]
    pub min_snp_iface_ver: Option<u8>,

    // =========================================================================
    // SEV: Measurement & Policy Flags
    // =========================================================================
    /// Launch measurement (96 hex chars). [SEV only]
    #[arg(long, value_parser = validate_measurement)]
    pub measurement: Option<String>,

    /// Host-provided data hash (96 hex chars). [SEV only]
    #[arg(long, value_parser = validate_measurement)]
    pub host_data: Option<String>,

    /// Required VMPL level (0-3). [SEV only]
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=3))]
    pub vmpl: Option<u8>,

    /// Allow debugging. [SEV only]
    #[arg(long)]
    pub debug_allowed: Option<bool>,

    /// Allow migration. [SEV only]
    #[arg(long)]
    pub migrate_ma_allowed: Option<bool>,

    /// Allow SMT/hyperthreading. [SEV only]
    #[arg(long)]
    pub smt_allowed: Option<bool>,

    // =========================================================================
    // SEV: Platform Info
    // =========================================================================
    /// Require ECC memory on host platform. [SEV only]
    #[arg(long)]
    pub ecc_enabled: Option<bool>,

    /// Require TSME (Transparent SME) on host platform. [SEV only]
    #[arg(long)]
    pub tsme_enabled: Option<bool>,

    /// Require alias check completed by platform. [SEV only]
    #[arg(long)]
    pub alias_check_complete: Option<bool>,

    /// Require SMT enabled on host platform. [SEV only]
    #[arg(long)]
    pub smt_enabled: Option<bool>,
}

// =============================================================================
// CLI-side enums (mapped to library types in convert.rs)
// =============================================================================

/// CVM type selector.
#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
#[clap(rename_all = "UPPER")]
pub enum CvmTypeArg {
    /// Intel Trust Domain Extensions
    #[value(alias = "tdx")]
    Tdx,
    /// AMD Secure Encrypted Virtualization
    #[value(alias = "sev")]
    Sev,
}

/// Processor family enum for CLI.
#[derive(ValueEnum, Clone, Debug)]
pub enum ProcessorFamilyArg {
    /// AMD Milan (Zen 3) - EPYC 7003 series
    Milan,
    /// AMD Genoa (Zen 4) - EPYC 9004 series
    Genoa,
    /// AMD Turin (Zen 5) - EPYC 9005 series (extended TCB_VERSION)
    Turin,
}

/// TCB update policy for CLI.
#[derive(ValueEnum, Clone, Debug)]
pub enum TcbUpdateArg {
    Standard,
    Early,
}

/// TCB status for CLI.
#[derive(ValueEnum, Clone, Debug)]
pub enum TcbStatusArg {
    UpToDate,
    OutOfDate,
    Revoked,
}

fn validate_measurement(s: &str) -> Result<String, String> {
    if s.len() != 96 {
        return Err(format!(
            "Expected 96 hex characters (48 bytes), got {}",
            s.len()
        ));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid hex characters".into());
    }
    Ok(s.to_lowercase())
}

// =============================================================================
// Update command arguments
// =============================================================================

/// Overridable policy fields for the `update` command.
///
/// All fields are `Option`: only the ones the user passes on the
/// command line will be `Some(...)`. The rest stay `None` and the
/// original value in the fetched policy is preserved.
#[derive(Args, Debug, Default)]
pub struct PolicyOverrides {
    // =========================================================================
    // Metadata
    // =========================================================================
    /// New human-readable policy name.
    #[arg(long)]
    pub name: Option<String>,

    /// New policy description.
    #[arg(long)]
    pub description: Option<String>,

    // =========================================================================
    // TDX: Measurements (96 hex characters each = 48 bytes)
    // =========================================================================
    /// MRTD: Build-time measurement of TD (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub mrtd: Option<String>,

    /// RTMR0: Firmware measurement register (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub rtmr0: Option<String>,

    /// RTMR1: OS/bootloader measurement register (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub rtmr1: Option<String>,

    /// RTMR2: Application measurement register (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub rtmr2: Option<String>,

    /// RTMR3: Runtime measurement register (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub rtmr3: Option<String>,

    /// Configuration ID measurement (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub mrconfigid: Option<String>,

    /// Owner measurement (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub mrowner: Option<String>,

    /// Owner configuration measurement (96 hex chars). [TDX only]
    #[arg(long, value_parser = validate_measurement)]
    pub mrownerconfig: Option<String>,

    // =========================================================================
    // TDX: TCB Configuration
    // =========================================================================
    /// TCB update policy. [TDX only]
    #[arg(long, value_enum)]
    pub tcb_update: Option<TcbUpdateArg>,

    /// Platform TCB status requirement. [TDX only]
    #[arg(long, value_enum)]
    pub platform_tcb: Option<TcbStatusArg>,

    /// TDX Module TCB status requirement. [TDX only]
    #[arg(long, value_enum)]
    pub tdx_module_tcb: Option<TcbStatusArg>,

    /// QE (Quoting Enclave) TCB status requirement. [TDX only]
    #[arg(long, value_enum)]
    pub qe_tcb: Option<TcbStatusArg>,

    /// Minimum TEE TCB SVN (optional additional version check). [TDX only]
    #[arg(long)]
    pub min_tee_tcb_svn: Option<u16>,

    // =========================================================================
    // SEV: Processor Family & TCB_VERSION
    // =========================================================================
    /// AMD processor family. [SEV only]
    #[arg(long, value_enum)]
    pub processor_family: Option<ProcessorFamilyArg>,

    /// Minimum PSP Bootloader SVN. [SEV only]
    #[arg(long)]
    pub min_boot_loader_svn: Option<u8>,

    /// Minimum PSP OS (TEE) SVN. [SEV only]
    #[arg(long)]
    pub min_tee_svn: Option<u8>,

    /// Minimum SNP firmware SVN. [SEV only]
    #[arg(long)]
    pub min_snp_svn: Option<u8>,

    /// Minimum CPU microcode SVN. [SEV only]
    #[arg(long)]
    pub min_microcode_svn: Option<u8>,

    /// Minimum UCODE_SVN (REQUIRED for Turin/Zen5). [SEV only]
    #[arg(long)]
    pub min_ucode_svn: Option<u8>,

    /// Minimum SNP_IFACE_VER (REQUIRED for Turin/Zen5). [SEV only]
    #[arg(long)]
    pub min_snp_iface_ver: Option<u8>,

    // =========================================================================
    // SEV: Measurement & Policy Flags
    // =========================================================================
    /// Launch measurement (96 hex chars). [SEV only]
    #[arg(long, value_parser = validate_measurement)]
    pub measurement: Option<String>,

    /// Host-provided data hash (96 hex chars). [SEV only]
    #[arg(long, value_parser = validate_measurement)]
    pub host_data: Option<String>,

    /// Required VMPL level (0-3). [SEV only]
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=3))]
    pub vmpl: Option<u8>,

    /// Allow debugging. [SEV only]
    #[arg(long)]
    pub debug_allowed: Option<bool>,

    /// Allow migration. [SEV only]
    #[arg(long)]
    pub migrate_ma_allowed: Option<bool>,

    /// Allow SMT/hyperthreading. [SEV only]
    #[arg(long)]
    pub smt_allowed: Option<bool>,

    // =========================================================================
    // SEV: Platform Info
    // =========================================================================
    /// Require ECC memory on host platform. [SEV only]
    #[arg(long)]
    pub ecc_enabled: Option<bool>,

    /// Require TSME (Transparent SME) on host platform. [SEV only]
    #[arg(long)]
    pub tsme_enabled: Option<bool>,

    /// Require alias check completed by platform. [SEV only]
    #[arg(long)]
    pub alias_check_complete: Option<bool>,

    /// Require SMT enabled on host platform. [SEV only]
    #[arg(long)]
    pub smt_enabled: Option<bool>,
}

/// Arguments for the `update` command.
///
/// Fetches the existing policy identified by `--policy-key`, merges
/// any user-supplied overrides, then uploads the updated policy.
#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// The key identifying the policy to update.
    #[arg(long)]
    pub policy_key: String,

    /// Path to signing key (PEM format). Required unless --unsigned is specified.
    #[arg(
        long,
        required_unless_present = "unsigned",
        conflicts_with = "unsigned"
    )]
    pub signing_key: Option<std::path::PathBuf>,

    /// Path to file containing signing key passphrase.
    #[arg(long, conflicts_with = "unsigned")]
    pub signing_key_pass_file: Option<std::path::PathBuf>,

    /// Update as an unsigned policy (no signature field).
    #[arg(long, conflicts_with = "signing_key")]
    pub unsigned: bool,

    /// Preview the merged policy without uploading.
    #[arg(long)]
    pub dry_run: bool,

    /// Fields to override in the existing policy.
    #[command(flatten)]
    pub overrides: PolicyOverrides,
}

impl PolicyOverrides {
    /// Returns true if any TDX-specific override flags were set.
    pub fn has_tdx_flags(&self) -> bool {
        self.mrtd.is_some()
            || self.rtmr0.is_some()
            || self.rtmr1.is_some()
            || self.rtmr2.is_some()
            || self.rtmr3.is_some()
            || self.mrconfigid.is_some()
            || self.mrowner.is_some()
            || self.mrownerconfig.is_some()
            || self.tcb_update.is_some()
            || self.platform_tcb.is_some()
            || self.tdx_module_tcb.is_some()
            || self.qe_tcb.is_some()
            || self.min_tee_tcb_svn.is_some()
    }

    /// Returns true if any SEV-specific override flags were set.
    pub fn has_sev_flags(&self) -> bool {
        self.measurement.is_some()
            || self.host_data.is_some()
            || self.processor_family.is_some()
            || self.min_boot_loader_svn.is_some()
            || self.min_tee_svn.is_some()
            || self.min_snp_svn.is_some()
            || self.min_microcode_svn.is_some()
            || self.min_ucode_svn.is_some()
            || self.min_snp_iface_ver.is_some()
            || self.vmpl.is_some()
            || self.debug_allowed.is_some()
            || self.migrate_ma_allowed.is_some()
            || self.smt_allowed.is_some()
            || self.ecc_enabled.is_some()
            || self.tsme_enabled.is_some()
            || self.alias_check_complete.is_some()
            || self.smt_enabled.is_some()
    }
}
