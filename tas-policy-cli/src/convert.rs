// TEE Attestation Service Policy CLI - CLI-to-Library type mapping
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides conversion functions to map CLI argument types to library types.

use crate::args::{CreateArgs, PolicyOverrides, ProcessorFamilyArg, TcbStatusArg, TcbUpdateArg};
use tas_policy_lib::{
    ProcessorFamily, SevConfig, SevOverrides, TcbStatus, TcbUpdate, TdxConfig, TdxOverrides,
};

// =============================================================================
// Enum conversions
// =============================================================================

impl From<ProcessorFamilyArg> for ProcessorFamily {
    fn from(arg: ProcessorFamilyArg) -> Self {
        match arg {
            ProcessorFamilyArg::Milan => ProcessorFamily::Milan,
            ProcessorFamilyArg::Genoa => ProcessorFamily::Genoa,
            ProcessorFamilyArg::Turin => ProcessorFamily::Turin,
        }
    }
}

impl From<TcbUpdateArg> for TcbUpdate {
    fn from(arg: TcbUpdateArg) -> Self {
        match arg {
            TcbUpdateArg::Standard => TcbUpdate::Standard,
            TcbUpdateArg::Early => TcbUpdate::Early,
        }
    }
}

impl From<TcbStatusArg> for TcbStatus {
    fn from(arg: TcbStatusArg) -> Self {
        match arg {
            TcbStatusArg::UpToDate => TcbStatus::UpToDate,
            TcbStatusArg::OutOfDate => TcbStatus::OutOfDate,
            TcbStatusArg::Revoked => TcbStatus::Revoked,
        }
    }
}

// =============================================================================
// CreateArgs → TdxConfig / SevConfig
// =============================================================================

/// Extract a TdxConfig from the unified CreateArgs.
pub fn into_tdx_config(args: &CreateArgs) -> TdxConfig {
    TdxConfig {
        policy_id: args.policy_id.clone(),
        key_id: args.key_id.clone(),
        name: args.name.clone(),
        version: None,
        description: args.description.clone(),
        // Measurements
        mrtd: args.mrtd.clone(),
        rtmr0: args.rtmr0.clone(),
        rtmr1: args.rtmr1.clone(),
        rtmr2: args.rtmr2.clone(),
        rtmr3: args.rtmr3.clone(),
        mrconfigid: args.mrconfigid.clone(),
        mrowner: args.mrowner.clone(),
        mrownerconfig: args.mrownerconfig.clone(),
        // TCB
        tcb_only: args.tcb_only,
        tcb_update: args.tcb_update.clone().into(),
        platform_tcb: args.platform_tcb.clone().into(),
        tdx_module_tcb: args.tdx_module_tcb.clone().into(),
        qe_tcb: args.qe_tcb.clone().into(),
        min_tee_tcb_svn: args.min_tee_tcb_svn,
    }
}

/// Extract a SevConfig from the unified CreateArgs.
///
/// Returns an error string if required SEV fields are missing.
pub fn into_sev_config(args: &CreateArgs) -> anyhow::Result<SevConfig> {
    let processor_family: ProcessorFamily = args
        .processor_family
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--processor-family is required for SEV"))?
        .into();

    let defaults = processor_family.default_tcb();

    Ok(SevConfig {
        policy_id: args.policy_id.clone(),
        key_id: args.key_id.clone(),
        name: args.name.clone(),
        description: args.description.clone(),
        measurement: args.measurement.clone(),
        host_data: args.host_data.clone(),
        svn_only: args.svn_only,
        processor_family,
        min_boot_loader_svn: args
            .min_boot_loader_svn
            .unwrap_or(defaults.min_boot_loader_svn),
        min_tee_svn: args.min_tee_svn.unwrap_or(defaults.min_tee_svn),
        min_snp_svn: args.min_snp_svn.unwrap_or(defaults.min_snp_svn),
        min_microcode_svn: args.min_microcode_svn.unwrap_or(defaults.min_microcode_svn),
        min_ucode_svn: args.min_ucode_svn.or(defaults.min_ucode_svn),
        min_snp_iface_ver: args.min_snp_iface_ver.or(defaults.min_snp_iface_ver),
        vmpl: args.vmpl,
        debug_allowed: args.debug_allowed,
        migrate_ma_allowed: args.migrate_ma_allowed,
        smt_allowed: args.smt_allowed,
        ecc_enabled: args.ecc_enabled,
        tsme_enabled: args.tsme_enabled,
        alias_check_complete: args.alias_check_complete,
        smt_enabled: args.smt_enabled,
    })
}

// =============================================================================
// GlobalOpts → TasClient (builder pattern)
// =============================================================================

/// Build a `TasClient` from the global CLI options.
///
/// Uses the fluent builder API so each field is set explicitly,
/// giving clear error messages for missing required values.
pub fn build_client(global: &crate::args::GlobalOpts) -> anyhow::Result<tas_policy_lib::TasClient> {
    let mut builder = tas_policy_lib::TasClient::builder();

    if let Some(ref host) = global.tas_host {
        builder = builder.host(host);
    }
    if let Some(port) = global.tas_port {
        builder = builder.port(port);
    }
    if let Some(ref path) = global.api_key_file {
        builder = builder.api_key_file(path);
    }
    if global.no_tls {
        builder = builder.tls(false);
    } else if let Some(ref path) = global.tls_ca_cert {
        builder = builder.tls_ca_cert(path);
    }

    Ok(builder.build()?)
}

// =============================================================================
// PolicyOverrides → TdxOverrides / SevOverrides
// =============================================================================

/// Convert CLI overrides into a `TdxOverrides` suitable for `TdxPolicy::merge`.
pub fn into_tdx_overrides(ov: &PolicyOverrides) -> TdxOverrides {
    TdxOverrides {
        name: ov.name.clone(),
        description: ov.description.clone(),
        mrtd: ov.mrtd.clone(),
        rtmr0: ov.rtmr0.clone(),
        rtmr1: ov.rtmr1.clone(),
        rtmr2: ov.rtmr2.clone(),
        rtmr3: ov.rtmr3.clone(),
        mrconfigid: ov.mrconfigid.clone(),
        mrowner: ov.mrowner.clone(),
        mrownerconfig: ov.mrownerconfig.clone(),
        tcb_update: ov.tcb_update.clone().map(Into::into),
        platform_tcb: ov.platform_tcb.clone().map(Into::into),
        tdx_module_tcb: ov.tdx_module_tcb.clone().map(Into::into),
        qe_tcb: ov.qe_tcb.clone().map(Into::into),
        min_tee_tcb_svn: ov.min_tee_tcb_svn,
    }
}

/// Convert CLI overrides into a `SevOverrides` suitable for `SevPolicy::merge`.
pub fn into_sev_overrides(ov: &PolicyOverrides) -> SevOverrides {
    SevOverrides {
        name: ov.name.clone(),
        description: ov.description.clone(),
        measurement: ov.measurement.clone(),
        host_data: ov.host_data.clone(),
        processor_family: ov.processor_family.clone().map(Into::into),
        min_boot_loader_svn: ov.min_boot_loader_svn,
        min_tee_svn: ov.min_tee_svn,
        min_snp_svn: ov.min_snp_svn,
        min_microcode_svn: ov.min_microcode_svn,
        min_ucode_svn: ov.min_ucode_svn,
        min_snp_iface_ver: ov.min_snp_iface_ver,
        debug_allowed: ov.debug_allowed,
        migrate_ma_allowed: ov.migrate_ma_allowed,
        smt_allowed: ov.smt_allowed,
        vmpl: ov.vmpl,
        ecc_enabled: ov.ecc_enabled,
        tsme_enabled: ov.tsme_enabled,
        alias_check_complete: ov.alias_check_complete,
        smt_enabled: ov.smt_enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tas_policy_lib::{ProcessorFamily, TcbStatus, TcbUpdate};

    // =========================================================================
    // Enum From conversions
    // =========================================================================

    #[test]
    fn processor_family_milan() {
        let lib: ProcessorFamily = ProcessorFamilyArg::Milan.into();
        assert!(matches!(lib, ProcessorFamily::Milan));
    }

    #[test]
    fn processor_family_genoa() {
        let lib: ProcessorFamily = ProcessorFamilyArg::Genoa.into();
        assert!(matches!(lib, ProcessorFamily::Genoa));
    }

    #[test]
    fn processor_family_turin() {
        let lib: ProcessorFamily = ProcessorFamilyArg::Turin.into();
        assert!(matches!(lib, ProcessorFamily::Turin));
    }

    #[test]
    fn tcb_update_standard() {
        let lib: TcbUpdate = TcbUpdateArg::Standard.into();
        assert!(matches!(lib, TcbUpdate::Standard));
    }

    #[test]
    fn tcb_update_early() {
        let lib: TcbUpdate = TcbUpdateArg::Early.into();
        assert!(matches!(lib, TcbUpdate::Early));
    }

    #[test]
    fn tcb_status_up_to_date() {
        let lib: TcbStatus = TcbStatusArg::UpToDate.into();
        assert!(matches!(lib, TcbStatus::UpToDate));
    }

    #[test]
    fn tcb_status_out_of_date() {
        let lib: TcbStatus = TcbStatusArg::OutOfDate.into();
        assert!(matches!(lib, TcbStatus::OutOfDate));
    }

    #[test]
    fn tcb_status_revoked() {
        let lib: TcbStatus = TcbStatusArg::Revoked.into();
        assert!(matches!(lib, TcbStatus::Revoked));
    }
}
