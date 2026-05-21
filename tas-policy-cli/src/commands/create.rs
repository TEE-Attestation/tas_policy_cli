// TEE Attestation Service Policy CLI - Create command
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the create command for creating new TAS policies.

use crate::args::{CreateArgs, CvmTypeArg, GlobalOpts};
use crate::convert;
use log::info;
use tas_policy_lib::SignedPolicyEnvelope;
use zeroize::Zeroize;

/// Execute the `create` command.
pub fn execute(args: CreateArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    match args.cvm_type {
        CvmTypeArg::Tdx => execute_tdx(&args, global),
        CvmTypeArg::Sev => execute_sev(&args, global),
    }
}

/// Read the signing key passphrase from a file, if provided.
fn read_passphrase(path: &Option<std::path::PathBuf>) -> anyhow::Result<Option<String>> {
    match path {
        Some(p) => {
            let mut raw = std::fs::read_to_string(p).map_err(|e| {
                anyhow::anyhow!("failed to read passphrase from {}: {}", p.display(), e)
            })?;
            let trimmed = raw.trim().to_string();
            raw.zeroize();
            Ok(Some(trimmed))
        }
        None => Ok(None),
    }
}

fn execute_tdx(args: &CreateArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    info!("Creating TDX policy with config: {:?}", args);

    let config = convert::into_tdx_config(args);
    let policy = tas_policy_lib::TdxPolicy::from_config(config)?;

    let passphrase = read_passphrase(&args.signing_key_pass_file)?;
    let key =
        tas_policy_lib::SigningKey::from_file(args.signing_key.as_path(), passphrase.as_deref())?;

    if args.dry_run {
        // Dry-run: sign and print envelope locally, don't upload
        let mut envelope =
            SignedPolicyEnvelope::from_tdx(&policy, tas_policy_lib::PolicySignature::placeholder());
        tas_policy_lib::sign_envelope(&key, &mut envelope)?;
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(());
    }

    // Build client and let it handle signing + upload
    let client = convert::build_client(global)?;
    let result = client.create_policy(policy, &key)?;
    crate::output::maybe_show_deprecation(&result, global.verbose);
    println!("Policy created: {}", result.data.policy_key);

    Ok(())
}

fn execute_sev(args: &CreateArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    info!("Creating SEV policy with config: {:?}", args);

    let config = convert::into_sev_config(args)?;
    let policy = tas_policy_lib::SevPolicy::from_config(config)?;

    let passphrase = read_passphrase(&args.signing_key_pass_file)?;
    let key =
        tas_policy_lib::SigningKey::from_file(args.signing_key.as_path(), passphrase.as_deref())?;

    if args.dry_run {
        // Dry-run: sign and print envelope locally, don't upload
        let mut envelope =
            SignedPolicyEnvelope::from_sev(&policy, tas_policy_lib::PolicySignature::placeholder());
        tas_policy_lib::sign_envelope(&key, &mut envelope)?;
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(());
    }

    // Build client and let it handle signing + upload
    let client = convert::build_client(global)?;
    let result = client.create_policy(policy, &key)?;
    crate::output::maybe_show_deprecation(&result, global.verbose);
    println!("Policy created: {}", result.data.policy_key);

    Ok(())
}
