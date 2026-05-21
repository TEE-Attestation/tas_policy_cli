// TEE Attestation Service Policy CLI - Update command
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the update command for modifying existing TAS policies.
// Since TAS policies cannot be overwritten, an update deletes the existing
// policy and then creates a new one with the merged changes.

use crate::args::{GlobalOpts, UpdateArgs};
use crate::convert;
use log::info;
use tas_policy_lib::{Policy, PolicySignature, SignedPolicyEnvelope, SigningKey, sign_envelope};
use zeroize::Zeroize;

/// Execute the update command.
///
/// 1. Build a TAS client from global options.
/// 2. Fetch the existing policy identified by `--policy-key`.
/// 3. Determine the CVM type (TDX or SEV) from the fetched policy.
/// 4. Convert CLI overrides to the appropriate overrides struct.
/// 5. Merge overrides into the policy (validates measurement hex, etc.).
/// 6. If `--dry-run`, print the merged policy and exit.
/// 7. Otherwise, delete the existing policy and create a new one.
pub fn execute(args: UpdateArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    let client = convert::build_client(global)?;

    // Fetch existing policy (server returns envelope format, convert to domain model)
    info!("Fetching existing policy '{}'...", args.policy_key);
    let mut policy = client
        .get_policy(&args.policy_key)
        .and_then(|resp| resp.data.to_policy())
        .map_err(|e| anyhow::anyhow!("Failed to fetch policy '{}': {}", args.policy_key, e))?;

    // Validate: reject overrides that don't match the fetched policy's CVM type
    match &policy {
        Policy::Tdx(_) if args.overrides.has_sev_flags() => {
            anyhow::bail!(
                "Policy '{}' is TDX, but SEV-specific flags were provided \
                 (e.g. --measurement, --processor-family, --vmpl). \
                 Remove them and retry.",
                args.policy_key
            );
        }
        Policy::Sev(_) if args.overrides.has_tdx_flags() => {
            anyhow::bail!(
                "Policy '{}' is SEV, but TDX-specific flags were provided \
                 (e.g. --tcb-update, --mrtd, --platform-tcb). \
                 Remove them and retry.",
                args.policy_key
            );
        }
        _ => {}
    }

    // Apply overrides based on CVM type
    info!("Applying updates to policy '{}'...", args.policy_key);
    match &mut policy {
        Policy::Tdx(tdx) => {
            let overrides = convert::into_tdx_overrides(&args.overrides);
            tdx.merge(overrides)
                .map_err(|e| anyhow::anyhow!("Failed to merge TDX overrides: {}", e))?;
        }
        Policy::Sev(sev) => {
            let overrides = convert::into_sev_overrides(&args.overrides);
            sev.merge(overrides)
                .map_err(|e| anyhow::anyhow!("Failed to merge SEV overrides: {}", e))?;
        }
    }

    // Load signing key
    info!(
        "Loading signing key from '{}'...",
        args.signing_key.display()
    );
    let mut pass_raw = args
        .signing_key_pass_file
        .as_ref()
        .map(std::fs::read_to_string)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Failed to read signing key passphrase file: {}", e))?;
    let password = pass_raw.as_deref().map(|s| s.trim());
    let signing_key = SigningKey::from_file(&args.signing_key, password)
        .map_err(|e| anyhow::anyhow!("Failed to load signing key: {}", e))?;
    if let Some(ref mut raw) = pass_raw {
        raw.zeroize();
    }

    // Dry-run: sign and print envelope locally, don't upload
    if args.dry_run {
        let mut envelope = match &policy {
            Policy::Tdx(tdx) => SignedPolicyEnvelope::from_tdx(tdx, PolicySignature::placeholder()),
            Policy::Sev(sev) => SignedPolicyEnvelope::from_sev(sev, PolicySignature::placeholder()),
        };
        sign_envelope(&signing_key, &mut envelope)?;
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(());
    }

    // Delete the existing policy
    info!("Deleting existing policy '{}'...", args.policy_key);
    client
        .delete_policy(&args.policy_key)
        .map_err(|e| anyhow::anyhow!("Failed to delete policy '{}': {}", args.policy_key, e))?;

    // Create the updated policy
    info!("Creating updated policy '{}'...", args.policy_key);
    let result = match policy {
        Policy::Tdx(tdx) => client
            .create_policy(*tdx, &signing_key)
            .map_err(|e| anyhow::anyhow!("Failed to create updated policy: {}", e))?,
        Policy::Sev(sev) => client
            .create_policy(*sev, &signing_key)
            .map_err(|e| anyhow::anyhow!("Failed to create updated policy: {}", e))?,
    };

    crate::output::maybe_show_deprecation(&result, global.verbose);
    println!("Policy '{}' updated successfully.", result.data.policy_key);
    Ok(())
}
