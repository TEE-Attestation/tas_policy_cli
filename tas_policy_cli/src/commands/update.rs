// TEE Attestation Service Policy CLI - Update command
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the update command for modifying existing TAS policies.
// Since TAS policies cannot be overwritten, an update deletes the existing
// policy and then creates a new one with the merged changes.

use crate::args::{GlobalOpts, UpdateArgs};
use crate::commands::signing;
use crate::convert;
use log::info;
use tas_policy_lib::Policy;

/// Execute the update command.
///
/// 1. Build a TAS client from global options.
/// 2. Fetch the existing policy identified by `--policy-id`.
/// 3. Determine the CVM type (TDX or SEV) from the fetched policy.
/// 4. Convert CLI overrides to the appropriate overrides struct.
/// 5. Merge overrides into the policy (validates measurement hex, etc.).
/// 6. If `--dry-run`, print the merged policy and exit.
/// 7. Otherwise, delete the existing policy and create a new one.
pub fn execute(args: UpdateArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    let client = convert::build_client(global)?;

    // Fetch existing policy (server returns envelope format, convert to domain model)
    info!("Fetching existing policy '{}'...", args.policy_id);
    let mut policy = client
        .get_policy(&args.policy_id)
        .and_then(|resp| resp.data.to_policy())
        .map_err(|e| anyhow::anyhow!("Failed to fetch policy '{}': {}", args.policy_id, e))?;

    // Validate: reject overrides that don't match the fetched policy's CVM type
    match &policy {
        Policy::Tdx(_) if args.overrides.has_sev_flags() => {
            anyhow::bail!(
                "Policy '{}' is TDX, but SEV-specific flags were provided \
                 (e.g. --measurement, --processor-family, --vmpl). \
                 Remove them and retry.",
                args.policy_id
            );
        }
        Policy::Sev(_) if args.overrides.has_tdx_flags() => {
            anyhow::bail!(
                "Policy '{}' is SEV, but TDX-specific flags were provided \
                 (e.g. --tcb-update, --mrtd, --platform-tcb). \
                 Remove them and retry.",
                args.policy_id
            );
        }
        _ => {}
    }

    // Apply overrides based on CVM type
    info!("Applying updates to policy '{}'...", args.policy_id);
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

    // Load signing key (None if --unsigned)
    let signing_key = if args.unsigned {
        None
    } else {
        let path = args
            .signing_key
            .as_ref()
            .expect("signing_key required when not unsigned");
        info!("Loading signing key from '{}'...", path.display());
        Some(signing::load_signing_key(
            path,
            &args.signing_key_pass_file,
        )?)
    };

    if args.dry_run {
        signing::dry_run(&policy, signing_key.as_ref())?;
        return Ok(());
    }

    // Delete the existing policy
    info!("Deleting existing policy '{}'...", args.policy_id);
    client
        .delete_policy(&args.policy_id)
        .map_err(|e| anyhow::anyhow!("Failed to delete policy '{}': {}", args.policy_id, e))?;

    // Create the updated policy
    info!("Creating updated policy '{}'...", args.policy_id);
    let policy_id = signing::upload(policy, signing_key.as_ref(), global)?;
    println!("Policy '{}' updated successfully.", policy_id);
    Ok(())
}
