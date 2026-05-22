// TEE Attestation Service Policy CLI - Signing/upload helpers
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// Shared logic for building, signing, and uploading policy envelopes.

use std::path::PathBuf;

use tas_policy_lib::{Policy, PolicySignature, SignedPolicyEnvelope, SigningKey, sign_envelope};
use zeroize::Zeroize;

use crate::args::GlobalOpts;
use crate::convert;

/// Read the signing key passphrase from a file, if provided.
pub fn read_passphrase(path: &Option<PathBuf>) -> anyhow::Result<Option<String>> {
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

/// Load a signing key from the given path and optional passphrase file.
pub fn load_signing_key(
    key_path: &std::path::Path,
    pass_file: &Option<PathBuf>,
) -> anyhow::Result<SigningKey> {
    let passphrase = read_passphrase(pass_file)?;
    SigningKey::from_file(key_path, passphrase.as_deref())
        .map_err(|e| anyhow::anyhow!("Failed to load signing key: {}", e))
}

/// Build an envelope from a policy, optionally with a placeholder signature.
fn build_envelope(policy: &Policy, unsigned: bool) -> SignedPolicyEnvelope {
    let sig = if unsigned {
        None
    } else {
        Some(PolicySignature::placeholder())
    };
    match policy {
        Policy::Tdx(tdx) => SignedPolicyEnvelope::from_tdx(tdx, sig),
        Policy::Sev(sev) => SignedPolicyEnvelope::from_sev(sev, sig),
    }
}

/// Dry-run: print the policy envelope as JSON without uploading.
///
/// If `signing_key` is provided, the envelope is signed before printing.
/// If `None`, the envelope is printed unsigned.
pub fn dry_run(policy: &Policy, signing_key: Option<&SigningKey>) -> anyhow::Result<()> {
    let mut envelope = build_envelope(policy, signing_key.is_none());
    if let Some(key) = signing_key {
        sign_envelope(key, &mut envelope)?;
    }
    println!("{}", serde_json::to_string_pretty(&envelope)?);
    Ok(())
}

/// Upload a policy to TAS (signed or unsigned).
///
/// Returns the policy key on success.
pub fn upload(
    policy: Policy,
    signing_key: Option<&SigningKey>,
    global: &GlobalOpts,
) -> anyhow::Result<String> {
    let client = convert::build_client(global)?;
    let result = match policy {
        Policy::Tdx(tdx) => client.create_policy(*tdx, signing_key),
        Policy::Sev(sev) => client.create_policy(*sev, signing_key),
    }
    .map_err(|e| anyhow::anyhow!("Failed to create policy: {}", e))?;

    crate::output::maybe_show_deprecation(&result, global.verbose);
    Ok(result.data.policy_key)
}
