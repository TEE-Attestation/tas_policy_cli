// TEE Attestation Service Policy Library - Policy Signer
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// RSA-SHA384-PSS signing that matches the TAS server verification.
// See: https://github.com/TEE-Attestation/tas/blob/main/docs/POLICY.md
//
// Signing process (matching TAS server verification):
// 1. Collect all top-level policy fields except `signature`
// 2. Canonicalize using RFC 8785 (JSON Canonicalization Scheme / JCS)
// 3. Sign with RSA-PSS (SHA-384 hash, MGF1-SHA384, max salt length)
// 4. Base64-encode the signature

use rsa::pss::{BlindedSigningKey, Signature as PssSignature};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use sha2::Sha384;

use super::key_loader::SigningKey;
use crate::error::{Error, Result};
use crate::policy::signed::{PolicySignature, SignedPolicyEnvelope};

/// RSA-SHA384-PSS signature bytes.
#[derive(Debug, Clone)]
pub struct Signature {
    pub bytes: Vec<u8>,
}

impl Signature {
    /// Encode signature as base64 (standard encoding with padding).
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.bytes)
    }
}

/// Produce the canonical JSON bytes of a policy body for signing.
///
/// Matches the TAS server verification process:
/// 1. Serialize the policy body to a serde_json::Value
/// 2. Remove the `signature` key from the top-level object
/// 3. Canonicalize using RFC 8785 JCS
fn canonical_policy_bytes(envelope: &SignedPolicyEnvelope) -> Result<Vec<u8>> {
    let mut value =
        serde_json::to_value(envelope).map_err(|e| Error::Serialization(e.to_string()))?;

    // Remove the signature field — it is not part of the signed data
    if let serde_json::Value::Object(ref mut map) = value {
        map.remove("signature");
    }

    serde_jcs::to_vec(&value).map_err(|e| Error::Serialization(e.to_string()))
}

/// Sign a policy envelope in place — fills in the real signature.
///
/// Signs all top-level fields except `signature` using RFC 8785 JCS
/// canonicalization. This is the default TAS server behavior.
pub fn sign_envelope(key: &SigningKey, envelope: &mut SignedPolicyEnvelope) -> Result<()> {
    let data = canonical_policy_bytes(envelope)?;
    let signing_key = BlindedSigningKey::<Sha384>::new(key.private_key.clone());
    let mut rng = rsa::rand_core::OsRng;
    let pss_sig: PssSignature = signing_key.sign_with_rng(&mut rng, &data);

    let sig = Signature {
        bytes: pss_sig.to_vec(),
    };

    envelope.signature = PolicySignature {
        algorithm: "SHA384".to_string(),
        padding: "PSS".to_string(),
        value: sig.to_base64(),
    };

    Ok(())
}
