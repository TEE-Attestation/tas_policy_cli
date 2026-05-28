// TEE Attestation Service Policy Library - Signing module
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides key loading and policy signing functionality.

pub mod key_loader;
pub mod signer;

pub use key_loader::SigningKey;
pub use signer::{Signature, sign_envelope};
