// TEE Attestation Service Policy Library - Policy validation
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides validation logic for TDX and SEV policies.

use super::types::Policy;
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

pub fn validate_policy(policy: &Policy) -> Result<Vec<ValidationError>> {
    let mut errors = Vec::new();
    match policy {
        Policy::Tdx(tdx) => {
            if tdx.key_id.is_empty() {
                errors.push(ValidationError {
                    field: "key_id".into(),
                    message: "must not be empty".into(),
                });
            }
            if tdx.tcb.is_none() && tdx.measurements.is_none() {
                errors.push(ValidationError {
                    field: "policy".into(),
                    message: "must have either TCB config or measurements".into(),
                });
            }
        }
        Policy::Sev(sev) => {
            if sev.key_id.is_empty() {
                errors.push(ValidationError {
                    field: "key_id".into(),
                    message: "must not be empty".into(),
                });
            }
            if let Some(vmpl) = sev.vmpl
                && vmpl > 3
            {
                errors.push(ValidationError {
                    field: "vmpl".into(),
                    message: format!("invalid value {}, expected 0-3", vmpl),
                });
            }
            if sev.tcb.is_none() && sev.measurement.is_none() {
                errors.push(ValidationError {
                    field: "policy".into(),
                    message: "must have either TCB config or measurement".into(),
                });
            }
        }
    }
    Ok(errors)
}
