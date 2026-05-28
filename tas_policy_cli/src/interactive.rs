// TEE Attestation Service Policy CLI - Interactive prompts
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides interactive confirmation prompts for CLI operations.

use dialoguer::Confirm;

pub fn confirm(message: &str, non_interactive: bool) -> bool {
    if non_interactive {
        return true;
    }
    Confirm::new()
        .with_prompt(message)
        .default(false)
        .interact()
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_interactive_always_confirms() {
        // In non-interactive mode, confirm() should return true without prompting
        assert!(confirm("Delete everything?", true));
    }

    #[test]
    fn non_interactive_ignores_message_content() {
        assert!(confirm("", true));
        assert!(confirm("Are you sure?", true));
    }
}
