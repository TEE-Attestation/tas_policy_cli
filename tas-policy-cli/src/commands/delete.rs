// TEE Attestation Service Policy CLI - Delete command
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the delete command for removing TAS policies.

use crate::args::GlobalOpts;
use crate::convert;
use crate::interactive;
use clap::Args;
use log::info;

#[derive(Args)]
pub struct DeleteArgs {
    #[arg(long)]
    pub policy_id: String,
}

pub fn execute(args: DeleteArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    let client = convert::build_client(global)?;

    if !interactive::confirm(
        &format!("Delete policy '{}'?", args.policy_id),
        global.non_interactive,
    ) {
        println!("Aborted.");
        return Ok(());
    }

    let resp = client.delete_policy(&args.policy_id)?;
    crate::output::maybe_show_deprecation(&resp, global.verbose);
    info!("Policy '{}' deleted.", args.policy_id);
    println!("Policy '{}' deleted successfully.", args.policy_id);
    Ok(())
}
