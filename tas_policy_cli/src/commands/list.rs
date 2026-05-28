// TEE Attestation Service Policy CLI - List command
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the list command for listing TAS policies.

use crate::args::GlobalOpts;
use crate::convert;
use crate::output;
use clap::Args;
use log::info;
use tas_policy_lib::CvmType;
use tas_policy_lib::client::ListFilter;

/// Arguments for the `list` command.
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Filter by CVM type (TDX or SEV).
    #[arg(long)]
    pub filter_type: Option<String>,

    /// Filter by key-id prefix.
    #[arg(long)]
    pub key_id_prefix: Option<String>,

    /// Fetch and display the full policy for each result (N+1 HTTP calls).
    #[arg(long)]
    pub full: bool,
}

pub fn execute(args: ListArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    info!("Listing policies with filter: {:?}", args);
    let client = convert::build_client(global)?;

    // Parse optional CVM type filter.
    let cvm_type = args.filter_type.map(|s| s.parse::<CvmType>()).transpose()?;

    let filter = if cvm_type.is_some() || args.key_id_prefix.is_some() {
        Some(ListFilter {
            cvm_type,
            key_id_prefix: args.key_id_prefix,
        })
    } else {
        None
    };

    let resp = client.list_policies(filter)?;
    crate::output::maybe_show_deprecation(&resp, global.verbose);
    let summaries = resp.data;

    if summaries.is_empty() {
        println!("No policies found.");
        return Ok(());
    }

    if args.full {
        // Fetch the full policy for each summary.
        let mut policies = Vec::new();
        for summary in &summaries {
            let policy_resp = client.get_policy(&summary.policy_id)?;
            policies.push(policy_resp.data);
        }
        output::print_value(&policies, &global.output_format);
    } else {
        match global.output_format {
            output::OutputFormat::Json => {
                output::print_value(&summaries, &global.output_format);
            }
            output::OutputFormat::Human => {
                println!(
                    "{} polic{} found:\n",
                    summaries.len(),
                    if summaries.len() == 1 { "y" } else { "ies" }
                );
                for s in &summaries {
                    let cvm = s.cvm_type().map_or("???".into(), |c| c.to_string());
                    println!("  {} [{}]", s.policy_id, cvm);
                    if let Some(ref name) = s.name {
                        println!("    Name:    {}", name);
                    }
                    if let Some(ref ver) = s.version {
                        println!("    Version: {}", ver);
                    }
                    if let Some(ref desc) = s.description {
                        println!("    Desc:    {}", desc);
                    }
                    if s.signed {
                        println!("    Signed:  yes");
                    }
                    println!();
                }
            }
        }
    }

    Ok(())
}
