// TEE Attestation Service Policy CLI - Application entry point
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This file defines the CLI entry point and top-level command dispatch.

mod args;
mod commands;
mod convert;
mod interactive;
mod output;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "tas-policy",
    version = "0.0.1-alpha",
    about = "TAS Policy Management CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[command(flatten)]
    global: args::GlobalOpts,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Create a new attestation policy.
    Create(args::CreateArgs),
    /// Update an existing attestation policy.
    Update(args::UpdateArgs),
    /// Delete an attestation policy.
    Delete(commands::delete::DeleteArgs),
    /// List attestation policies.
    List(commands::list::ListArgs),
    /// Get details of an attestation policy.
    Get(commands::get::GetArgs),
    /// Check connectivity to the TAS server.
    Healthcheck,
}

fn main() {
    let cli = Cli::parse();

    let log_level = match cli.global.verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        _ => log::LevelFilter::Debug,
    };
    env_logger::Builder::new()
        .filter_level(log_level)
        .format(|buf, record| {
            use std::io::Write;
            let style = buf.default_level_style(record.level());
            writeln!(
                buf,
                "[{style}{:<5}{style:#}] {}",
                record.level(),
                record.args()
            )
        })
        .parse_default_env()
        .init();

    let result = match cli.command {
        Commands::Create(args) => commands::create::execute(args, &cli.global),
        Commands::Update(args) => commands::update::execute(args, &cli.global),
        Commands::Delete(args) => commands::delete::execute(args, &cli.global),
        Commands::List(args) => commands::list::execute(args, &cli.global),
        Commands::Get(args) => commands::get::execute(args, &cli.global),
        Commands::Healthcheck => commands::healthcheck::execute(&cli.global),
    };

    if let Err(e) = result {
        format_error(e.as_ref());
        std::process::exit(1);
    }
}

/// Display errors in a structured, user-friendly format.
fn format_error(e: &dyn std::error::Error) {
    eprintln!("\x1b[1;31merror:\x1b[0m {}", e);

    // Print the chain of causes indented, skipping duplicates
    let mut source = e.source();
    while let Some(cause) = source {
        let cause_msg = cause.to_string();
        // Skip if this cause message is already contained in the top-level message
        if !e.to_string().contains(&cause_msg) {
            eprintln!("  \x1b[1;33mcaused by:\x1b[0m {}", cause_msg);
        }
        source = cause.source();
    }
}
