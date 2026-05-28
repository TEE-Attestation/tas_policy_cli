// TEE Attestation Service Policy CLI - Healthcheck command
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the healthcheck command for diagnosing connectivity
// to the TAS server. It performs layered checks (DNS, TCP, TLS, HTTP, Auth)
// and reports pass/fail with timing and actionable error details.

use crate::args::GlobalOpts;
use crate::output::OutputFormat;
use console::Style;
use tas_policy_lib::{CheckStatus, HealthCheckConfig, diagnose_connection};

pub fn execute(global: &GlobalOpts) -> anyhow::Result<()> {
    let host = global
        .tas_host
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--tas-host is required (or set TAS_HOST)"))?;

    let port = global.tas_port.unwrap_or(5001);
    let tls_enabled = !global.no_tls;

    // API key is optional for healthcheck — if absent, auth check is skipped
    let api_key = match global.api_key_file {
        Some(ref path) => {
            let key = std::fs::read_to_string(path).map_err(|e| {
                anyhow::anyhow!("failed to read API key from {}: {}", path.display(), e)
            })?;
            Some(key.trim().to_string())
        }
        None => None,
    };

    let config = HealthCheckConfig {
        host: host.to_string(),
        port,
        tls_enabled,
        tls_ca_cert: global.tls_ca_cert.clone(),
        api_key,
    };

    eprintln!("Checking connectivity to {}:{} ...\n", host, port);

    let report = diagnose_connection(&config);

    match global.output_format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
            );
        }
        OutputFormat::Human => {
            print_human(&report);
        }
    }

    if !report.healthy {
        std::process::exit(1);
    }

    Ok(())
}

fn print_human(report: &tas_policy_lib::HealthReport) {
    let pass_style = Style::new().green().bold();
    let fail_style = Style::new().red().bold();
    let skip_style = Style::new().yellow();
    let dim = Style::new().dim();

    for check in &report.checks {
        let (icon, style) = match check.status {
            CheckStatus::Pass => ("\u{2713}", &pass_style),
            CheckStatus::Fail => ("\u{2717}", &fail_style),
            CheckStatus::Skip => ("\u{2013}", &skip_style),
        };

        let latency = if check.latency_ms > 0 {
            format!("  {}ms", check.latency_ms)
        } else {
            String::new()
        };

        let detail = check
            .detail
            .as_deref()
            .map(|d| format!("  {}", dim.apply_to(d)))
            .unwrap_or_default();

        println!(
            " {} {}{}{}",
            style.apply_to(icon),
            style.apply_to(&check.name),
            dim.apply_to(latency),
            detail,
        );
    }

    println!();

    let passed = report
        .checks
        .iter()
        .filter(|c| c.status == CheckStatus::Pass)
        .count();
    let total = report.checks.len();

    if report.healthy {
        println!(
            "{}",
            pass_style.apply_to(format!("All checks passed ({}/{})", passed, total))
        );
    } else {
        let failed = report
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Fail)
            .count();
        println!(
            "{}",
            fail_style.apply_to(format!("{} of {} checks failed", failed, total))
        );
    }
}
