// Tests for the `healthcheck` subcommand (CLI integration).

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;

fn cmd() -> assert_cmd::Command {
    cargo_bin_cmd!("tas-policy")
}

// ─── Subcommand acceptance ───────────────────────────────────────────────────

#[test]
fn healthcheck_subcommand_accepted() {
    // `healthcheck` is recognized; it fails because --tas-host is missing,
    // not because the subcommand is unknown.
    cmd()
        .arg("healthcheck")
        .assert()
        .failure()
        .stderr(predicate::str::contains("tas-host").or(predicate::str::contains("TAS_HOST")));
}

#[test]
fn healthcheck_requires_tas_host() {
    cmd()
        .arg("healthcheck")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--tas-host").or(predicate::str::contains("TAS_HOST")));
}

#[test]
fn healthcheck_help_text() {
    cmd()
        .args(["healthcheck", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("connectivity"));
}

#[test]
fn healthcheck_json_output_flag_accepted() {
    // --output-format json is accepted; it still fails for missing --tas-host
    cmd()
        .args(["--output-format", "json", "healthcheck"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown option").not());
}

#[test]
fn healthcheck_no_tls_flag_accepted() {
    // --no-tls is accepted alongside healthcheck
    cmd()
        .args(["--no-tls", "healthcheck"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown option").not());
}
