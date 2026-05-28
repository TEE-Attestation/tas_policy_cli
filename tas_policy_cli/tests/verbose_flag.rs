// Tests for the -v / --verbose flag and env_logger integration.

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;

fn cmd() -> assert_cmd::Command {
    cargo_bin_cmd!("tas-policy")
}

// --- Flag acceptance ---------------------------------------------------------

#[test]
fn help_shows_verbose_flag() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("-v, --verbose"));
}

#[test]
fn short_v_flag_accepted_before_subcommand() {
    // -v is accepted; the command fails for missing --tas-host, not for flag parsing
    cmd()
        .args(["-v", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument").not());
}

#[test]
fn double_v_flag_accepted() {
    cmd()
        .args(["-vv", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument").not());
}

#[test]
fn long_verbose_flag_accepted() {
    cmd()
        .args(["--verbose", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument").not());
}

#[test]
fn verbose_flag_accepted_after_subcommand() {
    // global = true means -v works after the subcommand too
    cmd()
        .args(["list", "-v"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument").not());
}

// --- Log level behaviour -----------------------------------------------------

#[test]
fn default_verbosity_suppresses_info() {
    // Without -v, INFO messages should not appear in stderr
    let output = cmd().args(["list"]).output().expect("command runs");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("[INFO"),
        "INFO should be hidden at default verbosity, got: {stderr}"
    );
}

#[test]
fn single_v_does_not_crash() {
    // -v should not alter the exit behaviour vs no-flag (both fail for missing host)
    let without_v = cmd().args(["list"]).output().expect("command runs");

    let with_v = cmd().args(["-v", "list"]).output().expect("command runs");

    assert_eq!(without_v.status.code(), with_v.status.code());
}

// --- Version flag not shadowed -----------------------------------------------

#[test]
fn capital_v_still_shows_version() {
    // -V is clap's version flag; -v is verbose. They must coexist.
    cmd()
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains("tas-policy"));
}
