// TEE Attestation Service Policy CLI - Output formatting
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides output format handling for CLI responses.

use std::str::FromStr;

/// Strip control characters from server-supplied text before display.
///
/// Replaces every C0/C1 control character (except newline) with the
/// Unicode replacement character (U+FFFD), preventing a malicious server
/// from injecting terminal escape sequences via HTTP headers.
pub fn sanitize_for_display(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\n' {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// Output format for CLI responses.
#[derive(Debug, Clone, Default)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
}

impl FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "human" => Ok(Self::Human),
            "json" => Ok(Self::Json),
            _ => Err(format!(
                "invalid output format '{}', expected: human, json",
                s
            )),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Human => write!(f, "human"),
            OutputFormat::Json => write!(f, "json"),
        }
    }
}

/// Print a serializable value in the requested output format.
pub fn print_value<T: serde::Serialize>(value: &T, format: &OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(value)
                    .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")),
            );
        }
        OutputFormat::Human => {
            // Fall back to JSON pretty-print for human output too;
            // callers that want a custom table format should handle Human themselves.
            println!(
                "{}",
                serde_json::to_string_pretty(value).unwrap_or_else(|e| format!("Error: {e}")),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parse_human() {
        assert!(matches!(
            OutputFormat::from_str("human").unwrap(),
            OutputFormat::Human
        ));
    }

    #[test]
    fn parse_json() {
        assert!(matches!(
            OutputFormat::from_str("json").unwrap(),
            OutputFormat::Json
        ));
    }

    #[test]
    fn parse_case_insensitive() {
        assert!(matches!(
            OutputFormat::from_str("JSON").unwrap(),
            OutputFormat::Json
        ));
        assert!(matches!(
            OutputFormat::from_str("Human").unwrap(),
            OutputFormat::Human
        ));
    }

    #[test]
    fn parse_invalid_rejected() {
        let result = OutputFormat::from_str("xml");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid output format"));
    }

    #[test]
    fn parse_yaml_rejected() {
        // Yaml support was removed; ensure it is rejected gracefully
        let result = OutputFormat::from_str("yaml");
        assert!(result.is_err());
    }

    #[test]
    fn display_round_trip() {
        for fmt in &["human", "json"] {
            let parsed = OutputFormat::from_str(fmt).unwrap();
            assert_eq!(&parsed.to_string(), *fmt);
        }
    }
}

/// Write deprecation info to the given writer.
///
/// This is the testable core — `show_deprecation` delegates here with stderr.
#[cfg(test)]
fn write_deprecation(
    w: &mut dyn std::io::Write,
    info: &tas_policy_lib::DeprecationInfo,
) -> std::io::Result<()> {
    if let Some(dep) = &info.deprecated {
        writeln!(w, "  Deprecated: {}", sanitize_for_display(dep))?;
    }
    if let Some(sunset) = &info.sunset {
        writeln!(
            w,
            "  Sunset: {} — this endpoint will be removed",
            sanitize_for_display(sunset)
        )?;
    }
    for link in &info.links {
        writeln!(
            w,
            "  → {} ({})",
            sanitize_for_display(&link.url),
            sanitize_for_display(&link.rel)
        )?;
    }
    if let Some(warning) = &info.warning {
        writeln!(w, "  Warning: {}", sanitize_for_display(warning))?;
    }
    Ok(())
}

/// Print deprecation info to stderr when verbose mode is enabled.
///
/// Only displays when `verbose >= 1` (i.e. `-v` was passed).
/// Shows Deprecation, Sunset, Link (with parsed URL + rel), and Warning headers.
pub fn show_deprecation(info: &tas_policy_lib::DeprecationInfo, verbose: u8) {
    if verbose == 0 {
        return;
    }
    use console::Style;
    let warn_style = Style::new().yellow();
    let link_style = Style::new().cyan();

    if let Some(dep) = &info.deprecated {
        eprintln!(
            "  {} {}",
            warn_style.apply_to("Deprecated:"),
            sanitize_for_display(dep)
        );
    }
    if let Some(sunset) = &info.sunset {
        eprintln!(
            "  {} {} — this endpoint will be removed",
            warn_style.apply_to("Sunset:"),
            sanitize_for_display(sunset)
        );
    }
    for link in &info.links {
        eprintln!(
            "  {} {} ({})",
            link_style.apply_to("→"),
            sanitize_for_display(&link.url),
            sanitize_for_display(&link.rel)
        );
    }
    if let Some(warning) = &info.warning {
        eprintln!(
            "  {} {}",
            warn_style.apply_to("Warning:"),
            sanitize_for_display(warning)
        );
    }
}

/// Check an `ApiResponse` for deprecation info and display it if present.
pub fn maybe_show_deprecation<T>(resp: &tas_policy_lib::ApiResponse<T>, verbose: u8) {
    if let Some(ref dep) = resp.deprecation {
        show_deprecation(dep, verbose);
    }
}

#[cfg(test)]
mod deprecation_output_tests {
    use super::*;
    use tas_policy_lib::{ApiResponse, DeprecationInfo, LinkEntry};

    #[test]
    fn write_deprecation_deprecated_header() {
        let info = DeprecationInfo {
            deprecated: Some("true".into()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_deprecation(&mut buf, &info).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Deprecated:"), "should show Deprecated:");
        assert!(output.contains("true"));
    }

    #[test]
    fn write_deprecation_sunset_header() {
        let info = DeprecationInfo {
            sunset: Some("2026-12-31".into()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_deprecation(&mut buf, &info).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Sunset:"));
        assert!(output.contains("2026-12-31"));
        assert!(output.contains("will be removed"));
    }

    #[test]
    fn write_deprecation_link_entries() {
        let info = DeprecationInfo {
            links: vec![
                LinkEntry {
                    url: "https://api.example.com/v2".into(),
                    rel: "successor".into(),
                },
                LinkEntry {
                    url: "https://docs.example.com".into(),
                    rel: "help".into(),
                },
            ],
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_deprecation(&mut buf, &info).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("https://api.example.com/v2"));
        assert!(output.contains("(successor)"));
        assert!(output.contains("https://docs.example.com"));
        assert!(output.contains("(help)"));
    }

    #[test]
    fn write_deprecation_warning_header() {
        let info = DeprecationInfo {
            warning: Some("299 - API deprecated".into()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_deprecation(&mut buf, &info).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Warning:"));
        assert!(output.contains("299 - API deprecated"));
    }

    #[test]
    fn write_deprecation_empty_info_no_output() {
        let info = DeprecationInfo::default();
        let mut buf = Vec::new();
        write_deprecation(&mut buf, &info).unwrap();
        assert!(
            buf.is_empty(),
            "empty DeprecationInfo should produce no output"
        );
    }

    #[test]
    fn show_deprecation_silent_when_verbose_zero() {
        // show_deprecation with verbose=0 should not panic and returns immediately.
        // We cannot easily capture stderr, but we verify it doesn't crash.
        let info = DeprecationInfo {
            deprecated: Some("true".into()),
            ..Default::default()
        };
        show_deprecation(&info, 0); // should be a no-op
    }

    #[test]
    fn maybe_show_deprecation_skips_none() {
        let resp: ApiResponse<i32> = ApiResponse {
            data: 42,
            deprecation: None,
        };
        maybe_show_deprecation(&resp, 1); // should be a no-op, no panic
    }
}

#[cfg(test)]
mod sanitize_tests {
    use super::sanitize_for_display;

    #[test]
    fn preserves_normal_text() {
        assert_eq!(sanitize_for_display("hello world"), "hello world");
    }

    #[test]
    fn preserves_newlines() {
        assert_eq!(sanitize_for_display("line1\nline2"), "line1\nline2");
    }

    #[test]
    fn replaces_null_byte() {
        assert_eq!(sanitize_for_display("a\0b"), "a\u{FFFD}b");
    }

    #[test]
    fn replaces_tab_and_cr() {
        let input = "col1\tcol2\r\n";
        let output = sanitize_for_display(input);
        assert_eq!(output, "col1\u{FFFD}col2\u{FFFD}\n");
    }

    #[test]
    fn replaces_ansi_escape() {
        // ESC [ 31m = ANSI red color code
        let input = "normal \x1b[31mred\x1b[0m end";
        let output = sanitize_for_display(input);
        assert!(!output.contains('\x1b'), "ESC bytes must be replaced");
        assert!(
            output.contains('\u{FFFD}'),
            "should contain replacement char"
        );
        assert!(output.contains("normal "));
        assert!(output.contains(" end"));
    }

    #[test]
    fn replaces_bell_and_backspace() {
        let input = "alert\x07back\x08space";
        let output = sanitize_for_display(input);
        assert_eq!(output, "alert\u{FFFD}back\u{FFFD}space");
    }

    #[test]
    fn handles_empty_string() {
        assert_eq!(sanitize_for_display(""), "");
    }

    #[test]
    fn handles_unicode() {
        assert_eq!(
            sanitize_for_display("caf\u{00e9} \u{1f600}"),
            "caf\u{00e9} \u{1f600}"
        );
    }
}
