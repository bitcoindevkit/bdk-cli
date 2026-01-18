// Copyright (c) 2020-2025 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Compile Command Tests
//!
//! Tests for compile command and subcommands

use std::process::Command;

fn run_cmd(cmd: &str) -> Result<String, String> {
    let full_cmd = format!("run --features compiler -- {}", cmd);
    let args = shlex::split(&full_cmd).unwrap();

    let output = Command::new("cargo")
        .args(args)
        .env_remove("NETWORK")
        .env_remove("DATADIR")
        .env_remove("POLICY")
        .env_remove("TYPE")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(stdout)
    } else {
        Err(stderr)
    }
}

#[test]
fn test_compile_taproot() {
    let stdout = run_cmd(r#"compile "pk(ABC)" -t tr"#).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert!(json.get("descriptor").is_some());
    assert!(json.get("r").is_some());
}

#[test]
fn test_compile_sh() {
    let stdout = run_cmd(r#"compile "pk(ABC)" -t sh"#).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert!(json.get("descriptor").is_some());
    assert!(json.get("r").is_none());
}

#[test]
fn test_invalid_cases() {
    // Test invalid policy syntax
    let stderr = run_cmd(r#"compile "invalid_policy""#).unwrap_err();
    assert!(stderr.contains("Miniscript error"));

    // Test invalid script type
    let stderr = run_cmd(r#"compile "pk(A)" -t invalid_type"#).unwrap_err();
    assert!(stderr.contains("error: invalid value 'invalid_type' for '--type <SCRIPT_TYPE>'"));

    // Test empty policy
    let stderr = run_cmd("compile").unwrap_err();
    assert!(stderr.contains("error: the following required arguments were not provided"));
    assert!(stderr.contains("<POLICY>"));

    // Test malformed policy with unmatched parentheses
    let stderr = run_cmd(r#"compile "pk(A""#).unwrap_err();
    assert!(stderr.contains("Miniscript error: expected )"));

    // Test policy with unknown function
    let stderr = run_cmd(r#"compile "unknown_func(A)""#).unwrap_err();
    assert!(stderr.contains("Miniscript error: unexpected «unknown_func»"));
}
