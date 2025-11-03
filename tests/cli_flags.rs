// Copyright (c) 2020-2025 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! CLI Flags Tests
//!
//! Tests for global CLI flags and their behavior

use std::process::Command;

#[test]
fn test_without_pretty_flag() {
    let output = Command::new("cargo")
        .args("run -- key generate".split_whitespace())
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(serde_json::from_str::<serde_json::Value>(&stdout).is_ok());
}

#[test]
fn test_pretty_flag_before_subcommand() {
    let output = Command::new("cargo")
        .args("run -- --pretty key generate".split_whitespace())
        .output()
        .unwrap();

    assert!(output.status.success());
}

#[test]
fn test_pretty_flag_after_subcommand() {
    let output = Command::new("cargo")
        .args("run -- key generate --pretty".split_whitespace())
        .output()
        .unwrap();

    assert!(output.status.success());
}
