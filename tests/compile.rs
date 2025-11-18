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

use std::process::{Command, Output};

fn run_cmd(cmd: &str) -> Output {
    Command::new("cargo")
        .args(format!("run -- {}", cmd).split_whitespace())
        .output()
        .unwrap()
}

#[test]
fn test_invalid_cases() {
    // Test invalid policy syntax
    let output = run_cmd("compile invalid_policy");
    assert!(!output.status.success());

    // Test invalid script type
    let output = run_cmd("compile pk(A) -t invalid_type");
    assert!(!output.status.success());

    // Test empty policy
    let output = run_cmd("compile");
    assert!(!output.status.success());

    // Test malformed policy with unmatched parentheses
    let output = run_cmd(r#"compile "pk(A"#);
    assert!(!output.status.success());

    // Test policy with unknown function
    let output = run_cmd(r#"compile "unknown_func(A)"#);
    assert!(!output.status.success());
}
