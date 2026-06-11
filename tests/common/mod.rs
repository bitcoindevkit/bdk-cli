// Copyright (c) 2020-2026 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! bdk-cli Integration Test Framework
//!
//! This module provides the necessary helper methods for tests
//!
use assert_cmd::Command;
use std::path::PathBuf;

/// The bdk-cli command struct
#[allow(dead_code)]
#[derive(Debug)]
pub struct BdkCli {
    pub network: String,
    pub datadir: Option<PathBuf>,
    pub verbosity: bool,
    pub recv_desc: Option<String>,
    pub change_desc: Option<String>,
}

impl BdkCli {
    /// Construct a new test environment configuration
    pub fn new(network: &str, datadir: Option<PathBuf>) -> Self {
        Self {
            network: network.to_string(),
            datadir,
            verbosity: false,
            recv_desc: None,
            change_desc: None,
        }
    }

    /// Creates the base assert_cmd::Command with the global flags pre-loaded
    fn build_base_cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("bdk-cli").expect("bdk-cli binary must compile");

        cmd.arg("--network").arg(&self.network);

        if let Some(dir) = &self.datadir {
            cmd.arg("--datadir").arg(dir);
        }

        if self.verbosity {
            cmd.arg("--verbose");
        }

        cmd
    }

    /// Returns a pre-configured Command builder for `key` operations
    pub fn key_cmd(&self, args: &[&str]) -> Command {
        let mut cmd = self.build_base_cmd();
        cmd.arg("key");
        cmd.args(args); 
        cmd
    }

    /// Returns a pre-configured Command builder for `wallet` operations
    pub fn wallet_cmd(&self, args: &[&str]) -> Command {
        let mut cmd = self.build_base_cmd();
        cmd.arg("wallet");

        // Automatically inject descriptors if they are set in the helper state
        if let Some(recv) = &self.recv_desc {
            cmd.arg("--descriptor").arg(recv);
        }

        cmd.args(args);
        cmd
    }
}
