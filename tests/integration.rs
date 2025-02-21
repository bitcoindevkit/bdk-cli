// Copyright (c) 2020-2025 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! bdk-cli Integration Test Framework
//!
//! This modules performs the necessary integration test for bdk-cli
//! The tests can be run using `cargo test`

#[cfg(feature = "rpc")]
mod test {
    use electrsd::bitcoind::tempfile::TempDir;
    use serde_json::{json, Value};
    use std::convert::From;
    use std::path::PathBuf;
    use std::process::Command;

    /// Testing errors for integration tests
    #[derive(Debug)]
    enum IntTestError {
        // IO error
        IO(std::io::Error),
        // Command execution error
        CmdExec(String),
        // Json Data error
        JsonData(String),
    }

    impl From<std::io::Error> for IntTestError {
        fn from(e: std::io::Error) -> Self {
            IntTestError::IO(e)
        }
    }

    // Helper function
    // Runs a system command with given args
    fn run_cmd_with_args(cmd: &str, args: &[&str]) -> Result<serde_json::Value, IntTestError> {
        let output = Command::new(cmd).args(args).output().unwrap();
        let mut value = output.stdout;
        let error = output.stderr;
        if value.len() == 0 {
            return Err(IntTestError::CmdExec(String::from_utf8(error).unwrap()));
        }
        value.pop(); // remove `\n` at end
        let output_string = std::str::from_utf8(&value).unwrap();
        let json_value: serde_json::Value = match serde_json::from_str(output_string) {
            Ok(value) => value,
            Err(_) => json!(output_string), // bitcoin-cli will sometime return raw string
        };
        Ok(json_value)
    }

    // Helper Function
    // Transforms a json value to string
    fn value_to_string(value: &Value) -> Result<String, IntTestError> {
        match value {
            Value::Bool(bool) => match bool {
                true => Ok("true".to_string()),
                false => Ok("false".to_string()),
            },
            Value::Number(n) => Ok(n.to_string()),
            Value::String(s) => Ok(s.to_string()),
            _ => Err(IntTestError::JsonData(
                "Value parsing not implemented for this type".to_string(),
            )),
        }
    }

    // Helper Function
    // Extracts value from a given json object and key
    fn get_value(json: &Value, key: &str) -> Result<String, IntTestError> {
        let map = json
            .as_object()
            .ok_or(IntTestError::JsonData("Json is not an object".to_string()))?;
        let value = map
            .get(key)
            .ok_or(IntTestError::JsonData("Invalid key".to_string()))?
            .to_owned();
        let string_value = value_to_string(&value)?;
        Ok(string_value)
    }

    /// The bdk-cli command struct
    /// Use it to perform all bdk-cli operations
    #[derive(Debug)]
    struct BdkCli {
        target: String,
        network: String,
        verbosity: bool,
        recv_desc: Option<String>,
        chang_desc: Option<String>,
        node_datadir: Option<PathBuf>,
    }

    impl BdkCli {
        /// Construct a new [`BdkCli`] struct
        fn new(
            network: &str,
            node_datadir: Option<PathBuf>,
            verbosity: bool,
            features: &[&str],
        ) -> Result<Self, IntTestError> {
            // Build bdk-cli with given features
            let mut feat = "--features=".to_string();
            for item in features {
                feat.push_str(item);
                feat.push_str(",");
            }
            feat.pop(); // remove the last comma
            let _build = Command::new("cargo").args(&["build", &feat]).output()?;

            let mut bdk_cli = Self {
                target: "./target/debug/bdk-cli".to_string(),
                network: network.to_string(),
                verbosity,
                recv_desc: None,
                chang_desc: None,
                node_datadir,
            };

            println!("BDK-CLI Config : {:#?}", bdk_cli);
            let bdk_master_key = bdk_cli.key_exec(&["generate"])?;
            let bdk_xprv = get_value(&bdk_master_key, "xprv")?;

            let bdk_recv_desc =
                bdk_cli.key_exec(&["derive", "--path", "m/84h/1h/0h/0", "--xprv", &bdk_xprv])?;
            let bdk_recv_desc = get_value(&bdk_recv_desc, "xprv")?;
            let bdk_recv_desc = format!("wpkh({})", bdk_recv_desc);

            let bdk_chng_desc =
                bdk_cli.key_exec(&["derive", "--path", "m/84h/1h/0h/1", "--xprv", &bdk_xprv])?;
            let bdk_chng_desc = get_value(&bdk_chng_desc, "xprv")?;
            let bdk_chng_desc = format!("wpkh({})", bdk_chng_desc);

            bdk_cli.recv_desc = Some(bdk_recv_desc);
            bdk_cli.chang_desc = Some(bdk_chng_desc);

            Ok(bdk_cli)
        }

        /// Execute bdk-cli wallet commands with given args
        fn wallet_exec(&self, args: &[&str]) -> Result<Value, IntTestError> {
            // Check if data directory is specified
            let mut wallet_args = if let Some(datadir) = &self.node_datadir {
                let datadir = datadir.as_os_str().to_str().unwrap();
                ["--network", &self.network, "--datadir", datadir, "wallet"].to_vec()
            } else {
                ["--network", &self.network, "wallet"].to_vec()
            };

            if self.verbosity {
                wallet_args.push("-v");
            }

            wallet_args.push("-d");
            wallet_args.push(self.recv_desc.as_ref().unwrap());
            wallet_args.push("-c");
            wallet_args.push(&self.chang_desc.as_ref().unwrap());

            for arg in args {
                wallet_args.push(arg);
            }
            run_cmd_with_args(&self.target, &wallet_args)
        }

        /// Execute bdk-cli key commands with given args
        fn key_exec(&self, args: &[&str]) -> Result<Value, IntTestError> {
            let mut key_args = ["key"].to_vec();
            for arg in args {
                key_args.push(arg);
            }
            run_cmd_with_args(&self.target, &key_args)
        }

        /// Execute bdk-cli node command
        fn node_exec(&self, args: &[&str]) -> Result<Value, IntTestError> {
            // Check if data directory is specified
            let mut node_args = if let Some(datadir) = &self.node_datadir {
                let datadir = datadir.as_os_str().to_str().unwrap();
                ["--network", &self.network, "--datadir", datadir, "node"].to_vec()
            } else {
                ["--network", &self.network, "node"].to_vec()
            };

            for arg in args {
                node_args.push(arg);
            }
            run_cmd_with_args(&self.target, &node_args)
        }
    }

    // Run A Basic wallet operation test, with given feature
    #[cfg(test)]
    fn basic_wallet_ops(feature: &str) {
        // Create a temporary directory for testing env
        let mut test_dir = std::env::current_dir().unwrap();
        test_dir.push("bdk-testing");

        let test_temp_dir = TempDir::new().unwrap();
        let test_dir = test_temp_dir.into_path().to_path_buf();

        // Create bdk-cli instance
        let bdk_cli = BdkCli::new("regtest", Some(test_dir), false, &[feature]).unwrap();

        // Generate 101 blocks
        bdk_cli.node_exec(&["generate", "101"]).unwrap();

        // Get a bdk address
        let bdk_addr_json = bdk_cli.wallet_exec(&["get_new_address"]).unwrap();
        let bdk_addr = get_value(&bdk_addr_json, "address").unwrap();

        // Send coins from core to bdk
        bdk_cli
            .node_exec(&["sendtoaddress", &bdk_addr, "1000000000"])
            .unwrap();

        bdk_cli.node_exec(&["generate", "1"]).unwrap();

        // Sync the bdk wallet
        bdk_cli.wallet_exec(&["sync"]).unwrap();

        // Get the balance
        let balance_json = bdk_cli.wallet_exec(&["get_balance"]).unwrap();
        let confirmed_balance = balance_json
            .as_object()
            .unwrap()
            .get("satoshi")
            .unwrap()
            .as_object()
            .unwrap()
            .get("confirmed")
            .unwrap()
            .as_u64()
            .unwrap();
        assert_eq!(confirmed_balance, 1000000000u64);
    }

    #[test]
    #[cfg(feature = "regtest-bitcoin")]
    fn test_basic_wallet_op_bitcoind() {
        basic_wallet_ops("regtest-bitcoin")
    }

    #[test]
    #[cfg(feature = "regtest-electrum")]
    fn test_basic_wallet_op_electrum() {
        basic_wallet_ops("regtest-electrum")
    }
}
