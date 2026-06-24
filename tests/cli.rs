// Copyright (c) 2020-2026 Bitcoin Dev Kit Developers
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

mod common;

use crate::common::BdkCli;
use predicates::prelude::*;
use tempfile::TempDir;
// --- KEY COMMAND TESTS ---
mod test_key {
    use super::*;
    use serde_json::Value;

    #[test]
    fn test_cli_key_generate() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        cli.key_cmd(&["generate"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"xprv\":"))
            .stdout(predicate::str::contains("\"mnemonic\":"))
            .stdout(predicate::str::contains("\"fingerprint\":"));
    }

    #[test]
    fn test_cli_key_derive() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        let generate_output = cli
            .key_cmd(&["generate"])
            .output()
            .expect("Failed to execute generate command");
        assert!(generate_output.status.success(), "Generate command failed");

        let generate_json: Value =
            serde_json::from_slice(&generate_output.stdout).expect("Invalid JSON");
        let xprv = generate_json["xprv"].as_str().expect("Missing XPRV");

        let mut cmd = cli.key_cmd(&[
            "derive",
            "--xprv",
            xprv,
            "--derivation_path",
            "m/84'/1'/0'/0",
        ]);

        cmd.assert()
            .success()
            .stdout(predicate::str::contains("\"xprv\":"))
            .stdout(predicate::str::contains("\"xpub\":"));
    }

    #[test]
    fn test_cli_key_restore() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        // Execute the command and capture the output
        let generate_cmd = cli
            .key_cmd(&["generate"])
            .output()
            .expect("Failed to execute generate command");
        assert!(generate_cmd.status.success(), "Generate command failed");

        // Parse the JSON to extract the mnemonic
        let generate_json: Value =
            serde_json::from_slice(&generate_cmd.stdout).expect("Failed to parse JSON");

        let mnemonic = generate_json["mnemonic"]
            .as_str()
            .expect("Mnemonic missing");
        let xprv = generate_json["xprv"].as_str().expect("XPRV missing");
        let finger_print = generate_json["fingerprint"]
            .as_str()
            .expect("Fingerprint missing");

        // Restore using the mnemonic
        let output_restore = cli
            .key_cmd(&["restore", "--mnemonic", mnemonic])
            .output()
            .expect("Failed to execute restore command");
        assert!(output_restore.status.success(), "Restore command failed");

        // Parse the JSON from the restore command
        let restore_json: Value =
            serde_json::from_slice(&output_restore.stdout).expect("Failed to parse JSON");

        let restored_xprv = restore_json["xprv"]
            .as_str()
            .expect("Restored XPRV missing");
        let restored_fingerprint = restore_json["fingerprint"]
            .as_str()
            .expect("Restored fingerprint missing");

        // Assert that the restored data exactly matches the generated data
        assert_eq!(
            xprv, restored_xprv,
            "The restored XPRV does not match the generated XPRV!"
        );

        assert_eq!(
            finger_print, restored_fingerprint,
            "The restored fingerprint does not match the generated fingerprint!"
        );
    }
}

// --- WALLETS COMMAND TESTS ---
mod test_wallets {
    use super::*;

    #[test]
    fn test_list_wallets_empty() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        let mut cmd = cli.build_base_cmd();
        cmd.arg("wallets");

        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("No wallets configured yet."));
    }

    #[cfg(feature = "rpc")]
    #[test]
    fn test_list_wallets_with_entries() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        for wallet_name in ["wallet_one", "wallet_two"] {
            let desc = cli
                .cmd("descriptor", &["--type", "tr"])
                .output()
                .expect("Command to generate descriptors failed");
            let desc_values: serde_json::Value = serde_json::from_slice(&desc.stdout).unwrap();
            let pub_desc = &desc_values["public_descriptors"];
            let ext_desc = pub_desc["external"].as_str().unwrap();
            let int_desc = pub_desc["internal"].as_str().unwrap();

            cli.build_base_cmd()
                .arg("wallet")
                .arg("--wallet")
                .arg(wallet_name)
                .arg("config")
                .arg("--ext-descriptor")
                .arg(ext_desc)
                .arg("--int-descriptor")
                .arg(int_desc)
                .arg("--client-type")
                .arg("rpc")
                .arg("--database-type")
                .arg("sqlite")
                .arg("--url")
                .arg("http://localhost:18443")
                .assert()
                .success();
        }

        cli.build_base_cmd()
            .arg("wallets")
            .assert()
            .success()
            .stdout(predicate::str::contains("wallet_one"))
            .stdout(predicate::str::contains("wallet_two"));
    }
}

// --- DESCRIPTOR COMMAND TESTS ---
mod test_descriptor {
    use super::*;

    #[test]
    fn test_generate_new_descriptor() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        // Run `bdk-cli descriptor --type tr`
        cli.cmd("descriptor", &["--type", "tr"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"public_descriptors\":"))
            .stdout(predicate::str::contains("\"private_descriptors\":"))
            .stdout(predicate::str::contains("\"mnemonic\":"))
            .stdout(predicate::str::contains("\"fingerprint\":"));
    }
}

// --- COMPILE COMMAND TESTS ---
#[cfg(feature = "compiler")]
mod test_compile {
    use super::*;

    #[test]
    fn test_compile_valid_policy() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        let policy = "pk(02e5b88fdb71c696e1a473f309a47535b7190e21a22bd25e7fc8bd055db3bba12f)";

        cli.cmd("compile", &[policy, "--type", "wsh"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"descriptor\":"))
            .stdout(predicate::str::contains("wsh("));
    }

    #[test]
    fn test_compile_invalid_policy() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        cli.cmd("compile", &["invalid_policy", "--type", "wsh"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("Invalid policy"));
    }
}

// --- CONFIG COMMAND TESTS ---
#[cfg(feature = "rpc")]
mod test_config {
    use super::*;
    use serde_json::Value;

    #[test]
    fn test_save_and_read_wallet_config() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));

        let desc = cli
            .cmd("descriptor", &["--type", "tr"])
            .output()
            .expect("Command to generate descriptors failed");

        let desc_values: Value =
            serde_json::from_slice(&desc.stdout).expect("Invalid JSON from output descriptor");

        let pub_desc = &desc_values["public_descriptors"];

        let ext_desc = pub_desc["external"].as_str().unwrap();
        let int_desc = pub_desc["internal"].as_str().unwrap();
        let wallet_name = "test_config_wallet";
        let client_type = "rpc";
        let db = "sqlite";
        let url = "http://localhost:18443";

        let mut cmd_init = cli.build_base_cmd();
        cmd_init
            .arg("wallet")
            .arg("--wallet")
            .arg(wallet_name)
            .arg("config")
            .arg("--ext-descriptor")
            .arg(ext_desc)
            .arg("--int-descriptor")
            .arg(int_desc)
            .arg("--client-type")
            .arg(client_type)
            .arg("--database-type")
            .arg(db)
            .arg("--url")
            .arg(url);

        cmd_init.assert().success();

        // verify saved config
        let mut cmd = cli.build_base_cmd();
        cmd.arg("wallets");

        let output = cmd.output().expect("Failed to execute wallets command");

        assert!(
            output.status.success(),
            "The wallets command failed to execute"
        );

        let json_output: Value =
            serde_json::from_slice(&output.stdout).expect("CLI did not output valid JSON");

        let config = &json_output[wallet_name];

        assert!(
            !config.is_null(),
            "The wallet {wallet_name} was not found in the root JSON object"
        );

        assert_eq!(config["wallet"].as_str().unwrap(), wallet_name);
        assert_eq!(config["network"].as_str().unwrap(), "regtest");
        assert_eq!(config["database_type"].as_str().unwrap(), db);
        assert_eq!(config["client_type"].as_str().unwrap(), client_type);
        assert_eq!(config["server_url"].as_str().unwrap(), url);
        assert_eq!(config["ext_descriptor"].as_str().unwrap(), ext_desc);
        assert_eq!(config["int_descriptor"].as_str().unwrap(), int_desc);
    }
}

#[cfg(feature = "rpc")]
mod test_offline {
    use super::*;
    use assert_cmd::Command;
    use serde_json::Value;

    static WALLET_NAME: &str = "test_config_wallet";

    /// Helper to spin up a sandboxed CLI with the generated descriptors
    fn setup_wallet_config() -> (BdkCli, Command) {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));

        // generate descriptors
        let desc = cli
            .cmd("descriptor", &["--type", "tr"])
            .output()
            .expect("Command to generate descriptors failed");

        let desc_values: Value =
            serde_json::from_slice(&desc.stdout).expect("Invalid JSON from output descriptor");

        let priv_desc = &desc_values["private_descriptors"];

        let ext_desc = priv_desc["external"].as_str().unwrap();
        let int_desc = priv_desc["internal"].as_str().unwrap();
        let client_type = "rpc";
        let db: &str = "sqlite";
        let url = "http://localhost:18443";

        let mut cmd_init = cli.build_base_cmd();
        cmd_init
            .arg("wallet")
            .arg("--wallet")
            .arg(WALLET_NAME)
            .arg("config")
            .arg("--ext-descriptor")
            .arg(ext_desc)
            .arg("--int-descriptor")
            .arg(int_desc)
            .arg("--client-type")
            .arg(client_type)
            .arg("--database-type")
            .arg(db)
            .arg("--url")
            .arg(url);
        (cli, cmd_init)
    }

    #[test]
    fn test_new_and_unused_address() {
        let (cli, mut cmd_init) = setup_wallet_config();
        cmd_init.assert().success();

        // new address
        cli.wallet_cmd(&["--wallet", WALLET_NAME, "new_address"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"address\":"));

        // `unused-address`
        cli.wallet_cmd(&["--wallet", WALLET_NAME, "unused_address"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"address\":"));
    }

    #[test]
    fn test_empty_wallet_balances_and_lists() {
        let (cli, mut cmd_init) = setup_wallet_config();
        cmd_init.assert().success();

        // balance
        cli.wallet_cmd(&["--wallet", WALLET_NAME, "balance"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"total\":"))
            .stdout(predicate::str::contains("\"trusted_pending\":"))
            .stdout(predicate::str::contains("\"untrusted_pending\":"))
            .stdout(predicate::str::contains("\"immature\":"))
            .stdout(predicate::str::contains("\"confirmed\":"));

        // Unspent UTXOs
        cli.wallet_cmd(&["--wallet", WALLET_NAME, "unspent"])
            .assert()
            .success()
            .stdout(predicate::str::contains("[]"));

        // Transactions
        cli.wallet_cmd(&["--wallet", WALLET_NAME, "transactions"])
            .assert()
            .success()
            .stdout(predicate::str::contains("[]"));
    }

    #[test]
    fn test_policies_and_public_descriptor() {
        let (cli, mut cmd_init) = setup_wallet_config();
        cmd_init.assert().success();

        // Policies
        cli.wallet_cmd(&["--wallet", WALLET_NAME, "policies"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"external\":"))
            .stdout(predicate::str::contains("\"internal\":"));

        // Public Descriptor
        cli.wallet_cmd(&["--wallet", WALLET_NAME, "public_descriptor"])
            .assert()
            .success()
            .stdout(predicate::str::contains("external"))
            .stdout(predicate::str::contains("internal"));
    }

    #[test]
    fn test_create_tx_insufficient_funds() {
        let (cli, mut cmd_init) = setup_wallet_config();
        cmd_init.assert().success();

        // create transaction
        cli.wallet_cmd(&[
            "--wallet",
            WALLET_NAME,
            "create_tx",
            "--to",
            "tb1p4tp4l6glyr2gs94neqcpr5gha7344nfyznfkc8szkreflscsdkgqsdent4:1000",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Insufficient"));
    }

    #[test]
    fn test_combine_psbt_invalid_input() {
        let (cli, mut cmd_init) = setup_wallet_config();
        cmd_init.assert().success();

        // Invalid create-tx.
        cli.wallet_cmd(&[
            "--wallet",
            WALLET_NAME,
            "combine_psbt",
            "invalid_psbt",
            "another_invalid_psbt",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid"));
    }

    #[cfg(feature = "bip322")]
    #[test]
    fn test_sign_message_and_verify_message() {
        let (cli, mut cmd_init) = setup_wallet_config();
        cmd_init.assert().success();

        let message = "bdk-cli integration test";

        // Reveal exactly one address and reuse it for both sign and verify.
        let addr_output = cli
            .wallet_cmd(&["--wallet", WALLET_NAME, "new_address"])
            .output()
            .expect("Failed to generate address");
        assert!(
            addr_output.status.success(),
            "new_address failed: {}",
            String::from_utf8_lossy(&addr_output.stderr)
        );
        let addr_json: Value = serde_json::from_slice(&addr_output.stdout).unwrap();
        let address = addr_json["address"]
            .as_str()
            .expect("missing address")
            .to_string();
        println!("DEBUG signing address: {address}");

        // Sign (default signature_type = "simple").
        let sign_output = cli
            .wallet_cmd(&[
                "--wallet",
                WALLET_NAME,
                "sign_message",
                "--message",
                message,
                "--address",
                &address,
            ])
            .output()
            .expect("Failed to sign message");
        assert!(
            sign_output.status.success(),
            "sign_message failed: {}",
            String::from_utf8_lossy(&sign_output.stderr)
        );
        let sign_json: Value = serde_json::from_slice(&sign_output.stdout).unwrap();
        let proof = sign_json["proof"].as_str().expect("missing proof");
        println!("DEBUG proof: {proof}");
        println!("DEBUG verifying same address: {address}");

        // Verify with the identical address + message.
        cli.wallet_cmd(&[
            "--wallet",
            WALLET_NAME,
            "verify_message",
            "--address",
            &address,
            "--message",
            message,
            "--proof",
            proof,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"));
    }

    #[cfg(feature = "bip322")]
    #[test]
    fn test_verify_message_rejects_tampered_message() {
        let (cli, mut cmd_init) = setup_wallet_config();
        cmd_init.assert().success();

        let addr_output = cli
            .wallet_cmd(&["--wallet", WALLET_NAME, "new_address"])
            .output()
            .expect("Failed to generate address");
        let addr_json: Value = serde_json::from_slice(&addr_output.stdout).unwrap();
        let address = addr_json["address"].as_str().unwrap();

        let sign_output = cli
            .wallet_cmd(&[
                "--wallet",
                WALLET_NAME,
                "sign_message",
                "--message",
                "original message",
                "--address",
                address,
            ])
            .output()
            .expect("Failed to sign message");
        let sign_json: Value = serde_json::from_slice(&sign_output.stdout).unwrap();
        let proof = sign_json["proof"].as_str().unwrap();

        // A tampered message should fail
        cli.wallet_cmd(&[
            "--wallet",
            WALLET_NAME,
            "verify_message",
            "--proof",
            proof,
            "--message",
            "tampered message",
            "--address",
            address,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": false"));
    }
}

#[cfg(feature = "electrum")]
mod test_online {
    use crate::common::BdkCli;
    use assert_cmd::Command;
    use bdk_testenv::{TestEnv, bitcoincore_rpc::RpcApi};
    use bdk_wallet::bitcoin::{Address, Amount, Network, Txid};
    use serde_json::Value;
    use std::str::FromStr;
    use std::time::Duration;
    use tempfile::TempDir;

    static WALLET_NAME: &str = "test_online_wallet";
    static RECIPIENT: &str = "tb1p4tp4l6glyr2gs94neqcpr5gha7344nfyznfkc8szkreflscsdkgqsdent4";

    /// Spins up the envt, a Regtest node + electrs, and saves the wallet config.
    fn setup_online_wallet() -> (BdkCli, Command, TestEnv) {
        let env = TestEnv::new().expect("Failed to start bdk_testenv");
        let server_url = env.electrsd.electrum_url.as_str();

        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));

        let desc = cli
            .cmd("descriptor", &["--type", "tr"])
            .output()
            .expect("Command to generate descriptors failed");
        let desc_values: Value =
            serde_json::from_slice(&desc.stdout).expect("Invalid JSON from output descriptor");
        let priv_desc = &desc_values["private_descriptors"];
        let ext_desc = priv_desc["external"].as_str().unwrap();
        let int_desc = priv_desc["internal"].as_str().unwrap();

        let mut cmd_init = cli.build_base_cmd();
        cmd_init
            .arg("wallet")
            .arg("--wallet")
            .arg(WALLET_NAME)
            .arg("config")
            .arg("--ext-descriptor")
            .arg(ext_desc)
            .arg("--int-descriptor")
            .arg(int_desc)
            .arg("--client-type")
            .arg("electrum")
            .arg("--database-type")
            .arg("sqlite")
            .arg("--url")
            .arg(server_url);

        (cli, cmd_init, env)
    }

    /// Mines blocks, funds wallet with 0.5 BTC, confirms it, and
    /// runs `full_scan` so the wallet's persisted state reflects the funding.
    /// Asserts the resulting confirmed balance is exactly 50,000,000 sats.
    fn fund_and_sync_wallet(cli: &BdkCli, env: &TestEnv) {
        let address = cli_new_address(cli);

        let node_address = env
            .rpc_client()
            .get_new_address(None, None)
            .unwrap()
            .assume_checked();

        let mined_blocks = env
            .mine_blocks(101, Some(node_address))
            .expect("Failed to mine initial blocks");
        assert_eq!(mined_blocks.len(), 101, "expected exactly 101 blocks mined");
        env.wait_until_electrum_sees_block(Duration::from_secs(10))
            .expect("Electrum did not catch up to initial blocks");

        let txid = env
            .send(&address, Amount::from_btc(0.5).unwrap())
            .expect("Failed to fund wallet address");
        env.wait_until_electrum_sees_txid(txid, Duration::from_secs(10))
            .expect("Electrum did not see funding tx");

        env.mine_blocks(3, None)
            .expect("Failed to confirm funding tx");
        env.wait_until_electrum_sees_block(Duration::from_secs(10))
            .expect("Electrum did not catch up to confirmation blocks");

        cli_full_scan(cli);
        assert_eq!(
            cli_balance(cli),
            50_000_000,
            "wallet should show funded balance after full_scan"
        );
    }

    /// Runs `wallet --wallet <WALLET_NAME> <args>`, asserts the process exited
    /// successfully, and parses stdout as JSON.
    fn run_wallet_json(cli: &BdkCli, args: &[&str]) -> Value {
        let mut full_args = vec!["--wallet", WALLET_NAME];
        full_args.extend_from_slice(args);

        let output = cli
            .wallet_cmd(&full_args)
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn `{}`: {e}", args.join(" ")));

        assert!(
            output.status.success(),
            "`{}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );

        serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
            panic!(
                "`{}` returned non-JSON stdout ({e}): {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stdout)
            )
        })
    }

    fn cli_new_address(cli: &BdkCli) -> Address {
        let json = run_wallet_json(cli, &["new_address"]);
        let addr = json["address"]
            .as_str()
            .expect("new_address: missing 'address' field");
        Address::from_str(addr)
            .expect("new_address: invalid address string")
            .require_network(Network::Regtest)
            .expect("new_address: wrong network")
    }

    fn cli_full_scan(cli: &BdkCli) {
        run_wallet_json(cli, &["full_scan"]);
    }

    fn cli_sync(cli: &BdkCli) {
        run_wallet_json(cli, &["sync"]);
    }

    fn cli_balance(cli: &BdkCli) -> u64 {
        let json = run_wallet_json(cli, &["balance"]);
        json["confirmed"]
            .as_u64()
            .expect("balance: missing 'confirmed' field")
    }

    fn cli_create_tx(cli: &BdkCli, to: &str) -> String {
        let json = run_wallet_json(cli, &["create_tx", "--to", to]);
        json["psbt"]
            .as_str()
            .expect("create_tx: missing 'psbt' field")
            .to_string()
    }

    /// Returns (signed_psbt_base64, is_finalized).
    fn cli_sign(cli: &BdkCli, psbt: &str) -> (String, bool) {
        let json = run_wallet_json(cli, &["sign", psbt]);
        let signed = json["psbt"]
            .as_str()
            .expect("sign: missing 'psbt' field")
            .to_string();
        let finalized = json["is_finalized"]
            .as_bool()
            .expect("sign: missing 'is_finalized' field");
        (signed, finalized)
    }

    fn cli_extract_psbt(cli: &BdkCli, psbt: &str) -> String {
        let json = run_wallet_json(cli, &["extract_psbt", psbt]);
        json["raw_tx"]
            .as_str()
            .expect("extract_psbt: missing 'raw_tx' field")
            .to_string()
    }

    fn cli_broadcast(cli: &BdkCli, raw_tx: &str) -> Txid {
        let json = run_wallet_json(cli, &["broadcast", "--tx", raw_tx]);
        let txid = json["txid"]
            .as_str()
            .expect("broadcast: missing 'txid' field");
        Txid::from_str(txid).expect("broadcast: invalid txid")
    }

    #[test]
    fn test_full_online_transaction_lifecycle() {
        let (cli, mut cmd_init, env) = setup_online_wallet();
        cmd_init.assert().success();

        fund_and_sync_wallet(&cli, &env);

        // Build, sign, extract, and broadcast a spend
        let unsigned_psbt = cli_create_tx(&cli, &format!("{RECIPIENT}:20000"));

        let (signed_psbt, finalized) = cli_sign(&cli, &unsigned_psbt);
        assert!(finalized, "PSBT should be finalized after signing");

        let raw_tx = cli_extract_psbt(&cli, &signed_psbt);

        let spend_txid = cli_broadcast(&cli, &raw_tx);
        env.rpc_client()
            .get_mempool_entry(&spend_txid)
            .expect("broadcast tx not found in node mempool");

        // Confirm the spend and verify the final balance
        env.mine_blocks(1, None)
            .expect("Failed to mine spend confirmation block");
        env.wait_until_electrum_sees_block(Duration::from_secs(10))
            .expect("Electrum did not catch up to spend confirmation");

        cli_sync(&cli);
        let final_balance = cli_balance(&cli);
        assert!(
            (49_900_000..50_000_000).contains(&final_balance),
            "unexpected post-spend confirmed balance: {final_balance}"
        );
    }

    #[test]
    fn test_finalize_psbt_on_signed_tx() {
        let (cli, mut cmd_init, env) = setup_online_wallet();
        cmd_init.assert().success();
        fund_and_sync_wallet(&cli, &env);

        let unsigned_psbt = cli_create_tx(&cli, &format!("{RECIPIENT}:15000"));
        let (signed_psbt, finalized) = cli_sign(&cli, &unsigned_psbt);
        assert!(finalized, "PSBT should be finalized after signing");

        // finalize_psbt should be idempotent: finalizing an already-finalized
        // PSBT should succeed and still report is_finalized = true.
        let finalize_json = run_wallet_json(&cli, &["finalize_psbt", &signed_psbt]);
        assert_eq!(
            finalize_json["is_finalized"].as_bool(),
            Some(true),
            "finalize_psbt should report the PSBT as finalized"
        );
    }

    #[test]
    fn test_combine_psbt_merges_signatures() {
        let (cli, mut cmd_init, env) = setup_online_wallet();
        cmd_init.assert().success();
        fund_and_sync_wallet(&cli, &env);

        let unsigned_psbt = cli_create_tx(&cli, &format!("{RECIPIENT}:15000"));
        let (signed_psbt, finalized) = cli_sign(&cli, &unsigned_psbt);
        assert!(finalized, "PSBT should be finalized after signing");

        // Combine the unsigned and signed versions of the same transaction
        let combined_json = run_wallet_json(&cli, &["combine_psbt", &unsigned_psbt, &signed_psbt]);
        let combined_psbt = combined_json["psbt"]
            .as_str()
            .expect("combine_psbt: missing 'psbt' field");

        // If signature data survived the combine, this should extract cleanly.
        let raw_tx = cli_extract_psbt(&cli, combined_psbt);
        assert!(
            !raw_tx.is_empty(),
            "combined PSBT did not extract to a valid raw transaction"
        );
    }

    #[test]
    fn test_bump_fee_replaces_unconfirmed_tx() {
        let (cli, mut cmd_init, env) = setup_online_wallet();
        cmd_init.assert().success();
        fund_and_sync_wallet(&cli, &env);

        // Create and broadcast a low-fee-rate, RBF-enabled transaction.
        let unsigned_psbt = run_wallet_json(
            &cli,
            &[
                "create_tx",
                "--to",
                &format!("{RECIPIENT}:15000"),
                "--fee_rate",
                "1.0",
            ],
        )["psbt"]
            .as_str()
            .expect("create_tx: missing 'psbt' field")
            .to_string();

        let (signed_psbt, finalized) = cli_sign(&cli, &unsigned_psbt);
        assert!(finalized);
        let raw_tx = cli_extract_psbt(&cli, &signed_psbt);
        let original_txid = cli_broadcast(&cli, &raw_tx);

        env.rpc_client()
            .get_mempool_entry(&original_txid)
            .expect("original tx should be in the mempool before bumping");

        env.wait_until_electrum_sees_txid(original_txid, Duration::from_secs(10))
            .expect("electrs did not see the broadcast tx");
        cli_sync(&cli);

        // Bump to a much higher fee rate; this should replace the original tx.
        let bumped_json = run_wallet_json(
            &cli,
            &[
                "bump_fee",
                "--txid",
                &original_txid.to_string(),
                "--fee_rate",
                "10.0",
            ],
        );
        let bumped_psbt = bumped_json["psbt"]
            .as_str()
            .expect("bump_fee: missing 'psbt' field");

        let (signed_bumped, bumped_finalized) = cli_sign(&cli, bumped_psbt);
        assert!(
            bumped_finalized,
            "bumped PSBT should be finalized after signing"
        );

        let bumped_raw_tx = cli_extract_psbt(&cli, &signed_bumped);
        let bumped_txid = cli_broadcast(&cli, &bumped_raw_tx);

        assert_ne!(
            original_txid, bumped_txid,
            "fee-bumped transaction should have a different txid than the original"
        );

        env.mine_blocks(1, None)
            .expect("Failed to confirm bumped tx");
        env.wait_until_electrum_sees_block(Duration::from_secs(10))
            .expect("Electrum did not catch up after bump confirmation");
        cli_sync(&cli);

        let final_balance = cli_balance(&cli);
        assert!(
            final_balance < 50_000_000,
            "balance should reflect exactly one confirmed spend after RBF, got {final_balance}"
        );
    }
}
