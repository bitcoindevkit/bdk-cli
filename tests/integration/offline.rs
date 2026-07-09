#[cfg(feature = "rpc")]
mod test_offline {
    use crate::common::BdkCli;
    use assert_cmd::Command;
    use predicates::prelude::*;
    use serde_json::Value;
    use tempfile::TempDir;

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
    /**
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
    **/
    #[test]
    fn test_create_tx_send_all_rejects_multiple_recipients() {
        let (cli, mut cmd_init) = setup_wallet_config();
        cmd_init.assert().success();

        // Same address twice => two recipients => must be rejected under --send_all.
        let recipient = "tb1p4tp4l6glyr2gs94neqcpr5gha7344nfyznfkc8szkreflscsdkgqsdent4:0";
        cli.wallet_cmd(&[
            "--wallet",
            WALLET_NAME,
            "create_tx",
            "--send_all",
            "--to",
            recipient,
            "--to",
            recipient,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Wallet can only be drained to a single output",
        ));
    }
}

#[cfg(all(feature = "repl", feature = "electrum"))]
mod repl_tests {
    use crate::common::BdkCli;
    use serde_json::Value;
    use tempfile::TempDir;

    const WALLET_NAME: &str = "repl_test_wallet";

    fn setup_repl_wallet() -> (BdkCli, TempDir) {
        let temp = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp.path().to_path_buf()));

        let desc = cli.cmd("descriptor", &["--type", "tr"]).output().unwrap();
        let v: Value = serde_json::from_slice(&desc.stdout).unwrap();
        let ext = v["private_descriptors"]["external"].as_str().unwrap();
        let int = v["private_descriptors"]["internal"].as_str().unwrap();

        cli.build_base_cmd()
            .args(["wallet", "--wallet", WALLET_NAME, "config"])
            .args(["--ext-descriptor", ext, "--int-descriptor", int])
            .args(["--client-type", "electrum", "--database-type", "sqlite"])
            .args(["--url", "127.0.0.1:1"])
            .assert()
            .success();

        (cli, temp)
    }

    #[test]
    fn test_repl_executes_commands_and_exits() {
        let (cli, _temp) = setup_repl_wallet();

        let output = cli
            .build_base_cmd()
            .args(["repl", "--wallet", WALLET_NAME])
            .write_stdin("wallet new_address\nwallet balance\nexit\n")
            .output()
            .expect("failed to run repl");

        assert!(
            output.status.success(),
            "repl exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Entering REPL mode"),
            "missing banner:\n{stdout}"
        );
        assert!(
            stdout.contains("\"address\":"),
            "new_address output missing:\n{stdout}"
        );
        assert!(
            stdout.contains("\"confirmed\":"),
            "balance output missing:\n{stdout}"
        );
        assert!(
            stdout.contains("Exiting..."),
            "no exit acknowledgement:\n{stdout}"
        );
    }
}
