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
