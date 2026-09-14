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
        cmd.arg("wallets").arg("list");

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
            .arg("list")
            .assert()
            .success()
            .stdout(predicate::str::contains("wallet_one"))
            .stdout(predicate::str::contains("wallet_two"));
    }
}

// --- REDB WALLET CONFIGURATION TESTS ---
#[cfg(feature = "redb")]
mod test_redb_wallet_config {
    use super::*;
    use serde_json::Value;

    fn save_wallet(cli: &BdkCli, wallet_name: &str) {
        let descriptor = cli
            .cmd("descriptor", &["--type", "tr"])
            .output()
            .expect("Command to generate descriptors failed");
        assert!(descriptor.status.success());

        let descriptor_json: Value =
            serde_json::from_slice(&descriptor.stdout).expect("Invalid descriptor JSON");
        let public_descriptors = &descriptor_json["public_descriptors"];

        cli.build_base_cmd()
            .arg("wallet")
            .arg("--wallet")
            .arg(wallet_name)
            .arg("config")
            .arg("--ext-descriptor")
            .arg(public_descriptors["external"].as_str().unwrap())
            .arg("--int-descriptor")
            .arg(public_descriptors["internal"].as_str().unwrap())
            .arg("--database-type")
            .arg("redb")
            .assert()
            .success();
    }

    #[test]
    fn test_delete_redb_configs_preserves_shared_database() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));
        let persisted_wallet = "persisted_redb_wallet";
        let unused_wallet = "unused_redb_wallet";
        let config_path = temp_dir.path().join("config.toml");
        let database_path = temp_dir.path().join("wallet.redb");

        save_wallet(&cli, persisted_wallet);
        cli.wallet_cmd(&["--wallet", persisted_wallet, "new_address"])
            .assert()
            .success();
        assert!(database_path.is_file());

        save_wallet(&cli, unused_wallet);
        cli.build_base_cmd()
            .args(["wallets", "delete", unused_wallet])
            .assert()
            .success();

        assert!(config_path.is_file());
        assert!(database_path.is_file());
        cli.build_base_cmd()
            .args(["wallets", "list"])
            .assert()
            .success()
            .stdout(predicate::str::contains(persisted_wallet))
            .stdout(predicate::str::contains(unused_wallet).not());

        cli.build_base_cmd()
            .args(["wallets", "delete", persisted_wallet])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "Wallet data exists for configuration 'persisted_redb_wallet'; the saved configuration was not deleted",
            ));

        assert!(config_path.is_file());
        assert!(database_path.is_file());
    }
}

// --- SINGLE-BACKEND CROSS-BACKEND MARKER TESTS ---
#[cfg(all(feature = "sqlite", not(feature = "redb")))]
mod test_sqlite_only_cross_backend_marker {
    use super::*;
    use std::fs;

    #[test]
    fn test_delete_rejects_foreign_redb_file_with_sqlite_marker() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));
        let wallet_name = "sqlite_only_foreign_redb_data";
        let config_path = temp_dir.path().join("config.toml");
        let redb_path = temp_dir.path().join("wallet.redb");

        fs::write(
            &config_path,
            format!(
                "[wallets.{wallet_name}]\nwallet = \"{wallet_name}\"\nnetwork = \"regtest\"\next_descriptor = \"wpkh(test)\"\nint_descriptor = \"wpkh(test)\"\ndatabase_type = \"sqlite\"\n"
            ),
        )
        .unwrap();
        fs::write(&redb_path, []).unwrap();

        cli.build_base_cmd()
            .args(["wallets", "delete", wallet_name])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "Wallet data exists for configuration 'sqlite_only_foreign_redb_data'; the saved configuration was not deleted",
            ));

        assert!(config_path.is_file());
        assert!(redb_path.is_file());
    }
}

#[cfg(all(feature = "redb", not(feature = "sqlite")))]
mod test_redb_only_cross_backend_marker {
    use super::*;
    use std::fs;

    #[test]
    fn test_delete_rejects_foreign_sqlite_file_with_redb_marker() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));
        let wallet_name = "redb_only_foreign_sqlite_data";
        let config_path = temp_dir.path().join("config.toml");
        let sqlite_path = temp_dir.path().join(wallet_name).join("wallet.sqlite");

        fs::write(
            &config_path,
            format!(
                "[wallets.{wallet_name}]\nwallet = \"{wallet_name}\"\nnetwork = \"regtest\"\next_descriptor = \"wpkh(test)\"\nint_descriptor = \"wpkh(test)\"\ndatabase_type = \"redb\"\n"
            ),
        )
        .unwrap();
        fs::create_dir_all(sqlite_path.parent().unwrap()).unwrap();
        fs::write(&sqlite_path, []).unwrap();

        cli.build_base_cmd()
            .args(["wallets", "delete", wallet_name])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "Wallet data exists for configuration 'redb_only_foreign_sqlite_data'; the saved configuration was not deleted",
            ));

        assert!(config_path.is_file());
        assert!(sqlite_path.is_file());
    }
}

// --- DATABASE-DISABLED WALLET CONFIGURATION TESTS ---
#[cfg(not(any(feature = "sqlite", feature = "redb")))]
mod test_database_disabled_wallet_config {
    use super::*;
    use std::fs;

    fn write_config(datadir: &std::path::Path, wallet_name: &str, database_type: Option<&str>) {
        let database_type = database_type
            .map(|database_type| format!("\ndatabase_type = \"{database_type}\""))
            .unwrap_or_default();

        fs::write(
            datadir.join("config.toml"),
            format!(
                "[wallets.{wallet_name}]\nwallet = \"{wallet_name}\"\nnetwork = \"regtest\"\next_descriptor = \"wpkh(test)\"\nint_descriptor = \"wpkh(test)\"{database_type}\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn test_delete_wallet_config_without_database_support() {
        for (wallet_name, database_type) in [
            ("marker_wallet", Some("sqlite")),
            ("database_free_wallet", None),
        ] {
            let temp_dir = TempDir::new().unwrap();
            let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));
            let config_path = temp_dir.path().join("config.toml");

            write_config(temp_dir.path(), wallet_name, database_type);

            let assertion = cli
                .build_base_cmd()
                .args(["wallets", "delete", wallet_name])
                .assert();

            if database_type.is_some() {
                assertion.failure().stderr(predicate::str::contains(
                    "Wallet data exists for configuration",
                ));
                assert!(config_path.is_file());
            } else {
                assertion.success();
                assert!(!config_path.exists());
            }
        }
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
#[cfg(any(feature = "rpc", feature = "sqlite"))]
mod test_config {
    use super::*;
    use serde_json::Value;
    use std::fs;

    fn save_wallet(cli: &BdkCli, wallet_name: &str) {
        let desc = cli
            .cmd("descriptor", &["--type", "tr"])
            .output()
            .expect("Command to generate descriptors failed");

        let desc_values: Value =
            serde_json::from_slice(&desc.stdout).expect("Invalid JSON from output descriptor");

        let pub_desc = &desc_values["public_descriptors"];

        let mut command = cli.build_base_cmd();
        command
            .arg("wallet")
            .arg("--wallet")
            .arg(wallet_name)
            .arg("config")
            .arg("--ext-descriptor")
            .arg(pub_desc["external"].as_str().unwrap())
            .arg("--int-descriptor")
            .arg(pub_desc["internal"].as_str().unwrap());

        #[cfg(feature = "rpc")]
        command
            .arg("--client-type")
            .arg("rpc")
            .arg("--url")
            .arg("http://localhost:18443");

        command
            .arg("--database-type")
            .arg("sqlite")
            .assert()
            .success();
    }

    #[cfg(feature = "rpc")]
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
        cmd.arg("wallets").arg("list");

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

    #[test]
    fn test_delete_wallet_config() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));
        let remove_wallet_name = "test_delete_wallet";
        let keep_wallet_name = "test_keep_wallet";

        save_wallet(&cli, remove_wallet_name);
        save_wallet(&cli, keep_wallet_name);

        // Delete one config: the output is a confirmation message
        let output = cli
            .build_base_cmd()
            .arg("wallets")
            .arg("delete")
            .arg(remove_wallet_name)
            .output()
            .expect("Failed to execute wallets delete command");
        assert!(output.status.success(), "wallets delete failed");

        let json: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            json["message"].as_str().unwrap(),
            "Wallet configuration 'test_delete_wallet' deleted successfully"
        );

        // Re-listing no longer contains the deleted wallet
        let output = cli
            .build_base_cmd()
            .arg("wallets")
            .arg("list")
            .output()
            .expect("Failed to execute wallets list command");

        let list: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(list.get(remove_wallet_name).is_none());
        assert!(list.get(keep_wallet_name).is_some());
    }

    #[test]
    fn test_delete_unknown_wallet_config() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));
        save_wallet(&cli, "existing_wallet");

        cli.build_base_cmd()
            .arg("wallets")
            .arg("delete")
            .arg("ghost_wallet")
            .assert()
            .failure()
            .stderr(predicate::str::contains("not found in config"));
    }

    #[test]
    fn test_delete_last_wallet_config() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));
        let config_path = temp_dir.path().join("config.toml");

        save_wallet(&cli, "last_wallet");
        assert!(config_path.exists());

        cli.build_base_cmd()
            .arg("wallets")
            .arg("delete")
            .arg("last_wallet")
            .assert()
            .success();

        assert!(!config_path.exists());

        cli.build_base_cmd()
            .arg("wallets")
            .arg("list")
            .assert()
            .failure()
            .stderr(predicate::str::contains("No wallets configured yet."));
    }

    #[test]
    fn test_delete_wallet_config_with_persisted_data_fails() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));
        let wallet_name = "persisted_wallet";

        save_wallet(&cli, wallet_name);

        let config_path = temp_dir.path().join("config.toml");
        let database_path = temp_dir.path().join(wallet_name).join("wallet.sqlite");

        assert!(config_path.is_file());
        assert!(
            !database_path.exists(),
            "saving a configuration alone should not create wallet data"
        );

        cli.wallet_cmd(&["--wallet", wallet_name, "new_address"])
            .assert()
            .success();

        assert!(
            database_path.is_file(),
            "new_address should initialize the wallet database"
        );

        cli.build_base_cmd()
            .arg("wallets")
            .arg("delete")
            .arg(wallet_name)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "Wallet data exists for configuration 'persisted_wallet'",
            ));

        assert!(
            config_path.is_file(),
            "failed deletion should preserve config.toml"
        );

        assert!(
            database_path.is_file(),
            "failed deletion should preserve wallet data"
        );

        cli.build_base_cmd()
            .arg("wallets")
            .arg("list")
            .assert()
            .success()
            .stdout(predicate::str::contains(wallet_name));
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_delete_preserves_fields_unknown_to_current_build() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));
        let config_path = temp_dir.path().join("config.toml");

        fs::write(
            &config_path,
            r#"[wallets.remove_wallet]
wallet = "remove_wallet"
network = "regtest"
ext_descriptor = "wpkh(test)"
int_descriptor = "wpkh(test)"
database_type = "sqlite"

[wallets.preserved_wallet]
wallet = "preserved_wallet"
network = "regtest"
ext_descriptor = "wpkh(test)"
int_descriptor = "wpkh(test)"
database_type = "sqlite"
client_type = "rpc"
server_url = "http://localhost:18443"
rpc_user = "preserved-user"
rpc_password = "preserved-password"
"#,
        )
        .unwrap();

        cli.build_base_cmd()
            .args(["wallets", "delete", "remove_wallet"])
            .assert()
            .success();

        let raw_config: toml::Table =
            toml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        let preserved = raw_config["wallets"]["preserved_wallet"]
            .as_table()
            .unwrap();
        assert_eq!(preserved["client_type"].as_str(), Some("rpc"));
        assert_eq!(
            preserved["server_url"].as_str(),
            Some("http://localhost:18443")
        );
        assert_eq!(preserved["rpc_user"].as_str(), Some("preserved-user"));
        assert_eq!(
            preserved["rpc_password"].as_str(),
            Some("preserved-password")
        );
    }
}

//  SILENT PAYMENTS
#[cfg(feature = "silent-payments")]
mod test_silent_payments {
    use super::*;

    const SCAN: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const SPEND: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    #[test]
    fn test_silent_payment_code_network_hrp() {
        BdkCli::new("regtest", None)
            .cmd(
                "silent_payment_code",
                &["--scan_key", SCAN, "--spend_key", SPEND],
            )
            .assert()
            .success()
            .stdout(predicate::str::contains("sprt1"));

        BdkCli::new("testnet", None)
            .cmd(
                "silent_payment_code",
                &["--scan_key", SCAN, "--spend_key", SPEND],
            )
            .assert()
            .success()
            .stdout(predicate::str::contains("tsp1"));
    }

    #[test]
    fn test_silent_payment_code_rejects_invalid_pubkey() {
        BdkCli::new("regtest", None)
            .cmd(
                "silent_payment_code",
                &["--scan_key", "deadbeef", "--spend_key", SPEND],
            )
            .assert()
            .failure()
            .stderr(predicate::str::contains("malformed public key"));
    }
}
