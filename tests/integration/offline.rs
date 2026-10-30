#[cfg(feature = "rpc")]
mod test_offline {
    use crate::common::BdkCli;
    use assert_cmd::Command;
    use predicates::prelude::*;
    use serde_json::Value;
    use tempfile::TempDir;

    static WALLET_NAME: &str = "test_config_wallet";
    /// A `--to` argument, the wallet is unfunded, so nothing is spent.
    static RECIPIENT: &str = "tb1p4tp4l6glyr2gs94neqcpr5gha7344nfyznfkc8szkreflscsdkgqsdent4:10000";

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
            .args(["--wallet", WALLET_NAME])
            .arg("config")
            .args(["--ext-descriptor", ext_desc])
            .args(["--int-descriptor", int_desc])
            .args(["--client-type", client_type])
            .args(["--database-type", db])
            .args(["--url", url]);
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

    /// A malformed `create_tx` argument must be reported as an error (exit 1),
    /// never as a panic (exit 101).
    #[test]
    fn test_create_tx_rejects_malformed_input_without_panicking() {
        let (cli, mut cmd_init) = setup_wallet_config();
        cmd_init.assert().success();

        // Unknown outpoint
        cli.wallet_cmd(&[
            "--wallet",
            WALLET_NAME,
            "create_tx",
            "--to",
            RECIPIENT,
            "--utxos",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("UTXO not found"));

        // Malformed base64
        cli.wallet_cmd(&[
            "--wallet",
            WALLET_NAME,
            "create_tx",
            "--to",
            RECIPIENT,
            "--add_data",
            "!!!not-base64!!!",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Base64 decoding error"));
    }

    /// An invalid `--fee_rate` is rejected up front instead of
    /// silently becoming a zero fee or the builder default.
    #[test]
    fn test_create_tx_rejects_unusable_fee_rates() {
        let (cli, mut cmd_init) = setup_wallet_config();
        cmd_init.assert().success();

        for (fee_rate, expected) in [
            ("0", "below the smallest usable rate"),
            ("NaN", "must be a finite number"),
            ("1e30", "too large to represent"),
            ("abc", "expected a number in sat/vB"),
        ] {
            cli.wallet_cmd(&[
                "--wallet",
                WALLET_NAME,
                "create_tx",
                "--to",
                RECIPIENT,
                "--fee_rate",
                fee_rate,
            ])
            .assert()
            .code(2)
            .stderr(predicate::str::contains(expected));
        }
    }

    #[cfg(feature = "message_signer")]
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

    #[cfg(feature = "message_signer")]
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

#[cfg(all(
    feature = "sqlite",
    not(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf"
    ))
))]
mod multipath_tests {
    use crate::common::BdkCli;
    use assert_cmd::Command;
    use predicates::prelude::*;
    use tempfile::TempDir;

    // A public BIP-389 two-path (multipath) descriptor
    const MULTIPATH_DESC: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/<0;1>/*)";
    const INT_DESC: &str = "wpkh([07234a14/84'/1'/0']tpubDCSgT6PaVLQH9h2TAxKryhvkEurUBcYRJc9dhTcMDyahhWiMWfEWvQQX89yaw7w7XU8bcVujoALfxq59VkFATri3Cxm5mkp9kfHfRFDckEh/1/*)";

    fn save_config(cli: &BdkCli, wallet: &str, ext: &str, int: Option<&str>) -> Command {
        let mut cmd = cli.build_base_cmd();
        cmd.arg("wallet")
            .args(["--wallet", wallet])
            .arg("config")
            .args(["--ext-descriptor", ext])
            .args(["--database-type", "sqlite"]);
        if let Some(int) = int {
            cmd.arg("--int-descriptor").arg(int);
        }
        cmd
    }

    #[test]
    fn multipath_descriptor_creates_split_keychains() {
        let tmp = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(tmp.path().to_path_buf()));
        save_config(&cli, "multipath_wallet", MULTIPATH_DESC, None)
            .assert()
            .success();

        cli.wallet_cmd(&["--wallet", "multipath_wallet", "public_descriptor"])
            .assert()
            .success()
            .stdout(predicate::str::contains("/0/*"))
            .stdout(predicate::str::contains("/1/*"));
    }

    #[test]
    fn multipath_wallet_reloads() {
        let tmp = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(tmp.path().to_path_buf()));
        save_config(&cli, "multipath_wallet", MULTIPATH_DESC, None)
            .assert()
            .success();

        cli.wallet_cmd(&["--wallet", "multipath_wallet", "new_address"])
            .assert()
            .success();
        cli.wallet_cmd(&["--wallet", "multipath_wallet", "new_address"])
            .assert()
            .success();
    }

    #[test]
    fn multipath_with_internal_is_rejected_at_config_time() {
        let tmp = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(tmp.path().to_path_buf()));
        save_config(&cli, "multipath_wallet", MULTIPATH_DESC, Some(INT_DESC))
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "multipath descriptor and a separate internal descriptor",
            ));

        // Nothing was written, so the wallet does not exist.
        cli.wallet_cmd(&["--wallet", "multipath_wallet", "new_address"])
            .assert()
            .failure();
    }
}

/// Label tests need a persisted wallet, and only an `rpc` or a backend-less config can be
/// created here without a running server.
#[cfg(all(
    feature = "sqlite",
    any(
        feature = "rpc",
        not(any(feature = "electrum", feature = "esplora", feature = "cbf"))
    )
))]
mod label_tests {
    use crate::common::BdkCli;
    use assert_cmd::Command;
    use bdk_wallet::bitcoin::absolute::LockTime;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::transaction::Version;
    use bdk_wallet::bitcoin::{
        Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use bdk_wallet::{KeychainKind, Wallet};
    use predicates::prelude::*;
    use serde_json::Value;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const WALLET_NAME: &str = "label_wallet";
    /// A valid regtest address that does not belong to the test wallet.
    const FOREIGN_REGTEST_ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    /// A valid mainnet address.
    const MAINNET_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    /// A txid the wallet has never seen.
    const UNKNOWN_TXID: &str = "5fe2524f0c46bb12767d1865114031cd631578ac05422a767c0edf23f5c0aeaa";

    /// A regtest wallet in a fresh data directory.
    fn setup() -> (BdkCli, TempDir) {
        let (cli, temp_dir, _, _) = setup_with_descriptors();
        (cli, temp_dir)
    }

    /// Like [`setup`], also returning the wallet's external and internal descriptors.
    fn setup_with_descriptors() -> (BdkCli, TempDir, String, String) {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));

        let desc = cli
            .cmd("descriptor", &["--type", "tr"])
            .output()
            .expect("Command to generate descriptors failed");
        let desc: Value =
            serde_json::from_slice(&desc.stdout).expect("Invalid JSON from output descriptor");
        let ext_desc = desc["private_descriptors"]["external"].as_str().unwrap();
        let int_desc = desc["private_descriptors"]["internal"].as_str().unwrap();

        let mut config = cli.build_base_cmd();
        config
            .arg("wallet")
            .args(["--wallet", WALLET_NAME])
            .arg("config")
            .args(["--ext-descriptor", ext_desc])
            .args(["--int-descriptor", int_desc])
            .args(["--database-type", "sqlite"]);
        #[cfg(feature = "rpc")]
        config
            .args(["--client-type", "rpc"])
            .args(["--url", "http://localhost:18443"]);
        config.assert().success();

        (cli, temp_dir, ext_desc.to_string(), int_desc.to_string())
    }

    /// A transaction the wallet received, and the output it received it in.
    struct Received {
        txid: Txid,
        outpoint: OutPoint,
    }

    /// Writes `count` unconfirmed transactions, each paying 50 000 sats to a new address, into
    /// the wallet's database, as if a sync had found them. No node is needed to do this.
    fn receive(temp_dir: &TempDir, ext: &str, int: &str, count: u8) -> Vec<Received> {
        let wallet_dir = temp_dir.path().join(WALLET_NAME);
        std::fs::create_dir_all(&wallet_dir).unwrap();
        let db_file = wallet_dir.join("wallet.sqlite");
        let mut db = bdk_wallet::rusqlite::Connection::open(db_file).unwrap();
        let mut wallet = Wallet::create(ext.to_string(), int.to_string())
            .network(Network::Regtest)
            .create_wallet(&mut db)
            .unwrap();

        let received: Vec<_> = (1..=count)
            .map(|funding| {
                let address = wallet.reveal_next_address(KeychainKind::External);
                let tx = Transaction {
                    version: Version::TWO,
                    lock_time: LockTime::ZERO,
                    input: vec![TxIn {
                        previous_output: OutPoint::new(Txid::from_byte_array([funding; 32]), 0),
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    output: vec![TxOut {
                        value: Amount::from_sat(50_000),
                        script_pubkey: address.script_pubkey(),
                    }],
                };
                let txid = tx.compute_txid();
                wallet.apply_unconfirmed_txs([(tx, 1_700_000_000)]);
                Received {
                    txid,
                    outpoint: OutPoint::new(txid, 0),
                }
            })
            .collect();

        wallet.persist(&mut db).unwrap();
        received
    }

    /// The `label` of the entry of a JSON `items` list that has the given `key` equal to `id`.
    fn label_in(list: &Value, key: &str, id: &str) -> Option<String> {
        let entry = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry[key] == id)
            .unwrap_or_else(|| panic!("{id} is not in {list}"));
        entry
            .get("label")
            .map(|label| label.as_str().unwrap().to_string())
    }

    fn json(cli: &BdkCli, args: &[&str]) -> Value {
        let output = wallet(cli, args).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn wallet(cli: &BdkCli, args: &[&str]) -> Command {
        let mut all = vec!["--wallet", WALLET_NAME];
        all.extend_from_slice(args);
        cli.wallet_cmd(&all)
    }

    fn labels_file(temp_dir: &TempDir) -> PathBuf {
        temp_dir.path().join(WALLET_NAME).join("labels.jsonl")
    }

    fn new_address(cli: &BdkCli) -> String {
        let output = wallet(cli, &["new_address"]).output().unwrap();
        let json: Value = serde_json::from_slice(&output.stdout).unwrap();
        json["address"].as_str().unwrap().to_string()
    }

    #[test]
    fn labels_an_address_and_writes_a_bip329_file() {
        let (cli, temp_dir) = setup();
        let address = new_address(&cli);

        let output = wallet(
            &cli,
            &["label", "--address", &address, "--text", "from Alice"],
        )
        .output()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["type"], "addr");
        assert_eq!(result["ref"], address.as_str());
        assert_eq!(result["label"], "from Alice");

        let file = std::fs::read_to_string(labels_file(&temp_dir)).unwrap();
        assert_eq!(file.lines().count(), 1);
        let record: Value = serde_json::from_str(file.lines().next().unwrap()).unwrap();
        assert_eq!(record["type"], "addr");
        assert_eq!(record["ref"], address.as_str());
        assert_eq!(record["label"], "from Alice");
    }

    #[test]
    fn relabelling_replaces_the_label() {
        let (cli, temp_dir) = setup();
        let address = new_address(&cli);

        for text in ["first", "second"] {
            wallet(&cli, &["label", "--address", &address, "--text", text])
                .assert()
                .success();
        }

        let file = std::fs::read_to_string(labels_file(&temp_dir)).unwrap();
        assert_eq!(file.lines().count(), 1);
        assert!(file.contains("second"));
        assert!(!file.contains("first"));
    }

    #[test]
    fn labels_for_different_addresses_accumulate() {
        let (cli, temp_dir) = setup();
        let first = new_address(&cli);
        let second = new_address(&cli);

        wallet(&cli, &["label", "--address", &first, "--text", "one"])
            .assert()
            .success();
        wallet(&cli, &["label", "--address", &second, "--text", "two"])
            .assert()
            .success();

        let file = std::fs::read_to_string(labels_file(&temp_dir)).unwrap();
        assert_eq!(file.lines().count(), 2);
    }

    #[test]
    fn a_label_may_start_with_a_hyphen() {
        let (cli, temp_dir) = setup();
        let address = new_address(&cli);

        wallet(&cli, &["label", "--address", &address, "--text", "-5 sats"])
            .assert()
            .success();

        let file = std::fs::read_to_string(labels_file(&temp_dir)).unwrap();
        assert!(file.contains("-5 sats"));
    }

    #[test]
    fn rejects_an_address_of_another_network() {
        let (cli, temp_dir) = setup();

        wallet(
            &cli,
            &["label", "--address", MAINNET_ADDRESS, "--text", "wrong net"],
        )
        .assert()
        .failure()
        .stderr(predicate::str::contains("is not valid on regtest"));

        assert!(!labels_file(&temp_dir).exists());
    }

    #[test]
    fn rejects_an_address_that_is_not_the_wallets() {
        let (cli, temp_dir) = setup();

        wallet(
            &cli,
            &[
                "label",
                "--address",
                FOREIGN_REGTEST_ADDRESS,
                "--text",
                "not mine",
            ],
        )
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not belong to this wallet"));

        assert!(!labels_file(&temp_dir).exists());
    }

    #[test]
    fn an_unknown_transaction_asks_to_sync_first() {
        let (cli, temp_dir) = setup();

        wallet(
            &cli,
            &["label", "--txid", UNKNOWN_TXID, "--text", "mystery"],
        )
        .assert()
        .failure()
        .stderr(predicate::str::contains("sync the wallet first"));

        assert!(!labels_file(&temp_dir).exists());
    }

    #[test]
    fn an_unknown_utxo_asks_to_sync_first() {
        let (cli, _temp_dir) = setup();
        let outpoint = format!("{UNKNOWN_TXID}:0");

        wallet(&cli, &["label", "--utxo", &outpoint, "--text", "mystery"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("sync the wallet first"));
    }

    #[test]
    fn exactly_one_target_is_required() {
        let (cli, _temp_dir) = setup();
        let address = new_address(&cli);

        wallet(&cli, &["label", "--text", "no target"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--txid"));

        wallet(
            &cli,
            &[
                "label",
                "--txid",
                UNKNOWN_TXID,
                "--address",
                &address,
                "--text",
                "two targets",
            ],
        )
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
    }

    #[test]
    fn an_empty_label_is_rejected() {
        let (cli, temp_dir) = setup();
        let address = new_address(&cli);

        wallet(&cli, &["label", "--address", &address, "--text", "  "])
            .assert()
            .failure()
            .stderr(predicate::str::contains("must not be empty"));

        assert!(!labels_file(&temp_dir).exists());
    }

    #[test]
    fn a_corrupt_labels_file_fails_label_only() {
        let (cli, temp_dir) = setup();
        let address = new_address(&cli);
        std::fs::write(labels_file(&temp_dir), "this is not jsonl\n").unwrap();

        // The label command names the file it could not read...
        wallet(&cli, &["label", "--address", &address, "--text", "x"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("labels.jsonl"));

        // ...and does not touch it...
        assert_eq!(
            std::fs::read_to_string(labels_file(&temp_dir)).unwrap(),
            "this is not jsonl\n"
        );

        // ...while commands that do not use labels keep working.
        wallet(&cli, &["balance"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"total\":"));
    }

    #[cfg(feature = "repl")]
    #[test]
    fn labels_can_be_set_in_the_repl() {
        let (cli, temp_dir) = setup();
        let address = new_address(&cli);

        let output = cli
            .build_base_cmd()
            .args(["repl", "--wallet", WALLET_NAME])
            .write_stdin(format!(
                "wallet label --address {address} --text \"from the repl\"\nexit\n"
            ))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let file = std::fs::read_to_string(labels_file(&temp_dir)).unwrap();
        assert!(file.contains("from the repl"), "labels file: {file}");
    }

    #[test]
    fn transactions_and_unspent_show_labels() {
        let (cli, temp_dir, ext, int) = setup_with_descriptors();
        let received = receive(&temp_dir, &ext, &int, 1);
        let (txid, outpoint) = (
            received[0].txid.to_string(),
            received[0].outpoint.to_string(),
        );

        wallet(&cli, &["label", "--txid", &txid, "--text", "salary"])
            .assert()
            .success();
        wallet(&cli, &["label", "--utxo", &outpoint, "--text", "my coin"])
            .assert()
            .success();

        let transactions = json(&cli, &["transactions"]);
        assert_eq!(
            label_in(&transactions, "txid", &txid).as_deref(),
            Some("salary")
        );
        let unspent = json(&cli, &["unspent"]);
        assert_eq!(
            label_in(&unspent, "outpoint", &outpoint).as_deref(),
            Some("my coin")
        );
    }

    #[test]
    fn unlabelled_items_have_no_label_field() {
        let (cli, temp_dir, ext, int) = setup_with_descriptors();
        let received = receive(&temp_dir, &ext, &int, 1);

        let transactions = json(&cli, &["transactions"]);
        let unspent = json(&cli, &["unspent"]);

        assert_eq!(
            label_in(&transactions, "txid", &received[0].txid.to_string()),
            None
        );
        assert_eq!(
            label_in(&unspent, "outpoint", &received[0].outpoint.to_string()),
            None
        );
    }

    #[test]
    fn a_dash_label_is_told_apart_from_no_label() {
        let (cli, temp_dir, ext, int) = setup_with_descriptors();
        let received = receive(&temp_dir, &ext, &int, 2);
        let (first, second) = (received[0].txid.to_string(), received[1].txid.to_string());

        wallet(&cli, &["label", "--txid", &first, "--text", "\u{2014}"])
            .assert()
            .success();

        let transactions = json(&cli, &["transactions"]);
        assert_eq!(
            label_in(&transactions, "txid", &first).as_deref(),
            Some("\u{2014}")
        );
        assert_eq!(label_in(&transactions, "txid", &second), None);
    }

    #[test]
    fn labelling_a_utxo_keeps_it_spendable_or_frozen_as_it_was() {
        let (cli, temp_dir, ext, int) = setup_with_descriptors();
        let received = receive(&temp_dir, &ext, &int, 1);
        let outpoint = received[0].outpoint.to_string();
        let output_record = |file: &str| -> Value {
            file.lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .find(|record| record["type"] == "output")
                .unwrap()
        };

        // Naming a coin does not freeze it...
        wallet(&cli, &["label", "--utxo", &outpoint, "--text", "my coin"])
            .assert()
            .success();
        let file = std::fs::read_to_string(labels_file(&temp_dir)).unwrap();
        assert_eq!(output_record(&file)["spendable"], true);

        // ...and renaming a coin that was frozen elsewhere does not unfreeze it.
        let frozen = file.replace("\"spendable\":true", "\"spendable\":false");
        std::fs::write(labels_file(&temp_dir), frozen).unwrap();
        wallet(&cli, &["label", "--utxo", &outpoint, "--text", "renamed"])
            .assert()
            .success();
        let file = std::fs::read_to_string(labels_file(&temp_dir)).unwrap();
        assert_eq!(output_record(&file)["spendable"], false);
        assert_eq!(output_record(&file)["label"], "renamed");
    }

    #[test]
    fn unused_address_shows_its_label() {
        let (cli, _temp_dir) = setup();
        let address = new_address(&cli);

        assert_eq!(json(&cli, &["unused_address"]).get("label"), None);
        wallet(
            &cli,
            &["label", "--address", &address, "--text", "from Alice"],
        )
        .assert()
        .success();

        let unused = json(&cli, &["unused_address"]);
        assert_eq!(unused["address"], address.as_str());
        assert_eq!(unused["label"], "from Alice");
    }

    #[test]
    fn a_corrupt_labels_file_does_not_break_display_commands() {
        let (cli, temp_dir, ext, int) = setup_with_descriptors();
        let received = receive(&temp_dir, &ext, &int, 1);
        std::fs::write(labels_file(&temp_dir), "this is not jsonl\n").unwrap();

        // Commands that show labels warn about the file and carry on without labels...
        for command in ["transactions", "unspent", "unused_address"] {
            wallet(&cli, &[command])
                .assert()
                .success()
                .stderr(predicate::str::contains("labels.jsonl"));
        }
        // ...and commands that have nothing to do with labels do not even look at it.
        wallet(&cli, &["balance"])
            .assert()
            .success()
            .stderr(predicate::str::contains("labels.jsonl").not());

        let unspent = json(&cli, &["unspent"]);
        assert_eq!(
            label_in(&unspent, "outpoint", &received[0].outpoint.to_string()),
            None
        );
    }

    #[cfg(feature = "repl")]
    #[test]
    fn labels_are_shown_in_the_repl() {
        let (cli, temp_dir, ext, int) = setup_with_descriptors();
        let received = receive(&temp_dir, &ext, &int, 1);
        let outpoint = received[0].outpoint.to_string();
        wallet(&cli, &["label", "--utxo", &outpoint, "--text", "my coin"])
            .assert()
            .success();

        let output = cli
            .build_base_cmd()
            .args(["repl", "--wallet", WALLET_NAME])
            .write_stdin("wallet unspent\nexit\n")
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("my coin"), "REPL output: {stdout}");
    }

    /// A BIP-329 file with the given lines, in a fresh directory.
    fn bip329_file(lines: &[String]) -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("incoming.jsonl");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        (dir, path)
    }

    fn addr_line(address: &str, label: &str) -> String {
        format!(r#"{{"type":"addr","ref":"{address}","label":"{label}"}}"#)
    }

    fn records(path: &PathBuf) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn label_of(records: &[Value], reference: &str) -> Option<String> {
        records
            .iter()
            .find(|record| record["ref"] == reference)
            .map(|record| record["label"].as_str().unwrap().to_string())
    }

    #[test]
    fn exported_labels_can_be_imported_into_another_wallet() {
        let (cli, _temp_dir) = setup();
        let (first, second) = (new_address(&cli), new_address(&cli));
        wallet(&cli, &["label", "--address", &first, "--text", "one"])
            .assert()
            .success();
        wallet(&cli, &["label", "--address", &second, "--text", "two"])
            .assert()
            .success();
        let out_dir = TempDir::new().unwrap();
        let backup = out_dir.path().join("backup.jsonl");

        let exported = json(&cli, &["export_labels", backup.to_str().unwrap()]);
        assert_eq!(exported["exported"], 2);
        let content = std::fs::read_to_string(&backup).unwrap();
        assert!(
            content.ends_with('\n'),
            "JSONL lines are newline terminated"
        );

        // An empty wallet takes the backup, and exports the very same file again.
        let (other, other_dir) = setup();
        let imported = json(&other, &["import_labels", backup.to_str().unwrap()]);
        assert_eq!(imported["imported"], 2);
        assert_eq!(imported["total"], 2);
        let again = out_dir.path().join("again.jsonl");
        wallet(&other, &["export_labels", again.to_str().unwrap()])
            .assert()
            .success();
        assert_eq!(std::fs::read_to_string(&again).unwrap(), content);
        assert_eq!(records(&labels_file(&other_dir)).len(), 2);
    }

    #[test]
    fn import_keeps_existing_labels_by_default() {
        let (cli, temp_dir) = setup();
        let mine = new_address(&cli);
        wallet(&cli, &["label", "--address", &mine, "--text", "mine"])
            .assert()
            .success();
        let (_dir, incoming) = bip329_file(&[
            addr_line(&mine, "theirs"),
            addr_line(FOREIGN_REGTEST_ADDRESS, "new"),
        ]);

        let result = json(&cli, &["import_labels", incoming.to_str().unwrap()]);

        assert_eq!(result["imported"], 1);
        assert_eq!(result["total"], 2);
        let stored = records(&labels_file(&temp_dir));
        assert_eq!(label_of(&stored, &mine).as_deref(), Some("mine"));
        assert_eq!(
            label_of(&stored, FOREIGN_REGTEST_ADDRESS).as_deref(),
            Some("new")
        );
    }

    #[test]
    fn import_can_overwrite_existing_labels() {
        let (cli, temp_dir) = setup();
        let mine = new_address(&cli);
        wallet(&cli, &["label", "--address", &mine, "--text", "mine"])
            .assert()
            .success();
        let (_dir, incoming) = bip329_file(&[
            addr_line(&mine, "theirs"),
            addr_line(FOREIGN_REGTEST_ADDRESS, "new"),
        ]);

        let result = json(
            &cli,
            &[
                "import_labels",
                incoming.to_str().unwrap(),
                "--strategy",
                "overwrite",
            ],
        );

        assert_eq!(result["imported"], 2);
        let stored = records(&labels_file(&temp_dir));
        assert_eq!(label_of(&stored, &mine).as_deref(), Some("theirs"));
    }

    #[test]
    fn import_keeps_what_the_wallet_does_not_know_and_whether_a_coin_is_frozen() {
        let (cli, temp_dir) = setup();
        let frozen = format!(
            r#"{{"type":"output","ref":"{UNKNOWN_TXID}:1","label":"frozen","spendable":false}}"#
        );
        let (_dir, incoming) = bip329_file(&[
            format!(r#"{{"type":"tx","ref":"{UNKNOWN_TXID}","label":"elsewhere"}}"#),
            frozen,
        ]);

        wallet(&cli, &["import_labels", incoming.to_str().unwrap()])
            .assert()
            .success();

        let stored = records(&labels_file(&temp_dir));
        assert_eq!(stored.len(), 2);
        let output = stored.iter().find(|r| r["type"] == "output").unwrap();
        assert_eq!(output["spendable"], false);
    }

    #[test]
    fn a_bad_import_file_changes_nothing() {
        let (cli, temp_dir) = setup();
        let mine = new_address(&cli);
        wallet(&cli, &["label", "--address", &mine, "--text", "mine"])
            .assert()
            .success();
        let before = std::fs::read_to_string(labels_file(&temp_dir)).unwrap();
        let (_dir, incoming) = bip329_file(&[
            addr_line(FOREIGN_REGTEST_ADDRESS, "fine"),
            "this is not jsonl".to_string(),
        ]);

        wallet(&cli, &["import_labels", incoming.to_str().unwrap()])
            .assert()
            .failure()
            .stderr(predicate::str::contains("incoming.jsonl"));

        assert_eq!(
            std::fs::read_to_string(labels_file(&temp_dir)).unwrap(),
            before
        );
    }

    #[test]
    fn importing_a_missing_file_names_it() {
        let (cli, temp_dir) = setup();

        wallet(&cli, &["import_labels", "/nonexistent/incoming.jsonl"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("/nonexistent/incoming.jsonl"));

        assert!(!labels_file(&temp_dir).exists());
    }

    #[test]
    fn exporting_without_labels_writes_an_empty_file() {
        let (cli, _temp_dir) = setup();
        let out_dir = TempDir::new().unwrap();
        let backup = out_dir.path().join("backup.jsonl");

        let exported = json(&cli, &["export_labels", backup.to_str().unwrap()]);

        assert_eq!(exported["exported"], 0);
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "");
    }

    #[cfg(unix)]
    #[test]
    fn an_export_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let (cli, _temp_dir) = setup();
        let address = new_address(&cli);
        wallet(&cli, &["label", "--address", &address, "--text", "x"])
            .assert()
            .success();
        let out_dir = TempDir::new().unwrap();
        let backup = out_dir.path().join("backup.jsonl");

        wallet(&cli, &["export_labels", backup.to_str().unwrap()])
            .assert()
            .success();

        let mode = std::fs::metadata(&backup).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn imported_labels_survive_for_later_commands() {
        let (cli, temp_dir, ext, int) = setup_with_descriptors();
        let received = receive(&temp_dir, &ext, &int, 1);
        let txid = received[0].txid.to_string();
        let (_dir, incoming) = bip329_file(&[format!(
            r#"{{"type":"tx","ref":"{txid}","label":"from a backup"}}"#
        )]);

        wallet(&cli, &["import_labels", incoming.to_str().unwrap()])
            .assert()
            .success();

        let transactions = json(&cli, &["transactions"]);
        assert_eq!(
            label_in(&transactions, "txid", &txid).as_deref(),
            Some("from a backup")
        );
    }
}
