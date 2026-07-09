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
    fn test_funded_wallet_unspent_and_transactions() {
        let (cli, mut cmd_init, env) = setup_online_wallet();
        cmd_init.assert().success();
        fund_and_sync_wallet(&cli, &env);

        //  unspent: exactly one confirmed, unspent 50,000,000 sat UTXO
        let unspent = run_wallet_json(&cli, &["unspent"]);
        assert_eq!(
            unspent["count"].as_u64(),
            Some(1),
            "funded wallet should report exactly one UTXO, got: {unspent}"
        );

        let utxo = &unspent["items"][0];
        assert_eq!(
            utxo["txout"]["value"].as_u64(),
            Some(50_000_000),
            "the single UTXO should equal the 0.5 BTC funding amount"
        );
        assert_eq!(
            utxo["is_spent"].as_bool(),
            Some(false),
            "the funding UTXO must be unspent"
        );
        assert!(
            utxo["outpoint"].as_str().is_some_and(|o| o.contains(':')),
            "UTXO outpoint should be a `txid:vout` string, got: {}",
            utxo["outpoint"]
        );
        assert!(
            utxo["derivation_index"].is_number(),
            "UTXO should expose a numeric derivation_index"
        );

        // transactions: exactly one relevant tx, funding our address
        let txs = run_wallet_json(&cli, &["transactions"]);
        assert_eq!(
            txs["count"].as_u64(),
            Some(1),
            "funded wallet should report exactly one transaction, got: {txs}"
        );

        let tx = &txs["items"][0];
        assert_eq!(
            tx["is_coinbase"].as_bool(),
            Some(false),
            "the funding transaction is a normal send, not a coinbase"
        );
        assert!(
            tx["txid"].as_str().is_some_and(|t| t.len() == 64),
            "transaction should expose a 64-char hex txid, got: {}",
            tx["txid"]
        );
        // The funding tx must contain the output that paid us 0.5 BTC.
        let outputs = tx["outputs"]
            .as_array()
            .expect("transaction outputs should be a JSON array");
        assert!(
            outputs
                .iter()
                .any(|o| o["value"].as_u64() == Some(50_000_000)),
            "funding tx should contain a 50,000,000 sat output to the wallet"
        );
    }

    #[test]
    fn test_create_tx_send_all_drains_wallet() {
        let (cli, mut cmd_init, env) = setup_online_wallet();
        cmd_init.assert().success();
        fund_and_sync_wallet(&cli, &env);

        let unsigned_psbt = run_wallet_json(
            &cli,
            &["create_tx", "--send_all", "--to", &format!("{RECIPIENT}:0")],
        )["psbt"]
            .as_str()
            .expect("create_tx: missing 'psbt' field")
            .to_string();

        let (signed_psbt, finalized) = cli_sign(&cli, &unsigned_psbt);
        assert!(finalized, "drain PSBT should be finalized after signing");

        let raw_tx = cli_extract_psbt(&cli, &signed_psbt);
        let drain_txid = cli_broadcast(&cli, &raw_tx);
        env.rpc_client()
            .get_mempool_entry(&drain_txid)
            .expect("drain tx not found in node mempool");

        env.mine_blocks(1, None)
            .expect("Failed to mine drain confirmation block");
        env.wait_until_electrum_sees_block(Duration::from_secs(10))
            .expect("Electrum did not catch up to drain confirmation");

        cli_sync(&cli);
        assert_eq!(
            cli_balance(&cli),
            0,
            "send_all should leave a zero confirmed balance"
        );
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

    #[test]
    fn test_create_tx_multiple_recipients() {
        use bdk_wallet::bitcoin::Psbt;

        let (cli, mut cmd_init, env) = setup_online_wallet();
        cmd_init.assert().success();
        fund_and_sync_wallet(&cli, &env);

        let second = cli_new_address(&cli);

        let psbt_b64 = run_wallet_json(
            &cli,
            &[
                "create_tx",
                "--to",
                &format!("{RECIPIENT}:20000"),
                "--to",
                &format!("{second}:30000"),
            ],
        )["psbt"]
            .as_str()
            .expect("create_tx: missing 'psbt' field")
            .to_string();

        let psbt: Psbt = psbt_b64
            .parse()
            .expect("create_tx returned an invalid PSBT");
        let values: Vec<u64> = psbt
            .unsigned_tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .collect();

        assert!(
            values.contains(&20_000),
            "first recipient (20_000) output missing: {values:?}"
        );
        assert!(
            values.contains(&30_000),
            "second recipient (30_000) output missing: {values:?}"
        );
        assert!(
            psbt.unsigned_tx.output.len() >= 2,
            "expected at least the two recipient outputs, got {}",
            psbt.unsigned_tx.output.len()
        );
    }

    // `create_tx --add_string` embeds an OP_RETURN (nulldata) output carrying
    // the given text, at zero value.
    #[test]
    fn test_create_tx_op_return() {
        use bdk_wallet::bitcoin::Psbt;
        let (cli, mut cmd_init, env) = setup_online_wallet();
        cmd_init.assert().success();
        fund_and_sync_wallet(&cli, &env);

        let msg = "hello bdk cli";
        let psbt_b64 = run_wallet_json(
            &cli,
            &[
                "create_tx",
                "--to",
                &format!("{RECIPIENT}:20000"),
                "--add_string",
                msg,
            ],
        )["psbt"]
            .as_str()
            .unwrap()
            .to_string();

        let psbt: Psbt = psbt_b64.parse().expect("invalid PSBT");
        let op_return = psbt
            .unsigned_tx
            .output
            .iter()
            .find(|o| o.script_pubkey.is_op_return())
            .expect("expected an OP_RETURN output");
        assert_eq!(
            op_return.value.to_sat(),
            0,
            "OP_RETURN output must carry 0 value"
        );
        assert!(
            op_return
                .script_pubkey
                .as_bytes()
                .windows(msg.len())
                .any(|w| w == msg.as_bytes()),
            "OP_RETURN should embed the message bytes"
        );
    }

    // `create_tx --utxos` forces a specific UTXO to be spent;
    // `--unspendable`excludes one. Funds two UTXOs so the selection is actually observable.
    #[test]
    fn test_create_tx_utxo_selection() {
        use bdk_wallet::bitcoin::Psbt;
        let (cli, mut cmd_init, env) = setup_online_wallet();
        cmd_init.assert().success();

        let node_addr = env
            .rpc_client()
            .get_new_address(None, None)
            .unwrap()
            .assume_checked();
        env.mine_blocks(101, Some(node_addr)).unwrap();
        env.wait_until_electrum_sees_block(Duration::from_secs(10))
            .unwrap();
        let a1 = cli_new_address(&cli);
        let t1 = env.send(&a1, Amount::from_btc(0.3).unwrap()).unwrap();
        env.wait_until_electrum_sees_txid(t1, Duration::from_secs(10))
            .unwrap();
        let a2 = cli_new_address(&cli);
        let t2 = env.send(&a2, Amount::from_btc(0.2).unwrap()).unwrap();
        env.wait_until_electrum_sees_txid(t2, Duration::from_secs(10))
            .unwrap();
        env.mine_blocks(3, None).unwrap();
        env.wait_until_electrum_sees_block(Duration::from_secs(10))
            .unwrap();
        cli_full_scan(&cli);

        let unspent = run_wallet_json(&cli, &["unspent"]);
        let items = unspent["items"].as_array().unwrap();
        assert_eq!(items.len(), 2, "expected two UTXOs, got {}", items.len());
        let op0 = items[0]["outpoint"].as_str().unwrap().to_string();

        // --utxos forces op0 to be an input.
        let psbt_a: Psbt = run_wallet_json(
            &cli,
            &[
                "create_tx",
                "--to",
                &format!("{RECIPIENT}:10000"),
                "--utxos",
                &op0,
            ],
        )["psbt"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let inputs_a: Vec<String> = psbt_a
            .unsigned_tx
            .input
            .iter()
            .map(|i| i.previous_output.to_string())
            .collect();
        assert!(
            inputs_a.contains(&op0),
            "--utxos should force {op0}: {inputs_a:?}"
        );

        // --unspendable excludes op0 (the other UTXO covers the amount).
        let psbt_b: Psbt = run_wallet_json(
            &cli,
            &[
                "create_tx",
                "--to",
                &format!("{RECIPIENT}:10000"),
                "--unspendable",
                &op0,
            ],
        )["psbt"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let inputs_b: Vec<String> = psbt_b
            .unsigned_tx
            .input
            .iter()
            .map(|i| i.previous_output.to_string())
            .collect();
        assert!(
            !inputs_b.contains(&op0),
            "--unspendable should exclude {op0}: {inputs_b:?}"
        );
    }

    #[cfg(feature = "rpc")]
    mod test_rpc {
        use super::*;

        static WALLET_NAME: &str = "test_rpc_wallet";

        #[test]
        fn test_rpc_full_scan_reflects_funding() {
            let env = TestEnv::new().expect("start testenv");
            let rpc_url = env.bitcoind.rpc_url();
            let cookie = env
                .bitcoind
                .params
                .cookie_file
                .to_str()
                .unwrap()
                .to_string();

            let temp_dir = TempDir::new().unwrap();
            let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));

            // descriptors
            let desc = cli.cmd("descriptor", &["--type", "tr"]).output().unwrap();
            let dv: Value = serde_json::from_slice(&desc.stdout).unwrap();
            let ext = dv["private_descriptors"]["external"].as_str().unwrap();
            let int = dv["private_descriptors"]["internal"].as_str().unwrap();

            // config: rpc client-type, --url flag, cookie as a POSITIONAL arg
            cli.build_base_cmd()
                .args(["wallet", "--wallet", WALLET_NAME, "config"])
                .args(["--ext-descriptor", ext, "--int-descriptor", int])
                .args(["--client-type", "rpc", "--database-type", "sqlite"])
                .args(["--url", &rpc_url])
                .arg(&cookie)
                .assert()
                .success();

            // wallet address to fund
            let out = cli
                .wallet_cmd(&["--wallet", WALLET_NAME, "new_address"])
                .output()
                .unwrap();
            let addr_json: Value = serde_json::from_slice(&out.stdout).unwrap();
            let address = Address::from_str(addr_json["address"].as_str().unwrap())
                .unwrap()
                .require_network(Network::Regtest)
                .unwrap();

            // fund + confirm
            let node_addr = env
                .rpc_client()
                .get_new_address(None, None)
                .unwrap()
                .assume_checked();
            env.mine_blocks(101, Some(node_addr)).unwrap();
            env.send(&address, Amount::from_btc(0.5).unwrap()).unwrap();
            env.mine_blocks(3, None).unwrap();

            // full_scan + balance via rpc
            let scan = cli
                .wallet_cmd(&["--wallet", WALLET_NAME, "full_scan"])
                .output()
                .unwrap();
            assert!(
                scan.status.success(),
                "rpc full_scan failed: {}",
                String::from_utf8_lossy(&scan.stderr)
            );

            let bal = cli
                .wallet_cmd(&["--wallet", WALLET_NAME, "balance"])
                .output()
                .unwrap();
            let bj: Value = serde_json::from_slice(&bal.stdout).unwrap();
            assert_eq!(
                bj["confirmed"].as_u64(),
                Some(50_000_000),
                "rpc-synced confirmed balance mismatch: {bj}"
            );
        }
    }

    #[cfg(feature = "silent-payments")]
    mod test_sp {
        use super::*;
        use bdk_wallet::bitcoin::{Transaction, consensus::encode::deserialize_hex};

        const SCAN: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        const SPEND: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        static WALLET: &str = "sp_wallet";

        #[test]
        fn test_create_sp_tx_produces_taproot_output() {
            let env = TestEnv::new().unwrap();
            let url = env.electrsd.electrum_url.as_str();
            let tmp = TempDir::new().unwrap();
            let cli = BdkCli::new("regtest", Some(tmp.path().to_path_buf()));

            let desc = cli.cmd("descriptor", &["--type", "tr"]).output().unwrap();
            let dv: Value = serde_json::from_slice(&desc.stdout).unwrap();
            let ext_desc = dv["private_descriptors"]["external"].as_str().unwrap();
            let int_desc = dv["private_descriptors"]["internal"].as_str().unwrap();
            cli.build_base_cmd()
                .args([
                    "wallet",
                    "--wallet",
                    WALLET,
                    "config",
                    "--ext-descriptor",
                    ext_desc,
                    "--int-descriptor",
                    int_desc,
                    "--client-type",
                    "electrum",
                    "--database-type",
                    "sqlite",
                    "--url",
                    url,
                ])
                .assert()
                .success();

            let new_address = cli
                .wallet_cmd(&["--wallet", WALLET, "new_address"])
                .output()
                .unwrap();
            let addr = Address::from_str(
                serde_json::from_slice::<Value>(&new_address.stdout).unwrap()["address"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap();
            let node_address = env
                .rpc_client()
                .get_new_address(None, None)
                .unwrap()
                .assume_checked();
            env.mine_blocks(101, Some(node_address)).unwrap();
            env.wait_until_electrum_sees_block(Duration::from_secs(10))
                .unwrap();
            let txid = env.send(&addr, Amount::from_btc(0.5).unwrap()).unwrap();
            env.wait_until_electrum_sees_txid(txid, Duration::from_secs(10))
                .unwrap();
            env.mine_blocks(3, None).unwrap();
            env.wait_until_electrum_sees_block(Duration::from_secs(10))
                .unwrap();
            cli.wallet_cmd(&["--wallet", WALLET, "full_scan"])
                .assert()
                .success();

            let silent_payment_output = cli
                .cmd(
                    "silent_payment_code",
                    &["--scan_key", SCAN, "--spend_key", SPEND],
                )
                .output()
                .unwrap();
            let sp_code =
                serde_json::from_slice::<Value>(&silent_payment_output.stdout).unwrap()["message"]
                    .as_str()
                    .unwrap()
                    .to_string();

            let out = cli
                .wallet_cmd(&[
                    "--wallet",
                    WALLET,
                    "create_sp_tx",
                    "--to-sp",
                    &format!("{sp_code}:20000"),
                ])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "create_sp_tx failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let rawtx = serde_json::from_slice::<Value>(&out.stdout).unwrap()["raw_tx"]
                .as_str()
                .unwrap()
                .to_string();

            let tx: Transaction = deserialize_hex(&rawtx).expect("invalid raw tx");
            let sp_out = tx
                .output
                .iter()
                .find(|o| o.value.to_sat() == 20_000)
                .expect("no 20_000 output");
            assert!(
                sp_out.script_pubkey.is_p2tr(),
                "SP recipient output should be P2TR"
            );
        }
    }
    /**
        #[cfg(feature = "bip322")]
        #[test]
        fn test_verify_message_proof_of_funds_uses_persisted_utxos() {
            let env = TestEnv::new().expect("Failed to start bdk_testenv");
            let server_url = env.electrsd.electrum_url.as_str();
            let temp_dir = TempDir::new().unwrap();
            let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));

            // A wpkh wallet
            let desc = cli.cmd("descriptor", &["--type", "wpkh"]).output().unwrap();
            let desc_val: Value = serde_json::from_slice(&desc.stdout).unwrap();
            let ext_desc = desc_val["private_descriptors"]["external"]
                .as_str()
                .unwrap();
            let int_desc = desc_val["private_descriptors"]["internal"]
                .as_str()
                .unwrap();
            cli.build_base_cmd()
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
                .arg(server_url)
                .assert()
                .success();

            // Fund a single small UTXO
            let address = cli_new_address(&cli);
            let node_addr = env
                .rpc_client()
                .get_new_address(None, None)
                .unwrap()
                .assume_checked();
            env.mine_blocks(101, Some(node_addr)).unwrap();
            env.wait_until_electrum_sees_block(Duration::from_secs(10))
                .unwrap();
            let txid = env.send(&address, Amount::from_sat(5_000)).unwrap();
            env.wait_until_electrum_sees_txid(txid, Duration::from_secs(10))
                .unwrap();
            env.mine_blocks(3, None).unwrap();
            env.wait_until_electrum_sees_block(Duration::from_secs(10))
                .unwrap();
            cli_full_scan(&cli);

            // The funded outpoint to prove control of.
            let unspent = run_wallet_json(&cli, &["unspent"]);
            let outpoint = unspent["items"][0]["outpoint"]
                .as_str()
                .expect("funded wallet should have one UTXO")
                .to_string();
            let addr = address.to_string();

            // Produce a proof-of-funds over that UTXO.
            let proof = run_wallet_json(
                &cli,
                &[
                    "sign_message",
                    "--message",
                    "proof-of-funds",
                    "--address",
                    &addr,
                    "--signature-type",
                    "fullproofoffunds",
                    "--utxos",
                    &outpoint,
                ],
            )["proof"]
                .as_str()
                .expect("sign_message should return a proof")
                .to_string();

            let result = run_wallet_json(
                &cli,
                &[
                    "verify_message",
                    "--proof",
                    &proof,
                    "--message",
                    "proof-of-funds",
                    "--address",
                    &addr,
                ],
            );
            assert_eq!(
                result["valid"].as_bool(),
                Some(true),
                "proof-of-funds should verify against the persisted wallet: {result}"
            );
            assert_eq!(
                result["proven_amount"].as_u64(),
                Some(5_000),
                "proven_amount should equal the funded UTXO value: {result}"
            );
        }
    */
    // `create_dns_tx` with a plain `--to` recipient
    #[cfg(feature = "dns_payment")]
    #[test]
    fn test_create_dns_tx_plain_recipient() {
        use bdk_wallet::bitcoin::Psbt;
        let (cli, mut cmd_init, env) = setup_online_wallet();
        cmd_init.assert().success();
        fund_and_sync_wallet(&cli, &env);

        let psbt_b64 = run_wallet_json(
            &cli,
            &["create_dns_tx", "--to", &format!("{RECIPIENT}:20000")],
        )["psbt"]
            .as_str()
            .expect("create_dns_tx: missing 'psbt'")
            .to_string();

        let psbt: Psbt = psbt_b64
            .parse()
            .expect("create_dns_tx returned an invalid PSBT");
        assert!(
            psbt.unsigned_tx
                .output
                .iter()
                .any(|o| o.value.to_sat() == 20_000),
            "expected the 20_000 sat recipient output"
        );
    }

    // With neither `--to` nor `--to_dns`, the command errors.
    #[cfg(feature = "dns_payment")]
    #[test]
    fn test_create_dns_tx_requires_recipient() {
        let (cli, mut cmd_init, _env) = setup_online_wallet();
        cmd_init.assert().success();

        let out = cli
            .wallet_cmd(&["--wallet", WALLET_NAME, "create_dns_tx"])
            .output()
            .unwrap();
        assert!(!out.status.success(), "should fail with no recipients");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("Either --to or --to_dns"),
            "expected recipient-required error, got: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[cfg(feature = "esplora")]
mod test_esplora {
    use crate::common::BdkCli;
    use bdk_testenv::{TestEnv, bitcoincore_rpc::RpcApi};
    use bdk_wallet::bitcoin::{Address, Amount, Network};
    use serde_json::Value;
    use std::str::FromStr;
    use std::time::Duration;
    use tempfile::TempDir;

    static WALLET_NAME: &str = "test_esplora_wallet";

    // config an esplora wallet, fund it, `full_scan`, and confirm the synced balance.
    #[test]
    fn test_esplora_full_scan_reflects_funding() {
        let env = TestEnv::new().expect("start testenv");
        let esplora = env
            .electrsd
            .esplora_url
            .clone()
            .expect("esplora http endpoint (TestEnv sets http_enabled)");
        // esplora_url is a bind addr ("0.0.0.0:PORT"); connect via loopback.
        let url = format!("http://{}", esplora.replace("0.0.0.0", "127.0.0.1"));

        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));

        let desc = cli.cmd("descriptor", &["--type", "tr"]).output().unwrap();
        let desc_value: Value = serde_json::from_slice(&desc.stdout).unwrap();
        let ext = desc_value["private_descriptors"]["external"]
            .as_str()
            .unwrap();
        let int = desc_value["private_descriptors"]["internal"]
            .as_str()
            .unwrap();
        cli.build_base_cmd()
            .args(["wallet", "--wallet", WALLET_NAME, "config"])
            .args(["--ext-descriptor", ext, "--int-descriptor", int])
            .args(["--client-type", "esplora", "--database-type", "sqlite"])
            .args(["--url", &url])
            .assert()
            .success();

        let out = cli
            .wallet_cmd(&["--wallet", WALLET_NAME, "new_address"])
            .output()
            .unwrap();
        let address = Address::from_str(
            serde_json::from_slice::<Value>(&out.stdout).unwrap()["address"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();

        let node_addr = env
            .rpc_client()
            .get_new_address(None, None)
            .unwrap()
            .assume_checked();
        env.mine_blocks(101, Some(node_addr)).unwrap();
        env.wait_until_electrum_sees_block(Duration::from_secs(10))
            .unwrap();
        let txid = env.send(&address, Amount::from_btc(0.5).unwrap()).unwrap();
        env.wait_until_electrum_sees_txid(txid, Duration::from_secs(10))
            .unwrap();
        env.mine_blocks(3, None).unwrap();
        env.wait_until_electrum_sees_block(Duration::from_secs(10))
            .unwrap();

        let scan = cli
            .wallet_cmd(&["--wallet", WALLET_NAME, "full_scan"])
            .output()
            .unwrap();
        assert!(
            scan.status.success(),
            "esplora full_scan failed: {}",
            String::from_utf8_lossy(&scan.stderr)
        );

        let bal = cli
            .wallet_cmd(&["--wallet", WALLET_NAME, "balance"])
            .output()
            .unwrap();
        let bj: Value = serde_json::from_slice(&bal.stdout).unwrap();
        assert_eq!(
            bj["confirmed"].as_u64(),
            Some(50_000_000),
            "esplora-synced confirmed balance mismatch: {bj}"
        );
    }
}
