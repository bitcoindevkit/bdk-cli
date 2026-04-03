// Copyright (c) 2020-2025 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! bdk-cli integration tests

#[cfg(feature = "electrum")]
mod test {
    use std::{env, str::FromStr, time::Duration};

    #[cfg(feature = "cbf")]
    use bdk_cli::commands::CompactFilterOpts;
    #[cfg(any(feature = "sqlite", feature = "redb"))]
    use bdk_cli::commands::DatabaseType;
    use bdk_cli::commands::{
        CliOpts, CliSubCommand, ClientType, OfflineWalletSubCommand, OnlineWalletSubCommand,
        WalletOpts,
    };
    use bdk_cli::handlers::{handle_offline_wallet_subcommand, handle_online_wallet_subcommand};
    use bdk_cli::utils::new_blockchain_client;
    use bdk_testenv::{
        TestEnv,
        anyhow::{Context, Result, anyhow},
        bitcoincore_rpc::RpcApi,
    };
    use bdk_wallet::{
        Wallet,
        bitcoin::{Address, Amount, Network},
    };
    use serde_json::Value;

    const EXTERNAL_DESCRIPTOR: &str = "wpkh([07234a14/84'/1'/0']tpubDCSgT6PaVLQH9h2TAxKryhvkEurUBcYRJc9dhTcMDyahhWiMWfEWvQQX89yaw7w7XU8bcVujoALfxq59VkFATri3Cxm5mkp9kfHfRFDckEh/0/*)#429nsxmg";
    const INTERNAL_DESCRIPTOR: &str = "wpkh([07234a14/84'/1'/0']tpubDCSgT6PaVLQH9h2TAxKryhvkEurUBcYRJc9dhTcMDyahhWiMWfEWvQQX89yaw7w7XU8bcVujoALfxq59VkFATri3Cxm5mkp9kfHfRFDckEh/1/*)#y7qjdnts";

    fn test_env() -> Result<TestEnv> {
        TestEnv::new()
    }

    fn mine_blocks_in_batches(env: &TestEnv, count: usize, address: &Address) -> Result<()> {
        let mut remaining = count;
        while remaining > 0 {
            let batch_size = remaining.min(10);
            let mut attempt = 0;
            loop {
                match env.mine_blocks(batch_size, Some(address.clone())) {
                    Ok(_) => break,
                    Err(_) if attempt < 2 => {
                        attempt += 1;
                        std::thread::sleep(Duration::from_millis(250));
                        continue;
                    }
                    Err(error) => {
                        return Err(error).context(format!(
                            "failed to mine a batch of {batch_size} blocks after {attempt} retries"
                        ));
                    }
                }
            }
            remaining -= batch_size;
        }

        Ok(())
    }

    fn cli_opts() -> CliOpts {
        CliOpts {
            network: Network::Regtest,
            datadir: None,
            pretty: false,
            subcommand: CliSubCommand::Wallets,
        }
    }

    fn wallet_opts(electrum_url: String) -> WalletOpts {
        #[cfg(any(feature = "sqlite", feature = "redb"))]
        let database_type = {
            #[cfg(feature = "sqlite")]
            {
                DatabaseType::Sqlite
            }
            #[cfg(all(not(feature = "sqlite"), feature = "redb"))]
            {
                DatabaseType::Redb
            }
        };

        WalletOpts {
            wallet: Some("integration-test".to_string()),
            verbose: false,
            ext_descriptor: EXTERNAL_DESCRIPTOR.to_string(),
            int_descriptor: Some(INTERNAL_DESCRIPTOR.to_string()),
            #[cfg(any(
                feature = "electrum",
                feature = "esplora",
                feature = "rpc",
                feature = "cbf"
            ))]
            client_type: ClientType::Electrum,
            #[cfg(any(feature = "sqlite", feature = "redb"))]
            database_type,
            #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
            url: electrum_url,
            #[cfg(feature = "electrum")]
            batch_size: 10,
            #[cfg(feature = "esplora")]
            parallel_requests: 5,
            #[cfg(feature = "rpc")]
            basic_auth: ("user".to_string(), "password".to_string()),
            #[cfg(feature = "rpc")]
            cookie: None,
            #[cfg(feature = "cbf")]
            compactfilter_opts: CompactFilterOpts { conn_count: 2 },
        }
    }

    fn parse_json(output: &str) -> Result<Value> {
        Ok(serde_json::from_str(output)?)
    }

    fn address_from_output(output: &str) -> Result<Address> {
        let parsed_output = parse_json(output)?;
        let address = parsed_output
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("address missing from handler output"))?;
        Ok(Address::from_str(address)?.assume_checked())
    }

    fn confirmed_balance_from_output(output: &str) -> Result<u64> {
        parse_json(output)?
            .get("satoshi")
            .and_then(|balance| balance.get("confirmed"))
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("confirmed balance missing from handler output"))
    }

    #[tokio::test]
    async fn sync_updates_balance_for_a_funded_wallet() -> Result<()> {
        let env = test_env().context("failed to start test environment")?;
        let cli_opts = cli_opts();
        let wallet_opts = wallet_opts(env.electrsd.electrum_url.clone());
        let mut wallet = Wallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .context("failed to create in-memory wallet")?;

        let address_output = handle_offline_wallet_subcommand(
            &mut wallet,
            &wallet_opts,
            &cli_opts,
            OfflineWalletSubCommand::NewAddress,
        )
        .context("failed to derive a receive address from the offline handler")?;
        let receive_address =
            address_from_output(&address_output).context("failed to parse receive address")?;

        let miner = env
            .rpc_client()
            .get_new_address(None, None)
            .context("failed to get a mining address from bitcoind")?
            .assume_checked();
        mine_blocks_in_batches(&env, 101, &miner)
            .context("failed to mine initial spendable coins")?;

        let sent_amount = Amount::from_sat(50_000);
        let txid = env
            .send(&receive_address, sent_amount)
            .context("failed to fund the test wallet")?;
        mine_blocks_in_batches(&env, 1, &miner)
            .context("failed to confirm the funding transaction")?;
        env.wait_until_electrum_sees_block(Duration::from_secs(15))
            .context("electrs did not observe the confirmation block in time")?;
        env.wait_until_electrum_sees_txid(txid, Duration::from_secs(15))
            .context("electrs did not index the funding transaction in time")?;

        let blockchain_client = new_blockchain_client(&wallet_opts, &wallet, env::temp_dir())
            .context("failed to build the electrum blockchain client")?;
        handle_online_wallet_subcommand(
            &mut wallet,
            &blockchain_client,
            OnlineWalletSubCommand::Sync,
        )
        .await
        .context("wallet sync handler failed")?;

        let balance_output = handle_offline_wallet_subcommand(
            &mut wallet,
            &wallet_opts,
            &cli_opts,
            OfflineWalletSubCommand::Balance,
        )
        .context("balance handler failed after sync")?;
        let confirmed_balance = confirmed_balance_from_output(&balance_output)
            .context("failed to parse confirmed balance from handler output")?;

        assert_eq!(confirmed_balance, sent_amount.to_sat());

        Ok(())
    }
}
