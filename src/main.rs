// Copyright (c) 2020-2025 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://github.com/bitcoindevkit/bdk/raw/master/static/bdk.png")]
#![warn(missing_docs)]

mod client;
mod commands;
mod config;
mod error;
mod handlers;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
mod payjoin;
mod persister;
mod utils;

#[cfg(feature = "redb")]
use bdk_redb::Store as RedbStore;
use bdk_wallet::bitcoin::Network;
use log::{debug, warn};

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
use crate::client::new_blockchain_client;
use crate::commands::{CliOpts, CliSubCommand, WalletSubCommand};
use crate::error::BDKCliError as Error;
use crate::handlers::{AppCommand, AppContext};
#[cfg(any(feature = "sqlite", feature = "redb"))]
use crate::persister::{Persister, new_persisted_wallet};
use crate::utils::output::FormatOutput;
use crate::utils::prepare_wallet_db_dir;
use crate::utils::{load_wallet_config, prepare_home_dir};
use clap::Parser;

#[tokio::main]
async fn main() {
    env_logger::init();
    let cli_opts: CliOpts = CliOpts::parse();

    let network = &cli_opts.network;
    debug!("network: {network:?}");
    if network == &Network::Bitcoin {
        warn!(
            "This is experimental software and not currently recommended for use on Bitcoin mainnet, proceed with caution."
        )
    }

    if let Err(e) = run(cli_opts).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run(cli_opts: CliOpts) -> Result<(), Error> {
    let datadir = cli_opts.datadir.clone();
    let home_dir = prepare_home_dir(datadir)?;

    match cli_opts.subcommand.clone() {
        CliSubCommand::Wallet {
            wallet: wallet_name,
            subcommand,
        } => match subcommand {
            #[cfg(any(
                feature = "electrum",
                feature = "esplora",
                feature = "rpc",
                feature = "cbf"
            ))]
            WalletSubCommand::OnlineWalletSubCommand(online_cmd) => {
                let (wallet_opts, network) = load_wallet_config(&home_dir, &wallet_name)?;

                let database_path = prepare_wallet_db_dir(&home_dir, &wallet_name)?;
                #[cfg(any(feature = "sqlite", feature = "redb"))]
                let mut persister: Persister = match &wallet_opts.database_type {
                    #[cfg(feature = "sqlite")]
                    crate::persister::DatabaseType::Sqlite => {
                        let db_file = database_path.join("wallet.sqlite");
                        let connection = bdk_wallet::rusqlite::Connection::open(db_file)?;
                        Persister::Connection(connection)
                    }
                    #[cfg(feature = "redb")]
                    crate::persister::DatabaseType::Redb => {
                        use crate::persister::Persister;

                        let db = std::sync::Arc::new(bdk_redb::redb::Database::create(
                            home_dir.join("wallet.redb"),
                        )?);
                        let store = RedbStore::new(db, wallet_name)?;
                        log::debug!("Redb database opened successfully");
                        Persister::RedbStore(store)
                    }
                };

                let mut wallet = new_persisted_wallet(network, &mut persister, &wallet_opts)?;

                let client = new_blockchain_client(&wallet_opts, &wallet, database_path)?;

                let mut ctx = AppContext::new(network, home_dir)
                    .with_wallet(&mut wallet)
                    .with_client(&client);

                online_cmd.execute(&mut ctx).await?;
            }
            WalletSubCommand::OfflineWalletSubCommand(offline_cmd) => {
                let (wallet_opts, network) = load_wallet_config(&home_dir, &wallet_name)?;

                let database_path = prepare_wallet_db_dir(&home_dir, &wallet_name)?;

                #[cfg(any(feature = "sqlite", feature = "redb"))]
                let mut persister: Persister = match &wallet_opts.database_type {
                    #[cfg(feature = "sqlite")]
                    crate::persister::DatabaseType::Sqlite => {
                        let db_file = database_path.join("wallet.sqlite");
                        let connection = bdk_wallet::rusqlite::Connection::open(db_file)?;
                        Persister::Connection(connection)
                    }
                    #[cfg(feature = "redb")]
                    crate::persister::DatabaseType::Redb => {
                        use crate::persister::Persister;
                        let db = std::sync::Arc::new(bdk_redb::redb::Database::create(
                            home_dir.join("wallet.redb"),
                        )?);
                        let store = RedbStore::new(db, wallet_name)?;
                        Persister::RedbStore(store)
                    }
                };

                let mut wallet = new_persisted_wallet(network, &mut persister, &wallet_opts)?;

                let mut ctx = AppContext::new(network, home_dir).with_wallet(&mut wallet);

                offline_cmd.execute(&mut ctx)?;
            }
            WalletSubCommand::Config(mut config_cmd) => {
                config_cmd.wallet_opts.wallet = Some(wallet_name);

                let mut ctx = AppContext::new(cli_opts.network, home_dir);

                config_cmd.execute(&mut ctx)?.print()?;
            }
        },

        CliSubCommand::Key { subcommand } => {
            let mut ctx = AppContext::new(cli_opts.network, home_dir);
            subcommand.execute(&mut ctx)?;
        }
        CliSubCommand::Descriptor(descriptor_command) => {
            let mut ctx = AppContext::new(cli_opts.network, home_dir);
            descriptor_command.execute(&mut ctx)?.print()?;
        }
        CliSubCommand::Wallets(cmd) => {
            let mut ctx = AppContext::new(cli_opts.network, home_dir);
            cmd.execute(&mut ctx)?.print()?;
        }
        CliSubCommand::Repl { wallet: _ } => todo!(),
        CliSubCommand::Completions { shell } => {
        shell;
        }
        #[cfg(feature = "compiler")]
        CliSubCommand::Compile(cmd) => {
            let mut ctx = AppContext::new(cli_opts.network, home_dir);
            cmd.execute(&mut ctx)?.print()?;
        }
    };

    Ok(())
}
