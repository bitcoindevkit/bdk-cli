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

use bdk_wallet::bitcoin::Network;
use log::{debug, warn};

use crate::commands::{CliOpts, CliSubCommand, WalletSubCommand};
use crate::error::BDKCliError as Error;
use crate::handlers::{AppCommand, AppContext};
use crate::utils::output::FormatOutput;
use crate::utils::runtime::WalletRuntime;
use crate::utils::{command_requires_db, prepare_home_dir};
use clap::{CommandFactory, Parser};

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
            WalletSubCommand::OnlineWalletSubCommand(cmd) => {
                let runtime = WalletRuntime::load(&home_dir, &wallet_name)?;
                let mut wallet = runtime.build_wallet(true)?;
                let client = runtime.build_client(&wallet)?;
                {
                    let mut ctx = AppContext::new_online_wallet(
                        runtime.network,
                        runtime.home_dir.clone(),
                        &mut wallet,
                        &client,
                    );

                    cmd.execute(&mut ctx).await?;
                }
                wallet.persist()?;
            }

            WalletSubCommand::OfflineWalletSubCommand(cmd) => {
                let runtime = WalletRuntime::load(&home_dir, &wallet_name)?;
                let mut wallet = runtime.build_wallet(command_requires_db(&cmd))?;

                {
                    let mut ctx = AppContext::new_offline_wallet(
                        runtime.network,
                        runtime.home_dir.clone(),
                        &mut wallet,
                    );

                    cmd.execute(&mut ctx)?;
                }
                wallet.persist()?;
            }

            WalletSubCommand::Config(mut config_cmd) => {
                config_cmd.wallet_opts.wallet = Some(wallet_name);

                let mut ctx = AppContext::new(cli_opts.network, home_dir);

                config_cmd.execute(&mut ctx)?.write_out(std::io::stdout())?;
            }
        },

        CliSubCommand::Key { subcommand } => {
            let mut ctx = AppContext::new(cli_opts.network, home_dir);

            subcommand.execute(&mut ctx)?;
        }

        CliSubCommand::Descriptor(cmd) => {
            let mut ctx = AppContext::new(cli_opts.network, home_dir);

            cmd.execute(&mut ctx)?.write_out(std::io::stdout())?;
        }

        CliSubCommand::Wallets(cmd) => {
            let mut ctx = AppContext::new(cli_opts.network, home_dir);

            cmd.execute(&mut ctx)?.write_out(std::io::stdout())?;
        }

        #[cfg(feature = "repl")]
        CliSubCommand::Repl {
            wallet: wallet_name,
        } => {
            let runtime = WalletRuntime::load(&home_dir, &wallet_name)?;

            let mut wallet = runtime.build_wallet(true)?;

            #[cfg(any(
                feature = "electrum",
                feature = "esplora",
                feature = "rpc",
                feature = "cbf"
            ))]
            let client = runtime.build_client(&wallet).ok();

            println!(
                "Entering REPL mode for wallet '{}'. \
                     Type 'exit' to quit.",
                wallet_name
            );

            loop {
                let line = crate::handlers::repl::readline()?;

                if line.trim().is_empty() {
                    continue;
                }

                let should_exit = crate::handlers::repl::respond(
                    runtime.network,
                    &mut wallet,
                    #[cfg(any(
                        feature = "electrum",
                        feature = "esplora",
                        feature = "rpc",
                        feature = "cbf"
                    ))]
                    client.as_ref(),
                    &line,
                    runtime.home_dir.clone(),
                )
                .await
                .map_err(Error::Generic)?;

                if should_exit {
                    break;
                }
            }
        }

        #[cfg(feature = "compiler")]
        CliSubCommand::Compile(cmd) => {
            let mut ctx = AppContext::new(cli_opts.network, home_dir);

            cmd.execute(&mut ctx)?.write_out(std::io::stdout())?;
        }
        CliSubCommand::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut CliOpts::command(),
                "bdk-cli",
                &mut std::io::stdout(),
            );
        }
        #[cfg(feature = "silent-payments")]
        CliSubCommand::SilentPaymentCode(cmd) => {
            let mut ctx = AppContext::new(cli_opts.network, home_dir);

            cmd.execute(&mut ctx)?.write_out(std::io::stdout())?;
        }
    }

    Ok(())
}
