// Magical Bitcoin Library
// Written in 2020 by
//     Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020 Magical Bitcoin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use bitcoin::Network;
use clap::AppSettings;
use log::{debug, info, warn};
use rustyline::error::ReadlineError;
use rustyline::Editor;
use structopt::StructOpt;

#[cfg(feature = "esplora")]
use bdk::blockchain::esplora::EsploraBlockchainConfig;
use bdk::blockchain::{
    AnyBlockchain, AnyBlockchainConfig, ConfigurableBlockchain, ElectrumBlockchainConfig,
};
use bdk::database::BatchDatabase;
use bdk::sled;
use bdk::sled::Tree;
use bdk::Wallet;
use bdk::{bitcoin, Error};
use bdk_cli::WalletSubCommand;
use bdk_cli::{
    CliOpts, CliSubCommand, KeySubCommand, OfflineWalletSubCommand, OnlineWalletSubCommand,
    WalletOpts,
};
use regex::Regex;

#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(name = "", setting = AppSettings::NoBinaryName,
version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"),
author = option_env ! ("CARGO_PKG_AUTHORS").unwrap_or(""))]
struct ReplOpt {
    /// Wallet sub-command
    #[structopt(subcommand)]
    pub subcommand: ReplSubCommand,
}

#[derive(Debug, StructOpt, Clone, PartialEq)]
pub enum ReplSubCommand {
    #[structopt(flatten)]
    OnlineWalletSubCommand(OnlineWalletSubCommand),
    #[structopt(flatten)]
    OfflineWalletSubCommand(OfflineWalletSubCommand),
    #[structopt(flatten)]
    KeySubCommand(KeySubCommand),
    /// Exit REPL loop
    Exit,
}

fn prepare_home_dir() -> PathBuf {
    let mut dir = PathBuf::new();
    dir.push(&dirs_next::home_dir().unwrap());
    dir.push(".bdk-bitcoin");

    if !dir.exists() {
        info!("Creating home directory {}", dir.as_path().display());
        fs::create_dir(&dir).unwrap();
    }

    dir.push("database.sled");
    dir
}

fn open_database(wallet_opts: &WalletOpts) -> Tree {
    let database = sled::open(prepare_home_dir().to_str().unwrap()).unwrap();
    let tree = database.open_tree(&wallet_opts.wallet).unwrap();
    debug!("database opened successfully");
    tree
}

fn new_online_wallet<D>(
    network: Network,
    wallet_opts: &WalletOpts,
    database: D,
) -> Result<Wallet<AnyBlockchain, D>, Error>
where
    D: BatchDatabase,
{
    // Try to use Esplora config if "esplora" feature is enabled
    #[cfg(feature = "esplora")]
    let config_esplora: Option<AnyBlockchainConfig> = {
        let esplora_concurrency = wallet_opts.esplora_concurrency;
        wallet_opts.esplora.clone().map(|base_url| {
            AnyBlockchainConfig::Esplora(EsploraBlockchainConfig {
                base_url,
                concurrency: Some(esplora_concurrency),
            })
        })
    };
    #[cfg(not(feature = "esplora"))]
    let config_esplora = None;

    let config_electrum = AnyBlockchainConfig::Electrum(ElectrumBlockchainConfig {
        url: wallet_opts.electrum.clone(),
        socks5: wallet_opts.proxy.clone(),
        retry: wallet_opts.retries,
        timeout: wallet_opts.timeout,
    });

    // Fall back to Electrum config if Esplora config isn't provided
    let config = config_esplora.unwrap_or(config_electrum);

    let descriptor = wallet_opts.descriptor.as_str();
    let change_descriptor = wallet_opts.change_descriptor.as_deref();
    let wallet = Wallet::new(
        descriptor,
        change_descriptor,
        network,
        database,
        AnyBlockchain::from_config(&config)?,
    )?;
    Ok(wallet)
}

fn new_offline_wallet<D>(
    network: Network,
    wallet_opts: &WalletOpts,
    database: D,
) -> Result<Wallet<(), D>, Error>
where
    D: BatchDatabase,
{
    let descriptor = wallet_opts.descriptor.as_str();
    let change_descriptor = wallet_opts.change_descriptor.as_deref();
    let wallet = Wallet::new_offline(descriptor, change_descriptor, network, database)?;
    Ok(wallet)
}

fn main() {
    env_logger::init();

    let cli_opts: CliOpts = CliOpts::from_args();

    let network = cli_opts.network;
    debug!("network: {:?}", network);
    if network == Network::Bitcoin {
        warn!("This is experimental software and not currently recommended for use on Bitcoin mainnet, proceed with caution.")
    }

    //println!("cli_opts = {:?}", cli_opts);

    let result = match cli_opts.subcommand {
        CliSubCommand::Wallet {
            wallet_opts,
            subcommand: WalletSubCommand::OnlineWalletSubCommand(online_subcommand),
        } => {
            let database = open_database(&wallet_opts);
            let wallet = new_online_wallet(network, &wallet_opts, database).unwrap();
            let result = bdk_cli::handle_online_wallet_subcommand(&wallet, online_subcommand);
            serde_json::to_string_pretty(&result.unwrap()).unwrap()
        }
        CliSubCommand::Wallet {
            wallet_opts,
            subcommand: WalletSubCommand::OfflineWalletSubCommand(offline_subcommand),
        } => {
            let database = open_database(&wallet_opts);
            let wallet = new_offline_wallet(network, &wallet_opts, database).unwrap();
            let result = bdk_cli::handle_offline_wallet_subcommand(&wallet, offline_subcommand);
            serde_json::to_string_pretty(&result.unwrap()).unwrap()
        }
        CliSubCommand::Key {
            subcommand: key_subcommand,
        } => {
            let result = bdk_cli::handle_key_subcommand(network, key_subcommand);
            serde_json::to_string_pretty(&result.unwrap()).unwrap()
        }
        CliSubCommand::Repl { wallet_opts } => {
            let database = open_database(&wallet_opts);
            let online_wallet = new_online_wallet(network, &wallet_opts, database.clone()).unwrap();
            let online_wallet = Arc::new(online_wallet);

            let offline_wallet = new_offline_wallet(network, &wallet_opts, database).unwrap();
            let offline_wallet = Arc::new(offline_wallet);

            let mut rl = Editor::<()>::new();

            // if rl.load_history("history.txt").is_err() {
            //     println!("No previous history.");
            // }

            let split_regex = Regex::new(r#"[\w\-]+|"[\w\s]*""#).unwrap();
            let filter_regex = Regex::new(r#"[\w\s\-]+"#).unwrap();

            loop {
                let readline = rl.readline(">> ");
                match readline {
                    Ok(line) => {
                        if line.trim() == "" {
                            continue;
                        }
                        rl.add_history_entry(line.as_str());
                        let split_line: Vec<&str> =
                            split_regex.find_iter(&line).map(|m| m.as_str()).collect();
                        let filtered_line: Vec<&str> = split_line
                            .iter()
                            .flat_map(|s| filter_regex.find_iter(s).map(|m| m.as_str()))
                            .collect();
                        let repl_opt: Result<ReplOpt, clap::Error> =
                            ReplOpt::from_iter_safe(filtered_line);
                        debug!("repl_opt = {:?}", repl_opt);

                        if let Err(err) = repl_opt {
                            println!("{}", err.message);
                            continue;
                        }

                        let repl_subcommand = repl_opt.unwrap().subcommand;

                        let result = match repl_subcommand {
                            ReplSubCommand::OnlineWalletSubCommand(online_subcommand) => {
                                bdk_cli::handle_online_wallet_subcommand(
                                    &Arc::clone(&online_wallet),
                                    online_subcommand,
                                )
                            }
                            ReplSubCommand::OfflineWalletSubCommand(offline_subcommand) => {
                                bdk_cli::handle_offline_wallet_subcommand(
                                    &Arc::clone(&offline_wallet),
                                    offline_subcommand,
                                )
                            }
                            ReplSubCommand::KeySubCommand(key_subcommand) => {
                                bdk_cli::handle_key_subcommand(network, key_subcommand)
                            }
                            ReplSubCommand::Exit => break,
                        };

                        println!(
                            "{}",
                            serde_json::to_string_pretty(&result.unwrap()).unwrap()
                        );
                    }
                    Err(ReadlineError::Interrupted) => continue,
                    Err(ReadlineError::Eof) => break,
                    Err(err) => {
                        println!("{:?}", err);
                        break;
                    }
                }
            }

            // rl.save_history("history.txt").unwrap();
            "Exiting REPL".to_string()
        }
    };

    println!("{}", result);
}

#[cfg(test)]
mod test {
    use regex::Regex;

    #[test]
    fn test_regex() {
        let split_regex = Regex::new(r#"[\w\-]+|"[\w\s]*""#).unwrap();
        //println!("split_regex = {:?}", &split_regex);
        let filter_regex = Regex::new(r#"[\w\s\-]+"#).unwrap();
        //println!("filter_regex = {:?}", &filter_regex);
        let line = r#"restore -m "word1 word2 word3" -p test"#;
        let split_line: Vec<&str> = split_regex.find_iter(&line).map(|m| m.as_str()).collect();
        //println!("split_line({}) = {:?}", &line, &split_line);
        let filtered_line: Vec<&str> = split_line
            .iter()
            .flat_map(|s| filter_regex.find_iter(s).map(|m| m.as_str()))
            .collect();
        //println!("filtered_line({:?}) = {:?}", &split_line, &filtered_line);
        assert_eq!(
            vec!("restore", "-m", "word1 word2 word3", "-p", "test"),
            filtered_line
        );
    }
}
