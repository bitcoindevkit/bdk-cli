// Bitcoin Dev Kit
// Written in 2020 by
//     Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2022 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use std::fs;
use std::path::PathBuf;

use clap::AppSettings;
use log::{debug, error, info, warn};

#[cfg(feature = "repl")]
use rustyline::error::ReadlineError;
#[cfg(feature = "repl")]
use rustyline::Editor;

use structopt::StructOpt;

#[cfg(feature = "compact_filters")]
use bdk::blockchain::compact_filters::{BitcoinPeerConfig, CompactFiltersBlockchainConfig};
#[cfg(feature = "electrum")]
use bdk::blockchain::electrum::ElectrumBlockchainConfig;
#[cfg(feature = "esplora")]
use bdk::blockchain::esplora::EsploraBlockchainConfig;

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use bdk::blockchain::{AnyBlockchain, AnyBlockchainConfig, ConfigurableBlockchain};

#[cfg(feature = "rpc")]
use bdk::blockchain::rpc::{Auth, RpcConfig};

use bdk::database::BatchDatabase;
use bdk::sled;
use bdk::sled::Tree;
use bdk::wallet::wallet_name_from_descriptor;
use bdk::Wallet;
use bdk::{bitcoin, Error};
use bdk_cli::WalletSubCommand;
use bdk_cli::{CliOpts, CliSubCommand, KeySubCommand, OfflineWalletSubCommand, WalletOpts};

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use bdk_cli::OnlineWalletSubCommand;

#[cfg(feature = "repl")]
use regex::Regex;

#[cfg(feature = "repl")]
const REPL_LINE_SPLIT_REGEX: &str = r#""([^"]*)"|'([^']*)'|([\w\-]+)"#;

/// REPL mode
#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(name = "", setting = AppSettings::NoBinaryName,
version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"),
author = option_env ! ("CARGO_PKG_AUTHORS").unwrap_or(""))]
pub enum ReplSubCommand {
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "compact_filters",
        feature = "rpc"
    ))]
    #[structopt(flatten)]
    OnlineWalletSubCommand(OnlineWalletSubCommand),
    #[structopt(flatten)]
    OfflineWalletSubCommand(OfflineWalletSubCommand),
    #[structopt(flatten)]
    KeySubCommand(KeySubCommand),
    /// Exit REPL loop
    Exit,
}

fn prepare_home_dir() -> Result<PathBuf, Error> {
    let mut dir = PathBuf::new();
    dir.push(
        &dirs_next::home_dir().ok_or_else(|| Error::Generic("home dir not found".to_string()))?,
    );
    dir.push(".bdk-bitcoin");

    if !dir.exists() {
        info!("Creating home directory {}", dir.as_path().display());
        fs::create_dir(&dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    #[cfg(not(feature = "compact_filters"))]
    dir.push("database.sled");

    #[cfg(feature = "compact_filters")]
    dir.push("compact_filters");
    Ok(dir)
}

fn open_database(wallet_opts: &WalletOpts) -> Result<Tree, Error> {
    let mut database_path = prepare_home_dir()?;
    let wallet_name = wallet_opts
        .wallet
        .as_deref()
        .expect("We should always have a wallet name at this point");
    database_path.push(wallet_name);
    let database = sled::open(database_path)?;
    let tree = database.open_tree(&wallet_name)?;
    debug!("database opened successfully");
    Ok(tree)
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
pub fn new_blockchain(_network: Network, wallet_opts: &WalletOpts) -> Result<AnyBlockchain, Error> {
    #[cfg(feature = "electrum")]
    let config = AnyBlockchainConfig::Electrum(ElectrumBlockchainConfig {
        url: wallet_opts.electrum_opts.server.clone(),
        socks5: wallet_opts.proxy_opts.proxy.clone(),
        retry: wallet_opts.proxy_opts.retries,
        timeout: wallet_opts.electrum_opts.timeout,
        stop_gap: wallet_opts.electrum_opts.stop_gap,
    });

    #[cfg(feature = "esplora")]
    let config = AnyBlockchainConfig::Esplora(EsploraBlockchainConfig {
        base_url: wallet_opts.esplora_opts.server.clone(),
        timeout: Some(wallet_opts.esplora_opts.timeout),
        concurrency: Some(wallet_opts.esplora_opts.conc),
        stop_gap: wallet_opts.esplora_opts.stop_gap,
        proxy: wallet_opts.proxy_opts.proxy.clone(),
    });

    #[cfg(feature = "compact_filters")]
    let config = {
        let mut peers = vec![];
        for addrs in wallet_opts.compactfilter_opts.address.clone() {
            for _ in 0..wallet_opts.compactfilter_opts.conn_count {
                peers.push(BitcoinPeerConfig {
                    address: addrs.clone(),
                    socks5: wallet_opts.proxy_opts.proxy.clone(),
                    socks5_credentials: wallet_opts.proxy_opts.proxy_auth.clone(),
                })
            }
        }

        AnyBlockchainConfig::CompactFilters(CompactFiltersBlockchainConfig {
            peers,
            network: _network,
            storage_dir: prepare_home_dir()?
                .into_os_string()
                .into_string()
                .map_err(|_| Error::Generic("Internal OS_String conversion error".to_string()))?,
            skip_blocks: Some(wallet_opts.compactfilter_opts.skip_blocks),
        })
    };

    #[cfg(feature = "rpc")]
    let config: AnyBlockchainConfig = {
        let auth = if let Some(cookie) = &wallet_opts.rpc_opts.cookie {
            Auth::Cookie {
                file: cookie.into(),
            }
        } else {
            Auth::UserPass {
                username: wallet_opts.rpc_opts.basic_auth.0.clone(),
                password: wallet_opts.rpc_opts.basic_auth.1.clone(),
            }
        };

        // Use deterministic wallet name derived from descriptor
        let wallet_name = wallet_name_from_descriptor(
            &wallet_opts.descriptor[..],
            wallet_opts.change_descriptor.as_deref(),
            _network,
            &Secp256k1::new(),
        )?;

        let mut rpc_url = "http://".to_string();
        rpc_url.push_str(&wallet_opts.rpc_opts.address[..]);

        let rpc_config = RpcConfig {
            url: rpc_url,
            auth,
            network: _network,
            wallet_name,
            skip_blocks: wallet_opts.rpc_opts.skip_blocks,
        };

        AnyBlockchainConfig::Rpc(rpc_config)
    };

    Ok(AnyBlockchain::from_config(&config)?)
}

pub fn new_wallet<D>(
    network: Network,
    wallet_opts: &WalletOpts,
    database: D,
) -> Result<Wallet<D>, Error>
where
    D: BatchDatabase,
{
    let descriptor = wallet_opts.descriptor.as_str();
    let change_descriptor = wallet_opts.change_descriptor.as_deref();
    let wallet = Wallet::new(descriptor, change_descriptor, network, database)?;
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

    match handle_command(cli_opts, network) {
        Ok(result) => println!("{}", result),
        Err(e) => {
            match e {
                Error::ChecksumMismatch => error!("Descriptor checksum mismatch. Are you using a different descriptor for an already defined wallet name? (if you are not specifying the wallet name it is automatically named based on the descriptor)"),
                e => error!("{}", e.to_string()),
            }
        },
    }
}

fn maybe_descriptor_wallet_name(
    wallet_opts: WalletOpts,
    network: Network,
) -> Result<WalletOpts, Error> {
    if wallet_opts.wallet.is_some() {
        return Ok(wallet_opts);
    }
    // Use deterministic wallet name derived from descriptor
    let wallet_name = wallet_name_from_descriptor(
        &wallet_opts.descriptor[..],
        wallet_opts.change_descriptor.as_deref(),
        network,
        &Secp256k1::new(),
    )?;
    let mut wallet_opts = wallet_opts;
    wallet_opts.wallet = Some(wallet_name);

    Ok(wallet_opts)
}

fn handle_command(cli_opts: CliOpts, network: Network) -> Result<String, Error> {
    let result = match cli_opts.subcommand {
        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "compact_filters",
            feature = "rpc"
        ))]
        CliSubCommand::Wallet {
            wallet_opts,
            subcommand: WalletSubCommand::OnlineWalletSubCommand(online_subcommand),
        } => {
            let wallet_opts = maybe_descriptor_wallet_name(wallet_opts, network)?;
            let database = open_database(&wallet_opts)?;
            let blockchain = new_blockchain(network, &wallet_opts)?;
            let wallet = new_wallet(network, &wallet_opts, database)?;
            let result =
                bdk_cli::handle_online_wallet_subcommand(&wallet, &blockchain, online_subcommand)?;
            serde_json::to_string_pretty(&result)?
        }
        CliSubCommand::Wallet {
            wallet_opts,
            subcommand: WalletSubCommand::OfflineWalletSubCommand(offline_subcommand),
        } => {
            let wallet_opts = maybe_descriptor_wallet_name(wallet_opts, network)?;
            let database = open_database(&wallet_opts)?;
            let wallet = new_wallet(network, &wallet_opts, database)?;
            let result = bdk_cli::handle_offline_wallet_subcommand(
                &wallet,
                &wallet_opts,
                offline_subcommand,
            )?;
            serde_json::to_string_pretty(&result)?
        }
        CliSubCommand::Key {
            subcommand: key_subcommand,
        } => {
            let result = bdk_cli::handle_key_subcommand(network, key_subcommand)?;
            serde_json::to_string_pretty(&result)?
        }
        #[cfg(feature = "compiler")]
        CliSubCommand::Compile {
            policy,
            script_type,
        } => {
            let result = bdk_cli::handle_compile_subcommand(network, policy, script_type)?;
            serde_json::to_string_pretty(&result)?
        }
        #[cfg(feature = "repl")]
        CliSubCommand::Repl { wallet_opts } => {
            let wallet_opts = maybe_descriptor_wallet_name(wallet_opts, network)?;
            let database = open_database(&wallet_opts)?;

            #[cfg(any(
                feature = "electrum",
                feature = "esplora",
                feature = "compact_filters",
                feature = "rpc"
            ))]
            let wallet = new_wallet(network, &wallet_opts, database)?;

            #[cfg(not(any(
                feature = "electrum",
                feature = "esplora",
                feature = "compact_filters",
                feature = "rpc"
            )))]
            let wallet = new_wallet(network, &wallet_opts, database)?;

            let mut rl = Editor::<()>::new();

            // if rl.load_history("history.txt").is_err() {
            //     println!("No previous history.");
            // }

            let split_regex =
                Regex::new(REPL_LINE_SPLIT_REGEX).map_err(|e| Error::Generic(e.to_string()))?;

            loop {
                let readline = rl.readline(">> ");
                match readline {
                    Ok(line) => {
                        if line.trim() == "" {
                            continue;
                        }
                        rl.add_history_entry(line.as_str());
                        let split_line: Vec<&str> = split_regex
                            .captures_iter(&line)
                            .map(|c| {
                                Ok(c.get(1)
                                    .or_else(|| c.get(2))
                                    .or_else(|| c.get(3))
                                    .ok_or_else(|| Error::Generic("Invalid commands".to_string()))?
                                    .as_str())
                            })
                            .collect::<Result<Vec<_>, Error>>()?;
                        let repl_subcommand = ReplSubCommand::from_iter_safe(split_line);
                        if let Err(err) = repl_subcommand {
                            println!("{}", err.to_string());
                            continue;
                        }
                        // if error will be printed above
                        let repl_subcommand = repl_subcommand.unwrap();
                        debug!("repl_subcommand = {:?}", repl_subcommand);

                        let result = match repl_subcommand {
                            #[cfg(any(
                                feature = "electrum",
                                feature = "esplora",
                                feature = "compact_filters",
                                feature = "rpc"
                            ))]
                            ReplSubCommand::OnlineWalletSubCommand(online_subcommand) => {
                                let blockchain = new_blockchain(network, &wallet_opts)?;
                                bdk_cli::handle_online_wallet_subcommand(
                                    &wallet,
                                    &blockchain,
                                    online_subcommand,
                                )
                            }
                            ReplSubCommand::OfflineWalletSubCommand(offline_subcommand) => {
                                bdk_cli::handle_offline_wallet_subcommand(
                                    &wallet,
                                    &wallet_opts,
                                    offline_subcommand,
                                )
                            }
                            ReplSubCommand::KeySubCommand(key_subcommand) => {
                                bdk_cli::handle_key_subcommand(network, key_subcommand)
                            }
                            ReplSubCommand::Exit => break,
                        };

                        println!("{}", serde_json::to_string_pretty(&result?)?);
                    }
                    Err(ReadlineError::Interrupted) => continue,
                    Err(ReadlineError::Eof) => break,
                    Err(err) => {
                        println!("{:?}", err);
                        break;
                    }
                }
            }

            "Exiting REPL".to_string()
        }
        #[cfg(all(feature = "reserves", feature = "electrum"))]
        CliSubCommand::ExternalReserves {
            message,
            psbt,
            confirmations,
            addresses,
            electrum_opts,
        } => {
            let result = bdk_cli::handle_ext_reserves_subcommand(
                network,
                message,
                psbt,
                confirmations,
                addresses,
                electrum_opts,
            )?;
            serde_json::to_string_pretty(&result)?
        }
    };
    Ok(result)
}

#[cfg(test)]
mod test {
    use crate::REPL_LINE_SPLIT_REGEX;
    use regex::Regex;

    #[test]
    fn test_regex_double_quotes() {
        let split_regex = Regex::new(REPL_LINE_SPLIT_REGEX).unwrap();
        let line = r#"restore -m "word1 word2 word3" -p 'test! 123 -test' "#;
        let split_line: Vec<&str> = split_regex
            .captures_iter(&line)
            .map(|c| {
                c.get(1)
                    .or_else(|| c.get(2))
                    .or_else(|| c.get(3))
                    .unwrap()
                    .as_str()
            })
            .collect();
        assert_eq!(
            vec!(
                "restore",
                "-m",
                "word1 word2 word3",
                "-p",
                "test! 123 -test"
            ),
            split_line
        );
    }

    #[test]
    fn test_regex_single_quotes() {
        let split_regex = Regex::new(REPL_LINE_SPLIT_REGEX).unwrap();
        let line = r#"restore -m 'word1 word2 word3' -p "test *123 -test" "#;
        let split_line: Vec<&str> = split_regex
            .captures_iter(&line)
            .map(|c| {
                c.get(1)
                    .or_else(|| c.get(2))
                    .or_else(|| c.get(3))
                    .unwrap()
                    .as_str()
            })
            .collect();
        assert_eq!(
            vec!(
                "restore",
                "-m",
                "word1 word2 word3",
                "-p",
                "test *123 -test"
            ),
            split_line
        );
    }
}
