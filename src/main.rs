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
#[cfg(any(feature = "sqlite", feature = "redb"))]
mod persister;
mod utils;

use bdk_wallet::bitcoin::Network;
use log::{debug, error, warn};
use std::env;
use std::path::PathBuf;

use crate::commands::CliOpts;
use crate::config::WalletConfig;
use crate::error::BDKCliError as Error;
use crate::handlers::*;
use crate::utils::prepare_home_dir;
use clap::Parser;

fn is_value_arg(arg: &str) -> bool {
    matches!(
        arg,
        "-w" | "--wallet"
            | "-e"
            | "--ext-descriptor"
            | "-i"
            | "--int-descriptor"
            | "-c"
            | "--client-type"
            | "-d"
            | "--database-type"
            | "-u"
            | "--url"
            | "-b"
            | "--batch-size"
            | "-p"
            | "--parallel-requests"
            | "-a"
            | "--basic-auth"
            | "--cookie"
            | "-n"
            | "--network"
            | "--datadir"
    )
}

/// Inject configuration values from config.toml
/// when --use-config is present, except for the init subcommand.
fn preprocess_args(args: &mut Vec<String>) -> Result<(), Error> {
    let use_config = args.iter().any(|arg| arg == "--use-config");

    let is_init = args.iter().any(|arg| arg == "init");

    if !use_config || is_init {
        return Ok(());
    }

    let mut wallet_name: Option<String> = None;
    let mut datadir: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "-w" || args[i] == "--wallet" {
            if i + 1 < args.len() {
                wallet_name = Some(args[i + 1].clone());
            }
        } else if (args[i] == "-d" || args[i] == "--datadir") && i + 1 < args.len() {
            datadir = Some(args[i + 1].clone());
        }
        i += if is_value_arg(&args[i]) && i + 1 < args.len() {
            2
        } else {
            1
        };
    }

    if let Some(wallet_name) = wallet_name {
        let home_dir = prepare_home_dir(datadir.map(PathBuf::from))?;
        if let Ok(Some(config)) = WalletConfig::load(&home_dir) {
            if let Some(wallet_config) = config.wallets.get(&wallet_name) {
                let mut top_level_injections: Vec<String> = Vec::new();
                let mut wallet_injections: Vec<String> = Vec::new();

                if !args.iter().any(|arg| arg == "-n" || arg == "--network") {
                    top_level_injections.push("--network".to_string());
                    top_level_injections.push(wallet_config.network.clone());
                }

                if !args
                    .iter()
                    .any(|arg| arg == "-e" || arg == "--ext-descriptor")
                {
                    wallet_injections.push("--ext-descriptor".to_string());
                    wallet_injections.push(wallet_config.ext_descriptor.clone());
                }
                if !args
                    .iter()
                    .any(|arg| arg == "-i" || arg == "--int-descriptor")
                {
                    if let Some(int_descriptor) = &wallet_config.int_descriptor {
                        wallet_injections.push("--int-descriptor".to_string());
                        wallet_injections.push(int_descriptor.clone());
                    }
                }
                #[cfg(any(
                    feature = "electrum",
                    feature = "esplora",
                    feature = "rpc",
                    feature = "cbf"
                ))]
                if !args.iter().any(|arg| arg == "-c" || arg == "--client-type") {
                    if let Some(ct) = &wallet_config.client_type {
                        wallet_injections.push("--client-type".to_string());
                        wallet_injections.push(ct.clone());
                    }
                }
                if !args
                    .iter()
                    .any(|arg| arg == "-d" || arg == "--database-type")
                {
                    #[cfg(any(feature = "sqlite", feature = "redb"))]
                    {
                        wallet_injections.push("--database-type".to_string());
                        wallet_injections.push(wallet_config.database_type.clone());
                    }
                }
                #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
                if !args.iter().any(|arg| arg == "-u" || arg == "--url") {
                    if let Some(url) = &wallet_config.server_url {
                        wallet_injections.push("--url".to_string());
                        wallet_injections.push(url.clone());
                    }
                }

                let mut top_level_insert_pos = 1;
                while top_level_insert_pos < args.len()
                    && args[top_level_insert_pos].starts_with('-')
                {
                    if is_value_arg(&args[top_level_insert_pos])
                        && top_level_insert_pos + 1 < args.len()
                    {
                        top_level_insert_pos += 2;
                    } else {
                        top_level_insert_pos += 1;
                    }
                }
                args.splice(
                    top_level_insert_pos..top_level_insert_pos,
                    top_level_injections,
                );

                let wallet_pos = args
                    .iter()
                    .position(|arg| arg == "wallet")
                    .unwrap_or(args.len());
                let mut wallet_insert_pos = wallet_pos + 1;
                while wallet_insert_pos < args.len() && args[wallet_insert_pos].starts_with('-') {
                    if is_value_arg(&args[wallet_insert_pos]) && wallet_insert_pos + 1 < args.len()
                    {
                        wallet_insert_pos += 2;
                    } else {
                        wallet_insert_pos += 1;
                    }
                }
                args.splice(wallet_insert_pos..wallet_insert_pos, wallet_injections);
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let mut args: Vec<String> = env::args().collect();

    if let Err(e) = preprocess_args(&mut args) {
        error!("Failed to preprocess arguments: {e}");
        std::process::exit(1);
    }

    if let Some(pos) = args.iter().position(|arg| arg == "--use-config") {
        args.remove(pos);
    }

    let cli_opts: CliOpts = CliOpts::parse_from(args);

    let network = &cli_opts.network;
    debug!("network: {network:?}");
    if network == &Network::Bitcoin {
        warn!(
            "This is experimental software and not currently recommended for use on Bitcoin mainnet, proceed with caution."
        )
    }

    match handle_command(cli_opts).await {
        Ok(result) => println!("{result}"),
        Err(e) => {
            error!("{e}");
            std::process::exit(1);
        }
    }
}
