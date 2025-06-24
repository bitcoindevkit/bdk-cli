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
mod error;
mod handlers;
mod payjoin;
#[cfg(any(feature = "sqlite", feature = "redb"))]
mod persister;
mod utils;

use bdk_wallet::bitcoin::Network;
use log::{debug, error, warn};

use crate::commands::CliOpts;
use crate::handlers::*;
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

    match handle_command(cli_opts).await {
        Ok(result) => println!("{result}"),
        Err(e) => {
            error!("{e}");
            std::process::exit(1);
        }
    }
}
