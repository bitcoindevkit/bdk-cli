// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
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
mod handlers;
mod nodes;
mod utils;
#[cfg(target_arch = "wasm32")]
mod wasm;

use bitcoin::Network;

use log::{debug, error, warn};

use crate::commands::CliOpts;
use crate::handlers::*;
use bdk::{bitcoin, Error};
use bdk_macros::{maybe_async, maybe_await};
use structopt::StructOpt;

#[cfg(any(feature = "repl", target_arch = "wasm32"))]
const REPL_LINE_SPLIT_REGEX: &str = r#""([^"]*)"|'([^']*)'|([\w\-]+)"#;

#[maybe_async]
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "async-interface", tokio::main)]
fn main() {
    env_logger::init();

    let cli_opts: CliOpts = CliOpts::from_args();

    let network = cli_opts.network;
    debug!("network: {:?}", network);
    if network == Network::Bitcoin {
        warn!("This is experimental software and not currently recommended for use on Bitcoin mainnet, proceed with caution.")
    }

    match maybe_await!(handle_command(cli_opts)) {
        Ok(result) => println!("{}", result),
        Err(e) => {
            match e {
                Error::ChecksumMismatch => error!("Descriptor checksum mismatch. Are you using a different descriptor for an already defined wallet name? (if you are not specifying the wallet name it is automatically named based on the descriptor)"),
                e => error!("{}", e.to_string()),
            }
        },
    }
}

// wasm32 requires a non-async main
#[cfg(target_arch = "wasm32")]
fn main() {}
