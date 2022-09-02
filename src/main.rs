// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! BDK CLI APP
//!
//! This module describes the app's main() function

mod commands;
mod handlers;
mod nodes;
mod utils;

use nodes::Nodes;

use bitcoin::Network;

use log::{debug, error, warn};

use crate::commands::CliOpts;
use crate::handlers::*;
use bdk::{bitcoin, Error};
use bdk_macros::{maybe_async, maybe_await};
use structopt::StructOpt;

#[cfg(feature = "repl")]
const REPL_LINE_SPLIT_REGEX: &str = r#""([^"]*)"|'([^']*)'|([\w\-]+)"#;

#[maybe_async]
#[cfg_attr(feature = "async-interface", tokio::main)]
fn main() {
    env_logger::init();

    let cli_opts: CliOpts = CliOpts::from_args();

    let network = cli_opts.network;
    debug!("network: {:?}", network);
    if network == Network::Bitcoin {
        warn!("This is experimental software and not currently recommended for use on Bitcoin mainnet, proceed with caution.")
    }

    #[cfg(feature = "regtest-node")]
    let bitcoind = {
        if network != Network::Regtest {
            error!("Do not override default network value for `regtest-node` features");
        }
        let bitcoind_conf = electrsd::bitcoind::Conf::default();
        let bitcoind_exe = electrsd::bitcoind::downloaded_exe_path()
            .expect("We should always have downloaded path");
        electrsd::bitcoind::BitcoinD::with_conf(bitcoind_exe, &bitcoind_conf).unwrap()
    };

    #[cfg(feature = "regtest-bitcoin")]
    let backend = {
        Nodes::Bitcoin {
            rpc_url: bitcoind.params.rpc_socket.to_string(),
            rpc_auth: bitcoind
                .params
                .cookie_file
                .clone()
                .into_os_string()
                .into_string()
                .unwrap(),
        }
    };

    #[cfg(feature = "regtest-electrum")]
    let (_electrsd, backend) = {
        let elect_conf = electrsd::Conf::default();
        let elect_exe =
            electrsd::downloaded_exe_path().expect("We should always have downloaded path");
        let electrsd = electrsd::ElectrsD::with_conf(elect_exe, &bitcoind, &elect_conf).unwrap();
        let backend = Nodes::Electrum {
            electrum_url: electrsd.electrum_url.clone(),
        };
        (electrsd, backend)
    };

    #[cfg(any(feature = "regtest-esplora-ureq", feature = "regtest-esplora-reqwest"))]
    let (_electrsd, backend) = {
        let mut elect_conf = electrsd::Conf::default();
        elect_conf.http_enabled = true;
        let elect_exe =
            electrsd::downloaded_exe_path().expect("Electrsd downloaded binaries not found");
        let electrsd = electrsd::ElectrsD::with_conf(elect_exe, &bitcoind, &elect_conf).unwrap();
        let backend = Nodes::Esplora {
            esplora_url: electrsd
                .esplora_url
                .clone()
                .expect("Esplora port not open in electrum"),
        };
        (electrsd, nodes)
    };

    #[cfg(not(feature = "regtest-node"))]
    let backend = Nodes::None;

    match maybe_await!(handle_command(cli_opts, network, backend)) {
        Ok(result) => println!("{}", result),
        Err(e) => {
            match e {
                Error::ChecksumMismatch => error!("Descriptor checksum mismatch. Are you using a different descriptor for an already defined wallet name? (if you are not specifying the wallet name it is automatically named based on the descriptor)"),
                e => error!("{}", e.to_string()),
            }
        },
    }
}
