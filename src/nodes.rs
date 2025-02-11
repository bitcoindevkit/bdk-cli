// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The Node structures
//!
//! This module defines containers for different backend clients.
//! These Backends are auto-deployed in `regtest-*` features to spawn a blockchain
//! interface of selected types, and connects the bdk-cli wallet to it.
//!
//! For more information check TODO: [Add readme section for `regtest-*` features.]

#[cfg(feature = "regtest-node")]
use {
    crate::{commands::NodeSubCommand, error::BDKCliError as Error},
    bdk_wallet::bitcoin::{Address, Amount},
    electrsd::corepc_node::{Client, Node},
    serde_json::Value,
    std::str::FromStr,
};

#[allow(dead_code)]
// Different regtest node types activated with `regtest-*` mode.
// If `regtest-*` feature not activated, then default is `None`.
pub enum Nodes {
    None,
    #[cfg(feature = "regtest-bitcoin")]
    /// A bitcoin core backend. Wallet connected to it via RPC.
    Bitcoin {
        bitcoind: Box<Node>,
    },
    #[cfg(feature = "regtest-electrum")]
    /// An Electrum backend with an underlying bitcoin core
    /// Wallet connected to it, via the electrum url.
    Electrum {
        bitcoind: Box<Node>,
        electrsd: Box<electrsd::ElectrsD>,
    },
    /// An Esplora backend with an underlying bitcoin core
    /// Wallet connected to it, via the esplora url.
    #[cfg(any(feature = "regtest-esplora-ureq", feature = "regtest-esplora-reqwest"))]
    Esplora {
        bitcoind: Box<Node>,
        esplorad: Box<electrsd::ElectrsD>,
    },
}

#[cfg(feature = "regtest-node")]
impl Nodes {
    /// Execute a [`NodeSubCommand`] in the backend
    pub fn exec_cmd(&self, cmd: NodeSubCommand) -> Result<serde_json::Value, Error> {
        let client = self.get_client()?;
        match cmd {
            NodeSubCommand::GetInfo => Ok(serde_json::to_value(client.get_blockchain_info()?)?),
            NodeSubCommand::GetNewAddress => Ok(serde_json::to_value(client.new_address()?)?),

            NodeSubCommand::Generate { block_num } => {
                let core_addrs = client.new_address()?;
                let block_hashes = client.generate_to_address(block_num as usize, &core_addrs)?;
                Ok(serde_json::to_value(block_hashes)?)
            }

            NodeSubCommand::GetBalance => Ok(serde_json::to_value(client.get_balance()?)?),

            NodeSubCommand::SendToAddress { address, amount } => {
                let address = Address::from_str(&address)?.assume_checked();
                let amount = Amount::from_sat(amount);
                let txid = client.send_to_address(&address, amount)?;
                Ok(serde_json::to_value(&txid)?)
            }

            NodeSubCommand::BitcoinCli(args) => {
                let cmd = &args[0];
                let args = args[1..]
                    .iter()
                    .map(|arg| serde_json::Value::from_str(arg))
                    .collect::<Result<Vec<Value>, _>>()?;
                Ok(client.call::<Value>(cmd, &args)?)
            }
        }
    }

    // Expose the underlying RPC client.
    pub fn get_client(&self) -> Result<&Client, Error> {
        match self {
            Self::None => Err(Error::Generic(
                "No backend available. Cannot execute node commands".to_string(),
            )),
            #[cfg(feature = "regtest-bitcoin")]
            Self::Bitcoin { bitcoind } => Ok(&bitcoind.client),
            #[cfg(feature = "regtest-electrum")]
            Self::Electrum { bitcoind, .. } => Ok(&bitcoind.client), // question: shouldn't we initialize electrsd with bitcoind?
            #[cfg(any(feature = "regtest-esplora-ureq", feature = "regtest-esplora-reqwest"))]
            Self::Esplora { bitcoind, .. } => Ok(&bitcoind.client),
        }
    }
}
