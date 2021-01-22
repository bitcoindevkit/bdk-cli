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

//! BDK Command line interface
//!
//! This lib provides a [structopt](https://docs.rs/crate/structopt) `struct` and `enum` that
//! parse global wallet options and wallet subcommand options needed for a wallet command line
//! interface.
//!
//! See the `bdk-cli` example bin for how to use this module to create a simple command line
//! wallet application.
//!
//! See [`WalletOpt`] for global wallet options and [`WalletSubCommand`] for supported sub-commands.
//!
//! # Example
//!
//! ```
//! # use bdk::bitcoin::Network;
//! # use bdk::blockchain::esplora::EsploraBlockchainConfig;
//! # use bdk::blockchain::{AnyBlockchain, ConfigurableBlockchain};
//! # use bdk::blockchain::{AnyBlockchainConfig, ElectrumBlockchainConfig};
//! # use bdk_cli::{self, WalletOpt, WalletSubCommand};
//! # use bdk::database::MemoryDatabase;
//! # use bdk::Wallet;
//! # use std::sync::Arc;
//! # use structopt::StructOpt;
//! # use std::str::FromStr;
//!
//! // to get args from cli use:
//! // let cli_opt = WalletOpt::from_args();
//!
//! let cli_args = vec!["bdk-cli", "--network", "testnet", "--descriptor",
//!                     "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)",
//!                     "sync", "--max_addresses", "50"];
//! let cli_opt = WalletOpt::from_iter(&cli_args);
//!
//! let network = cli_opt.network;
//!
//! let descriptor = cli_opt.descriptor.as_str();
//! let change_descriptor = cli_opt.change_descriptor.as_deref();
//!
//! let database = MemoryDatabase::new();
//!
//! let config = match cli_opt.esplora {
//!     Some(base_url) => AnyBlockchainConfig::Esplora(EsploraBlockchainConfig {
//!         base_url: base_url.to_string(),
//!         concurrency: Some(cli_opt.esplora_concurrency),
//!     }),
//!     None => AnyBlockchainConfig::Electrum(ElectrumBlockchainConfig {
//!         url: cli_opt.electrum,
//!         socks5: cli_opt.proxy,
//!         retry: 3,
//!         timeout: None,
//!     }),
//! };
//!
//! let wallet = Wallet::new(
//!     descriptor,
//!     change_descriptor,
//!     network,
//!     database,
//!     AnyBlockchain::from_config(&config).unwrap(),
//! ).unwrap();
//!
//! let wallet = Arc::new(wallet);
//!
//! let result = bdk_cli::handle_wallet_subcommand(&wallet, cli_opt.subcommand).unwrap();
//! println!("{}", serde_json::to_string_pretty(&result).unwrap());
//! ```

pub extern crate bdk;
#[macro_use]
extern crate serde_json;
#[cfg(any(target_arch = "wasm32", feature = "async-interface"))]
#[macro_use]
extern crate async_trait;
#[macro_use]
extern crate bdk_macros;

use std::collections::BTreeMap;
use std::str::FromStr;

use structopt::StructOpt;

use bdk::bitcoin::consensus::encode::{deserialize, serialize, serialize_hex};
use bdk::bitcoin::hashes::hex::FromHex;
use bdk::bitcoin::util::psbt::PartiallySignedTransaction;
use bdk::bitcoin::{Address, Network, OutPoint, Script, Txid};
use bdk::blockchain::log_progress;
use bdk::Error;
use bdk::{FeeRate, KeychainKind, TxBuilder, Wallet};

/// Wallet global options and sub-command
///
/// A [structopt](https://docs.rs/crate/structopt) `struct` that parses wallet global options and
/// sub-command from the command line or from a `String` vector. See [`WalletSubCommand`] for details
/// on parsing sub-commands.
///
/// # Example
///
/// ```
/// # use bdk::bitcoin::Network;
/// # use structopt::StructOpt;
/// # use bdk_cli::{WalletSubCommand, WalletOpt};
///
/// let cli_args = vec!["bdk-cli", "--network", "testnet",
///                     "--descriptor", "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/44'/1'/0'/0/*)",
///                     "sync", "--max_addresses", "50"];
///
/// // to get WalletOpt from OS command line args use:
/// // let wallet_opt = WalletOpt::from_args();
///
/// let wallet_opt = WalletOpt::from_iter(&cli_args);
///
/// let expected_wallet_opt = WalletOpt {
///         network: Network::Testnet,
///         wallet: "main".to_string(),
///         proxy: None,
///         descriptor: "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/44'/1'/0'/0/*)".to_string(),
///         change_descriptor: None,
///         #[cfg(feature = "esplora")]
///         esplora: None,
///         #[cfg(feature = "esplora")]
///         esplora_concurrency: 4,
///         electrum: "ssl://electrum.blockstream.info:60002".to_string(),
///         subcommand: WalletSubCommand::Sync {
///             max_addresses: Some(50)
///         },
/// };
///
/// assert_eq!(expected_wallet_opt, wallet_opt);
/// ```

#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(name = "BDK CLI",
version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"),
author = option_env ! ("CARGO_PKG_AUTHORS").unwrap_or(""))]
pub struct WalletOpt {
    /// Sets the network
    #[structopt(
        name = "NETWORK",
        short = "n",
        long = "network",
        default_value = "testnet"
    )]
    pub network: Network,
    /// Selects the wallet to use
    #[structopt(
        name = "WALLET_NAME",
        short = "w",
        long = "wallet",
        default_value = "main"
    )]
    pub wallet: String,
    #[cfg(feature = "electrum")]
    /// Sets the SOCKS5 proxy for the Electrum client
    #[structopt(name = "PROXY_SERVER:PORT", short = "p", long = "proxy")]
    pub proxy: Option<String>,
    /// Sets the descriptor to use for the external addresses
    #[structopt(name = "DESCRIPTOR", short = "d", long = "descriptor", required = true)]
    pub descriptor: String,
    /// Sets the descriptor to use for internal addresses
    #[structopt(name = "CHANGE_DESCRIPTOR", short = "c", long = "change_descriptor")]
    pub change_descriptor: Option<String>,
    #[cfg(feature = "esplora")]
    /// Use the esplora server if given as parameter
    #[structopt(name = "ESPLORA_URL", short = "e", long = "esplora")]
    pub esplora: Option<String>,
    #[cfg(feature = "esplora")]
    /// Concurrency of requests made to the esplora server
    #[structopt(
        name = "ESPLORA_CONCURRENCY",
        long = "esplora_concurrency",
        default_value = "4"
    )]
    pub esplora_concurrency: u8,
    #[cfg(feature = "electrum")]
    /// Sets the Electrum server to use
    #[structopt(
        name = "SERVER:PORT",
        short = "s",
        long = "server",
        default_value = "ssl://electrum.blockstream.info:60002"
    )]
    pub electrum: String,
    /// Wallet sub-command
    #[structopt(subcommand)]
    pub subcommand: WalletSubCommand,
}

/// Wallet sub-command
///
/// A [structopt](https://docs.rs/crate/structopt) enum that parses wallet sub-command arguments from
/// the command line or from a `String` vector, such as in the [`bdk-cli`](https://github.com/bitcoindevkit/bdk-cli/blob/master/src/bdkcli.rs)
/// example cli wallet.
///
/// # Example
///
/// ```
/// # use bdk_cli::WalletSubCommand;
/// # use structopt::StructOpt;
///
/// let sync_sub_command = WalletSubCommand::from_iter(&["bdk-cli", "sync", "--max_addresses", "50"]);
/// assert!(matches!(
///     sync_sub_command,
///     WalletSubCommand::Sync {
///         max_addresses: Some(50)
///     }
/// ));
/// ```
///
/// To capture wallet sub-commands from a string vector without a preceeding binary name you can
/// create a custom struct the includes the `NoBinaryName` clap setting and wraps the WalletSubCommand
/// enum. See also the [`bdk-cli`](https://github.com/bitcoindevkit/bdk-cli/blob/master/src/bdkcli.rs)
/// example app.
///
/// # Example
/// ```
/// # use bdk_cli::WalletSubCommand;
/// # use structopt::StructOpt;
/// # use clap::AppSettings;
///
/// #[derive(Debug, StructOpt, Clone, PartialEq)]
/// #[structopt(name = "BDK CLI", setting = AppSettings::NoBinaryName,
/// version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"),
/// author = option_env ! ("CARGO_PKG_AUTHORS").unwrap_or(""))]
/// struct ReplOpt {
///     /// Wallet sub-command
///     #[structopt(subcommand)]
///     pub subcommand: WalletSubCommand,
/// }
/// ```
#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(
    rename_all = "snake",
    long_about = "A modern, lightweight, descriptor-based wallet"
)]
pub enum WalletSubCommand {
    /// Generates a new external address
    GetNewAddress,
    /// Syncs with the chosen blockchain server
    Sync {
        /// max addresses to consider
        #[structopt(short = "v", long = "max_addresses")]
        max_addresses: Option<u32>,
    },
    /// Lists the available spendable UTXOs
    ListUnspent,
    /// Lists all the incoming and outgoing transactions of the wallet
    ListTransactions,
    /// Returns the current wallet balance
    GetBalance,
    /// Creates a new unsigned transaction
    CreateTx {
        /// Adds a recipient to the transaction
        #[structopt(name = "ADDRESS:SAT", long = "to", required = true, parse(try_from_str = parse_recipient))]
        recipients: Vec<(Script, u64)>,
        /// Sends all the funds (or all the selected utxos). Requires only one recipients of value 0
        #[structopt(short = "all", long = "send_all")]
        send_all: bool,
        /// Enables Replace-By-Fee (BIP125)
        #[structopt(short = "rbf", long = "enable_rbf")]
        enable_rbf: bool,
        /// Make a PSBT that can be signed by offline signers and hardware wallets. Forces the addition of `non_witness_utxo` and more details to let the signer identify the change output.
        #[structopt(long = "offline_signer")]
        offline_signer: bool,
        /// Selects which utxos *must* be spent
        #[structopt(name = "MUST_SPEND_TXID:VOUT", long = "utxos", parse(try_from_str = parse_outpoint))]
        utxos: Option<Vec<OutPoint>>,
        /// Marks a utxo as unspendable
        #[structopt(name = "CANT_SPEND_TXID:VOUT", long = "unspendable", parse(try_from_str = parse_outpoint))]
        unspendable: Option<Vec<OutPoint>>,
        /// Fee rate to use in sat/vbyte
        #[structopt(name = "SATS_VBYTE", short = "fee", long = "fee_rate")]
        fee_rate: Option<f32>,
        /// Selects which policy should be used to satisfy the external descriptor
        #[structopt(name = "EXT_POLICY", long = "external_policy")]
        external_policy: Option<String>,
        /// Selects which policy should be used to satisfy the internal descriptor
        #[structopt(name = "INT_POLICY", long = "internal_policy")]
        internal_policy: Option<String>,
    },
    /// Bumps the fees of an RBF transaction
    BumpFee {
        /// TXID of the transaction to update
        #[structopt(name = "TXID", short = "txid", long = "txid")]
        txid: String,
        /// Allows the wallet to reduce the amount of the only output in order to increase fees. This is generally the expected behavior for transactions originally created with `send_all`
        #[structopt(short = "all", long = "send_all")]
        send_all: bool,
        /// Make a PSBT that can be signed by offline signers and hardware wallets. Forces the addition of `non_witness_utxo` and more details to let the signer identify the change output.
        #[structopt(long = "offline_signer")]
        offline_signer: bool,
        /// Selects which utxos *must* be added to the tx. Unconfirmed utxos cannot be used
        #[structopt(name = "MUST_SPEND_TXID:VOUT", long = "utxos", parse(try_from_str = parse_outpoint))]
        utxos: Option<Vec<OutPoint>>,
        /// Marks an utxo as unspendable, in case more inputs are needed to cover the extra fees
        #[structopt(name = "CANT_SPEND_TXID:VOUT", long = "unspendable", parse(try_from_str = parse_outpoint))]
        unspendable: Option<Vec<OutPoint>>,
        /// The new targeted fee rate in sat/vbyte
        #[structopt(name = "SATS_VBYTE", short = "fee", long = "fee_rate")]
        fee_rate: f32,
    },
    /// Returns the available spending policies for the descriptor
    Policies,
    /// Returns the public version of the wallet's descriptor(s)
    PublicDescriptor,
    /// Signs and tries to finalize a PSBT
    Sign {
        /// Sets the PSBT to sign
        #[structopt(name = "BASE64_PSBT", long = "psbt")]
        psbt: String,
        /// Assume the blockchain has reached a specific height. This affects the transaction finalization, if there are timelocks in the descriptor
        #[structopt(name = "HEIGHT", long = "assume_height")]
        assume_height: Option<u32>,
    },
    /// Broadcasts a transaction to the network. Takes either a raw transaction or a PSBT to extract
    Broadcast {
        /// Sets the PSBT to sign
        #[structopt(
            name = "BASE64_PSBT",
            long = "psbt",
            required_unless = "RAWTX",
            conflicts_with = "RAWTX"
        )]
        psbt: Option<String>,
        /// Sets the raw transaction to broadcast
        #[structopt(
            name = "RAWTX",
            long = "tx",
            required_unless = "BASE64_PSBT",
            conflicts_with = "BASE64_PSBT"
        )]
        tx: Option<String>,
    },
    /// Extracts a raw transaction from a PSBT
    ExtractPsbt {
        /// Sets the PSBT to extract
        #[structopt(name = "BASE64_PSBT", long = "psbt")]
        psbt: String,
    },
    /// Finalizes a PSBT
    FinalizePsbt {
        /// Sets the PSBT to finalize
        #[structopt(name = "BASE64_PSBT", long = "psbt")]
        psbt: String,
        /// Assume the blockchain has reached a specific height
        #[structopt(name = "HEIGHT", long = "assume_height")]
        assume_height: Option<u32>,
    },
    /// Combines multiple PSBTs into one
    CombinePsbt {
        /// Add one PSBT to combine. This option can be repeated multiple times, one for each PSBT
        #[structopt(name = "BASE64_PSBT", long = "psbt", required = true)]
        psbt: Vec<String>,
    },
    /// Enter REPL command loop mode
    Repl,
}

fn parse_recipient(s: &str) -> Result<(Script, u64), String> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid format".to_string());
    }

    let addr = Address::from_str(&parts[0]);
    if let Err(e) = addr {
        return Err(format!("{:?}", e));
    }
    let val = u64::from_str(&parts[1]);
    if let Err(e) = val {
        return Err(format!("{:?}", e));
    }

    Ok((addr.unwrap().script_pubkey(), val.unwrap()))
}

fn parse_outpoint(s: &str) -> Result<OutPoint, String> {
    OutPoint::from_str(s).map_err(|e| format!("{:?}", e))
}

/// Execute a wallet sub-command with a given [`Wallet`].
///
/// Wallet sub-commands are described in [`WalletSubCommand`]. See [`crate`] for example usage.
#[maybe_async]
pub fn handle_wallet_subcommand<C, D>(
    wallet: &Wallet<C, D>,
    wallet_subcommand: WalletSubCommand,
) -> Result<serde_json::Value, Error>
where
    C: bdk::blockchain::Blockchain,
    D: bdk::database::BatchDatabase,
{
    match wallet_subcommand {
        WalletSubCommand::GetNewAddress => Ok(json!({"address": wallet.get_new_address()?})),
        WalletSubCommand::Sync { max_addresses } => {
            maybe_await!(wallet.sync(log_progress(), max_addresses))?;
            Ok(json!({}))
        }
        WalletSubCommand::ListUnspent => Ok(serde_json::to_value(&wallet.list_unspent()?)?),
        WalletSubCommand::ListTransactions => {
            Ok(serde_json::to_value(&wallet.list_transactions(false)?)?)
        }
        WalletSubCommand::GetBalance => Ok(json!({"satoshi": wallet.get_balance()?})),
        WalletSubCommand::CreateTx {
            recipients,
            send_all,
            enable_rbf,
            offline_signer,
            utxos,
            unspendable,
            fee_rate,
            external_policy,
            internal_policy,
        } => {
            let mut tx_builder = TxBuilder::new();

            if send_all {
                tx_builder = tx_builder
                    .drain_wallet()
                    .set_single_recipient(recipients[0].0.clone());
            } else {
                tx_builder = tx_builder.set_recipients(recipients);
            }

            if enable_rbf {
                tx_builder = tx_builder.enable_rbf();
            }

            if offline_signer {
                tx_builder = tx_builder
                    .force_non_witness_utxo()
                    .include_output_redeem_witness_script();
            }

            if let Some(fee_rate) = fee_rate {
                tx_builder = tx_builder.fee_rate(FeeRate::from_sat_per_vb(fee_rate));
            }

            if let Some(utxos) = utxos {
                tx_builder = tx_builder.utxos(utxos).manually_selected_only();
            }

            if let Some(unspendable) = unspendable {
                tx_builder = tx_builder.unspendable(unspendable);
            }

            let policies = vec![
                external_policy.map(|p| (p, KeychainKind::External)),
                internal_policy.map(|p| (p, KeychainKind::Internal)),
            ];

            for (policy, keychain) in policies.into_iter().filter_map(|x| x) {
                let policy = serde_json::from_str::<BTreeMap<String, Vec<usize>>>(&policy)
                    .map_err(|s| Error::Generic(s.to_string()))?;
                tx_builder = tx_builder.policy_path(policy, keychain);
            }

            let (psbt, details) = wallet.create_tx(tx_builder)?;
            Ok(json!({"psbt": base64::encode(&serialize(&psbt)),"details": details,}))
        }
        WalletSubCommand::BumpFee {
            txid,
            send_all,
            offline_signer,
            utxos,
            unspendable,
            fee_rate,
        } => {
            let txid = Txid::from_str(txid.as_str()).map_err(|s| Error::Generic(s.to_string()))?;

            let mut tx_builder = TxBuilder::new().fee_rate(FeeRate::from_sat_per_vb(fee_rate));

            if send_all {
                tx_builder = tx_builder.maintain_single_recipient();
            }

            if offline_signer {
                tx_builder = tx_builder
                    .force_non_witness_utxo()
                    .include_output_redeem_witness_script();
            }

            if let Some(utxos) = utxos {
                tx_builder = tx_builder.utxos(utxos);
            }

            if let Some(unspendable) = unspendable {
                tx_builder = tx_builder.unspendable(unspendable);
            }

            let (psbt, details) = wallet.bump_fee(&txid, tx_builder)?;
            Ok(json!({"psbt": base64::encode(&serialize(&psbt)),"details": details,}))
        }
        WalletSubCommand::Policies => Ok(json!({
            "external": wallet.policies(KeychainKind::External)?,
            "internal": wallet.policies(KeychainKind::Internal)?,
        })),
        WalletSubCommand::PublicDescriptor => Ok(json!({
            "external": wallet.public_descriptor(KeychainKind::External)?.map(|d| d.to_string()),
            "internal": wallet.public_descriptor(KeychainKind::Internal)?.map(|d| d.to_string()),
        })),
        WalletSubCommand::Sign {
            psbt,
            assume_height,
        } => {
            let psbt = base64::decode(&psbt).unwrap();
            let psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();
            let (psbt, finalized) = wallet.sign(psbt, assume_height)?;
            Ok(json!({"psbt": base64::encode(&serialize(&psbt)),"is_finalized": finalized,}))
        }
        WalletSubCommand::Broadcast { psbt, tx } => {
            let tx = match (psbt, tx) {
                (Some(psbt), None) => {
                    let psbt = base64::decode(&psbt).unwrap();
                    let psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();
                    psbt.extract_tx()
                }
                (None, Some(tx)) => deserialize(&Vec::<u8>::from_hex(&tx).unwrap()).unwrap(),
                (Some(_), Some(_)) => panic!("Both `psbt` and `tx` options not allowed"),
                (None, None) => panic!("Missing `psbt` and `tx` option"),
            };

            let txid = maybe_await!(wallet.broadcast(tx))?;
            Ok(json!({ "txid": txid }))
        }
        WalletSubCommand::ExtractPsbt { psbt } => {
            let psbt = base64::decode(&psbt).unwrap();
            let psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();
            Ok(json!({"raw_tx": serialize_hex(&psbt.extract_tx()),}))
        }
        WalletSubCommand::FinalizePsbt {
            psbt,
            assume_height,
        } => {
            let psbt = base64::decode(&psbt).unwrap();
            let psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();

            let (psbt, finalized) = wallet.finalize_psbt(psbt, assume_height)?;
            Ok(json!({ "psbt": base64::encode(&serialize(&psbt)),"is_finalized": finalized,}))
        }
        WalletSubCommand::CombinePsbt { psbt } => {
            let mut psbts = psbt
                .iter()
                .map(|s| {
                    let psbt = base64::decode(&s).unwrap();
                    let psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();
                    psbt
                })
                .collect::<Vec<_>>();

            let init_psbt = psbts.pop().unwrap();
            let final_psbt = psbts
                .into_iter()
                .try_fold::<_, _, Result<PartiallySignedTransaction, Error>>(
                    init_psbt,
                    |mut acc, x| {
                        acc.merge(x)?;
                        Ok(acc)
                    },
                )?;

            Ok(json!({ "psbt": base64::encode(&serialize(&final_psbt)) }))
        }
        WalletSubCommand::Repl => Ok(json!({})),
    }
}

#[cfg(test)]
mod test {
    use super::{WalletOpt, WalletSubCommand};
    use bdk::bitcoin::{Address, Network, OutPoint};
    use std::str::FromStr;
    use structopt::StructOpt;

    #[test]
    fn test_get_new_address() {
        let cli_args = vec!["bdk-cli", "--network", "bitcoin",
                            "--descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "--change_descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)",
                            "--esplora", "https://blockstream.info/api/",
                            "--esplora_concurrency", "5",
                            "get_new_address"];

        let wallet_opt = WalletOpt::from_iter(&cli_args);

        let expected_wallet_opt = WalletOpt {
            network: Network::Bitcoin,
            wallet: "main".to_string(),
            proxy: None,
            descriptor: "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
            change_descriptor: Some("wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
            #[cfg(feature = "esplora")]
            esplora: Some("https://blockstream.info/api/".to_string()),
            #[cfg(feature = "esplora")]
            esplora_concurrency: 5,
            electrum: "ssl://electrum.blockstream.info:60002".to_string(),
            subcommand: WalletSubCommand::GetNewAddress,
        };

        assert_eq!(expected_wallet_opt, wallet_opt);
    }

    #[test]
    fn test_sync() {
        let cli_args = vec!["bdk-cli", "--network", "testnet",
                            "--descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "sync", "--max_addresses", "50"];

        let wallet_opt = WalletOpt::from_iter(&cli_args);

        let expected_wallet_opt = WalletOpt {
            network: Network::Testnet,
            wallet: "main".to_string(),
            proxy: None,
            descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
            change_descriptor: None,
            #[cfg(feature = "esplora")]
            esplora: None,
            #[cfg(feature = "esplora")]
            esplora_concurrency: 4,
            electrum: "ssl://electrum.blockstream.info:60002".to_string(),
            subcommand: WalletSubCommand::Sync {
                max_addresses: Some(50)
            },
        };

        assert_eq!(expected_wallet_opt, wallet_opt);
    }

    #[test]
    fn test_create_tx() {
        let cli_args = vec!["bdk-cli", "--network", "testnet", "--proxy", "127.0.0.1:9150",
                            "--descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "--change_descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)",
                            "--server","ssl://electrum.blockstream.info:50002",
                            "create_tx", "--to", "n2Z3YNXtceeJhFkTknVaNjT1mnCGWesykJ:123456","mjDZ34icH4V2k9GmC8niCrhzVuR3z8Mgkf:78910",
                            "--utxos","87345e46bfd702d24d54890cc094d08a005f773b27c8f965dfe0eb1e23eef88e:1",
                            "--utxos","87345e46bfd702d24d54890cc094d08a005f773b27c8f965dfe0eb1e23eef88e:2"];

        let wallet_opt = WalletOpt::from_iter(&cli_args);

        let script1 = Address::from_str("n2Z3YNXtceeJhFkTknVaNjT1mnCGWesykJ")
            .unwrap()
            .script_pubkey();
        let script2 = Address::from_str("mjDZ34icH4V2k9GmC8niCrhzVuR3z8Mgkf")
            .unwrap()
            .script_pubkey();
        let outpoint1 = OutPoint::from_str(
            "87345e46bfd702d24d54890cc094d08a005f773b27c8f965dfe0eb1e23eef88e:1",
        )
        .unwrap();
        let outpoint2 = OutPoint::from_str(
            "87345e46bfd702d24d54890cc094d08a005f773b27c8f965dfe0eb1e23eef88e:2",
        )
        .unwrap();

        let expected_wallet_opt = WalletOpt {
            network: Network::Testnet,
            wallet: "main".to_string(),
            proxy: Some("127.0.0.1:9150".to_string()),
            descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
            change_descriptor: Some("wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
            #[cfg(feature = "esplora")]
            esplora: None,
            #[cfg(feature = "esplora")]
            esplora_concurrency: 4,
            electrum: "ssl://electrum.blockstream.info:50002".to_string(),
            subcommand: WalletSubCommand::CreateTx {
                recipients: vec![(script1, 123456), (script2, 78910)],
                send_all: false,
                enable_rbf: false,
                offline_signer: false,
                utxos: Some(vec!(outpoint1, outpoint2)),
                unspendable: None,
                fee_rate: None,
                external_policy: None,
                internal_policy: None,
            },
        };

        assert_eq!(expected_wallet_opt, wallet_opt);
    }

    #[test]
    fn test_broadcast() {
        let cli_args = vec!["bdk-cli", "--network", "testnet",
                            "--descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "broadcast",
                            "--psbt", "cHNidP8BAEICAAAAASWhGE1AhvtO+2GjJHopssFmgfbq+WweHd8zN/DeaqmDAAAAAAD/////AQAAAAAAAAAABmoEAAECAwAAAAAAAAA="];

        let wallet_opt = WalletOpt::from_iter(&cli_args);

        let expected_wallet_opt = WalletOpt {
            network: Network::Testnet,
            wallet: "main".to_string(),
            proxy: None,
            descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
            change_descriptor: None,
            #[cfg(feature = "esplora")]
            esplora: None,
            #[cfg(feature = "esplora")]
            esplora_concurrency: 4,
            electrum: "ssl://electrum.blockstream.info:60002".to_string(),
            subcommand: WalletSubCommand::Broadcast {
                psbt: Some("cHNidP8BAEICAAAAASWhGE1AhvtO+2GjJHopssFmgfbq+WweHd8zN/DeaqmDAAAAAAD/////AQAAAAAAAAAABmoEAAECAwAAAAAAAAA=".to_string()),
                tx: None
            },
        };

        assert_eq!(expected_wallet_opt, wallet_opt);
    }

    #[test]
    fn test_wrong_network() {
        let cli_args = vec!["repl", "--network", "badnet",
                            "--descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "sync", "--max_addresses", "50"];

        let wallet_opt = WalletOpt::from_iter_safe(&cli_args);
        assert!(wallet_opt.is_err());
    }
}
