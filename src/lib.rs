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

//! BDK command line interface
//!
//! This lib provides [`structopt`] structs and enums that parse CLI options and sub-commands from
//! the command line or from a `String` vector that can be used to access features of the [`bdk`]
//! library. Functions are also provided to handle subcommands and options and provide results via
//! the [`bdk`] lib.  
//!
//! See the [`bdk-cli`] example bin for how to use this lib to create a simple command line
//! application that demonstrates [`bdk`] wallet and key management features.
//!
//! See [`CliOpts`] for global cli options and [`CliSubCommand`] for supported top level sub-commands.
//!
//! [`structopt`]: https://docs.rs/crate/structopt
//! [`bdk`]: https://github.com/bitcoindevkit/bdk
//! [`bdk-cli`]: https://github.com/bitcoindevkit/bdk-cli/blob/master/src/bdk_cli.rs
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "electrum")]
//! # {
//! # use bdk::bitcoin::Network;
//! # use bdk::blockchain::{AnyBlockchain, ConfigurableBlockchain};
//! # use bdk::blockchain::{AnyBlockchainConfig, ElectrumBlockchainConfig};
//! # use bdk_cli::{self, CliOpts, CliSubCommand, WalletOpts, OfflineWalletSubCommand, WalletSubCommand};
//! # use bdk::database::MemoryDatabase;
//! # use bdk::Wallet;
//! # use std::sync::Arc;
//! # use structopt::StructOpt;
//! # use std::str::FromStr;
//!
//! // to get args from cli use:
//! // let cli_opts = CliOpts::from_args();
//!
//! let cli_args = vec!["bdk-cli", "--network", "testnet", "wallet", "--descriptor",
//!                     "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)",
//!                     "sync", "--max_addresses", "50"];
//!
//! let cli_opts = CliOpts::from_iter(&cli_args);
//! let network = cli_opts.network;
//!
//! if let CliSubCommand::Wallet {
//!         wallet_opts,
//!         subcommand: WalletSubCommand::OnlineWalletSubCommand(online_subcommand)
//!     } = cli_opts.subcommand {
//!
//!     let descriptor = wallet_opts.descriptor.as_str();
//!     let change_descriptor = wallet_opts.change_descriptor.as_deref();
//!
//!     let database = MemoryDatabase::new();
//!
//!     let config = AnyBlockchainConfig::Electrum(ElectrumBlockchainConfig {
//!                 url: wallet_opts.electrum_opts.electrum,
//!                 socks5: wallet_opts.electrum_opts.proxy,
//!                 retry: 3,
//!                 timeout: None,
//!             });
//!
//!     let wallet = Wallet::new(
//!         descriptor,
//!         change_descriptor,
//!         network,
//!         database,
//!         AnyBlockchain::from_config(&config).unwrap(),
//!     ).unwrap();
//!
//!     let result = bdk_cli::handle_online_wallet_subcommand(&wallet, online_subcommand).unwrap();
//!     println!("{}", serde_json::to_string_pretty(&result).unwrap());
//! }
//! # }
//! ```

pub extern crate bdk;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate bdk_macros;

use std::collections::BTreeMap;
use std::str::FromStr;

pub use structopt;
use structopt::StructOpt;

use crate::OfflineWalletSubCommand::*;
use crate::OnlineWalletSubCommand::*;
use bdk::bitcoin::consensus::encode::{deserialize, serialize, serialize_hex};
use bdk::bitcoin::hashes::hex::FromHex;
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, KeySource};
use bdk::bitcoin::util::psbt::PartiallySignedTransaction;
use bdk::bitcoin::{Address, Network, OutPoint, Script, Txid};
use bdk::blockchain::{log_progress, Blockchain};
use bdk::database::BatchDatabase;
use bdk::descriptor::Segwitv0;
#[cfg(feature = "compiler")]
use bdk::descriptor::{Descriptor, Legacy, Miniscript};
use bdk::keys::bip39::{Language, Mnemonic, MnemonicType};
use bdk::keys::DescriptorKey::Secret;
use bdk::keys::KeyError::{InvalidNetwork, Message};
use bdk::keys::{DerivableKey, DescriptorKey, ExtendedKey, GeneratableKey, GeneratedKey};
use bdk::miniscript::miniscript;
#[cfg(feature = "compiler")]
use bdk::miniscript::policy::Concrete;
use bdk::Error;
use bdk::{FeeRate, KeychainKind, Wallet};

/// Global options
///
/// The global options and top level sub-command required for all subsequent [`CliSubCommand`]'s.
///
/// # Example
///
/// ```
/// # use bdk::bitcoin::Network;
/// # use structopt::StructOpt;
/// # use bdk_cli::{CliOpts, WalletOpts, CliSubCommand, WalletSubCommand};
/// # #[cfg(feature = "electrum")]
/// # use bdk_cli::ElectrumOpts;
/// # #[cfg(feature = "esplora")]
/// # use bdk_cli::EsploraOpts;
/// # use bdk_cli::OnlineWalletSubCommand::Sync;
///
/// let cli_args = vec!["bdk-cli", "--network", "testnet", "wallet",
///                     "--descriptor", "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/44'/1'/0'/0/*)",
///                     "sync", "--max_addresses", "50"];
///
/// // to get CliOpts from the OS command line args use:
/// // let cli_opts = CliOpts::from_args();
/// let cli_opts = CliOpts::from_iter(&cli_args);
///
/// let expected_cli_opts = CliOpts {
///             network: Network::Testnet,
///             subcommand: CliSubCommand::Wallet {
///                 wallet_opts: WalletOpts {
///                     wallet: "main".to_string(),
///                     descriptor: "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/44'/1'/0'/0/*)".to_string(),
///                     change_descriptor: None,
///               #[cfg(feature = "electrum")]
///               electrum_opts: ElectrumOpts {
///                   proxy: None,
///                   retries: 5,
///                   timeout: None,
///                   electrum: "ssl://electrum.blockstream.info:60002".to_string(),
///               },
///               #[cfg(feature = "esplora")]
///               esplora_opts: EsploraOpts {               
///                   esplora: None,
///                   esplora_concurrency: 4,
///               }
///                 },
///                 subcommand: WalletSubCommand::OnlineWalletSubCommand(Sync {
///                     max_addresses: Some(50)
///                 }),
///             },
///         };
///
/// assert_eq!(expected_cli_opts, cli_opts);
/// ```
#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(name = "BDK CLI",
version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"),
author = option_env ! ("CARGO_PKG_AUTHORS").unwrap_or(""))]
pub struct CliOpts {
    /// Sets the network
    #[structopt(
        name = "NETWORK",
        short = "n",
        long = "network",
        default_value = "testnet"
    )]
    pub network: Network,
    /// Top level cli sub-command
    #[structopt(subcommand)]
    pub subcommand: CliSubCommand,
}

/// CLI sub-commands
///
/// The top level sub-commands, each may have different required options. For
/// instance [`CliSubCommand::Wallet`] requires [`WalletOpts`] with a required descriptor but
/// [`CliSubCommand::Key`] sub-command does not. [`CliSubCommand::Repl`] also requires
/// [`WalletOpts`] and a descriptor because in this mode both [`WalletSubCommand`] and
/// [`KeySubCommand`] sub-commands are available.
#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(
    rename_all = "snake",
    long_about = "Top level options and command modes"
)]
pub enum CliSubCommand {
    /// Wallet options and sub-commands
    #[structopt(long_about = "Wallet mode")]
    Wallet {
        #[structopt(flatten)]
        wallet_opts: WalletOpts,
        #[structopt(subcommand)]
        subcommand: WalletSubCommand,
    },
    /// Key management sub-commands
    #[structopt(long_about = "Key management mode")]
    Key {
        #[structopt(subcommand)]
        subcommand: KeySubCommand,
    },
    /// Compile a miniscript policy to an output descriptor
    #[cfg(feature = "compiler")]
    #[structopt(long_about = "Miniscript policy compiler")]
    Compile {
        /// Sets the spending policy to compile
        #[structopt(name = "POLICY", required = true, index = 1)]
        policy: String,
        /// Sets the script type used to embed the compiled policy
        #[structopt(name = "TYPE", short = "t", long = "type", default_value = "wsh", possible_values = &["sh","wsh", "sh-wsh"])]
        script_type: String,
    },
    /// Enter REPL command loop mode
    #[structopt(long_about = "REPL command loop mode")]
    Repl {
        #[structopt(flatten)]
        wallet_opts: WalletOpts,
    },
}

/// Wallet sub-commands
///
/// Can use either an online or offline wallet. An [`OnlineWalletSubCommand`] requires a blockchain
/// client and network connection and an [`OfflineWalletSubCommand`] does not.
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub enum WalletSubCommand {
    #[structopt(flatten)]
    OnlineWalletSubCommand(OnlineWalletSubCommand),
    #[structopt(flatten)]
    OfflineWalletSubCommand(OfflineWalletSubCommand),
}

/// Wallet options
///
/// The wallet options required for all [`CliSubCommand::Wallet`] or [`CliSubCommand::Repl`]
/// sub-commands. These options capture wallet descriptor and blockchain client information. The
/// blockchain client details are only used for [`OnlineWalletSubCommand`]s.   
///
/// # Example
///
/// ```
/// # use bdk::bitcoin::Network;
/// # use structopt::StructOpt;
/// # use bdk_cli::WalletOpts;
/// # #[cfg(feature = "electrum")]
/// # use bdk_cli::ElectrumOpts;
/// # #[cfg(feature = "esplora")]
/// # use bdk_cli::EsploraOpts;
///
/// let cli_args = vec!["wallet",
///                     "--descriptor", "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/44'/1'/0'/0/*)"];
///
/// // to get WalletOpt from OS command line args use:
/// // let wallet_opt = WalletOpt::from_args();
///
/// let wallet_opts = WalletOpts::from_iter(&cli_args);
///
/// let expected_wallet_opts = WalletOpts {
///               wallet: "main".to_string(),
///               descriptor: "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/44'/1'/0'/0/*)".to_string(),
///               change_descriptor: None,
///               #[cfg(feature = "electrum")]
///               electrum_opts: ElectrumOpts {
///                   proxy: None,
///                   retries: 5,
///                   timeout: None,
///                   electrum: "ssl://electrum.blockstream.info:60002".to_string(),
///               },
///               #[cfg(feature = "esplora")]
///               esplora_opts: EsploraOpts {               
///                   esplora: None,
///                   esplora_concurrency: 4,
///               }
/// };
///
/// assert_eq!(expected_wallet_opts, wallet_opts);
/// ```
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct WalletOpts {
    /// Selects the wallet to use
    #[structopt(
        name = "WALLET_NAME",
        short = "w",
        long = "wallet",
        default_value = "main"
    )]
    pub wallet: String,
    /// Sets the descriptor to use for the external addresses
    #[structopt(name = "DESCRIPTOR", short = "d", long = "descriptor", required = true)]
    pub descriptor: String,
    /// Sets the descriptor to use for internal addresses
    #[structopt(name = "CHANGE_DESCRIPTOR", short = "c", long = "change_descriptor")]
    pub change_descriptor: Option<String>,
    #[cfg(feature = "electrum")]
    #[structopt(flatten)]
    pub electrum_opts: ElectrumOpts,
    #[cfg(feature = "esplora")]
    #[structopt(flatten)]
    pub esplora_opts: EsploraOpts,
}

/// Electrum options
///
/// Electrum blockchain client information used by [`OnlineWalletSubCommand`]s.
#[cfg(feature = "electrum")]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct ElectrumOpts {
    /// Sets the SOCKS5 proxy for the Electrum client
    #[structopt(name = "PROXY_SERVER:PORT", short = "p", long = "proxy")]
    pub proxy: Option<String>,
    /// Sets the SOCKS5 proxy retries for the Electrum client
    #[structopt(
        name = "PROXY_RETRIES",
        short = "r",
        long = "retries",
        default_value = "5"
    )]
    pub retries: u8,
    /// Sets the SOCKS5 proxy timeout for the Electrum client
    #[structopt(name = "PROXY_TIMEOUT", short = "t", long = "timeout")]
    pub timeout: Option<u8>,
    /// Sets the Electrum server to use
    #[structopt(
        name = "SERVER:PORT",
        short = "s",
        long = "server",
        default_value = "ssl://electrum.blockstream.info:60002"
    )]
    pub electrum: String,
}

/// Esplora options
///
/// Esplora blockchain client information used by [`OnlineWalletSubCommand`]s.
#[cfg(feature = "esplora")]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct EsploraOpts {
    /// Use the esplora server if given as parameter
    #[structopt(name = "ESPLORA_URL", short = "e", long = "esplora")]
    pub esplora: Option<String>,
    /// Concurrency of requests made to the esplora server
    #[structopt(
        name = "ESPLORA_CONCURRENCY",
        long = "esplora_concurrency",
        default_value = "4"
    )]
    pub esplora_concurrency: u8,
}

// This is a workaround for `structopt` issue #333, #391, #418; see https://github.com/TeXitoi/structopt/issues/333#issuecomment-712265332
#[cfg_attr(not(doc), allow(missing_docs))]
#[cfg_attr(
    doc,
    doc = r#"
Offline Wallet sub-command

[`CliSubCommand::Wallet`] sub-commands that do not require a blockchain client and network
connection. These sub-commands use only the provided descriptor or locally cached wallet
information.

# Example

```
# use bdk_cli::OfflineWalletSubCommand;
# use structopt::StructOpt;

let address_sub_command = OfflineWalletSubCommand::from_iter(&["wallet", "get_new_address"]);
assert!(matches!(
     address_sub_command,
    OfflineWalletSubCommand::GetNewAddress
));
```

To capture wallet sub-commands from a string vector without a preceeding binary name you can
create a custom struct the includes the `NoBinaryName` clap setting and wraps the WalletSubCommand
enum. See also the [`bdk-cli`](https://github.com/bitcoindevkit/bdk-cli/blob/master/src/bdkcli.rs)
example app.
"#
)]
#[cfg_attr(
    all(doc, feature = "repl"),
    doc = r#"

# Example
```
# use bdk_cli::OfflineWalletSubCommand;
# use structopt::StructOpt;
# use clap::AppSettings;

#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(name = "BDK CLI", setting = AppSettings::NoBinaryName,
version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"),
author = option_env ! ("CARGO_PKG_AUTHORS").unwrap_or(""))]
struct ReplOpts {
    /// Wallet sub-command
    #[structopt(subcommand)]
    pub subcommand: OfflineWalletSubCommand,
}

let repl_opts = ReplOpts::from_iter(&["get_new_address"]);
assert!(matches!(
    repl_opts.subcommand,
    OfflineWalletSubCommand::GetNewAddress
));
"#
)]
#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(rename_all = "snake")]
pub enum OfflineWalletSubCommand {
    /// Generates a new external address
    GetNewAddress,
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
}

#[cfg_attr(not(doc), allow(missing_docs))]
#[cfg_attr(
    doc,
    doc = r#"
Online Wallet sub-command

[`CliSubCommand::Wallet`] sub-commands that require a blockchain client and network connection.
These sub-commands use a provided descriptor, locally cached wallet information, and require a
blockchain client and network connection.
"#
)]
#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(rename_all = "snake")]
pub enum OnlineWalletSubCommand {
    /// Syncs with the chosen blockchain server
    Sync {
        /// max addresses to consider
        #[structopt(short = "v", long = "max_addresses")]
        max_addresses: Option<u32>,
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

/// Execute an offline wallet sub-command
///
/// Offline wallet sub-commands are described in [`OfflineWalletSubCommand`].
pub fn handle_offline_wallet_subcommand<T, D>(
    wallet: &Wallet<T, D>,
    offline_subcommand: OfflineWalletSubCommand,
) -> Result<serde_json::Value, Error>
where
    D: BatchDatabase,
{
    match offline_subcommand {
        GetNewAddress => Ok(json!({"address": wallet.get_new_address()?})),
        ListUnspent => Ok(serde_json::to_value(&wallet.list_unspent()?)?),
        ListTransactions => Ok(serde_json::to_value(&wallet.list_transactions(false)?)?),
        GetBalance => Ok(json!({"satoshi": wallet.get_balance()?})),
        CreateTx {
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
            let mut tx_builder = wallet.build_tx();

            if send_all {
                tx_builder
                    .drain_wallet()
                    .set_single_recipient(recipients[0].0.clone());
            } else {
                tx_builder.set_recipients(recipients);
            }

            if enable_rbf {
                tx_builder.enable_rbf();
            }

            if offline_signer {
                tx_builder
                    .force_non_witness_utxo()
                    .include_output_redeem_witness_script();
            }

            if let Some(fee_rate) = fee_rate {
                tx_builder.fee_rate(FeeRate::from_sat_per_vb(fee_rate));
            }

            if let Some(utxos) = utxos {
                tx_builder.add_utxos(&utxos[..])?.manually_selected_only();
            }

            if let Some(unspendable) = unspendable {
                tx_builder.unspendable(unspendable);
            }

            let policies = vec![
                external_policy.map(|p| (p, KeychainKind::External)),
                internal_policy.map(|p| (p, KeychainKind::Internal)),
            ];

            for (policy, keychain) in policies.into_iter().filter_map(|x| x) {
                let policy = serde_json::from_str::<BTreeMap<String, Vec<usize>>>(&policy)
                    .map_err(|s| Error::Generic(s.to_string()))?;
                tx_builder.policy_path(policy, keychain);
            }

            let (psbt, details) = tx_builder.finish()?;
            Ok(json!({"psbt": base64::encode(&serialize(&psbt)),"details": details,}))
        }
        BumpFee {
            txid,
            send_all,
            offline_signer,
            utxos,
            unspendable,
            fee_rate,
        } => {
            let txid = Txid::from_str(txid.as_str()).map_err(|s| Error::Generic(s.to_string()))?;

            let mut tx_builder = wallet.build_fee_bump(txid)?;
            tx_builder.fee_rate(FeeRate::from_sat_per_vb(fee_rate));

            if send_all {
                tx_builder.maintain_single_recipient()?;
            }

            if offline_signer {
                tx_builder
                    .force_non_witness_utxo()
                    .include_output_redeem_witness_script();
            }

            if let Some(utxos) = utxos {
                tx_builder.add_utxos(&utxos[..])?;
            }

            if let Some(unspendable) = unspendable {
                tx_builder.unspendable(unspendable);
            }

            let (psbt, details) = tx_builder.finish()?;
            Ok(json!({"psbt": base64::encode(&serialize(&psbt)),"details": details,}))
        }
        Policies => Ok(json!({
            "external": wallet.policies(KeychainKind::External)?,
            "internal": wallet.policies(KeychainKind::Internal)?,
        })),
        PublicDescriptor => Ok(json!({
            "external": wallet.public_descriptor(KeychainKind::External)?.map(|d| d.to_string()),
            "internal": wallet.public_descriptor(KeychainKind::Internal)?.map(|d| d.to_string()),
        })),
        Sign {
            psbt,
            assume_height,
        } => {
            let psbt = base64::decode(&psbt).unwrap();
            let psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();
            let (psbt, finalized) = wallet.sign(psbt, assume_height)?;
            Ok(json!({"psbt": base64::encode(&serialize(&psbt)),"is_finalized": finalized,}))
        }
        ExtractPsbt { psbt } => {
            let psbt = base64::decode(&psbt).unwrap();
            let psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();
            Ok(json!({"raw_tx": serialize_hex(&psbt.extract_tx()),}))
        }
        FinalizePsbt {
            psbt,
            assume_height,
        } => {
            let psbt = base64::decode(&psbt).unwrap();
            let psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();

            let (psbt, finalized) = wallet.finalize_psbt(psbt, assume_height)?;
            Ok(json!({ "psbt": base64::encode(&serialize(&psbt)),"is_finalized": finalized,}))
        }
        CombinePsbt { psbt } => {
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
    }
}

/// Execute an online wallet sub-command
///
/// Online wallet sub-commands are described in [`OnlineWalletSubCommand`]. See [`crate`] for
/// example usage.
#[maybe_async]
pub fn handle_online_wallet_subcommand<C, D>(
    wallet: &Wallet<C, D>,
    online_subcommand: OnlineWalletSubCommand,
) -> Result<serde_json::Value, Error>
where
    C: Blockchain,
    D: BatchDatabase,
{
    match online_subcommand {
        Sync { max_addresses } => {
            maybe_await!(wallet.sync(log_progress(), max_addresses))?;
            Ok(json!({}))
        }
        Broadcast { psbt, tx } => {
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
    }
}

#[cfg_attr(not(doc), allow(missing_docs))]
#[cfg_attr(
    doc,
    doc = r#"
Key sub-command

Provides basic key operations that are not related to a specific wallet such as generating a
new random master extended key or restoring a master extended key from mnemonic words.

These sub-commands are **EXPERIMENTAL** and should only be used for testing. Do not use this
feature to create keys that secure actual funds on the Bitcoin mainnet.  
"#
)]
#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(rename_all = "snake")]
pub enum KeySubCommand {
    /// Generates new random seed mnemonic phrase and corresponding master extended key
    Generate {
        /// Entropy level based on number of random seed mnemonic words
        #[structopt(
        name = "WORD_COUNT",
        short = "e",
        long = "entropy",
        default_value = "24",
        possible_values = &["12","24"],
        )]
        word_count: usize,
        /// Seed password
        #[structopt(name = "PASSWORD", short = "p", long = "password")]
        password: Option<String>,
    },
    /// Restore a master extended key from seed backup mnemonic words
    Restore {
        /// Seed mnemonic words, must be quoted (eg. "word1 word2 ...")
        #[structopt(name = "MNEMONIC", short = "m", long = "mnemonic")]
        mnemonic: String,
        /// Seed password
        #[structopt(name = "PASSWORD", short = "p", long = "password")]
        password: Option<String>,
    },
    /// Derive a child key pair from a master extended key and a derivation path string (eg. "m/84'/1'/0'/0" or "m/84h/1h/0h/0")
    Derive {
        /// Extended private key to derive from
        #[structopt(name = "XPRV", short = "x", long = "xprv")]
        xprv: String,
        /// Path to use to derive extended public key from extended private key
        #[structopt(name = "PATH", short = "p", long = "path")]
        path: String,
    },
}

/// Execute a key sub-command
///
/// Key sub-commands are described in [`KeySubCommand`].
pub fn handle_key_subcommand(
    network: Network,
    subcommand: KeySubCommand,
) -> Result<serde_json::Value, Error> {
    let secp = Secp256k1::new();

    match subcommand {
        KeySubCommand::Generate {
            word_count,
            password,
        } => {
            let mnemonic_type = match word_count {
                12 => MnemonicType::Words12,
                _ => MnemonicType::Words24,
            };
            let mnemonic: GeneratedKey<_, miniscript::BareCtx> =
                Mnemonic::generate((mnemonic_type, Language::English)).unwrap();
            //.map_err(|e| KeyError::from(e.unwrap()))?;
            let mnemonic = mnemonic.into_key();
            let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).unwrap();
            let fingerprint = xprv.fingerprint(&secp);
            Ok(
                json!({ "mnemonic": mnemonic.phrase(), "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }),
            )
        }
        KeySubCommand::Restore { mnemonic, password } => {
            let mnemonic = Mnemonic::from_phrase(mnemonic.as_ref(), Language::English).unwrap();
            //     .map_err(|e| {
            //     KeyError::from(e.downcast::<bdk::keys::bip39::ErrorKind>().unwrap())
            // })?;
            let xkey: ExtendedKey = (mnemonic, password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).unwrap();
            let fingerprint = xprv.fingerprint(&secp);

            Ok(json!({ "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }))
        }
        KeySubCommand::Derive { xprv, path } => {
            let xprv = ExtendedPrivKey::from_str(xprv.as_str())?;
            if xprv.network != network {
                return Err(Error::Key(InvalidNetwork));
            }
            let deriv_path: DerivationPath = DerivationPath::from_str(path.as_str())?;

            let derived_xprv = &xprv.derive_priv(&secp, &deriv_path)?;

            let origin: KeySource = (xprv.fingerprint(&secp), deriv_path);

            let derived_xprv_desc_key: DescriptorKey<Segwitv0> =
                derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default())?;

            if let Secret(desc_seckey, _, _) = derived_xprv_desc_key {
                let desc_pubkey = desc_seckey.as_public(&secp).unwrap();
                Ok(json!({"xpub": desc_pubkey.to_string(), "xprv": desc_seckey.to_string()}))
            } else {
                Err(Error::Key(Message("Invalid key variant".to_string())))
            }
        }
    }
}

/// Execute the miniscript compiler sub-command
///
/// Compiler options are described in [`CliSubCommand::Compile`].
#[cfg(feature = "compiler")]
pub fn handle_compile_subcommand(
    _network: Network,
    policy: String,
    script_type: String,
) -> Result<serde_json::Value, Error> {
    let policy = Concrete::<String>::from_str(policy.as_str())?;
    let legacy_policy: Miniscript<String, Legacy> = policy
        .compile()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let segwit_policy: Miniscript<String, Segwitv0> = policy
        .compile()
        .map_err(|e| Error::Generic(e.to_string()))?;

    let descriptor = match script_type.as_str() {
        "sh" => Descriptor::new_sh(legacy_policy),
        "wsh" => Descriptor::new_wsh(segwit_policy),
        "sh-wsh" => Descriptor::new_sh_wsh(segwit_policy),
        _ => panic!("Invalid type"),
    }
    .map_err(Error::Miniscript)?;

    Ok(json!({"descriptor": descriptor.to_string()}))
}

#[cfg(test)]
mod test {
    use super::{CliOpts, WalletOpts};
    #[cfg(feature = "compiler")]
    use crate::handle_compile_subcommand;
    #[cfg(feature = "electrum")]
    use crate::ElectrumOpts;
    #[cfg(feature = "esplora")]
    use crate::EsploraOpts;
    use crate::OfflineWalletSubCommand::{CreateTx, GetNewAddress};
    use crate::OnlineWalletSubCommand::{Broadcast, Sync};
    use crate::{handle_key_subcommand, CliSubCommand, KeySubCommand, WalletSubCommand};

    use bdk::bitcoin::{Address, Network, OutPoint};
    use bdk::miniscript::bitcoin::network::constants::Network::Testnet;
    use std::str::FromStr;
    use structopt::StructOpt;

    #[test]
    fn test_parse_wallet_get_new_address() {
        let cli_args = vec!["bdk-cli", "--network", "bitcoin", "wallet",
                            "--descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "--change_descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)",
                            "get_new_address"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    descriptor: "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        proxy: None,
                        retries: 5,
                        timeout: None,
                        electrum: "ssl://electrum.blockstream.info:60002".to_string()
                    },
                    #[cfg(feature = "esplora")]
                    esplora_opts: EsploraOpts {
                        esplora: None,
                        esplora_concurrency: 4
                    },
                },
                subcommand: WalletSubCommand::OfflineWalletSubCommand(GetNewAddress),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[cfg(feature = "electrum")]
    #[test]
    fn test_parse_wallet_electrum() {
        let cli_args = vec!["bdk-cli", "--network", "testnet", "wallet",
                            "--proxy", "127.0.0.1:9150", "--retries", "3", "--timeout", "10",
                            "--descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "--change_descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)",
                            "--server","ssl://electrum.blockstream.info:50002",
                            "get_new_address"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Testnet,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        proxy: Some("127.0.0.1:9150".to_string()),
                        retries: 3,
                        timeout: Some(10),
                        electrum: "ssl://electrum.blockstream.info:50002".to_string(),
                    },
                    #[cfg(feature = "esplora")]
                    esplora_opts: EsploraOpts {
                        esplora: None,
                        esplora_concurrency: 4,
                    }
                },
                subcommand: WalletSubCommand::OfflineWalletSubCommand(GetNewAddress),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[cfg(feature = "esplora")]
    #[test]
    fn test_parse_wallet_esplora() {
        let cli_args = vec!["bdk-cli", "--network", "bitcoin", "wallet",
                            "--descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "--change_descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)",             
                            "--esplora", "https://blockstream.info/api/",
                            "--esplora_concurrency", "5",
                            "get_new_address"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    descriptor: "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        proxy: None,
                        retries: 5,
                        timeout: None,
                        electrum: "ssl://electrum.blockstream.info:60002".to_string(),
                    },
                    #[cfg(feature = "esplora")]
                    esplora_opts: EsploraOpts {
                        esplora: Some("https://blockstream.info/api/".to_string()),
                        esplora_concurrency: 5,
                    }
                },
                subcommand: WalletSubCommand::OfflineWalletSubCommand(GetNewAddress),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[test]
    fn test_parse_wallet_sync() {
        let cli_args = vec!["bdk-cli", "--network", "testnet", "wallet",
                            "--descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "sync", "--max_addresses", "50"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Testnet,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: None,
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        proxy: None,
                        retries: 5,
                        timeout: None,
                        electrum: "ssl://electrum.blockstream.info:60002".to_string(),
                    },
                    #[cfg(feature = "esplora")]
                    esplora_opts: EsploraOpts {
                        esplora: None,
                        esplora_concurrency: 4,
                    }
                },
                subcommand: WalletSubCommand::OnlineWalletSubCommand(Sync {
                    max_addresses: Some(50)
                }),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[test]
    fn test_parse_wallet_create_tx() {
        let cli_args = vec!["bdk-cli", "--network", "testnet", "wallet",
                            "--descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "--change_descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)",
                            "create_tx", "--to", "n2Z3YNXtceeJhFkTknVaNjT1mnCGWesykJ:123456","mjDZ34icH4V2k9GmC8niCrhzVuR3z8Mgkf:78910",
                            "--utxos","87345e46bfd702d24d54890cc094d08a005f773b27c8f965dfe0eb1e23eef88e:1",
                            "--utxos","87345e46bfd702d24d54890cc094d08a005f773b27c8f965dfe0eb1e23eef88e:2"];

        let cli_opts = CliOpts::from_iter(&cli_args);

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

        let expected_cli_opts = CliOpts {
            network: Network::Testnet,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        proxy: None,
                        retries: 5,
                        timeout: None,
                        electrum: "ssl://electrum.blockstream.info:60002".to_string(),
                    },
                    #[cfg(feature = "esplora")]
                    esplora_opts: EsploraOpts {
                        esplora: None,
                        esplora_concurrency: 4,
                    }
                },
                subcommand: WalletSubCommand::OfflineWalletSubCommand(CreateTx {
                    recipients: vec![(script1, 123456), (script2, 78910)],
                    send_all: false,
                    enable_rbf: false,
                    offline_signer: false,
                    utxos: Some(vec!(outpoint1, outpoint2)),
                    unspendable: None,
                    fee_rate: None,
                    external_policy: None,
                    internal_policy: None,
                }),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[test]
    fn test_parse_wallet_broadcast() {
        let cli_args = vec!["bdk-cli", "--network", "testnet", "wallet",
                            "--descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "broadcast",
                            "--psbt", "cHNidP8BAEICAAAAASWhGE1AhvtO+2GjJHopssFmgfbq+WweHd8zN/DeaqmDAAAAAAD/////AQAAAAAAAAAABmoEAAECAwAAAAAAAAA="];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Testnet,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: None,
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        proxy: None,
                        retries: 5,
                        timeout: None,
                        electrum: "ssl://electrum.blockstream.info:60002".to_string(),
                    },
                    #[cfg(feature = "esplora")]
                    esplora_opts: EsploraOpts {
                        esplora: None,
                        esplora_concurrency: 4,
                    }
                },
                subcommand: WalletSubCommand::OnlineWalletSubCommand(Broadcast {
                    psbt: Some("cHNidP8BAEICAAAAASWhGE1AhvtO+2GjJHopssFmgfbq+WweHd8zN/DeaqmDAAAAAAD/////AQAAAAAAAAAABmoEAAECAwAAAAAAAAA=".to_string()),
                    tx: None
                }),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[test]
    fn test_parse_wrong_network() {
        let cli_args = vec!["repl", "--network", "badnet", "wallet",
                            "--descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "sync", "--max_addresses", "50"];

        let cli_opts = CliOpts::from_iter_safe(&cli_args);
        assert!(cli_opts.is_err());
    }

    #[test]
    fn test_key_generate() {
        let network = Testnet;
        let key_generate_cmd = KeySubCommand::Generate {
            word_count: 12,
            password: Some("test123".to_string()),
        };

        let result = handle_key_subcommand(network, key_generate_cmd).unwrap();
        let result_obj = result.as_object().unwrap();

        let mnemonic = result_obj.get("mnemonic").unwrap().as_str().unwrap();
        let mnemonic: Vec<&str> = mnemonic.split(' ').collect();
        let xprv = result_obj.get("xprv").unwrap().as_str().unwrap();

        assert_eq!(mnemonic.len(), 12);
        assert_eq!(&xprv[0..4], "tprv");
    }

    #[test]
    fn test_key_restore() {
        let network = Testnet;
        let key_generate_cmd = KeySubCommand::Restore {
            mnemonic: "payment battle unit sword token broccoli era violin purse trip blood hire"
                .to_string(),
            password: Some("test123".to_string()),
        };

        let result = handle_key_subcommand(network, key_generate_cmd).unwrap();
        let result_obj = result.as_object().unwrap();

        let fingerprint = result_obj.get("fingerprint").unwrap().as_str().unwrap();
        let xprv = result_obj.get("xprv").unwrap().as_str().unwrap();

        assert_eq!(&fingerprint, &"828af366");
        assert_eq!(&xprv, &"tprv8ZgxMBicQKsPd18TeiFknZKqaZFwpdX9tvvKh8eeHSSPBQi5g9xPHztBg411o78G8XkrhQb6Q1cVvBJ1a9xuFHpmWgvQsvkJkNxBjfGoqhK");
    }

    #[test]
    fn test_key_derive() {
        let network = Testnet;
        let key_generate_cmd = KeySubCommand::Derive {
            xprv: "tprv8ZgxMBicQKsPfQjJy8ge2cvBfDjLxJSkvNLVQiw7BQ5gTjKadG2rrcQB5zjcdaaUTz5EDNJaS77q4DzjqjogQBfMsaXFFNP3UqoBnwt2kyT"
                .to_string(),
            path: "m/84'/1'/0'/0".to_string(),
        };

        let result = handle_key_subcommand(network, key_generate_cmd).unwrap();
        let result_obj = result.as_object().unwrap();

        let xpub = result_obj.get("xpub").unwrap().as_str().unwrap();
        let xprv = result_obj.get("xprv").unwrap().as_str().unwrap();

        assert_eq!(&xpub, &"[566844c5/84'/1'/0'/0]tpubDFeqiDkfwR1tAhPxsXSZMfEmfpDhwhLyhLKZgmeBvuBkZQusoWeL62oGg2oTNGcENeKdwuGepAB85eMvyLemabYe9PSqv6cr5mFXktHc3Ka/*");
        assert_eq!(&xprv, &"[566844c5/84'/1'/0'/0]tprv8ixoZoiRo3LDHENAysmxxFaf6nhmnNA582inQFbtWdPMivf7B7pjuYBQVuLC5bkM7tJZEDbfoivENsGZPBnQg1n52Kuc1P8X2Ei3XJuJX7c/*");
    }

    #[cfg(feature = "compiler")]
    #[test]
    fn test_parse_compile() {
        let cli_args = vec![
            "bdk-cli",
            "compile",
            "thresh(3,pk(Alice),pk(Bob),pk(Carol),older(2))",
            "--type",
            "sh-wsh",
        ];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Testnet,
            subcommand: CliSubCommand::Compile {
                policy: "thresh(3,pk(Alice),pk(Bob),pk(Carol),older(2))".to_string(),
                script_type: "sh-wsh".to_string(),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[cfg(feature = "compiler")]
    #[test]
    fn test_compile() {
        let result = handle_compile_subcommand(
            Network::Testnet,
            "thresh(3,pk(Alice),pk(Bob),pk(Carol),older(2))".to_string(),
            "sh-wsh".to_string(),
        )
        .unwrap();
        let result_obj = result.as_object().unwrap();

        let descriptor = result_obj.get("descriptor").unwrap().as_str().unwrap();
        assert_eq!(
            &descriptor,
            &"sh(wsh(thresh(3,pk(Alice),s:pk(Bob),s:pk(Carol),sdv:older(2))))#l4qaawgv"
        );
    }
}
