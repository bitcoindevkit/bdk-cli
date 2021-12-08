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
//!                 url: wallet_opts.electrum_opts.server,
//!                 socks5: wallet_opts.proxy_opts.proxy,
//!                 retry: wallet_opts.proxy_opts.retries,
//!                 timeout: None,
//!                 stop_gap: 10
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

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
#[macro_use]
extern crate bdk_macros;

use std::collections::BTreeMap;
use std::str::FromStr;

pub use structopt;
use structopt::StructOpt;

use crate::OfflineWalletSubCommand::*;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use crate::OnlineWalletSubCommand::*;
#[cfg(all(feature = "reserves", feature = "electrum"))]
use bdk::bitcoin::blockdata::transaction::TxOut;
use bdk::bitcoin::consensus::encode::{deserialize, serialize, serialize_hex};
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use bdk::bitcoin::hashes::hex::FromHex;
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, KeySource};
use bdk::bitcoin::util::psbt::PartiallySignedTransaction;
use bdk::bitcoin::{Address, Network, OutPoint, Script, Txid};
#[cfg(feature = "reserves")]
use bdk::blockchain::Capability;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use bdk::blockchain::{log_progress, Blockchain};
use bdk::database::BatchDatabase;
use bdk::descriptor::Segwitv0;
#[cfg(feature = "compiler")]
use bdk::descriptor::{Descriptor, Legacy, Miniscript};
#[cfg(all(feature = "reserves", feature = "electrum"))]
use bdk::electrum_client::{Client, ElectrumApi};
use bdk::keys::bip39::{Language, Mnemonic, WordCount};
use bdk::keys::DescriptorKey::Secret;
use bdk::keys::KeyError::{InvalidNetwork, Message};
use bdk::keys::{DerivableKey, DescriptorKey, ExtendedKey, GeneratableKey, GeneratedKey};
use bdk::miniscript::miniscript;
#[cfg(feature = "compiler")]
use bdk::miniscript::policy::Concrete;
use bdk::wallet::AddressIndex;
use bdk::Error;
use bdk::SignOptions;
use bdk::{FeeRate, KeychainKind, Wallet};
#[cfg(all(feature = "reserves", feature = "electrum"))]
use bdk_reserves::reserves::verify_proof;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
#[cfg(feature = "reserves")]
use bdk_reserves::reserves::ProofOfReserves;

/// Global options
///
/// The global options and top level sub-command required for all subsequent [`CliSubCommand`]'s.
///
/// # Example
///
/// ```
/// # #[cfg(any(feature = "electrum", feature = "esplora", feature = "compact_filters", feature = "rpc"))]
/// # {
/// # use bdk::bitcoin::Network;
/// # use structopt::StructOpt;
/// # use bdk_cli::{CliOpts, WalletOpts, CliSubCommand, WalletSubCommand};
/// # #[cfg(feature = "electrum")]
/// # use bdk_cli::ElectrumOpts;
/// # #[cfg(feature = "esplora")]
/// # use bdk_cli::EsploraOpts;
/// # #[cfg(feature = "rpc")]
/// # use bdk_cli::RpcOpts;
/// # #[cfg(feature = "compact_filters")]
/// # use bdk_cli::CompactFilterOpts;
/// # #[cfg(any(feature = "compact_filters", feature = "electrum", feature="esplora"))]
/// # use bdk_cli::ProxyOpts;
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
///                     verbose: false,
///                     descriptor: "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/44'/1'/0'/0/*)".to_string(),
///                     change_descriptor: None,
///               #[cfg(feature = "electrum")]
///               electrum_opts: ElectrumOpts {
///                   timeout: None,
///                   server: "ssl://electrum.blockstream.info:60002".to_string(),
///                   stop_gap: 10
///               },
///               #[cfg(feature = "esplora-ureq")]
///               esplora_opts: EsploraOpts {
///                   server: "https://blockstream.info/testnet/api/".to_string(),
///                   read_timeout: 5,
///                   write_timeout: 5,
///                   stop_gap: 10
///               },
///               #[cfg(feature = "esplora-reqwest")]
///               esplora_opts: EsploraOpts {
///                   server: "https://blockstream.info/testnet/api/".to_string(),
///                   conc: 4,
///                   stop_gap: 10
///               },
///                 #[cfg(feature = "rpc")]
///                 rpc_opts: RpcOpts{
///                    address: "127.0.0.1:18443".to_string(),
///                    auth: ("user".to_string(), "password".to_string()),
///                    skip_blocks: None,
///                },
///                #[cfg(feature = "compact_filters")]
///                compactfilter_opts: CompactFilterOpts{
///                    address: vec!["127.0.0.1:18444".to_string()],
///                    conn_count: 4,
///                    skip_blocks: 0,
///                },
///                #[cfg(any(feature="compact_filters", feature="electrum", feature="esplora"))]
///                    proxy_opts: ProxyOpts{
///                        proxy: None,
///                        proxy_auth: None,
///                        retries: 5,
///                    },
///                 },
///                 subcommand: WalletSubCommand::OnlineWalletSubCommand(Sync {
///                     max_addresses: Some(50)
///                 }),
///             },
///         };
///
/// assert_eq!(expected_cli_opts, cli_opts);
/// # }
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
    #[cfg(feature = "repl")]
    #[structopt(long_about = "REPL command loop mode")]
    Repl {
        #[structopt(flatten)]
        wallet_opts: WalletOpts,
    },
    /// Proof of reserves external sub-commands
    #[cfg(all(feature = "reserves", feature = "electrum"))]
    #[structopt(long_about = "Proof of reserves external verification")]
    ExternalReserves {
        /// Sets the challenge message with which the proof was produced
        #[structopt(name = "MESSAGE", required = true, index = 1)]
        message: String,
        /// Sets the proof in form of a PSBT to verify
        #[structopt(name = "PSBT", required = true, index = 2)]
        psbt: String,
        /// Sets the number of block confirmations for UTXOs to be considered.
        #[structopt(name = "CONFIRMATIONS", required = true, index = 3)]
        confirmations: usize,
        /// Sets the addresses for which the proof was produced
        #[structopt(name = "ADDRESSES", required = true, index = 4)]
        addresses: Vec<String>,
        #[structopt(flatten)]
        electrum_opts: ElectrumOpts,
    },
}

/// Wallet sub-commands
///
/// Can use either an online or offline wallet. An [`OnlineWalletSubCommand`] requires a blockchain
/// client and network connection and an [`OfflineWalletSubCommand`] does not.
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub enum WalletSubCommand {
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
/// # #[cfg(feature = "compact_filters")]
/// # use bdk_cli::CompactFilterOpts;
/// # #[cfg(feature = "rpc")]
/// # use bdk_cli::RpcOpts;
/// # #[cfg(any(feature = "compact_filters", feature = "electrum", feature="esplora"))]
/// # use bdk_cli::ProxyOpts;
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
///                     verbose: false,
///               descriptor: "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/44'/1'/0'/0/*)".to_string(),
///               change_descriptor: None,
///               #[cfg(feature = "electrum")]
///               electrum_opts: ElectrumOpts {
///                   timeout: None,
///                   server: "ssl://electrum.blockstream.info:60002".to_string(),
///                   stop_gap: 10
///               },
///               #[cfg(feature = "esplora-ureq")]
///               esplora_opts: EsploraOpts {
///                   server: "https://blockstream.info/testnet/api/".to_string(),
///                   read_timeout: 5,
///                   write_timeout: 5,
///                   stop_gap: 10
///               },
///               #[cfg(feature = "esplora-reqwest")]
///               esplora_opts: EsploraOpts {
///                   server: "https://blockstream.info/testnet/api/".to_string(),
///                   conc: 4,
///                   stop_gap: 10
///               },
///                #[cfg(feature = "compact_filters")]
///                compactfilter_opts: CompactFilterOpts{
///                    address: vec!["127.0.0.1:18444".to_string()],
///                    conn_count: 4,
///                    skip_blocks: 0,
///                },
///                 #[cfg(feature = "rpc")]
///                 rpc_opts: RpcOpts{
///                    address: "127.0.0.1:18443".to_string(),
///                    auth: ("user".to_string(), "password".to_string()),
///                    skip_blocks: None,
///                },
///               #[cfg(any(feature="compact_filters", feature="electrum", feature="esplora"))]
///                    proxy_opts: ProxyOpts{
///                        proxy: None,
///                        proxy_auth: None,
///                        retries: 5,
///               },
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
    /// Adds verbosity, returns PSBT in JSON format alongside serialized, displays expanded objects
    #[structopt(name = "VERBOSE", short = "v", long = "verbose")]
    pub verbose: bool,
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
    #[cfg(feature = "compact_filters")]
    #[structopt(flatten)]
    pub compactfilter_opts: CompactFilterOpts,
    #[cfg(feature = "rpc")]
    #[structopt(flatten)]
    pub rpc_opts: RpcOpts,
    #[cfg(any(feature = "compact_filters", feature = "electrum", feature = "esplora"))]
    #[structopt(flatten)]
    pub proxy_opts: ProxyOpts,
}

/// Proxy Server options
///
/// Only activated for `compact_filters` or `electrum`
#[cfg(any(feature = "compact_filters", feature = "electrum", feature = "esplora"))]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct ProxyOpts {
    /// Sets the SOCKS5 proxy for Blockchain backend
    #[structopt(name = "PROXY_ADDRS:PORT", long = "proxy", short = "p")]
    pub proxy: Option<String>,

    /// Sets the SOCKS5 proxy credential
    #[structopt(name="PROXY_USER:PASSWD", long="proxy_auth", short="a", parse(try_from_str = parse_proxy_auth))]
    pub proxy_auth: Option<(String, String)>,

    /// Sets the SOCKS5 proxy retries for the Electrum client
    #[structopt(
        name = "PROXY_RETRIES",
        short = "r",
        long = "retries",
        default_value = "5"
    )]
    pub retries: u8,
}

/// Compact Filter options
///
/// Compact filter peer information used by [`OnlineWalletSubCommand`]s.
#[cfg(feature = "compact_filters")]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct CompactFilterOpts {
    /// Sets the full node network address
    #[structopt(
        name = "ADDRESS:PORT",
        short = "n",
        long = "node",
        default_value = "127.0.0.1:18444"
    )]
    pub address: Vec<String>,

    /// Sets the number of parallel node connections
    #[structopt(name = "CONNECTIONS", long = "conn_count", default_value = "4")]
    pub conn_count: usize,

    /// Optionally skip initial `skip_blocks` blocks
    #[structopt(
        name = "SKIP_BLOCKS",
        short = "k",
        long = "skip_blocks",
        default_value = "0"
    )]
    pub skip_blocks: usize,
}

#[cfg(feature = "rpc")]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct RpcOpts {
    /// Sets the full node address for rpc connection
    #[structopt(
        name = "ADDRESS:PORT",
        short = "n",
        long = "node",
        default_value = "127.0.0.1:18443"
    )]
    pub address: String,

    /// Sets the rpc authentication username:password
    #[structopt(
        name = "USER:PASSWD",
        short = "a",
        long = "auth",
        parse(try_from_str = parse_proxy_auth),
        default_value = "user:password",
    )]
    pub auth: (String, String),

    /// Optionally skip initial `skip_blocks` blocks
    #[structopt(name = "SKIP_BLOCKS", short = "s", long = "skip-blocks")]
    pub skip_blocks: Option<u32>,
}

/// Electrum options
///
/// Electrum blockchain client information used by [`OnlineWalletSubCommand`]s.
#[cfg(feature = "electrum")]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct ElectrumOpts {
    /// Sets the SOCKS5 proxy timeout for the Electrum client
    #[structopt(name = "PROXY_TIMEOUT", short = "t", long = "timeout")]
    pub timeout: Option<u8>,
    /// Sets the Electrum server to use
    #[structopt(
        name = "ELECTRUM_URL",
        short = "s",
        long = "server",
        default_value = "ssl://electrum.blockstream.info:60002"
    )]
    pub server: String,

    /// Stop searching addresses for transactions after finding an unused gap of this length.
    #[structopt(
        name = "STOP_GAP",
        long = "stop_gap",
        short = "g",
        default_value = "10"
    )]
    pub stop_gap: usize,
}

/// Esplora options
///
/// Esplora blockchain client information used by [`OnlineWalletSubCommand`]s.
#[cfg(feature = "esplora-ureq")]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct EsploraOpts {
    /// Use the esplora server if given as parameter
    #[structopt(
        name = "ESPLORA_URL",
        short = "s",
        long = "server",
        default_value = "https://blockstream.info/testnet/api/"
    )]
    pub server: String,

    /// Socket read timeout
    #[structopt(name = "READ_TIMEOUT", long = "read_timeout", default_value = "5")]
    pub read_timeout: u64,

    /// Socket write timeout
    #[structopt(name = "WRITE_TIMEOUT", long = "write_timeout", default_value = "5")]
    pub write_timeout: u64,

    /// Stop searching addresses for transactions after finding an unused gap of this length.
    #[structopt(
        name = "STOP_GAP",
        long = "stop_gap",
        short = "g",
        default_value = "10"
    )]
    pub stop_gap: usize,
}

#[cfg(feature = "esplora-reqwest")]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct EsploraOpts {
    /// Use the esplora server if given as parameter
    #[structopt(
        name = "ESPLORA_URL",
        short = "s",
        long = "server",
        default_value = "https://blockstream.info/testnet/api/"
    )]
    pub server: String,

    /// Number of parallel requests sent to the esplora service (default: 4)
    #[structopt(name = "CONCURRENCY", long = "conc", default_value = "4")]
    pub conc: u8,

    /// Stop searching addresses for transactions after finding an unused gap of this length.
    #[structopt(
        name = "STOP_GAP",
        long = "stop_gap",
        short = "g",
        default_value = "10"
    )]
    pub stop_gap: usize,
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
        /// Allows the wallet to reduce the amount to the specified address in order to increase fees.
        #[structopt(name = "SHRINK_ADDRESS", short = "s", long = "shrink")]
        shrink_address: Option<Address>,
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
        /// Whether the signer should trust the witness_utxo, if the non_witness_utxo hasn’t been provided
        #[structopt(name = "WITNESS", long = "trust_witness_utxo")]
        trust_witness_utxo: Option<bool>,
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
        /// Whether the signer should trust the witness_utxo, if the non_witness_utxo hasn’t been provided
        #[structopt(name = "WITNESS", long = "trust_witness_utxo")]
        trust_witness_utxo: Option<bool>,
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
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
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
    /// Produce a proof of reserves
    #[cfg(feature = "reserves")]
    ProduceProof {
        /// Sets the message
        #[structopt(name = "MESSAGE", long = "message")]
        msg: String,
    },
    /// Verify a proof of reserves for our wallet
    #[cfg(feature = "reserves")]
    VerifyProof {
        /// Sets the PSBT to verify
        #[structopt(name = "BASE64_PSBT", long = "psbt")]
        psbt: String,
        /// Sets the message to verify
        #[structopt(name = "MESSAGE", long = "message")]
        msg: String,
        /// Sets the number of block confirmations for UTXOs to be considered. If nothing is specified, 6 is used.
        #[structopt(name = "CONFIRMATIONS", long = "confirmations", default_value = "6")]
        confirmations: u32,
    },
}

fn parse_recipient(s: &str) -> Result<(Script, u64), String> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid format".to_string());
    }

    let addr = Address::from_str(parts[0]);
    if let Err(e) = addr {
        return Err(format!("{:?}", e));
    }
    let val = u64::from_str(parts[1]);
    if let Err(e) = val {
        return Err(format!("{:?}", e));
    }

    Ok((addr.unwrap().script_pubkey(), val.unwrap()))
}
#[cfg(any(
    feature = "electrum",
    feature = "compact_filters",
    feature = "esplora",
    feature = "rpc"
))]
fn parse_proxy_auth(s: &str) -> Result<(String, String), String> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid format".to_string());
    }

    let user = parts[0].to_string();
    let passwd = parts[1].to_string();

    Ok((user, passwd))
}

fn parse_outpoint(s: &str) -> Result<OutPoint, String> {
    OutPoint::from_str(s).map_err(|e| format!("{:?}", e))
}

/// Execute an offline wallet sub-command
///
/// Offline wallet sub-commands are described in [`OfflineWalletSubCommand`].
pub fn handle_offline_wallet_subcommand<T, D>(
    wallet: &Wallet<T, D>,
    wallet_opts: &WalletOpts,
    offline_subcommand: OfflineWalletSubCommand,
) -> Result<serde_json::Value, Error>
where
    D: BatchDatabase,
{
    match offline_subcommand {
        GetNewAddress => Ok(json!({"address": wallet.get_address(AddressIndex::New)?.address})),
        ListUnspent => Ok(serde_json::to_value(&wallet.list_unspent()?)?),
        ListTransactions => Ok(serde_json::to_value(
            &wallet.list_transactions(wallet_opts.verbose)?,
        )?),
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
                tx_builder.drain_wallet().drain_to(recipients[0].0.clone());
            } else {
                tx_builder.set_recipients(recipients);
            }

            if enable_rbf {
                tx_builder.enable_rbf();
            }

            if offline_signer {
                tx_builder.include_output_redeem_witness_script();
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

            for (policy, keychain) in policies.into_iter().flatten() {
                let policy = serde_json::from_str::<BTreeMap<String, Vec<usize>>>(&policy)
                    .map_err(|s| Error::Generic(s.to_string()))?;
                tx_builder.policy_path(policy, keychain);
            }

            let (psbt, details) = tx_builder.finish()?;
            if wallet_opts.verbose {
                Ok(
                    json!({"psbt": base64::encode(&serialize(&psbt)),"details": details, "serialized_psbt": psbt}),
                )
            } else {
                Ok(json!({"psbt": base64::encode(&serialize(&psbt)),"details": details}))
            }
        }
        BumpFee {
            txid,
            shrink_address,
            offline_signer,
            utxos,
            unspendable,
            fee_rate,
        } => {
            let txid = Txid::from_str(txid.as_str()).map_err(|s| Error::Generic(s.to_string()))?;

            let mut tx_builder = wallet.build_fee_bump(txid)?;
            tx_builder.fee_rate(FeeRate::from_sat_per_vb(fee_rate));

            if let Some(address) = shrink_address {
                let script_pubkey = address.script_pubkey();
                tx_builder.allow_shrinking(script_pubkey)?;
            }

            if offline_signer {
                tx_builder.include_output_redeem_witness_script();
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
            trust_witness_utxo,
        } => {
            let psbt = base64::decode(&psbt)
                .map_err(|e| Error::Generic(format!("Base64 decode error: {:?}", e)))?;
            let mut psbt: PartiallySignedTransaction = deserialize(&psbt)?;
            let signopt = SignOptions {
                assume_height,
                trust_witness_utxo: trust_witness_utxo.unwrap_or(false),
                ..Default::default()
            };
            let finalized = wallet.sign(&mut psbt, signopt)?;
            if wallet_opts.verbose {
                Ok(
                    json!({"psbt": base64::encode(&serialize(&psbt)),"is_finalized": finalized, "serialized_psbt": psbt}),
                )
            } else {
                Ok(json!({"psbt": base64::encode(&serialize(&psbt)),"is_finalized": finalized,}))
            }
        }
        ExtractPsbt { psbt } => {
            let psbt = base64::decode(&psbt).unwrap();
            let psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();
            Ok(json!({"raw_tx": serialize_hex(&psbt.extract_tx()),}))
        }
        FinalizePsbt {
            psbt,
            assume_height,
            trust_witness_utxo,
        } => {
            let psbt = base64::decode(&psbt).unwrap();
            let mut psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();

            let signopt = SignOptions {
                assume_height,
                trust_witness_utxo: trust_witness_utxo.unwrap_or(false),
                ..Default::default()
            };
            let finalized = wallet.finalize_psbt(&mut psbt, signopt)?;
            if wallet_opts.verbose {
                Ok(
                    json!({ "psbt": base64::encode(&serialize(&psbt)),"is_finalized": finalized, "serialized_psbt": psbt}),
                )
            } else {
                Ok(json!({ "psbt": base64::encode(&serialize(&psbt)),"is_finalized": finalized,}))
            }
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
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
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

            let txid = maybe_await!(wallet.broadcast(&tx))?;
            Ok(json!({ "txid": txid }))
        }
        #[cfg(feature = "reserves")]
        ProduceProof { msg } => {
            let mut psbt = maybe_await!(wallet.create_proof(&msg))?;

            let _finalized = wallet.sign(
                &mut psbt,
                SignOptions {
                    trust_witness_utxo: true,
                    ..Default::default()
                },
            )?;

            let psbt_ser = serialize(&psbt);
            let psbt_b64 = base64::encode(&psbt_ser);

            Ok(json!({ "psbt": psbt , "psbt_base64" : psbt_b64}))
        }
        #[cfg(feature = "reserves")]
        VerifyProof {
            psbt,
            msg,
            confirmations,
        } => {
            let psbt = base64::decode(&psbt).unwrap();
            let psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();
            let current_height = wallet.client().get_height()?;
            let max_confirmation_height = if confirmations == 0 {
                None
            } else {
                if !wallet
                    .client()
                    .get_capabilities()
                    .contains(&Capability::GetAnyTx)
                {
                    return Err(Error::Generic(
                        "For validating a proof with a certain number of confirmations, we need a Blockchain with the GetAnyTx capability."
                        .to_string()
                    ));
                }
                Some(current_height - confirmations)
            };

            let spendable =
                maybe_await!(wallet.verify_proof(&psbt, &msg, max_confirmation_height))?;
            Ok(json!({ "spendable": spendable }))
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
        xprv: ExtendedPrivKey,
        /// Path to use to derive extended public key from extended private key
        #[structopt(name = "PATH", short = "p", long = "path")]
        path: DerivationPath,
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
                12 => WordCount::Words12,
                _ => WordCount::Words24,
            };
            let mnemonic: GeneratedKey<_, miniscript::BareCtx> =
                Mnemonic::generate((mnemonic_type, Language::English)).unwrap();
            //.map_err(|e| KeyError::from(e.unwrap()))?;
            let mnemonic = mnemonic.into_key();
            let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).unwrap();
            let fingerprint = xprv.fingerprint(&secp);
            let phrase = mnemonic
                .word_iter()
                .fold("".to_string(), |phrase, w| phrase + w + " ")
                .trim()
                .to_string();
            Ok(
                json!({ "mnemonic": phrase, "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }),
            )
        }
        KeySubCommand::Restore { mnemonic, password } => {
            let mnemonic = Mnemonic::parse(mnemonic).unwrap();
            //     .map_err(|e| {
            //     KeyError::from(e.downcast::<bdk::keys::bip39::ErrorKind>().unwrap())
            // })?;
            let xkey: ExtendedKey = (mnemonic, password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).unwrap();
            let fingerprint = xprv.fingerprint(&secp);

            Ok(json!({ "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }))
        }
        KeySubCommand::Derive { xprv, path } => {
            if xprv.network != network {
                return Err(Error::Key(InvalidNetwork));
            }
            let derived_xprv = &xprv.derive_priv(&secp, &path)?;

            let origin: KeySource = (xprv.fingerprint(&secp), path);

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

/// Proof of reserves verification sub-command
///
/// Proof of reserves options are described in [`CliSubCommand::ExternalReserves`].
#[cfg(all(feature = "reserves", feature = "electrum"))]
pub fn handle_ext_reserves_subcommand(
    network: Network,
    message: String,
    psbt: String,
    confirmations: usize,
    addresses: Vec<String>,
    electrum_opts: ElectrumOpts,
) -> Result<serde_json::Value, Error> {
    let psbt = base64::decode(&psbt)
        .map_err(|e| Error::Generic(format!("Base64 decode error: {:?}", e)))?;
    let psbt: PartiallySignedTransaction = deserialize(&psbt)?;
    let client = Client::new(&electrum_opts.server)?;

    let current_block_height = client.block_headers_subscribe().map(|data| data.height)?;
    let max_confirmation_height = Some(current_block_height - confirmations);

    let outpoints_per_addr = addresses
        .iter()
        .map(|address| {
            let address = Address::from_str(&address)
                .map_err(|e| Error::Generic(format!("Invalid address: {:?}", e)))?;
            get_outpoints_for_address(address, &client, max_confirmation_height)
        })
        .collect::<Result<Vec<Vec<_>>, Error>>()?;
    let outpoints_combined = outpoints_per_addr
        .iter()
        .fold(Vec::new(), |mut outpoints, outs| {
            outpoints.append(&mut outs.clone());
            outpoints
        });

    let spendable = verify_proof(&psbt, &message, outpoints_combined, network)
        .map_err(|e| Error::Generic(format!("{:?}", e)))?;

    Ok(json!({ "spendable": spendable }))
}

#[cfg(all(feature = "reserves", feature = "electrum"))]
pub fn get_outpoints_for_address(
    address: Address,
    client: &Client,
    max_confirmation_height: Option<usize>,
) -> Result<Vec<(OutPoint, TxOut)>, Error> {
    let unspents = client
        .script_list_unspent(&address.script_pubkey())
        .map_err(Error::Electrum)?;

    unspents
        .iter()
        .filter(|utxo| {
            utxo.height > 0 && utxo.height <= max_confirmation_height.unwrap_or(usize::MAX)
        })
        .map(|utxo| {
            let tx = match client.transaction_get(&utxo.tx_hash) {
                Ok(tx) => tx,
                Err(e) => {
                    return Err(e).map_err(Error::Electrum);
                }
            };

            Ok((
                OutPoint {
                    txid: utxo.tx_hash,
                    vout: utxo.tx_pos as u32,
                },
                tx.output[utxo.tx_pos].clone(),
            ))
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::{CliOpts, WalletOpts};
    #[cfg(feature = "compiler")]
    use crate::handle_compile_subcommand;
    #[cfg(feature = "compact_filters")]
    use crate::CompactFilterOpts;
    #[cfg(feature = "electrum")]
    use crate::ElectrumOpts;
    #[cfg(feature = "esplora")]
    use crate::EsploraOpts;
    use crate::OfflineWalletSubCommand::{BumpFee, CreateTx, GetNewAddress};
    #[cfg(all(feature = "reserves", feature = "compact_filters"))]
    use crate::OnlineWalletSubCommand::ProduceProof;
    #[cfg(all(feature = "reserves", feature = "esplora-ureq"))]
    use crate::OnlineWalletSubCommand::VerifyProof;
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "compact_filters",
        feature = "rpc"
    ))]
    use crate::OnlineWalletSubCommand::{Broadcast, Sync};
    #[cfg(any(feature = "compact_filters", feature = "electrum", feature = "esplora"))]
    use crate::ProxyOpts;
    #[cfg(feature = "rpc")]
    use crate::RpcOpts;
    #[cfg(all(feature = "reserves", feature = "electrum"))]
    use crate::{handle_ext_reserves_subcommand, handle_online_wallet_subcommand};
    use crate::{handle_key_subcommand, CliSubCommand, KeySubCommand, WalletSubCommand};
    use bdk::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
    #[cfg(all(feature = "reserves", feature = "electrum"))]
    use bdk::bitcoin::{consensus::Encodable, util::psbt::PartiallySignedTransaction};
    use bdk::bitcoin::{Address, Network, OutPoint};
    use bdk::miniscript::bitcoin::network::constants::Network::Testnet;
    #[cfg(all(feature = "reserves", feature = "electrum"))]
    use bdk::{
        blockchain::{noop_progress, ElectrumBlockchain},
        database::MemoryDatabase,
        electrum_client::Client,
        Wallet,
    };
    use std::str::{self, FromStr};
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
                    verbose: false,
                    descriptor: "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        timeout: None,
                        server: "ssl://electrum.blockstream.info:60002".to_string(),
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora-ureq")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        read_timeout: 5,
                        write_timeout: 5,
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora-reqwest")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        conc: 4,
                        stop_gap: 10,
                    },
                    #[cfg(feature = "compact_filters")]
                    compactfilter_opts: CompactFilterOpts{
                        address: vec!["127.0.0.1:18444".to_string()],
                        conn_count: 4,
                        skip_blocks: 0,
                    },
                    #[cfg(any(feature="compact_filters", feature="electrum", feature="esplora"))]
                    proxy_opts: ProxyOpts{
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    },
                    #[cfg(feature = "rpc")]
                    rpc_opts: RpcOpts {
                        address: "127.0.0.1:18443".to_string(),
                        auth: ("user".to_string(), "password".to_string()),
                        skip_blocks: None,
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
                            "--stop_gap", "20",
                            "get_new_address"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Testnet,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    verbose: false,
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    electrum_opts: ElectrumOpts {
                        timeout: Some(10),
                        server: "ssl://electrum.blockstream.info:50002".to_string(),
                        stop_gap: 20
                    },
                    proxy_opts: ProxyOpts{
                        proxy: Some("127.0.0.1:9150".to_string()),
                        proxy_auth: None,
                        retries: 3,
                    },
                    #[cfg(feature = "rpc")]
                    rpc_opts: RpcOpts {
                        address: "127.0.0.1:18443".to_string(),
                        auth: ("user".to_string(), "password".to_string()),
                        skip_blocks: None,
                    }
                },
                subcommand: WalletSubCommand::OfflineWalletSubCommand(GetNewAddress),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[cfg(feature = "esplora-ureq")]
    #[test]
    fn test_parse_wallet_esplora() {
        let cli_args = vec!["bdk-cli", "--network", "bitcoin", "wallet",
                            "--descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "--change_descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)",
                            "--server", "https://blockstream.info/api/",
                            "--read_timeout", "10",
                            "--write_timeout", "10",
                            "--stop_gap", "20",
                            "get_new_address"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    verbose: false,
                    descriptor: "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/api/".to_string(),
                        read_timeout: 10,
                        write_timeout: 10,
                        stop_gap: 20
                    },
                    proxy_opts: ProxyOpts{
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    }
                },
                subcommand: WalletSubCommand::OfflineWalletSubCommand(GetNewAddress),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[cfg(feature = "esplora-reqwest")]
    #[test]
    fn test_parse_wallet_esplora() {
        let cli_args = vec!["bdk-cli", "--network", "bitcoin", "wallet",
                            "--descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "--change_descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)",
                            "--server", "https://blockstream.info/api/",
                            "--conc", "10",
                            "--stop_gap", "20",
                            "get_new_address"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    verbose: false,
                    descriptor: "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/api/".to_string(),
                        conc: 10,
                        stop_gap: 20
                    },
                    proxy_opts: ProxyOpts{
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    }
                },
                subcommand: WalletSubCommand::OfflineWalletSubCommand(GetNewAddress),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[cfg(feature = "rpc")]
    #[test]
    fn test_parse_wallet_rpc() {
        let cli_args = vec!["bdk-cli", "--network", "bitcoin", "wallet",
                            "--descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "--change_descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)",
                            "--node", "125.67.89.101:56678",
                            "--auth", "user:password",
                            "--skip-blocks", "5",
                            "get_new_address"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    verbose: false,
                    descriptor: "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        timeout: None,
                        server: "ssl://electrum.blockstream.info:60002".to_string(),
                    },
                    #[cfg(feature = "esplora")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/api/".to_string(),
                        concurrency: 5,
                    },
                    #[cfg(feature = "compact_filters")]
                    compactfilter_opts: CompactFilterOpts{
                        address: vec!["127.0.0.1:18444".to_string()],
                        skip_blocks: 0,
                        conn_count: 4,
                    },
                    #[cfg(any(feature="compact_filters", feature="electrum"))]
                    proxy_opts: ProxyOpts{
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    },
                    #[cfg(feature = "rpc")]
                    rpc_opts: RpcOpts {
                        address: "125.67.89.101:56678".to_string(),
                        auth: ("user".to_string(), "password".to_string()),
                        skip_blocks: Some(5),
                    },
                },
                subcommand: WalletSubCommand::OfflineWalletSubCommand(GetNewAddress),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[cfg(feature = "compact_filters")]
    #[test]
    fn test_parse_wallet_compact_filters() {
        let cli_args = vec!["bdk-cli", "--network", "bitcoin", "wallet",
                            "--descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "--change_descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)",
                            "--proxy", "127.0.0.1:9005",
                            "--proxy_auth", "random_user:random_passwd",
                            "--node", "127.0.0.1:18444", "127.2.3.1:19695",
                            "--conn_count", "4",
                            "--skip_blocks", "5",
                            "get_new_address"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    verbose: false,
                    descriptor: "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    compactfilter_opts: CompactFilterOpts{
                        address: vec!["127.0.0.1:18444".to_string(), "127.2.3.1:19695".to_string()],
                        conn_count: 4,
                        skip_blocks: 5,
                    },
                    proxy_opts: ProxyOpts{
                        proxy: Some("127.0.0.1:9005".to_string()),
                        proxy_auth: Some(("random_user".to_string(), "random_passwd".to_string())),
                        retries: 5,
                    }
                },
                subcommand: WalletSubCommand::OfflineWalletSubCommand(GetNewAddress),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "compact_filters",
        feature = "rpc"
    ))]
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
                    verbose: false,
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: None,
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        timeout: None,
                        server: "ssl://electrum.blockstream.info:60002".to_string(),
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora-ureq")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        read_timeout: 5,
                        write_timeout: 5,
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora-reqwest")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        conc: 4,
                        stop_gap: 10,
                    },
                    #[cfg(feature = "compact_filters")]
                    compactfilter_opts: CompactFilterOpts{
                        address: vec!["127.0.0.1:18444".to_string()],
                        conn_count: 4,
                        skip_blocks: 0,
                    },
                    #[cfg(any(feature="compact_filters", feature="electrum", feature="esplora"))]
                    proxy_opts: ProxyOpts{
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    },
                    #[cfg(feature = "rpc")]
                    rpc_opts: RpcOpts {
                        address: "127.0.0.1:18443".to_string(),
                        auth: ("user".to_string(), "password".to_string()),
                        skip_blocks: None,
                    },
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
                    verbose: false,
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        timeout: None,
                        server: "ssl://electrum.blockstream.info:60002".to_string(),
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora-ureq")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        read_timeout: 5,
                        write_timeout: 5,
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora-reqwest")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        conc: 4,
                        stop_gap: 10,
                    },
                    #[cfg(feature = "compact_filters")]
                    compactfilter_opts: CompactFilterOpts{
                        address: vec!["127.0.0.1:18444".to_string()],
                        conn_count: 4,
                        skip_blocks: 0,
                    },
                    #[cfg(any(feature="compact_filters", feature="electrum", feature="esplora"))]
                    proxy_opts: ProxyOpts{
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    },
                    #[cfg(feature = "rpc")]
                    rpc_opts: RpcOpts {
                        address: "127.0.0.1:18443".to_string(),
                        auth: ("user".to_string(), "password".to_string()),
                        skip_blocks: None,
                    },
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
    fn test_parse_wallet_bump_fee() {
        let cli_args = vec!["bdk-cli", "--network", "testnet", "wallet",
                            "--descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "--change_descriptor", "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)",
                            "bump_fee", "--fee_rate", "6.1",
                            "--txid","35aab0d0213f8996f9e236a28630319b93109754819e8abf48a0835708d33506",
                            "--shrink","tb1ql7w62elx9ucw4pj5lgw4l028hmuw80sndtntxt"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Testnet,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    verbose: false,
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        timeout: None,
                        server: "ssl://electrum.blockstream.info:60002".to_string(),
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora-ureq")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        read_timeout: 5,
                        write_timeout: 5,
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora-reqwest")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        conc: 4,
                        stop_gap: 10,
                    },
                    #[cfg(feature = "compact_filters")]
                    compactfilter_opts: CompactFilterOpts{
                        address: vec!["127.0.0.1:18444".to_string()],
                        conn_count: 4,
                        skip_blocks: 0,
                    },
                    #[cfg(any(feature="compact_filters", feature="electrum", feature="esplora"))]
                    proxy_opts: ProxyOpts{
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    }
                },
                subcommand: WalletSubCommand::OfflineWalletSubCommand(BumpFee {
                    txid: "35aab0d0213f8996f9e236a28630319b93109754819e8abf48a0835708d33506".to_string(),
                    shrink_address: Some(Address::from_str("tb1ql7w62elx9ucw4pj5lgw4l028hmuw80sndtntxt").unwrap()),
                    offline_signer: false,
                    utxos: None,
                    unspendable: None,
                    fee_rate: 6.1
                }),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "compact_filters",
        feature = "rpc"
    ))]
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
                    verbose: false,
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: None,
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        timeout: None,
                        server: "ssl://electrum.blockstream.info:60002".to_string(),
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora-ureq")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        read_timeout: 5,
                        write_timeout: 5,
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora-reqwest")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        conc: 4,
                        stop_gap: 10,
                    },
                    #[cfg(feature = "compact_filters")]
                    compactfilter_opts: CompactFilterOpts{
                        address: vec!["127.0.0.1:18444".to_string()],
                        conn_count: 4,
                        skip_blocks: 0,
                    },
                    #[cfg(any(feature="compact_filters", feature="electrum", feature="esplora"))]
                    proxy_opts: ProxyOpts{
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    },
                    #[cfg(feature = "rpc")]
                    rpc_opts: RpcOpts {
                        address: "127.0.0.1:18443".to_string(),
                        auth: ("user".to_string(), "password".to_string()),
                        skip_blocks: None,
                    },
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
            xprv: ExtendedPrivKey::from_str("tprv8ZgxMBicQKsPfQjJy8ge2cvBfDjLxJSkvNLVQiw7BQ5gTjKadG2rrcQB5zjcdaaUTz5EDNJaS77q4DzjqjogQBfMsaXFFNP3UqoBnwt2kyT").unwrap(),
            path: DerivationPath::from_str("m/84'/1'/0'/0").unwrap(),
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

    #[cfg(all(feature = "reserves", feature = "compact_filters"))]
    #[test]
    fn test_parse_produce_proof() {
        let message = "Those coins belong to Satoshi Nakamoto";
        let cli_args = vec![
            "bdk-cli",
            "--network",
            "bitcoin",
            "wallet",
            "--descriptor",
            "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)",
            "produce_proof",
            "--message",
            message.clone(),
        ];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    verbose: false,
                    descriptor: "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)"
                        .to_string(),
                    change_descriptor: None,
                    compactfilter_opts: CompactFilterOpts {
                        address: vec!["127.0.0.1:18444".to_string()],
                        conn_count: 4,
                        skip_blocks: 0,
                    },
                    proxy_opts: ProxyOpts {
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    },
                },
                subcommand: WalletSubCommand::OnlineWalletSubCommand(ProduceProof {
                    msg: message.to_string(),
                }),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[cfg(all(feature = "reserves", feature = "esplora-ureq"))]
    #[test]
    fn test_parse_verify_proof_internal() {
        let psbt = r#"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"#;
        let message = "Those coins belong to Satoshi Nakamoto";
        let cli_args = vec![
            "bdk-cli",
            "--network",
            "bitcoin",
            "wallet",
            "--descriptor",
            "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)",
            "verify_proof",
            "--psbt",
            psbt.clone(),
            "--message",
            message.clone(),
        ];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    verbose: false,
                    descriptor: "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)"
                        .to_string(),
                    change_descriptor: None,
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        read_timeout: 5,
                        write_timeout: 5,
                        stop_gap: 10,
                    },
                    proxy_opts: ProxyOpts {
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    },
                },
                subcommand: WalletSubCommand::OnlineWalletSubCommand(VerifyProof {
                    psbt: psbt.to_string(),
                    msg: message.to_string(),
                    confirmations: 6,
                }),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[cfg(all(feature = "reserves", feature = "esplora-ureq"))]
    #[test]
    fn test_parse_verify_proof_internal_confirmation() {
        let psbt = r#"cHNidP8BAKcBAAAAA31Ko7U8mQMXxjrKhYvd5N06BrT2dBPwWVhZQYABZbdZAAAAAAD/////mAqA48Jx/UDORZswhCLAQiyCxhu4IZMXzWRUMx5PVIUAAAAAAP////+YCoDjwnH9QM5FmzCEIsBCLILGG7ghkxfNZFQzHk9UhQEAAAAA/////wHo7zMDAAAAABl2qRSff9CW037SwOP38M/JJL7vT/zraIisAAAAAAABAQoAAAAAAAAAAAFRAQMEAQAAAAEHAAABASAQJwAAAAAAABepFBCNSAfpaNUWLsnOLKCLqO4EAl4UhyICAyS3XurSwfnGDoretecAn+x6Ka/Nsw2CnYLQlWL+i66FRzBEAiA3wllP5sFLWtT5NOthk2OaD42fNATjDzBVL4dPsG538QIgC7r4Hs2qQrKzY/WJOl2Idx7KAEY+J5xniJfEB1D7TzsBIgIDdGj46pm2xkeIOYta0lSAytCPSw1lvlTOOlX9IGta5HJIMEUCIQDETYrRs/Lamq1zew92oa2zFUFBeaWADxcKXmMf8/pMgAIgeQCUTF6jvi5iD9LxD54YKD3STmWy/Y4WwtVebZJWeh4BIgID9y09lmY7DqmbCusNfyc8qxGo3jeIXx3dyNkRKtuHFpNHMEQCIEIkdGA0m2sxDlRArMN5cVflkK3OZt0thfgntyqv8PuoAiBjtkZejhZ2YgB/C3oiGjZM2L7QA+QoXc7Ma677P7+87wEBBCIAIHQQ4qnMe1dC7RoA6/AqOG53jareHaC0Fbqu6vBAL08NAQXxUyECL1M7Zn4uo7NuIZYcn+nco0D74K9SEBc6g64DN6sgpXYhAmu1OpjoEL0O5hoO0RZLpsAkeG12VU55PiAtxs6ceMTqIQLVuKfWakH/229MU9YZlAIuiGtPRQAfsVi5XJFk1F+MoyEDJLde6tLB+cYOit615wCf7Hopr82zDYKdgtCVYv6LroUhAy00+JMiAIM0h70pSqIZ3L4AC5+bPYJHmVQUMACfD6VRIQN0aPjqmbbGR4g5i1rSVIDK0I9LDWW+VM46Vf0ga1rkciED9y09lmY7DqmbCusNfyc8qxGo3jeIXx3dyNkRKtuHFpNXrgEHIyIAIHQQ4qnMe1dC7RoA6/AqOG53jareHaC0Fbqu6vBAL08NAQj9zQEFAEcwRAIgN8JZT+bBS1rU+TTrYZNjmg+NnzQE4w8wVS+HT7Bud/ECIAu6+B7NqkKys2P1iTpdiHceygBGPiecZ4iXxAdQ+087AUgwRQIhAMRNitGz8tqarXN7D3ahrbMVQUF5pYAPFwpeYx/z+kyAAiB5AJRMXqO+LmIP0vEPnhgoPdJOZbL9jhbC1V5tklZ6HgFHMEQCIEIkdGA0m2sxDlRArMN5cVflkK3OZt0thfgntyqv8PuoAiBjtkZejhZ2YgB/C3oiGjZM2L7QA+QoXc7Ma677P7+87wHxUyECL1M7Zn4uo7NuIZYcn+nco0D74K9SEBc6g64DN6sgpXYhAmu1OpjoEL0O5hoO0RZLpsAkeG12VU55PiAtxs6ceMTqIQLVuKfWakH/229MU9YZlAIuiGtPRQAfsVi5XJFk1F+MoyEDJLde6tLB+cYOit615wCf7Hopr82zDYKdgtCVYv6LroUhAy00+JMiAIM0h70pSqIZ3L4AC5+bPYJHmVQUMACfD6VRIQN0aPjqmbbGR4g5i1rSVIDK0I9LDWW+VM46Vf0ga1rkciED9y09lmY7DqmbCusNfyc8qxGo3jeIXx3dyNkRKtuHFpNXrgABASDYyDMDAAAAABepFBCNSAfpaNUWLsnOLKCLqO4EAl4UhyICAyS3XurSwfnGDoretecAn+x6Ka/Nsw2CnYLQlWL+i66FRzBEAiBER55YOumAJFkXvTrb1GSuXxYfenIqK+LRx7PPvoKGLQIgVp0yY/2YB63O2tzzjtEZpI+GVkHblhI/dWASuoKTUt4BIgIDdGj46pm2xkeIOYta0lSAytCPSw1lvlTOOlX9IGta5HJHMEQCIGjiLiZbmAJB6+x2D2K6FYWczwRx4XCKaBIsvvdyt1ouAiBTlhGF+7tXHXRWv4pWisXPlJ8oBvUN8c+CbdNxsfB8oQEiAgP3LT2WZjsOqZsK6w1/JzyrEajeN4hfHd3I2REq24cWk0gwRQIhAKxzC4IYfuSVMbIk1dkOgi+xCg/zEh7Drie9E1r0KKUPAiAEJM+oGgJw5CTKiLoO80uyWlHnNYXRt0bDLaM0OaoVtgEBBCIAIHQQ4qnMe1dC7RoA6/AqOG53jareHaC0Fbqu6vBAL08NAQXxUyECL1M7Zn4uo7NuIZYcn+nco0D74K9SEBc6g64DN6sgpXYhAmu1OpjoEL0O5hoO0RZLpsAkeG12VU55PiAtxs6ceMTqIQLVuKfWakH/229MU9YZlAIuiGtPRQAfsVi5XJFk1F+MoyEDJLde6tLB+cYOit615wCf7Hopr82zDYKdgtCVYv6LroUhAy00+JMiAIM0h70pSqIZ3L4AC5+bPYJHmVQUMACfD6VRIQN0aPjqmbbGR4g5i1rSVIDK0I9LDWW+VM46Vf0ga1rkciED9y09lmY7DqmbCusNfyc8qxGo3jeIXx3dyNkRKtuHFpNXrgEHIyIAIHQQ4qnMe1dC7RoA6/AqOG53jareHaC0Fbqu6vBAL08NAQj9zQEFAEcwRAIgREeeWDrpgCRZF70629Rkrl8WH3pyKivi0cezz76Chi0CIFadMmP9mAetztrc847RGaSPhlZB25YSP3VgErqCk1LeAUcwRAIgaOIuJluYAkHr7HYPYroVhZzPBHHhcIpoEiy+93K3Wi4CIFOWEYX7u1cddFa/ilaKxc+UnygG9Q3xz4Jt03Gx8HyhAUgwRQIhAKxzC4IYfuSVMbIk1dkOgi+xCg/zEh7Drie9E1r0KKUPAiAEJM+oGgJw5CTKiLoO80uyWlHnNYXRt0bDLaM0OaoVtgHxUyECL1M7Zn4uo7NuIZYcn+nco0D74K9SEBc6g64DN6sgpXYhAmu1OpjoEL0O5hoO0RZLpsAkeG12VU55PiAtxs6ceMTqIQLVuKfWakH/229MU9YZlAIuiGtPRQAfsVi5XJFk1F+MoyEDJLde6tLB+cYOit615wCf7Hopr82zDYKdgtCVYv6LroUhAy00+JMiAIM0h70pSqIZ3L4AC5+bPYJHmVQUMACfD6VRIQN0aPjqmbbGR4g5i1rSVIDK0I9LDWW+VM46Vf0ga1rkciED9y09lmY7DqmbCusNfyc8qxGo3jeIXx3dyNkRKtuHFpNXrgAA"#;
        let message = "Those coins belong to Satoshi Nakamoto";
        let cli_args = vec![
            "bdk-cli",
            "--network",
            "bitcoin",
            "wallet",
            "--descriptor",
            "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)",
            "verify_proof",
            "--psbt",
            psbt.clone(),
            "--message",
            message.clone(),
            "--confirmations",
            "0",
        ];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: "main".to_string(),
                    verbose: false,
                    descriptor: "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)"
                        .to_string(),
                    change_descriptor: None,
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        read_timeout: 5,
                        write_timeout: 5,
                        stop_gap: 10,
                    },
                    proxy_opts: ProxyOpts {
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    },
                },
                subcommand: WalletSubCommand::OnlineWalletSubCommand(VerifyProof {
                    psbt: psbt.to_string(),
                    msg: message.to_string(),
                    confirmations: 0,
                }),
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    #[cfg(all(feature = "reserves", feature = "electrum"))]
    #[test]
    fn test_parse_verify_proof_external() {
        let psbt = r#"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"#.to_string();
        let address = "tb1qanjjv4cs20dgv32vncrxw702l8g4qtn2m9wn7d".to_string();
        let message = "Those coins belong to Satoshi Nakamoto".to_string();
        let cli_args = vec![
            "bdk-cli",
            "--network",
            "bitcoin",
            "external_reserves",
            &message,
            &psbt,
            "6",
            &address,
            "--server",
            "ssl://electrum.blockstream.info:60002",
        ];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            subcommand: CliSubCommand::ExternalReserves {
                message,
                psbt,
                confirmations: 6,
                addresses: [address].to_vec(),
                electrum_opts: ElectrumOpts {
                    timeout: None,
                    server: "ssl://electrum.blockstream.info:60002".to_string(),
                    stop_gap: 10,
                },
            },
        };

        assert_eq!(expected_cli_opts, cli_opts);
    }

    /// Encodes a partially signed transaction as base64 and returns the  bytes of the resulting string.
    #[cfg(all(feature = "reserves", feature = "electrum"))]
    fn encode_psbt(psbt: PartiallySignedTransaction) -> Vec<u8> {
        let mut encoded = Vec::<u8>::new();
        psbt.consensus_encode(&mut encoded).unwrap();
        let base64_psbt = base64::encode(&encoded);

        base64_psbt.as_bytes().to_vec()
    }

    #[cfg(all(feature = "reserves", feature = "electrum"))]
    #[test]
    fn test_proof_of_reserves_wallet() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)".to_string();
        let message = "Those coins belong to Satoshi Nakamoto";

        let client = Client::new("ssl://electrum.blockstream.info:60002").unwrap();
        let wallet = Wallet::new(
            &descriptor,
            None,
            Network::Testnet,
            MemoryDatabase::default(),
            ElectrumBlockchain::from(client),
        )
        .unwrap();

        wallet.sync(noop_progress(), None).unwrap();
        let balance = wallet.get_balance().unwrap();

        let addr = wallet.get_address(bdk::wallet::AddressIndex::New).unwrap();
        assert_eq!(
            "tb1qanjjv4cs20dgv32vncrxw702l8g4qtn2m9wn7d",
            addr.to_string()
        );

        let cli_args = vec![
            "bdk-cli",
            "--network",
            "bitcoin",
            "wallet",
            "--descriptor",
            &descriptor,
            "produce_proof",
            "--message",
            message.clone(),
        ];
        let cli_opts = CliOpts::from_iter(&cli_args);

        let wallet_subcmd = match cli_opts.subcommand {
            CliSubCommand::Wallet {
                wallet_opts: _,
                subcommand: WalletSubCommand::OnlineWalletSubCommand(online_subcommand),
            } => online_subcommand,
            _ => panic!("unexpected subcommand"),
        };
        let result = handle_online_wallet_subcommand(&wallet, wallet_subcmd).unwrap();
        let psbt: PartiallySignedTransaction =
            serde_json::from_str(&result.as_object().unwrap().get("psbt").unwrap().to_string())
                .unwrap();
        let psbt = encode_psbt(psbt);
        let psbt = str::from_utf8(&psbt).unwrap();
        assert_eq!(format!("{}", psbt), "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");

        let psbt_b64 = &result
            .as_object()
            .unwrap()
            .get("psbt_base64")
            .unwrap()
            .to_string();
        assert_eq!(&format!("{}", psbt), psbt_b64.trim_matches('\"'));

        let cli_args = vec![
            "bdk-cli",
            "--network",
            "bitcoin",
            "wallet",
            "--descriptor",
            &descriptor,
            "verify_proof",
            "--psbt",
            psbt,
            "--message",
            message.clone(),
        ];
        let cli_opts = CliOpts::from_iter(&cli_args);

        let wallet_subcmd = match cli_opts.subcommand {
            CliSubCommand::Wallet {
                wallet_opts: _,
                subcommand: WalletSubCommand::OnlineWalletSubCommand(online_subcommand),
            } => online_subcommand,
            _ => panic!("unexpected subcommand"),
        };
        let result = handle_online_wallet_subcommand(&wallet, wallet_subcmd).unwrap();
        let spendable = result
            .as_object()
            .unwrap()
            .get("spendable")
            .unwrap()
            .as_u64()
            .unwrap();
        assert_eq!(spendable, balance);
    }

    #[cfg(all(feature = "reserves", feature = "electrum"))]
    #[test]
    fn test_proof_of_reserves_veryfy() {
        let message = "Those coins belong to Satoshi Nakamoto";
        let address = "tb1qanjjv4cs20dgv32vncrxw702l8g4qtn2m9wn7d";
        let psbt = "cHNidP8BAKcBAAAAA9A7AuVMuwIrkAuXtKDqw3BruovK2PH7E90MzCbyaAMlAAAAAAD/////sq+79fxJ+5F8951Xcbp8N5VYVJoesG1zd3AxStcGwPYAAAAAAP/////AUS4n/SkO9SSvIv8MI2Xdm3xdn77Sud6uX5PyqCganAEAAAAA/////wGwrQEAAAAAABl2qRSff9CW037SwOP38M/JJL7vT/zraIisAAAAAAABAQoAAAAAAAAAAAFRAQcAAAEBHxAnAAAAAAAAFgAU7OUmVxBT2oZFTJ4GZ3nq+dFQLmoiAgMrBVgHi+w4aUqEkz1lkwPiV12ufpFoWRFFQRW/1kSH40gwRQIhAPgByvkajQrNeQDSGik2gnxpo/P/owiEHR+0nWefkXurAiBgrAlDvwuTiaGEEWQW/Kd7L7u7YOQnqvrd46DR0A8yPgEBBwABCGwCSDBFAiEA+AHK+RqNCs15ANIaKTaCfGmj8/+jCIQdH7SdZ5+Re6sCIGCsCUO/C5OJoYQRZBb8p3svu7tg5Ceq+t3joNHQDzI+ASEDKwVYB4vsOGlKhJM9ZZMD4lddrn6RaFkRRUEVv9ZEh+MAAQEfoIYBAAAAAAAWABTs5SZXEFPahkVMngZneer50VAuaiICAysFWAeL7DhpSoSTPWWTA+JXXa5+kWhZEUVBFb/WRIfjRzBEAiBSfiX0qP7vR+2Qx/mRJS8pwma8nTfOWKerzo6c0iSAfwIgEfX4Wt7YXd8MkKUEY627GWYCmKfMsJGcIC0U1wgc1vUBAQcAAQhrAkcwRAIgUn4l9Kj+70ftkMf5kSUvKcJmvJ03zlinq86OnNIkgH8CIBH1+Fre2F3fDJClBGOtuxlmApinzLCRnCAtFNcIHNb1ASEDKwVYB4vsOGlKhJM9ZZMD4lddrn6RaFkRRUEVv9ZEh+MAAA==";

        let cli_args = vec![
            "bdk-cli",
            "--network",
            "bitcoin",
            "external_reserves",
            message,
            psbt,
            "6",
            address,
            address, // passing the address twice on purpose, to test passing of multiple addresses
            "--server",
            "ssl://electrum.blockstream.info:60002",
        ];
        let cli_opts = CliOpts::from_iter(&cli_args);

        let (message, psbt, confirmations, addresses, electrum_opts) = match cli_opts.subcommand {
            CliSubCommand::ExternalReserves {
                message,
                psbt,
                confirmations,
                addresses,
                electrum_opts,
            } => (message, psbt, confirmations, addresses, electrum_opts),
            _ => panic!("unexpected subcommand"),
        };
        let result = handle_ext_reserves_subcommand(
            Network::Bitcoin,
            message,
            psbt,
            confirmations,
            addresses,
            electrum_opts,
        )
        .unwrap();
        let spendable = result
            .as_object()
            .unwrap()
            .get("spendable")
            .unwrap()
            .as_u64()
            .unwrap();
        assert!(spendable > 0);
    }
}
