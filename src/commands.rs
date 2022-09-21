// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! bdk-cli Command structure
//!
//! This module defines all the bdk-cli commands structure.
//! All optional args are defined in the structs below.
//! All subcommands are defined in the below enums.

#![allow(clippy::large_enum_variant)]
use structopt::clap::AppSettings;

use structopt::StructOpt;

use bdk::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use bdk::bitcoin::{Address, Network, OutPoint, Script};

#[cfg(any(
    feature = "compact_filters",
    feature = "electrum",
    feature = "esplora",
    feature = "rpc"
))]
use crate::utils::parse_proxy_auth;
use crate::utils::{parse_outpoint, parse_recipient};

#[derive(PartialEq, Clone, Debug, StructOpt)]
/// The BDK Command Line Wallet App
///
/// bdk-cli is a light weight command line bitcoin wallet, powered by BDK.
/// This app can be used as a playground as well as testing environment to simulate
/// various wallet testing situations. If you are planning to use BDK in your wallet, bdk-cli
/// is also a great intro tool to get familiar with the BDK API.
///
/// But this is not just any toy.
/// bdk-cli is also a fully functioning Bitcoin wallet with taproot support!
///
/// For more information checkout <https://bitcoindevkit.org/>
#[structopt(version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"),
author = option_env ! ("CARGO_PKG_AUTHORS").unwrap_or(""))]
pub struct CliOpts {
    /// Sets the network.
    #[structopt(
        name = "NETWORK",
        short = "n",
        long = "network",
        default_value = "testnet",
        possible_values = &["bitcoin", "testnet", "signet", "regtest"]
    )]
    pub network: Network,
    /// Sets the wallet data directory.
    /// Default value : "~/.bdk-bitcoin
    #[structopt(name = "DATADIR", short = "d", long = "datadir")]
    pub datadir: Option<std::path::PathBuf>,
    /// Top level cli sub-commands.
    #[structopt(subcommand)]
    pub subcommand: CliSubCommand,
}

/// Top level cli sub-commands.
#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(rename_all = "snake")]
pub enum CliSubCommand {
    /// Node operation subcommands.
    ///
    /// These commands can be used to control the backend bitcoin-core node
    /// launched automatically with the `regtest-*` feature sets. The commands issue
    /// bitcoin-cli rpc calls on the daemon, in the background.
    ///
    /// Feel free to open a feature request issue in <https://github.com/bitcoindevkit/bdk-cli>
    /// if you need extra rpc calls not covered in the command list.
    #[cfg(feature = "regtest-node")]
    #[structopt(long_about = "Regtest Node mode")]
    Node {
        #[structopt(subcommand)]
        subcommand: NodeSubCommand,
    },
    /// Wallet operations.
    ///
    /// bdk-cli wallet operations includes all the basic wallet level tasks.
    /// Most commands can be used without connecting to any backend. To use commands that
    /// needs backend like `sync` and `broadcast`, compile the binary with specific backend feature
    /// and use the configuration options below to configure for that backend.
    Wallet {
        #[structopt(flatten)]
        wallet_opts: WalletOpts,
        #[structopt(subcommand)]
        subcommand: WalletSubCommand,
    },
    /// Key management operations.
    ///
    /// Provides basic key operations that are not related to a specific wallet such as generating a
    /// new random master extended key or restoring a master extended key from mnemonic words.
    ///
    /// These sub-commands are **EXPERIMENTAL** and should only be used for testing. Do not use this
    /// feature to create keys that secure actual funds on the Bitcoin mainnet.
    Key {
        #[structopt(subcommand)]
        subcommand: KeySubCommand,
    },
    /// Compile a miniscript policy to an output descriptor.
    #[cfg(feature = "compiler")]
    #[structopt(long_about = "Miniscript policy compiler")]
    Compile {
        /// Sets the spending policy to compile.
        #[structopt(name = "POLICY", required = true, index = 1)]
        policy: String,
        /// Sets the script type used to embed the compiled policy.
        #[structopt(name = "TYPE", short = "t", long = "type", default_value = "wsh", possible_values = &["sh","wsh", "sh-wsh"])]
        script_type: String,
    },
    #[cfg(feature = "repl")]
    /// REPL command loop mode.
    ///
    /// REPL command loop can be used to make recurring callbacks to an already loaded wallet.
    /// This mode is useful for hands on live testing of wallet operations.
    Repl {
        #[structopt(flatten)]
        wallet_opts: WalletOpts,
    },
    /// Proof of reserves operations.
    ///
    /// This can be used to produce and verify Proof of Reserves (similar to BIP 322) using bdk-cli.
    #[cfg(all(feature = "reserves", feature = "electrum"))]
    ExternalReserves {
        /// Sets the challenge message with which the proof was produced.
        #[structopt(name = "MESSAGE", required = true, index = 1)]
        message: String,
        /// Sets the proof in form of a PSBT to verify.
        #[structopt(name = "PSBT", required = true, index = 2)]
        psbt: String,
        /// Sets the number of block confirmations for UTXOs to be considered.
        #[structopt(name = "CONFIRMATIONS", required = true, index = 3)]
        confirmations: usize,
        /// Sets the addresses for which the proof was produced.
        #[structopt(name = "ADDRESSES", required = true, index = 4)]
        addresses: Vec<String>,
        #[structopt(flatten)]
        electrum_opts: ElectrumOpts,
    },
}

/// Backend Node operation subcommands.
#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(rename_all = "lower")]
#[cfg(any(feature = "regtest-node"))]
pub enum NodeSubCommand {
    /// Get info.
    GetInfo,
    /// Get new address from node's test wallet.
    GetNewAddress,
    /// Generate given number of blocks and fund the internal wallet with coinbases.
    Generate { block_num: u64 },
    /// Get Wallet balance.
    GetBalance,
    /// Send to an external wallet address.
    SendToAddress { address: String, amount: u64 },
    /// Execute any bitcoin-cli commands.
    #[structopt(external_subcommand)]
    BitcoinCli(Vec<String>),
}

/// Wallet operation subcommands.
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

/// Config options wallet operations can take.
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct WalletOpts {
    /// Selects the wallet to use.
    #[structopt(name = "WALLET_NAME", short = "w", long = "wallet")]
    pub wallet: Option<String>,
    /// Adds verbosity, returns PSBT in JSON format alongside serialized, displays expanded objects.
    #[structopt(name = "VERBOSE", short = "v", long = "verbose")]
    pub verbose: bool,
    /// Sets the descriptor to use for the external addresses.
    #[structopt(name = "DESCRIPTOR", short = "d", long = "descriptor", required = true)]
    pub descriptor: String,
    /// Sets the descriptor to use for internal addresses.
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

/// Options to configure a SOCKS5 proxy for a blockchain client connection.
#[cfg(any(feature = "compact_filters", feature = "electrum", feature = "esplora"))]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct ProxyOpts {
    /// Sets the SOCKS5 proxy for a blockchain client.
    #[structopt(name = "PROXY_ADDRS:PORT", long = "proxy", short = "p")]
    pub proxy: Option<String>,

    /// Sets the SOCKS5 proxy credential.
    #[structopt(name="PROXY_USER:PASSWD", long="proxy_auth", short="a", parse(try_from_str = parse_proxy_auth))]
    pub proxy_auth: Option<(String, String)>,

    /// Sets the SOCKS5 proxy retries for the blockchain client.
    #[structopt(
        name = "PROXY_RETRIES",
        short = "r",
        long = "retries",
        default_value = "5"
    )]
    pub retries: u8,
}

/// Options to configure a BIP157 Compact Filter backend.
#[cfg(feature = "compact_filters")]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct CompactFilterOpts {
    /// Sets the full node network address.
    #[structopt(
        name = "ADDRESS:PORT",
        short = "n",
        long = "node",
        default_value = "127.0.0.1:18444"
    )]
    pub address: Vec<String>,

    /// Sets the number of parallel node connections.
    #[structopt(name = "CONNECTIONS", long = "conn_count", default_value = "4")]
    pub conn_count: usize,

    /// Optionally skip initial `skip_blocks` blocks.
    #[structopt(
        name = "SKIP_BLOCKS",
        short = "k",
        long = "skip_blocks",
        default_value = "0"
    )]
    pub skip_blocks: usize,
}

/// Options to configure a bitcoin core rpc backend.
#[cfg(feature = "rpc")]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct RpcOpts {
    /// Sets the full node address for rpc connection.
    #[structopt(
        name = "ADDRESS:PORT",
        short = "n",
        long = "node",
        default_value = "127.0.0.1:18443"
    )]
    pub address: String,

    /// Sets the rpc basic authentication.
    #[structopt(
        name = "USER:PASSWD",
        short = "a",
        long = "basic-auth",
        parse(try_from_str = parse_proxy_auth),
        default_value = "user:password",
    )]
    pub basic_auth: (String, String),

    /// Sets an optional cookie authentication.
    #[structopt(name = "COOKIE", long = "cookie")]
    pub cookie: Option<String>,

    /// Time in unix seconds in which initial sync will start scanning from (0 to start from genesis).
    #[structopt(
        name = "RPC_START_TIME",
        short = "s",
        long = "start-time",
        default_value = "0"
    )]
    pub start_time: u64,
}

/// Options to configure electrum backend.
#[cfg(feature = "electrum")]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct ElectrumOpts {
    /// Sets the SOCKS5 proxy timeout for the Electrum client.
    #[structopt(name = "PROXY_TIMEOUT", short = "t", long = "timeout")]
    pub timeout: Option<u8>,
    /// Sets the Electrum server to use.
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

/// Options to configure Esplora backend.
#[cfg(feature = "esplora")]
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub struct EsploraOpts {
    /// Use the esplora server if given as parameter.
    #[structopt(
        name = "ESPLORA_URL",
        short = "s",
        long = "server",
        default_value = "https://blockstream.info/testnet/api/"
    )]
    pub server: String,

    /// Socket timeout.
    #[structopt(name = "TIMEOUT", long = "timeout", default_value = "5")]
    pub timeout: u64,

    /// Stop searching addresses for transactions after finding an unused gap of this length.
    #[structopt(
        name = "STOP_GAP",
        long = "stop_gap",
        short = "g",
        default_value = "10"
    )]
    pub stop_gap: usize,

    /// Number of parallel requests sent to the esplora service.
    #[structopt(name = "CONCURRENCY", long = "conc", default_value = "4")]
    pub conc: u8,
}

/// Wallet subcommands that can be issued without a blockchain backend.
#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(rename_all = "snake")]
pub enum OfflineWalletSubCommand {
    /// Generates a new external address.
    GetNewAddress,
    /// Lists the available spendable UTXOs.
    ListUnspent,
    /// Lists all the incoming and outgoing transactions of the wallet.
    ListTransactions,
    /// Returns the current wallet balance.
    GetBalance,
    /// Creates a new unsigned transaction.
    CreateTx {
        /// Adds a recipient to the transaction.
        #[structopt(name = "ADDRESS:SAT", long = "to", required = true, parse(try_from_str = parse_recipient))]
        recipients: Vec<(Script, u64)>,
        /// Sends all the funds (or all the selected utxos). Requires only one recipient with value 0.
        #[structopt(short = "all", long = "send_all")]
        send_all: bool,
        /// Enables Replace-By-Fee (BIP125).
        #[structopt(short = "rbf", long = "enable_rbf")]
        enable_rbf: bool,
        /// Make a PSBT that can be signed by offline signers and hardware wallets. Forces the addition of `non_witness_utxo` and more details to let the signer identify the change output.
        #[structopt(long = "offline_signer")]
        offline_signer: bool,
        /// Selects which utxos *must* be spent.
        #[structopt(name = "MUST_SPEND_TXID:VOUT", long = "utxos", parse(try_from_str = parse_outpoint))]
        utxos: Option<Vec<OutPoint>>,
        /// Marks a utxo as unspendable.
        #[structopt(name = "CANT_SPEND_TXID:VOUT", long = "unspendable", parse(try_from_str = parse_outpoint))]
        unspendable: Option<Vec<OutPoint>>,
        /// Fee rate to use in sat/vbyte.
        #[structopt(name = "SATS_VBYTE", short = "fee", long = "fee_rate")]
        fee_rate: Option<f32>,
        /// Selects which policy should be used to satisfy the external descriptor.
        #[structopt(name = "EXT_POLICY", long = "external_policy")]
        external_policy: Option<String>,
        /// Selects which policy should be used to satisfy the internal descriptor.
        #[structopt(name = "INT_POLICY", long = "internal_policy")]
        internal_policy: Option<String>,
        /// Optionally create an OP_RETURN output containing given String in utf8 encoding (max 80 bytes)
        #[structopt(
            name = "ADD_STRING",
            long = "add_string",
            short = "s",
            conflicts_with = "ADD_DATA"
        )]
        add_string: Option<String>,
        /// Optionally create an OP_RETURN output containing given base64 encoded String. (max 80 bytes)
        #[structopt(
            name = "ADD_DATA",
            long = "add_data",
            short = "o",
            conflicts_with = "ADD_STRING"
        )]
        add_data: Option<String>, //base 64 econding
    },
    /// Bumps the fees of an RBF transaction.
    BumpFee {
        /// TXID of the transaction to update.
        #[structopt(name = "TXID", short = "txid", long = "txid")]
        txid: String,
        /// Allows the wallet to reduce the amount to the specified address in order to increase fees.
        #[structopt(name = "SHRINK_ADDRESS", short = "s", long = "shrink")]
        shrink_address: Option<Address>,
        /// Make a PSBT that can be signed by offline signers and hardware wallets. Forces the addition of `non_witness_utxo` and more details to let the signer identify the change output.
        #[structopt(long = "offline_signer")]
        offline_signer: bool,
        /// Selects which utxos *must* be added to the tx. Unconfirmed utxos cannot be used.
        #[structopt(name = "MUST_SPEND_TXID:VOUT", long = "utxos", parse(try_from_str = parse_outpoint))]
        utxos: Option<Vec<OutPoint>>,
        /// Marks an utxo as unspendable, in case more inputs are needed to cover the extra fees.
        #[structopt(name = "CANT_SPEND_TXID:VOUT", long = "unspendable", parse(try_from_str = parse_outpoint))]
        unspendable: Option<Vec<OutPoint>>,
        /// The new targeted fee rate in sat/vbyte.
        #[structopt(name = "SATS_VBYTE", short = "fee", long = "fee_rate")]
        fee_rate: f32,
    },
    /// Returns the available spending policies for the descriptor.
    Policies,
    /// Returns the public version of the wallet's descriptor(s).
    PublicDescriptor,
    /// Signs and tries to finalize a PSBT.
    Sign {
        /// Sets the PSBT to sign.
        #[structopt(name = "BASE64_PSBT", long = "psbt")]
        psbt: String,
        /// Assume the blockchain has reached a specific height. This affects the transaction finalization, if there are timelocks in the descriptor.
        #[structopt(name = "HEIGHT", long = "assume_height")]
        assume_height: Option<u32>,
        /// Whether the signer should trust the witness_utxo, if the non_witness_utxo hasn’t been provided.
        #[structopt(name = "WITNESS", long = "trust_witness_utxo")]
        trust_witness_utxo: Option<bool>,
    },
    /// Extracts a raw transaction from a PSBT.
    ExtractPsbt {
        /// Sets the PSBT to extract
        #[structopt(name = "BASE64_PSBT", long = "psbt")]
        psbt: String,
    },
    /// Finalizes a PSBT.
    FinalizePsbt {
        /// Sets the PSBT to finalize.
        #[structopt(name = "BASE64_PSBT", long = "psbt")]
        psbt: String,
        /// Assume the blockchain has reached a specific height.
        #[structopt(name = "HEIGHT", long = "assume_height")]
        assume_height: Option<u32>,
        /// Whether the signer should trust the witness_utxo, if the non_witness_utxo hasn’t been provided.
        #[structopt(name = "WITNESS", long = "trust_witness_utxo")]
        trust_witness_utxo: Option<bool>,
    },
    /// Combines multiple PSBTs into one.
    CombinePsbt {
        /// Add one PSBT to combine. This option can be repeated multiple times, one for each PSBT.
        #[structopt(name = "BASE64_PSBT", long = "psbt", required = true)]
        psbt: Vec<String>,
    },
}

/// Wallet subcommands that needs a blockchain backend.
#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(rename_all = "snake")]
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
pub enum OnlineWalletSubCommand {
    /// Syncs with the chosen blockchain server.
    Sync,
    /// Broadcasts a transaction to the network. Takes either a raw transaction or a PSBT to extract.
    Broadcast {
        /// Sets the PSBT to sign.
        #[structopt(
            name = "BASE64_PSBT",
            long = "psbt",
            required_unless = "RAWTX",
            conflicts_with = "RAWTX"
        )]
        psbt: Option<String>,
        /// Sets the raw transaction to broadcast.
        #[structopt(
            name = "RAWTX",
            long = "tx",
            required_unless = "BASE64_PSBT",
            conflicts_with = "BASE64_PSBT"
        )]
        tx: Option<String>,
    },
    /// Produce a proof of reserves.
    #[cfg(feature = "reserves")]
    ProduceProof {
        /// Sets the message.
        #[structopt(name = "MESSAGE", long = "message")]
        msg: String,
    },
    /// Verify a proof of reserves for our wallet.
    #[cfg(feature = "reserves")]
    VerifyProof {
        /// Sets the PSBT to verify.
        #[structopt(name = "BASE64_PSBT", long = "psbt")]
        psbt: String,
        /// Sets the message to verify.
        #[structopt(name = "MESSAGE", long = "message")]
        msg: String,
        /// Sets the number of block confirmations for UTXOs to be considered.
        #[structopt(name = "CONFIRMATIONS", long = "confirmations", default_value = "6")]
        confirmations: u32,
    },
}

/// Subcommands for Key operations.
#[derive(Debug, StructOpt, Clone, PartialEq)]
pub enum KeySubCommand {
    /// Generates new random seed mnemonic phrase and corresponding master extended key.
    Generate {
        /// Entropy level based on number of random seed mnemonic words.
        #[structopt(
        name = "WORD_COUNT",
        short = "e",
        long = "entropy",
        default_value = "24",
        possible_values = &["12","24"],
        )]
        word_count: usize,
        /// Seed password.
        #[structopt(name = "PASSWORD", short = "p", long = "password")]
        password: Option<String>,
    },
    /// Restore a master extended key from seed backup mnemonic words.
    Restore {
        /// Seed mnemonic words, must be quoted (eg. "word1 word2 ...").
        #[structopt(name = "MNEMONIC", short = "m", long = "mnemonic")]
        mnemonic: String,
        /// Seed password.
        #[structopt(name = "PASSWORD", short = "p", long = "password")]
        password: Option<String>,
    },
    /// Derive a child key pair from a master extended key and a derivation path string (eg. "m/84'/1'/0'/0" or "m/84h/1h/0h/0").
    Derive {
        /// Extended private key to derive from.
        #[structopt(name = "XPRV", short = "x", long = "xprv")]
        xprv: ExtendedPrivKey,
        /// Path to use to derive extended public key from extended private key.
        #[structopt(name = "PATH", short = "p", long = "path")]
        path: DerivationPath,
    },
}

/// Subcommands available in REPL mode.
#[cfg(feature = "repl")]
#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(global_settings =&[AppSettings::NoBinaryName], rename_all = "lower")]
pub enum ReplSubCommand {
    /// Execute wallet commands.
    Wallet {
        #[structopt(subcommand)]
        subcommand: WalletSubCommand,
    },
    /// Execute key commands.
    Key {
        #[structopt(subcommand)]
        subcommand: KeySubCommand,
    },
    /// Execute node commands.
    #[cfg(feature = "regtest-node")]
    Node {
        #[structopt(subcommand)]
        subcommand: NodeSubCommand,
    },
    /// Exit REPL loop.
    Exit,
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "compiler")]
    use crate::handlers::handle_compile_subcommand;
    use crate::handlers::handle_key_subcommand;
    #[cfg(all(feature = "reserves", feature = "electrum"))]
    use crate::handlers::{handle_ext_reserves_subcommand, handle_online_wallet_subcommand};
    use bdk::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
    #[cfg(all(feature = "reserves", feature = "electrum"))]
    use bdk::bitcoin::{consensus::Encodable, util::psbt::PartiallySignedTransaction};
    use bdk::bitcoin::{Address, Network, OutPoint};
    use bdk::miniscript::bitcoin::network::constants::Network::Testnet;
    #[cfg(all(feature = "reserves", feature = "electrum"))]
    use bdk::{
        blockchain::ElectrumBlockchain, database::MemoryDatabase, electrum_client::Client,
        SyncOptions, Wallet,
    };
    use std::str::{self, FromStr};
    use structopt::StructOpt;

    use super::OfflineWalletSubCommand::{BumpFee, CreateTx, GetNewAddress};
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "compact_filters",
        feature = "rpc"
    ))]
    use super::OnlineWalletSubCommand::{Broadcast, Sync};
    use super::WalletSubCommand::OfflineWalletSubCommand;
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "compact_filters",
        feature = "rpc"
    ))]
    use super::WalletSubCommand::OnlineWalletSubCommand;
    #[cfg(feature = "repl")]
    use regex::Regex;

    #[test]
    fn test_parse_wallet_get_new_address() {
        let cli_args = vec!["bdk-cli", "--network", "bitcoin", "wallet",
                            "--descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)",
                            "--change_descriptor", "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)",
                            "get_new_address"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            datadir: None,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: None,
                    verbose: false,
                    descriptor: "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        timeout: None,
                        server: "ssl://electrum.blockstream.info:60002".to_string(),
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        timeout: 5,
                        stop_gap: 10,
                        conc: 4,
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
                        basic_auth: ("user".to_string(), "password".to_string()),
                        cookie: None,
                        start_time: 0,
                    },
                },
                subcommand: OfflineWalletSubCommand(GetNewAddress),
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
            datadir: None,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: None,
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
                },
                subcommand: OfflineWalletSubCommand(GetNewAddress),
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
                            "--timeout", "10",
                            "--stop_gap", "20",
                            "get_new_address"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            datadir: None,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: None,
                    verbose: false,
                    descriptor: "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/api/".to_string(),
                        timeout: 10,
                        stop_gap: 20,
                        conc: 4,
                    },
                    proxy_opts: ProxyOpts{
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    }
                },
                subcommand: OfflineWalletSubCommand(GetNewAddress),
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
            datadir: None,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: None,
                    verbose: false,
                    descriptor: "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/api/".to_string(),
                        conc: 10,
                        stop_gap: 20,
                        timeout: 5,
                    },
                    proxy_opts: ProxyOpts{
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    }
                },
                subcommand: OfflineWalletSubCommand(GetNewAddress),
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
                            "--basic-auth", "user:password",
                            "--cookie", "/home/user/.bitcoin/regtest/.cookie",
                            "--start-time", "123456",
                            "get_new_address"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            datadir: None,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: None,
                    verbose: false,
                    descriptor: "wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(xpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    rpc_opts: RpcOpts {
                        address: "125.67.89.101:56678".to_string(),
                        basic_auth: ("user".to_string(), "password".to_string()),
                        cookie: Some("/home/user/.bitcoin/regtest/.cookie".to_string()),
                        start_time: 123456,
                    },
                },
                subcommand: OfflineWalletSubCommand(GetNewAddress),
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
            datadir: None,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: None,
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
                subcommand: OfflineWalletSubCommand(GetNewAddress),
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
                            "sync"];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Testnet,
            datadir: None,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: None,
                    verbose: false,
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: None,
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        timeout: None,
                        server: "ssl://electrum.blockstream.info:60002".to_string(),
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        timeout: 5,
                        stop_gap: 10,
                        conc: 4,
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
                        basic_auth: ("user".to_string(), "password".to_string()),
                        cookie: None,
                        start_time: 0,
                    },
                },
                subcommand: OnlineWalletSubCommand(Sync),
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
                            "--utxos","87345e46bfd702d24d54890cc094d08a005f773b27c8f965dfe0eb1e23eef88e:2",
                            "--add_string","Hello BDK",
                           ];

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
            datadir: None,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: None,
                    verbose: false,
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        timeout: None,
                        server: "ssl://electrum.blockstream.info:60002".to_string(),
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        timeout: 5,
                        stop_gap: 10,
                        conc: 4,
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
                        basic_auth: ("user".to_string(), "password".to_string()),
                        cookie: None,
                        start_time: 0,
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
                    add_data: None,
                    add_string: Some("Hello BDK".to_string()),
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
            datadir: None,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: None,
                    verbose: false,
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: Some("wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/1/*)".to_string()),
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        timeout: None,
                        server: "ssl://electrum.blockstream.info:60002".to_string(),
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        timeout: 5,
                        stop_gap: 10,
                        conc: 4,
                    },
                    #[cfg(feature = "compact_filters")]
                    compactfilter_opts: CompactFilterOpts{
                        address: vec!["127.0.0.1:18444".to_string()],
                        conn_count: 4,
                        skip_blocks: 0,
                    },
                    #[cfg(feature = "rpc")]
                    rpc_opts: RpcOpts {
                        address: "127.0.0.1:18443".to_string(),
                        basic_auth: ("user".to_string(), "password".to_string()),
                        cookie: None,
                        start_time: 0,
                    },
                    #[cfg(any(feature="compact_filters", feature="electrum", feature="esplora"))]
                    proxy_opts: ProxyOpts{
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    }
                },
                subcommand: OfflineWalletSubCommand(BumpFee {
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
            datadir: None,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: None,
                    verbose: false,
                    descriptor: "wpkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)".to_string(),
                    change_descriptor: None,
                    #[cfg(feature = "electrum")]
                    electrum_opts: ElectrumOpts {
                        timeout: None,
                        server: "ssl://electrum.blockstream.info:60002".to_string(),
                        stop_gap: 10,
                    },
                    #[cfg(feature = "esplora")]
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        timeout: 5,
                        stop_gap: 10,
                        conc: 4,
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
                        basic_auth: ("user".to_string(), "password".to_string()),
                        cookie: None,
                        start_time: 0,
                    },
                },
                subcommand: OnlineWalletSubCommand(Broadcast {
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
                            "sync"];

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
            datadir: None,
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
            &"sh(wsh(thresh(3,pk(Alice),s:pk(Bob),s:pk(Carol),snl:older(2))))#rmef3s78"
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
                    wallet: None,
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
                subcommand: OnlineWalletSubCommand(ProduceProof {
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
                    wallet: None,
                    verbose: false,
                    descriptor: "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)"
                        .to_string(),
                    change_descriptor: None,
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        timeout: 5,
                        stop_gap: 10,
                        conc: 4,
                    },
                    proxy_opts: ProxyOpts {
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    },
                },
                subcommand: OnlineWalletSubCommand(VerifyProof {
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
            "--confirmations",
            "0",
        ];

        let cli_opts = CliOpts::from_iter(&cli_args);

        let expected_cli_opts = CliOpts {
            network: Network::Bitcoin,
            subcommand: CliSubCommand::Wallet {
                wallet_opts: WalletOpts {
                    wallet: None,
                    verbose: false,
                    descriptor: "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)"
                        .to_string(),
                    change_descriptor: None,
                    esplora_opts: EsploraOpts {
                        server: "https://blockstream.info/testnet/api/".to_string(),
                        timeout: 5,
                        stop_gap: 10,
                        conc: 4,
                    },
                    proxy_opts: ProxyOpts {
                        proxy: None,
                        proxy_auth: None,
                        retries: 5,
                    },
                },
                subcommand: OnlineWalletSubCommand(VerifyProof {
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
            datadir: None,
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
        let base64_psbt = bdk::bitcoin::base64::encode(&encoded);

        base64_psbt.as_bytes().to_vec()
    }

    #[cfg(all(feature = "reserves", feature = "electrum"))]
    #[test]
    fn test_proof_of_reserves_wallet() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)".to_string();
        let message = "Those coins belong to Satoshi Nakamoto";

        let client = Client::new("ssl://electrum.blockstream.info:60002").unwrap();
        let blockchain = ElectrumBlockchain::from(client);
        let wallet = Wallet::new(
            &descriptor,
            None,
            Network::Testnet,
            MemoryDatabase::default(),
        )
        .unwrap();

        wallet.sync(&blockchain, SyncOptions::default()).unwrap();
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
                subcommand: OnlineWalletSubCommand(online_subcommand),
            } => online_subcommand,
            _ => panic!("unexpected subcommand"),
        };
        let result = handle_online_wallet_subcommand(&wallet, &blockchain, wallet_subcmd).unwrap();
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
                subcommand: OnlineWalletSubCommand(online_subcommand),
            } => online_subcommand,
            _ => panic!("unexpected subcommand"),
        };
        let result = handle_online_wallet_subcommand(&wallet, &blockchain, wallet_subcmd).unwrap();
        let spendable = result
            .as_object()
            .unwrap()
            .get("spendable")
            .unwrap()
            .as_u64()
            .unwrap();
        assert_eq!(spendable, balance.get_spendable());
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

    #[cfg(feature = "repl")]
    #[test]
    fn test_regex_double_quotes() {
        let split_regex = Regex::new(crate::REPL_LINE_SPLIT_REGEX).unwrap();
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

    #[cfg(feature = "repl")]
    #[test]
    fn test_regex_single_quotes() {
        let split_regex = Regex::new(crate::REPL_LINE_SPLIT_REGEX).unwrap();
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
