// Copyright (c) 2020-2025 Bitcoin Dev Kit Developers
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

use bdk_wallet::bitcoin::{
    bip32::{DerivationPath, Xpriv},
    Address, Network, OutPoint, ScriptBuf,
};
use clap::{value_parser, Args, Parser, Subcommand, ValueEnum};

#[cfg(any(
    feature = "cbf",
    feature = "electrum",
    feature = "esplora",
    feature = "rpc"
))]
use crate::utils::parse_proxy_auth;
use crate::utils::{parse_address, parse_outpoint, parse_recipient};

/// The BDK Command Line Wallet App
///
/// bdk-cli is a lightweight command line bitcoin wallet, powered by BDK.
/// This app can be used as a playground as well as testing environment to simulate
/// various wallet testing situations. If you are planning to use BDK in your wallet, bdk-cli
/// is also a great intro tool to get familiar with the BDK API.
///
/// But this is not just any toy.
/// bdk-cli is also a fully functioning Bitcoin wallet with taproot support!
///
/// For more information checkout <https://bitcoindevkit.org/>
#[derive(PartialEq, Clone, Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct CliOpts {
    /// Sets the network.
    #[arg(
        env = "NETWORK",
        short = 'n',
        long = "network",
        default_value = "testnet",
        value_parser = value_parser!(Network)
    )]
    pub network: Network,
    /// Sets the wallet data directory.
    /// Default value : ~/.bdk-bitcoin
    #[arg(env = "DATADIR", short = 'd', long = "datadir")]
    pub datadir: Option<std::path::PathBuf>,
    /// Top level cli sub-commands.
    #[command(subcommand)]
    pub subcommand: CliSubCommand,
}

/// Top level cli sub-commands.
#[derive(Debug, Subcommand, Clone, PartialEq)]
#[command(rename_all = "snake")]
pub enum CliSubCommand {
    /// Wallet operations.
    ///
    /// bdk-cli wallet operations includes all the basic wallet level tasks.
    /// Most commands can be used without connecting to any backend. To use commands that
    /// needs backend like `sync` and `broadcast`, compile the binary with specific backend feature
    /// and use the configuration options below to configure for that backend.
    Wallet {
        #[command(flatten)]
        wallet_opts: WalletOpts,
        #[command(subcommand)]
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
        #[clap(subcommand)]
        subcommand: KeySubCommand,
    },
    /// Compile a miniscript policy to an output descriptor.
    #[cfg(feature = "compiler")]
    #[clap(long_about = "Miniscript policy compiler")]
    Compile {
        /// Sets the spending policy to compile.
        #[arg(env = "POLICY", required = true, index = 1)]
        policy: String,
        /// Sets the script type used to embed the compiled policy.
        #[arg(env = "TYPE", short = 't', long = "type", default_value = "wsh", value_parser = ["sh","wsh", "sh-wsh"]
        )]
        script_type: String,
    },
    #[cfg(feature = "repl")]
    /// REPL command loop mode.
    ///
    /// REPL command loop can be used to make recurring callbacks to an already loaded wallet.
    /// This mode is useful for hands on live testing of wallet operations.
    Repl {
        #[command(flatten)]
        wallet_opts: WalletOpts,
    },
    /// BIP322 message signing and verification operations.
    ///
    /// This subcommand allows for standalone signing and verification of messages using the BIP322
    /// standard, without requiring a full wallet setup. It is useful for simple use cases or testing.
    ///
    /// Available operations:
    /// - `sign`: Sign a message using a private key in WIF format.
    /// - `verify`: Verify a BIP322 signature for a given message and address.
    ///
    /// **Security Note**: This subcommand requires direct handling of private keys. Ensure you are in a
    /// secure environment to prevent key exposure. For generating keys securely, consider using the `wallet`
    /// subcommand instead.
    #[cfg(any(feature = "bip322"))]
    Bip322 {
        #[command(subcommand)]
        subcommand: Bip322SubCommand,
    },
}

#[derive(Debug, Subcommand, Clone, PartialEq)]
#[command(rename_all = "snake")]
pub enum Bip322SubCommand {
    /// Sign a message using BIP322
    Sign {
        /// Path to a file containing the private key in WIF format. If not provided, you will be prompted to enter the key securely.
        #[arg(long)]
        key_file: Option<String>,
        /// Address to sign
        #[arg(long)]
        address: String,
        /// The message to sign
        #[arg(long)]
        message: String,
        /// The signature format (e.g., Legacy, Simple, Full)
        #[arg(long, default_value = "simple")]
        signature_type: String,
    },
    /// Verify a BIP322 signature
    Verify {
        /// The address associated with the signature
        #[arg(long)]
        address: String,
        /// Base64-encoded signature
        #[arg(long)]
        signature: String,
        /// The message that was signed
        #[arg(long)]
        message: String,
        /// The signature format (e.g., Legacy, Simple, Full)
        #[arg(long, default_value = "simple")]
        signature_type: String,
        /// Path to a file containing the private key in WIF format. If not provided, you will be prompted to enter the key securely.
        #[arg(long)]
        key_file: Option<String>,
    },
}

/// Wallet operation subcommands.
#[derive(Debug, Subcommand, Clone, PartialEq)]
pub enum WalletSubCommand {
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "cbf",
        feature = "rpc"
    ))]
    #[command(flatten)]
    OnlineWalletSubCommand(OnlineWalletSubCommand),
    #[command(flatten)]
    OfflineWalletSubCommand(OfflineWalletSubCommand),
}

#[derive(Clone, ValueEnum, Debug, Eq, PartialEq)]
pub enum DatabaseType {
    /// Sqlite database
    #[cfg(feature = "sqlite")]
    Sqlite,
}

#[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
#[derive(Clone, ValueEnum, Debug, Eq, PartialEq)]
pub enum ClientType {
    #[cfg(feature = "electrum")]
    Electrum,
    #[cfg(feature = "esplora")]
    Esplora,
    #[cfg(feature = "rpc")]
    Rpc,
}

/// Config options wallet operations can take.
#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct WalletOpts {
    /// Selects the wallet to use.
    #[arg(env = "WALLET_NAME", short = 'w', long = "wallet")]
    pub wallet: Option<String>,
    /// Adds verbosity, returns PSBT in JSON format alongside serialized, displays expanded objects.
    #[arg(env = "VERBOSE", short = 'v', long = "verbose")]
    pub verbose: bool,
    /// Sets the descriptor to use for the external addresses.
    #[arg(env = "EXT_DESCRIPTOR", short = 'e', long)]
    pub ext_descriptor: Option<String>,
    /// Sets the descriptor to use for internal/change addresses.
    #[arg(env = "INT_DESCRIPTOR", short = 'i', long)]
    pub int_descriptor: Option<String>,
    #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
    #[arg(env = "CLIENT_TYPE", short = 'c', long, value_enum, required = true)]
    pub client_type: ClientType,
    #[cfg(feature = "sqlite")]
    #[arg(env = "DATABASE_TYPE", short = 'd', long, value_enum, required = true)]
    pub database_type: DatabaseType,
    /// Sets the server url.
    #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
    #[arg(env = "SERVER_URL", short = 'u', long, required = true)]
    pub url: String,
    /// Electrum batch size.
    #[cfg(feature = "electrum")]
    #[arg(env = "ELECTRUM_BATCH_SIZE", short = 'b', long, default_value = "10")]
    pub batch_size: usize,
    /// Esplora parallel requests.
    #[cfg(feature = "esplora")]
    #[arg(
        env = "ESPLORA_PARALLEL_REQUESTS",
        short = 'p',
        long,
        default_value = "5"
    )]
    pub parallel_requests: usize,
    #[cfg(feature = "rpc")]
    /// Sets the rpc basic authentication.
    #[arg(
        env = "USER:PASSWD",
        short = 'a',
        long,
        value_parser = parse_proxy_auth,
        default_value = "user:password",
    )]
    pub basic_auth: (String, String),
    #[cfg(feature = "rpc")]
    /// Sets an optional cookie authentication.
    #[arg(env = "COOKIE")]
    pub cookie: Option<String>,
}

/// Options to configure a SOCKS5 proxy for a blockchain client connection.
#[cfg(any(feature = "cbf", feature = "electrum", feature = "esplora"))]
#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct ProxyOpts {
    /// Sets the SOCKS5 proxy for a blockchain client.
    #[arg(env = "PROXY_ADDRS:PORT", long = "proxy", short = 'p')]
    pub proxy: Option<String>,

    /// Sets the SOCKS5 proxy credential.
    #[arg(env = "PROXY_USER:PASSWD", long="proxy_auth", short='a', value_parser = parse_proxy_auth)]
    pub proxy_auth: Option<(String, String)>,

    /// Sets the SOCKS5 proxy retries for the blockchain client.
    #[arg(
        env = "PROXY_RETRIES",
        short = 'r',
        long = "retries",
        default_value = "5"
    )]
    pub retries: u8,

    /// Sets the SOCKS5 proxy timeout for the blockchain client.
    #[arg(env = "PROXY_TIMEOUT", short = 't', long = "timeout")]
    pub timeout: Option<u8>,
}

/// Options to configure a BIP157 Compact Filter backend.
#[cfg(feature = "cbf")]
#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct CompactFilterOpts {
    /// Sets the full node network address.
    #[clap(
        env = "ADDRESS:PORT",
        long = "cbf-node",
        default_value = "127.0.0.1:18444"
    )]
    pub address: Vec<String>,

    /// Sets the number of parallel node connections.
    #[clap(name = "CONNECTIONS", long = "cbf-conn-count", default_value = "4")]
    pub conn_count: usize,

    /// Optionally skip initial `skip_blocks` blocks.
    #[clap(
        env = "SKIP_BLOCKS",
        short = 'k',
        long = "cbf-skip-blocks",
        default_value = "0"
    )]
    pub skip_blocks: usize,
}

/// Wallet subcommands that can be issued without a blockchain backend.
#[derive(Debug, Subcommand, Clone, PartialEq)]
#[command(rename_all = "snake")]
pub enum OfflineWalletSubCommand {
    /// Get a new external address.
    NewAddress,
    /// Get the first unused external address.
    UnusedAddress,
    /// Lists the available spendable UTXOs.
    Unspent,
    /// Lists all the incoming and outgoing transactions of the wallet.
    Transactions,
    /// Returns the current wallet balance.
    Balance,
    /// Creates a new unsigned transaction.
    CreateTx {
        /// Adds a recipient to the transaction.
        // Clap Doesn't support complex vector parsing https://github.com/clap-rs/clap/issues/1704.
        // Address and amount parsing is done at run time in handler function.
        #[arg(env = "ADDRESS:SAT", long = "to", required = true, value_parser = parse_recipient)]
        recipients: Vec<(ScriptBuf, u64)>,
        /// Sends all the funds (or all the selected utxos). Requires only one recipient with value 0.
        #[arg(long = "send_all", short = 'a')]
        send_all: bool,
        /// Enables Replace-By-Fee (BIP125).
        #[arg(long = "enable_rbf", short = 'r', default_value_t = true)]
        enable_rbf: bool,
        /// Make a PSBT that can be signed by offline signers and hardware wallets. Forces the addition of `non_witness_utxo` and more details to let the signer identify the change output.
        #[arg(long = "offline_signer")]
        offline_signer: bool,
        /// Selects which utxos *must* be spent.
        #[arg(env = "MUST_SPEND_TXID:VOUT", long = "utxos", value_parser = parse_outpoint)]
        utxos: Option<Vec<OutPoint>>,
        /// Marks a utxo as unspendable.
        #[arg(env = "CANT_SPEND_TXID:VOUT", long = "unspendable", value_parser = parse_outpoint)]
        unspendable: Option<Vec<OutPoint>>,
        /// Fee rate to use in sat/vbyte.
        #[arg(env = "SATS_VBYTE", short = 'f', long = "fee_rate")]
        fee_rate: Option<f32>,
        /// Selects which policy should be used to satisfy the external descriptor.
        #[arg(env = "EXT_POLICY", long = "external_policy")]
        external_policy: Option<String>,
        /// Selects which policy should be used to satisfy the internal descriptor.
        #[arg(env = "INT_POLICY", long = "internal_policy")]
        internal_policy: Option<String>,
        /// Optionally create an OP_RETURN output containing given String in utf8 encoding (max 80 bytes)
        #[arg(
            env = "ADD_STRING",
            long = "add_string",
            short = 's',
            conflicts_with = "add_data"
        )]
        add_string: Option<String>,
        /// Optionally create an OP_RETURN output containing given base64 encoded String. (max 80 bytes)
        #[arg(
            env = "ADD_DATA",
            long = "add_data",
            short = 'o',
            conflicts_with = "add_string"
        )]
        add_data: Option<String>, //base 64 econding
    },
    /// Bumps the fees of an RBF transaction.
    BumpFee {
        /// TXID of the transaction to update.
        #[arg(env = "TXID", long = "txid")]
        txid: String,
        /// Allows the wallet to reduce the amount to the specified address in order to increase fees.
        #[arg(env = "SHRINK_ADDRESS", long = "shrink", value_parser = parse_address)]
        shrink_address: Option<Address>,
        /// Make a PSBT that can be signed by offline signers and hardware wallets. Forces the addition of `non_witness_utxo` and more details to let the signer identify the change output.
        #[arg(long = "offline_signer")]
        offline_signer: bool,
        /// Selects which utxos *must* be added to the tx. Unconfirmed utxos cannot be used.
        #[arg(env = "MUST_SPEND_TXID:VOUT", long = "utxos", value_parser = parse_outpoint)]
        utxos: Option<Vec<OutPoint>>,
        /// Marks an utxo as unspendable, in case more inputs are needed to cover the extra fees.
        #[arg(env = "CANT_SPEND_TXID:VOUT", long = "unspendable", value_parser = parse_outpoint)]
        unspendable: Option<Vec<OutPoint>>,
        /// The new targeted fee rate in sat/vbyte.
        #[arg(
            env = "SATS_VBYTE",
            short = 'f',
            long = "fee_rate",
            default_value = "1.0"
        )]
        fee_rate: f32,
    },
    /// Returns the available spending policies for the descriptor.
    Policies,
    /// Returns the public version of the wallet's descriptor(s).
    PublicDescriptor,
    /// Signs and tries to finalize a PSBT.
    Sign {
        /// Sets the PSBT to sign.
        #[arg(env = "BASE64_PSBT")]
        psbt: String,
        /// Assume the blockchain has reached a specific height. This affects the transaction finalization, if there are timelocks in the descriptor.
        #[arg(env = "HEIGHT", long = "assume_height")]
        assume_height: Option<u32>,
        /// Whether the signer should trust the witness_utxo, if the non_witness_utxo hasn’t been provided.
        #[arg(env = "WITNESS", long = "trust_witness_utxo")]
        trust_witness_utxo: Option<bool>,
    },
    /// Extracts a raw transaction from a PSBT.
    ExtractPsbt {
        /// Sets the PSBT to extract
        #[arg(env = "BASE64_PSBT")]
        psbt: String,
    },
    /// Finalizes a PSBT.
    FinalizePsbt {
        /// Sets the PSBT to finalize.
        #[arg(env = "BASE64_PSBT")]
        psbt: String,
        /// Assume the blockchain has reached a specific height.
        #[arg(env = "HEIGHT", long = "assume_height")]
        assume_height: Option<u32>,
        /// Whether the signer should trust the witness_utxo, if the non_witness_utxo hasn’t been provided.
        #[arg(env = "WITNESS", long = "trust_witness_utxo")]
        trust_witness_utxo: Option<bool>,
    },
    /// Combines multiple PSBTs into one.
    CombinePsbt {
        /// Add one PSBT to combine. This option can be repeated multiple times, one for each PSBT.
        #[arg(env = "BASE64_PSBT", required = true)]
        psbt: Vec<String>,
    },
}

/// Wallet subcommands that needs a blockchain backend.
#[derive(Debug, Subcommand, Clone, PartialEq, Eq)]
#[command(rename_all = "snake")]
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
pub enum OnlineWalletSubCommand {
    /// Full Scan with the chosen blockchain server.
    FullScan {
        /// Stop searching addresses for transactions after finding an unused gap of this length.
        #[arg(env = "STOP_GAP", long = "scan-stop-gap", default_value = "20")]
        stop_gap: usize,
    },
    /// Syncs with the chosen blockchain server.
    Sync,
    /// Broadcasts a transaction to the network. Takes either a raw transaction or a PSBT to extract.
    Broadcast {
        /// Sets the PSBT to sign.
        #[arg(
            env = "BASE64_PSBT",
            long = "psbt",
            required_unless_present = "tx",
            conflicts_with = "tx"
        )]
        psbt: Option<String>,
        /// Sets the raw transaction to broadcast.
        #[arg(
            env = "RAWTX",
            long = "tx",
            required_unless_present = "psbt",
            conflicts_with = "psbt"
        )]
        tx: Option<String>,
    },
}

/// Subcommands for Key operations.
#[derive(Debug, Subcommand, Clone, PartialEq, Eq)]
pub enum KeySubCommand {
    /// Generates new random seed mnemonic phrase and corresponding master extended key.
    Generate {
        /// Entropy level based on number of random seed mnemonic words.
        #[arg(
            env = "WORD_COUNT",
            short = 'e',
            long = "entropy",
            default_value = "12"
        )]
        word_count: usize,
        /// Seed password.
        #[arg(env = "PASSWORD", short = 'p', long = "password")]
        password: Option<String>,
    },
    /// Restore a master extended key from seed backup mnemonic words.
    Restore {
        /// Seed mnemonic words, must be quoted (eg. "word1 word2 ...").
        #[arg(env = "MNEMONIC", short = 'm', long = "mnemonic")]
        mnemonic: String,
        /// Seed password.
        #[arg(env = "PASSWORD", short = 'p', long = "password")]
        password: Option<String>,
    },
    /// Derive a child key pair from a master extended key and a derivation path string (eg. "m/84'/1'/0'/0" or "m/84h/1h/0h/0").
    Derive {
        /// Extended private key to derive from.
        #[arg(env = "XPRV", short = 'x', long = "xprv")]
        xprv: Xpriv,
        /// Path to use to derive extended public key from extended private key.
        #[arg(env = "PATH", short = 'p', long = "path")]
        path: DerivationPath,
    },
}

/// Subcommands available in REPL mode.
#[cfg(any(feature = "repl", target_arch = "wasm32"))]
#[derive(Debug, Parser)]
#[command(rename_all = "lower", multicall = true)]
pub enum ReplSubCommand {
    /// Execute wallet commands.
    Wallet {
        #[command(subcommand)]
        subcommand: WalletSubCommand,
    },
    /// Execute key commands.
    Key {
        #[command(subcommand)]
        subcommand: KeySubCommand,
    },
    /// Exit REPL loop.
    Exit,
}
