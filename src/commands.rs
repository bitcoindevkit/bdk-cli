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
#[cfg(feature = "bip322")]
use crate::handlers::offline::{SignMessageCommand, VerifyMessageCommand};
use crate::handlers::{
    config::{ListWalletsCommand, SaveConfigCommand},
    descriptor::DescriptorCommand,
    key::{DeriveKeyCommand, GenerateKeyCommand, RestoreKeyCommand},
    offline::{
        BalanceCommand, BumpFeeCommand, CombinePsbtCommand, CreateTxCommand, ExtractPsbtCommand,
        FinalizePsbtCommand, LockUtxoCommand, LockedUtxosCommand, NewAddressCommand,
        PoliciesCommand, PublicDescriptorCommand, SignCommand, TransactionsCommand,
        UnlockUtxoCommand, UnspentCommand, UnusedAddressCommand,
    },
};

#[cfg(feature = "silent-payments")]
use crate::handlers::{descriptor::SilentPaymentCodeCommand, offline::CreateSpTxCommand};

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
use crate::{
    client::ClientType,
    handlers::online::{
        BroadcastCommand, FullScanCommand, PayjoinHistoryCommand, ReceivePayjoinCommand,
        ResumePayjoinCommand, SendPayjoinCommand, SyncCommand,
    },
};

#[cfg(feature = "compiler")]
use crate::handlers::descriptor::CompileCommand;
#[cfg(any(feature = "sqlite", feature = "redb"))]
use crate::persister::DatabaseType;

use bdk_wallet::bitcoin::Network;
use clap::{Args, Parser, Subcommand, value_parser};
use clap_complete::Shell;

#[cfg(feature = "dns_payment")]
use crate::handlers::dns::{CreateDnsTxCommand, ResolveDnsRecipientCommand};

#[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
use crate::utils::parse_proxy_auth;

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
        /// Selects the wallet to use.
        #[arg(env = "WALLET_NAME", short = 'w', long = "wallet", required = true)]
        wallet: String,

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
    Compile(CompileCommand),
    #[cfg(feature = "repl")]
    /// REPL command loop mode.
    ///
    /// REPL command loop can be used to make recurring callbacks to an already loaded wallet.
    /// This mode is useful for hands on live testing of wallet operations.
    Repl {
        /// Wallet name for this REPL session
        #[arg(env = "WALLET_NAME", short = 'w', long = "wallet", required = true)]
        wallet: String,
    },

    /// Output Descriptors operations.
    ///
    /// Generate output descriptors from either extended key (Xprv/Xpub) or mnemonic phrase.
    /// This feature is intended for development and testing purposes only.
    Descriptor(DescriptorCommand),

    /// List all saved wallet configurations.
    Wallets(ListWalletsCommand),
    /// Generate tab-completion scripts for your shell.
    ///
    /// The completion script is output on stdout, allowing you to redirect
    /// it to a file of your choosing. Where you place the file will depend
    /// on your shell and operating system.
    ///
    /// Here are common setups for supported shells:
    ///
    /// Bash:
    ///
    ///     Completion files are commonly stored in
    ///     `~/.local/share/bash-completion/completions` for user-specific commands.
    ///     Run the commands:
    ///
    ///         $ mkdir -p ~/.local/share/bash-completion/completions
    ///         $ bdk-cli completions bash > ~/.local/share/bash-completion/completions/bdk-cli
    ///
    /// Zsh:
    ///
    ///     Completion files are commonly stored in a directory listed in your `fpath`.
    ///     Run the commands:
    ///
    ///         $ mkdir -p ~/.zfunc
    ///         $ bdk-cli completions zsh > ~/.zfunc/_bdk-cli
    ///
    ///     Make sure `~/.zfunc` is in your fpath by adding to your `.zshrc`:
    ///
    ///         fpath=(~/.zfunc $fpath)
    ///         autoload -Uz compinit && compinit
    ///
    /// Fish:
    ///
    ///     Completion files are commonly stored in
    ///     `~/.config/fish/completions`. Run the commands:
    ///
    ///         $ mkdir -p ~/.config/fish/completions
    ///         $ bdk-cli completions fish > ~/.config/fish/completions/bdk-cli.fish
    ///
    /// PowerShell:
    ///
    ///         $ bdk-cli completions powershell >> $PROFILE
    ///
    /// Elvish:
    ///
    ///         $ bdk-cli completions elvish >> ~/.elvish/rc.elv
    ///
    /// After installing the completion script, restart your shell or source
    /// the configuration file for the changes to take effect.
    #[command(verbatim_doc_comment)]
    Completions {
        /// Target shell syntax
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Silent payment code generation tool.
    ///
    /// Allows the encoding of two public keys into a silent payment code.
    /// Useful to create silent payment transactions using fake silent payment codes.
    #[cfg(feature = "silent-payments")]
    SilentPaymentCode(SilentPaymentCodeCommand),
    /// Resolves BIP-353 DNS payment instructions for a human-readable name.
    #[cfg(feature = "dns_payment")]
    ResolveDnsRecipient(ResolveDnsRecipientCommand),
}

/// Wallet operation subcommands.
#[derive(Debug, Subcommand, Clone, PartialEq)]
pub enum WalletSubCommand {
    /// Save wallet configuration to `config.toml`.
    Config(SaveConfigCommand),
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

/// Config options wallet operations can take.
#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct WalletOpts {
    /// Selects the wallet to use.
    #[arg(skip)]
    pub wallet: Option<String>,
    /// Sets the descriptor to use for the external addresses.
    #[arg(env = "EXT_DESCRIPTOR", short = 'e', long, required = true)]
    pub ext_descriptor: String,
    /// Sets the descriptor to use for internal/change addresses.
    #[arg(env = "INT_DESCRIPTOR", short = 'i', long)]
    pub int_descriptor: Option<String>,
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf"
    ))]
    #[arg(env = "CLIENT_TYPE", short = 'c', long, value_enum, required = true)]
    pub client_type: ClientType,
    #[cfg(any(feature = "sqlite", feature = "redb"))]
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
    #[cfg(feature = "cbf")]
    #[clap(flatten)]
    pub compactfilter_opts: CompactFilterOpts,
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[command(flatten)]
    pub proxy_opts: ProxyOpts,
}

/// Options to configure a SOCKS5 proxy for a blockchain client connection.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct ProxyOpts {
    /// Sets the SOCKS5 proxy for a blockchain client.
    #[arg(env = "PROXY_ADDRS:PORT", long = "proxy")]
    pub proxy: Option<String>,

    /// Sets the SOCKS5 proxy credential.
    #[arg(env = "PROXY_USER:PASSWD", long="proxy_auth", value_parser = parse_proxy_auth)]
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
    /// Sets the number of parallel node connections.
    #[clap(name = "CONNECTIONS", long = "cbf-conn-count", default_value = "2", value_parser = value_parser!(u8).range(1..=15))]
    pub conn_count: u8,
}

/// Wallet subcommands that can be issued without a blockchain backend.
#[derive(Debug, Subcommand, Clone, PartialEq)]
#[command(rename_all = "snake")]
pub enum OfflineWalletSubCommand {
    /// Get a new external address.
    NewAddress(NewAddressCommand),
    /// Get the first unused external address.
    UnusedAddress(UnusedAddressCommand),
    /// Lists the available spendable UTXOs.
    Unspent(UnspentCommand),
    /// Lists all the incoming and outgoing transactions of the wallet.
    Transactions(TransactionsCommand),
    /// Returns the current wallet balance.
    Balance(BalanceCommand),
    /// Creates a new unsigned transaction.
    CreateTx(CreateTxCommand),
    /// Creates a silent payment transaction
    ///
    /// This sub-command is **EXPERIMENTAL** and should only be used for testing. Do not use this
    /// feature to create transactions that spend actual funds on the Bitcoin mainnet.
    // This command DOES NOT return a PSBT. Instead, it directly returns a signed transaction
    // ready for broadcast, as it is not yet possible to perform a shared derivation of a silent
    // payment script pubkey in a secure and trustless manner.
    #[cfg(feature = "silent-payments")]
    CreateSpTx(CreateSpTxCommand),
    /// Bumps the fees of an RBF transaction.
    BumpFee(BumpFeeCommand),
    /// Returns the available spending policies for the descriptor.
    Policies(PoliciesCommand),
    /// Returns the public version of the wallet's descriptor(s).
    PublicDescriptor(PublicDescriptorCommand),
    /// Signs and tries to finalize a PSBT.
    Sign(SignCommand),
    /// Extracts a raw transaction from a PSBT.
    ExtractPsbt(ExtractPsbtCommand),
    /// Finalizes a PSBT.
    FinalizePsbt(FinalizePsbtCommand),
    /// Combines multiple PSBTs into one.
    CombinePsbt(CombinePsbtCommand),
    /// Sign a message using BIP322
    #[cfg(feature = "bip322")]
    SignMessage(SignMessageCommand),
    /// Verify a BIP322 signature
    #[cfg(feature = "bip322")]
    VerifyMessage(VerifyMessageCommand),
    /// Lock UTXO(s) so they're excluded from coin selection.
    LockUtxo(LockUtxoCommand),
    /// Unlock previously locked UTXO(s).
    UnlockUtxo(UnlockUtxoCommand),
    /// List currently locked UTXOs.
    LockedUtxos(LockedUtxosCommand),
    /// Creates a new unsigned transaction from DNS payment instructions.
    #[cfg(feature = "dns_payment")]
    CreateDnsTx(CreateDnsTxCommand),
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
    FullScan(FullScanCommand),
    /// Syncs with the chosen blockchain server.
    Sync(SyncCommand),
    /// Broadcasts a transaction to the network. Takes either a raw transaction or a PSBT to extract.
    Broadcast(BroadcastCommand),
    /// Generates a Payjoin receive URI and processes the sender's Payjoin proposal.
    ReceivePayjoin(ReceivePayjoinCommand),
    /// Sends an original PSBT to a BIP 21 URI and broadcasts the returned Payjoin PSBT.
    SendPayjoin(SendPayjoinCommand),
    /// Resume pending payjoin sessions.
    ResumePayjoin(ResumePayjoinCommand),
    /// Show payjoin session history.
    PayjoinHistory(PayjoinHistoryCommand),
}

/// Subcommands for Key operations.
#[derive(Debug, Subcommand, Clone, PartialEq, Eq)]
pub enum KeySubCommand {
    /// Generates new random seed mnemonic phrase and corresponding master extended key.
    Generate(GenerateKeyCommand),
    /// Restore a master extended key from seed backup mnemonic words.
    Restore(RestoreKeyCommand),
    /// Derive a child key pair from a master extended key and a derivation path string (eg. "m/84'/1'/0'/0" or "m/84h/1h/0h/0").
    Derive(DeriveKeyCommand),
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
    /// Generate descriptors
    Descriptor(DescriptorCommand),
    /// Exit REPL loop.
    Exit,
}
