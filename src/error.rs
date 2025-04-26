use bdk_wallet::bitcoin::hex::HexToBytesError;
use bdk_wallet::bitcoin::{base64, consensus};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BDKCliError {
    #[error("BIP39 error: {0}")]
    BIP39Error(#[from] bdk_wallet::bip39::Error),

    #[error("BIP32 error: {0}")]
    BIP32Error(#[from] bdk_wallet::bitcoin::bip32::Error),

    #[error("FeeBump error: {0}")]
    BuildFeeBumpError(#[from] bdk_wallet::error::BuildFeeBumpError),

    #[allow(dead_code)]
    #[error("Checksum error")]
    ChecksumMismatch,

    #[error("Create transaction error: {0}")]
    CreateTx(#[from] bdk_wallet::error::CreateTxError),

    #[error("Descriptor error: {0}")]
    DescriptorError(#[from] bdk_wallet::descriptor::error::Error),

    #[error("Descriptor key parse error: {0}")]
    DescriptorKeyParseError(#[from] bdk_wallet::miniscript::descriptor::DescriptorKeyParseError),

    #[error("Base64 decoding error: {0}")]
    DecodeError(#[from] base64::DecodeError),

    #[error("Generic error: {0}")]
    Generic(String),

    #[error("Hex conversion error: {0}")]
    HexToArrayError(#[from] bdk_wallet::bitcoin::hashes::hex::HexToArrayError),

    #[error("Key error: {0}")]
    KeyError(#[from] bdk_wallet::keys::KeyError),

    #[error("LocalChain error: {0}")]
    LocalChainError(#[from] bdk_wallet::chain::local_chain::ApplyHeaderError),

    #[error("Miniscript error: {0}")]
    MiniscriptError(#[from] bdk_wallet::miniscript::Error),

    #[error("ParseError: {0}")]
    ParseError(#[from] bdk_wallet::bitcoin::address::ParseError),

    #[error("ParseOutPointError: {0}")]
    ParseOutPointError(#[from] bdk_wallet::bitcoin::blockdata::transaction::ParseOutPointError),

    #[error("PsbtExtractTxError: {0}")]
    PsbtExtractTxError(#[from] bdk_wallet::bitcoin::psbt::ExtractTxError),

    #[error("PsbtError: {0}")]
    PsbtError(#[from] bdk_wallet::bitcoin::psbt::Error),

    #[error("Rusqlite error: {0}")]
    RusqliteError(#[from] bdk_wallet::rusqlite::Error),

    #[error("Serde json error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Bitcoin consensus encoding error: {0}")]
    Serde(#[from] consensus::encode::Error),

    #[error("Signer error: {0}")]
    SignerError(#[from] bdk_wallet::signer::SignerError),

    #[cfg(feature = "electrum")]
    #[error("Electrum error: {0}")]
    Electrum(#[from] bdk_electrum::electrum_client::Error),

    #[cfg(feature = "esplora")]
    #[error("Esplora error: {0}")]
    Esplora(#[from] bdk_esplora::esplora_client::Error),

    #[error("Chain connect error: {0}")]
    Chain(#[from] bdk_wallet::chain::local_chain::CannotConnectError),

    #[error("Consensus decoding error: {0}")]
    Hex(#[from] HexToBytesError),

    #[cfg(feature = "rpc")]
    #[error("RPC error: {0}")]
    BitcoinCoreRpcError(#[from] bdk_bitcoind_rpc::bitcoincore_rpc::Error),

    #[error("BIP322 error: {0}")]
    #[cfg(any(feature = "bip322"))]
    BIP322Error(#[from] bdk_bip322::Error),
}
