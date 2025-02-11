use thiserror::Error;

#[derive(Debug, Error)]
pub enum BDKCliError {
    #[error("BIP39 error: {0}")]
    BIP39Errror(#[from] bdk_wallet::bip39::Error),

    #[error("BIP32 error: {0}")]
    BIP32Error(#[from] bdk_wallet::bitcoin::bip32::Error),

    #[error("FeeBump error: {0}")]
    BuildFeeBumpError(#[from] bdk_wallet::error::BuildFeeBumpError),

    #[allow(dead_code)]
    #[error("Checksum error")]
    ChecksumMismatch,

    #[error("Create transaction error: {0}")]
    CreateTx(#[from] bdk_wallet::error::CreateTxError),

    #[error("CoreRPC error: {0}")]
    CoreRPCError(#[from] electrsd::corepc_client::client_sync::Error),

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

    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),

    #[error("Rusqlite error: {0}")]
    RusqliteError(#[from] bdk_wallet::rusqlite::Error),

    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Signer error: {0}")]
    SignerError(#[from] bdk_wallet::signer::SignerError),
}
