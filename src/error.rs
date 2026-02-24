use bdk_wallet::bitcoin::hex::HexToBytesError;
use bdk_wallet::bitcoin::psbt::ExtractTxError;
use bdk_wallet::bitcoin::{base64, consensus};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BDKCliError {
    #[error("BIP39 error: {0:?}")]
    BIP39Error(#[from] Option<bdk_wallet::bip39::Error>),

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
    PsbtExtractTxError(Box<ExtractTxError>),

    #[error("PsbtError: {0}")]
    PsbtError(#[from] bdk_wallet::bitcoin::psbt::Error),

    #[cfg(feature = "sqlite")]
    #[error("Rusqlite error: {0}")]
    RusqliteError(Box<bdk_wallet::rusqlite::Error>),

    #[cfg(feature = "redb")]
    #[error("Redb StoreError: {0}")]
    RedbStoreError(Box<bdk_redb::error::StoreError>),

    #[cfg(feature = "redb")]
    #[error("Redb dabtabase error: {0}")]
    RedbDatabaseError(Box<bdk_redb::redb::DatabaseError>),

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

    #[cfg(feature = "cbf")]
    #[error("BDK-Kyoto builder error: {0}")]
    KyotoBuilderError(#[from] bdk_kyoto::builder::BuilderError),

    #[cfg(feature = "cbf")]
    #[error("BDK-Kyoto update error: {0}")]
    KyotoUpdateError(#[from] bdk_kyoto::UpdateError),

    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf",
    ))]
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[cfg(feature = "payjoin")]
    #[error("Payjoin URL parse error: {0}")]
    PayjoinUrlParse(#[from] payjoin::IntoUrlError),

    #[cfg(feature = "payjoin")]
    #[error("Payjoin send response error: {0}")]
    PayjoinSendResponse(#[from] payjoin::send::ResponseError),

    #[cfg(feature = "payjoin")]
    #[error("Payjoin sender build error: {0}")]
    PayjoinSenderBuild(#[from] payjoin::send::BuildSenderError),

    #[cfg(feature = "payjoin")]
    #[error("Payjoin receive error: {0}")]
    PayjoinReceive(#[from] payjoin::receive::Error),

    #[cfg(feature = "payjoin")]
    #[error("Payjoin selection error: {0}")]
    PayjoinSelection(#[from] payjoin::receive::SelectionError),

    #[cfg(feature = "payjoin")]
    #[error("Payjoin input contribution error: {0}")]
    PayjoinInputContribution(#[from] payjoin::receive::InputContributionError),

    #[cfg(feature = "payjoin")]
    #[error("Payjoin create request error: {0}")]
    PayjoinCreateRequest(#[from] payjoin::send::v2::CreateRequestError),

    #[cfg(feature = "payjoin")]
    #[error("Payjoin database error: {0}")]
    PayjoinDb(#[from] PayjoinDbError),
}

impl From<ExtractTxError> for BDKCliError {
    fn from(value: ExtractTxError) -> Self {
        BDKCliError::PsbtExtractTxError(Box::new(value))
    }
}

#[cfg(feature = "redb")]
impl From<bdk_redb::error::StoreError> for BDKCliError {
    fn from(err: bdk_redb::error::StoreError) -> Self {
        BDKCliError::RedbStoreError(Box::new(err))
    }
}

#[cfg(feature = "redb")]
impl From<bdk_redb::redb::DatabaseError> for BDKCliError {
    fn from(err: bdk_redb::redb::DatabaseError) -> Self {
        BDKCliError::RedbDatabaseError(Box::new(err))
    }
}

#[cfg(feature = "sqlite")]
impl From<bdk_wallet::rusqlite::Error> for BDKCliError {
    fn from(err: bdk_wallet::rusqlite::Error) -> Self {
        BDKCliError::RusqliteError(Box::new(err))
    }
}

/// Error type for payjoin database operations
#[cfg(feature = "payjoin")]
#[derive(Debug)]
pub enum PayjoinDbError {
    /// SQLite database error
    Rusqlite(bdk_wallet::rusqlite::Error),
    /// JSON serialization error
    Serialize(serde_json::Error),
    /// JSON deserialization error
    Deserialize(serde_json::Error),
}

#[cfg(feature = "payjoin")]
impl std::fmt::Display for PayjoinDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayjoinDbError::Rusqlite(e) => write!(f, "Database operation failed: {e}"),
            PayjoinDbError::Serialize(e) => write!(f, "Serialization failed: {e}"),
            PayjoinDbError::Deserialize(e) => write!(f, "Deserialization failed: {e}"),
        }
    }
}

#[cfg(feature = "payjoin")]
impl std::error::Error for PayjoinDbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PayjoinDbError::Rusqlite(e) => Some(e),
            PayjoinDbError::Serialize(e) => Some(e),
            PayjoinDbError::Deserialize(e) => Some(e),
        }
    }
}

#[cfg(feature = "payjoin")]
impl From<bdk_wallet::rusqlite::Error> for PayjoinDbError {
    fn from(error: bdk_wallet::rusqlite::Error) -> Self {
        PayjoinDbError::Rusqlite(error)
    }
}

#[cfg(feature = "payjoin")]
impl From<PayjoinDbError> for payjoin::ImplementationError {
    fn from(error: PayjoinDbError) -> Self {
        payjoin::ImplementationError::new(error)
    }
}

#[cfg(feature = "payjoin")]
impl<ApiErr, StorageErr, ErrorState>
    From<payjoin::persist::PersistedError<ApiErr, StorageErr, ErrorState>> for BDKCliError
where
    ApiErr: std::error::Error,
    StorageErr: std::error::Error,
    ErrorState: std::fmt::Debug,
{
    fn from(e: payjoin::persist::PersistedError<ApiErr, StorageErr, ErrorState>) -> Self {
        BDKCliError::Generic(e.to_string())
    }
}
