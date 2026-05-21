use std::collections::HashMap;

use crate::config::WalletConfigInner;
use crate::utils::output::FormatOutput;
use crate::utils::shorten;
use bdk_wallet::Balance;
use bdk_wallet::bitcoin::{
    Address, Network, Psbt, Transaction, base64::Engine, consensus::encode::serialize_hex,
};
use bdk_wallet::{AddressInfo, LocalOutput, chain::ChainPosition};
use serde::Serialize;
use serde_json::json;

/// Represent address result
#[derive(Serialize)]
pub struct AddressResult {
    pub address: String,
    pub index: u32,
}

impl From<AddressInfo> for AddressResult {
    fn from(info: AddressInfo) -> Self {
        Self {
            address: info.address.to_string(),
            index: info.index,
        }
    }
}

impl FormatOutput for AddressResult {}

/// Represents the data for a single transaction
#[derive(Serialize)]
pub struct TransactionDetails {
    pub txid: String,
    pub is_coinbase: bool,
    pub wtxid: String,
    pub version: serde_json::Value,
    pub is_rbf: bool,
    pub inputs: serde_json::Value,
    pub outputs: serde_json::Value,
    #[serde(skip)]
    pub version_display: String,
    #[serde(skip)]
    pub input_count: usize,
    #[serde(skip)]
    pub output_count: usize,
    #[serde(skip)]
    pub total_value: u64,
}

/// A wrapper type for a list of transactions.
#[derive(Serialize)]
#[serde(transparent)]
pub struct TransactionListResult(pub Vec<TransactionDetails>);

impl FormatOutput for TransactionListResult {}

/// single UTXO
#[derive(Serialize)]
pub struct UnspentDetails {
    pub outpoint: String,
    pub txout: serde_json::Value,
    pub keychain: String,
    pub is_spent: bool,
    pub derivation_index: u32,
    pub chain_position: serde_json::Value,

}

impl UnspentDetails {
    pub fn from_local_output(utxo: &LocalOutput, network: Network) -> Self {
        let height = utxo.chain_position.confirmation_height_upper_bound();
        let height_display = height
            .map(|h| h.to_string())
            .unwrap_or_else(|| "Pending".to_string());

        let (_, block_hash_display) = match &utxo.chain_position {
            ChainPosition::Confirmed { anchor, .. } => {
                let hash = anchor.block_id.hash.to_string();
                (Some(hash.clone()), shorten(&hash, 8, 8))
            }
            ChainPosition::Unconfirmed { .. } => (None, "Unconfirmed".to_string()),
        };

        let address = Address::from_script(&utxo.txout.script_pubkey, network)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "Unknown Script".to_string());

        let outpoint_str = utxo.outpoint.to_string();

        Self {
            outpoint: outpoint_str.clone(),
            txout: serde_json::to_value(&utxo.txout).unwrap_or(json!({})),
            keychain: format!("{:?}", utxo.keychain),
            is_spent: utxo.is_spent,
            derivation_index: utxo.derivation_index,
            chain_position: serde_json::to_value(utxo.chain_position).unwrap_or(json!({})),
        }
    }
}

/// Wrapper for the list of UTXOs
#[derive(Serialize)]
#[serde(transparent)]
pub struct UnspentListResult(pub Vec<UnspentDetails>);

impl FormatOutput for UnspentListResult {}

#[derive(Serialize)]
pub struct PsbtResult {
    pub psbt: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_finalized: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl PsbtResult {
    pub fn new(psbt: &Psbt, verbose: bool, finalized: Option<bool>) -> Self {
        Self {
            psbt: bdk_wallet::bitcoin::base64::prelude::BASE64_STANDARD.encode(psbt.serialize()),
            is_finalized: finalized,
            details: if verbose {
                Some(serde_json::to_value(psbt).unwrap_or_default())
            } else {
                None
            },
        }
    }
}

impl FormatOutput for PsbtResult {}

#[derive(Serialize)]
pub struct RawPsbt {
    pub raw_tx: String,
}

impl RawPsbt {
    pub fn new(tx: &Transaction) -> Self {
        Self {
            raw_tx: serialize_hex(tx),
        }
    }
}

impl FormatOutput for RawPsbt {}

#[derive(Serialize)]
pub struct KeychainPair<T> {
    pub external: T,
    pub internal: T,
}

impl FormatOutput for KeychainPair<String> {}

// Table formatting for JSON value pairs (used by Policies)
impl FormatOutput for KeychainPair<serde_json::Value> {}

#[derive(Serialize, Debug, Default)]
pub struct MessageResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proven_amount: Option<u64>,
}

impl FormatOutput for MessageResult {}

#[derive(Serialize, Debug)]
pub struct StatusResult {
    pub message: String,
}

impl StatusResult {
    pub fn new(msg: &str) -> Self {
        Self {
            message: msg.to_string(),
        }
    }
}

impl FormatOutput for StatusResult {}

#[derive(Serialize, Debug)]
pub struct TransactionResult {
    pub txid: String,
}

impl FormatOutput for TransactionResult {}



/// Return type definition
#[derive(Serialize)]
#[serde(transparent)]
pub struct WalletsListResult(pub HashMap<String, WalletConfigInner>);

impl FormatOutput for WalletsListResult {}


/// return type
#[derive(Serialize)]
pub struct DescriptorResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub multipath_descriptor: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_descriptors: Option<KeychainPair<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_descriptors: Option<KeychainPair<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl FormatOutput for DescriptorResult {}

#[derive(Serialize)]
pub struct KeyResult {
    pub xprv: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub xpub: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl FormatOutput for KeyResult {}


/// Balance representation
#[derive(Serialize)]
pub struct BalanceResult {
    pub total: u64,
    pub trusted_pending: u64,
    pub untrusted_pending: u64,
    pub immature: u64,
    pub confirmed: u64,
}

impl From<Balance> for BalanceResult {
    fn from(b: Balance) -> Self {
        Self {
            total: b.total().to_sat(),
            confirmed: b.confirmed.to_sat(),
            trusted_pending: b.trusted_pending.to_sat(),
            untrusted_pending: b.untrusted_pending.to_sat(),
            immature: b.immature.to_sat(),
        }
    }
}

impl FormatOutput for BalanceResult {}
