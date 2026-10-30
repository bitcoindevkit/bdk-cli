use std::collections::HashMap;

use crate::config::WalletConfigInner;
use bdk_wallet::Balance;
use bdk_wallet::bitcoin::{
    Network, Psbt, Transaction, base64::Engine, consensus::encode::serialize_hex,
};
use bdk_wallet::{AddressInfo, LocalOutput};
use serde::Serialize;
use serde_json::json;

/// Represent address result
#[derive(Serialize)]
pub struct AddressResult {
    pub address: String,
    pub index: u32,
    /// The address' BIP-329 label, left out when it has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl AddressResult {
    pub fn with_label(mut self, label: Option<String>) -> Self {
        self.label = label;
        self
    }
}

impl From<AddressInfo> for AddressResult {
    fn from(info: AddressInfo) -> Self {
        Self {
            address: info.address.to_string(),
            index: info.index,
            label: None,
        }
    }
}

#[allow(unused)]
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
    /// The transaction's BIP-329 label, left out when it has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// single UTXO
#[derive(Serialize)]
pub struct UnspentDetails {
    pub outpoint: String,
    pub txout: serde_json::Value,
    pub keychain: String,
    pub is_spent: bool,
    pub derivation_index: u32,
    pub chain_position: serde_json::Value,
    pub is_locked: bool,
    /// The UTXO's BIP-329 label, left out when it has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl UnspentDetails {
    pub fn from_local_output(
        utxo: &LocalOutput,
        _network: Network,
        is_locked: bool,
        label: Option<String>,
    ) -> Self {
        let outpoint_str = utxo.outpoint.to_string();

        Self {
            outpoint: outpoint_str.clone(),
            txout: serde_json::to_value(&utxo.txout).unwrap_or(json!({})),
            keychain: format!("{:?}", utxo.keychain),
            is_spent: utxo.is_spent,
            derivation_index: utxo.derivation_index,
            chain_position: serde_json::to_value(utxo.chain_position).unwrap_or(json!({})),
            is_locked,
            label,
        }
    }
}

#[derive(Serialize)]
pub struct PsbtResult {
    pub psbt: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_finalized: Option<bool>,
}

impl PsbtResult {
    pub fn new(psbt: &Psbt, finalized: Option<bool>) -> Self {
        Self {
            psbt: bdk_wallet::bitcoin::base64::prelude::BASE64_STANDARD.encode(psbt.serialize()),
            is_finalized: finalized,
        }
    }
}

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

#[derive(Serialize)]
pub struct KeychainPair<T> {
    pub external: T,
    pub internal: T,
}

#[cfg(feature = "message_signer")]
#[derive(Serialize, Debug, Default)]
pub struct MessageResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proven_amount: Option<u64>,
}

#[derive(Serialize, Debug)]
pub struct StatusResult {
    pub message: String,
}

/// What importing a BIP-329 file did to the wallet's labels.
#[derive(Serialize, Debug)]
pub struct ImportLabelsResult {
    pub file: String,
    /// Labels added or replaced, which excludes the ones that were kept.
    pub imported: usize,
    /// All the wallet's labels, after the import.
    pub total: usize,
}

/// What exporting the wallet's labels to a BIP-329 file wrote.
#[derive(Serialize, Debug)]
pub struct ExportLabelsResult {
    pub file: String,
    pub exported: usize,
}

/// The label that was set, shaped like the BIP-329 record it is stored as.
#[derive(Serialize, Debug)]
pub struct LabelResult {
    /// The BIP-329 record type: `tx`, `output` or `addr`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// What was labelled: a txid, a `TXID:VOUT` outpoint or an address.
    #[serde(rename = "ref")]
    pub reference: String,
    pub label: String,
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
#[derive(Serialize, Debug)]
pub struct TransactionResult {
    pub txid: String,
}

/// Return type definition
#[derive(Serialize)]
#[serde(transparent)]
pub struct WalletsListResult(pub HashMap<String, WalletConfigInner>);

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

    /// Randomness factor `r` used to derive the taproot unspendable internal key (H + rG).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<String>,
}

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
