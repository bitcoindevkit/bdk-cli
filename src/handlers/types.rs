use std::collections::HashMap;

use crate::config::WalletConfigInner;
use crate::utils::output::{FormatOutput, simple_table};
use crate::{error::BDKCliError as Error, utils::shorten};
use bdk_wallet::bitcoin::{
    Address, Network, Psbt, Transaction, base64::Engine, consensus::encode::serialize_hex,
};
use bdk_wallet::{AddressInfo, Balance, LocalOutput, chain::ChainPosition};
use cli_table::{Cell, CellStruct, Style, format::Justify};
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

/// pretty presentation for address
impl FormatOutput for AddressResult {
    fn to_table(&self) -> Result<String, Error> {
        simple_table(
            vec![
                vec!["Address".cell().bold(true), self.address.clone().cell()],
                vec![
                    "Index".cell().bold(true),
                    self.index.cell().justify(Justify::Right),
                ],
            ],
            None,
        )
    }
}

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

impl FormatOutput for TransactionListResult {
    fn to_table(&self) -> Result<String, Error> {
        let mut rows: Vec<Vec<CellStruct>> = vec![];

        for tx in &self.0 {
            rows.push(vec![
                tx.txid.clone().cell(),
                tx.version_display.clone().cell().justify(Justify::Right),
                tx.is_rbf.to_string().cell().justify(Justify::Center),
                tx.input_count.to_string().cell().justify(Justify::Right),
                tx.output_count.to_string().cell().justify(Justify::Right),
                tx.total_value.to_string().cell().justify(Justify::Right),
            ]);
        }

        let title = vec![
            "Txid".cell().bold(true),
            "Version".cell().bold(true),
            "Is RBF".cell().bold(true),
            "Input Count".cell().bold(true),
            "Output Count".cell().bold(true),
            "Total Value (sat)".cell().bold(true),
        ];

        simple_table(rows, Some(title))
    }
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

impl FormatOutput for BalanceResult {
    fn to_table(&self) -> Result<String, Error> {
        simple_table(
            vec![
                vec![
                    "Total".cell().bold(true),
                    self.total.cell().justify(Justify::Right),
                ],
                vec![
                    "Confirmed".cell().bold(true),
                    self.confirmed.cell().justify(Justify::Right),
                ],
                vec![
                    "Trusted Pending".cell().bold(true),
                    self.trusted_pending.cell().justify(Justify::Right),
                ],
                vec![
                    "Untrusted Pending".cell().bold(true),
                    self.untrusted_pending.cell().justify(Justify::Right),
                ],
                vec![
                    "Immature".cell().bold(true),
                    self.immature.cell().justify(Justify::Right),
                ],
            ],
            Some(vec![
                "Status".cell().bold(true),
                "Amount (sat)".cell().bold(true),
            ]),
        )
    }
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

    #[serde(skip)]
    pub value_sat: u64,
    #[serde(skip)]
    pub address: String,
    #[serde(skip)]
    pub outpoint_display: String,
    #[serde(skip)]
    pub height_display: String,
    #[serde(skip)]
    pub block_hash_display: String,
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

            value_sat: utxo.txout.value.to_sat(),
            address,
            outpoint_display: shorten(&outpoint_str, 8, 10),
            height_display,
            block_hash_display,
        }
    }
}

/// Wrapper for the list of UTXOs
#[derive(Serialize)]
#[serde(transparent)]
pub struct UnspentListResult(pub Vec<UnspentDetails>);

impl FormatOutput for UnspentListResult {
    fn to_table(&self) -> Result<String, Error> {
        let mut rows: Vec<Vec<CellStruct>> = vec![];

        for utxo in &self.0 {
            rows.push(vec![
                utxo.outpoint_display.clone().cell(),
                utxo.value_sat.to_string().cell().justify(Justify::Right),
                utxo.address.clone().cell(),
                utxo.keychain.clone().cell(),
                utxo.is_spent.cell(),
                utxo.derivation_index.cell(),
                utxo.height_display.clone().cell().justify(Justify::Right),
                utxo.block_hash_display
                    .clone()
                    .cell()
                    .justify(Justify::Right),
            ]);
        }

        let title = vec![
            "Outpoint".cell().bold(true),
            "Output (sat)".cell().bold(true),
            "Output Address".cell().bold(true),
            "Keychain".cell().bold(true),
            "Is Spent".cell().bold(true),
            "Index".cell().bold(true),
            "Block Height".cell().bold(true),
            "Block Hash".cell().bold(true),
        ];
        simple_table(rows, Some(title))
    }
}

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

impl FormatOutput for PsbtResult {
    fn to_table(&self) -> Result<String, Error> {
        let mut rows = vec![vec![
            "PSBT (Base64)".cell().bold(true),
            self.psbt.clone().cell(),
        ]];

        if let Some(finalized) = self.is_finalized {
            rows.push(vec!["Is Finalized".cell().bold(true), finalized.cell()]);
        }

        if self.details.is_some() {
            rows.push(vec![
                "Details".cell().bold(true),
                "Run without --pretty to view verbose JSON details".cell(),
            ]);
        }

        simple_table(rows, None)
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

impl FormatOutput for RawPsbt {
    fn to_table(&self) -> Result<String, Error> {
        let rows = vec![vec![
            "Raw Transaction".cell().bold(true),
            self.raw_tx.clone().cell(),
        ]];
        simple_table(rows, None)
    }
}

#[derive(Serialize)]
pub struct KeychainPair<T> {
    pub external: T,
    pub internal: T,
}

// Table formatting for string pairs (used by PublicDescriptor)
impl FormatOutput for KeychainPair<String> {
    fn to_table(&self) -> Result<String, Error> {
        let rows = vec![
            vec!["External".cell().bold(true), self.external.clone().cell()],
            vec!["Internal".cell().bold(true), self.internal.clone().cell()],
        ];
        simple_table(rows, None)
    }
}

// Table formatting for JSON value pairs (used by Policies)
impl FormatOutput for KeychainPair<serde_json::Value> {
    fn to_table(&self) -> Result<String, Error> {
        let ext_str = serde_json::to_string_pretty(&self.external)
            .map_err(|e| Error::Generic(e.to_string()))?;
        let int_str = serde_json::to_string_pretty(&self.internal)
            .map_err(|e| Error::Generic(e.to_string()))?;

        let rows = vec![
            vec!["External".cell().bold(true), ext_str.cell()],
            vec!["Internal".cell().bold(true), int_str.cell()],
        ];
        simple_table(rows, None)
    }
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

impl FormatOutput for KeyResult {
    fn to_table(&self) -> Result<String, Error> {
        let mut rows: Vec<Vec<CellStruct>> = vec![];

        if let Some(mnemonic) = &self.mnemonic {
            rows.push(vec!["Mnemonic".cell().bold(true), mnemonic.clone().cell()]);
        }
        if let Some(xpub) = &self.xpub {
            rows.push(vec!["Xpub".cell().bold(true), xpub.clone().cell()]);
        }

        rows.push(vec!["Xprv".cell().bold(true), self.xprv.clone().cell()]);

        if let Some(fingerprint) = &self.fingerprint {
            rows.push(vec![
                "Fingerprint".cell().bold(true),
                fingerprint.clone().cell(),
            ]);
        }

        simple_table(rows, None)
    }
}

#[derive(Serialize)]
#[serde(transparent)]
pub struct WalletsListResult(pub HashMap<String, WalletConfigInner>);

impl FormatOutput for WalletsListResult {
    fn to_table(&self) -> Result<String, Error> {
        if self.0.is_empty() {
            return Ok("No wallets configured yet.".to_string());
        }

        let mut rows: Vec<Vec<CellStruct>> = vec![];
        for (name, inner) in &self.0 {
            let desc: String = inner.ext_descriptor.chars().take(30).collect();
            let desc_display = if inner.ext_descriptor.len() > 30 {
                format!("{}...", desc)
            } else {
                desc
            };

            rows.push(vec![
                name.clone().cell(),
                inner.network.clone().cell(),
                desc_display.cell(),
            ]);
        }

        simple_table(
            rows,
            Some(vec![
                "Wallet Name".cell().bold(true),
                "Network".cell().bold(true),
                "External Descriptor".cell().bold(true),
            ]),
        )
    }
}


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
}

impl FormatOutput for DescriptorResult {
    fn to_table(&self) -> Result<String, Error> {
        let mut rows: Vec<Vec<CellStruct>> = vec![];
        
        if let Some(desc) = &self.descriptor {
            rows.push(vec!["Descriptor".cell().bold(true), desc.clone().cell()]);
        }
        if let Some(desc) = &self.multipath_descriptor {
            rows.push(vec!["Multipath Descriptor".cell().bold(true), desc.clone().cell()]);
        }
        if let Some(pub_desc) = &self.public_descriptors {
            rows.push(vec!["External Public".cell().bold(true), pub_desc.external.clone().cell()]);
            rows.push(vec!["Internal Public".cell().bold(true), pub_desc.internal.clone().cell()]);
        }
        if let Some(priv_desc) = &self.private_descriptors {
            rows.push(vec!["External Private".cell().bold(true), priv_desc.external.clone().cell()]);
            rows.push(vec!["Internal Private".cell().bold(true), priv_desc.internal.clone().cell()]);
        }
        if let Some(mnemonic) = &self.mnemonic {
            rows.push(vec!["Mnemonic".cell().bold(true), mnemonic.clone().cell()]);
        }

        simple_table(rows, None)
    }
}
