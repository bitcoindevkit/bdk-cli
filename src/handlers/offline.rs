use crate::commands::OfflineWalletSubCommand;
use crate::error::BDKCliError as Error;
use crate::handlers::{AppCommand, AppContext, OfflineOperations};
use crate::utils::output::{FormatOutput, ListResult};
use crate::utils::parse_address;
use crate::utils::types::{
    AddressResult, BalanceResult, KeychainPair, PsbtResult, RawPsbt, TransactionDetails,
    UnspentDetails,
};
use crate::utils::{parse_outpoint, parse_recipient};
use bdk_wallet::bitcoin::base64::Engine;
use bdk_wallet::bitcoin::base64::prelude::BASE64_STANDARD;
use bdk_wallet::bitcoin::script::PushBytesBuf;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Sequence, Txid};
use bdk_wallet::{KeychainKind, SignOptions};
use clap::Parser;
use serde_json::json;
use std::collections::BTreeMap;
use std::str::FromStr;
#[cfg(feature = "bip322")]
use {
    crate::utils::parse_signature_format,
    crate::utils::types::MessageResult,
    bdk_bip322::{BIP322, MessageProof},
};

impl OfflineWalletSubCommand {
    pub fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<(), Error> {
        match self {
            Self::NewAddress(new_address) => new_address.execute(ctx)?.write_out(std::io::stdout()),
            Self::Balance(balance) => balance.execute(ctx)?.write_out(std::io::stdout()),
            Self::UnusedAddress(unused_address_command) => unused_address_command
                .execute(ctx)?
                .write_out(std::io::stdout()),
            Self::Unspent(unspent_command) => {
                unspent_command.execute(ctx)?.write_out(std::io::stdout())
            }
            Self::Transactions(transactions_command) => transactions_command
                .execute(ctx)?
                .write_out(std::io::stdout()),
            Self::CreateTx(createtx_command) => {
                createtx_command.execute(ctx)?.write_out(std::io::stdout())
            }
            Self::BumpFee(bumpfee_command) => {
                bumpfee_command.execute(ctx)?.write_out(std::io::stdout())
            }
            Self::Policies(policies_command) => {
                policies_command.execute(ctx)?.write_out(std::io::stdout())
            }
            Self::PublicDescriptor(public_descriptor_command) => public_descriptor_command
                .execute(ctx)?
                .write_out(std::io::stdout()),
            Self::Sign(sign_command) => sign_command.execute(ctx)?.write_out(std::io::stdout()),
            Self::ExtractPsbt(extract_psbt_command) => extract_psbt_command
                .execute(ctx)?
                .write_out(std::io::stdout()),
            Self::FinalizePsbt(finalize_psbt_command) => finalize_psbt_command
                .execute(ctx)?
                .write_out(std::io::stdout()),
            Self::CombinePsbt(combine_psbt_command) => combine_psbt_command
                .execute(ctx)?
                .write_out(std::io::stdout()),
            #[cfg(feature = "bip322")]
            Self::SignMessage(sign_message_command) => sign_message_command
                .execute(ctx)?
                .write_out(std::io::stdout()),
            #[cfg(feature = "bip322")]
            Self::VerifyMessage(verify_message_command) => verify_message_command
                .execute(ctx)?
                .write_out(std::io::stdout()),
        }
    }
}

#[derive(Parser, Debug, Clone, PartialEq)]
pub struct NewAddressCommand {}

impl AppCommand<AppContext<OfflineOperations<'_>>> for NewAddressCommand {
    type Output = AddressResult;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;
        let address_info = wallet.reveal_next_address(KeychainKind::External);
        Ok(AddressResult::from(address_info))
    }
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct UnusedAddressCommand {}

impl AppCommand<AppContext<OfflineOperations<'_>>> for UnusedAddressCommand {
    type Output = AddressResult;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;
        let address_info = wallet.next_unused_address(KeychainKind::External);
        Ok(AddressResult::from(address_info))
    }
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct UnspentCommand {}

impl AppCommand<AppContext<OfflineOperations<'_>>> for UnspentCommand {
    type Output = ListResult<UnspentDetails>;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;
        let utxos = wallet
            .list_unspent()
            .map(|utxo| UnspentDetails::from_local_output(&utxo, ctx.network))
            .collect();

        Ok(ListResult::new(utxos))
    }
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct TransactionsCommand {}

impl AppCommand<AppContext<OfflineOperations<'_>>> for TransactionsCommand {
    type Output = ListResult<TransactionDetails>;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let transactions = &mut ctx.state.wallet.transactions();

        let txns: Vec<TransactionDetails> = transactions
            .map(|tx| {
                let total_value = tx
                    .tx_node
                    .output
                    .iter()
                    .map(|output| output.value.to_sat())
                    .sum::<u64>();

                TransactionDetails {
                    txid: tx.tx_node.txid.to_string(),
                    is_coinbase: tx.tx_node.is_coinbase(),
                    wtxid: tx.tx_node.compute_wtxid().to_string(),
                    version: serde_json::to_value(tx.tx_node.version).unwrap_or(json!(1)),
                    version_display: tx.tx_node.version.to_string(),
                    is_rbf: tx.tx_node.is_explicitly_rbf(),
                    inputs: serde_json::to_value(&tx.tx_node.input).unwrap_or_default(),
                    outputs: serde_json::to_value(&tx.tx_node.output).unwrap_or_default(),
                    input_count: tx.tx_node.input.len(),
                    output_count: tx.tx_node.output.len(),
                    total_value,
                }
            })
            .collect();

        Ok(ListResult::new(txns))
    }
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct BalanceCommand {}

impl AppCommand<AppContext<OfflineOperations<'_>>> for BalanceCommand {
    type Output = BalanceResult;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let balance = ctx.state.wallet.balance();
        Ok(BalanceResult::from(balance))
    }
}
#[derive(Debug, Parser, Clone, PartialEq)]
pub struct CreateTxCommand {
    /// Adds a recipient to the transaction.
    #[arg(env = "ADDRESS:SAT", long = "to", required = true, value_parser = parse_recipient)]
    pub recipients: Vec<(ScriptBuf, u64)>,

    /// Sends all the funds (or all the selected utxos). Requires only one recipient with value 0.
    #[arg(long = "send_all", short = 'a')]
    pub send_all: bool,

    /// Enables Replace-By-Fee (BIP125).
    #[arg(long = "enable_rbf", short = 'r', default_value_t = true)]
    pub enable_rbf: bool,

    /// Make a PSBT that can be signed by offline signers and hardware wallets. Forces the addition of `non_witness_utxo` and more details to let the signer identify the change output.
    #[arg(long = "offline_signer")]
    pub offline_signer: bool,

    /// Selects which utxos *must* be spent.
    #[arg(env = "MUST_SPEND_TXID:VOUT", long = "utxos", value_parser = parse_outpoint)]
    pub utxos: Option<Vec<OutPoint>>,

    /// Marks a utxo as unspendable.
    #[arg(env = "CANT_SPEND_TXID:VOUT", long = "unspendable", value_parser = parse_outpoint)]
    pub unspendable: Option<Vec<OutPoint>>,

    /// Fee rate to use in sat/vbyte.
    #[arg(env = "SATS_VBYTE", short = 'f', long = "fee_rate")]
    pub fee_rate: Option<f32>,

    /// Selects which policy should be used to satisfy the external descriptor.
    #[arg(env = "EXT_POLICY", long = "external_policy")]
    pub external_policy: Option<String>,

    /// Selects which policy should be used to satisfy the internal descriptor.
    #[arg(env = "INT_POLICY", long = "internal_policy")]
    pub internal_policy: Option<String>,

    /// Optionally create an OP_RETURN output containing given String in utf8 encoding (max 80 bytes)
    #[arg(
        env = "ADD_STRING",
        long = "add_string",
        short = 's',
        conflicts_with = "add_data"
    )]
    pub add_string: Option<String>,

    /// Optionally create an OP_RETURN output containing given base64 encoded String. (max 80 bytes)
    #[arg(
        env = "ADD_DATA",
        long = "add_data",
        short = 'o',
        conflicts_with = "add_string"
    )]
    pub add_data: Option<String>,
}

impl AppCommand<AppContext<OfflineOperations<'_>>> for CreateTxCommand {
    type Output = PsbtResult;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let mut tx_builder = ctx.state.wallet.build_tx();

        if self.send_all {
            tx_builder
                .drain_wallet()
                .drain_to(self.recipients[0].0.clone());
        } else {
            let recipients = self
                .recipients
                .clone()
                .into_iter()
                .map(|(script, amount)| (script, Amount::from_sat(amount)))
                .collect();
            tx_builder.set_recipients(recipients);
        }

        if !self.enable_rbf {
            tx_builder.set_exact_sequence(Sequence::MAX);
        }

        if self.offline_signer {
            tx_builder.include_output_redeem_witness_script();
        }

        if let Some(fee_rate) = self.fee_rate
            && let Some(fee_rate) = FeeRate::from_sat_per_vb(fee_rate as u64)
        {
            tx_builder.fee_rate(fee_rate);
        }

        if let Some(utxos) = &self.utxos {
            tx_builder.add_utxos(&utxos[..]).unwrap();
        }

        if let Some(unspendable) = &self.unspendable {
            tx_builder.unspendable(unspendable.to_vec());
        }

        if let Some(base64_data) = &self.add_data {
            let op_return_data = BASE64_STANDARD.decode(base64_data).unwrap();
            tx_builder.add_data(&PushBytesBuf::try_from(op_return_data).unwrap());
        } else if let Some(string_data) = &self.add_string {
            let data = PushBytesBuf::try_from(string_data.as_bytes().to_vec()).unwrap();
            tx_builder.add_data(&data);
        }

        let policies = vec![
            self.external_policy
                .clone()
                .map(|p| (p, KeychainKind::External)),
            self.internal_policy
                .clone()
                .map(|p| (p, KeychainKind::Internal)),
        ];

        for (policy, keychain) in policies.into_iter().flatten() {
            let policy = serde_json::from_str::<BTreeMap<String, Vec<usize>>>(&policy)?;
            tx_builder.policy_path(policy, keychain);
        }

        let psbt = tx_builder.finish()?;

        // let psbt_base64 = BASE64_STANDARD.encode(psbt.serialize());

        Ok(PsbtResult::new(&psbt, false, Some(false)))
    }
}

#[derive(Debug, Parser, Clone, PartialEq)]
pub struct BumpFeeCommand {
    /// TXID of the transaction to update.
    #[arg(env = "TXID", long = "txid")]
    pub txid: String,

    /// Allows the wallet to reduce the amount to the specified address in order to increase fees.
    #[arg(env = "SHRINK_ADDRESS", long = "shrink", value_parser = parse_address)]
    pub shrink_address: Option<Address>,

    /// Make a PSBT that can be signed by offline signers and hardware wallets. Forces the addition of `non_witness_utxo` and more details to let the signer identify the change output.
    #[arg(long = "offline_signer")]
    pub offline_signer: bool,

    /// Selects which utxos *must* be added to the tx. Unconfirmed utxos cannot be used.
    #[arg(env = "MUST_SPEND_TXID:VOUT", long = "utxos", value_parser = parse_outpoint)]
    pub utxos: Option<Vec<OutPoint>>,

    /// Marks an utxo as unspendable, in case more inputs are needed to cover the extra fees.
    #[arg(env = "CANT_SPEND_TXID:VOUT", long = "unspendable", value_parser = parse_outpoint)]
    pub unspendable: Option<Vec<OutPoint>>,

    /// The new targeted fee rate in sat/vbyte.
    #[arg(
        env = "SATS_VBYTE",
        short = 'f',
        long = "fee_rate",
        default_value = "1.0"
    )]
    pub fee_rate: f32,
}

impl AppCommand<AppContext<OfflineOperations<'_>>> for BumpFeeCommand {
    type Output = PsbtResult;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;

        let txid = Txid::from_str(self.txid.as_str())?;

        let mut tx_builder = wallet.build_fee_bump(txid)?;
        let fee_rate =
            FeeRate::from_sat_per_vb(self.fee_rate as u64).unwrap_or(FeeRate::BROADCAST_MIN);
        tx_builder.fee_rate(fee_rate);

        if let Some(address) = &self.shrink_address {
            let script_pubkey = address.script_pubkey();
            tx_builder.drain_to(script_pubkey);
        }

        if self.offline_signer {
            tx_builder.include_output_redeem_witness_script();
        }

        if let Some(utxos) = &self.utxos {
            tx_builder.add_utxos(&utxos[..]).unwrap();
        }

        if let Some(unspendable) = &self.unspendable {
            tx_builder.unspendable(unspendable.to_vec());
        }

        let psbt = tx_builder.finish()?;

        // let psbt_base64 = BASE64_STANDARD.encode(psbt.serialize());

        Ok(PsbtResult::new(&psbt, false, Some(false)))
    }
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct PoliciesCommand {}

impl AppCommand<AppContext<OfflineOperations<'_>>> for PoliciesCommand {
    type Output = KeychainPair<serde_json::Value>;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;
        let external_policy = wallet.policies(KeychainKind::External)?;
        let internal_policy = wallet.policies(KeychainKind::Internal)?;

        Ok(KeychainPair {
            external: serde_json::to_value(&external_policy).unwrap_or(serde_json::json!(null)),
            internal: serde_json::to_value(&internal_policy).unwrap_or(serde_json::json!(null)),
        })
    }
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct PublicDescriptorCommand {}

impl AppCommand<AppContext<OfflineOperations<'_>>> for PublicDescriptorCommand {
    type Output = KeychainPair<String>;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;
        Ok(KeychainPair {
            external: wallet.public_descriptor(KeychainKind::External).to_string(),
            internal: wallet.public_descriptor(KeychainKind::Internal).to_string(),
        })
    }
}

#[derive(Debug, Parser, Clone, PartialEq)]
pub struct SignCommand {
    /// Sets the PSBT to sign.
    #[arg(env = "BASE64_PSBT")]
    pub psbt: String,

    /// Assume the blockchain has reached a specific height. This affects the transaction finalization, if there are timelocks in the descriptor.
    #[arg(env = "HEIGHT", long = "assume_height")]
    pub assume_height: Option<u32>,

    /// Whether the signer should trust the witness_utxo, if the non_witness_utxo hasn’t been provided.
    #[arg(env = "WITNESS", long = "trust_witness_utxo")]
    pub trust_witness_utxo: Option<bool>,
}

impl AppCommand<AppContext<OfflineOperations<'_>>> for SignCommand {
    type Output = PsbtResult;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;
        let psbt_bytes = BASE64_STANDARD
            .decode(&self.psbt)
            .map_err(|e| Error::Generic(e.to_string()))?;
        let mut psbt = Psbt::deserialize(&psbt_bytes).map_err(|e| Error::Generic(e.to_string()))?;

        let signopt = SignOptions {
            assume_height: self.assume_height,
            trust_witness_utxo: self.trust_witness_utxo.unwrap_or(false),
            ..Default::default()
        };
        let finalized = wallet.sign(&mut psbt, signopt)?;
        Ok(PsbtResult::new(&psbt, false, Some(finalized)))
    }
}

#[derive(Debug, Parser, Clone, PartialEq)]
pub struct ExtractPsbtCommand {
    /// Sets the PSBT to extract
    #[arg(env = "BASE64_PSBT")]
    pub psbt: String,
}

impl AppCommand<AppContext<OfflineOperations<'_>>> for ExtractPsbtCommand {
    type Output = RawPsbt;

    fn execute(&self, _ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let psbt_serialized = BASE64_STANDARD.decode(self.psbt.clone())?;
        let psbt = Psbt::deserialize(&psbt_serialized)?;
        let raw_tx = psbt.extract_tx()?;

        Ok(RawPsbt::new(&raw_tx))
    }
}

#[derive(Debug, Parser, Clone, PartialEq)]
pub struct FinalizePsbtCommand {
    /// Sets the PSBT to finalize.
    #[arg(env = "BASE64_PSBT")]
    pub psbt: String,

    /// Assume the blockchain has reached a specific height.
    #[arg(env = "HEIGHT", long = "assume_height")]
    pub assume_height: Option<u32>,

    /// Whether the signer should trust the witness_utxo, if the non_witness_utxo hasn’t been provided.
    #[arg(env = "WITNESS", long = "trust_witness_utxo")]
    pub trust_witness_utxo: Option<bool>,
}

impl AppCommand<AppContext<OfflineOperations<'_>>> for FinalizePsbtCommand {
    type Output = PsbtResult;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;
        let psbt_bytes = BASE64_STANDARD
            .decode(&self.psbt)
            .map_err(|e| Error::Generic(e.to_string()))?;
        let mut psbt = Psbt::deserialize(&psbt_bytes).map_err(|e| Error::Generic(e.to_string()))?;

        let signopt = SignOptions {
            assume_height: self.assume_height,
            trust_witness_utxo: self.trust_witness_utxo.unwrap_or(false),
            ..Default::default()
        };

        let finalized = wallet.finalize_psbt(&mut psbt, signopt)?;

        Ok(PsbtResult::new(&psbt, false, Some(finalized)))
    }
}

#[derive(Debug, Parser, Clone, PartialEq)]
pub struct CombinePsbtCommand {
    /// Add one PSBT to combine. This option can be repeated multiple times, one for each PSBT.
    #[arg(env = "BASE64_PSBT", required = true)]
    pub psbt: Vec<String>,
}

impl AppCommand<AppContext<OfflineOperations<'_>>> for CombinePsbtCommand {
    type Output = PsbtResult;

    fn execute(&self, _ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let mut psbts = self
            .psbt
            .iter()
            .map(|s| {
                let psbt = BASE64_STANDARD.decode(s)?;
                Ok(Psbt::deserialize(&psbt)?)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let init_psbt = psbts
            .pop()
            .ok_or_else(|| Error::Generic("Invalid PSBT input".to_string()))?;
        let final_psbt =
            psbts
                .into_iter()
                .try_fold::<_, _, Result<Psbt, Error>>(init_psbt, |mut acc, x| {
                    let _ = acc.combine(x);
                    Ok(acc)
                })?;

        Ok(PsbtResult::new(&final_psbt, false, None))
    }
}

#[cfg(feature = "bip322")]
#[derive(Debug, Parser, Clone, PartialEq)]
pub struct SignMessageCommand {
    /// The message to sign
    #[arg(long)]
    pub message: String,

    /// The signature format (e.g., Legacy, Simple, Full)
    #[arg(long, default_value = "simple")]
    pub signature_type: String,

    /// Address to sign
    #[arg(long)]
    pub address: String,

    /// Optional list of specific UTXOs for proof-of-funds (only for `FullWithProofOfFunds`)
    #[arg(long)]
    pub utxos: Option<Vec<OutPoint>>,
}

#[cfg(feature = "bip322")]
impl AppCommand<AppContext<OfflineOperations<'_>>> for SignMessageCommand {
    type Output = MessageResult;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;
        let address: Address = parse_address(&self.address)?;
        let signature_format = parse_signature_format(&self.signature_type)?;

        if !wallet.is_mine(address.script_pubkey()) {
            return Err(Error::Generic(format!(
                "Address {} does not belong to this wallet.",
                address
            )));
        }

        let proof = wallet.sign_message(
            self.message.as_str(),
            signature_format,
            &address,
            self.utxos.clone(),
        )?;

        Ok(MessageResult {
            proof: Some(proof.to_base64()),
            ..Default::default()
        })
    }
}

#[cfg(feature = "bip322")]
#[derive(Debug, Parser, Clone, PartialEq)]
pub struct VerifyMessageCommand {
    /// The signature proof to verify
    #[arg(long)]
    pub proof: String,

    /// The message that was signed
    #[arg(long)]
    pub message: String,

    /// The address associated with the signature
    #[arg(long)]
    pub address: String,
}

#[cfg(feature = "bip322")]
impl AppCommand<AppContext<OfflineOperations<'_>>> for VerifyMessageCommand {
    type Output = MessageResult;

    fn execute(&self, ctx: &mut AppContext<OfflineOperations<'_>>) -> Result<Self::Output, Error> {
        let wallet = &ctx.state.wallet;

        let address: Address = parse_address(&self.address)?;

        let parsed_proof = MessageProof::from_base64(&self.proof)
            .map_err(|e| Error::Generic(format!("Invalid proof format: {e}")))?;

        let is_valid = wallet.verify_message(&parsed_proof, &self.message, &address)?;

        Ok(MessageResult {
            valid: Some(is_valid.valid),
            proven_amount: is_valid.proven_amount.map(|a| a.to_sat()),
            ..Default::default()
        })
    }
}
