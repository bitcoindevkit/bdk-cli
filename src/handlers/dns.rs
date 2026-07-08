use crate::dns_payment_instructions::{
    parse_dns_instructions, process_instructions, resolve_dns_recipient,
};
use crate::error::BDKCliError as Error;
use crate::handlers::{AppContext, AsyncAppCommand, Init, OfflineOperations};
use crate::utils::types::{PsbtResult, StatusResult};
use crate::utils::{parse_dns_recipient, parse_outpoint, parse_recipient};
use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::base64::Engine;
use bdk_wallet::bitcoin::base64::prelude::BASE64_STANDARD;
use bdk_wallet::bitcoin::script::PushBytesBuf;
use bdk_wallet::bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, Sequence};
use clap::Parser;
use std::collections::BTreeMap;

/// Resolves BIP-353 DNS payment instructions for a human-readable name.
#[derive(Parser, Debug, Clone, PartialEq)]
pub struct ResolveDnsRecipientCommand {
    /// Human-readable name (e.g. user@domain.com)
    pub hrn: String,
    /// DNS resolver address
    #[arg(long, default_value = "8.8.8.8")]
    pub resolver: String,
}

impl AsyncAppCommand<AppContext<Init>> for ResolveDnsRecipientCommand {
    type Output = StatusResult;

    async fn execute(&self, ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        let resolved = resolve_dns_recipient(&self.hrn, ctx.network, &self.resolver)
            .await
            .map_err(|e| Error::Generic(format!("{:?}", e)))?;
        Ok(StatusResult {
            message: resolved.display()?,
        })
    }
}

/// Creates a new unsigned transaction from DNS payment instructions.
#[derive(Parser, Debug, Clone, PartialEq)]
pub struct CreateDnsTxCommand {
    #[arg(env = "ADDRESS:SAT", long = "to", value_parser = parse_recipient)]
    pub recipients: Vec<(ScriptBuf, u64)>,
    #[arg(long = "to_dns", value_parser = parse_dns_recipient)]
    pub dns_recipients: Vec<(String, u64)>,
    #[arg(long = "dns_resolver", default_value = "8.8.8.8")]
    pub dns_resolver: String,
    #[arg(long = "send_all", short = 'a')]
    pub send_all: bool,
    #[arg(long = "enable_rbf", short = 'r', default_value_t = true)]
    pub enable_rbf: bool,
    #[arg(long = "offline_signer")]
    pub offline_signer: bool,
    #[arg(env = "MUST_SPEND_TXID:VOUT", long = "utxos", value_parser = parse_outpoint)]
    pub utxos: Option<Vec<OutPoint>>,
    #[arg(env = "CANT_SPEND_TXID:VOUT", long = "unspendable", value_parser = parse_outpoint)]
    pub unspendable: Option<Vec<OutPoint>>,
    #[arg(env = "SATS_VBYTE", short = 'f', long = "fee_rate")]
    pub fee_rate: Option<f32>,
    #[arg(env = "EXT_POLICY", long = "external_policy")]
    pub external_policy: Option<String>,
    #[arg(env = "INT_POLICY", long = "internal_policy")]
    pub internal_policy: Option<String>,
    #[arg(
        env = "ADD_STRING",
        long = "add_string",
        short = 's',
        conflicts_with = "add_data"
    )]
    pub add_string: Option<String>,
    #[arg(
        env = "ADD_DATA",
        long = "add_data",
        short = 'o',
        conflicts_with = "add_string"
    )]
    pub add_data: Option<String>,
}

impl AsyncAppCommand<AppContext<OfflineOperations<'_>>> for CreateDnsTxCommand {
    type Output = PsbtResult;

    async fn execute(
        &self,
        ctx: &mut AppContext<OfflineOperations<'_>>,
    ) -> Result<Self::Output, Error> {
        let network = ctx.network;
        let mut recipients: Vec<(ScriptBuf, u64)> = self.recipients.clone();

        for (hrn, amount_sat) in &self.dns_recipients {
            log::info!("Resolving DNS instructions for recipient {hrn}");
            let amount = Amount::from_sat(*amount_sat);
            let (resolver, instructions) = parse_dns_instructions(hrn, network, &self.dns_resolver)
                .await
                .map_err(|e| Error::Generic(format!("Parsing error occured {e:#?}")))?;
            let payment = process_instructions(amount, &instructions, resolver).await?;
            recipients.push((payment.0.into(), payment.1.to_sat()));
        }

        if recipients.is_empty() {
            return Err(Error::Generic(
                "Either --to or --to_dns parameters must be specified".to_string(),
            ));
        }

        let mut tx_builder = ctx.state.wallet.build_tx();

        if self.send_all {
            if recipients.len() == 1 {
                tx_builder.drain_wallet().drain_to(recipients[0].0.clone());
            } else {
                return Err(Error::Generic(
                    "Wallet can only be drained to a single output".to_string(),
                ));
            }
        } else {
            let recipients = recipients
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
            tx_builder
                .add_utxos(&utxos[..])
                .map_err(|_| bdk_wallet::error::CreateTxError::UnknownUtxo)?;
        }
        if let Some(unspendable) = &self.unspendable {
            tx_builder.unspendable(unspendable.to_vec());
        }
        if let Some(base64_data) = &self.add_data {
            let op_return_data = BASE64_STANDARD
                .decode(base64_data)
                .map_err(|e| Error::Generic(e.to_string()))?;
            tx_builder.add_data(
                &PushBytesBuf::try_from(op_return_data)
                    .map_err(|e| Error::Generic(e.to_string()))?,
            );
        } else if let Some(string_data) = &self.add_string {
            let data = PushBytesBuf::try_from(string_data.as_bytes().to_vec())
                .map_err(|e| Error::Generic(e.to_string()))?;
            tx_builder.add_data(&data);
        }

        let policies = vec![
            self.external_policy
                .as_ref()
                .map(|p| (p, KeychainKind::External)),
            self.internal_policy
                .as_ref()
                .map(|p| (p, KeychainKind::Internal)),
        ];
        for (policy, keychain) in policies.into_iter().flatten() {
            let policy = serde_json::from_str::<BTreeMap<String, Vec<usize>>>(policy)?;
            tx_builder.policy_path(policy, keychain);
        }

        let psbt = tx_builder.finish()?;
        Ok(PsbtResult::new(&psbt, false, Some(false)))
    }
}
