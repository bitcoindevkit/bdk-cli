use crate::commands::OfflineWalletSubCommand::*;
use crate::commands::{CliOpts, OfflineWalletSubCommand, WalletOpts};
use crate::error::BDKCliError as Error;
use crate::handlers::types::{
    AddressResult, BalanceResult, PoliciesResult, PsbtResult, PublicDescriptorResult, RawPsbt,
    TransactionDetails, TransactionListResult, UnspentDetails, UnspentListResult,
};
use crate::utils::output::FormatOutput;
use bdk_wallet::bitcoin::base64::Engine;
use bdk_wallet::bitcoin::base64::prelude::BASE64_STANDARD;
use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
use bdk_wallet::bitcoin::script::PushBytesBuf;
use bdk_wallet::bitcoin::{Amount, FeeRate, Psbt, Sequence, Txid};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use serde_json::json;
use std::collections::BTreeMap;
use std::str::FromStr;

/// Execute an offline wallet sub-command
///
/// Offline wallet sub-commands are described in [`OfflineWalletSubCommand`].
pub fn handle_offline_wallet_subcommand(
    wallet: &mut Wallet,
    wallet_opts: &WalletOpts,
    cli_opts: &CliOpts,
    offline_subcommand: OfflineWalletSubCommand,
) -> Result<String, Error> {
    let pretty = cli_opts.pretty;
    match offline_subcommand {
        NewAddress => {
            let addr = wallet.reveal_next_address(KeychainKind::External);
            let result: AddressResult = addr.into();
            result.format(pretty)
        }
        UnusedAddress => {
            let addr = wallet.next_unused_address(KeychainKind::External);
            let result: AddressResult = addr.into();
            result.format(pretty)
        }
        Unspent => {
            let utxos: Vec<UnspentDetails> = wallet
                .list_unspent()
                .map(|utxo| UnspentDetails::from_local_output(&utxo, cli_opts.network))
                .collect();

            let result = UnspentListResult(utxos);
            result.format(pretty)
        }
        Transactions => {
            let transactions = wallet.transactions();

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

            let result = TransactionListResult(txns);
            result.format(pretty)
        }
        Balance => {
            let balance = wallet.balance();
            let result: BalanceResult = balance.into();
            result.format(pretty)
        }

        CreateTx {
            recipients,
            send_all,
            enable_rbf,
            offline_signer,
            utxos,
            unspendable,
            fee_rate,
            external_policy,
            internal_policy,
            add_data,
            add_string,
        } => {
            let mut tx_builder = wallet.build_tx();

            if send_all {
                tx_builder.drain_wallet().drain_to(recipients[0].0.clone());
            } else {
                let recipients = recipients
                    .into_iter()
                    .map(|(script, amount)| (script, Amount::from_sat(amount)))
                    .collect();
                tx_builder.set_recipients(recipients);
            }

            if !enable_rbf {
                tx_builder.set_exact_sequence(Sequence::MAX);
            }

            if offline_signer {
                tx_builder.include_output_redeem_witness_script();
            }

            if let Some(fee_rate) = fee_rate
                && let Some(fee_rate) = FeeRate::from_sat_per_vb(fee_rate as u64)
            {
                tx_builder.fee_rate(fee_rate);
            }

            if let Some(utxos) = utxos {
                tx_builder.add_utxos(&utxos[..]).unwrap();
            }

            if let Some(unspendable) = unspendable {
                tx_builder.unspendable(unspendable);
            }

            if let Some(base64_data) = add_data {
                let op_return_data = BASE64_STANDARD.decode(base64_data).unwrap();
                tx_builder.add_data(&PushBytesBuf::try_from(op_return_data).unwrap());
            } else if let Some(string_data) = add_string {
                let data = PushBytesBuf::try_from(string_data.as_bytes().to_vec()).unwrap();
                tx_builder.add_data(&data);
            }

            let policies = vec![
                external_policy.map(|p| (p, KeychainKind::External)),
                internal_policy.map(|p| (p, KeychainKind::Internal)),
            ];

            for (policy, keychain) in policies.into_iter().flatten() {
                let policy = serde_json::from_str::<BTreeMap<String, Vec<usize>>>(&policy)?;
                tx_builder.policy_path(policy, keychain);
            }

            let psbt = tx_builder.finish()?;

            let result = PsbtResult::with_details(&psbt, wallet_opts.verbose);
            result.format(pretty)
        }
        BumpFee {
            txid,
            shrink_address,
            offline_signer,
            utxos,
            unspendable,
            fee_rate,
        } => {
            let txid = Txid::from_str(txid.as_str())?;

            let mut tx_builder = wallet.build_fee_bump(txid)?;
            let fee_rate =
                FeeRate::from_sat_per_vb(fee_rate as u64).unwrap_or(FeeRate::BROADCAST_MIN);
            tx_builder.fee_rate(fee_rate);

            if let Some(address) = shrink_address {
                let script_pubkey = address.script_pubkey();
                tx_builder.drain_to(script_pubkey);
            }

            if offline_signer {
                tx_builder.include_output_redeem_witness_script();
            }

            if let Some(utxos) = utxos {
                tx_builder.add_utxos(&utxos[..]).unwrap();
            }

            if let Some(unspendable) = unspendable {
                tx_builder.unspendable(unspendable);
            }

            let psbt = tx_builder.finish()?;

            let result = PsbtResult::with_details(&psbt, wallet_opts.verbose);
            result.format(pretty)
        }
        Policies => {
            let external_policy = wallet.policies(KeychainKind::External)?;
            let internal_policy = wallet.policies(KeychainKind::Internal)?;
            let result = PoliciesResult {
                external: serde_json::to_value(&external_policy).unwrap_or(json!(null)),
                internal: serde_json::to_value(&internal_policy).unwrap_or(json!(null)),
            };
            result.format(pretty)
        }
        PublicDescriptor => {
            let result = PublicDescriptorResult {
                external: wallet.public_descriptor(KeychainKind::External).to_string(),
                internal: wallet.public_descriptor(KeychainKind::Internal).to_string(),
            };
            result.format(pretty)
        }
        Sign {
            psbt,
            assume_height,
            trust_witness_utxo,
        } => {
            let psbt_bytes = BASE64_STANDARD.decode(psbt)?;
            let mut psbt = Psbt::deserialize(&psbt_bytes)?;
            let signopt = SignOptions {
                assume_height,
                trust_witness_utxo: trust_witness_utxo.unwrap_or(false),
                ..Default::default()
            };
            let finalized = wallet.sign(&mut psbt, signopt)?;

            let result = PsbtResult::with_status_and_details(&psbt, finalized, wallet_opts.verbose);
            result.format(pretty)
        }
        ExtractPsbt { psbt } => {
            let psbt_serialized = BASE64_STANDARD.decode(psbt)?;
            let psbt = Psbt::deserialize(&psbt_serialized)?;
            let raw_tx = psbt.extract_tx()?;
            let result = RawPsbt::new(&raw_tx);
            result.format(pretty)
        }
        FinalizePsbt {
            psbt,
            assume_height,
            trust_witness_utxo,
        } => {
            let psbt_bytes = BASE64_STANDARD.decode(psbt)?;
            let mut psbt: Psbt = Psbt::deserialize(&psbt_bytes)?;

            let signopt = SignOptions {
                assume_height,
                trust_witness_utxo: trust_witness_utxo.unwrap_or(false),
                ..Default::default()
            };
            let finalized = wallet.finalize_psbt(&mut psbt, signopt)?;

            let result = PsbtResult::with_status_and_details(&psbt, finalized, wallet_opts.verbose);
            result.format(pretty)
        }
        CombinePsbt { psbt } => {
            let mut psbts = psbt
                .iter()
                .map(|s| {
                    let psbt = BASE64_STANDARD.decode(s)?;
                    Ok(Psbt::deserialize(&psbt)?)
                })
                .collect::<Result<Vec<_>, Error>>()?;

            let init_psbt = psbts
                .pop()
                .ok_or_else(|| Error::Generic("Invalid PSBT input".to_string()))?;
            let final_psbt = psbts.into_iter().try_fold::<_, _, Result<Psbt, Error>>(
                init_psbt,
                |mut acc, x| {
                    let _ = acc.combine(x);
                    Ok(acc)
                },
            )?;
            let result = PsbtResult::new(&final_psbt);
            result.format(pretty)
        }
    }
}
