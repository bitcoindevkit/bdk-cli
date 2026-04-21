use crate::commands::OfflineWalletSubCommand::*;
use crate::commands::{CliOpts, OfflineWalletSubCommand, WalletOpts};
use crate::error::BDKCliError as Error;
use crate::utils::shorten;
use bdk_wallet::bitcoin::base64::Engine;
use bdk_wallet::bitcoin::base64::prelude::BASE64_STANDARD;
use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
use bdk_wallet::bitcoin::script::PushBytesBuf;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Psbt, Sequence, Txid};
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use cli_table::format::Justify;
use cli_table::{Cell, CellStruct, Style, Table};
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
    match offline_subcommand {
        NewAddress => {
            let addr = wallet.reveal_next_address(KeychainKind::External);
            if cli_opts.pretty {
                let table = vec![
                    vec!["Address".cell().bold(true), addr.address.to_string().cell()],
                    vec![
                        "Index".cell().bold(true),
                        addr.index.to_string().cell().justify(Justify::Right),
                    ],
                ]
                .table()
                .display()
                .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(format!("{table}"))
            } else if wallet_opts.verbose {
                Ok(serde_json::to_string_pretty(&json!({
                    "address": addr.address,
                    "index": addr.index
                }))?)
            } else {
                Ok(serde_json::to_string_pretty(&json!({
                    "address": addr.address,
                }))?)
            }
        }
        UnusedAddress => {
            let addr = wallet.next_unused_address(KeychainKind::External);

            if cli_opts.pretty {
                let table = vec![
                    vec!["Address".cell().bold(true), addr.address.to_string().cell()],
                    vec![
                        "Index".cell().bold(true),
                        addr.index.to_string().cell().justify(Justify::Right),
                    ],
                ]
                .table()
                .display()
                .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(format!("{table}"))
            } else if wallet_opts.verbose {
                Ok(serde_json::to_string_pretty(&json!({
                    "address": addr.address,
                    "index": addr.index
                }))?)
            } else {
                Ok(serde_json::to_string_pretty(&json!({
                    "address": addr.address,
                }))?)
            }
        }
        Unspent => {
            let utxos = wallet.list_unspent().collect::<Vec<_>>();
            if cli_opts.pretty {
                let mut rows: Vec<Vec<CellStruct>> = vec![];
                for utxo in &utxos {
                    let height = utxo
                        .chain_position
                        .confirmation_height_upper_bound()
                        .map(|h| h.to_string())
                        .unwrap_or("Pending".to_string());

                    let block_hash = match &utxo.chain_position {
                        ChainPosition::Confirmed { anchor, .. } => anchor.block_id.hash.to_string(),
                        ChainPosition::Unconfirmed { .. } => "Unconfirmed".to_string(),
                    };

                    rows.push(vec![
                        shorten(utxo.outpoint, 8, 10).cell(),
                        utxo.txout
                            .value
                            .to_sat()
                            .to_string()
                            .cell()
                            .justify(Justify::Right),
                        Address::from_script(&utxo.txout.script_pubkey, cli_opts.network)
                            .unwrap()
                            .cell(),
                        utxo.keychain.cell(),
                        utxo.is_spent.cell(),
                        utxo.derivation_index.cell(),
                        height.to_string().cell().justify(Justify::Right),
                        shorten(block_hash, 8, 8).cell().justify(Justify::Right),
                    ]);
                }
                let table = rows
                    .table()
                    .title(vec![
                        "Outpoint".cell().bold(true),
                        "Output (sat)".cell().bold(true),
                        "Output Address".cell().bold(true),
                        "Keychain".cell().bold(true),
                        "Is Spent".cell().bold(true),
                        "Index".cell().bold(true),
                        "Block Height".cell().bold(true),
                        "Block Hash".cell().bold(true),
                    ])
                    .display()
                    .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(format!("{table}"))
            } else {
                Ok(serde_json::to_string_pretty(&utxos)?)
            }
        }
        Transactions => {
            let transactions = wallet.transactions();

            if cli_opts.pretty {
                let txns = transactions
                    .map(|tx| {
                        let total_value = tx
                            .tx_node
                            .output
                            .iter()
                            .map(|output| output.value.to_sat())
                            .sum::<u64>();
                        (
                            tx.tx_node.txid.to_string(),
                            tx.tx_node.version,
                            tx.tx_node.is_explicitly_rbf(),
                            tx.tx_node.input.len(),
                            tx.tx_node.output.len(),
                            total_value,
                        )
                    })
                    .collect::<Vec<_>>();
                let mut rows: Vec<Vec<CellStruct>> = vec![];
                for (txid, version, is_rbf, input_count, output_count, total_value) in txns {
                    rows.push(vec![
                        txid.cell(),
                        version.to_string().cell().justify(Justify::Right),
                        is_rbf.to_string().cell().justify(Justify::Center),
                        input_count.to_string().cell().justify(Justify::Right),
                        output_count.to_string().cell().justify(Justify::Right),
                        total_value.to_string().cell().justify(Justify::Right),
                    ]);
                }
                let table = rows
                    .table()
                    .title(vec![
                        "Txid".cell().bold(true),
                        "Version".cell().bold(true),
                        "Is RBF".cell().bold(true),
                        "Input Count".cell().bold(true),
                        "Output Count".cell().bold(true),
                        "Total Value (sat)".cell().bold(true),
                    ])
                    .display()
                    .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(format!("{table}"))
            } else {
                let txns: Vec<_> = transactions
                    .map(|tx| {
                        json!({
                            "txid": tx.tx_node.txid,
                            "is_coinbase": tx.tx_node.is_coinbase(),
                            "wtxid": tx.tx_node.compute_wtxid(),
                            "version": tx.tx_node.version,
                            "is_rbf": tx.tx_node.is_explicitly_rbf(),
                            "inputs": tx.tx_node.input,
                            "outputs": tx.tx_node.output,
                        })
                    })
                    .collect();
                Ok(serde_json::to_string_pretty(&txns)?)
            }
        }
        Balance => {
            let balance = wallet.balance();
            if cli_opts.pretty {
                let table = vec![
                    vec!["Type".cell().bold(true), "Amount (sat)".cell().bold(true)],
                    vec![
                        "Total".cell(),
                        balance
                            .total()
                            .to_sat()
                            .to_string()
                            .cell()
                            .justify(Justify::Right),
                    ],
                    vec![
                        "Confirmed".cell(),
                        balance
                            .confirmed
                            .to_sat()
                            .to_string()
                            .cell()
                            .justify(Justify::Right),
                    ],
                    vec![
                        "Unconfirmed".cell(),
                        balance
                            .immature
                            .to_sat()
                            .to_string()
                            .cell()
                            .justify(Justify::Right),
                    ],
                    vec![
                        "Trusted Pending".cell(),
                        balance
                            .trusted_pending
                            .to_sat()
                            .cell()
                            .justify(Justify::Right),
                    ],
                    vec![
                        "Untrusted Pending".cell(),
                        balance
                            .untrusted_pending
                            .to_sat()
                            .cell()
                            .justify(Justify::Right),
                    ],
                ]
                .table()
                .display()
                .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(format!("{table}"))
            } else {
                Ok(serde_json::to_string_pretty(
                    &json!({"satoshi": wallet.balance()}),
                )?)
            }
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

            let psbt_base64 = BASE64_STANDARD.encode(psbt.serialize());

            if wallet_opts.verbose {
                Ok(serde_json::to_string_pretty(
                    &json!({"psbt": psbt_base64, "details": psbt}),
                )?)
            } else {
                Ok(serde_json::to_string_pretty(
                    &json!({"psbt": psbt_base64 }),
                )?)
            }
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

            let psbt_base64 = BASE64_STANDARD.encode(psbt.serialize());

            Ok(serde_json::to_string_pretty(
                &json!({"psbt": psbt_base64 }),
            )?)
        }
        Policies => {
            let external_policy = wallet.policies(KeychainKind::External)?;
            let internal_policy = wallet.policies(KeychainKind::Internal)?;
            if cli_opts.pretty {
                let table = vec![
                    vec![
                        "External".cell().bold(true),
                        serde_json::to_string_pretty(&external_policy)?.cell(),
                    ],
                    vec![
                        "Internal".cell().bold(true),
                        serde_json::to_string_pretty(&internal_policy)?.cell(),
                    ],
                ]
                .table()
                .display()
                .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(format!("{table}"))
            } else {
                Ok(serde_json::to_string_pretty(&json!({
                    "external": external_policy,
                    "internal": internal_policy,
                }))?)
            }
        }
        PublicDescriptor => {
            let external = wallet.public_descriptor(KeychainKind::External).to_string();
            let internal = wallet.public_descriptor(KeychainKind::Internal).to_string();

            if cli_opts.pretty {
                let table = vec![
                    vec![
                        "External Descriptor".cell().bold(true),
                        external.to_string().cell(),
                    ],
                    vec![
                        "Internal Descriptor".cell().bold(true),
                        internal.to_string().cell(),
                    ],
                ]
                .table()
                .display()
                .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(format!("{table}"))
            } else {
                Ok(serde_json::to_string_pretty(&json!({
                    "external": external.to_string(),
                    "internal": internal.to_string(),
                }))?)
            }
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
            let psbt_base64 = BASE64_STANDARD.encode(psbt.serialize());
            if wallet_opts.verbose {
                Ok(serde_json::to_string_pretty(
                    &json!({"psbt": &psbt_base64, "is_finalized": finalized, "serialized_psbt": &psbt}),
                )?)
            } else {
                Ok(serde_json::to_string_pretty(
                    &json!({"psbt": &psbt_base64, "is_finalized": finalized}),
                )?)
            }
        }
        ExtractPsbt { psbt } => {
            let psbt_serialized = BASE64_STANDARD.decode(psbt)?;
            let psbt = Psbt::deserialize(&psbt_serialized)?;
            let raw_tx = psbt.extract_tx()?;
            if cli_opts.pretty {
                let table = vec![vec![
                    "Raw Transaction".cell().bold(true),
                    serialize_hex(&raw_tx).cell(),
                ]]
                .table()
                .display()
                .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(format!("{table}"))
            } else {
                Ok(serde_json::to_string_pretty(
                    &json!({"raw_tx": serialize_hex(&raw_tx)}),
                )?)
            }
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
            if wallet_opts.verbose {
                Ok(serde_json::to_string_pretty(
                    &json!({ "psbt": BASE64_STANDARD.encode(psbt.serialize()), "is_finalized": finalized, "details": psbt}),
                )?)
            } else {
                Ok(serde_json::to_string_pretty(
                    &json!({ "psbt": BASE64_STANDARD.encode(psbt.serialize()), "is_finalized": finalized}),
                )?)
            }
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
            Ok(serde_json::to_string_pretty(
                &json!({ "psbt": BASE64_STANDARD.encode(final_psbt.serialize()) }),
            )?)
        }
    }
}
