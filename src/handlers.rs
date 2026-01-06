// Copyright (c) 2020-2025 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Command Handlers
//!
//! This module describes all the command handling logic used by bdk-cli.
use crate::commands::OfflineWalletSubCommand::*;
use crate::commands::*;
use crate::error::BDKCliError as Error;
#[cfg(any(feature = "sqlite", feature = "redb"))]
use crate::persister::Persister;
#[cfg(feature = "cbf")]
use crate::utils::BlockchainClient::KyotoClient;
use crate::utils::*;
#[cfg(feature = "redb")]
use bdk_redb::Store as RedbStore;
use bdk_wallet::bip39::{Language, Mnemonic};
use bdk_wallet::bitcoin::base64::Engine;
use bdk_wallet::bitcoin::base64::prelude::BASE64_STANDARD;
use bdk_wallet::bitcoin::{
    Address, Amount, FeeRate, Network, Psbt, Sequence, Txid,
    bip32::{DerivationPath, KeySource},
    consensus::encode::serialize_hex,
    script::PushBytesBuf,
    secp256k1::Secp256k1,
};
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::descriptor::Segwitv0;
use bdk_wallet::keys::{
    DerivableKey, DescriptorKey, DescriptorKey::Secret, ExtendedKey, GeneratableKey, GeneratedKey,
    bip39::WordCount,
};
use bdk_wallet::miniscript::miniscript;
#[cfg(feature = "sqlite")]
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
#[cfg(feature = "compiler")]
use bdk_wallet::{
    bitcoin::XOnlyPublicKey,
    descriptor::{Descriptor, Legacy, Miniscript},
    miniscript::{Tap, descriptor::TapTree, policy::Concrete},
};
use cli_table::{Cell, CellStruct, Style, Table, format::Justify};
use serde_json::json;

#[cfg(feature = "electrum")]
use crate::utils::BlockchainClient::Electrum;
use std::collections::BTreeMap;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use std::collections::HashSet;
use std::convert::TryFrom;
#[cfg(any(feature = "repl", feature = "electrum", feature = "esplora"))]
use std::io::Write;
use std::str::FromStr;
#[cfg(any(
    feature = "redb",
    feature = "compiler",
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
use std::sync::Arc;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
use {
    crate::commands::OnlineWalletSubCommand::*,
    crate::payjoin::{PayjoinManager, ohttp::RelayManager},
    bdk_wallet::bitcoin::{Transaction, consensus::Decodable, hex::FromHex},
    std::sync::Mutex,
};
#[cfg(feature = "esplora")]
use {crate::utils::BlockchainClient::Esplora, bdk_esplora::EsploraAsyncExt};
#[cfg(feature = "rpc")]
use {
    crate::utils::BlockchainClient::RpcClient,
    bdk_bitcoind_rpc::{Emitter, NO_EXPECTED_MEMPOOL_TXS, bitcoincore_rpc::RpcApi},
    bdk_wallet::chain::{BlockId, CanonicalizationParams, CheckPoint},
};

#[cfg(feature = "compiler")]
const NUMS_UNSPENDABLE_KEY_HEX: &str =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

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

            if let Some(fee_rate) = fee_rate {
                if let Some(fee_rate) = FeeRate::from_sat_per_vb(fee_rate as u64) {
                    tx_builder.fee_rate(fee_rate);
                }
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

/// Execute an online wallet sub-command
///
/// Online wallet sub-commands are described in [`OnlineWalletSubCommand`].
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
pub(crate) async fn handle_online_wallet_subcommand(
    wallet: &mut Wallet,
    client: &BlockchainClient,
    online_subcommand: OnlineWalletSubCommand,
) -> Result<String, Error> {
    match online_subcommand {
        FullScan {
            stop_gap: _stop_gap,
        } => {
            #[cfg(any(feature = "electrum", feature = "esplora"))]
            let request = wallet.start_full_scan().inspect({
                let mut stdout = std::io::stdout();
                let mut once = HashSet::<KeychainKind>::new();
                move |k, spk_i, _| {
                    if once.insert(k) {
                        print!("\nScanning keychain [{k:?}]");
                    }
                    print!(" {spk_i:<3}");
                    stdout.flush().expect("must flush");
                }
            });
            match client {
                #[cfg(feature = "electrum")]
                Electrum { client, batch_size } => {
                    // Populate the electrum client's transaction cache so it doesn't re-download transaction we
                    // already have.
                    client
                        .populate_tx_cache(wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));

                    let update = client.full_scan(request, _stop_gap, *batch_size, false)?;
                    wallet.apply_update(update)?;
                }
                #[cfg(feature = "esplora")]
                Esplora {
                    client,
                    parallel_requests,
                } => {
                    let update = client
                        .full_scan(request, _stop_gap, *parallel_requests)
                        .await
                        .map_err(|e| *e)?;
                    wallet.apply_update(update)?;
                }

                #[cfg(feature = "rpc")]
                RpcClient { client } => {
                    let blockchain_info = client.get_blockchain_info()?;

                    let genesis_block =
                        bdk_wallet::bitcoin::constants::genesis_block(wallet.network());
                    let genesis_cp = CheckPoint::new(BlockId {
                        height: 0,
                        hash: genesis_block.block_hash(),
                    });
                    let mut emitter = Emitter::new(
                        &**client,
                        genesis_cp.clone(),
                        genesis_cp.height(),
                        NO_EXPECTED_MEMPOOL_TXS,
                    );

                    while let Some(block_event) = emitter.next_block()? {
                        if block_event.block_height() % 10_000 == 0 {
                            let percent_done = f64::from(block_event.block_height())
                                / f64::from(blockchain_info.headers as u32)
                                * 100f64;
                            println!(
                                "Applying block at height: {}, {:.2}% done.",
                                block_event.block_height(),
                                percent_done
                            );
                        }

                        wallet.apply_block_connected_to(
                            &block_event.block,
                            block_event.block_height(),
                            block_event.connected_to(),
                        )?;
                    }

                    let mempool_txs = emitter.mempool()?;
                    wallet.apply_unconfirmed_txs(mempool_txs.update);
                }
                #[cfg(feature = "cbf")]
                KyotoClient { client } => {
                    sync_kyoto_client(wallet, client).await?;
                }
            }
            Ok(serde_json::to_string_pretty(&json!({}))?)
        }
        Sync => {
            sync_wallet(client, wallet).await?;
            Ok(serde_json::to_string_pretty(&json!({}))?)
        }
        Broadcast { psbt, tx } => {
            let tx = match (psbt, tx) {
                (Some(psbt), None) => {
                    let psbt = BASE64_STANDARD
                        .decode(psbt)
                        .map_err(|e| Error::Generic(e.to_string()))?;
                    let psbt: Psbt = Psbt::deserialize(&psbt)?;
                    is_final(&psbt)?;
                    psbt.extract_tx()?
                }
                (None, Some(tx)) => {
                    let tx_bytes = Vec::<u8>::from_hex(&tx)?;
                    Transaction::consensus_decode(&mut tx_bytes.as_slice())?
                }
                (Some(_), Some(_)) => panic!("Both `psbt` and `tx` options not allowed"),
                (None, None) => panic!("Missing `psbt` and `tx` option"),
            };
            let txid = broadcast_transaction(client, tx).await?;
            Ok(serde_json::to_string_pretty(&json!({ "txid": txid }))?)
        }
        ReceivePayjoin {
            amount,
            directory,
            ohttp_relay,
            max_fee_rate,
        } => {
            let relay_manager = Arc::new(Mutex::new(RelayManager::new()));
            let mut payjoin_manager = PayjoinManager::new(wallet, relay_manager);
            return payjoin_manager
                .receive_payjoin(amount, directory, max_fee_rate, ohttp_relay, client)
                .await;
        }
        SendPayjoin {
            uri,
            ohttp_relay,
            fee_rate,
        } => {
            let relay_manager = Arc::new(Mutex::new(RelayManager::new()));
            let mut payjoin_manager = PayjoinManager::new(wallet, relay_manager);
            return payjoin_manager
                .send_payjoin(uri, fee_rate, ohttp_relay, client)
                .await;
        }
    }
}

/// Determine if PSBT has final script sigs or witnesses for all unsigned tx inputs.
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
pub(crate) fn is_final(psbt: &Psbt) -> Result<(), Error> {
    let unsigned_tx_inputs = psbt.unsigned_tx.input.len();
    let psbt_inputs = psbt.inputs.len();
    if unsigned_tx_inputs != psbt_inputs {
        return Err(Error::Generic(format!(
            "Malformed PSBT, {unsigned_tx_inputs} unsigned tx inputs and {psbt_inputs} psbt inputs."
        )));
    }
    let sig_count = psbt.inputs.iter().fold(0, |count, input| {
        if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
            count + 1
        } else {
            count
        }
    });
    if unsigned_tx_inputs > sig_count {
        return Err(Error::Generic(
            "The PSBT is not finalized, inputs are are not fully signed.".to_string(),
        ));
    }
    Ok(())
}

/// Handle a key sub-command
///
/// Key sub-commands are described in [`KeySubCommand`].
pub(crate) fn handle_key_subcommand(
    network: Network,
    subcommand: KeySubCommand,
    pretty: bool,
) -> Result<String, Error> {
    let secp = Secp256k1::new();

    match subcommand {
        KeySubCommand::Generate {
            word_count,
            password,
        } => {
            let mnemonic_type = match word_count {
                12 => WordCount::Words12,
                _ => WordCount::Words24,
            };
            let mnemonic: GeneratedKey<_, miniscript::BareCtx> =
                Mnemonic::generate((mnemonic_type, Language::English))
                    .map_err(|_| Error::Generic("Mnemonic generation error".to_string()))?;
            let mnemonic = mnemonic.into_key();
            let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).ok_or_else(|| {
                Error::Generic("Privatekey info not found (should not happen)".to_string())
            })?;
            let fingerprint = xprv.fingerprint(&secp);
            let phrase = mnemonic
                .words()
                .fold("".to_string(), |phrase, w| phrase + w + " ")
                .trim()
                .to_string();
            if pretty {
                let table = vec![
                    vec![
                        "Fingerprint".cell().bold(true),
                        fingerprint.to_string().cell(),
                    ],
                    vec!["Mnemonic".cell().bold(true), mnemonic.to_string().cell()],
                    vec!["Xprv".cell().bold(true), xprv.to_string().cell()],
                ]
                .table()
                .display()
                .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(format!("{table}"))
            } else {
                Ok(serde_json::to_string_pretty(
                    &json!({ "mnemonic": phrase, "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }),
                )?)
            }
        }
        KeySubCommand::Restore { mnemonic, password } => {
            let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)?;
            let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).ok_or_else(|| {
                Error::Generic("Privatekey info not found (should not happen)".to_string())
            })?;
            let fingerprint = xprv.fingerprint(&secp);
            if pretty {
                let table = vec![
                    vec![
                        "Fingerprint".cell().bold(true),
                        fingerprint.to_string().cell(),
                    ],
                    vec!["Mnemonic".cell().bold(true), mnemonic.to_string().cell()],
                    vec!["Xprv".cell().bold(true), xprv.to_string().cell()],
                ]
                .table()
                .display()
                .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(format!("{table}"))
            } else {
                Ok(serde_json::to_string_pretty(
                    &json!({ "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }),
                )?)
            }
        }
        KeySubCommand::Derive { xprv, path } => {
            if xprv.network != network.into() {
                return Err(Error::Generic("Invalid network".to_string()));
            }
            let derived_xprv = &xprv.derive_priv(&secp, &path)?;

            let origin: KeySource = (xprv.fingerprint(&secp), path);

            let derived_xprv_desc_key: DescriptorKey<Segwitv0> =
                derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default())?;

            if let Secret(desc_seckey, _, _) = derived_xprv_desc_key {
                let desc_pubkey = desc_seckey.to_public(&secp)?;
                if pretty {
                    let table = vec![
                        vec!["Xpub".cell().bold(true), desc_pubkey.to_string().cell()],
                        vec!["Xprv".cell().bold(true), xprv.to_string().cell()],
                    ]
                    .table()
                    .display()
                    .map_err(|e| Error::Generic(e.to_string()))?;
                    Ok(format!("{table}"))
                } else {
                    Ok(serde_json::to_string_pretty(
                        &json!({"xpub": desc_pubkey.to_string(), "xprv": desc_seckey.to_string()}),
                    )?)
                }
            } else {
                Err(Error::Generic("Invalid key variant".to_string()))
            }
        }
    }
}

/// Handle the miniscript compiler sub-command
///
/// Compiler options are described in [`CliSubCommand::Compile`].
#[cfg(feature = "compiler")]
pub(crate) fn handle_compile_subcommand(
    _network: Network,
    policy: String,
    script_type: String,
    pretty: bool,
) -> Result<String, Error> {
    let policy = Concrete::<String>::from_str(policy.as_str())?;
    let legacy_policy: Miniscript<String, Legacy> = policy
        .compile()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let segwit_policy: Miniscript<String, Segwitv0> = policy
        .compile()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let taproot_policy: Miniscript<String, Tap> = policy
        .compile()
        .map_err(|e| Error::Generic(e.to_string()))?;

    let descriptor = match script_type.as_str() {
        "sh" => Descriptor::new_sh(legacy_policy),
        "wsh" => Descriptor::new_wsh(segwit_policy),
        "sh-wsh" => Descriptor::new_sh_wsh(segwit_policy),
        "tr" => {
            // For tr descriptors, we use a well-known unspendable key (NUMS point).
            // This ensures the key path is effectively disabled and only script path can be used.
            // See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs

            let xonly_public_key = XOnlyPublicKey::from_str(NUMS_UNSPENDABLE_KEY_HEX)
                .map_err(|e| Error::Generic(format!("Invalid NUMS key: {e}")))?;

            let tree = TapTree::Leaf(Arc::new(taproot_policy));
            Descriptor::new_tr(xonly_public_key.to_string(), Some(tree))
        }
        _ => {
            return Err(Error::Generic(
                "Invalid script type. Supported types: sh, wsh, sh-wsh, tr".to_string(),
            ));
        }
    }?;
    if pretty {
        let table = vec![vec![
            "Descriptor".cell().bold(true),
            descriptor.to_string().cell(),
        ]]
        .table()
        .display()
        .map_err(|e| Error::Generic(e.to_string()))?;
        Ok(format!("{table}"))
    } else {
        Ok(serde_json::to_string_pretty(
            &json!({"descriptor": descriptor.to_string()}),
        )?)
    }
}

/// The global top level handler.
pub(crate) async fn handle_command(cli_opts: CliOpts) -> Result<String, Error> {
    let network = cli_opts.network;
    let pretty = cli_opts.pretty;

    let result: Result<String, Error> = match cli_opts.subcommand {
        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "cbf",
            feature = "rpc"
        ))]
        CliSubCommand::Wallet {
            ref wallet_opts,
            subcommand: WalletSubCommand::OnlineWalletSubCommand(online_subcommand),
        } => {
            // let network = cli_opts.network;
            let home_dir = prepare_home_dir(cli_opts.datadir)?;
            let wallet_name = &wallet_opts.wallet;
            let database_path = prepare_wallet_db_dir(wallet_name, &home_dir)?;

            #[cfg(any(feature = "sqlite", feature = "redb"))]
            let result = {
                let mut persister: Persister = match &wallet_opts.database_type {
                    #[cfg(feature = "sqlite")]
                    DatabaseType::Sqlite => {
                        let db_file = database_path.join("wallet.sqlite");
                        let connection = Connection::open(db_file)?;
                        log::debug!("Sqlite database opened successfully");
                        Persister::Connection(connection)
                    }
                    #[cfg(feature = "redb")]
                    DatabaseType::Redb => {
                        let db = Arc::new(bdk_redb::redb::Database::create(
                            home_dir.join("wallet.redb"),
                        )?);
                        let store = RedbStore::new(
                            db,
                            wallet_name.as_deref().unwrap_or("wallet").to_string(),
                        )?;
                        log::debug!("Redb database opened successfully");
                        Persister::RedbStore(store)
                    }
                };

                let mut wallet = new_persisted_wallet(network, &mut persister, wallet_opts)?;
                let blockchain_client = new_blockchain_client(wallet_opts, &wallet, database_path)?;

                let result = handle_online_wallet_subcommand(
                    &mut wallet,
                    &blockchain_client,
                    online_subcommand,
                )
                .await?;
                wallet.persist(&mut persister)?;
                result
            };
            #[cfg(not(any(feature = "sqlite", feature = "redb")))]
            let result = {
                let mut wallet = new_wallet(network, wallet_opts)?;
                let blockchain_client =
                    crate::utils::new_blockchain_client(wallet_opts, &wallet, database_path)?;
                handle_online_wallet_subcommand(&mut wallet, &blockchain_client, online_subcommand)
                    .await?
            };
            Ok(result)
        }
        CliSubCommand::Wallet {
            ref wallet_opts,
            subcommand: WalletSubCommand::OfflineWalletSubCommand(ref offline_subcommand),
        } => {
            let network = cli_opts.network;
            #[cfg(any(feature = "sqlite", feature = "redb"))]
            let result = {
                let home_dir = prepare_home_dir(cli_opts.datadir.clone())?;
                let wallet_name = &wallet_opts.wallet;
                let mut persister: Persister = match &wallet_opts.database_type {
                    #[cfg(feature = "sqlite")]
                    DatabaseType::Sqlite => {
                        let database_path = prepare_wallet_db_dir(wallet_name, &home_dir)?;
                        let db_file = database_path.join("wallet.sqlite");
                        let connection = Connection::open(db_file)?;
                        log::debug!("Sqlite database opened successfully");
                        Persister::Connection(connection)
                    }
                    #[cfg(feature = "redb")]
                    DatabaseType::Redb => {
                        let db = Arc::new(bdk_redb::redb::Database::create(
                            home_dir.join("wallet.redb"),
                        )?);
                        let store = RedbStore::new(
                            db,
                            wallet_name.as_deref().unwrap_or("wallet").to_string(),
                        )?;
                        log::debug!("Redb database opened successfully");
                        Persister::RedbStore(store)
                    }
                };

                let mut wallet = new_persisted_wallet(network, &mut persister, wallet_opts)?;

                let result = handle_offline_wallet_subcommand(
                    &mut wallet,
                    wallet_opts,
                    &cli_opts,
                    offline_subcommand.clone(),
                )?;
                wallet.persist(&mut persister)?;
                result
            };
            #[cfg(not(any(feature = "sqlite", feature = "redb")))]
            let result = {
                let mut wallet = new_wallet(network, wallet_opts)?;
                handle_offline_wallet_subcommand(
                    &mut wallet,
                    wallet_opts,
                    &cli_opts,
                    offline_subcommand.clone(),
                )?
            };
            Ok(result)
        }
        CliSubCommand::Key {
            subcommand: key_subcommand,
        } => {
            let result = handle_key_subcommand(network, key_subcommand, pretty)?;
            Ok(result)
        }
        #[cfg(feature = "compiler")]
        CliSubCommand::Compile {
            policy,
            script_type,
        } => {
            let result = handle_compile_subcommand(network, policy, script_type, pretty)?;
            Ok(result)
        }
        #[cfg(feature = "repl")]
        CliSubCommand::Repl { ref wallet_opts } => {
            let network = cli_opts.network;
            #[cfg(any(feature = "sqlite", feature = "redb"))]
            let (mut wallet, mut persister) = {
                let wallet_name = &wallet_opts.wallet;

                let home_dir = prepare_home_dir(cli_opts.datadir.clone())?;

                let mut persister: Persister = match &wallet_opts.database_type {
                    #[cfg(feature = "sqlite")]
                    DatabaseType::Sqlite => {
                        let database_path = prepare_wallet_db_dir(wallet_name, &home_dir)?;
                        let db_file = database_path.join("wallet.sqlite");
                        let connection = Connection::open(db_file)?;
                        log::debug!("Sqlite database opened successfully");
                        Persister::Connection(connection)
                    }
                    #[cfg(feature = "redb")]
                    DatabaseType::Redb => {
                        let db = Arc::new(bdk_redb::redb::Database::create(
                            home_dir.join("wallet.redb"),
                        )?);
                        let store = RedbStore::new(
                            db,
                            wallet_name.as_deref().unwrap_or("wallet").to_string(),
                        )?;
                        log::debug!("Redb database opened successfully");
                        Persister::RedbStore(store)
                    }
                };
                let wallet = new_persisted_wallet(network, &mut persister, wallet_opts)?;
                (wallet, persister)
            };
            #[cfg(not(any(feature = "sqlite", feature = "redb")))]
            let mut wallet = new_wallet(network, &wallet_opts)?;
            let home_dir = prepare_home_dir(cli_opts.datadir.clone())?;
            let database_path = prepare_wallet_db_dir(&wallet_opts.wallet, &home_dir)?;

            loop {
                let line = readline()?;
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let result = respond(
                    network,
                    &mut wallet,
                    wallet_opts,
                    line,
                    database_path.clone(),
                    &cli_opts,
                )
                .await;
                #[cfg(any(feature = "sqlite", feature = "redb"))]
                wallet.persist(&mut persister)?;

                match result {
                    Ok(quit) => {
                        if quit {
                            break;
                        }
                    }
                    Err(err) => {
                        writeln!(std::io::stdout(), "{err}")
                            .map_err(|e| Error::Generic(e.to_string()))?;
                        std::io::stdout()
                            .flush()
                            .map_err(|e| Error::Generic(e.to_string()))?;
                    }
                }
            }
            Ok("".to_string())
        }
        CliSubCommand::Descriptor { desc_type, key } => {
            let descriptor = handle_descriptor_command(cli_opts.network, desc_type, key, pretty)?;
            Ok(descriptor)
        }
    };
    result
}

#[cfg(feature = "repl")]
async fn respond(
    network: Network,
    wallet: &mut Wallet,
    wallet_opts: &WalletOpts,
    line: &str,
    _datadir: std::path::PathBuf,
    cli_opts: &CliOpts,
) -> Result<bool, String> {
    use clap::Parser;

    let args = shlex::split(line).ok_or("error: Invalid quoting".to_string())?;
    let repl_subcommand = ReplSubCommand::try_parse_from(args).map_err(|e| e.to_string())?;
    let response = match repl_subcommand {
        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "cbf",
            feature = "rpc"
        ))]
        ReplSubCommand::Wallet {
            subcommand: WalletSubCommand::OnlineWalletSubCommand(online_subcommand),
        } => {
            let blockchain =
                new_blockchain_client(wallet_opts, wallet, _datadir).map_err(|e| e.to_string())?;
            let value = handle_online_wallet_subcommand(wallet, &blockchain, online_subcommand)
                .await
                .map_err(|e| e.to_string())?;
            Some(value)
        }
        ReplSubCommand::Wallet {
            subcommand: WalletSubCommand::OfflineWalletSubCommand(offline_subcommand),
        } => {
            let value =
                handle_offline_wallet_subcommand(wallet, wallet_opts, cli_opts, offline_subcommand)
                    .map_err(|e| e.to_string())?;
            Some(value)
        }
        ReplSubCommand::Key { subcommand } => {
            let value = handle_key_subcommand(network, subcommand, cli_opts.pretty)
                .map_err(|e| e.to_string())?;
            Some(value)
        }
        ReplSubCommand::Descriptor { desc_type, key } => {
            let value = handle_descriptor_command(network, desc_type, key, cli_opts.pretty)
                .map_err(|e| e.to_string())?;
            Some(value)
        }
        ReplSubCommand::Exit => None,
    };
    if let Some(value) = response {
        writeln!(std::io::stdout(), "{value}").map_err(|e| e.to_string())?;
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        Ok(false)
    } else {
        writeln!(std::io::stdout(), "Exiting...").map_err(|e| e.to_string())?;
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        Ok(true)
    }
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
/// Syncs a given wallet using the blockchain client.
pub async fn sync_wallet(client: &BlockchainClient, wallet: &mut Wallet) -> Result<(), Error> {
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    let request = wallet
        .start_sync_with_revealed_spks()
        .inspect(|item, progress| {
            let pc = (100 * progress.consumed()) as f32 / progress.total() as f32;
            eprintln!("[ SCANNING {pc:03.0}% ] {item}");
        });
    match client {
        #[cfg(feature = "electrum")]
        Electrum { client, batch_size } => {
            // Populate the electrum client's transaction cache so it doesn't re-download transaction we
            // already have.
            client.populate_tx_cache(wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));

            let update = client.sync(request, *batch_size, false)?;
            wallet
                .apply_update(update)
                .map_err(|e| Error::Generic(e.to_string()))
        }
        #[cfg(feature = "esplora")]
        Esplora {
            client,
            parallel_requests,
        } => {
            let update = client
                .sync(request, *parallel_requests)
                .await
                .map_err(|e| *e)?;
            wallet
                .apply_update(update)
                .map_err(|e| Error::Generic(e.to_string()))
        }
        #[cfg(feature = "rpc")]
        RpcClient { client } => {
            let blockchain_info = client.get_blockchain_info()?;
            let wallet_cp = wallet.latest_checkpoint();

            // reload the last 200 blocks in case of a reorg
            let emitter_height = wallet_cp.height().saturating_sub(200);
            let mut emitter = Emitter::new(
                &**client,
                wallet_cp,
                emitter_height,
                wallet
                    .tx_graph()
                    .list_canonical_txs(
                        wallet.local_chain(),
                        wallet.local_chain().tip().block_id(),
                        CanonicalizationParams::default(),
                    )
                    .filter(|tx| tx.chain_position.is_unconfirmed()),
            );

            while let Some(block_event) = emitter.next_block()? {
                if block_event.block_height() % 10_000 == 0 {
                    let percent_done = f64::from(block_event.block_height())
                        / f64::from(blockchain_info.headers as u32)
                        * 100f64;
                    println!(
                        "Applying block at height: {}, {:.2}% done.",
                        block_event.block_height(),
                        percent_done
                    );
                }

                wallet.apply_block_connected_to(
                    &block_event.block,
                    block_event.block_height(),
                    block_event.connected_to(),
                )?;
            }

            let mempool_txs = emitter.mempool()?;
            wallet.apply_unconfirmed_txs(mempool_txs.update);
            Ok(())
        }
        #[cfg(feature = "cbf")]
        KyotoClient { client } => sync_kyoto_client(wallet, client)
            .await
            .map_err(|e| Error::Generic(e.to_string())),
    }
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
/// Broadcasts a given transaction using the blockchain client.
pub async fn broadcast_transaction(
    client: &BlockchainClient,
    tx: Transaction,
) -> Result<Txid, Error> {
    match client {
        #[cfg(feature = "electrum")]
        Electrum {
            client,
            batch_size: _,
        } => client
            .transaction_broadcast(&tx)
            .map_err(|e| Error::Generic(e.to_string())),
        #[cfg(feature = "esplora")]
        Esplora {
            client,
            parallel_requests: _,
        } => client
            .broadcast(&tx)
            .await
            .map(|()| tx.compute_txid())
            .map_err(|e| Error::Generic(e.to_string())),
        #[cfg(feature = "rpc")]
        RpcClient { client } => client
            .send_raw_transaction(&tx)
            .map_err(|e| Error::Generic(e.to_string())),

        #[cfg(feature = "cbf")]
        KyotoClient { client } => {
            let txid = tx.compute_txid();
            let wtxid = client
                .requester
                .broadcast_random(tx.clone())
                .await
                .map_err(|_| {
                    tracing::warn!("Broadcast was unsuccessful");
                    Error::Generic("Transaction broadcast timed out after 30 seconds".into())
                })?;
            tracing::info!("Successfully broadcast WTXID: {wtxid}");
            Ok(txid)
        }
    }
}

#[cfg(feature = "repl")]
fn readline() -> Result<String, Error> {
    write!(std::io::stdout(), "> ").map_err(|e| Error::Generic(e.to_string()))?;
    std::io::stdout()
        .flush()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let mut buffer = String::new();
    std::io::stdin()
        .read_line(&mut buffer)
        .map_err(|e| Error::Generic(e.to_string()))?;
    Ok(buffer)
}

/// Handle the descriptor command
pub fn handle_descriptor_command(
    network: Network,
    desc_type: String,
    key: Option<String>,
    pretty: bool,
) -> Result<String, Error> {
    let result = match key {
        Some(key) => {
            if is_mnemonic(&key) {
                // User provided mnemonic
                generate_descriptor_from_mnemonic(&key, network, &desc_type)
            } else {
                // User provided xprv/xpub
                generate_descriptors(&desc_type, &key, network)
            }
        }
        // Generate new mnemonic and descriptors
        None => generate_descriptor_with_mnemonic(network, &desc_type),
    }?;
    format_descriptor_output(&result, pretty)
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
#[cfg(test)]
mod test {
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "cbf",
        feature = "rpc"
    ))]
    #[test]
    fn test_psbt_is_final() {
        use super::is_final;
        use bdk_wallet::bitcoin::Psbt;
        use std::str::FromStr;

        let unsigned_psbt = Psbt::from_str("cHNidP8BAIkBAAAAASWJHzxzyVORV/C3lAynKHVVL7+Rw7/Jj8U9fuvD24olAAAAAAD+////AiBOAAAAAAAAIgAgLzY9yE4jzTFJnHtTjkc+rFAtJ9NB7ENFQ1xLYoKsI1cfqgKVAAAAACIAIFsbWgDeLGU8EA+RGwBDIbcv4gaGG0tbEIhDvwXXa/E7LwEAAAABALUCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BALLAAD/////AgD5ApUAAAAAIgAgWxtaAN4sZTwQD5EbAEMhty/iBoYbS1sQiEO/Bddr8TsAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQErAPkClQAAAAAiACBbG1oA3ixlPBAPkRsAQyG3L+IGhhtLWxCIQ78F12vxOwEFR1IhA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDIQLKhV/gEZYmlsQXnsL5/Uqv5Y8O31tmWW1LQqIBkiqzCVKuIgYCyoVf4BGWJpbEF57C+f1Kr+WPDt9bZlltS0KiAZIqswkEboH3lCIGA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDBDS6ZSEAACICAsqFX+ARliaWxBeewvn9Sq/ljw7fW2ZZbUtCogGSKrMJBG6B95QiAgPyVdlP9KV1voj+PUHLGIpRL5GRHeKYZgzPJ1fMAvjHgwQ0umUhAA==").unwrap();
        assert!(is_final(&unsigned_psbt).is_err());

        let part_signed_psbt = Psbt::from_str("cHNidP8BAIkBAAAAASWJHzxzyVORV/C3lAynKHVVL7+Rw7/Jj8U9fuvD24olAAAAAAD+////AiBOAAAAAAAAIgAgLzY9yE4jzTFJnHtTjkc+rFAtJ9NB7ENFQ1xLYoKsI1cfqgKVAAAAACIAIFsbWgDeLGU8EA+RGwBDIbcv4gaGG0tbEIhDvwXXa/E7LwEAAAABALUCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BALLAAD/////AgD5ApUAAAAAIgAgWxtaAN4sZTwQD5EbAEMhty/iBoYbS1sQiEO/Bddr8TsAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQErAPkClQAAAAAiACBbG1oA3ixlPBAPkRsAQyG3L+IGhhtLWxCIQ78F12vxOyICA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDSDBFAiEAnNPpu6wNX2HXYz8s2q5nXug4cWfvCGD3SSH2CNKm+yECIEQO7/URhUPsGoknMTE+GrYJf9Wxqn9QsuN9FGj32cQpAQEFR1IhA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDIQLKhV/gEZYmlsQXnsL5/Uqv5Y8O31tmWW1LQqIBkiqzCVKuIgYCyoVf4BGWJpbEF57C+f1Kr+WPDt9bZlltS0KiAZIqswkEboH3lCIGA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDBDS6ZSEAACICAsqFX+ARliaWxBeewvn9Sq/ljw7fW2ZZbUtCogGSKrMJBG6B95QiAgPyVdlP9KV1voj+PUHLGIpRL5GRHeKYZgzPJ1fMAvjHgwQ0umUhAA==").unwrap();
        assert!(is_final(&part_signed_psbt).is_err());

        let full_signed_psbt = Psbt::from_str("cHNidP8BAIkBAAAAASWJHzxzyVORV/C3lAynKHVVL7+Rw7/Jj8U9fuvD24olAAAAAAD+////AiBOAAAAAAAAIgAgLzY9yE4jzTFJnHtTjkc+rFAtJ9NB7ENFQ1xLYoKsI1cfqgKVAAAAACIAIFsbWgDeLGU8EA+RGwBDIbcv4gaGG0tbEIhDvwXXa/E7LwEAAAABALUCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BALLAAD/////AgD5ApUAAAAAIgAgWxtaAN4sZTwQD5EbAEMhty/iBoYbS1sQiEO/Bddr8TsAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQErAPkClQAAAAAiACBbG1oA3ixlPBAPkRsAQyG3L+IGhhtLWxCIQ78F12vxOwEFR1IhA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDIQLKhV/gEZYmlsQXnsL5/Uqv5Y8O31tmWW1LQqIBkiqzCVKuIgYCyoVf4BGWJpbEF57C+f1Kr+WPDt9bZlltS0KiAZIqswkEboH3lCIGA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDBDS6ZSEBBwABCNsEAEgwRQIhAJzT6busDV9h12M/LNquZ17oOHFn7whg90kh9gjSpvshAiBEDu/1EYVD7BqJJzExPhq2CX/Vsap/ULLjfRRo99nEKQFHMEQCIGoFCvJ2zPB7PCpznh4+1jsY03kMie49KPoPDdr7/T9TAiB3jV7wzR9BH11FSbi+8U8gSX95PrBlnp1lOBgTUIUw3QFHUiED8lXZT/Sldb6I/j1ByxiKUS+RkR3imGYMzydXzAL4x4MhAsqFX+ARliaWxBeewvn9Sq/ljw7fW2ZZbUtCogGSKrMJUq4AACICAsqFX+ARliaWxBeewvn9Sq/ljw7fW2ZZbUtCogGSKrMJBG6B95QiAgPyVdlP9KV1voj+PUHLGIpRL5GRHeKYZgzPJ1fMAvjHgwQ0umUhAA==").unwrap();
        assert!(is_final(&full_signed_psbt).is_ok());
    }

    #[cfg(feature = "compiler")]
    #[test]
    fn test_compile_taproot() {
        use super::{NUMS_UNSPENDABLE_KEY_HEX, handle_compile_subcommand};
        use bdk_wallet::bitcoin::Network;

        // Expected taproot descriptors with checksums (using NUMS key from constant)
        let expected_pk_a = format!("tr({},pk(A))#a2mlskt0", NUMS_UNSPENDABLE_KEY_HEX);
        let expected_and_ab = format!(
            "tr({},and_v(v:pk(A),pk(B)))#sfplm6kv",
            NUMS_UNSPENDABLE_KEY_HEX
        );

        // Test simple pk policy compilation to taproot
        let result = handle_compile_subcommand(
            Network::Testnet,
            "pk(A)".to_string(),
            "tr".to_string(),
            false,
        );
        assert!(result.is_ok());
        let json_string = result.unwrap();
        let json_result: serde_json::Value = serde_json::from_str(&json_string).unwrap();
        let descriptor = json_result.get("descriptor").unwrap().as_str().unwrap();
        assert_eq!(descriptor, expected_pk_a);

        // Test more complex policy
        let result = handle_compile_subcommand(
            Network::Testnet,
            "and(pk(A),pk(B))".to_string(),
            "tr".to_string(),
            false,
        );
        assert!(result.is_ok());
        let json_string = result.unwrap();
        let json_result: serde_json::Value = serde_json::from_str(&json_string).unwrap();
        let descriptor = json_result.get("descriptor").unwrap().as_str().unwrap();
        assert_eq!(descriptor, expected_and_ab);
    }

    #[cfg(feature = "compiler")]
    #[test]
    fn test_compile_invalid_cases() {
        use super::handle_compile_subcommand;
        use bdk_wallet::bitcoin::Network;

        // Test invalid policy syntax
        let result = handle_compile_subcommand(
            Network::Testnet,
            "invalid_policy".to_string(),
            "tr".to_string(),
            false,
        );
        assert!(result.is_err());

        // Test invalid script type
        let result = handle_compile_subcommand(
            Network::Testnet,
            "pk(A)".to_string(),
            "invalid_type".to_string(),
            false,
        );
        assert!(result.is_err());

        // Test empty policy
        let result =
            handle_compile_subcommand(Network::Testnet, "".to_string(), "tr".to_string(), false);
        assert!(result.is_err());

        // Test malformed policy with unmatched parentheses
        let result = handle_compile_subcommand(
            Network::Testnet,
            "pk(A".to_string(),
            "tr".to_string(),
            false,
        );
        assert!(result.is_err());

        // Test policy with unknown function
        let result = handle_compile_subcommand(
            Network::Testnet,
            "unknown_func(A)".to_string(),
            "tr".to_string(),
            false,
        );
        assert!(result.is_err());
    }
}
