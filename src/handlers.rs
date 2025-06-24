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
#[cfg(feature = "cbf")]
use crate::utils::BlockchainClient::KyotoClient;
use crate::utils::*;
use bdk_wallet::bip39::{Language, Mnemonic};
use bdk_wallet::bitcoin::bip32::{DerivationPath, KeySource};
use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
use bdk_wallet::bitcoin::script::PushBytesBuf;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::bitcoin::{secp256k1::Secp256k1, Txid};
use bdk_wallet::bitcoin::{Amount, FeeRate, Psbt, Sequence};
use bdk_wallet::descriptor::Segwitv0;
use bdk_wallet::keys::bip39::WordCount;
#[cfg(feature = "sqlite")]
use bdk_wallet::rusqlite::Connection;
#[cfg(feature = "compiler")]
use bdk_wallet::{
    descriptor::{Descriptor, Legacy, Miniscript},
    miniscript::policy::Concrete,
};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};

use bdk_wallet::keys::DescriptorKey::Secret;
use bdk_wallet::keys::{DerivableKey, DescriptorKey, ExtendedKey, GeneratableKey, GeneratedKey};
use bdk_wallet::miniscript::miniscript;
use serde_json::json;
use std::collections::BTreeMap;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use std::collections::HashSet;
use std::convert::TryFrom;
#[cfg(any(feature = "repl", feature = "electrum", feature = "esplora"))]
use std::io::Write;
use std::str::FromStr;

#[cfg(feature = "electrum")]
use crate::utils::BlockchainClient::Electrum;
#[cfg(feature = "cbf")]
use bdk_kyoto::{Info, LightClient};
use bdk_wallet::bitcoin::base64::prelude::*;
#[cfg(feature = "cbf")]
use tokio::select;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
use {
    crate::commands::OnlineWalletSubCommand::*,
    bdk_wallet::bitcoin::{consensus::Decodable, hex::FromHex, Transaction},
    payjoin::{
        send::v2::{Sender, SenderBuilder},
        UriExt, Url,
    },
};
#[cfg(feature = "esplora")]
use {crate::utils::BlockchainClient::Esplora, bdk_esplora::EsploraAsyncExt};
#[cfg(feature = "rpc")]
use {
    crate::utils::BlockchainClient::RpcClient,
    bdk_bitcoind_rpc::{bitcoincore_rpc::RpcApi, Emitter},
    bdk_wallet::chain::{BlockId, CanonicalizationParams, CheckPoint},
};

/// Execute an offline wallet sub-command
///
/// Offline wallet sub-commands are described in [`OfflineWalletSubCommand`].
pub fn handle_offline_wallet_subcommand(
    wallet: &mut Wallet,
    wallet_opts: &WalletOpts,
    offline_subcommand: OfflineWalletSubCommand,
) -> Result<serde_json::Value, Error> {
    match offline_subcommand {
        NewAddress => {
            let addr = wallet.reveal_next_address(KeychainKind::External);
            if wallet_opts.verbose {
                Ok(json!({
                    "address": addr.address,
                    "index": addr.index
                }))
            } else {
                Ok(json!({
                    "address": addr.address,
                }))
            }
        }
        UnusedAddress => {
            let addr = wallet.next_unused_address(KeychainKind::External);
            if wallet_opts.verbose {
                Ok(json!({
                    "address": addr.address,
                    "index": addr.index
                }))
            } else {
                Ok(json!({
                    "address": addr.address,
                }))
            }
        }
        Unspent => Ok(serde_json::to_value(
            wallet.list_unspent().collect::<Vec<_>>(),
        )?),
        Transactions => {
            let transactions: Vec<_> = wallet
                .transactions()
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

            Ok(serde_json::to_value(transactions)?)
        }
        Balance => Ok(json!({"satoshi": wallet.balance()})),
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
                Ok(json!({"psbt": psbt_base64, "details": psbt}))
            } else {
                Ok(json!({"psbt": psbt_base64 }))
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

            Ok(json!({"psbt": psbt_base64 }))
        }
        Policies => {
            let external_policy = wallet.policies(KeychainKind::External)?;
            let internal_policy = wallet.policies(KeychainKind::Internal)?;

            Ok(json!({
                "external": external_policy,
                "internal": internal_policy,
            }))
        }
        PublicDescriptor => Ok(json!({
            "external": wallet.public_descriptor(KeychainKind::External).to_string(),
            "internal": wallet.public_descriptor(KeychainKind::Internal).to_string(),
        })),
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
                Ok(
                    json!({"psbt": &psbt_base64, "is_finalized": finalized, "serialized_psbt": &psbt}),
                )
            } else {
                Ok(json!({"psbt": &psbt_base64, "is_finalized": finalized,}))
            }
        }
        ExtractPsbt { psbt } => {
            let psbt_serialized = BASE64_STANDARD.decode(psbt)?;
            let psbt = Psbt::deserialize(&psbt_serialized)?;
            let raw_tx = psbt.extract_tx()?;
            Ok(json!({"raw_tx": serialize_hex(&raw_tx),}))
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
                Ok(
                    json!({ "psbt": BASE64_STANDARD.encode(psbt.serialize()), "is_finalized": finalized, "details": psbt}),
                )
            } else {
                Ok(
                    json!({ "psbt": BASE64_STANDARD.encode(psbt.serialize()), "is_finalized": finalized,}),
                )
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
            Ok(json!({ "psbt": BASE64_STANDARD.encode(final_psbt.serialize()) }))
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
    client: BlockchainClient,
    online_subcommand: OnlineWalletSubCommand,
) -> Result<serde_json::Value, Error> {
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
                        print!("\nScanning keychain [{:?}]", k);
                    }
                    print!(" {:<3}", spk_i);
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

                    let update = client.full_scan(request, _stop_gap, batch_size, false)?;
                    wallet.apply_update(update)?;
                }
                #[cfg(feature = "esplora")]
                Esplora {
                    client,
                    parallel_requests,
                } => {
                    let update = client
                        .full_scan(request, _stop_gap, parallel_requests)
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
                    let mut emitter =
                        Emitter::new(&*client, genesis_cp.clone(), genesis_cp.height(), [].iter());

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
                    wallet.apply_unconfirmed_txs(mempool_txs.new_txs.into_iter());
                }
                #[cfg(feature = "cbf")]
                KyotoClient { client } => {
                    sync_kyoto_client(wallet, client).await?;
                }
            }
            Ok(json!({}))
        }
        Sync => {
            #[cfg(any(feature = "electrum", feature = "esplora"))]
            let request = wallet
                .start_sync_with_revealed_spks()
                .inspect(|item, progress| {
                    let pc = (100 * progress.consumed()) as f32 / progress.total() as f32;
                    eprintln!("[ SCANNING {:03.0}% ] {}", pc, item);
                });
            match client {
                #[cfg(feature = "electrum")]
                Electrum { client, batch_size } => {
                    // Populate the electrum client's transaction cache so it doesn't re-download transaction we
                    // already have.
                    client
                        .populate_tx_cache(wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));

                    let update = client.sync(request, batch_size, false)?;
                    wallet.apply_update(update)?;
                }
                #[cfg(feature = "esplora")]
                Esplora {
                    client,
                    parallel_requests,
                } => {
                    let update = client
                        .sync(request, parallel_requests)
                        .await
                        .map_err(|e| *e)?;
                    wallet.apply_update(update)?;
                }
                #[cfg(feature = "rpc")]
                RpcClient { client } => {
                    let blockchain_info = client.get_blockchain_info()?;
                    let wallet_cp = wallet.latest_checkpoint();

                    // reload the last 200 blocks in case of a reorg
                    let emitter_height = wallet_cp.height().saturating_sub(200);
                    let mut emitter = Emitter::new(
                        &*client,
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
                    wallet.apply_unconfirmed_txs(mempool_txs.new_txs.into_iter());
                }
                #[cfg(feature = "cbf")]
                KyotoClient { client } => {
                    sync_kyoto_client(wallet, client).await?;
                }
            }
            Ok(json!({}))
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
            Ok(json!({ "txid": txid }))
        }
        SendPayjoin {
            uri,
            fee_rate,
            ohttp_relay,
        } => {
            let uri = payjoin::Uri::try_from(uri)
                .map_err(|e| Error::Generic(format!("Failed parsing to Payjoin URI: {}", e)))?;
            let uri = uri.require_network(wallet.network()).map_err(|e| {
                Error::Generic(format!(
                    "Failed setting the right network for the URI: {}",
                    e
                ))
            })?;
            let uri = uri
                .check_pj_supported()
                .map_err(|e| Error::Generic(format!("URI does not support Payjoin: {}", e)))?;

            let sats = uri
                .amount
                .ok_or_else(|| Error::Generic("Amount is not specified in the URI.".to_string()))?;

            let fee_rate =
                FeeRate::from_sat_per_vb(fee_rate).expect("Provided fee rate is not valid.");

            // Validating all OHTTP relays before we go ahead and potentially use them.
            let ohttp_relays = match ohttp_relay {
                None => Ok(vec![]),
                Some(relays) => relays.into_iter().map(|s| Url::parse(&s)).collect(),
            }
            .map_err(|e| {
                Error::Generic(format!("Failed to parse one or more OHTTP URls: {}", e))
            })?;

            // Build and sign the original PSBT which pays to the receiver.
            let mut original_psbt = {
                let mut tx_builder = wallet.build_tx();
                tx_builder
                    .add_recipient(uri.address.script_pubkey(), sats)
                    .fee_rate(fee_rate);

                tx_builder.finish().map_err(|e| {
                    Error::Generic(format!(
                        "Error occurred when building original Payjoin transaction: {}",
                        e
                    ))
                })?
            };
            if !wallet.sign(&mut original_psbt, SignOptions::default())? {
                return Err(Error::Generic(
                    "Failed to sign and finalize the original PSBT.".to_string(),
                ));
            }

            // TODO: Implement proper persisting after the design is finalized on the PDK end (see https://github.com/payjoin/rust-payjoin/pull/675).
            let mut persister = payjoin::persist::NoopPersister;

            // Using an original PSBT clone since we are going to use it later to re-introduce `..._utxo` fields to the Payjoin proposal.
            let new_sender = SenderBuilder::new(original_psbt.clone(), uri.clone())
                .build_recommended(fee_rate)
                .map_err(|e| {
                    Error::Generic(format!(
                        "Failed initializing Payjoin sender using the transaction fee rate: {}",
                        e
                    ))
                })?;
            let storage_token = new_sender.persist(&mut persister).map_err(|e| {
                Error::Generic(format!(
                    "Failed to generate the storage token with the receiver and persister: {}",
                    e
                ))
            })?;
            let req_ctx = Sender::load(storage_token, &persister)
                .map_err(|e| Error::Generic(format!("Failed to load the request context using the storage token and the persister {}", e)))?;

            // We will go with Payjoin v2 if there is at least one functional OHTTP relay passed as
            // an argument and the request-context extraction is successful. Otherwise, if there is
            // an error in finding a healthy relay or extracting the v2 context, we use v1.
            let v2_setup = if ohttp_relays.is_empty() {
                Err("No OHTTP relays provided.".to_string())
            } else {
                async {
                    for relay in ohttp_relays {
                        if let Ok(_) =
                            payjoin::io::fetch_ohttp_keys(relay.clone(), req_ctx.endpoint()).await
                        {
                            return Ok(relay);
                        }
                    }
                    Err("Unable to find a responsive OHTTP relay in the provided list.".to_string())
                }
                .await
                .and_then(|ohttp_relay| {
                    req_ctx
                        .extract_v2(ohttp_relay.clone())
                        .map(|(req, ctx)| (req, ctx, ohttp_relay))
                        .map_err(|_| "Failed to initialize a Payjoin v2 session.".to_string())
                })
            };

            let mut psbt = match v2_setup {
                Ok((req, ctx, ohttp_relay)) => {
                    println!(
                        "Sending using Payjoin v2 (Asynchronous) through the OHTTP relay {}",
                        ohttp_relay.to_string()
                    );
                    let response = send_payjoin_post_request(req)
                        .await
                        .map_err(|e| Error::Generic(format!("Failed to send request: {}", e)))?;

                    let v2_ctx = ctx
                        .process_response(&response.bytes().await?)
                        .map_err(|e| {
                            Error::Generic(format!("Failed to initialize v2 context: {}", e))
                        })?;

                    // Loop until the receiver sends back a Payjoin proposal
                    loop {
                        let (req, ohttp_ctx) =
                            v2_ctx.extract_req(ohttp_relay.clone()).map_err(|e| {
                                Error::Generic(format!(
                                    "Failed to extract request for polling: {}",
                                    e
                                ))
                            })?;

                        let response = send_payjoin_post_request(req).await.map_err(|e| {
                            Error::Generic(format!("Failed to send polling request: {}", e))
                        })?;

                        match v2_ctx.process_response(&response.bytes().await?, ohttp_ctx) {
                            Ok(Some(receiver_response_psbt)) => break receiver_response_psbt,
                            Ok(None) => {
                                println!("No response yet. Keep polling...")
                            }
                            Err(e) => {
                                Err(Error::Generic(format!(
                                    "Failed to process v2 response: {}",
                                    e
                                )))?;
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("Sending using Payjoin v1 (Synchronous). Reason: {e}");
                    let (req, ctx) = req_ctx.extract_v1();
                    let response = send_payjoin_post_request(req)
                        .await
                        .map_err(|e| Error::Generic(format!("Failed to send request: {}", e)))?;

                    // TODO: Remove `as_ref()` when the type change is merged in the next release
                    // through the commit https://github.com/payjoin/rust-payjoin/commit/e88750b0ae59e3583b2e3233c5bef191624af0a4.
                    ctx.process_response(&mut response.bytes().await?.as_ref())
                        .map_err(|e| {
                            Error::Generic(format!("Failed to send a Payjoin v1: {}", e))
                        })?
                }
            };

            /// Collects the inputs of a given transaction as (TxIn, Input) pairs and returns the iterator.
            fn input_pairs(
                psbt: &mut Psbt,
            ) -> impl Iterator<Item = (&payjoin::bitcoin::TxIn, &mut payjoin::bitcoin::psbt::Input)> + '_
            {
                psbt.unsigned_tx.input.iter().zip(psbt.inputs.iter_mut())
            }

            // We need to re-introduce the UTXO information of the original PSBT's inputs
            // back into the Payjoin proposal we received from the receiver. The receiver strips
            // the transaction of the information, so we need to add the `..._utxo` information back
            // before we can re-sign our input(s) into the transaction.
            let mut original_inputs_iter = input_pairs(&mut original_psbt).peekable();
            for (proposal_txin, proposal_psbt_input) in input_pairs(&mut psbt) {
                if let Some((orig_txin, orig_psbt_input)) = original_inputs_iter.peek() {
                    if proposal_txin.previous_output == orig_txin.previous_output {
                        proposal_psbt_input.witness_utxo = orig_psbt_input.witness_utxo.clone();
                        proposal_psbt_input.non_witness_utxo =
                            orig_psbt_input.non_witness_utxo.clone();
                        original_inputs_iter.next();
                    }
                }
            }

            if !wallet.sign(&mut psbt, SignOptions::default())? {
                return Err(Error::Generic(
                    "Failed to sign and finalize the Payjoin proposal PSBT.".to_string(),
                ));
            }

            let txid = broadcast_transaction(client, psbt.extract_tx_fee_rate_limit()?).await?;
            Ok(json!({ "txid": txid }))
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
            "Malformed PSBT, {} unsigned tx inputs and {} psbt inputs.",
            unsigned_tx_inputs, psbt_inputs
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
) -> Result<serde_json::Value, Error> {
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
            Ok(
                json!({ "mnemonic": phrase, "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }),
            )
        }
        KeySubCommand::Restore { mnemonic, password } => {
            let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)?;
            let xkey: ExtendedKey = (mnemonic, password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).ok_or_else(|| {
                Error::Generic("Privatekey info not found (should not happen)".to_string())
            })?;
            let fingerprint = xprv.fingerprint(&secp);

            Ok(json!({ "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }))
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
                Ok(json!({"xpub": desc_pubkey.to_string(), "xprv": desc_seckey.to_string()}))
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
) -> Result<serde_json::Value, Error> {
    let policy = Concrete::<String>::from_str(policy.as_str())?;
    let legacy_policy: Miniscript<String, Legacy> = policy
        .compile()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let segwit_policy: Miniscript<String, Segwitv0> = policy
        .compile()
        .map_err(|e| Error::Generic(e.to_string()))?;

    let descriptor = match script_type.as_str() {
        "sh" => Descriptor::new_sh(legacy_policy),
        "wsh" => Descriptor::new_wsh(segwit_policy),
        "sh-wsh" => Descriptor::new_sh_wsh(segwit_policy),
        _ => panic!("Invalid type"),
    }?;

    Ok(json!({"descriptor": descriptor.to_string()}))
}

/// The global top level handler.
pub(crate) async fn handle_command(cli_opts: CliOpts) -> Result<String, Error> {
    let network = cli_opts.network;

    let result = match cli_opts.subcommand {
        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "cbf",
            feature = "rpc"
        ))]
        CliSubCommand::Wallet {
            wallet_opts,
            subcommand: WalletSubCommand::OnlineWalletSubCommand(online_subcommand),
        } => {
            let network = cli_opts.network;
            let home_dir = prepare_home_dir(cli_opts.datadir)?;
            let wallet_name = &wallet_opts.wallet;
            let database_path = prepare_wallet_db_dir(wallet_name, &home_dir)?;
            #[cfg(feature = "sqlite")]
            let result = {
                let mut persister = match &wallet_opts.database_type {
                    #[cfg(feature = "sqlite")]
                    DatabaseType::Sqlite => {
                        let db_file = database_path.join("wallet.sqlite");
                        let connection = Connection::open(db_file)?;
                        log::debug!("Sqlite database opened successfully");
                        connection
                    }
                };

                let mut wallet = new_persisted_wallet(network, &mut persister, &wallet_opts)?;
                let blockchain_client =
                    new_blockchain_client(&wallet_opts, &wallet, database_path)?;

                let result = handle_online_wallet_subcommand(
                    &mut wallet,
                    blockchain_client,
                    online_subcommand,
                )
                .await?;
                wallet.persist(&mut persister)?;
                result
            };
            #[cfg(not(any(feature = "sqlite")))]
            let result = {
                let wallet = new_wallet(network, &wallet_opts)?;
                let blockchain_client =
                    crate::utils::new_blockchain_client(&wallet_opts, &wallet, database_path)?;
                let mut wallet = new_wallet(network, &wallet_opts)?;
                handle_online_wallet_subcommand(&mut wallet, blockchain_client, online_subcommand)
                    .await?
            };
            serde_json::to_string_pretty(&result)
        }
        CliSubCommand::Wallet {
            wallet_opts,
            subcommand: WalletSubCommand::OfflineWalletSubCommand(offline_subcommand),
        } => {
            let network = cli_opts.network;
            #[cfg(feature = "sqlite")]
            let result = {
                let home_dir = prepare_home_dir(cli_opts.datadir)?;
                let wallet_name = &wallet_opts.wallet;
                let database_path = prepare_wallet_db_dir(wallet_name, &home_dir)?;
                let mut persister = match &wallet_opts.database_type {
                    #[cfg(feature = "sqlite")]
                    DatabaseType::Sqlite => {
                        let db_file = database_path.join("wallet.sqlite");
                        let connection = Connection::open(db_file)?;
                        log::debug!("Sqlite database opened successfully");
                        connection
                    }
                };

                let mut wallet = new_persisted_wallet(network, &mut persister, &wallet_opts)?;
                let result = handle_offline_wallet_subcommand(
                    &mut wallet,
                    &wallet_opts,
                    offline_subcommand,
                )?;
                wallet.persist(&mut persister)?;
                result
            };
            #[cfg(not(any(feature = "sqlite")))]
            let result = {
                let mut wallet = new_wallet(network, &wallet_opts)?;
                handle_offline_wallet_subcommand(&mut wallet, &wallet_opts, offline_subcommand)?
            };
            serde_json::to_string_pretty(&result)
        }
        CliSubCommand::Key {
            subcommand: key_subcommand,
        } => {
            let result = handle_key_subcommand(network, key_subcommand)?;
            serde_json::to_string_pretty(&result)
        }
        #[cfg(feature = "compiler")]
        CliSubCommand::Compile {
            policy,
            script_type,
        } => {
            let result = handle_compile_subcommand(network, policy, script_type)?;
            serde_json::to_string_pretty(&result)
        }
        #[cfg(feature = "repl")]
        CliSubCommand::Repl { wallet_opts } => {
            let network = cli_opts.network;
            #[cfg(feature = "sqlite")]
            let (mut wallet, mut persister) = {
                let wallet_name = &wallet_opts.wallet;

                let home_dir = prepare_home_dir(cli_opts.datadir.clone())?;

                let database_path = prepare_wallet_db_dir(wallet_name, &home_dir)?;

                let mut persister = match &wallet_opts.database_type {
                    #[cfg(feature = "sqlite")]
                    DatabaseType::Sqlite => {
                        let db_file = database_path.join("wallet.sqlite");
                        let connection = Connection::open(db_file)?;
                        log::debug!("Sqlite database opened successfully");
                        connection
                    }
                };
                let wallet = new_persisted_wallet(network, &mut persister, &wallet_opts)?;
                (wallet, persister)
            };
            #[cfg(not(any(feature = "sqlite")))]
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
                    &wallet_opts,
                    line,
                    database_path.clone(),
                )
                .await;
                #[cfg(feature = "sqlite")]
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
    };
    result.map_err(|e| e.into())
}

#[cfg(feature = "repl")]
async fn respond(
    network: Network,
    wallet: &mut Wallet,
    wallet_opts: &WalletOpts,
    line: &str,
    _datadir: std::path::PathBuf,
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
            let value = handle_online_wallet_subcommand(wallet, blockchain, online_subcommand)
                .await
                .map_err(|e| e.to_string())?;
            Some(value)
        }
        ReplSubCommand::Wallet {
            subcommand: WalletSubCommand::OfflineWalletSubCommand(offline_subcommand),
        } => {
            let value = handle_offline_wallet_subcommand(wallet, wallet_opts, offline_subcommand)
                .map_err(|e| e.to_string())?;
            Some(value)
        }
        ReplSubCommand::Key { subcommand } => {
            let value = handle_key_subcommand(network, subcommand).map_err(|e| e.to_string())?;
            Some(value)
        }
        ReplSubCommand::Exit => None,
    };
    if let Some(value) = response {
        let value = serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?;
        writeln!(std::io::stdout(), "{}", value).map_err(|e| e.to_string())?;
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
/// Broadcasts a given transaction using the blockchain client.
async fn broadcast_transaction(client: BlockchainClient, tx: Transaction) -> Result<Txid, Error> {
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
            let LightClient {
                requester,
                mut log_subscriber,
                mut info_subscriber,
                mut warning_subscriber,
                update_subscriber: _,
                node,
            } = *client;

            let subscriber = tracing_subscriber::FmtSubscriber::new();
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|e| Error::Generic(format!("SetGlobalDefault error: {}", e)))?;

            tokio::task::spawn(async move { node.run().await });
            tokio::task::spawn(async move {
                select! {
                    log = log_subscriber.recv() => {
                        if let Some(log) = log {
                            tracing::info!("{log}");
                        }
                    },
                    warn = warning_subscriber.recv() => {
                        if let Some(warn) = warn {
                            tracing::warn!("{warn}");
                        }
                    }
                }
            });
            let txid = tx.compute_txid();
            requester
                .broadcast_random(tx.clone())
                .map_err(|e| Error::Generic(format!("{}", e)))?;
            tokio::time::timeout(tokio::time::Duration::from_secs(30), async move {
                while let Some(info) = info_subscriber.recv().await {
                    match info {
                        Info::TxGossiped(wtxid) => {
                            tracing::info!("Successfully broadcast WTXID: {wtxid}");
                            break;
                        }
                        Info::ConnectionsMet => {
                            tracing::info!("Rebroadcasting to new connections");
                            requester.broadcast_random(tx.clone()).unwrap();
                        }
                        _ => tracing::info!("{info}"),
                    }
                }
            })
            .await
            .map_err(|_| {
                tracing::warn!("Broadcast was unsuccessful");
                Error::Generic("Transaction broadcast timed out after 30 seconds".into())
            })?;
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

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
#[cfg(test)]
mod test {
    use bdk_wallet::bitcoin::Psbt;

    use super::is_final;
    use std::str::FromStr;

    #[test]
    fn test_psbt_is_final() {
        let unsigned_psbt = Psbt::from_str("cHNidP8BAIkBAAAAASWJHzxzyVORV/C3lAynKHVVL7+Rw7/Jj8U9fuvD24olAAAAAAD+////AiBOAAAAAAAAIgAgLzY9yE4jzTFJnHtTjkc+rFAtJ9NB7ENFQ1xLYoKsI1cfqgKVAAAAACIAIFsbWgDeLGU8EA+RGwBDIbcv4gaGG0tbEIhDvwXXa/E7LwEAAAABALUCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BALLAAD/////AgD5ApUAAAAAIgAgWxtaAN4sZTwQD5EbAEMhty/iBoYbS1sQiEO/Bddr8TsAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQErAPkClQAAAAAiACBbG1oA3ixlPBAPkRsAQyG3L+IGhhtLWxCIQ78F12vxOwEFR1IhA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDIQLKhV/gEZYmlsQXnsL5/Uqv5Y8O31tmWW1LQqIBkiqzCVKuIgYCyoVf4BGWJpbEF57C+f1Kr+WPDt9bZlltS0KiAZIqswkEboH3lCIGA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDBDS6ZSEAACICAsqFX+ARliaWxBeewvn9Sq/ljw7fW2ZZbUtCogGSKrMJBG6B95QiAgPyVdlP9KV1voj+PUHLGIpRL5GRHeKYZgzPJ1fMAvjHgwQ0umUhAA==").unwrap();
        assert!(is_final(&unsigned_psbt).is_err());

        let part_signed_psbt = Psbt::from_str("cHNidP8BAIkBAAAAASWJHzxzyVORV/C3lAynKHVVL7+Rw7/Jj8U9fuvD24olAAAAAAD+////AiBOAAAAAAAAIgAgLzY9yE4jzTFJnHtTjkc+rFAtJ9NB7ENFQ1xLYoKsI1cfqgKVAAAAACIAIFsbWgDeLGU8EA+RGwBDIbcv4gaGG0tbEIhDvwXXa/E7LwEAAAABALUCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BALLAAD/////AgD5ApUAAAAAIgAgWxtaAN4sZTwQD5EbAEMhty/iBoYbS1sQiEO/Bddr8TsAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQErAPkClQAAAAAiACBbG1oA3ixlPBAPkRsAQyG3L+IGhhtLWxCIQ78F12vxOyICA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDSDBFAiEAnNPpu6wNX2HXYz8s2q5nXug4cWfvCGD3SSH2CNKm+yECIEQO7/URhUPsGoknMTE+GrYJf9Wxqn9QsuN9FGj32cQpAQEFR1IhA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDIQLKhV/gEZYmlsQXnsL5/Uqv5Y8O31tmWW1LQqIBkiqzCVKuIgYCyoVf4BGWJpbEF57C+f1Kr+WPDt9bZlltS0KiAZIqswkEboH3lCIGA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDBDS6ZSEAACICAsqFX+ARliaWxBeewvn9Sq/ljw7fW2ZZbUtCogGSKrMJBG6B95QiAgPyVdlP9KV1voj+PUHLGIpRL5GRHeKYZgzPJ1fMAvjHgwQ0umUhAA==").unwrap();
        assert!(is_final(&part_signed_psbt).is_err());

        let full_signed_psbt = Psbt::from_str("cHNidP8BAIkBAAAAASWJHzxzyVORV/C3lAynKHVVL7+Rw7/Jj8U9fuvD24olAAAAAAD+////AiBOAAAAAAAAIgAgLzY9yE4jzTFJnHtTjkc+rFAtJ9NB7ENFQ1xLYoKsI1cfqgKVAAAAACIAIFsbWgDeLGU8EA+RGwBDIbcv4gaGG0tbEIhDvwXXa/E7LwEAAAABALUCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BALLAAD/////AgD5ApUAAAAAIgAgWxtaAN4sZTwQD5EbAEMhty/iBoYbS1sQiEO/Bddr8TsAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQErAPkClQAAAAAiACBbG1oA3ixlPBAPkRsAQyG3L+IGhhtLWxCIQ78F12vxOwEFR1IhA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDIQLKhV/gEZYmlsQXnsL5/Uqv5Y8O31tmWW1LQqIBkiqzCVKuIgYCyoVf4BGWJpbEF57C+f1Kr+WPDt9bZlltS0KiAZIqswkEboH3lCIGA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDBDS6ZSEBBwABCNsEAEgwRQIhAJzT6busDV9h12M/LNquZ17oOHFn7whg90kh9gjSpvshAiBEDu/1EYVD7BqJJzExPhq2CX/Vsap/ULLjfRRo99nEKQFHMEQCIGoFCvJ2zPB7PCpznh4+1jsY03kMie49KPoPDdr7/T9TAiB3jV7wzR9BH11FSbi+8U8gSX95PrBlnp1lOBgTUIUw3QFHUiED8lXZT/Sldb6I/j1ByxiKUS+RkR3imGYMzydXzAL4x4MhAsqFX+ARliaWxBeewvn9Sq/ljw7fW2ZZbUtCogGSKrMJUq4AACICAsqFX+ARliaWxBeewvn9Sq/ljw7fW2ZZbUtCogGSKrMJBG6B95QiAgPyVdlP9KV1voj+PUHLGIpRL5GRHeKYZgzPJ1fMAvjHgwQ0umUhAA==").unwrap();
        assert!(is_final(&full_signed_psbt).is_ok());
    }
}
