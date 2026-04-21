#[cfg(feature = "electrum")]
use crate::backend::BlockchainClient::Electrum;
#[cfg(feature = "cbf")]
use crate::backend::BlockchainClient::KyotoClient;
#[cfg(feature = "rpc")]
use crate::backend::BlockchainClient::RpcClient;
#[cfg(feature = "esplora")]
use {crate::backend::BlockchainClient::Esplora, bdk_esplora::EsploraAsyncExt};
#[cfg(feature = "rpc")]
use {
    bdk_bitcoind_rpc::{Emitter, NO_EXPECTED_MEMPOOL_TXS, bitcoincore_rpc::RpcApi},
    bdk_wallet::chain::{BlockId, CanonicalizationParams, CheckPoint},
};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use {bdk_wallet::KeychainKind, std::collections::HashSet, std::io::Write};

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
use {
    crate::backend::{BlockchainClient, sync_kyoto_client},
    crate::commands::OnlineWalletSubCommand::*,
    crate::error::BDKCliError as Error,
    crate::payjoin::PayjoinManager,
    crate::payjoin::ohttp::RelayManager,
    crate::utils::is_final,
    bdk_wallet::Wallet,
    bdk_wallet::bitcoin::{
        Psbt, Transaction, Txid, base64::Engine, base64::prelude::BASE64_STANDARD,
        consensus::Decodable, hex::FromHex,
    },
    serde_json::json,
    std::sync::{Arc, Mutex},
};

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
    online_subcommand: crate::commands::OnlineWalletSubCommand,
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
                        client.as_ref(),
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

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
/// Syncs a given wallet using the blockchain client.
pub async fn sync_wallet(client: &BlockchainClient, wallet: &mut Wallet) -> Result<(), Error> {
    // #[cfg(any(feature = "electrum", feature = "esplora"))]
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
                client.as_ref(),
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
