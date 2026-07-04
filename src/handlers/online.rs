use clap::Parser;

#[cfg(feature = "electrum")]
use crate::client::BlockchainClient::Electrum;
#[cfg(feature = "rpc")]
use crate::client::BlockchainClient::RpcClient;
#[cfg(feature = "cbf")]
use crate::client::{BlockchainClient::KyotoClient, sync_kyoto_client};
#[cfg(feature = "esplora")]
use {crate::client::BlockchainClient::Esplora, bdk_esplora::EsploraAsyncExt};
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
    crate::commands::OnlineWalletSubCommand,
    crate::error::BDKCliError as Error,
    crate::handlers::{AppContext, AsyncAppCommand, OnlineOperations},
    crate::payjoin::{PayjoinManager, ohttp::RelayManager},
    crate::utils::is_final,
    crate::utils::output::FormatOutput,
    crate::utils::print_wallet_events,
    crate::utils::types::{StatusResult, TransactionResult},
    bdk_wallet::bitcoin::{
        Psbt, Transaction, Txid, base64::Engine, base64::prelude::BASE64_STANDARD,
        consensus::Decodable, hex::FromHex,
    },
    std::sync::{Arc, Mutex},
};
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
impl OnlineWalletSubCommand {
    pub async fn execute(&self, ctx: &mut AppContext<OnlineOperations<'_>>) -> Result<(), Error> {
        match self {
            OnlineWalletSubCommand::FullScan(full_scan_command) => {
                let response: StatusResult = full_scan_command.execute(ctx).await?;
                response.write_out(std::io::stdout())
            }
            OnlineWalletSubCommand::Sync(sync_command) => {
                let response: StatusResult = sync_command.execute(ctx).await?;
                response.write_out(std::io::stdout())
            }
            OnlineWalletSubCommand::Broadcast(broadcast_command) => {
                let response: TransactionResult = broadcast_command.execute(ctx).await?;
                response.write_out(std::io::stdout())
            }
            OnlineWalletSubCommand::ReceivePayjoin(receive_payjoin_command) => {
                let response: StatusResult = receive_payjoin_command.execute(ctx).await?;
                response.write_out(std::io::stdout())
            }
            OnlineWalletSubCommand::SendPayjoin(send_payjoin_command) => {
                let response: StatusResult = send_payjoin_command.execute(ctx).await?;
                response.write_out(std::io::stdout())
            }
        }
    }
}

#[derive(Parser, Debug, PartialEq, Clone, Eq)]
pub struct FullScanCommand {
    /// Stop searching addresses for transactions after finding an unused gap of this length.
    #[arg(env = "STOP_GAP", long = "scan-stop-gap", default_value = "20")]
    stop_gap: usize,
    // #[clap(long, default_value = "5")]
    // pub parallel_request: usize,
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
impl AsyncAppCommand<AppContext<OnlineOperations<'_>>> for FullScanCommand {
    type Output = StatusResult;

    async fn execute(
        &self,
        ctx: &mut AppContext<OnlineOperations<'_>>,
    ) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;
        let client = ctx.state.client;

        #[cfg(any(feature = "electrum", feature = "esplora"))]
        let request = wallet.start_full_scan().inspect({
            let mut stderr = std::io::stderr();
            let mut once = HashSet::<KeychainKind>::new();
            move |k, spk_i, _| {
                if once.insert(k) {
                    eprint!("\nScanning keychain [{k:?}]");
                }
                eprint!(" {spk_i:<3}");
                stderr.flush().expect("must flush");
            }
        });

        match client {
            #[cfg(feature = "electrum")]
            Electrum { client, batch_size } => {
                client.populate_tx_cache(wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));
                let update = client.full_scan(request, self.stop_gap, *batch_size, false)?;
                let events = wallet.apply_update_events(update)?;
                print_wallet_events(&events);
            }

            #[cfg(feature = "esplora")]
            Esplora {
                client,
                parallel_requests,
            } => {
                let update = client
                    .full_scan(request, self.stop_gap, *parallel_requests)
                    .await
                    .map_err(|e| *e)?;
                let events = wallet.apply_update_events(update)?;
                print_wallet_events(&events);
            }
            #[cfg(feature = "rpc")]
            RpcClient { client } => {
                let blockchain_info = client.get_blockchain_info()?;

                let genesis_block = bdk_wallet::bitcoin::constants::genesis_block(wallet.network());
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

                let block_events = wallet.events_helper(|w| {
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

                        w.apply_block_connected_to(
                            &block_event.block,
                            block_event.block_height(),
                            block_event.connected_to(),
                        )?;
                    }
                    Ok::<_, Error>(())
                })?;
                print_wallet_events(&block_events);

                let mempool_txs = emitter.mempool()?;
                let mempool_events = wallet.apply_unconfirmed_txs_events(mempool_txs.update);
                print_wallet_events(&mempool_events);

                let evicted_events = wallet.apply_evicted_txs_events(mempool_txs.evicted);
                print_wallet_events(&evicted_events);
            }

            #[cfg(feature = "cbf")]
            KyotoClient { client } => {
                sync_kyoto_client(wallet, client).await?;
            }
        }
        Ok(StatusResult {
            message: "Full scan completed successfully.".to_string(),
        })
    }
}

#[derive(Parser, Debug, PartialEq, Eq, Clone)]
pub struct SyncCommand {}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
impl AsyncAppCommand<AppContext<OnlineOperations<'_>>> for SyncCommand {
    type Output = StatusResult;

    async fn execute(
        &self,
        ctx: &mut AppContext<OnlineOperations<'_>>,
    ) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;
        let client = ctx.state.client;
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
                let events = wallet.apply_update_events(update)?;
                print_wallet_events(&events);
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
                let events = wallet.apply_update_events(update)?;
                print_wallet_events(&events);
            }
            #[cfg(feature = "rpc")]
            RpcClient { client } => {
                let blockchain_info = client.get_blockchain_info()?;
                let wallet_cp = wallet.latest_checkpoint();

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

                let block_events = wallet.events_helper(|w| {
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

                        w.apply_block_connected_to(
                            &block_event.block,
                            block_event.block_height(),
                            block_event.connected_to(),
                        )?;
                    }
                    Ok::<_, Error>(())
                })?;
                print_wallet_events(&block_events);

                let mempool_txs = emitter.mempool()?;
                let mempool_events = wallet.apply_unconfirmed_txs_events(mempool_txs.update);
                print_wallet_events(&mempool_events);

                let evicted_events = wallet.apply_evicted_txs_events(mempool_txs.evicted);
                print_wallet_events(&evicted_events);
            }
            #[cfg(feature = "cbf")]
            KyotoClient { client } => sync_kyoto_client(wallet, client)
                .await
                .map_err(|e| Error::Generic(e.to_string()))?,
        }
        Ok(StatusResult {
            message: "Wallet synced successfully.".to_string(),
        })
    }
}

#[derive(Parser, Debug, Clone, PartialEq, Eq)]
pub struct BroadcastCommand {
    /// Sets the PSBT to sign.
    #[arg(
        env = "BASE64_PSBT",
        long = "psbt",
        required_unless_present = "tx",
        conflicts_with = "tx"
    )]
    psbt: Option<String>,
    /// Sets the raw transaction to broadcast.
    #[arg(
        env = "RAWTX",
        long = "tx",
        required_unless_present = "psbt",
        conflicts_with = "psbt"
    )]
    tx: Option<String>,
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
impl AsyncAppCommand<AppContext<OnlineOperations<'_>>> for BroadcastCommand {
    type Output = TransactionResult;

    async fn execute(
        &self,
        ctx: &mut AppContext<OnlineOperations<'_>>,
    ) -> Result<Self::Output, Error> {
        let client = ctx.state.client;

        let tx = match (&self.psbt, &self.tx) {
            (Some(psbt), None) => {
                let psbt = BASE64_STANDARD
                    .decode(psbt)
                    .map_err(|e| Error::Generic(e.to_string()))?;
                let psbt: Psbt = Psbt::deserialize(&psbt)?;
                is_final(&psbt)?;
                psbt.extract_tx()?
            }
            (None, Some(tx)) => {
                let tx_bytes = Vec::<u8>::from_hex(tx)?;
                Transaction::consensus_decode(&mut tx_bytes.as_slice())?
            }
            (Some(_), Some(_)) => {
                return Err(Error::Generic(
                    "Both `psbt` and `tx` options are not allowed".into(),
                ));
            }
            (None, None) => {
                return Err(Error::Generic(
                    "Must provide either a `psbt` or `tx` to broadcast".into(),
                ));
            }
        };

        let txid: Txid = client.broadcast(tx).await?;

        Ok(TransactionResult {
            txid: txid.to_string(),
        })
    }
}

#[derive(Parser, Debug, Clone, PartialEq, Eq)]
pub struct ReceivePayjoinCommand {
    /// Amount to be received in sats.
    #[arg(env = "PAYJOIN_AMOUNT", long = "amount", required = true)]
    amount: u64,
    /// Payjoin directory which will be used to store the PSBTs which are pending action
    /// from one of the parties.
    #[arg(env = "PAYJOIN_DIRECTORY", long = "directory", required = true)]
    directory: String,
    /// URL of the Payjoin OHTTP relay. Can be repeated multiple times to attempt the
    /// operation with multiple relays for redundancy.
    #[arg(env = "PAYJOIN_OHTTP_RELAY", long = "ohttp_relay", required = true)]
    ohttp_relay: Vec<String>,
    /// Maximum effective fee rate the receiver is willing to pay for their own input/output contributions.
    #[arg(env = "PAYJOIN_RECEIVER_MAX_FEE_RATE", long = "max_fee_rate")]
    max_fee_rate: Option<u64>,
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
impl AsyncAppCommand<AppContext<OnlineOperations<'_>>> for ReceivePayjoinCommand {
    type Output = StatusResult;

    async fn execute(
        &self,
        ctx: &mut AppContext<OnlineOperations<'_>>,
    ) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;
        let client = ctx.state.client;

        let relay_manager = Arc::new(Mutex::new(RelayManager::new()));
        let mut payjoin_manager = PayjoinManager::new(wallet, relay_manager);
        let result = payjoin_manager
            .receive_payjoin(
                self.amount,
                self.directory.clone(),
                self.max_fee_rate,
                self.ohttp_relay.clone(),
                client,
            )
            .await?;

        Ok(StatusResult { message: result })
    }
}

#[derive(Parser, Debug, Clone, PartialEq, Eq)]
pub struct SendPayjoinCommand {
    /// BIP 21 URI for the Payjoin.
    #[arg(env = "PAYJOIN_URI", long = "uri", required = true)]
    uri: String,
    /// URL of the Payjoin OHTTP relay. Can be repeated multiple times to attempt the
    /// operation with multiple relays for redundancy.
    #[arg(env = "PAYJOIN_OHTTP_RELAY", long = "ohttp_relay", required = true)]
    ohttp_relay: Vec<String>,
    /// Fee rate to use in sat/vbyte.
    #[arg(
        env = "PAYJOIN_SENDER_FEE_RATE",
        short = 'f',
        long = "fee_rate",
        required = true
    )]
    fee_rate: u64,
}
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
impl AsyncAppCommand<AppContext<OnlineOperations<'_>>> for SendPayjoinCommand {
    type Output = StatusResult;

    async fn execute(
        &self,
        ctx: &mut AppContext<OnlineOperations<'_>>,
    ) -> Result<Self::Output, Error> {
        let wallet = &mut ctx.state.wallet;
        let client = ctx.state.client;

        let relay_manager = Arc::new(Mutex::new(RelayManager::new()));
        let mut payjoin_manager = PayjoinManager::new(wallet, relay_manager);
        let result = payjoin_manager
            .send_payjoin(
                self.uri.clone(),
                self.fee_rate,
                self.ohttp_relay.clone(),
                client,
            )
            .await?;

        Ok(StatusResult { message: result })
    }
}
