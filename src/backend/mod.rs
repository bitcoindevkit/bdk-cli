#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
use {
    crate::commands::{ClientType, WalletOpts},
    crate::error::BDKCliError as Error,
    bdk_wallet::Wallet,
    std::path::PathBuf,
};

#[cfg(feature = "cbf")]
use {
    crate::utils::trace_logger,
    bdk_kyoto::{BuilderExt, LightClient},
};

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
pub(crate) enum BlockchainClient {
    #[cfg(feature = "electrum")]
    Electrum {
        client: Box<bdk_electrum::BdkElectrumClient<bdk_electrum::electrum_client::Client>>,
        batch_size: usize,
    },
    #[cfg(feature = "esplora")]
    Esplora {
        client: Box<bdk_esplora::esplora_client::AsyncClient>,
        parallel_requests: usize,
    },
    #[cfg(feature = "rpc")]
    RpcClient {
        client: Box<bdk_bitcoind_rpc::bitcoincore_rpc::Client>,
    },

    #[cfg(feature = "cbf")]
    KyotoClient { client: Box<KyotoClientHandle> },
}

/// Handle for the Kyoto client after the node has been started.
/// Contains only the components needed for sync and broadcast operations.
#[cfg(feature = "cbf")]
pub struct KyotoClientHandle {
    pub requester: bdk_kyoto::Requester,
    pub update_subscriber: tokio::sync::Mutex<bdk_kyoto::UpdateSubscriber>,
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf",
))]
/// Create a new blockchain from the wallet configuration options.
pub(crate) fn new_blockchain_client(
    wallet_opts: &WalletOpts,
    _wallet: &Wallet,
    _datadir: PathBuf,
) -> Result<BlockchainClient, Error> {
    #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
    let url = &wallet_opts.url;
    let client = match wallet_opts.client_type {
        #[cfg(feature = "electrum")]
        ClientType::Electrum => {
            let client = bdk_electrum::electrum_client::Client::new(url)
                .map(bdk_electrum::BdkElectrumClient::new)?;
            BlockchainClient::Electrum {
                client: Box::new(client),
                batch_size: wallet_opts.batch_size,
            }
        }
        #[cfg(feature = "esplora")]
        ClientType::Esplora => {
            let client = bdk_esplora::esplora_client::Builder::new(url).build_async()?;
            BlockchainClient::Esplora {
                client: Box::new(client),
                parallel_requests: wallet_opts.parallel_requests,
            }
        }

        #[cfg(feature = "rpc")]
        ClientType::Rpc => {
            let auth = match &wallet_opts.cookie {
                Some(cookie) => bdk_bitcoind_rpc::bitcoincore_rpc::Auth::CookieFile(cookie.into()),
                None => bdk_bitcoind_rpc::bitcoincore_rpc::Auth::UserPass(
                    wallet_opts.basic_auth.0.clone(),
                    wallet_opts.basic_auth.1.clone(),
                ),
            };
            let client = bdk_bitcoind_rpc::bitcoincore_rpc::Client::new(url, auth)
                .map_err(|e| Error::Generic(e.to_string()))?;
            BlockchainClient::RpcClient {
                client: Box::new(client),
            }
        }

        #[cfg(feature = "cbf")]
        ClientType::Cbf => {
            let scan_type = bdk_kyoto::ScanType::Sync;
            let builder = bdk_kyoto::builder::Builder::new(_wallet.network());

            let light_client = builder
                .required_peers(wallet_opts.compactfilter_opts.conn_count)
                .data_dir(&_datadir)
                .build_with_wallet(_wallet, scan_type)?;

            let LightClient {
                requester,
                info_subscriber,
                warning_subscriber,
                update_subscriber,
                node,
            } = light_client;

            let subscriber = tracing_subscriber::FmtSubscriber::new();
            let _ = tracing::subscriber::set_global_default(subscriber);

            tokio::task::spawn(async move { node.run().await });
            tokio::task::spawn(
                async move { trace_logger(info_subscriber, warning_subscriber).await },
            );

            BlockchainClient::KyotoClient {
                client: Box::new(KyotoClientHandle {
                    requester,
                    update_subscriber: tokio::sync::Mutex::new(update_subscriber),
                }),
            }
        }
    };
    Ok(client)
}

// Handle Kyoto Client sync
#[cfg(feature = "cbf")]
pub async fn sync_kyoto_client(
    wallet: &mut Wallet,
    handle: &KyotoClientHandle,
) -> Result<(), Error> {
    if !handle.requester.is_running() {
        tracing::error!("Kyoto node is not running");
        return Err(Error::Generic("Kyoto node failed to start".to_string()));
    }
    tracing::info!("Kyoto node is running");

    let update = handle.update_subscriber.lock().await.update().await?;
    tracing::info!("Received update: applying to wallet");
    wallet
        .apply_update(update)
        .map_err(|e| Error::Generic(format!("Failed to apply update: {e}")))?;

    tracing::info!(
        "Chain tip: {}, Transactions: {}, Balance: {}",
        wallet.local_chain().tip().height(),
        wallet.transactions().count(),
        wallet.balance().total().to_sat()
    );

    tracing::info!(
        "Sync completed: tx_count={}, balance={}",
        wallet.transactions().count(),
        wallet.balance().total().to_sat()
    );

    Ok(())
}
