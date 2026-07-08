pub mod config;
pub mod descriptor;
#[cfg(feature = "dns_payment")]
pub mod dns;
pub mod key;
pub mod offline;
pub mod online;
pub mod repl;

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
use crate::client::BlockchainClient;
use std::path::PathBuf;

use crate::{error::BDKCliError as Error, utils::output::FormatOutput};
use bdk_wallet::{Wallet, bitcoin::Network};

// The state for no wallet, no client.
pub struct Init;

/// Offline wallet operations.
/// Requires only a wallet.
pub struct OfflineOperations<'a> {
    pub wallet: &'a mut Wallet,
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
/// Online wallet operations.
/// Requires a wallet and a client.
pub struct OnlineOperations<'a> {
    pub wallet: &'a mut Wallet,
    pub client: &'a BlockchainClient,
    pub wallet_name: String,
}

/// The generic context
pub struct AppContext<S> {
    pub network: Network,
    pub datadir: PathBuf,
    pub state: S,
}

/// Construct for a specific state.
impl AppContext<Init> {
    pub fn new(network: Network, datadir: PathBuf) -> Self {
        Self {
            network,
            datadir,
            state: Init,
        }
    }
}

impl<'a> AppContext<OfflineOperations<'a>> {
    pub fn new_offline_wallet(network: Network, datadir: PathBuf, wallet: &'a mut Wallet) -> Self {
        Self {
            network,
            datadir,
            state: OfflineOperations { wallet },
        }
    }
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
impl<'a> AppContext<OnlineOperations<'a>> {
    pub fn new_online_wallet(
        network: Network,
        datadir: PathBuf,
        wallet: &'a mut Wallet,
        client: &'a BlockchainClient,
        wallet_name: String,
    ) -> Self {
        Self {
            network,
            datadir,
            state: OnlineOperations {
                wallet,
                client,
                wallet_name,
            },
        }
    }
}

pub trait AppCommand<C> {
    type Output: FormatOutput;

    fn execute(&self, ctx: &mut C) -> Result<Self::Output, Error>;
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf",
    feature = "dns_payment"
))]
pub trait AsyncAppCommand<C> {
    type Output: FormatOutput;

    async fn execute(&self, ctx: &mut C) -> Result<Self::Output, Error>;
}
