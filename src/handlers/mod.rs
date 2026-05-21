pub mod config;
pub mod descriptor;
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

/// The shared environment for all commands
pub struct AppContext<'a> {
    pub network: Network,
    pub datadir: PathBuf,
    pub wallet: Option<&'a mut Wallet>,
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf"
    ))]
    pub client: Option<&'a BlockchainClient>,
}

impl<'a> AppContext<'a> {
    pub fn new(network: Network, datadir: PathBuf) -> Self {
        Self {
            network,
            datadir,
            wallet: None,
            #[cfg(any(
                feature = "electrum",
                feature = "esplora",
                feature = "rpc",
                feature = "cbf"
            ))]
            client: None,
        }
    }

    /// Attach a mutable wallet reference to the context.
    pub fn with_wallet(mut self, wallet: &'a mut Wallet) -> Self {
        self.wallet = Some(wallet);
        self
    }

    /// Attach a client reference to the context.
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf"
    ))]
    pub fn with_client(mut self, client: &'a BlockchainClient) -> Self {
        self.client = Some(client);
        self
    }
}

pub trait AsyncCommand {
    type Output: FormatOutput;
    async fn execute(&self, ctx: &mut AppContext<'_>) -> Result<Self::Output, Error>;
}

/// The command trait
pub trait AppCommand {
    type Output: FormatOutput;

    /// The execution logic
    fn execute(&self, ctx: &mut AppContext) -> Result<Self::Output, Error>;
}

// context for online and online
// => cli.rs
// handlers/{mod for commands}
// wallet subdir /
// wallet-offline and wallet-online (client mod)
