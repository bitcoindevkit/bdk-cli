#[cfg(feature = "redb")]
use bdk_redb::Store as RedbStore;
use bdk_wallet::{Wallet, bitcoin::Network};
use std::{
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
};

use crate::{
    error::BDKCliError as Error,
    persister::new_wallet,
    utils::{load_wallet_config, prepare_wallet_db_dir},
};
#[cfg(any(feature = "sqlite", feature = "redb"))]
use {
    crate::persister::{DatabaseType, Persister, new_persisted_wallet},
    bdk_wallet::PersistedWallet,
};

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
use crate::client::{BlockchainClient, new_blockchain_client};

pub enum RuntimeWallet {
    Standard(Box<Wallet>),
    #[cfg(any(feature = "sqlite", feature = "redb"))]
    Persisted(Box<PersistedWallet<Persister>>, Box<Persister>),
}

impl Deref for RuntimeWallet {
    type Target = Wallet;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Standard(wallet) => wallet,
            #[cfg(any(feature = "sqlite", feature = "redb"))]
            Self::Persisted(wallet, _) => wallet,
        }
    }
}

impl DerefMut for RuntimeWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Standard(wallet) => wallet,
            #[cfg(any(feature = "sqlite", feature = "redb"))]
            Self::Persisted(wallet, _) => wallet,
        }
    }
}

impl RuntimeWallet {
    pub fn persist(&mut self) -> Result<(), Error> {
        match self {
            Self::Standard(_) => Ok(()),
            #[cfg(any(feature = "sqlite", feature = "redb"))]
            Self::Persisted(wallet, persister) => {
                wallet.persist(persister)?;
                Ok(())
            }
        }
    }
}

#[allow(unused)]
pub struct WalletRuntime {
    pub wallet_name: String,
    pub wallet_opts: crate::commands::WalletOpts,
    pub network: Network,
    pub home_dir: PathBuf,
    pub database_path: PathBuf,
}

impl WalletRuntime {
    pub fn load(home_dir: &Path, wallet_name: &str) -> Result<Self, Error> {
        let (wallet_opts, network) = load_wallet_config(home_dir, wallet_name)?;

        let database_path = prepare_wallet_db_dir(home_dir, wallet_name)?;

        Ok(Self {
            wallet_name: wallet_name.to_string(),
            wallet_opts,
            network,
            home_dir: home_dir.to_path_buf(),
            database_path,
        })
    }

    pub fn build_wallet(&self, require_db: bool) -> Result<RuntimeWallet, Error> {
        if !require_db {
            return Ok(RuntimeWallet::Standard(Box::new(new_wallet(
                self.network,
                &self.wallet_opts,
            )?)));
        }

        #[cfg(any(feature = "sqlite", feature = "redb"))]
        {
            let mut persister = self.create_persister()?;
            let wallet = new_persisted_wallet(self.network, &mut persister, &self.wallet_opts)?;
            Ok(RuntimeWallet::Persisted(
                Box::new(wallet),
                Box::new(persister),
            ))
        }

        #[cfg(not(any(feature = "sqlite", feature = "redb")))]
        {
            Ok(RuntimeWallet::Standard(Box::new(new_wallet(
                self.network,
                &self.wallet_opts,
            )?)))
        }
    }

    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf"
    ))]
    pub fn build_client(&self, wallet: &Wallet) -> Result<BlockchainClient, Error> {
        new_blockchain_client(&self.wallet_opts, wallet, self.database_path.clone())
    }

    #[cfg(any(feature = "sqlite", feature = "redb"))]
    fn create_persister(&self) -> Result<Persister, Error> {
        match &self.wallet_opts.database_type {
            #[cfg(feature = "sqlite")]
            DatabaseType::Sqlite => {
                let db_file = self.database_path.join("wallet.sqlite");

                let connection = bdk_wallet::rusqlite::Connection::open(db_file)?;

                Ok(Persister::Connection(connection))
            }

            #[cfg(feature = "redb")]
            DatabaseType::Redb => {
                let db = std::sync::Arc::new(bdk_redb::redb::Database::create(
                    self.home_dir.join("wallet.redb"),
                )?);

                let store = RedbStore::new(db, self.wallet_name.clone())?;

                Ok(Persister::RedbStore(store))
            }
        }
    }
}
