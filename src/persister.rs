use crate::error::BDKCliError;
use bdk_wallet::WalletPersister;

// Types of Persistence backends supported by bdk-cli
pub(crate) enum Persister {
    #[cfg(feature = "sqlite")]
    Connection(bdk_wallet::rusqlite::Connection),
    #[cfg(feature = "redb")]
    RedbStore(bdk_redb::Store),
}

impl WalletPersister for Persister {
    type Error = BDKCliError;

    fn initialize(persister: &mut Self) -> Result<bdk_wallet::ChangeSet, Self::Error> {
        match persister {
            #[cfg(feature = "sqlite")]
            Persister::Connection(connection) => {
                WalletPersister::initialize(connection).map_err(BDKCliError::from)
            }
            #[cfg(feature = "redb")]
            Persister::RedbStore(store) => {
                WalletPersister::initialize(store).map_err(BDKCliError::from)
            }
        }
    }

    fn persist(persister: &mut Self, changeset: &bdk_wallet::ChangeSet) -> Result<(), Self::Error> {
        match persister {
            #[cfg(feature = "sqlite")]
            Persister::Connection(connection) => {
                WalletPersister::persist(connection, changeset).map_err(BDKCliError::from)
            }
            #[cfg(feature = "redb")]
            Persister::RedbStore(store) => {
                WalletPersister::persist(store, changeset).map_err(BDKCliError::from)
            }
        }
    }
}
