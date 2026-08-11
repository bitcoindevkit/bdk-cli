use crate::commands::WalletOpts;
use crate::error::BDKCliError as Error;
use crate::utils::descriptors::validate_descriptor_pair;
use crate::utils::path_exists;
#[cfg(feature = "redb")]
use bdk_redb::redb::TableHandle;
use bdk_wallet::Wallet;
use bdk_wallet::bitcoin::Network;
#[cfg(any(feature = "sqlite", feature = "redb"))]
use bdk_wallet::{KeychainKind, PersistedWallet, WalletPersister};
#[cfg(any(feature = "sqlite", feature = "redb"))]
use clap::ValueEnum;

#[cfg(any(feature = "sqlite", feature = "redb"))]
#[derive(Clone, ValueEnum, Debug, Eq, PartialEq)]
pub enum DatabaseType {
    /// Sqlite database
    #[cfg(feature = "sqlite")]
    Sqlite,
    /// Redb database
    #[cfg(feature = "redb")]
    Redb,
}

// Types of Persistence backends supported by bdk-cli
#[cfg(any(feature = "sqlite", feature = "redb"))]
pub(crate) enum Persister {
    #[cfg(feature = "sqlite")]
    Connection(bdk_wallet::rusqlite::Connection),
    #[cfg(feature = "redb")]
    RedbStore(bdk_redb::Store),
}

#[cfg(any(feature = "sqlite", feature = "redb"))]
impl WalletPersister for Persister {
    type Error = Error;

    fn initialize(persister: &mut Self) -> Result<bdk_wallet::ChangeSet, Self::Error> {
        match persister {
            #[cfg(feature = "sqlite")]
            Persister::Connection(connection) => {
                WalletPersister::initialize(connection).map_err(Error::from)
            }
            #[cfg(feature = "redb")]
            Persister::RedbStore(store) => WalletPersister::initialize(store).map_err(Error::from),
        }
    }

    fn persist(persister: &mut Self, changeset: &bdk_wallet::ChangeSet) -> Result<(), Self::Error> {
        match persister {
            #[cfg(feature = "sqlite")]
            Persister::Connection(connection) => {
                WalletPersister::persist(connection, changeset).map_err(Error::from)
            }
            #[cfg(feature = "redb")]
            Persister::RedbStore(store) => {
                WalletPersister::persist(store, changeset).map_err(Error::from)
            }
        }
    }
}

#[cfg(any(feature = "sqlite", feature = "redb"))]
pub(crate) fn new_persisted_wallet<P: WalletPersister>(
    network: Network,
    persister: &mut P,
    wallet_opts: &WalletOpts,
) -> Result<PersistedWallet<P>, Error>
where
    P::Error: std::fmt::Display,
{
    let ext_descriptor = wallet_opts.ext_descriptor.clone();
    let int_descriptor = wallet_opts.int_descriptor.clone();

    let ext_is_multipath =
        validate_descriptor_pair(&ext_descriptor, int_descriptor.as_deref(), network)?;

    let mut wallet_load_params = Wallet::load();
    wallet_load_params = if ext_is_multipath {
        // Load a wallet created from a two-path (BIP-389) descriptor.
        wallet_load_params.two_path_descriptor(ext_descriptor.clone())
    } else {
        let mut params =
            wallet_load_params.descriptor(KeychainKind::External, Some(ext_descriptor.clone()));
        if int_descriptor.is_some() {
            params = params.descriptor(KeychainKind::Internal, int_descriptor.clone());
        }
        params
    };
    wallet_load_params = wallet_load_params.extract_keys();

    let wallet_opt = wallet_load_params
        .check_network(network)
        .load_wallet(persister)
        .map_err(|e| Error::Generic(e.to_string()))?;

    let wallet = match wallet_opt {
        Some(wallet) => wallet,
        None => {
            let builder = if let Some(int_descriptor) = int_descriptor {
                Wallet::create(ext_descriptor, int_descriptor)
            } else if ext_is_multipath {
                Wallet::create_from_two_path_descriptor(ext_descriptor)
            } else {
                Wallet::create_single(ext_descriptor)
            };

            builder
                .network(network)
                .create_wallet(persister)
                .map_err(|e| Error::Generic(e.to_string()))?
        }
    };

    Ok(wallet)
}

#[cfg(feature = "redb")]
fn redb_wallet_data_exists(datadir: &std::path::Path, wallet_name: &str) -> Result<bool, Error> {
    let db_path = datadir.join("wallet.redb");
    if !path_exists(&db_path)? {
        return Ok(false);
    }

    let database =
        bdk_redb::redb::Database::open(&db_path).map_err(|source| Error::RedbInspection {
            wallet_name: wallet_name.to_owned(),
            db_path: db_path.clone(),
            source: Box::new(source.into()),
        })?;

    let read_transactions = database
        .begin_read()
        .map_err(|source| Error::RedbInspection {
            wallet_name: wallet_name.to_owned(),
            db_path: db_path.clone(),
            source: Box::new(source.into()),
        })?;

    let mut tables = read_transactions
        .list_tables()
        .map_err(|source| Error::RedbInspection {
            wallet_name: wallet_name.to_owned(),
            db_path: db_path.clone(),
            source: Box::new(source.into()),
        })?;

    // bdk_redb creates this per-wallet table in the first committed table batch for a
    // persisted wallet, so it is the sentinel for an initialized wallet store.
    let keychain_table_name = format!("{wallet_name}_keychain");

    Ok(tables.any(|table| table.name() == keychain_table_name.as_str()))
}

#[cfg(any(feature = "sqlite", feature = "redb"))]
pub(crate) fn wallet_data_exists(
    datadir: &std::path::Path,
    wallet_name: &str,
    database_type: &str,
) -> Result<bool, Error> {
    // Validate the persisted configuration before inspecting any data. In particular, an
    // unknown database type must never turn a delete into a silent success.
    match database_type {
        // Both markers are valid persisted formats even when this binary only
        // supports one of them; the opposite backend is checked conservatively below.
        "sqlite" | "redb" => {}
        _ => {
            return Err(Error::Generic(format!(
                "Unsupported database type: {database_type}"
            )));
        }
    }

    // A configuration can be changed to another backend without moving the original data, so
    // inspect every persistence backend marker rather than only the configured backend.
    let sqlite_path = datadir.join(wallet_name).join("wallet.sqlite");
    let sqlite_data_exists = path_exists(&sqlite_path)?;

    #[cfg(feature = "redb")]
    let redb_data_exists = {
        // Redb is shared by wallets, so only block deletion when this wallet has its sentinel
        // table.
        redb_wallet_data_exists(datadir, wallet_name)?
    };

    #[cfg(not(feature = "redb"))]
    let redb_data_exists = {
        // Without Redb support, conservatively treat the shared marker as data because this
        // build cannot inspect its wallet-specific tables.
        path_exists(&datadir.join("wallet.redb"))?
    };

    Ok(sqlite_data_exists || redb_data_exists)
}

#[cfg(not(any(feature = "sqlite", feature = "redb")))]
pub(crate) fn wallet_data_exists(
    datadir: &std::path::Path,
    wallet_name: &str,
) -> Result<bool, Error> {
    // The typed config intentionally omits `database_type` in this build, so inspect the raw
    // wallet entry as well. A config carrying that field may have been created by a build with a
    // database backend and must not be silently deleted just because its marker is absent.
    let config_path = datadir.join("config.toml");
    let config_content = std::fs::read_to_string(&config_path)
        .map_err(|error| Error::Generic(format!("Failed to read config file: {error}")))?;
    let raw_config: toml::Table = toml::from_str(&config_content)
        .map_err(|error| Error::Generic(format!("Failed to parse config file: {error}")))?;
    let database_type_present = raw_config
        .get("wallets")
        .and_then(toml::Value::as_table)
        .and_then(|wallets| wallets.get(wallet_name))
        .and_then(toml::Value::as_table)
        .is_some_and(|wallet| wallet.contains_key("database_type"));

    Ok(database_type_present
        || path_exists(&datadir.join(wallet_name).join("wallet.sqlite"))?
        || path_exists(&datadir.join("wallet.redb"))?)
}

pub(crate) fn new_wallet(network: Network, wallet_opts: &WalletOpts) -> Result<Wallet, Error> {
    let ext_descriptor = wallet_opts.ext_descriptor.clone();
    let int_descriptor = wallet_opts.int_descriptor.clone();

    let ext_is_multipath =
        validate_descriptor_pair(&ext_descriptor, int_descriptor.as_deref(), network)?;

    let builder = if let Some(int_descriptor) = int_descriptor {
        Wallet::create(ext_descriptor, int_descriptor)
    } else if ext_is_multipath {
        Wallet::create_from_two_path_descriptor(ext_descriptor)
    } else {
        Wallet::create_single(ext_descriptor)
    };

    let wallet = builder.network(network).create_wallet_no_persist()?;
    Ok(wallet)
}
