use std::collections::HashMap;

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
use crate::client::ClientType;
use crate::commands::{WalletOpts, WalletsSubCommand};
use crate::config::{WalletConfig, WalletConfigInner};
use crate::error::BDKCliError as Error;
use crate::handlers::Init;
use crate::handlers::{AppCommand, AppContext};
#[cfg(any(feature = "sqlite", feature = "redb"))]
use crate::persister::DatabaseType;
use crate::utils::descriptors::validate_descriptor_pair;
use crate::utils::output::FormatOutput;
use crate::utils::types::{StatusResult, WalletsListResult};
#[cfg(feature = "redb")]
use bdk_redb::redb::TableHandle;
use bdk_wallet::bitcoin::Network;
use clap::Args;

#[derive(Args, Debug, Clone, PartialEq)]
pub struct SaveConfigCommand {
    /// Overwrite existing wallet configuration if it exists.
    #[arg(short = 'f', long = "force", default_value_t = false)]
    pub(crate) force: bool,

    #[command(flatten)]
    pub(crate) wallet_opts: WalletOpts,
}

impl AppCommand<AppContext<Init>> for SaveConfigCommand {
    type Output = StatusResult;

    fn execute(&self, ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        if ctx.network == Network::Bitcoin {
            eprintln!("WARNING: Configuring for Bitcoin MAINNET. Experimental software!");
        }

        let wallet_name = match &self.wallet_opts.wallet {
            Some(wallet) => wallet,
            None => return Err(Error::Generic("wallet is required".to_owned())),
        };

        let ext_descriptor = self.wallet_opts.ext_descriptor.clone();
        let int_descriptor = self.wallet_opts.int_descriptor.clone();

        validate_descriptor_pair(&ext_descriptor, int_descriptor.as_deref(), ctx.network)?;

        if ext_descriptor.contains("xprv") || ext_descriptor.contains("tprv") {
            eprintln!(
                "WARNING: Your external descriptor contains PRIVATE KEYS.
             Private keys will be saved in PLAINTEXT in the config file.
             This is a security risk. Consider using public descriptors instead.\n"
            );
        }

        if let Some(ref internal_desc) = int_descriptor
            && (internal_desc.contains("xprv") || internal_desc.contains("tprv"))
        {
            eprintln!(
                "WARNING: Your internal descriptor contains PRIVATE KEYS.
                 Private keys will be saved in PLAINTEXT in the config file.
                 This is a security risk. Consider using public descriptors instead.\n"
            );
        }

        let mut config = WalletConfig::load(&ctx.datadir)?.unwrap_or(WalletConfig {
            wallets: HashMap::new(),
        });

        if config.wallets.contains_key(wallet_name.as_str()) && !self.force {
            return Err(Error::Generic(format!(
                "Wallet '{}' already exists. Use --force to overwrite.",
                wallet_name
            )));
        };

        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "rpc",
            feature = "cbf"
        ))]
        let client_type = match self.wallet_opts.client_type.clone() {
            #[cfg(feature = "electrum")]
            ClientType::Electrum => "electrum".to_string(),
            #[cfg(feature = "esplora")]
            ClientType::Esplora => "esplora".to_string(),
            #[cfg(feature = "rpc")]
            ClientType::Rpc => "rpc".to_string(),
            #[cfg(feature = "cbf")]
            ClientType::Cbf => "cbf".to_string(),
        };

        let wallet_config = WalletConfigInner {
            wallet: wallet_name.clone(),
            network: ctx.network.to_string(),
            ext_descriptor: self.wallet_opts.ext_descriptor.clone(),
            int_descriptor: self.wallet_opts.int_descriptor.clone(),
            #[cfg(any(feature = "sqlite", feature = "redb"))]
            database_type: match self.wallet_opts.database_type {
                #[cfg(feature = "sqlite")]
                DatabaseType::Sqlite => "sqlite".to_string(),
                #[cfg(feature = "redb")]
                DatabaseType::Redb => "redb".to_string(),
            },

            #[cfg(any(
                feature = "electrum",
                feature = "esplora",
                feature = "rpc",
                feature = "cbf"
            ))]
            client_type: Some(client_type),

            #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
            server_url: Some(self.wallet_opts.url.clone()),

            #[cfg(feature = "rpc")]
            rpc_user: Some(self.wallet_opts.basic_auth.0.clone()),
            #[cfg(feature = "rpc")]
            rpc_password: Some(self.wallet_opts.basic_auth.1.clone()),
            #[cfg(feature = "electrum")]
            batch_size: Some(self.wallet_opts.batch_size),
            #[cfg(feature = "esplora")]
            parallel_requests: Some(self.wallet_opts.parallel_requests),
            #[cfg(feature = "rpc")]
            cookie: self.wallet_opts.cookie.clone(),

            #[cfg(any(feature = "electrum", feature = "esplora"))]
            proxy: self.wallet_opts.proxy_opts.proxy.clone(),
            #[cfg(any(feature = "electrum", feature = "esplora"))]
            proxy_auth: self
                .wallet_opts
                .proxy_opts
                .proxy_auth
                .as_ref()
                .map(|(u, p)| format!("{u}:{p}")),
            #[cfg(any(feature = "electrum", feature = "esplora"))]
            proxy_retries: Some(self.wallet_opts.proxy_opts.retries),
            #[cfg(any(feature = "electrum", feature = "esplora"))]
            proxy_timeout: self.wallet_opts.proxy_opts.timeout,
            #[cfg(feature = "cbf")]
            conn_count: Some(self.wallet_opts.compactfilter_opts.conn_count),
        };

        config.wallets.insert(wallet_name.clone(), wallet_config);
        config
            .save(&ctx.datadir)
            .map_err(|error| Error::Generic(error.to_string()))?;

        Ok(StatusResult {
            message: format!(
                "Wallet '{}' initialized successfully in {:?}",
                wallet_name,
                ctx.datadir.join("config.toml")
            ),
        })
    }
}

#[derive(Args, Debug, Clone, PartialEq)]
pub struct ListWalletsCommand;

impl AppCommand<AppContext<Init>> for ListWalletsCommand {
    type Output = WalletsListResult;

    fn execute(&self, ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        let config = match WalletConfig::load(&ctx.datadir)? {
            Some(cfg) => cfg,
            None => return Err(Error::Generic("No wallets configured yet.".into())),
        };

        Ok(WalletsListResult(config.wallets))
    }
}

fn wallet_data_path_exists(path: &std::path::Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::Generic(format!(
            "Failed to inspect wallet data at {path:?}: {error}"
        ))),
    }
}

#[cfg(any(feature = "sqlite", feature = "redb"))]
fn wallet_data_exists(
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
    let sqlite_data_exists = wallet_data_path_exists(&sqlite_path)?;

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
        wallet_data_path_exists(&datadir.join("wallet.redb"))?
    };

    Ok(sqlite_data_exists || redb_data_exists)
}

#[cfg(feature = "redb")]
fn redb_wallet_data_exists(datadir: &std::path::Path, wallet_name: &str) -> Result<bool, Error> {
    let db_path = datadir.join("wallet.redb");
    if !wallet_data_path_exists(&db_path)? {
        return Ok(false);
    }

    let database = bdk_redb::redb::Database::open(&db_path).map_err(|error| {
        Error::Generic(format!(
            "Failed to open Redb database at {db_path:?}: {error}"
        ))
    })?;

    let read_transactions = database
        .begin_read()
        .map_err(|error| Error::Generic(error.to_string()))?;

    let mut tables = read_transactions.list_tables().map_err(|error| {
        Error::Generic(format!(
            "Failed to list tables in Redb database at {db_path:?}: {error}"
        ))
    })?;

    // bdk_redb creates this per-wallet table in the first committed table batch for a
    // persisted wallet, so it is the sentinel for an initialized wallet store.
    let keychain_table_name = format!("{wallet_name}_keychain");

    Ok(tables.any(|table| table.name() == keychain_table_name.as_str()))
}

#[cfg(not(any(feature = "sqlite", feature = "redb")))]
fn wallet_data_exists(datadir: &std::path::Path, wallet_name: &str) -> Result<bool, Error> {
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
        || wallet_data_path_exists(&datadir.join(wallet_name).join("wallet.sqlite"))?
        || wallet_data_path_exists(&datadir.join("wallet.redb"))?)
}

fn remove_wallet_from_config_file(
    datadir: &std::path::Path,
    wallet_name: &str,
) -> Result<(), Error> {
    let config_path = datadir.join("config.toml");
    let config_content = std::fs::read_to_string(&config_path)
        .map_err(|error| Error::Generic(format!("Failed to read config file: {error}")))?;
    let mut raw_config: toml::Table = toml::from_str(&config_content)
        .map_err(|error| Error::Generic(format!("Failed to parse config file: {error}")))?;
    let wallets = raw_config
        .get_mut("wallets")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| Error::Generic("Config does not contain a wallets table".into()))?;

    if wallets.remove(wallet_name).is_none() {
        return Err(Error::Generic(format!(
            "Wallet '{wallet_name}' not found in config"
        )));
    }

    let updated_config = toml::to_string_pretty(&raw_config)
        .map_err(|error| Error::Generic(format!("Failed to serialize config: {error}")))?;
    std::fs::write(&config_path, updated_config)
        .map_err(|error| Error::Generic(format!("Failed to write config file: {error}")))
}

#[derive(Args, Debug, Clone, PartialEq)]
pub struct DeleteWalletConfigCommand {
    /// Name of the saved wallet configuration to delete.
    #[arg(value_name = "WALLET_NAME")]
    pub(crate) wallet_name: String,
}

impl AppCommand<AppContext<Init>> for DeleteWalletConfigCommand {
    type Output = StatusResult;

    fn execute(&self, ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        let config = match WalletConfig::load(&ctx.datadir)? {
            Some(config) => config,
            None => return Err(Error::Generic("No wallets configured yet.".into())),
        };

        #[cfg(any(feature = "sqlite", feature = "redb"))]
        let data_exists = {
            let wallet_config = config.wallets.get(&self.wallet_name).ok_or_else(|| {
                Error::Generic(format!("Wallet '{}' not found in config", self.wallet_name))
            })?;

            wallet_data_exists(
                &ctx.datadir,
                &self.wallet_name,
                &wallet_config.database_type,
            )?
        };

        #[cfg(not(any(feature = "sqlite", feature = "redb")))]
        let data_exists = {
            if !config.wallets.contains_key(&self.wallet_name) {
                return Err(Error::Generic(format!(
                    "Wallet '{}' not found in config",
                    self.wallet_name
                )));
            }

            wallet_data_exists(&ctx.datadir, &self.wallet_name)?
        };

        if data_exists {
            return Err(Error::Generic(format!(
                "Wallet data exists for configuration '{}'; the saved configuration was not deleted",
                self.wallet_name
            )));
        }

        if config.wallets.len() == 1 {
            let config_path = ctx.datadir.join("config.toml");
            std::fs::remove_file(&config_path).map_err(|error| {
                Error::Generic(format!(
                    "Failed to remove config at {config_path:?}: {error}"
                ))
            })?;
        } else {
            remove_wallet_from_config_file(&ctx.datadir, &self.wallet_name)?;
        }

        Ok(StatusResult {
            message: format!(
                "Wallet configuration '{}' deleted successfully",
                self.wallet_name
            ),
        })
    }
}

impl WalletsSubCommand {
    pub fn execute(&self, ctx: &mut AppContext<Init>) -> Result<(), Error> {
        match self {
            Self::List(command) => command.execute(ctx)?.write_out(std::io::stdout()),
            Self::Delete(command) => command.execute(ctx)?.write_out(std::io::stdout()),
        }
    }
}
