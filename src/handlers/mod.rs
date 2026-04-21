pub mod config;
pub mod descriptor;
pub mod key;
pub mod offline;
pub mod online;
pub mod repl;
pub mod wallets;

#[cfg(feature = "repl")]
use crate::handlers::repl::respond;
use crate::{
    commands::{CliOpts, CliSubCommand, WalletSubCommand},
    error::BDKCliError as Error,
    handlers::{
        config::handle_config_subcommand, descriptor::handle_descriptor_command,
        key::handle_key_subcommand, wallets::handle_wallets_subcommand,
    },
    utils::{load_wallet_config, prepare_home_dir},
};

#[cfg(any(feature = "sqlite", feature = "redb"))]
use crate::utils::prepare_wallet_db_dir;
#[cfg(not(any(feature = "sqlite", feature = "redb")))]
use crate::wallet::new_wallet;

#[cfg(feature = "compiler")]
use {
    crate::handlers::descriptor::handle_compile_subcommand, bdk_redb::Store as RedbStore,
    std::sync::Arc,
};

#[cfg(feature = "repl")]
use crate::handlers::repl::readline;

#[cfg(any(feature = "sqlite", feature = "redb"))]
use crate::commands::DatabaseType;
use crate::handlers::offline::handle_offline_wallet_subcommand;
use clap::CommandFactory;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf",
))]
use {
    crate::backend::new_blockchain_client, crate::handlers::online::handle_online_wallet_subcommand,
};
#[cfg(any(feature = "sqlite", feature = "redb"))]
use {
    crate::wallet::{new_persisted_wallet, persister::Persister},
    bdk_wallet::rusqlite::Connection,
    std::io::Write,
};

/// The global top level handler.
pub(crate) async fn handle_command(cli_opts: CliOpts) -> Result<String, Error> {
    let pretty = cli_opts.pretty;
    let subcommand = cli_opts.subcommand.clone();

    let result: Result<String, Error> = match subcommand {
        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "cbf",
            feature = "rpc"
        ))]
        CliSubCommand::Wallet {
            wallet,
            subcommand: WalletSubCommand::OnlineWalletSubCommand(online_subcommand),
        } => {
            let home_dir = prepare_home_dir(cli_opts.datadir)?;

            let (wallet_opts, network) = load_wallet_config(&home_dir, &wallet)?;

            let database_path = prepare_wallet_db_dir(&home_dir, &wallet)?;

            #[cfg(any(feature = "sqlite", feature = "redb"))]
            let result = {
                #[cfg(feature = "sqlite")]
                let mut persister: Persister = match &wallet_opts.database_type {
                    #[cfg(feature = "sqlite")]
                    DatabaseType::Sqlite => {
                        let db_file = database_path.join("wallet.sqlite");
                        let connection = Connection::open(db_file)?;
                        log::debug!("Sqlite database opened successfully");
                        Persister::Connection(connection)
                    }
                    #[cfg(feature = "redb")]
                    DatabaseType::Redb => {
                        let wallet_name = &wallet_opts.wallet;
                        let db = Arc::new(bdk_redb::redb::Database::create(
                            home_dir.join("wallet.redb"),
                        )?);
                        let store = RedbStore::new(
                            db,
                            wallet_name.as_deref().unwrap_or("wallet").to_string(),
                        )?;
                        log::debug!("Redb database opened successfully");
                        Persister::RedbStore(store)
                    }
                };

                let mut wallet = new_persisted_wallet(network, &mut persister, &wallet_opts)?;
                let blockchain_client =
                    new_blockchain_client(&wallet_opts, &wallet, database_path)?;

                let result = handle_online_wallet_subcommand(
                    &mut wallet,
                    &blockchain_client,
                    online_subcommand,
                )
                .await?;
                wallet.persist(&mut persister)?;
                result
            };
            #[cfg(not(any(feature = "sqlite", feature = "redb")))]
            let result = {
                let mut wallet = new_wallet(network, &wallet_opts)?;
                let blockchain_client =
                    new_blockchain_client(&wallet_opts, &wallet, database_path)?;
                handle_online_wallet_subcommand(&mut wallet, &blockchain_client, online_subcommand)
                    .await?
            };
            Ok(result)
        }
        CliSubCommand::Wallet {
            wallet: wallet_name,
            subcommand: WalletSubCommand::OfflineWalletSubCommand(offline_subcommand),
        } => {
            let datadir = cli_opts.datadir.clone();
            let home_dir = prepare_home_dir(datadir)?;
            let (wallet_opts, network) = load_wallet_config(&home_dir, &wallet_name)?;

            #[cfg(any(feature = "sqlite", feature = "redb"))]
            let result = {
                let mut persister: Persister = match &wallet_opts.database_type {
                    #[cfg(feature = "sqlite")]
                    DatabaseType::Sqlite => {
                        let database_path = prepare_wallet_db_dir(&home_dir, &wallet_name)?;
                        let db_file = database_path.join("wallet.sqlite");
                        let connection = Connection::open(db_file)?;
                        log::debug!("Sqlite database opened successfully");
                        Persister::Connection(connection)
                    }
                    #[cfg(feature = "redb")]
                    DatabaseType::Redb => {
                        let db = Arc::new(bdk_redb::redb::Database::create(
                            home_dir.join("wallet.redb"),
                        )?);
                        let store = RedbStore::new(db, wallet_name)?;
                        log::debug!("Redb database opened successfully");
                        Persister::RedbStore(store)
                    }
                };

                let mut wallet = new_persisted_wallet(network, &mut persister, &wallet_opts)?;

                let result = handle_offline_wallet_subcommand(
                    &mut wallet,
                    &wallet_opts,
                    &cli_opts,
                    offline_subcommand.clone(),
                )?;
                wallet.persist(&mut persister)?;
                result
            };
            #[cfg(not(any(feature = "sqlite", feature = "redb")))]
            let result = {
                let mut wallet = new_wallet(network, &wallet_opts)?;
                handle_offline_wallet_subcommand(
                    &mut wallet,
                    &wallet_opts,
                    &cli_opts,
                    offline_subcommand.clone(),
                )?
            };
            Ok(result)
        }
        CliSubCommand::Wallet {
            wallet,
            subcommand: WalletSubCommand::Config { force, wallet_opts },
        } => {
            let network = cli_opts.network;
            let home_dir = prepare_home_dir(cli_opts.datadir)?;
            let result = handle_config_subcommand(&home_dir, network, wallet, &wallet_opts, force)?;
            Ok(result)
        }
        CliSubCommand::Wallets => {
            let home_dir = prepare_home_dir(cli_opts.datadir)?;
            let result = handle_wallets_subcommand(&home_dir, pretty)?;
            Ok(result)
        }
        CliSubCommand::Key {
            subcommand: key_subcommand,
        } => {
            let network = cli_opts.network;
            let result = handle_key_subcommand(network, key_subcommand, pretty)?;
            Ok(result)
        }
        #[cfg(feature = "compiler")]
        CliSubCommand::Compile {
            policy,
            script_type,
        } => {
            let network = cli_opts.network;
            let result = handle_compile_subcommand(network, policy, script_type, pretty)?;
            Ok(result)
        }
        #[cfg(feature = "repl")]
        CliSubCommand::Repl {
            wallet: wallet_name,
        } => {
            let home_dir = prepare_home_dir(cli_opts.datadir.clone())?;
            let (wallet_opts, network) = load_wallet_config(&home_dir, &wallet_name)?;

            #[cfg(any(feature = "sqlite", feature = "redb"))]
            let (mut wallet, mut persister) = {
                let mut persister: Persister = match &wallet_opts.database_type {
                    #[cfg(feature = "sqlite")]
                    DatabaseType::Sqlite => {
                        let database_path = prepare_wallet_db_dir(&home_dir, &wallet_name)?;
                        let db_file = database_path.join("wallet.sqlite");
                        let connection = Connection::open(db_file)?;
                        log::debug!("Sqlite database opened successfully");
                        Persister::Connection(connection)
                    }
                    #[cfg(feature = "redb")]
                    DatabaseType::Redb => {
                        let db = Arc::new(bdk_redb::redb::Database::create(
                            home_dir.join("wallet.redb"),
                        )?);
                        let store = RedbStore::new(db, wallet_name.clone())?;
                        log::debug!("Redb database opened successfully");
                        Persister::RedbStore(store)
                    }
                };
                let wallet = new_persisted_wallet(network, &mut persister, &wallet_opts)?;
                (wallet, persister)
            };
            #[cfg(not(any(feature = "sqlite", feature = "redb")))]
            let mut wallet = new_wallet(network, &loaded_wallet_opts)?;
            let home_dir = prepare_home_dir(cli_opts.datadir.clone())?;
            let database_path = prepare_wallet_db_dir(&home_dir, &wallet_name)?;
            loop {
                let line = readline()?;
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let result = respond(
                    network,
                    &mut wallet,
                    &wallet_name,
                    &mut wallet_opts.clone(),
                    line,
                    database_path.clone(),
                    &cli_opts,
                )
                .await;
                #[cfg(any(feature = "sqlite", feature = "redb"))]
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
        CliSubCommand::Descriptor { desc_type, key } => {
            let descriptor = handle_descriptor_command(cli_opts.network, desc_type, key, pretty)?;
            Ok(descriptor)
        }
        CliSubCommand::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut CliOpts::command(),
                "bdk-cli",
                &mut std::io::stdout(),
            );

            Ok("".to_string())
        }
    };
    result
}
