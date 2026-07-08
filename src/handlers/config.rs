use std::collections::HashMap;

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
use crate::client::ClientType;
use crate::commands::WalletOpts;
use crate::config::{WalletConfig, WalletConfigInner};
use crate::error::BDKCliError as Error;
use crate::handlers::Init;
use crate::handlers::{AppCommand, AppContext};
#[cfg(feature = "sqlite")]
use crate::persister::DatabaseType;
use crate::utils::types::{StatusResult, WalletsListResult};
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
