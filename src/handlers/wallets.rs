use crate::error::BDKCliError as Error;
use crate::utils::output::FormatOutput;
use crate::{config::WalletConfig, handlers::types::WalletsListResult};
use std::path::Path;

/// Handle the top-level `wallets` command (lists all saved wallets)
pub fn handle_wallets_subcommand(home_dir: &Path, pretty: bool) -> Result<String, Error> {
    let config = match WalletConfig::load(home_dir)? {
        Some(cfg) => cfg,
        None => return Ok("No wallets configured yet.".to_string()),
    };

    let result = WalletsListResult(config.wallets);
    result.format(pretty)
}
