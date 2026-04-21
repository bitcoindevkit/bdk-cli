use crate::config::WalletConfig;
use crate::error::BDKCliError as Error;
use cli_table::{Cell, CellStruct, Style, Table};
use std::path::Path;

/// Handle the top-level `wallets` command (lists all saved wallets)
pub fn handle_wallets_subcommand(home_dir: &Path, pretty: bool) -> Result<String, Error> {
    let config = match WalletConfig::load(home_dir)? {
        Some(cfg) => cfg,
        None => return Ok("No wallets configured yet.".to_string()),
    };

    if pretty {
        let mut rows: Vec<Vec<CellStruct>> = vec![];
        for (name, inner) in &config.wallets {
            rows.push(vec![
                name.cell(),
                inner.network.clone().cell(),
                inner.ext_descriptor[..30].to_string().cell(),
            ]);
        }

        let table = rows
            .table()
            .title(vec![
                "Wallet Name".cell().bold(true),
                "Network".cell().bold(true),
                "External Descriptor (truncated)".cell().bold(true),
            ])
            .display()
            .map_err(|e| Error::Generic(e.to_string()))?;

        Ok(format!("{table}"))
    } else {
        Ok(serde_json::to_string_pretty(&config.wallets)?)
    }
}
