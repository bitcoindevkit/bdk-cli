use bdk_wallet::{Wallet, bitcoin::Network};

// #[cfg(feature = "repl")]
use crate::handlers::{AppCommand, AppContext};
use crate::utils::output::FormatOutput;

#[cfg(feature = "sqlite")]
use crate::commands::ReplSubCommand;
use clap::Parser;
#[cfg(feature = "repl")]
use std::io::Write;
use {
    crate::commands::{CliOpts, WalletSubCommand},
    crate::error::BDKCliError as Error,
};

#[cfg(feature = "repl")]
pub(crate) async fn respond(
    network: Network,
    wallet: &mut Wallet,
    line: &str,
    datadir: std::path::PathBuf,
    cli_opts: &CliOpts,
) -> Result<bool, String> {
    let args = shlex::split(line).ok_or("error: Invalid quoting".to_string())?;

    let mut repl_args = vec!["repl".to_string()];
    repl_args.extend(args);

    let repl_subcommand = match ReplSubCommand::try_parse_from(&repl_args) {
        Ok(cmd) => cmd,
        Err(e) => {
            writeln!(std::io::stdout(), "{}", e).map_err(|e| e.to_string())?;
            return Ok(false);
        }
    };

    let mut ctx = AppContext::new(network, datadir.clone()).with_wallet(&mut *wallet);

    let response = match repl_subcommand {
        ReplSubCommand::Wallet { subcommand } => match subcommand {
            WalletSubCommand::OfflineWalletSubCommand(cmd) => {
                cmd.execute(&mut ctx).map_err(|e| e.to_string())?;
                Some(())
            }
            #[cfg(any(
                feature = "electrum",
                feature = "esplora",
                feature = "cbf",
                feature = "rpc"
            ))]
            WalletSubCommand::OnlineWalletSubCommand(cmd) => {
                let value = cmd.execute(&mut ctx).await.map_err(|e| e.to_string())?;
                Some(())
                // Some(value)
            }
            WalletSubCommand::Config(config_cmd) => {
                let mut ctx = AppContext::new(network, datadir);
                let res = config_cmd
                    .execute(&mut ctx)
                    .map_err(|e| e.to_string())?
                    .print();
                Some(())
            }
        },

        // Assuming your REPL Descriptor command is an inline struct based on commands.rs
        ReplSubCommand::Descriptor(cmd) => {
            let value = cmd.execute(&mut ctx).map_err(|e| e.to_string())?.print();
            Some(())
        }

        ReplSubCommand::Exit => None,
        _ => todo!(),
    };

    if let Some(value) = response {
        // writeln!(std::io::stdout(), "{value}").map_err(|e| e.to_string())?;
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        Ok(false)
    } else {
        writeln!(std::io::stdout(), "Exiting...").map_err(|e| e.to_string())?;
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        Ok(true)
    }
}

#[cfg(feature = "repl")]
pub(crate) fn readline() -> Result<String, Error> {
    write!(std::io::stdout(), "> ").map_err(|e| Error::Generic(e.to_string()))?;
    std::io::stdout()
        .flush()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let mut buffer = String::new();
    std::io::stdin()
        .read_line(&mut buffer)
        .map_err(|e| Error::Generic(e.to_string()))?;
    Ok(buffer)
}
