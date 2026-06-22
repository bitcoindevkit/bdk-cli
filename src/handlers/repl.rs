#[cfg(feature = "repl")]
use {
    crate::commands::ReplSubCommand,
    crate::handlers::{AppCommand, AppContext},
    crate::utils::output::FormatOutput,
    bdk_wallet::{Wallet, bitcoin::Network},
    clap::Parser,
};

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
use crate::client::BlockchainClient;
#[cfg(feature = "repl")]
use {crate::commands::WalletSubCommand, crate::error::BDKCliError as Error, std::io::Write};

#[cfg(feature = "repl")]
pub(crate) async fn respond(
    network: Network,
    wallet: &mut Wallet,
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf"
    ))]
    client: Option<&BlockchainClient>,
    line: &str,
    datadir: std::path::PathBuf,
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

    let response = match repl_subcommand {
        ReplSubCommand::Wallet { subcommand } => match subcommand {
            WalletSubCommand::OfflineWalletSubCommand(cmd) => {
                let mut ctx = AppContext::new_offline_wallet(network, datadir, wallet);
                cmd.execute(&mut ctx)
                    .map_err(|e| e.to_string())?
                    .write_out(std::io::stdout())
                    .map_err(|e| e.to_string())?;
                Some(())
            }
            #[cfg(any(
                feature = "electrum",
                feature = "esplora",
                feature = "cbf",
                feature = "rpc"
            ))]
            WalletSubCommand::OnlineWalletSubCommand(cmd) => {
                let client_ref = client.ok_or("Online commands require a client.".to_string())?;
                let mut ctx = AppContext::new_online_wallet(network, datadir, wallet, client_ref);

                cmd.execute(&mut ctx)
                    .await
                    .map_err(|e| e.to_string())?
                    .write_out(std::io::stdout())
                    .map_err(|e| e.to_string())?;
                Some(())
            }
            WalletSubCommand::Config(config_cmd) => {
                let mut ctx = AppContext::new(network, datadir);
                config_cmd
                    .execute(&mut ctx)
                    .map_err(|e| e.to_string())?
                    .write_out(std::io::stdout())
                    .map_err(|e| e.to_string())?;
                Some(())
            }
        },

        ReplSubCommand::Descriptor(cmd) => {
            let mut ctx = AppContext::new(network, datadir);
            cmd.execute(&mut ctx)
                .map_err(|e| e.to_string())?
                .write_out(std::io::stdout())
                .map_err(|e| e.to_string())?;
            Some(())
        }

        ReplSubCommand::Key { subcommand } => {
            let mut ctx = AppContext::new(network, datadir);
            subcommand.execute(&mut ctx).map_err(|e| e.to_string())?;
            Some(())
        }

        ReplSubCommand::Exit => None,
    };

    if response.is_some() {
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
