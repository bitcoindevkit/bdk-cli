#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
use crate::{backend::new_blockchain_client, handlers::online::handle_online_wallet_subcommand};

#[cfg(feature = "sqlite")]
use crate::commands::ReplSubCommand;
#[cfg(feature = "repl")]
use {
    crate::error::BDKCliError as Error,
    crate::{
        commands::{CliOpts, WalletOpts, WalletSubCommand},
        handlers::{
            config::handle_config_subcommand, descriptor::handle_descriptor_command,
            key::handle_key_subcommand, offline::handle_offline_wallet_subcommand,
        },
    },
    bdk_wallet::{Wallet, bitcoin::Network},
    std::io::Write,
};

#[cfg(feature = "repl")]
pub(crate) async fn respond(
    network: Network,
    wallet: &mut Wallet,
    wallet_name: &String,
    wallet_opts: &mut WalletOpts,
    line: &str,
    _datadir: std::path::PathBuf,
    cli_opts: &CliOpts,
) -> Result<bool, String> {
    use clap::Parser;

    let args = shlex::split(line).ok_or("error: Invalid quoting".to_string())?;
    let repl_subcommand = ReplSubCommand::try_parse_from(args).map_err(|e| e.to_string())?;
    let response = match repl_subcommand {
        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "cbf",
            feature = "rpc"
        ))]
        ReplSubCommand::Wallet {
            subcommand: WalletSubCommand::OnlineWalletSubCommand(online_subcommand),
        } => {
            let blockchain =
                new_blockchain_client(wallet_opts, wallet, _datadir).map_err(|e| e.to_string())?;
            let value = handle_online_wallet_subcommand(wallet, &blockchain, online_subcommand)
                .await
                .map_err(|e| e.to_string())?;
            Some(value)
        }
        ReplSubCommand::Wallet {
            subcommand: WalletSubCommand::OfflineWalletSubCommand(offline_subcommand),
        } => {
            let value =
                handle_offline_wallet_subcommand(wallet, wallet_opts, cli_opts, offline_subcommand)
                    .map_err(|e| e.to_string())?;
            Some(value)
        }
        ReplSubCommand::Wallet {
            subcommand: WalletSubCommand::Config { force, wallet_opts },
        } => {
            let value = handle_config_subcommand(
                &_datadir,
                network,
                wallet_name.to_string(),
                &wallet_opts,
                force,
            )
            .map_err(|e| e.to_string())?;
            Some(value)
        }
        ReplSubCommand::Key { subcommand } => {
            let value = handle_key_subcommand(network, subcommand, cli_opts.pretty)
                .map_err(|e| e.to_string())?;
            Some(value)
        }
        ReplSubCommand::Descriptor { desc_type, key } => {
            let value = handle_descriptor_command(network, desc_type, key, cli_opts.pretty)
                .map_err(|e| e.to_string())?;
            Some(value)
        }
        ReplSubCommand::Exit => None,
    };
    if let Some(value) = response {
        writeln!(std::io::stdout(), "{value}").map_err(|e| e.to_string())?;
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
