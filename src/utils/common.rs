use crate::{commands::WalletOpts, config::WalletConfig, error::BDKCliError as Error};
// #[cfg(feature = "bip322")]
// use bdk_bip322::SignatureFormat;
#[cfg(feature = "cbf")]
use bdk_kyoto::{Info, Receiver, UnboundedReceiver, Warning};
#[cfg(feature = "silent-payments")]
use bdk_sp::encoding::SilentPaymentCode;
use bdk_wallet::bitcoin::{Address, Network, OutPoint, ScriptBuf};
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
use bdk_wallet::{WalletEvent, bitcoin::Psbt};

use crate::commands::OfflineWalletSubCommand;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

/// Determine if PSBT has final script sigs or witnesses for all unsigned tx inputs.
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
pub(crate) fn is_final(psbt: &Psbt) -> Result<(), Error> {
    let unsigned_tx_inputs = psbt.unsigned_tx.input.len();
    let psbt_inputs = psbt.inputs.len();
    if unsigned_tx_inputs != psbt_inputs {
        return Err(Error::Generic(format!(
            "Malformed PSBT, {unsigned_tx_inputs} unsigned tx inputs and {psbt_inputs} psbt inputs."
        )));
    }
    let sig_count = psbt.inputs.iter().fold(0, |count, input| {
        if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
            count + 1
        } else {
            count
        }
    });
    if unsigned_tx_inputs > sig_count {
        return Err(Error::Generic(
            "The PSBT is not finalized, inputs are are not fully signed.".to_string(),
        ));
    }
    Ok(())
}

/// Parse the recipient (Address,Amount) argument from cli input.
pub(crate) fn parse_recipient(s: &str) -> Result<(ScriptBuf, u64), String> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid format".to_string());
    }
    let addr = Address::from_str(parts[0])
        .map_err(|e| e.to_string())?
        .assume_checked();
    let val = u64::from_str(parts[1]).map_err(|e| e.to_string())?;

    Ok((addr.script_pubkey(), val))
}

#[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
/// Parse the proxy (Socket:Port) argument from the cli input.
pub(crate) fn parse_proxy_auth(s: &str) -> Result<(String, String), Error> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(Error::Generic("Invalid format".to_string()));
    }

    let user = parts[0].to_string();
    let passwd = parts[1].to_string();

    Ok((user, passwd))
}

/// Parse a outpoint (Txid:Vout) argument from cli input.
pub(crate) fn parse_outpoint(s: &str) -> Result<OutPoint, Error> {
    Ok(OutPoint::from_str(s)?)
}

/// Parse an address string into `Address<NetworkChecked>`.
pub(crate) fn parse_address(address_str: &str) -> Result<Address, Error> {
    let unchecked_address = Address::from_str(address_str)?;
    Ok(unchecked_address.assume_checked())
}

/// Prepare bdk-cli home directory
///
/// This function is called to check if [`crate::CliOpts`] datadir is set.
/// If not the default home directory is created at `~/.bdk-bitcoin`.
#[allow(dead_code)]
pub(crate) fn prepare_home_dir(home_path: Option<PathBuf>) -> Result<PathBuf, Error> {
    let dir = match home_path {
        Some(dir) => dir,
        None => {
            let mut dir =
                dirs::home_dir().ok_or_else(|| Error::Generic("Home dir not found".to_string()))?;
            dir.push(".bdk-bitcoin");
            dir
        }
    };

    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    Ok(dir)
}

/// Prepare wallet database directory.
#[allow(dead_code)]
pub(crate) fn prepare_wallet_db_dir(
    home_path: &Path,
    wallet_name: &str,
) -> Result<std::path::PathBuf, Error> {
    let mut dir = home_path.to_owned();
    dir.push(wallet_name);

    if !dir.exists() {
        std::fs::create_dir(&dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    Ok(dir)
}

pub fn is_mnemonic(s: &str) -> bool {
    let word_count = s.split_whitespace().count();
    (12..=24).contains(&word_count) && s.chars().all(|c| c.is_alphanumeric() || c.is_whitespace())
}

#[cfg(feature = "cbf")]
pub async fn trace_logger(
    mut info_subcriber: Receiver<Info>,
    mut warning_subscriber: UnboundedReceiver<Warning>,
) {
    loop {
        tokio::select! {
            info = info_subcriber.recv() => {
                if let Some(info) = info {
                    tracing::info!("{info}")
                }
            }
            warn = warning_subscriber.recv() => {
                if let Some(warn) = warn {
                    tracing::warn!("{warn}")
                }
            }
        }
    }
}

pub fn load_wallet_config(
    home_dir: &Path,
    wallet_name: &str,
) -> Result<(WalletOpts, Network), Error> {
    let config = WalletConfig::load(home_dir)?.ok_or(Error::Generic(format!(
        "No config found for wallet {wallet_name}",
    )))?;

    let wallet_opts = config.get_wallet_opts(wallet_name)?;
    let wallet_config = config
        .wallets
        .get(wallet_name)
        .ok_or(Error::Generic(format!(
            "Wallet '{wallet_name}' not found in config"
        )))?;

    let network = Network::from_str(&wallet_config.network)
        .map_err(|_| Error::Generic("Invalid network in config".to_string()))?;

    Ok((wallet_opts, network))
}

#[cfg(feature = "silent-payments")]
pub(crate) fn parse_sp_code_value_pairs(s: &str) -> Result<(SilentPaymentCode, u64), Error> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(Error::Generic(format!(
            "Invalid format '{}'. Expected 'key:value'",
            s
        )));
    }

    let value_0 = parts[0].trim();
    let key = SilentPaymentCode::try_from(value_0)?;

    let value = parts[1]
        .trim()
        .parse::<u64>()
        .map_err(|_| Error::Generic(format!("Invalid number '{}' for key '{}'", parts[1], key)))?;

    Ok((key, value))
}

// /// Function to parse the signature format from a string
// #[cfg(feature = "bip322")]
// pub(crate) fn parse_signature_format(format_str: &str) -> Result<SignatureFormat, Error> {
//     match format_str.to_lowercase().as_str() {
//         "legacy" => Ok(SignatureFormat::Legacy),
//         "simple" => Ok(SignatureFormat::Simple),
//         "full" => Ok(SignatureFormat::Full),
//         "fullproofoffunds" => Ok(SignatureFormat::FullProofOfFunds),
//         _ => Err(Error::Generic(
//             "Invalid signature format. Use 'legacy', 'simple', 'full', or 'fullproofoffunds'"
//                 .to_string(),
//         )),
//     }
// }

pub fn command_requires_db(command: &OfflineWalletSubCommand) -> bool {
    match command {
        OfflineWalletSubCommand::Balance(_)
        | OfflineWalletSubCommand::Unspent(_)
        | OfflineWalletSubCommand::Transactions(_)
        | OfflineWalletSubCommand::BumpFee(_)
        | OfflineWalletSubCommand::NewAddress(_)
        | OfflineWalletSubCommand::UnusedAddress(_)
        | OfflineWalletSubCommand::CreateTx(_)
        | OfflineWalletSubCommand::LockUtxo(_)
        | OfflineWalletSubCommand::UnlockUtxo(_)
        | OfflineWalletSubCommand::LockedUtxos(_) => true,

        OfflineWalletSubCommand::Policies(_)
        | OfflineWalletSubCommand::PublicDescriptor(_)
        | OfflineWalletSubCommand::Sign(_)
        | OfflineWalletSubCommand::ExtractPsbt(_)
        | OfflineWalletSubCommand::FinalizePsbt(_)
        | OfflineWalletSubCommand::CombinePsbt(_) => false,

        // #[cfg(feature = "bip322")]
        // OfflineWalletSubCommand::SignMessage(_) => true,

        // #[cfg(feature = "bip322")]
        // OfflineWalletSubCommand::VerifyMessage(_) => true,
        #[cfg(feature = "silent-payments")]
        OfflineWalletSubCommand::CreateSpTx(_) => true,
        #[cfg(feature = "dns_payment")]
        OfflineWalletSubCommand::CreateDnsTx(_) => true,
    }
}

/// Print a human-readable summary of the wallet events produced by a sync or scan.
///
/// Emitted to stderr so it does not pollute the JSON result on stdout.
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
pub fn print_wallet_events(events: &[WalletEvent]) {
    for event in events {
        match event {
            WalletEvent::ChainTipChanged { old_tip, new_tip } => {
                eprintln!(
                    "Chain tip advanced from height {} to {}",
                    old_tip.height, new_tip.height
                );
            }
            WalletEvent::TxConfirmed {
                txid,
                block_time,
                old_block_time,
                ..
            } => match old_block_time {
                Some(old) => eprintln!(
                    "Transaction {txid} re-confirmed at height {} (was height {}, likely a reorg)",
                    block_time.block_id.height, old.block_id.height
                ),
                None => eprintln!(
                    "Transaction {txid} confirmed at height {}",
                    block_time.block_id.height
                ),
            },
            WalletEvent::TxUnconfirmed {
                txid,
                old_block_time,
                ..
            } => match old_block_time {
                Some(old) => eprintln!(
                    "Transaction {txid} became unconfirmed (was confirmed at height {}, likely a reorg)",
                    old.block_id.height
                ),
                None => eprintln!("Transaction {txid} seen in mempool"),
            },
            WalletEvent::TxReplaced {
                txid, conflicts, ..
            } => {
                let ids: Vec<String> = conflicts.iter().map(|(_, c)| c.to_string()).collect();
                eprintln!(
                    "Transaction {txid} was replaced (conflicts with: {})",
                    ids.join(", ")
                );
            }
            WalletEvent::TxDropped { txid, .. } => {
                eprintln!("Transaction {txid} dropped from the mempool");
            }
            _ => {}
        }
    }
}

#[cfg(feature = "dns_payment")]
/// Parse dns recipients in the form "test@me.com:10000" from cli input
pub(crate) fn parse_dns_recipient(s: &str) -> Result<(String, u64), String> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid format".to_string());
    }
    let sending_amount = u64::from_str(parts[1]).map_err(|e| e.to_string())?;
    Ok((parts[0].to_string(), sending_amount))
}
