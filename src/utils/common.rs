use crate::{commands::WalletOpts, config::WalletConfig, error::BDKCliError as Error};
#[cfg(feature = "cbf")]
use bdk_kyoto::{Info, Receiver, UnboundedReceiver, Warning};
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
use bdk_wallet::bitcoin::Psbt;
use bdk_wallet::bitcoin::{Address, Network, OutPoint, ScriptBuf};

use std::{
    fmt::Display,
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

pub(crate) fn shorten(displayable: impl Display, start: u8, end: u8) -> String {
    let displayable = displayable.to_string();

    if displayable.len() <= (start + end) as usize {
        return displayable;
    }

    let start_str: &str = &displayable[0..start as usize];
    let end_str: &str = &displayable[displayable.len() - end as usize..];
    format!("{start_str}...{end_str}")
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
    let dir = home_path.unwrap_or_else(|| {
        let mut dir = PathBuf::new();
        dir.push(
            dirs::home_dir()
                .ok_or_else(|| Error::Generic("home dir not found".to_string()))
                .unwrap(),
        );
        dir.push(".bdk-bitcoin");
        dir
    });

    if !dir.exists() {
        std::fs::create_dir(&dir).map_err(|e| Error::Generic(e.to_string()))?;
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

    let network = match wallet_config.network.as_str() {
        "bitcoin" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        "signet" => Ok(Network::Signet),
        "testnet4" => Ok(Network::Testnet4),
        _ => Err(Error::Generic("Invalid network in config".to_string())),
    }?;

    Ok((wallet_opts, network))
}
