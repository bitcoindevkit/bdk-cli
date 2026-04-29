use crate::commands::WalletOpts;
use crate::error::BDKCliError as Error;
use bdk_wallet::Wallet;
use bdk_wallet::bitcoin::Network;
#[cfg(any(feature = "sqlite", feature = "redb"))]
use bdk_wallet::{KeychainKind, PersistedWallet, WalletPersister};

#[cfg(any(feature = "sqlite", feature = "redb"))]
pub mod persister;

#[cfg(any(feature = "sqlite", feature = "redb"))]
pub(crate) fn new_persisted_wallet<P: WalletPersister>(
    network: Network,
    persister: &mut P,
    wallet_opts: &WalletOpts,
) -> Result<PersistedWallet<P>, Error>
where
    P::Error: std::fmt::Display,
{
    let ext_descriptor = wallet_opts.ext_descriptor.clone();
    let int_descriptor = wallet_opts.int_descriptor.clone();

    let mut wallet_load_params = Wallet::load();
    wallet_load_params =
        wallet_load_params.descriptor(KeychainKind::External, Some(ext_descriptor.clone()));

    if int_descriptor.is_some() {
        wallet_load_params =
            wallet_load_params.descriptor(KeychainKind::Internal, int_descriptor.clone());
    }
    wallet_load_params = wallet_load_params.extract_keys();

    let wallet_opt = wallet_load_params
        .check_network(network)
        .load_wallet(persister)
        .map_err(|e| Error::Generic(e.to_string()))?;

    let wallet = match wallet_opt {
        Some(wallet) => wallet,
        None => match int_descriptor {
            Some(int_descriptor) => Wallet::create(ext_descriptor, int_descriptor)
                .network(network)
                .create_wallet(persister)
                .map_err(|e| Error::Generic(e.to_string()))?,
            None => Wallet::create_single(ext_descriptor)
                .network(network)
                .create_wallet(persister)
                .map_err(|e| Error::Generic(e.to_string()))?,
        },
    };

    Ok(wallet)
}

#[cfg(not(any(feature = "sqlite", feature = "redb")))]
pub(crate) fn new_wallet(network: Network, wallet_opts: &WalletOpts) -> Result<Wallet, Error> {
    let ext_descriptor = wallet_opts.ext_descriptor.clone();
    let int_descriptor = wallet_opts.int_descriptor.clone();

    match int_descriptor {
        Some(int_descriptor) => {
            let wallet = Wallet::create(ext_descriptor, int_descriptor)
                .network(network)
                .create_wallet_no_persist()?;
            Ok(wallet)
        }
        None => {
            let wallet = Wallet::create_single(ext_descriptor)
                .network(network)
                .create_wallet_no_persist()?;
            Ok(wallet)
        }
    }
}
