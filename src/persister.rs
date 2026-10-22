use crate::commands::WalletOpts;
use crate::error::BDKCliError as Error;
use crate::utils::descriptors::validate_descriptor_pair;
use bdk_wallet::bitcoin::{Network, NetworkKind, secp256k1::Secp256k1};
use bdk_wallet::descriptor::IntoWalletDescriptor;
use bdk_wallet::miniscript::descriptor::KeyMap;
use bdk_wallet::{KeychainKind, Wallet};
#[cfg(any(feature = "sqlite", feature = "redb"))]
use bdk_wallet::{PersistedWallet, WalletPersister};
#[cfg(any(feature = "sqlite", feature = "redb"))]
use clap::ValueEnum;

#[cfg(any(feature = "sqlite", feature = "redb"))]
#[derive(Clone, ValueEnum, Debug, Eq, PartialEq)]
pub enum DatabaseType {
    /// Sqlite database
    #[cfg(feature = "sqlite")]
    Sqlite,
    /// Redb database
    #[cfg(feature = "redb")]
    Redb,
}

// Types of Persistence backends supported by bdk-cli
#[cfg(any(feature = "sqlite", feature = "redb"))]
pub(crate) enum Persister {
    #[cfg(feature = "sqlite")]
    Connection(bdk_wallet::rusqlite::Connection),
    #[cfg(feature = "redb")]
    RedbStore(bdk_redb::Store),
}

/// Keep the descriptor key maps outside the
/// wallet and construct the signer only when a PSBT is being signed.
pub(crate) struct WalletSigners {
    pub external: KeyMap,
    pub internal: KeyMap,
}

impl WalletSigners {
    pub(crate) fn new(network: Network, wallet_opts: &WalletOpts) -> Result<Self, Error> {
        let secp = Secp256k1::new();
        let ext_is_multipath = validate_descriptor_pair(
            &wallet_opts.ext_descriptor,
            wallet_opts.int_descriptor.as_deref(),
            network,
        )?;

        if ext_is_multipath {
            return Err(Error::Generic(
                "Multipath descriptors are not supported by WalletSigners yet.".to_string(),
            ));
        }

        let (_, external_keymap) = wallet_opts
            .ext_descriptor
            .clone()
            .into_wallet_descriptor(&secp, NetworkKind::from(network))?;
        let external = external_keymap;

        let internal = wallet_opts
            .int_descriptor
            .clone()
            .map(|descriptor| {
                descriptor
                    .into_wallet_descriptor(&secp, NetworkKind::from(network))
                    .map(|(_, keymap)| keymap)
            })
            .transpose()?;

        Ok(Self {
            external,
            internal: internal.unwrap_or_default(),
        })
    }

    pub(crate) fn sign_psbt(
        &self,
        wallet: &Wallet,
        psbt: &mut bdk_wallet::bitcoin::Psbt,
    ) -> Result<(), Error> {
        let signer = bdk_wallet::bdk_tx::Signer(
            self.external
                .clone()
                .into_iter()
                .chain(self.internal.clone())
                .collect(),
        );
        psbt.sign(&signer, wallet.secp_ctx())
            .map(|_| ())
            .map_err(|(_, errors)| Error::Generic(format!("Failed to sign PSBT: {errors:?}")))
    }
}

#[cfg(any(feature = "sqlite", feature = "redb"))]
impl WalletPersister for Persister {
    type Error = Error;

    fn initialize(persister: &mut Self) -> Result<bdk_wallet::ChangeSet, Self::Error> {
        match persister {
            #[cfg(feature = "sqlite")]
            Persister::Connection(connection) => {
                WalletPersister::initialize(connection).map_err(Error::from)
            }
            #[cfg(feature = "redb")]
            Persister::RedbStore(store) => WalletPersister::initialize(store).map_err(Error::from),
        }
    }

    fn persist(persister: &mut Self, changeset: &bdk_wallet::ChangeSet) -> Result<(), Self::Error> {
        match persister {
            #[cfg(feature = "sqlite")]
            Persister::Connection(connection) => {
                WalletPersister::persist(connection, changeset).map_err(Error::from)
            }
            #[cfg(feature = "redb")]
            Persister::RedbStore(store) => {
                WalletPersister::persist(store, changeset).map_err(Error::from)
            }
        }
    }
}

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

    let ext_is_multipath =
        validate_descriptor_pair(&ext_descriptor, int_descriptor.as_deref(), network)?;

    let mut wallet_load_params = Wallet::load();
    wallet_load_params = if ext_is_multipath {
        // Load a wallet created from a two-path (BIP-389) descriptor.
        wallet_load_params.two_path_descriptor(ext_descriptor.clone())
    } else {
        let mut params =
            wallet_load_params.descriptor(KeychainKind::External, Some(ext_descriptor.clone()));
        if int_descriptor.is_some() {
            params = params.descriptor(KeychainKind::Internal, int_descriptor.clone());
        }
        params
    };
    wallet_load_params = wallet_load_params.extract_keys();

    let wallet_opt = wallet_load_params
        .check_network(network)
        .load_wallet(persister)
        .map_err(|e| Error::Generic(e.to_string()))?;

    let wallet = match wallet_opt {
        Some(wallet) => wallet,
        None => {
            let builder = if let Some(int_descriptor) = int_descriptor {
                Wallet::create(ext_descriptor, int_descriptor)
            } else if ext_is_multipath {
                Wallet::create_from_two_path_descriptor(ext_descriptor)
            } else {
                Wallet::create_single(ext_descriptor)
            };

            builder
                .network(network)
                .create_wallet(persister)
                .map_err(|e| Error::Generic(e.to_string()))?
        }
    };

    Ok(wallet)
}

pub(crate) fn new_wallet(network: Network, wallet_opts: &WalletOpts) -> Result<Wallet, Error> {
    let ext_descriptor = wallet_opts.ext_descriptor.clone();
    let int_descriptor = wallet_opts.int_descriptor.clone();

    let ext_is_multipath =
        validate_descriptor_pair(&ext_descriptor, int_descriptor.as_deref(), network)?;

    let builder = if let Some(int_descriptor) = int_descriptor {
        Wallet::create(ext_descriptor, int_descriptor)
    } else if ext_is_multipath {
        Wallet::create_from_two_path_descriptor(ext_descriptor)
    } else {
        Wallet::create_single(ext_descriptor)
    };

    let wallet = builder.network(network).create_wallet_no_persist()?;
    Ok(wallet)
}
