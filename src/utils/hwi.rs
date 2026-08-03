//! Hardware wallet (HWI) device discovery.
//!
//! Enumerates every supported hardware wallet that is currently reachable and
//! returns them as trait objects. Supported devices: Specter, Jade, Ledger,
//! Coldcard and BitBox02 (plus the Specter and Ledger simulators). The logic
//! mirrors the reference implementation shipped with the `async-hwi` crate so
//! that new devices supported upstream become available here with minimal
//! changes.

use async_hwi::{
    HWI,
    bitbox::{BitBox02, PairingBitbox02WithLocalCache, api::runtime},
    coldcard,
    jade::{self, Jade},
    ledger::{HidApi, Ledger, LedgerSimulator, TransportHID},
    specter::{Specter, SpecterSimulator},
};
use bdk_wallet::bitcoin::{Network, hex::FromHex};
use tracing::warn;

use crate::error::BDKCliError as Error;

/// Optional wallet context required by some devices (Ledger/Coldcard/BitBox)
/// to register and operate on a specific multisig/miniscript policy.
#[derive(Default, Clone)]
pub struct HwiWallet<'a> {
    pub name: Option<&'a str>,
    pub policy: Option<&'a str>,
    pub hmac: Option<&'a str>,
}

/// Enumerate every hardware wallet currently connected.
///
/// Returns one boxed [`HWI`] trait object per reachable device. The list can be
/// empty if nothing is plugged in. Enumeration never fails hard for a single
/// device kind: failures are logged and the other device kinds are still
/// probed.
pub async fn enumerate_hwi_devices(
    network: Network,
    wallet: &HwiWallet<'_>,
) -> Result<Vec<Box<dyn HWI + Send>>, Error> {
    let mut devices: Vec<Box<dyn HWI + Send>> = Vec::new();

    // Specter simulator (TCP) then physical Specter devices (serial).
    if let Ok(device) = SpecterSimulator::try_connect().await {
        devices.push(device.into());
    }
    match Specter::enumerate().await {
        Ok(specters) => devices.extend(specters.into_iter().map(Into::into)),
        Err(e) => warn!("Specter enumeration failed: {e:?}"),
    }

    // Jade (serial).
    match Jade::enumerate().await {
        Ok(jades) => {
            for device in jades {
                let device = device.with_network(network);
                match device.get_info().await {
                    Ok(info) => {
                        if info.jade_state == jade::api::JadeState::Locked
                            && let Err(e) = device.auth().await
                        {
                            warn!("Jade authentication failed: {e:?}");
                            continue;
                        }
                        devices.push(device.into());
                    }
                    Err(e) => warn!("Jade get_info failed: {e:?}"),
                }
            }
        }
        Err(e) => warn!("Jade enumeration failed: {e:?}"),
    }

    // Ledger simulator (Speculos).
    if let Ok(device) = LedgerSimulator::try_connect().await {
        devices.push(device.into());
    }

    // USB (HID) devices: BitBox02 and Coldcard.
    let api = Box::new(HidApi::new().map_err(|e| Error::Generic(e.to_string()))?);

    for device_info in api.device_list() {
        // BitBox02
        if async_hwi::bitbox::is_bitbox02(device_info)
            && let Ok(handle) = device_info.open_device(&api)
            && let Ok(pairing) =
                PairingBitbox02WithLocalCache::<runtime::TokioRuntime>::connect(handle, None).await
            && let Ok((device, _)) = pairing.wait_confirm().await
        {
            let mut bb02 = BitBox02::from(device).with_network(network);
            if let Some(policy) = wallet.policy {
                bb02 = bb02.with_policy(policy).map_err(map_device_err)?;
            }
            devices.push(bb02.into());
        }

        // Coldcard
        if device_info.vendor_id() == coldcard::api::COINKITE_VID
            && device_info.product_id() == coldcard::api::CKCC_PID
            && let Some(sn) = device_info.serial_number()
        {
            match coldcard::api::Coldcard::open(&api, sn, None) {
                Ok((cc, _)) => {
                    let mut hw = coldcard::Coldcard::from(cc);
                    if let Some(name) = wallet.name {
                        hw = hw.with_wallet_name(name.to_string());
                    }
                    devices.push(hw.into());
                }
                Err(e) => warn!("Failed to open Coldcard (SN {sn}): {e:?}"),
            }
        }
    }

    // Ledger (HID).
    for detected in Ledger::<TransportHID>::enumerate(&api) {
        if let Ok(mut device) = Ledger::<TransportHID>::connect(&api, detected) {
            // A registered wallet policy (and its HMAC) is required before a
            // Ledger will operate on anything other than default single-sig.
            if let (Some(name), Some(policy)) = (wallet.name, wallet.policy) {
                let hmac = match wallet.hmac {
                    Some(s) => {
                        let bytes = Vec::from_hex(s)
                            .map_err(|e| Error::Generic(format!("Invalid HMAC hex: {e}")))?;
                        let mut h = [0u8; 32];
                        if bytes.len() != h.len() {
                            return Err(Error::Generic(
                                "HMAC must be 32 bytes (64 hex chars)".to_string(),
                            ));
                        }
                        h.copy_from_slice(&bytes);
                        Some(h)
                    }
                    None => None,
                };
                device = device
                    .with_wallet(name, policy, hmac)
                    .map_err(map_device_err)?;
            }
            devices.push(device.into());
        }
    }

    Ok(devices)
}

/// Enumerate devices and return the first one, erroring if none are found.
///
/// Used by the single-device subcommands (register/address/sign). If more than
/// one device is connected a warning is logged and the first is used.
pub async fn first_hwi_device(
    network: Network,
    wallet: &HwiWallet<'_>,
) -> Result<Box<dyn HWI + Send>, Error> {
    let devices = enumerate_hwi_devices(network, wallet).await?;
    let count = devices.len();
    if count > 1 {
        warn!("{count} hardware wallets detected; using the first one.");
    }
    devices
        .into_iter()
        .next()
        .ok_or_else(|| Error::Generic("No hardware wallet detected".to_string()))
}

fn map_device_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Generic(e.to_string())
}
