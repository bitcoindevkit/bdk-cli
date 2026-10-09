//! Hardware wallet (HWI) device discovery.
//!
//! Enumerates every supported hardware wallet that is currently reachable and
//! returns them as trait objects. Supported devices: Specter, Jade, Ledger,
//! Coldcard and BitBox02 (plus the Specter and Ledger simulators). The logic
//! mirrors the reference implementation shipped with the `async-hwi` crate so
//! that new devices supported upstream become available here with minimal
//! changes.

use async_hwi::bitbox::api::BitBox as BitBoxApi;
use async_hwi::bitbox::api::runtime::TokioRuntime;
use async_hwi::{
    HWI,
    bitbox::{BitBox02, NoiseConfigNoCache, PairingBitbox02WithLocalCache, api::runtime},
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

    // Specter (serial).
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

    // USB (HID): BitBox02, Coldcard and Ledger. A HID init failure is non-fatal
    match HidApi::new() {
        Ok(api) => {
            let api = Box::new(api);

            for device_info in api.device_list() {
                // BitBox02
                if async_hwi::bitbox::is_bitbox02(device_info)
                    && let Ok(handle) = device_info.open_device(&api)
                    && let Ok(pairing) =
                        PairingBitbox02WithLocalCache::<runtime::TokioRuntime>::connect(
                            handle, None,
                        )
                        .await
                    && let Ok((device, _)) = pairing.wait_confirm().await
                {
                    push_bitbox(
                        &mut devices,
                        BitBox02::from(device).with_network(network),
                        wallet.policy,
                    );
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
                if let Ok(device) = Ledger::<TransportHID>::connect(&api, detected) {
                    push_ledger(&mut devices, device, wallet)?;
                }
            }
        }
        Err(e) => warn!("HID API init failed; skipping USB devices: {e}"),
    }

    //  Simulators

    if let Ok(device) = SpecterSimulator::try_connect().await {
        devices.push(device.into());
    }
    if let Ok(device) = LedgerSimulator::try_connect().await {
        devices.push(device.into());
    }

    // BitBox02 simulator
    if let Ok(bitbox) =
        BitBoxApi::<TokioRuntime>::from_simulator(None, Box::new(NoiseConfigNoCache {})).await
    {
        match bitbox.unlock_and_pair().await {
            Ok(pairing) => match pairing.wait_confirm().await {
                Ok(paired) => {
                    // A freshly started simulator is unseeded, so key operations
                    // fail. Create a seed to carry out operations
                    if let Ok(info) = paired.device_info().await
                        && !info.initialized
                        && let Err(e) = paired.restore_from_mnemonic().await
                    {
                        warn!("BitBox simulator seeding failed: {e:?}");
                    }
                    push_bitbox(
                        &mut devices,
                        BitBox02::from(paired).with_network(network),
                        wallet.policy,
                    );
                }
                Err(e) => warn!("BitBox simulator pairing confirmation failed: {e:?}"),
            },
            Err(e) => warn!("BitBox simulator unlock/pair failed: {e:?}"),
        }
    }

    Ok(devices)
}

/// Select a single connected device, by `target_fingerprint` when given.
///
/// With no target and several devices connected, the first (physical devices
/// rank before simulators) is used and a warning lists the alternatives. The
/// chosen device's fingerprint and model are always logged.
pub async fn first_hwi_device(
    network: Network,
    wallet: &HwiWallet<'_>,
    target_fingerprint: Option<&str>,
) -> Result<Box<dyn HWI + Send>, Error> {
    let devices = enumerate_hwi_devices(network, wallet).await?;
    if devices.is_empty() {
        return Err(Error::Generic("No hardware wallet detected".to_string()));
    }

    // Label devices with their master fingerprint for selection and logging.
    let mut labeled: Vec<(String, Box<dyn HWI + Send>)> = Vec::with_capacity(devices.len());
    for device in devices {
        match device.get_master_fingerprint().await {
            Ok(fp) => labeled.push((fp.to_string(), device)),
            Err(e) => warn!("Ignoring a device with an unreadable fingerprint: {e:?}"),
        }
    }
    if labeled.is_empty() {
        return Err(Error::Generic(
            "No usable hardware wallet detected".to_string(),
        ));
    }

    let (fingerprint, device) = match target_fingerprint {
        Some(target) => labeled
            .into_iter()
            .find(|(fp, _)| fp.eq_ignore_ascii_case(target))
            .ok_or_else(|| {
                Error::Generic(format!("No connected device matches fingerprint {target}"))
            })?,
        None => {
            if labeled.len() > 1 {
                let fingerprints: Vec<&str> = labeled.iter().map(|(fp, _)| fp.as_str()).collect();
                warn!(
                    "{} hardware wallets connected ({}); using the first. Select one with --fingerprint.",
                    labeled.len(),
                    fingerprints.join(", ")
                );
            }
            labeled
                .into_iter()
                .next()
                .expect("labeled is non-empty here")
        }
    };

    warn!(
        "Using hardware wallet {fingerprint} ({})",
        device.device_kind()
    );
    Ok(device)
}

/// Attach an optional policy to a BitBox and push it. A policy failure skips
/// the device with a warning instead of aborting the whole scan.
fn push_bitbox(
    devices: &mut Vec<Box<dyn HWI + Send>>,
    bb02: BitBox02<TokioRuntime>,
    policy: Option<&str>,
) {
    match policy {
        Some(policy) => match bb02.with_policy(policy) {
            Ok(device) => devices.push(device.into()),
            Err(e) => warn!("BitBox with_policy failed; skipping device: {e:?}"),
        },
        None => devices.push(bb02.into()),
    }
}

/// Attach the wallet (name/policy/hmac) to a Ledger and push it. A `with_wallet`
/// failure skips the device with a warning; a malformed `--hmac` is a user error
/// and is returned.
fn push_ledger(
    devices: &mut Vec<Box<dyn HWI + Send>>,
    device: Ledger<TransportHID>,
    wallet: &HwiWallet<'_>,
) -> Result<(), Error> {
    let device = match (wallet.name, wallet.policy) {
        (Some(name), Some(policy)) => {
            let hmac = parse_registration_hmac(wallet.hmac)?;
            match device.with_wallet(name, policy, hmac) {
                Ok(device) => device,
                Err(e) => {
                    warn!("Ledger with_wallet failed; skipping device: {e:?}");
                    return Ok(());
                }
            }
        }
        _ => device,
    };
    devices.push(device.into());
    Ok(())
}

/// Parse a 32-byte registration HMAC from its hex representation.
fn parse_registration_hmac(hmac: Option<&str>) -> Result<Option<[u8; 32]>, Error> {
    let Some(s) = hmac else {
        return Ok(None);
    };
    let bytes = Vec::from_hex(s).map_err(|e| Error::Generic(format!("Invalid HMAC hex: {e}")))?;
    let mut h = [0u8; 32];
    if bytes.len() != h.len() {
        return Err(Error::Generic(
            "HMAC must be 32 bytes (64 hex chars)".to_string(),
        ));
    }
    h.copy_from_slice(&bytes);
    Ok(Some(h))
}
