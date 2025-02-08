// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Command Handlers
//!
//! This module describes all the command handling logic used by bdk-cli.

use std::collections::BTreeMap;
use std::convert::TryFrom;

use crate::commands::OfflineWalletSubCommand::*;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use crate::commands::OnlineWalletSubCommand::*;
use crate::commands::*;
use crate::error::BDKCliError as Error;
use crate::utils::*;
#[cfg(all(feature = "reserves", feature = "electrum"))]
use bdk_electrum::electrum_client::{Client, ElectrumApi};
#[cfg(all(feature = "reserves", feature = "electrum"))]
use bdk_reserves::bdk::bitcoin::psbt::PartiallySignedTransaction;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use bdk_reserves::bdk::{
    blockchain::{log_progress, Blockchain},
    SyncOptions,
};
use bdk_wallet::bip39::{Language, Mnemonic};
use bdk_wallet::bitcoin::bip32::{DerivationPath, KeySource};
use bdk_wallet::bitcoin::consensus::encode::{serialize, serialize_hex};
use bdk_wallet::bitcoin::script::PushBytesBuf;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::bitcoin::{secp256k1::Secp256k1, Txid};
use bdk_wallet::bitcoin::{Amount, FeeRate, Psbt, Sequence};
use bdk_wallet::descriptor::Segwitv0;
#[cfg(feature = "compiler")]
use bdk_wallet::descriptor::{Descriptor, Legacy, Miniscript};
use bdk_wallet::keys::bip39::WordCount;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, PersistedWallet, SignOptions};
use clap::Parser;

use bdk_wallet::keys::DescriptorKey::Secret;
use bdk_wallet::keys::{DerivableKey, DescriptorKey, ExtendedKey, GeneratableKey, GeneratedKey};
use bdk_wallet::miniscript::miniscript;
#[cfg(feature = "hardware-signer")]
use hwi::{
    types::{HWIChain, HWIDescriptor},
    HWIClient,
};

use bdk_macros::maybe_async;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use bdk_macros::maybe_await;
#[cfg(all(feature = "reserves", feature = "electrum"))]
use bdk_reserves::bdk::blockchain::Capability;
#[cfg(feature = "reserves")]
use bdk_reserves::reserves::{verify_proof, ProofOfReserves};
#[cfg(all(feature = "reserves", feature = "electrum"))]
use bdk_wallet::bitcoin::Address;
#[cfg(feature = "compiler")]
use bdk_wallet::miniscript::policy::Concrete;
#[cfg(feature = "repl")]
use regex::Regex;
#[cfg(feature = "repl")]
use rustyline::{error::ReadlineError, Editor};
use serde_json::json;
use std::str::FromStr;

/// Execute an offline wallet sub-command
///
/// Offline wallet sub-commands are described in [`OfflineWalletSubCommand`].
pub fn handle_offline_wallet_subcommand(
    wallet: &mut PersistedWallet<Connection>,
    wallet_opts: &WalletOpts,
    offline_subcommand: OfflineWalletSubCommand,
) -> Result<serde_json::Value, Error> {
    match offline_subcommand {
        GetNewAddress => {
            let addr = wallet.reveal_next_address(KeychainKind::External);
            if wallet_opts.verbose {
                Ok(json!({
                    "address": addr.address,
                    "index": addr.index
                }))
            } else {
                Ok(json!({
                    "address": addr.address,
                }))
            }
        }
        ListUnspent => Ok(serde_json::to_value(
            wallet.list_unspent().collect::<Vec<_>>(),
        )?),
        ListTransactions => {
            let transactions: Vec<_> = wallet
                .transactions()
                .map(|tx| {
                    json!({
                        "txid": tx.tx_node.txid,
                        "is_coinbase": tx.tx_node.is_coinbase(),
                        "wtxid": tx.tx_node.compute_wtxid(),
                        "version": tx.tx_node.version,
                        "is_rbf": tx.tx_node.is_explicitly_rbf(),
                        "inputs": tx.tx_node.input,
                        "outputs": tx.tx_node.output,
                    })
                })
                .collect();

            Ok(serde_json::to_value(transactions)?)
        }
        GetBalance => Ok(json!({"satoshi": wallet.balance()})),
        CreateTx {
            recipients,
            send_all,
            enable_rbf,
            offline_signer,
            utxos,
            unspendable,
            fee_rate,
            external_policy,
            internal_policy,
            add_data,
            add_string,
        } => {
            let mut tx_builder = wallet.build_tx();

            if send_all {
                tx_builder.drain_wallet().drain_to(recipients[0].0.clone());
            } else {
                let recipients = recipients
                    .into_iter()
                    .map(|(script, amount)| (script, Amount::from_sat(amount)))
                    .collect();
                tx_builder.set_recipients(recipients);
            }

            if !enable_rbf {
                tx_builder.set_exact_sequence(Sequence::MAX);
            }

            if offline_signer {
                tx_builder.include_output_redeem_witness_script();
            }

            if let Some(fee_rate) = fee_rate {
                if let Some(fee_rate) = FeeRate::from_sat_per_vb(fee_rate as u64) {
                    tx_builder.fee_rate(fee_rate);
                }
            }

            if let Some(utxos) = utxos {
                tx_builder.add_utxos(&utxos[..]);
            }

            if let Some(unspendable) = unspendable {
                tx_builder.unspendable(unspendable);
            }

            if let Some(base64_data) = add_data {
                let op_return_data = base64::decode(&base64_data).unwrap();
                tx_builder.add_data(&PushBytesBuf::try_from(op_return_data).unwrap());
            } else if let Some(string_data) = add_string {
                let data = PushBytesBuf::try_from(string_data.as_bytes().to_vec()).unwrap();
                tx_builder.add_data(&data);
            }

            let policies = vec![
                external_policy.map(|p| (p, KeychainKind::External)),
                internal_policy.map(|p| (p, KeychainKind::Internal)),
            ];

            for (policy, keychain) in policies.into_iter().flatten() {
                let policy = serde_json::from_str::<BTreeMap<String, Vec<usize>>>(&policy)?;
                tx_builder.policy_path(policy, keychain);
            }

            let psbt = tx_builder.finish()?;

            let serialized_psbt = psbt.serialize();
            let psbt_base64 = base64::encode(&serialized_psbt);

            if wallet_opts.verbose {
                Ok(
                    json!({"psbt": psbt_base64, "serialized_psbt": serialized_psbt, "details": psbt}),
                )
            } else {
                Ok(json!({"psbt": psbt_base64, "details": psbt}))
            }
        }
        BumpFee {
            txid,
            shrink_address,
            offline_signer,
            utxos,
            unspendable,
            fee_rate,
        } => {
            let txid = Txid::from_str(txid.as_str())?;

            let mut tx_builder = wallet.build_fee_bump(txid)?;
            let fee_rate =
                FeeRate::from_sat_per_vb(fee_rate as u64).unwrap_or(FeeRate::BROADCAST_MIN);
            tx_builder.fee_rate(fee_rate);

            if let Some(address) = shrink_address {
                let script_pubkey = address.script_pubkey();
                tx_builder.drain_to(script_pubkey);
            }

            if offline_signer {
                tx_builder.include_output_redeem_witness_script();
            }

            if let Some(utxos) = utxos {
                tx_builder.add_utxos(&utxos[..]);
            }

            if let Some(unspendable) = unspendable {
                tx_builder.unspendable(unspendable);
            }

            let psbt = tx_builder.finish()?;

            let serialized_psbt = psbt.serialize();
            let psbt_base64 = base64::encode(serialized_psbt);

            Ok(json!({"psbt": psbt_base64, "details": psbt}))
        }
        Policies => {
            let external_policy = wallet.policies(KeychainKind::External)?;
            let internal_policy = wallet.policies(KeychainKind::Internal)?;

            Ok(json!({
                "external": external_policy,
                "internal": internal_policy,
            }))
        }
        PublicDescriptor => Ok(json!({
            "external": wallet.public_descriptor(KeychainKind::External).to_string(),
            "internal": wallet.public_descriptor(KeychainKind::Internal).to_string(),
        })),
        Sign {
            psbt,
            assume_height,
            trust_witness_utxo,
        } => {
            let psbt_bytes = base64::decode(psbt)?;
            let mut psbt = Psbt::deserialize(&psbt_bytes)?;
            let signopt = SignOptions {
                assume_height,
                trust_witness_utxo: trust_witness_utxo.unwrap_or(false),
                ..Default::default()
            };
            let finalized = wallet.sign(&mut psbt, signopt)?;
            if wallet_opts.verbose {
                Ok(
                    json!({"psbt": base64::encode(serialize(&psbt_bytes)),"is_finalized": finalized, "serialized_psbt": psbt}),
                )
            } else {
                Ok(
                    json!({"psbt": base64::encode(serialize(&psbt_bytes)),"is_finalized": finalized,}),
                )
            }
        }
        ExtractPsbt { psbt } => {
            let psbt_serialized = base64::decode(psbt)?;
            let psbt = Psbt::deserialize(&psbt_serialized)?;
            let raw_tx = psbt.extract_tx()?;
            Ok(json!({"raw_tx": serialize_hex(&raw_tx),}))
        }
        FinalizePsbt {
            psbt,
            assume_height,
            trust_witness_utxo,
        } => {
            let psbt_bytes = base64::decode(psbt)?;
            let mut psbt: Psbt = Psbt::deserialize(&psbt_bytes)?;

            let signopt = SignOptions {
                assume_height,
                trust_witness_utxo: trust_witness_utxo.unwrap_or(false),
                ..Default::default()
            };
            let finalized = wallet.finalize_psbt(&mut psbt, signopt)?;
            if wallet_opts.verbose {
                Ok(
                    json!({ "psbt": base64::encode(serialize(&psbt_bytes)),"is_finalized": finalized, "serialized_psbt": psbt}),
                )
            } else {
                Ok(
                    json!({ "psbt": base64::encode(serialize(&psbt_bytes)),"is_finalized": finalized,}),
                )
            }
        }
        CombinePsbt { psbt } => {
            let mut psbts = psbt
                .iter()
                .map(|s| {
                    let psbt = base64::decode(s)?;
                    Ok(Psbt::deserialize(&psbt)?)
                })
                .collect::<Result<Vec<_>, Error>>()?;

            let init_psbt = psbts
                .pop()
                .ok_or_else(|| Error::Generic("Invalid PSBT input".to_string()))?;
            let final_psbt = psbts.into_iter().try_fold::<_, _, Result<Psbt, Error>>(
                init_psbt,
                |mut acc, x| {
                    let _ = acc.combine(x);
                    Ok(acc)
                },
            )?;
            Ok(json!({ "psbt": base64::encode(final_psbt.serialize()) }))
        }
    }
}

/// Execute an online wallet sub-command
///
/// Online wallet sub-commands are described in [`OnlineWalletSubCommand`].
#[maybe_async]
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
pub(crate) fn handle_online_wallet_subcommand(
    wallet: &Wallet,
    blockchain: &B,
    online_subcommand: OnlineWalletSubCommand,
) -> Result<serde_json::Value, Error> {
    match online_subcommand {
        Sync => {
            maybe_await!(wallet.sync(
                blockchain,
                SyncOptions {
                    progress: Some(Box::new(log_progress())),
                }
            ))?;
            Ok(json!({}))
        }
        Broadcast { psbt, tx } => {
            let tx = match (psbt, tx) {
                (Some(psbt), None) => {
                    let psbt = base64::decode(&psbt).map_err(|e| Error::Generic(e.to_string()))?;
                    let psbt: Psbt = Psbt::deserialize(&psbt)?;
                    is_final(&psbt)?;
                    psbt.extract_tx()
                }
                (None, Some(tx)) => Psbt::deserialize(&Vec::<u8>::from_hex(&tx)?)?,
                (Some(_), Some(_)) => panic!("Both `psbt` and `tx` options not allowed"),
                (None, None) => panic!("Missing `psbt` and `tx` option"),
            };
            maybe_await!(blockchain.broadcast(&tx))?;
            Ok(json!({ "txid": tx.txid() }))
        }
        #[cfg(feature = "reserves")]
        ProduceProof { msg } => {
            let mut psbt = maybe_await!(wallet.create_proof(&msg))?;

            let _finalized = wallet.sign(
                &mut psbt,
                SignOptions {
                    trust_witness_utxo: true,
                    ..Default::default()
                },
            )?;

            let psbt_ser = serialize(&psbt);
            let psbt_b64 = base64::encode(&psbt_ser);

            Ok(json!({ "psbt": psbt , "psbt_base64" : psbt_b64}))
        }
        #[cfg(feature = "reserves")]
        VerifyProof {
            psbt,
            msg,
            confirmations,
        } => {
            let psbt = base64::decode(&psbt)?;
            let psbt: Psbt = Psbt::deserialize(&psbt)?;
            let current_height = blockchain.get_height()?;
            let max_confirmation_height = if confirmations == 0 {
                None
            } else {
                if !blockchain
                    .get_capabilities()
                    .contains(&Capability::GetAnyTx)
                {
                    return Err(Error::Generic(
                        "For validating a proof with a certain number of confirmations, we need a Blockchain with the GetAnyTx capability."
                        .to_string()
                    ));
                }
                Some(current_height - confirmations)
            };

            let spendable =
                maybe_await!(wallet.verify_proof(&psbt, &msg, max_confirmation_height))?;
            Ok(json!({ "spendable": spendable }))
        }
    }
}

/// Determine if PSBT has final script sigs or witnesses for all unsigned tx inputs.
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
pub(crate) fn is_final(psbt: &Psbt) -> Result<(), Error> {
    let unsigned_tx_inputs = psbt.unsigned_tx.input.len();
    let psbt_inputs = psbt.inputs.len();
    if unsigned_tx_inputs != psbt_inputs {
        return Err(Error::Generic(format!(
            "Malformed PSBT, {} unsigned tx inputs and {} psbt inputs.",
            unsigned_tx_inputs, psbt_inputs
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

/// Handle a key sub-command
///
/// Key sub-commands are described in [`KeySubCommand`].
pub(crate) fn handle_key_subcommand(
    network: Network,
    subcommand: KeySubCommand,
) -> Result<serde_json::Value, Error> {
    let secp = Secp256k1::new();

    match subcommand {
        KeySubCommand::Generate {
            word_count,
            password,
        } => {
            let mnemonic_type = match word_count {
                12 => WordCount::Words12,
                _ => WordCount::Words24,
            };
            let mnemonic: GeneratedKey<_, miniscript::BareCtx> =
                Mnemonic::generate((mnemonic_type, Language::English))
                    .map_err(|_| Error::Generic("Mnemonic generation error".to_string()))?;
            let mnemonic = mnemonic.into_key();
            let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).ok_or_else(|| {
                Error::Generic("Privatekey info not found (should not happen)".to_string())
            })?;
            let fingerprint = xprv.fingerprint(&secp);
            let phrase = mnemonic
                .words()
                .fold("".to_string(), |phrase, w| phrase + w + " ")
                .trim()
                .to_string();
            Ok(
                json!({ "mnemonic": phrase, "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }),
            )
        }
        KeySubCommand::Restore { mnemonic, password } => {
            let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)?;
            let xkey: ExtendedKey = (mnemonic, password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).ok_or_else(|| {
                Error::Generic("Privatekey info not found (should not happen)".to_string())
            })?;
            let fingerprint = xprv.fingerprint(&secp);

            Ok(json!({ "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }))
        }
        KeySubCommand::Derive { xprv, path } => {
            if xprv.network != network.into() {
                return Err(Error::Generic("Invalid network".to_string()));
            }
            let derived_xprv = &xprv.derive_priv(&secp, &path)?;

            let origin: KeySource = (xprv.fingerprint(&secp), path);

            let derived_xprv_desc_key: DescriptorKey<Segwitv0> =
                derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default())?;

            if let Secret(desc_seckey, _, _) = derived_xprv_desc_key {
                let desc_pubkey = desc_seckey.to_public(&secp)?;
                Ok(json!({"xpub": desc_pubkey.to_string(), "xprv": desc_seckey.to_string()}))
            } else {
                Err(Error::Generic("Invalid key variant".to_string()))
            }
        }
        #[cfg(feature = "hardware-signer")]
        KeySubCommand::Hardware {} => {
            let chain = HWIChain::from(network);
            let devices = HWIClient::enumerate().map_err(|e| Error::Generic(e.to_string()))?;
            let descriptors = devices.iter().map(|device_| {
                let device = device_.as_ref().map_err(|e| Error::Generic(e.to_string()))?;
                let client = HWIClient::get_client(&device, true, chain.clone()).unwrap();
                let descriptors: HWIDescriptor<String> = client.get_descriptors(None).map_err(|e|Error::Generic(e.to_string()))?;
                Ok(json!({"device": device.model, "receiving": descriptors.receive[0].to_string(), "change": descriptors.internal[0]}))
            }).collect::<Result<Vec<_>, Error>>()?;
            Ok(json!(descriptors))
        }
    }
}

/// Handle the miniscript compiler sub-command
///
/// Compiler options are described in [`CliSubCommand::Compile`].
#[cfg(feature = "compiler")]
pub(crate) fn handle_compile_subcommand(
    _network: Network,
    policy: String,
    script_type: String,
) -> Result<serde_json::Value, Error> {
    let policy = Concrete::<String>::from_str(policy.as_str())?;
    let legacy_policy: Miniscript<String, Legacy> = policy
        .compile()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let segwit_policy: Miniscript<String, Segwitv0> = policy
        .compile()
        .map_err(|e| Error::Generic(e.to_string()))?;

    let descriptor = match script_type.as_str() {
        "sh" => Descriptor::new_sh(legacy_policy),
        "wsh" => Descriptor::new_wsh(segwit_policy),
        "sh-wsh" => Descriptor::new_sh_wsh(segwit_policy),
        _ => panic!("Invalid type"),
    }?;

    Ok(json!({"descriptor": descriptor.to_string()}))
}

/// Handle Proof of Reserves commands
///
/// Proof of reserves options are described in [`CliSubCommand::ExternalReserves`].
#[cfg(all(feature = "reserves", feature = "electrum"))]
pub(crate) fn handle_ext_reserves_subcommand(
    network: bdk_reserves::bdk::bitcoin::Network,
    message: String,
    psbt: String,
    confirmations: usize,
    addresses: Vec<String>,
    electrum_opts: ElectrumOpts,
) -> Result<serde_json::Value, Error> {
    let psbt = base64::decode(&psbt)?;

    let psbt: PartiallySignedTransaction = PartiallySignedTransaction::deserialize(&psbt)
        .map_err(|e| Error::Generic(e.to_string()))?;
    let client = Client::new(&electrum_opts.server).map_err(|e| Error::Generic(e.to_string()))?;

    let current_block_height = client
        .block_headers_subscribe()
        .map(|data| data.height)
        .map_err(|e| {
            Error::Generic(format!(
                "Failed to get block height from electrum server: {:?}",
                e
            ))
        })?;
    let max_confirmation_height = Some(current_block_height - confirmations);

    let outpoints_per_addr = addresses
        .iter()
        .map(|address| {
            let address = Address::from_str(address)?.assume_checked();
            get_outpoints_for_address(address, &client, max_confirmation_height)
        })
        .collect::<Result<Vec<Vec<_>>, Error>>()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let outpoints_combined = outpoints_per_addr
        .iter()
        .fold(Vec::new(), |mut outpoints, outs| {
            outpoints.append(&mut outs.clone());
            outpoints
        });

    let spendable = verify_proof(&psbt, &message, outpoints_combined, network)
        .map_err(|e| Error::Generic(format!("{:?}", e)))?;

    Ok(json!({ "spendable": spendable }))
}

/// The global top level handler.
#[maybe_async]
pub(crate) fn handle_command(cli_opts: CliOpts) -> Result<String, Error> {
    let network = cli_opts.network;
    let home_dir = prepare_home_dir(cli_opts.datadir)?;
    let result = match cli_opts.subcommand {
        #[cfg(feature = "regtest-node")]
        CliSubCommand::Node { subcommand: cmd } => {
            let backend = new_backend(&home_dir)?;
            serde_json::to_string_pretty(&backend.exec_cmd(cmd)?)
        }
        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "compact_filters",
            feature = "rpc"
        ))]
        CliSubCommand::Wallet {
            wallet_opts,
            subcommand: WalletSubCommand::OnlineWalletSubCommand(online_subcommand),
        } => {
            let wallet_opts = maybe_descriptor_wallet_name(wallet_opts, cli_opts.network)?;
            let database = open_database(&wallet_opts, &home_dir)?;
            let backend = new_backend(&home_dir)?;
            let blockchain = new_blockchain(network, &wallet_opts, &backend, &home_dir)?;
            let wallet = new_wallet(network, &wallet_opts, database)?;
            let result = maybe_await!(handle_online_wallet_subcommand(
                &wallet,
                &blockchain,
                online_subcommand
            ))?;
            serde_json::to_string_pretty(&result)
        }
        CliSubCommand::Wallet {
            wallet_opts,
            subcommand: WalletSubCommand::OfflineWalletSubCommand(offline_subcommand),
        } => {
            let wallet_opts = maybe_descriptor_wallet_name(wallet_opts, network)?;
            let database = open_database(&wallet_opts, &home_dir)?;
            let mut wallet = new_wallet(network, &wallet_opts, database)?;
            let result =
                handle_offline_wallet_subcommand(&mut wallet, &wallet_opts, offline_subcommand)?;
            serde_json::to_string_pretty(&result)
        }
        CliSubCommand::Key {
            subcommand: key_subcommand,
        } => {
            let result = handle_key_subcommand(cli_opts.network, key_subcommand)?;
            serde_json::to_string_pretty(&result)
        }
        #[cfg(feature = "compiler")]
        CliSubCommand::Compile {
            policy,
            script_type,
        } => {
            let result = handle_compile_subcommand(cli_opts.network, policy, script_type)?;
            serde_json::to_string_pretty(&result)
        }
        #[cfg(feature = "repl")]
        CliSubCommand::Repl { wallet_opts } => {
            let wallet_opts = maybe_descriptor_wallet_name(wallet_opts, cli_opts.network)?;
            let database = open_database(&wallet_opts, &home_dir)?;

            let mut wallet = new_wallet(cli_opts.network, &wallet_opts, database)?;

            let mut rl = Editor::<()>::new();

            // if rl.load_history("history.txt").is_err() {
            //     println!("No previous history.");
            // }

            let split_regex = Regex::new(crate::REPL_LINE_SPLIT_REGEX)?;

            #[cfg(any(
                feature = "electrum",
                feature = "esplora",
                feature = "compact_filters",
                feature = "rpc"
            ))]
            let backend = new_backend(&home_dir)?;

            loop {
                let readline = rl.readline(">> ");
                match readline {
                    Ok(line) => {
                        if line.trim() == "" {
                            continue;
                        }
                        rl.add_history_entry(line.as_str());
                        let split_line: Vec<&str> = split_regex
                            .captures_iter(&line)
                            .map(|c| {
                                Ok(c.get(1)
                                    .or_else(|| c.get(2))
                                    .or_else(|| c.get(3))
                                    .ok_or_else(|| Error::Generic("Invalid commands".to_string()))?
                                    .as_str())
                            })
                            .collect::<Result<Vec<_>, Error>>()?;
                        let repl_subcommand = ReplSubCommand::from_iter_safe(split_line);
                        if let Err(err) = repl_subcommand {
                            println!("{}", err);
                            continue;
                        }
                        // if error will be printed above
                        let repl_subcommand = repl_subcommand.unwrap();
                        log::debug!("repl_subcommand = {:?}", repl_subcommand);

                        let result = match repl_subcommand {
                            #[cfg(feature = "regtest-node")]
                            ReplSubCommand::Node { subcommand } => {
                                match backend.exec_cmd(subcommand) {
                                    Ok(result) => Ok(result),
                                    Err(e) => Ok(serde_json::Value::String(e.to_string())),
                                }
                            }
                            #[cfg(any(
                                feature = "electrum",
                                feature = "esplora",
                                feature = "compact_filters",
                                feature = "rpc"
                            ))]
                            ReplSubCommand::Wallet {
                                subcommand:
                                    WalletSubCommand::OnlineWalletSubCommand(online_subcommand),
                            } => {
                                let blockchain = new_blockchain(
                                    cli_opts.network,
                                    &wallet_opts,
                                    &backend,
                                    &home_dir,
                                )?;
                                maybe_await!(handle_online_wallet_subcommand(
                                    &wallet,
                                    &blockchain,
                                    online_subcommand,
                                ))
                            }
                            ReplSubCommand::Wallet {
                                subcommand:
                                    WalletSubCommand::OfflineWalletSubCommand(offline_subcommand),
                            } => handle_offline_wallet_subcommand(
                                &mut wallet,
                                &wallet_opts,
                                offline_subcommand,
                            ),
                            ReplSubCommand::Key { subcommand } => {
                                handle_key_subcommand(cli_opts.network, subcommand)
                            }
                            ReplSubCommand::Exit => break,
                        };

                        println!("{}", serde_json::to_string_pretty(&result?)?);
                    }
                    Err(ReadlineError::Interrupted) => continue,
                    Err(ReadlineError::Eof) => break,
                    Err(err) => {
                        println!("{:?}", err);
                        break;
                    }
                }
            }

            Ok("Exiting REPL".to_string())
        }
        #[cfg(all(feature = "reserves", feature = "electrum"))]
        CliSubCommand::ExternalReserves {
            message,
            psbt,
            confirmations,
            addresses,
            electrum_opts,
        } => {
            let result = handle_ext_reserves_subcommand(
                cli_opts.network,
                message,
                psbt,
                confirmations,
                addresses,
                electrum_opts,
            )?;
            serde_json::to_string_pretty(&result)
        }
    };
    result.map_err(|e| e.into())
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
#[cfg(test)]
mod test {
    use bdk_wallet::bitcoin::Psbt;

    use super::is_final;
    use std::str::FromStr;

    #[test]
    fn test_psbt_is_final() {
        let unsigned_psbt = Psbt::from_str("cHNidP8BAIkBAAAAASWJHzxzyVORV/C3lAynKHVVL7+Rw7/Jj8U9fuvD24olAAAAAAD+////AiBOAAAAAAAAIgAgLzY9yE4jzTFJnHtTjkc+rFAtJ9NB7ENFQ1xLYoKsI1cfqgKVAAAAACIAIFsbWgDeLGU8EA+RGwBDIbcv4gaGG0tbEIhDvwXXa/E7LwEAAAABALUCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BALLAAD/////AgD5ApUAAAAAIgAgWxtaAN4sZTwQD5EbAEMhty/iBoYbS1sQiEO/Bddr8TsAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQErAPkClQAAAAAiACBbG1oA3ixlPBAPkRsAQyG3L+IGhhtLWxCIQ78F12vxOwEFR1IhA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDIQLKhV/gEZYmlsQXnsL5/Uqv5Y8O31tmWW1LQqIBkiqzCVKuIgYCyoVf4BGWJpbEF57C+f1Kr+WPDt9bZlltS0KiAZIqswkEboH3lCIGA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDBDS6ZSEAACICAsqFX+ARliaWxBeewvn9Sq/ljw7fW2ZZbUtCogGSKrMJBG6B95QiAgPyVdlP9KV1voj+PUHLGIpRL5GRHeKYZgzPJ1fMAvjHgwQ0umUhAA==").unwrap();
        assert!(is_final(&unsigned_psbt).is_err());

        let part_signed_psbt = Psbt::from_str("cHNidP8BAIkBAAAAASWJHzxzyVORV/C3lAynKHVVL7+Rw7/Jj8U9fuvD24olAAAAAAD+////AiBOAAAAAAAAIgAgLzY9yE4jzTFJnHtTjkc+rFAtJ9NB7ENFQ1xLYoKsI1cfqgKVAAAAACIAIFsbWgDeLGU8EA+RGwBDIbcv4gaGG0tbEIhDvwXXa/E7LwEAAAABALUCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BALLAAD/////AgD5ApUAAAAAIgAgWxtaAN4sZTwQD5EbAEMhty/iBoYbS1sQiEO/Bddr8TsAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQErAPkClQAAAAAiACBbG1oA3ixlPBAPkRsAQyG3L+IGhhtLWxCIQ78F12vxOyICA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDSDBFAiEAnNPpu6wNX2HXYz8s2q5nXug4cWfvCGD3SSH2CNKm+yECIEQO7/URhUPsGoknMTE+GrYJf9Wxqn9QsuN9FGj32cQpAQEFR1IhA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDIQLKhV/gEZYmlsQXnsL5/Uqv5Y8O31tmWW1LQqIBkiqzCVKuIgYCyoVf4BGWJpbEF57C+f1Kr+WPDt9bZlltS0KiAZIqswkEboH3lCIGA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDBDS6ZSEAACICAsqFX+ARliaWxBeewvn9Sq/ljw7fW2ZZbUtCogGSKrMJBG6B95QiAgPyVdlP9KV1voj+PUHLGIpRL5GRHeKYZgzPJ1fMAvjHgwQ0umUhAA==").unwrap();
        assert!(is_final(&part_signed_psbt).is_err());

        let full_signed_psbt = Psbt::from_str("cHNidP8BAIkBAAAAASWJHzxzyVORV/C3lAynKHVVL7+Rw7/Jj8U9fuvD24olAAAAAAD+////AiBOAAAAAAAAIgAgLzY9yE4jzTFJnHtTjkc+rFAtJ9NB7ENFQ1xLYoKsI1cfqgKVAAAAACIAIFsbWgDeLGU8EA+RGwBDIbcv4gaGG0tbEIhDvwXXa/E7LwEAAAABALUCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BALLAAD/////AgD5ApUAAAAAIgAgWxtaAN4sZTwQD5EbAEMhty/iBoYbS1sQiEO/Bddr8TsAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQErAPkClQAAAAAiACBbG1oA3ixlPBAPkRsAQyG3L+IGhhtLWxCIQ78F12vxOwEFR1IhA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDIQLKhV/gEZYmlsQXnsL5/Uqv5Y8O31tmWW1LQqIBkiqzCVKuIgYCyoVf4BGWJpbEF57C+f1Kr+WPDt9bZlltS0KiAZIqswkEboH3lCIGA/JV2U/0pXW+iP49QcsYilEvkZEd4phmDM8nV8wC+MeDBDS6ZSEBBwABCNsEAEgwRQIhAJzT6busDV9h12M/LNquZ17oOHFn7whg90kh9gjSpvshAiBEDu/1EYVD7BqJJzExPhq2CX/Vsap/ULLjfRRo99nEKQFHMEQCIGoFCvJ2zPB7PCpznh4+1jsY03kMie49KPoPDdr7/T9TAiB3jV7wzR9BH11FSbi+8U8gSX95PrBlnp1lOBgTUIUw3QFHUiED8lXZT/Sldb6I/j1ByxiKUS+RkR3imGYMzydXzAL4x4MhAsqFX+ARliaWxBeewvn9Sq/ljw7fW2ZZbUtCogGSKrMJUq4AACICAsqFX+ARliaWxBeewvn9Sq/ljw7fW2ZZbUtCogGSKrMJBG6B95QiAgPyVdlP9KV1voj+PUHLGIpRL5GRHeKYZgzPJ1fMAvjHgwQ0umUhAA==").unwrap();
        assert!(is_final(&full_signed_psbt).is_ok());
    }
}
