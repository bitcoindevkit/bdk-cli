// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Command Handlers
//!
//! This module describes all the command handling logic used by bdk-cli

use std::collections::BTreeMap;

use crate::commands::OfflineWalletSubCommand::*;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use crate::commands::OnlineWalletSubCommand::*;
use crate::commands::*;
use crate::utils::*;
use crate::Nodes;
use bdk::{database::BatchDatabase, wallet::AddressIndex, Error, FeeRate, KeychainKind, Wallet};

use structopt::StructOpt;

use bdk::bitcoin::base64;
use bdk::bitcoin::consensus::encode::{deserialize, serialize, serialize_hex};
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use bdk::bitcoin::hashes::hex::FromHex;
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::{DerivationPath, KeySource};
use bdk::bitcoin::util::psbt::PartiallySignedTransaction;
use bdk::bitcoin::{Network, Txid};
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use bdk::blockchain::{log_progress, Blockchain};
use bdk::descriptor::Segwitv0;
#[cfg(feature = "compiler")]
use bdk::descriptor::{Descriptor, Legacy, Miniscript};
#[cfg(all(feature = "reserves", feature = "electrum"))]
use bdk::electrum_client::{Client, ElectrumApi};
use bdk::keys::bip39::{Language, Mnemonic, WordCount};
use bdk::keys::DescriptorKey::Secret;
use bdk::keys::KeyError::{InvalidNetwork, Message};
use bdk::keys::{DerivableKey, DescriptorKey, ExtendedKey, GeneratableKey, GeneratedKey};
use bdk::miniscript::miniscript;
#[cfg(feature = "compiler")]
use bdk::miniscript::policy::Concrete;
use bdk::SignOptions;
#[cfg(all(feature = "reserves", feature = "electrum"))]
use bdk::{
    bitcoin::{Address, OutPoint, TxOut},
    blockchain::Capability,
};
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use bdk_macros::{maybe_async, maybe_await};
#[cfg(feature = "reserves")]
use bdk_reserves::reserves::verify_proof;
#[cfg(feature = "reserves")]
use bdk_reserves::reserves::ProofOfReserves;
#[cfg(feature = "repl")]
use regex::Regex;
#[cfg(feature = "repl")]
use rustyline::error::ReadlineError;
#[cfg(feature = "repl")]
use rustyline::Editor;
use serde_json::json;
use std::str::FromStr;

/// Execute an offline wallet sub-command
///
/// Offline wallet sub-commands are described in [`OfflineWalletSubCommand`].
pub fn handle_offline_wallet_subcommand<D>(
    wallet: &Wallet<D>,
    wallet_opts: &WalletOpts,
    offline_subcommand: OfflineWalletSubCommand,
) -> Result<serde_json::Value, Error>
where
    D: BatchDatabase,
{
    match offline_subcommand {
        GetNewAddress => {
            let addr = wallet.get_address(AddressIndex::New)?;
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
        ListUnspent => Ok(serde_json::to_value(&wallet.list_unspent()?)?),
        ListTransactions => Ok(serde_json::to_value(
            &wallet.list_transactions(wallet_opts.verbose)?,
        )?),
        GetBalance => Ok(json!({"satoshi": wallet.get_balance()?})),
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
                tx_builder.set_recipients(recipients);
            }

            if enable_rbf {
                tx_builder.enable_rbf();
            }

            if offline_signer {
                tx_builder.include_output_redeem_witness_script();
            }

            if let Some(fee_rate) = fee_rate {
                tx_builder.fee_rate(FeeRate::from_sat_per_vb(fee_rate));
            }

            if let Some(utxos) = utxos {
                tx_builder.add_utxos(&utxos[..])?.manually_selected_only();
            }

            if let Some(unspendable) = unspendable {
                tx_builder.unspendable(unspendable);
            }

            if let Some(base64_data) = add_data {
                let op_return_data = base64::decode(&base64_data).unwrap();
                tx_builder.add_data(op_return_data.as_slice());
            } else if let Some(string_data) = add_string {
                tx_builder.add_data(string_data.as_bytes());
            }

            let policies = vec![
                external_policy.map(|p| (p, KeychainKind::External)),
                internal_policy.map(|p| (p, KeychainKind::Internal)),
            ];

            for (policy, keychain) in policies.into_iter().flatten() {
                let policy = serde_json::from_str::<BTreeMap<String, Vec<usize>>>(&policy)
                    .map_err(|s| Error::Generic(s.to_string()))?;
                tx_builder.policy_path(policy, keychain);
            }

            let (psbt, details) = tx_builder.finish()?;
            if wallet_opts.verbose {
                Ok(
                    json!({"psbt": base64::encode(&serialize(&psbt)),"details": details, "serialized_psbt": psbt}),
                )
            } else {
                Ok(json!({"psbt": base64::encode(&serialize(&psbt)),"details": details}))
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
            let txid = Txid::from_str(txid.as_str()).map_err(|s| Error::Generic(s.to_string()))?;

            let mut tx_builder = wallet.build_fee_bump(txid)?;
            tx_builder.fee_rate(FeeRate::from_sat_per_vb(fee_rate));

            if let Some(address) = shrink_address {
                let script_pubkey = address.script_pubkey();
                tx_builder.allow_shrinking(script_pubkey)?;
            }

            if offline_signer {
                tx_builder.include_output_redeem_witness_script();
            }

            if let Some(utxos) = utxos {
                tx_builder.add_utxos(&utxos[..])?;
            }

            if let Some(unspendable) = unspendable {
                tx_builder.unspendable(unspendable);
            }

            let (psbt, details) = tx_builder.finish()?;
            Ok(json!({"psbt": base64::encode(&serialize(&psbt)),"details": details,}))
        }
        Policies => Ok(json!({
            "external": wallet.policies(KeychainKind::External)?,
            "internal": wallet.policies(KeychainKind::Internal)?,
        })),
        PublicDescriptor => Ok(json!({
            "external": wallet.public_descriptor(KeychainKind::External)?.map(|d| d.to_string()),
            "internal": wallet.public_descriptor(KeychainKind::Internal)?.map(|d| d.to_string()),
        })),
        Sign {
            psbt,
            assume_height,
            trust_witness_utxo,
        } => {
            let psbt = base64::decode(&psbt).map_err(|e| Error::Generic(e.to_string()))?;
            let mut psbt: PartiallySignedTransaction = deserialize(&psbt)?;
            let signopt = SignOptions {
                assume_height,
                trust_witness_utxo: trust_witness_utxo.unwrap_or(false),
                ..Default::default()
            };
            let finalized = wallet.sign(&mut psbt, signopt)?;
            if wallet_opts.verbose {
                Ok(
                    json!({"psbt": base64::encode(&serialize(&psbt)),"is_finalized": finalized, "serialized_psbt": psbt}),
                )
            } else {
                Ok(json!({"psbt": base64::encode(&serialize(&psbt)),"is_finalized": finalized,}))
            }
        }
        ExtractPsbt { psbt } => {
            let psbt = base64::decode(&psbt).map_err(|e| Error::Generic(e.to_string()))?;
            let psbt: PartiallySignedTransaction = deserialize(&psbt)?;
            Ok(json!({"raw_tx": serialize_hex(&psbt.extract_tx()),}))
        }
        FinalizePsbt {
            psbt,
            assume_height,
            trust_witness_utxo,
        } => {
            let psbt = base64::decode(&psbt).map_err(|e| Error::Generic(e.to_string()))?;
            let mut psbt: PartiallySignedTransaction = deserialize(&psbt)?;

            let signopt = SignOptions {
                assume_height,
                trust_witness_utxo: trust_witness_utxo.unwrap_or(false),
                ..Default::default()
            };
            let finalized = wallet.finalize_psbt(&mut psbt, signopt)?;
            if wallet_opts.verbose {
                Ok(
                    json!({ "psbt": base64::encode(&serialize(&psbt)),"is_finalized": finalized, "serialized_psbt": psbt}),
                )
            } else {
                Ok(json!({ "psbt": base64::encode(&serialize(&psbt)),"is_finalized": finalized,}))
            }
        }
        CombinePsbt { psbt } => {
            let mut psbts = psbt
                .iter()
                .map(|s| {
                    let psbt = base64::decode(&s).map_err(|e| Error::Generic(e.to_string()))?;
                    let psbt: PartiallySignedTransaction = deserialize(&psbt)?;
                    Ok(psbt)
                })
                .collect::<Result<Vec<_>, Error>>()?;

            let init_psbt = psbts
                .pop()
                .ok_or_else(|| Error::Generic("Invalid PSBT input".to_string()))?;
            let final_psbt = psbts
                .into_iter()
                .try_fold::<_, _, Result<PartiallySignedTransaction, Error>>(
                    init_psbt,
                    |mut acc, x| {
                        acc.combine(x)?;
                        Ok(acc)
                    },
                )?;
            Ok(json!({ "psbt": base64::encode(&serialize(&final_psbt)) }))
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
pub fn handle_online_wallet_subcommand<B, D>(
    wallet: &Wallet<D>,
    blockchain: &B,
    online_subcommand: OnlineWalletSubCommand,
) -> Result<serde_json::Value, Error>
where
    B: Blockchain,
    D: BatchDatabase,
{
    use bdk::SyncOptions;

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
                    let psbt: PartiallySignedTransaction = deserialize(&psbt)?;
                    psbt.extract_tx()
                }
                (None, Some(tx)) => deserialize(&Vec::<u8>::from_hex(&tx)?)?,
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
            let psbt = base64::decode(&psbt).unwrap();
            let psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();
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

/// Execute a key sub-command
///
/// Key sub-commands are described in [`KeySubCommand`].
pub fn handle_key_subcommand(
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
                .word_iter()
                .fold("".to_string(), |phrase, w| phrase + w + " ")
                .trim()
                .to_string();
            Ok(
                json!({ "mnemonic": phrase, "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }),
            )
        }
        KeySubCommand::Restore { mnemonic, password } => {
            let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
                .map_err(|e| Error::Generic(e.to_string()))?;
            let xkey: ExtendedKey = (mnemonic, password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).ok_or_else(|| {
                Error::Generic("Privatekey info not found (should not happen)".to_string())
            })?;
            let fingerprint = xprv.fingerprint(&secp);

            Ok(json!({ "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }))
        }
        KeySubCommand::Derive { xprv, path } => {
            if xprv.network != network {
                return Err(Error::Key(InvalidNetwork));
            }
            let derived_xprv = &xprv.derive_priv(&secp, &path)?;

            let origin: KeySource = (xprv.fingerprint(&secp), path);

            let derived_xprv_desc_key: DescriptorKey<Segwitv0> =
                derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default())?;

            if let Secret(desc_seckey, _, _) = derived_xprv_desc_key {
                let desc_pubkey = desc_seckey
                    .as_public(&secp)
                    .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(json!({"xpub": desc_pubkey.to_string(), "xprv": desc_seckey.to_string()}))
            } else {
                Err(Error::Key(Message("Invalid key variant".to_string())))
            }
        }
    }
}

/// Execute the miniscript compiler sub-command
///
/// Compiler options are described in [`CliSubCommand::Compile`].
#[cfg(feature = "compiler")]
pub fn handle_compile_subcommand(
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
    }
    .map_err(Error::Miniscript)?;

    Ok(json!({"descriptor": descriptor.to_string()}))
}

/// Proof of reserves verification sub-command
///
/// Proof of reserves options are described in [`CliSubCommand::ExternalReserves`].
#[cfg(all(feature = "reserves", feature = "electrum"))]
pub fn handle_ext_reserves_subcommand(
    network: Network,
    message: String,
    psbt: String,
    confirmations: usize,
    addresses: Vec<String>,
    electrum_opts: ElectrumOpts,
) -> Result<serde_json::Value, Error> {
    let psbt = base64::decode(&psbt)
        .map_err(|e| Error::Generic(format!("Base64 decode error: {:?}", e)))?;
    let psbt: PartiallySignedTransaction = deserialize(&psbt)?;
    let client = Client::new(&electrum_opts.server)?;

    let current_block_height = client.block_headers_subscribe().map(|data| data.height)?;
    let max_confirmation_height = Some(current_block_height - confirmations);

    let outpoints_per_addr = addresses
        .iter()
        .map(|address| {
            let address = Address::from_str(address)
                .map_err(|e| Error::Generic(format!("Invalid address: {:?}", e)))?;
            get_outpoints_for_address(address, &client, max_confirmation_height)
        })
        .collect::<Result<Vec<Vec<_>>, Error>>()?;
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

#[cfg(all(feature = "reserves", feature = "electrum"))]
pub fn get_outpoints_for_address(
    address: Address,
    client: &Client,
    max_confirmation_height: Option<usize>,
) -> Result<Vec<(OutPoint, TxOut)>, Error> {
    let unspents = client
        .script_list_unspent(&address.script_pubkey())
        .map_err(Error::Electrum)?;

    unspents
        .iter()
        .filter(|utxo| {
            utxo.height > 0 && utxo.height <= max_confirmation_height.unwrap_or(usize::MAX)
        })
        .map(|utxo| {
            let tx = match client.transaction_get(&utxo.tx_hash) {
                Ok(tx) => tx,
                Err(e) => {
                    return Err(e).map_err(Error::Electrum);
                }
            };

            Ok((
                OutPoint {
                    txid: utxo.tx_hash,
                    vout: utxo.tx_pos as u32,
                },
                tx.output[utxo.tx_pos].clone(),
            ))
        })
        .collect()
}

pub fn handle_command(
    cli_opts: CliOpts,
    network: Network,
    _backend: Nodes,
) -> Result<String, Error> {
    let result = match cli_opts.subcommand {
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
            let wallet_opts = maybe_descriptor_wallet_name(wallet_opts, network)?;
            let database = open_database(&wallet_opts)?;
            let blockchain = new_blockchain(network, &wallet_opts, &_backend)?;
            let wallet = new_wallet(network, &wallet_opts, database)?;
            let result = handle_online_wallet_subcommand(&wallet, &blockchain, online_subcommand)?;
            serde_json::to_string_pretty(&result)?
        }
        CliSubCommand::Wallet {
            wallet_opts,
            subcommand: WalletSubCommand::OfflineWalletSubCommand(offline_subcommand),
        } => {
            let wallet_opts = maybe_descriptor_wallet_name(wallet_opts, network)?;
            let database = open_database(&wallet_opts)?;
            let wallet = new_wallet(network, &wallet_opts, database)?;
            let result =
                handle_offline_wallet_subcommand(&wallet, &wallet_opts, offline_subcommand)?;
            serde_json::to_string_pretty(&result)?
        }
        CliSubCommand::Key {
            subcommand: key_subcommand,
        } => {
            let result = handle_key_subcommand(network, key_subcommand)?;
            serde_json::to_string_pretty(&result)?
        }
        #[cfg(feature = "compiler")]
        CliSubCommand::Compile {
            policy,
            script_type,
        } => {
            let result = handle_compile_subcommand(network, policy, script_type)?;
            serde_json::to_string_pretty(&result)?
        }
        #[cfg(feature = "repl")]
        CliSubCommand::Repl { wallet_opts } => {
            let wallet_opts = maybe_descriptor_wallet_name(wallet_opts, network)?;
            let database = open_database(&wallet_opts)?;

            let wallet = new_wallet(network, &wallet_opts, database)?;

            let mut rl = Editor::<()>::new();

            // if rl.load_history("history.txt").is_err() {
            //     println!("No previous history.");
            // }

            let split_regex = Regex::new(crate::REPL_LINE_SPLIT_REGEX)
                .map_err(|e| Error::Generic(e.to_string()))?;

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
                            #[cfg(any(
                                feature = "electrum",
                                feature = "esplora",
                                feature = "compact_filters",
                                feature = "rpc"
                            ))]
                            ReplSubCommand::OnlineWalletSubCommand(online_subcommand) => {
                                let blockchain = new_blockchain(network, &wallet_opts, &_backend)?;
                                handle_online_wallet_subcommand(
                                    &wallet,
                                    &blockchain,
                                    online_subcommand,
                                )
                            }
                            ReplSubCommand::OfflineWalletSubCommand(offline_subcommand) => {
                                handle_offline_wallet_subcommand(
                                    &wallet,
                                    &wallet_opts,
                                    offline_subcommand,
                                )
                            }
                            ReplSubCommand::KeySubCommand(key_subcommand) => {
                                handle_key_subcommand(network, key_subcommand)
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

            "Exiting REPL".to_string()
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
                network,
                message,
                psbt,
                confirmations,
                addresses,
                electrum_opts,
            )?;
            serde_json::to_string_pretty(&result)?
        }
    };
    Ok(result)
}
