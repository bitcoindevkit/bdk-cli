use crate::commands::*;
use crate::handlers::*;
use crate::nodes::Nodes;
use crate::utils::*;
use bdk::*;

use bitcoin::*;

use bdk::blockchain::AnyBlockchain;
use bdk::database::AnyDatabase;
use js_sys::Promise;
use regex::Regex;
use std::error::Error;
use std::ops::Deref;
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;
use structopt::StructOpt;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

#[cfg(feature = "compiler")]
use bdk::keys::{GeneratableDefaultOptions, GeneratedKey};
#[cfg(feature = "compiler")]
use bdk::miniscript::{self, policy::Concrete, Descriptor, TranslatePk};
#[cfg(feature = "compiler")]
use serde::Deserialize;

#[wasm_bindgen]
pub struct WasmWallet {
    wallet: Rc<Wallet<AnyDatabase>>,
    wallet_opts: Rc<WalletOpts>,
    blockchain: Rc<AnyBlockchain>,
    network: Network,
}

#[wasm_bindgen]
pub fn log_init() {
    wasm_logger::init(wasm_logger::Config::default());
}

#[wasm_bindgen]
impl WasmWallet {
    #[wasm_bindgen(constructor)]
    pub fn new(network: String, wallet_opts: Vec<JsValue>) -> Result<WasmWallet, String> {
        fn new_inner(
            network: String,
            wallet_opts: Vec<JsValue>,
        ) -> Result<WasmWallet, Box<dyn Error>> {
            // Both open_database and new_blockchain need a home path to be passed
            // in, even tho it won't be used
            let dummy_home_dir = PathBuf::new();
            let wallet_opts = wallet_opts
                .into_iter()
                .map(|a| a.as_string().expect("Invalid type"));
            let wallet_opts: WalletOpts = WalletOpts::from_iter_safe(wallet_opts)?;
            let network = Network::from_str(&network)?;
            let wallet_opts = maybe_descriptor_wallet_name(wallet_opts, network)?;
            let database = open_database(&wallet_opts, &dummy_home_dir)?;
            let wallet = new_wallet(network, &wallet_opts, database)?;
            let blockchain = new_blockchain(network, &wallet_opts, &Nodes::None, &dummy_home_dir)?;
            Ok(WasmWallet {
                wallet: Rc::new(wallet),
                wallet_opts: Rc::new(wallet_opts),
                blockchain: Rc::new(blockchain),
                network,
            })
        }

        new_inner(network, wallet_opts).map_err(|e| e.to_string().into())
    }

    pub fn run_command(&self, command: String) -> Promise {
        let wallet = Rc::clone(&self.wallet);
        let wallet_opts = Rc::clone(&self.wallet_opts);
        let blockchain = Rc::clone(&self.blockchain);
        let network = self.network;

        async fn run_command_inner(
            command: String,
            wallet: Rc<Wallet<AnyDatabase>>,
            wallet_opts: Rc<WalletOpts>,
            blockchain: Rc<AnyBlockchain>,
            network: Network,
        ) -> Result<serde_json::Value, Box<dyn Error>> {
            let split_regex = Regex::new(crate::REPL_LINE_SPLIT_REGEX)?;
            let split_line: Vec<&str> = split_regex
                .captures_iter(&command)
                .map(|c| {
                    Ok(c.get(1)
                        .or_else(|| c.get(2))
                        .or_else(|| c.get(3))
                        .ok_or_else(|| "Invalid commands".to_string())?
                        .as_str())
                })
                .collect::<Result<Vec<_>, String>>()?;
            let repl_subcommand = ReplSubCommand::from_iter_safe(split_line)?;
            log::debug!("repl_subcommand = {:?}", repl_subcommand);

            let result = match repl_subcommand {
                ReplSubCommand::Wallet {
                    subcommand: WalletSubCommand::OnlineWalletSubCommand(online_subcommand),
                } => {
                    handle_online_wallet_subcommand(&wallet, blockchain.deref(), online_subcommand)
                        .await?
                }
                ReplSubCommand::Wallet {
                    subcommand: WalletSubCommand::OfflineWalletSubCommand(offline_subcommand),
                } => handle_offline_wallet_subcommand(&wallet, &wallet_opts, offline_subcommand)?,
                ReplSubCommand::Key { subcommand } => handle_key_subcommand(network, subcommand)?,
                ReplSubCommand::Exit => return Ok(serde_json::Value::Null),
            };

            Ok(result)
        }

        future_to_promise(async move {
            run_command_inner(command, wallet, wallet_opts, blockchain, network)
                .await
                .map(|v| JsValue::from_serde(&v).expect("Serde serialization failed"))
                .map_err(|e| e.to_string().into())
        })
    }
}

#[wasm_bindgen]
#[cfg(feature = "compiler")]
pub fn compile(policy: String, aliases: String, script_type: String) -> Result<JsValue, String> {
    fn compile_inner(
        policy: String,
        aliases: String,
        script_type: String,
    ) -> Result<String, Box<dyn Error>> {
        use std::collections::HashMap;
        let aliases: HashMap<String, Alias> = serde_json::from_str(&aliases)?;
        let aliases: HashMap<String, String> = aliases
            .into_iter()
            .map(|(k, v)| (k, v.into_key()))
            .collect();

        let policy = Concrete::<String>::from_str(&policy)?;

        let descriptor = match script_type.as_str() {
            "sh" => Descriptor::new_sh(policy.compile()?)?,
            "wsh" => Descriptor::new_wsh(policy.compile()?)?,
            "sh-wsh" => Descriptor::new_sh_wsh(policy.compile()?)?,
            _ => return Err(Box::<dyn Error>::from("InvalidScriptType")),
        };

        let descriptor: Result<Descriptor<String>, bdk::Error> = descriptor.translate_pk(
            |key| Ok(aliases.get(key).unwrap_or(key).into()),
            |key| Ok(aliases.get(key).unwrap_or(key).into()),
        );
        let descriptor = descriptor?;

        Ok(descriptor.to_string().into())
    }

    compile_inner(policy, aliases, script_type)
        .map(|v| JsValue::from_serde(&v).expect("Serde serialization failed"))
        .map_err(|e| e.to_string().into())
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg(feature = "compiler")]
enum Alias {
    GenWif,
    GenExt { extra: String },
    Existing { extra: String },
}

#[cfg(feature = "compiler")]
impl Alias {
    fn into_key(self) -> String {
        match self {
            Alias::GenWif => {
                let generated: GeneratedKey<bitcoin::PrivateKey, miniscript::Legacy> =
                    GeneratableDefaultOptions::generate_default().unwrap();

                let mut key = generated.into_key();
                key.network = Network::Testnet;

                key.to_wif()
            }
            Alias::GenExt { extra: path } => {
                let generated: GeneratedKey<
                    bitcoin::util::bip32::ExtendedPrivKey,
                    miniscript::Legacy,
                > = GeneratableDefaultOptions::generate_default().unwrap();

                let mut xprv = generated.into_key();
                xprv.network = Network::Testnet;

                format!("{}{}", xprv, path)
            }
            Alias::Existing { extra } => extra,
        }
    }
}
