use crate::error::BDKCliError as Error;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub(crate) struct RelayManager {
    selected_relay: Option<url::Url>,
    failed_relays: Vec<url::Url>,
}

impl RelayManager {
    pub fn new() -> Self {
        RelayManager {
            selected_relay: None,
            failed_relays: Vec::new(),
        }
    }

    pub fn set_selected_relay(&mut self, relay: url::Url) {
        self.selected_relay = Some(relay);
    }

    pub fn get_selected_relay(&self) -> Option<url::Url> {
        self.selected_relay.clone()
    }

    pub fn add_failed_relay(&mut self, relay: url::Url) {
        self.failed_relays.push(relay);
    }

    pub fn get_failed_relays(&self) -> Vec<url::Url> {
        self.failed_relays.clone()
    }
}

pub(crate) struct ValidatedOhttpKeys {
    pub(crate) ohttp_keys: payjoin::OhttpKeys,
    pub(crate) relay_url: url::Url,
}

pub(crate) async fn fetch_ohttp_keys(
    relays: Vec<url::Url>,
    payjoin_directory: impl payjoin::IntoUrl,
    relay_manager: Arc<Mutex<RelayManager>>,
) -> Result<ValidatedOhttpKeys, Error> {
    use payjoin::bitcoin::secp256k1::rand::prelude::SliceRandom;

    loop {
        let failed_relays = relay_manager
            .lock()
            .expect("Lock should not be poisoned")
            .get_failed_relays();

        let remaining_relays: Vec<_> = relays
            .iter()
            .filter(|r| !failed_relays.contains(r))
            .cloned()
            .collect();

        if remaining_relays.is_empty() {
            return Err(Error::Generic(
                "No valid OHTTP relays available".to_string(),
            ));
        }

        let selected_relay =
            match remaining_relays.choose(&mut payjoin::bitcoin::key::rand::thread_rng()) {
                Some(relay) => relay.clone(),
                None => {
                    return Err(Error::Generic(
                        "Failed to select from remaining relays".to_string(),
                    ));
                }
            };

        relay_manager
            .lock()
            .expect("Lock should not be poisoned")
            .set_selected_relay(selected_relay.clone());

        let ohttp_keys =
            payjoin::io::fetch_ohttp_keys(selected_relay.as_str(), payjoin_directory.as_str())
                .await;

        match ohttp_keys {
            Ok(keys) => {
                return Ok(ValidatedOhttpKeys {
                    ohttp_keys: keys,
                    relay_url: selected_relay,
                });
            }
            Err(payjoin::io::Error::UnexpectedStatusCode(e)) => {
                return Err(Error::Generic(format!(
                    "Unexpected error occurred when fetching OHTTP keys: {}",
                    e
                )));
            }
            Err(e) => {
                tracing::debug!(
                    "Failed to connect to OHTTP relay: {}, {}",
                    selected_relay,
                    e
                );
                relay_manager
                    .lock()
                    .expect("Lock should not be poisoned")
                    .add_failed_relay(selected_relay);
            }
        }
    }
}
