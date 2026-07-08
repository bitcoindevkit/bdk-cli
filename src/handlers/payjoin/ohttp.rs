use crate::error::BDKCliError as Error;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub(crate) struct RelayManager {
    relays: Vec<url::Url>,
    failed_relays: Arc<Mutex<Vec<url::Url>>>,
}

impl RelayManager {
    pub(crate) fn new() -> Self {
        Self {
            relays: Vec::new(),
            failed_relays: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn configure(&mut self, relays: Vec<url::Url>) -> Result<(), Error> {
        if relays.is_empty() {
            return Err(Error::Generic(
                "At least one valid OHTTP relay must be provided.".into(),
            ));
        }

        self.relays = relays;
        self.failed_relays
            .lock()
            .expect("Lock should not be poisoned")
            .clear();
        Ok(())
    }

    pub(crate) fn add_failed_relay(&self, relay: url::Url) {
        let mut failed_relays = self
            .failed_relays
            .lock()
            .expect("Lock should not be poisoned");
        if !failed_relays.contains(&relay) {
            failed_relays.push(relay);
        }
    }

    pub(crate) fn choose_relay(&self) -> Result<url::Url, Error> {
        use payjoin::bitcoin::secp256k1::rand::prelude::SliceRandom;

        let failed_relays = self
            .failed_relays
            .lock()
            .expect("Lock should not be poisoned");
        let remaining_relays: Vec<_> = self
            .relays
            .iter()
            .filter(|relay| !failed_relays.contains(relay))
            .cloned()
            .collect();

        remaining_relays
            .choose(&mut payjoin::bitcoin::key::rand::thread_rng())
            .cloned()
            .ok_or_else(|| Error::Generic("No valid OHTTP relays available".to_string()))
    }

    pub(crate) async fn fetch_ohttp_keys(
        &self,
        payjoin_directory: impl payjoin::IntoUrl,
    ) -> Result<payjoin::OhttpKeys, Error> {
        loop {
            let selected_relay = self.choose_relay()?;
            let ohttp_keys =
                payjoin::io::fetch_ohttp_keys(selected_relay.as_str(), payjoin_directory.as_str())
                    .await;

            match ohttp_keys {
                Ok(keys) => return Ok(keys),
                Err(payjoin::io::Error::UnexpectedStatusCode(e)) => {
                    return Err(Error::Generic(format!(
                        "Unexpected error occurred when fetching OHTTP keys: {e}"
                    )));
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to connect to OHTTP relay: {}, {}",
                        selected_relay,
                        e
                    );
                    self.add_failed_relay(selected_relay);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RelayManager;

    fn relay(url: &str) -> url::Url {
        url::Url::parse(url).expect("valid relay URL")
    }

    #[test]
    fn choose_relay_excludes_failed_relays() {
        let mut manager = RelayManager::new();
        let failed = relay("https://failed.example");
        let available = relay("https://available.example");
        manager
            .configure(vec![failed.clone(), available.clone()])
            .expect("relay configuration");

        manager.add_failed_relay(failed);

        assert_eq!(manager.choose_relay().expect("available relay"), available);
    }

    #[test]
    fn choose_relay_fails_when_all_relays_failed() {
        let mut manager = RelayManager::new();
        let failed = relay("https://failed.example");
        manager
            .configure(vec![failed.clone()])
            .expect("relay configuration");

        manager.add_failed_relay(failed);

        assert!(manager.choose_relay().is_err());
    }
}
