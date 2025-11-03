use crate::error::BDKCliError as Error;
use crate::handlers::broadcast_transaction;
use crate::utils::{BlockchainClient, send_payjoin_post_request};
use bdk_wallet::{
    SignOptions, Wallet,
    bitcoin::{FeeRate, Psbt, Txid},
};
use payjoin::UriExt;
use payjoin::persist::{OptionalTransitionOutcome, SessionPersister};
use payjoin::send::v2::{
    PollingForProposal, SendSession, Sender, SessionEvent as SenderSessionEvent, WithReplyKey,
};
use serde_json::{json, to_string_pretty};
use std::sync::{Arc, Mutex};

use crate::payjoin::ohttp::{RelayManager, fetch_ohttp_keys};

pub mod ohttp;

pub(crate) struct PayjoinManager<'a> {
    blockchain_client: &'a BlockchainClient,
    wallet: &'a mut Wallet,
    relay_manager: Arc<Mutex<RelayManager>>,
    // TODO: Implement persister!
    // persister: ...
}

impl<'a> PayjoinManager<'a> {
    pub fn new(
        blockchain_client: &'a BlockchainClient,
        wallet: &'a mut Wallet,
        relay_manager: Arc<Mutex<RelayManager>>,
    ) -> Self {
        Self {
            blockchain_client,
            wallet,
            relay_manager,
        }
    }

    pub async fn send_payjoin(
        &mut self,
        uri: String,
        fee_rate: u64,
        ohttp_relay: Option<Vec<String>>,
    ) -> Result<String, Error> {
        let uri = payjoin::Uri::try_from(uri)
            .map_err(|e| Error::Generic(format!("Failed parsing to Payjoin URI: {}", e)))?;
        let uri = uri.require_network(self.wallet.network()).map_err(|e| {
            Error::Generic(format!(
                "Failed setting the right network for the URI: {}",
                e
            ))
        })?;
        let uri = uri
            .check_pj_supported()
            .map_err(|e| Error::Generic(format!("URI does not support Payjoin: {}", e)))?;

        let sats = uri
            .amount
            .ok_or_else(|| Error::Generic("Amount is not specified in the URI.".to_string()))?;

        let fee_rate = FeeRate::from_sat_per_vb(fee_rate).expect("Provided fee rate is not valid.");

        // Build and sign the original PSBT which pays to the receiver.
        let mut original_psbt = {
            let mut tx_builder = self.wallet.build_tx();
            tx_builder
                .add_recipient(uri.address.script_pubkey(), sats)
                .fee_rate(fee_rate);

            tx_builder.finish().map_err(|e| {
                Error::Generic(format!(
                    "Error occurred when building original Payjoin transaction: {}",
                    e
                ))
            })?
        };
        if !self
            .wallet
            .sign(&mut original_psbt, SignOptions::default())?
        {
            return Err(Error::Generic(
                "Failed to sign and finalize the original PSBT.".to_string(),
            ));
        }

        let txid = match uri.extras.pj_param() {
            payjoin::PjParam::V1(_) => {
                let (req, ctx) = payjoin::send::v1::SenderBuilder::new(original_psbt.clone(), uri)
                    .build_recommended(fee_rate)
                    .map_err(|e| {
                        Error::Generic(format!("Failed to build a Payjoin v1 sender: {}", e))
                    })?
                    .create_v1_post_request();

                let response = send_payjoin_post_request(req)
                    .await
                    .map_err(|e| Error::Generic(format!("Failed to send request: {}", e)))?;

                let psbt = ctx
                    .process_response(&response.bytes().await?)
                    .map_err(|e| Error::Generic(format!("Failed to send a Payjoin v1: {}", e)))?;

                self.process_payjoin_proposal(psbt).await?
            }
            payjoin::PjParam::V2(_) => {
                // Validating all OHTTP relays before we go ahead and potentially use them.
                let ohttp_relays = match ohttp_relay {
                    None => Ok(vec![]),
                    Some(relays) => relays.into_iter().map(|s| url::Url::parse(&s)).collect(),
                }
                .map_err(|e| {
                    Error::Generic(format!("Failed to parse one or more OHTTP URLs: {}", e))
                })?;

                if ohttp_relays.is_empty() {
                    return Err(Error::Generic(format!(
                        "No OHTTP relays were provided with the Payjoin v2 URI."
                    )));
                }

                // TODO: Implement proper persister.
                let persister =
                    payjoin::persist::NoopSessionPersister::<SenderSessionEvent>::default();
                let sender = payjoin::send::v2::SenderBuilder::new(original_psbt.clone(), uri)
                    .build_recommended(fee_rate)
                    .map_err(|e| {
                        Error::Generic(format!("Failed to build a Payjoin v2 sender: {}", e))
                    })?
                    .save(&persister)
                    .map_err(|e| {
                        Error::Generic(format!(
                            "Failed to save the Payjoin v2 sender in the persister: {}",
                            e
                        ))
                    })?;

                let selected_relay =
                    fetch_ohttp_keys(ohttp_relays, &sender.endpoint(), self.relay_manager.clone())
                        .await?
                        .relay_url;

                self.proceed_sender_session(
                    SendSession::WithReplyKey(sender),
                    &persister,
                    selected_relay,
                )
                .await?
            }
            _ => {
                unimplemented!("Payjoin version not recognized.");
            }
        };

        Ok(to_string_pretty(&json!({ "txid": txid }))?)
    }

    async fn proceed_sender_session(
        &self,
        session: SendSession,
        persister: &impl SessionPersister<SessionEvent = SenderSessionEvent>,
        relay: url::Url,
    ) -> Result<Txid, Error> {
        match session {
            SendSession::WithReplyKey(context) => {
                self.post_original_proposal(context, relay, persister).await
            }
            SendSession::PollingForProposal(context) => {
                self.get_proposed_payjoin_proposal(context, relay, persister)
                    .await
            }
            SendSession::ProposalReceived(psbt) => self.process_payjoin_proposal(psbt).await,
            _ => Err(Error::Generic("Unexpected SendSession state!".to_string())),
        }
    }

    async fn post_original_proposal(
        &self,
        sender: Sender<WithReplyKey>,
        relay: url::Url,
        persister: &impl SessionPersister<SessionEvent = SenderSessionEvent>,
    ) -> Result<Txid, Error> {
        let (req, ctx) = sender.create_v2_post_request(relay.as_str()).map_err(|e| {
            Error::Generic(format!(
                "Failed to create a post request for a Payjoin send: {}",
                e
            ))
        })?;
        let response = send_payjoin_post_request(req).await?;
        let sender = sender
            .process_response(&response.bytes().await?, ctx)
            .save(persister)
        .map_err(|e| {
                Error::Generic(format!("Failed to persist the Payjoin send after successfully sending original proposal: {}", e))
            })?;
        self.get_proposed_payjoin_proposal(sender, relay, persister)
            .await
    }

    async fn get_proposed_payjoin_proposal(
        &self,
        sender: Sender<PollingForProposal>,
        relay: url::Url,
        persister: &impl SessionPersister<SessionEvent = SenderSessionEvent>,
    ) -> Result<Txid, Error> {
        let mut sender = sender.clone();
        loop {
            let (req, ctx) = sender.create_poll_request(relay.as_str()).map_err(|e| {
                Error::Generic(format!(
                    "Failed to create a poll request during a Payjoin send: {}",
                    e
                ))
            })?;
            let response = send_payjoin_post_request(req).await?;
            let processed_response = sender
                .process_response(&response.bytes().await?, ctx)
                .save(persister);
            match processed_response {
                Ok(OptionalTransitionOutcome::Progress(psbt)) => {
                    println!("Proposal received. Processing...");
                    return self.process_payjoin_proposal(psbt).await;
                }
                Ok(OptionalTransitionOutcome::Stasis(current_state)) => {
                    println!("No response yet. Continuing polling...");
                    sender = current_state;
                    continue;
                }
                Err(e) => {
                    break Err(Error::Generic(format!(
                        "Error occurred when polling for Payjoin v2 proposal: {}",
                        e
                    )));
                }
            }
        }
    }

    async fn process_payjoin_proposal(&self, mut psbt: Psbt) -> Result<Txid, Error> {
        if !self.wallet.sign(&mut psbt, SignOptions::default())? {
            return Err(Error::Generic(
                "Failed to sign and finalize the Payjoin proposal PSBT.".to_string(),
            ));
        }

        broadcast_transaction(self.blockchain_client, psbt.extract_tx_fee_rate_limit()?).await
    }
}
