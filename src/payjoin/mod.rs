use crate::error::BDKCliError as Error;
use crate::handlers::{broadcast_transaction, sync_wallet};
use crate::utils::BlockchainClient;
use bdk_wallet::{
    SignOptions, Wallet,
    bitcoin::{FeeRate, Psbt, Txid, consensus::encode::serialize_hex},
};
use payjoin::bitcoin::TxIn;
use payjoin::persist::{OptionalTransitionOutcome, SessionPersister};
use payjoin::receive::InputPair;
use payjoin::receive::v2::{
    HasReplyableError, Initialized, MaybeInputsOwned, MaybeInputsSeen, Monitor, OutputsUnknown,
    PayjoinProposal, ProvisionalProposal, ReceiveSession, Receiver,
    SessionEvent as ReceiverSessionEvent, UncheckedOriginalPayload, WantsFeeRange, WantsInputs,
    WantsOutputs,
};
use payjoin::send::v2::{
    PollingForProposal, SendSession, Sender, SessionEvent as SenderSessionEvent,
    SessionOutcome as SenderSessionOutcome, WithReplyKey,
};
use payjoin::{ImplementationError, UriExt};
use serde_json::{json, to_string_pretty};
use std::sync::{Arc, Mutex};

use crate::payjoin::ohttp::{RelayManager, fetch_ohttp_keys};

pub mod ohttp;

/// Implements all of the functions required to go through the Payjoin receive and send processes.
///
/// TODO: At the time of writing, this struct is written to make a Persister implementation easier
/// but the persister is not implemented yet! For instance [`PayjoinManager::proceed_sender_session`] and
/// [`PayjoinManager::proceed_receiver_session`] are designed such that the manager can enable
/// resuming ongoing payjoins are well. So... this is a TODO for implementing persister.
pub(crate) struct PayjoinManager<'a> {
    wallet: &'a mut Wallet,
    relay_manager: Arc<Mutex<RelayManager>>,
}

impl<'a> PayjoinManager<'a> {
    pub fn new(wallet: &'a mut Wallet, relay_manager: Arc<Mutex<RelayManager>>) -> Self {
        Self {
            wallet,
            relay_manager,
        }
    }

    async fn proceed_sender_session(
        &self,
        session: SendSession,
        persister: &impl SessionPersister<SessionEvent = SenderSessionEvent>,
        relay: url::Url,
        blockchain_client: BlockchainClient,
    ) -> Result<Txid, Error> {
        match session {
            SendSession::WithReplyKey(context) => {
                self.post_original_proposal(context, relay, persister, blockchain_client)
                    .await
            }
            SendSession::PollingForProposal(context) => {
                self.get_proposed_payjoin_proposal(context, relay, persister, blockchain_client)
                    .await
            }
            SendSession::Closed(SenderSessionOutcome::Success(psbt)) => {
                self.process_payjoin_proposal(psbt, blockchain_client).await
            }
            _ => Err(Error::Generic("Unexpected SendSession state!".to_string())),
        }
    }

    async fn post_original_proposal(
        &self,
        sender: Sender<WithReplyKey>,
        relay: url::Url,
        persister: &impl SessionPersister<SessionEvent = SenderSessionEvent>,
        blockchain_client: BlockchainClient,
    ) -> Result<Txid, Error> {
        let (req, ctx) = sender.create_v2_post_request(relay.as_str()).map_err(|e| {
            Error::Generic(format!(
                "Failed to create a post request for a Payjoin send: {}",
                e
            ))
        })?;
        let response = self.send_payjoin_post_request(req).await?;
        let sender = sender
            .process_response(&response.bytes().await?, ctx)
            .save(persister)
        .map_err(|e| {
                Error::Generic(format!("Failed to persist the Payjoin send after successfully sending original proposal: {}", e))
            })?;
        self.get_proposed_payjoin_proposal(sender, relay, persister, blockchain_client)
            .await
    }

    async fn get_proposed_payjoin_proposal(
        &self,
        sender: Sender<PollingForProposal>,
        relay: url::Url,
        persister: &impl SessionPersister<SessionEvent = SenderSessionEvent>,
        blockchain_client: BlockchainClient,
    ) -> Result<Txid, Error> {
        let mut sender = sender.clone();
        loop {
            let (req, ctx) = sender.create_poll_request(relay.as_str()).map_err(|e| {
                Error::Generic(format!(
                    "Failed to create a poll request during a Payjoin send: {}",
                    e
                ))
            })?;
            let response = self.send_payjoin_post_request(req).await?;
            let processed_response = sender
                .process_response(&response.bytes().await?, ctx)
                .save(persister);
            match processed_response {
                Ok(OptionalTransitionOutcome::Progress(psbt)) => {
                    println!("Proposal received. Processing...");
                    return self.process_payjoin_proposal(psbt, blockchain_client).await;
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

    async fn process_payjoin_proposal(
        &self,
        mut psbt: Psbt,
        blockchain_client: BlockchainClient,
    ) -> Result<Txid, Error> {
        if !self.wallet.sign(&mut psbt, SignOptions::default())? {
            return Err(Error::Generic(
                "Failed to sign and finalize the Payjoin proposal PSBT.".to_string(),
            ));
        }

        broadcast_transaction(blockchain_client, psbt.extract_tx_fee_rate_limit()?).await
    }

    async fn send_payjoin_post_request(
        &self,
        req: payjoin::Request,
    ) -> reqwest::Result<reqwest::Response> {
        let client = reqwest::Client::new();
        client
            .post(req.url)
            .header("Content-Type", req.content_type)
            .body(req.body)
            .send()
            .await
    }
}
