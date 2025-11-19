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

    pub async fn receive_payjoin(
        &mut self,
        amount: u64,
        directory: String,
        max_fee_rate: Option<u64>,
        ohttp_relays: Vec<String>,
        blockchain_client: BlockchainClient,
    ) -> Result<String, Error> {
        let address = self
            .wallet
            .next_unused_address(bdk_wallet::KeychainKind::External);

        let ohttp_relays: Vec<url::Url> = ohttp_relays
            .into_iter() // if ohttp_relay: Option<Vec<String>>
            .map(|s| url::Url::parse(&s))
            .collect::<Result<_, _>>()
            .map_err(|e| {
                Error::Generic(format!("Failed to parse one or more OHTTP URLs: {}", e))
            })?;

        if ohttp_relays.is_empty() {
            return Err(Error::Generic(
                "At least one valid OHTTP relay must be provided.".into(),
            ));
        }

        let ohttp_keys =
            fetch_ohttp_keys(ohttp_relays, &directory, self.relay_manager.clone()).await?;
        // TODO: Implement proper persister.
        let persister = payjoin::persist::NoopSessionPersister::<ReceiverSessionEvent>::default();

        let checked_max_fee_rate = max_fee_rate
            .map(|rate| FeeRate::from_sat_per_kwu(rate))
            .unwrap_or(FeeRate::BROADCAST_MIN);

        let receiver = payjoin::receive::v2::ReceiverBuilder::new(
            address.address,
            directory,
            ohttp_keys.ohttp_keys,
        )
        .map_err(|e| {
            Error::Generic(format!(
                "Failed to initialize a Payjoin ReceieverBuilder: {}",
                e
            ))
        })?
        .with_amount(payjoin::bitcoin::Amount::from_sat(amount))
        .with_max_fee_rate(checked_max_fee_rate)
        .build()
        .save(&persister)
        .map_err(|e| {
            Error::Generic(format!(
                "Failed to persister the receiver after initialization: {}",
                e
            ))
        })?;

        let pj_uri = receiver.pj_uri();
        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{pj_uri}");

        self.proceed_receiver_session(
            ReceiveSession::Initialized(receiver.clone()),
            &persister,
            ohttp_keys.relay_url,
            blockchain_client,
        )
        .await?;

        Ok(to_string_pretty(&json!({}))?)
    }

    pub async fn send_payjoin(
        &mut self,
        uri: String,
        fee_rate: u64,
        ohttp_relays: Vec<String>,
        blockchain_client: BlockchainClient,
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

                let response = self
                    .send_payjoin_post_request(req)
                    .await
                    .map_err(|e| Error::Generic(format!("Failed to send request: {}", e)))?;

                let psbt = ctx
                    .process_response(&response.bytes().await?)
                    .map_err(|e| Error::Generic(format!("Failed to send a Payjoin v1: {}", e)))?;

                self.process_payjoin_proposal(psbt, blockchain_client)
                    .await?
            }
            payjoin::PjParam::V2(_) => {
                let ohttp_relays: Vec<url::Url> = ohttp_relays
                    .into_iter() // if ohttp_relay: Option<Vec<String>>
                    .map(|s| url::Url::parse(&s))
                    .collect::<Result<_, _>>()
                    .map_err(|e| {
                        Error::Generic(format!("Failed to parse one or more OHTTP URLs: {}", e))
                    })?;

                if ohttp_relays.is_empty() {
                    return Err(Error::Generic(
                        "At least one valid OHTTP relay must be provided.".into(),
                    ));
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
                    blockchain_client,
                )
                .await?
            }
            _ => {
                unimplemented!("Payjoin version not recognized.");
            }
        };

        Ok(to_string_pretty(&json!({ "txid": txid }))?)
    }

    async fn proceed_receiver_session(
        &mut self,
        session: ReceiveSession,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
        relay: url::Url,
        blockchain_client: BlockchainClient,
    ) -> Result<(), Error> {
        match session {
            ReceiveSession::Initialized(proposal) => {
                self.read_from_directory(proposal, persister, relay, blockchain_client)
                    .await
            }
            ReceiveSession::UncheckedOriginalPayload(proposal) => {
                self.check_proposal(proposal, persister, blockchain_client)
                    .await
            }
            ReceiveSession::MaybeInputsOwned(proposal) => {
                self.check_inputs_not_owned(proposal, persister, blockchain_client)
                    .await
            }
            ReceiveSession::MaybeInputsSeen(proposal) => {
                self.check_no_inputs_seen_before(proposal, persister, blockchain_client)
                    .await
            }
            ReceiveSession::OutputsUnknown(proposal) => {
                self.identify_receiver_outputs(proposal, persister, blockchain_client)
                    .await
            }
            ReceiveSession::WantsOutputs(proposal) => {
                self.commit_outputs(proposal, persister, blockchain_client)
                    .await
            }
            ReceiveSession::WantsInputs(proposal) => {
                self.contribute_inputs(proposal, persister, blockchain_client)
                    .await
            }
            ReceiveSession::WantsFeeRange(proposal) => {
                self.apply_fee_range(proposal, persister, blockchain_client)
                    .await
            }
            ReceiveSession::ProvisionalProposal(proposal) => {
                self.finalize_proposal(proposal, persister, blockchain_client)
                    .await
            }
            ReceiveSession::PayjoinProposal(proposal) => {
                self.send_payjoin_proposal(proposal, persister, blockchain_client)
                    .await
            }
            ReceiveSession::Monitor(proposal) => {
                self.monitor_payjoin_proposal(proposal, persister, blockchain_client)
                    .await
            }
            ReceiveSession::HasReplyableError(error) => self.handle_error(error, persister).await,
            ReceiveSession::Closed(_) => return Err(Error::Generic("Session closed".to_string())),
        }
    }

    async fn read_from_directory(
        &mut self,
        receiver: Receiver<Initialized>,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
        relay: url::Url,
        blockchain_client: BlockchainClient,
    ) -> Result<(), Error> {
        let mut current_receiver_typestate = receiver;
        let next_receiver_typestate = loop {
            let (req, context) = current_receiver_typestate
                .create_poll_request(relay.as_str())
                .map_err(|e| {
                    Error::Generic(format!(
                        "Failed to create a poll request to read from the Payjoin directory: {}",
                        e
                    ))
                })?;
            println!("Polling receive request...");
            let response = self.send_payjoin_post_request(req).await?;
            let state_transition = current_receiver_typestate
                .process_response(response.bytes().await?.to_vec().as_slice(), context)
                .save(persister);
            match state_transition {
                Ok(OptionalTransitionOutcome::Progress(next_state)) => {
                    println!("Got a request from the sender. Responding with a Payjoin proposal.");
                    break next_state;
                }
                Ok(OptionalTransitionOutcome::Stasis(current_state)) => {
                    current_receiver_typestate = current_state;
                    continue;
                }
                Err(e) => {
                    return Err(Error::Generic(format!(
                        "Error occurred when polling for Payjoin proposal from the directory: {}",
                        e.to_string()
                    )));
                }
            }
        };
        self.check_proposal(next_receiver_typestate, persister, blockchain_client)
            .await
    }

    async fn check_proposal(
        &mut self,
        receiver: Receiver<UncheckedOriginalPayload>,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
        blockchain_client: BlockchainClient,
    ) -> Result<(), Error> {
        let next_receiver_typestate = receiver
            .check_broadcast_suitability(None, |_| return Ok(true))
            .save(persister)
            .map_err(|e| {
                Error::Generic(format!(
                    "Error occurred when saving after checking if the original proposal can be broadcasted: {}",
                    e
                ))
            })?;

        println!(
            "Checking whether the original proposal can be broadcasted itself is not supported. If the Payjoin fails, manually fall back to the transaction below."
        );
        println!(
            "{}",
            serialize_hex(&next_receiver_typestate.extract_tx_to_schedule_broadcast())
        );

        self.check_inputs_not_owned(next_receiver_typestate, persister, blockchain_client)
            .await
    }

    async fn check_inputs_not_owned(
        &mut self,
        receiver: Receiver<MaybeInputsOwned>,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
        blockchain_client: BlockchainClient,
    ) -> Result<(), Error> {
        let next_receiver_typestate = receiver
            .check_inputs_not_owned(&mut |input| {
                Ok(self.wallet.is_mine(input.to_owned()))
            })
            .save(persister)
            .map_err(|e| {
                Error::Generic(format!("Error occurred when saving after checking if inputs in the original proposal are not owned: {}", e))
            })?;

        self.check_no_inputs_seen_before(next_receiver_typestate, persister, blockchain_client)
            .await
    }

    async fn check_no_inputs_seen_before(
        &mut self,
        receiver: Receiver<MaybeInputsSeen>,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
        blockchain_client: BlockchainClient,
    ) -> Result<(), Error> {
        // This is not supported as there is no persistence of previous Payjoin attempts in BDK CLI
        // yet. If there is support either in the BDK persister or Payjoin persister, this can be
        // implemented, but it is not a concern as the use cases of the CLI does not warrant
        // protection against probing attacks.
        println!(
            "Checking whether the inputs in the proposal were seen before to protect from probing attacks is not supported. Skipping the check..."
        );
        let next_receiver_typestate = receiver.check_no_inputs_seen_before(&mut |_| Ok(false)).save(persister).map_err(|e| {
            Error::Generic(format!("Error occurred when saving after checking if the inputs in the proposal were seen before: {}", e))
        })?;
        self.identify_receiver_outputs(next_receiver_typestate, persister, blockchain_client)
            .await
    }

    async fn identify_receiver_outputs(
        &mut self,
        receiver: Receiver<OutputsUnknown>,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
        blockchain_client: BlockchainClient,
    ) -> Result<(), Error> {
        let next_receiver_typestate = receiver.identify_receiver_outputs(&mut |output_script| {
            Ok(self.wallet.is_mine(output_script.to_owned()))
        }).save(persister).map_err(|e| {
            Error::Generic(format!("Error occurred when saving after checking if the outputs in the original proposal are owned by the receiver: {}", e))
        })?;

        self.commit_outputs(next_receiver_typestate, persister, blockchain_client)
            .await
    }

    async fn commit_outputs(
        &mut self,
        receiver: Receiver<WantsOutputs>,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
        blockchain_client: BlockchainClient,
    ) -> Result<(), Error> {
        // This is a typestate to modify existing receiver-owned outputs in case the receiver wants
        // to do that. This is a very simple implementation of Payjoin so we are just going
        // to commit to the existing outputs which the sender included in the original proposal.
        let next_receiver_typestate = receiver.commit_outputs().save(persister).map_err(|e| {
            Error::Generic(format!(
                "Error occurred when saving after committing to the outputs in the proposal: {}",
                e
            ))
        })?;
        self.contribute_inputs(next_receiver_typestate, persister, blockchain_client)
            .await
    }

    async fn contribute_inputs(
        &mut self,
        receiver: Receiver<WantsInputs>,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
        blockchain_client: BlockchainClient,
    ) -> Result<(), Error> {
        let candidate_inputs: Vec<InputPair> = self
            .wallet
            .list_unspent()
            .map(|output| {
                let psbtin = self
                    .wallet
                    .get_psbt_input(output.clone(), None, false)
                    .expect(
                        "Failed to get the PSBT Input using the output of the unspent transaction",
                    );
                let txin = TxIn {
                    previous_output: output.outpoint,
                    ..Default::default()
                };
                InputPair::new(txin, psbtin, None)
                    .expect("Failed to create InputPair when contributing outputs to the proposal")
            })
            .collect();
        let selected_input = receiver
            .try_preserving_privacy(candidate_inputs)
            .map_err(|e| {
                Error::Generic(format!(
                    "Error occurred when trying to pick an unspent UTXO for input contribution: {}",
                    e
                ))
            })?;

        let next_receiver_typestate = receiver.contribute_inputs(vec![selected_input])
            .map_err(|e| {
                Error::Generic(format!("Error occurred when contributing the selected input to the proposal: {}", e))
            })?.commit_inputs().save(persister)
            .map_err(|e| {
                Error::Generic(format!("Error occurred when saving after committing to the inputs after receiver contribution: {}", e))
            })?;

        self.apply_fee_range(next_receiver_typestate, persister, blockchain_client)
            .await
    }

    async fn apply_fee_range(
        &mut self,
        receiver: Receiver<WantsFeeRange>,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
        blockchain_client: BlockchainClient,
    ) -> Result<(), Error> {
        let next_receiver_typestate = receiver.apply_fee_range(None, None).save(persister).map_err(|e| {
            Error::Generic(format!("Error occurred when saving after applying the receiver fee range to the transaction: {}", e))
        })?;
        self.finalize_proposal(next_receiver_typestate, persister, blockchain_client)
            .await
    }

    async fn finalize_proposal(
        &mut self,
        receiver: Receiver<ProvisionalProposal>,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
        blockchain_client: BlockchainClient,
    ) -> Result<(), Error> {
        let next_receiver_typestate = receiver
            .finalize_proposal(|psbt| {
                let mut psbt_clone = psbt.clone();
                if !self
                    .wallet
                    .sign(&mut psbt_clone, SignOptions::default())
                    .map_err(|e| {
                        ImplementationError::from(
                            format!("Error occurred when signing the Payjoin PSBT: {}", e).as_str(),
                        )
                    })?
                {
                    return Err(ImplementationError::from(
                        "Failed to sign and finalize the Payjoin proposal PSBT.",
                    ));
                }

                Ok(psbt_clone)
            })
            .save(persister)
            .map_err(|e| {
                Error::Generic(format!(
                    "Error occurred when saving after signing the Payjoin proposal: {}",
                    e
                ))
            })?;

        self.send_payjoin_proposal(next_receiver_typestate, persister, blockchain_client)
            .await
    }

    async fn send_payjoin_proposal(
        &mut self,
        receiver: Receiver<PayjoinProposal>,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
        blockchain_client: BlockchainClient,
    ) -> Result<(), Error> {
        let (req, ctx) = receiver.create_post_request(
            self.relay_manager
                .lock()
                .expect("Lock should not be poisoned")
                .get_selected_relay()
                .expect("A relay should already be selected")
                .as_str(),
        ).map_err(|e| {
                Error::Generic(format!("Error occurred when creating a post request for sending final Payjoin proposal: {}", e))
            })?;

        let res = self.send_payjoin_post_request(req).await?;
        let payjoin_psbt = receiver.psbt().clone();
        let next_receiver_typestate = receiver.process_response(&res.bytes().await?, ctx).save(persister).map_err(|e| {
            Error::Generic(format!("Error occurred when saving after processing the response to the Payjoin proposal send: {}", e))
        })?;
        println!(
            "Response successful. TXID: {}",
            payjoin_psbt.extract_tx_unchecked_fee_rate().compute_txid()
        );
        return self
            .monitor_payjoin_proposal(next_receiver_typestate, persister, blockchain_client)
            .await;
    }

    /// Syncs the blockchain once and then checks whether the Payjoin was broadcasted by the
    /// sender.
    ///
    /// The currenty implementation does not support checking for the PAyjoin broadcast in a loop
    /// and returning only when it is detected or if a timeout is reached because the [`sync_wallet`]
    /// function consumes the BlockchainClient. BDK CLI supports multiple blockchain clients, and
    /// at the time of writing, Kyoto consumes the client since BDK CLI is not designed for long-running
    /// tasks.
    async fn monitor_payjoin_proposal(
        &mut self,
        receiver: Receiver<Monitor>,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
        blockchain_client: BlockchainClient,
    ) -> Result<(), Error> {
        let wait_time_for_sync = 3;
        let poll_internal = tokio::time::Duration::from_secs(3);

        let mut interval = tokio::time::interval(poll_internal);

        println!(
            "Waiting for {wait_time_for_sync} seconds before syncing the blockchain and checking if the transaction has been broadcast..."
        );
        interval.tick().await;
        sync_wallet(blockchain_client, self.wallet).await?;

        let check_result = receiver
            .check_payment(
                |txid| {
                    let tx_details = self.wallet.tx_details(txid).expect("Cannot find transaction in the wallet");
                    let is_seen = match tx_details.chain_position {
                        bdk_wallet::chain::ChainPosition::Confirmed { .. } => true,
                        bdk_wallet::chain::ChainPosition::Unconfirmed { first_seen: Some(_), .. } => true,
                        _ => false
                    };
                    if is_seen {
                        return Ok(Some(tx_details.tx.as_ref().clone()));
                    }
                    return Err(ImplementationError::from("Cannot find the transaction in the mempool or the blockchain"));
                },
                |outpoint| {
                    let utxo = self.wallet.get_utxo(outpoint);
                    match utxo {
                        Some(_) => Ok(false),
                        None => Ok(true),
                    }
                }
            )
            .save(persister)
            .map_err(|e| {
                Error::Generic(format!("Error occurred when saving after checking that sender has broadcasted the Payjoin transaction: {}", e))
            });

        match check_result {
            Ok(_) => {
                println!("Payjoin transaction detected in the mempool!");
            }
            Err(_) => {
                println!(
                    "Transaction was not found in the mempool after {wait_time_for_sync}. Check the state of the transaction manually after running the sync command."
                );
            }
        }

        Ok(())
    }

    async fn handle_error(
        &self,
        receiver: Receiver<HasReplyableError>,
        persister: &impl SessionPersister<SessionEvent = ReceiverSessionEvent>,
    ) -> Result<(), Error> {
        let (err_req, err_ctx) = receiver
            .create_error_request(
                self.relay_manager
                    .lock()
                    .expect("Lock should not be poisoned")
                    .get_selected_relay()
                    .expect("A relay should already be selected")
                    .as_str(),
            )
            .map_err(|e| {
                Error::Generic(format!(
                    "Error occurred when creating a receiver error request: {}",
                    e
                ))
            })?;

        let err_response = match self.send_payjoin_post_request(err_req).await {
            Ok(response) => response,
            Err(e) => {
                return Err(Error::Generic(format!(
                    "Failed to post error request: {}",
                    e
                )));
            }
        };

        let err_bytes = match err_response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(Error::Generic(format!(
                    "Failed to get error response bytes: {}",
                    e
                )));
            }
        };

        if let Err(e) = receiver
            .process_error_response(&err_bytes, err_ctx)
            .save(persister)
        {
            return Err(Error::Generic(format!(
                "Failed to process error response: {}",
                e
            )));
        }

        Ok(())
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
