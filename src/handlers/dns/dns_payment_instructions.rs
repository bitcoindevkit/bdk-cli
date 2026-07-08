use bdk_wallet::bitcoin::{Address, Amount, Network};
use bitcoin_payment_instructions::{
    FixedAmountPaymentInstructions, ParseError, PaymentInstructions, PaymentMethod,
    PaymentMethodType, amount, dns_resolver::DNSHrnResolver,
};
use core::{net::SocketAddr, str::FromStr};
use tokio::time::timeout;

use crate::error::BDKCliError as Error;

#[derive(Debug)]
pub struct ResolvedPaymentInfo {
    pub hrn: String,
    pub payment_methods: Vec<PaymentMethod>,
    pub description: Option<String>,
    pub min_amount: Option<Amount>,
    pub max_amount: Option<Amount>,
    pub notes: String,
}

impl ResolvedPaymentInfo {
    pub fn display(&self) -> Result<String, Error> {
        let methods: Vec<String> = self
            .payment_methods
            .iter()
            .map(|pm| match pm {
                PaymentMethod::LightningBolt11(bolt11) => {
                    format!("Bolt 11 invoice ({})", bolt11)
                }
                PaymentMethod::LightningBolt12(offer) => format!("Bolt 12 invoice ({})", offer),
                PaymentMethod::OnChain(address) => format!("On chain ({})", address),
                PaymentMethod::Cashu(csh) => format!("Cashu payment ({})", csh),
            })
            .collect();

        Ok(serde_json::to_string_pretty(&serde_json::json!({
                "hrn": self.hrn,
                "payment_methods": methods,
                "description": self.description,
                "min_amount": self.min_amount,
                "max_amount": self.max_amount,
                "notes": self.notes
        }))?)
    }
}

pub(crate) async fn parse_dns_instructions(
    hrn: &str,
    network: Network,
    dns_resolver: &str,
) -> Result<(DNSHrnResolver, PaymentInstructions), ParseError> {
    let ip_address = if dns_resolver.contains(':') {
        dns_resolver
    } else {
        &format!("{dns_resolver}:53")
    };

    let sock_addr = SocketAddr::from_str(ip_address).map_err(|_| {
        ParseError::HrnResolutionError("Unable to create socket from provided address")
    })?;
    let resolver = DNSHrnResolver(sock_addr);
    let instructions = timeout(
        std::time::Duration::from_secs(30),
        PaymentInstructions::parse(hrn, network, &resolver, true),
    )
    .await
    .map_err(|_| ParseError::HrnResolutionError("Resolution request timed out"))??;
    Ok((resolver, instructions))
}

fn get_onchain_info(
    instructions: &FixedAmountPaymentInstructions,
) -> Result<(Address, Amount), Error> {
    // Look for on chain payment method as it's the only one we can support
    let PaymentMethod::OnChain(addr) = instructions
        .methods()
        .iter()
        .find(|ix| matches!(ix, PaymentMethod::OnChain(_)))
        .ok_or(Error::Generic(
            "Missing Onchain payment method option.".to_string(),
        ))?
    else {
        return Err(Error::Generic("Unsupported payment method".to_string()));
    };

    let Some(onchain_amount) = instructions.onchain_payment_amount() else {
        return Err(Error::Generic(
            "On chain amount should be specified".to_string(),
        ));
    };

    // We need this conversion since Amount from instructions is different from Amount from bitcoin
    Ok((addr.clone(), Amount::from_sat(onchain_amount.milli_sats())))
}

pub async fn process_instructions(
    amount_to_send: Amount,
    payment_instructions: &PaymentInstructions,
    resolver: DNSHrnResolver,
) -> Result<(Address, Amount), Error> {
    match payment_instructions {
        PaymentInstructions::ConfigurableAmount(instructions) => {
            // Look for on chain payment method as it's the only one we can support
            if !instructions
                .methods()
                .any(|method| matches!(method.method_type(), PaymentMethodType::OnChain))
            {
                return Err(Error::Generic("Unsupported payment method".to_string()));
            }

            let min_amount = instructions
                .min_amt()
                .map(|amnt| Amount::from_sat(amnt.sats_rounding_up()));

            let max_amount = instructions
                .max_amt()
                .map(|amnt| Amount::from_sat(amnt.sats_rounding_up()));

            if min_amount.is_some_and(|min| amount_to_send < min) {
                return Err(Error::Generic(
                    format!(
                        "Amount to send should be greater than min {}",
                        min_amount.unwrap()
                    )
                    .to_string(),
                ));
            }

            if max_amount.is_some_and(|max| amount_to_send > max) {
                return Err(Error::Generic(
                    format!(
                        "Amount to send should be lower than max {}",
                        max_amount.unwrap()
                    )
                    .to_string(),
                ));
            }

            let fixed_instructions = instructions
                .clone()
                .set_amount(
                    amount::Amount::from_sats(amount_to_send.to_sat()).unwrap(),
                    &resolver,
                )
                .await
                .map_err(|err| {
                    Error::Generic(format!("Error occured while parsing instructions {err}"))
                })?;

            let onchain_details = get_onchain_info(&fixed_instructions)?;

            Ok((onchain_details.0.clone(), onchain_details.1))
        }

        PaymentInstructions::FixedAmount(instructions) => Ok(get_onchain_info(instructions)?),
    }
}

/// Resolves the dns payment instructions found at the specified Human Readable Name
pub async fn resolve_dns_recipient(
    hrn: &str,
    network: Network,
    dns_resolver: &str,
) -> Result<ResolvedPaymentInfo, ParseError> {
    let (resolver, instructions) = parse_dns_instructions(hrn, network, dns_resolver).await?;

    match instructions {
        PaymentInstructions::ConfigurableAmount(ix) => {
            let description = ix.recipient_description().map(|s| s.to_string());
            let min_amount = ix.min_amt().map(|amnt| Amount::from_sat(amnt.milli_sats()));
            let max_amount = ix.max_amt().map(|amnt| Amount::from_sat(amnt.milli_sats()));

            // Let's set a dummy amount to resolve the payment methods accepted.
            let fixed_instructions = ix
                .set_amount(amount::Amount::ZERO, &resolver)
                .await
                .map_err(ParseError::InvalidInstructions)?;

            let payment = ResolvedPaymentInfo {
                min_amount,
                max_amount,
                payment_methods: fixed_instructions.methods().into(),
                description,
                hrn: hrn.to_string(),
                notes: "This is configurable payment instructions. You must send an amount between min_amount and max_amount if set.".to_string(),
            };

            Ok(payment)
        }

        PaymentInstructions::FixedAmount(ix) => {
            let max_amount = ix
                .max_amount()
                .map(|amnt| Amount::from_sat(amnt.milli_sats()));

            let payment = ResolvedPaymentInfo {
                min_amount: None,
                max_amount,
                payment_methods: ix.methods().into(),
                description: ix.recipient_description().map(|s| s.to_string()),
                hrn: hrn.to_string(),
                notes: "This is a fixed payment instructions. You must send exactly the amount specified in max_amount.".to_string(),
            };

            Ok(payment)
        }
    }
}
