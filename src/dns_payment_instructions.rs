use bdk_wallet::bitcoin::{Address, Amount, Network};
use bitcoin_payment_instructions::{
    FixedAmountPaymentInstructions, ParseError, PaymentInstructions, PaymentMethod,
    PaymentMethodType, amount, dns_resolver::DNSHrnResolver,
};
use cli_table::{Cell, Style, Table, format::Justify};
use core::{net::SocketAddr, str::FromStr};

use crate::{error::BDKCliError as Error, utils::shorten};

#[derive(Debug)]
pub struct Payment {
    pub payment_methods: Vec<PaymentMethod>,
    pub min_amount: Option<Amount>,
    pub max_amount: Option<Amount>,
    pub description: Option<String>,
    pub expected_amount: Option<Amount>,
    pub receiving_addr: Option<Address>,
    pub hrn: String,
    pub notes: String,
}

impl Payment {

    pub fn display(&self, pretty: bool) -> Result<String, Error> {
    let mut methods: Vec<String> = Vec::new();
    self.payment_methods.iter().for_each(|pm| match pm {
        bitcoin_payment_instructions::PaymentMethod::LightningBolt11(bolt11) => {
            methods.push(format!("Bolt 11 invoice ({})", shorten(bolt11, 20, 15)))
        }
        bitcoin_payment_instructions::PaymentMethod::LightningBolt12(offer) => {
            methods.push(format!("Bolt 12 invoice ({})", shorten(offer, 20, 15)))
        }
        bitcoin_payment_instructions::PaymentMethod::OnChain(address) => {
            methods.push(format!("On chain ({})", address))
        }
        bitcoin_payment_instructions::PaymentMethod::Cashu(csh) => {
            methods.push(format!("Cashu payment ({})", shorten(csh, 20, 15)))
        }
    });

    if pretty {
        let mut table = vec![vec![
            "HRN".cell().bold(true),
            self.hrn.to_string().cell().justify(Justify::Right),
        ]];

        if let Some(min_amnt) = self.min_amount {
            table.push(vec![
                "Min amount".cell().bold(true),
                min_amnt.to_string().cell().justify(Justify::Right),
            ]);
        }

        if let Some(max_amnt) = self.max_amount {
            table.push(vec![
                "Max amount".cell().bold(true),
                max_amnt.to_string().cell().justify(Justify::Right),
            ]);
        }

        if let Some(send_amnt) = self.expected_amount {
            table.push(vec![
                "Expected Amount to send".cell().bold(true),
                send_amnt.to_string().cell().justify(Justify::Right),
            ]);
        }

        if let Some(descr) = &self.description {
            table.push(vec![
                "Description".cell().bold(true),
                descr.cell().justify(Justify::Right),
            ]);
        }

        table.push(vec![
            "Accepted methods".cell().bold(true),
            methods.join(", ").cell().justify(Justify::Right),
        ]);
        table.push(vec![
            "Notes".cell().bold(true),
            self.notes.clone().cell().justify(Justify::Right),
        ]);

        let table = table
            .table()
            .display()
            .map_err(|e| Error::Generic(e.to_string()))?;

        Ok(format!("{table}"))
    } else {
        Ok(serde_json::to_string_pretty(&serde_json::json!({
                "hrn": self.hrn,
                "payment_methods": methods,
                "description": self.description,
                "min_amount": self.min_amount,
                "max_amount": self.max_amount,
                "expected_amount_to_send": self.expected_amount,
                "notes": self.notes
        }))?)
    }
    }
}
pub(crate) async fn parse_dns_instructions(
    hrn: &str,
    network: Network,
    resolver_ip: Option<String>
) -> Result<(DNSHrnResolver, PaymentInstructions), ParseError> {
    
    let mut ip_address = "8.8.8.8:53".to_string();
    if let Some(res_addr) = resolver_ip {
        ip_address = res_addr;
    }

    let resolver = DNSHrnResolver(SocketAddr::from_str(&ip_address).expect("Should not fail."));
    let instructions = PaymentInstructions::parse(hrn, network, &resolver, true).await?;
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
        return Err(Error::Generic(
            "Unsupported payment method".to_string(),
        ));
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
    resolver: DNSHrnResolver
) -> Result<Payment, Error> {
    
    match payment_instructions {
        PaymentInstructions::ConfigurableAmount(instructions) => {
            // Look for on chain payment method as it's the only one we can support
            if !instructions
                .methods()
                .any(|method| matches!(method.method_type(), PaymentMethodType::OnChain))
            {
                return Err(Error::Generic(
                    "Unsupported payment method".to_string(),
                ));
            }

            let min_amount = instructions
                .min_amt()
                .map(|amnt| Amount::from_sat(amnt.milli_sats()));

            let max_amount = instructions
                .max_amt()
                .map(|amnt| Amount::from_sat(amnt.milli_sats()));

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

            Ok(Payment {
                payment_methods: vec![PaymentMethod::OnChain(onchain_details.clone().0)],
                min_amount,
                max_amount,
                description: instructions.recipient_description().map(|s| s.to_string()),
                expected_amount: Some(onchain_details.1),
                receiving_addr: Some(onchain_details.0.clone()),
                hrn: instructions.human_readable_name().unwrap().to_string(),
                notes: "".to_string()
            })
        }

        PaymentInstructions::FixedAmount(instructions) => {
            let onchain_info = get_onchain_info(instructions)?;

            Ok(Payment {
                payment_methods: vec![PaymentMethod::OnChain(onchain_info.clone().0)],
                min_amount: None,
                max_amount: instructions
                    .max_amount()
                    .map(|amnt| Amount::from_sat(amnt.milli_sats())),
                description: instructions.recipient_description().map(|s| s.to_string()),
                expected_amount: Some(onchain_info.1),
                receiving_addr: Some(onchain_info.0),
                notes: "".to_string(),
                hrn: instructions.human_readable_name().unwrap().to_string(),
            })
        }
    }
}

/// Resolves the dns payment instructions found at the specified Human Readable Name
pub async fn resolve_dns_recipient(hrn: &str, network: Network, ip: Option<String>) -> Result<Payment, ParseError> {
    let (resolver, instructions) = parse_dns_instructions(hrn, network, ip).await?;
 
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

            let payment = Payment {
                min_amount,
                max_amount,
                payment_methods: fixed_instructions.methods().into(),
                description,
                expected_amount: None,
                receiving_addr: None,
                hrn: hrn.to_string(),
                notes: "This is configurable payment instructions. You must send an amount between min_amount and max_amount if set.".to_string()
            };

            Ok(payment)
        }

        PaymentInstructions::FixedAmount(ix) => {
            let max_amount = ix
                .max_amount()
                .map(|amnt| Amount::from_sat(amnt.milli_sats()));

            let payment = Payment {
                min_amount: None,
                max_amount,
                payment_methods: ix.methods().into(),
                description: ix.recipient_description().map(|s| s.to_string()),
                expected_amount: None,
                receiving_addr: None,
                hrn: hrn.to_string(),
                notes: "This is a fixed payment instructions. You must send exactly the amount specified in max_amount.".to_string()
            };

            Ok(payment)
        }
    }
}
