use bdk_wallet::bitcoin::{Address, Amount, Network};
use bitcoin_payment_instructions::{
    FixedAmountPaymentInstructions, ParseError, PaymentInstructions, PaymentMethod,
    PaymentMethodType, amount, dns_resolver::DNSHrnResolver, hrn_resolution::HrnResolver,
};
use core::{net::SocketAddr, str::FromStr};

async fn parse_dns_instructions(
    hrn: &str,
    resolver: &impl HrnResolver,
    network: Network,
) -> Result<PaymentInstructions, ParseError> {
    let instructions = PaymentInstructions::parse(hrn, network, resolver, true).await?;
    Ok(instructions)
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Payment {
    pub address: Address,
    pub amount: Amount,
    pub min_amount: Option<Amount>,
    pub max_amount: Option<Amount>,
    pub dnssec_proof: Option<Vec<u8>>,
}

fn process_fixed_instructions(
    instructions: &FixedAmountPaymentInstructions,
) -> Result<Payment, ParseError> {
    // Look for on chain payment method as it's the only one we can support
    let PaymentMethod::OnChain(addr) = instructions
        .methods()
        .iter()
        .find(|ix| matches!(ix, PaymentMethod::OnChain(_)))
        .map(|pm| pm)
        .unwrap()
    else {
        return Err(ParseError::InvalidInstructions(
            "Unsupported payment method",
        ));
    };

    let Some(onchain_amount) = instructions.onchain_payment_amount() else {
        return Err(ParseError::InvalidInstructions(
            "On chain amount should be specified",
        ));
    };

    // We need this conversion since Amount from instructions is different from Amount from bitcoin
    let onchain_amount = Amount::from_sat(onchain_amount.milli_sats());

    Ok(Payment {
        address: addr.clone(),
        amount: onchain_amount,
        min_amount: None,
        max_amount: None,
        dnssec_proof: instructions.bip_353_dnssec_proof().clone(),
    })
}

pub async fn resolve_dns_recipient(
    hrn: &str,
    amount: Amount,
    network: Network,
) -> Result<Payment, ParseError> {
    let resolver = DNSHrnResolver(SocketAddr::from_str("8.8.8.8:53").expect("Should not fail."));
    let payment_instructions = parse_dns_instructions(hrn, &resolver, network).await?;

    match payment_instructions {
        PaymentInstructions::ConfigurableAmount(instructions) => {
            // Look for on chain payment method as it's the only one we can support
            if instructions
                .methods()
                .find(|method| matches!(method.method_type(), PaymentMethodType::OnChain))
                .is_none()
            {
                return Err(ParseError::InvalidInstructions(
                    "Unsupported payment method",
                ));
            }

            let min_amount = instructions
                .min_amt()
                .map(|amnt| Amount::from_sat(amnt.sats_rounding_up()));
            let max_amount = instructions
                .max_amt()
                .map(|amnt| Amount::from_sat(amnt.sats_rounding_up()));

            let fixed_instructions = instructions
                .set_amount(
                    amount::Amount::from_sats(amount.to_sat()).unwrap(),
                    &resolver,
                )
                .await
                .map_err(|s| ParseError::InvalidInstructions(s))?;

            let mut instructions = process_fixed_instructions(&fixed_instructions)?;

            instructions.min_amount = min_amount;
            instructions.max_amount = max_amount;

            Ok(instructions)
        }

        PaymentInstructions::FixedAmount(instructions) => process_fixed_instructions(&instructions),
    }
}
