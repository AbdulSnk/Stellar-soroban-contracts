use crate::dispute::Dispute;

impl ClaimsContract {
    pub fn settle_claim(env: Env, claim_id: u64, processor: Address) -> Result<(), ContractError> {
        // 1. Basic Authorization & State Check
        processor.require_auth();
        let mut claim: Claim =
            env.storage().instance().get(&claim_id).ok_or(ContractError::NotFound)?;

        if claim.status != ClaimStatus::Approved {
            return Err(ContractError::InvalidState);
        }

        // 2. Define the High-Value Threshold (e.g., 5,000 USDC/XLM)
        let msig_threshold_limit: i128 = 5_000 * 10_000_000; // Adjust based on token decimals

        if claim.amount > msig_threshold_limit {
            // 3. Generate a Unique Action Hash for this specific claim settlement
            // We hash the claim_id and amount to ensure signers know exactly what they are approving
            let mut hasher = env.crypto().sha256();
            hasher.update(&claim_id.to_xdr(&env));
            hasher.update(&claim.amount.to_xdr(&env));
            let action_hash = hasher.finalize();

            // 4. Call the Shared Authorization Module
            let is_authorized = insurance_contracts::authorization::check_multisig_auth(
                &env,
                &processor,
                action_hash,
                Role::ClaimProcessor,
            )
            .map_err(|_| ContractError::Unauthorized)?;

            if !is_authorized {
                // Return early - the signature is recorded, but we need more
                env.events()
                    .publish((Symbol::new(&env, "settlement_pending"), claim_id), processor);
                return Ok(());
            }
        } else {
            // For low-value claims, standard single-signer check is enough
            insurance_contracts::authorization::require_claim_processing(&env, &processor)
                .map_err(|_| ContractError::Unauthorized)?;
        }

        // 5. Execution: If we reached here, Multi-Sig is complete or not required
        claim.status = ClaimStatus::Settled;
        env.storage().instance().set(&claim_id, &claim);

        // 6. Cross-Contract Call to Risk Pool to trigger actual payment
        let risk_pool_addr: Address = env.storage().instance().get(&"RISK_POOL").unwrap();
        let client = RiskPoolClient::new(&env, &risk_pool_addr);
        client.payout_reserved_claim(
            &env.current_contract_address(),
            &claim_id,
            &claim.policyholder,
        );

        env.events()
            .publish((Symbol::new(&env, "claim_settled"), claim_id), claim.amount);

        Ok(())
    }
}
