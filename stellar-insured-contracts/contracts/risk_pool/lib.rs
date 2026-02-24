#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, Address, Env, Symbol};
use soroban_sdk::{contract, contractimpl, contracterror, contracttype, Address, Env, Symbol};

// Import authorization from the common library
use insurance_contracts::authorization::{
    get_role, initialize_admin, register_trusted_contract, require_admin,
    require_risk_pool_management, require_trusted_contract, Role,
};

// Import invariant checks and error types
use insurance_invariants::{InvariantError, ProtocolInvariants};

// Import gas optimization utilities
use insurance_contracts::gas_optimization::{GasOptimizer, PerformanceMonitor};

// Import optimized risk pool implementation
use crate::optimized_risk_pool::OptimizedRiskPool;

#[contract]
pub struct RiskPoolContract;

const PAUSED: Symbol = Symbol::short("PAUSED");
const CONFIG: Symbol = Symbol::short("CONFIG");
const POOL_STATS: Symbol = Symbol::short("POOL_ST");
const PROVIDER: Symbol = Symbol::short("PROVIDER");
const RESERVED_TOTAL: Symbol = Symbol::short("RSV_TOT");
const CLAIM_RESERVATION: Symbol = Symbol::short("CLM_RSV");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ContractError {
    Unauthorized = 1,
    Paused = 2,
    InvalidInput = 3,
    InsufficientFunds = 4,
    NotFound = 5,
    AlreadyExists = 6,
    InvalidState = 7,
    NotInitialized = 9,
    AlreadyInitialized = 10,
    InvalidRole = 11,
    RoleNotFound = 12,
    NotTrustedContract = 13,
    // Invariant violation errors (100-199)
    LiquidityViolation = 100,
    InvalidAmount = 103,
    Overflow = 107,
}

impl From<insurance_contracts::authorization::AuthError> for ContractError {
    fn from(err: insurance_contracts::authorization::AuthError) -> Self {
        match err {
            insurance_contracts::authorization::AuthError::Unauthorized => {
                ContractError::Unauthorized
            }
            insurance_contracts::authorization::AuthError::InvalidRole => {
                ContractError::InvalidRole
            }
            insurance_contracts::authorization::AuthError::RoleNotFound => {
                ContractError::RoleNotFound
            }
            insurance_contracts::authorization::AuthError::NotTrustedContract => {
                ContractError::NotTrustedContract
            }
        }
    }
}

impl From<InvariantError> for ContractError {
    fn from(err: InvariantError) -> Self {
        match err {
            InvariantError::LiquidityViolation => ContractError::LiquidityViolation,
            InvariantError::InvalidAmount => ContractError::InvalidAmount,
            InvariantError::Overflow => ContractError::Overflow,
            _ => ContractError::InvalidState,
        }
    }
}

/// Structured view of risk pool statistics for frontend/indexer consumption.
/// Contains both raw stats and derived metrics for efficient data transfer.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RiskPoolStatsView {
    /// Total liquidity currently in the pool
    pub total_liquidity: i128,
    /// Total amount paid out in claims
    pub total_claims_paid: i128,
    /// Total deposits made to the pool
    pub total_deposits: i128,
    /// Number of liquidity providers
    pub provider_count: u64,
    /// Amount reserved for pending/approved claims
    pub reserved_for_claims: i128,
    /// Liquidity available for new claims (total_liquidity - reserved)
    pub available_liquidity: i128,
    /// Utilization rate in basis points (reserved / total * 10000)
    /// Returns 0 if total_liquidity is 0
    pub utilization_rate_bps: u32,
}

fn validate_address(_env: &Env, _address: &Address) -> Result<(), ContractError> {
    Ok(())
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

/// I1: Check liquidity preservation invariant
/// Ensures: total_liquidity >= reserved_for_claims
fn check_liquidity_invariant(env: &Env) -> Result<(), ContractError> {
    let stats: (i128, i128, i128, u64) =
        env.storage().persistent().get(&POOL_STATS).ok_or(ContractError::NotFound)?;

    let reserved_total: i128 = env.storage().persistent().get(&RESERVED_TOTAL).unwrap_or(0i128);

    // I1: Liquidity Preservation: available_liquidity >= reserved_claims
    if stats.0 < reserved_total {
        return Err(ContractError::LiquidityViolation);
    }

    Ok(())
}

/// I4: Validate amount is positive and within safe range
fn validate_amount(amount: i128) -> Result<(), ContractError> {
    if amount <= 0 {
        return Err(ContractError::InvalidAmount);
    }
    Ok(())
}

#[contractimpl]
impl RiskPoolContract {
    pub fn initialize(
        env: Env,
        admin: Address,
        xlm_token: Address,
        min_provider_stake: i128,
        claims_contract: Address,
    ) -> Result<(), ContractError> {
        // Check if already initialized
        if insurance_contracts::authorization::get_admin(&env).is_some() {
            return Err(ContractError::AlreadyInitialized);
        }

        validate_address(&env, &admin)?;
        validate_address(&env, &xlm_token)?;
        validate_address(&env, &claims_contract)?;

        if min_provider_stake <= 0 {
            return Err(ContractError::InvalidInput);
        }
        // Sanity cap: min stake cannot exceed 1 billion XLM expressed in stroops
        const MAX_MIN_STAKE: i128 = 10_000_000_000_000_000;
        if min_provider_stake > MAX_MIN_STAKE {
            return Err(ContractError::InvalidInput);
        }

        // Initialize authorization system with admin
        admin.require_auth();
        initialize_admin(&env, admin.clone());

        // Register claims contract as trusted for cross-contract calls
        register_trusted_contract(&env, &admin, &claims_contract)?;

        env.storage().persistent().set(&CONFIG, &(xlm_token, min_provider_stake));

        let stats = (0i128, 0i128, 0i128, 0u64);
        env.storage().persistent().set(&POOL_STATS, &stats);

        env.events().publish((Symbol::new(&env, "initialized"), ()), admin);

        Ok(())
    }

    pub fn deposit_liquidity(
        env: Env,
        provider: Address,
        amount: i128,
    ) -> Result<(), ContractError> {
        // Use performance monitoring
        PerformanceMonitor::track_operation(&env, "deposit_liquidity", || {
            Self::deposit_liquidity_impl(env.clone(), provider.clone(), amount)
        })
    }

    pub fn withdraw_liquidity(
        env: Env,
        provider: Address,
        amount: i128,
    ) -> Result<(), ContractError> {
        PerformanceMonitor::track_operation(&env, "withdraw_liquidity", || {
            Self::withdraw_liquidity_impl(env.clone(), provider.clone(), amount)
        })
    }

    fn withdraw_liquidity_impl(
        env: Env,
        provider: Address,
        amount: i128,
    ) -> Result<(), ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Provider must authorize the withdrawal
        provider.require_auth();

        validate_address(&env, &provider)?;

        // Amount must be positive
        validate_amount(amount)?;

        // Ensure pool is initialized
        let _config: (Address, i128) =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;

        // Fetch current pool stats and reserved total
        let mut stats: (i128, i128, i128, u64) =
            env.storage().persistent().get(&POOL_STATS).ok_or(ContractError::NotFound)?;

        let reserved_total: i128 = env.storage().persistent().get(&RESERVED_TOTAL).unwrap_or(0i128);

        // Pool must have available (unreserved) liquidity
        let available_pool = stats.0.checked_sub(reserved_total).ok_or(ContractError::Overflow)?;
        if available_pool < amount {
            return Err(ContractError::InsufficientFunds);
        }

        // Fetch provider info and ensure provider has sufficient balance
        let provider_info: (i128, i128, u64) = env
            .storage()
            .persistent()
            .get(&(PROVIDER, provider.clone()))
            .ok_or(ContractError::NotFound)?;

        let provider_balance = provider_info.0;
        if provider_balance < amount {
            return Err(ContractError::InsufficientFunds);
        }

        // Update provider balance (decrease) using optimized helper
        OptimizedRiskPool::update_provider_info_optimized(&env, &provider, -amount, 0)?;

        // Update pool statistics: reduce liquidity, do not change deposits or provider count
        OptimizedRiskPool::update_pool_stats_optimized(&env, -amount, 0, 0, 0)?;

        // Re-check invariants
        check_liquidity_invariant(&env)?;

        let new_balance = provider_balance.checked_sub(amount).ok_or(ContractError::Overflow)?;
        env.events().publish(
            (Symbol::new(&env, "liquidity_withdrawn"), provider.clone()),
            (amount, new_balance),
        );

        Ok(())
    }

    fn deposit_liquidity_impl(
        env: Env,
        provider: Address,
        amount: i128,
    ) -> Result<(), ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_address(&env, &provider)?;

        // I4: Amount Non-Negativity - amount must be positive
        validate_amount(amount)?;

        let config: (Address, i128) =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;

        // Use optimized provider info access
        let provider_info = OptimizedRiskPool::get_provider_info_optimized(&env, &provider)?;
        let current_stake = OptimizedRiskPool::from_compact_amount(provider_info.total_deposited);

        // After the amount is added, the provider's cumulative stake must meet min_provider_stake
        if current_stake.checked_add(amount).unwrap_or(i128::MAX) < config.1 {
            return Err(ContractError::InvalidInput);
        }

        // Sanity cap: a single deposit cannot exceed 10 billion XLM in stroops
        const MAX_DEPOSIT: i128 = 100_000_000_000_000_000;
        if amount > MAX_DEPOSIT {
            return Err(ContractError::InvalidInput);
        }

        // Use optimized update operations
        OptimizedRiskPool::update_provider_info_optimized(&env, &provider, amount, amount)?;
        OptimizedRiskPool::update_pool_stats_optimized(&env, amount, 0, amount, 0)?;

        // I1: Assert liquidity invariant holds after deposit
        check_liquidity_invariant(&env)?;

        env.events().publish(
            (Symbol::new(&env, "liquidity_deposited"), provider.clone()),
            (amount, current_stake + amount),
        );

        Ok(())
    }

    pub fn get_pool_stats(env: Env) -> Result<(i128, i128, i128, u64), ContractError> {
        let stats: (i128, i128, i128, u64) =
            env.storage().persistent().get(&POOL_STATS).ok_or(ContractError::NotFound)?;
        let stats: (i128, i128, i128, u64) = env
            .storage()
            .persistent()
            .get(&POOL_STATS)
            .ok_or(ContractError::NotFound)?;

        Ok(stats)
    }

    pub fn get_provider_info(env: Env, provider: Address) -> Result<(i128, i128, u64), ContractError> {
        validate_address(&env, &provider)?;
    
        let provider_info: (i128, i128, u64) = env
            .storage()
            .persistent()
            .get(&(PROVIDER, provider))
            .ok_or(ContractError::NotFound)?;
    
        Ok(provider_info)
    }

    pub fn reserve_liquidity(
        env: Env,
        caller_contract: Address,
        claim_id: u64,
        amount: i128,
    ) -> Result<(), ContractError> {
        // Verify that the caller is a trusted contract (e.g., claims contract)
        caller_contract.require_auth();
        require_trusted_contract(&env, &caller_contract)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // I4: Amount Non-Negativity - amount must be positive
        validate_amount(amount)?;

        if env.storage().persistent().has(&(CLAIM_RESERVATION, claim_id)) {
            return Err(ContractError::AlreadyExists);
        }

        let stats: (i128, i128, i128, u64) =
            env.storage().persistent().get(&POOL_STATS).ok_or(ContractError::NotFound)?;

        let reserved_total: i128 = env.storage().persistent().get(&RESERVED_TOTAL).unwrap_or(0i128);

        let available = stats.0.checked_sub(reserved_total).ok_or(ContractError::Overflow)?;
        if available < amount {
            return Err(ContractError::InsufficientFunds);
        }

        // Safe arithmetic for reservation
        let new_reserved_total =
            reserved_total.checked_add(amount).ok_or(ContractError::Overflow)?;

        env.storage().persistent().set(&RESERVED_TOTAL, &new_reserved_total);
        env.storage().persistent().set(&(CLAIM_RESERVATION, claim_id), &amount);

        // I1: Assert liquidity invariant holds after reservation
        check_liquidity_invariant(&env)?;

        env.events().publish(
            (Symbol::new(&env, "liquidity_reserved"), claim_id),
            (amount, new_reserved_total),
        );

        Ok(())
    }

    pub fn payout_reserved_claim(
        env: Env,
        caller_contract: Address,
        claim_id: u64,
        recipient: Address,
    ) -> Result<(), ContractError> {
        // Default to Native asset for backward compatibility
        Self::payout_reserved_claim_multi_asset(
            env,
            caller_contract,
            claim_id,
            recipient,
            shared::types::Asset::Native,
        )
    }

    /// Multi-asset version of payout_reserved_claim
    pub fn payout_reserved_claim_multi_asset(
        env: Env,
        caller_contract: Address,
        claim_id: u64,
        recipient: Address,
        payout_asset: shared::types::Asset,
    ) -> Result<(), ContractError> {
        // Verify that the caller is a trusted contract (e.g., claims contract)
        caller_contract.require_auth();
        require_trusted_contract(&env, &caller_contract)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_address(&env, &recipient)?;

        let mut stats: (i128, i128, i128, u64) =
            env.storage().persistent().get(&POOL_STATS).ok_or(ContractError::NotFound)?;

        let mut reserved_total: i128 =
            env.storage().persistent().get(&RESERVED_TOTAL).unwrap_or(0i128);

        let amount: i128 = env
            .storage()
            .persistent()
            .get(&(CLAIM_RESERVATION, claim_id))
            .ok_or(ContractError::NotFound)?;

        if amount <= 0 {
            return Err(ContractError::InvalidState);
        }

        if reserved_total < amount {
            return Err(ContractError::InvalidState);
        }

        if stats.0 < amount {
            return Err(ContractError::InsufficientFunds);
        }

        // Safe arithmetic for payout
        reserved_total = reserved_total.checked_sub(amount).ok_or(ContractError::Overflow)?;
        stats.0 = stats.0.checked_sub(amount).ok_or(ContractError::Overflow)?;
        stats.1 = stats.1.checked_add(amount).ok_or(ContractError::Overflow)?;

        env.storage().persistent().set(&RESERVED_TOTAL, &reserved_total);
        env.storage().persistent().remove(&(CLAIM_RESERVATION, claim_id));
        env.storage().persistent().set(&POOL_STATS, &stats);

        // Store payout asset information for tracking
        env.storage().persistent().set(
            &(Symbol::new(&env, "PAYOUT_ASSET"), claim_id),
            &payout_asset,
        );

        // I1: Assert liquidity invariant holds after payout
        check_liquidity_invariant(&env)?;

        env.events().publish(
            (Symbol::new(&env, "reserved_claim_payout"), claim_id),
            (recipient, amount, payout_asset),
        );

        Ok(())
    }

    /// Get the payout asset for a claim
    pub fn get_claim_payout_asset(
        env: Env,
        claim_id: u64,
    ) -> Result<shared::types::Asset, ContractError> {
        env.storage()
            .persistent()
            .get(&(Symbol::new(&env, "PAYOUT_ASSET"), claim_id))
            .ok_or(ContractError::NotFound)
    }

pub fn payout_claim(
    env: Env,
    manager: Address,
    recipient: Address,
    amount: i128,
) -> Result<(), ContractError> {
    manager.require_auth();
    
    // I4: Amount Non-Negativity
    validate_amount(amount)?;

    // --- NEW: MULTI-SIG LOGIC ---
    
    // Define what constitutes a "High Value" transaction
    let high_value_threshold: i128 = 10_000 * 10_000_000; // e.g., 10k XLM

    if amount > high_value_threshold {
        // Create a unique hash for this specific payout
        // We use a hash of (recipient, amount) so people are signing the ACTUAL data
        let mut hasher = env.crypto().sha256();
        hasher.update(&recipient.to_xdr(&env));
        hasher.update(&amount.to_xdr(&env));
        let action_hash = hasher.finalize();

        // Check with Auth Module
        let is_authorized = insurance_contracts::authorization::check_multisig_auth(
            &env, 
            manager.clone(), 
            action_hash, 
            Role::RiskPoolManager
        );

        if !is_authorized {
            // Emit event that a signature was collected but more are needed
            env.events().publish((Symbol::new(&env, "payout_pending"), manager), amount);
            return Ok(()); // Exit early, waiting for more signatures
        }
    } else {
        // For small amounts, standard single-sig role check is enough
        require_risk_pool_management(&env, &manager)?;
    }

    // --- END MULTI-SIG LOGIC ---

    // If we reach here, it's either a small amount OR multi-sig threshold was met
    if is_paused(&env) { return Err(ContractError::Paused); }

    let mut stats: (i128, i128, i128, u64) =
        env.storage().persistent().get(&POOL_STATS).ok_or(ContractError::NotFound)?;
    
    // ... rest of your existing logic for subtracting from stats.0 and adding to stats.1 ...

    env.events().publish((Symbol::new(&env, "claim_payout"), recipient), (amount,));
    Ok(())
}

    pub fn pause(env: Env, admin: Address) -> Result<(), ContractError> {
        // Verify identity and require admin permission
        admin.require_auth();
        require_admin(&env, &admin)?;

        set_paused(&env, true);

        env.events().publish((Symbol::new(&env, "paused"), ()), admin);

        Ok(())
    }

    pub fn unpause(env: Env, admin: Address) -> Result<(), ContractError> {
        // Verify identity and require admin permission
        admin.require_auth();
        require_admin(&env, &admin)?;

        set_paused(&env, false);

        env.events().publish((Symbol::new(&env, "unpaused"), ()), admin);

        Ok(())
    }

    /// Grant risk pool manager role to an address (admin only)
    pub fn grant_manager_role(
        env: Env,
        admin: Address,
        manager: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        insurance_contracts::authorization::grant_role(
            &env,
            &admin,
            &manager,
            Role::RiskPoolManager,
        )?;

        env.events()
            .publish((Symbol::new(&env, "role_granted"), manager.clone()), admin);

        Ok(())
    }

    /// Revoke risk pool manager role from an address (admin only)
    pub fn revoke_manager_role(
        env: Env,
        admin: Address,
        manager: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        insurance_contracts::authorization::revoke_role(&env, &admin, &manager)?;

        env.events()
            .publish((Symbol::new(&env, "role_revoked"), manager.clone()), admin);

        Ok(())
    }

    /// Grant auditor role to an address (admin only)
    pub fn grant_auditor_role(
        env: Env,
        admin: Address,
        auditor: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        insurance_contracts::authorization::grant_role(
            &env,
            &admin,
            &auditor,
            Role::Auditor,
        )?;

        env.events()
            .publish((Symbol::new(&env, "auditor_role_granted"), auditor.clone()), admin);

        Ok(())
    }

    /// Revoke auditor role from an address (admin only)
    pub fn revoke_auditor_role(
        env: Env,
        admin: Address,
        auditor: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        insurance_contracts::authorization::revoke_role(&env, &admin, &auditor)?;

        env.events()
            .publish((Symbol::new(&env, "auditor_role_revoked"), auditor.clone()), admin);

        Ok(())
    }

    /// Allow role delegation by eligible users
    pub fn delegate_role(
        env: Env,
        delegator: Address,
        delegatee: Address,
        role: Role,
    ) -> Result<(), ContractError> {
        delegator.require_auth();

        insurance_contracts::authorization::delegate_role(&env, &delegator, &delegatee, role)?;

        env.events()
            .publish((Symbol::new(&env, "role_delegated"), delegatee.clone(), role.clone()), delegator);

        Ok(())
    }

    /// Revoke a delegated role (admin only)
    pub fn revoke_delegated_role(
        env: Env,
        admin: Address,
        target: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        insurance_contracts::authorization::revoke_delegated_role(&env, &admin, &target)?;

        env.events()
            .publish((Symbol::new(&env, "delegated_role_revoked"), target.clone()), admin);

        Ok(())
    }

    /// Get the role of an address
    pub fn get_user_role(env: Env, address: Address) -> Role {
        get_role(&env, &address)
    }

    /// Grant auditor role to an address (admin only)
    pub fn grant_auditor_role(
        env: Env,
        admin: Address,
        auditor: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        insurance_contracts::authorization::grant_role(
            &env,
            &admin,
            &auditor,
            Role::Auditor,
        )?;

        env.events()
            .publish((Symbol::new(&env, "auditor_role_granted"), auditor.clone()), admin);

        Ok(())
    }

    /// Revoke auditor role from an address (admin only)
    pub fn revoke_auditor_role(
        env: Env,
        admin: Address,
        auditor: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        insurance_contracts::authorization::revoke_role(&env, &admin, &auditor)?;

        env.events()
            .publish((Symbol::new(&env, "auditor_role_revoked"), auditor.clone()), admin);

        Ok(())
    }

    /// Allow role delegation by eligible users
    pub fn delegate_role(
        env: Env,
        delegator: Address,
        delegatee: Address,
        role: Role,
    ) -> Result<(), ContractError> {
        delegator.require_auth();

        insurance_contracts::authorization::delegate_role(&env, &delegator, &delegatee, role)?;

        env.events()
            .publish((Symbol::new(&env, "role_delegated"), delegatee.clone(), role.clone()), delegator);

        Ok(())
    }

    /// Revoke a delegated role (admin only)
    pub fn revoke_delegated_role(
        env: Env,
        admin: Address,
        target: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        insurance_contracts::authorization::revoke_delegated_role(&env, &admin, &target)?;

        env.events()
            .publish((Symbol::new(&env, "delegated_role_revoked"), target.clone()), admin);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Env, Address};

    fn setup_test_env() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let xlm_token = Address::generate(&env);
        let claims_contract = Address::generate(&env);

        (env, admin, xlm_token, claims_contract)
    }

    fn initialize_pool(
        env: &Env,
        admin: &Address,
        xlm_token: &Address,
        claims_contract: &Address,
    ) {
        RiskPoolContract::initialize(
            env.clone(),
            admin.clone(),
            xlm_token.clone(),
            1000,  // min_provider_stake
            claims_contract.clone(),
        ).unwrap();
    }

    // ============================================================
    // INITIALIZATION TESTS
    // ============================================================

    #[test]
    fn test_initialize_success() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();

        let result = RiskPoolContract::initialize(
            env.clone(),
            admin.clone(),
            xlm_token.clone(),
            1000,
            claims_contract.clone(),
        );

        assert!(result.is_ok());

        let stats = RiskPoolContract::get_pool_stats(env.clone()).unwrap();
        assert_eq!(stats.0, 0);  // total_liquidity
        assert_eq!(stats.1, 0);  // total_paid_out
        assert_eq!(stats.2, 0);  // total_deposited
        assert_eq!(stats.3, 0);  // providers_count
    }

    #[test]
    fn test_initialize_already_initialized() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let result = RiskPoolContract::initialize(
            env.clone(),
            admin.clone(),
            xlm_token.clone(),
            1000,
            claims_contract.clone(),
        );

        assert_eq!(result, Err(ContractError::AlreadyInitialized));
    }

    #[test]
    fn test_initialize_invalid_min_stake_zero() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();

        let result = RiskPoolContract::initialize(
            env.clone(),
            admin.clone(),
            xlm_token.clone(),
            0,  // invalid
            claims_contract.clone(),
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_initialize_invalid_min_stake_negative() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();

        let result = RiskPoolContract::initialize(
            env.clone(),
            admin.clone(),
            xlm_token.clone(),
            -100,  // invalid
            claims_contract.clone(),
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    // ============================================================
    // DEPOSIT LIQUIDITY TESTS - Happy Path
    // ============================================================

    #[test]
    fn test_deposit_liquidity_success() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);

        let result = RiskPoolContract::deposit_liquidity(
            env.clone(),
            provider.clone(),
            5000,
        );

        assert!(result.is_ok());

        let stats = RiskPoolContract::get_pool_stats(env.clone()).unwrap();
        assert_eq!(stats.0, 5000);  // total_liquidity
        assert_eq!(stats.2, 5000);  // total_deposited

        let provider_info = RiskPoolContract::get_provider_info(env.clone(), provider.clone()).unwrap();
        assert_eq!(provider_info.1, 5000);  // total_deposited by provider
    }

    #[test]
    fn test_deposit_liquidity_multiple_deposits_same_provider() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);

        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 5000).unwrap();
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 3000).unwrap();

        let stats = RiskPoolContract::get_pool_stats(env.clone()).unwrap();
        assert_eq!(stats.0, 8000);  // total_liquidity

        let provider_info = RiskPoolContract::get_provider_info(env.clone(), provider.clone()).unwrap();
        assert_eq!(provider_info.1, 8000);  // total_deposited by provider
    }

    #[test]
    fn test_deposit_liquidity_multiple_providers() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider1 = Address::generate(&env);
        let provider2 = Address::generate(&env);
        let provider3 = Address::generate(&env);

        RiskPoolContract::deposit_liquidity(env.clone(), provider1.clone(), 5000).unwrap();
        RiskPoolContract::deposit_liquidity(env.clone(), provider2.clone(), 3000).unwrap();
        RiskPoolContract::deposit_liquidity(env.clone(), provider3.clone(), 2000).unwrap();

        let stats = RiskPoolContract::get_pool_stats(env.clone()).unwrap();
        assert_eq!(stats.0, 10000);  // total_liquidity
    }

    // ============================================================
    // DEPOSIT LIQUIDITY TESTS - Edge Cases & Failures
    // ============================================================

    #[test]
    fn test_deposit_liquidity_below_minimum_stake() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);

        let result = RiskPoolContract::deposit_liquidity(
            env.clone(),
            provider.clone(),
            500,  // below min_provider_stake of 1000
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_deposit_liquidity_zero_amount() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);

        let result = RiskPoolContract::deposit_liquidity(
            env.clone(),
            provider.clone(),
            0,
        );

        assert_eq!(result, Err(ContractError::InvalidAmount));
    }

    #[test]
    fn test_deposit_liquidity_negative_amount() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);

        let result = RiskPoolContract::deposit_liquidity(
            env.clone(),
            provider.clone(),
            -100,
        );

        assert_eq!(result, Err(ContractError::InvalidAmount));
    }

    #[test]
    fn test_deposit_liquidity_when_paused() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        RiskPoolContract::pause(env.clone(), admin.clone()).unwrap();

        let provider = Address::generate(&env);

        let result = RiskPoolContract::deposit_liquidity(
            env.clone(),
            provider.clone(),
            5000,
        );

        assert_eq!(result, Err(ContractError::Paused));
    }

    #[test]
    fn test_deposit_liquidity_exact_minimum_stake() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);

        let result = RiskPoolContract::deposit_liquidity(
            env.clone(),
            provider.clone(),
            1000,  // exactly min_provider_stake
        );

        assert!(result.is_ok());
    }

    // ============================================================
    // RESERVE LIQUIDITY TESTS - Happy Path
    // ============================================================

    #[test]
    fn test_reserve_liquidity_success() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        let result = RiskPoolContract::reserve_liquidity(
            env.clone(),
            claims_contract.clone(),
            1,  // claim_id
            3000,
        );

        assert!(result.is_ok());

        // Verify reservation was recorded
        let reserved_total: i128 = env.storage().persistent().get(&RESERVED_TOTAL).unwrap();
        assert_eq!(reserved_total, 3000);
    }

    #[test]
    fn test_reserve_liquidity_multiple_claims() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 1, 2000).unwrap();
        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 2, 3000).unwrap();

        let reserved_total: i128 = env.storage().persistent().get(&RESERVED_TOTAL).unwrap();
        assert_eq!(reserved_total, 5000);
    }

    // ============================================================
    // RESERVE LIQUIDITY TESTS - Liquidity Exhaustion Scenarios
    // ============================================================

    #[test]
    fn test_reserve_liquidity_insufficient_funds() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 5000).unwrap();

        let result = RiskPoolContract::reserve_liquidity(
            env.clone(),
            claims_contract.clone(),
            1,
            6000,  // more than available
        );

        assert_eq!(result, Err(ContractError::InsufficientFunds));
    }

    #[test]
    fn test_reserve_liquidity_exhaustion_with_multiple_claims() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        // Reserve most of the liquidity
        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 1, 6000).unwrap();
        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 2, 3000).unwrap();

        // Try to reserve more than remaining
        let result = RiskPoolContract::reserve_liquidity(
            env.clone(),
            claims_contract.clone(),
            3,
            2000,  // only 1000 available
        );

        assert_eq!(result, Err(ContractError::InsufficientFunds));
    }

    #[test]
    fn test_reserve_liquidity_exact_available_amount() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 5000).unwrap();

        let result = RiskPoolContract::reserve_liquidity(
            env.clone(),
            claims_contract.clone(),
            1,
            5000,  // exactly all available
        );

        assert!(result.is_ok());

        // Try to reserve more - should fail
        let result2 = RiskPoolContract::reserve_liquidity(
            env.clone(),
            claims_contract.clone(),
            2,
            1,
        );

        assert_eq!(result2, Err(ContractError::InsufficientFunds));
    }

    #[test]
    fn test_reserve_liquidity_unauthorized_contract() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        let untrusted_contract = Address::generate(&env);

        let result = RiskPoolContract::reserve_liquidity(
            env.clone(),
            untrusted_contract.clone(),
            1,
            3000,
        );

        assert_eq!(result, Err(ContractError::NotTrustedContract));
    }

    #[test]
    fn test_reserve_liquidity_duplicate_claim_id() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 1, 3000).unwrap();

        let result = RiskPoolContract::reserve_liquidity(
            env.clone(),
            claims_contract.clone(),
            1,  // same claim_id
            2000,
        );

        assert_eq!(result, Err(ContractError::AlreadyExists));
    }

    #[test]
    fn test_reserve_liquidity_zero_amount() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        let result = RiskPoolContract::reserve_liquidity(
            env.clone(),
            claims_contract.clone(),
            1,
            0,
        );

        assert_eq!(result, Err(ContractError::InvalidAmount));
    }

    #[test]
    fn test_reserve_liquidity_when_paused() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        RiskPoolContract::pause(env.clone(), admin.clone()).unwrap();

        let result = RiskPoolContract::reserve_liquidity(
            env.clone(),
            claims_contract.clone(),
            1,
            3000,
        );

        assert_eq!(result, Err(ContractError::Paused));
    }

    // ============================================================
    // PAYOUT RESERVED CLAIM TESTS
    // ============================================================

    #[test]
    fn test_payout_reserved_claim_success() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        let recipient = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 1, 3000).unwrap();

        let result = RiskPoolContract::payout_reserved_claim(
            env.clone(),
            claims_contract.clone(),
            1,
            recipient.clone(),
        );

        assert!(result.is_ok());

        let stats = RiskPoolContract::get_pool_stats(env.clone()).unwrap();
        assert_eq!(stats.0, 7000);  // 10000 - 3000
        assert_eq!(stats.1, 3000);  // total_paid_out

        let reserved_total: i128 = env.storage().persistent().get(&RESERVED_TOTAL).unwrap();
        assert_eq!(reserved_total, 0);
    }

    #[test]
    fn test_payout_reserved_claim_not_found() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let recipient = Address::generate(&env);

        let result = RiskPoolContract::payout_reserved_claim(
            env.clone(),
            claims_contract.clone(),
            999,  // nonexistent claim_id
            recipient.clone(),
        );

        assert_eq!(result, Err(ContractError::NotFound));
    }

    #[test]
    fn test_payout_reserved_claim_unauthorized() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        let recipient = Address::generate(&env);
        let untrusted_contract = Address::generate(&env);

        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();
        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 1, 3000).unwrap();

        let result = RiskPoolContract::payout_reserved_claim(
            env.clone(),
            untrusted_contract.clone(),
            1,
            recipient.clone(),
        );

        assert_eq!(result, Err(ContractError::NotTrustedContract));
    }

    #[test]
    fn test_payout_reserved_claim_when_paused() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        let recipient = Address::generate(&env);

        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();
        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 1, 3000).unwrap();

        RiskPoolContract::pause(env.clone(), admin.clone()).unwrap();

        let result = RiskPoolContract::payout_reserved_claim(
            env.clone(),
            claims_contract.clone(),
            1,
            recipient.clone(),
        );

        assert_eq!(result, Err(ContractError::Paused));
    }

    // ============================================================
    // PAYOUT CLAIM TESTS (Non-Reserved)
    // ============================================================

    #[test]
    fn test_payout_claim_success() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        let manager = Address::generate(&env);
        let recipient = Address::generate(&env);

        RiskPoolContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        let result = RiskPoolContract::payout_claim(
            env.clone(),
            manager.clone(),
            recipient.clone(),
            3000,
        );

        assert!(result.is_ok());

        let stats = RiskPoolContract::get_pool_stats(env.clone()).unwrap();
        assert_eq!(stats.0, 7000);  // 10000 - 3000
        assert_eq!(stats.1, 3000);  // total_paid_out
    }

    #[test]
    fn test_payout_claim_insufficient_funds() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        let manager = Address::generate(&env);
        let recipient = Address::generate(&env);

        RiskPoolContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 5000).unwrap();

        let result = RiskPoolContract::payout_claim(
            env.clone(),
            manager.clone(),
            recipient.clone(),
            6000,
        );

        assert_eq!(result, Err(ContractError::InsufficientFunds));
    }

    #[test]
    fn test_payout_claim_respects_reserved_liquidity() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        let manager = Address::generate(&env);
        let recipient = Address::generate(&env);

        RiskPoolContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        // Reserve 7000
        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 1, 7000).unwrap();

        // Try to payout 4000 (only 3000 available unreserved)
        let result = RiskPoolContract::payout_claim(
            env.clone(),
            manager.clone(),
            recipient.clone(),
            4000,
        );

        assert_eq!(result, Err(ContractError::InsufficientFunds));
    }

    #[test]
    fn test_payout_claim_unauthorized() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        let unauthorized = Address::generate(&env);
        let recipient = Address::generate(&env);

        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        let result = RiskPoolContract::payout_claim(
            env.clone(),
            unauthorized.clone(),
            recipient.clone(),
            3000,
        );

        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    #[test]
    fn test_payout_claim_zero_amount() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        let manager = Address::generate(&env);
        let recipient = Address::generate(&env);

        RiskPoolContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        let result = RiskPoolContract::payout_claim(
            env.clone(),
            manager.clone(),
            recipient.clone(),
            0,
        );

        assert_eq!(result, Err(ContractError::InvalidAmount));
    }

    // ============================================================
    // LIQUIDITY INVARIANT TESTS
    // ============================================================

    #[test]
    fn test_liquidity_invariant_maintained_after_operations() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        let recipient = Address::generate(&env);

        // Deposit
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();
        assert!(check_liquidity_invariant(&env).is_ok());

        // Reserve
        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 1, 3000).unwrap();
        assert!(check_liquidity_invariant(&env).is_ok());

        // Reserve more
        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 2, 2000).unwrap();
        assert!(check_liquidity_invariant(&env).is_ok());

        // Payout reserved
        RiskPoolContract::payout_reserved_claim(env.clone(), claims_contract.clone(), 1, recipient.clone()).unwrap();
        assert!(check_liquidity_invariant(&env).is_ok());
    }

    // ============================================================
    // ROLE MANAGEMENT TESTS
    // ============================================================

    #[test]
    fn test_grant_manager_role_success() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let manager = Address::generate(&env);

        let result = RiskPoolContract::grant_manager_role(
            env.clone(),
            admin.clone(),
            manager.clone(),
        );

        assert!(result.is_ok());

        let role = RiskPoolContract::get_user_role(env.clone(), manager.clone());
        assert_eq!(role, Role::RiskPoolManager);
    }

    #[test]
    fn test_grant_manager_role_unauthorized() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let unauthorized = Address::generate(&env);
        let manager = Address::generate(&env);

        let result = RiskPoolContract::grant_manager_role(
            env.clone(),
            unauthorized.clone(),
            manager.clone(),
        );

        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    #[test]
    fn test_revoke_manager_role_success() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let manager = Address::generate(&env);

        RiskPoolContract::grant_manager_role(
            env.clone(),
            admin.clone(),
            manager.clone(),
        ).unwrap();

        let result = RiskPoolContract::revoke_manager_role(
            env.clone(),
            admin.clone(),
            manager.clone(),
        );

        assert!(result.is_ok());

        let role = RiskPoolContract::get_user_role(env.clone(), manager.clone());
        assert_eq!(role, Role::User);
    }

    // ============================================================
    // PAUSE/UNPAUSE TESTS
    // ============================================================

    #[test]
    fn test_pause_success() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let result = RiskPoolContract::pause(env.clone(), admin.clone());
        assert!(result.is_ok());
        assert!(is_paused(&env));
    }

    #[test]
    fn test_pause_unauthorized() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let unauthorized = Address::generate(&env);

        let result = RiskPoolContract::pause(env.clone(), unauthorized.clone());
        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    #[test]
    fn test_unpause_success() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        RiskPoolContract::pause(env.clone(), admin.clone()).unwrap();

        let result = RiskPoolContract::unpause(env.clone(), admin.clone());
        assert!(result.is_ok());
        assert!(!is_paused(&env));
    }

    // ============================================================
    // COMPLEX SCENARIO TESTS
    // ============================================================

    #[test]
    fn test_complex_liquidity_scenario() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider1 = Address::generate(&env);
        let provider2 = Address::generate(&env);
        let recipient = Address::generate(&env);

        // Multiple providers deposit
        RiskPoolContract::deposit_liquidity(env.clone(), provider1.clone(), 10000).unwrap();
        RiskPoolContract::deposit_liquidity(env.clone(), provider2.clone(), 5000).unwrap();

        let stats = RiskPoolContract::get_pool_stats(env.clone()).unwrap();
        assert_eq!(stats.0, 15000);

        // Reserve for multiple claims
        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 1, 4000).unwrap();
        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 2, 3000).unwrap();

        // Payout one claim
        RiskPoolContract::payout_reserved_claim(env.clone(), claims_contract.clone(), 1, recipient.clone()).unwrap();

        let stats = RiskPoolContract::get_pool_stats(env.clone()).unwrap();
        assert_eq!(stats.0, 11000);  // 15000 - 4000
        assert_eq!(stats.1, 4000);   // total_paid_out

        let reserved_total: i128 = env.storage().persistent().get(&RESERVED_TOTAL).unwrap();
        assert_eq!(reserved_total, 3000);  // Only claim 2 is still reserved
    }

    // ============================================================
    // WITHDRAW LIQUIDITY TESTS
    // ============================================================

    #[test]
    fn test_withdraw_liquidity_success() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);

        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 10000).unwrap();

        let result = RiskPoolContract::withdraw_liquidity(env.clone(), provider.clone(), 4000);
        assert!(result.is_ok());

        let stats = RiskPoolContract::get_pool_stats(env.clone()).unwrap();
        assert_eq!(stats.0, 6000);  // 10000 - 4000

        let provider_info = RiskPoolContract::get_provider_info(env.clone(), provider.clone()).unwrap();
        assert_eq!(provider_info.0, 6000); // provider balance reduced
        assert_eq!(provider_info.1, 10000); // total_deposited unchanged
    }

    #[test]
    fn test_withdraw_liquidity_exceeds_provider_balance() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);

        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 2000).unwrap();

        let result = RiskPoolContract::withdraw_liquidity(env.clone(), provider.clone(), 3000);
        assert_eq!(result, Err(ContractError::InsufficientFunds));
    }

    #[test]
    fn test_withdraw_liquidity_insufficient_pool_available_due_to_reserve() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 5000).unwrap();

        // Reserve most liquidity
        RiskPoolContract::reserve_liquidity(env.clone(), claims_contract.clone(), 1, 4000).unwrap();

        // Try to withdraw more than available (5000 - 4000 = 1000 available)
        let result = RiskPoolContract::withdraw_liquidity(env.clone(), provider.clone(), 2000);
        assert_eq!(result, Err(ContractError::InsufficientFunds));
    }

    #[test]
    fn test_withdraw_liquidity_when_paused() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 5000).unwrap();

        RiskPoolContract::pause(env.clone(), admin.clone()).unwrap();

        let result = RiskPoolContract::withdraw_liquidity(env.clone(), provider.clone(), 1000);
        assert_eq!(result, Err(ContractError::Paused));
    }

    #[test]
    fn test_withdraw_liquidity_zero_amount() {
        let (env, admin, xlm_token, claims_contract) = setup_test_env();
        initialize_pool(&env, &admin, &xlm_token, &claims_contract);

        let provider = Address::generate(&env);
        RiskPoolContract::deposit_liquidity(env.clone(), provider.clone(), 5000).unwrap();

        let result = RiskPoolContract::withdraw_liquidity(env.clone(), provider.clone(), 0);
        assert_eq!(result, Err(ContractError::InvalidAmount));
    }

    #[test]
    fn test_validate_amount_function() {
        assert!(validate_amount(1).is_ok());
        assert!(validate_amount(1000).is_ok());
        assert!(validate_amount(i128::MAX).is_ok());

        assert_eq!(validate_amount(0), Err(ContractError::InvalidAmount));
        assert_eq!(validate_amount(-1), Err(ContractError::InvalidAmount));
        assert_eq!(validate_amount(-1000), Err(ContractError::InvalidAmount));
    }
}
