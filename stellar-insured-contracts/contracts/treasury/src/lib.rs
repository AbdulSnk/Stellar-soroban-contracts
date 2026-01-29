#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Env, Map, Symbol, Vec,
};

// Import authorization from the common library
use insurance_contracts::authorization::{
    get_role, initialize_admin, register_trusted_contract, require_admin,
    require_governance_permission, Role,
};

// Import invariant checks
use insurance_invariants::{InvariantError, ProtocolInvariants};

// ============================================================================
// Constants
// ============================================================================

const PAUSED: Symbol = Symbol::short("PAUSED");
const CONFIG: Symbol = Symbol::short("CONFIG");
const TREASURY_BALANCE: Symbol = Symbol::short("BALANCE");
const WITHDRAWAL_PROPOSALS: Symbol = Symbol::short("WITH_PROP");
const PROPOSAL_COUNTER: Symbol = Symbol::short("PROP_CNT");
const ALLOCATIONS: Symbol = Symbol::short("ALLOC");
const TOTAL_FEES_COLLECTED: Symbol = Symbol::short("TOTAL_FEE");
const TOTAL_WITHDRAWN: Symbol = Symbol::short("TOTAL_WIT");
const TRUSTED_CONTRACTS: Symbol = Symbol::short("TRUST_CON");

// ============================================================================
// Error Handling
// ============================================================================

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
    NotInitialized = 8,
    AlreadyInitialized = 9,
    NotTrustedContract = 10,
    InvalidRole = 11,
    RoleNotFound = 12,
    ProposalNotApproved = 13,
    VotingPeriodEnded = 14,
    AlreadyVoted = 15,
    ProposalNotActive = 16,
    QuorumNotMet = 17,
    ThresholdNotMet = 18,
    // Invariant violation errors (100-199)
    InvalidAmount = 103,
    BalanceViolation = 100,
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

// ============================================================================
// Small helpers for Soroban SDK v25
// ============================================================================

/// In SDK v25 there is no `env.invoker()`. For our purposes, we treat the
/// contract "caller" as the current invoker address.
fn invoker(env: &Env) -> Address {
    env.current_contract_address()
}

impl From<InvariantError> for ContractError {
    fn from(err: InvariantError) -> Self {
        match err {
            InvariantError::InvalidAmount => ContractError::InvalidAmount,
            InvariantError::Overflow => ContractError::Overflow,
            _ => ContractError::InvalidState,
        }
    }
}

// ============================================================================
// Type Definitions
// ============================================================================

/// Represents a fee source category
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeeType {
    PremiumFee = 1,   // Fee from policy premiums
    ClaimPenalty = 2, // Penalty from rejected claims
    SlashingFee = 3,  // Fee from slashing events
    Other = 4,        // Miscellaneous fees
}

/// Represents a withdrawal allocation category
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationPurpose {
    AuditFunding = 1,        // Fund security audits
    DevelopmentGrants = 2,   // Development team grants
    InsuranceReserves = 3,   // Insurance pool reserves
    DaoOperations = 4,       // DAO operational costs
    CommunityIncentives = 5, // Community rewards/incentives
}

/// Treasury configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasuryConfig {
    pub admin: Address,
    pub governance_contract: Address,
    pub fee_percentage: u32, // Fee percentage in basis points (e.g., 500 = 5%)
}

/// Fee deposit record
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeDeposit {
    pub fee_id: u64,
    pub fee_type: u32, // FeeType enum
    pub amount: i128,
    pub depositor: Address,
    pub timestamp: u64,
    pub source_contract: Address,
}

/// Withdrawal proposal for DAO governance
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalProposal {
    pub proposal_id: u64,
    pub recipient: Address,
    pub amount: i128,
    pub purpose: u32, // AllocationPurpose enum
    pub description: Symbol,
    pub proposed_by: Address,
    pub created_at: u64,
    pub voting_ends_at: u64,
    pub yes_votes: i128,
    pub no_votes: i128,
    pub status: u32, // ProposalStatus enum: 0=Active, 1=Approved, 2=Rejected, 3=Executed
    pub executed: bool,
}

/// Allocation tracking per purpose
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationRecord {
    pub purpose: u32, // AllocationPurpose enum
    pub total_allocated: i128,
    pub total_withdrawn: i128,
    pub allocation_count: u64,
}

/// Treasury statistics
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasuryStats {
    pub total_fees_collected: i128,
    pub total_balance: i128,
    pub total_withdrawn: i128,
    pub active_proposals: u64,
    pub completed_proposals: u64,
    pub total_allocations: u64,
}

/// ============================================================================
/// Treasury Contract
/// ============================================================================

#[contract]
pub struct TreasuryContract;

// ============================================================================
// Helper Functions
// ============================================================================

fn validate_address(_env: &Env, _address: &Address) -> Result<(), ContractError> {
    Ok(())
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

/// Get current treasury balance
fn get_balance(env: &Env) -> i128 {
    env.storage().persistent().get(&TREASURY_BALANCE).unwrap_or(0i128)
}

/// Set treasury balance with invariant checking
fn set_balance(env: &Env, amount: i128) -> Result<(), ContractError> {
    if amount < 0 {
        return Err(ContractError::BalanceViolation);
    }
    env.storage().persistent().set(&TREASURY_BALANCE, &amount);
    Ok(())
}

/// Get next proposal ID
fn next_proposal_id(env: &Env) -> u64 {
    let current_id: u64 = env.storage().persistent().get(&PROPOSAL_COUNTER).unwrap_or(0u64);
    let next_id = current_id + 1;
    env.storage().persistent().set(&PROPOSAL_COUNTER, &next_id);
    next_id
}

/// Validate positive amount
fn validate_amount(amount: i128) -> Result<(), ContractError> {
    if amount <= 0 {
        return Err(ContractError::InvalidAmount);
    }
    Ok(())
}

/// Check if contract is trusted
fn is_trusted_contract(env: &Env, contract: &Address) -> bool {
    env.storage().persistent().has(&(TRUSTED_CONTRACTS, contract))
}

// ============================================================================
// Contract Implementation
// ============================================================================

#[contractimpl]
impl TreasuryContract {
    /// Initialize the Treasury contract
    /// Only called once at deployment
    pub fn initialize(
        env: Env,
        admin: Address,
        governance_contract: Address,
        fee_percentage: u32,
    ) -> Result<(), ContractError> {
        // Check if already initialized
        if insurance_contracts::authorization::get_admin(&env).is_some() {
            return Err(ContractError::AlreadyInitialized);
        }

        validate_address(&env, &admin)?;
        validate_address(&env, &governance_contract)?;

        if fee_percentage == 0 || fee_percentage > 10000 {
            return Err(ContractError::InvalidInput);
        }

        admin.require_auth();
        initialize_admin(&env, admin.clone());

        let config = TreasuryConfig { admin: admin.clone(), governance_contract, fee_percentage };

        env.storage().persistent().set(&CONFIG, &config);
        env.storage().persistent().set(&TREASURY_BALANCE, &0i128);
        env.storage().persistent().set(&TOTAL_FEES_COLLECTED, &0i128);
        env.storage().persistent().set(&TOTAL_WITHDRAWN, &0i128);
        env.storage().persistent().set(&PROPOSAL_COUNTER, &0u64);

        env.events().publish((Symbol::new(&env, "treasury_initialized"), ()), admin);

        Ok(())
    }

    /// Register a trusted contract that can deposit fees
    pub fn register_trusted_contract(
        env: Env,
        contract_address: Address,
    ) -> Result<(), ContractError> {
        // Admin-only: use transaction source as the acting address.
        let caller = env.current_contract_address();
        require_admin(&env, &caller)?;
        validate_address(&env, &contract_address)?;

        env.storage().persistent().set(&(TRUSTED_CONTRACTS, &contract_address), &true);

        env.events().publish(
            (Symbol::new(&env, "trusted_contract_registered"), contract_address.clone()),
            contract_address,
        );

        Ok(())
    }

    /// Deposit premium fees from policy contract
    pub fn deposit_premium_fee(env: Env, from: Address, amount: i128) -> Result<(), ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_amount(amount)?;

        // Verify caller is a trusted contract
        let caller = invoker(&env);
        if !is_trusted_contract(&env, &caller) {
            return Err(ContractError::NotTrustedContract);
        }

        let current_balance = get_balance(&env);
        let new_balance = current_balance.checked_add(amount).ok_or(ContractError::Overflow)?;
        set_balance(&env, new_balance)?;

        // Update total fees collected
        let total_fees: i128 =
            env.storage().persistent().get(&TOTAL_FEES_COLLECTED).unwrap_or(0i128);
        let new_total = total_fees.checked_add(amount).ok_or(ContractError::Overflow)?;
        env.storage().persistent().set(&TOTAL_FEES_COLLECTED, &new_total);

        env.events().publish(
            (Symbol::new(&env, "premium_fee_deposited"), ()),
            (from.clone(), amount, new_balance),
        );

        Ok(())
    }

    /// Deposit claim penalty fees
    pub fn deposit_claim_penalty(
        env: Env,
        from: Address,
        amount: i128,
    ) -> Result<(), ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_amount(amount)?;

        // Verify caller is a trusted contract
        let caller = invoker(&env);
        if !is_trusted_contract(&env, &caller) {
            return Err(ContractError::NotTrustedContract);
        }

        let current_balance = get_balance(&env);
        let new_balance = current_balance.checked_add(amount).ok_or(ContractError::Overflow)?;
        set_balance(&env, new_balance)?;

        // Update total fees collected
        let total_fees: i128 =
            env.storage().persistent().get(&TOTAL_FEES_COLLECTED).unwrap_or(0i128);
        let new_total = total_fees.checked_add(amount).ok_or(ContractError::Overflow)?;
        env.storage().persistent().set(&TOTAL_FEES_COLLECTED, &new_total);

        env.events().publish(
            (Symbol::new(&env, "claim_penalty_deposited"), ()),
            (from.clone(), amount, new_balance),
        );

        Ok(())
    }

    /// Deposit slashing fees
    pub fn deposit_slashing_fee(
        env: Env,
        from: Address,
        amount: i128,
    ) -> Result<(), ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_amount(amount)?;

        // Verify caller is a trusted contract
        let caller = invoker(&env);
        if !is_trusted_contract(&env, &caller) {
            return Err(ContractError::NotTrustedContract);
        }

        let current_balance = get_balance(&env);
        let new_balance = current_balance.checked_add(amount).ok_or(ContractError::Overflow)?;
        set_balance(&env, new_balance)?;

        // Update total fees collected
        let total_fees: i128 =
            env.storage().persistent().get(&TOTAL_FEES_COLLECTED).unwrap_or(0i128);
        let new_total = total_fees.checked_add(amount).ok_or(ContractError::Overflow)?;
        env.storage().persistent().set(&TOTAL_FEES_COLLECTED, &new_total);

        env.events().publish(
            (Symbol::new(&env, "slashing_fee_deposited"), ()),
            (from.clone(), amount, new_balance),
        );

        Ok(())
    }

    /// Generic fee deposit function for other sources
    pub fn deposit_fee(
        env: Env,
        from: Address,
        amount: i128,
        fee_type: u32,
    ) -> Result<(), ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_amount(amount)?;

        // Verify caller is a trusted contract
        let caller = invoker(&env);
        if !is_trusted_contract(&env, &caller) {
            return Err(ContractError::NotTrustedContract);
        }

        let current_balance = get_balance(&env);
        let new_balance = current_balance.checked_add(amount).ok_or(ContractError::Overflow)?;
        set_balance(&env, new_balance)?;

        // Update total fees collected
        let total_fees: i128 =
            env.storage().persistent().get(&TOTAL_FEES_COLLECTED).unwrap_or(0i128);
        let new_total = total_fees.checked_add(amount).ok_or(ContractError::Overflow)?;
        env.storage().persistent().set(&TOTAL_FEES_COLLECTED, &new_total);

        env.events().publish(
            (Symbol::new(&env, "fee_deposited"), ()),
            (from.clone(), amount, fee_type, new_balance),
        );

        Ok(())
    }

    /// Create a withdrawal proposal (DAO governance required)
    pub fn propose_withdrawal(
        env: Env,
        proposer: Address,
        recipient: Address,
        amount: i128,
        purpose: u32,
        description: Symbol,
    ) -> Result<u64, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        proposer.require_auth();
        validate_amount(amount)?;
        validate_address(&env, &recipient)?;

        // Check treasury has sufficient balance
        let balance = get_balance(&env);
        if amount > balance {
            return Err(ContractError::InsufficientFunds);
        }

        // Get config
        let config: TreasuryConfig =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;

        // Get current timestamp for voting period (7 days = 604800 seconds)
        let now = env.ledger().timestamp();
        let voting_period = 7u64 * 24 * 60 * 60; // 7 days
        let voting_ends_at = now + voting_period;

        let proposal_id = next_proposal_id(&env);

        let proposal = WithdrawalProposal {
            proposal_id,
            recipient: recipient.clone(),
            amount,
            purpose,
            description: description.clone(),
            proposed_by: proposer.clone(),
            created_at: now,
            voting_ends_at,
            yes_votes: 0i128,
            no_votes: 0i128,
            status: 0, // Active
            executed: false,
        };

        env.storage().persistent().set(&(WITHDRAWAL_PROPOSALS, proposal_id), &proposal);

        env.events().publish(
            (Symbol::new(&env, "withdrawal_proposed"), ()),
            (proposal_id, recipient, amount, purpose, proposer, voting_ends_at),
        );

        Ok(proposal_id)
    }

    /// Execute approved withdrawal (DAO governance required)
    pub fn execute_withdrawal(env: Env, proposal_id: u64) -> Result<(), ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let caller = env.current_contract_address();
        require_admin(&env, &caller)?;

        // Get proposal
        let mut proposal: WithdrawalProposal = env
            .storage()
            .persistent()
            .get(&(WITHDRAWAL_PROPOSALS, proposal_id))
            .ok_or(ContractError::NotFound)?;

        // Check if already executed
        if proposal.executed {
            return Err(ContractError::InvalidState);
        }

        // Check if proposal is approved (status = 1)
        if proposal.status != 1 {
            return Err(ContractError::ProposalNotApproved);
        }

        // Check treasury has sufficient balance
        let balance = get_balance(&env);
        if proposal.amount > balance {
            return Err(ContractError::InsufficientFunds);
        }

        // Execute withdrawal
        let new_balance =
            balance.checked_sub(proposal.amount).ok_or(ContractError::BalanceViolation)?;
        set_balance(&env, new_balance)?;

        // Update total withdrawn
        let total_withdrawn: i128 =
            env.storage().persistent().get(&TOTAL_WITHDRAWN).unwrap_or(0i128);
        let new_total_withdrawn =
            total_withdrawn.checked_add(proposal.amount).ok_or(ContractError::Overflow)?;
        env.storage().persistent().set(&TOTAL_WITHDRAWN, &new_total_withdrawn);

        // Update allocation record
        let mut allocation: AllocationRecord =
            env.storage().persistent().get(&(ALLOCATIONS, proposal.purpose)).unwrap_or(
                AllocationRecord {
                    purpose: proposal.purpose,
                    total_allocated: 0i128,
                    total_withdrawn: 0i128,
                    allocation_count: 0u64,
                },
            );

        allocation.total_withdrawn = allocation
            .total_withdrawn
            .checked_add(proposal.amount)
            .ok_or(ContractError::Overflow)?;
        env.storage().persistent().set(&(ALLOCATIONS, proposal.purpose), &allocation);

        // Mark proposal as executed
        proposal.executed = true;
        env.storage().persistent().set(&(WITHDRAWAL_PROPOSALS, proposal_id), &proposal);

        env.events().publish(
            (Symbol::new(&env, "withdrawal_executed"), ()),
            (proposal_id, proposal.recipient.clone(), proposal.amount, new_balance),
        );

        Ok(())
    }

    /// Reject a withdrawal proposal
    pub fn reject_proposal(env: Env, proposal_id: u64) -> Result<(), ContractError> {
        let caller = env.current_contract_address();
        require_admin(&env, &caller)?;

        let mut proposal: WithdrawalProposal = env
            .storage()
            .persistent()
            .get(&(WITHDRAWAL_PROPOSALS, proposal_id))
            .ok_or(ContractError::NotFound)?;

        if proposal.executed {
            return Err(ContractError::InvalidState);
        }

        proposal.status = 2; // Rejected
        env.storage().persistent().set(&(WITHDRAWAL_PROPOSALS, proposal_id), &proposal);

        env.events().publish(
            (Symbol::new(&env, "proposal_rejected"), ()),
            (proposal_id, proposal.recipient.clone(), proposal.amount),
        );

        Ok(())
    }

    /// Approve a withdrawal proposal (DAO governance required)
    pub fn approve_proposal(env: Env, proposal_id: u64) -> Result<(), ContractError> {
        let caller = env.current_contract_address();
        require_admin(&env, &caller)?;

        let mut proposal: WithdrawalProposal = env
            .storage()
            .persistent()
            .get(&(WITHDRAWAL_PROPOSALS, proposal_id))
            .ok_or(ContractError::NotFound)?;

        if proposal.executed {
            return Err(ContractError::InvalidState);
        }

        // Check voting period has ended
        let now = env.ledger().timestamp();
        if now < proposal.voting_ends_at {
            return Err(ContractError::VotingPeriodEnded);
        }

        proposal.status = 1; // Approved
        env.storage().persistent().set(&(WITHDRAWAL_PROPOSALS, proposal_id), &proposal);

        env.events().publish(
            (Symbol::new(&env, "proposal_approved"), ()),
            (proposal_id, proposal.recipient.clone(), proposal.amount),
        );

        Ok(())
    }

    /// Get current treasury balance
    pub fn get_balance(env: Env) -> i128 {
        get_balance(&env)
    }

    /// Get treasury statistics
    pub fn get_stats(env: Env) -> Result<TreasuryStats, ContractError> {
        let total_fees: i128 =
            env.storage().persistent().get(&TOTAL_FEES_COLLECTED).unwrap_or(0i128);

        let total_balance = get_balance(&env);

        let total_withdrawn: i128 =
            env.storage().persistent().get(&TOTAL_WITHDRAWN).unwrap_or(0i128);

        Ok(TreasuryStats {
            total_fees_collected: total_fees,
            total_balance,
            total_withdrawn,
            active_proposals: 0u64,
            completed_proposals: 0u64,
            total_allocations: 0u64,
        })
    }

    /// Get withdrawal proposal details
    pub fn get_proposal(env: Env, proposal_id: u64) -> Result<WithdrawalProposal, ContractError> {
        env.storage()
            .persistent()
            .get(&(WITHDRAWAL_PROPOSALS, proposal_id))
            .ok_or(ContractError::NotFound)
    }

    /// Get allocation record for a purpose
    pub fn get_allocation(env: Env, purpose: u32) -> Result<AllocationRecord, ContractError> {
        env.storage()
            .persistent()
            .get(&(ALLOCATIONS, purpose))
            .ok_or(ContractError::NotFound)
    }

    /// Pause/unpause contract (admin only)
    pub fn set_pause(env: Env, paused: bool) -> Result<(), ContractError> {
        let caller = env.current_contract_address();
        require_admin(&env, &caller)?;
        set_paused(&env, paused);

        env.events().publish((Symbol::new(&env, "pause_state_changed"), ()), paused);

        Ok(())
    }

    /// Update fee percentage (admin only)
    pub fn update_fee_percentage(env: Env, new_percentage: u32) -> Result<(), ContractError> {
        let caller = env.current_contract_address();
        require_admin(&env, &caller)?;

        if new_percentage == 0 || new_percentage > 10000 {
            return Err(ContractError::InvalidInput);
        }

        let mut config: TreasuryConfig =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;

        config.fee_percentage = new_percentage;
        env.storage().persistent().set(&CONFIG, &config);

        env.events()
            .publish((Symbol::new(&env, "fee_percentage_updated"), ()), new_percentage);

        Ok(())
    }
}
