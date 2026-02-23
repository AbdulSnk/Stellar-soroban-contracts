#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, Symbol, Vec};

// Import authorization from the common library
use insurance_contracts::authorization::{
    get_role, has_role, initialize_admin, register_trusted_contract, require_admin,
    require_policy_management, Role,
};
use insurance_contracts::rate_limit::{self, RateLimitConfig};
use insurance_contracts::gas_optimization::{GasOptimizer, PerformanceMonitor};
use insurance_contracts::emergency_pause::EmergencyPause;

// Import invariant checks and error types
use insurance_invariants::{InvariantError, ProtocolInvariants};

// Import optimized policy implementation
use crate::optimized_policy::OptimizedPolicyContract;

// Policy validation constants
const MIN_COVERAGE_AMOUNT: i128 = 1_000_000; // 1 unit (assuming 6 decimals)
const MAX_COVERAGE_AMOUNT: i128 = 1_000_000_000_000_000; // 1M units
const MIN_PREMIUM_AMOUNT: i128 = 100_000; // 0.1 units
const MAX_PREMIUM_AMOUNT: i128 = 100_000_000_000_000; // 100k units
const MIN_POLICY_DURATION_DAYS: u32 = 1;
const MAX_POLICY_DURATION_DAYS: u32 = 365;

/// Maximum number of policies to return in a single paginated request.
const MAX_PAGINATION_LIMIT: u32 = 50;

/// Storage key for the list of active policy IDs
const ACTIVE_POLICY_LIST: Symbol = Symbol::short("ACT_POL");
const POLICY_ISSUE_SCOPE: &str = "policy_issue";
const DEFAULT_POLICY_ISSUE_RATE_LIMIT_MAX_CALLS: u32 = 5;
const DEFAULT_POLICY_ISSUE_RATE_LIMIT_WINDOW_SECS: u64 = 60;

#[contract]
pub struct PolicyContract;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Paused,
    Config,
    Policy(u64),
    PolicyCounter,
    PolicyStatusHistory(u64), // history_id
    PolicyStatusHistoryCounter,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub risk_pool: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyStatusHistory {
    pub policy_id: u64,
    pub previous_state: PolicyState,
    pub new_state: PolicyState,
    pub actor: Address,
    pub timestamp: u64,
}

/// Structured view of a policy for frontend/indexer consumption.
/// Contains essential policy data in a gas-efficient format.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PolicyView {
    /// Unique policy identifier
    pub id: u64,
    /// Policy holder address
    pub holder: Address,
    /// Coverage amount in stroops
    pub coverage_amount: i128,
    /// Premium amount in stroops
    pub premium_amount: i128,
    /// Policy start timestamp
    pub start_time: u64,
    /// Policy end timestamp
    pub end_time: u64,
    /// Current state (ACTIVE, EXPIRED, CANCELLED)
    pub state: PolicyState,
    /// Timestamp when policy was created
    pub created_at: u64,
    /// Whether the policy is set to auto-renew
    pub auto_renew: bool,
    /// Asset used for coverage amount
    pub coverage_asset: shared::types::Asset,
    /// Asset used for premium payments
    pub premium_asset: shared::types::Asset,
    /// Whether multi-asset claims are allowed
    pub allow_multi_asset_claims: bool,
}

/// Result of a paginated policies query.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedPoliciesResult {
    /// List of policies in the current page
    pub policies: Vec<PolicyView>,
    /// Total number of active policies (for pagination calculations)
    pub total_count: u32,
}

// Step 1: Define the Policy State Enum
/// Represents the lifecycle states of a policy.
/// This is a closed enum with only valid states - no string states allowed.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyState {
    ACTIVE,
    EXPIRED,
    CANCELLED,
}

// Step 2: Define Allowed State Transitions
impl PolicyState {
    /// Validates whether a transition from the current state to the next state is allowed.
    ///
    /// Valid transitions:
    /// - ACTIVE → EXPIRED
    /// - ACTIVE → CANCELLED
    /// - EXPIRED → (no transitions)
    /// - CANCELLED → (no transitions)
    pub fn can_transition_to(self, next: PolicyState) -> bool {
        match (self, next) {
            // ACTIVE can transition to EXPIRED or CANCELLED
            (PolicyState::ACTIVE, PolicyState::EXPIRED) => true,
            (PolicyState::ACTIVE, PolicyState::CANCELLED) => true,
            // EXPIRED and CANCELLED are terminal states - no transitions allowed
            (PolicyState::EXPIRED, _) => false,
            (PolicyState::CANCELLED, _) => false,
            // Self-transitions are not allowed
            _ => false,
        }
    }
}

// Step 3: Define the Policy Struct
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub holder: Address,
    pub coverage_amount: i128,
    pub premium_amount: i128,
    pub start_time: u64,
    pub end_time: u64,
    state: PolicyState, // Private - controlled through methods
    pub created_at: u64,
    pub auto_renew: bool,
    /// Asset used for coverage amount
    pub coverage_asset: shared::types::Asset,
    /// Asset used for premium payments
    pub premium_asset: shared::types::Asset,
    /// Whether multi-asset claims are allowed for this policy
    pub allow_multi_asset_claims: bool,
}

// Step 4: Implement Policy Methods
impl Policy {
    /// Creates a new policy in ACTIVE state
    pub fn new(
        holder: Address,
        coverage_amount: i128,
        premium_amount: i128,
        start_time: u64,
        end_time: u64,
        created_at: u64,
        auto_renew: bool,
        coverage_asset: shared::types::Asset,
        premium_asset: shared::types::Asset,
        allow_multi_asset_claims: bool,
    ) -> Self {
        Policy {
            holder,
            coverage_amount,
            premium_amount,
            start_time,
            end_time,
            state: PolicyState::ACTIVE,
            created_at,
            auto_renew,
            coverage_asset,
            premium_asset,
            allow_multi_asset_claims,
        }
    }

    /// Returns the current state (read-only)
    pub fn state(&self) -> PolicyState {
        self.state
    }

    /// Attempts to transition to a new state
    pub fn transition_to(&mut self, next: PolicyState) -> Result<(), ContractError> {
        if !self.state.can_transition_to(next) {
            return Err(ContractError::InvalidStateTransition);
        }
        self.state = next;
        Ok(())
    }

    /// Cancels the policy (only if Active)
    pub fn cancel(&mut self) -> Result<(), ContractError> {
        self.transition_to(PolicyState::CANCELLED)
    }

    /// Expires the policy (only if Active)
    pub fn expire(&mut self) -> Result<(), ContractError> {
        self.transition_to(PolicyState::EXPIRED)
    }

    /// Checks if the policy is active
    pub fn is_active(&self) -> bool {
        matches!(self.state, PolicyState::ACTIVE)
    }

    /// Checks if the policy is expired
    pub fn is_expired(&self) -> bool {
        matches!(self.state, PolicyState::EXPIRED)
    }

    /// Checks if the policy is cancelled
    pub fn is_cancelled(&self) -> bool {
        matches!(self.state, PolicyState::CANCELLED)
    }
}

// Step 5: Policy State Machine
pub struct PolicyStateMachine;

impl PolicyStateMachine {
    /// Transitions a policy to a new state, validating the transition and recording history
    pub fn transition(
        env: &Env,
        policy_id: u64,
        target_state: PolicyState,
        actor: Address,
    ) -> Result<(), ContractError> {
        // Get current policy
        let mut policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;

        let previous_state = policy.state();

        // Validate transition
        if !previous_state.can_transition_to(target_state) {
            return Err(ContractError::InvalidStateTransition);
        }

        // Update policy state
        policy.transition_to(target_state)?;

        // Save updated policy
        env.storage().persistent().set(&DataKey::Policy(policy_id), &policy);

        // Remove from active policy list if transitioning to a terminal state
        if matches!(target_state, PolicyState::CANCELLED | PolicyState::EXPIRED) {
            let mut active_list: Vec<u64> = env
                .storage()
                .persistent()
                .get(&ACTIVE_POLICY_LIST)
                .unwrap_or_else(|| Vec::new(env));

            // Find and remove the policy ID from the list
            let mut new_list: Vec<u64> = Vec::new(env);
            for i in 0..active_list.len() {
                let id = active_list.get(i).unwrap();
                if id != policy_id {
                    new_list.push_back(id);
                }
            }
            env.storage()
                .persistent()
                .set(&ACTIVE_POLICY_LIST, &new_list);
        }

        // Record history
        let history_id = Self::next_history_id(env);
        let history = PolicyStatusHistory {
            policy_id,
            previous_state,
            new_state: target_state,
            actor: actor.clone(),
            timestamp: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::PolicyStatusHistory(history_id), &history);

        // Emit event
        let event_name = match target_state {
            PolicyState::ACTIVE => Symbol::new(env, "PolicyActivated"),
            PolicyState::EXPIRED => Symbol::new(env, "PolicyExpired"),
            PolicyState::CANCELLED => Symbol::new(env, "PolicyCancelled"),
        };
        env.events().publish(
            (event_name, policy_id),
            (actor, previous_state, target_state, env.ledger().timestamp()),
        );

        Ok(())
    }

    /// Gets the next history ID
    fn next_history_id(env: &Env) -> u64 {
        let current_id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::PolicyStatusHistoryCounter)
            .unwrap_or(0u64);
        let next_id = current_id + 1;
        env.storage().persistent().set(&DataKey::PolicyStatusHistoryCounter, &next_id);
        next_id
    }

    /// Gets policy status history for a policy
    pub fn get_policy_history(env: &Env, policy_id: u64) -> Vec<PolicyStatusHistory> {
        let mut history = Vec::new(env);
        let mut history: Vec<PolicyStatusHistory> = Vec::new(env);
        let counter: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::PolicyStatusHistoryCounter)
            .unwrap_or(0u64);

        for i in 1..=counter {
            if let Some(h) = env
                .storage()
                .persistent()
                .get::<DataKey, PolicyStatusHistory>(&DataKey::PolicyStatusHistory(i))
                .get::<_, PolicyStatusHistory>(&DataKey::PolicyStatusHistory(i))
            {
                if h.policy_id == policy_id {
                    history.push_back(h);
                }
            }
        }
        history
    }
}

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
    Overflow = 8,
    NotInitialized = 9,
    AlreadyInitialized = 10,
    InvalidRole = 11,
    RoleNotFound = 12,
    NotTrustedContract = 13,
    PolicyExpired = 14,

    /// Invalid state transition attempted
    // State transition errors
    InvalidStateTransition = 15,
    // Invariant violation errors (100-199)
    InvalidPolicyState = 101,
    InvalidAmount = 103,
    InvalidPremium = 106,
    Overflow2 = 107,
    RateLimitExceeded = 108,
    InvalidRateLimitConfig = 109,
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
            InvariantError::InvalidPolicyState => ContractError::InvalidPolicyState,
            InvariantError::InvalidAmount => ContractError::InvalidAmount,
            InvariantError::InvalidPremium => ContractError::InvalidPremium,
            InvariantError::Overflow => ContractError::Overflow2,
            _ => ContractError::InvalidState,
        }
    }
}

impl From<insurance_contracts::rate_limit::RateLimitError> for ContractError {
    fn from(err: insurance_contracts::rate_limit::RateLimitError) -> Self {
        match err {
            insurance_contracts::rate_limit::RateLimitError::Exceeded => {
                ContractError::RateLimitExceeded
            }
            insurance_contracts::rate_limit::RateLimitError::InvalidConfig => {
                ContractError::InvalidRateLimitConfig
            }
        }
    }
}

fn validate_address(_env: &Env, _address: &Address) -> Result<(), ContractError> {
    Ok(())
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&DataKey::Paused).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&DataKey::Paused, &paused);
}

fn next_policy_id(env: &Env) -> u64 {
    let current_id: u64 = env.storage().persistent().get(&DataKey::PolicyCounter).unwrap_or(0u64);
    let next_id = current_id + 1;
    env.storage().persistent().set(&DataKey::PolicyCounter, &next_id);
    next_id
}

/// I4: Validate coverage amount within bounds
fn validate_coverage_amount(amount: i128) -> Result<(), ContractError> {
    if amount < MIN_COVERAGE_AMOUNT || amount > MAX_COVERAGE_AMOUNT {
        return Err(ContractError::InvalidAmount);
    }
    Ok(())
}

/// I7: Validate premium amount within bounds
fn validate_premium_amount(premium: i128) -> Result<(), ContractError> {
    if premium < MIN_PREMIUM_AMOUNT || premium > MAX_PREMIUM_AMOUNT {
        return Err(ContractError::InvalidPremium);
    }
    Ok(())
}

/// Validate policy duration
fn validate_duration(duration_days: u32) -> Result<(), ContractError> {
    if duration_days < MIN_POLICY_DURATION_DAYS || duration_days > MAX_POLICY_DURATION_DAYS {
        return Err(ContractError::InvalidInput);
    }
    Ok(())
}

/// Check if a policy is expired based on current ledger time
fn is_policy_expired(env: &Env, policy: &Policy) -> bool {
    let current_time = env.ledger().timestamp();
    current_time > policy.end_time
}

/// Automatically expire policy if its end time has passed
/// Returns true if policy was expired, false if still active
fn auto_expire_policy_if_needed(env: &Env, policy_id: u64, policy: &mut Policy) -> Result<bool, ContractError> {
    // Only check auto-expiry for ACTIVE policies
    if !policy.is_active() {
        return Ok(false);
    }
    
    if is_policy_expired(env, policy) {
        // Policy has expired - transition to EXPIRED state
        policy.transition_to(PolicyState::EXPIRED)?;
        
        // Save updated policy
        env.storage().persistent().set(&DataKey::Policy(policy_id), policy);
        
        // Remove from active policy list
        let mut active_list: Vec<u64> = env
            .storage()
            .persistent()
            .get(&ACTIVE_POLICY_LIST)
            .unwrap_or_else(|| Vec::new(env));

        // Find and remove the policy ID from the list
        let mut new_list: Vec<u64> = Vec::new(env);
        for i in 0..active_list.len() {
            let id = active_list.get(i).unwrap();
            if id != policy_id {
                new_list.push_back(id);
            }
        }
        env.storage()
            .persistent()
            .set(&ACTIVE_POLICY_LIST, &new_list);

        // Record history
        let history_id = PolicyStateMachine::next_history_id(env);
        let history = PolicyStatusHistory {
            policy_id,
            previous_state: PolicyState::ACTIVE,
            new_state: PolicyState::EXPIRED,
            actor: Address::generate(env), // System address for auto-expiry
            timestamp: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::PolicyStatusHistory(history_id), &history);

        // Emit auto-expiry event
        env.events().publish(
            (Symbol::new(env, "PolicyAutoExpired"), policy_id),
            (
                policy.holder.clone(),
                policy.end_time,
                env.ledger().timestamp(),
            ),
        );
        
        Ok(true)
    } else {
        Ok(false)
    }
}

#[contractimpl]
impl PolicyContract {
    pub fn initialize(env: Env, admin: Address, risk_pool: Address) -> Result<(), ContractError> {
        // Check if already initialized
        if insurance_contracts::authorization::get_admin(&env).is_some() {
            return Err(ContractError::AlreadyInitialized);
        }

        validate_address(&env, &admin)?;
        validate_address(&env, &risk_pool)?;

        // Initialize authorization system with admin
        admin.require_auth();
        initialize_admin(&env, admin.clone());

        // Register risk pool contract as trusted for cross-contract calls
        register_trusted_contract(&env, &admin, &risk_pool)?;

        // Initialize emergency pause system
        EmergencyPause::initialize(&env, &admin)?;

        let config = Config { risk_pool };
        env.storage().persistent().set(&DataKey::Config, &config);

        env.storage().persistent().set(&DataKey::PolicyCounter, &0u64);

        set_paused(&env, false);

        env.events().publish((Symbol::new(&env, "initialized"), ()), admin);

        Ok(())
    }

    pub fn set_issue_policy_rate_limit(
        env: Env,
        admin: Address,
        max_calls: u32,
        window_secs: u64,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        rate_limit::set_config(
            &env,
            Symbol::new(&env, POLICY_ISSUE_SCOPE),
            RateLimitConfig {
                max_calls,
                window_secs,
            },
        );

        Ok(())
    }

    pub fn issue_policy(
        env: Env,
        manager: Address,
        holder: Address,
        coverage_amount: i128,
        premium_amount: i128,
        duration_days: u32,
        auto_renew: bool,
        coverage_asset: Option<shared::types::Asset>,
        premium_asset: Option<shared::types::Asset>,
        allow_multi_asset_claims: Option<bool>,
    ) -> Result<u64, ContractError> {
        // Use performance monitoring for optimization tracking
        PerformanceMonitor::track_operation(&env, "issue_policy", || {
            Self::issue_policy_impl(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage_amount,
                premium_amount,
                duration_days,
                auto_renew,
            )
        })
    }

    /// Optimized implementation of policy issuance
    fn issue_policy_impl(
        env: Env,
        manager: Address,
        holder: Address,
        coverage_amount: i128,
        premium_amount: i128,
        duration_days: u32,
        auto_renew: bool,
    ) -> Result<u64, ContractError> {
        // Verify identity and require policy management permission
        manager.require_auth();
        require_policy_management(&env, &manager)?;

        // Check emergency pause status
        EmergencyPause::validate_not_paused(&env, Some(&Symbol::new(&env, "issue_policy")))?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        rate_limit::enforce(
            &env,
            Symbol::new(&env, POLICY_ISSUE_SCOPE),
            &manager,
            RateLimitConfig {
                max_calls: DEFAULT_POLICY_ISSUE_RATE_LIMIT_MAX_CALLS,
                window_secs: DEFAULT_POLICY_ISSUE_RATE_LIMIT_WINDOW_SECS,
            },
        )?;

        validate_address(&env, &holder)?;

        // Validate coverage amount within bounds
        validate_coverage_amount(coverage_amount)?;

        // Validate premium amount within bounds
        validate_premium_amount(premium_amount)?;

        // Validate duration within bounds
        validate_duration(duration_days)?;

        // Use optimized policy issuance for gas efficiency
        let policy_id = OptimizedPolicyContract::issue_policy_optimized(
            &env,
            manager.clone(),
        // Use default assets if not specified (Native XLM)
        let cov_asset = coverage_asset.unwrap_or(shared::types::Asset::Native);
        let prem_asset = premium_asset.unwrap_or(shared::types::Asset::Native);
        let multi_asset = allow_multi_asset_claims.unwrap_or(false);

        let policy_id = next_policy_id(&env);
        let current_time = env.ledger().timestamp();
        let end_time = current_time
            .checked_add(
                u64::from(duration_days).checked_mul(86400).ok_or(ContractError::Overflow2)?,
            )
            .ok_or(ContractError::Overflow2)?;

        // Use the new Policy constructor which initializes state to Active
        let policy = Policy::new(
            holder.clone(),
            coverage_amount,
            premium_amount,
            duration_days,
            auto_renew,
        )?;
            cov_asset,
            prem_asset,
            multi_asset,
        );

        env.storage().persistent().set(&DataKey::Policy(policy_id), &policy);

        // Add policy ID to the active policy list for efficient querying
        let mut active_list: Vec<u64> = env
            .storage()
            .persistent()
            .get(&ACTIVE_POLICY_LIST)
            .unwrap_or_else(|| Vec::new(&env));
        active_list.push_back(policy_id);
        env.storage()
            .persistent()
            .set(&ACTIVE_POLICY_LIST, &active_list);

        env.events().publish(
            (Symbol::new(&env, "PolicyIssued"), policy_id),
            (holder, coverage_amount, premium_amount, duration_days, manager, current_time),
        );
        env.events().publish(
            (Symbol::new(&env, "PolicyIssuedFull"), policy_id),
            (holder.clone(), coverage_amount, premium_amount, duration_days, manager.clone(), current_time, end_time, auto_renew),
        );


        Ok(policy_id)
    }

    pub fn renew_policy(
        env: Env,
        actor: Address,
        policy_id: u64,
        duration_days: u32,
    ) -> Result<(), ContractError> {
        actor.require_auth();

        // Check emergency pause status for renewal
        EmergencyPause::validate_not_paused(&env, Some(&Symbol::new(&env, "renew_policy")))?;

        let mut policy = Self::get_policy(env.clone(), policy_id)?;

        // Auto-expiry check already performed in get_policy
        // Additional explicit check for expired policies
        if policy.is_expired() {
            return Err(ContractError::PolicyExpired);
        }

        // Authorization logic
        let is_holder = actor == policy.holder;
        let is_privileged = has_role(&env, &actor, Role::Admin)
            || has_role(&env, &actor, Role::PolicyManager);

        if !is_holder && !is_privileged {
            return Err(ContractError::Unauthorized);
        }

        // If privileged (automation), require auto_renew to be true
        if is_privileged && !is_holder && !policy.auto_renew {
            return Err(ContractError::Unauthorized);
        }

        // Validate state (must be ACTIVE)
        if !policy.is_active() {
            return Err(ContractError::InvalidState);
        }

        // Validate duration
        validate_duration(duration_days)?;

        // Calculate new end time
        // Extend from the current end_time to avoid gaps
        let new_end_time = policy
            .end_time
            .checked_add(
                u64::from(duration_days)
                    .checked_mul(86400)
                    .ok_or(ContractError::Overflow2)?,
            )
            .ok_or(ContractError::Overflow2)?;

        policy.end_time = new_end_time;

        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id), &policy);

        env.events().publish(
            (Symbol::new(&env, "PolicyRenewed"), policy_id),
            (actor, new_end_time, duration_days),

        );
        env.events().publish((Symbol::new(&env, "PolicyRenewedFull"), policy_id), (actor, new_end_time, duration_days, env.ledger().timestamp()));

        Ok(())
    }

    pub fn set_auto_renew(
        env: Env,
        holder: Address,
        policy_id: u64,
        auto_renew: bool,
    ) -> Result<(), ContractError> {
        holder.require_auth();

        let mut policy = Self::get_policy(env.clone(), policy_id)?;

        if policy.holder != holder {
            return Err(ContractError::Unauthorized);
        }

        policy.auto_renew = auto_renew;
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id), &policy);

        env.events().publish(
            (Symbol::new(&env, "AutoRenewUpdated"), policy_id),
            (holder, auto_renew),

        );

        env.events().publish((Symbol::new(&env, "AutoRenewUpdatedFull"), policy_id), (holder.clone(), auto_renew, env.ledger().timestamp()));


        Ok(())
    }

    pub fn get_policy(env: Env, policy_id: u64) -> Result<Policy, ContractError> {
        let mut policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;
            
        // Auto-expiry check - will transition to EXPIRED if needed
        auto_expire_policy_if_needed(&env, policy_id, &mut policy)?;
        
        Ok(policy)
    }

    pub fn get_policy_holder(env: Env, policy_id: u64) -> Result<Address, ContractError> {
        let mut policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;
            
        // Auto-expiry check - will transition to EXPIRED if needed
        auto_expire_policy_if_needed(&env, policy_id, &mut policy)?;
        
        Ok(policy.holder)
    }

    pub fn get_coverage_amount(env: Env, policy_id: u64) -> Result<i128, ContractError> {
        let mut policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;
            
        // Auto-expiry check - will transition to EXPIRED if needed
        auto_expire_policy_if_needed(&env, policy_id, &mut policy)?;
        
        Ok(policy.coverage_amount)
    }

    pub fn get_premium_amount(env: Env, policy_id: u64) -> Result<i128, ContractError> {
        let mut policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;
            
        // Auto-expiry check - will transition to EXPIRED if needed
        auto_expire_policy_if_needed(&env, policy_id, &mut policy)?;
        
        Ok(policy.premium_amount)
    }

    pub fn get_policy_state(env: Env, policy_id: u64) -> Result<PolicyState, ContractError> {
        let mut policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;
            
        // Auto-expiry check - will transition to EXPIRED if needed
        auto_expire_policy_if_needed(&env, policy_id, &mut policy)?;
        
        Ok(policy.state())
    }

    pub fn get_policy_dates(env: Env, policy_id: u64) -> Result<(u64, u64), ContractError> {
        let mut policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;
            
        // Auto-expiry check - will transition to EXPIRED if needed
        auto_expire_policy_if_needed(&env, policy_id, &mut policy)?;
        
        Ok((policy.start_time, policy.end_time))
    }

    /// Cancels a policy. Only allowed when the policy is ACTIVE.
    pub fn cancel_policy(env: Env, actor: Address, policy_id: u64) -> Result<(), ContractError> {
        require_admin(&env, &actor)?;

        // Check emergency pause status for policy cancellation
        EmergencyPause::validate_not_paused(&env, Some(&Symbol::new(&env, "cancel_policy")))?;

        // Use the state machine to transition to CANCELLED
        PolicyStateMachine::transition(&env, policy_id, PolicyState::CANCELLED, actor)?;

    Ok(())


    }

    /// Expires a policy. Only allowed when the policy is ACTIVE.
    pub fn expire_policy(env: Env, actor: Address, policy_id: u64) -> Result<(), ContractError> {
        require_admin(&env, &actor)?;

        // Check emergency pause status for policy expiration
        EmergencyPause::validate_not_paused(&env, Some(&Symbol::new(&env, "expire_policy")))?;

        // Use the state machine to transition to EXPIRED
        PolicyStateMachine::transition(&env, policy_id, PolicyState::EXPIRED, actor)?;

        Ok(())
    }

    pub fn get_admin(env: Env) -> Result<Address, ContractError> {
        insurance_contracts::authorization::get_admin(&env).ok_or(ContractError::NotInitialized)
    }

    pub fn get_config(env: Env) -> Result<Config, ContractError> {
        env.storage()
            .persistent()
            .get(&DataKey::Config)
            .ok_or(ContractError::NotInitialized)
    }

    pub fn get_risk_pool(env: Env) -> Result<Address, ContractError> {
        let config: Config = env
            .storage()
            .persistent()
            .get(&DataKey::Config)
            .ok_or(ContractError::NotInitialized)?;
        Ok(config.risk_pool)
    }

    pub fn get_policy_count(env: Env) -> u64 {
        env.storage().persistent().get(&DataKey::PolicyCounter).unwrap_or(0u64)
    }

    /// Returns a paginated list of active policies with structured view data.
    /// This is a read-only function optimized for frontend/indexer consumption.
    ///
    /// # Arguments
    /// * `start_index` - Zero-based index to start from in the active policy list
    /// * `limit` - Maximum number of policies to return (capped at 50)
    ///
    /// # Returns
    /// * `PaginatedPoliciesResult` containing the policies and total count
    ///
    /// # Example
    /// To get the first page: `get_active_policies(0, 50)`
    /// To get the second page: `get_active_policies(50, 50)`
    pub fn get_active_policies(
        env: Env,
        start_index: u32,
        limit: u32,
    ) -> PaginatedPoliciesResult {
        // Use performance monitoring
        PerformanceMonitor::track_operation(&env, "get_active_policies", || {
            Self::get_active_policies_impl(env.clone(), start_index, limit)
        }).unwrap_or_else(|_| PaginatedPoliciesResult {
            policies: Vec::new(&env),
            total_count: 0,
        })
    }

    /// Optimized implementation of active policies query
    fn get_active_policies_impl(
        env: Env,
        start_index: u32,
        limit: u32,
    ) -> Result<PaginatedPoliciesResult, ContractError> {
        // Use optimized batched query
        let (policies_vec, total_count) = OptimizedPolicyContract::get_policies_batched(
            &env,
            start_index,
            limit,
            None, // No state filter
        );

        Ok(PaginatedPoliciesResult {
            policies: policies_vec,
            total_count,
        })
    }

    /// Get policies by specific state with optimization
    pub fn get_policies_by_state(
        env: Env,
        state: PolicyState,
        start_index: u32,
        limit: u32,
    ) -> PaginatedPoliciesResult {
        PerformanceMonitor::track_operation(&env, "get_policies_by_state", || {
            Self::get_policies_by_state_impl(env.clone(), state, start_index, limit)
        }).unwrap_or_else(|_| PaginatedPoliciesResult {
            policies: Vec::new(&env),
            total_count: 0,
        })
    }

    fn get_policies_by_state_impl(
        env: Env,
        state: PolicyState,
        start_index: u32,
        limit: u32,
    ) -> Result<PaginatedPoliciesResult, ContractError> {
        // Use optimized batched query with state filter
        let (policies_vec, total_count) = OptimizedPolicyContract::get_policies_batched(
            &env,
            start_index,
            limit,
            Some(state),
        );

        Ok(PaginatedPoliciesResult {
            policies: policies_vec,
            total_count,
        })
    }

    /// Returns the count of currently active policies.
    pub fn get_active_policy_count(env: Env) -> u32 {
        let active_list: Vec<u64> = env
            .storage()
            .persistent()
            .get(&ACTIVE_POLICY_LIST)
            .unwrap_or_else(|| Vec::new(&env));
        active_list.len()
    }

    pub fn is_paused(env: Env) -> bool {
        is_paused(&env)
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
        env.events().publish(
            (Symbol::new(&env, "ContractUnpaused"), ()),
            (admin, env.ledger().timestamp()),
        );


        Ok(())
    }

    /// Emergency pause the entire contract
    pub fn emergency_pause(
        env: Env,
        admin: Address,
        reason: Symbol,
        max_duration_seconds: u64,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        EmergencyPause::activate_emergency_pause(&env, &admin, reason, max_duration_seconds)
    }

    /// Deactivate emergency pause
    pub fn emergency_unpause(
        env: Env,
        admin: Address,
        reason: Symbol,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        EmergencyPause::deactivate_emergency_pause(&env, &admin, reason)
    }

    /// Pause specific functions
    pub fn pause_functions(
        env: Env,
        admin: Address,
        functions: Vec<Symbol>,
        reason: Symbol,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        EmergencyPause::pause_functions(&env, &admin, &functions, reason)
    }

    /// Unpause specific functions
    pub fn unpause_functions(
        env: Env,
        admin: Address,
        functions: Vec<Symbol>,
        reason: Symbol,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        EmergencyPause::unpause_functions(&env, &admin, &functions, reason)
    }

    /// Get emergency pause configuration
    pub fn get_emergency_pause_config(env: Env) -> Result<insurance_contracts::emergency_pause::EmergencyPauseConfig, ContractError> {
        EmergencyPause::get_pause_config(&env)
    }

    /// Get emergency pause history
    pub fn get_emergency_pause_history(env: Env, limit: u32) -> Vec<insurance_contracts::emergency_pause::EmergencyPauseEvent> {
        EmergencyPause::get_pause_history(&env, limit)
    }

    /// Grant policy manager role to an address (admin only)
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
            Role::PolicyManager,
        )?;

        env.events()
            .publish((Symbol::new(&env, "role_granted"), manager.clone()), admin);
        env.events().publish(
            (Symbol::new(&env, "PolicyManagerGranted"), ()),
            (admin, manager.clone(), env.ledger().timestamp()),

            );
        env.events().publish((Symbol::new(&env, "PolicyManagerGrantedFull"), ()), (admin.clone(), manager.clone(), env.ledger().timestamp()));
        );



        Ok(())
    }

    /// Revoke policy manager role from an address (admin only)
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
        env.events().publish(
            (Symbol::new(&env, "PolicyManagerRevoked"), ()),
            (admin, manager.clone(), env.ledger().timestamp()),
        );


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
        env.events().publish(
            (Symbol::new(&env, "AuditorGranted"), ()),
            (admin, auditor.clone(), env.ledger().timestamp()),

            );
        env.events().publish((Symbol::new(&env, "AuditorGrantedFull"), ()), (admin.clone(), auditor.clone(), env.ledger().timestamp()));
        );



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
        env.events().publish(
            (Symbol::new(&env, "AuditorRevoked"), ()),
            (admin, auditor.clone(), env.ledger().timestamp()),
        );


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
        env.events().publish((Symbol::new(&env, "RoleDelegated"), ()), (delegator, delegatee.clone(), role.clone(), env.ledger().timestamp()));

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

    // ========================================================================
    // Disaster Recovery & Backup
    // ========================================================================

    /// Updates the risk pool address in case of emergency or migration.
    /// This ensures the policy contract points to a valid risk pool.
    pub fn update_risk_pool(
        env: Env,
        admin: Address,
        new_risk_pool: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        validate_address(&env, &new_risk_pool)?;

        let mut config = Self::get_config(env.clone())?;
        let old_risk_pool = config.risk_pool;
        
        if old_risk_pool == new_risk_pool {
            return Err(ContractError::InvalidInput);
        }

        config.risk_pool = new_risk_pool.clone();
        env.storage().persistent().set(&DataKey::Config, &config);

        // Ensure the new risk pool is trusted
        register_trusted_contract(&env, &admin, &new_risk_pool)?;

        env.events().publish(
            (Symbol::new(&env, "RiskPoolUpdated"), ()),
            (admin, old_risk_pool, new_risk_pool, env.ledger().timestamp()),
        );

        Ok(())
    }

    /// Synchronizes the active policy list with the actual state of a policy.
    /// This is a recovery function to fix data integrity issues if the list gets out of sync.
    pub fn sync_policy_state(
        env: Env,
        admin: Address,
        policy_id: u64,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        // Verify policy exists
        let policy = Self::get_policy(env.clone(), policy_id)?;
        let is_active = policy.is_active();

        let mut active_list: Vec<u64> = env
            .storage()
            .persistent()
            .get(&ACTIVE_POLICY_LIST)
            .unwrap_or_else(|| Vec::new(&env));

        let mut found_index = None;
        for i in 0..active_list.len() {
            if active_list.get(i).unwrap() == policy_id {
                found_index = Some(i);
                break;
            }
        }

        if is_active && found_index.is_none() {
            // Policy is active but missing from list -> Add it
            active_list.push_back(policy_id);
            env.storage().persistent().set(&ACTIVE_POLICY_LIST, &active_list);
            
            env.events().publish(
                (Symbol::new(&env, "PolicyStateSynced"), policy_id),
                (Symbol::new(&env, "AddedToActiveList"), env.ledger().timestamp()),
            );
        } else if !is_active && found_index.is_some() {
            // Policy is not active but present in list -> Remove it
            let index = found_index.unwrap();
            active_list.remove(index);
            env.storage().persistent().set(&ACTIVE_POLICY_LIST, &active_list);

            env.events().publish(
                (Symbol::new(&env, "PolicyStateSynced"), policy_id),
                (Symbol::new(&env, "RemovedFromActiveList"), env.ledger().timestamp()),
            );
        }

        Ok(())
    }

    /// Emits a snapshot of the policy state to the event log.
    /// This facilitates off-chain backup and verification.
    pub fn snapshot_policy(
        env: Env,
        admin: Address,
        policy_id: u64,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        let policy = Self::get_policy(env.clone(), policy_id)?;

        env.events().publish(
            (Symbol::new(&env, "PolicySnapshot"), policy_id),
            (policy, env.ledger().timestamp()),
        );

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn with_contract_env<T>(env: &Env, f: impl FnOnce() -> T) -> T {
        let cid = env.register_contract(None, PolicyContract);
        env.as_contract(&cid, f)
    }

    #[test]
    fn test_valid_policy_issuance() {
        let env = Env::default();

        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone())
                .unwrap();

            let coverage = MIN_COVERAGE_AMOUNT + 1000;
            let premium = MIN_PREMIUM_AMOUNT + 100;
            let duration = 30;

            let policy_id = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                duration,
                false,
                None, // coverage_asset - defaults to Native
                None, // premium_asset - defaults to Native
                None, // allow_multi_asset_claims - defaults to false
            )
            .unwrap();

            assert_eq!(policy_id, 1);
            let policy = PolicyContract::get_policy(env.clone(), policy_id).unwrap();
            assert_eq!(policy.holder, holder);
            assert_eq!(policy.coverage_amount, coverage);
            assert_eq!(policy.premium_amount, premium);
            assert_eq!(policy.state(), PolicyState::ACTIVE);
            // Verify default asset values
            assert!(matches!(policy.coverage_asset, shared::types::Asset::Native));
            assert!(matches!(policy.premium_asset, shared::types::Asset::Native));
            assert_eq!(policy.allow_multi_asset_claims, false);
        });
    }

    #[test]
    fn test_invalid_coverage_too_low() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone())
                .unwrap();

            let result = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                MIN_COVERAGE_AMOUNT - 1,
                MIN_PREMIUM_AMOUNT + 100,
                30,
                false,
                None,
                None,
                None,
            );

            assert_eq!(result, Err(ContractError::InvalidAmount));
        });
    }

    #[test]
    fn test_invalid_coverage_too_high() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone())
                .unwrap();

            let result = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                MAX_COVERAGE_AMOUNT + 1,
                MIN_PREMIUM_AMOUNT + 100,
                30,
                false,
                None,
                None,
                None,
            );

            assert_eq!(result, Err(ContractError::InvalidAmount));
        });
    }

    #[test]
    fn test_invalid_premium_too_low() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone())
                .unwrap();

            let result = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                MIN_COVERAGE_AMOUNT + 1000,
                MIN_PREMIUM_AMOUNT - 1,
                30,
                false,
                None,
                None,
                None,
            );

            assert_eq!(result, Err(ContractError::InvalidPremium));
        });
    }

    #[test]
    fn test_invalid_premium_too_high() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone())
                .unwrap();

            let result = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                MIN_COVERAGE_AMOUNT + 1000,
                MAX_PREMIUM_AMOUNT + 1,
                30,
                false,
                None,
                None,
                None,
            );

            assert_eq!(result, Err(ContractError::InvalidPremium));
        });
    }

    #[test]
    fn test_invalid_duration_too_short() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone())
                .unwrap();

            let result = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                MIN_COVERAGE_AMOUNT + 1000,
                MIN_PREMIUM_AMOUNT + 100,
                MIN_POLICY_DURATION_DAYS - 1,
                false,
                None,
                None,
                None,
            );

            assert_eq!(result, Err(ContractError::InvalidInput));
        });
    }

    #[test]
    fn test_invalid_duration_too_long() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone())
                .unwrap();

            let result = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                MIN_COVERAGE_AMOUNT + 1000,
                MIN_PREMIUM_AMOUNT + 100,
                MAX_POLICY_DURATION_DAYS + 1,
                false,
                None,
                None,
                None,
            );

            assert_eq!(result, Err(ContractError::InvalidInput));
        });
    }

    #[test]
    fn test_duplicate_policy_issuance_not_possible() {
        // Since policy IDs are unique via counter, duplicate issuance isn't possible
        // This test ensures the counter increments properly
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone())
                .unwrap();

            let coverage = MIN_COVERAGE_AMOUNT + 1000;
            let premium = MIN_PREMIUM_AMOUNT + 100;
            let duration = 30;

            let policy_id1 = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                duration,
                false,
                None,
                None,
                None,
            )
            .unwrap();

            let policy_id2 = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                duration,
                false,
                None,
                None,
                None,
            )
            .unwrap();

            assert_eq!(policy_id1, 1);
            assert_eq!(policy_id2, 2);
            assert_ne!(policy_id1, policy_id2);
        });
    }

    #[test]
    fn test_state_machine_valid_transitions() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone())
                .unwrap();

            let coverage = MIN_COVERAGE_AMOUNT + 1000;
            let premium = MIN_PREMIUM_AMOUNT + 100;
            let duration = 30;

            let policy_id = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                duration,
                false,
                None,
                None,
                None,
            )
            .unwrap();

            // Test ACTIVE -> CANCELLED
            PolicyStateMachine::transition(&env, policy_id, PolicyState::CANCELLED, admin.clone())
                .unwrap();
            let policy = PolicyContract::get_policy(env.clone(), policy_id).unwrap();
            assert_eq!(policy.state(), PolicyState::CANCELLED);

            // Check history
            let history = PolicyStateMachine::get_policy_history(&env, policy_id);
            assert_eq!(history.len(), 1);
            let h0 = history.get(0).unwrap();
            assert_eq!(h0.previous_state, PolicyState::ACTIVE);
            assert_eq!(h0.new_state, PolicyState::CANCELLED);
        });
    }

    #[test]
    fn test_state_machine_invalid_transitions() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone())
                .unwrap();

            let coverage = MIN_COVERAGE_AMOUNT + 1000;
            let premium = MIN_PREMIUM_AMOUNT + 100;
            let duration = 30;

            let policy_id = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                duration,
                false,
                None,
                None,
                None,
            )
            .unwrap();

            // Transition to CANCELLED
            PolicyStateMachine::transition(&env, policy_id, PolicyState::CANCELLED, admin.clone())
                .unwrap();

            // Try invalid transition from CANCELLED to EXPIRED
            let result = PolicyStateMachine::transition(
                &env,
                policy_id,
                PolicyState::EXPIRED,
                admin.clone(),
            );
            assert_eq!(result, Err(ContractError::InvalidStateTransition));
        });
    }

    #[test]
    fn test_state_based_access_control() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone())
                .unwrap();

            let coverage = MIN_COVERAGE_AMOUNT + 1000;
            let premium = MIN_PREMIUM_AMOUNT + 100;
            let duration = 30;

            let policy_id = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                duration,
                false,
                None,
                None,
                None,
            )
            .unwrap();

            // Cancel the policy
            PolicyContract::cancel_policy(env.clone(), admin.clone(), policy_id).unwrap();

            // Try to cancel again - should fail due to state
            let result = PolicyContract::cancel_policy(env.clone(), admin.clone(), policy_id);
            assert_eq!(result, Err(ContractError::InvalidStateTransition));
        });
    }

    #[test]
    fn test_policy_renewal() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone())
                .unwrap();

            let coverage = MIN_COVERAGE_AMOUNT + 1000;
            let premium = MIN_PREMIUM_AMOUNT + 100;
            let duration = 30;

            let policy_id = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                duration,
                true, // Auto renew enabled
                None,
                None,
                None,
            )
            .unwrap();

            // Renew by holder
            PolicyContract::renew_policy(env.clone(), holder.clone(), policy_id, 30).unwrap();

            let policy = PolicyContract::get_policy(env.clone(), policy_id).unwrap();
            // Duration was 30 days, renewed for 30 days. Total duration from start should be 60 days.
            assert_eq!(policy.end_time, policy.start_time + 60 * 86400);

            // Renew by manager (allowed because auto_renew is true)
            PolicyContract::renew_policy(env.clone(), manager.clone(), policy_id, 30).unwrap();
            let policy = PolicyContract::get_policy(env.clone(), policy_id).unwrap();
            assert_eq!(policy.end_time, policy.start_time + 90 * 86400);

            // Disable auto renew
            PolicyContract::set_auto_renew(env.clone(), holder.clone(), policy_id, false).unwrap();

            // Renew by manager (should fail)
            let res = PolicyContract::renew_policy(env.clone(), manager.clone(), policy_id, 30);
            assert_eq!(res, Err(ContractError::Unauthorized));
        });
    }

    #[test]
    fn test_disaster_recovery_functions() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);
            let new_risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

            // 1. Test Update Risk Pool
            PolicyContract::update_risk_pool(env.clone(), admin.clone(), new_risk_pool.clone()).unwrap();
            let config = PolicyContract::get_config(env.clone()).unwrap();
            assert_eq!(config.risk_pool, new_risk_pool);

            // 2. Test Snapshot
            let coverage = MIN_COVERAGE_AMOUNT + 1000;
            let premium = MIN_PREMIUM_AMOUNT + 100;
            let duration = 30;
            let policy_id = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                duration,
                false,
            ).unwrap();

            PolicyContract::snapshot_policy(env.clone(), admin.clone(), policy_id).unwrap();

            // 3. Test Sync Policy State (Integrity Check)
            // Verify it's in the list
            let active_count = PolicyContract::get_active_policy_count(env.clone());
            assert_eq!(active_count, 1);

            // Run sync (should be no-op but succeed)
            PolicyContract::sync_policy_state(env.clone(), admin.clone(), policy_id).unwrap();
            
            // Expire and verify sync
            PolicyContract::expire_policy(env.clone(), admin.clone(), policy_id).unwrap();
            PolicyContract::sync_policy_state(env.clone(), admin.clone(), policy_id).unwrap();
            
            let active_count_final = PolicyContract::get_active_policy_count(env.clone());
            assert_eq!(active_count_final, 0);
        });
    }

    #[test]
    fn test_policy_auto_expiry_on_access() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

            let coverage = MIN_COVERAGE_AMOUNT + 1000;
            let premium = MIN_PREMIUM_AMOUNT + 100;
            let duration = 30; // 30 days

            let policy_id = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                duration,
                false,
                None,
                None,
                None,
            )
            .unwrap();

            // Policy should be active initially
            let policy = PolicyContract::get_policy(env.clone(), policy_id).unwrap();
            assert_eq!(policy.state(), PolicyState::ACTIVE);
            assert_eq!(policy.end_time, policy.start_time + 30 * 86400);

            // Fast forward time beyond policy end time
            env.ledger().set_timestamp(policy.start_time + 31 * 86400);

            // Access policy should trigger auto-expiry
            let expired_policy = PolicyContract::get_policy(env.clone(), policy_id).unwrap();
            assert_eq!(expired_policy.state(), PolicyState::EXPIRED);

            // Verify policy is no longer in active list
            let active_count = PolicyContract::get_active_policy_count(env.clone());
            assert_eq!(active_count, 0);
        });
    }

    #[test]
    fn test_policy_renewal_rejected_for_expired_policy() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

            let coverage = MIN_COVERAGE_AMOUNT + 1000;
            let premium = MIN_PREMIUM_AMOUNT + 100;
            let duration = 30;

            let policy_id = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                duration,
                false,
                None,
                None,
                None,
            )
            .unwrap();

            // Fast forward time beyond policy end time
            let policy = PolicyContract::get_policy(env.clone(), policy_id).unwrap();
            env.ledger().set_timestamp(policy.start_time + 31 * 86400);

            // Try to renew expired policy - should fail
            let result = PolicyContract::renew_policy(env.clone(), holder.clone(), policy_id, 30);
            assert_eq!(result, Err(ContractError::PolicyExpired));
        });
    }

    #[test]
    fn test_policy_cancellation_rejected_for_expired_policy() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

            let coverage = MIN_COVERAGE_AMOUNT + 1000;
            let premium = MIN_PREMIUM_AMOUNT + 100;
            let duration = 30;

            let policy_id = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                duration,
                false,
                None,
                None,
                None,
            )
            .unwrap();

            // Fast forward time beyond policy end time
            let policy = PolicyContract::get_policy(env.clone(), policy_id).unwrap();
            env.ledger().set_timestamp(policy.start_time + 31 * 86400);

            // Try to cancel expired policy - should fail due to state transition
            let result = PolicyContract::cancel_policy(env.clone(), admin.clone(), policy_id);
            assert_eq!(result, Err(ContractError::InvalidStateTransition));
        });
    }

    #[test]
    fn test_edge_case_policy_expires_exactly_at_current_time() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

            let coverage = MIN_COVERAGE_AMOUNT + 1000;
            let premium = MIN_PREMIUM_AMOUNT + 100;
            let duration = 30;

            let policy_id = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                duration,
                false,
                None,
                None,
                None,
            )
            .unwrap();

            let policy = PolicyContract::get_policy(env.clone(), policy_id).unwrap();
            
            // Set time exactly to end_time - policy should still be active
            env.ledger().set_timestamp(policy.end_time);
            let policy_at_end = PolicyContract::get_policy(env.clone(), policy_id).unwrap();
            assert_eq!(policy_at_end.state(), PolicyState::ACTIVE);

            // Set time 1 second after end_time - policy should be expired
            env.ledger().set_timestamp(policy.end_time + 1);
            let policy_expired = PolicyContract::get_policy(env.clone(), policy_id).unwrap();
            assert_eq!(policy_expired.state(), PolicyState::EXPIRED);
        });
    }

    #[test]
    fn test_multiple_policy_auto_expiry() {
        let env = Env::default();
        with_contract_env(&env, || {
            let admin = Address::generate(&env);
            let manager = Address::generate(&env);
            let holder = Address::generate(&env);
            let risk_pool = Address::generate(&env);

            PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
            PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

            let coverage = MIN_COVERAGE_AMOUNT + 1000;
            let premium = MIN_PREMIUM_AMOUNT + 100;

            // Issue multiple policies with different durations
            let policy1 = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                10, // 10 days
                false,
                None,
                None,
                None,
            )
            .unwrap();

            let policy2 = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                20, // 20 days
                false,
                None,
                None,
                None,
            )
            .unwrap();

            let policy3 = PolicyContract::issue_policy(
                env.clone(),
                manager.clone(),
                holder.clone(),
                coverage,
                premium,
                30, // 30 days
                false,
                None,
                None,
                None,
            )
            .unwrap();

            // Initially all should be active
            assert_eq!(PolicyContract::get_active_policy_count(env.clone()), 3);

            // Fast forward to day 15 - policy1 should be expired
            let base_time = env.ledger().timestamp();
            env.ledger().set_timestamp(base_time + 15 * 86400);

            // Access all policies to trigger auto-expiry checks
            let p1 = PolicyContract::get_policy(env.clone(), policy1).unwrap();
            let p2 = PolicyContract::get_policy(env.clone(), policy2).unwrap();
            let p3 = PolicyContract::get_policy(env.clone(), policy3).unwrap();

            assert_eq!(p1.state(), PolicyState::EXPIRED);
            assert_eq!(p2.state(), PolicyState::ACTIVE);
            assert_eq!(p3.state(), PolicyState::ACTIVE);
            assert_eq!(PolicyContract::get_active_policy_count(env.clone()), 2);

            // Fast forward to day 25 - policy2 should also be expired
            env.ledger().set_timestamp(base_time + 25 * 86400);

            let p2_expired = PolicyContract::get_policy(env.clone(), policy2).unwrap();
            let p3_still_active = PolicyContract::get_policy(env.clone(), policy3).unwrap();

            assert_eq!(p2_expired.state(), PolicyState::EXPIRED);
            assert_eq!(p3_still_active.state(), PolicyState::ACTIVE);
            assert_eq!(PolicyContract::get_active_policy_count(env.clone()), 1);
        });
    }
}
