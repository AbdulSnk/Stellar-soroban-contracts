#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, Symbol, Vec, Map, BytesN};

use insurance_contracts::authorization::{
    get_role, initialize_admin, register_trusted_contract, require_admin,
    Role,
};
use insurance_contracts::emergency_pause::EmergencyPause;

#[contract]
pub struct CrossChainBridgeContract;

const PAUSED: Symbol = Symbol::short("PAUSED");
const CONFIG: Symbol = Symbol::short("CONFIG");
const VALIDATORS: Symbol = Symbol::short("VALIDATORS");
const TRANSFER: Symbol = Symbol::short("TRANSFER");
const CONSENSUS: Symbol = Symbol::short("CONSENSUS");
const ATOMIC_SWAP: Symbol = Symbol::short("ATOMIC_SW");
const CHAIN_STATUS: Symbol = Symbol::short("CHAIN_ST");
const EMERGENCY: Symbol = Symbol::short("EMERGENCY");

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainId {
    Stellar,
    Ethereum,
    Polygon,
    BSC,
    Arbitrum,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferStatus {
    Initiated,
    Validated,
    ConsensusReached,
    Executing,
    Completed,
    Failed,
    RolledBack,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainStatus {
    Active,
    Degraded,
    Suspended,
    Failed,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Validator {
    pub address: Address,
    pub chain_id: ChainId,
    pub voting_power: u32,
    pub is_active: bool,
    pub last_seen: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct BridgeTransfer {
    pub transfer_id: BytesN<32>,
    pub from_chain: ChainId,
    pub to_chain: ChainId,
    pub sender: Address,
    pub recipient: Address,
    pub amount: i128,
    pub asset: Symbol,
    pub status: TransferStatus,
    pub initiated_at: u64,
    pub timeout_at: u64,
    pub consensus_votes: Map<Address, bool>,
    pub atomic_swap_id: Option<BytesN<32>>,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    pub min_votes_required: u32,
    pub threshold_percentage: u32,
    pub voting_timeout: u64,
    pub max_validators: u32,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct AtomicSwap {
    pub swap_id: BytesN<32>,
    pub transfer_id: BytesN<32>,
    pub secret_hash: BytesN<32>,
    pub secret: Option<BytesN<32>>,
    pub initiator: Address,
    pub participant: Address,
    pub amount: i128,
    pub timeout: u64,
    pub is_completed: bool,
    pub is_refunded: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct ChainStatusInfo {
    pub chain_id: ChainId,
    pub status: ChainStatus,
    pub last_block_height: u64,
    pub last_verified: u64,
    pub failure_count: u32,
    pub recovery_attempts: u32,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ContractError {
    Unauthorized = 1,
    Paused = 2,
    InvalidInput = 3,
    NotFound = 4,
    NotInitialized = 5,
    InvalidRole = 6,
    RoleNotFound = 7,
    NotTrustedContract = 8,
    // Bridge specific errors
    InsufficientConsensus = 100,
    TransferTimeout = 101,
    ChainNotActive = 102,
    InvalidValidator = 103,
    AtomicSwapFailed = 104,
    RollbackFailed = 105,
    DuplicateTransfer = 106,
    InvalidChain = 107,
    ConsensusNotReached = 108,
}

impl From<insurance_contracts::authorization::AuthError> for ContractError {
    fn from(err: insurance_contracts::authorization::AuthError) -> Self {
        match err {
            insurance_contracts::authorization::AuthError::Unauthorized => ContractError::Unauthorized,
            insurance_contracts::authorization::AuthError::InvalidRole => ContractError::InvalidRole,
            insurance_contracts::authorization::AuthError::RoleNotFound => ContractError::RoleNotFound,
            insurance_contracts::authorization::AuthError::NotTrustedContract => ContractError::NotTrustedContract,
        }
    }
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

fn generate_transfer_id(env: &Env, transfer_data: &(Address, Address, i128, u64)) -> BytesN<32> {
    let mut hasher = env.crypto().sha256();
    hasher.update(&transfer_data.0.to_xdr(env));
    hasher.update(&transfer_data.1.to_xdr(env));
    hasher.update(&transfer_data.2.to_xdr(env));
    hasher.update(&transfer_data.3.to_xdr(env));
    hasher.finalize()
}

#[contractimpl]
impl CrossChainBridgeContract {
    pub fn initialize(
        env: Env,
        admin: Address,
        consensus_config: ConsensusConfig,
    ) -> Result<(), ContractError> {
        if insurance_contracts::authorization::get_admin(&env).is_some() {
            return Err(ContractError::NotInitialized);
        }

        validate_address(&env, &admin)?;

        admin.require_auth();
        initialize_admin(&env, admin.clone());

        // Validate consensus config
        if consensus_config.min_votes_required == 0 
            || consensus_config.threshold_percentage == 0 
            || consensus_config.threshold_percentage > 10000 {
            return Err(ContractError::InvalidInput);
        }

        env.storage().persistent().set(&CONFIG, &consensus_config);
        env.storage().persistent().set(&VALIDATORS, &Map::<Address, Validator>::new(&env));

        // Initialize chain statuses
        let mut chain_statuses = Map::<ChainId, ChainStatusInfo>::new(&env);
        chain_statuses.set(ChainId::Stellar, ChainStatusInfo {
            chain_id: ChainId::Stellar,
            status: ChainStatus::Active,
            last_block_height: 0,
            last_verified: env.ledger().timestamp(),
            failure_count: 0,
            recovery_attempts: 0,
        });
        env.storage().persistent().set(&CHAIN_STATUS, &chain_statuses);

        // Initialize emergency pause system
        EmergencyPause::initialize(&env, &admin)?;

        env.events().publish((Symbol::new(&env, "bridge_initialized"), ()), admin);

        Ok(())
    }

    /// Add a validator for cross-chain validation
    pub fn add_validator(
        env: Env,
        admin: Address,
        validator_address: Address,
        chain_id: ChainId,
        voting_power: u32,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_address(&env, &validator_address)?;

        let consensus_config: ConsensusConfig = env.storage().persistent()
            .get(&CONFIG)
            .ok_or(ContractError::NotInitialized)?;

        let mut validators: Map<Address, Validator> = env.storage().persistent()
            .get(&VALIDATORS)
            .unwrap_or_else(|| Map::new(&env));

        if validators.len() >= consensus_config.max_validators {
            return Err(ContractError::InvalidInput);
        }

        let validator = Validator {
            address: validator_address.clone(),
            chain_id,
            voting_power,
            is_active: true,
            last_seen: env.ledger().timestamp(),
        };

        validators.set(validator_address.clone(), validator);
        env.storage().persistent().set(&VALIDATORS, &validators);

        env.events().publish(
            (Symbol::new(&env, "validator_added"), validator_address),
            (chain_id, voting_power),
        );

        Ok(())
    }

    /// Initiate a cross-chain transfer with atomic swap
    pub fn initiate_transfer(
        env: Env,
        sender: Address,
        from_chain: ChainId,
        to_chain: ChainId,
        recipient: Address,
        amount: i128,
        asset: Symbol,
        timeout_seconds: u64,
    ) -> Result<BytesN<32>, ContractError> {
        sender.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_address(&env, &recipient)?;

        if amount <= 0 {
            return Err(ContractError::InvalidInput);
        }

        // Check chain statuses
        let chain_statuses: Map<ChainId, ChainStatusInfo> = env.storage().persistent()
            .get(&CHAIN_STATUS)
            .ok_or(ContractError::NotFound)?;

        let from_status = chain_statuses.get(from_chain).ok_or(ContractError::InvalidChain)?;
        let to_status = chain_statuses.get(to_chain).ok_or(ContractError::InvalidChain)?;

        if from_status.status != ChainStatus::Active || to_status.status != ChainStatus::Active {
            return Err(ContractError::ChainNotActive);
        }

        let current_time = env.ledger().timestamp();
        let transfer_data = (sender.clone(), recipient.clone(), amount, current_time);
        let transfer_id = generate_transfer_id(&env, &transfer_data);

        // Check for duplicate transfer
        if env.storage().persistent().has(&TRANSFER, transfer_id) {
            return Err(ContractError::DuplicateTransfer);
        }

        let timeout_at = current_time + timeout_seconds;

        let transfer = BridgeTransfer {
            transfer_id,
            from_chain,
            to_chain,
            sender: sender.clone(),
            recipient: recipient.clone(),
            amount,
            asset,
            status: TransferStatus::Initiated,
            initiated_at: current_time,
            timeout_at,
            consensus_votes: Map::new(&env),
            atomic_swap_id: None,
        };

        env.storage().persistent().set(&TRANSFER, transfer_id, &transfer);

        env.events().publish(
            (Symbol::new(&env, "transfer_initiated"), transfer_id),
            (sender, from_chain, to_chain, recipient, amount, asset),
        );

        Ok(transfer_id)
    }

    /// Vote on a transfer validation (validator only)
    pub fn validate_transfer(
        env: Env,
        validator: Address,
        transfer_id: BytesN<32>,
        approve: bool,
    ) -> Result<(), ContractError> {
        validator.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Check if validator is valid and active
        let validators: Map<Address, Validator> = env.storage().persistent()
            .get(&VALIDATORS)
            .ok_or(ContractError::NotFound)?;

        let validator_info = validators.get(validator.clone())
            .ok_or(ContractError::InvalidValidator)?;

        if !validator_info.is_active {
            return Err(ContractError::InvalidValidator);
        }

        let mut transfer: BridgeTransfer = env.storage().persistent()
            .get(&TRANSFER, transfer_id)
            .ok_or(ContractError::NotFound)?;

        // Check if transfer is still in validation phase
        if transfer.status != TransferStatus::Initiated && transfer.status != TransferStatus::Validated {
            return Err(ContractError::InvalidInput);
        }

        // Check timeout
        if env.ledger().timestamp() > transfer.timeout_at {
            transfer.status = TransferStatus::Failed;
            env.storage().persistent().set(&TRANSFER, transfer_id, &transfer);
            return Err(ContractError::TransferTimeout);
        }

        // Record vote
        transfer.consensus_votes.set(validator.clone(), approve);

        // Update validator last seen
        let mut updated_validator = validator_info;
        updated_validator.last_seen = env.ledger().timestamp();
        validators.set(validator.clone(), updated_validator);
        env.storage().persistent().set(&VALIDATORS, &validators);

        // Check if consensus is reached
        let consensus_config: ConsensusConfig = env.storage().persistent()
            .get(&CONFIG)
            .ok_or(ContractError::NotInitialized)?;

        if Self::check_consensus(&env, &transfer, &consensus_config) {
            transfer.status = TransferStatus::ConsensusReached;
            env.events().publish(
                (Symbol::new(&env, "consensus_reached"), transfer_id),
                (transfer.sender, transfer.recipient, transfer.amount),
            );
        } else {
            transfer.status = TransferStatus::Validated;
        }

        env.storage().persistent().set(&TRANSFER, transfer_id, &transfer);

        env.events().publish(
            (Symbol::new(&env, "transfer_validated"), transfer_id),
            (validator, approve),
        );

        Ok(())
    }

    /// Execute atomic swap for cross-chain transfer
    pub fn execute_atomic_swap(
        env: Env,
        transfer_id: BytesN<32>,
        secret_hash: BytesN<32>,
    ) -> Result<BytesN<32>, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let mut transfer: BridgeTransfer = env.storage().persistent()
            .get(&TRANSFER, transfer_id)
            .ok_or(ContractError::NotFound)?;

        if transfer.status != TransferStatus::ConsensusReached {
            return Err(ContractError::ConsensusNotReached);
        }

        // Generate atomic swap ID
        let mut hasher = env.crypto().sha256();
        hasher.update(&transfer_id);
        hasher.update(&secret_hash);
        let swap_id = hasher.finalize();

        let atomic_swap = AtomicSwap {
            swap_id,
            transfer_id,
            secret_hash,
            secret: None,
            initiator: transfer.sender.clone(),
            participant: transfer.recipient.clone(),
            amount: transfer.amount,
            timeout: transfer.timeout_at,
            is_completed: false,
            is_refunded: false,
        };

        transfer.atomic_swap_id = Some(swap_id);
        transfer.status = TransferStatus::Executing;

        env.storage().persistent().set(&TRANSFER, transfer_id, &transfer);
        env.storage().persistent().set(&ATOMIC_SWAP, swap_id, &atomic_swap);

        env.events().publish(
            (Symbol::new(&env, "atomic_swap_created"), swap_id),
            (transfer_id, transfer.sender, transfer.recipient, transfer.amount),
        );

        Ok(swap_id)
    }

    /// Complete atomic swap with secret
    pub fn complete_atomic_swap(
        env: Env,
        participant: Address,
        swap_id: BytesN<32>,
        secret: BytesN<32>,
    ) -> Result<(), ContractError> {
        participant.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let mut atomic_swap: AtomicSwap = env.storage().persistent()
            .get(&ATOMIC_SWAP, swap_id)
            .ok_or(ContractError::NotFound)?;

        if atomic_swap.is_completed || atomic_swap.is_refunded {
            return Err(ContractError::AtomicSwapFailed);
        }

        if atomic_swap.participant != participant {
            return Err(ContractError::Unauthorized);
        }

        // Verify secret hash
        let mut hasher = env.crypto().sha256();
        hasher.update(&secret);
        let computed_hash = hasher.finalize();

        if computed_hash != atomic_swap.secret_hash {
            return Err(ContractError::InvalidInput);
        }

        // Check timeout
        if env.ledger().timestamp() > atomic_swap.timeout {
            return Err(ContractError::TransferTimeout);
        }

        atomic_swap.secret = Some(secret);
        atomic_swap.is_completed = true;

        // Update transfer status
        let transfer_id = atomic_swap.transfer_id;
        let mut transfer: BridgeTransfer = env.storage().persistent()
            .get(&TRANSFER, transfer_id)
            .ok_or(ContractError::NotFound)?;

        transfer.status = TransferStatus::Completed;

        env.storage().persistent().set(&ATOMIC_SWAP, swap_id, &atomic_swap);
        env.storage().persistent().set(&TRANSFER, transfer_id, &transfer);

        env.events().publish(
            (Symbol::new(&env, "atomic_swap_completed"), swap_id),
            (participant, transfer_id),
        );

        Ok(())
    }

    /// Refund atomic swap after timeout
    pub fn refund_atomic_swap(
        env: Env,
        initiator: Address,
        swap_id: BytesN<32>,
    ) -> Result<(), ContractError> {
        initiator.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let mut atomic_swap: AtomicSwap = env.storage().persistent()
            .get(&ATOMIC_SWAP, swap_id)
            .ok_or(ContractError::NotFound)?;

        if atomic_swap.is_completed || atomic_swap.is_refunded {
            return Err(ContractError::AtomicSwapFailed);
        }

        if atomic_swap.initiator != initiator {
            return Err(ContractError::Unauthorized);
        }

        // Check timeout
        if env.ledger().timestamp() <= atomic_swap.timeout {
            return Err(ContractError::InvalidInput);
        }

        atomic_swap.is_refunded = true;

        // Update transfer status
        let transfer_id = atomic_swap.transfer_id;
        let mut transfer: BridgeTransfer = env.storage().persistent()
            .get(&TRANSFER, transfer_id)
            .ok_or(ContractError::NotFound)?;

        transfer.status = TransferStatus::RolledBack;

        env.storage().persistent().set(&ATOMIC_SWAP, swap_id, &atomic_swap);
        env.storage().persistent().set(&TRANSFER, transfer_id, &transfer);

        env.events().publish(
            (Symbol::new(&env, "atomic_swap_refunded"), swap_id),
            (initiator, transfer_id),
        );

        Ok(())
    }

    /// Emergency pause all bridge operations
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

    /// Update chain status (for monitoring and recovery)
    pub fn update_chain_status(
        env: Env,
        admin: Address,
        chain_id: ChainId,
        status: ChainStatus,
        block_height: u64,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        let mut chain_statuses: Map<ChainId, ChainStatusInfo> = env.storage().persistent()
            .get(&CHAIN_STATUS)
            .ok_or(ContractError::NotFound)?;

        let mut chain_info = chain_statuses.get(chain_id).ok_or(ContractError::InvalidChain)?;
        
        chain_info.status = status;
        chain_info.last_block_height = block_height;
        chain_info.last_verified = env.ledger().timestamp();

        if status == ChainStatus::Failed {
            chain_info.failure_count += 1;
        }

        chain_statuses.set(chain_id, chain_info);
        env.storage().persistent().set(&CHAIN_STATUS, &chain_statuses);

        env.events().publish(
            (Symbol::new(&env, "chain_status_updated"), chain_id),
            (status, block_height),
        );

        Ok(())
    }

    /// Rollback a failed transfer
    pub fn rollback_transfer(
        env: Env,
        admin: Address,
        transfer_id: BytesN<32>,
        reason: Symbol,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        let mut transfer: BridgeTransfer = env.storage().persistent()
            .get(&TRANSFER, transfer_id)
            .ok_or(ContractError::NotFound)?;

        match transfer.status {
            TransferStatus::Initiated | TransferStatus::Validated | TransferStatus::ConsensusReached | TransferStatus::Executing => {
                transfer.status = TransferStatus::RolledBack;
                env.storage().persistent().set(&TRANSFER, transfer_id, &transfer);

                env.events().publish(
                    (Symbol::new(&env, "transfer_rolled_back"), transfer_id),
                    (admin, reason),
                );

                Ok(())
            }
            _ => Err(ContractError::InvalidInput),
        }
    }

    // Query functions

    pub fn get_transfer(env: Env, transfer_id: BytesN<32>) -> Result<BridgeTransfer, ContractError> {
        env.storage().persistent()
            .get(&TRANSFER, transfer_id)
            .ok_or(ContractError::NotFound)
    }

    pub fn get_atomic_swap(env: Env, swap_id: BytesN<32>) -> Result<AtomicSwap, ContractError> {
        env.storage().persistent()
            .get(&ATOMIC_SWAP, swap_id)
            .ok_or(ContractError::NotFound)
    }

    pub fn get_validators(env: Env) -> Result<Map<Address, Validator>, ContractError> {
        Ok(env.storage().persistent()
            .get(&VALIDATORS)
            .unwrap_or_else(|| Map::new(&env)))
    }

    pub fn get_chain_status(env: Env, chain_id: ChainId) -> Result<ChainStatusInfo, ContractError> {
        let chain_statuses: Map<ChainId, ChainStatusInfo> = env.storage().persistent()
            .get(&CHAIN_STATUS)
            .ok_or(ContractError::NotFound)?;

        chain_statuses.get(chain_id).ok_or(ContractError::InvalidChain)
    }

    pub fn get_all_chain_statuses(env: Env) -> Result<Map<ChainId, ChainStatusInfo>, ContractError> {
        env.storage().persistent()
            .get(&CHAIN_STATUS)
            .ok_or(ContractError::NotFound)
    }

    // Helper functions

    fn check_consensus(
        env: &Env,
        transfer: &BridgeTransfer,
        config: &ConsensusConfig,
    ) -> bool {
        let validators: Map<Address, Validator> = env.storage().persistent()
            .get(&VALIDATORS)
            .unwrap_or_else(|| Map::new(env));

        let mut total_voting_power = 0u32;
        let mut approve_votes = 0u32;
        let mut total_votes = 0u32;

        // Count votes from active validators
        for (validator_addr, vote) in transfer.consensus_votes.iter() {
            if let Some(validator_info) = validators.get(validator_addr) {
                if validator_info.is_active {
                    total_voting_power += validator_info.voting_power;
                    total_votes += 1;

                    if *vote {
                        approve_votes += validator_info.voting_power;
                    }
                }
            }
        }

        // Check minimum votes requirement
        if total_votes < config.min_votes_required {
            return false;
        }

        // Check threshold percentage
        if total_voting_power == 0 {
            return false;
        }

        let approval_percentage = (approve_votes * 10000) / total_voting_power;
        approval_percentage >= config.threshold_percentage
    }

    /// Pause the bridge
    pub fn pause(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        set_paused(&env, true);

        env.events().publish((Symbol::new(&env, "bridge_paused"), ()), admin);

        Ok(())
    }

    /// Unpause the bridge
    pub fn unpause(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        set_paused(&env, false);

        env.events().publish((Symbol::new(&env, "bridge_unpaused"), ()), admin);

        Ok(())
    }
}
