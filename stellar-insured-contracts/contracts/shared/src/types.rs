//! Common types and data structures for insurance contracts
//!
//! This module defines shared enums and structs that represent core concepts
//! used across all insurance contracts (policies, claims, governance, etc.).

use soroban_sdk::{contracttype, Address, BytesN, Symbol, Vec};

// ===== Asset Types =====

/// Represents an asset type in the insurance protocol
/// Supports both native XLM and custom Stellar assets
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Asset {
    /// Native XLM asset
    Native,
    /// Stellar asset with issuer (asset_code, issuer_address)
    Stellar((Symbol, Address)),
    /// Contract-based token (token contract address)
    Contract(Address),
}

impl Asset {
    /// Returns a unique identifier for the asset for storage purposes
    pub fn to_key(&self) -> Symbol {
        match self {
            Asset::Native => Symbol::new(&soroban_sdk::Env::default(), "XLM"),
            Asset::Stellar((code, _)) => code.clone(),
            Asset::Contract(_addr) => {
                // Use first 4 bytes of address as identifier
                Symbol::new(&soroban_sdk::Env::default(), "CONTR")
            }
        }
    }
}

/// Asset metadata for registered assets
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetMetadata {
    /// The asset identifier
    pub asset: Asset,
    /// Asset symbol (e.g., "USDC", "XLM")
    pub symbol: Symbol,
    /// Asset name
    pub name: Symbol,
    /// Number of decimal places
    pub decimals: u32,
    /// Whether the asset is active for use
    pub is_active: bool,
    /// Whether the asset is accepted for premiums
    pub accept_for_premium: bool,
    /// Whether the asset is accepted for claims
    pub accept_for_claims: bool,
    /// Minimum amount allowed for transactions
    pub min_amount: i128,
    /// Maximum amount allowed for transactions
    pub max_amount: i128,
    /// Timestamp when asset was registered
    pub registered_at: u64,
}

/// Multi-asset balance structure for tracking balances across assets
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiAssetBalance {
    /// The asset type
    pub asset: Asset,
    /// Balance amount
    pub amount: i128,
    /// Last updated timestamp
    pub updated_at: u64,
}

/// Asset conversion rate information
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetConversionRate {
    /// Source asset
    pub from_asset: Asset,
    /// Target asset
    pub to_asset: Asset,
    /// Conversion rate in basis points (e.g., 10000 = 1:1)
    /// Rate represents (to_amount * 10000) / from_amount
    pub rate_bps: u32,
    /// Timestamp when rate was last updated
    pub updated_at: u64,
    /// Oracle source address
    pub oracle_source: Address,
}

/// Policy asset configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAssetConfig {
    /// Asset used for coverage amount
    pub coverage_asset: Asset,
    /// Asset used for premium payments
    pub premium_asset: Asset,
    /// Whether multi-asset claims are allowed
    pub allow_multi_asset_claims: bool,
    /// List of assets accepted for claim payouts (if multi-asset enabled)
    pub accepted_claim_assets: Vec<Asset>,
}

/// Claim payout asset preference
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimPayoutPreference {
    /// Preferred asset for payout
    pub preferred_asset: Asset,
    /// Whether to accept equivalent value in other assets
    pub accept_alternative: bool,
    /// Alternative assets accepted (in order of preference)
    pub alternatives: Vec<Asset>,
}

// ===== Status Enums =====

/// Represents the lifecycle status of a policy
///
/// # Transitions
/// - `Active` → `Expired` or `Cancelled`
/// - `Expired` → Terminal (no further transitions)
/// - `Cancelled` → Terminal (no further transitions)
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyStatus {
    /// Policy is currently active and valid
    Active = 0,

    /// Policy has expired naturally
    Expired = 1,

    /// Policy has been cancelled
    Cancelled = 2,

    /// Policy has been claimed against
    Claimed = 3,
}

/// Represents the lifecycle status of a claim
///
/// # Transitions
/// - `Submitted` → `UnderReview`, `Rejected`
/// - `UnderReview` → `Approved`, `Rejected`
/// - `Approved` → `Settled`
/// - `Rejected` → Terminal (no further transitions)
/// - `Settled` → Terminal (no further transitions)
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimStatus {
    /// Claim has been submitted but not reviewed
    Submitted = 0,

    /// Claim is currently under review
    UnderReview = 1,

    /// Claim has been approved
    Approved = 2,

    /// Claim has been rejected
    Rejected = 3,

    /// Claim has been settled (payment made)
    Settled = 4,
}

/// Represents the status of a governance proposal
///
/// # Transitions
/// - `Active` → `Passed`, `Rejected`, or `Expired`
/// - `Passed` → `Executed`
/// - `Rejected` → Terminal (no further transitions)
/// - `Executed` → Terminal (no further transitions)
/// - `Expired` → Terminal (no further transitions)
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalStatus {
    /// Proposal is currently active for voting
    Active = 0,

    /// Proposal has passed voting
    Passed = 1,

    /// Proposal has been rejected
    Rejected = 2,

    /// Proposal has been executed
    Executed = 3,

    /// Proposal voting period has expired
    Expired = 4,
}

/// Types of governance proposals
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalType {
    /// Proposal to change protocol parameters
    ParameterChange = 0,

    /// Proposal to upgrade a contract
    ContractUpgrade = 1,

    /// Proposal to execute slashing
    SlashingAction = 2,

    /// Proposal to allocate treasury funds
    TreasuryAllocation = 3,

    /// Proposal for emergency actions
    EmergencyAction = 4,
}

/// Vote choice in governance
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteType {
    /// Vote in favor
    Yes = 0,

    /// Vote against
    No = 1,

    /// Abstain from voting
    Abstain = 2,
}

/// Risk pool status
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskPoolStatus {
    /// Risk pool is operational
    Active = 0,

    /// Risk pool is temporarily closed
    Paused = 1,

    /// Risk pool is in emergency mode
    Emergency = 2,

    /// Risk pool is shut down
    Closed = 3,
}

// ===== Data Structures =====

/// Represents evidence for a claim (hash-only, immutable)
///
/// Evidence is stored as a SHA-256 hash to maintain immutability
/// while keeping storage costs reasonable.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimEvidence {
    /// Unique claim identifier
    pub claim_id: BytesN<32>,

    /// SHA-256 hash of the evidence
    pub evidence_hash: BytesN<32>,

    /// Address that submitted the evidence
    pub submitter: Address,

    /// Timestamp when evidence was submitted
    pub submitted_at: u64,
}

/// Represents a vote record in governance
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteRecord {
    /// Proposal identifier
    pub proposal_id: u64,

    /// Address of the voter
    pub voter: Address,

    /// Vote choice (Yes, No, Abstain)
    pub vote: VoteType,

    /// Voting power used
    pub voting_power: i128,

    /// Timestamp of the vote
    pub voted_at: u64,
}

/// Configuration for oracle validation
///
/// Used to configure how claims and other operations are validated
/// against oracle data.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleConfig {
    /// Address of the oracle contract
    pub oracle_contract: Address,

    /// Whether oracle validation is required
    pub require_oracle_validation: bool,

    /// Minimum number of oracle submissions required
    pub min_oracle_submissions: u32,

    /// Maximum allowed age of oracle data in seconds
    pub max_data_age: u64,

    /// Maximum allowed deviation from median (basis points, 0-10000)
    pub max_deviation_bps: u32,
}

/// Risk metrics for a policy or pool
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskMetrics {
    /// Total value at risk
    pub total_value_at_risk: i128,

    /// Current reserve balance
    pub reserve_balance: i128,

    /// Reserve ratio as percentage (0-100)
    pub reserve_ratio_percent: u32,

    /// Total claims paid out
    pub total_claims_paid: i128,

    /// Loss ratio percentage (0-100)
    pub loss_ratio_percent: u32,
}

/// Policy metadata for tracking
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyMetadata {
    /// Policy identifier
    pub policy_id: u64,

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

    /// Policy status
    pub status: PolicyStatus,

    /// Timestamp when policy was created
    pub created_at: u64,

    /// Timestamp of last update
    pub updated_at: u64,
}

/// Claim metadata for tracking
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimMetadata {
    /// Claim identifier
    pub claim_id: u64,

    /// Associated policy identifier
    pub policy_id: u64,

    /// Claimant address
    pub claimant: Address,

    /// Claimed amount in stroops
    pub claimed_amount: i128,

    /// Approved amount in stroops
    pub approved_amount: i128,

    /// Claim status
    pub status: ClaimStatus,

    /// Timestamp when claim was submitted
    pub submitted_at: u64,

    /// Timestamp of last update
    pub updated_at: u64,

    /// Optional evidence hash (SHA-256)
    pub evidence_hash: Option<BytesN<32>>,
}

/// Treasury allocation record
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasuryAllocation {
    /// Allocation identifier
    pub allocation_id: u64,

    /// Recipient address
    pub recipient: Address,

    /// Allocated amount
    pub amount: i128,

    /// Purpose of allocation
    pub purpose: BytesN<32>, // Hash of purpose string

    /// Timestamp when allocated
    pub allocated_at: u64,

    /// Timestamp when funds were released
    pub released_at: Option<u64>,

    /// Whether allocation has been executed
    pub executed: bool,
}

// ===== Product Template Types =====

/// Insurance product categories
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductCategory {
    /// Property insurance (homes, buildings, etc.)
    Property = 0,
    /// Health insurance
    Health = 1,
    /// Auto insurance
    Auto = 2,
    /// Life insurance
    Life = 3,
    /// Travel insurance
    Travel = 4,
    /// Cyber insurance
    Cyber = 5,
    /// Business insurance
    Business = 6,
    /// Custom/Other insurance
    Custom = 7,
}

/// Template status lifecycle
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemplateStatus {
    /// Template is being drafted
    Draft = 0,
    /// Template submitted for review
    PendingReview = 1,
    /// Template approved and ready for use
    Approved = 2,
    /// Template is active and can be used to create policies
    Active = 3,
    /// Template is deprecated but existing policies remain valid
    Deprecated = 4,
    /// Template is archived and cannot be used
    Archived = 5,
}

/// Risk level classification
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskLevel {
    /// Low risk - minimal likelihood of claims
    Low = 0,
    /// Medium risk - moderate likelihood of claims
    Medium = 1,
    /// High risk - significant likelihood of claims
    High = 2,
    /// Very high risk - maximum likelihood of claims
    VeryHigh = 3,
}

/// Premium calculation model
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PremiumModel {
    /// Fixed premium amount
    Fixed = 0,
    /// Percentage of coverage amount
    Percentage = 1,
    /// Risk-based calculation
    RiskBased = 2,
    /// Tiered pricing based on coverage tiers
    Tiered = 3,
}

/// Coverage type specification
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageType {
    /// Full coverage for specified risks
    Full = 0,
    /// Partial coverage with specified limits
    Partial = 1,
    /// Excess coverage above deductible
    Excess = 2,
}

/// Customization parameter types
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CustomParam {
    /// Integer parameter (e.g., coverage limit, duration)
    Integer((Symbol, i128, i128, i128)),
    /// Decimal parameter (e.g., premium rate, deductible percentage)
    Decimal((Symbol, i128, i128, i128)),
    /// Boolean parameter (e.g., additional coverage options)
    Boolean((Symbol, bool)),
    /// Choice parameter from predefined options
    Choice((Symbol, Vec<Symbol>, u32)),
}

/// Product template definition
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductTemplate {
    /// Unique template identifier
    pub id: u64,
    /// Template name
    pub name: Symbol,
    /// Template description
    pub description: Symbol,
    /// Product category
    pub category: ProductCategory,
    /// Current template status
    pub status: TemplateStatus,
    /// Risk level classification
    pub risk_level: RiskLevel,
    /// Premium calculation model
    pub premium_model: PremiumModel,
    /// Coverage type
    pub coverage_type: CoverageType,
    /// Minimum coverage amount allowed
    pub min_coverage: i128,
    /// Maximum coverage amount allowed
    pub max_coverage: i128,
    /// Minimum policy duration in days
    pub min_duration_days: u32,
    /// Maximum policy duration in days
    pub max_duration_days: u32,
    /// Base premium rate (basis points, 0-10000)
    pub base_premium_rate_bps: u32,
    /// Minimum deductible amount
    pub min_deductible: i128,
    /// Maximum deductible amount
    pub max_deductible: i128,
    /// Required collateral ratio (basis points, 0-10000)
    pub collateral_ratio_bps: u32,
    /// Customizable parameters
    pub custom_params: Vec<CustomParam>,
    /// Creator/administrator address
    pub creator: Address,
    /// Timestamp when template was created
    pub created_at: u64,
    /// Timestamp of last update
    pub updated_at: u64,
    /// Version number for template updates
    pub version: u32,
}

/// Custom parameter values for a specific policy instance
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomParamValue {
    /// Parameter name
    pub name: Symbol,
    /// Parameter value
    pub value: CustomParamValueData,
}

/// Custom parameter value data
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CustomParamValueData {
    /// Integer value
    Integer(i128),
    /// Decimal value
    Decimal(i128),
    /// Boolean value
    Boolean(bool),
    /// Choice index
    Choice(u32),
}

/// Policy instance created from a template
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplatePolicy {
    /// Policy identifier
    pub policy_id: u64,
    /// Template ID this policy was created from
    pub template_id: u64,
    /// Policy holder address
    pub holder: Address,
    /// Selected coverage amount
    pub coverage_amount: i128,
    /// Calculated premium amount
    pub premium_amount: i128,
    /// Policy duration in days
    pub duration_days: u32,
    /// Selected deductible amount
    pub deductible: i128,
    /// Custom parameter values
    pub custom_values: Vec<CustomParamValue>,
    /// Timestamp when policy was created
    pub created_at: u64,
    /// Timestamp when policy starts
    pub start_time: u64,
    /// Timestamp when policy expires
    pub end_time: u64,
}

/// Template validation rules
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplateValidationRules {
    /// Minimum required collateral ratio (basis points)
    pub min_collateral_ratio_bps: u32,
    /// Maximum allowed premium rate (basis points)
    pub max_premium_rate_bps: u32,
    /// Minimum policy duration
    pub min_duration_days: u32,
    /// Maximum policy duration
    pub max_duration_days: u32,
    /// Required governance approval threshold for new templates
    pub approval_threshold_bps: u32,
    /// Minimum time between template updates (seconds)
    pub min_update_interval: u64,
}

// ===== Cross-Chain Types =====

/// Status of a cross-chain message
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossChainMessageStatus {
    /// Message has been sent/queued
    Pending = 0,
    /// Message has been confirmed by validators
    Confirmed = 1,
    /// Message has been executed on target chain
    Executed = 2,
    /// Message has failed execution
    Failed = 3,
    /// Message has expired
    Expired = 4,
}

/// Types of cross-chain messages
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossChainMessageType {
    /// Asset transfer between chains
    AssetTransfer = 0,
    /// Governance action across chains
    GovernanceAction = 1,
    /// Data synchronization between chains
    DataSync = 2,
    /// Insurance claim across chains
    InsuranceClaim = 3,
    /// Policy update across chains
    PolicyUpdate = 4,
}

/// Status of a registered bridge
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeStatus {
    /// Bridge is active and operational
    Active = 0,
    /// Bridge is temporarily paused
    Paused = 1,
    /// Bridge has been deprecated
    Deprecated = 2,
    /// Bridge has been deactivated
    Inactive = 3,
}

// ===== Common Enums for Storage Keys =====

/// Data key enumeration for contract storage
///
/// These are used to organize data in contract storage in a type-safe way.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// Admin address key
    Admin,

    /// Paused state key
    Paused,

    /// General configuration key
    Config,

    /// Counter for various entities (Symbol → counter value)
    Counter,

    /// Policy by ID
    Policy,

    /// Claim by ID
    Claim,

    /// Governance proposal by ID
    Proposal,

    /// Claim evidence by claim ID
    ClaimEvidence,

    /// Oracle configuration
    OracleConfig,

    /// Treasury fund
    Treasury,

    /// Risk pool state
    RiskPool,

    /// Validator information
    Validator,

    /// Slashing record
    SlashingRecord,

    /// Authorization role
    AuthRole,
    /// Product template by ID
    ProductTemplate,
    /// Template counter
    TemplateCounter,
    /// Template policy by ID
    TemplatePolicy,
    /// Template policy counter
    TemplatePolicyCounter,
    /// Template validation rules
    TemplateValidationRules,
    /// Template status history
    TemplateStatusHistory,
    /// Cross-chain bridge registration
    CrossChainBridge,
    /// Cross-chain message
    CrossChainMessage,
    /// Cross-chain asset mapping
    CrossChainAssetMap,
    /// Cross-chain validator
    CrossChainValidator,
    /// Cross-chain governance proposal
    CrossChainProposal,
    /// Cross-chain counter
    CrossChainCounter,
    /// Asset registry storage
    AssetRegistry,
    /// Asset metadata by asset
    AssetMetadata,
    /// Asset conversion rate
    AssetConversionRate,
    /// Multi-asset balance
    MultiAssetBalance,
    /// Policy asset configuration
    PolicyAssetConfig,
    /// Asset balance by (owner, asset)
    AssetBalance,
    /// Governance staking information
    GovernanceStake,
    /// Governance reward configuration
    GovernanceRewardConfig,
    /// Governance staking statistics
    GovernanceStakingStats,
    /// Privacy/ZKP related data
    PrivacyProof,
    /// Confidential claim data
    ConfidentialClaim,
}

// ===== Governance Staking Types =====

/// Staking information for a governance participant
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StakeInfo {
    /// Staker address
    pub staker: Address,
    /// Amount of governance tokens staked
    pub amount: i128,
    /// Timestamp when stake was created
    pub staked_at: u64,
    /// Timestamp of last reward calculation
    pub last_claim_at: u64,
    /// Accumulated rewards not yet claimed
    pub pending_rewards: i128,
    /// Whether the stake is currently locked
    pub is_locked: bool,
    /// Unlock timestamp (if unstaking)
    pub unlock_at: Option<u64>,
    /// Voting power multiplier (based on stake duration)
    pub voting_power_multiplier: u32,
}

/// Reward distribution configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardConfig {
    /// Reward token contract address
    pub reward_token: Address,
    /// Base reward rate per staked token per second (in basis points)
    pub base_reward_rate_bps: u32,
    /// Bonus rate for long-term stakers (additional bps per year locked)
    pub loyalty_bonus_bps: u32,
    /// Minimum staking period for rewards (seconds)
    pub min_stake_period: u64,
    /// Unstaking cooldown period (seconds)
    pub unstake_cooldown: u64,
    /// Whether rewards are currently enabled
    pub rewards_enabled: bool,
    /// Total reward pool allocated
    pub total_reward_pool: i128,
    /// Remaining rewards in pool
    pub remaining_rewards: i128,
    /// Last update timestamp
    pub last_update: u64,
}

/// Governance staking statistics
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StakingStats {
    /// Total number of active stakers
    pub total_stakers: u32,
    /// Total amount staked
    pub total_staked: i128,
    /// Total rewards distributed
    pub total_rewards_distributed: i128,
    /// Average stake duration (seconds)
    pub avg_stake_duration: u64,
    /// Timestamp of last update
    pub last_update: u64,
}

/// Staking position for a user
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StakingPosition {
    /// User address
    pub user: Address,
    /// Staked amount
    pub staked_amount: i128,
    /// Reward debt for accurate reward calculation
    pub reward_debt: i128,
    /// When staking started
    pub stake_start_time: u64,
    /// Lock period end (0 if no lock)
    pub lock_end_time: u64,
    /// Accumulated pending rewards
    pub pending_rewards: i128,
}

/// Vote delegation information
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteDelegation {
    /// Delegator address
    pub delegator: Address,
    /// Delegatee address (who receives voting power)
    pub delegatee: Address,
    /// Amount of voting power delegated
    pub amount: i128,
    /// When delegation was created
    pub delegated_at: u64,
    /// Whether delegation is active
    pub is_active: bool,
}

// ===== Privacy / ZKP Types =====

/// Zero-knowledge proof for private claim verification
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkProof {
    /// Proof identifier (hash of proof data)
    pub proof_id: BytesN<32>,
    /// Circuit identifier (which verification circuit was used)
    pub circuit_id: Symbol,
    /// Public inputs for verification
    pub public_inputs: Vec<i128>,
    /// Verification key hash
    pub vk_hash: BytesN<32>,
    /// Proof timestamp
    pub created_at: u64,
    /// Proof expiration (if applicable)
    pub expires_at: Option<u64>,
}

/// Privacy settings for a user
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacySettings {
    /// User address
    pub user: Address,
    /// Whether privacy mode is enabled
    pub privacy_enabled: bool,
    /// Preferred privacy level (1-3)
    pub privacy_level: u32,
    /// Encryption public key (for confidential data)
    pub encryption_key: Option<BytesN<32>>,
    /// Data retention period in days
    pub retention_days: u32,
    /// Whether data can be shared with regulators
    pub regulatory_compliance: bool,
    /// Last updated timestamp
    pub updated_at: u64,
}

/// Confidential claim data (encrypted/hashed)
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfidentialClaim {
    /// Claim identifier
    pub claim_id: u64,
    /// Policy ID (public)
    pub policy_id: u64,
    /// Claimant address (public)
    pub claimant: Address,
    /// Encrypted claim amount (only claimant and validator can decrypt)
    pub encrypted_amount: BytesN<32>,
    /// Commitment hash of claim details
    pub commitment_hash: BytesN<32>,
    /// ZK proof ID for claim validity (empty if no proof)
    pub validity_proof_id: BytesN<32>,
    /// Proof of coverage (without revealing policy details)
    pub coverage_proof: BytesN<32>,
    /// Timestamp
    pub submitted_at: u64,
    /// Privacy level used
    pub privacy_level: u32,
}

/// Private policy data (encrypted)
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivatePolicyData {
    /// Policy identifier
    pub policy_id: u64,
    /// Policy holder
    pub holder: Address,
    /// Encrypted coverage amount
    pub encrypted_coverage: BytesN<32>,
    /// Encrypted premium amount
    pub encrypted_premium: BytesN<32>,
    /// Policy commitment hash
    pub policy_commitment: BytesN<32>,
    /// ZK proof ID of valid policy (empty if no proof)
    pub policy_proof_id: BytesN<32>,
    /// Created timestamp
    pub created_at: u64,
}

/// Verification result for ZKP
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZkVerificationResult {
    /// Proof is valid
    Valid = 0,
    /// Proof is invalid
    Invalid = 1,
    /// Proof has expired
    Expired = 2,
    /// Circuit not recognized
    UnknownCircuit = 3,
    /// Verification failed due to error
    VerificationFailed = 4,
}

/// Privacy proof record for storage
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyProof {
    /// Proof ID
    pub proof_id: BytesN<32>,
    /// Associated claim or policy ID
    pub entity_id: u64,
    /// Entity type (claim, policy, etc.)
    pub entity_type: Symbol,
    /// ZK proof data
    pub zk_proof: ZkProof,
    /// Verification result
    pub verification_result: ZkVerificationResult,
    /// Verified at timestamp
    pub verified_at: Option<u64>,
    /// Verifier address
    pub verifier: Option<Address>,
}

/// Regulatory compliance record (for audits)
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComplianceRecord {
    /// Record ID
    pub record_id: u64,
    /// Entity type (claim, policy)
    pub entity_type: Symbol,
    /// Entity ID
    pub entity_id: u64,
    /// Compliance check type
    pub check_type: Symbol,
    /// Whether compliant
    pub is_compliant: bool,
    /// Encrypted compliance data (for regulators)
    pub encrypted_data: Option<BytesN<32>>,
    /// Timestamp
    pub checked_at: u64,
    /// Auditor address (if applicable)
    pub auditor: Option<Address>,
}

// ===== DID (Decentralized Identity) Types =====

/// DID Document structure following W3C DID Core specification
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidDocument {
    /// DID identifier
    pub id: soroban_sdk::String,
    /// List of DIDs that can control this document
    pub controller: Vec<soroban_sdk::String>,
    /// Verification methods (public keys, etc.)
    pub verification_method: Vec<VerificationMethod>,
    /// Authentication verification method references
    pub authentication: Vec<soroban_sdk::String>,
    /// Assertion method verification method references
    pub assertion_method: Vec<soroban_sdk::String>,
    /// Key agreement verification method references
    pub key_agreement: Vec<soroban_sdk::String>,
    /// Capability invocation verification method references
    pub capability_invocation: Vec<soroban_sdk::String>,
    /// Capability delegation verification method references
    pub capability_delegation: Vec<soroban_sdk::String>,
    /// Service endpoints
    pub service: Vec<DidService>,
    /// Document creation timestamp
    pub created_at: u64,
    /// Document last updated timestamp
    pub updated_at: u64,
    /// Document version ID
    pub version_id: u64,
}

/// Verification method for DID documents
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationMethod {
    /// Verification method ID
    pub id: soroban_sdk::String,
    /// Verification method type (e.g., "Ed25519VerificationKey2018")
    pub type_: soroban_sdk::String,
    /// Controller DID
    pub controller: soroban_sdk::String,
    /// Public key in base58 format
    pub public_key_base58: Option<soroban_sdk::String>,
    /// Public key in JWK format
    pub public_key_jwk: Option<PublicKeyJwk>,
}

/// JSON Web Key representation
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyJwk {
    /// Key type
    pub kty: soroban_sdk::String,
    /// Curve name
    pub crv: Option<soroban_sdk::String>,
    /// X coordinate
    pub x: Option<soroban_sdk::String>,
    /// Y coordinate
    pub y: Option<soroban_sdk::String>,
    /// Key usage
    pub use_: Option<soroban_sdk::String>,
}

/// DID Service endpoint
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidService {
    /// Service ID
    pub id: soroban_sdk::String,
    /// Service type
    pub type_: soroban_sdk::String,
    /// Service endpoint URL
    pub service_endpoint: soroban_sdk::String,
    /// Additional service properties
    pub properties: Vec<ServiceProperty>,
}

/// Service property key-value pair
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceProperty {
    /// Property key
    pub key: soroban_sdk::String,
    /// Property value
    pub value: soroban_sdk::String,
}

/// Identity verification record
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityVerification {
    /// Verification ID
    pub verification_id: u64,
    /// DID being verified
    pub did: soroban_sdk::String,
    /// Verifier address
    pub verifier: Address,
    /// Verification type
    pub verification_type: Symbol,
    /// Verification level (1-5)
    pub verification_level: u32,
    /// List of verified attributes
    pub verified_attributes: Vec<soroban_sdk::String>,
    /// Verification expiration timestamp
    pub expires_at: u64,
    /// Verification timestamp
    pub verified_at: u64,
    /// Hash of verification proof
    pub proof_hash: BytesN<32>,
    /// Whether verification is revoked
    pub is_revoked: bool,
}

/// KYC record for regulatory compliance
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KycRecord {
    /// KYC record ID
    pub kyc_id: u64,
    /// DID being KYC'd
    pub did: soroban_sdk::String,
    /// KYC provider address
    pub kyc_provider: Address,
    /// KYC level (1-4)
    pub kyc_level: u32,
    /// Risk score (1-100, lower = lower risk)
    pub risk_score: u32,
    /// Jurisdiction code
    pub jurisdiction: soroban_sdk::String,
    /// KYC verification timestamp
    pub verified_at: u64,
    /// KYC expiration timestamp
    pub expires_at: u64,
    /// Hash of compliance data
    pub compliance_data_hash: BytesN<32>,
    /// Whether KYC is active
    pub is_active: bool,
    /// Whether AML screening passed
    pub aml_screening_passed: bool,
}

/// Zero-knowledge identity proof
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkIdentityProof {
    /// Proof ID
    pub proof_id: BytesN<32>,
    /// DID this proof belongs to
    pub did: soroban_sdk::String,
    /// Circuit ID used for proof
    pub circuit_id: Symbol,
    /// Public inputs for the proof
    pub public_inputs: Vec<soroban_sdk::String>,
    /// Proof data
    pub proof_data: BytesN<32>,
    /// Hash of verification key
    pub verification_key_hash: BytesN<32>,
    /// Proof creation timestamp
    pub created_at: u64,
    /// Proof expiration timestamp
    pub expires_at: u64,
    /// Whether proof is revoked
    pub is_revoked: bool,
}

/// DID resolution result
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidResolutionResult {
    /// Resolved DID document
    pub did_document: DidDocument,
    /// Resolver metadata
    pub resolver_metadata: Vec<MetadataProperty>,
    /// DID method metadata
    pub method_metadata: Vec<MetadataProperty>,
}

/// Metadata property key-value pair
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataProperty {
    /// Property key
    pub key: soroban_sdk::String,
    /// Property value
    pub value: soroban_sdk::String,
}
