#![no_std]
//! # Shared Insurance Contracts Library
//!
//! A comprehensive library providing reusable types, errors, constants, and validation
//! helpers for all Stellar Insured Soroban contracts.
//!
//! ## Modules
//!
//! - `errors`     – Common error types used across contracts
//! - `types`      – Shared data types and enums (PolicyStatus, ClaimStatus, etc.)
//! - `constants`  – Configuration constants for validation and limits
//! - `validation` – Centralized, domain-specific validation helper functions
//!
//! ## Usage
//!
//! Import the shared library in your contract's Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! shared = { path = "shared" }
//! ```
//!
//! Then use it in your code:
//!
//! ```rust,ignore
//! use shared::errors::ContractError;
//! use shared::types::{PolicyStatus, ClaimStatus};
//! use shared::validation::{validate_policy_params, validate_claim_params};
//! use shared::constants::MIN_COVERAGE_AMOUNT;
//! ```

pub mod errors;
pub mod types;
pub mod constants;
pub mod validation;
pub mod versioning;
pub mod upgradeable;
pub mod gas_optimization;
pub mod emergency_pause;

// Re-export commonly used types
pub use errors::ContractError;
pub use types::{
    PolicyStatus, ClaimStatus, ProposalStatus, ProposalType, VoteType,
    RiskPoolStatus, ClaimEvidence, VoteRecord, OracleConfig, RiskMetrics,
    PolicyMetadata, ClaimMetadata, TreasuryAllocation, DataKey,
    CrossChainMessageStatus, CrossChainMessageType, BridgeStatus,
    // Governance staking types
    RewardConfig, StakeInfo, StakingPosition, StakingStats, VoteDelegation,
    // Privacy/ZKP types
    ZkProof, PrivacySettings, ConfidentialClaim, PrivatePolicyData,
    ZkVerificationResult, PrivacyProof, ComplianceRecord,
    // DID (Decentralized Identity) types
    DidDocument, VerificationMethod, PublicKeyJwk, DidService, ServiceProperty,
    IdentityVerification, KycRecord, ZkIdentityProof, DidResolutionResult,
    MetadataProperty,
};

// Re-export all validation helpers (grouped by domain)
pub use validation::{
    // Address
    validate_address,
    validate_addresses,
    validate_addresses_different,
    validate_non_zero_address,

    // Amount
    validate_positive_amount,
    validate_non_negative_amount,
    validate_amount_in_bounds,
    validate_coverage_amount,
    validate_premium_amount,
    validate_claim_amount,
    validate_deposit_amount,
    validate_withdrawal_amount,
    validate_allocation_amount,
    validate_sufficient_funds,

    // Time / Duration
    validate_future_timestamp,
    validate_past_timestamp,
    validate_time_range,
    validate_duration_days,
    validate_voting_duration,

    // Percentage / Basis Points
    validate_percentage,
    validate_basis_points,
    validate_oracle_deviation,
    validate_quorum_percent,
    validate_voting_threshold,
    validate_reserve_ratio,

    // Contract State
    validate_not_paused,
    validate_initialized,
    validate_not_initialized,

    // Evidence & String Sanitization
    validate_evidence_hash,
    validate_bytes_length,
    validate_string_length,
    validate_metadata,
    validate_description,
    validate_proposal_title,

    // Governance Proposal
    validate_proposal_params,

    // Oracle
    validate_oracle_submissions,
    validate_oracle_data_age,
    validate_min_oracle_submissions,

    // Slashing
    validate_slashing_amount,
    validate_slashing_percent,

    // Pagination
    validate_pagination,

    // Safe arithmetic
    safe_add,
    safe_sub,
    safe_mul,
    safe_div,

    // Batch & Calculation helpers
    validate_all,
    calculate_percentage,
    calculate_basis_points,
    calculate_reserve_ratio,

    // Domain-level composite validators
    validate_policy_params,
    validate_claim_params,
    validate_risk_pool_init_params,
};

pub use gas_optimization::{
    GasOptimizer,
    OptimizedStructures,
    PerformanceMonitor,
    GasMeasurement,
    GasMetrics,
    StorageOptimization,
    OptimizedDataKey,
};

pub use emergency_pause::{
    EmergencyPause,
    EmergencyPauseConfig,
    EmergencyPauseEvent,
};

pub use versioning::{
    VersionManager, VersioningError, VersionInfo, VersionTransition,
    MigrationState, migration_state_to_u32, u32_to_migration_state,
};
pub use upgradeable::UpgradeableContract;
