#![no_std]

use soroban_sdk::{contracttype, Address, String};

/// How serious the error is.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorSeverity {
    /// Informational — no immediate action required
    Info,
    /// Unexpected but non-blocking
    Warning,
    /// Operation failed; caller must take action
    Error,
    /// System-level failure; requires operator intervention
    Critical,
}

/// What action was taken (or should be taken) to recover.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    /// No recovery needed or possible
    None,
    /// Operation was retried automatically and succeeded
    AutoRetried,
    /// State was rolled back to the last known-good snapshot
    StateRolledBack,
    /// Contract was paused pending operator review
    ContractPaused,
    /// Funds were redirected to the escrow/fallback address
    FundsEscrowed,
    /// Operator must intervene manually
    ManualInterventionRequired,
}

/// Current status of a recovery attempt.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryStatus {
    Pending,
    Resolved,
    Failed,
    EscalatedToOperator,
}

/// A single error event recorded in the on-chain error log.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ErrorEntry {
    pub entry_id: u64,
    pub error_code: u32,
    pub severity: ErrorSeverity,
    pub source_contract: Address,
    pub caller: Address,
    pub ledger: u32,
    pub timestamp: u64,
    /// Static message from InsuranceError::message()
    pub message: String,
    /// Static hint from InsuranceError::hint()
    pub hint: String,
    pub recovery_action: RecoveryAction,
    pub recovery_status: RecoveryStatus,
    /// Optional ID in the domain object that was involved (policy, claim, etc.)
    pub subject_id: Option<u64>,
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    Admin,
    Paused,
    ErrorCount,
    Error(u64),
    AuthorizedReporter(Address),
}