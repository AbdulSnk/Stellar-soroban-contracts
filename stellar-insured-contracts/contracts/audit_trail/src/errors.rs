#![no_std]

use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum AuditError {
    // Authorization errors (1-19)
    Unauthorized = 1,
    CallerNotAuthorized = 2,
    AuditorNotRegistered = 3,
    AuditorInactive = 4,
    InsufficientPermissions = 5,

    // Entry errors (20-39)
    EntryNotFound = 20,
    InvalidEntryHash = 21,
    ChainBroken = 22, // Previous entry hash mismatch

    // Query errors (40-59)
    LimitExceeded = 40,
    InvalidTimeRange = 41,
    InvalidFilter = 42,

    // Report errors (60-79)
    ReportNotFound = 60,
    InvalidReportHash = 61,

    // Merkle tree errors (80-99)
    MerkleRootNotFound = 80,
    InvalidProof = 81,
    ProofVerificationFailed = 82,
    BatchTooSmall = 83,
    BatchTooLarge = 84,

    // Retention policy errors (100-119)
    PolicyNotFound = 100,
    InvalidRetentionPeriod = 101,
    PolicyAlreadyExists = 102,
}
