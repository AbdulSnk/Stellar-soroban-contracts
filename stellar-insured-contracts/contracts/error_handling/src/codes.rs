#![no_std]

use soroban_sdk::contracterror;

/// Unified error codes shared across all insurance platform contracts.
///
/// Ranges:
///   1–99    Auth & Access
///   100–199 Policy
///   200–299 Claims
///   300–399 Payments & Premiums
///   400–499 KYC / Compliance
///   500–599 Data / Storage
///   600–699 Oracle / External
///   700–799 System / Config
#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum InsuranceError {
    // ── Auth & Access (1–99) ─────────────────────────────────────────────────
    /// Caller has not been granted any role on this contract
    Unauthorized = 1,
    /// Caller's role does not permit this specific action
    InsufficientPermissions = 2,
    /// Auth token or session has expired
    AuthExpired = 3,
    /// Contract has already been initialized
    AlreadyInitialized = 4,

    // ── Policy (100–199) ─────────────────────────────────────────────────────
    /// No policy exists with the provided ID
    PolicyNotFound = 100,
    /// Policy is not in a state that allows this action
    PolicyInvalidState = 101,
    /// Policy coverage period has ended
    PolicyExpired = 102,
    /// Policy has already been cancelled
    PolicyAlreadyCancelled = 103,
    /// Proposed coverage amount is outside allowed limits
    PolicyCoverageOutOfRange = 104,

    // ── Claims (200–299) ─────────────────────────────────────────────────────
    /// No claim exists with the provided ID
    ClaimNotFound = 200,
    /// Claim amount exceeds the policy's coverage limit
    ClaimExceedsLimit = 201,
    /// A claim for this event was already submitted
    ClaimDuplicate = 202,
    /// Claim is past the allowed filing deadline
    ClaimDeadlineExceeded = 203,
    /// Claim is in a state that does not allow this action
    ClaimInvalidState = 204,
    /// Required claim documentation is missing
    ClaimMissingDocuments = 205,

    // ── Payments & Premiums (300–399) ────────────────────────────────────────
    /// Provided amount is zero or negative
    PaymentInvalidAmount = 300,
    /// Token or asset type is not accepted
    PaymentUnsupportedAsset = 301,
    /// Premium payment was not received before the deadline
    PremiumPaymentOverdue = 302,
    /// Requested refund amount exceeds what was paid
    RefundExceedsBalance = 303,

    // ── KYC / Compliance (400–499) ───────────────────────────────────────────
    /// Policy holder has not completed KYC
    KycNotVerified = 400,
    /// KYC has expired and must be renewed
    KycExpired = 401,
    /// Submitted KYC documents were rejected
    KycDocumentRejected = 402,
    /// Operation blocked due to regulatory restriction
    ComplianceViolation = 403,

    // ── Data / Storage (500–599) ─────────────────────────────────────────────
    /// Record could not be found in storage
    RecordNotFound = 500,
    /// Provided data fails format or range validation
    InvalidData = 501,
    /// Ledger entry TTL has lapsed
    StorageExpired = 502,

    // ── Oracle / External (600–699) ──────────────────────────────────────────
    /// Oracle has not published data for this feed
    OracleDataMissing = 600,
    /// Oracle data is older than the acceptable staleness window
    OracleDataStale = 601,
    /// Cross-contract call returned an unexpected error
    ExternalCallFailed = 602,

    // ── System / Config (700–799) ────────────────────────────────────────────
    /// Contract is paused for maintenance or emergency
    ContractPaused = 700,
    /// Requested operation is not yet implemented
    NotImplemented = 701,
    /// Numerical overflow detected
    ArithmeticOverflow = 702,
    /// Value exceeds the maximum allowed
    LimitExceeded = 703,
}

impl InsuranceError {
    /// Short machine-readable slug, suitable for logs and monitoring.
    pub fn code(&self) -> u32 {
        *self as u32
    }

    /// Human-readable description of what went wrong.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Unauthorized            => "Caller is not authorized on this contract",
            Self::InsufficientPermissions => "Caller's role does not allow this action",
            Self::AuthExpired             => "Authorization has expired; please re-authenticate",
            Self::AlreadyInitialized      => "Contract has already been initialized",

            Self::PolicyNotFound          => "No policy found with the given ID",
            Self::PolicyInvalidState      => "Policy is in a state that does not permit this action",
            Self::PolicyExpired           => "Policy coverage period has ended",
            Self::PolicyAlreadyCancelled  => "Policy has already been cancelled",
            Self::PolicyCoverageOutOfRange => "Coverage amount is outside the permitted range",

            Self::ClaimNotFound           => "No claim found with the given ID",
            Self::ClaimExceedsLimit       => "Claim amount exceeds the policy coverage limit",
            Self::ClaimDuplicate          => "A claim for this event already exists",
            Self::ClaimDeadlineExceeded   => "Claim was submitted past the filing deadline",
            Self::ClaimInvalidState       => "Claim is in a state that does not permit this action",
            Self::ClaimMissingDocuments   => "Required documentation for the claim is missing",

            Self::PaymentInvalidAmount    => "Payment amount must be greater than zero",
            Self::PaymentUnsupportedAsset => "This asset type is not accepted for payment",
            Self::PremiumPaymentOverdue   => "Premium payment is past the due date",
            Self::RefundExceedsBalance    => "Refund amount exceeds the available balance",

            Self::KycNotVerified          => "Policy holder has not completed identity verification",
            Self::KycExpired              => "Identity verification has expired and must be renewed",
            Self::KycDocumentRejected     => "Submitted KYC documents were not accepted",
            Self::ComplianceViolation     => "Operation is blocked by a regulatory restriction",

            Self::RecordNotFound          => "The requested record does not exist in storage",
            Self::InvalidData             => "Provided data is malformed or out of range",
            Self::StorageExpired          => "Storage entry has expired; re-submit the data",

            Self::OracleDataMissing       => "Oracle has not published data for this feed",
            Self::OracleDataStale         => "Oracle data is too old to be used for this operation",
            Self::ExternalCallFailed      => "A required external contract call failed",

            Self::ContractPaused          => "Contract is paused; try again later",
            Self::NotImplemented          => "This feature is not yet available",
            Self::ArithmeticOverflow      => "Calculation resulted in an overflow",
            Self::LimitExceeded           => "Value exceeds the maximum allowed limit",
        }
    }

    /// Suggested recovery action for the caller.
    pub fn hint(&self) -> &'static str {
        match self {
            Self::Unauthorized            => "Request access from the contract admin",
            Self::InsufficientPermissions => "Check which role is required and request it from admin",
            Self::AuthExpired             => "Re-authenticate and retry the operation",
            Self::AlreadyInitialized      => "No action needed; contract is ready",

            Self::PolicyNotFound          => "Verify the policy ID and try again",
            Self::PolicyInvalidState      => "Check the policy lifecycle state before retrying",
            Self::PolicyExpired           => "Renew the policy before attempting this action",
            Self::PolicyAlreadyCancelled  => "Create a new policy if coverage is still required",
            Self::PolicyCoverageOutOfRange => "Adjust the coverage amount to within allowed limits",

            Self::ClaimNotFound           => "Verify the claim ID and try again",
            Self::ClaimExceedsLimit       => "Reduce the claim amount to within coverage limits",
            Self::ClaimDuplicate          => "Retrieve the existing claim instead of submitting a new one",
            Self::ClaimDeadlineExceeded   => "Contact support for late-filing assistance",
            Self::ClaimInvalidState       => "Check the claim status before retrying",
            Self::ClaimMissingDocuments   => "Upload the required documents and resubmit",

            Self::PaymentInvalidAmount    => "Provide a positive payment amount",
            Self::PaymentUnsupportedAsset => "Use an accepted asset (e.g., USDC)",
            Self::PremiumPaymentOverdue   => "Pay the overdue premium to reinstate the policy",
            Self::RefundExceedsBalance    => "Request a refund of at most the paid balance",

            Self::KycNotVerified          => "Complete KYC verification to proceed",
            Self::KycExpired              => "Renew identity verification to continue",
            Self::KycDocumentRejected     => "Resubmit corrected documents for review",
            Self::ComplianceViolation     => "Contact compliance team to resolve the restriction",

            Self::RecordNotFound          => "Confirm the ID is correct and retry",
            Self::InvalidData             => "Validate all field formats and ranges before retrying",
            Self::StorageExpired          => "Re-submit the data to refresh the storage entry",

            Self::OracleDataMissing       => "Wait for the oracle to publish and retry",
            Self::OracleDataStale         => "Wait for a fresh oracle update and retry",
            Self::ExternalCallFailed      => "Check the external contract status and retry",

            Self::ContractPaused          => "Monitor for a resume announcement and retry later",
            Self::NotImplemented          => "Use an alternative method or wait for the next release",
            Self::ArithmeticOverflow      => "Reduce the input values and retry",
            Self::LimitExceeded           => "Reduce the value to within the allowed limit",
        }
    }

    /// Whether this error is transient (safe to retry automatically).
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::OracleDataMissing
                | Self::OracleDataStale
                | Self::ExternalCallFailed
                | Self::ContractPaused
        )
    }

    /// Whether this error requires human intervention before retrying.
    pub fn requires_manual_action(&self) -> bool {
        matches!(
            self,
            Self::KycNotVerified
                | Self::KycExpired
                | Self::KycDocumentRejected
                | Self::ComplianceViolation
                | Self::ClaimMissingDocuments
                | Self::ClaimDeadlineExceeded
        )
    }
}