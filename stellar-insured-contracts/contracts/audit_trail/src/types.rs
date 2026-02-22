#![no_std]

use soroban_sdk::{contracttype, Address, Bytes, String, Symbol};

/// Categories of auditable actions in the insurance platform
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionCategory {
    // Policy lifecycle
    PolicyCreated,
    PolicyUpdated,
    PolicyCancelled,
    PolicyRenewed,
    PolicyExpired,
    // Claims
    ClaimSubmitted,
    ClaimApproved,
    ClaimRejected,
    ClaimPaid,
    ClaimEscalated,
    // Payments & Premiums
    PremiumPaid,
    PremiumRefunded,
    PaymentFailed,
    // KYC / Compliance
    KycVerified,
    KycRejected,
    KycDocumentSubmitted,
    // Access & Admin
    AdminActionTaken,
    RoleAssigned,
    RoleRevoked,
    ContractUpgraded,
    // Risk & Underwriting
    RiskAssessed,
    UnderwritingDecision,
    // Regulatory
    RegulatoryReportGenerated,
    DataExported,
    AuditQueried,
}

/// Severity level for compliance classification
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Compliance status of an audit entry
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComplianceStatus {
    Compliant,
    PendingReview,
    Flagged,
    Exempted,
}

/// A single immutable audit log entry
#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditEntry {
    /// Unique sequential ID
    pub entry_id: u64,
    /// Ledger sequence when recorded
    pub ledger: u32,
    /// Unix timestamp (seconds)
    pub timestamp: u64,
    /// Actor who performed the action
    pub actor: Address,
    /// Subject of the action (e.g., policy holder, claim ID)
    pub subject: Bytes,
    /// Action performed
    pub action: ActionCategory,
    /// Source contract or module
    pub source_contract: Address,
    /// Keccak/SHA-256 hash of associated data for integrity
    pub data_hash: Bytes,
    /// Human-readable description
    pub description: String,
    /// Severity classification
    pub severity: Severity,
    /// Compliance status at time of recording
    pub compliance_status: ComplianceStatus,
    /// Optional reference to related entry (e.g., approval references submission)
    pub related_entry_id: Option<u64>,
    /// Metadata key-value pairs encoded as bytes
    pub metadata: Bytes,
}

/// Compliance report summary
#[contracttype]
#[derive(Clone, Debug)]
pub struct ComplianceReport {
    pub report_id: u64,
    pub generated_at: u64,
    pub generated_by: Address,
    pub period_start: u64,
    pub period_end: u64,
    pub total_entries: u32,
    pub compliant_count: u32,
    pub flagged_count: u32,
    pub pending_review_count: u32,
    pub critical_events: u32,
    pub categories_covered: Bytes, // Serialized list of ActionCategory variants present
    pub report_hash: Bytes,        // Hash of the full report for integrity
}

/// Query filter for audit trail searches
#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditFilter {
    pub actor: Option<Address>,
    pub action: Option<ActionCategory>,
    pub severity: Option<Severity>,
    pub compliance_status: Option<ComplianceStatus>,
    pub from_timestamp: Option<u64>,
    pub to_timestamp: Option<u64>,
    pub from_entry_id: u64,
    pub limit: u32,
}

/// External audit system registration
#[contracttype]
#[derive(Clone, Debug)]
pub struct ExternalAuditor {
    pub auditor_address: Address,
    pub name: String,
    pub registered_at: u64,
    pub is_active: bool,
    pub permissions: AuditorPermissions,
}

/// Permissions granted to an external auditor
#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditorPermissions {
    pub can_query: bool,
    pub can_export: bool,
    pub can_generate_reports: bool,
    pub can_flag_entries: bool,
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    Admin,
    EntryCount,
    Entry(u64),
    ReportCount,
    Report(u64),
    ExternalAuditor(Address),
    // Index: action category -> list of entry IDs
    ActionIndex(u8),
    // Index: actor -> latest entry ID for efficient lookups
    ActorLatest(Address),
    // Index: ledger -> entry ID (for time-based queries)
    LedgerIndex(u32),
    // Authorized caller contracts
    AuthorizedCaller(Address),
}