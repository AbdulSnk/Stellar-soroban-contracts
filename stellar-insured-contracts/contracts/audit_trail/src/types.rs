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
    /// Hash of the previous entry for chain integrity (32 bytes)
    pub previous_entry_hash: Option<Bytes>,
    /// SHA-256 hash of this entry's content for verification (32 bytes)
    pub entry_hash: Bytes,
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

/// Merkle tree node for batch verification
#[contracttype]
#[derive(Clone, Debug)]
pub struct MerkleNode {
    pub hash: Bytes,
    pub left_child: Option<u64>,
    pub right_child: Option<u64>,
    pub entry_id: Option<u64>, // For leaf nodes
}

/// Merkle tree root for a batch of entries
#[contracttype]
#[derive(Clone, Debug)]
pub struct MerkleRoot {
    pub root_hash: Bytes,
    pub start_entry_id: u64,
    pub end_entry_id: u64,
    pub created_at: u64,
    pub ledger: u32,
}

/// Cryptographic proof for entry verification
#[contracttype]
#[derive(Clone, Debug)]
pub struct EntryProof {
    pub entry_id: u64,
    pub entry_hash: Bytes,
    pub proof_path: Vec<Bytes>, // Sibling hashes from leaf to root
    pub merkle_root: Bytes,
}

/// Retention policy configuration
#[contracttype]
#[derive(Clone, Debug)]
pub struct RetentionPolicy {
    pub policy_id: u64,
    pub severity: Option<Severity>, // None = applies to all
    pub action_category: Option<ActionCategory>, // None = applies to all
    pub retention_period_days: u32,
    pub archive_after_days: u32,
    pub auto_purge: bool,
    pub created_at: u64,
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
    // Index: actor -> list of entry IDs
    ActorIndex(Address),
    // Index: ledger -> entry ID (for time-based queries)
    LedgerIndex(u32),
    // Authorized caller contracts
    AuthorizedCaller(Address),
    // Merkle roots for entry batches
    MerkleRoot(u64), // batch number
    MerkleRootCount,
    // Retention policies
    RetentionPolicy(u64),
    RetentionPolicyCount,
    // Last entry hash for chain
    LastEntryHash,
}