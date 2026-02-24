#![no_std]

mod audit;
mod compliance;
mod crypto;
mod errors;
mod integration;
mod storage;
mod types;

pub use audit::AuditTrailContract;
pub use errors::AuditError;
pub use integration::{Auditable, AuditLogger, compute_data_hash};
pub use types::{
    ActionCategory, AuditEntry, AuditFilter, AuditorPermissions, ComplianceReport,
    ComplianceStatus, EntryProof, ExternalAuditor, MerkleRoot, RetentionPolicy, Severity,
};

#[cfg(test)]
mod test;