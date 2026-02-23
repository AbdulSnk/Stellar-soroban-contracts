#![no_std]

//! Integration helper for other contracts to log audit events.
//!
//! This module provides convenient traits and functions for contracts
//! to integrate with the audit trail system.

use soroban_sdk::{Address, Bytes, Env, String};

use crate::{
    errors::AuditError,
    types::{ActionCategory, Severity},
    AuditTrailContractClient,
};

/// Trait for contracts that can log audit events.
/// Implement this trait to enable audit logging in your contract.
pub trait Auditable {
    /// Get the audit trail contract address
    fn audit_trail_address(&self, env: &Env) -> Address;

    /// Log an audit event
    fn log_audit_event(
        &self,
        env: &Env,
        actor: Address,
        subject: Bytes,
        action: ActionCategory,
        data_hash: Bytes,
        description: String,
        severity: Severity,
        related_entry_id: Option<u64>,
        metadata: Bytes,
    ) -> Result<u64, AuditError> {
        let audit_client = AuditTrailContractClient::new(env, &self.audit_trail_address(env));
        audit_client.log_entry(
            &actor,
            &subject,
            &action,
            &env.current_contract_address(),
            &data_hash,
            &description,
            &severity,
            &related_entry_id,
            &metadata,
        )
    }

    /// Log a critical audit event
    fn log_critical_event(
        &self,
        env: &Env,
        actor: Address,
        subject: Bytes,
        action: ActionCategory,
        data_hash: Bytes,
        description: String,
        metadata: Bytes,
    ) -> Result<u64, AuditError> {
        let audit_client = AuditTrailContractClient::new(env, &self.audit_trail_address(env));
        audit_client.log_critical_entry(
            &actor,
            &subject,
            &action,
            &env.current_contract_address(),
            &data_hash,
            &description,
            &metadata,
        )
    }
}

/// Helper struct for direct audit logging without implementing a trait.
pub struct AuditLogger;

impl AuditLogger {
    /// Log a policy creation event
    pub fn log_policy_created(
        env: &Env,
        audit_trail: &Address,
        actor: &Address,
        policy_id: &Bytes,
        data_hash: &Bytes,
        description: &str,
    ) -> Result<u64, AuditError> {
        let client = AuditTrailContractClient::new(env, audit_trail);
        client.log_entry(
            actor,
            policy_id,
            &ActionCategory::PolicyCreated,
            &env.current_contract_address(),
            data_hash,
            &String::from_str(env, description),
            &Severity::Info,
            &None,
            &Bytes::new(env),
        )
    }

    /// Log a claim submission event
    pub fn log_claim_submitted(
        env: &Env,
        audit_trail: &Address,
        actor: &Address,
        claim_id: &Bytes,
        data_hash: &Bytes,
        description: &str,
    ) -> Result<u64, AuditError> {
        let client = AuditTrailContractClient::new(env, audit_trail);
        client.log_entry(
            actor,
            claim_id,
            &ActionCategory::ClaimSubmitted,
            &env.current_contract_address(),
            data_hash,
            &String::from_str(env, description),
            &Severity::Warning,
            &None,
            &Bytes::new(env),
        )
    }

    /// Log a claim approval event
    pub fn log_claim_approved(
        env: &Env,
        audit_trail: &Address,
        actor: &Address,
        claim_id: &Bytes,
        submission_entry_id: u64,
        data_hash: &Bytes,
        description: &str,
    ) -> Result<u64, AuditError> {
        let client = AuditTrailContractClient::new(env, audit_trail);
        client.log_entry(
            actor,
            claim_id,
            &ActionCategory::ClaimApproved,
            &env.current_contract_address(),
            data_hash,
            &String::from_str(env, description),
            &Severity::Info,
            &Some(submission_entry_id),
            &Bytes::new(env),
        )
    }

    /// Log a premium payment event
    pub fn log_premium_paid(
        env: &Env,
        audit_trail: &Address,
        actor: &Address,
        policy_id: &Bytes,
        data_hash: &Bytes,
        description: &str,
    ) -> Result<u64, AuditError> {
        let client = AuditTrailContractClient::new(env, audit_trail);
        client.log_entry(
            actor,
            policy_id,
            &ActionCategory::PremiumPaid,
            &env.current_contract_address(),
            data_hash,
            &String::from_str(env, description),
            &Severity::Info,
            &None,
            &Bytes::new(env),
        )
    }

    /// Log an admin action
    pub fn log_admin_action(
        env: &Env,
        audit_trail: &Address,
        actor: &Address,
        subject: &Bytes,
        data_hash: &Bytes,
        description: &str,
    ) -> Result<u64, AuditError> {
        let client = AuditTrailContractClient::new(env, audit_trail);
        client.log_entry(
            actor,
            subject,
            &ActionCategory::AdminActionTaken,
            &env.current_contract_address(),
            data_hash,
            &String::from_str(env, description),
            &Severity::Warning,
            &None,
            &Bytes::new(env),
        )
    }

    /// Log a critical security event
    pub fn log_security_event(
        env: &Env,
        audit_trail: &Address,
        actor: &Address,
        subject: &Bytes,
        data_hash: &Bytes,
        description: &str,
    ) -> Result<u64, AuditError> {
        let client = AuditTrailContractClient::new(env, audit_trail);
        client.log_critical_entry(
            actor,
            subject,
            &ActionCategory::AdminActionTaken,
            &env.current_contract_address(),
            data_hash,
            &String::from_str(env, description),
            &Bytes::new(env),
        )
    }
}

/// Compute a simple data hash from bytes.
/// This is a helper for contracts that need to hash their data before logging.
pub fn compute_data_hash(env: &Env, data: &Bytes) -> Bytes {
    let hash = env.crypto().sha256(data);
    Bytes::from_array(env, &hash.to_array())
}
