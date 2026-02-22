#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Bytes, Env, String, Vec};

use crate::{
    compliance,
    errors::AuditError,
    storage,
    types::{
        ActionCategory, AuditEntry, AuditFilter, AuditorPermissions, ComplianceReport,
        ComplianceStatus, ExternalAuditor, Severity,
    },
};

#[contract]
pub struct AuditTrailContract;

#[contractimpl]
impl AuditTrailContract {
    // ── Initialization ───────────────────────────────────────────────────────

    /// Initialize the contract with an admin address.
    /// Can only be called once.
    pub fn initialize(env: Env, admin: Address) -> Result<(), AuditError> {
        if storage::has_admin(&env) {
            return Err(AuditError::Unauthorized);
        }
        admin.require_auth();
        storage::set_admin(&env, &admin);

        env.events().publish(
            (soroban_sdk::symbol_short!("init"),),
            (admin,),
        );

        Ok(())
    }

    // ── Access Control ───────────────────────────────────────────────────────

    /// Authorize a contract address to log audit entries.
    pub fn authorize_caller(
        env: Env,
        caller_address: Address,
    ) -> Result<(), AuditError> {
        let admin = storage::get_admin(&env);
        admin.require_auth();
        storage::set_authorized_caller(&env, &caller_address, true);
        Ok(())
    }

    /// Revoke a contract's authorization to log entries.
    pub fn revoke_caller(
        env: Env,
        caller_address: Address,
    ) -> Result<(), AuditError> {
        let admin = storage::get_admin(&env);
        admin.require_auth();
        storage::set_authorized_caller(&env, &caller_address, false);
        Ok(())
    }

    /// Transfer admin role to a new address.
    pub fn transfer_admin(env: Env, new_admin: Address) -> Result<(), AuditError> {
        let admin = storage::get_admin(&env);
        admin.require_auth();
        storage::set_admin(&env, &new_admin);
        env.events().publish(
            (soroban_sdk::symbol_short!("adm_xfer"),),
            (admin, new_admin),
        );
        Ok(())
    }

    // ── Core Audit Logging ───────────────────────────────────────────────────

    /// Log a new audit entry. Must be called from an authorized contract.
    ///
    /// # Arguments
    /// * `actor`           – Account that performed the action
    /// * `subject`         – Bytes identifier of the subject (policy ID, claim ID, etc.)
    /// * `action`          – Type of action performed
    /// * `source_contract` – Address of the calling contract
    /// * `data_hash`       – SHA-256 hash of the associated off-chain data payload
    /// * `description`     – Human-readable summary (max 256 chars recommended)
    /// * `severity`        – Info / Warning / Critical
    /// * `related_entry_id`– Optional link to a prior entry
    /// * `metadata`        – Additional key-value pairs encoded as bytes
    pub fn log_entry(
        env: Env,
        actor: Address,
        subject: Bytes,
        action: ActionCategory,
        source_contract: Address,
        data_hash: Bytes,
        description: String,
        severity: Severity,
        related_entry_id: Option<u64>,
        metadata: Bytes,
    ) -> Result<u64, AuditError> {
        // Verify the immediate invoker is an authorized contract
        source_contract.require_auth();
        if !storage::is_authorized_caller(&env, &source_contract) {
            return Err(AuditError::CallerNotAuthorized);
        }

        let entry_id = storage::increment_entry_count(&env);
        let ledger = env.ledger().sequence();
        let timestamp = env.ledger().timestamp();

        let entry = AuditEntry {
            entry_id,
            ledger,
            timestamp,
            actor: actor.clone(),
            subject: subject.clone(),
            action: action.clone(),
            source_contract: source_contract.clone(),
            data_hash: data_hash.clone(),
            description: description.clone(),
            severity: severity.clone(),
            compliance_status: ComplianceStatus::Compliant,
            related_entry_id,
            metadata,
        };

        storage::save_entry(&env, &entry);

        // Emit structured event for external indexers / audit systems
        env.events().publish(
            (soroban_sdk::symbol_short!("audit"), entry_id),
            (actor, subject, action, severity, timestamp, source_contract),
        );

        Ok(entry_id)
    }

    /// Convenience: log a critical event and automatically flag it for review.
    pub fn log_critical_entry(
        env: Env,
        actor: Address,
        subject: Bytes,
        action: ActionCategory,
        source_contract: Address,
        data_hash: Bytes,
        description: String,
        metadata: Bytes,
    ) -> Result<u64, AuditError> {
        source_contract.require_auth();
        if !storage::is_authorized_caller(&env, &source_contract) {
            return Err(AuditError::CallerNotAuthorized);
        }

        let entry_id = storage::increment_entry_count(&env);
        let ledger = env.ledger().sequence();
        let timestamp = env.ledger().timestamp();

        let entry = AuditEntry {
            entry_id,
            ledger,
            timestamp,
            actor: actor.clone(),
            subject: subject.clone(),
            action: action.clone(),
            source_contract: source_contract.clone(),
            data_hash,
            description,
            severity: Severity::Critical,
            // Auto-flag critical events for mandatory review
            compliance_status: ComplianceStatus::Flagged,
            related_entry_id: None,
            metadata,
        };

        storage::save_entry(&env, &entry);

        env.events().publish(
            (soroban_sdk::symbol_short!("critical"), entry_id),
            (actor, subject, action, timestamp),
        );

        Ok(entry_id)
    }

    // ── Query Functions ──────────────────────────────────────────────────────

    /// Retrieve a single audit entry by ID.
    pub fn get_entry(env: Env, entry_id: u64) -> Result<AuditEntry, AuditError> {
        storage::get_entry(&env, entry_id).ok_or(AuditError::EntryNotFound)
    }

    /// Get the current total number of audit entries.
    pub fn get_entry_count(env: Env) -> u64 {
        storage::get_entry_count(&env)
    }

    /// Query audit entries with filters.
    /// Returns up to `filter.limit` entries starting from `filter.from_entry_id`.
    /// Maximum limit is 100 entries per call to stay within instruction budget.
    pub fn query_entries(
        env: Env,
        caller: Address,
        filter: AuditFilter,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        // Admin or registered auditor can query
        Self::require_query_permission(&env, &caller)?;

        if filter.limit == 0 || filter.limit > 100 {
            return Err(AuditError::LimitExceeded);
        }

        let total = storage::get_entry_count(&env);
        let mut results: Vec<AuditEntry> = Vec::new(&env);
        let mut count: u32 = 0;
        let mut entry_id = filter.from_entry_id;

        while entry_id <= total && count < filter.limit {
            if let Some(entry) = storage::get_entry(&env, entry_id) {
                if Self::matches_filter(&filter, &entry) {
                    results.push_back(entry);
                    count += 1;
                }
            }
            entry_id += 1;
        }

        env.events().publish(
            (soroban_sdk::symbol_short!("queried"),),
            (caller, filter.from_entry_id, count),
        );

        Ok(results)
    }

    /// Get entries for a specific actor (paginated).
    pub fn get_entries_by_actor(
        env: Env,
        caller: Address,
        actor: Address,
        from_entry_id: u64,
        limit: u32,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        Self::require_query_permission(&env, &caller)?;

        if limit == 0 || limit > 100 {
            return Err(AuditError::LimitExceeded);
        }

        let total = storage::get_entry_count(&env);
        let mut results: Vec<AuditEntry> = Vec::new(&env);
        let mut count: u32 = 0;
        let mut entry_id = from_entry_id;

        while entry_id <= total && count < limit {
            if let Some(entry) = storage::get_entry(&env, entry_id) {
                if entry.actor == actor {
                    results.push_back(entry);
                    count += 1;
                }
            }
            entry_id += 1;
        }

        Ok(results)
    }

    /// Get flagged entries requiring compliance review (paginated, max 50).
    pub fn get_flagged_entries(
        env: Env,
        caller: Address,
        from_entry_id: u64,
        limit: u32,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        Self::require_query_permission(&env, &caller)?;

        let limit = limit.min(50);
        let total = storage::get_entry_count(&env);
        let mut results: Vec<AuditEntry> = Vec::new(&env);
        let mut count: u32 = 0;
        let mut entry_id = from_entry_id;

        while entry_id <= total && count < limit {
            if let Some(entry) = storage::get_entry(&env, entry_id) {
                if matches!(entry.compliance_status, ComplianceStatus::Flagged) {
                    results.push_back(entry);
                    count += 1;
                }
            }
            entry_id += 1;
        }

        Ok(results)
    }

    // ── Compliance Report Generation ─────────────────────────────────────────

    /// Generate a compliance report for a time period.
    /// Scans entries in [scan_from_entry, scan_to_entry] that fall within
    /// [period_start, period_end] timestamps.
    pub fn generate_compliance_report(
        env: Env,
        caller: Address,
        period_start: u64,
        period_end: u64,
        scan_from_entry: u64,
        scan_to_entry: u64,
    ) -> Result<ComplianceReport, AuditError> {
        Self::require_report_permission(&env, &caller)?;

        let report = compliance::generate_report(
            &env,
            &caller,
            period_start,
            period_end,
            scan_from_entry,
            scan_to_entry,
        )?;

        // Log the report generation itself as an audit entry (self-referential audit)
        let entry_count = storage::increment_entry_count(&env);
        let meta = Bytes::new(&env);
        let report_entry = AuditEntry {
            entry_id: entry_count,
            ledger: env.ledger().sequence(),
            timestamp: env.ledger().timestamp(),
            actor: caller.clone(),
            subject: Bytes::from_array(&env, &report.report_id.to_be_bytes()),
            action: ActionCategory::RegulatoryReportGenerated,
            source_contract: env.current_contract_address(),
            data_hash: report.report_hash.clone(),
            description: String::from_str(&env, "Compliance report generated"),
            severity: Severity::Info,
            compliance_status: ComplianceStatus::Compliant,
            related_entry_id: None,
            metadata: meta,
        };
        storage::save_entry(&env, &report_entry);

        Ok(report)
    }

    /// Retrieve a previously generated compliance report.
    pub fn get_compliance_report(
        env: Env,
        caller: Address,
        report_id: u64,
    ) -> Result<ComplianceReport, AuditError> {
        Self::require_query_permission(&env, &caller)?;
        storage::get_report(&env, report_id).ok_or(AuditError::ReportNotFound)
    }

    /// Get total number of compliance reports generated.
    pub fn get_report_count(env: Env) -> u64 {
        storage::get_report_count(&env)
    }

    // ── Compliance Management ────────────────────────────────────────────────

    /// Flag an entry for compliance review.
    pub fn flag_entry(
        env: Env,
        caller: Address,
        entry_id: u64,
        reason: String,
    ) -> Result<(), AuditError> {
        Self::require_flag_permission(&env, &caller)?;
        compliance::flag_entry(&env, &caller, entry_id, reason)
    }

    /// Clear a compliance flag after review.
    pub fn clear_entry_flag(
        env: Env,
        caller: Address,
        entry_id: u64,
    ) -> Result<(), AuditError> {
        // Only admin can clear flags
        let admin = storage::get_admin(&env);
        admin.require_auth();
        if caller != admin {
            return Err(AuditError::Unauthorized);
        }
        compliance::clear_entry_flag(&env, &caller, entry_id)
    }

    // ── External Auditor Management ──────────────────────────────────────────

    /// Register an external audit system with specific permissions.
    pub fn register_auditor(
        env: Env,
        auditor_address: Address,
        name: String,
        permissions: AuditorPermissions,
    ) -> Result<(), AuditError> {
        let admin = storage::get_admin(&env);
        admin.require_auth();

        let auditor = ExternalAuditor {
            auditor_address: auditor_address.clone(),
            name,
            registered_at: env.ledger().timestamp(),
            is_active: true,
            permissions,
        };

        storage::save_auditor(&env, &auditor);

        env.events().publish(
            (soroban_sdk::symbol_short!("aud_reg"),),
            (auditor_address,),
        );

        Ok(())
    }

    /// Deactivate an external auditor.
    pub fn deactivate_auditor(
        env: Env,
        auditor_address: Address,
    ) -> Result<(), AuditError> {
        let admin = storage::get_admin(&env);
        admin.require_auth();

        let mut auditor = storage::get_auditor(&env, &auditor_address)
            .ok_or(AuditError::AuditorNotRegistered)?;

        auditor.is_active = false;
        storage::save_auditor(&env, &auditor);

        env.events().publish(
            (soroban_sdk::symbol_short!("aud_off"),),
            (auditor_address,),
        );

        Ok(())
    }

    /// Get an external auditor's registration details.
    pub fn get_auditor(
        env: Env,
        auditor_address: Address,
    ) -> Result<ExternalAuditor, AuditError> {
        storage::get_auditor(&env, &auditor_address).ok_or(AuditError::AuditorNotRegistered)
    }

    // ── Data Export ──────────────────────────────────────────────────────────

    /// Export a batch of entries as a serialized snapshot for off-chain systems.
    /// Returns a Vec of entries. The caller is responsible for serialization.
    /// Emits a DataExported event for audit purposes.
    pub fn export_entries(
        env: Env,
        caller: Address,
        from_entry_id: u64,
        to_entry_id: u64,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        Self::require_export_permission(&env, &caller)?;

        if to_entry_id < from_entry_id || (to_entry_id - from_entry_id) > 100 {
            return Err(AuditError::LimitExceeded);
        }

        let mut results: Vec<AuditEntry> = Vec::new(&env);

        for entry_id in from_entry_id..=to_entry_id {
            if let Some(entry) = storage::get_entry(&env, entry_id) {
                results.push_back(entry);
            }
        }

        // Audit the export itself
        let audit_id = storage::increment_entry_count(&env);
        let subject = {
            let mut b = Bytes::new(&env);
            b.extend_from_array(&from_entry_id.to_be_bytes());
            b.extend_from_array(&to_entry_id.to_be_bytes());
            b
        };
        let export_entry = AuditEntry {
            entry_id: audit_id,
            ledger: env.ledger().sequence(),
            timestamp: env.ledger().timestamp(),
            actor: caller.clone(),
            subject,
            action: ActionCategory::DataExported,
            source_contract: env.current_contract_address(),
            data_hash: Bytes::new(&env),
            description: String::from_str(&env, "Batch data export"),
            severity: Severity::Warning,
            compliance_status: ComplianceStatus::Compliant,
            related_entry_id: None,
            metadata: Bytes::new(&env),
        };
        storage::save_entry(&env, &export_entry);

        env.events().publish(
            (soroban_sdk::symbol_short!("exported"),),
            (caller, from_entry_id, to_entry_id),
        );

        Ok(results)
    }

    // ── Admin Utilities ──────────────────────────────────────────────────────

    /// Get the current admin address.
    pub fn get_admin(env: Env) -> Address {
        storage::get_admin(&env)
    }

    /// Extend TTL for a specific entry (admin only — for regulatory hold).
    pub fn extend_entry_ttl(env: Env, entry_id: u64) -> Result<(), AuditError> {
        let admin = storage::get_admin(&env);
        admin.require_auth();
        storage::bump_entry_ttl(&env, entry_id);
        Ok(())
    }

    // ── Private Helpers ──────────────────────────────────────────────────────

    fn require_query_permission(env: &Env, caller: &Address) -> Result<(), AuditError> {
        caller.require_auth();
        let admin = storage::get_admin(env);
        if *caller == admin {
            return Ok(());
        }
        let auditor = storage::get_auditor(env, caller).ok_or(AuditError::InsufficientPermissions)?;
        if !auditor.is_active {
            return Err(AuditError::AuditorInactive);
        }
        if !auditor.permissions.can_query {
            return Err(AuditError::InsufficientPermissions);
        }
        Ok(())
    }

    fn require_report_permission(env: &Env, caller: &Address) -> Result<(), AuditError> {
        caller.require_auth();
        let admin = storage::get_admin(env);
        if *caller == admin {
            return Ok(());
        }
        let auditor = storage::get_auditor(env, caller).ok_or(AuditError::InsufficientPermissions)?;
        if !auditor.is_active {
            return Err(AuditError::AuditorInactive);
        }
        if !auditor.permissions.can_generate_reports {
            return Err(AuditError::InsufficientPermissions);
        }
        Ok(())
    }

    fn require_export_permission(env: &Env, caller: &Address) -> Result<(), AuditError> {
        caller.require_auth();
        let admin = storage::get_admin(env);
        if *caller == admin {
            return Ok(());
        }
        let auditor = storage::get_auditor(env, caller).ok_or(AuditError::InsufficientPermissions)?;
        if !auditor.is_active {
            return Err(AuditError::AuditorInactive);
        }
        if !auditor.permissions.can_export {
            return Err(AuditError::InsufficientPermissions);
        }
        Ok(())
    }

    fn require_flag_permission(env: &Env, caller: &Address) -> Result<(), AuditError> {
        caller.require_auth();
        let admin = storage::get_admin(env);
        if *caller == admin {
            return Ok(());
        }
        let auditor = storage::get_auditor(env, caller).ok_or(AuditError::InsufficientPermissions)?;
        if !auditor.is_active {
            return Err(AuditError::AuditorInactive);
        }
        if !auditor.permissions.can_flag_entries {
            return Err(AuditError::InsufficientPermissions);
        }
        Ok(())
    }

    fn matches_filter(filter: &AuditFilter, entry: &AuditEntry) -> bool {
        if let Some(ref actor) = filter.actor {
            if entry.actor != *actor {
                return false;
            }
        }
        if let Some(ref action) = filter.action {
            if core::mem::discriminant(&entry.action) != core::mem::discriminant(action) {
                return false;
            }
        }
        if let Some(ref severity) = filter.severity {
            if core::mem::discriminant(&entry.severity) != core::mem::discriminant(severity) {
                return false;
            }
        }
        if let Some(ref status) = filter.compliance_status {
            if core::mem::discriminant(&entry.compliance_status) != core::mem::discriminant(status) {
                return false;
            }
        }
        if let Some(from_ts) = filter.from_timestamp {
            if entry.timestamp < from_ts {
                return false;
            }
        }
        if let Some(to_ts) = filter.to_timestamp {
            if entry.timestamp > to_ts {
                return false;
            }
        }
        true
    }
}