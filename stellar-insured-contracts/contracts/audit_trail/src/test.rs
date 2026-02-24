#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    Address, Bytes, Env, String,
};

use crate::{
    audit::AuditTrailContract,
    errors::AuditError,
    types::{ActionCategory, AuditFilter, AuditorPermissions, ComplianceStatus, Severity},
    AuditTrailContractClient,
};

// ── Test Helpers ─────────────────────────────────────────────────────────────

fn setup_env() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    env.ledger().set(LedgerInfo {
        timestamp: 1_700_000_000,
        protocol_version: 20,
        sequence_number: 100,
        network_id: Default::default(),
        base_reserve: 10,
        min_temp_entry_ttl: 1,
        min_persistent_entry_ttl: 1,
        max_entry_ttl: 100_000_000,
    });

    let contract_id = env.register_contract(None, AuditTrailContract);
    let admin = Address::generate(&env);

    (env, contract_id, admin)
}

fn get_client<'a>(env: &'a Env, contract_id: &'a Address) -> AuditTrailContractClient<'a> {
    AuditTrailContractClient::new(env, contract_id)
}

fn sample_bytes(env: &Env, seed: u8) -> Bytes {
    Bytes::from_array(env, &[seed; 32])
}

fn sample_string(env: &Env, s: &str) -> String {
    String::from_str(env, s)
}

// ── Initialization Tests ──────────────────────────────────────────────────────

#[test]
fn test_initialize_success() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);

    client.initialize(&admin);
    assert_eq!(client.get_admin(), admin);
}

#[test]
#[should_panic]
fn test_initialize_twice_fails() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);

    client.initialize(&admin);
    client.initialize(&admin); // should panic
}

// ── Authorization Tests ───────────────────────────────────────────────────────

#[test]
fn test_authorize_and_revoke_caller() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let caller = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&caller);
    client.revoke_caller(&caller);
}

// ── Log Entry Tests ───────────────────────────────────────────────────────────

#[test]
fn test_log_entry_success() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    let entry_id = client.log_entry(
        &actor,
        &sample_bytes(&env, 1),
        &ActionCategory::PolicyCreated,
        &source,
        &sample_bytes(&env, 2),
        &sample_string(&env, "Policy POL-001 created"),
        &Severity::Info,
        &None,
        &Bytes::new(&env),
    );

    assert_eq!(entry_id, 1u64);
    assert_eq!(client.get_entry_count(), 1u64);

    let entry = client.get_entry(&entry_id);
    assert_eq!(entry.actor, actor);
    assert_eq!(entry.entry_id, 1u64);
    assert!(matches!(entry.action, ActionCategory::PolicyCreated));
    assert!(matches!(entry.severity, Severity::Info));
    assert!(matches!(entry.compliance_status, ComplianceStatus::Compliant));
}

#[test]
fn test_log_multiple_entries_increments_count() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    for i in 0u8..5 {
        client.log_entry(
            &actor,
            &sample_bytes(&env, i),
            &ActionCategory::PremiumPaid,
            &source,
            &sample_bytes(&env, i),
            &sample_string(&env, "Premium payment"),
            &Severity::Info,
            &None,
            &Bytes::new(&env),
        );
    }

    assert_eq!(client.get_entry_count(), 5u64);
}

#[test]
fn test_log_entry_unauthorized_caller_fails() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let unauthorized = Address::generate(&env);

    client.initialize(&admin);
    // NOT authorizing `unauthorized`

    let result = client.try_log_entry(
        &actor,
        &sample_bytes(&env, 1),
        &ActionCategory::ClaimSubmitted,
        &unauthorized,
        &sample_bytes(&env, 2),
        &sample_string(&env, "Claim submitted"),
        &Severity::Warning,
        &None,
        &Bytes::new(&env),
    );

    assert_eq!(result, Err(Ok(AuditError::CallerNotAuthorized)));
}

// ── Critical Entry Tests ──────────────────────────────────────────────────────

#[test]
fn test_log_critical_entry_auto_flagged() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    let entry_id = client.log_critical_entry(
        &actor,
        &sample_bytes(&env, 99),
        &ActionCategory::ClaimRejected,
        &source,
        &sample_bytes(&env, 88),
        &sample_string(&env, "Suspicious claim rejected"),
        &Bytes::new(&env),
    );

    let entry = client.get_entry(&entry_id);
    assert!(matches!(entry.severity, Severity::Critical));
    assert!(matches!(entry.compliance_status, ComplianceStatus::Flagged));
}

// ── Related Entry Tests ───────────────────────────────────────────────────────

#[test]
fn test_related_entry_linking() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    let first_id = client.log_entry(
        &actor,
        &sample_bytes(&env, 1),
        &ActionCategory::ClaimSubmitted,
        &source,
        &sample_bytes(&env, 1),
        &sample_string(&env, "Claim submitted"),
        &Severity::Info,
        &None,
        &Bytes::new(&env),
    );

    let second_id = client.log_entry(
        &actor,
        &sample_bytes(&env, 2),
        &ActionCategory::ClaimApproved,
        &source,
        &sample_bytes(&env, 2),
        &sample_string(&env, "Claim approved"),
        &Severity::Info,
        &Some(first_id),
        &Bytes::new(&env),
    );

    let second_entry = client.get_entry(&second_id);
    assert_eq!(second_entry.related_entry_id, Some(first_id));
}

// ── Query Tests ───────────────────────────────────────────────────────────────

#[test]
fn test_query_entries_by_actor() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor_a = Address::generate(&env);
    let actor_b = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    // Log 3 entries for actor_a, 2 for actor_b
    for i in 0u8..3 {
        client.log_entry(
            &actor_a,
            &sample_bytes(&env, i),
            &ActionCategory::PolicyCreated,
            &source,
            &sample_bytes(&env, i),
            &sample_string(&env, "Policy"),
            &Severity::Info,
            &None,
            &Bytes::new(&env),
        );
    }
    for i in 10u8..12 {
        client.log_entry(
            &actor_b,
            &sample_bytes(&env, i),
            &ActionCategory::ClaimSubmitted,
            &source,
            &sample_bytes(&env, i),
            &sample_string(&env, "Claim"),
            &Severity::Warning,
            &None,
            &Bytes::new(&env),
        );
    }

    let results = client.get_entries_by_actor(&admin, &actor_a, &0u32, &10u32);
    assert_eq!(results.len(), 3);

    let results_b = client.get_entries_by_actor(&admin, &actor_b, &0u32, &10u32);
    assert_eq!(results_b.len(), 2);
}

#[test]
fn test_query_with_filter_by_severity() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    client.log_entry(
        &actor, &sample_bytes(&env, 1), &ActionCategory::PolicyCreated,
        &source, &sample_bytes(&env, 1), &sample_string(&env, "Info entry"),
        &Severity::Info, &None, &Bytes::new(&env),
    );
    client.log_entry(
        &actor, &sample_bytes(&env, 2), &ActionCategory::ClaimRejected,
        &source, &sample_bytes(&env, 2), &sample_string(&env, "Warning entry"),
        &Severity::Warning, &None, &Bytes::new(&env),
    );

    let filter = AuditFilter {
        actor: None,
        action: None,
        severity: Some(Severity::Warning),
        compliance_status: None,
        from_timestamp: None,
        to_timestamp: None,
        from_entry_id: 1,
        limit: 20,
    };

    let results = client.query_entries(&admin, &filter);
    assert_eq!(results.len(), 1);
    assert!(matches!(results.get(0).unwrap().severity, Severity::Warning));
}

#[test]
fn test_get_flagged_entries() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    let id1 = client.log_entry(
        &actor, &sample_bytes(&env, 1), &ActionCategory::PolicyCreated,
        &source, &sample_bytes(&env, 1), &sample_string(&env, "Normal"),
        &Severity::Info, &None, &Bytes::new(&env),
    );

    let _id2 = client.log_critical_entry(
        &actor, &sample_bytes(&env, 2), &ActionCategory::ClaimRejected,
        &source, &sample_bytes(&env, 2), &sample_string(&env, "Critical event"),
        &Bytes::new(&env),
    );

    // Manually flag id1
    client.flag_entry(&admin, &id1, &sample_string(&env, "Manual review required"));

    let flagged = client.get_flagged_entries(&admin, &1u64, &20u32);
    assert_eq!(flagged.len(), 2); // id1 (manually flagged) + id2 (auto-flagged critical)
}

// ── Compliance Report Tests ───────────────────────────────────────────────────

#[test]
fn test_generate_compliance_report() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    // Log some entries
    for i in 0u8..5 {
        client.log_entry(
            &actor, &sample_bytes(&env, i), &ActionCategory::PremiumPaid,
            &source, &sample_bytes(&env, i), &sample_string(&env, "Premium"),
            &Severity::Info, &None, &Bytes::new(&env),
        );
    }

    let period_start = 1_699_000_000u64;
    let period_end   = 1_800_000_000u64;

    let report = client.generate_compliance_report(
        &admin,
        &period_start,
        &period_end,
        &1u64,
        &5u64,
    );

    assert_eq!(report.report_id, 1u64);
    assert_eq!(report.total_entries, 5u32);
    assert_eq!(report.compliant_count, 5u32);
    assert_eq!(report.flagged_count, 0u32);
    assert_eq!(report.critical_events, 0u32);
    assert_eq!(report.generated_by, admin);

    // Verify it can be retrieved
    let fetched = client.get_compliance_report(&admin, &1u64);
    assert_eq!(fetched.report_id, 1u64);
}

#[test]
fn test_compliance_report_invalid_time_range_fails() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);

    client.initialize(&admin);

    let result = client.try_generate_compliance_report(
        &admin,
        &1_800_000_000u64, // start > end
        &1_700_000_000u64,
        &1u64,
        &1u64,
    );

    assert_eq!(result, Err(Ok(AuditError::InvalidTimeRange)));
}

#[test]
fn test_report_with_mixed_compliance_statuses() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    // Normal entry
    let id1 = client.log_entry(
        &actor, &sample_bytes(&env, 1), &ActionCategory::PolicyCreated,
        &source, &sample_bytes(&env, 1), &sample_string(&env, "Normal"),
        &Severity::Info, &None, &Bytes::new(&env),
    );

    // Critical (auto-flagged)
    client.log_critical_entry(
        &actor, &sample_bytes(&env, 2), &ActionCategory::ClaimRejected,
        &source, &sample_bytes(&env, 2), &sample_string(&env, "Critical"),
        &Bytes::new(&env),
    );

    let report = client.generate_compliance_report(
        &admin,
        &1_699_000_000u64,
        &1_800_000_000u64,
        &1u64,
        &2u64,
    );

    assert_eq!(report.total_entries, 2u32);
    assert_eq!(report.compliant_count, 1u32);
    assert_eq!(report.flagged_count, 1u32);
    assert_eq!(report.critical_events, 1u32);
}

// ── External Auditor Tests ────────────────────────────────────────────────────

#[test]
fn test_register_and_use_external_auditor() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let auditor_addr = Address::generate(&env);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    // Register auditor with query + report permissions
    let perms = AuditorPermissions {
        can_query: true,
        can_export: false,
        can_generate_reports: true,
        can_flag_entries: false,
    };
    client.register_auditor(
        &auditor_addr,
        &sample_string(&env, "RegCorp Audit LLC"),
        &perms,
    );

    let auditor = client.get_auditor(&auditor_addr);
    assert!(auditor.is_active);
    assert!(auditor.permissions.can_query);
    assert!(!auditor.permissions.can_export);

    // Log an entry, then let auditor query it
    client.log_entry(
        &actor, &sample_bytes(&env, 1), &ActionCategory::PolicyRenewed,
        &source, &sample_bytes(&env, 1), &sample_string(&env, "Renewal"),
        &Severity::Info, &None, &Bytes::new(&env),
    );

    let filter = AuditFilter {
        actor: None, action: None, severity: None, compliance_status: None,
        from_timestamp: None, to_timestamp: None, from_entry_id: 1, limit: 10,
    };

    let results = client.query_entries(&auditor_addr, &filter);
    assert_eq!(results.len(), 1);
}

#[test]
fn test_auditor_without_export_permission_fails() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let auditor_addr = Address::generate(&env);

    client.initialize(&admin);

    let perms = AuditorPermissions {
        can_query: true,
        can_export: false,  // no export
        can_generate_reports: false,
        can_flag_entries: false,
    };
    client.register_auditor(&auditor_addr, &sample_string(&env, "Auditor"), &perms);

    let result = client.try_export_entries(&auditor_addr, &1u64, &5u64);
    assert_eq!(result, Err(Ok(AuditError::InsufficientPermissions)));
}

#[test]
fn test_deactivate_auditor() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let auditor_addr = Address::generate(&env);

    client.initialize(&admin);

    let perms = AuditorPermissions {
        can_query: true, can_export: true,
        can_generate_reports: true, can_flag_entries: true,
    };
    client.register_auditor(&auditor_addr, &sample_string(&env, "Auditor"), &perms);
    client.deactivate_auditor(&auditor_addr);

    let auditor = client.get_auditor(&auditor_addr);
    assert!(!auditor.is_active);

    // Inactive auditor can't query
    let filter = AuditFilter {
        actor: None, action: None, severity: None, compliance_status: None,
        from_timestamp: None, to_timestamp: None, from_entry_id: 1, limit: 10,
    };
    let result = client.try_query_entries(&auditor_addr, &filter);
    assert_eq!(result, Err(Ok(AuditError::AuditorInactive)));
}

// ── Export Tests ──────────────────────────────────────────────────────────────

#[test]
fn test_export_entries_admin() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    for i in 0u8..3 {
        client.log_entry(
            &actor, &sample_bytes(&env, i), &ActionCategory::PremiumPaid,
            &source, &sample_bytes(&env, i), &sample_string(&env, "Premium"),
            &Severity::Info, &None, &Bytes::new(&env),
        );
    }

    let exported = client.export_entries(&admin, &1u64, &3u64);
    assert_eq!(exported.len(), 3);

    // Export itself creates an audit entry
    assert!(client.get_entry_count() > 3u64);
}

#[test]
fn test_export_range_too_large_fails() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);

    client.initialize(&admin);

    let result = client.try_export_entries(&admin, &1u64, &200u64);
    assert_eq!(result, Err(Ok(AuditError::LimitExceeded)));
}

// ── Flag / Clear Tests ────────────────────────────────────────────────────────

#[test]
fn test_flag_and_clear_entry() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    let entry_id = client.log_entry(
        &actor, &sample_bytes(&env, 1), &ActionCategory::ClaimPaid,
        &source, &sample_bytes(&env, 1), &sample_string(&env, "Claim paid"),
        &Severity::Info, &None, &Bytes::new(&env),
    );

    client.flag_entry(&admin, &entry_id, &sample_string(&env, "Review overpayment"));
    let flagged = client.get_entry(&entry_id);
    assert!(matches!(flagged.compliance_status, ComplianceStatus::Flagged));

    client.clear_entry_flag(&admin, &entry_id);
    let cleared = client.get_entry(&entry_id);
    assert!(matches!(cleared.compliance_status, ComplianceStatus::Compliant));
}

// ── Edge Case Tests ───────────────────────────────────────────────────────────

#[test]
fn test_get_nonexistent_entry_fails() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);

    client.initialize(&admin);

    let result = client.try_get_entry(&999u64);
    assert_eq!(result, Err(Ok(AuditError::EntryNotFound)));
}

#[test]
fn test_query_limit_exceeded_fails() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);

    client.initialize(&admin);

    let filter = AuditFilter {
        actor: None, action: None, severity: None, compliance_status: None,
        from_timestamp: None, to_timestamp: None, from_entry_id: 1, limit: 200, // > 100
    };

    let result = client.try_query_entries(&admin, &filter);
    assert_eq!(result, Err(Ok(AuditError::LimitExceeded)));
}

#[test]
fn test_admin_transfer() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let new_admin = Address::generate(&env);

    client.initialize(&admin);
    client.transfer_admin(&new_admin);

    assert_eq!(client.get_admin(), new_admin);
}

// ── Cryptographic Verification Tests ──────────────────────────────────────────

#[test]
fn test_entry_hash_computed() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    let entry_id = client.log_entry(
        &actor,
        &sample_bytes(&env, 1),
        &ActionCategory::PolicyCreated,
        &source,
        &sample_bytes(&env, 2),
        &sample_string(&env, "Test entry"),
        &Severity::Info,
        &None,
        &Bytes::new(&env),
    );

    let entry = client.get_entry(&entry_id);
    // Entry hash should be 32 bytes (SHA-256)
    assert_eq!(entry.entry_hash.len(), 32);
    // First entry should have no previous hash
    assert!(entry.previous_entry_hash.is_none());
}

#[test]
fn test_entry_chain_integrity() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    // Log first entry
    let id1 = client.log_entry(
        &actor,
        &sample_bytes(&env, 1),
        &ActionCategory::PolicyCreated,
        &source,
        &sample_bytes(&env, 2),
        &sample_string(&env, "First entry"),
        &Severity::Info,
        &None,
        &Bytes::new(&env),
    );

    // Log second entry
    let id2 = client.log_entry(
        &actor,
        &sample_bytes(&env, 3),
        &ActionCategory::PolicyUpdated,
        &source,
        &sample_bytes(&env, 4),
        &sample_string(&env, "Second entry"),
        &Severity::Info,
        &None,
        &Bytes::new(&env),
    );

    let entry1 = client.get_entry(&id1);
    let entry2 = client.get_entry(&id2);

    // Second entry should reference first entry's hash
    assert!(entry2.previous_entry_hash.is_some());
    assert_eq!(entry2.previous_entry_hash.unwrap(), entry1.entry_hash);
}

#[test]
fn test_verify_entry_integrity() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    let entry_id = client.log_entry(
        &actor,
        &sample_bytes(&env, 1),
        &ActionCategory::PolicyCreated,
        &source,
        &sample_bytes(&env, 2),
        &sample_string(&env, "Test entry"),
        &Severity::Info,
        &None,
        &Bytes::new(&env),
    );

    let is_valid = client.verify_entry_integrity(&entry_id);
    assert!(is_valid);
}

#[test]
fn test_verify_chain_integrity() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    // Log multiple entries
    for i in 0u8..5 {
        client.log_entry(
            &actor,
            &sample_bytes(&env, i),
            &ActionCategory::PremiumPaid,
            &source,
            &sample_bytes(&env, i + 10),
            &sample_string(&env, "Payment"),
            &Severity::Info,
            &None,
            &Bytes::new(&env),
        );
    }

    let is_valid = client.verify_chain_integrity(&1u64, &5u64);
    assert!(is_valid);
}

// ── Index Query Tests ─────────────────────────────────────────────────────────

#[test]
fn test_get_entries_by_actor_index() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor_a = Address::generate(&env);
    let actor_b = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    // Log entries for different actors
    for i in 0u8..3 {
        client.log_entry(
            &actor_a,
            &sample_bytes(&env, i),
            &ActionCategory::PolicyCreated,
            &source,
            &sample_bytes(&env, i),
            &sample_string(&env, "Policy A"),
            &Severity::Info,
            &None,
            &Bytes::new(&env),
        );
    }

    for i in 10u8..12 {
        client.log_entry(
            &actor_b,
            &sample_bytes(&env, i),
            &ActionCategory::ClaimSubmitted,
            &source,
            &sample_bytes(&env, i),
            &sample_string(&env, "Claim B"),
            &Severity::Warning,
            &None,
            &Bytes::new(&env),
        );
    }

    // Query using index (from_index = 0)
    let results_a = client.get_entries_by_actor(&admin, &actor_a, &0u32, &10u32);
    assert_eq!(results_a.len(), 3);

    let results_b = client.get_entries_by_actor(&admin, &actor_b, &0u32, &10u32);
    assert_eq!(results_b.len(), 2);
}

#[test]
fn test_get_entries_by_action_index() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    // Log different action types
    client.log_entry(
        &actor,
        &sample_bytes(&env, 1),
        &ActionCategory::PolicyCreated,
        &source,
        &sample_bytes(&env, 1),
        &sample_string(&env, "Policy"),
        &Severity::Info,
        &None,
        &Bytes::new(&env),
    );

    client.log_entry(
        &actor,
        &sample_bytes(&env, 2),
        &ActionCategory::ClaimSubmitted,
        &source,
        &sample_bytes(&env, 2),
        &sample_string(&env, "Claim"),
        &Severity::Warning,
        &None,
        &Bytes::new(&env),
    );

    client.log_entry(
        &actor,
        &sample_bytes(&env, 3),
        &ActionCategory::PolicyCreated,
        &source,
        &sample_bytes(&env, 3),
        &sample_string(&env, "Another policy"),
        &Severity::Info,
        &None,
        &Bytes::new(&env),
    );

    // Query by action using index
    let results = client.get_entries_by_action(&admin, &ActionCategory::PolicyCreated, &0u32, &10u32);
    assert_eq!(results.len(), 2);
}

// ── Merkle Tree Tests ─────────────────────────────────────────────────────────

#[test]
fn test_create_merkle_root() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    // Create multiple entries
    for i in 0u8..4 {
        client.log_entry(
            &actor,
            &sample_bytes(&env, i),
            &ActionCategory::PremiumPaid,
            &source,
            &sample_bytes(&env, i + 10),
            &sample_string(&env, "Payment"),
            &Severity::Info,
            &None,
            &Bytes::new(&env),
        );
    }

    // Create Merkle root for entries 1-4
    let root = client.create_merkle_root(&admin, &1u64, &4u64);
    assert_eq!(root.start_entry_id, 1u64);
    assert_eq!(root.end_entry_id, 4u64);
    assert_eq!(root.root_hash.len(), 32);
}

#[test]
fn test_generate_and_verify_proof() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);
    let actor = Address::generate(&env);
    let source = Address::generate(&env);

    client.initialize(&admin);
    client.authorize_caller(&source);

    // Create entries
    for i in 0u8..4 {
        client.log_entry(
            &actor,
            &sample_bytes(&env, i),
            &ActionCategory::PremiumPaid,
            &source,
            &sample_bytes(&env, i + 10),
            &sample_string(&env, "Payment"),
            &Severity::Info,
            &None,
            &Bytes::new(&env),
        );
    }

    // Create Merkle root
    let root = client.create_merkle_root(&admin, &1u64, &4u64);

    // Generate proof for entry 2
    let proof = client.generate_entry_proof(&admin, &2u64, &1u64, &4u64);
    assert_eq!(proof.entry_id, 2u64);
    assert_eq!(proof.merkle_root, root.root_hash);
    assert!(!proof.proof_path.is_empty());
}

// ── Retention Policy Tests ────────────────────────────────────────────────────

#[test]
fn test_create_retention_policy() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);

    client.initialize(&admin);

    let policy_id = client.create_retention_policy(
        &admin,
        &Some(Severity::Critical),
        &None, // Applies to all actions
        &365u32, // 1 year retention
        &180u32, // Archive after 6 months
        &false,  // Don't auto-purge
    );

    assert_eq!(policy_id, 1u64);

    let policy = client.get_retention_policy(&policy_id);
    assert_eq!(policy.policy_id, 1u64);
    assert!(matches!(policy.severity, Some(Severity::Critical)));
    assert_eq!(policy.retention_period_days, 365u32);
    assert_eq!(policy.archive_after_days, 180u32);
    assert!(!policy.auto_purge);
}

#[test]
fn test_remove_retention_policy() {
    let (env, contract_id, admin) = setup_env();
    let client = get_client(&env, &contract_id);

    client.initialize(&admin);

    let policy_id = client.create_retention_policy(
        &admin,
        &None,
        &None,
        &365u32,
        &180u32,
        &false,
    );

    client.remove_retention_policy(&admin, &policy_id);

    // Verify policy is removed
    let result = client.try_get_retention_policy(&policy_id);
    assert_eq!(result, Err(Ok(AuditError::PolicyNotFound)));
}