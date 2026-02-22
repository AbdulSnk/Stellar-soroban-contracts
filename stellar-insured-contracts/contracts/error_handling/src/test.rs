#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    Address, Env,
};

use crate::{
    codes::InsuranceError,
    recovery::RecoveryContract,
    types::{ErrorSeverity, RecoveryAction, RecoveryStatus},
    RecoveryContractClient,
};

fn setup() -> (Env, Address, Address) {
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
    let id = env.register_contract(None, RecoveryContract);
    let admin = Address::generate(&env);
    (env, id, admin)
}

fn client<'a>(env: &'a Env, id: &'a Address) -> RecoveryContractClient<'a> {
    RecoveryContractClient::new(env, id)
}

// ── Init ─────────────────────────────────────────────────────────────────────

#[test]
fn test_initialize() {
    let (env, id, admin) = setup();
    let c = client(&env, &id);
    c.initialize(&admin);
    assert_eq!(c.get_admin(), admin);
}

#[test]
fn test_double_initialize_fails() {
    let (env, id, admin) = setup();
    let c = client(&env, &id);
    c.initialize(&admin);
    assert_eq!(
        c.try_initialize(&admin),
        Err(Ok(InsuranceError::AlreadyInitialized))
    );
}

// ── Error Codes ───────────────────────────────────────────────────────────────

#[test]
fn test_error_codes_are_unique_and_in_range() {
    // Auth range
    assert_eq!(InsuranceError::Unauthorized as u32, 1);
    assert_eq!(InsuranceError::AlreadyInitialized as u32, 4);
    // Policy range
    assert_eq!(InsuranceError::PolicyNotFound as u32, 100);
    // Claims range
    assert_eq!(InsuranceError::ClaimNotFound as u32, 200);
    // Payments range
    assert_eq!(InsuranceError::PaymentInvalidAmount as u32, 300);
    // KYC range
    assert_eq!(InsuranceError::KycNotVerified as u32, 400);
    // System range
    assert_eq!(InsuranceError::ContractPaused as u32, 700);
}

#[test]
fn test_error_messages_are_non_empty() {
    let errors = [
        InsuranceError::Unauthorized,
        InsuranceError::PolicyNotFound,
        InsuranceError::ClaimExceedsLimit,
        InsuranceError::PaymentInvalidAmount,
        InsuranceError::KycNotVerified,
        InsuranceError::OracleDataStale,
        InsuranceError::ArithmeticOverflow,
    ];
    for e in &errors {
        assert!(!e.message().is_empty());
        assert!(!e.hint().is_empty());
    }
}

#[test]
fn test_retryable_errors() {
    assert!(InsuranceError::OracleDataMissing.is_retryable());
    assert!(InsuranceError::OracleDataStale.is_retryable());
    assert!(InsuranceError::ExternalCallFailed.is_retryable());
    assert!(InsuranceError::ContractPaused.is_retryable());
    assert!(!InsuranceError::Unauthorized.is_retryable());
    assert!(!InsuranceError::ClaimDuplicate.is_retryable());
}

#[test]
fn test_manual_action_errors() {
    assert!(InsuranceError::KycNotVerified.requires_manual_action());
    assert!(InsuranceError::ClaimMissingDocuments.requires_manual_action());
    assert!(!InsuranceError::PolicyNotFound.requires_manual_action());
}

// ── Reporting ─────────────────────────────────────────────────────────────────

#[test]
fn test_report_error_success() {
    let (env, id, admin) = setup();
    let c = client(&env, &id);
    let reporter = Address::generate(&env);
    let caller = Address::generate(&env);

    c.initialize(&admin);
    c.authorize_reporter(&reporter);

    let entry_id = c.report_error(
        &reporter,
        &caller,
        &InsuranceError::PolicyNotFound,
        &None,
    );

    assert_eq!(entry_id, 1u64);
    assert_eq!(c.get_error_count(), 1u64);

    let entry = c.get_error(&1u64);
    assert_eq!(entry.error_code, InsuranceError::PolicyNotFound as u32);
    assert!(matches!(entry.severity, ErrorSeverity::Info));
    assert!(matches!(entry.recovery_status, RecoveryStatus::Pending));
}

#[test]
fn test_critical_error_severity() {
    let (env, id, admin) = setup();
    let c = client(&env, &id);
    let reporter = Address::generate(&env);
    let caller = Address::generate(&env);

    c.initialize(&admin);
    c.authorize_reporter(&reporter);

    let entry_id = c.report_error(
        &reporter,
        &caller,
        &InsuranceError::ArithmeticOverflow,
        &None,
    );

    let entry = c.get_error(&entry_id);
    assert!(matches!(entry.severity, ErrorSeverity::Critical));
    assert!(matches!(entry.recovery_action, RecoveryAction::StateRolledBack));
}

#[test]
fn test_retryable_error_gets_auto_retry_action() {
    let (env, id, admin) = setup();
    let c = client(&env, &id);
    let reporter = Address::generate(&env);
    let caller = Address::generate(&env);

    c.initialize(&admin);
    c.authorize_reporter(&reporter);

    let entry_id = c.report_error(
        &reporter, &caller, &InsuranceError::OracleDataStale, &None,
    );
    let entry = c.get_error(&entry_id);
    assert!(matches!(entry.recovery_action, RecoveryAction::AutoRetried));
}

#[test]
fn test_unauthorized_reporter_fails() {
    let (env, id, admin) = setup();
    let c = client(&env, &id);
    let not_reporter = Address::generate(&env);
    let caller = Address::generate(&env);

    c.initialize(&admin);

    assert_eq!(
        c.try_report_error(&not_reporter, &caller, &InsuranceError::PolicyNotFound, &None),
        Err(Ok(InsuranceError::Unauthorized))
    );
}

// ── Recovery ──────────────────────────────────────────────────────────────────

#[test]
fn test_resolve_error() {
    let (env, id, admin) = setup();
    let c = client(&env, &id);
    let reporter = Address::generate(&env);
    let caller = Address::generate(&env);

    c.initialize(&admin);
    c.authorize_reporter(&reporter);

    let entry_id = c.report_error(&reporter, &caller, &InsuranceError::ClaimNotFound, &None);
    c.resolve_error(&admin, &entry_id);

    let entry = c.get_error(&entry_id);
    assert!(matches!(entry.recovery_status, RecoveryStatus::Resolved));
}

#[test]
fn test_escalate_error() {
    let (env, id, admin) = setup();
    let c = client(&env, &id);
    let reporter = Address::generate(&env);
    let caller = Address::generate(&env);

    c.initialize(&admin);
    c.authorize_reporter(&reporter);

    let entry_id = c.report_error(&reporter, &caller, &InsuranceError::ComplianceViolation, &None);
    c.escalate_error(&entry_id);

    let entry = c.get_error(&entry_id);
    assert!(matches!(entry.recovery_status, RecoveryStatus::EscalatedToOperator));
    assert!(matches!(entry.recovery_action, RecoveryAction::ManualInterventionRequired));
}

// ── Emergency Controls ────────────────────────────────────────────────────────

#[test]
fn test_pause_and_resume() {
    let (env, id, admin) = setup();
    let c = client(&env, &id);
    let reporter = Address::generate(&env);
    let caller = Address::generate(&env);

    c.initialize(&admin);
    c.authorize_reporter(&reporter);
    c.pause();

    assert!(c.is_paused());
    assert_eq!(
        c.try_report_error(&reporter, &caller, &InsuranceError::PolicyNotFound, &None),
        Err(Ok(InsuranceError::ContractPaused))
    );

    c.resume();
    assert!(!c.is_paused());
    // Should succeed now
    c.report_error(&reporter, &caller, &InsuranceError::PolicyNotFound, &None);
}

// ── Pending Query ─────────────────────────────────────────────────────────────

#[test]
fn test_get_pending_errors() {
    let (env, id, admin) = setup();
    let c = client(&env, &id);
    let reporter = Address::generate(&env);
    let caller = Address::generate(&env);

    c.initialize(&admin);
    c.authorize_reporter(&reporter);

    let id1 = c.report_error(&reporter, &caller, &InsuranceError::PolicyNotFound, &None);
    let id2 = c.report_error(&reporter, &caller, &InsuranceError::ClaimDuplicate, &None);
    c.resolve_error(&admin, &id1);

    let pending = c.get_pending_errors(&admin, &1u64, &20u32);
    // Only id2 should remain pending
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.get(0).unwrap().entry_id, id2);
}

#[test]
fn test_subject_id_recorded() {
    let (env, id, admin) = setup();
    let c = client(&env, &id);
    let reporter = Address::generate(&env);
    let caller = Address::generate(&env);

    c.initialize(&admin);
    c.authorize_reporter(&reporter);

    let entry_id = c.report_error(
        &reporter, &caller, &InsuranceError::ClaimNotFound, &Some(42u64),
    );

    let entry = c.get_error(&entry_id);
    assert_eq!(entry.subject_id, Some(42u64));
}