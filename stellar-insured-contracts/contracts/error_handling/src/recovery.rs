#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Env, String, Vec};

use crate::{
    codes::InsuranceError,
    registry,
    types::{ErrorEntry, ErrorSeverity, RecoveryAction, RecoveryStatus},
};

#[contract]
pub struct RecoveryContract;

#[contractimpl]
impl RecoveryContract {
    // ── Setup ─────────────────────────────────────────────────────────────────

    pub fn initialize(env: Env, admin: Address) -> Result<(), InsuranceError> {
        if registry::has_admin(&env) {
            return Err(InsuranceError::AlreadyInitialized);
        }
        admin.require_auth();
        registry::set_admin(&env, &admin);
        Ok(())
    }

    pub fn authorize_reporter(env: Env, reporter: Address) -> Result<(), InsuranceError> {
        registry::get_admin(&env).require_auth();
        registry::set_authorized_reporter(&env, &reporter, true);
        Ok(())
    }

    pub fn revoke_reporter(env: Env, reporter: Address) -> Result<(), InsuranceError> {
        registry::get_admin(&env).require_auth();
        registry::set_authorized_reporter(&env, &reporter, false);
        Ok(())
    }

    // ── Error Reporting ───────────────────────────────────────────────────────

    /// Report an error from any authorized contract.
    /// Automatically derives severity, recovery action, and hint from the error code.
    pub fn report_error(
        env: Env,
        source_contract: Address,
        caller: Address,
        error: InsuranceError,
        subject_id: Option<u64>,
    ) -> Result<u64, InsuranceError> {
        source_contract.require_auth();
        if !registry::is_authorized_reporter(&env, &source_contract) {
            return Err(InsuranceError::Unauthorized);
        }
        if registry::is_paused(&env) {
            return Err(InsuranceError::ContractPaused);
        }

        let severity = Self::derive_severity(&error);
        let recovery_action = Self::derive_recovery_action(&error);

        let entry_id = registry::next_error_id(&env);
        let entry = ErrorEntry {
            entry_id,
            error_code: error.code(),
            severity: severity.clone(),
            source_contract: source_contract.clone(),
            caller,
            ledger: env.ledger().sequence(),
            timestamp: env.ledger().timestamp(),
            message: String::from_str(&env, error.message()),
            hint: String::from_str(&env, error.hint()),
            recovery_action: recovery_action.clone(),
            recovery_status: RecoveryStatus::Pending,
            subject_id,
        };

        registry::save_error(&env, &entry);

        env.events().publish(
            (soroban_sdk::symbol_short!("err"), entry_id),
            (error.code(), source_contract, severity, recovery_action),
        );

        Ok(entry_id)
    }

    // ── Recovery Management ───────────────────────────────────────────────────

    /// Mark an error as resolved (admin or the reporting contract).
    pub fn resolve_error(env: Env, caller: Address, entry_id: u64) -> Result<(), InsuranceError> {
        caller.require_auth();
        let admin = registry::get_admin(&env);
        if caller != admin && !registry::is_authorized_reporter(&env, &caller) {
            return Err(InsuranceError::Unauthorized);
        }

        let mut entry = registry::get_error(&env, entry_id)
            .ok_or(InsuranceError::RecordNotFound)?;

        entry.recovery_status = RecoveryStatus::Resolved;
        registry::save_error(&env, &entry);

        env.events().publish(
            (soroban_sdk::symbol_short!("resolved"), entry_id),
            (caller,),
        );
        Ok(())
    }

    /// Escalate a pending error to the operator for manual intervention.
    pub fn escalate_error(env: Env, entry_id: u64) -> Result<(), InsuranceError> {
        registry::get_admin(&env).require_auth();

        let mut entry = registry::get_error(&env, entry_id)
            .ok_or(InsuranceError::RecordNotFound)?;

        entry.recovery_action = RecoveryAction::ManualInterventionRequired;
        entry.recovery_status = RecoveryStatus::EscalatedToOperator;
        registry::save_error(&env, &entry);

        env.events().publish(
            (soroban_sdk::symbol_short!("escalated"), entry_id),
            (entry.error_code,),
        );
        Ok(())
    }

    // ── Emergency Controls ────────────────────────────────────────────────────

    /// Pause all error reporting (emergency stop).
    pub fn pause(env: Env) -> Result<(), InsuranceError> {
        registry::get_admin(&env).require_auth();
        registry::set_paused(&env, true);
        env.events().publish((soroban_sdk::symbol_short!("paused"),), ());
        Ok(())
    }

    /// Resume error reporting.
    pub fn resume(env: Env) -> Result<(), InsuranceError> {
        registry::get_admin(&env).require_auth();
        registry::set_paused(&env, false);
        env.events().publish((soroban_sdk::symbol_short!("resumed"),), ());
        Ok(())
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    pub fn get_error(env: Env, entry_id: u64) -> Result<ErrorEntry, InsuranceError> {
        registry::get_error(&env, entry_id).ok_or(InsuranceError::RecordNotFound)
    }

    pub fn get_error_count(env: Env) -> u64 {
        registry::get_error_count(&env)
    }

    /// Fetch pending (unresolved) errors, paginated, max 50.
    pub fn get_pending_errors(
        env: Env,
        caller: Address,
        from_id: u64,
        limit: u32,
    ) -> Result<Vec<ErrorEntry>, InsuranceError> {
        caller.require_auth();
        let admin = registry::get_admin(&env);
        if caller != admin && !registry::is_authorized_reporter(&env, &caller) {
            return Err(InsuranceError::Unauthorized);
        }

        let limit = limit.min(50);
        let total = registry::get_error_count(&env);
        let mut results: Vec<ErrorEntry> = Vec::new(&env);
        let mut id = from_id;
        let mut found: u32 = 0;

        while id <= total && found < limit {
            if let Some(entry) = registry::get_error(&env, id) {
                if matches!(entry.recovery_status, RecoveryStatus::Pending) {
                    results.push_back(entry);
                    found += 1;
                }
            }
            id += 1;
        }
        Ok(results)
    }

    pub fn get_admin(env: Env) -> Address {
        registry::get_admin(&env)
    }

    pub fn is_paused(env: Env) -> bool {
        registry::is_paused(&env)
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn derive_severity(error: &InsuranceError) -> ErrorSeverity {
        match error {
            InsuranceError::ArithmeticOverflow
            | InsuranceError::ContractPaused
            | InsuranceError::ComplianceViolation => ErrorSeverity::Critical,

            InsuranceError::Unauthorized
            | InsuranceError::ClaimExceedsLimit
            | InsuranceError::PremiumPaymentOverdue
            | InsuranceError::ExternalCallFailed => ErrorSeverity::Error,

            InsuranceError::OracleDataStale
            | InsuranceError::KycExpired
            | InsuranceError::StorageExpired => ErrorSeverity::Warning,

            _ => ErrorSeverity::Info,
        }
    }

    fn derive_recovery_action(error: &InsuranceError) -> RecoveryAction {
        if error.is_retryable() {
            return RecoveryAction::AutoRetried;
        }
        if error.requires_manual_action() {
            return RecoveryAction::ManualInterventionRequired;
        }
        match error {
            InsuranceError::ArithmeticOverflow => RecoveryAction::StateRolledBack,
            InsuranceError::ContractPaused     => RecoveryAction::ContractPaused,
            InsuranceError::PaymentInvalidAmount
            | InsuranceError::ClaimExceedsLimit => RecoveryAction::FundsEscrowed,
            _ => RecoveryAction::None,
        }
    }
}