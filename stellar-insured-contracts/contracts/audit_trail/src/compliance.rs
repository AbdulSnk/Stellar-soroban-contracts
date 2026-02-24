#![no_std]

use soroban_sdk::{Address, Bytes, BytesN, Env};

use crate::{
    crypto::hash_to_bytes,
    errors::AuditError,
    storage,
    types::{ActionCategory, AuditEntry, ComplianceReport, ComplianceStatus, Severity},
};

/// Scan entries in [from_id, to_id) range and produce a ComplianceReport.
/// This is intentionally iterative to stay within Soroban instruction budget.
/// Callers should paginate if the range is large.
pub fn generate_report(
    env: &Env,
    caller: &Address,
    period_start: u64,
    period_end: u64,
    scan_from_entry: u64,
    scan_to_entry: u64,
) -> Result<ComplianceReport, AuditError> {
    if period_start >= period_end {
        return Err(AuditError::InvalidTimeRange);
    }

    let mut total_entries: u32 = 0;
    let mut compliant_count: u32 = 0;
    let mut flagged_count: u32 = 0;
    let mut pending_review_count: u32 = 0;
    let mut critical_events: u32 = 0;

    for entry_id in scan_from_entry..=scan_to_entry {
        if let Some(entry) = storage::get_entry(env, entry_id) {
            // Filter to the requested time window
            if entry.timestamp < period_start || entry.timestamp > period_end {
                continue;
            }

            total_entries += 1;

            match entry.compliance_status {
                ComplianceStatus::Compliant => compliant_count += 1,
                ComplianceStatus::Flagged => flagged_count += 1,
                ComplianceStatus::PendingReview => pending_review_count += 1,
                ComplianceStatus::Exempted => {} // counted in total but not in sub-buckets
            }

            if matches!(entry.severity, Severity::Critical) {
                critical_events += 1;
            }
        }
    }

    let report_id = storage::increment_report_count(env);
    let now = env.ledger().timestamp();

    // Compute SHA-256 hash of report data for integrity
    let report_hash = compute_report_hash(
        env,
        report_id,
        now,
        caller,
        period_start,
        period_end,
        total_entries,
        compliant_count,
        flagged_count,
        pending_review_count,
        critical_events,
    );

    let report = ComplianceReport {
        report_id,
        generated_at: now,
        generated_by: caller.clone(),
        period_start,
        period_end,
        total_entries,
        compliant_count,
        flagged_count,
        pending_review_count,
        critical_events,
        categories_covered: Bytes::new(env),
        report_hash: hash_to_bytes(env, &report_hash),
    };

    storage::save_report(env, &report);

    // Emit event for external systems
    env.events().publish(
        (soroban_sdk::symbol_short!("rpt_gen"), report_id),
        (caller.clone(), period_start, period_end, total_entries),
    );

    Ok(report)
}

/// Flag an existing audit entry for regulatory review.
pub fn flag_entry(
    env: &Env,
    caller: &Address,
    entry_id: u64,
    reason: soroban_sdk::String,
) -> Result<(), AuditError> {
    let mut entry = storage::get_entry(env, entry_id).ok_or(AuditError::EntryNotFound)?;

    entry.compliance_status = ComplianceStatus::Flagged;

    storage::save_entry(env, &entry);

    env.events().publish(
        (soroban_sdk::symbol_short!("flagged"), entry_id),
        (caller.clone(), reason),
    );

    Ok(())
}

/// Mark an entry as compliant after review.
pub fn clear_entry_flag(
    env: &Env,
    caller: &Address,
    entry_id: u64,
) -> Result<(), AuditError> {
    let mut entry = storage::get_entry(env, entry_id).ok_or(AuditError::EntryNotFound)?;

    entry.compliance_status = ComplianceStatus::Compliant;
    storage::save_entry(env, &entry);

    env.events().publish(
        (soroban_sdk::symbol_short!("cleared"), entry_id),
        (caller.clone(),),
    );

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn compute_report_hash(
    env: &Env,
    report_id: u64,
    generated_at: u64,
    generated_by: &Address,
    period_start: u64,
    period_end: u64,
    total: u32,
    compliant: u32,
    flagged: u32,
    pending: u32,
    critical: u32,
) -> BytesN<32> {
    let mut data = Bytes::new(env);
    data.extend_from_array(&report_id.to_be_bytes());
    data.extend_from_array(&generated_at.to_be_bytes());
    data.extend_from_array(&generated_by.to_xdr(env).to_vec());
    data.extend_from_array(&period_start.to_be_bytes());
    data.extend_from_array(&period_end.to_be_bytes());
    data.extend_from_array(&total.to_be_bytes());
    data.extend_from_array(&compliant.to_be_bytes());
    data.extend_from_array(&flagged.to_be_bytes());
    data.extend_from_array(&pending.to_be_bytes());
    data.extend_from_array(&critical.to_be_bytes());
    env.crypto().sha256(&data)
}