#![no_std]

use soroban_sdk::{Address, Env};

use crate::types::{AuditEntry, ComplianceReport, DataKey, ExternalAuditor};

// ── Ledger TTL constants ─────────────────────────────────────────────────────
// Audit entries must persist long-term for regulatory compliance.
// Stellar Soroban persistent storage TTL is set to ~10 years worth of ledgers.
// At ~5s per ledger: 10 years ≈ 63,072,000 ledgers.
const AUDIT_TTL_LEDGERS: u32 = 63_072_000;
const REPORT_TTL_LEDGERS: u32 = 63_072_000;
const ADMIN_TTL_LEDGERS: u32 = 63_072_000;

// ── Admin ────────────────────────────────────────────────────────────────────

pub fn set_admin(env: &Env, admin: &Address) {
    env.storage()
        .persistent()
        .set(&DataKey::Admin, admin);
    env.storage()
        .persistent()
        .extend_ttl(&DataKey::Admin, ADMIN_TTL_LEDGERS, ADMIN_TTL_LEDGERS);
}

pub fn get_admin(env: &Env) -> Address {
    env.storage()
        .persistent()
        .get(&DataKey::Admin)
        .unwrap()
}

pub fn has_admin(env: &Env) -> bool {
    env.storage().persistent().has(&DataKey::Admin)
}

// ── Authorized Callers ───────────────────────────────────────────────────────

pub fn set_authorized_caller(env: &Env, caller: &Address, authorized: bool) {
    env.storage()
        .persistent()
        .set(&DataKey::AuthorizedCaller(caller.clone()), &authorized);
    env.storage()
        .persistent()
        .extend_ttl(&DataKey::AuthorizedCaller(caller.clone()), ADMIN_TTL_LEDGERS, ADMIN_TTL_LEDGERS);
}

pub fn is_authorized_caller(env: &Env, caller: &Address) -> bool {
    env.storage()
        .persistent()
        .get::<DataKey, bool>(&DataKey::AuthorizedCaller(caller.clone()))
        .unwrap_or(false)
}

// ── Entry Count ──────────────────────────────────────────────────────────────

pub fn get_entry_count(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::EntryCount)
        .unwrap_or(0u64)
}

pub fn increment_entry_count(env: &Env) -> u64 {
    let count = get_entry_count(env) + 1;
    env.storage()
        .persistent()
        .set(&DataKey::EntryCount, &count);
    env.storage()
        .persistent()
        .extend_ttl(&DataKey::EntryCount, AUDIT_TTL_LEDGERS, AUDIT_TTL_LEDGERS);
    count
}

// ── Audit Entries ────────────────────────────────────────────────────────────

pub fn save_entry(env: &Env, entry: &AuditEntry) {
    let key = DataKey::Entry(entry.entry_id);
    env.storage().persistent().set(&key, entry);
    env.storage()
        .persistent()
        .extend_ttl(&key, AUDIT_TTL_LEDGERS, AUDIT_TTL_LEDGERS);
}

pub fn get_entry(env: &Env, entry_id: u64) -> Option<AuditEntry> {
    env.storage()
        .persistent()
        .get(&DataKey::Entry(entry_id))
}

pub fn bump_entry_ttl(env: &Env, entry_id: u64) {
    let key = DataKey::Entry(entry_id);
    if env.storage().persistent().has(&key) {
        env.storage()
            .persistent()
            .extend_ttl(&key, AUDIT_TTL_LEDGERS, AUDIT_TTL_LEDGERS);
    }
}

// ── Report Count ─────────────────────────────────────────────────────────────

pub fn get_report_count(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::ReportCount)
        .unwrap_or(0u64)
}

pub fn increment_report_count(env: &Env) -> u64 {
    let count = get_report_count(env) + 1;
    env.storage()
        .persistent()
        .set(&DataKey::ReportCount, &count);
    env.storage()
        .persistent()
        .extend_ttl(&DataKey::ReportCount, REPORT_TTL_LEDGERS, REPORT_TTL_LEDGERS);
    count
}

// ── Compliance Reports ───────────────────────────────────────────────────────

pub fn save_report(env: &Env, report: &ComplianceReport) {
    let key = DataKey::Report(report.report_id);
    env.storage().persistent().set(&key, report);
    env.storage()
        .persistent()
        .extend_ttl(&key, REPORT_TTL_LEDGERS, REPORT_TTL_LEDGERS);
}

pub fn get_report(env: &Env, report_id: u64) -> Option<ComplianceReport> {
    env.storage()
        .persistent()
        .get(&DataKey::Report(report_id))
}

// ── External Auditors ────────────────────────────────────────────────────────

pub fn save_auditor(env: &Env, auditor: &ExternalAuditor) {
    let key = DataKey::ExternalAuditor(auditor.auditor_address.clone());
    env.storage().persistent().set(&key, auditor);
    env.storage()
        .persistent()
        .extend_ttl(&key, ADMIN_TTL_LEDGERS, ADMIN_TTL_LEDGERS);
}

pub fn get_auditor(env: &Env, address: &Address) -> Option<ExternalAuditor> {
    env.storage()
        .persistent()
        .get(&DataKey::ExternalAuditor(address.clone()))
}