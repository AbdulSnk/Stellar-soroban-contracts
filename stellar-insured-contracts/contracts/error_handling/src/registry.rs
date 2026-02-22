#![no_std]

use soroban_sdk::{Address, Env};

use crate::types::{DataKey, ErrorEntry};

const LONG_TTL: u32 = 63_072_000; // ~10 years at 5s/ledger

pub fn set_admin(env: &Env, admin: &Address) {
    env.storage().persistent().set(&DataKey::Admin, admin);
    env.storage().persistent().extend_ttl(&DataKey::Admin, LONG_TTL, LONG_TTL);
}

pub fn get_admin(env: &Env) -> Address {
    env.storage().persistent().get(&DataKey::Admin).unwrap()
}

pub fn has_admin(env: &Env) -> bool {
    env.storage().persistent().has(&DataKey::Admin)
}

pub fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&DataKey::Paused, &paused);
    env.storage().persistent().extend_ttl(&DataKey::Paused, LONG_TTL, LONG_TTL);
}

pub fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&DataKey::Paused).unwrap_or(false)
}

pub fn set_authorized_reporter(env: &Env, reporter: &Address, authorized: bool) {
    env.storage()
        .persistent()
        .set(&DataKey::AuthorizedReporter(reporter.clone()), &authorized);
    env.storage()
        .persistent()
        .extend_ttl(&DataKey::AuthorizedReporter(reporter.clone()), LONG_TTL, LONG_TTL);
}

pub fn is_authorized_reporter(env: &Env, reporter: &Address) -> bool {
    env.storage()
        .persistent()
        .get::<DataKey, bool>(&DataKey::AuthorizedReporter(reporter.clone()))
        .unwrap_or(false)
}

pub fn next_error_id(env: &Env) -> u64 {
    let count: u64 = env.storage().persistent().get(&DataKey::ErrorCount).unwrap_or(0) + 1;
    env.storage().persistent().set(&DataKey::ErrorCount, &count);
    env.storage().persistent().extend_ttl(&DataKey::ErrorCount, LONG_TTL, LONG_TTL);
    count
}

pub fn get_error_count(env: &Env) -> u64 {
    env.storage().persistent().get(&DataKey::ErrorCount).unwrap_or(0)
}

pub fn save_error(env: &Env, entry: &ErrorEntry) {
    let key = DataKey::Error(entry.entry_id);
    env.storage().persistent().set(&key, entry);
    env.storage().persistent().extend_ttl(&key, LONG_TTL, LONG_TTL);
}

pub fn get_error(env: &Env, id: u64) -> Option<ErrorEntry> {
    env.storage().persistent().get(&DataKey::Error(id))
}