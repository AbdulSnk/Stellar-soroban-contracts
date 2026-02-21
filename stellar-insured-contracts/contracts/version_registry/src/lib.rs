#![no_std]

//! # Version Registry
//! Central on-chain registry tracking current version + full upgrade history
//! for every registered contract in the ecosystem.

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    Address, BytesN, Env, String, Vec,
};

#[contracttype]
#[derive(Clone)]
pub struct ContractVersion {
    pub address:    Address,
    pub major:      u32,
    pub minor:      u32,
    pub patch:      u32,
    pub wasm_hash:  BytesN<32>,
    pub updated_at: u64,
    pub label:      String,
}

#[contracttype]
#[derive(Clone)]
pub struct HistoryEntry {
    pub major:      u32,
    pub minor:      u32,
    pub patch:      u32,
    pub wasm_hash:  BytesN<32>,
    pub updated_at: u64,
    pub note:       String,
}

#[contract]
pub struct VersionRegistry;

#[contractimpl]
impl VersionRegistry {

    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&symbol_short!("admin")) {
            panic!("Already initialised");
        }
        admin.require_auth();
        env.storage().instance().set(&symbol_short!("admin"), &admin);
    }

    pub fn register(
        env:       Env,
        contract:  Address,
        major:     u32,
        minor:     u32,
        patch:     u32,
        wasm_hash: BytesN<32>,
        label:     String,
    ) {
        Self::require_admin(&env);
        let version = ContractVersion {
            address: contract.clone(), major, minor, patch,
            wasm_hash: wasm_hash.clone(),
            updated_at: env.ledger().timestamp(), label,
        };
        env.storage().instance().set(&contract, &version);

        let entry = HistoryEntry {
            major, minor, patch, wasm_hash,
            updated_at: env.ledger().timestamp(),
            note: String::from_str(&env, "Initial registration"),
        };
        let mut hist: Vec<HistoryEntry> = Vec::new(&env);
        hist.push_back(entry);
        env.storage().instance().set(&(symbol_short!("hist"), contract), &hist);
    }

    pub fn record_upgrade(
        env:       Env,
        caller:    Address,
        contract:  Address,
        major:     u32,
        minor:     u32,
        patch:     u32,
        wasm_hash: BytesN<32>,
        note:      String,
    ) {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&symbol_short!("admin")).unwrap();
        if caller != admin {
            let gov_key = (symbol_short!("gov"), caller.clone());
            if !env.storage().instance().has(&gov_key) {
                panic!("Caller not authorised");
            }
        }

        let mut version: ContractVersion = env.storage()
            .instance().get(&contract)
            .unwrap_or_else(|| panic!("Contract not registered"));
        version.major = major; version.minor = minor; version.patch = patch;
        version.wasm_hash = wasm_hash.clone();
        version.updated_at = env.ledger().timestamp();
        env.storage().instance().set(&contract, &version);

        let hist_key = (symbol_short!("hist"), contract.clone());
        let mut hist: Vec<HistoryEntry> =
            env.storage().instance().get(&hist_key).unwrap_or(Vec::new(&env));
        hist.push_back(HistoryEntry { major, minor, patch, wasm_hash, updated_at: env.ledger().timestamp(), note });
        env.storage().instance().set(&hist_key, &hist);
    }

    pub fn whitelist_governance(env: Env, governance: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&(symbol_short!("gov"), governance), &true);
    }

    pub fn get_version(env: Env, contract: Address) -> ContractVersion {
        env.storage().instance().get(&contract)
            .unwrap_or_else(|| panic!("Contract not registered"))
    }

    pub fn get_history(env: Env, contract: Address) -> Vec<HistoryEntry> {
        env.storage().instance()
            .get(&(symbol_short!("hist"), contract))
            .unwrap_or(Vec::new(&env))
    }

    pub fn history_length(env: Env, contract: Address) -> u32 {
        let hist: Vec<HistoryEntry> = env.storage().instance()
            .get(&(symbol_short!("hist"), contract))
            .unwrap_or(Vec::new(&env));
        hist.len()
    }

    fn require_admin(env: &Env) {
        let admin: Address = env.storage().instance().get(&symbol_short!("admin")).unwrap();
        admin.require_auth();
    }
}