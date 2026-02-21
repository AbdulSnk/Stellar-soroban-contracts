#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    Address, BytesN, Env, String, Vec,
};

// ─── Storage Keys ────────────────────────────────────────────────────────────

const ADMIN_KEY: &str        = "admin";
const VERSION_KEY: &str      = "version";
const GOV_KEY: &str          = "governance";
const HISTORY_KEY: &str      = "history";

// ─── Data Structures ─────────────────────────────────────────────────────────

/// Represents a single entry in the upgrade history ledger.
#[contracttype]
#[derive(Clone)]
pub struct UpgradeRecord {
    pub version:    u32,
    pub new_wasm:   BytesN<32>,
    pub upgraded_by: Address,
    pub timestamp:  u64,
    pub description: String,
}

/// On-chain version descriptor.
#[contracttype]
#[derive(Clone)]
pub struct VersionInfo {
    pub major:   u32,
    pub minor:   u32,
    pub patch:   u32,
    pub deployed_at: u64,
}

// ─── Contract ────────────────────────────────────────────────────────────────

#[contract]
pub struct UpgradeableContract;

#[contractimpl]
impl UpgradeableContract {

    // ── Initialisation ───────────────────────────────────────────────────────

    /// Deploy and initialise the contract.
    /// `governance` is the governance contract that controls upgrades.
    pub fn initialize(
        env: Env,
        admin: Address,
        governance: Address,
        major: u32,
        minor: u32,
        patch: u32,
    ) {
        // Prevent re-initialisation.
        if env.storage().instance().has(&symbol_short!("version")) {
            panic!("Already initialised");
        }

        admin.require_auth();

        env.storage().instance().set(&symbol_short!("admin"), &admin);
        env.storage().instance().set(&symbol_short!("gov"), &governance);

        let version = VersionInfo {
            major,
            minor,
            patch,
            deployed_at: env.ledger().timestamp(),
        };
        env.storage().instance().set(&symbol_short!("version"), &version);

        // Initialise empty history list.
        let history: Vec<UpgradeRecord> = Vec::new(&env);
        env.storage().instance().set(&symbol_short!("history"), &history);
    }

    // ── Upgrade ──────────────────────────────────────────────────────────────

    /// Execute an approved upgrade.
    /// Only callable by the governance contract after a successful proposal vote.
    ///
    /// * `new_wasm_hash`  – SHA-256 hash of the new WASM blob (already uploaded).
    /// * `new_major/minor/patch` – next semantic version.
    /// * `description`    – human-readable change summary stored on-chain.
    pub fn upgrade(
        env: Env,
        new_wasm_hash: BytesN<32>,
        new_major: u32,
        new_minor: u32,
        new_patch: u32,
        description: String,
    ) {
        // Only the governance contract may trigger an upgrade.
        let governance: Address = env.storage().instance().get(&symbol_short!("gov")).unwrap();
        governance.require_auth();

        // Version guard: new version must be strictly greater.
        let current: VersionInfo = env.storage().instance().get(&symbol_short!("version")).unwrap();
        let current_num = Self::encode_version(current.major, current.minor, current.patch);
        let new_num     = Self::encode_version(new_major, new_minor, new_patch);
        if new_num <= current_num {
            panic!("New version must be greater than current version");
        }

        // Record history before upgrading.
        let record = UpgradeRecord {
            version:     new_num,
            new_wasm:    new_wasm_hash.clone(),
            upgraded_by: governance.clone(),
            timestamp:   env.ledger().timestamp(),
            description,
        };
        let mut history: Vec<UpgradeRecord> =
            env.storage().instance().get(&symbol_short!("history")).unwrap();
        history.push_back(record);
        env.storage().instance().set(&symbol_short!("history"), &history);

        // Persist new version info.
        let new_version = VersionInfo {
            major: new_major,
            minor: new_minor,
            patch: new_patch,
            deployed_at: env.ledger().timestamp(),
        };
        env.storage().instance().set(&symbol_short!("version"), &new_version);

        // ⬇️  Soroban native upgrade – atomically replaces contract WASM.
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    // ── Governance management ────────────────────────────────────────────────

    /// Replace the governance contract (admin only). Useful for governance migrations.
    pub fn set_governance(env: Env, new_governance: Address) {
        let admin: Address = env.storage().instance().get(&symbol_short!("admin")).unwrap();
        admin.require_auth();
        env.storage().instance().set(&symbol_short!("gov"), &new_governance);
    }

    // ── Views ────────────────────────────────────────────────────────────────

    pub fn version(env: Env) -> VersionInfo {
        env.storage().instance().get(&symbol_short!("version")).unwrap()
    }

    pub fn governance(env: Env) -> Address {
        env.storage().instance().get(&symbol_short!("gov")).unwrap()
    }

    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&symbol_short!("admin")).unwrap()
    }

    /// Returns the full upgrade history (all records).
    pub fn upgrade_history(env: Env) -> Vec<UpgradeRecord> {
        env.storage().instance().get(&symbol_short!("history")).unwrap_or(Vec::new(&env))
    }

    /// Returns the last N upgrade records.
    pub fn recent_upgrades(env: Env, n: u32) -> Vec<UpgradeRecord> {
        let history: Vec<UpgradeRecord> =
            env.storage().instance().get(&symbol_short!("history")).unwrap_or(Vec::new(&env));
        let len  = history.len();
        let skip = if len > n { len - n } else { 0 };
        let mut result = Vec::new(&env);
        for i in skip..len {
            result.push_back(history.get(i).unwrap());
        }
        result
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Encode major.minor.patch → single comparable u32.
    /// Supports up to major 999, minor 999, patch 9999.
    fn encode_version(major: u32, minor: u32, patch: u32) -> u32 {
        major * 1_000_0000 + minor * 10000 + patch
    }
}