// Issue #106 — Comprehensive Gas Optimization
// Lazy evaluation, batch operations, caching, storage tiering, and gas metering

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    Address, Env, Map, Symbol, Vec,
    log,
};

// ─────────────────────────────────────────────
// Design Principles Applied
// ─────────────────────────────────────────────
//
// 1. STORAGE TIERING
//    - instance()    → tiny, most-read config (cheapest per-byte, shared TTL)
//    - persistent()  → user balances / history (moderate cost, long TTL)
//    - temporary()   → short-lived cache / nonces (cheapest, auto-expiry)
//
// 2. LAZY EVALUATION
//    - Derived / aggregated values are computed on demand and cached in
//      temporary storage; stale on next ledger-close if needed.
//
// 3. BATCH OPERATIONS
//    - All mutating operations accept Vec inputs to amortise per-tx overhead.
//
// 4. PACKED STORAGE STRUCTS
//    - Related fields bundled into a single XDR struct → one read/write.
//
// 5. EARLY-EXIT GUARDS
//    - Auth and bounds checks before any storage access.

// ─────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────

#[contracttype]
pub enum OptKey {
    Config,                      // Packed config struct (instance)
    Balance(Address),            // Packed user balance struct (persistent)
    BalanceCache(Address),       // Lazy-computed derived balance (temporary)
    BatchResult(u32),            // Batch processing result cache (temporary)
    GasMeter,                    // Running gas metrics (instance)
    Nonce(Address),              // Anti-replay nonce (temporary)
}

/// Packed user balance — ONE storage read instead of several.
#[contracttype]
#[derive(Clone)]
pub struct UserBalance {
    pub principal:   i128,
    pub rewards:     i128,
    pub last_update: u64,
    pub locked:      i128,
}

/// Protocol-wide config — all in one slot.
#[contracttype]
#[derive(Clone)]
pub struct ProtocolConfig {
    pub reward_rate_bps:  u32,   // BPS per ledger
    pub lock_period_secs: u64,
    pub max_batch_size:   u32,
    pub fee_bps:          u32,
    pub governance:       Address,
}

/// Lightweight gas accounting (approximate, not ledger-native).
#[contracttype]
#[derive(Clone)]
pub struct GasMeter {
    pub reads:         u64,
    pub writes:        u64,
    pub cross_calls:   u64,
    pub events_emitted: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct BatchTransferItem {
    pub to:     Address,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone)]
pub struct BatchResult {
    pub succeeded: u32,
    pub failed:    u32,
    pub gas_saved: u64,   // Estimated ops saved vs individual calls
}

// ─────────────────────────────────────────────
// Contract
// ─────────────────────────────────────────────

#[contract]
pub struct GasOptimized;

#[contractimpl]
impl GasOptimized {

    // ── Initialization ───────────────────────

    pub fn initialize(env: Env, governance: Address) {
        if env.storage().instance().has(&OptKey::Config) {
            panic!("already initialised");
        }
        let cfg = ProtocolConfig {
            reward_rate_bps:  10,
            lock_period_secs: 30 * 24 * 3600,
            max_batch_size:   50,
            fee_bps:          30,
            governance,
        };
        env.storage().instance().set(&OptKey::Config, &cfg);
        env.storage().instance().set(&OptKey::GasMeter, &GasMeter {
            reads: 0, writes: 0, cross_calls: 0, events_emitted: 0,
        });
    }

    // ── OPTIMISATION 1: Packed Reads / Writes ──

    /// Read the entire user state in a SINGLE storage call.
    pub fn get_balance(env: Env, user: Address) -> UserBalance {
        Self::meter_read(&env);
        env.storage().persistent()
            .get(&OptKey::Balance(user))
            .unwrap_or(UserBalance { principal: 0, rewards: 0, last_update: 0, locked: 0 })
    }

    /// Write the entire user state in a SINGLE storage call.
    pub fn set_balance(env: Env, caller: Address, user: Address, balance: UserBalance) {
        caller.require_auth();
        Self::meter_write(&env);
        env.storage().persistent().set(&OptKey::Balance(user.clone()), &balance);
        // Invalidate lazy cache
        env.storage().temporary().remove(&OptKey::BalanceCache(user));
    }

    // ── OPTIMISATION 2: Lazy Derived Values ──

    /// Compute available (unlocked) balance lazily; cache result in temporary storage.
    /// Subsequent calls within the same ledger pay zero storage reads.
    pub fn get_available_balance(env: Env, user: Address) -> i128 {
        // Try cache first (zero-cost if warm)
        if let Some(cached) = env.storage().temporary()
            .get::<OptKey, i128>(&OptKey::BalanceCache(user.clone()))
        {
            return cached;
        }

        // Cold path: compute and cache
        Self::meter_read(&env);
        let bal: UserBalance = env.storage().persistent()
            .get(&OptKey::Balance(user.clone()))
            .unwrap_or(UserBalance { principal: 0, rewards: 0, last_update: 0, locked: 0 });

        let now = env.ledger().timestamp();
        let cfg: ProtocolConfig = env.storage().instance().get(&OptKey::Config).unwrap();
        let locked = if now >= bal.last_update + cfg.lock_period_secs { 0 } else { bal.locked };
        let available = bal.principal + bal.rewards - locked;

        Self::meter_write(&env);
        env.storage().temporary().set(&OptKey::BalanceCache(user), &available);
        available
    }

    // ── OPTIMISATION 3: Batch Transfers ──────

    /// Process up to `max_batch_size` transfers in a single transaction.
    /// Gas savings: (N-1) × auth_overhead + (N-1) × per-tx-base eliminated.
    pub fn batch_transfer(
        env:     Env,
        caller:  Address,
        items:   Vec<BatchTransferItem>,
    ) -> BatchResult {
        caller.require_auth();  // ONE auth check for entire batch
        Self::require_not_paused(&env);

        let cfg: ProtocolConfig = env.storage().instance().get(&OptKey::Config).unwrap();
        if items.len() > cfg.max_batch_size {
            panic!("batch exceeds max size");
        }

        // Load sender balance once
        Self::meter_read(&env);
        let mut sender_bal: UserBalance = env.storage().persistent()
            .get(&OptKey::Balance(caller.clone()))
            .unwrap_or(UserBalance { principal: 0, rewards: 0, last_update: 0, locked: 0 });

        let mut succeeded = 0u32;
        let mut failed    = 0u32;
        let now = env.ledger().timestamp();

        for i in 0..items.len() {
            let item = items.get(i).unwrap();
            if item.amount <= 0 || sender_bal.principal < item.amount {
                failed += 1;
                continue;
            }

            sender_bal.principal -= item.amount;
            sender_bal.last_update = now;

            // Load, update, write recipient in packed struct
            Self::meter_read(&env);
            let mut rec_bal: UserBalance = env.storage().persistent()
                .get(&OptKey::Balance(item.to.clone()))
                .unwrap_or(UserBalance { principal: 0, rewards: 0, last_update: 0, locked: 0 });

            rec_bal.principal  += item.amount;
            rec_bal.last_update = now;

            Self::meter_write(&env);
            env.storage().persistent().set(&OptKey::Balance(item.to.clone()), &rec_bal);
            // Invalidate recipient cache
            env.storage().temporary().remove(&OptKey::BalanceCache(item.to));
            succeeded += 1;
        }

        // Write sender back ONCE (not per-item)
        Self::meter_write(&env);
        env.storage().persistent().set(&OptKey::Balance(caller.clone()), &sender_bal);
        env.storage().temporary().remove(&OptKey::BalanceCache(caller));

        let gas_saved = (succeeded.saturating_sub(1) as u64) * 3; // Approx ops saved
        let result = BatchResult { succeeded, failed, gas_saved };
        log!(&env, "batch: {} ok {} fail {} gas saved", succeeded, failed, gas_saved);
        result
    }

    // ── OPTIMISATION 4: Config Update Batching ──

    /// Update multiple config params in ONE storage write.
    pub fn update_config(
        env:              Env,
        caller:           Address,
        reward_rate_bps:  Option<u32>,
        lock_period_secs: Option<u64>,
        max_batch_size:   Option<u32>,
        fee_bps:          Option<u32>,
    ) {
        caller.require_auth();
        Self::require_governance(&env, &caller);

        Self::meter_read(&env);
        let mut cfg: ProtocolConfig = env.storage().instance()
            .get(&OptKey::Config)
            .expect("not initialised");

        if let Some(v) = reward_rate_bps  { cfg.reward_rate_bps  = v; }
        if let Some(v) = lock_period_secs { cfg.lock_period_secs = v; }
        if let Some(v) = max_batch_size   { cfg.max_batch_size   = v; }
        if let Some(v) = fee_bps          { cfg.fee_bps          = v; }

        Self::meter_write(&env);
        env.storage().instance().set(&OptKey::Config, &cfg);
    }

    // ── OPTIMISATION 5: Batch Balance Reward Accrual ──

    /// Accrue rewards for multiple users in a single call.
    /// Avoids N separate transactions with their individual overheads.
    pub fn batch_accrue_rewards(env: Env, users: Vec<Address>) {
        Self::require_not_paused(&env);

        Self::meter_read(&env);
        let cfg: ProtocolConfig = env.storage().instance()
            .get(&OptKey::Config)
            .expect("not initialised");

        let now = env.ledger().timestamp();

        for i in 0..users.len() {
            let user = users.get(i).unwrap();
            Self::meter_read(&env);
            let mut bal: UserBalance = env.storage().persistent()
                .get(&OptKey::Balance(user.clone()))
                .unwrap_or(UserBalance { principal: 0, rewards: 0, last_update: 0, locked: 0 });

            if bal.principal > 0 && bal.last_update > 0 {
                let elapsed = now.saturating_sub(bal.last_update);
                // reward = principal × rate × elapsed / 10_000
                let new_reward = (bal.principal
                    * cfg.reward_rate_bps as i128
                    * elapsed as i128)
                    / (10_000 * 86_400); // per-day normalisation
                bal.rewards    += new_reward;
                bal.last_update = now;

                Self::meter_write(&env);
                env.storage().persistent().set(&OptKey::Balance(user.clone()), &bal);
                env.storage().temporary().remove(&OptKey::BalanceCache(user));
            }
        }
    }

    // ── Gas Metering Dashboard ──────────────

    pub fn get_gas_metrics(env: Env) -> GasMeter {
        env.storage().instance()
            .get(&OptKey::GasMeter)
            .unwrap_or(GasMeter { reads: 0, writes: 0, cross_calls: 0, events_emitted: 0 })
    }

    pub fn reset_gas_metrics(env: Env, caller: Address) {
        caller.require_auth();
        Self::require_governance(&env, &caller);
        env.storage().instance().set(&OptKey::GasMeter, &GasMeter {
            reads: 0, writes: 0, cross_calls: 0, events_emitted: 0,
        });
    }

    // ── Internal Metering ────────────────────

    fn meter_read(env: &Env) {
        let mut m: GasMeter = env.storage().instance()
            .get(&OptKey::GasMeter)
            .unwrap_or(GasMeter { reads: 0, writes: 0, cross_calls: 0, events_emitted: 0 });
        m.reads += 1;
        env.storage().instance().set(&OptKey::GasMeter, &m);
    }

    fn meter_write(env: &Env) {
        let mut m: GasMeter = env.storage().instance()
            .get(&OptKey::GasMeter)
            .unwrap_or(GasMeter { reads: 0, writes: 0, cross_calls: 0, events_emitted: 0 });
        m.writes += 1;
        env.storage().instance().set(&OptKey::GasMeter, &m);
    }

    fn require_governance(env: &Env, caller: &Address) {
        let cfg: ProtocolConfig = env.storage().instance()
            .get(&OptKey::Config)
            .expect("not initialised");
        if *caller != cfg.governance {
            panic!("not governance");
        }
    }

    fn require_not_paused(_env: &Env) {
        // Extend with instance flag as needed
    }
}