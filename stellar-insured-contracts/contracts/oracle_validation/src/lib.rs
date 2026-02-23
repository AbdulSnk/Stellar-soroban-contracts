// Issue #104 — Oracle Data Validation Framework
// Consensus checks, anomaly detection, fallback pricing, history tracking, quality metrics

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    Address, Env, Map, Symbol, Vec,
    log,
};

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

const MAX_PRICE_DEVIATION_BPS: i128 = 500;   // 5 % max deviation between sources
const MIN_SOURCES_FOR_CONSENSUS: u32  = 3;    // Minimum oracle sources required
const STALENESS_THRESHOLD_SECS: u64   = 300;  // 5 minutes
const ANOMALY_MULTIPLIER_BPS: i128    = 2000; // 20 % jump = anomaly
const HISTORY_MAX_ENTRIES: u32        = 100;
const QUALITY_DECAY_PER_MISS: u32     = 10;   // Quality score penalty per missing round

// ─────────────────────────────────────────────
// Storage Types
// ─────────────────────────────────────────────

#[contracttype]
pub enum OracleKey {
    SourceList,                   // Vec<Address> of approved oracle sources
    SourcePrice(Address),         // Latest price submission per source
    AggregatedPrice(Symbol),      // Consensus price per asset symbol
    PriceHistory(Symbol),         // Vec<PricePoint> for asset
    FallbackPrice(Symbol),        // Admin-set fallback price
    QualityScore(Address),        // Per-source reliability score (0–100)
    AnomalyFlag(Symbol),          // Whether current price is flagged
    Governance,
    Paused,
}

#[contracttype]
#[derive(Clone)]
pub struct PriceSubmission {
    pub source:    Address,
    pub price:     i128,   // Price in smallest unit (e.g. 7 decimal places)
    pub timestamp: u64,
    pub confidence: u32,   // Source self-reported confidence 0–100
}

#[contracttype]
#[derive(Clone)]
pub struct PricePoint {
    pub price:     i128,
    pub timestamp: u64,
    pub sources:   u32,   // How many sources agreed
    pub anomaly:   bool,
}

#[contracttype]
#[derive(Clone)]
pub struct ConsensusResult {
    pub price:       i128,
    pub sources_used: u32,
    pub deviation:   i128,  // Max deviation from median in BPS
    pub is_valid:    bool,
    pub timestamp:   u64,
}

// ─────────────────────────────────────────────
// Contract
// ─────────────────────────────────────────────

#[contract]
pub struct OracleValidation;

#[contractimpl]
impl OracleValidation {

    // ── Initialization ───────────────────────

    pub fn initialize(env: Env, governance: Address) {
        if env.storage().instance().has(&OracleKey::Governance) {
            panic!("already initialised");
        }
        env.storage().instance().set(&OracleKey::Governance,   &governance);
        env.storage().instance().set(&OracleKey::SourceList,   &Vec::<Address>::new(&env));
        env.storage().instance().set(&OracleKey::Paused,       &false);
    }

    // ── Source Management ────────────────────

    pub fn add_source(env: Env, caller: Address, source: Address) {
        caller.require_auth();
        Self::require_governance(&env, &caller);
        let mut list: Vec<Address> = env.storage().instance()
            .get(&OracleKey::SourceList)
            .unwrap_or(Vec::new(&env));
        list.push_back(source.clone());
        env.storage().instance().set(&OracleKey::SourceList, &list);
        env.storage().instance().set(&OracleKey::QualityScore(source), &100u32);
    }

    pub fn remove_source(env: Env, caller: Address, source: Address) {
        caller.require_auth();
        Self::require_governance(&env, &caller);
        let mut list: Vec<Address> = env.storage().instance()
            .get(&OracleKey::SourceList)
            .unwrap_or(Vec::new(&env));
        // Filter out the source
        let mut new_list = Vec::<Address>::new(&env);
        for i in 0..list.len() {
            let s = list.get(i).unwrap();
            if s != source {
                new_list.push_back(s);
            }
        }
        env.storage().instance().set(&OracleKey::SourceList, &new_list);
    }

    // ── Price Submission ─────────────────────

    /// Called by each oracle source with its latest price for an asset.
    pub fn submit_price(
        env:     Env,
        source:  Address,
        asset:   Symbol,
        price:   i128,
        confidence: u32,
    ) {
        source.require_auth();
        Self::require_not_paused(&env);
        Self::require_approved_source(&env, &source);

        if price <= 0 {
            panic!("price must be positive");
        }
        if confidence > 100 {
            panic!("confidence must be 0–100");
        }

        let sub = PriceSubmission {
            source:     source.clone(),
            price,
            timestamp:  env.ledger().timestamp(),
            confidence,
        };
        env.storage().temporary().set(&OracleKey::SourcePrice(source.clone()), &sub);

        // Attempt to run consensus immediately
        let result = Self::run_consensus_internal(&env, &asset);
        if result.is_valid {
            Self::store_consensus(&env, &asset, &result);
        }
    }

    // ── Consensus Engine ─────────────────────

    /// Public trigger to re-evaluate consensus for an asset.
    pub fn evaluate_consensus(env: Env, asset: Symbol) -> ConsensusResult {
        let result = Self::run_consensus_internal(&env, &asset);
        if result.is_valid {
            Self::store_consensus(&env, &asset, &result);
        }
        result
    }

    fn run_consensus_internal(env: &Env, asset: &Symbol) -> ConsensusResult {
        let sources: Vec<Address> = env.storage().instance()
            .get(&OracleKey::SourceList)
            .unwrap_or(Vec::new(env));

        let now = env.ledger().timestamp();
        let mut prices = Vec::<i128>::new(env);

        // Collect fresh, non-stale submissions
        for i in 0..sources.len() {
            let source = sources.get(i).unwrap();
            if let Some(sub) = env.storage().temporary()
                .get::<OracleKey, PriceSubmission>(&OracleKey::SourcePrice(source.clone()))
            {
                if now.saturating_sub(sub.timestamp) <= STALENESS_THRESHOLD_SECS {
                    prices.push_back(sub.price);
                } else {
                    // Penalise stale source quality
                    let score: u32 = env.storage().instance()
                        .get(&OracleKey::QualityScore(source.clone()))
                        .unwrap_or(50);
                    env.storage().instance().set(
                        &OracleKey::QualityScore(source),
                        &score.saturating_sub(QUALITY_DECAY_PER_MISS),
                    );
                }
            }
        }

        let count = prices.len();
        if count < MIN_SOURCES_FOR_CONSENSUS {
            return ConsensusResult {
                price: 0,
                sources_used: count,
                deviation: 0,
                is_valid: false,
                timestamp: now,
            };
        }

        // Sort prices (insertion sort — small N, no_std)
        let sorted = Self::sort_prices(env, &prices);
        let median  = Self::median(&sorted);
        let max_dev = Self::max_deviation_bps(&sorted, median);

        if max_dev > MAX_PRICE_DEVIATION_BPS {
            log!(env, "consensus rejected: deviation {} bps", max_dev);
            return ConsensusResult {
                price: median,
                sources_used: count,
                deviation: max_dev,
                is_valid: false,
                timestamp: now,
            };
        }

        ConsensusResult {
            price: median,
            sources_used: count,
            deviation: max_dev,
            is_valid: true,
            timestamp: now,
        }
    }

    // ── Anomaly Detection ────────────────────

    fn detect_anomaly(env: &Env, asset: &Symbol, new_price: i128) -> bool {
        let history: Vec<PricePoint> = env.storage().persistent()
            .get(&OracleKey::PriceHistory(asset.clone()))
            .unwrap_or(Vec::new(env));

        if history.is_empty() {
            return false; // No history to compare against
        }

        // Use latest historical price
        let last = history.get(history.len() - 1).unwrap();
        let prev = last.price;

        if prev == 0 {
            return false;
        }

        let diff_bps = ((new_price - prev).abs() * 10_000) / prev;
        diff_bps > ANOMALY_MULTIPLIER_BPS
    }

    // ── Storage & History ────────────────────

    fn store_consensus(env: &Env, asset: &Symbol, result: &ConsensusResult) {
        let anomaly = Self::detect_anomaly(env, asset, result.price);

        if anomaly {
            env.storage().instance().set(&OracleKey::AnomalyFlag(asset.clone()), &true);
            log!(env, "anomaly detected for asset");
            // Still store but flag it; callers can decide how to handle
        } else {
            env.storage().instance().set(&OracleKey::AnomalyFlag(asset.clone()), &false);
        }

        let point = PricePoint {
            price:     result.price,
            timestamp: result.timestamp,
            sources:   result.sources_used,
            anomaly,
        };

        // Persist aggregated price
        env.storage().persistent().set(&OracleKey::AggregatedPrice(asset.clone()), &result.price);

        // Append to history (capped)
        let mut history: Vec<PricePoint> = env.storage().persistent()
            .get(&OracleKey::PriceHistory(asset.clone()))
            .unwrap_or(Vec::new(env));
        if history.len() >= HISTORY_MAX_ENTRIES {
            // Remove oldest
            let mut trimmed = Vec::<PricePoint>::new(env);
            for i in 1..history.len() {
                trimmed.push_back(history.get(i).unwrap());
            }
            history = trimmed;
        }
        history.push_back(point);
        env.storage().persistent().set(&OracleKey::PriceHistory(asset.clone()), &history);
    }

    // ── Fallback Pricing ──────────────────────

    pub fn set_fallback_price(env: Env, caller: Address, asset: Symbol, price: i128) {
        caller.require_auth();
        Self::require_governance(&env, &caller);
        env.storage().persistent().set(&OracleKey::FallbackPrice(asset), &price);
    }

    /// Get the validated price or fall back to the admin-set price.
    pub fn get_price(env: Env, asset: Symbol) -> i128 {
        let anomaly: bool = env.storage().instance()
            .get(&OracleKey::AnomalyFlag(asset.clone()))
            .unwrap_or(false);

        if !anomaly {
            if let Some(price) = env.storage().persistent()
                .get::<OracleKey, i128>(&OracleKey::AggregatedPrice(asset.clone()))
            {
                return price;
            }
        }

        // Fallback
        env.storage().persistent()
            .get(&OracleKey::FallbackPrice(asset))
            .expect("no price available and no fallback set")
    }

    // ── Data Quality Metrics ─────────────────

    pub fn get_source_quality(env: Env, source: Address) -> u32 {
        env.storage().instance()
            .get(&OracleKey::QualityScore(source))
            .unwrap_or(0)
    }

    pub fn get_price_history(env: Env, asset: Symbol) -> Vec<PricePoint> {
        env.storage().persistent()
            .get(&OracleKey::PriceHistory(asset))
            .unwrap_or(Vec::new(&env))
    }

    pub fn is_anomaly(env: Env, asset: Symbol) -> bool {
        env.storage().instance()
            .get(&OracleKey::AnomalyFlag(asset))
            .unwrap_or(false)
    }

    // ── Utilities ───────────────────────────

    fn sort_prices(env: &Env, prices: &Vec<i128>) -> Vec<i128> {
        let mut v = Vec::<i128>::new(env);
        for i in 0..prices.len() {
            v.push_back(prices.get(i).unwrap());
        }
        let n = v.len();
        for i in 0..n {
            for j in 0..n.saturating_sub(i + 1) {
                let a = v.get(j).unwrap();
                let b = v.get(j + 1).unwrap();
                if a > b {
                    v.set(j,     b);
                    v.set(j + 1, a);
                }
            }
        }
        v
    }

    fn median(sorted: &Vec<i128>) -> i128 {
        let n = sorted.len();
        if n == 0 { return 0; }
        if n % 2 == 1 {
            sorted.get(n / 2).unwrap()
        } else {
            let a = sorted.get(n / 2 - 1).unwrap();
            let b = sorted.get(n / 2).unwrap();
            (a + b) / 2
        }
    }

    fn max_deviation_bps(sorted: &Vec<i128>, median: i128) -> i128 {
        if median == 0 { return 0; }
        let mut max = 0i128;
        for i in 0..sorted.len() {
            let p = sorted.get(i).unwrap();
            let d = ((p - median).abs() * 10_000) / median;
            if d > max { max = d; }
        }
        max
    }

    fn require_governance(env: &Env, caller: &Address) {
        let gov: Address = env.storage().instance()
            .get(&OracleKey::Governance)
            .expect("governance not set");
        if *caller != gov {
            panic!("not governance");
        }
    }

    fn require_not_paused(env: &Env) {
        if env.storage().instance().get(&OracleKey::Paused).unwrap_or(false) {
            panic!("paused");
        }
    }

    fn require_approved_source(env: &Env, source: &Address) {
        let list: Vec<Address> = env.storage().instance()
            .get(&OracleKey::SourceList)
            .unwrap_or(Vec::new(env));
        let mut found = false;
        for i in 0..list.len() {
            if list.get(i).unwrap() == *source {
                found = true;
                break;
            }
        }
        if !found {
            panic!("source not approved");
        }
    }
}