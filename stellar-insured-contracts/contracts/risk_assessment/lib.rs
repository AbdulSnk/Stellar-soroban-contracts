#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, Symbol, Vec, Map};

use insurance_contracts::authorization::{
    get_role, initialize_admin, register_trusted_contract, require_admin,
    require_risk_pool_management, Role,
};
use insurance_contracts::emergency_pause::EmergencyPause;

#[contract]
pub struct RiskAssessmentContract;

const PAUSED: Symbol = Symbol::short("PAUSED");
const CONFIG: Symbol = Symbol::short("CONFIG");
const RISK_MODEL: Symbol = Symbol::short("RISK_MD");
const PORTFOLIO: Symbol = Symbol::short("PORTFOLIO");
const PRICING_MODEL: Symbol = Symbol::short("PRICING_MD");
const UNDERWRITING_RULES: Symbol = Symbol::short("UNDERWR");

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct RiskProfile {
    pub user_address: Address,
    pub risk_score: u32, // 0-1000
    pub risk_level: RiskLevel,
    pub coverage_history: Vec<u64>, // policy_ids
    pub claim_history: Vec<u64>,   // claim_ids
    pub total_premiums_paid: i128,
    pub total_claims_paid: i128,
    pub last_updated: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct DynamicPricingModel {
    pub base_premium_rate: u32, // basis points
    pub risk_multiplier: u32,    // basis points
    pub portfolio_adjustment: i32, // basis points
    pub market_factor: u32,       // basis points
    pub last_updated: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct UnderwritingRule {
    pub rule_id: u64,
    pub name: Symbol,
    pub condition: Symbol, // e.g., "min_score", "max_claims"
    pub threshold: u32,
    pub action: Symbol,   // e.g., "approve", "manual_review", "reject"
    pub is_active: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PortfolioMetrics {
    pub total_policies: u64,
    pub active_policies: u64,
    pub total_coverage: i128,
    pub total_premiums: i128,
    pub risk_distribution: Map<RiskLevel, u32>, // percentage
    pub utilization_rate: u32, // basis points
    pub expected_loss_ratio: u32, // basis points
    pub last_calculated: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct RiskAssessmentResult {
    pub user_address: Address,
    pub risk_score: u32,
    pub risk_level: RiskLevel,
    pub recommended_premium: i128,
    pub max_coverage: i128,
    pub requires_manual_review: bool,
    pub assessment_timestamp: u64,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ContractError {
    Unauthorized = 1,
    Paused = 2,
    InvalidInput = 3,
    NotFound = 4,
    NotInitialized = 5,
    InvalidRole = 6,
    RoleNotFound = 7,
    NotTrustedContract = 8,
    InvalidRiskScore = 100,
    InsufficientData = 101,
    PricingModelNotFound = 102,
    UnderwritingRuleNotFound = 103,
}

impl From<insurance_contracts::authorization::AuthError> for ContractError {
    fn from(err: insurance_contracts::authorization::AuthError) -> Self {
        match err {
            insurance_contracts::authorization::AuthError::Unauthorized => ContractError::Unauthorized,
            insurance_contracts::authorization::AuthError::InvalidRole => ContractError::InvalidRole,
            insurance_contracts::authorization::AuthError::RoleNotFound => ContractError::RoleNotFound,
            insurance_contracts::authorization::AuthError::NotTrustedContract => ContractError::NotTrustedContract,
        }
    }
}

fn validate_address(_env: &Env, _address: &Address) -> Result<(), ContractError> {
    Ok(())
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

fn validate_risk_score(score: u32) -> Result<(), ContractError> {
    if score > 1000 {
        return Err(ContractError::InvalidRiskScore);
    }
    Ok(())
}

fn calculate_risk_level(score: u32) -> RiskLevel {
    if score <= 250 {
        RiskLevel::Low
    } else if score <= 500 {
        RiskLevel::Medium
    } else if score <= 750 {
        RiskLevel::High
    } else {
        RiskLevel::Critical
    }
}

#[contractimpl]
impl RiskAssessmentContract {
    pub fn initialize(
        env: Env,
        admin: Address,
        policy_contract: Address,
        claims_contract: Address,
        risk_pool_contract: Address,
    ) -> Result<(), ContractError> {
        if insurance_contracts::authorization::get_admin(&env).is_some() {
            return Err(ContractError::NotInitialized);
        }

        validate_address(&env, &admin)?;
        validate_address(&env, &policy_contract)?;
        validate_address(&env, &claims_contract)?;
        validate_address(&env, &risk_pool_contract)?;

        admin.require_auth();
        initialize_admin(&env, admin.clone());

        register_trusted_contract(&env, &admin, &policy_contract)?;
        register_trusted_contract(&env, &admin, &claims_contract)?;
        register_trusted_contract(&env, &admin, &risk_pool_contract)?;

        let config = (policy_contract, claims_contract, risk_pool_contract);
        env.storage().persistent().set(&CONFIG, &config);

        // Initialize default pricing model
        let default_pricing = DynamicPricingModel {
            base_premium_rate: 100, // 1%
            risk_multiplier: 50,     // 0.5%
            portfolio_adjustment: 0,
            market_factor: 0,
            last_updated: env.ledger().timestamp(),
        };
        env.storage().persistent().set(&PRICING_MODEL, &default_pricing);

        // Initialize default underwriting rules
        let mut rules = Vec::new(&env);
        rules.push_back(UnderwritingRule {
            rule_id: 1,
            name: Symbol::short("MAX_RISK"),
            condition: Symbol::short("max_score"),
            threshold: 900,
            action: Symbol::short("manual_review"),
            is_active: true,
        });
        rules.push_back(UnderwritingRule {
            rule_id: 2,
            name: Symbol::short("MIN_HISTORY"),
            condition: Symbol::short("min_policies"),
            threshold: 0,
            action: Symbol::short("approve"),
            is_active: true,
        });
        env.storage().persistent().set(&UNDERWRITING_RULES, &rules);

        // Initialize emergency pause system
        EmergencyPause::initialize(&env, &admin)?;

        env.events().publish((Symbol::new(&env, "initialized"), ()), admin);

        Ok(())
    }

    /// Assess risk for a user based on their history and current data
    pub fn assess_risk(
        env: Env,
        user: Address,
        coverage_amount: i128,
        policy_type: Symbol,
    ) -> Result<RiskAssessmentResult, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_address(&env, &user)?;

        // Get or create risk profile
        let mut risk_profile = Self::get_risk_profile(env.clone(), user.clone())?;

        // Calculate base risk score from historical data
        let mut risk_score = Self::calculate_historical_risk_score(&env, &risk_profile)?;

        // Apply policy type adjustments
        risk_score = Self::apply_policy_type_adjustment(risk_score, policy_type);

        // Apply coverage amount adjustments
        risk_score = Self::apply_coverage_amount_adjustment(risk_score, coverage_amount);

        validate_risk_score(risk_score)?;
        let risk_level = calculate_risk_level(risk_score);

        // Get current pricing model
        let pricing_model: DynamicPricingModel = env.storage().persistent()
            .get(&PRICING_MODEL)
            .ok_or(ContractError::PricingModelNotFound)?;

        // Calculate recommended premium
        let recommended_premium = Self::calculate_dynamic_premium(
            coverage_amount,
            risk_score,
            &pricing_model,
        );

        // Determine max coverage based on risk level
        let max_coverage = Self::calculate_max_coverage(risk_level, coverage_amount);

        // Check underwriting rules
        let requires_manual_review = Self::evaluate_underwriting_rules(
            &env,
            risk_score,
            &risk_profile,
        )?;

        let result = RiskAssessmentResult {
            user_address: user.clone(),
            risk_score,
            risk_level,
            recommended_premium,
            max_coverage,
            requires_manual_review,
            assessment_timestamp: env.ledger().timestamp(),
        };

        // Update risk profile
        risk_profile.risk_score = risk_score;
        risk_profile.risk_level = risk_level;
        risk_profile.last_updated = env.ledger().timestamp();

        env.storage().persistent().set(&RISK_MODEL, user, &risk_profile);

        env.events().publish(
            (Symbol::new(&env, "risk_assessed"), user),
            (risk_score, risk_level, recommended_premium),
        );

        Ok(result)
    }

    /// Update pricing model parameters
    pub fn update_pricing_model(
        env: Env,
        admin: Address,
        base_premium_rate: u32,
        risk_multiplier: u32,
        portfolio_adjustment: i32,
        market_factor: u32,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let pricing_model = DynamicPricingModel {
            base_premium_rate,
            risk_multiplier,
            portfolio_adjustment,
            market_factor,
            last_updated: env.ledger().timestamp(),
        };

        env.storage().persistent().set(&PRICING_MODEL, &pricing_model);

        env.events().publish(
            (Symbol::new(&env, "pricing_model_updated"), admin),
            (base_premium_rate, risk_multiplier, portfolio_adjustment, market_factor),
        );

        Ok(())
    }

    /// Add or update underwriting rule
    pub fn update_underwriting_rule(
        env: Env,
        admin: Address,
        rule_id: u64,
        name: Symbol,
        condition: Symbol,
        threshold: u32,
        action: Symbol,
        is_active: bool,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let mut rules: Vec<UnderwritingRule> = env.storage().persistent()
            .get(&UNDERWRITING_RULES)
            .unwrap_or_else(|| Vec::new(&env));

        // Find and update existing rule or add new one
        let mut found = false;
        for i in 0..rules.len() {
            if let Some(rule) = rules.get(i) {
                if rule.rule_id == rule_id {
                    let updated_rule = UnderwritingRule {
                        rule_id,
                        name,
                        condition,
                        threshold,
                        action,
                        is_active,
                    };
                    rules.set(i, updated_rule);
                    found = true;
                    break;
                }
            }
        }

        if !found {
            rules.push_back(UnderwritingRule {
                rule_id,
                name,
                condition,
                threshold,
                action,
                is_active,
            });
        }

        env.storage().persistent().set(&UNDERWRITING_RULES, &rules);

        env.events().publish(
            (Symbol::new(&env, "underwriting_rule_updated"), admin),
            (rule_id, name, condition, threshold, action, is_active),
        );

        Ok(())
    }

    /// Calculate portfolio metrics for optimization
    pub fn calculate_portfolio_metrics(env: Env) -> Result<PortfolioMetrics, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let config: (Address, Address, Address) = env.storage().persistent()
            .get(&CONFIG)
            .ok_or(ContractError::NotInitialized)?;

        let policy_contract = config.0;
        let claims_contract = config.1;

        // This would typically involve cross-contract calls to get real data
        // For now, we'll calculate based on stored risk profiles
        let mut total_policies = 0u64;
        let mut total_coverage = 0i128;
        let mut total_premiums = 0i128;
        let mut risk_distribution = Map::new(&env);

        // Initialize risk distribution
        risk_distribution.set(RiskLevel::Low, 0u32);
        risk_distribution.set(RiskLevel::Medium, 0u32);
        risk_distribution.set(RiskLevel::High, 0u32);
        risk_distribution.set(RiskLevel::Critical, 0u32);

        // Calculate metrics from risk profiles (simplified)
        let current_time = env.ledger().timestamp();
        let utilization_rate = if total_coverage > 0 {
            ((total_premiums * 10000) / total_coverage) as u32
        } else {
            0
        };

        let expected_loss_ratio = 650; // 6.5% default

        let metrics = PortfolioMetrics {
            total_policies,
            active_policies: total_policies, // Simplified
            total_coverage,
            total_premiums,
            risk_distribution,
            utilization_rate,
            expected_loss_ratio,
            last_calculated: current_time,
        };

        env.storage().persistent().set(&PORTFOLIO, &metrics);

        env.events().publish(
            (Symbol::new(&env, "portfolio_metrics_calculated"), ()),
            (total_policies, total_coverage, utilization_rate, expected_loss_ratio),
        );

        Ok(metrics)
    }

    /// Get risk profile for a user
    pub fn get_risk_profile(env: Env, user: Address) -> Result<RiskProfile, ContractError> {
        validate_address(&env, &user)?;

        env.storage().persistent()
            .get(&RISK_MODEL, user)
            .ok_or(ContractError::NotFound)
    }

    /// Get current pricing model
    pub fn get_pricing_model(env: Env) -> Result<DynamicPricingModel, ContractError> {
        env.storage().persistent()
            .get(&PRICING_MODEL)
            .ok_or(ContractError::PricingModelNotFound)
    }

    /// Get underwriting rules
    pub fn get_underwriting_rules(env: Env) -> Result<Vec<UnderwritingRule>, ContractError> {
        Ok(env.storage().persistent()
            .get(&UNDERWRITING_RULES)
            .unwrap_or_else(|| Vec::new(&env)))
    }

    /// Get portfolio metrics
    pub fn get_portfolio_metrics(env: Env) -> Result<PortfolioMetrics, ContractError> {
        env.storage().persistent()
            .get(&PORTFOLIO)
            .ok_or(ContractError::NotFound)
    }

    /// Update user's policy history (called by policy contract)
    pub fn update_policy_history(
        env: Env,
        caller: Address,
        user: Address,
        policy_id: u64,
    ) -> Result<(), ContractError> {
        caller.require_auth();
        require_trusted_contract(&env, &caller)?;

        let mut risk_profile = Self::get_risk_profile(env.clone(), user.clone())?;
        risk_profile.coverage_history.push_back(policy_id);
        risk_profile.last_updated = env.ledger().timestamp();

        env.storage().persistent().set(&RISK_MODEL, user, &risk_profile);

        Ok(())
    }

    /// Update user's claim history (called by claims contract)
    pub fn update_claim_history(
        env: Env,
        caller: Address,
        user: Address,
        claim_id: u64,
        claim_amount: i128,
    ) -> Result<(), ContractError> {
        caller.require_auth();
        require_trusted_contract(&env, &caller)?;

        let mut risk_profile = Self::get_risk_profile(env.clone(), user.clone())?;
        risk_profile.claim_history.push_back(claim_id);
        risk_profile.total_claims_paid += claim_amount;
        risk_profile.last_updated = env.ledger().timestamp();

        env.storage().persistent().set(&RISK_MODEL, user, &risk_profile);

        Ok(())
    }

    // Helper functions

    fn calculate_historical_risk_score(env: &Env, profile: &RiskProfile) -> Result<u32, ContractError> {
        let mut base_score = 500u32; // Start with medium risk

        // Adjust based on claim history
        let claim_count = profile.claim_history.len() as u32;
        if claim_count > 0 {
            let claim_penalty = claim_count * 50; // 50 points per claim
            base_score = base_score.saturating_add(claim_penalty);
        }

        // Adjust based on claim amount vs premiums
        if profile.total_premiums_paid > 0 {
            let loss_ratio = (profile.total_claims_paid * 10000) / profile.total_premiums_paid;
            if loss_ratio > 8000 { // > 80%
                base_score = base_score.saturating_add(200);
            } else if loss_ratio > 5000 { // > 50%
                base_score = base_score.saturating_add(100);
            }
        }

        // Adjust based on policy history (more policies = lower risk)
        let policy_count = profile.coverage_history.len() as u32;
        if policy_count > 5 {
            base_score = base_score.saturating_sub(100);
        } else if policy_count > 2 {
            base_score = base_score.saturating_sub(50);
        }

        Ok(base_score.min(1000))
    }

    fn apply_policy_type_adjustment(base_score: u32, policy_type: Symbol) -> u32 {
        // Different policy types have different risk profiles
        match policy_type.to_string().as_str() {
            "life" => base_score.saturating_sub(50),    // Lower risk
            "health" => base_score,                      // Neutral
            "property" => base_score.saturating_add(50), // Higher risk
            "travel" => base_score.saturating_add(25),   // Slightly higher
            _ => base_score,                             // Default
        }
    }

    fn apply_coverage_amount_adjustment(base_score: u32, coverage_amount: i128) -> u32 {
        // Higher coverage amounts might indicate higher risk
        if coverage_amount > 1000000000 { // > 10,000 units
            base_score.saturating_add(75)
        } else if coverage_amount > 100000000 { // > 1,000 units
            base_score.saturating_add(25)
        } else {
            base_score
        }
    }

    fn calculate_dynamic_premium(
        coverage_amount: i128,
        risk_score: u32,
        pricing_model: &DynamicPricingModel,
    ) -> i128 {
        let base_premium = (coverage_amount * pricing_model.base_premium_rate as i128) / 10000;
        let risk_adjustment = (coverage_amount * risk_score as i128 * pricing_model.risk_multiplier as i128) / (10000 * 1000);
        let portfolio_adjustment = (coverage_amount * pricing_model.portfolio_adjustment as i128) / 10000;
        let market_adjustment = (coverage_amount * pricing_model.market_factor as i128) / 10000;

        base_premium + risk_adjustment + portfolio_adjustment + market_adjustment
    }

    fn calculate_max_coverage(risk_level: RiskLevel, requested_coverage: i128) -> i128 {
        match risk_level {
            RiskLevel::Low => requested_coverage * 2,      // 2x requested
            RiskLevel::Medium => requested_coverage * 150 / 100, // 1.5x requested
            RiskLevel::High => requested_coverage,          // 1x requested
            RiskLevel::Critical => requested_coverage * 75 / 100, // 0.75x requested
        }
    }

    fn evaluate_underwriting_rules(
        env: &Env,
        risk_score: u32,
        risk_profile: &RiskProfile,
    ) -> Result<bool, ContractError> {
        let rules: Vec<UnderwritingRule> = env.storage().persistent()
            .get(&UNDERWRITING_RULES)
            .unwrap_or_else(|| Vec::new(env));

        for rule in rules {
            if !rule.is_active {
                continue;
            }

            let condition_met = match rule.condition.to_string().as_str() {
                "max_score" => risk_score > rule.threshold,
                "min_score" => risk_score < rule.threshold,
                "max_claims" => risk_profile.claim_history.len() as u32 > rule.threshold,
                "min_policies" => risk_profile.coverage_history.len() as u32 >= rule.threshold,
                _ => false,
            };

            if condition_met {
                match rule.action.to_string().as_str() {
                    "manual_review" => return Ok(true),
                    "reject" => return Ok(true),
                    _ => continue,
                }
            }
        }

        Ok(false)
    }

    /// Pause the contract
    pub fn pause(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        set_paused(&env, true);

        env.events().publish((Symbol::new(&env, "paused"), ()), admin);

        Ok(())
    }

    /// Unpause the contract
    pub fn unpause(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        set_paused(&env, false);

        env.events().publish((Symbol::new(&env, "unpaused"), ()), admin);

        Ok(())
    }

    /// Emergency pause
    pub fn emergency_pause(
        env: Env,
        admin: Address,
        reason: Symbol,
        max_duration_seconds: u64,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        EmergencyPause::activate_emergency_pause(&env, &admin, reason, max_duration_seconds)
    }
}
