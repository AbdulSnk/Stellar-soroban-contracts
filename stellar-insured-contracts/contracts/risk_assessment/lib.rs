#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, log, Address, Env, Map, Symbol, Vec,
};

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
const EXTERNAL_RISK_DATA: Symbol = Symbol::short("EXT_RISK");
const ML_MODEL_WEIGHTS: Symbol = Symbol::short("ML_WEIGHTS");
const REAL_TIME_MONITORING: Symbol = Symbol::short("RT_MONITOR");
const PORTFOLIO_OPTIMIZATION: Symbol = Symbol::short("PORT_OPT");

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RiskFactor {
    CreditScore,
    ClaimHistory,
    Age,
    Occupation,
    Location,
    Health,
    MarketVolatility,
    ExternalEvents,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MLModelWeights {
    pub feature_weights: Map<RiskFactor, i32>, // basis points
    pub bias: i32,
    pub model_version: u32,
    pub last_trained: u64,
    pub accuracy_score: u32, // basis points
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct ExternalRiskData {
    pub data_source: Symbol,
    pub data_type: Symbol,
    pub value: i128,
    pub confidence_score: u32, // basis points
    pub timestamp: u64,
    pub relevance_weight: u32, // basis points
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct RealTimeRiskAlert {
    pub alert_id: u64,
    pub user_address: Address,
    pub risk_factor: RiskFactor,
    pub severity: RiskLevel,
    pub current_value: i128,
    pub threshold_value: i128,
    pub timestamp: u64,
    pub action_required: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PortfolioOptimizationResult {
    pub optimal_allocation: Map<RiskLevel, u32>, // percentage
    pub expected_return: i128,
    pub risk_adjusted_return: i128,
    pub sharpe_ratio: u32, // scaled by 1000
    pub max_drawdown: u32, // basis points
    pub volatility: u32,   // basis points
    pub optimization_timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct RiskProfile {
    pub user_address: Address,
    pub risk_score: u32, // 0-1000
    pub risk_level: RiskLevel,
    pub coverage_history: Vec<u64>, // policy_ids
    pub claim_history: Vec<u64>,    // claim_ids
    pub total_premiums_paid: i128,
    pub total_claims_paid: i128,
    pub last_updated: u64,
    // Advanced fields
    pub behavioral_score: u32,
    pub predictive_score: u32,
    pub external_factors: Map<RiskFactor, i128>,
    pub trend_analysis: Map<Symbol, i32>, // trend direction and strength
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct DynamicPricingModel {
    pub base_premium_rate: u32,    // basis points
    pub risk_multiplier: u32,      // basis points
    pub portfolio_adjustment: i32, // basis points
    pub market_factor: u32,        // basis points
    pub last_updated: u64,
    // Advanced pricing factors
    pub volatility_adjustment: u32,
    pub liquidity_premium: u32,
    pub correlation_discount: u32,
    pub tail_risk_adjustment: u32,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct UnderwritingRule {
    pub rule_id: u64,
    pub name: Symbol,
    pub condition: Symbol, // e.g., "min_score", "max_claims"
    pub threshold: u32,
    pub action: Symbol, // e.g., "approve", "manual_review", "reject"
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
    pub utilization_rate: u32,                  // basis points
    pub expected_loss_ratio: u32,               // basis points
    pub last_calculated: u64,
    // Advanced metrics
    pub value_at_risk_95: i128, // VaR at 95% confidence
    pub conditional_var: i128,  // Expected shortfall
    pub maximum_drawdown: u32,  // basis points
    pub correlation_matrix: Map<RiskLevel, Map<RiskLevel, i32>>, // correlation coefficients
    pub concentration_risk: u32, // basis points
    pub diversification_ratio: u32, // basis points
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
    // Advanced assessment results
    pub confidence_interval: (i128, i128), // min, max expected loss
    pub probability_of_default: u32,       // basis points
    pub loss_given_default: u32,           // basis points
    pub expected_loss: i128,
    pub risk_contributions: Map<RiskFactor, u32>, // percentage contribution
    pub model_confidence: u32,                    // basis points
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
    MLModelNotFound = 104,
    ExternalDataInvalid = 105,
    OptimizationFailed = 106,
    RealTimeMonitoringFailed = 107,
    CorrelationCalculationFailed = 108,
    VaRCalculationFailed = 109,
}

impl From<insurance_contracts::authorization::AuthError> for ContractError {
    fn from(err: insurance_contracts::authorization::AuthError) -> Self {
        match err {
            insurance_contracts::authorization::AuthError::Unauthorized => {
                ContractError::Unauthorized
            }
            insurance_contracts::authorization::AuthError::InvalidRole => {
                ContractError::InvalidRole
            }
            insurance_contracts::authorization::AuthError::RoleNotFound => {
                ContractError::RoleNotFound
            }
            insurance_contracts::authorization::AuthError::NotTrustedContract => {
                ContractError::NotTrustedContract
            }
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

        // Initialize default pricing model with advanced factors
        let default_pricing = DynamicPricingModel {
            base_premium_rate: 100, // 1%
            risk_multiplier: 50,    // 0.5%
            portfolio_adjustment: 0,
            market_factor: 0,
            last_updated: env.ledger().timestamp(),
            volatility_adjustment: 25, // 0.25%
            liquidity_premium: 10,     // 0.1%
            correlation_discount: 5,   // 0.05%
            tail_risk_adjustment: 15,  // 0.15%
        };
        env.storage().persistent().set(&PRICING_MODEL, &default_pricing);

        // Initialize default ML model weights
        let mut feature_weights = Map::new(&env);
        feature_weights.set(RiskFactor::CreditScore, 3000); // 30% weight
        feature_weights.set(RiskFactor::ClaimHistory, 2500); // 25% weight
        feature_weights.set(RiskFactor::Age, 1500); // 15% weight
        feature_weights.set(RiskFactor::Occupation, 1000); // 10% weight
        feature_weights.set(RiskFactor::Location, 800); // 8% weight
        feature_weights.set(RiskFactor::Health, 700); // 7% weight
        feature_weights.set(RiskFactor::MarketVolatility, 300); // 3% weight
        feature_weights.set(RiskFactor::ExternalEvents, 200); // 2% weight

        let default_ml_weights = MLModelWeights {
            feature_weights,
            bias: 500,
            model_version: 1,
            last_trained: env.ledger().timestamp(),
            accuracy_score: 8500, // 85% accuracy
        };
        env.storage().persistent().set(&ML_MODEL_WEIGHTS, &default_ml_weights);

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

    /// Advanced risk assessment using ML models and external data
    pub fn advanced_risk_assessment(
        env: Env,
        user: Address,
        coverage_amount: i128,
        policy_type: Symbol,
        external_data: Vec<ExternalRiskData>,
    ) -> Result<RiskAssessmentResult, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_address(&env, &user)?;

        // Get or create enhanced risk profile
        let mut risk_profile = Self::get_risk_profile(env.clone(), user.clone())?;

        // Initialize advanced fields if not present
        if risk_profile.behavioral_score == 0 {
            risk_profile.behavioral_score = 500; // Default neutral
        }
        if risk_profile.predictive_score == 0 {
            risk_profile.predictive_score = 500; // Default neutral
        }
        if risk_profile.external_factors.is_empty() {
            risk_profile.external_factors = Map::new(&env);
        }
        if risk_profile.trend_analysis.is_empty() {
            risk_profile.trend_analysis = Map::new(&env);
        }

        // Get ML model weights
        let ml_weights: MLModelWeights = env
            .storage()
            .persistent()
            .get(&ML_MODEL_WEIGHTS)
            .ok_or(ContractError::MLModelNotFound)?;

        // Process external risk data
        let processed_external_data = Self::process_external_data(&env, external_data)?;

        // Update external factors in risk profile
        for data in processed_external_data.iter() {
            let factor = Self::map_data_type_to_risk_factor(data.data_type);
            risk_profile.external_factors.set(factor, data.value);
        }

        // Calculate ML-based risk score
        let ml_risk_score = Self::calculate_ml_risk_score(
            &risk_profile,
            &ml_weights,
            coverage_amount,
            policy_type,
        )?;

        // Calculate behavioral score
        let behavioral_score = Self::calculate_behavioral_score(&risk_profile)?;
        risk_profile.behavioral_score = behavioral_score;

        // Calculate predictive score
        let predictive_score = Self::calculate_predictive_score(&risk_profile)?;
        risk_profile.predictive_score = predictive_score;

        // Combine scores with weights
        let final_risk_score =
            (ml_risk_score * 50 + behavioral_score * 30 + predictive_score * 20) / 100;

        validate_risk_score(final_risk_score)?;
        let risk_level = calculate_risk_level(final_risk_score);

        // Get advanced pricing model
        let pricing_model: DynamicPricingModel = env
            .storage()
            .persistent()
            .get(&PRICING_MODEL)
            .ok_or(ContractError::PricingModelNotFound)?;

        // Calculate advanced premium with all factors
        let recommended_premium = Self::calculate_advanced_premium(
            coverage_amount,
            final_risk_score,
            &pricing_model,
            &risk_profile,
        );

        // Calculate risk metrics
        let probability_of_default = Self::calculate_probability_of_default(final_risk_score);
        let loss_given_default = Self::calculate_loss_given_default(risk_level);
        let expected_loss =
            (recommended_premium * probability_of_default as i128 * loss_given_default as i128)
                / (10000 * 10000);

        // Calculate confidence interval
        let confidence_interval =
            Self::calculate_confidence_interval(expected_loss, final_risk_score, &ml_weights);

        // Calculate risk contributions
        let risk_contributions = Self::calculate_risk_contributions(&risk_profile, &ml_weights);

        // Determine max coverage
        let max_coverage = Self::calculate_max_coverage(risk_level, coverage_amount);

        // Check underwriting rules
        let requires_manual_review =
            Self::evaluate_underwriting_rules(&env, final_risk_score, &risk_profile)?;

        let result = RiskAssessmentResult {
            user_address: user.clone(),
            risk_score: final_risk_score,
            risk_level,
            recommended_premium,
            max_coverage,
            requires_manual_review,
            assessment_timestamp: env.ledger().timestamp(),
            confidence_interval,
            probability_of_default,
            loss_given_default,
            expected_loss,
            risk_contributions,
            model_confidence: ml_weights.accuracy_score,
        };

        // Update risk profile
        risk_profile.risk_score = final_risk_score;
        risk_profile.risk_level = risk_level;
        risk_profile.last_updated = env.ledger().timestamp();

        env.storage().persistent().set(&RISK_MODEL, user, &risk_profile);

        env.events().publish(
            (Symbol::new(&env, "advanced_risk_assessed"), user),
            (final_risk_score, risk_level, recommended_premium, probability_of_default),
        );

        Ok(result)
    }

    /// Update ML model weights
    pub fn update_ml_model(
        env: Env,
        admin: Address,
        feature_weights: Map<RiskFactor, i32>,
        bias: i32,
        model_version: u32,
        accuracy_score: u32,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let ml_weights = MLModelWeights {
            feature_weights,
            bias,
            model_version,
            last_trained: env.ledger().timestamp(),
            accuracy_score,
        };

        env.storage().persistent().set(&ML_MODEL_WEIGHTS, &ml_weights);

        env.events().publish(
            (Symbol::new(&env, "ml_model_updated"), admin),
            (model_version, accuracy_score),
        );

        Ok(())
    }

    /// Add external risk data
    pub fn add_external_risk_data(
        env: Env,
        oracle: Address,
        data: ExternalRiskData,
    ) -> Result<(), ContractError> {
        oracle.require_auth();
        require_trusted_contract(&env, &oracle)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Validate external data
        if data.confidence_score > 10000 || data.relevance_weight > 10000 {
            return Err(ContractError::ExternalDataInvalid);
        }

        let data_key = (EXTERNAL_RISK_DATA, data.data_type, data.timestamp);
        env.storage().persistent().set(&data_key, &data);

        env.events().publish(
            (Symbol::new(&env, "external_risk_data_added"), oracle),
            (data.data_type, data.value, data.confidence_score),
        );

        Ok(())
    }

    /// Real-time risk monitoring
    pub fn monitor_real_time_risk(
        env: Env,
        user: Address,
        risk_factor: RiskFactor,
        current_value: i128,
        threshold_value: i128,
    ) -> Result<RealTimeRiskAlert, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_address(&env, &user)?;

        let current_time = env.ledger().timestamp();
        let alert_id = current_time; // Use timestamp as unique ID

        // Determine severity based on deviation from threshold
        let deviation = if current_value > threshold_value {
            current_value - threshold_value
        } else {
            threshold_value - current_value
        };

        let severity = match deviation {
            0..=100 => RiskLevel::Low,
            101..=500 => RiskLevel::Medium,
            501..=1000 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        let action_required = matches!(severity, RiskLevel::High | RiskLevel::Critical);

        let alert = RealTimeRiskAlert {
            alert_id,
            user_address: user.clone(),
            risk_factor,
            severity,
            current_value,
            threshold_value,
            timestamp: current_time,
            action_required,
        };

        // Store alert
        let alert_key = (REAL_TIME_MONITORING, alert_id);
        env.storage().persistent().set(&alert_key, &alert);

        env.events().publish(
            (Symbol::new(&env, "risk_alert"), user),
            (alert_id, risk_factor, severity, action_required),
        );

        Ok(alert)
    }

    /// Portfolio optimization using modern portfolio theory
    pub fn optimize_portfolio(
        env: Env,
        risk_tolerance: u32, // 0-1000
        expected_returns: Map<RiskLevel, i128>,
        covariance_matrix: Map<(RiskLevel, RiskLevel), i32>,
    ) -> Result<PortfolioOptimizationResult, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        if risk_tolerance > 1000 {
            return Err(ContractError::InvalidInput);
        }

        // Calculate optimal allocation using mean-variance optimization
        let optimal_allocation = Self::calculate_optimal_allocation(
            risk_tolerance,
            &expected_returns,
            &covariance_matrix,
        )?;

        // Calculate portfolio metrics
        let expected_return =
            Self::calculate_portfolio_expected_return(&optimal_allocation, &expected_returns);

        let portfolio_risk =
            Self::calculate_portfolio_risk(&optimal_allocation, &covariance_matrix);

        let risk_adjusted_return = if portfolio_risk > 0 {
            (expected_return * 10000) / portfolio_risk
        } else {
            0
        };

        let sharpe_ratio = (risk_adjusted_return * 1000) / 10000; // Scale by 1000

        let max_drawdown = Self::estimate_max_drawdown(risk_tolerance);
        let volatility = portfolio_risk;

        let result = PortfolioOptimizationResult {
            optimal_allocation,
            expected_return,
            risk_adjusted_return,
            sharpe_ratio,
            max_drawdown,
            volatility,
            optimization_timestamp: env.ledger().timestamp(),
        };

        // Store optimization result
        env.storage().persistent().set(&PORTFOLIO_OPTIMIZATION, &result);

        env.events().publish(
            (Symbol::new(&env, "portfolio_optimized"), ()),
            (expected_return, sharpe_ratio, max_drawdown),
        );

        Ok(result)
    }

    /// Enhanced portfolio metrics with VaR and correlation analysis
    pub fn calculate_enhanced_portfolio_metrics(
        env: Env,
        confidence_level: u32, // basis points, e.g., 9500 for 95%
        time_horizon_days: u32,
    ) -> Result<PortfolioMetrics, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        if confidence_level > 10000 || confidence_level < 5000 {
            return Err(ContractError::InvalidInput);
        }

        let config: (Address, Address, Address) =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;

        // Get base metrics
        let mut base_metrics = Self::calculate_portfolio_metrics(env.clone())?;

        // Calculate VaR
        let var_95 =
            Self::calculate_value_at_risk(&base_metrics, confidence_level, time_horizon_days)?;
        base_metrics.value_at_risk_95 = var_95;

        // Calculate Conditional VaR (Expected Shortfall)
        let conditional_var =
            Self::calculate_conditional_var(&base_metrics, confidence_level, time_horizon_days)?;
        base_metrics.conditional_var = conditional_var;

        // Calculate correlation matrix
        let correlation_matrix = Self::calculate_correlation_matrix(&env)?;
        base_metrics.correlation_matrix = correlation_matrix;

        // Calculate concentration risk
        let concentration_risk = Self::calculate_concentration_risk(&base_metrics);
        base_metrics.concentration_risk = concentration_risk;

        // Calculate diversification ratio
        let diversification_ratio = Self::calculate_diversification_ratio(&base_metrics);
        base_metrics.diversification_ratio = diversification_ratio;

        // Estimate maximum drawdown
        let max_drawdown =
            Self::estimate_max_drawdown_from_volatility(base_metrics.utilization_rate);
        base_metrics.maximum_drawdown = max_drawdown;

        env.storage().persistent().set(&PORTFOLIO, &base_metrics);

        env.events().publish(
            (Symbol::new(&env, "enhanced_portfolio_metrics_calculated"), ()),
            (var_95, conditional_var, concentration_risk, diversification_ratio),
        );

        Ok(base_metrics)
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

        let mut rules: Vec<UnderwritingRule> = env
            .storage()
            .persistent()
            .get(&UNDERWRITING_RULES)
            .unwrap_or_else(|| Vec::new(&env));

        // Find and update existing rule or add new one
        let mut found = false;
        for i in 0..rules.len() {
            if let Some(rule) = rules.get(i) {
                if rule.rule_id == rule_id {
                    let updated_rule =
                        UnderwritingRule { rule_id, name, condition, threshold, action, is_active };
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

        let config: (Address, Address, Address) =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;

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

        env.storage().persistent().get(&RISK_MODEL, user).ok_or(ContractError::NotFound)
    }

    /// Get current pricing model
    pub fn get_pricing_model(env: Env) -> Result<DynamicPricingModel, ContractError> {
        env.storage()
            .persistent()
            .get(&PRICING_MODEL)
            .ok_or(ContractError::PricingModelNotFound)
    }

    /// Get underwriting rules
    pub fn get_underwriting_rules(env: Env) -> Result<Vec<UnderwritingRule>, ContractError> {
        Ok(env
            .storage()
            .persistent()
            .get(&UNDERWRITING_RULES)
            .unwrap_or_else(|| Vec::new(&env)))
    }

    /// Get portfolio metrics
    pub fn get_portfolio_metrics(env: Env) -> Result<PortfolioMetrics, ContractError> {
        env.storage().persistent().get(&PORTFOLIO).ok_or(ContractError::NotFound)
    }

    /// Get ML model weights
    pub fn get_ml_model(env: Env) -> Result<MLModelWeights, ContractError> {
        env.storage()
            .persistent()
            .get(&ML_MODEL_WEIGHTS)
            .ok_or(ContractError::MLModelNotFound)
    }

    /// Get external risk data for a specific type and timestamp
    pub fn get_external_risk_data(
        env: Env,
        data_type: Symbol,
        timestamp: u64,
    ) -> Result<ExternalRiskData, ContractError> {
        let data_key = (EXTERNAL_RISK_DATA, data_type, timestamp);
        env.storage().persistent().get(&data_key).ok_or(ContractError::NotFound)
    }

    /// Get real-time risk alert
    pub fn get_risk_alert(env: Env, alert_id: u64) -> Result<RealTimeRiskAlert, ContractError> {
        let alert_key = (REAL_TIME_MONITORING, alert_id);
        env.storage().persistent().get(&alert_key).ok_or(ContractError::NotFound)
    }

    /// Get portfolio optimization result
    pub fn get_portfolio_optimization(
        env: Env,
    ) -> Result<PortfolioOptimizationResult, ContractError> {
        env.storage()
            .persistent()
            .get(&PORTFOLIO_OPTIMIZATION)
            .ok_or(ContractError::NotFound)
    }

    /// Update pricing model with advanced parameters
    pub fn update_advanced_pricing_model(
        env: Env,
        admin: Address,
        base_premium_rate: u32,
        risk_multiplier: u32,
        portfolio_adjustment: i32,
        market_factor: u32,
        volatility_adjustment: u32,
        liquidity_premium: u32,
        correlation_discount: u32,
        tail_risk_adjustment: u32,
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
            volatility_adjustment,
            liquidity_premium,
            correlation_discount,
            tail_risk_adjustment,
        };

        env.storage().persistent().set(&PRICING_MODEL, &pricing_model);

        env.events().publish(
            (Symbol::new(&env, "advanced_pricing_model_updated"), admin),
            (base_premium_rate, risk_multiplier, volatility_adjustment, liquidity_premium),
        );

        Ok(())
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

    // Advanced Helper Functions

    fn process_external_data(
        env: &Env,
        external_data: Vec<ExternalRiskData>,
    ) -> Result<Vec<ExternalRiskData>, ContractError> {
        let mut processed_data = Vec::new(env);

        for data in external_data.iter() {
            // Filter by confidence and relevance
            if data.confidence_score >= 7000 && data.relevance_weight >= 5000 {
                processed_data.push_back(data.clone());
            }
        }

        if processed_data.is_empty() {
            return Err(ContractError::InsufficientData);
        }

        Ok(processed_data)
    }

    fn map_data_type_to_risk_factor(data_type: Symbol) -> RiskFactor {
        match data_type.to_string().as_str() {
            "credit" => RiskFactor::CreditScore,
            "claims" => RiskFactor::ClaimHistory,
            "age" => RiskFactor::Age,
            "occupation" => RiskFactor::Occupation,
            "location" => RiskFactor::Location,
            "health" => RiskFactor::Health,
            "market" => RiskFactor::MarketVolatility,
            "external" => RiskFactor::ExternalEvents,
            _ => RiskFactor::ExternalEvents, // Default
        }
    }

    fn calculate_ml_risk_score(
        risk_profile: &RiskProfile,
        ml_weights: &MLModelWeights,
        coverage_amount: i128,
        policy_type: Symbol,
    ) -> Result<u32, ContractError> {
        let mut weighted_sum = ml_weights.bias;

        // Apply feature weights
        for (factor, weight) in ml_weights.feature_weights.iter() {
            let factor_value = risk_profile.external_factors.get(factor).unwrap_or(0);
            weighted_sum += factor_value * weight as i128;
        }

        // Add historical factors
        let claim_factor = risk_profile.claim_history.len() as i128 * 100;
        weighted_sum += claim_factor;

        let policy_factor = Self::apply_policy_type_adjustment(500, policy_type) as i128 - 500;
        weighted_sum += policy_factor;

        let coverage_factor =
            Self::apply_coverage_amount_adjustment(500, coverage_amount) as i128 - 500;
        weighted_sum += coverage_factor;

        // Normalize to 0-1000 range
        let normalized_score = ((weighted_sum + 1000000) * 1000) / 2000000; // Rough normalization

        Ok(normalized_score.min(1000).max(0) as u32)
    }

    fn calculate_behavioral_score(risk_profile: &RiskProfile) -> Result<u32, ContractError> {
        let mut score = 500u32; // Base score

        // Payment consistency (based on premium history)
        if risk_profile.total_premiums_paid > 0 {
            let payment_ratio = (risk_profile.total_premiums_paid * 10000)
                / (risk_profile.total_premiums_paid + risk_profile.total_claims_paid);

            if payment_ratio > 9000 {
                score -= 100; // Good payment history
            } else if payment_ratio < 5000 {
                score += 150; // Poor payment history
            }
        }

        // Policy loyalty (more policies = better behavior)
        let policy_count = risk_profile.coverage_history.len() as u32;
        if policy_count > 10 {
            score -= 50;
        } else if policy_count < 2 {
            score += 25;
        }

        Ok(score.min(1000).max(0))
    }

    fn calculate_predictive_score(risk_profile: &RiskProfile) -> Result<u32, ContractError> {
        let mut score = 500u32;

        // Trend analysis
        for (trend_name, trend_value) in risk_profile.trend_analysis.iter() {
            match trend_name.to_string().as_str() {
                "claim_frequency" => {
                    if trend_value > 0 {
                        score += trend_value as u32 * 10; // Increasing trend = higher risk
                    } else {
                        score -= (-trend_value) as u32 * 5; // Decreasing trend = lower risk
                    }
                }
                "payment_behavior" => {
                    if trend_value < 0 {
                        score -= (-trend_value) as u32 * 8; // Improving payments = lower risk
                    } else {
                        score += trend_value as u32 * 12; // Deteriorating payments = higher risk
                    }
                }
                _ => {}
            }
        }

        // Seasonal adjustments
        let current_time = risk_profile.last_updated;
        let season_factor = (current_time % 31536000) / 86400; // Day of year

        // Assume higher risk in certain seasons (simplified)
        if season_factor >= 274 && season_factor <= 365 {
            // Oct-Dec
            score += 50; // Holiday season risk
        } else if season_factor >= 60 && season_factor <= 152 {
            // Mar-Jun
            score -= 25; // Spring season lower risk
        }

        Ok(score.min(1000).max(0))
    }

    fn calculate_advanced_premium(
        coverage_amount: i128,
        risk_score: u32,
        pricing_model: &DynamicPricingModel,
        risk_profile: &RiskProfile,
    ) -> i128 {
        let base_premium = (coverage_amount * pricing_model.base_premium_rate as i128) / 10000;
        let risk_adjustment =
            (coverage_amount * risk_score as i128 * pricing_model.risk_multiplier as i128)
                / (10000 * 1000);
        let portfolio_adjustment =
            (coverage_amount * pricing_model.portfolio_adjustment as i128) / 10000;
        let market_adjustment = (coverage_amount * pricing_model.market_factor as i128) / 10000;

        // Advanced adjustments
        let volatility_adjustment =
            (coverage_amount * pricing_model.volatility_adjustment as i128) / 10000;
        let liquidity_premium = (coverage_amount * pricing_model.liquidity_premium as i128) / 10000;
        let correlation_discount =
            (coverage_amount * pricing_model.correlation_discount as i128) / 10000;
        let tail_risk_adjustment =
            (coverage_amount * pricing_model.tail_risk_adjustment as i128) / 10000;

        // Behavioral and predictive adjustments
        let behavioral_adjustment =
            (coverage_amount * (risk_profile.behavioral_score as i128 - 500) * 10) / 10000;
        let predictive_adjustment =
            (coverage_amount * (risk_profile.predictive_score as i128 - 500) * 8) / 10000;

        base_premium
            + risk_adjustment
            + portfolio_adjustment
            + market_adjustment
            + volatility_adjustment
            + liquidity_premium
            - correlation_discount
            + tail_risk_adjustment
            + behavioral_adjustment
            + predictive_adjustment
    }

    fn calculate_probability_of_default(risk_score: u32) -> u32 {
        // Logistic function approximation for PD calculation
        let normalized_score = risk_score as i128 - 500; // Center around 0
        let exponent = -normalized_score * 15 / 1000; // Scale factor

        // Approximate e^x using Taylor series (simplified for blockchain)
        let exp_approx = if exponent > 0 {
            1000 + exponent * 1000 / 100 // Rough approximation
        } else {
            1000 - (-exponent) * 500 / 100 // Rough approximation
        };

        let pd = (10000 * 1000) / (1000 + exp_approx); // Convert to basis points
        pd.min(9900).max(10) as u32 // Cap between 0.1% and 99%
    }

    fn calculate_loss_given_default(risk_level: RiskLevel) -> u32 {
        match risk_level {
            RiskLevel::Low => 2000,      // 20%
            RiskLevel::Medium => 4000,   // 40%
            RiskLevel::High => 6500,     // 65%
            RiskLevel::Critical => 8500, // 85%
        }
    }

    fn calculate_confidence_interval(
        expected_loss: i128,
        risk_score: u32,
        ml_weights: &MLModelWeights,
    ) -> (i128, i128) {
        let confidence_factor = ml_weights.accuracy_score as i128;
        let risk_adjustment = (risk_score as i128 * 50) / 1000;

        let variance = (expected_loss * risk_adjustment) / 10000;
        let std_dev = if variance > 0 {
            Self::integer_sqrt(variance)
        } else {
            0
        };

        // 95% confidence interval (approximately 2 standard deviations)
        let margin = (std_dev * 2 * confidence_factor) / 10000;

        let min_loss = if expected_loss > margin {
            expected_loss - margin
        } else {
            0
        };
        let max_loss = expected_loss + margin;

        (min_loss, max_loss)
    }

    fn calculate_risk_contributions(
        risk_profile: &RiskProfile,
        ml_weights: &MLModelWeights,
    ) -> Map<RiskFactor, u32> {
        let mut contributions = Map::new(&risk_profile.user_address.env);
        let mut total_contribution = 0i128;

        // Calculate contribution for each factor
        for (factor, weight) in ml_weights.feature_weights.iter() {
            let factor_value = risk_profile.external_factors.get(factor).unwrap_or(0);
            let contribution = (factor_value * weight as i128).abs();
            total_contribution += contribution;
            contributions.set(factor, contribution as u32);
        }

        // Normalize to percentages
        if total_contribution > 0 {
            for factor in contributions.iter() {
                let current = contributions.get(factor).unwrap();
                let normalized = (current * 10000) / total_contribution as u32;
                contributions.set(factor, normalized);
            }
        }

        contributions
    }

    fn calculate_optimal_allocation(
        risk_tolerance: u32,
        expected_returns: &Map<RiskLevel, i128>,
        covariance_matrix: &Map<(RiskLevel, RiskLevel), i32>,
    ) -> Result<Map<RiskLevel, u32>, ContractError> {
        let mut allocation = Map::new(&expected_returns.env);

        // Simplified mean-variance optimization
        // In practice, this would use quadratic programming
        let risk_factor = (1000 - risk_tolerance) as i128;

        // Initialize with equal weights
        allocation.set(RiskLevel::Low, 2500);
        allocation.set(RiskLevel::Medium, 2500);
        allocation.set(RiskLevel::High, 2500);
        allocation.set(RiskLevel::Critical, 2500);

        // Adjust based on risk tolerance and expected returns
        for risk_level in [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            let expected_return = expected_returns.get(risk_level).unwrap_or(0);
            let current_weight = allocation.get(risk_level).unwrap();

            // Higher expected returns get more allocation for risk-tolerant portfolios
            let adjustment = (expected_return * (1000 - risk_factor)) / 10000;
            let new_weight = (current_weight as i128 + adjustment).min(5000).max(500) as u32;

            allocation.set(risk_level, new_weight);
        }

        // Normalize to 100%
        let mut total_weight = 0u32;
        for weight in allocation.iter() {
            total_weight += weight;
        }

        if total_weight > 0 {
            for risk_level in [
                RiskLevel::Low,
                RiskLevel::Medium,
                RiskLevel::High,
                RiskLevel::Critical,
            ] {
                let current = allocation.get(risk_level).unwrap();
                let normalized = (current * 10000) / total_weight;
                allocation.set(risk_level, normalized);
            }
        }

        Ok(allocation)
    }

    fn calculate_portfolio_expected_return(
        allocation: &Map<RiskLevel, u32>,
        expected_returns: &Map<RiskLevel, i128>,
    ) -> i128 {
        let mut total_return = 0i128;

        for (risk_level, weight) in allocation.iter() {
            let expected_return = expected_returns.get(risk_level).unwrap_or(0);
            total_return += (expected_return * weight as i128) / 10000;
        }

        total_return
    }

    fn calculate_portfolio_risk(
        allocation: &Map<RiskLevel, u32>,
        covariance_matrix: &Map<(RiskLevel, RiskLevel), i32>,
    ) -> i128 {
        let mut portfolio_variance = 0i128;

        // Calculate portfolio variance: w^T * Σ * w
        for (risk_level_i, weight_i) in allocation.iter() {
            for (risk_level_j, weight_j) in allocation.iter() {
                let covariance = covariance_matrix.get((risk_level_i, risk_level_j)).unwrap_or(0);
                portfolio_variance +=
                    (weight_i as i128 * weight_j as i128 * covariance as i128) / (10000 * 10000);
            }
        }

        // Return standard deviation (risk)
        if portfolio_variance > 0 {
            Self::integer_sqrt(portfolio_variance)
        } else {
            0
        }
    }

    fn estimate_max_drawdown(risk_tolerance: u32) -> u32 {
        // Higher risk tolerance = higher expected max drawdown
        let base_drawdown = 1000; // 10% base
        let risk_adjustment = (risk_tolerance * 3000) / 1000; // Up to 30% additional

        base_drawdown + risk_adjustment
    }

    fn calculate_value_at_risk(
        metrics: &PortfolioMetrics,
        confidence_level: u32,
        time_horizon_days: u32,
    ) -> Result<i128, ContractError> {
        // Simplified VaR calculation using parametric approach
        let confidence_multiplier = match confidence_level {
            9000..=10000 => 233, // 99% VaR
            9500..=9999 => 164,  // 95% VaR
            8000..=9499 => 128,  // 80% VaR
            _ => 128,            // Default to 80%
        };

        let time_adjustment = if time_horizon_days > 0 {
            Self::integer_sqrt(time_horizon_days as i128)
        } else {
            1
        };

        let portfolio_value = metrics.total_coverage;
        let volatility = metrics.utilization_rate as i128;

        let var = (portfolio_value * volatility * confidence_multiplier * time_adjustment)
            / (10000 * 1000);

        Ok(var)
    }

    fn calculate_conditional_var(
        metrics: &PortfolioMetrics,
        confidence_level: u32,
        time_horizon_days: u32,
    ) -> Result<i128, ContractError> {
        // Conditional VaR is typically 1.2-1.5 times VaR
        let var = Self::calculate_value_at_risk(metrics, confidence_level, time_horizon_days)?;
        let cvar_multiplier = 1300; // 1.3x VaR

        Ok((var * cvar_multiplier) / 1000)
    }

    fn calculate_correlation_matrix(
        env: &Env,
    ) -> Result<Map<RiskLevel, Map<RiskLevel, i32>>, ContractError> {
        let mut correlation_matrix = Map::new(env);

        // Simplified correlation matrix (in practice, calculated from historical data)
        let correlations = Map::from_array(
            env,
            [
                (
                    RiskLevel::Low,
                    Map::from_array(
                        env,
                        [
                            (RiskLevel::Low, 10000),     // Perfect correlation with itself
                            (RiskLevel::Medium, 6000),   // Moderate positive correlation
                            (RiskLevel::High, 3000),     // Low positive correlation
                            (RiskLevel::Critical, 1000), // Very low correlation
                        ],
                    ),
                ),
                (
                    RiskLevel::Medium,
                    Map::from_array(
                        env,
                        [
                            (RiskLevel::Low, 6000),
                            (RiskLevel::Medium, 10000),
                            (RiskLevel::High, 5000),
                            (RiskLevel::Critical, 2000),
                        ],
                    ),
                ),
                (
                    RiskLevel::High,
                    Map::from_array(
                        env,
                        [
                            (RiskLevel::Low, 3000),
                            (RiskLevel::Medium, 5000),
                            (RiskLevel::High, 10000),
                            (RiskLevel::Critical, 4000),
                        ],
                    ),
                ),
                (
                    RiskLevel::Critical,
                    Map::from_array(
                        env,
                        [
                            (RiskLevel::Low, 1000),
                            (RiskLevel::Medium, 2000),
                            (RiskLevel::High, 4000),
                            (RiskLevel::Critical, 10000),
                        ],
                    ),
                ),
            ],
        );

        Ok(correlations)
    }

    fn calculate_concentration_risk(metrics: &PortfolioMetrics) -> u32 {
        // Calculate Herfindahl-Hirschman Index for concentration
        let mut hhi = 0u32;

        for percentage in metrics.risk_distribution.iter() {
            let weight = percentage / 100; // Convert to percentage points
            hhi += weight * weight;
        }

        // Normalize to basis points
        (hhi * 10000) / 10000
    }

    fn calculate_diversification_ratio(metrics: &PortfolioMetrics) -> u32 {
        // Simplified diversification ratio
        let risk_levels_count = metrics.risk_distribution.len() as u32;
        let max_possible_levels = 4; // Low, Medium, High, Critical

        // More evenly distributed risks = higher diversification
        let concentration = Self::calculate_concentration_risk(metrics);
        let diversification = 10000 - concentration;

        // Adjust for number of risk levels present
        let level_factor = (risk_levels_count * 2500) / max_possible_levels;

        (diversification + level_factor) / 2
    }

    fn estimate_max_drawdown_from_volatility(volatility: u32) -> u32 {
        // Rule of thumb: max drawdown ≈ 2-3x volatility
        (volatility * 250) / 100 // 2.5x volatility
    }

    fn integer_sqrt(n: i128) -> i128 {
        if n < 0 {
            return 0;
        }

        let mut x = n;
        let mut y = (x + 1) / 2;

        while y < x {
            x = y;
            y = (x + n / x) / 2;
        }

        x
    }

    // Helper functions

    fn calculate_historical_risk_score(
        env: &Env,
        profile: &RiskProfile,
    ) -> Result<u32, ContractError> {
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
            if loss_ratio > 8000 {
                // > 80%
                base_score = base_score.saturating_add(200);
            } else if loss_ratio > 5000 {
                // > 50%
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
            "life" => base_score.saturating_sub(50),     // Lower risk
            "health" => base_score,                      // Neutral
            "property" => base_score.saturating_add(50), // Higher risk
            "travel" => base_score.saturating_add(25),   // Slightly higher
            _ => base_score,                             // Default
        }
    }

    fn apply_coverage_amount_adjustment(base_score: u32, coverage_amount: i128) -> u32 {
        // Higher coverage amounts might indicate higher risk
        if coverage_amount > 1000000000 {
            // > 10,000 units
            base_score.saturating_add(75)
        } else if coverage_amount > 100000000 {
            // > 1,000 units
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
        let risk_adjustment =
            (coverage_amount * risk_score as i128 * pricing_model.risk_multiplier as i128)
                / (10000 * 1000);
        let portfolio_adjustment =
            (coverage_amount * pricing_model.portfolio_adjustment as i128) / 10000;
        let market_adjustment = (coverage_amount * pricing_model.market_factor as i128) / 10000;

        base_premium + risk_adjustment + portfolio_adjustment + market_adjustment
    }

    fn calculate_max_coverage(risk_level: RiskLevel, requested_coverage: i128) -> i128 {
        match risk_level {
            RiskLevel::Low => requested_coverage * 2, // 2x requested
            RiskLevel::Medium => requested_coverage * 150 / 100, // 1.5x requested
            RiskLevel::High => requested_coverage,    // 1x requested
            RiskLevel::Critical => requested_coverage * 75 / 100, // 0.75x requested
        }
    }

    fn evaluate_underwriting_rules(
        env: &Env,
        risk_score: u32,
        risk_profile: &RiskProfile,
    ) -> Result<bool, ContractError> {
        let rules: Vec<UnderwritingRule> = env
            .storage()
            .persistent()
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
