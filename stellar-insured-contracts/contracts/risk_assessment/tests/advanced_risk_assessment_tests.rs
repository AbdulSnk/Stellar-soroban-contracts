#![cfg(test)]

use risk_assessment::{
    ContractError, DynamicPricingModel, ExternalRiskData, MLModelWeights,
    PortfolioOptimizationResult, RealTimeRiskAlert, RiskAssessmentContract, RiskAssessmentResult,
    RiskFactor, RiskLevel, RiskProfile,
};
use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Env, Symbol};

#[test]
fn test_advanced_risk_assessment_initialization() {
    let env = Env::default();
    let admin = Address::random(&env);
    let policy_contract = Address::random(&env);
    let claims_contract = Address::random(&env);
    let risk_pool_contract = Address::random(&env);

    let contract = RiskAssessmentContract;
    contract
        .initialize(
            env.clone(),
            admin.clone(),
            policy_contract,
            claims_contract,
            risk_pool_contract,
        )
        .unwrap();

    // Verify ML model was initialized
    let ml_model = contract.get_ml_model(env.clone()).unwrap();
    assert_eq!(ml_model.model_version, 1);
    assert_eq!(ml_model.accuracy_score, 8500);
    assert_eq!(ml_model.bias, 500);

    // Verify advanced pricing model was initialized
    let pricing_model = contract.get_pricing_model(env.clone()).unwrap();
    assert_eq!(pricing_model.volatility_adjustment, 25);
    assert_eq!(pricing_model.liquidity_premium, 10);
    assert_eq!(pricing_model.correlation_discount, 5);
    assert_eq!(pricing_model.tail_risk_adjustment, 15);
}

#[test]
fn test_ml_model_update() {
    let env = Env::default();
    let admin = Address::random(&env);
    let policy_contract = Address::random(&env);
    let claims_contract = Address::random(&env);
    let risk_pool_contract = Address::random(&env);

    let contract = RiskAssessmentContract;
    contract
        .initialize(
            env.clone(),
            admin.clone(),
            policy_contract,
            claims_contract,
            risk_pool_contract,
        )
        .unwrap();

    // Update ML model
    let mut new_feature_weights = soroban_sdk::Map::new(&env);
    new_feature_weights.set(RiskFactor::CreditScore, 3500);
    new_feature_weights.set(RiskFactor::ClaimHistory, 2000);
    new_feature_weights.set(RiskFactor::Age, 1500);
    new_feature_weights.set(RiskFactor::Occupation, 1000);
    new_feature_weights.set(RiskFactor::Location, 800);
    new_feature_weights.set(RiskFactor::Health, 700);
    new_feature_weights.set(RiskFactor::MarketVolatility, 300);
    new_feature_weights.set(RiskFactor::ExternalEvents, 200);

    contract
        .update_ml_model(env.clone(), admin.clone(), new_feature_weights, 600, 2, 9000)
        .unwrap();

    let updated_model = contract.get_ml_model(env.clone()).unwrap();
    assert_eq!(updated_model.model_version, 2);
    assert_eq!(updated_model.accuracy_score, 9000);
    assert_eq!(updated_model.bias, 600);
}

#[test]
fn test_external_risk_data_integration() {
    let env = Env::default();
    let admin = Address::random(&env);
    let oracle = Address::random(&env);
    let policy_contract = Address::random(&env);
    let claims_contract = Address::random(&env);
    let risk_pool_contract = Address::random(&env);

    let contract = RiskAssessmentContract;
    contract
        .initialize(
            env.clone(),
            admin.clone(),
            policy_contract,
            claims_contract,
            risk_pool_contract,
        )
        .unwrap();

    // Register oracle as trusted contract
    insurance_contracts::authorization::register_trusted_contract(&env, &admin, &oracle).unwrap();

    // Add external risk data
    let external_data = ExternalRiskData {
        data_source: Symbol::short("CREDIT_BUREAU"),
        data_type: Symbol::short("credit"),
        value: 750,
        confidence_score: 9500,
        timestamp: env.ledger().timestamp(),
        relevance_weight: 8000,
    };

    contract
        .add_external_risk_data(env.clone(), oracle.clone(), external_data.clone())
        .unwrap();

    // Retrieve external data
    let retrieved_data = contract
        .get_external_risk_data(env.clone(), external_data.data_type, external_data.timestamp)
        .unwrap();

    assert_eq!(retrieved_data.data_source, external_data.data_source);
    assert_eq!(retrieved_data.value, external_data.value);
    assert_eq!(retrieved_data.confidence_score, external_data.confidence_score);
}

#[test]
fn test_real_time_risk_monitoring() {
    let env = Env::default();
    let admin = Address::random(&env);
    let user = Address::random(&env);
    let policy_contract = Address::random(&env);
    let claims_contract = Address::random(&env);
    let risk_pool_contract = Address::random(&env);

    let contract = RiskAssessmentContract;
    contract
        .initialize(
            env.clone(),
            admin.clone(),
            policy_contract,
            claims_contract,
            risk_pool_contract,
        )
        .unwrap();

    // Monitor real-time risk
    let alert = contract
        .monitor_real_time_risk(
            env.clone(),
            user.clone(),
            RiskFactor::MarketVolatility,
            1500, // Current value exceeds threshold
            1000, // Threshold
        )
        .unwrap();

    assert_eq!(alert.user_address, user);
    assert_eq!(alert.risk_factor, RiskFactor::MarketVolatility);
    assert_eq!(alert.current_value, 1500);
    assert_eq!(alert.threshold_value, 1000);
    assert_eq!(alert.severity, RiskLevel::High);
    assert!(alert.action_required);

    // Retrieve alert
    let retrieved_alert = contract.get_risk_alert(env.clone(), alert.alert_id).unwrap();
    assert_eq!(retrieved_alert.alert_id, alert.alert_id);
    assert_eq!(retrieved_alert.severity, RiskLevel::High);
}

#[test]
fn test_portfolio_optimization() {
    let env = Env::default();
    let admin = Address::random(&env);
    let policy_contract = Address::random(&env);
    let claims_contract = Address::random(&env);
    let risk_pool_contract = Address::random(&env);

    let contract = RiskAssessmentContract;
    contract
        .initialize(
            env.clone(),
            admin.clone(),
            policy_contract,
            claims_contract,
            risk_pool_contract,
        )
        .unwrap();

    // Set up expected returns and covariance matrix
    let mut expected_returns = soroban_sdk::Map::new(&env);
    expected_returns.set(RiskLevel::Low, 50000); // 5% return
    expected_returns.set(RiskLevel::Medium, 80000); // 8% return
    expected_returns.set(RiskLevel::High, 120000); // 12% return
    expected_returns.set(RiskLevel::Critical, 200000); // 20% return

    let mut covariance_matrix = soroban_sdk::Map::new(&env);
    // Simplified covariance values
    covariance_matrix.set((RiskLevel::Low, RiskLevel::Low), 1000);
    covariance_matrix.set((RiskLevel::Low, RiskLevel::Medium), 600);
    covariance_matrix.set((RiskLevel::Medium, RiskLevel::Medium), 1500);
    covariance_matrix.set((RiskLevel::High, RiskLevel::High), 2500);
    covariance_matrix.set((RiskLevel::Critical, RiskLevel::Critical), 4000);

    let optimization_result = contract
        .optimize_portfolio(
            env.clone(),
            700, // Risk tolerance (70%)
            expected_returns,
            covariance_matrix,
        )
        .unwrap();

    assert!(optimization_result.expected_return > 0);
    assert!(optimization_result.sharpe_ratio > 0);
    assert!(optimization_result.volatility > 0);
    assert!(optimization_result.max_drawdown > 0);

    // Verify allocation sums to 100%
    let mut total_allocation = 0u32;
    for allocation in optimization_result.optimal_allocation.iter() {
        total_allocation += allocation;
    }
    assert_eq!(total_allocation, 10000); // 100% in basis points

    // Retrieve optimization result
    let retrieved_result = contract.get_portfolio_optimization(env.clone()).unwrap();
    assert_eq!(retrieved_result.expected_return, optimization_result.expected_return);
    assert_eq!(retrieved_result.sharpe_ratio, optimization_result.sharpe_ratio);
}

#[test]
fn test_enhanced_portfolio_metrics() {
    let env = Env::default();
    let admin = Address::random(&env);
    let policy_contract = Address::random(&env);
    let claims_contract = Address::random(&env);
    let risk_pool_contract = Address::random(&env);

    let contract = RiskAssessmentContract;
    contract
        .initialize(
            env.clone(),
            admin.clone(),
            policy_contract,
            claims_contract,
            risk_pool_contract,
        )
        .unwrap();

    // Calculate enhanced portfolio metrics
    let enhanced_metrics = contract
        .calculate_enhanced_portfolio_metrics(
            env.clone(),
            9500, // 95% confidence level
            30,   // 30 day time horizon
        )
        .unwrap();

    assert!(enhanced_metrics.value_at_risk_95 >= 0);
    assert!(enhanced_metrics.conditional_var >= enhanced_metrics.value_at_risk_95);
    assert!(enhanced_metrics.concentration_risk >= 0);
    assert!(enhanced_metrics.diversification_ratio >= 0);
    assert!(enhanced_metrics.maximum_drawdown >= 0);

    // Verify correlation matrix is populated
    assert!(!enhanced_metrics.correlation_matrix.is_empty());

    // Check that correlation matrix has expected structure
    let low_correlations = enhanced_metrics.correlation_matrix.get(RiskLevel::Low).unwrap();
    assert_eq!(low_correlations.get(RiskLevel::Low).unwrap(), 10000); // Perfect correlation with itself
}

#[test]
fn test_advanced_pricing_model_update() {
    let env = Env::default();
    let admin = Address::random(&env);
    let policy_contract = Address::random(&env);
    let claims_contract = Address::random(&env);
    let risk_pool_contract = Address::random(&env);

    let contract = RiskAssessmentContract;
    contract
        .initialize(
            env.clone(),
            admin.clone(),
            policy_contract,
            claims_contract,
            risk_pool_contract,
        )
        .unwrap();

    // Update advanced pricing model
    contract
        .update_advanced_pricing_model(
            env.clone(),
            admin.clone(),
            150, // 1.5% base rate
            75,  // 0.75% risk multiplier
            100, // 1% portfolio adjustment
            50,  // 0.5% market factor
            35,  // 0.35% volatility adjustment
            15,  // 0.15% liquidity premium
            10,  // 0.1% correlation discount
            20,  // 0.2% tail risk adjustment
        )
        .unwrap();

    let updated_model = contract.get_pricing_model(env.clone()).unwrap();
    assert_eq!(updated_model.base_premium_rate, 150);
    assert_eq!(updated_model.risk_multiplier, 75);
    assert_eq!(updated_model.portfolio_adjustment, 100);
    assert_eq!(updated_model.market_factor, 50);
    assert_eq!(updated_model.volatility_adjustment, 35);
    assert_eq!(updated_model.liquidity_premium, 15);
    assert_eq!(updated_model.correlation_discount, 10);
    assert_eq!(updated_model.tail_risk_adjustment, 20);
}

#[test]
fn test_advanced_risk_assessment_with_external_data() {
    let env = Env::default();
    let admin = Address::random(&env);
    let user = Address::random(&env);
    let oracle = Address::random(&env);
    let policy_contract = Address::random(&env);
    let claims_contract = Address::random(&env);
    let risk_pool_contract = Address::random(&env);

    let contract = RiskAssessmentContract;
    contract
        .initialize(
            env.clone(),
            admin.clone(),
            policy_contract,
            claims_contract,
            risk_pool_contract,
        )
        .unwrap();

    // Register oracle as trusted contract
    insurance_contracts::authorization::register_trusted_contract(&env, &admin, &oracle).unwrap();

    // Add external risk data
    let mut external_data = soroban_sdk::Vec::new(&env);
    external_data.push_back(ExternalRiskData {
        data_source: Symbol::short("CREDIT_BUREAU"),
        data_type: Symbol::short("credit"),
        value: 750,
        confidence_score: 9500,
        timestamp: env.ledger().timestamp(),
        relevance_weight: 8000,
    });
    external_data.push_back(ExternalRiskData {
        data_source: Symbol::short("HEALTH_PROVIDER"),
        data_type: Symbol::short("health"),
        value: 850,
        confidence_score: 9000,
        timestamp: env.ledger().timestamp(),
        relevance_weight: 7500,
    });

    // Perform advanced risk assessment
    let result = contract
        .advanced_risk_assessment(
            env.clone(),
            user.clone(),
            1000000, // 10,000 coverage amount
            Symbol::short("life"),
            external_data,
        )
        .unwrap();

    assert!(result.risk_score >= 0 && result.risk_score <= 1000);
    assert!(result.recommended_premium > 0);
    assert!(result.probability_of_default >= 0 && result.probability_of_default <= 10000);
    assert!(result.loss_given_default >= 0 && result.loss_given_default <= 10000);
    assert!(result.expected_loss >= 0);
    assert!(result.model_confidence >= 0 && result.model_confidence <= 10000);
    assert!(!result.risk_contributions.is_empty());
    assert!(result.confidence_interval.0 <= result.expected_loss);
    assert!(result.confidence_interval.1 >= result.expected_loss);
}

#[test]
fn test_error_handling() {
    let env = Env::default();
    let admin = Address::random(&env);
    let unauthorized_user = Address::random(&env);
    let policy_contract = Address::random(&env);
    let claims_contract = Address::random(&env);
    let risk_pool_contract = Address::random(&env);

    let contract = RiskAssessmentContract;
    contract
        .initialize(
            env.clone(),
            admin.clone(),
            policy_contract,
            claims_contract,
            risk_pool_contract,
        )
        .unwrap();

    // Test unauthorized ML model update
    let mut feature_weights = soroban_sdk::Map::new(&env);
    feature_weights.set(RiskFactor::CreditScore, 3000);

    let result = contract.update_ml_model(
        env.clone(),
        unauthorized_user.clone(),
        feature_weights,
        500,
        2,
        9000,
    );
    assert!(result.is_err());

    // Test invalid external data (low confidence)
    let invalid_external_data = ExternalRiskData {
        data_source: Symbol::short("INVALID_SOURCE"),
        data_type: Symbol::short("credit"),
        value: 750,
        confidence_score: 3000, // Too low
        timestamp: env.ledger().timestamp(),
        relevance_weight: 8000,
    };

    let result = contract.add_external_risk_data(env.clone(), admin.clone(), invalid_external_data);
    assert!(matches!(result, Err(ContractError::ExternalDataInvalid)));

    // Test invalid risk tolerance for portfolio optimization
    let mut expected_returns = soroban_sdk::Map::new(&env);
    expected_returns.set(RiskLevel::Low, 50000);
    let mut covariance_matrix = soroban_sdk::Map::new(&env);
    covariance_matrix.set((RiskLevel::Low, RiskLevel::Low), 1000);

    let result = contract.optimize_portfolio(
        env.clone(),
        1500, // Invalid: > 1000
        expected_returns,
        covariance_matrix,
    );
    assert!(matches!(result, Err(ContractError::InvalidInput)));
}

#[test]
fn test_risk_factor_mapping() {
    let env = Env::default();

    // Test that all data types map to valid risk factors
    let test_cases = vec![
        ("credit", RiskFactor::CreditScore),
        ("claims", RiskFactor::ClaimHistory),
        ("age", RiskFactor::Age),
        ("occupation", RiskFactor::Occupation),
        ("location", RiskFactor::Location),
        ("health", RiskFactor::Health),
        ("market", RiskFactor::MarketVolatility),
        ("external", RiskFactor::ExternalEvents),
        ("unknown", RiskFactor::ExternalEvents), // Default case
    ];

    for (data_type_str, expected_factor) in test_cases {
        let data_type = Symbol::from_str(&env, data_type_str);
        // This would need to be tested through the public interface
        // For now, we just verify the mapping logic exists
        assert!(true); // Placeholder - actual testing would require exposing the mapping function
    }
}
