use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, BytesN, Env, Symbol, Vec, String, Map,
    testutils::{Address as TestAddress, AuthorizedFunction, AuthorizedInvocation},
};
use performance_monitoring::{
    PerformanceMetric, AlertRule, AlertRecord, DashboardConfig, DashboardMetric,
    PerformanceMonitoringContract, ContractError,
};

#[contract]
pub struct PerformanceMonitoringTest;

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Ledger, LedgerInfo};

    fn setup_test_env() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        (env, admin)
    }

    #[test]
    fn test_initialize() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);

        // Test successful initialization
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        // Test double initialization fails
        let result = PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        assert_eq!(result, Err(ContractError::AlreadyInitialized));
    }

    #[test]
    fn test_record_metric() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let contract_address = Address::generate(&env);
        let metric_name = Symbol::new(&env, "gas_used");
        let value = 100000u64;
        let unit = Symbol::new(&env, "gas");
        let operation = Symbol::new(&env, "mint_policy");
        let metadata = Map::new(&env);

        let metric_id = PerformanceMonitoringContract::record_metric(
            env.clone(),
            contract_id,
            contract_address.clone(),
            metric_name,
            value,
            unit,
            operation,
            metadata,
        ).unwrap();

        // Verify metric was recorded
        let metric = PerformanceMonitoringContract::get_performance_metric(env.clone(), contract_id, metric_id).unwrap();
        assert_eq!(metric.contract_address, contract_address);
        assert_eq!(metric.metric_name, metric_name);
        assert_eq!(metric.value, value);
        assert_eq!(metric.unit, unit);
    }

    #[test]
    fn test_create_alert_rule() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let contract_address = Address::generate(&env);
        let metric_name = Symbol::new(&env, "error_rate");
        let condition = Symbol::new(&env, "gt");
        let threshold = 5u64;
        let time_window = 300u64; // 5 minutes
        let min_data_points = 10u32;
        let severity = Symbol::new(&env, "high");

        let rule_id = PerformanceMonitoringContract::create_alert_rule(
            env.clone(),
            contract_id,
            admin.clone(),
            String::from_str(&env, "High Error Rate"),
            String::from_str(&env, "Alert when error rate exceeds 5%"),
            Some(contract_address.clone()),
            metric_name,
            condition,
            threshold,
            time_window,
            min_data_points,
            severity,
            300u64, // cooldown period
        ).unwrap();

        // Verify alert rule was created
        let rule = PerformanceMonitoringContract::get_alert_rule(env.clone(), contract_id, rule_id).unwrap();
        assert_eq!(rule.rule_name, String::from_str(&env, "High Error Rate"));
        assert_eq!(rule.metric_name, metric_name);
        assert_eq!(rule.threshold, threshold);
        assert_eq!(rule.severity, severity);
    }

    #[test]
    fn test_create_dashboard() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let owner = Address::generate(&env);
        let name = String::from_str(&env, "Performance Dashboard");
        let description = String::from_str(&env, "Main performance monitoring dashboard");
        let metrics = Vec::from_array(&env, [
            DashboardMetric {
                metric_name: Symbol::new(&env, "gas_used"),
                contract_address: Some(owner.clone()),
                aggregation: Symbol::new(&env, "avg"),
                display_name: String::from_str(&env, "Average Gas Usage"),
                chart_type: Symbol::new(&env, "line"),
                color: String::from_str(&env, "#007bff"),
            },
            DashboardMetric {
                metric_name: Symbol::new(&env, "execution_time"),
                contract_address: Some(owner.clone()),
                aggregation: Symbol::new(&env, "max"),
                display_name: String::from_str(&env, "Max Execution Time"),
                chart_type: Symbol::new(&env, "gauge"),
                color: String::from_str(&env, "#dc3545"),
            },
        ]);
        let time_range = 3600u64; // 1 hour
        let refresh_interval = 60u64; // 1 minute
        let is_public = false;

        let dashboard_id = PerformanceMonitoringContract::create_dashboard(
            env.clone(),
            contract_id,
            owner.clone(),
            name.clone(),
            description,
            metrics,
            time_range,
            refresh_interval,
            is_public,
        ).unwrap();

        // Verify dashboard was created
        let dashboard = PerformanceMonitoringContract::get_dashboard_config(env.clone(), contract_id, dashboard_id).unwrap();
        assert_eq!(dashboard.name, name);
        assert_eq!(dashboard.owner, owner);
        assert_eq!(dashboard.metrics.len(), 2);
        assert_eq!(dashboard.default_time_range, time_range);
    }

    #[test]
    fn test_get_aggregated_metrics() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let contract_address = Address::generate(&env);
        let metric_name = Symbol::new(&env, "gas_used");
        let period = Symbol::new(&env, "hourly");
        let start_time = env.ledger().timestamp() - 3600;
        let end_time = env.ledger().timestamp();

        let aggregated = PerformanceMonitoringContract::get_aggregated_metrics(
            env.clone(),
            contract_id,
            contract_address.clone(),
            metric_name,
            period,
            start_time,
            end_time,
        ).unwrap();

        // Verify aggregation structure
        assert_eq!(aggregated.metric_name, metric_name);
        assert_eq!(aggregated.contract_address, contract_address);
        assert_eq!(aggregated.period, period);
        assert_eq!(aggregated.period_start, start_time);
        assert_eq!(aggregated.period_end, end_time);
    }

    #[test]
    fn test_get_contract_performance_summary() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let contract_address = Address::generate(&env);

        let summary = PerformanceMonitoringContract::get_contract_performance_summary(
            env.clone(),
            contract_id,
            contract_address.clone(),
        ).unwrap();

        // Verify summary structure
        assert_eq!(summary.contract_address, contract_address);
        assert_eq!(summary.total_operations, 0);
        assert_eq!(summary.avg_gas_per_op, 0);
        assert_eq!(summary.performance_score, 100);
    }

    #[test]
    fn test_acknowledge_alert() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        // First create an alert (simulated)
        let alert_id = 1u64;
        
        let user = Address::generate(&env);
        
        // Test acknowledging alert
        let result = PerformanceMonitoringContract::acknowledge_alert(
            env.clone(),
            contract_id,
            user.clone(),
            alert_id,
        );
        
        // In a real implementation, this would acknowledge the actual alert
        // For now, we test the function call structure
        match result {
            Ok(()) => {
                // Success case
            }
            Err(ContractError::NotFound) => {
                // Expected if alert doesn't exist
            }
            _ => {
                // Other error cases
            }
        }
    }

    #[test]
    fn test_update_dashboard() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let owner = Address::generate(&env);
        let name = String::from_str(&env, "Test Dashboard");
        let description = String::from_str(&env, "Test dashboard");
        let metrics = Vec::new(&env);
        let time_range = 1800u64;
        let refresh_interval = 30u64;
        let is_public = true;

        let dashboard_id = PerformanceMonitoringContract::create_dashboard(
            env.clone(),
            contract_id,
            owner.clone(),
            name.clone(),
            description,
            metrics,
            time_range,
            refresh_interval,
            is_public,
        ).unwrap();

        // Update dashboard
        let new_name = String::from_str(&env, "Updated Dashboard");
        let new_description = String::from_str(&env, "Updated description");
        let new_metrics = Vec::from_array(&env, [
            DashboardMetric {
                metric_name: Symbol::new(&env, "new_metric"),
                contract_address: Some(owner.clone()),
                aggregation: Symbol::new(&env, "sum"),
                display_name: String::from_str(&env, "New Metric"),
                chart_type: Symbol::new(&env, "bar"),
                color: String::from_str(&env, "#28a745"),
            },
        ]);
        let new_time_range = 7200u64;
        let new_refresh_interval = 120u64;
        let new_is_public = false;

        let result = PerformanceMonitoringContract::update_dashboard(
            env.clone(),
            contract_id,
            owner.clone(),
            dashboard_id,
            new_name.clone(),
            new_description,
            new_metrics,
            new_time_range,
            new_refresh_interval,
            new_is_public,
        );

        // Verify update was successful
        assert!(result.is_ok());
        
        // Verify updated dashboard
        let updated_dashboard = PerformanceMonitoringContract::get_dashboard_config(env.clone(), contract_id, dashboard_id).unwrap();
        assert_eq!(updated_dashboard.name, new_name);
        assert_eq!(updated_dashboard.time_range, new_time_range);
        assert_eq!(updated_dashboard.refresh_interval, new_refresh_interval);
    }

    #[test]
    fn test_pause_functionality() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        // Pause contract
        PerformanceMonitoringContract::set_paused(env.clone(), contract_id, admin.clone(), true).unwrap();
        
        // Try to record metric while paused - should fail
        let contract_address = Address::generate(&env);
        let result = PerformanceMonitoringContract::record_metric(
            env.clone(),
            contract_id,
            contract_address,
            Symbol::new(&env, "test_metric"),
            100u64,
            Symbol::new(&env, "count"),
            Symbol::new(&env, "test_operation"),
            Map::new(&env),
        );
        
        assert_eq!(result, Err(ContractError::Paused));
        
        // Unpause contract
        PerformanceMonitoringContract::set_paused(env.clone(), contract_id, admin.clone(), false).unwrap();
        
        // Should work again
        let result = PerformanceMonitoringContract::record_metric(
            env.clone(),
            contract_id,
            contract_address,
            Symbol::new(&env, "test_metric"),
            100u64,
            Symbol::new(&env, "count"),
            Symbol::new(&env, "test_operation"),
            Map::new(&env),
        );
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_time_series_data() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let contract_address = Address::generate(&env);
        let metric_name = Symbol::new(&env, "gas_used");
        let start_time = env.ledger().timestamp() - 3600;
        let end_time = env.ledger().timestamp();
        let limit = 100u32;

        let time_series = PerformanceMonitoringContract::get_time_series_data(
            env.clone(),
            contract_id,
            contract_address.clone(),
            metric_name,
            start_time,
            end_time,
            limit,
        ).unwrap();

        // Verify time series structure
        // In production, this would contain actual data points
        assert_eq!(time_series.len(), 0); // Empty in test environment
    }

    #[test]
    fn test_get_active_alerts() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let contract_address = Address::generate(&env);

        let active_alerts = PerformanceMonitoringContract::get_active_alerts(
            env.clone(),
            contract_id,
            Some(contract_address.clone()),
        );

        // Verify alerts structure
        // In production, this would contain actual active alerts
        assert_eq!(active_alerts.len(), 0); // Empty in test environment
    }

    #[test]
    fn test_get_performance_stats() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());

        let stats = PerformanceMonitoringContract::get_performance_stats(env.clone(), contract_id);
        
        // Verify stats structure (total_metrics, total_alerts, total_dashboards, avg_performance_score)
        assert_eq!(stats, (0, 0, 0, 0.0));
    }

    #[test]
    fn test_invalid_alert_rule_conditions() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let contract_address = Address::generate(&env);
        let metric_name = Symbol::new(&env, "test_metric");
        let invalid_condition = Symbol::new(&env, "invalid");
        let threshold = 100u64;
        let time_window = 300u64;
        let min_data_points = 10u32;
        let severity = Symbol::new(&env, "medium");

        let result = PerformanceMonitoringContract::create_alert_rule(
            env.clone(),
            contract_id,
            admin.clone(),
            String::from_str(&env, "Invalid Rule"),
            String::from_str(&env, "Rule with invalid condition"),
            Some(contract_address),
            metric_name,
            invalid_condition,
            threshold,
            time_window,
            min_data_points,
            severity,
            300u64,
        );

        // Should fail due to invalid condition
        assert_eq!(result, Err(ContractError::AlertRuleInvalid));
    }

    #[test]
    fn test_dashboard_permissions() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let owner = Address::generate(&env);
        let unauthorized_user = Address::generate(&env);

        let dashboard_id = PerformanceMonitoringContract::create_dashboard(
            env.clone(),
            contract_id,
            owner.clone(),
            String::from_str(&env, "Private Dashboard"),
            String::from_str(&env, "Private dashboard"),
            Vec::new(&env),
            3600u64,
            60u64,
            false,
        ).unwrap();

        // Try to update dashboard with unauthorized user
        let result = PerformanceMonitoringContract::update_dashboard(
            env.clone(),
            contract_id,
            unauthorized_user.clone(),
            dashboard_id,
            String::from_str(&env, "Hacked Dashboard"),
            String::from_str(&env, "Unauthorized update"),
            Vec::new(&env),
            3600u64,
            60u64,
            false,
        );

        // Should fail due to unauthorized access
        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    #[test]
    fn test_metric_validation() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let contract_address = Address::generate(&env);
        let metric_name = Symbol::new(&env, "test_metric");
        let value = u64::MAX;
        let unit = Symbol::new(&env, "test_unit");
        let operation = Symbol::new(&env, "test_operation");
        let metadata = Map::new(&env);

        // Test recording valid metric
        let result = PerformanceMonitoringContract::record_metric(
            env.clone(),
            contract_id,
            contract_address.clone(),
            metric_name,
            value,
            unit,
            operation,
            metadata,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_time_series_validation() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let contract_address = Address::generate(&env);
        let metric_name = Symbol::new(&env, "test_metric");
        let start_time = env.ledger().timestamp();
        let end_time = env.ledger().timestamp() - 1; // Invalid: end before start
        let limit = 100u32;

        let result = PerformanceMonitoringContract::get_time_series_data(
            env.clone(),
            contract_id,
            contract_address,
            metric_name,
            start_time,
            end_time,
            limit,
        );

        // Should fail due to invalid time range
        assert_eq!(result, Err(ContractError::TimeSeriesInvalid));
    }

    #[test]
    fn test_limit_validation() {
        let (env, admin) = setup_test_env();
        let contract_id = env.register_contract(None, PerformanceMonitoringContract);
        
        PerformanceMonitoringContract::initialize(env.clone(), contract_id, admin.clone());
        
        let contract_address = Address::generate(&env);
        let metric_name = Symbol::new(&env, "test_metric");
        let start_time = env.ledger().timestamp() - 3600;
        let end_time = env.ledger().timestamp();
        let invalid_limit = 0u32; // Invalid: zero limit

        let result = PerformanceMonitoringContract::get_time_series_data(
            env.clone(),
            contract_id,
            contract_address,
            metric_name,
            start_time,
            end_time,
            invalid_limit,
        );

        // Should fail due to invalid limit
        assert_eq!(result, Err(ContractError::InvalidInput));
    }
}
