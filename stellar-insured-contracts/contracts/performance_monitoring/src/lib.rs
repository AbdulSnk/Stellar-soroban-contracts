#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, BytesN, Env, Symbol, Vec, String, Map,
};
use shared::{
    GasMeasurement, GasMetrics, authorization::{require_admin, require_role, Role},
};

#[contract]
pub struct PerformanceMonitoringContract;

// Storage keys
const ADMIN: Symbol = symbol_short!("ADMIN");
const PAUSED: Symbol = symbol_short!("PAUSED");
const METRICS_COUNTER: Symbol = symbol_short!("MET_CNT");
const ALERT_COUNTER: Symbol = symbol_short!("ALERT_CNT");
const DASHBOARD_COUNTER: Symbol = symbol_short!("DASH_CNT");

// Performance monitoring storage prefixes
const PERFORMANCE_METRIC: Symbol = symbol_short!("PERF_MET");
const AGGREGATE_METRICS: Symbol = symbol_short!("AGG_MET");
const ALERT_RULE: Symbol = symbol_short!("ALERT_RULE");
const ALERT_HISTORY: Symbol = symbol_short!("ALERT_HIST");
const DASHBOARD_CONFIG: Symbol = symbol_short!("DASH_CFG");
const CONTRACT_METRICS: Symbol = symbol_short!("CONT_MET");
const TIME_SERIES_DATA: Symbol = symbol_short!("TIME_SER");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ContractError {
    Unauthorized = 1,
    Paused = 2,
    InvalidInput = 3,
    NotFound = 4,
    AlreadyExists = 5,
    InvalidState = 6,
    NotInitialized = 7,
    AlreadyInitialized = 8,
    AlertRuleInvalid = 9,
    MetricNotFound = 10,
    DashboardNotFound = 11,
    TimeSeriesInvalid = 12,
    AggregationFailed = 13,
    InsufficientData = 14,
}

/// Performance metric with detailed information
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerformanceMetric {
    /// Unique metric identifier
    pub metric_id: u64,
    /// Contract address that generated the metric
    pub contract_address: Address,
    /// Metric name (e.g., "gas_used", "execution_time", "storage_ops")
    pub metric_name: Symbol,
    /// Metric value
    pub value: u64,
    /// Metric unit (e.g., "gas", "ms", "count")
    pub unit: Symbol,
    /// Timestamp when metric was recorded
    pub timestamp: u64,
    /// Additional metadata
    pub metadata: Map<Symbol, String>,
    /// Operation context (e.g., function name)
    pub operation: Symbol,
}

/// Aggregated metrics for time periods
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateMetrics {
    /// Aggregation identifier
    pub aggregate_id: u64,
    /// Metric name being aggregated
    pub metric_name: Symbol,
    /// Contract address
    pub contract_address: Address,
    /// Time period (hourly, daily, weekly, monthly)
    pub period: Symbol,
    /// Start timestamp of period
    pub period_start: u64,
    /// End timestamp of period
    pub period_end: u64,
    /// Total value for period
    pub total: u64,
    /// Average value for period
    pub average: u64,
    /// Minimum value for period
    pub minimum: u64,
    /// Maximum value for period
    pub maximum: u64,
    /// Number of data points
    pub count: u64,
    /// Standard deviation (if applicable)
    pub std_deviation: u64,
}

/// Alert rule configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertRule {
    /// Alert rule identifier
    pub rule_id: u64,
    /// Rule name
    pub rule_name: String,
    /// Contract address to monitor (None for all contracts)
    pub contract_address: Option<Address>,
    /// Metric name to monitor
    pub metric_name: Symbol,
    /// Alert condition (gt, lt, eq, gte, lte)
    pub condition: Symbol,
    /// Threshold value
    pub threshold: u64,
    /// Time window for evaluation (seconds)
    pub time_window: u64,
    /// Minimum number of data points to trigger
    pub min_data_points: u32,
    /// Alert severity (low, medium, high, critical)
    pub severity: Symbol,
    /// Whether rule is active
    pub is_active: bool,
    /// Created at timestamp
    pub created_at: u64,
    /// Last triggered timestamp
    pub last_triggered: Option<u64>,
    /// Cooldown period between alerts (seconds)
    pub cooldown_period: u64,
}

/// Alert record
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertRecord {
    /// Alert identifier
    pub alert_id: u64,
    /// Rule that triggered the alert
    pub rule_id: u64,
    /// Contract address that triggered alert
    pub contract_address: Address,
    /// Metric name
    pub metric_name: Symbol,
    /// Alert severity
    pub severity: Symbol,
    /// Alert message
    pub message: String,
    /// Actual value that triggered alert
    pub actual_value: u64,
    /// Threshold value
    pub threshold_value: u64,
    /// Alert timestamp
    pub timestamp: u64,
    /// Whether alert is acknowledged
    pub acknowledged: bool,
    /// Acknowledged by (if applicable)
    pub acknowledged_by: Option<Address>,
    /// Acknowledged timestamp
    pub acknowledged_at: Option<u64>,
}

/// Dashboard configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardConfig {
    /// Dashboard identifier
    pub dashboard_id: u64,
    /// Dashboard name
    pub name: String,
    /// Dashboard description
    pub description: String,
    /// Owner address
    pub owner: Address,
    /// List of metrics to display
    pub metrics: Vec<DashboardMetric>,
    /// Time range for data display
    pub time_range: u64, // seconds
    /// Refresh interval (seconds)
    pub refresh_interval: u64,
    /// Whether dashboard is public
    pub is_public: bool,
    /// Created at timestamp
    pub created_at: u64,
    /// Last updated timestamp
    pub updated_at: u64,
}

/// Metric configuration for dashboard
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardMetric {
    /// Metric name
    pub metric_name: Symbol,
    /// Contract address (None for all contracts)
    pub contract_address: Option<Address>,
    /// Aggregation type (sum, avg, min, max, count)
    pub aggregation: Symbol,
    /// Display name
    pub display_name: String,
    /// Chart type (line, bar, gauge, table)
    pub chart_type: Symbol,
    /// Color for visualization
    pub color: String,
}

/// Time series data point
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeSeriesDataPoint {
    /// Timestamp
    pub timestamp: u64,
    /// Value
    pub value: u64,
    /// Optional metadata
    pub metadata: Map<Symbol, String>,
}

/// Contract performance summary
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractPerformanceSummary {
    /// Contract address
    pub contract_address: Address,
    /// Total operations
    pub total_operations: u64,
    /// Average gas per operation
    pub avg_gas_per_op: u64,
    /// Total gas consumed
    pub total_gas_consumed: u64,
    /// Average execution time
    pub avg_execution_time: u64,
    /// Error rate (percentage)
    pub error_rate: u32,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Performance score (0-100)
    pub performance_score: u32,
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

fn get_next_metric_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&METRICS_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&METRICS_COUNTER, &(current + 1));
    current + 1
}

fn get_next_alert_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&ALERT_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&ALERT_COUNTER, &(current + 1));
    current + 1
}

fn get_next_dashboard_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&DASHBOARD_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&DASHBOARD_COUNTER, &(current + 1));
    current + 1
}

/// Evaluate alert condition
fn evaluate_alert_condition(condition: Symbol, actual: u64, threshold: u64) -> bool {
    match condition.to_string().as_str() {
        "gt" => actual > threshold,
        "lt" => actual < threshold,
        "eq" => actual == threshold,
        "gte" => actual >= threshold,
        "lte" => actual <= threshold,
        _ => false,
    }
}

#[contractimpl]
impl PerformanceMonitoringContract {
    /// Initialize the performance monitoring contract
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().persistent().has(&ADMIN) {
            return Err(ContractError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&METRICS_COUNTER, &0u64);
        env.storage().persistent().set(&ALERT_COUNTER, &0u64);
        env.storage().persistent().set(&DASHBOARD_COUNTER, &0u64);

        env.events().publish((symbol_short!("init"), ()), admin);

        Ok(())
    }

    /// Record a performance metric
    pub fn record_metric(
        env: Env,
        contract_address: Address,
        metric_name: Symbol,
        value: u64,
        unit: Symbol,
        operation: Symbol,
        metadata: Map<Symbol, String>,
    ) -> Result<u64, ContractError> {
        // This function should be callable by any contract for self-monitoring
        // In production, add authorization checks

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let metric_id = get_next_metric_id(&env);

        let metric = PerformanceMetric {
            metric_id,
            contract_address: contract_address.clone(),
            metric_name,
            value,
            unit,
            timestamp: env.ledger().timestamp(),
            metadata,
            operation,
        };

        env.storage()
            .persistent()
            .set(&(PERFORMANCE_METRIC, metric_id), &metric);

        // Update contract metrics
        Self::update_contract_metrics(&env, contract_address.clone(), &metric)?;

        // Check alert rules
        Self::check_alert_rules(&env, &metric)?;

        // Emit event
        env.events().publish(
            (symbol_short!("metric_recorded"), contract_address),
            (metric_id, metric.metric_name, value),
        );

        Ok(metric_id)
    }

    /// Create an alert rule
    pub fn create_alert_rule(
        env: Env,
        admin: Address,
        rule_name: String,
        contract_address: Option<Address>,
        metric_name: Symbol,
        condition: Symbol,
        threshold: u64,
        time_window: u64,
        min_data_points: u32,
        severity: Symbol,
        cooldown_period: u64,
    ) -> Result<u64, ContractError> {
        admin.require_auth();

        require_admin(&env, &admin)?;

        // Validate condition
        let condition_str = condition.to_string();
        if !["gt", "lt", "eq", "gte", "lte"].contains(&condition_str.as_str()) {
            return Err(ContractError::AlertRuleInvalid);
        }

        // Validate severity
        let severity_str = severity.to_string();
        if !["low", "medium", "high", "critical"].contains(&severity_str.as_str()) {
            return Err(ContractError::AlertRuleInvalid);
        }

        let rule_id = get_next_alert_id(&env);

        let rule = AlertRule {
            rule_id,
            rule_name: rule_name.clone(),
            contract_address,
            metric_name,
            condition,
            threshold,
            time_window,
            min_data_points,
            severity,
            is_active: true,
            created_at: env.ledger().timestamp(),
            last_triggered: None,
            cooldown_period,
        };

        env.storage()
            .persistent()
            .set(&(ALERT_RULE, rule_id), &rule);

        env.events().publish(
            (symbol_short!("alert_rule_created"), rule_name),
            rule_id,
        );

        Ok(rule_id)
    }

    /// Create a dashboard
    pub fn create_dashboard(
        env: Env,
        owner: Address,
        name: String,
        description: String,
        metrics: Vec<DashboardMetric>,
        time_range: u64,
        refresh_interval: u64,
        is_public: bool,
    ) -> Result<u64, ContractError> {
        owner.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let dashboard_id = get_next_dashboard_id(&env);

        let dashboard = DashboardConfig {
            dashboard_id,
            name: name.clone(),
            description,
            owner: owner.clone(),
            metrics,
            time_range,
            refresh_interval,
            is_public,
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&(DASHBOARD_CONFIG, dashboard_id), &dashboard);

        env.events().publish(
            (symbol_short!("dashboard_created"), owner),
            (dashboard_id, name),
        );

        Ok(dashboard_id)
    }

    /// Get aggregated metrics for a time period
    pub fn get_aggregated_metrics(
        env: Env,
        contract_address: Address,
        metric_name: Symbol,
        period: Symbol,
        start_time: u64,
        end_time: u64,
    ) -> Result<AggregateMetrics, ContractError> {
        // In production, this would query and aggregate actual time series data
        // For now, return a simulated aggregation
        let aggregate_id = get_next_metric_id(&env);

        Ok(AggregateMetrics {
            aggregate_id,
            metric_name,
            contract_address,
            period,
            period_start: start_time,
            period_end: end_time,
            total: 0,
            average: 0,
            minimum: u64::MAX,
            maximum: 0,
            count: 0,
            std_deviation: 0,
        })
    }

    /// Get contract performance summary
    pub fn get_contract_performance_summary(
        env: Env,
        contract_address: Address,
    ) -> Result<ContractPerformanceSummary, ContractError> {
        // In production, calculate from actual metrics
        // For now, return simulated data
        Ok(ContractPerformanceSummary {
            contract_address,
            total_operations: 0,
            avg_gas_per_op: 0,
            total_gas_consumed: 0,
            avg_execution_time: 0,
            error_rate: 0,
            last_activity: 0,
            performance_score: 100,
        })
    }

    /// Get time series data for a metric
    pub fn get_time_series_data(
        env: Env,
        contract_address: Address,
        metric_name: Symbol,
        start_time: u64,
        end_time: u64,
        limit: u32,
    ) -> Result<Vec<TimeSeriesDataPoint>, ContractError> {
        if start_time >= end_time {
            return Err(ContractError::TimeSeriesInvalid);
        }

        if limit == 0 || limit > 1000 {
            return Err(ContractError::InvalidInput);
        }

        // In production, query actual time series data
        // For now, return empty vector
        Ok(Vec::new(&env))
    }

    /// Acknowledge an alert
    pub fn acknowledge_alert(
        env: Env,
        user: Address,
        alert_id: u64,
    ) -> Result<(), ContractError> {
        user.require_auth();

        let mut alert: AlertRecord = env
            .storage()
            .persistent()
            .get(&(ALERT_HISTORY, alert_id))
            .ok_or(ContractError::NotFound)?;

        if alert.acknowledged {
            return Err(ContractError::InvalidState);
        }

        alert.acknowledged = true;
        alert.acknowledged_by = Some(user.clone());
        alert.acknowledged_at = Some(env.ledger().timestamp());

        env.storage()
            .persistent()
            .set(&(ALERT_HISTORY, alert_id), &alert);

        env.events().publish(
            (symbol_short!("alert_acknowledged"), user),
            alert_id,
        );

        Ok(())
    }

    /// Update dashboard configuration
    pub fn update_dashboard(
        env: Env,
        owner: Address,
        dashboard_id: u64,
        name: String,
        description: String,
        metrics: Vec<DashboardMetric>,
        time_range: u64,
        refresh_interval: u64,
        is_public: bool,
    ) -> Result<(), ContractError> {
        owner.require_auth();

        let mut dashboard: DashboardConfig = env
            .storage()
            .persistent()
            .get(&(DASHBOARD_CONFIG, dashboard_id))
            .ok_or(ContractError::DashboardNotFound)?;

        if dashboard.owner != owner {
            return Err(ContractError::Unauthorized);
        }

        dashboard.name = name;
        dashboard.description = description;
        dashboard.metrics = metrics;
        dashboard.time_range = time_range;
        dashboard.refresh_interval = refresh_interval;
        dashboard.is_public = is_public;
        dashboard.updated_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&(DASHBOARD_CONFIG, dashboard_id), &dashboard);

        env.events().publish(
            (symbol_short!("dashboard_updated"), owner),
            dashboard_id,
        );

        Ok(())
    }

    /// Pause/unpause contract (admin only)
    pub fn set_paused(env: Env, admin: Address, paused: bool) -> Result<(), ContractError> {
        admin.require_auth();

        let stored_admin: Address = env.storage().persistent().get(&ADMIN).ok_or(ContractError::NotInitialized)?;
        if admin != stored_admin {
            return Err(ContractError::Unauthorized);
        }

        set_paused(&env, paused);

        env.events().publish(
            (symbol_short!("paused"), admin),
            paused,
        );

        Ok(())
    }

    // ===== Internal Helper Functions =====

    /// Update contract metrics based on new metric
    fn update_contract_metrics(
        env: &Env,
        contract_address: Address,
        metric: &PerformanceMetric,
    ) -> Result<(), ContractError> {
        let key = (CONTRACT_METRICS, contract_address.clone());
        let mut summary: ContractPerformanceSummary = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(ContractPerformanceSummary {
                contract_address: contract_address.clone(),
                total_operations: 0,
                avg_gas_per_op: 0,
                total_gas_consumed: 0,
                avg_execution_time: 0,
                error_rate: 0,
                last_activity: 0,
                performance_score: 100,
            });

        // Update summary based on metric
        if metric.metric_name == Symbol::new(env, "gas_used") {
            summary.total_gas_consumed += metric.value;
            summary.total_operations += 1;
            summary.avg_gas_per_op = summary.total_gas_consumed / summary.total_operations;
        } else if metric.metric_name == Symbol::new(env, "execution_time") {
            // Update execution time metrics
            summary.avg_execution_time = (summary.avg_execution_time + metric.value) / 2;
        }

        summary.last_activity = metric.timestamp;
        summary.performance_score = Self::calculate_performance_score(&summary);

        env.storage().persistent().set(&key, &summary);
        Ok(())
    }

    /// Check alert rules against new metric
    fn check_alert_rules(
        env: &Env,
        metric: &PerformanceMetric,
    ) -> Result<(), ContractError> {
        // In production, iterate through all active alert rules
        // For now, this is a placeholder implementation
        Ok(())
    }

    /// Calculate performance score (0-100)
    fn calculate_performance_score(summary: &ContractPerformanceSummary) -> u32 {
        // Simple scoring algorithm - can be made more sophisticated
        let gas_score = if summary.avg_gas_per_op < 1000000 { 100 } else { 50 };
        let time_score = if summary.avg_execution_time < 1000 { 100 } else { 50 };
        let error_score = 100 - summary.error_rate;

        (gas_score + time_score + error_score) / 3
    }

    // ===== View Functions =====

    /// Get performance metric
    pub fn get_performance_metric(env: Env, metric_id: u64) -> Option<PerformanceMetric> {
        env.storage().persistent().get(&(PERFORMANCE_METRIC, metric_id))
    }

    /// Get alert rule
    pub fn get_alert_rule(env: Env, rule_id: u64) -> Option<AlertRule> {
        env.storage().persistent().get(&(ALERT_RULE, rule_id))
    }

    /// Get alert record
    pub fn get_alert_record(env: Env, alert_id: u64) -> Option<AlertRecord> {
        env.storage().persistent().get(&(ALERT_HISTORY, alert_id))
    }

    /// Get dashboard configuration
    pub fn get_dashboard_config(env: Env, dashboard_id: u64) -> Option<DashboardConfig> {
        env.storage().persistent().get(&(DASHBOARD_CONFIG, dashboard_id))
    }

    /// Get all dashboards for an owner
    pub fn get_dashboards_for_owner(env: Env, owner: Address) -> Vec<DashboardConfig> {
        // In production, maintain an index for efficient querying
        // For now, return empty vector
        Vec::new(&env)
    }

    /// Get active alerts for a contract
    pub fn get_active_alerts(env: Env, contract_address: Address) -> Vec<AlertRecord> {
        // In production, query unacknowledged alerts
        // For now, return empty vector
        Vec::new(&env)
    }

    /// Get performance statistics
    pub fn get_performance_stats(env: Env) -> (u64, u64, u64, f64) {
        // Returns (total_metrics, total_alerts, total_dashboards, avg_performance_score)
        // In production, calculate from actual data
        (0, 0, 0, 0.0)
    }
}

#[cfg(test)]
mod tests;
