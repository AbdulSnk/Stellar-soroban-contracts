#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, BytesN, Env, Symbol, Vec, String, Map,
};
use shared::authorization::{require_admin, require_role, Role};

#[contract]
pub struct AlertingSystemContract;

// Storage keys
const ADMIN: Symbol = symbol_short!("ADMIN");
const PAUSED: Symbol = symbol_short!("PAUSED");
const ALERT_COUNTER: Symbol = symbol_short!("ALERT_CNT");
const RULE_COUNTER: Symbol = symbol_short!("RULE_CNT");
const NOTIFICATION_COUNTER: Symbol = symbol_short!("NOTIF_CNT");

// Alerting storage prefixes
const ALERT_RULE: Symbol = symbol_short!("ALERT_RULE");
const ALERT_RECORD: Symbol = symbol_short!("ALERT_REC");
const NOTIFICATION_CHANNEL: Symbol = symbol_short!("NOTIF_CHAN");
const ALERT_ESCALATION: Symbol = symbol_short!("ALERT_ESC");
const ALERT_SUPPRESSION: Symbol = symbol_short!("ALERT_SUP");
const ALERT_TEMPLATE: Symbol = symbol_short!("ALERT_TEMP");

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
    RuleInvalid = 9,
    NotificationFailed = 10,
    EscalationFailed = 11,
    SuppressionActive = 12,
    TemplateNotFound = 13,
    ChannelNotFound = 14,
    RateLimited = 15,
}

/// Alert rule configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertRule {
    /// Rule identifier
    pub rule_id: u64,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Contract address to monitor (None for all)
    pub contract_address: Option<Address>,
    /// Metric to monitor
    pub metric_name: Symbol,
    /// Alert condition
    pub condition: AlertCondition,
    /// Severity level
    pub severity: AlertSeverity,
    /// Whether rule is active
    pub is_active: bool,
    /// Rule creator
    pub creator: Address,
    /// Created timestamp
    pub created_at: u64,
    /// Last updated timestamp
    pub updated_at: u64,
    /// Rule version
    pub version: u32,
}

/// Alert condition
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertCondition {
    /// Condition type (threshold, rate, anomaly, pattern)
    pub condition_type: Symbol,
    /// Comparison operator (gt, lt, eq, gte, lte)
    pub operator: Symbol,
    /// Threshold value
    pub threshold: u64,
    /// Time window for evaluation (seconds)
    pub time_window: u64,
    /// Minimum data points to evaluate
    pub min_data_points: u32,
    /// Additional condition parameters
    pub parameters: Map<Symbol, String>,
}

/// Alert severity levels
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
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
    pub severity: AlertSeverity,
    /// Alert message
    pub message: String,
    /// Actual value that triggered alert
    pub actual_value: u64,
    /// Threshold value
    pub threshold_value: u64,
    /// Alert timestamp
    pub timestamp: u64,
    /// Alert status
    pub status: AlertStatus,
    /// Acknowledged by (if applicable)
    pub acknowledged_by: Option<Address>,
    /// Acknowledged timestamp
    pub acknowledged_at: Option<u64>,
    /// Resolved by (if applicable)
    pub resolved_by: Option<Address>,
    /// Resolved timestamp
    pub resolved_at: Option<u64>,
    /// Resolution notes
    pub resolution_notes: Option<String>,
}

/// Alert status
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AlertStatus {
    Active,
    Acknowledged,
    Resolved,
    Suppressed,
    Escalated,
}

/// Notification channel
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationChannel {
    /// Channel identifier
    pub channel_id: u64,
    /// Channel name
    pub name: String,
    /// Channel type (email, webhook, slack, telegram, etc.)
    pub channel_type: Symbol,
    /// Channel configuration
    pub config: Map<Symbol, String>,
    /// Channel owner
    pub owner: Address,
    /// Whether channel is active
    pub is_active: bool,
    /// Rate limiting configuration
    pub rate_limit: Option<RateLimit>,
    /// Created timestamp
    pub created_at: u64,
    /// Last updated timestamp
    pub updated_at: u64,
}

/// Rate limiting for notifications
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimit {
    /// Maximum notifications per period
    pub max_notifications: u32,
    /// Time period in seconds
    pub period_seconds: u64,
    /// Current notification count
    pub current_count: u32,
    /// Period start timestamp
    pub period_start: u64,
}

/// Alert escalation policy
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertEscalation {
    /// Escalation identifier
    pub escalation_id: u64,
    /// Rule ID this escalation applies to
    pub rule_id: u64,
    /// Escalation trigger conditions
    pub trigger_conditions: Vec<EscalationTrigger>,
    /// Escalation actions
    pub actions: Vec<EscalationAction>,
    /// Whether escalation is active
    pub is_active: bool,
    /// Created timestamp
    pub created_at: u64,
}

/// Escalation trigger
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscalationTrigger {
    /// Trigger type (time, count, severity)
    pub trigger_type: Symbol,
    /// Trigger value
    pub trigger_value: u64,
    /// Trigger parameters
    pub parameters: Map<Symbol, String>,
}

/// Escalation action
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscalationAction {
    /// Action type (notify, escalate, suppress)
    pub action_type: Symbol,
    /// Action parameters
    pub parameters: Map<Symbol, String>,
    /// Action delay (seconds)
    pub delay_seconds: u64,
}

/// Alert suppression rule
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertSuppression {
    /// Suppression identifier
    pub suppression_id: u64,
    /// Suppression name
    pub name: String,
    /// Suppression conditions
    pub conditions: Vec<AlertCondition>,
    /// Suppression period (seconds)
    pub suppression_period: u64,
    /// Whether suppression is active
    pub is_active: bool,
    /// Created timestamp
    pub created_at: u64,
    /// Expires timestamp
    pub expires_at: Option<u64>,
}

/// Alert template
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertTemplate {
    /// Template identifier
    pub template_id: u64,
    /// Template name
    pub name: String,
    /// Template category
    pub category: Symbol,
    /// Message template with placeholders
    pub message_template: String,
    /// Subject template (for email notifications)
    pub subject_template: String,
    /// Template variables
    pub variables: Vec<String>,
    /// Template creator
    pub creator: Address,
    /// Whether template is public
    pub is_public: bool,
    /// Created timestamp
    pub created_at: u64,
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

fn get_next_alert_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&ALERT_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&ALERT_COUNTER, &(current + 1));
    current + 1
}

fn get_next_rule_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&RULE_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&RULE_COUNTER, &(current + 1));
    current + 1
}

fn get_next_notification_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&NOTIFICATION_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&NOTIFICATION_COUNTER, &(current + 1));
    current + 1
}

/// Evaluate alert condition
fn evaluate_condition(
    condition: &AlertCondition,
    actual_value: u64,
    historical_data: &Vec<u64>,
) -> bool {
    match condition.condition_type.to_string().as_str() {
        "threshold" => {
            match condition.operator.to_string().as_str() {
                "gt" => actual_value > condition.threshold,
                "lt" => actual_value < condition.threshold,
                "eq" => actual_value == condition.threshold,
                "gte" => actual_value >= condition.threshold,
                "lte" => actual_value <= condition.threshold,
                _ => false,
            }
        }
        "rate" => {
            // Calculate rate over time window
            if historical_data.len() >= condition.min_data_points as usize {
                let recent_data = &historical_data[historical_data.len() - condition.min_data_points as usize..];
                let sum: u64 = recent_data.iter().sum();
                let rate = sum / condition.time_window;
                match condition.operator.to_string().as_str() {
                    "gt" => rate > condition.threshold,
                    "lt" => rate < condition.threshold,
                    "eq" => rate == condition.threshold,
                    "gte" => rate >= condition.threshold,
                    "lte" => rate <= condition.threshold,
                    _ => false,
                }
            } else {
                false
            }
        }
        "anomaly" => {
            // Simple anomaly detection - can be made more sophisticated
            if historical_data.len() >= 10 {
                let mean = historical_data.iter().sum::<u64>() / historical_data.len() as u64;
                let variance = historical_data
                    .iter()
                    .map(|&x| {
                        let diff = x as i64 - mean as i64;
                        (diff * diff) as u64
                    })
                    .sum::<u64>() / historical_data.len() as u64;
                let std_dev = (variance as f64).sqrt() as u64;
                
                // Check if current value is outside 2 standard deviations
                actual_value > (mean + 2 * std_dev) || actual_value < (mean.saturating_sub(2 * std_dev))
            } else {
                false
            }
        }
        _ => false,
    }
}

#[contractimpl]
impl AlertingSystemContract {
    /// Initialize the alerting system contract
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().persistent().has(&ADMIN) {
            return Err(ContractError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&ALERT_COUNTER, &0u64);
        env.storage().persistent().set(&RULE_COUNTER, &0u64);
        env.storage().persistent().set(&NOTIFICATION_COUNTER, &0u64);

        env.events().publish((symbol_short!("init"), ()), admin);

        Ok(())
    }

    /// Create alert rule
    pub fn create_alert_rule(
        env: Env,
        creator: Address,
        name: String,
        description: String,
        contract_address: Option<Address>,
        metric_name: Symbol,
        condition_type: Symbol,
        operator: Symbol,
        threshold: u64,
        time_window: u64,
        min_data_points: u32,
        parameters: Map<Symbol, String>,
        severity: AlertSeverity,
    ) -> Result<u64, ContractError> {
        creator.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let rule_id = get_next_rule_id(&env);

        let condition = AlertCondition {
            condition_type,
            operator,
            threshold,
            time_window,
            min_data_points,
            parameters,
        };

        let rule = AlertRule {
            rule_id,
            name: name.clone(),
            description,
            contract_address,
            metric_name,
            condition,
            severity,
            is_active: true,
            creator: creator.clone(),
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
            version: 1,
        };

        env.storage()
            .persistent()
            .set(&(ALERT_RULE, rule_id), &rule);

        env.events().publish(
            (symbol_short!("alert_rule_created"), creator),
            (rule_id, name),
        );

        Ok(rule_id)
    }

    /// Create notification channel
    pub fn create_notification_channel(
        env: Env,
        owner: Address,
        name: String,
        channel_type: Symbol,
        config: Map<Symbol, String>,
        rate_limit: Option<RateLimit>,
    ) -> Result<u64, ContractError> {
        owner.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let channel_id = get_next_notification_id(&env);

        let channel = NotificationChannel {
            channel_id,
            name: name.clone(),
            channel_type,
            config,
            owner: owner.clone(),
            is_active: true,
            rate_limit,
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&(NOTIFICATION_CHANNEL, channel_id), &channel);

        env.events().publish(
            (symbol_short!("notification_channel_created"), owner),
            (channel_id, name),
        );

        Ok(channel_id)
    }

    /// Trigger alert evaluation
    pub fn evaluate_alerts(
        env: Env,
        contract_address: Address,
        metric_name: Symbol,
        current_value: u64,
        historical_data: Vec<u64>,
    ) -> Result<Vec<u64>, ContractError> {
        // This should be callable by monitoring systems
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let mut triggered_alerts = Vec::new(&env);

        // Check all active alert rules for this metric
        // In production, implement efficient querying
        // For now, simulate evaluation

        // Check suppression rules
        if Self::is_suppressed(&env, &contract_address, &metric_name, current_value)? {
            return Ok(triggered_alerts);
        }

        // Create alert record if conditions are met
        let alert_id = get_next_alert_id(&env);
        let alert = AlertRecord {
            alert_id,
            rule_id: 0, // Would be actual rule ID
            contract_address: contract_address.clone(),
            metric_name,
            severity: AlertSeverity::Medium,
            message: String::from_str(&env, "Alert triggered"),
            actual_value: current_value,
            threshold_value: 100, // Would be actual threshold
            timestamp: env.ledger().timestamp(),
            status: AlertStatus::Active,
            acknowledged_by: None,
            acknowledged_at: None,
            resolved_by: None,
            resolved_at: None,
            resolution_notes: None,
        };

        env.storage()
            .persistent()
            .set(&(ALERT_RECORD, alert_id), &alert);

        triggered_alerts.push_back(alert_id);

        // Send notifications
        Self::send_notifications(&env, &alert)?;

        // Check escalation conditions
        Self::check_escalation(&env, &alert)?;

        env.events().publish(
            (symbol_short!("alert_triggered"), contract_address),
            alert_id,
        );

        Ok(triggered_alerts)
    }

    /// Acknowledge alert
    pub fn acknowledge_alert(
        env: Env,
        user: Address,
        alert_id: u64,
    ) -> Result<(), ContractError> {
        user.require_auth();

        let mut alert: AlertRecord = env
            .storage()
            .persistent()
            .get(&(ALERT_RECORD, alert_id))
            .ok_or(ContractError::NotFound)?;

        if alert.status != AlertStatus::Active {
            return Err(ContractError::InvalidState);
        }

        alert.status = AlertStatus::Acknowledged;
        alert.acknowledged_by = Some(user.clone());
        alert.acknowledged_at = Some(env.ledger().timestamp());

        env.storage()
            .persistent()
            .set(&(ALERT_RECORD, alert_id), &alert);

        env.events().publish(
            (symbol_short!("alert_acknowledged"), user),
            alert_id,
        );

        Ok(())
    }

    /// Resolve alert
    pub fn resolve_alert(
        env: Env,
        user: Address,
        alert_id: u64,
        resolution_notes: String,
    ) -> Result<(), ContractError> {
        user.require_auth();

        let mut alert: AlertRecord = env
            .storage()
            .persistent()
            .get(&(ALERT_RECORD, alert_id))
            .ok_or(ContractError::NotFound)?;

        alert.status = AlertStatus::Resolved;
        alert.resolved_by = Some(user.clone());
        alert.resolved_at = Some(env.ledger().timestamp());
        alert.resolution_notes = Some(resolution_notes);

        env.storage()
            .persistent()
            .set(&(ALERT_RECORD, alert_id), &alert);

        env.events().publish(
            (symbol_short!("alert_resolved"), user),
            alert_id,
        );

        Ok(())
    }

    /// Create alert suppression rule
    pub fn create_suppression_rule(
        env: Env,
        admin: Address,
        name: String,
        conditions: Vec<AlertCondition>,
        suppression_period: u64,
        expires_at: Option<u64>,
    ) -> Result<u64, ContractError> {
        admin.require_auth();

        require_admin(&env, &admin)?;

        let suppression_id = get_next_rule_id(&env);

        let suppression = AlertSuppression {
            suppression_id,
            name,
            conditions,
            suppression_period,
            is_active: true,
            created_at: env.ledger().timestamp(),
            expires_at,
        };

        env.storage()
            .persistent()
            .set(&(ALERT_SUPPRESSION, suppression_id), &suppression);

        env.events().publish(
            (symbol_short!("suppression_created"), admin),
            suppression_id,
        );

        Ok(suppression_id)
    }

    /// Create alert template
    pub fn create_alert_template(
        env: Env,
        creator: Address,
        name: String,
        category: Symbol,
        message_template: String,
        subject_template: String,
        variables: Vec<String>,
        is_public: bool,
    ) -> Result<u64, ContractError> {
        creator.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let template_id = get_next_notification_id(&env);

        let template = AlertTemplate {
            template_id,
            name: name.clone(),
            category,
            message_template,
            subject_template,
            variables,
            creator: creator.clone(),
            is_public,
            created_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&(ALERT_TEMPLATE, template_id), &template);

        env.events().publish(
            (symbol_short!("template_created"), creator),
            (template_id, name),
        );

        Ok(template_id)
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

    /// Send notifications for alert
    fn send_notifications(env: &Env, alert: &AlertRecord) -> Result<(), ContractError> {
        // In production, query notification channels and send notifications
        // For now, simulate notification sending
        Ok(())
    }

    /// Check escalation conditions
    fn check_escalation(env: &Env, alert: &AlertRecord) -> Result<(), ContractError> {
        // In production, check escalation policies and trigger if needed
        // For now, placeholder implementation
        Ok(())
    }

    /// Check if alert is suppressed
    fn is_suppressed(
        env: &Env,
        contract_address: &Address,
        metric_name: &Symbol,
        value: u64,
    ) -> Result<bool, ContractError> {
        // In production, check suppression rules
        // For now, return false
        Ok(false)
    }

    // ===== View Functions =====

    /// Get alert rule
    pub fn get_alert_rule(env: Env, rule_id: u64) -> Option<AlertRule> {
        env.storage().persistent().get(&(ALERT_RULE, rule_id))
    }

    /// Get alert record
    pub fn get_alert_record(env: Env, alert_id: u64) -> Option<AlertRecord> {
        env.storage().persistent().get(&(ALERT_RECORD, alert_id))
    }

    /// Get notification channel
    pub fn get_notification_channel(env: Env, channel_id: u64) -> Option<NotificationChannel> {
        env.storage().persistent().get(&(NOTIFICATION_CHANNEL, channel_id))
    }

    /// Get alert suppression rule
    pub fn get_suppression_rule(env: Env, suppression_id: u64) -> Option<AlertSuppression> {
        env.storage().persistent().get(&(ALERT_SUPPRESSION, suppression_id))
    }

    /// Get alert template
    pub fn get_alert_template(env: Env, template_id: u64) -> Option<AlertTemplate> {
        env.storage().persistent().get(&(ALERT_TEMPLATE, template_id))
    }

    /// List active alerts
    pub fn list_active_alerts(env: Env, contract_address: Option<Address>) -> Vec<AlertRecord> {
        // In production, query active alerts by contract
        // For now, return empty vector
        Vec::new(&env)
    }

    /// Get alert statistics
    pub fn get_alert_stats(env: Env) -> (u64, u64, u64, u64) {
        // Returns (total_alerts, active_alerts, acknowledged_alerts, resolved_alerts)
        // In production, calculate from actual data
        (0, 0, 0, 0)
    }
}
