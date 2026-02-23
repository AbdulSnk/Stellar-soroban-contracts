#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, BytesN, Env, Symbol, Vec, String, Map,
};
use shared::authorization::{require_admin, require_role, Role};

#[contract]
pub struct ExternalMonitoringContract;

// Storage keys
const ADMIN: Symbol = symbol_short!("ADMIN");
const PAUSED: Symbol = symbol_short!("PAUSED");
const INTEGRATION_COUNTER: Symbol = symbol_short!("INT_CNT");
const WEBHOOK_COUNTER: Symbol = symbol_short!("WEB_CNT");

// External monitoring storage prefixes
const EXTERNAL_INTEGRATION: Symbol = symbol_short!("EXT_INT");
const WEBHOOK_ENDPOINT: Symbol = symbol_short!("WEB_HOOK");
const DATA_EXPORT: Symbol = symbol_short!("DATA_EXP");
const API_KEY: Symbol = symbol_short!("API_KEY");
const MONITORING_CONFIG: Symbol = symbol_short!("MON_CFG");
const SYNC_STATUS: Symbol = symbol_short!("SYNC_STAT");

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
    IntegrationFailed = 9,
    WebhookInvalid = 10,
    ExportFailed = 11,
    ApiKeyInvalid = 12,
    SyncFailed = 13,
    RateLimited = 14,
    ExternalServiceError = 15,
}

/// External monitoring integration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalIntegration {
    /// Integration identifier
    pub integration_id: u64,
    /// Integration name
    pub name: String,
    /// External service name (prometheus, grafana, datadog, etc.)
    pub service_name: Symbol,
    /// Integration type (push, pull, webhook, api)
    pub integration_type: Symbol,
    /// Integration configuration
    pub config: Map<Symbol, String>,
    /// Authentication credentials
    pub auth_credentials: AuthCredentials,
    /// Data format (json, protobuf, csv)
    pub data_format: Symbol,
    /// Sync frequency (seconds)
    pub sync_frequency: u64,
    /// Last sync timestamp
    pub last_sync: u64,
    /// Whether integration is active
    pub is_active: bool,
    /// Integration owner
    pub owner: Address,
    /// Created timestamp
    pub created_at: u64,
    /// Last updated timestamp
    pub updated_at: u64,
}

/// Authentication credentials for external services
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthCredentials {
    /// Authentication type (api_key, oauth, basic, bearer)
    pub auth_type: Symbol,
    /// Encrypted credentials
    pub encrypted_credentials: BytesN<32>,
    /// Credential metadata
    pub metadata: Map<Symbol, String>,
    /// Expires timestamp (if applicable)
    pub expires_at: Option<u64>,
}

/// Webhook endpoint configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookEndpoint {
    /// Webhook identifier
    pub webhook_id: u64,
    /// Webhook name
    pub name: String,
    /// Endpoint URL
    pub endpoint_url: String,
    /// Event types this webhook handles
    pub event_types: Vec<Symbol>,
    /// Secret token for verification
    pub secret_token: BytesN<32>,
    /// Retry configuration
    pub retry_config: RetryConfig,
    /// Rate limiting
    pub rate_limit: Option<RateLimit>,
    /// Whether webhook is active
    pub is_active: bool,
    /// Webhook owner
    pub owner: Address,
    /// Created timestamp
    pub created_at: u64,
    /// Last triggered timestamp
    pub last_triggered: Option<u64>,
}

/// Retry configuration for webhooks
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,
    /// Initial retry delay (seconds)
    pub initial_delay: u64,
    /// Backoff multiplier
    pub backoff_multiplier: u32,
    /// Maximum retry delay (seconds)
    pub max_delay: u64,
}

/// Rate limiting configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimit {
    /// Maximum requests per period
    pub max_requests: u32,
    /// Time period in seconds
    pub period_seconds: u64,
    /// Current request count
    pub current_count: u32,
    /// Period start timestamp
    pub period_start: u64,
}

/// Data export configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataExport {
    /// Export identifier
    pub export_id: u64,
    /// Export name
    pub name: String,
    /// Export type (metrics, logs, alerts, dashboards)
    pub export_type: Symbol,
    /// Data filters
    pub filters: Map<Symbol, String>,
    /// Time range for export
    pub time_range: TimeRange,
    /// Export format (json, csv, parquet)
    pub export_format: Symbol,
    /// Compression settings
    pub compression: CompressionSettings,
    /// Export status
    pub status: ExportStatus,
    /// Export file location (if applicable)
    pub file_location: Option<String>,
    /// Export requester
    pub requester: Address,
    /// Created timestamp
    pub created_at: u64,
    /// Completed timestamp
    pub completed_at: Option<u64>,
}

/// Time range for data export
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeRange {
    /// Start timestamp
    pub start_time: u64,
    /// End timestamp
    pub end_time: u64,
    /// Time zone
    pub timezone: String,
}

/// Compression settings
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompressionSettings {
    /// Compression algorithm (gzip, zip, lz4)
    pub algorithm: Symbol,
    /// Compression level (1-9)
    pub compression_level: u32,
}

/// Export status
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

/// API key for external access
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKey {
    /// API key identifier
    pub key_id: u64,
    /// API key value
    pub key_value: BytesN<32>,
    /// Key name
    pub name: String,
    /// Key permissions
    pub permissions: Vec<Symbol>,
    /// Rate limiting
    pub rate_limit: Option<RateLimit>,
    /// Key owner
    pub owner: Address,
    /// Created timestamp
    pub created_at: u64,
    /// Expires timestamp
    pub expires_at: Option<u64>,
    /// Last used timestamp
    pub last_used: Option<u64>,
    /// Whether key is active
    pub is_active: bool,
}

/// Monitoring configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitoringConfig {
    /// Config identifier
    pub config_id: u64,
    /// Configuration name
    pub name: String,
    /// Metrics to monitor
    pub monitored_metrics: Vec<Symbol>,
    /// Sampling interval (seconds)
    pub sampling_interval: u64,
    /// Data retention policy
    pub retention_policy: RetentionPolicy,
    /// Alert thresholds
    pub alert_thresholds: Map<Symbol, u64>,
    /// Dashboard configurations
    pub dashboard_configs: Vec<DashboardConfig>,
    /// Integration settings
    pub integration_settings: Map<Symbol, String>,
}

/// Data retention policy
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    /// Retention period in seconds
    pub retention_period: u64,
    /// Whether to compress old data
    pub compress_old_data: bool,
    /// Granularity levels to keep
    pub keep_granularities: Vec<Symbol>,
}

/// Dashboard configuration for external tools
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardConfig {
    /// Dashboard name
    pub name: String,
    /// Dashboard type (grafana, kibana, custom)
    pub dashboard_type: Symbol,
    /// Dashboard configuration JSON
    pub config_json: String,
    /// Data source mappings
    pub data_sources: Map<Symbol, String>,
}

/// Sync status for external integrations
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncStatus {
    /// Integration ID
    pub integration_id: u64,
    /// Last sync timestamp
    pub last_sync: u64,
    /// Sync status
    pub status: SyncStatusType,
    /// Error message (if failed)
    pub error_message: Option<String>,
    /// Records synced
    pub records_synced: u64,
    /// Records failed
    pub records_failed: u64,
    /// Next sync timestamp
    pub next_sync: u64,
}

/// Sync status type
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncStatusType {
    Success,
    Failed,
    InProgress,
    Scheduled,
    Disabled,
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

fn get_next_integration_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&INTEGRATION_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&INTEGRATION_COUNTER, &(current + 1));
    current + 1
}

fn get_next_webhook_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&WEBHOOK_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&WEBHOOK_COUNTER, &(current + 1));
    current + 1
}

/// Generate API key
fn generate_api_key(env: &Env) -> BytesN<32> {
    let timestamp = env.ledger().timestamp();
    // In production, use cryptographically secure random generation
    BytesN::from_array(env, &[
        (timestamp >> 24) as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ])
}

#[contractimpl]
impl ExternalMonitoringContract {
    /// Initialize the external monitoring contract
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().persistent().has(&ADMIN) {
            return Err(ContractError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&INTEGRATION_COUNTER, &0u64);
        env.storage().persistent().set(&WEBHOOK_COUNTER, &0u64);

        env.events().publish((symbol_short!("init"), ()), admin);

        Ok(())
    }

    /// Create external monitoring integration
    pub fn create_integration(
        env: Env,
        owner: Address,
        name: String,
        service_name: Symbol,
        integration_type: Symbol,
        config: Map<Symbol, String>,
        auth_type: Symbol,
        encrypted_credentials: BytesN<32>,
        data_format: Symbol,
        sync_frequency: u64,
    ) -> Result<u64, ContractError> {
        owner.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let integration_id = get_next_integration_id(&env);

        let auth_credentials = AuthCredentials {
            auth_type,
            encrypted_credentials,
            metadata: Map::new(&env),
            expires_at: None,
        };

        let integration = ExternalIntegration {
            integration_id,
            name: name.clone(),
            service_name,
            integration_type,
            config,
            auth_credentials,
            data_format,
            sync_frequency,
            last_sync: 0,
            is_active: true,
            owner: owner.clone(),
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&(EXTERNAL_INTEGRATION, integration_id), &integration);

        env.events().publish(
            (symbol_short!("integration_created"), owner),
            (integration_id, name),
        );

        Ok(integration_id)
    }

    /// Create webhook endpoint
    pub fn create_webhook(
        env: Env,
        owner: Address,
        name: String,
        endpoint_url: String,
        event_types: Vec<Symbol>,
        secret_token: BytesN<32>,
        max_attempts: u32,
        initial_delay: u64,
        backoff_multiplier: u32,
        max_delay: u64,
    ) -> Result<u64, ContractError> {
        owner.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let webhook_id = get_next_webhook_id(&env);

        let retry_config = RetryConfig {
            max_attempts,
            initial_delay,
            backoff_multiplier,
            max_delay,
        };

        let webhook = WebhookEndpoint {
            webhook_id,
            name: name.clone(),
            endpoint_url,
            event_types,
            secret_token,
            retry_config,
            rate_limit: None,
            is_active: true,
            owner: owner.clone(),
            created_at: env.ledger().timestamp(),
            last_triggered: None,
        };

        env.storage()
            .persistent()
            .set(&(WEBHOOK_ENDPOINT, webhook_id), &webhook);

        env.events().publish(
            (symbol_short!("webhook_created"), owner),
            (webhook_id, name),
        );

        Ok(webhook_id)
    }

    /// Create API key for external access
    pub fn create_api_key(
        env: Env,
        owner: Address,
        name: String,
        permissions: Vec<Symbol>,
        expires_in_days: Option<u32>,
        rate_limit: Option<RateLimit>,
    ) -> Result<u64, ContractError> {
        owner.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let key_id = get_next_integration_id(&env);
        let key_value = generate_api_key(&env);
        let expires_at = expires_in_days.map(|days| env.ledger().timestamp() + (days as u64 * 86400));

        let api_key = ApiKey {
            key_id,
            key_value: key_value.clone(),
            name: name.clone(),
            permissions,
            rate_limit,
            owner: owner.clone(),
            created_at: env.ledger().timestamp(),
            expires_at,
            last_used: None,
            is_active: true,
        };

        env.storage()
            .persistent()
            .set(&(API_KEY, key_id), &api_key);

        env.events().publish(
            (symbol_short!("api_key_created"), owner),
            (key_id, name),
        );

        Ok(key_id)
    }

    /// Export data to external system
    pub fn export_data(
        env: Env,
        requester: Address,
        name: String,
        export_type: Symbol,
        filters: Map<Symbol, String>,
        start_time: u64,
        end_time: u64,
        timezone: String,
        export_format: Symbol,
        compression_algorithm: Symbol,
        compression_level: u32,
    ) -> Result<u64, ContractError> {
        requester.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let export_id = get_next_integration_id(&env);

        let time_range = TimeRange {
            start_time,
            end_time,
            timezone,
        };

        let compression = CompressionSettings {
            algorithm: compression_algorithm,
            compression_level,
        };

        let export = DataExport {
            export_id,
            name: name.clone(),
            export_type,
            filters,
            time_range,
            export_format,
            compression,
            status: ExportStatus::Pending,
            file_location: None,
            requester: requester.clone(),
            created_at: env.ledger().timestamp(),
            completed_at: None,
        };

        env.storage()
            .persistent()
            .set(&(DATA_EXPORT, export_id), &export);

        // Start export process (in production, this would be async)
        Self::process_export(&env, export_id)?;

        env.events().publish(
            (symbol_short!("export_started"), requester),
            (export_id, name),
        );

        Ok(export_id)
    }

    /// Trigger webhook
    pub fn trigger_webhook(
        env: Env,
        webhook_id: u64,
        event_type: Symbol,
        payload: Map<Symbol, String>,
    ) -> Result<(), ContractError> {
        // This should be callable by internal contracts
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let webhook: WebhookEndpoint = env
            .storage()
            .persistent()
            .get(&(WEBHOOK_ENDPOINT, webhook_id))
            .ok_or(ContractError::NotFound)?;

        if !webhook.is_active {
            return Err(ContractError::InvalidState);
        }

        if !webhook.event_types.contains(&event_type) {
            return Err(ContractError::InvalidInput);
        }

        // Check rate limiting
        if let Some(rate_limit) = &webhook.rate_limit {
            if Self::check_rate_limit(&env, webhook_id, rate_limit)? {
                return Err(ContractError::RateLimited);
            }
        }

        // In production, actually send HTTP request to webhook endpoint
        // For now, simulate webhook trigger
        let mut updated_webhook = webhook;
        updated_webhook.last_triggered = Some(env.ledger().timestamp());

        env.storage()
            .persistent()
            .set(&(WEBHOOK_ENDPOINT, webhook_id), &updated_webhook);

        env.events().publish(
            (symbol_short!("webhook_triggered"), webhook_id),
            event_type,
        );

        Ok(())
    }

    /// Sync data with external integration
    pub fn sync_integration(
        env: Env,
        integration_id: u64,
    ) -> Result<(), ContractError> {
        // This should be callable by admin or scheduled jobs
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let integration: ExternalIntegration = env
            .storage()
            .persistent()
            .get(&(EXTERNAL_INTEGRATION, integration_id))
            .ok_or(ContractError::NotFound)?;

        if !integration.is_active {
            return Err(ContractError::InvalidState);
        }

        // Update sync status
        let sync_status = SyncStatus {
            integration_id,
            last_sync: env.ledger().timestamp(),
            status: SyncStatusType::InProgress,
            error_message: None,
            records_synced: 0,
            records_failed: 0,
            next_sync: env.ledger().timestamp() + integration.sync_frequency,
        };

        env.storage()
            .persistent()
            .set(&(SYNC_STATUS, integration_id), &sync_status);

        // In production, perform actual sync with external service
        // For now, simulate sync
        let mut updated_status = sync_status;
        updated_status.status = SyncStatusType::Success;
        updated_status.records_synced = 100; // Simulated

        env.storage()
            .persistent()
            .set(&(SYNC_STATUS, integration_id), &updated_status);

        env.events().publish(
            (symbol_short!("integration_synced"), integration_id),
            updated_status.records_synced,
        );

        Ok(())
    }

    /// Revoke API key
    pub fn revoke_api_key(
        env: Env,
        owner: Address,
        key_id: u64,
    ) -> Result<(), ContractError> {
        owner.require_auth();

        let mut api_key: ApiKey = env
            .storage()
            .persistent()
            .get(&(API_KEY, key_id))
            .ok_or(ContractError::NotFound)?;

        if api_key.owner != owner {
            return Err(ContractError::Unauthorized);
        }

        api_key.is_active = false;

        env.storage()
            .persistent()
            .set(&(API_KEY, key_id), &api_key);

        env.events().publish(
            (symbol_short!("api_key_revoked"), owner),
            key_id,
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

    /// Process data export
    fn process_export(env: &Env, export_id: u64) -> Result<(), ContractError> {
        // In production, this would be an async process
        // For now, simulate export completion
        let mut export: DataExport = env
            .storage()
            .persistent()
            .get(&(DATA_EXPORT, export_id))
            .ok_or(ContractError::NotFound)?;

        export.status = ExportStatus::Completed;
        export.completed_at = Some(env.ledger().timestamp());
        export.file_location = Some(String::from_str(env, "/exports/data.json"));

        env.storage()
            .persistent()
            .set(&(DATA_EXPORT, export_id), &export);

        Ok(())
    }

    /// Check rate limit for webhook
    fn check_rate_limit(
        env: &Env,
        webhook_id: u64,
        rate_limit: &RateLimit,
    ) -> Result<bool, ContractError> {
        let current_time = env.ledger().timestamp();
        
        // In production, implement proper rate limiting logic
        // For now, return false (not rate limited)
        Ok(false)
    }

    // ===== View Functions =====

    /// Get external integration
    pub fn get_integration(env: Env, integration_id: u64) -> Option<ExternalIntegration> {
        env.storage().persistent().get(&(EXTERNAL_INTEGRATION, integration_id))
    }

    /// Get webhook endpoint
    pub fn get_webhook(env: Env, webhook_id: u64) -> Option<WebhookEndpoint> {
        env.storage().persistent().get(&(WEBHOOK_ENDPOINT, webhook_id))
    }

    /// Get API key
    pub fn get_api_key(env: Env, key_id: u64) -> Option<ApiKey> {
        env.storage().persistent().get(&(API_KEY, key_id))
    }

    /// Get data export
    pub fn get_data_export(env: Env, export_id: u64) -> Option<DataExport> {
        env.storage().persistent().get(&(DATA_EXPORT, export_id))
    }

    /// Get sync status
    pub fn get_sync_status(env: Env, integration_id: u64) -> Option<SyncStatus> {
        env.storage().persistent().get(&(SYNC_STATUS, integration_id))
    }

    /// List integrations for owner
    pub fn list_integrations(env: Env, owner: Address) -> Vec<ExternalIntegration> {
        // In production, query integrations by owner
        // For now, return empty vector
        Vec::new(&env)
    }

    /// Get integration statistics
    pub fn get_integration_stats(env: Env) -> (u64, u64, u64, u64) {
        // Returns (total_integrations, active_integrations, successful_syncs, failed_syncs)
        // In production, calculate from actual data
        (0, 0, 0, 0)
    }
}
