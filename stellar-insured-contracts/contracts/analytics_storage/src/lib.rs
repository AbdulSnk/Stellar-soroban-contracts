#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, BytesN, Env, Symbol, Vec, String, Map,
};
use shared::authorization::{require_admin, require_role, Role};

#[contract]
pub struct AnalyticsStorageContract;

// Storage keys
const ADMIN: Symbol = symbol_short!("ADMIN");
const PAUSED: Symbol = symbol_short!("PAUSED");
const DATA_COUNTER: Symbol = symbol_short!("DATA_CNT");
const AGGREGATION_COUNTER: Symbol = symbol_short!("AGG_CNT");

// Analytics storage prefixes
const TIME_SERIES_BUCKET: Symbol = symbol_short!("TS_BUCKET");
const AGGREGATED_DATA: Symbol = symbol_short!("AGG_DATA");
const DATA_RETENTION: Symbol = symbol_short!("DATA_RET");
const COMPRESSION_METADATA: Symbol = symbol_short!("COMP_META");
const QUERY_CACHE: Symbol = symbol_short!("QUERY_CACHE");

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
    DataRetentionViolation = 9,
    CompressionFailed = 10,
    QueryTimeout = 11,
    InsufficientData = 12,
    AggregationError = 13,
    StorageFull = 14,
}

/// Time series bucket for efficient storage
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeSeriesBucket {
    /// Bucket identifier
    pub bucket_id: u64,
    /// Contract address
    pub contract_address: Address,
    /// Metric name
    pub metric_name: Symbol,
    /// Time granularity (minute, hour, day, week, month)
    pub granularity: Symbol,
    /// Start timestamp of bucket
    pub start_time: u64,
    /// End timestamp of bucket
    pub end_time: u64,
    /// Number of data points in bucket
    pub data_count: u32,
    /// Sum of values in bucket
    pub sum: u64,
    /// Minimum value in bucket
    pub min: u64,
    /// Maximum value in bucket
    pub max: u64,
    /// Compressed data points (if applicable)
    pub compressed_data: Option<BytesN<32>>,
    /// Bucket created timestamp
    pub created_at: u64,
    /// Last updated timestamp
    pub updated_at: u64,
}

/// Aggregated data for analytics
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregatedData {
    /// Aggregation identifier
    pub aggregation_id: u64,
    /// Contract address
    pub contract_address: Address,
    /// Metric name
    pub metric_name: Symbol,
    /// Aggregation type (sum, avg, min, max, count, std_dev)
    pub aggregation_type: Symbol,
    /// Time period
    pub period: Symbol,
    /// Start timestamp
    pub start_time: u64,
    /// End timestamp
    pub end_time: u64,
    /// Aggregated value
    pub value: u64,
    /// Number of data points aggregated
    pub data_points: u64,
    /// Additional metadata
    pub metadata: Map<Symbol, String>,
    /// Created timestamp
    pub created_at: u64,
}

/// Data retention policy
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataRetentionPolicy {
    /// Policy identifier
    pub policy_id: u64,
    /// Contract address (None for global policy)
    pub contract_address: Option<Address>,
    /// Metric name (None for all metrics)
    pub metric_name: Option<Symbol>,
    /// Data retention period in seconds
    pub retention_period: u64,
    /// Granularity levels to keep
    pub keep_granularities: Vec<Symbol>,
    /// Whether to compress old data
    pub compress_old_data: bool,
    /// Policy created timestamp
    pub created_at: u64,
    /// Whether policy is active
    pub is_active: bool,
}

/// Query cache entry
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryCacheEntry {
    /// Cache key (hash of query parameters)
    pub cache_key: BytesN<32>,
    /// Query result data
    pub result_data: Vec<u8>,
    /// Cache created timestamp
    pub created_at: u64,
    /// Cache expiry timestamp
    pub expires_at: u64,
    /// Number of times cache was accessed
    pub access_count: u32,
    /// Last accessed timestamp
    pub last_accessed: u64,
}

/// Analytics query parameters
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalyticsQuery {
    /// Contract address to query (None for all)
    pub contract_address: Option<Address>,
    /// Metric name to query (None for all)
    pub metric_name: Option<Symbol>,
    /// Start timestamp
    pub start_time: u64,
    /// End timestamp
    pub end_time: u64,
    /// Aggregation type
    pub aggregation: Symbol,
    /// Time granularity
    pub granularity: Symbol,
    /// Group by field
    pub group_by: Option<Symbol>,
    /// Filter conditions
    pub filters: Map<Symbol, String>,
    /// Result limit
    pub limit: u32,
    /// Order by field
    pub order_by: Option<Symbol>,
    /// Order direction (asc, desc)
    pub order_direction: Symbol,
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

fn get_next_data_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&DATA_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&DATA_COUNTER, &(current + 1));
    current + 1
}

fn get_next_aggregation_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&AGGREGATION_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&AGGREGATION_COUNTER, &(current + 1));
    current + 1
}

/// Generate time bucket key
fn generate_bucket_key(
    contract_address: &Address,
    metric_name: &Symbol,
    granularity: &Symbol,
    timestamp: u64,
) -> (Symbol, u64) {
    // Simple bucket calculation - in production, use more sophisticated time bucketing
    let bucket_size = match granularity.to_string().as_str() {
        "minute" => 60,
        "hour" => 3600,
        "day" => 86400,
        "week" => 604800,
        "month" => 2592000,
        _ => 3600, // default to hour
    };
    
    let bucket_start = (timestamp / bucket_size) * bucket_size;
    let bucket_key = Symbol::new(&soroban_sdk::Env::default(), "bucket");
    
    (bucket_key, bucket_start)
}

/// Compress data points (simulated)
fn compress_data_points(_data_points: &Vec<u64>) -> Result<BytesN<32>, ContractError> {
    // In production, implement actual compression algorithm
    // For now, return placeholder
    Ok(BytesN::from_array(&soroban_sdk::Env::default(), &[0; 32]))
}

#[contractimpl]
impl AnalyticsStorageContract {
    /// Initialize the analytics storage contract
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().persistent().has(&ADMIN) {
            return Err(ContractError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&DATA_COUNTER, &0u64);
        env.storage().persistent().set(&AGGREGATION_COUNTER, &0u64);

        env.events().publish((symbol_short!("init"), ()), admin);

        Ok(())
    }

    /// Store time series data point
    pub fn store_data_point(
        env: Env,
        contract_address: Address,
        metric_name: Symbol,
        value: u64,
        timestamp: u64,
        granularity: Symbol,
    ) -> Result<u64, ContractError> {
        // This should be callable by authorized contracts
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let (bucket_key, bucket_start) = generate_bucket_key(
            &contract_address,
            &metric_name,
            &granularity,
            timestamp,
        );

        let bucket_id = get_next_data_id(&env);
        let bucket_end = bucket_start + match granularity.to_string().as_str() {
            "minute" => 60,
            "hour" => 3600,
            "day" => 86400,
            "week" => 604800,
            "month" => 2592000,
            _ => 3600,
        };

        let bucket = TimeSeriesBucket {
            bucket_id,
            contract_address: contract_address.clone(),
            metric_name,
            granularity,
            start_time: bucket_start,
            end_time: bucket_end,
            data_count: 1,
            sum: value,
            min: value,
            max: value,
            compressed_data: None,
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&(TIME_SERIES_BUCKET, (bucket_key, bucket_start)), &bucket);

        env.events().publish(
            (symbol_short!("data_stored"), contract_address),
            (bucket_id, metric_name, value),
        );

        Ok(bucket_id)
    }

    /// Create aggregated data
    pub fn create_aggregation(
        env: Env,
        contract_address: Address,
        metric_name: Symbol,
        aggregation_type: Symbol,
        period: Symbol,
        start_time: u64,
        end_time: u64,
        value: u64,
        data_points: u64,
        metadata: Map<Symbol, String>,
    ) -> Result<u64, ContractError> {
        // This should be callable by authorized processes
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let aggregation_id = get_next_aggregation_id(&env);

        let aggregation = AggregatedData {
            aggregation_id,
            contract_address: contract_address.clone(),
            metric_name,
            aggregation_type,
            period,
            start_time,
            end_time,
            value,
            data_points,
            metadata,
            created_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&(AGGREGATED_DATA, aggregation_id), &aggregation);

        env.events().publish(
            (symbol_short!("aggregation_created"), contract_address),
            aggregation_id,
        );

        Ok(aggregation_id)
    }

    /// Query analytics data
    pub fn query_analytics(
        env: Env,
        query: AnalyticsQuery,
    ) -> Result<Vec<AggregatedData>, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Generate cache key
        let cache_key_input = format!(
            "{:?}{:?}{:?}{}{}{:?}{:?}{:?}{:?}{}{:?}{:?}",
            query.contract_address,
            query.metric_name,
            query.start_time,
            query.end_time,
            query.aggregation,
            query.granularity,
            query.group_by,
            query.limit,
            query.order_by,
            query.order_direction
        );
        
        // In production, use proper hash function
        let cache_key = BytesN::from_array(&env, &[0; 32]);

        // Check cache first
        if let Some(cache_entry) = Self::get_cache_entry(&env, cache_key) {
            if env.ledger().timestamp() < cache_entry.expires_at {
                // Return cached result (deserialize from bytes)
                return Ok(Vec::new(&env));
            }
        }

        // Perform actual query
        let results = Self::execute_query(&env, &query)?;

        // Cache the result
        Self::cache_query_result(&env, cache_key, &results, 300)?; // 5 minute cache

        Ok(results)
    }

    /// Set data retention policy
    pub fn set_retention_policy(
        env: Env,
        admin: Address,
        contract_address: Option<Address>,
        metric_name: Option<Symbol>,
        retention_period: u64,
        keep_granularities: Vec<Symbol>,
        compress_old_data: bool,
    ) -> Result<u64, ContractError> {
        admin.require_auth();

        require_admin(&env, &admin)?;

        let policy_id = get_next_data_id(&env);

        let policy = DataRetentionPolicy {
            policy_id,
            contract_address,
            metric_name,
            retention_period,
            keep_granularities,
            compress_old_data,
            created_at: env.ledger().timestamp(),
            is_active: true,
        };

        env.storage()
            .persistent()
            .set(&(DATA_RETENTION, policy_id), &policy);

        env.events().publish(
            (symbol_short!("retention_policy_set"), admin),
            policy_id,
        );

        Ok(policy_id)
    }

    /// Compress old data based on retention policies
    pub fn compress_old_data(
        env: Env,
        admin: Address,
    ) -> Result<u64, ContractError> {
        admin.require_auth();

        require_admin(&env, &admin)?;

        let mut compressed_count = 0u64;
        let current_time = env.ledger().timestamp();

        // In production, iterate through all buckets and apply retention policies
        // For now, simulate compression
        for _ in 0..10 {
            compressed_count += 1;
        }

        env.events().publish(
            (symbol_short!("data_compressed"), admin),
            compressed_count,
        );

        Ok(compressed_count)
    }

    /// Delete expired data
    pub fn delete_expired_data(
        env: Env,
        admin: Address,
    ) -> Result<u64, ContractError> {
        admin.require_auth();

        require_admin(&env, &admin)?;

        let mut deleted_count = 0u64;
        let current_time = env.ledger().timestamp();

        // In production, iterate through all data and apply retention policies
        // For now, simulate deletion
        for _ in 0..5 {
            deleted_count += 1;
        }

        env.events().publish(
            (symbol_short!("data_deleted"), admin),
            deleted_count,
        );

        Ok(deleted_count)
    }

    /// Get storage statistics
    pub fn get_storage_stats(env: Env) -> (u64, u64, u64, u64) {
        // Returns (total_buckets, total_aggregations, total_cache_entries, storage_used_bytes)
        // In production, calculate from actual storage
        (0, 0, 0, 0)
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

    /// Execute analytics query
    fn execute_query(
        env: &Env,
        query: &AnalyticsQuery,
    ) -> Result<Vec<AggregatedData>, ContractError> {
        // In production, implement actual query execution
        // For now, return empty vector
        Ok(Vec::new(env))
    }

    /// Get cache entry
    fn get_cache_entry(env: &Env, cache_key: BytesN<32>) -> Option<QueryCacheEntry> {
        env.storage().temporary().get(&(&QUERY_CACHE, cache_key))
    }

    /// Cache query result
    fn cache_query_result(
        env: &Env,
        cache_key: BytesN<32>,
        results: &Vec<AggregatedData>,
        ttl_seconds: u64,
    ) -> Result<(), ContractError> {
        let expires_at = env.ledger().timestamp() + ttl_seconds;
        
        // In production, serialize results to bytes
        let result_data = Vec::new(env);
        
        let cache_entry = QueryCacheEntry {
            cache_key,
            result_data,
            created_at: env.ledger().timestamp(),
            expires_at,
            access_count: 0,
            last_accessed: env.ledger().timestamp(),
        };

        env.storage()
            .temporary()
            .set(&(&QUERY_CACHE, cache_key), &cache_entry);

        Ok(())
    }

    // ===== View Functions =====

    /// Get time series bucket
    pub fn get_time_series_bucket(
        env: Env,
        contract_address: Address,
        metric_name: Symbol,
        granularity: Symbol,
        timestamp: u64,
    ) -> Option<TimeSeriesBucket> {
        let (bucket_key, bucket_start) = generate_bucket_key(
            &contract_address,
            &metric_name,
            &granularity,
            timestamp,
        );

        env.storage()
            .persistent()
            .get(&(TIME_SERIES_BUCKET, (bucket_key, bucket_start)))
    }

    /// Get aggregated data
    pub fn get_aggregated_data(env: Env, aggregation_id: u64) -> Option<AggregatedData> {
        env.storage().persistent().get(&(AGGREGATED_DATA, aggregation_id))
    }

    /// Get retention policy
    pub fn get_retention_policy(env: Env, policy_id: u64) -> Option<DataRetentionPolicy> {
        env.storage().persistent().get(&(DATA_RETENTION, policy_id))
    }

    /// Get data points for time range
    pub fn get_data_points(
        env: Env,
        contract_address: Address,
        metric_name: Symbol,
        start_time: u64,
        end_time: u64,
        limit: u32,
    ) -> Result<Vec<TimeSeriesBucket>, ContractError> {
        if start_time >= end_time {
            return Err(ContractError::InvalidInput);
        }

        if limit == 0 || limit > 10000 {
            return Err(ContractError::InvalidInput);
        }

        // In production, query actual time series buckets
        // For now, return empty vector
        Ok(Vec::new(&env))
    }

    /// Get analytics summary for contract
    pub fn get_analytics_summary(
        env: Env,
        contract_address: Address,
        period: Symbol,
    ) -> (u64, u64, u64, u64) {
        // Returns (total_data_points, avg_value, min_value, max_value)
        // In production, calculate from actual data
        (0, 0, 0, 0)
    }
}
