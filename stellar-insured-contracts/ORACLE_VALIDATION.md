# Oracle Validation System Documentation

## Overview

The Oracle Validation System is a fault-tolerant mechanism for protecting the Stellar Insured protocol from bad, delayed, or malicious oracle data. Instead of trusting a single oracle response, this system implements consensus-based validation and safety thresholds to ensure data integrity.

## Architecture

### Core Components

1. **OracleContract** - Main contract managing oracle submissions and validation
2. **ValidationThreshold** - Configuration for consensus parameters
3. **OracleSubmission** - Individual oracle data point
4. **OracleData** - Finalized consensus result
5. **Claims Integration** - Claims contract uses oracle validation for approval

## Key Features

### 1. Multiple Oracle Submissions

The system supports unlimited oracle data submissions for each data point, enabling consensus-based determination.

```rust
pub fn submit_oracle_data(
    env: Env,
    data_id: u64,
    value: i128,
) -> Result<bool, OracleError>
```

**Features:**
- Each oracle can submit once per data point (duplicate detection)
- Submissions tracked with timestamp for staleness checks
- Automatic consensus attempt on each submission

### 2. Consensus Validation

#### Majority Voting with Configurable Threshold
- Default: 66% agreement (2 out of 3 oracles)
- Configurable from 0-100%
- Ensures data integrity through collective agreement

#### Median-Based Consensus Value
- Uses statistical median for robustness
- Less susceptible to single outlier attacks
- Deterministic and reproducible

#### Weighted Average Support
- Alternative calculation method available
- Equal weighting by default
- Extensible for weighted oracle reputation

### 3. Outlier Detection

Automatic statistical detection and rejection of outlier values using deviation-based filtering.

```rust
fn detect_outliers(
    values: &Vec<i128>,
    deviation_percent: i128,
) -> Vec<bool>
```

**Mechanism:**
1. Calculate median of all submissions
2. Define acceptable deviation range (default: 15%)
3. Mark values outside range as outliers
4. Exclude outliers from consensus calculation

**Example:**
```
Submissions: [100, 102, 101, 500]
Median: 101.5
15% deviation: ±15.225
Outlier range: 86.275 - 116.725
Result: [100, 102, 101, 500(outlier)]
```

### 4. Staleness Detection

Prevents use of outdated oracle data that may no longer reflect reality.

```rust
fn is_data_stale(
    timestamp: u64,
    current_time: u64,
    staleness_threshold: u64,
) -> bool
```

**Configuration:**
- Default staleness threshold: 3600 seconds (1 hour)
- Configurable per use case
- Rejects data older than threshold
- Rejects future-dated submissions

**Safety Mechanism:**
```
Current Time: 10:00
Data Age: 45 minutes
Threshold: 1 hour
Status: FRESH ✓

Current Time: 11:05
Data Age: 1 hour 5 minutes
Threshold: 1 hour
Status: STALE ✗
```

### 5. Validation Thresholds

Configurable parameters that control consensus behavior:

```rust
pub struct ValidationThreshold {
    pub min_submissions: u32,                    // Minimum oracles required
    pub majority_threshold_percent: u32,         // Consensus % needed
    pub outlier_deviation_percent: i128,         // Deviation tolerance
    pub staleness_threshold_seconds: u64,        // Max data age
}
```

**Default Values:**
| Parameter | Default | Range |
|-----------|---------|-------|
| Min Submissions | 3 | 1+ |
| Majority Threshold | 66% | 0-100% |
| Outlier Deviation | 15% | 0+ |
| Staleness Threshold | 3600 sec | 0+ |

**Configuration:**
```rust
// Update thresholds
oracle_contract.set_thresholds(
    env,
    5,      // Require 5 oracle submissions
    75,     // 75% consensus needed
    10,     // 10% outlier deviation
    1800,   // 30 minutes max age
)?;
```

### 6. Deterministic Resolution Logic

Multi-stage resolution ensures consistent, predictable outcome:

```
Phase 1: Validate Minimum Submissions
    └─ Fail if fewer than min_submissions

Phase 2: Check Staleness
    └─ Fail if any submission exceeds staleness_threshold

Phase 3: Detect and Filter Outliers
    └─ Mark values outside deviation_percent as outliers

Phase 4: Verify Consensus
    └─ Calculate consensus_percentage = valid_submissions / total_submissions
    └─ Fail if < majority_threshold_percent

Phase 5: Calculate Consensus Value
    └─ Compute median of valid submissions
    └─ Return finalized OracleData
```

## Claims Integration

### Oracle-Validated Claim Approval

Claims contract can require oracle validation before approval:

```rust
pub fn approve_claim(
    env: Env,
    claim_id: u64,
    oracle_data_id: Option<u64>,
) -> Result<(), ContractError>
```

**Flow:**
1. Admin initiates claim approval
2. If oracle validation enabled, check oracle data ID
3. Verify oracle submissions meet thresholds
4. Link oracle data to claim for audit trail
5. Proceed with approval

**Configuration:**

```rust
// Set oracle validation config
claims_contract.set_oracle_config(
    env,
    oracle_contract_address,
    true,  // require_oracle_validation
    3,     // min_oracle_submissions
)?;
```

### Audit Trail

Every approved claim maintains link to oracle data used:

```rust
// Retrieve oracle data for claim
let oracle_data_id = claims_contract.get_claim_oracle_data(env, claim_id)?;
let oracle_data = oracle_contract.get_oracle_data(env, oracle_data_id)?;

// Verify consensus details
println!("Consensus value: {}", oracle_data.consensus_value);
println!("Agreement: {}%", oracle_data.consensus_percentage);
println!("Accepted: {}/{} submissions", 
    oracle_data.included_submissions, 
    oracle_data.submission_count);
```

## Test Coverage

### Test Scenarios

1. **Oracle Disagreement**
   - Multiple oracles submit different values
   - System calculates median correctly
   - Consensus is reached when values cluster

2. **Outlier Rejection**
   - One outlier among valid submissions
   - Outlier detected and excluded
   - Consensus determined from valid data

3. **Insufficient Submissions**
   - Fewer submissions than minimum required
   - Consensus rejected with appropriate error
   - System waits for additional submissions

4. **Stale Data Rejection**
   - Data exceeds staleness threshold
   - Entire resolution fails (safety-first)
   - Fresh data required for approval

5. **Duplicate Submission Prevention**
   - Same oracle attempts multiple submissions
   - Second submission rejected
   - Maintains one-oracle-one-vote model

6. **Consensus Threshold Enforcement**
   - High threshold requires broad agreement
   - Tight agreement fails if threshold too high
   - System respects configured threshold

7. **Independent Data Points**
   - Multiple simultaneous oracle data points
   - Each resolves independently
   - No cross-contamination

8. **Pause Functionality**
   - Admin can pause contract during attacks
   - No new submissions accepted when paused
   - Resume normal operation when safe

## Security Considerations

### Attack Vectors Mitigated

| Attack | Mitigation |
|--------|-----------|
| Single Oracle Corruption | Multiple submissions required |
| Malicious Value Injection | Outlier detection filters extremes |
| Stale Data Attack | Staleness checks reject old data |
| Consensus Bypass | Configurable thresholds enforce agreement |
| Repeated False Submissions | Duplicate detection per oracle |
| System Manipulation | Deterministic calculation logic |

### Deployment Best Practices

1. **Conservative Thresholds Initially**
   ```rust
   min_submissions: 5,           // 5+ trusted oracles
   majority_threshold: 80,       // 80% agreement required
   outlier_deviation: 5,         // 5% tolerance only
   staleness_threshold: 1800,    // 30 minutes max age
   ```

2. **Monitor Oracle Health**
   - Track submission counts
   - Monitor rejection rates
   - Alert on consensus failures

3. **Gradual Parameter Adjustment**
   - Start conservative, adjust based on data
   - Increase outlier tolerance if frequent rejections
   - Decrease if attackers detected

4. **Fallback Strategy**
   - Implement claims holding during disputes
   - Use multiple oracle sources
   - Maintain human override capability

## API Reference

### OracleContract Functions

#### Initialization
```rust
pub fn initialize(env: Env, admin: Address) -> Result<(), OracleError>
```

#### Configuration
```rust
pub fn set_thresholds(
    env: Env,
    min_submissions: u32,
    majority_threshold_percent: u32,
    outlier_deviation_percent: i128,
    staleness_threshold_seconds: u64,
) -> Result<(), OracleError>

pub fn get_thresholds(env: Env) -> Result<ValidationThreshold, OracleError>

pub fn set_paused(env: Env, paused: bool) -> Result<(), OracleError>
```

#### Oracle Operations
```rust
pub fn submit_oracle_data(
    env: Env,
    data_id: u64,
    value: i128,
) -> Result<bool, OracleError>

pub fn resolve_oracle_data(
    env: Env,
    data_id: u64,
) -> Result<OracleData, OracleError>

pub fn get_oracle_data(env: Env, data_id: u64) -> Result<OracleData, OracleError>

pub fn get_pending_submissions(
    env: Env,
    data_id: u64,
) -> Result<Vec<OracleSubmission>, OracleError>

pub fn get_submission_count(env: Env, data_id: u64) -> Result<u32, OracleError>
```

## Example Usage

### Setup Phase

```rust
// Initialize oracle contract
let oracle_contract = OracleContract {};
oracle_contract.initialize(env.clone(), admin.clone())?;

// Configure thresholds
oracle_contract.set_thresholds(
    env.clone(),
    3,      // min 3 oracles
    66,     // 66% consensus
    15,     // 15% outlier tolerance
    3600,   // 1 hour staleness
)?;

// Configure claims to use oracle
claims_contract.set_oracle_config(
    env.clone(),
    oracle_contract_address,
    true,
    3,
)?;
```

### Oracle Submission Phase

```rust
// Oracle 1 submits price data
oracle_contract.submit_oracle_data(env.clone(), claim_1, 1000)?;

// Oracle 2 submits price data
oracle_contract.submit_oracle_data(env.clone(), claim_1, 1010)?;

// Oracle 3 submits price data
oracle_contract.submit_oracle_data(env.clone(), claim_1, 995)?;
```

### Claim Approval Phase

```rust
// Admin approves claim with oracle validation
claims_contract.approve_claim(
    env.clone(),
    claim_id,
    Some(oracle_data_id),  // Reference oracle data
)?;

// System automatically:
// 1. Verifies oracle consensus
// 2. Checks staleness
// 3. Validates outliers
// 4. Links data to claim
```

### Audit Phase

```rust
// Retrieve oracle data for claim
let oracle_id = claims_contract.get_claim_oracle_data(env, claim_id)?;
let oracle_data = oracle_contract.get_oracle_data(env, oracle_id)?;

println!("Consensus Value: {}", oracle_data.consensus_value);
println!("Agreement: {}%", oracle_data.consensus_percentage);
println!("Submissions Used: {}/{}", 
    oracle_data.included_submissions,
    oracle_data.submission_count);
```

## Error Handling

| Error | Cause | Resolution |
|-------|-------|-----------|
| `InsufficientSubmissions` | Fewer than min_submissions | Wait for more oracles |
| `StaleData` | Data age exceeds threshold | Require fresh submissions |
| `OutlierDetected` | Value outside deviation range | Removed from consensus |
| `ConsensusNotReached` | Agreement below threshold | May retry with relaxed threshold |
| `DuplicateSubmission` | Oracle submitted twice | Each oracle limited to one |
| `InvalidThreshold` | Threshold > 100% or invalid | Adjust configuration |
| `Unauthorized` | Non-admin action | Use authorized account |
| `Paused` | Contract paused during emergency | Admin must unpause |

## Future Enhancements

1. **Weighted Oracle Reputation**
   - Track oracle accuracy history
   - Weight submissions by reputation score
   - Penalize consistently wrong oracles

2. **Dynamic Threshold Adjustment**
   - Auto-adjust thresholds based on disagreement rate
   - Relax during low-confidence periods
   - Tighten during attacks

3. **Multi-Stage Consensus**
   - Preliminary consensus with loose thresholds
   - Final consensus with strict thresholds
   - Staged approval process

4. **Oracle Performance Metrics**
   - Track submission latency
   - Monitor accuracy rates
   - Dashboard for oracle health

5. **Advanced Outlier Detection**
   - Interquartile range (IQR) method
   - Standard deviation-based detection
   - Machine learning anomaly detection

## Conclusion

The Oracle Validation System provides a robust, configurable framework for protecting the Stellar Insured protocol from oracle-based attacks and failures. Through consensus-based validation, outlier detection, and staleness checks, the system ensures only high-quality, trustworthy data is used for critical decisions like claim approval.
