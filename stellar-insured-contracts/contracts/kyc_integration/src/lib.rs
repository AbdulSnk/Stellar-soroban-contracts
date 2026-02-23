#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, BytesN, Env, Symbol, Vec, String,
};
use shared::{
    KycRecord, IdentityVerification, authorization::{require_admin, require_role, Role},
};

#[contract]
pub struct KycIntegrationContract;

// Storage keys
const ADMIN: Symbol = symbol_short!("ADMIN");
const PAUSED: Symbol = symbol_short!("PAUSED");
const KYC_COUNTER: Symbol = symbol_short!("KYC_CNT");
const PROVIDER_REGISTRY: Symbol = symbol_short!("PROV_REG");
const JURISDICTION_CONFIG: Symbol = symbol_short!("JUR_CFG");

// KYC-specific storage prefixes
const KYC_RECORD: Symbol = symbol_short!("KYC_REC");
const PROVIDER_KYC_MAPPING: Symbol = symbol_short!("PROV_KYC");
const DID_KYC_MAPPING: Symbol = symbol_short!("DID_KYC");
const AML_SCREENING: Symbol = symbol_short!("AML_SCR");

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
    KycExpired = 9,
    ProviderNotAuthorized = 10,
    JurisdictionNotSupported = 11,
    RiskScoreTooHigh = 12,
    KycLevelInsufficient = 13,
    AmlScreeningFailed = 14,
    DuplicateKyc = 15,
    InvalidJurisdiction = 16,
    ProviderNotActive = 17,
}

/// KYC provider registration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KycProvider {
    pub provider_address: Address,
    pub provider_name: String,
    pub provider_type: Symbol, // "financial_institution", "digital_identity", "government"
    pub supported_jurisdictions: Vec<String>,
    pub max_kyc_level: u32,
    pub registration_date: u64,
    pub is_active: bool,
    pub compliance_score: u32, // 1-100
    pub aml_capabilities: bool,
}

/// Jurisdiction configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JurisdictionConfig {
    pub jurisdiction_code: String,
    pub min_kyc_level: u32,
    pub max_risk_score: u32,
    pub aml_required: bool,
    pub data_retention_days: u32,
    pub supported_providers: Vec<Address>,
    pub is_active: bool,
}

/// AML screening result
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmlScreeningResult {
    pub screening_id: u64,
    pub did: String,
    pub provider: Address,
    pub screening_date: u64,
    pub risk_score: u32,
    pub flags: Vec<String>, // e.g., ["sanction_list", "pep", "adverse_media"]
    pub is_passed: bool,
    pub review_required: bool,
    pub next_screening_date: u64,
}

/// KYC requirements for different use cases
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KycRequirements {
    pub use_case: Symbol, // "insurance", "defi", "payments", "investments"
    pub min_kyc_level: u32,
    pub max_risk_score: u32,
    pub required_jurisdictions: Vec<String>,
    pub aml_required: bool,
    pub identity_verification_required: bool,
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

fn get_next_kyc_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&KYC_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&KYC_COUNTER, &(current + 1));
    current + 1
}

fn get_next_screening_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&KYC_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&KYC_COUNTER, &(current + 1));
    current + 1
}

/// Validate jurisdiction code format
fn validate_jurisdiction(jurisdiction: &String) -> Result<(), ContractError> {
    if jurisdiction.len() != 2 {
        return Err(ContractError::InvalidJurisdiction);
    }
    Ok(())
}

#[contractimpl]
impl KycIntegrationContract {
    /// Initialize the KYC integration contract
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().persistent().has(&ADMIN) {
            return Err(ContractError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&KYC_COUNTER, &0u64);

        env.events().publish((symbol_short!("init"), ()), admin);

        Ok(())
    }

    /// Register a KYC provider
    pub fn register_kyc_provider(
        env: Env,
        admin: Address,
        provider_address: Address,
        provider_name: String,
        provider_type: Symbol,
        supported_jurisdictions: Vec<String>,
        max_kyc_level: u32,
        aml_capabilities: bool,
    ) -> Result<(), ContractError> {
        admin.require_auth();

        require_admin(&env, &admin)?;

        if max_kyc_level == 0 || max_kyc_level > 4 {
            return Err(ContractError::InvalidInput);
        }

        // Validate jurisdictions
        for jurisdiction in supported_jurisdictions.iter() {
            validate_jurisdiction(jurisdiction)?;
        }

        let provider = KycProvider {
            provider_address: provider_address.clone(),
            provider_name,
            provider_type,
            supported_jurisdictions,
            max_kyc_level,
            registration_date: env.ledger().timestamp(),
            is_active: true,
            compliance_score: 75, // Start with good compliance score
            aml_capabilities,
        };

        env.storage()
            .persistent()
            .set(&(PROVIDER_REGISTRY, provider_address.clone()), &provider);

        env.events().publish(
            (symbol_short!("provider_registered"), provider_address),
            (),
        );

        Ok(())
    }

    /// Configure jurisdiction requirements
    pub fn configure_jurisdiction(
        env: Env,
        admin: Address,
        jurisdiction_code: String,
        min_kyc_level: u32,
        max_risk_score: u32,
        aml_required: bool,
        data_retention_days: u32,
        supported_providers: Vec<Address>,
    ) -> Result<(), ContractError> {
        admin.require_auth();

        require_admin(&env, &admin)?;

        validate_jurisdiction(&jurisdiction_code)?;

        if min_kyc_level == 0 || min_kyc_level > 4 {
            return Err(ContractError::InvalidInput);
        }

        if max_risk_score > 100 {
            return Err(ContractError::InvalidInput);
        }

        let config = JurisdictionConfig {
            jurisdiction_code: jurisdiction_code.clone(),
            min_kyc_level,
            max_risk_score,
            aml_required,
            data_retention_days,
            supported_providers,
            is_active: true,
        };

        env.storage()
            .persistent()
            .set(&(JURISDICTION_CONFIG, jurisdiction_code.clone()), &config);

        env.events().publish(
            (symbol_short!("jurisdiction_configured"), jurisdiction_code),
            (min_kyc_level, max_risk_score),
        );

        Ok(())
    }

    /// Create KYC record for a DID
    pub fn create_kyc_record(
        env: Env,
        provider: Address,
        did: String,
        kyc_level: u32,
        risk_score: u32,
        jurisdiction: String,
        compliance_data_hash: BytesN<32>,
        expires_in_days: u32,
        aml_screening_passed: bool,
    ) -> Result<u64, ContractError> {
        provider.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Validate provider
        let provider_info: KycProvider = env
            .storage()
            .persistent()
            .get(&(PROVIDER_REGISTRY, provider.clone()))
            .ok_or(ContractError::ProviderNotAuthorized)?;

        if !provider_info.is_active {
            return Err(ContractError::ProviderNotActive);
        }

        if kyc_level > provider_info.max_kyc_level {
            return Err(ContractError::KycLevelInsufficient);
        }

        if !provider_info.supported_jurisdictions.contains(&jurisdiction) {
            return Err(ContractError::JurisdictionNotSupported);
        }

        // Validate jurisdiction config
        let jurisdiction_config: JurisdictionConfig = env
            .storage()
            .persistent()
            .get(&(JURISDICTION_CONFIG, jurisdiction.clone()))
            .ok_or(ContractError::JurisdictionNotSupported)?;

        if !jurisdiction_config.is_active {
            return Err(ContractError::JurisdictionNotSupported);
        }

        if kyc_level < jurisdiction_config.min_kyc_level {
            return Err(ContractError::KycLevelInsufficient);
        }

        if risk_score > jurisdiction_config.max_risk_score {
            return Err(ContractError::RiskScoreTooHigh);
        }

        if jurisdiction_config.aml_required && !aml_screening_passed {
            return Err(ContractError::AmlScreeningFailed);
        }

        // Check for existing KYC record
        if let Some(existing_kyc) = Self::get_active_kyc_for_did(env.clone(), did.clone()) {
            if existing_kyc.kyc_level >= kyc_level {
                return Err(ContractError::DuplicateKyc);
            }
        }

        let kyc_id = get_next_kyc_id(&env);
        let expires_at = env.ledger().timestamp() + (expires_in_days as u64 * 86400);

        let kyc_record = KycRecord {
            kyc_id,
            did: did.clone(),
            kyc_provider: provider.clone(),
            kyc_level,
            risk_score,
            jurisdiction,
            verified_at: env.ledger().timestamp(),
            expires_at,
            compliance_data_hash,
            is_active: true,
            aml_screening_passed,
        };

        env.storage()
            .persistent()
            .set(&(KYC_RECORD, kyc_id), &kyc_record);

        // Update mappings
        env.storage()
            .persistent()
            .set(&(PROVIDER_KYC_MAPPING, (provider.clone(), kyc_id)), &did);
        env.storage()
            .persistent()
            .set(&(DID_KYC_MAPPING, did.clone()), &kyc_id);

        env.events().publish(
            (symbol_short!("kyc_created"), did.clone()),
            (kyc_id, kyc_level, risk_score),
        );

        Ok(kyc_id)
    }

    /// Submit AML screening
    pub fn submit_aml_screening(
        env: Env,
        provider: Address,
        did: String,
        risk_score: u32,
        flags: Vec<String>,
        is_passed: bool,
        review_required: bool,
        next_screening_days: u32,
    ) -> Result<u64, ContractError> {
        provider.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Validate provider
        let provider_info: KycProvider = env
            .storage()
            .persistent()
            .get(&(PROVIDER_REGISTRY, provider.clone()))
            .ok_or(ContractError::ProviderNotAuthorized)?;

        if !provider_info.aml_capabilities {
            return Err(ContractError::AmlScreeningFailed);
        }

        let screening_id = get_next_screening_id(&env);
        let next_screening_date = env.ledger().timestamp() + (next_screening_days as u64 * 86400);

        let screening_result = AmlScreeningResult {
            screening_id,
            did: did.clone(),
            provider: provider.clone(),
            screening_date: env.ledger().timestamp(),
            risk_score,
            flags: flags.clone(),
            is_passed,
            review_required,
            next_screening_date,
        };

        env.storage()
            .persistent()
            .set(&(AML_SCREENING, screening_id), &screening_result);

        env.events().publish(
            (symbol_short!("aml_screening"), did.clone()),
            (screening_id, risk_score, is_passed),
        );

        Ok(screening_id)
    }

    /// Check if DID meets KYC requirements for use case
    pub fn check_kyc_requirements(
        env: Env,
        did: String,
        use_case: Symbol,
        jurisdiction: String,
    ) -> Result<bool, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Get active KYC record for DID
        let kyc_record = Self::get_active_kyc_for_did(env.clone(), did.clone())
            .ok_or(ContractError::KycLevelInsufficient)?;

        // Check if KYC is still valid
        if env.ledger().timestamp() > kyc_record.expires_at {
            return Err(ContractError::KycExpired);
        }

        // Check jurisdiction match
        if kyc_record.jurisdiction != jurisdiction {
            return Err(ContractError::JurisdictionNotSupported);
        }

        // Get use case requirements (simplified - in production, use predefined requirements)
        let min_kyc_level = match use_case.to_string().as_str() {
            "insurance" => 2,
            "defi" => 1,
            "payments" => 2,
            "investments" => 3,
            _ => 2,
        };

        if kyc_record.kyc_level < min_kyc_level {
            return Err(ContractError::KycLevelInsufficient);
        }

        // Check risk score (simplified threshold)
        let max_risk_score = 50;
        if kyc_record.risk_score > max_risk_score {
            return Err(ContractError::RiskScoreTooHigh);
        }

        Ok(true)
    }

    /// Deactivate KYC record
    pub fn deactivate_kyc(
        env: Env,
        provider: Address,
        kyc_id: u64,
    ) -> Result<(), ContractError> {
        provider.require_auth();

        let mut kyc_record: KycRecord = env
            .storage()
            .persistent()
            .get(&(KYC_RECORD, kyc_id))
            .ok_or(ContractError::NotFound)?;

        if kyc_record.kyc_provider != provider {
            return Err(ContractError::Unauthorized);
        }

        kyc_record.is_active = false;
        env.storage()
            .persistent()
            .set(&(KYC_RECORD, kyc_id), &kyc_record);

        env.events().publish(
            (symbol_short!("kyc_deactivated"), kyc_record.did),
            kyc_id,
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

    // ===== View Functions =====

    /// Get KYC record
    pub fn get_kyc_record(env: Env, kyc_id: u64) -> Option<KycRecord> {
        env.storage().persistent().get(&(KYC_RECORD, kyc_id))
    }

    /// Get KYC provider
    pub fn get_kyc_provider(env: Env, provider_address: Address) -> Option<KycProvider> {
        env.storage().persistent().get(&(PROVIDER_REGISTRY, provider_address))
    }

    /// Get jurisdiction config
    pub fn get_jurisdiction_config(env: Env, jurisdiction_code: String) -> Option<JurisdictionConfig> {
        env.storage().persistent().get(&(JURISDICTION_CONFIG, jurisdiction_code))
    }

    /// Get AML screening result
    pub fn get_aml_screening(env: Env, screening_id: u64) -> Option<AmlScreeningResult> {
        env.storage().persistent().get(&(AML_SCREENING, screening_id))
    }

    /// Get active KYC for DID
    pub fn get_active_kyc_for_did(env: Env, did: String) -> Option<KycRecord> {
        if let Some(kyc_id) = env.storage().persistent().get(&(DID_KYC_MAPPING, did)) {
            if let Some(kyc_record) = env.storage().persistent().get(&(KYC_RECORD, kyc_id)) {
                if kyc_record.is_active && env.ledger().timestamp() <= kyc_record.expires_at {
                    return Some(kyc_record);
                }
            }
        }
        None
    }

    /// Get all KYC records for provider
    pub fn get_provider_kyc_records(env: Env, provider: Address) -> Vec<KycRecord> {
        // In production, maintain an index for efficient querying
        // For now, return empty vector
        Vec::new(&env)
    }

    /// Check if provider is authorized for jurisdiction
    pub fn is_provider_authorized_for_jurisdiction(
        env: Env,
        provider: Address,
        jurisdiction: String,
    ) -> bool {
        if let Some(provider_info) = Self::get_kyc_provider(env, provider) {
            provider_info.is_active && provider_info.supported_jurisdictions.contains(&jurisdiction)
        } else {
            false
        }
    }

    /// Get KYC statistics
    pub fn get_kyc_stats(env: Env, provider: Address) -> (u32, u32, u32) {
        // Returns (total_kyc_records, active_kyc_records, expired_kyc_records)
        // In production, calculate from actual data
        (0, 0, 0)
    }
}
