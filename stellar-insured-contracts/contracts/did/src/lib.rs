#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, BytesN, Env, Symbol, Vec, String,
};
use shared::{
    DidDocument, VerificationMethod, PublicKeyJwk, DidService, ServiceProperty,
    IdentityVerification, KycRecord, ZkIdentityProof, DidResolutionResult,
    MetadataProperty, authorization::{require_admin, require_role, Role},
};

#[contract]
pub struct DidContract;

// Storage keys
const ADMIN: Symbol = symbol_short!("ADMIN");
const PAUSED: Symbol = symbol_short!("PAUSED");
const DID_COUNTER: Symbol = symbol_short!("DID_CNT");
const VERIFICATION_COUNTER: Symbol = symbol_short!("VER_CNT");
const KYC_COUNTER: Symbol = symbol_short!("KYC_CNT");

// DID-specific storage prefixes
const DID_DOCUMENT: Symbol = symbol_short!("DID_DOC");
const DID_CONTROLLER: Symbol = symbol_short!("DID_CTRL");
const VERIFICATION_METHOD: Symbol = symbol_short!("VER_METH");
const DID_SERVICE: Symbol = symbol_short!("DID_SVC");
const IDENTITY_VERIFICATION: Symbol = symbol_short!("ID_VER");
const KYC_RECORD: Symbol = symbol_short!("KYC_REC");
const ZK_IDENTITY_PROOF: Symbol = symbol_short!("ZK_ID");

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
    DidInvalid = 9,
    VerificationFailed = 10,
    Expired = 11,
    NotCompliant = 12,
    InsufficientProof = 13,
    InvalidProof = 14,
    KycRequired = 15,
    IdentityAlreadyVerified = 16,
    ServiceNotFound = 17,
    ControllerNotFound = 18,
    MethodNotFound = 19,
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

fn get_next_did_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&DID_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&DID_COUNTER, &(current + 1));
    current + 1
}

fn get_next_verification_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&VERIFICATION_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&VERIFICATION_COUNTER, &(current + 1));
    current + 1
}

fn get_next_kyc_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&KYC_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&KYC_COUNTER, &(current + 1));
    current + 1
}

/// Validate DID format (basic validation for did:stellar:method)
fn validate_did_format(did: &String) -> Result<(), ContractError> {
    if did.len() < 10 || !did.starts_with("did:") {
        return Err(ContractError::DidInvalid);
    }
    
    // Simple validation - in production, use more sophisticated DID parsing
    Ok(())
}

/// Generate a Stellar-based DID
fn generate_stellar_did(env: &Env, address: &Address) -> String {
    let did_id = get_next_did_id(env);
    let address_str = address.to_string();
    String::from_str(env, &format!("did:stellar:{}", address_str))
}

#[contractimpl]
impl DidContract {
    /// Initialize the DID contract
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().persistent().has(&ADMIN) {
            return Err(ContractError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&DID_COUNTER, &0u64);
        env.storage().persistent().set(&VERIFICATION_COUNTER, &0u64);
        env.storage().persistent().set(&KYC_COUNTER, &0u64);

        env.events().publish((symbol_short!("init"), ()), admin);

        Ok(())
    }

    /// Create a new DID document
    pub fn create_did(
        env: Env,
        owner: Address,
        public_key: String,
        key_type: String,
        service_endpoints: Vec<DidService>,
    ) -> Result<String, ContractError> {
        owner.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let did = generate_stellar_did(&env, &owner);
        validate_did_format(&did)?;

        let keys_1_id = String::from_str(&env, &format!("{}#keys-1", did));
        let verification_method = VerificationMethod {
            id: keys_1_id.clone(),
            type_: String::from_str(&env, &key_type),
            controller: did.clone(),
            public_key_base58: Some(String::from_str(&env, &public_key)),
            public_key_jwk: None,
        };

        let did_document = DidDocument {
            id: did.clone(),
            controller: Vec::from_array(&env, [did.clone()]),
            verification_method: Vec::from_array(&env, [verification_method]),
            authentication: Vec::from_array(&env, [keys_1_id]),
            assertion_method: Vec::new(&env),
            key_agreement: Vec::new(&env),
            capability_invocation: Vec::new(&env),
            capability_delegation: Vec::new(&env),
            service: service_endpoints,
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
            version_id: 1,
        };

        env.storage()
            .persistent()
            .set(&(DID_DOCUMENT, did.clone()), &did_document);

        env.events().publish((symbol_short!("did_created"), owner), did.clone());

        Ok(did)
    }

    /// Update DID document
    pub fn update_did(
        env: Env,
        owner: Address,
        did: String,
        new_services: Vec<DidService>,
        new_verification_methods: Vec<VerificationMethod>,
    ) -> Result<(), ContractError> {
        owner.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_did_format(&did)?;

        let mut doc: DidDocument = env
            .storage()
            .persistent()
            .get(&(DID_DOCUMENT, did.clone()))
            .ok_or(ContractError::NotFound)?;

        // Verify ownership
        let owner_did = generate_stellar_did(&env, &owner);
        if doc.id != owner_did && !doc.controller.contains(&owner_did) {
            return Err(ContractError::Unauthorized);
        }

        // Update document
        doc.service = new_services;
        doc.verification_method.extend(new_verification_methods);
        doc.updated_at = env.ledger().timestamp();
        doc.version_id += 1;

        env.storage()
            .persistent()
            .set(&(DID_DOCUMENT, did.clone()), &doc);

        env.events().publish((symbol_short!("did_updated"), owner), did);

        Ok(())
    }

    /// Add controller to DID document
    pub fn add_controller(
        env: Env,
        owner: Address,
        did: String,
        controller_did: String,
    ) -> Result<(), ContractError> {
        owner.require_auth();

        validate_did_format(&did)?;
        validate_did_format(&controller_did)?;

        let mut doc: DidDocument = env
            .storage()
            .persistent()
            .get(&(DID_DOCUMENT, did.clone()))
            .ok_or(ContractError::NotFound)?;

        let owner_did = generate_stellar_did(&env, &owner);
        if doc.id != owner_did && !doc.controller.contains(&owner_did) {
            return Err(ContractError::Unauthorized);
        }

        if !doc.controller.contains(&controller_did) {
            doc.controller.push(controller_did.clone());
            doc.updated_at = env.ledger().timestamp();
            doc.version_id += 1;

            env.storage()
                .persistent()
                .set(&(DID_DOCUMENT, did.clone()), &doc);

            env.events().publish(
                (symbol_short!("controller_added"), did.clone()),
                controller_did,
            );
        }

        Ok(())
    }

    /// Verify identity with privacy-preserving proofs
    pub fn verify_identity(
        env: Env,
        verifier: Address,
        did: String,
        verification_type: Symbol,
        verification_level: u32,
        verified_attributes: Vec<String>,
        proof_hash: BytesN<32>,
        expires_in_days: u32,
    ) -> Result<u64, ContractError> {
        verifier.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_did_format(&did)?;

        if verification_level == 0 || verification_level > 5 {
            return Err(ContractError::InvalidInput);
        }

        // Check if DID exists
        let _doc: DidDocument = env
            .storage()
            .persistent()
            .get(&(DID_DOCUMENT, did.clone()))
            .ok_or(ContractError::NotFound)?;

        let verification_id = get_next_verification_id(&env);
        let expires_at = env.ledger().timestamp() + (expires_in_days as u64 * 86400);

        let verification = IdentityVerification {
            verification_id,
            did: did.clone(),
            verifier: verifier.clone(),
            verification_type,
            verification_level,
            verified_attributes: verified_attributes.clone(),
            expires_at,
            verified_at: env.ledger().timestamp(),
            proof_hash,
            is_revoked: false,
        };

        env.storage()
            .persistent()
            .set(&(IDENTITY_VERIFICATION, verification_id), &verification);

        env.events().publish(
            (symbol_short!("identity_verified"), did.clone()),
            (verification_id, verification_type, verification_level),
        );

        Ok(verification_id)
    }

    /// Create KYC record for regulatory compliance
    pub fn create_kyc_record(
        env: Env,
        kyc_provider: Address,
        did: String,
        kyc_level: u32,
        risk_score: u32,
        jurisdiction: String,
        compliance_data_hash: BytesN<32>,
        expires_in_days: u32,
        aml_screening_passed: bool,
    ) -> Result<u64, ContractError> {
        kyc_provider.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_did_format(&did)?;

        if kyc_level == 0 || kyc_level > 4 {
            return Err(ContractError::InvalidInput);
        }

        if risk_score > 100 {
            return Err(ContractError::InvalidInput);
        }

        // Check if KYC provider is authorized
        require_admin(&env, &kyc_provider)?;

        let kyc_id = get_next_kyc_id(&env);
        let expires_at = env.ledger().timestamp() + (expires_in_days as u64 * 86400);

        let kyc_record = KycRecord {
            kyc_id,
            did: did.clone(),
            kyc_provider: kyc_provider.clone(),
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

        env.events().publish(
            (symbol_short!("kyc_created"), did.clone()),
            (kyc_id, kyc_level, risk_score),
        );

        Ok(kyc_id)
    }

    /// Submit zero-knowledge identity proof
    pub fn submit_zk_identity_proof(
        env: Env,
        submitter: Address,
        did: String,
        circuit_id: Symbol,
        public_inputs: Vec<String>,
        proof_data: BytesN<32>,
        verification_key_hash: BytesN<32>,
        expires_in_days: u32,
    ) -> Result<BytesN<32>, ContractError> {
        submitter.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_did_format(&did)?;

        // Check if DID exists
        let _doc: DidDocument = env
            .storage()
            .persistent()
            .get(&(DID_DOCUMENT, did.clone()))
            .ok_or(ContractError::NotFound)?;

        let proof_id = BytesN::from_array(&env, &[
            (env.ledger().timestamp() >> 24) as u8,
            (env.ledger().timestamp() >> 16) as u8,
            (env.ledger().timestamp() >> 8) as u8,
            env.ledger().timestamp() as u8,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let expires_at = env.ledger().timestamp() + (expires_in_days as u64 * 86400);

        let zk_proof = ZkIdentityProof {
            proof_id: proof_id.clone(),
            did: did.clone(),
            circuit_id,
            public_inputs: public_inputs.clone(),
            proof_data,
            verification_key_hash,
            created_at: env.ledger().timestamp(),
            expires_at,
            is_revoked: false,
        };

        env.storage()
            .persistent()
            .set(&(ZK_IDENTITY_PROOF, proof_id.clone()), &zk_proof);

        env.events().publish(
            (symbol_short!("zk_proof_submitted"), did.clone()),
            proof_id,
        );

        Ok(proof_id)
    }

    /// Verify zero-knowledge identity proof
    pub fn verify_zk_proof(
        env: Env,
        verifier: Address,
        proof_id: BytesN<32>,
    ) -> Result<bool, ContractError> {
        verifier.require_auth();

        let zk_proof: ZkIdentityProof = env
            .storage()
            .persistent()
            .get(&(ZK_IDENTITY_PROOF, proof_id))
            .ok_or(ContractError::NotFound)?;

        if zk_proof.is_revoked {
            return Ok(false);
        }

        if env.ledger().timestamp() > zk_proof.expires_at {
            return Ok(false);
        }

        // In a real implementation, this would perform actual ZK proof verification
        // For now, we simulate verification success
        let is_valid = !zk_proof.proof_data.is_empty() && !zk_proof.public_inputs.is_empty();

        env.events().publish(
            (symbol_short!("zk_proof_verified"), proof_id),
            is_valid,
        );

        Ok(is_valid)
    }

    /// Revoke identity verification
    pub fn revoke_verification(
        env: Env,
        verifier: Address,
        verification_id: u64,
    ) -> Result<(), ContractError> {
        verifier.require_auth();

        let mut verification: IdentityVerification = env
            .storage()
            .persistent()
            .get(&(IDENTITY_VERIFICATION, verification_id))
            .ok_or(ContractError::NotFound)?;

        if verification.verifier != verifier {
            return Err(ContractError::Unauthorized);
        }

        verification.is_revoked = true;
        env.storage()
            .persistent()
            .set(&(IDENTITY_VERIFICATION, verification_id), &verification);

        env.events().publish(
            (symbol_short!("verification_revoked"), verification.did),
            verification_id,
        );

        Ok(())
    }

    /// Deactivate KYC record
    pub fn deactivate_kyc(
        env: Env,
        kyc_provider: Address,
        kyc_id: u64,
    ) -> Result<(), ContractError> {
        kyc_provider.require_auth();

        let mut kyc_record: KycRecord = env
            .storage()
            .persistent()
            .get(&(KYC_RECORD, kyc_id))
            .ok_or(ContractError::NotFound)?;

        if kyc_record.kyc_provider != kyc_provider {
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

    /// Resolve DID document
    pub fn resolve_did(env: Env, did: String) -> Result<DidResolutionResult, ContractError> {
        validate_did_format(&did)?;

        let did_document: DidDocument = env
            .storage()
            .persistent()
            .get(&(DID_DOCUMENT, did.clone()))
            .ok_or(ContractError::NotFound)?;

        let resolver_metadata = Vec::new(&env);
        let method_metadata = Vec::new(&env);

        Ok(DidResolutionResult {
            did_document,
            resolver_metadata,
            method_metadata,
        })
    }

    /// Get identity verification
    pub fn get_identity_verification(env: Env, verification_id: u64) -> Option<IdentityVerification> {
        env.storage().persistent().get(&(IDENTITY_VERIFICATION, verification_id))
    }

    /// Get KYC record
    pub fn get_kyc_record(env: Env, kyc_id: u64) -> Option<KycRecord> {
        env.storage().persistent().get(&(KYC_RECORD, kyc_id))
    }

    /// Get ZK identity proof
    pub fn get_zk_identity_proof(env: Env, proof_id: BytesN<32>) -> Option<ZkIdentityProof> {
        env.storage().persistent().get(&(ZK_IDENTITY_PROOF, proof_id))
    }

    /// Check if DID exists
    pub fn did_exists(env: Env, did: String) -> Result<bool, ContractError> {
        validate_did_format(&did)?;
        Ok(env.storage().persistent().has(&(DID_DOCUMENT, did)))
    }

    /// Get active KYC records for a DID
    pub fn get_active_kyc_records(env: Env, did: String) -> Vec<KycRecord> {
        // In production, maintain an index for efficient querying
        // For now, return empty vector
        Vec::new(&env)
    }

    /// Get valid identity verifications for a DID
    pub fn get_valid_verifications(env: Env, did: String) -> Vec<IdentityVerification> {
        // In production, maintain an index for efficient querying
        // For now, return empty vector
        Vec::new(&env)
    }

    /// Check if DID meets minimum KYC requirements
    pub fn meets_kyc_requirements(
        env: Env,
        did: String,
        required_kyc_level: u32,
        max_risk_score: u32,
    ) -> Result<bool, ContractError> {
        validate_did_format(&did)?;

        let kyc_records = Self::get_active_kyc_records(env, did.clone());
        
        for record in kyc_records.iter() {
            if record.kyc_level >= required_kyc_level && record.risk_score <= max_risk_score {
                if env.ledger().timestamp() <= record.expires_at {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests;
