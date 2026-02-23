#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, BytesN, Env, Symbol, Vec, String,
};
use shared::{
    IdentityVerification, KycRecord, ZkIdentityProof, ZkProof, ZkVerificationResult,
    authorization::{require_admin, require_role, Role},
};

#[contract]
pub struct IdentityVerificationContract;

// Storage keys
const ADMIN: Symbol = symbol_short!("ADMIN");
const PAUSED: Symbol = symbol_short!("PAUSED");
const VERIFICATION_COUNTER: Symbol = symbol_short!("VER_CNT");
const ATTESTATION_COUNTER: Symbol = symbol_short!("ATT_CNT");
const CIRCUIT_REGISTRY: Symbol = symbol_short!("CIR_REG");

// Verification-specific storage prefixes
const VERIFICATION_REQUEST: Symbol = symbol_short!("VER_REQ");
const ATTESTATION: Symbol = symbol_short!("ATTEST");
const VERIFIER_REGISTRY: Symbol = symbol_short!("VER_REG");
const CIRCUIT_VERIFICATION_KEY: Symbol = symbol_short!("CIR_VK");
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
    VerificationExpired = 9,
    ProofInvalid = 10,
    CircuitNotRegistered = 11,
    VerifierNotAuthorized = 12,
    InsufficientAttestations = 13,
    AttestationRevoked = 14,
    IdentityNotVerified = 15,
    KycLevelInsufficient = 16,
    RiskScoreTooHigh = 17,
}

/// Verification request for identity verification
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationRequest {
    pub request_id: u64,
    pub did: String,
    pub requester: Address,
    pub verification_type: Symbol,
    pub required_level: u32,
    pub requested_attributes: Vec<String>,
    pub expires_at: u64,
    pub created_at: u64,
    pub status: Symbol, // "pending", "approved", "rejected", "expired"
    pub approver: Option<Address>,
    pub approved_at: Option<u64>,
}

/// Attestation from a verifier
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attestation {
    pub attestation_id: u64,
    pub verification_request_id: u64,
    pub verifier: Address,
    pub did: String,
    pub attestation_type: Symbol,
    pub verified_attributes: Vec<String>,
    pub confidence_score: u32, // 1-100
    pub proof_hash: BytesN<32>,
    pub expires_at: u64,
    pub created_at: u64,
    pub is_revoked: bool,
}

/// Circuit verification key registration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitVerificationKey {
    pub circuit_id: Symbol,
    pub verification_key_hash: BytesN<32>,
    pub verifier: Address,
    pub registered_at: u64,
    pub is_active: bool,
}

/// Verifier registration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierRegistration {
    pub verifier: Address,
    pub verifier_type: Symbol, // "individual", "institutional", "automated"
    pub verification_types: Vec<Symbol>, // Types of verification they can perform
    pub max_level: u32, // Maximum verification level they can grant
    pub jurisdiction: String,
    pub registered_at: u64,
    pub is_active: bool,
    pub reputation_score: u32, // 1-100
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

fn get_next_verification_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&VERIFICATION_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&VERIFICATION_COUNTER, &(current + 1));
    current + 1
}

fn get_next_attestation_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&ATTESTATION_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&ATTESTATION_COUNTER, &(current + 1));
    current + 1
}

/// Verify a zero-knowledge proof with enhanced validation
fn verify_zk_proof_enhanced(
    env: &Env,
    proof: &ZkIdentityProof,
    circuit_vk: &CircuitVerificationKey,
) -> Result<ZkVerificationResult, ContractError> {
    // Check if proof has expired
    if env.ledger().timestamp() > proof.expires_at {
        return Ok(ZkVerificationResult::Expired);
    }

    // Check if proof is revoked
    if proof.is_revoked {
        return Ok(ZkVerificationResult::Invalid);
    }

    // Verify circuit matches registered verification key
    if proof.circuit_id != circuit_vk.circuit_id {
        return Err(ContractError::CircuitNotRegistered);
    }

    if proof.verification_key_hash != circuit_vk.verification_key_hash {
        return Err(ContractError::CircuitNotRegistered);
    }

    // Check if circuit is active
    if !circuit_vk.is_active {
        return Err(ContractError::CircuitNotRegistered);
    }

    // In a real implementation, this would perform actual cryptographic verification
    // For now, we simulate verification based on structure validity
    if proof.proof_data.is_empty() || proof.public_inputs.is_empty() {
        return Ok(ZkVerificationResult::Invalid);
    }

    Ok(ZkVerificationResult::Valid)
}

#[contractimpl]
impl IdentityVerificationContract {
    /// Initialize the identity verification contract
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().persistent().has(&ADMIN) {
            return Err(ContractError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&VERIFICATION_COUNTER, &0u64);
        env.storage().persistent().set(&ATTESTATION_COUNTER, &0u64);

        env.events().publish((symbol_short!("init"), ()), admin);

        Ok(())
    }

    /// Register a verifier
    pub fn register_verifier(
        env: Env,
        admin: Address,
        verifier: Address,
        verifier_type: Symbol,
        verification_types: Vec<Symbol>,
        max_level: u32,
        jurisdiction: String,
    ) -> Result<(), ContractError> {
        admin.require_auth();

        require_admin(&env, &admin)?;

        if max_level == 0 || max_level > 5 {
            return Err(ContractError::InvalidInput);
        }

        let registration = VerifierRegistration {
            verifier: verifier.clone(),
            verifier_type,
            verification_types,
            max_level,
            jurisdiction,
            registered_at: env.ledger().timestamp(),
            is_active: true,
            reputation_score: 50, // Start with neutral reputation
        };

        env.storage()
            .persistent()
            .set(&(VERIFIER_REGISTRY, verifier.clone()), &registration);

        env.events().publish((symbol_short!("verifier_registered"), verifier), ());

        Ok(())
    }

    /// Register a circuit verification key
    pub fn register_circuit_vk(
        env: Env,
        verifier: Address,
        circuit_id: Symbol,
        verification_key_hash: BytesN<32>,
    ) -> Result<(), ContractError> {
        verifier.require_auth();

        // Check if verifier is authorized
        let registration: VerifierRegistration = env
            .storage()
            .persistent()
            .get(&(VERIFIER_REGISTRY, verifier.clone()))
            .ok_or(ContractError::VerifierNotAuthorized)?;

        if !registration.is_active {
            return Err(ContractError::VerifierNotAuthorized);
        }

        let circuit_vk = CircuitVerificationKey {
            circuit_id,
            verification_key_hash,
            verifier: verifier.clone(),
            registered_at: env.ledger().timestamp(),
            is_active: true,
        };

        env.storage()
            .persistent()
            .set(&(CIRCUIT_VERIFICATION_KEY, circuit_id), &circuit_vk);

        env.events().publish(
            (symbol_short!("circuit_vk_registered"), verifier),
            circuit_id,
        );

        Ok(())
    }

    /// Submit a verification request
    pub fn submit_verification_request(
        env: Env,
        requester: Address,
        did: String,
        verification_type: Symbol,
        required_level: u32,
        requested_attributes: Vec<String>,
        expires_in_days: u32,
    ) -> Result<u64, ContractError> {
        requester.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        if required_level == 0 || required_level > 5 {
            return Err(ContractError::InvalidInput);
        }

        if expires_in_days == 0 || expires_in_days > 365 {
            return Err(ContractError::InvalidInput);
        }

        let request_id = get_next_verification_id(&env);
        let expires_at = env.ledger().timestamp() + (expires_in_days as u64 * 86400);

        let request = VerificationRequest {
            request_id,
            did: did.clone(),
            requester: requester.clone(),
            verification_type,
            required_level,
            requested_attributes: requested_attributes.clone(),
            expires_at,
            created_at: env.ledger().timestamp(),
            status: Symbol::new(&env, "pending"),
            approver: None,
            approved_at: None,
        };

        env.storage()
            .persistent()
            .set(&(VERIFICATION_REQUEST, request_id), &request);

        env.events().publish(
            (symbol_short!("verification_requested"), did.clone()),
            (request_id, verification_type, required_level),
        );

        Ok(request_id)
    }

    /// Create attestation for a verification request
    pub fn create_attestation(
        env: Env,
        verifier: Address,
        verification_request_id: u64,
        attestation_type: Symbol,
        verified_attributes: Vec<String>,
        confidence_score: u32,
        proof_hash: BytesN<32>,
        expires_in_days: u32,
    ) -> Result<u64, ContractError> {
        verifier.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Check if verifier is authorized
        let registration: VerifierRegistration = env
            .storage()
            .persistent()
            .get(&(VERIFIER_REGISTRY, verifier.clone()))
            .ok_or(ContractError::VerifierNotAuthorized)?;

        if !registration.is_active {
            return Err(ContractError::VerifierNotAuthorized);
        }

        if confidence_score == 0 || confidence_score > 100 {
            return Err(ContractError::InvalidInput);
        }

        // Get the verification request
        let request: VerificationRequest = env
            .storage()
            .persistent()
            .get(&(VERIFICATION_REQUEST, verification_request_id))
            .ok_or(ContractError::NotFound)?;

        if env.ledger().timestamp() > request.expires_at {
            return Err(ContractError::VerificationExpired);
        }

        let attestation_id = get_next_attestation_id(&env);
        let expires_at = env.ledger().timestamp() + (expires_in_days as u64 * 86400);

        let attestation = Attestation {
            attestation_id,
            verification_request_id,
            verifier: verifier.clone(),
            did: request.did.clone(),
            attestation_type,
            verified_attributes: verified_attributes.clone(),
            confidence_score,
            proof_hash,
            expires_at,
            created_at: env.ledger().timestamp(),
            is_revoked: false,
        };

        env.storage()
            .persistent()
            .set(&(ATTESTATION, attestation_id), &attestation);

        env.events().publish(
            (symbol_short!("attestation_created"), request.did.clone()),
            (attestation_id, attestation_type, confidence_score),
        );

        Ok(attestation_id)
    }

    /// Submit zero-knowledge identity proof for verification
    pub fn submit_zk_identity_proof(
        env: Env,
        submitter: Address,
        did: String,
        circuit_id: Symbol,
        public_inputs: Vec<String>,
        proof_data: BytesN<32>,
        expires_in_days: u32,
    ) -> Result<BytesN<32>, ContractError> {
        submitter.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Get circuit verification key
        let circuit_vk: CircuitVerificationKey = env
            .storage()
            .persistent()
            .get(&(CIRCUIT_VERIFICATION_KEY, circuit_id))
            .ok_or(ContractError::CircuitNotRegistered)?;

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
            verification_key_hash: circuit_vk.verification_key_hash,
            created_at: env.ledger().timestamp(),
            expires_at,
            is_revoked: false,
        };

        // Verify the proof
        let verification_result = verify_zk_proof_enhanced(&env, &zk_proof, &circuit_vk)?;
        
        if verification_result != ZkVerificationResult::Valid {
            return Err(ContractError::ProofInvalid);
        }

        env.storage()
            .persistent()
            .set(&(ZK_IDENTITY_PROOF, proof_id.clone()), &zk_proof);

        env.events().publish(
            (symbol_short!("zk_proof_verified"), did.clone()),
            proof_id,
        );

        Ok(proof_id)
    }

    /// Verify identity meets requirements
    pub fn verify_identity_requirements(
        env: Env,
        did: String,
        required_verification_type: Symbol,
        required_level: u32,
        required_attributes: Vec<String>,
        max_risk_score: u32,
    ) -> Result<bool, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Check for valid attestations
        let attestations = Self::get_valid_attestations(env.clone(), did.clone());
        
        for attestation in attestations.iter() {
            if attestation.attestation_type == required_verification_type 
                && attestation.confidence_score >= (required_level * 20) // Convert level to confidence score
                && !attestation.is_revoked
                && env.ledger().timestamp() <= attestation.expires_at {
                
                // Check if all required attributes are verified
                let mut all_attributes_verified = true;
                for required_attr in required_attributes.iter() {
                    if !attestation.verified_attributes.contains(required_attr) {
                        all_attributes_verified = false;
                        break;
                    }
                }
                
                if all_attributes_verified {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Revoke attestation
    pub fn revoke_attestation(
        env: Env,
        verifier: Address,
        attestation_id: u64,
    ) -> Result<(), ContractError> {
        verifier.require_auth();

        let mut attestation: Attestation = env
            .storage()
            .persistent()
            .get(&(ATTESTATION, attestation_id))
            .ok_or(ContractError::NotFound)?;

        if attestation.verifier != verifier {
            return Err(ContractError::Unauthorized);
        }

        attestation.is_revoked = true;
        env.storage()
            .persistent()
            .set(&(ATTESTATION, attestation_id), &attestation);

        env.events().publish(
            (symbol_short!("attestation_revoked"), attestation.did),
            attestation_id,
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

    /// Get verification request
    pub fn get_verification_request(env: Env, request_id: u64) -> Option<VerificationRequest> {
        env.storage().persistent().get(&(VERIFICATION_REQUEST, request_id))
    }

    /// Get attestation
    pub fn get_attestation(env: Env, attestation_id: u64) -> Option<Attestation> {
        env.storage().persistent().get(&(ATTESTATION, attestation_id))
    }

    /// Get verifier registration
    pub fn get_verifier_registration(env: Env, verifier: Address) -> Option<VerifierRegistration> {
        env.storage().persistent().get(&(VERIFIER_REGISTRY, verifier))
    }

    /// Get circuit verification key
    pub fn get_circuit_verification_key(env: Env, circuit_id: Symbol) -> Option<CircuitVerificationKey> {
        env.storage().persistent().get(&(CIRCUIT_VERIFICATION_KEY, circuit_id))
    }

    /// Get valid attestations for a DID
    pub fn get_valid_attestations(env: Env, did: String) -> Vec<Attestation> {
        // In production, maintain an index for efficient querying
        // For now, return empty vector
        Vec::new(&env)
    }

    /// Check if verifier is authorized for verification type
    pub fn is_verifier_authorized(
        env: Env,
        verifier: Address,
        verification_type: Symbol,
    ) -> bool {
        if let Some(registration) = Self::get_verifier_registration(env, verifier) {
            registration.is_active 
                && registration.verification_types.contains(&verification_type)
        } else {
            false
        }
    }

    /// Get verification statistics
    pub fn get_verification_stats(env: Env, verifier: Address) -> (u32, u32, u32) {
        // Returns (total_attestations, active_attestations, revoked_attestations)
        // In production, calculate from actual data
        (0, 0, 0)
    }
}
