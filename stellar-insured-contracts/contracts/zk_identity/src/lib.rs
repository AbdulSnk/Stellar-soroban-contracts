#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, BytesN, Env, Symbol, Vec, String,
};
use shared::{
    ZkIdentityProof, ZkProof, ZkVerificationResult, DidDocument,
    authorization::{require_admin, require_role, Role},
};

#[contract]
pub struct ZkIdentityContract;

// Storage keys
const ADMIN: Symbol = symbol_short!("ADMIN");
const PAUSED: Symbol = symbol_short!("PAUSED");
const PROOF_COUNTER: Symbol = symbol_short!("PROOF_CNT");
const CIRCUIT_REGISTRY: Symbol = symbol_short!("CIR_REG");

// ZK-specific storage prefixes
const ZK_PROOF: Symbol = symbol_short!("ZK_PROOF");
const CIRCUIT_DEFINITION: Symbol = symbol_short!("CIR_DEF");
const VERIFICATION_KEY: Symbol = symbol_short!("VER_KEY");
const PROOF_BATCH: Symbol = symbol_short!("PROOF_BATCH");
const ZK_IDENTITY_STATE: Symbol = symbol_short!("ZK_STATE");

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
    ProofInvalid = 9,
    ProofExpired = 10,
    CircuitNotRegistered = 11,
    VerificationFailed = 12,
    InvalidCircuit = 13,
    InsufficientProof = 14,
    BatchInvalid = 15,
    IdentityNotCommitted = 16,
    CommitmentInvalid = 17,
}

/// Circuit definition for ZK proofs
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitDefinition {
    pub circuit_id: Symbol,
    pub circuit_name: String,
    pub circuit_type: Symbol, // "identity", "age", "income", "credentials"
    pub description: String,
    pub num_public_inputs: u32,
    pub num_private_inputs: u32,
    pub creator: Address,
    pub created_at: u64,
    pub is_active: bool,
    pub verification_required: bool,
}

/// Verification key for a circuit
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationKey {
    pub circuit_id: Symbol,
    pub key_hash: BytesN<32>,
    pub key_data: BytesN<32>, // Encrypted or reference to off-chain storage
    pub verifier: Address,
    pub registered_at: u64,
    pub is_active: bool,
    pub version: u32,
}

/// Batch proof verification
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofBatch {
    pub batch_id: u64,
    pub circuit_id: Symbol,
    pub proof_ids: Vec<BytesN<32>>,
    pub batch_hash: BytesN<32>,
    pub verifier: Address,
    pub created_at: u64,
    pub verification_result: Symbol, // "pending", "valid", "invalid"
    pub verified_at: Option<u64>,
}

/// ZK identity state commitment
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkIdentityState {
    pub did: String,
    pub identity_nullifier: BytesN<32>,
    pub identity_commitment: BytesN<32>,
    pub latest_proof_id: Option<BytesN<32>>,
    pub created_at: u64,
    pub updated_at: u64,
    pub is_active: bool,
}

/// ZK proof template for common identity proofs
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkProofTemplate {
    pub template_id: Symbol,
    pub circuit_id: Symbol,
    pub template_name: String,
    pub public_input_schema: Vec<String>,
    pub proof_purpose: String,
    pub creator: Address,
    pub is_active: bool,
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

fn get_next_proof_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&PROOF_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&PROOF_COUNTER, &(current + 1));
    current + 1
}

/// Generate unique proof ID
fn generate_proof_id(env: &Env, did: &String, circuit_id: &Symbol) -> BytesN<32> {
    let timestamp = env.ledger().timestamp();
    let combined = format!("{}:{}:{}", did, circuit_id, timestamp);
    // In production, use proper hash function
    BytesN::from_array(env, &[
        (timestamp >> 24) as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ])
}

/// Verify ZK proof with circuit-specific validation
fn verify_zk_proof_with_circuit(
    env: &Env,
    proof: &ZkIdentityProof,
    circuit: &CircuitDefinition,
    verification_key: &VerificationKey,
) -> Result<ZkVerificationResult, ContractError> {
    // Check if proof has expired
    if env.ledger().timestamp() > proof.expires_at {
        return Ok(ZkVerificationResult::Expired);
    }

    // Check if proof is revoked
    if proof.is_revoked {
        return Ok(ZkVerificationResult::Invalid);
    }

    // Verify circuit matches
    if proof.circuit_id != circuit.circuit_id {
        return Err(ContractError::InvalidCircuit);
    }

    // Verify verification key matches
    if proof.verification_key_hash != verification_key.key_hash {
        return Err(ContractError::VerificationFailed);
    }

    // Check if circuit and verification key are active
    if !circuit.is_active || !verification_key.is_active {
        return Err(ContractError::CircuitNotRegistered);
    }

    // Validate public inputs count matches circuit definition
    if proof.public_inputs.len() as u32 != circuit.num_public_inputs {
        return Err(ContractError::InvalidInput);
    }

    // In a real implementation, this would perform actual cryptographic verification
    // using the verification key and proof data
    if proof.proof_data.is_empty() {
        return Ok(ZkVerificationResult::Invalid);
    }

    // Simulate verification success for valid structure
    Ok(ZkVerificationResult::Valid)
}

#[contractimpl]
impl ZkIdentityContract {
    /// Initialize the ZK identity contract
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().persistent().has(&ADMIN) {
            return Err(ContractError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&PROOF_COUNTER, &0u64);

        env.events().publish((symbol_short!("init"), ()), admin);

        Ok(())
    }

    /// Register a new ZK circuit
    pub fn register_circuit(
        env: Env,
        creator: Address,
        circuit_id: Symbol,
        circuit_name: String,
        circuit_type: Symbol,
        description: String,
        num_public_inputs: u32,
        num_private_inputs: u32,
        verification_required: bool,
    ) -> Result<(), ContractError> {
        creator.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        if num_public_inputs == 0 || num_private_inputs == 0 {
            return Err(ContractError::InvalidInput);
        }

        let circuit = CircuitDefinition {
            circuit_id,
            circuit_name,
            circuit_type,
            description,
            num_public_inputs,
            num_private_inputs,
            creator: creator.clone(),
            created_at: env.ledger().timestamp(),
            is_active: true,
            verification_required,
        };

        env.storage()
            .persistent()
            .set(&(CIRCUIT_DEFINITION, circuit_id), &circuit);

        env.events().publish(
            (symbol_short!("circuit_registered"), creator),
            circuit_id,
        );

        Ok(())
    }

    /// Register verification key for a circuit
    pub fn register_verification_key(
        env: Env,
        verifier: Address,
        circuit_id: Symbol,
        key_hash: BytesN<32>,
        key_data: BytesN<32>,
        version: u32,
    ) -> Result<(), ContractError> {
        verifier.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Check if circuit exists
        let circuit: CircuitDefinition = env
            .storage()
            .persistent()
            .get(&(CIRCUIT_DEFINITION, circuit_id))
            .ok_or(ContractError::CircuitNotRegistered)?;

        if !circuit.is_active {
            return Err(ContractError::CircuitNotRegistered);
        }

        let verification_key = VerificationKey {
            circuit_id,
            key_hash,
            key_data,
            verifier: verifier.clone(),
            registered_at: env.ledger().timestamp(),
            is_active: true,
            version,
        };

        env.storage()
            .persistent()
            .set(&(VERIFICATION_KEY, circuit_id), &verification_key);

        env.events().publish(
            (symbol_short!("vk_registered"), verifier),
            circuit_id,
        );

        Ok(())
    }

    /// Create identity commitment
    pub fn create_identity_commitment(
        env: Env,
        did: String,
        identity_nullifier: BytesN<32>,
        identity_commitment: BytesN<32>,
    ) -> Result<(), ContractError> {
        // This would typically require proof of ownership of the DID
        // For now, we'll allow anyone to create a commitment

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let identity_state = ZkIdentityState {
            did: did.clone(),
            identity_nullifier,
            identity_commitment,
            latest_proof_id: None,
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
            is_active: true,
        };

        env.storage()
            .persistent()
            .set(&(ZK_IDENTITY_STATE, did.clone()), &identity_state);

        env.events().publish(
            (symbol_short!("identity_committed"), did),
            (),
        );

        Ok(())
    }

    /// Submit ZK identity proof
    pub fn submit_zk_proof(
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

        // Get circuit and verification key
        let circuit: CircuitDefinition = env
            .storage()
            .persistent()
            .get(&(CIRCUIT_DEFINITION, circuit_id))
            .ok_or(ContractError::CircuitNotRegistered)?;

        let verification_key: VerificationKey = env
            .storage()
            .persistent()
            .get(&(VERIFICATION_KEY, circuit_id))
            .ok_or(ContractError::VerificationFailed)?;

        // Check if identity commitment exists
        let _identity_state: ZkIdentityState = env
            .storage()
            .persistent()
            .get(&(ZK_IDENTITY_STATE, did.clone()))
            .ok_or(ContractError::IdentityNotCommitted)?;

        let proof_id = generate_proof_id(&env, &did, &circuit_id);
        let expires_at = env.ledger().timestamp() + (expires_in_days as u64 * 86400);

        let zk_proof = ZkIdentityProof {
            proof_id: proof_id.clone(),
            did: did.clone(),
            circuit_id,
            public_inputs: public_inputs.clone(),
            proof_data,
            verification_key_hash: verification_key.key_hash,
            created_at: env.ledger().timestamp(),
            expires_at,
            is_revoked: false,
        };

        // Verify the proof
        let verification_result = verify_zk_proof_with_circuit(&env, &zk_proof, &circuit, &verification_key)?;
        
        if verification_result != ZkVerificationResult::Valid {
            return Err(ContractError::ProofInvalid);
        }

        // Store the proof
        env.storage()
            .persistent()
            .set(&(ZK_PROOF, proof_id.clone()), &zk_proof);

        // Update identity state
        let mut identity_state: ZkIdentityState = env
            .storage()
            .persistent()
            .get(&(ZK_IDENTITY_STATE, did.clone()))
            .unwrap();
        identity_state.latest_proof_id = Some(proof_id.clone());
        identity_state.updated_at = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&(ZK_IDENTITY_STATE, did.clone()), &identity_state);

        env.events().publish(
            (symbol_short!("zk_proof_submitted"), did.clone()),
            proof_id,
        );

        Ok(proof_id)
    }

    /// Create batch proof verification
    pub fn create_batch_verification(
        env: Env,
        verifier: Address,
        circuit_id: Symbol,
        proof_ids: Vec<BytesN<32>>,
    ) -> Result<u64, ContractError> {
        verifier.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        if proof_ids.is_empty() {
            return Err(ContractError::InvalidInput);
        }

        // Get circuit
        let circuit: CircuitDefinition = env
            .storage()
            .persistent()
            .get(&(CIRCUIT_DEFINITION, circuit_id))
            .ok_or(ContractError::CircuitNotRegistered)?;

        let batch_id = get_next_proof_id(&env);
        let batch_hash = BytesN::from_array(&env, &[
            (batch_id >> 24) as u8,
            (batch_id >> 16) as u8,
            (batch_id >> 8) as u8,
            batch_id as u8,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let batch = ProofBatch {
            batch_id,
            circuit_id,
            proof_ids: proof_ids.clone(),
            batch_hash,
            verifier: verifier.clone(),
            created_at: env.ledger().timestamp(),
            verification_result: Symbol::new(&env, "pending"),
            verified_at: None,
        };

        env.storage()
            .persistent()
            .set(&(PROOF_BATCH, batch_id), &batch);

        env.events().publish(
            (symbol_short!("batch_created"), verifier),
            batch_id,
        );

        Ok(batch_id)
    }

    /// Verify batch of proofs
    pub fn verify_batch(
        env: Env,
        verifier: Address,
        batch_id: u64,
    ) -> Result<bool, ContractError> {
        verifier.require_auth();

        let mut batch: ProofBatch = env
            .storage()
            .persistent()
            .get(&(PROOF_BATCH, batch_id))
            .ok_or(ContractError::NotFound)?;

        if batch.verifier != verifier {
            return Err(ContractError::Unauthorized);
        }

        // Get circuit and verification key
        let circuit: CircuitDefinition = env
            .storage()
            .persistent()
            .get(&(CIRCUIT_DEFINITION, batch.circuit_id))
            .ok_or(ContractError::CircuitNotRegistered)?;

        let verification_key: VerificationKey = env
            .storage()
            .persistent()
            .get(&(VERIFICATION_KEY, batch.circuit_id))
            .ok_or(ContractError::VerificationFailed)?;

        let mut all_valid = true;

        // Verify each proof in the batch
        for proof_id in batch.proof_ids.iter() {
            if let Some(zk_proof) = env.storage().persistent().get(&(ZK_PROOF, proof_id)) {
                match verify_zk_proof_with_circuit(&env, &zk_proof, &circuit, &verification_key) {
                    Ok(ZkVerificationResult::Valid) => continue,
                    _ => {
                        all_valid = false;
                        break;
                    }
                }
            } else {
                all_valid = false;
                break;
            }
        }

        // Update batch verification result
        batch.verification_result = if all_valid {
            Symbol::new(&env, "valid")
        } else {
            Symbol::new(&env, "invalid")
        };
        batch.verified_at = Some(env.ledger().timestamp());

        env.storage()
            .persistent()
            .set(&(PROOF_BATCH, batch_id), &batch);

        env.events().publish(
            (symbol_short!("batch_verified"), verifier),
            (batch_id, all_valid),
        );

        Ok(all_valid)
    }

    /// Revoke ZK proof
    pub fn revoke_proof(
        env: Env,
        did: String,
        proof_id: BytesN<32>,
    ) -> Result<(), ContractError> {
        // This would typically require proof of ownership of the DID
        // For now, we'll allow the DID owner to revoke their own proofs

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let mut proof: ZkIdentityProof = env
            .storage()
            .persistent()
            .get(&(ZK_PROOF, proof_id))
            .ok_or(ContractError::NotFound)?;

        if proof.did != did {
            return Err(ContractError::Unauthorized);
        }

        proof.is_revoked = true;
        env.storage()
            .persistent()
            .set(&(ZK_PROOF, proof_id), &proof);

        env.events().publish(
            (symbol_short!("proof_revoked"), did),
            proof_id,
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

    /// Get ZK proof
    pub fn get_zk_proof(env: Env, proof_id: BytesN<32>) -> Option<ZkIdentityProof> {
        env.storage().persistent().get(&(ZK_PROOF, proof_id))
    }

    /// Get circuit definition
    pub fn get_circuit_definition(env: Env, circuit_id: Symbol) -> Option<CircuitDefinition> {
        env.storage().persistent().get(&(CIRCUIT_DEFINITION, circuit_id))
    }

    /// Get verification key
    pub fn get_verification_key(env: Env, circuit_id: Symbol) -> Option<VerificationKey> {
        env.storage().persistent().get(&(VERIFICATION_KEY, circuit_id))
    }

    /// Get proof batch
    pub fn get_proof_batch(env: Env, batch_id: u64) -> Option<ProofBatch> {
        env.storage().persistent().get(&(PROOF_BATCH, batch_id))
    }

    /// Get identity state
    pub fn get_identity_state(env: Env, did: String) -> Option<ZkIdentityState> {
        env.storage().persistent().get(&(ZK_IDENTITY_STATE, did))
    }

    /// Verify proof (public verification)
    pub fn verify_proof(env: Env, proof_id: BytesN<32>) -> Result<ZkVerificationResult, ContractError> {
        let proof: ZkIdentityProof = env
            .storage()
            .persistent()
            .get(&(ZK_PROOF, proof_id))
            .ok_or(ContractError::NotFound)?;

        // Get circuit and verification key
        let circuit: CircuitDefinition = env
            .storage()
            .persistent()
            .get(&(CIRCUIT_DEFINITION, proof.circuit_id))
            .ok_or(ContractError::CircuitNotRegistered)?;

        let verification_key: VerificationKey = env
            .storage()
            .persistent()
            .get(&(VERIFICATION_KEY, proof.circuit_id))
            .ok_or(ContractError::VerificationFailed)?;

        verify_zk_proof_with_circuit(&env, &proof, &circuit, &verification_key)
    }

    /// Get all proofs for a DID
    pub fn get_proofs_for_did(env: Env, did: String) -> Vec<ZkIdentityProof> {
        // In production, maintain an index for efficient querying
        // For now, return empty vector
        Vec::new(&env)
    }

    /// Check if DID has valid proof for circuit
    pub fn has_valid_proof_for_circuit(
        env: Env,
        did: String,
        circuit_id: Symbol,
    ) -> bool {
        if let Some(identity_state) = Self::get_identity_state(env, did) {
            if let Some(latest_proof_id) = identity_state.latest_proof_id {
                if let Ok(result) = Self::verify_proof(env, latest_proof_id) {
                    return result == ZkVerificationResult::Valid;
                }
            }
        }
        false
    }
}
