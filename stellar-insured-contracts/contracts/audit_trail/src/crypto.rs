#![no_std]

use soroban_sdk::{Bytes, BytesN, Env, Vec};

use crate::types::AuditEntry;

/// Compute SHA-256 hash of audit entry data
/// This creates a deterministic hash of all entry fields for integrity verification
pub fn compute_entry_hash(env: &Env, entry: &AuditEntry) -> BytesN<32> {
    let mut data = Bytes::new(env);

    // Add all entry fields to hash input
    data.extend_from_array(&entry.entry_id.to_be_bytes());
    data.extend_from_array(&entry.ledger.to_be_bytes());
    data.extend_from_array(&entry.timestamp.to_be_bytes());
    data.extend_from_array(&entry.actor.to_xdr(env).to_vec());
    data.extend_from_array(&entry.subject.to_vec());
    data.extend_from_array(&(entry.action as u32).to_be_bytes());
    data.extend_from_array(&entry.source_contract.to_xdr(env).to_vec());
    data.extend_from_array(&entry.data_hash.to_vec());
    data.extend_from_array(&entry.description.to_xdr(env).to_vec());
    data.extend_from_array(&(entry.severity as u32).to_be_bytes());
    data.extend_from_array(&(entry.compliance_status as u32).to_be_bytes());

    if let Some(related_id) = entry.related_entry_id {
        data.extend_from_array(&related_id.to_be_bytes());
    } else {
        data.extend_from_array(&[0u8; 8]);
    }

    data.extend_from_array(&entry.metadata.to_vec());

    if let Some(prev_hash) = &entry.previous_entry_hash {
        data.extend_from_array(&prev_hash.to_vec());
    } else {
        data.extend_from_array(&[0u8; 32]);
    }

    env.crypto().sha256(&data)
}

/// Compute SHA-256 hash of two child hashes (for Merkle tree)
pub fn compute_merkle_hash(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let mut data = Bytes::new(env);
    data.extend_from_array(&left.to_array());
    data.extend_from_array(&right.to_array());
    env.crypto().sha256(&data)
}

/// Build a Merkle tree from entry hashes and return the root
/// Returns None if entries is empty
pub fn compute_merkle_root(env: &Env, entry_hashes: Vec<BytesN<32>>) -> Option<BytesN<32>> {
    if entry_hashes.is_empty() {
        return None;
    }

    let mut current_level = entry_hashes;

    while current_level.len() > 1 {
        let mut next_level: Vec<BytesN<32>> = Vec::new(env);
        let len = current_level.len();
        let mut i = 0;

        while i < len {
            let left = current_level.get(i).unwrap();

            // If odd number of nodes, duplicate the last one
            let right = if i + 1 < len {
                current_level.get(i + 1).unwrap()
            } else {
                left.clone()
            };

            let parent_hash = compute_merkle_hash(env, &left, &right);
            next_level.push_back(parent_hash);

            i += 2;
        }

        current_level = next_level;
    }

    current_level.get(0)
}

/// Generate a Merkle proof for a specific entry
/// Returns the proof path (sibling hashes from leaf to root)
pub fn generate_merkle_proof(
    env: &Env,
    entry_hashes: Vec<BytesN<32>>,
    entry_index: u32,
) -> Vec<BytesN<32>> {
    let mut proof: Vec<BytesN<32>> = Vec::new(env);
    let mut current_level = entry_hashes;
    let mut current_index = entry_index;

    while current_level.len() > 1 {
        let len = current_level.len();
        let mut next_level: Vec<BytesN<32>> = Vec::new(env);
        let mut i = 0;

        while i < len {
            let left = current_level.get(i).unwrap();
            let right = if i + 1 < len {
                current_level.get(i + 1).unwrap()
            } else {
                left.clone()
            };

            // Add sibling to proof if current index is in this pair
            if i == (current_index & !1) {
                if current_index == i {
                    proof.push_back(right); // Left child, add right sibling
                } else {
                    proof.push_back(left); // Right child, add left sibling
                }
            }

            let parent_hash = compute_merkle_hash(env, &left, &right);
            next_level.push_back(parent_hash);

            i += 2;
        }

        current_level = next_level;
        current_index /= 2;
    }

    proof
}

/// Verify a Merkle proof
/// Returns true if the proof is valid
pub fn verify_merkle_proof(
    env: &Env,
    leaf_hash: &BytesN<32>,
    proof_path: &Vec<BytesN<32>>,
    expected_root: &BytesN<32>,
    entry_index: u32,
) -> bool {
    let mut current_hash = leaf_hash.clone();
    let mut index = entry_index;

    for i in 0..proof_path.len() {
        let sibling = proof_path.get(i).unwrap();
        let (left, right) = if index % 2 == 0 {
            (&current_hash, &sibling)
        } else {
            (&sibling, &current_hash)
        };

        current_hash = compute_merkle_hash(env, left, right);
        index /= 2;
    }

    current_hash == *expected_root
}

/// Create a 32-byte hash from Bytes (for storage compatibility)
pub fn bytes_to_hash(bytes: &Bytes) -> BytesN<32> {
    let mut array = [0u8; 32];
    let len = bytes.len().min(32);
    for i in 0..len {
        array[i as usize] = bytes.get(i).unwrap_or(0);
    }
    BytesN::from_array(bytes.env(), &array)
}

/// Convert BytesN<32> to Bytes (for storage compatibility)
pub fn hash_to_bytes(env: &Env, hash: &BytesN<32>) -> Bytes {
    Bytes::from_array(env, &hash.to_array())
}
