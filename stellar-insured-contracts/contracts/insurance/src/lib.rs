#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    Address, BytesN, Env, Map, String, Vec,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Minimum ledger-time (seconds) a proposal must remain open for voting.
const VOTING_PERIOD_SECS: u64 = 7 * 24 * 3600; // 7 days

/// Fraction of total votes required for quorum (basis points, 10000 = 100%).
const QUORUM_BPS: u32 = 2000; // 20%

/// Fraction of YES votes required for approval (basis points).
const APPROVAL_BPS: u32 = 5000; // 50%

// ─── Data Structures ─────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, PartialEq)]
pub enum ProposalStatus {
    Active,
    Approved,
    Rejected,
    Executed,
    Cancelled,
}

#[contracttype]
#[derive(Clone)]
pub struct UpgradeProposal {
    pub id:           u32,
    pub proposer:     Address,
    pub target:       Address,
    pub new_wasm:     BytesN<32>,
    pub new_major:    u32,
    pub new_minor:    u32,
    pub new_patch:    u32,
    pub description:  String,
    pub created_at:   u64,
    pub voting_end:   u64,
    pub status:       ProposalStatus,
    pub yes_votes:    u32,
    pub no_votes:     u32,
    pub total_voters: u32,
}

// ─── Contract ────────────────────────────────────────────────────────────────

#[contract]
pub struct GovernanceContract;

#[contractimpl]
impl GovernanceContract {

    // ── Initialisation ───────────────────────────────────────────────────────

    pub fn initialize(env: Env, admin: Address, council: Vec<Address>) {
        if env.storage().instance().has(&symbol_short!("admin")) {
            panic!("Already initialised");
        }
        admin.require_auth();
        env.storage().instance().set(&symbol_short!("admin"),   &admin);
        env.storage().instance().set(&symbol_short!("council"), &council);
        let next_id: u32 = 0;
        env.storage().instance().set(&symbol_short!("nxtid"), &next_id);
    }

    // ── Council management ───────────────────────────────────────────────────

    pub fn add_member(env: Env, member: Address) {
        Self::require_admin(&env);
        let mut council: Vec<Address> =
            env.storage().instance().get(&symbol_short!("council")).unwrap();
        for i in 0..council.len() {
            if council.get(i).unwrap() == member {
                panic!("Already a council member");
            }
        }
        council.push_back(member);
        env.storage().instance().set(&symbol_short!("council"), &council);
    }

    pub fn remove_member(env: Env, member: Address) {
        Self::require_admin(&env);
        let council: Vec<Address> =
            env.storage().instance().get(&symbol_short!("council")).unwrap();
        let mut new_council = Vec::new(&env);
        for i in 0..council.len() {
            let m = council.get(i).unwrap();
            if m != member { new_council.push_back(m); }
        }
        env.storage().instance().set(&symbol_short!("council"), &new_council);
    }

    // ── Proposal lifecycle ───────────────────────────────────────────────────

    pub fn propose_upgrade(
        env:         Env,
        proposer:    Address,
        target:      Address,
        new_wasm:    BytesN<32>,
        new_major:   u32,
        new_minor:   u32,
        new_patch:   u32,
        description: String,
    ) -> u32 {
        proposer.require_auth();
        Self::require_council_member(&env, &proposer);

        let council: Vec<Address> =
            env.storage().instance().get(&symbol_short!("council")).unwrap();
        let total_voters = council.len();

        let id  = Self::next_id(&env);
        let now = env.ledger().timestamp();

        let proposal = UpgradeProposal {
            id,
            proposer,
            target,
            new_wasm,
            new_major,
            new_minor,
            new_patch,
            description,
            created_at:   now,
            voting_end:   now + VOTING_PERIOD_SECS,
            status:       ProposalStatus::Active,
            yes_votes:    0,
            no_votes:     0,
            total_voters,
        };

        Self::save_proposal(&env, &proposal);
        id
    }

    pub fn vote(env: Env, voter: Address, proposal_id: u32, approve: bool) {
        voter.require_auth();
        Self::require_council_member(&env, &voter);

        let mut proposal = Self::load_proposal(&env, proposal_id);

        if proposal.status != ProposalStatus::Active {
            panic!("Proposal is not active");
        }
        if env.ledger().timestamp() > proposal.voting_end {
            panic!("Voting period has ended");
        }

        let vote_key = (symbol_short!("votes"), proposal_id);
        let mut votes: Map<Address, bool> =
            env.storage().instance().get(&vote_key).unwrap_or(Map::new(&env));

        if votes.contains_key(voter.clone()) {
            panic!("Already voted");
        }
        votes.set(voter, approve);
        env.storage().instance().set(&vote_key, &votes);

        if approve { proposal.yes_votes += 1; } else { proposal.no_votes += 1; }
        Self::save_proposal(&env, &proposal);
    }

    /// Permissionless – anyone can finalise once voting window closes.
    pub fn finalize(env: Env, proposal_id: u32) {
        let mut proposal = Self::load_proposal(&env, proposal_id);

        if proposal.status != ProposalStatus::Active {
            panic!("Proposal already finalised");
        }
        if env.ledger().timestamp() <= proposal.voting_end {
            panic!("Voting period still open");
        }

        let total_cast   = proposal.yes_votes + proposal.no_votes;
        let quorum_needed = (proposal.total_voters * QUORUM_BPS + 9999) / 10000;

        if total_cast < quorum_needed {
            proposal.status = ProposalStatus::Rejected;
        } else {
            let yes_bps = proposal.yes_votes * 10000 / total_cast;
            if yes_bps >= APPROVAL_BPS {
                proposal.status = ProposalStatus::Approved;
            } else {
                proposal.status = ProposalStatus::Rejected;
            }
        }
        Self::save_proposal(&env, &proposal);
    }

    pub fn execute(env: Env, executor: Address, proposal_id: u32) {
        executor.require_auth();
        Self::require_council_member(&env, &executor);

        let mut proposal = Self::load_proposal(&env, proposal_id);
        if proposal.status != ProposalStatus::Approved {
            panic!("Proposal not approved");
        }

        proposal.status = ProposalStatus::Executed;
        Self::save_proposal(&env, &proposal);

        // Cross-contract call – triggers the actual WASM swap.
        let client = UpgradeableContractClient::new(&env, &proposal.target);
        client.upgrade(
            &proposal.new_wasm,
            &proposal.new_major,
            &proposal.new_minor,
            &proposal.new_patch,
            &proposal.description,
        );
    }

    pub fn cancel(env: Env, proposal_id: u32) {
        Self::require_admin(&env);
        let mut proposal = Self::load_proposal(&env, proposal_id);
        if proposal.status != ProposalStatus::Active {
            panic!("Only active proposals can be cancelled");
        }
        proposal.status = ProposalStatus::Cancelled;
        Self::save_proposal(&env, &proposal);
    }

    // ── Views ────────────────────────────────────────────────────────────────

    pub fn get_proposal(env: Env, id: u32) -> UpgradeProposal {
        Self::load_proposal(&env, id)
    }

    pub fn get_council(env: Env) -> Vec<Address> {
        env.storage().instance().get(&symbol_short!("council")).unwrap()
    }

    pub fn proposal_count(env: Env) -> u32 {
        env.storage().instance().get(&symbol_short!("nxtid")).unwrap_or(0)
    }

    pub fn get_vote(env: Env, proposal_id: u32, voter: Address) -> Option<bool> {
        let vote_key = (symbol_short!("votes"), proposal_id);
        let votes: Map<Address, bool> =
            env.storage().instance().get(&vote_key).unwrap_or(Map::new(&env));
        votes.get(voter)
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn require_admin(env: &Env) {
        let admin: Address = env.storage().instance().get(&symbol_short!("admin")).unwrap();
        admin.require_auth();
    }

    fn require_council_member(env: &Env, addr: &Address) {
        let council: Vec<Address> =
            env.storage().instance().get(&symbol_short!("council")).unwrap();
        for i in 0..council.len() {
            if &council.get(i).unwrap() == addr { return; }
        }
        panic!("Not a council member");
    }

    fn next_id(env: &Env) -> u32 {
        let id: u32 = env.storage().instance().get(&symbol_short!("nxtid")).unwrap_or(0);
        env.storage().instance().set(&symbol_short!("nxtid"), &(id + 1));
        id
    }

    fn save_proposal(env: &Env, p: &UpgradeProposal) {
        env.storage().instance().set(&(symbol_short!("prop"), p.id), p);
    }

    fn load_proposal(env: &Env, id: u32) -> UpgradeProposal {
        env.storage()
            .instance()
            .get(&(symbol_short!("prop"), id))
            .unwrap_or_else(|| panic!("Proposal not found"))
    }
}

// ─── Cross-contract client (auto-generated in real projects) ─────────────────

use soroban_sdk::contractclient;

#[contractclient(name = "UpgradeableContractClient")]
pub trait UpgradeableTrait {
    fn upgrade(
        env:       Env,
        new_wasm:  BytesN<32>,
        new_major: u32,
        new_minor: u32,
        new_patch: u32,
        desc:      String,
    );
}