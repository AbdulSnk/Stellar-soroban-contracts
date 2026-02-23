// Issue #103 — Decentralised Governance Voting System
// Full ballot system with delegation chains, timelocks, and analytics

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    Address, Env, Map, Symbol, Vec, String,
    log,
};

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

const VOTING_PERIOD_SECS:   u64 = 7 * 24 * 3600;   // 7 days
const TIMELOCK_SECS:        u64 = 2 * 24 * 3600;   // 2 days post-vote
const QUORUM_BPS:           u32 = 2_000;            // 20 % quorum
const APPROVAL_THRESHOLD_BPS: u32 = 5_000;          // 50 % + 1 = simple majority
const MAX_DELEGATION_DEPTH: u32 = 5;

// ─────────────────────────────────────────────
// Storage Keys
// ─────────────────────────────────────────────

#[contracttype]
pub enum GovKey {
    GovernanceToken,                 // Token contract used for voting weight
    TotalSupply,
    Proposal(u64),                   // ProposalState by ID
    ProposalCount,
    Vote(u64, Address),              // VoteRecord per proposal per voter
    Delegation(Address),             // Who Address delegates to
    DelegationDepth(Address),        // Cycle guard
    ProposalList,                    // Vec<u64> of all proposals
    Paused,
}

// ─────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────

#[contracttype]
#[derive(Clone, PartialEq)]
pub enum ProposalStatus {
    Active,
    Defeated,
    Succeeded,
    Queued,
    Executed,
    Cancelled,
}

#[contracttype]
#[derive(Clone)]
pub struct Proposal {
    pub id:            u64,
    pub proposer:      Address,
    pub title:         String,
    pub description:   String,
    pub target:        Address,    // Contract to call on execution
    pub calldata:      Symbol,     // Entry-point symbol to invoke
    pub start_time:    u64,
    pub end_time:      u64,
    pub execute_after: u64,        // Timelock: end_time + TIMELOCK_SECS
    pub votes_for:     i128,
    pub votes_against: i128,
    pub votes_abstain: i128,
    pub status:        ProposalStatus,
    pub executed_at:   u64,
}

#[contracttype]
#[derive(Clone, PartialEq)]
pub enum VoteChoice {
    For,
    Against,
    Abstain,
}

#[contracttype]
#[derive(Clone)]
pub struct VoteRecord {
    pub voter:    Address,
    pub choice:   VoteChoice,
    pub weight:   i128,
    pub delegated_from: Vec<Address>,  // Chain of delegators
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct GovernanceAnalytics {
    pub total_proposals:   u64,
    pub active_proposals:  u64,
    pub executed_proposals: u64,
    pub total_votes_cast:  i128,
    pub avg_participation: u32,   // BPS of total supply
}

// ─────────────────────────────────────────────
// Contract
// ─────────────────────────────────────────────

#[contract]
pub struct GovernanceVoting;

#[contractimpl]
impl GovernanceVoting {

    // ── Initialization ───────────────────────

    pub fn initialize(env: Env, governance_token: Address, total_supply: i128) {
        if env.storage().instance().has(&GovKey::GovernanceToken) {
            panic!("already initialised");
        }
        env.storage().instance().set(&GovKey::GovernanceToken, &governance_token);
        env.storage().instance().set(&GovKey::TotalSupply,      &total_supply);
        env.storage().instance().set(&GovKey::ProposalCount,    &0u64);
        env.storage().instance().set(&GovKey::ProposalList,     &Vec::<u64>::new(&env));
        env.storage().instance().set(&GovKey::Paused,           &false);
    }

    // ── Proposal Creation ────────────────────

    pub fn create_proposal(
        env:         Env,
        proposer:    Address,
        title:       String,
        description: String,
        target:      Address,
        calldata:    Symbol,
    ) -> u64 {
        proposer.require_auth();
        Self::require_not_paused(&env);

        let count: u64 = env.storage().instance()
            .get(&GovKey::ProposalCount)
            .unwrap_or(0);
        let id = count + 1;
        let now = env.ledger().timestamp();

        let proposal = Proposal {
            id,
            proposer,
            title,
            description,
            target,
            calldata,
            start_time:    now,
            end_time:      now + VOTING_PERIOD_SECS,
            execute_after: now + VOTING_PERIOD_SECS + TIMELOCK_SECS,
            votes_for:     0,
            votes_against: 0,
            votes_abstain: 0,
            status:        ProposalStatus::Active,
            executed_at:   0,
        };

        env.storage().persistent().set(&GovKey::Proposal(id), &proposal);
        env.storage().instance().set(&GovKey::ProposalCount, &id);

        let mut list: Vec<u64> = env.storage().instance()
            .get(&GovKey::ProposalList)
            .unwrap_or(Vec::new(&env));
        list.push_back(id);
        env.storage().instance().set(&GovKey::ProposalList, &list);

        log!(&env, "proposal {} created", id);
        id
    }

    // ── Delegation ───────────────────────────

    /// Delegate voting power to `delegate`. Chains up to MAX_DELEGATION_DEPTH.
    pub fn delegate(env: Env, delegator: Address, delegate: Address) {
        delegator.require_auth();
        if delegator == delegate {
            panic!("cannot self-delegate");
        }
        // Cycle detection: walk the chain
        let depth = Self::delegation_depth(&env, &delegate, 0);
        if depth >= MAX_DELEGATION_DEPTH {
            panic!("delegation chain too long or cycle detected");
        }
        env.storage().instance().set(&GovKey::Delegation(delegator), &delegate);
        log!(&env, "delegation set, chain depth {}", depth + 1);
    }

    pub fn undelegate(env: Env, delegator: Address) {
        delegator.require_auth();
        env.storage().instance().remove(&GovKey::Delegation(delegator));
    }

    /// Resolve the ultimate delegate for `voter` (follow the chain).
    pub fn resolve_delegate(env: Env, voter: Address) -> Address {
        Self::follow_delegation(&env, &voter, 0)
    }

    // ── Voting ───────────────────────────────

    /// Cast a vote on behalf of `voter` (weight comes from `token_balance`).
    /// Delegation is followed automatically.
    pub fn cast_vote(
        env:           Env,
        voter:         Address,
        proposal_id:   u64,
        choice:        VoteChoice,
        token_balance: i128,      // Caller supplies their balance; validated off-chain or via token
    ) {
        voter.require_auth();
        Self::require_not_paused(&env);

        let mut proposal: Proposal = env.storage().persistent()
            .get(&GovKey::Proposal(proposal_id))
            .expect("proposal not found");

        let now = env.ledger().timestamp();
        if proposal.status != ProposalStatus::Active {
            panic!("proposal not active");
        }
        if now < proposal.start_time || now > proposal.end_time {
            panic!("voting period closed");
        }

        // Follow delegation chain to effective voter
        let effective_voter = Self::follow_delegation(&env, &voter, 0);
        let mut delegated_from = Vec::<Address>::new(&env);
        if effective_voter != voter {
            delegated_from.push_back(voter.clone());
        }

        // Prevent double-voting
        if env.storage().temporary()
            .has(&GovKey::Vote(proposal_id, effective_voter.clone()))
        {
            panic!("already voted");
        }

        let weight = token_balance;
        if weight <= 0 {
            panic!("no voting power");
        }

        match choice {
            VoteChoice::For     => proposal.votes_for     += weight,
            VoteChoice::Against => proposal.votes_against += weight,
            VoteChoice::Abstain => proposal.votes_abstain += weight,
        }

        let record = VoteRecord {
            voter:          effective_voter.clone(),
            choice,
            weight,
            delegated_from,
            timestamp: now,
        };

        env.storage().temporary().set(&GovKey::Vote(proposal_id, effective_voter), &record);
        env.storage().persistent().set(&GovKey::Proposal(proposal_id), &proposal);

        log!(&env, "vote cast on proposal {} weight {}", proposal_id, weight);
    }

    // ── Proposal Finalisation ────────────────

    /// Evaluate the outcome of a proposal after its voting period.
    pub fn finalize_proposal(env: Env, proposal_id: u64) -> ProposalStatus {
        let mut proposal: Proposal = env.storage().persistent()
            .get(&GovKey::Proposal(proposal_id))
            .expect("proposal not found");

        let now = env.ledger().timestamp();
        if proposal.status != ProposalStatus::Active {
            return proposal.status;
        }
        if now <= proposal.end_time {
            panic!("voting period still open");
        }

        let total_supply: i128 = env.storage().instance()
            .get(&GovKey::TotalSupply)
            .unwrap_or(1);

        let total_votes = proposal.votes_for + proposal.votes_against + proposal.votes_abstain;
        let quorum_bps  = ((total_votes * 10_000) / total_supply) as u32;
        let approval_bps = if total_votes > 0 {
            ((proposal.votes_for * 10_000) / total_votes) as u32
        } else {
            0
        };

        proposal.status = if quorum_bps >= QUORUM_BPS && approval_bps > APPROVAL_THRESHOLD_BPS {
            ProposalStatus::Succeeded
        } else {
            ProposalStatus::Defeated
        };

        env.storage().persistent().set(&GovKey::Proposal(proposal_id), &proposal);
        log!(&env, "proposal {} finalised: quorum {}bps approval {}bps",
             proposal_id, quorum_bps, approval_bps);
        proposal.status
    }

    /// Queue a succeeded proposal for execution (starts timelock countdown).
    pub fn queue_proposal(env: Env, caller: Address, proposal_id: u64) {
        caller.require_auth();
        let mut proposal: Proposal = env.storage().persistent()
            .get(&GovKey::Proposal(proposal_id))
            .expect("proposal not found");

        if proposal.status != ProposalStatus::Succeeded {
            panic!("proposal has not succeeded");
        }
        proposal.status = ProposalStatus::Queued;
        env.storage().persistent().set(&GovKey::Proposal(proposal_id), &proposal);
    }

    /// Execute a queued proposal after the timelock has expired.
    pub fn execute_proposal(env: Env, caller: Address, proposal_id: u64) {
        caller.require_auth();
        Self::require_not_paused(&env);

        let mut proposal: Proposal = env.storage().persistent()
            .get(&GovKey::Proposal(proposal_id))
            .expect("proposal not found");

        if proposal.status != ProposalStatus::Queued {
            panic!("proposal not queued");
        }

        let now = env.ledger().timestamp();
        if now < proposal.execute_after {
            panic!("timelock not expired");
        }

        proposal.status      = ProposalStatus::Executed;
        proposal.executed_at = now;
        env.storage().persistent().set(&GovKey::Proposal(proposal_id), &proposal);

        // NOTE: In production, invoke proposal.target.calldata here via cross-contract call.
        log!(&env, "proposal {} executed at {}", proposal_id, now);
    }

    pub fn cancel_proposal(env: Env, caller: Address, proposal_id: u64) {
        caller.require_auth();
        let mut proposal: Proposal = env.storage().persistent()
            .get(&GovKey::Proposal(proposal_id))
            .expect("proposal not found");

        if caller != proposal.proposer {
            panic!("only proposer can cancel");
        }
        if proposal.status == ProposalStatus::Executed {
            panic!("cannot cancel executed proposal");
        }
        proposal.status = ProposalStatus::Cancelled;
        env.storage().persistent().set(&GovKey::Proposal(proposal_id), &proposal);
    }

    // ── Analytics ────────────────────────────

    pub fn get_analytics(env: Env) -> GovernanceAnalytics {
        let list: Vec<u64> = env.storage().instance()
            .get(&GovKey::ProposalList)
            .unwrap_or(Vec::new(&env));

        let total = list.len() as u64;
        let mut active    = 0u64;
        let mut executed  = 0u64;
        let mut total_votes_cast = 0i128;
        let total_supply: i128 = env.storage().instance()
            .get(&GovKey::TotalSupply)
            .unwrap_or(1);

        for i in 0..list.len() {
            let id = list.get(i).unwrap();
            if let Some(p) = env.storage().persistent()
                .get::<GovKey, Proposal>(&GovKey::Proposal(id))
            {
                if p.status == ProposalStatus::Active   { active   += 1; }
                if p.status == ProposalStatus::Executed { executed += 1; }
                total_votes_cast += p.votes_for + p.votes_against + p.votes_abstain;
            }
        }

        let avg_participation = if total > 0 {
            ((total_votes_cast / total as i128) * 10_000 / total_supply) as u32
        } else {
            0
        };

        GovernanceAnalytics {
            total_proposals:    total,
            active_proposals:   active,
            executed_proposals: executed,
            total_votes_cast,
            avg_participation,
        }
    }

    pub fn get_proposal(env: Env, id: u64) -> Proposal {
        env.storage().persistent()
            .get(&GovKey::Proposal(id))
            .expect("not found")
    }

    // ── Internal Helpers ─────────────────────

    fn follow_delegation(env: &Env, voter: &Address, depth: u32) -> Address {
        if depth >= MAX_DELEGATION_DEPTH {
            return voter.clone();
        }
        match env.storage().instance().get::<GovKey, Address>(&GovKey::Delegation(voter.clone())) {
            Some(next) => Self::follow_delegation(env, &next, depth + 1),
            None       => voter.clone(),
        }
    }

    fn delegation_depth(env: &Env, voter: &Address, depth: u32) -> u32 {
        if depth >= MAX_DELEGATION_DEPTH {
            return depth;
        }
        match env.storage().instance().get::<GovKey, Address>(&GovKey::Delegation(voter.clone())) {
            Some(next) => Self::delegation_depth(env, &next, depth + 1),
            None       => depth,
        }
    }

    fn require_not_paused(env: &Env) {
        if env.storage().instance().get::<GovKey, bool>(&GovKey::Paused).unwrap_or(false) {
            panic!("paused");
        }
    }
}