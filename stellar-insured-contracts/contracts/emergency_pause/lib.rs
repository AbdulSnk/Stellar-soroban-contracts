#![no_std]

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, Symbol};

const ADMIN: Symbol = Symbol::short("ADMIN");
const EMERGENCY_PAUSE: Symbol = Symbol::short("EMERGENCY");
const PAUSE_REASON: Symbol = Symbol::short("PAUSE_REASON");
const PAUSE_TIMESTAMP: Symbol = Symbol::short("PAUSE_TIME");
const MAX_DURATION: Symbol = Symbol::short("MAX_DURATION");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum EmergencyPauseError {
    Unauthorized = 1,
    AlreadyPaused = 2,
    NotPaused = 3,
    InvalidDuration = 4,
    NotInitialized = 5,
    DurationExceeded = 6,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct EmergencyPauseState {
    pub is_paused: bool,
    pub reason: Symbol,
    pub pause_timestamp: u64,
    pub max_duration_seconds: u64,
    pub paused_by: Address,
}

#[contract]
pub struct EmergencyPauseContract;

impl EmergencyPauseContract {
    pub fn initialize(env: &Env, admin: &Address) -> Result<(), EmergencyPauseError> {
        if env.storage().persistent().has(&ADMIN) {
            return Err(EmergencyPauseError::NotInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&ADMIN, admin);

        Ok(())
    }

    pub fn activate_emergency_pause(
        env: &Env,
        admin: &Address,
        reason: Symbol,
        max_duration_seconds: u64,
    ) -> Result<(), EmergencyPauseError> {
        admin.require_auth();
        
        let stored_admin: Address = env.storage().persistent()
            .get(&ADMIN)
            .ok_or(EmergencyPauseError::NotInitialized)?;

        if stored_admin != *admin {
            return Err(EmergencyPauseError::Unauthorized);
        }

        if env.storage().persistent().has(&EMERGENCY_PAUSE) {
            return Err(EmergencyPauseError::AlreadyPaused);
        }

        if max_duration_seconds == 0 || max_duration_seconds > 86400 * 30 { // Max 30 days
            return Err(EmergencyPauseError::InvalidDuration);
        }

        let pause_state = EmergencyPauseState {
            is_paused: true,
            reason,
            pause_timestamp: env.ledger().timestamp(),
            max_duration_seconds,
            paused_by: admin.clone(),
        };

        env.storage().persistent().set(&EMERGENCY_PAUSE, &pause_state);

        Ok(())
    }

    pub fn deactivate_emergency_pause(env: &Env, admin: &Address) -> Result<(), EmergencyPauseError> {
        admin.require_auth();
        
        let stored_admin: Address = env.storage().persistent()
            .get(&ADMIN)
            .ok_or(EmergencyPauseError::NotInitialized)?;

        if stored_admin != *admin {
            return Err(EmergencyPauseError::Unauthorized);
        }

        if !env.storage().persistent().has(&EMERGENCY_PAUSE) {
            return Err(EmergencyPauseError::NotPaused);
        }

        env.storage().persistent().remove(&EMERGENCY_PAUSE);

        Ok(())
    }

    pub fn is_emergency_paused(env: &Env) -> Result<bool, EmergencyPauseError> {
        if let Some(pause_state) = env.storage().persistent().get::<_, EmergencyPauseState>(&EMERGENCY_PAUSE) {
            let current_time = env.ledger().timestamp();
            
            // Auto-expire if duration exceeded
            if current_time > pause_state.pause_timestamp + pause_state.max_duration_seconds {
                env.storage().persistent().remove(&EMERGENCY_PAUSE);
                return Ok(false);
            }
            
            Ok(pause_state.is_paused)
        } else {
            Ok(false)
        }
    }

    pub fn get_emergency_pause_state(env: &Env) -> Result<EmergencyPauseState, EmergencyPauseError> {
        env.storage().persistent()
            .get(&EMERGENCY_PAUSE)
            .ok_or(EmergencyPauseError::NotPaused)
    }
}
