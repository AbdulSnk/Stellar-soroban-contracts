#![no_std]

mod codes;
mod recovery;
mod registry;
mod types;

pub use codes::InsuranceError;
pub use recovery::RecoveryContract;
pub use types::{ErrorEntry, ErrorSeverity, RecoveryAction, RecoveryStatus};

#[cfg(test)]
mod test;