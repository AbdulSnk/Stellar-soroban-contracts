use soroban_sdk::{testutils::{Address as _, Ledger}, Address, Env, Symbol};

use super::*;  // Your TreasuryContract

pub struct TestEnvironment {
    pub env: Env,
    pub admin: Address,
    pub governance: Address,
    pub trusted_contract: Address,
    pub treasury_id: Address,
    pub treasury_client: TreasuryContractClient<'static>,
}

impl TestEnvironment {
    pub fn new() -> Self {
        let env = Env::default();
        let admin = Address::generate(&env);
        let governance = Address::generate(&env);
        let trusted_contract = Address::generate(&env);

        // Setup consistent ledger state
        env.ledger().set_timestamp(1_640_995_200);
        env.ledger().set_sequence_number(1);

        // Deploy Treasury
        let treasury_id = env.register_contract(None, TreasuryContract);
        let treasury_client = TreasuryContractClient::new(&env, &treasury_id);

        // Initialize treasury
        treasury_client.initialize(&admin, &governance, &500); // 5%

        // Register trusted contract
        treasury_client.register_trusted_contract(&trusted_contract);

        Self {
            env,
            admin,
            governance,
            trusted_contract,
            treasury_id,
            treasury_client,
        }
    }

    pub fn with_balance(&mut self, amount: i128) -> &mut Self {
        // Mock deposit from trusted contract
        self.env.mock_all_auths();
        self.treasury_client.deposit_premium_fee(
            &self.trusted_contract,
            &amount
        );
        self
    }

    pub fn advance_time(&mut self, seconds: u64) -> &mut Self {
        let current = self.env.ledger().timestamp();
        self.env.ledger().set_timestamp(current + seconds);
        self
    }

    pub fn create_user(&self) -> Address {
        Address::generate(&self.env)
    }
}
