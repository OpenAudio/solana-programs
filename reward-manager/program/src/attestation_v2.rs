//! Versioned reward claim encoding and per-manager revocation policy.
#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{keccak, program_error::ProgramError, pubkey::Pubkey};

pub const DOMAIN: &[u8] = b"AudiusRewardClaimV2";
pub const ORACLE: u8 = 1;
pub const VALIDATOR: u8 = 2;
pub const POLICY_SEED: &[u8] = b"reward_policy_v2";

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
pub struct Policy {
    pub version: u8,
    pub reward_manager: Pubkey,
    pub chain_domain: [u8; 32],
    pub oracle: [u8; 20],
    pub epoch: u64,
    pub enabled: bool,
}

impl Policy {
    pub const LEN: usize = 94;

    pub fn check(
        &self,
        manager: &Pubkey,
        oracle: &[u8; 20],
        epoch: u64,
        expiry: u64,
        slot: u64,
    ) -> Result<(), ProgramError> {
        if self.version != 2
            || !self.enabled
            || self.reward_manager != *manager
            || self.oracle != *oracle
            || self.epoch == 0
            || epoch != self.epoch
            || expiry == 0
            || slot > expiry
        {
            return Err(ProgramError::InvalidArgument);
        }
        Ok(())
    }
}

pub fn policy_address(program: &Pubkey, manager: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[POLICY_SEED, manager.as_ref()], program)
}

#[derive(Clone, Debug)]
pub struct Claim {
    pub chain_domain: [u8; 32],
    pub program: Pubkey,
    pub reward_manager: Pubkey,
    pub mint: Pubkey,
    pub reward_address: [u8; 20],
    pub recipient: [u8; 20],
    pub oracle: [u8; 20],
    pub amount: u64,
    pub epoch: u64,
    pub valid_until_slot: u64,
    pub disbursement_id: String,
}

impl Claim {
    /// The exact canonical format is shared with go-openaudio RewardClaimV2.
    pub fn message(&self, role: u8) -> Result<Vec<u8>, ProgramError> {
        if (role != ORACLE && role != VALIDATOR)
            || self.chain_domain == [0; 32]
            || self.program == Pubkey::default()
            || self.reward_manager == Pubkey::default()
            || self.mint == Pubkey::default()
            || self.reward_address == [0; 20]
            || self.oracle == [0; 20]
            || self.amount == 0
            || self.epoch == 0
            || self.valid_until_slot == 0
            || self.disbursement_id.is_empty()
            || self.disbursement_id.len() > 30
        {
            return Err(ProgramError::InvalidArgument);
        }
        let mut preimage = DOMAIN.to_vec();
        preimage.extend_from_slice(&self.chain_domain);
        preimage.extend_from_slice(self.program.as_ref());
        preimage.extend_from_slice(self.reward_manager.as_ref());
        preimage.extend_from_slice(self.mint.as_ref());
        preimage.extend_from_slice(&self.reward_address);
        preimage.extend_from_slice(&self.recipient);
        preimage.extend_from_slice(&self.oracle);
        preimage.extend_from_slice(&self.amount.to_le_bytes());
        preimage.extend_from_slice(&self.epoch.to_le_bytes());
        preimage.extend_from_slice(&self.valid_until_slot.to_le_bytes());
        preimage.extend_from_slice(&(self.disbursement_id.len() as u16).to_le_bytes());
        preimage.extend_from_slice(self.disbursement_id.as_bytes());
        let mut message = DOMAIN.to_vec();
        message.push(role);
        message.extend_from_slice(keccak::hash(&preimage).as_ref());
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim() -> Claim {
        Claim {
            chain_domain: [1; 32],
            program: Pubkey::new_from_array([2; 32]),
            reward_manager: Pubkey::new_from_array([3; 32]),
            mint: Pubkey::new_from_array([4; 32]),
            reward_address: [5; 20],
            recipient: [6; 20],
            oracle: [7; 20],
            amount: 2325000000000000,
            epoch: 1,
            valid_until_slot: 500000000,
            disbursement_id: "reward:nonce".into(),
        }
    }

    #[test]
    fn go_rust_golden_vector() {
        let c = claim();
        for (role, expected) in [
            (ORACLE, "417564697573526577617264436c61696d56320119f09a18a91318a4fb4ea4fab4957998682a5ea154eb4e5ac8e5c5b1a02e15c5"),
            (VALIDATOR, "417564697573526577617264436c61696d56320219f09a18a91318a4fb4ea4fab4957998682a5ea154eb4e5ac8e5c5b1a02e15c5"),
        ] {
            let hex: String = c.message(role).unwrap().iter().map(|b| format!("{:02x}", b)).collect();
            assert_eq!(hex, expected);
        }
    }

    #[test]
    fn roles_and_domains_are_distinct() {
        let c = claim();
        let v = c.message(VALIDATOR).unwrap();
        assert_eq!(v.len(), 52);
        assert_ne!(v, c.message(ORACLE).unwrap());
        let mut other = c.clone();
        other.reward_manager = Pubkey::new_unique();
        assert_ne!(v, other.message(VALIDATOR).unwrap());
        let mut other = c.clone();
        other.chain_domain[0] ^= 1;
        assert_ne!(v, other.message(VALIDATOR).unwrap());
        let mut other = c.clone();
        other.epoch += 1;
        assert_ne!(v, other.message(VALIDATOR).unwrap());
        let mut other = c.clone();
        other.reward_address[0] ^= 1;
        assert_ne!(v, other.message(VALIDATOR).unwrap());
    }

    #[test]
    fn delimiter_collision_is_rejected() {
        let mut v = claim();
        v.disbursement_id = "reward:d3".into();
        v.oracle = [0x41; 20];
        let mut o = v.clone();
        o.disbursement_id = "reward:d3_AAAAAAAAAAAAAAAAAAAA".into();
        assert_ne!(v.message(VALIDATOR).unwrap(), o.message(ORACLE).unwrap());
    }

    #[test]
    fn policy_revokes_and_expires_claims() {
        let c = claim();
        let mut p = Policy {
            version: 2,
            reward_manager: c.reward_manager,
            chain_domain: c.chain_domain,
            oracle: c.oracle,
            epoch: 1,
            enabled: true,
        };
        assert_eq!(p.try_to_vec().unwrap().len(), Policy::LEN);
        assert!(p.check(&c.reward_manager, &c.oracle, 1, 100, 100).is_ok());
        assert!(p.check(&c.reward_manager, &c.oracle, 1, 100, 101).is_err());
        assert!(p.check(&c.reward_manager, &[8; 20], 1, 100, 99).is_err());
        p.epoch += 1;
        assert!(p.check(&c.reward_manager, &c.oracle, 1, 100, 99).is_err());
        p.enabled = false;
        assert!(p.check(&c.reward_manager, &c.oracle, 2, 100, 99).is_err());
    }
}
