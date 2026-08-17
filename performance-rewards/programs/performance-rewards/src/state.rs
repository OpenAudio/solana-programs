use anchor_lang::prelude::*;

#[account]
pub struct Config {
    pub authority: Pubkey,
    pub audio_mint: Pubkey,
    pub claimable_tokens_program: Pubkey,
    pub latest_opened_epoch: u64,
    pub has_opened_epoch: bool,
    pub last_finalized_epoch: u64,
    pub has_finalized_epoch: bool,
    pub current_claim_epoch: u64,
    pub has_current_claim_epoch: bool,
    pub total_funded: u64,
    pub total_claimed: u64,
    pub total_expired: u64,
    pub bump: u8,
}

impl Config {
    pub const SPACE: usize = 8 + 32 + 32 + 32 + 8 + 1 + 8 + 1 + 8 + 1 + 8 + 8 + 8 + 1;
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochStatus {
    Pending,
    ClaimsOpen,
    Expired,
}

#[account]
pub struct EpochState {
    pub config: Pubkey,
    pub id: u64,
    pub start_unix: i64,
    pub end_unix: i64,
    pub start_block: u64,
    pub end_block: u64,
    pub scoring_version: [u8; 32],
    pub eligible_root: [u8; 32],
    pub total_eligible_weight: u64,
    pub budget: u64,
    pub snapshot_root: [u8; 32],
    pub total_score: u64,
    pub total_allocated: u64,
    pub attested_weight: u64,
    pub funded_amount: u64,
    pub claimed_amount: u64,
    pub expired_amount: u64,
    pub candidate_set: bool,
    pub status: EpochStatus,
    pub bump: u8,
    pub vault_bump: u8,
}

impl EpochState {
    pub const SPACE: usize =
        8 + 32 + 8 + 8 + 8 + 8 + 8 + 32 + 32 + 8 + 8 + 32 + 8 + 8 + 8 + 8 + 8 + 8 + 1 + 1 + 1 + 1;
}

#[account]
pub struct AttestationRecord {
    pub epoch: Pubkey,
    pub signer: [u8; 20],
    pub operator: [u8; 20],
    pub weight: u64,
    pub snapshot_root: [u8; 32],
    pub bump: u8,
}

impl AttestationRecord {
    pub const SPACE: usize = 8 + 32 + 20 + 20 + 8 + 32 + 1;
}

#[account]
pub struct ClaimRecord {
    pub epoch: Pubkey,
    pub operator: [u8; 20],
    pub score: u64,
    pub allocation: u64,
    pub evidence_hash: [u8; 32],
    pub claimed_at: i64,
    pub bump: u8,
}

impl ClaimRecord {
    pub const SPACE: usize = 8 + 32 + 20 + 8 + 8 + 32 + 8 + 1;
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenEpochArgs {
    pub id: u64,
    pub start_unix: i64,
    pub end_unix: i64,
    pub start_block: u64,
    pub end_block: u64,
    pub scoring_version: [u8; 32],
    pub eligible_root: [u8; 32],
    pub total_eligible_weight: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotCommitment {
    pub root: [u8; 32],
    pub total_score: u64,
    pub total_allocated: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct EligibilityProof {
    pub signer: [u8; 20],
    pub operator: [u8; 20],
    pub weight: u64,
    pub proof: Vec<[u8; 32]>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ClaimArgs {
    pub operator: [u8; 20],
    pub score: u64,
    pub allocation: u64,
    pub scoring_version: [u8; 32],
    pub evidence_hash: [u8; 32],
    pub proof: Vec<[u8; 32]>,
}
