use anchor_lang::prelude::*;

#[error_code]
pub enum PerformanceRewardsError {
    #[msg("Only the immutable epoch opener may perform this action")]
    Unauthorized,
    #[msg("The epoch range must be one non-empty week")]
    InvalidEpochRange,
    #[msg("The epoch block range must be non-empty")]
    InvalidBlockRange,
    #[msg("Epochs must be opened sequentially without gaps")]
    NonSequentialEpoch,
    #[msg("The epoch must be opened after it starts and before it ends")]
    InvalidOpenTime,
    #[msg("Eligible root, scoring version, and total weight must be non-zero")]
    InvalidEligibility,
    #[msg("The epoch is not pending snapshot finalization")]
    EpochNotPending,
    #[msg("The epoch has not ended")]
    EpochNotEnded,
    #[msg("The eligibility proof is invalid")]
    InvalidEligibilityProof,
    #[msg("The attester weight must be non-zero")]
    InvalidWeight,
    #[msg("The snapshot commitment is invalid")]
    InvalidCommitment,
    #[msg("A competing snapshot commitment was already proposed")]
    CompetingSnapshot,
    #[msg("The secp256k1 verification instruction is missing or malformed")]
    InvalidSecpInstruction,
    #[msg("The secp256k1 signer does not match the frozen signer")]
    WrongEthSigner,
    #[msg("The signed snapshot commitment is wrong")]
    WrongSignedMessage,
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
    #[msg("Strictly more than two thirds of eligible weight has not attested")]
    QuorumNotReached,
    #[msg("Snapshots must finalize sequentially")]
    NonSequentialFinalization,
    #[msg("The previous epoch is not the currently open claim epoch")]
    WrongPreviousEpoch,
    #[msg("The epoch vault balance does not match its audit state")]
    VaultBalanceMismatch,
    #[msg("Claims are not open for this epoch")]
    ClaimsNotOpen,
    #[msg("The reward proof is invalid")]
    InvalidRewardProof,
    #[msg("A zero score or allocation cannot be claimed")]
    ZeroReward,
    #[msg("The claim scoring version does not match the epoch")]
    WrongScoringVersion,
    #[msg("The recipient is not the Ethereum identity's claimable AUDIO account")]
    WrongClaimableRecipient,
    #[msg("The claim would exceed the finalized allocation")]
    OverAllocation,
    #[msg("The AUDIO mint does not use the required eight decimals")]
    WrongMintDecimals,
}
