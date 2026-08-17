#![allow(clippy::result_large_err)] // Anchor 0.28's Error is intentionally rich.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::pubkey::PubkeyError;
use anchor_spl::token::{self, Burn, Mint, Token, TokenAccount, Transfer};

pub mod constants;
pub mod error;
pub mod merkle;
pub mod secp;
pub mod state;

use constants::*;
use error::PerformanceRewardsError;
use merkle::{eligible_leaf, reward_leaf, verify_proof};
use secp::{snapshot_commitment_message, verify_preceding_secp256k1_instruction};
use state::*;

declare_id!("GuzBj2tXuqJWu5KqinF2bba5E9Leqq6udebrGhLKboGV");

#[program]
pub mod performance_rewards {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        require_eq!(
            ctx.accounts.audio_mint.decimals,
            8,
            PerformanceRewardsError::WrongMintDecimals
        );
        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.audio_mint = ctx.accounts.audio_mint.key();
        config.claimable_tokens_program = ctx.accounts.claimable_tokens_program.key();
        config.latest_opened_epoch = 0;
        config.has_opened_epoch = false;
        config.last_finalized_epoch = 0;
        config.has_finalized_epoch = false;
        config.current_claim_epoch = 0;
        config.has_current_claim_epoch = false;
        config.total_funded = 0;
        config.total_claimed = 0;
        config.total_expired = 0;
        config.bump = *ctx
            .bumps
            .get("config")
            .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?;
        Ok(())
    }

    pub fn open_first_epoch(ctx: Context<OpenFirstEpoch>, args: OpenEpochArgs) -> Result<()> {
        require!(
            !ctx.accounts.config.has_opened_epoch,
            PerformanceRewardsError::NonSequentialEpoch
        );
        require_eq!(args.id, 0, PerformanceRewardsError::NonSequentialEpoch);
        initialize_epoch(
            &mut ctx.accounts.epoch,
            ctx.accounts.config.key(),
            &args,
            *ctx.bumps
                .get("epoch")
                .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?,
            *ctx.bumps
                .get("epoch_vault")
                .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?,
            Clock::get()?.unix_timestamp,
        )?;
        fund_epoch(
            &ctx.accounts.token_program,
            &ctx.accounts.funder,
            &ctx.accounts.funder_token,
            &ctx.accounts.epoch_vault,
        )?;
        mark_epoch_opened(&mut ctx.accounts.config, args.id)?;
        Ok(())
    }

    pub fn open_epoch(ctx: Context<OpenEpoch>, args: OpenEpochArgs) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(
            config.has_opened_epoch,
            PerformanceRewardsError::NonSequentialEpoch
        );
        let expected_id = config
            .latest_opened_epoch
            .checked_add(1)
            .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?;
        require_eq!(
            args.id,
            expected_id,
            PerformanceRewardsError::NonSequentialEpoch
        );
        require_eq!(
            ctx.accounts.previous_epoch.id,
            config.latest_opened_epoch,
            PerformanceRewardsError::NonSequentialEpoch
        );
        require_eq!(
            args.start_unix,
            ctx.accounts.previous_epoch.end_unix,
            PerformanceRewardsError::NonSequentialEpoch
        );
        require_eq!(
            args.start_block,
            ctx.accounts.previous_epoch.end_block,
            PerformanceRewardsError::NonSequentialEpoch
        );

        initialize_epoch(
            &mut ctx.accounts.epoch,
            ctx.accounts.config.key(),
            &args,
            *ctx.bumps
                .get("epoch")
                .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?,
            *ctx.bumps
                .get("epoch_vault")
                .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?,
            Clock::get()?.unix_timestamp,
        )?;
        fund_epoch(
            &ctx.accounts.token_program,
            &ctx.accounts.funder,
            &ctx.accounts.funder_token,
            &ctx.accounts.epoch_vault,
        )?;
        mark_epoch_opened(&mut ctx.accounts.config, args.id)?;
        Ok(())
    }

    pub fn attest_snapshot(
        ctx: Context<AttestSnapshot>,
        commitment: SnapshotCommitment,
        eligibility: EligibilityProof,
    ) -> Result<()> {
        let epoch = &mut ctx.accounts.epoch;
        require!(
            epoch.status == EpochStatus::Pending,
            PerformanceRewardsError::EpochNotPending
        );
        require!(
            Clock::get()?.unix_timestamp >= epoch.end_unix,
            PerformanceRewardsError::EpochNotEnded
        );
        require_gt!(
            eligibility.weight,
            0,
            PerformanceRewardsError::InvalidWeight
        );

        let leaf = eligible_leaf(
            &eligibility.signer,
            &eligibility.operator,
            eligibility.weight,
        );
        require!(
            verify_proof(leaf, &eligibility.proof, &epoch.eligible_root),
            PerformanceRewardsError::InvalidEligibilityProof
        );
        validate_commitment(epoch.budget, &commitment)?;

        let message = snapshot_commitment_message(
            ctx.program_id,
            &ctx.accounts.config.key(),
            epoch,
            &commitment,
        );
        verify_preceding_secp256k1_instruction(
            &ctx.accounts.instructions.to_account_info(),
            &eligibility.signer,
            &message,
        )?;

        record_attestation(epoch, &commitment, eligibility.weight)?;

        let record = &mut ctx.accounts.attestation;
        record.epoch = epoch.key();
        record.signer = eligibility.signer;
        record.operator = eligibility.operator;
        record.weight = eligibility.weight;
        record.snapshot_root = commitment.root;
        record.bump = *ctx
            .bumps
            .get("attestation")
            .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?;
        Ok(())
    }

    pub fn finalize_first_snapshot(ctx: Context<FinalizeFirstSnapshot>) -> Result<()> {
        require!(
            !ctx.accounts.config.has_finalized_epoch,
            PerformanceRewardsError::NonSequentialFinalization
        );
        require_eq!(
            ctx.accounts.epoch.id,
            0,
            PerformanceRewardsError::NonSequentialFinalization
        );
        validate_finalizable(
            &ctx.accounts.epoch,
            ctx.accounts.epoch_vault.amount,
            Clock::get()?.unix_timestamp,
        )?;
        open_claims(&mut ctx.accounts.config, &mut ctx.accounts.epoch)?;
        Ok(())
    }

    pub fn finalize_snapshot(ctx: Context<FinalizeSnapshot>) -> Result<()> {
        validate_finalization_sequence(
            &ctx.accounts.config,
            &ctx.accounts.previous_epoch,
            &ctx.accounts.epoch,
        )?;
        validate_finalizable(
            &ctx.accounts.epoch,
            ctx.accounts.epoch_vault.amount,
            Clock::get()?.unix_timestamp,
        )?;

        let expected_remaining = ctx
            .accounts
            .previous_epoch
            .budget
            .checked_sub(ctx.accounts.previous_epoch.claimed_amount)
            .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?;
        require!(
            ctx.accounts.previous_vault.amount >= expected_remaining,
            PerformanceRewardsError::VaultBalanceMismatch
        );
        let burn_amount = ctx.accounts.previous_vault.amount;
        if burn_amount > 0 {
            let id_bytes = ctx.accounts.previous_epoch.id.to_be_bytes();
            let bump = [ctx.accounts.previous_epoch.bump];
            let signer_seeds: &[&[u8]] = &[EPOCH_SEED, &id_bytes, &bump];
            token::burn(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Burn {
                        mint: ctx.accounts.audio_mint.to_account_info(),
                        from: ctx.accounts.previous_vault.to_account_info(),
                        authority: ctx.accounts.previous_epoch.to_account_info(),
                    },
                    &[signer_seeds],
                ),
                burn_amount,
            )?;
        }

        let previous = &mut ctx.accounts.previous_epoch;
        previous.expired_amount = expected_remaining;
        previous.status = EpochStatus::Expired;
        ctx.accounts.config.total_expired = ctx
            .accounts
            .config
            .total_expired
            .checked_add(expected_remaining)
            .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?;
        open_claims(&mut ctx.accounts.config, &mut ctx.accounts.epoch)?;
        Ok(())
    }

    pub fn claim(ctx: Context<Claim>, args: ClaimArgs) -> Result<()> {
        let epoch = &ctx.accounts.epoch;
        let new_claimed = validate_claim(&ctx.accounts.config, epoch, &args)?;
        validate_claimable_recipient(
            &ctx.accounts.config,
            &ctx.accounts.audio_mint.key(),
            &ctx.accounts.claimable_base.key(),
            &ctx.accounts.claimable_recipient,
            &args.operator,
        )?;

        let id_bytes = epoch.id.to_be_bytes();
        let bump = [epoch.bump];
        let signer_seeds: &[&[u8]] = &[EPOCH_SEED, &id_bytes, &bump];
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.epoch_vault.to_account_info(),
                    to: ctx.accounts.claimable_recipient.to_account_info(),
                    authority: ctx.accounts.epoch.to_account_info(),
                },
                &[signer_seeds],
            ),
            args.allocation,
        )?;

        ctx.accounts.epoch.claimed_amount = new_claimed;
        ctx.accounts.config.total_claimed = ctx
            .accounts
            .config
            .total_claimed
            .checked_add(args.allocation)
            .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?;
        let record = &mut ctx.accounts.claim_record;
        record.epoch = ctx.accounts.epoch.key();
        record.operator = args.operator;
        record.score = args.score;
        record.allocation = args.allocation;
        record.evidence_hash = args.evidence_hash;
        record.claimed_at = Clock::get()?.unix_timestamp;
        record.bump = *ctx
            .bumps
            .get("claim_record")
            .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, seeds = [CONFIG_SEED], bump, space = Config::SPACE)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub audio_mint: Account<'info, Mint>,
    /// CHECK: Stored immutably and used only for deterministic PDA derivation.
    #[account(executable)]
    pub claimable_tokens_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(args: OpenEpochArgs)]
pub struct OpenFirstEpoch<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = authority, has_one = audio_mint)]
    pub config: Account<'info, Config>,
    pub authority: Signer<'info>,
    #[account(init, payer = funder, seeds = [EPOCH_SEED, &args.id.to_be_bytes()], bump, space = EpochState::SPACE)]
    pub epoch: Account<'info, EpochState>,
    #[account(init, payer = funder, seeds = [VAULT_SEED, &args.id.to_be_bytes()], bump, token::mint = audio_mint, token::authority = epoch)]
    pub epoch_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub funder: Signer<'info>,
    #[account(mut, token::mint = audio_mint, token::authority = funder)]
    pub funder_token: Account<'info, TokenAccount>,
    pub audio_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(args: OpenEpochArgs)]
pub struct OpenEpoch<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = authority, has_one = audio_mint)]
    pub config: Account<'info, Config>,
    pub authority: Signer<'info>,
    #[account(has_one = config)]
    pub previous_epoch: Account<'info, EpochState>,
    #[account(init, payer = funder, seeds = [EPOCH_SEED, &args.id.to_be_bytes()], bump, space = EpochState::SPACE)]
    pub epoch: Account<'info, EpochState>,
    #[account(init, payer = funder, seeds = [VAULT_SEED, &args.id.to_be_bytes()], bump, token::mint = audio_mint, token::authority = epoch)]
    pub epoch_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub funder: Signer<'info>,
    #[account(mut, token::mint = audio_mint, token::authority = funder)]
    pub funder_token: Account<'info, TokenAccount>,
    pub audio_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(commitment: SnapshotCommitment, eligibility: EligibilityProof)]
pub struct AttestSnapshot<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, has_one = config)]
    pub epoch: Account<'info, EpochState>,
    #[account(init, payer = payer, seeds = [ATTESTATION_SEED, epoch.key().as_ref(), &eligibility.signer], bump, space = AttestationRecord::SPACE)]
    pub attestation: Account<'info, AttestationRecord>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Address and contents are validated against the instructions sysvar.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FinalizeFirstSnapshot<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, has_one = config)]
    pub epoch: Account<'info, EpochState>,
    #[account(seeds = [VAULT_SEED, &epoch.id.to_be_bytes()], bump = epoch.vault_bump, token::mint = audio_mint, token::authority = epoch)]
    pub epoch_vault: Account<'info, TokenAccount>,
    #[account(address = config.audio_mint)]
    pub audio_mint: Account<'info, Mint>,
}

#[derive(Accounts)]
pub struct FinalizeSnapshot<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, has_one = config)]
    pub epoch: Account<'info, EpochState>,
    #[account(seeds = [VAULT_SEED, &epoch.id.to_be_bytes()], bump = epoch.vault_bump, token::mint = audio_mint, token::authority = epoch)]
    pub epoch_vault: Account<'info, TokenAccount>,
    #[account(mut, has_one = config)]
    pub previous_epoch: Account<'info, EpochState>,
    #[account(mut, seeds = [VAULT_SEED, &previous_epoch.id.to_be_bytes()], bump = previous_epoch.vault_bump, token::mint = audio_mint, token::authority = previous_epoch)]
    pub previous_vault: Account<'info, TokenAccount>,
    #[account(mut, address = config.audio_mint)]
    pub audio_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
#[instruction(args: ClaimArgs)]
pub struct Claim<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = audio_mint)]
    pub config: Account<'info, Config>,
    #[account(mut, has_one = config)]
    pub epoch: Account<'info, EpochState>,
    #[account(mut, seeds = [VAULT_SEED, &epoch.id.to_be_bytes()], bump = epoch.vault_bump, token::mint = audio_mint, token::authority = epoch)]
    pub epoch_vault: Account<'info, TokenAccount>,
    #[account(init, payer = payer, seeds = [CLAIM_SEED, epoch.key().as_ref(), &args.operator], bump, space = ClaimRecord::SPACE)]
    pub claim_record: Account<'info, ClaimRecord>,
    /// CHECK: Exact PDA is checked in the handler.
    pub claimable_base: UncheckedAccount<'info>,
    #[account(mut, token::mint = audio_mint)]
    pub claimable_recipient: Account<'info, TokenAccount>,
    pub audio_mint: Account<'info, Mint>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

fn initialize_epoch(
    epoch: &mut Account<EpochState>,
    config: Pubkey,
    args: &OpenEpochArgs,
    bump: u8,
    vault_bump: u8,
    now: i64,
) -> Result<()> {
    validate_open_epoch(args, now)?;
    epoch.config = config;
    epoch.id = args.id;
    epoch.start_unix = args.start_unix;
    epoch.end_unix = args.end_unix;
    epoch.start_block = args.start_block;
    epoch.end_block = args.end_block;
    epoch.scoring_version = args.scoring_version;
    epoch.eligible_root = args.eligible_root;
    epoch.total_eligible_weight = args.total_eligible_weight;
    epoch.budget = EPOCH_BUDGET;
    epoch.snapshot_root = [0; 32];
    epoch.total_score = 0;
    epoch.total_allocated = 0;
    epoch.attested_weight = 0;
    epoch.funded_amount = EPOCH_BUDGET;
    epoch.claimed_amount = 0;
    epoch.expired_amount = 0;
    epoch.candidate_set = false;
    epoch.status = EpochStatus::Pending;
    epoch.bump = bump;
    epoch.vault_bump = vault_bump;
    Ok(())
}

fn validate_open_epoch(args: &OpenEpochArgs, now: i64) -> Result<()> {
    let duration = args
        .end_unix
        .checked_sub(args.start_unix)
        .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?;
    require_eq!(
        duration,
        EPOCH_DURATION_SECONDS,
        PerformanceRewardsError::InvalidEpochRange
    );
    require_gte!(
        args.start_unix,
        0,
        PerformanceRewardsError::InvalidEpochRange
    );
    require!(
        args.end_block > args.start_block,
        PerformanceRewardsError::InvalidBlockRange
    );
    require!(
        now >= args.start_unix && now < args.end_unix,
        PerformanceRewardsError::InvalidOpenTime
    );
    require!(
        args.scoring_version != [0; 32]
            && args.eligible_root != [0; 32]
            && args.total_eligible_weight > 0,
        PerformanceRewardsError::InvalidEligibility
    );
    Ok(())
}

fn fund_epoch<'info>(
    token_program: &Program<'info, Token>,
    funder: &Signer<'info>,
    funder_token: &Account<'info, TokenAccount>,
    epoch_vault: &Account<'info, TokenAccount>,
) -> Result<()> {
    token::transfer(
        CpiContext::new(
            token_program.to_account_info(),
            Transfer {
                from: funder_token.to_account_info(),
                to: epoch_vault.to_account_info(),
                authority: funder.to_account_info(),
            },
        ),
        EPOCH_BUDGET,
    )
}

fn mark_epoch_opened(config: &mut Account<Config>, id: u64) -> Result<()> {
    config.latest_opened_epoch = id;
    config.has_opened_epoch = true;
    config.total_funded = config
        .total_funded
        .checked_add(EPOCH_BUDGET)
        .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?;
    Ok(())
}

fn validate_commitment(budget: u64, commitment: &SnapshotCommitment) -> Result<()> {
    require!(
        commitment.root != [0; 32],
        PerformanceRewardsError::InvalidCommitment
    );
    require!(
        commitment.total_allocated <= budget,
        PerformanceRewardsError::InvalidCommitment
    );
    require!(
        commitment.total_score != 0 || commitment.total_allocated == 0,
        PerformanceRewardsError::InvalidCommitment
    );
    Ok(())
}

fn record_attestation(
    epoch: &mut EpochState,
    commitment: &SnapshotCommitment,
    weight: u64,
) -> Result<()> {
    if epoch.candidate_set {
        require!(
            epoch.snapshot_root == commitment.root
                && epoch.total_score == commitment.total_score
                && epoch.total_allocated == commitment.total_allocated,
            PerformanceRewardsError::CompetingSnapshot
        );
    } else {
        epoch.snapshot_root = commitment.root;
        epoch.total_score = commitment.total_score;
        epoch.total_allocated = commitment.total_allocated;
        epoch.candidate_set = true;
    }
    epoch.attested_weight = epoch
        .attested_weight
        .checked_add(weight)
        .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?;
    require!(
        epoch.attested_weight <= epoch.total_eligible_weight,
        PerformanceRewardsError::ArithmeticOverflow
    );
    Ok(())
}

fn has_strict_supermajority(attested: u64, total: u64) -> bool {
    total > 0 && (attested as u128) * 3 > (total as u128) * 2
}

fn validate_finalizable(epoch: &EpochState, vault_amount: u64, now: i64) -> Result<()> {
    require!(
        epoch.status == EpochStatus::Pending,
        PerformanceRewardsError::EpochNotPending
    );
    require!(
        epoch.candidate_set,
        PerformanceRewardsError::InvalidCommitment
    );
    require!(
        now >= epoch.end_unix,
        PerformanceRewardsError::EpochNotEnded
    );
    require!(
        has_strict_supermajority(epoch.attested_weight, epoch.total_eligible_weight),
        PerformanceRewardsError::QuorumNotReached
    );
    require!(
        vault_amount >= epoch.budget,
        PerformanceRewardsError::VaultBalanceMismatch
    );
    Ok(())
}

fn validate_finalization_sequence(
    config: &Config,
    previous: &EpochState,
    current: &EpochState,
) -> Result<()> {
    require!(
        config.has_finalized_epoch && config.has_current_claim_epoch,
        PerformanceRewardsError::NonSequentialFinalization
    );
    let expected = config
        .last_finalized_epoch
        .checked_add(1)
        .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?;
    require_eq!(
        current.id,
        expected,
        PerformanceRewardsError::NonSequentialFinalization
    );
    require_eq!(
        previous.id,
        config.current_claim_epoch,
        PerformanceRewardsError::WrongPreviousEpoch
    );
    require_eq!(
        previous
            .id
            .checked_add(1)
            .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?,
        current.id,
        PerformanceRewardsError::WrongPreviousEpoch
    );
    require!(
        previous.status == EpochStatus::ClaimsOpen,
        PerformanceRewardsError::WrongPreviousEpoch
    );
    Ok(())
}

fn validate_claim(config: &Config, epoch: &EpochState, args: &ClaimArgs) -> Result<u64> {
    require!(
        epoch.status == EpochStatus::ClaimsOpen,
        PerformanceRewardsError::ClaimsNotOpen
    );
    require!(
        config.has_current_claim_epoch && config.current_claim_epoch == epoch.id,
        PerformanceRewardsError::ClaimsNotOpen
    );
    require!(
        args.score > 0 && args.allocation > 0,
        PerformanceRewardsError::ZeroReward
    );
    require!(
        args.scoring_version == epoch.scoring_version,
        PerformanceRewardsError::WrongScoringVersion
    );
    let leaf = reward_leaf(
        epoch.id,
        &args.operator,
        args.score,
        args.allocation,
        &args.scoring_version,
        &args.evidence_hash,
    );
    require!(
        verify_proof(leaf, &args.proof, &epoch.snapshot_root),
        PerformanceRewardsError::InvalidRewardProof
    );
    let new_claimed = epoch
        .claimed_amount
        .checked_add(args.allocation)
        .ok_or_else(|| error!(PerformanceRewardsError::ArithmeticOverflow))?;
    require!(
        new_claimed <= epoch.total_allocated && new_claimed <= epoch.budget,
        PerformanceRewardsError::OverAllocation
    );
    Ok(new_claimed)
}

fn claimable_addresses(
    claimable_tokens_program: &Pubkey,
    mint: &Pubkey,
    operator: &[u8; 20],
) -> Result<(Pubkey, Pubkey)> {
    let (base, _) = Pubkey::find_program_address(&[mint.as_ref()], claimable_tokens_program);
    let seed = bs58::encode(operator).into_string();
    let recipient = Pubkey::create_with_seed(&base, &seed, &anchor_spl::token::ID)
        .map_err(|_: PubkeyError| error!(PerformanceRewardsError::WrongClaimableRecipient))?;
    Ok((base, recipient))
}

fn open_claims(config: &mut Account<Config>, epoch: &mut Account<EpochState>) -> Result<()> {
    epoch.status = EpochStatus::ClaimsOpen;
    config.last_finalized_epoch = epoch.id;
    config.has_finalized_epoch = true;
    config.current_claim_epoch = epoch.id;
    config.has_current_claim_epoch = true;
    Ok(())
}

fn validate_claimable_recipient(
    config: &Config,
    mint: &Pubkey,
    claimable_base: &Pubkey,
    recipient: &Account<TokenAccount>,
    operator: &[u8; 20],
) -> Result<()> {
    let (expected_base, expected_recipient) =
        claimable_addresses(&config.claimable_tokens_program, mint, operator)?;
    require_keys_eq!(
        *claimable_base,
        expected_base,
        PerformanceRewardsError::WrongClaimableRecipient
    );
    require_keys_eq!(
        recipient.key(),
        expected_recipient,
        PerformanceRewardsError::WrongClaimableRecipient
    );
    require_keys_eq!(
        recipient.owner,
        expected_base,
        PerformanceRewardsError::WrongClaimableRecipient
    );
    require_keys_eq!(
        recipient.mint,
        *mint,
        PerformanceRewardsError::WrongClaimableRecipient
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_args() -> OpenEpochArgs {
        OpenEpochArgs {
            id: 0,
            start_unix: 1_000,
            end_unix: 1_000 + EPOCH_DURATION_SECONDS,
            start_block: 1,
            end_block: 2,
            scoring_version: [1; 32],
            eligible_root: [2; 32],
            total_eligible_weight: 100,
        }
    }

    fn config() -> Config {
        Config {
            authority: Pubkey::new_unique(),
            audio_mint: Pubkey::new_unique(),
            claimable_tokens_program: Pubkey::new_unique(),
            latest_opened_epoch: 1,
            has_opened_epoch: true,
            last_finalized_epoch: 0,
            has_finalized_epoch: true,
            current_claim_epoch: 0,
            has_current_claim_epoch: true,
            total_funded: EPOCH_BUDGET * 2,
            total_claimed: 0,
            total_expired: 0,
            bump: 1,
        }
    }

    fn epoch(id: u64) -> EpochState {
        EpochState {
            config: Pubkey::new_unique(),
            id,
            start_unix: 1_000,
            end_unix: 1_000 + EPOCH_DURATION_SECONDS,
            start_block: 1,
            end_block: 2,
            scoring_version: [1; 32],
            eligible_root: [2; 32],
            total_eligible_weight: 100,
            budget: EPOCH_BUDGET,
            snapshot_root: [3; 32],
            total_score: 10,
            total_allocated: EPOCH_BUDGET,
            attested_weight: 67,
            funded_amount: EPOCH_BUDGET,
            claimed_amount: 0,
            expired_amount: 0,
            candidate_set: true,
            status: EpochStatus::Pending,
            bump: 1,
            vault_bump: 2,
        }
    }

    #[test]
    fn validates_every_open_epoch_boundary() {
        let args = open_args();
        assert!(validate_open_epoch(&args, args.start_unix).is_ok());
        assert!(validate_open_epoch(&args, args.end_unix - 1).is_ok());
        assert!(validate_open_epoch(&args, args.start_unix - 1).is_err());
        assert!(validate_open_epoch(&args, args.end_unix).is_err());

        let mut bad = args;
        bad.end_unix -= 1;
        assert!(validate_open_epoch(&bad, bad.start_unix).is_err());
        bad = args;
        bad.end_block = bad.start_block;
        assert!(validate_open_epoch(&bad, bad.start_unix).is_err());
        bad = args;
        bad.start_unix = -1;
        bad.end_unix = EPOCH_DURATION_SECONDS - 1;
        assert!(validate_open_epoch(&bad, 0).is_err());
        bad = args;
        bad.scoring_version = [0; 32];
        assert!(validate_open_epoch(&bad, bad.start_unix).is_err());
        bad = args;
        bad.eligible_root = [0; 32];
        assert!(validate_open_epoch(&bad, bad.start_unix).is_err());
        bad = args;
        bad.total_eligible_weight = 0;
        assert!(validate_open_epoch(&bad, bad.start_unix).is_err());
    }

    #[test]
    fn quorum_is_strictly_greater_than_two_thirds_without_overflow() {
        assert!(!has_strict_supermajority(0, 0));
        assert!(!has_strict_supermajority(66, 100));
        assert!(!has_strict_supermajority(2, 3));
        assert!(has_strict_supermajority(67, 100));
        assert!(has_strict_supermajority(3, 3));
        assert!(has_strict_supermajority(u64::MAX, u64::MAX));
    }

    #[test]
    fn validates_commitment_boundaries() {
        assert!(validate_commitment(
            EPOCH_BUDGET,
            &SnapshotCommitment {
                root: [1; 32],
                total_score: 1,
                total_allocated: EPOCH_BUDGET
            }
        )
        .is_ok());
        assert!(validate_commitment(
            EPOCH_BUDGET,
            &SnapshotCommitment {
                root: [1; 32],
                total_score: 0,
                total_allocated: 0
            }
        )
        .is_ok());
        assert!(validate_commitment(
            EPOCH_BUDGET,
            &SnapshotCommitment {
                root: [0; 32],
                total_score: 1,
                total_allocated: 1
            }
        )
        .is_err());
        assert!(validate_commitment(
            EPOCH_BUDGET,
            &SnapshotCommitment {
                root: [1; 32],
                total_score: 1,
                total_allocated: EPOCH_BUDGET + 1
            }
        )
        .is_err());
        assert!(validate_commitment(
            EPOCH_BUDGET,
            &SnapshotCommitment {
                root: [1; 32],
                total_score: 0,
                total_allocated: 1
            }
        )
        .is_err());
    }

    #[test]
    fn candidate_is_fixed_and_weight_is_checked() {
        let commitment = SnapshotCommitment {
            root: [3; 32],
            total_score: 10,
            total_allocated: 20,
        };
        let mut state = epoch(0);
        state.candidate_set = false;
        state.snapshot_root = [0; 32];
        state.total_score = 0;
        state.total_allocated = 0;
        state.attested_weight = 0;
        assert!(record_attestation(&mut state, &commitment, 40).is_ok());
        assert_eq!(state.snapshot_root, commitment.root);
        assert_eq!(state.attested_weight, 40);
        assert!(record_attestation(&mut state, &commitment, 60).is_ok());
        assert_eq!(state.attested_weight, 100);

        let mut competing = commitment;
        competing.root[0] ^= 1;
        assert!(record_attestation(&mut state, &competing, 0).is_err());

        let mut too_heavy = epoch(0);
        too_heavy.attested_weight = 100;
        assert!(record_attestation(&mut too_heavy, &commitment, 1).is_err());

        let mut overflow = epoch(0);
        overflow.total_eligible_weight = u64::MAX;
        overflow.attested_weight = u64::MAX;
        assert!(record_attestation(&mut overflow, &commitment, 1).is_err());
    }

    #[test]
    fn finalization_requires_every_state_condition() {
        let state = epoch(0);
        assert!(validate_finalizable(&state, EPOCH_BUDGET, state.end_unix).is_ok());

        let mut bad = epoch(0);
        bad.status = EpochStatus::ClaimsOpen;
        assert!(validate_finalizable(&bad, EPOCH_BUDGET, bad.end_unix).is_err());
        bad = epoch(0);
        bad.candidate_set = false;
        assert!(validate_finalizable(&bad, EPOCH_BUDGET, bad.end_unix).is_err());
        bad = epoch(0);
        assert!(validate_finalizable(&bad, EPOCH_BUDGET, bad.end_unix - 1).is_err());
        bad = epoch(0);
        bad.attested_weight = 2;
        bad.total_eligible_weight = 3;
        assert!(validate_finalizable(&bad, EPOCH_BUDGET, bad.end_unix).is_err());
        bad = epoch(0);
        assert!(validate_finalizable(&bad, EPOCH_BUDGET - 1, bad.end_unix).is_err());
    }

    #[test]
    fn later_finalization_is_strictly_sequential() {
        let cfg = config();
        let mut previous = epoch(0);
        previous.status = EpochStatus::ClaimsOpen;
        let current = epoch(1);
        assert!(validate_finalization_sequence(&cfg, &previous, &current).is_ok());

        let mut bad_cfg = config();
        bad_cfg.has_finalized_epoch = false;
        assert!(validate_finalization_sequence(&bad_cfg, &previous, &current).is_err());
        bad_cfg = config();
        bad_cfg.last_finalized_epoch = 1;
        assert!(validate_finalization_sequence(&bad_cfg, &previous, &current).is_err());
        bad_cfg = config();
        bad_cfg.current_claim_epoch = 1;
        assert!(validate_finalization_sequence(&bad_cfg, &previous, &current).is_err());
        let mut bad_previous = epoch(0);
        bad_previous.status = EpochStatus::Expired;
        assert!(validate_finalization_sequence(&cfg, &bad_previous, &current).is_err());
        let skipped = epoch(2);
        assert!(validate_finalization_sequence(&cfg, &previous, &skipped).is_err());
    }

    #[test]
    fn claim_rejects_each_tampered_field_replay_state_and_overallocation() {
        let cfg = config();
        let mut state = epoch(0);
        state.status = EpochStatus::ClaimsOpen;
        let operator = [4; 20];
        let evidence = [5; 32];
        let allocation = 10;
        let score = 9;
        state.snapshot_root = reward_leaf(
            state.id,
            &operator,
            score,
            allocation,
            &state.scoring_version,
            &evidence,
        );
        let args = ClaimArgs {
            operator,
            score,
            allocation,
            scoring_version: state.scoring_version,
            evidence_hash: evidence,
            proof: vec![],
        };
        assert_eq!(validate_claim(&cfg, &state, &args).unwrap(), allocation);

        let mut bad = args.clone();
        bad.operator[0] ^= 1;
        assert!(validate_claim(&cfg, &state, &bad).is_err());
        bad = args.clone();
        bad.score += 1;
        assert!(validate_claim(&cfg, &state, &bad).is_err());
        bad = args.clone();
        bad.allocation += 1;
        assert!(validate_claim(&cfg, &state, &bad).is_err());
        bad = args.clone();
        bad.scoring_version[0] ^= 1;
        assert!(validate_claim(&cfg, &state, &bad).is_err());
        bad = args.clone();
        bad.evidence_hash[0] ^= 1;
        assert!(validate_claim(&cfg, &state, &bad).is_err());
        bad = args.clone();
        bad.proof.push([8; 32]);
        assert!(validate_claim(&cfg, &state, &bad).is_err());
        bad = args.clone();
        bad.score = 0;
        assert!(validate_claim(&cfg, &state, &bad).is_err());
        bad = args.clone();
        bad.allocation = 0;
        assert!(validate_claim(&cfg, &state, &bad).is_err());

        let mut closed = epoch(0);
        closed.snapshot_root = state.snapshot_root;
        closed.status = EpochStatus::Expired;
        assert!(validate_claim(&cfg, &closed, &args).is_err());
        let mut wrong_current = cfg;
        wrong_current.current_claim_epoch = 1;
        assert!(validate_claim(&wrong_current, &state, &args).is_err());
        let mut over = epoch(0);
        over.status = EpochStatus::ClaimsOpen;
        over.snapshot_root = state.snapshot_root;
        over.claimed_amount = over.total_allocated;
        assert!(validate_claim(&config(), &over, &args).is_err());
    }

    #[test]
    fn claimable_addresses_match_legacy_bridge_derivation() {
        let program = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let operator = [7; 20];
        let (base, recipient) = claimable_addresses(&program, &mint, &operator).unwrap();
        let (expected_base, _) = Pubkey::find_program_address(&[mint.as_ref()], &program);
        assert_eq!(base, expected_base);
        assert_eq!(
            recipient,
            Pubkey::create_with_seed(
                &base,
                &bs58::encode(operator).into_string(),
                &anchor_spl::token::ID,
            )
            .unwrap()
        );
        assert_ne!(
            recipient,
            claimable_addresses(&program, &mint, &[8; 20]).unwrap().1
        );
    }
}

#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "Open Audio Performance Rewards",
    project_url: "https://openaudio.org",
    contacts: "email:security@audius.co",
    policy: "",
    preferred_languages: "en",
    source_code: "https://github.com/OpenAudio/solana-programs/tree/main/performance-rewards"
}
