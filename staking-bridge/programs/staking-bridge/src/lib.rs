use anchor_lang::prelude::*;
use anchor_spl::token::Token;

pub mod constant;
pub mod error;
pub mod raydium;
pub mod wormhole;

use crate::raydium::{
    check_raydium_programs,
    check_raydium_token_accounts,
    check_raydium_pdas,
    swap
};
use crate::wormhole::{
    check_wormhole_programs,
    check_wormhole_token_accounts,
    check_wormhole_pdas,
    approve_wormhole_transfer,
    execute_wormhole_transfer
};

declare_id!("HEDM7Zg7wNVSCWpV4TF7zp6rgj44C43CXnLtpY68V7bV");

#[program]
pub mod staking_bridge {
    use super::*;

    /**
     * Creates the PDA.
     * This instruction can be called by anyone.
     * Immediately returns successfully because Anchor handles
     * the PDA creation via the CreateStakingBridgeBalancePda struct account macros.
     */
    pub fn create_staking_bridge_balance_pda(_ctx: Context<CreateStakingBridgeBalancePda>) -> Result<()> {
        Ok(())
    }

    /**
     * Verifies that correct programs, token accounts, PDAs are being used,
     * and then swaps tokens via the Raydium AMM Program.
     */
    pub fn raydium_swap(
        ctx: Context<RaydiumSwap>,
        amount_in: u64,
        minimum_amount_out: u64,
        vault_nonce: u64,
        staking_bridge_pda_bump: u8
    ) -> Result<()> {
        let accounts = ctx.accounts;
        check_raydium_programs(accounts)?;
        check_raydium_token_accounts(accounts)?;
        check_raydium_pdas(
            accounts,
            vault_nonce
        )?;
        swap(
            accounts,
            amount_in,
            minimum_amount_out,
            staking_bridge_pda_bump
        )?;
        Ok(())
    }

    pub fn post_wormhole_message(
        ctx: Context<PostWormholeMessage>,
        nonce: u32,
        amount: u64,
        config_bump: u8,
        wrapped_mint_bump: u8,
        wrapped_meta_bump: u8,
        authority_signer_bump: u8,
        bridge_config_bump: u8,
        emitter_bump: u8,
        sequence_bump: u8,
        fee_collector_bump: u8,
        staking_bridge_pda_bump: u8,
    ) -> Result<()> {
        let accounts = ctx.accounts;
        check_wormhole_programs(accounts)?;
        check_wormhole_token_accounts(accounts)?;
        check_wormhole_pdas(
            accounts,
            config_bump,
            wrapped_mint_bump,
            wrapped_meta_bump,
            authority_signer_bump,
            bridge_config_bump,
            emitter_bump,
            sequence_bump,
            fee_collector_bump,
        )?;
        approve_wormhole_transfer(
            accounts,
            amount,
            staking_bridge_pda_bump
        )?;
        execute_wormhole_transfer(
            accounts,
            nonce,
            amount,
            staking_bridge_pda_bump
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateStakingBridgeBalancePda<'info> {
    #[account(
        init,
        seeds = [b"staking_bridge".as_ref()],
        payer = payer,
        bump,
        space = 8
    )]
    /// CHECK: This is the PDA owned by this program. This account holds both SOL USDC and SOL AUDIO. It is used to swap between the two tokens. This PDA is also used to transfer SOL AUDIO to ETH AUDIO via the wormhole.
    pub staking_bridge_pda: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(AnchorDeserialize, AnchorSerialize, Default)]
pub struct Amounts {
    pub amount_in: u64,
    pub minimum_amount_out: u64,
}

#[derive(Accounts)]
#[instruction(
  _amount_in: u64,
  _minimum_amount_out: u64,
  _vault_nonce: u64,
  staking_bridge_pda_bump: u8
)]
pub struct RaydiumSwap<'info> {
    /// CHECK: This is the Raydium Liquidity Pool V4 program id. No check necessary.
    pub program_id: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the AMM id for the pool. No check necessary.
    pub amm: UncheckedAccount<'info>,
    #[account()]
    /// CHECK: This is the authority for the pool. No check necessary.
    pub amm_authority: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the open orders account for the pool. No check necessary.
    pub amm_open_orders: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the target orders account for the pool. No check necessary.
    pub amm_target_orders: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the coin token account for the pool. No check necessary.
    pub pool_coin_token_account: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the pc token account for the pool. No check necessary.
    pub pool_pc_token_account: UncheckedAccount<'info>,
    #[account()]
    /// CHECK: This is the Serum DEX program. No check necessary.
    pub serum_program: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the market address. No check necessary.
    pub serum_market: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the bids account for the serum market. No check necessary.
    pub serum_bids: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the asks account for the serum market. No check necessary.
    pub serum_asks: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the event queue for the serum market. No check necessary.
    pub serum_event_queue: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the coin vault for the serum market. No check necessary.
    pub serum_coin_vault_account: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the pc vault for the serum market. No check necessary.
    pub serum_pc_vault_account: UncheckedAccount<'info>,
    #[account()]
    /// CHECK: This is the vault signer for the serum market. No check necessary.
    pub serum_vault_signer: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the SOL USDC token account for the PDA, which is checked by the implementation of this method.
    pub user_source_token_account: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the SOL AUDIO token account for the PDA, which is checked by the implementation of this method.
    pub user_destination_token_account: UncheckedAccount<'info>,
    #[account(
        seeds = [b"staking_bridge".as_ref()],
        bump = staking_bridge_pda_bump
    )]
    /// CHECK: This is the PDA initialized in the CreateStakingBridgeBalancePda instruction.
    pub user_source_owner: UncheckedAccount<'info>,
    pub spl_token_program: Program<'info, Token>,
}

#[derive(AnchorDeserialize, AnchorSerialize, Default)]
pub struct PostWormholeMessageData {
    pub nonce: u32,
    pub amount: u64,
    pub fee: u64,
    pub target_address: [u8; 32],
    pub target_chain: u16,
}

#[derive(Accounts)]
#[instruction(
    _nonce: u32,
    _amount: u64,
    _config_bump: u8,
    _wrapped_mint_bump: u8,
    _wrapped_meta_bump: u8,
    _authority_signer_bump: u8,
    _bridge_config_bump: u8,
    _emitter_bump: u8,
    _sequence_bump: u8,
    _fee_collector_bump: u8,
    staking_bridge_pda_bump: u8
)]
pub struct PostWormholeMessage<'info> {
    /// CHECK: This is the Token Bridge program id
    pub program_id: UncheckedAccount<'info>,
    /// CHECK: This is the Core Bridge program id
    pub bridge_id: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account()]
    /// CHECK: This is the config PDA owned by the Token Bridge
    pub config: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the wrapped mint PDA, which also depends on the origin token chain and origin token address, owned by the Token Bridge
    pub wrapped_mint: UncheckedAccount<'info>,
    #[account()]
    /// CHECK: This is the wrapped meta PDA, which also depends on the wrapped mint, owned by the Token Bridge
    pub wrapped_meta: UncheckedAccount<'info>,
    #[account()]
    /// CHECK: This is the authority signer PDA owned by the Token Bridge
    pub authority_signer: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the bridge PDA owned by the Core Bridge
    pub bridge_config: UncheckedAccount<'info>,
    #[account()]
    /// CHECK: This is the emitter PDA owned by the Token Bridge
    pub emitter: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the sequence PDA, which also depends on the emitter, owned by the Core Bridge
    pub sequence: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the fee collector PDA owned by the Core Bridge
    pub fee_collector: UncheckedAccount<'info>,
    #[account(mut)]
    pub message: Signer<'info>,
    #[account(
        mut,
        seeds = [b"staking_bridge".as_ref()],
        bump = staking_bridge_pda_bump
    )]
    /// CHECK: This is the PDA initialized in the CreateStakingBridgeBalancePda instruction.
    pub from_owner: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: This is the associated token account of the PDA, from which the tokens will be transferred
    pub from: UncheckedAccount<'info>,
    pub clock: Sysvar<'info, Clock>,
    pub rent: Sysvar<'info, Rent>,
    pub spl_token: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}
