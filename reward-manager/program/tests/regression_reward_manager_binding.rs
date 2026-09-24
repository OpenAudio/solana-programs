#![cfg(feature = "test-bpf")]
//! Regression test for the missing verified_messages <-> reward_manager binding
//! in `evaluate_attestations` (the `Transfer` instruction).
//!
//! `evaluate_attestations` only checked that the program owned the
//! verified_messages account. Every such account is program-owned, so nothing
//! stopped a caller from pairing a victim's verified_messages account with a
//! DIFFERENT, attacker-controlled reward manager and reaching the block that
//! zeroes the victim account's lamports into a caller-chosen payer. That is the
//! rent-drain half of the reported exploit.
//!
//! The fix asserts `verified_messages.reward_manager == reward_manager` (and
//! re-derives the "V_"||id PDA), mirroring what `submit_attestations` already
//! does.
mod utils;

use audius_reward_manager::{instruction, utils::EthereumAddress};
use libsecp256k1::SecretKey;
use rand::Rng;
use solana_program::{instruction::Instruction, instruction::InstructionError};
use solana_program_test::*;
use solana_sdk::{signature::Keypair, signer::Signer, transaction::Transaction};
use std::mem::MaybeUninit;
use utils::*;

#[tokio::test]
/// Settling a victim's verified_messages account against a foreign reward
/// manager must be rejected.
async fn failure_evaluate_with_foreign_reward_manager() {
    let TestConstants {
        reward_manager, // victim reward manager ("A")
        bot_oracle_message,
        oracle_priv_key,
        senders_message,
        mut context,
        transfer_id,
        oracle_derived_address, // A's bot oracle (program-owned)
        recipient_eth_key,
        token_account, // A's token source
        mut rng,
        manager_account,
        recipient_sol_key,
        min_votes,
        mint,
        ..
    } = setup_test_environment().await;

    // --- Populate victim A's verified_messages account legitimately:
    //     min_votes sender attestations + 1 bot-oracle attestation. ---
    let keys: [[u8; 32]; 3] = rng.gen();
    let operators: [EthereumAddress; 3] = rng.gen();
    let mut signers: [solana_program::pubkey::Pubkey; 3] =
        unsafe { MaybeUninit::zeroed().assume_init() };
    for (i, key) in keys.iter().enumerate() {
        signers[i] = create_sender_from(
            &reward_manager,
            &manager_account,
            &mut context,
            key,
            operators[i],
        )
        .await;
    }

    let mut instructions = Vec::<Instruction>::new();
    for item in keys.iter().enumerate() {
        let priv_key = SecretKey::parse(item.1).unwrap();
        instructions.push(new_secp256k1_instruction_2_0(
            &priv_key,
            senders_message.as_ref(),
            (2 * item.0) as u8,
        ));
        instructions.push(
            instruction::submit_attestations(
                &audius_reward_manager::id(),
                &reward_manager.pubkey(),
                &signers[item.0],
                &context.payer.pubkey(),
                transfer_id.to_string(),
            )
            .unwrap(),
        );
    }
    let oracle_sign = new_secp256k1_instruction_2_0(
        &oracle_priv_key,
        bot_oracle_message.as_ref(),
        (keys.len() * 2) as u8,
    );
    instructions.push(oracle_sign);
    instructions.push(
        instruction::submit_attestations(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            &oracle_derived_address,
            &context.payer.pubkey(),
            transfer_id.to_string(),
        )
        .unwrap(),
    );

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    context.banks_client.process_transaction(tx).await.unwrap();

    let verified_messages_account = get_messages_account(&reward_manager, transfer_id);

    // --- Attacker sets up their OWN reward manager ("B"), which is
    //     permissionless (InitRewardManager takes no privileged signer), plus
    //     their OWN bot oracle registered under B. Using B's own oracle (rather
    //     than A's) is what makes this a meaningful regression: on the UNPATCHED
    //     program the existing `bot_oracle.reward_manager == reward_manager`
    //     check then passes, and the call instead fails later in
    //     `assert_valid_attestations` (IncorrectMessages) because A's stored
    //     messages don't reference B's oracle. On the PATCHED program the new
    //     reward-manager binding check fires first and returns InvalidArgument.
    //     So this test passes only when the binding fix is present. ---
    let attacker_reward_manager = Keypair::new();
    let attacker_token_account = Keypair::new();
    init_reward_manager(
        &mut context,
        &attacker_reward_manager,
        &attacker_token_account,
        &mint.pubkey(),
        &manager_account.pubkey(),
        min_votes,
    )
    .await;

    let attacker_oracle_eth: EthereumAddress = rng.gen();
    let attacker_oracle_operator: EthereumAddress = rng.gen();
    create_sender(
        &mut context,
        &attacker_reward_manager.pubkey(),
        &manager_account,
        attacker_oracle_eth,
        attacker_oracle_operator,
    )
    .await;
    let attacker_oracle = get_oracle_address(&attacker_reward_manager, attacker_oracle_eth);

    // --- Attacker calls evaluate_attestations with the VICTIM's
    //     verified_messages account but their OWN reward manager and oracle. ---
    let tx = Transaction::new_signed_with_payer(
        &[instruction::evaluate_attestations(
            &audius_reward_manager::id(),
            &verified_messages_account,        // victim A's account
            &attacker_reward_manager.pubkey(), // attacker's reward manager B
            &token_account.pubkey(),
            &recipient_sol_key.derive.address,
            &attacker_oracle, // attacker's own oracle, registered under B
            &context.payer.pubkey(),
            10_000u64,
            transfer_id.to_string(),
            recipient_eth_key,
        )
        .unwrap()],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    let res = context.banks_client.process_transaction(tx).await;

    // The fix rejects this: assert_account_key(reward_manager, verified_messages
    // .reward_manager) fails with InvalidArgument because the stored reward
    // manager (A) does not match the passed one (B). Single instruction => idx 0.
    assert_instruction_error(res, 0, InstructionError::InvalidArgument);
}
