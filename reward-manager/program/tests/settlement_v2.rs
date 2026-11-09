#![cfg(feature = "test-bpf")]
mod utils;

use audius_reward_manager::{
    attestation_v2::{self, Claim, Policy},
    instruction::{
        self, EvaluateAttestationsArgs, EvaluateAttestationsV2Args, SetAttestationPolicyArgs,
    },
};
use borsh::BorshDeserialize;
use libsecp256k1::SecretKey;
use solana_program::{instruction::Instruction, program_pack::Pack, system_instruction};
use solana_program_test::tokio;
use solana_sdk::{signature::Signer, transaction::Transaction, transport::TransportError};
use utils::*;

async fn send(
    env: &mut TestConstants<'_>,
    instructions: &[Instruction],
) -> Result<(), TransportError> {
    let tx = Transaction::new_signed_with_payer(
        instructions,
        Some(&env.context.payer.pubkey()),
        &[&env.context.payer],
        env.context.last_blockhash,
    );
    env.context.banks_client.process_transaction(tx).await
}

async fn set_policy(env: &mut TestConstants<'_>, enabled: bool) {
    let instruction = instruction::set_attestation_policy(
        &audius_reward_manager::id(),
        &env.reward_manager.pubkey(),
        &env.manager_account.pubkey(),
        &env.context.payer.pubkey(),
        SetAttestationPolicyArgs {
            chain_domain: [1; 32],
            oracle: env.eth_oracle_address,
            enabled,
        },
    )
    .unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&env.context.payer.pubkey()),
        &[&env.context.payer, &env.manager_account],
        env.context.last_blockhash,
    );
    env.context
        .banks_client
        .process_transaction(tx)
        .await
        .unwrap();
}

async fn staged_claim() -> (TestConstants<'static>, EvaluateAttestationsV2Args) {
    let mut env = setup_test_environment().await;
    let (policy, _) =
        attestation_v2::policy_address(&audius_reward_manager::id(), &env.reward_manager.pubkey());
    // A third party prefunding the PDA must not prevent initialization.
    let prefund = system_instruction::transfer(&env.context.payer.pubkey(), &policy, 1);
    send(&mut env, &[prefund]).await.unwrap();
    set_policy(&mut env, true).await;
    let account = get_account(&mut env.context, &policy).await.unwrap();
    assert_eq!(Policy::try_from_slice(&account.data).unwrap().epoch, 1);
    let claim = Claim {
        chain_domain: [1; 32],
        program: audius_reward_manager::id(),
        reward_manager: env.reward_manager.pubkey(),
        mint: env.mint.pubkey(),
        reward_address: [2; 20],
        recipient: env.recipient_eth_key,
        oracle: env.eth_oracle_address,
        amount: env.tokens_amount,
        epoch: 1,
        valid_until_slot: 100_000,
        disbursement_id: env.transfer_id.into(),
    };
    // Submit separately to stay within transaction size and compute limits.
    for i in 1..=3u8 {
        let key = [i; 32];
        let sender = create_sender_from(
            &env.reward_manager,
            &env.manager_account,
            &mut env.context,
            &key,
            [i; 20],
        )
        .await;
        let signed = new_secp256k1_instruction_2_0(
            &SecretKey::parse(&key).unwrap(),
            &claim.message(attestation_v2::VALIDATOR).unwrap(),
            0,
        );
        let submit = instruction::submit_attestations(
            &audius_reward_manager::id(),
            &env.reward_manager.pubkey(),
            &sender,
            &env.context.payer.pubkey(),
            env.transfer_id.into(),
        )
        .unwrap();
        send(&mut env, &[signed, submit]).await.unwrap();
    }
    let signed = new_secp256k1_instruction_2_0(
        &env.oracle_priv_key,
        &claim.message(attestation_v2::ORACLE).unwrap(),
        0,
    );
    let submit = instruction::submit_attestations(
        &audius_reward_manager::id(),
        &env.reward_manager.pubkey(),
        &env.oracle_derived_address,
        &env.context.payer.pubkey(),
        env.transfer_id.into(),
    )
    .unwrap();
    send(&mut env, &[signed, submit]).await.unwrap();
    let args = EvaluateAttestationsV2Args {
        transfer: EvaluateAttestationsArgs {
            amount: claim.amount,
            id: claim.disbursement_id,
            eth_recipient: claim.recipient,
        },
        reward_address: claim.reward_address,
        epoch: claim.epoch,
        valid_until_slot: claim.valid_until_slot,
    };
    (env, args)
}

fn settle(env: &TestConstants<'_>, args: EvaluateAttestationsV2Args) -> Instruction {
    instruction::evaluate_attestations_v2(
        &audius_reward_manager::id(),
        &get_messages_account(&env.reward_manager, env.transfer_id),
        &env.reward_manager.pubkey(),
        &env.token_account.pubkey(),
        &env.recipient_sol_key.derive.address,
        &env.oracle_derived_address,
        &env.context.payer.pubkey(),
        args,
    )
    .unwrap()
}

#[tokio::test]
async fn bound_claim_settles_once_and_rejects_mutations() {
    let (mut env, args) = staged_claim().await;
    for mutation in 0..4 {
        let mut changed = args.clone();
        match mutation {
            0 => changed.transfer.amount -= 1,
            1 => changed.reward_address[0] ^= 1,
            2 => changed.epoch += 1,
            _ => changed.valid_until_slot += 1,
        }
        let instruction = settle(&env, changed);
        assert!(send(&mut env, &[instruction]).await.is_err());
    }
    let source = get_account(&mut env.context, &env.token_account.pubkey())
        .await
        .unwrap();
    assert_eq!(
        spl_token::state::Account::unpack(&source.data)
            .unwrap()
            .amount,
        env.tokens_amount
    );
    let instruction = settle(&env, args.clone());
    send(&mut env, &[instruction]).await.unwrap();
    let recipient = get_account(&mut env.context, &env.recipient_sol_key.derive.address)
        .await
        .unwrap();
    assert_eq!(
        spl_token::state::Account::unpack(&recipient.data)
            .unwrap()
            .amount,
        env.tokens_amount
    );
    // Vary the transaction so the runtime actually re-executes settlement.
    let instruction = settle(&env, args);
    let noop = system_instruction::transfer(
        &env.context.payer.pubkey(),
        &env.manager_account.pubkey(),
        1,
    );
    assert!(send(&mut env, &[noop, instruction]).await.is_err());
}

#[tokio::test]
async fn policy_update_invalidates_already_submitted_signatures() {
    let (mut env, args) = staged_claim().await;
    set_policy(&mut env, false).await;
    let instruction = settle(&env, args);
    assert!(send(&mut env, &[instruction]).await.is_err());
    let source = get_account(&mut env.context, &env.token_account.pubkey())
        .await
        .unwrap();
    assert_eq!(
        spl_token::state::Account::unpack(&source.data)
            .unwrap()
            .amount,
        env.tokens_amount
    );
}
