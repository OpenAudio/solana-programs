#![cfg(feature = "test-bpf")]
//! Regression test for the secp256k1 `message_data_size` under-validation
//! (attestation forgery).
//!
//! The secp256k1 precompile only verifies the signature over
//! `data[message_data_offset .. message_data_offset + message_data_size]`, but
//! the reward manager's message extractors previously read `data[97..]` to the
//! end of the instruction. That let a genuine historical signature be replayed
//! with arbitrary trailing bytes appended, and those attacker-controlled bytes
//! were stored as if they had been signed.
//!
//! The fix (`extract_verified_message`) reads exactly the verified region, so
//! any appended bytes are ignored: a submit with a trailing suffix still
//! succeeds, but the stored message is the genuine signed message only. The
//! attacker therefore cannot inject content (e.g. a different reward id) via
//! the suffix.
mod utils;

use audius_reward_manager::{
    instruction, state::VerifiedMessages, utils::EthereumAddress, vote_message,
};
use libsecp256k1::SecretKey;
use rand::Rng;
use solana_program::program_pack::Pack;
use solana_program_test::*;
use solana_sdk::{signature::Signer, transaction::Transaction};
use utils::*;

#[tokio::test]
/// Unsigned trailing bytes appended after the signed message must be ignored,
/// not treated as part of the signed message.
async fn trailing_bytes_after_signed_message_are_ignored() {
    let TestConstants {
        reward_manager,
        mut context,
        transfer_id,
        mut rng,
        manager_account,
        ..
    } = setup_test_environment().await;

    // Create a single, legitimate sender whose key we control.
    let key: [u8; 32] = rng.gen();
    let operator: EthereumAddress = rng.gen();
    let signer = create_sender_from(
        &reward_manager,
        &manager_account,
        &mut context,
        &key,
        operator,
    )
    .await;

    let priv_key = SecretKey::parse(&key).unwrap();

    // Genuinely sign a short message, then append unsigned trailing bytes.
    // `message_data_size` still covers only `genuine_message`, so the secp256k1
    // precompile verifies the signature and passes. Before the fix the program
    // would store `genuine_message || attacker_suffix`; after the fix it stores
    // only `genuine_message`.
    let genuine_message = b"reward_attestation_v1".to_vec();
    let attacker_suffix = b"_attacker_appended_bytes".to_vec();
    let sender_sign = new_secp256k1_instruction_with_trailing_bytes(
        &priv_key,
        &genuine_message,
        &attacker_suffix,
        0,
    );

    let instructions = vec![
        sender_sign,
        instruction::submit_attestations(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            &signer,
            &context.payer.pubkey(),
            transfer_id.to_string(),
        )
        .unwrap(),
    ];

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    // The submit itself succeeds: the trailing bytes are not signed, but they
    // are silently dropped rather than causing a hard failure.
    context.banks_client.process_transaction(tx).await.unwrap();

    // Read back the stored message and confirm the suffix was stripped.
    let verified_messages_account = get_messages_account(&reward_manager, transfer_id);
    let account = get_account(&mut context, &verified_messages_account)
        .await
        .unwrap();
    let verified_messages = VerifiedMessages::unpack_unchecked(&account.data).unwrap();

    assert_eq!(verified_messages.messages.len(), 1);
    let stored = verified_messages.messages[0].message;

    // Stored message is exactly the genuinely-signed bytes (zero-padded) ...
    assert_eq!(stored, vote_message!(genuine_message));
    // ... and specifically NOT the attacker-extended message.
    let extended = [genuine_message.as_slice(), attacker_suffix.as_slice()].concat();
    assert_ne!(stored, vote_message!(extended));
}
