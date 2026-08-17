#![allow(clippy::too_many_arguments)] // Builders intentionally mirror Anchor account lists.

use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use performance_rewards::{accounts, constants::*, instruction, merkle, secp, state::*, ID};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_sdk::{
    account::Account,
    bpf_loader,
    clock::Clock,
    compute_budget::ComputeBudgetInstruction,
    instruction::Instruction,
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    secp256k1_instruction,
    signature::{Keypair, Signer},
    system_instruction, system_program, sysvar,
    transaction::Transaction,
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};
use std::sync::atomic::{AtomicUsize, Ordering};

static SEND_COUNT: AtomicUsize = AtomicUsize::new(0);

async fn send(
    context: &mut ProgramTestContext,
    instructions: Vec<Instruction>,
    extra_signers: &[&Keypair],
) {
    let blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let mut signers: Vec<&dyn Signer> = vec![&context.payer];
    signers.extend(extra_signers.iter().map(|signer| *signer as &dyn Signer));
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &signers,
        blockhash,
    );
    let send_index = SEND_COUNT.fetch_add(1, Ordering::Relaxed);
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap_or_else(|error| panic!("send {send_index} failed: {error:?}"));
}

async fn send_failing(context: &mut ProgramTestContext, instructions: Vec<Instruction>) {
    let blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap_err();
}

async fn get_anchor_account<T: AccountDeserialize>(
    context: &mut ProgramTestContext,
    address: Pubkey,
) -> T {
    let account = context
        .banks_client
        .get_account(address)
        .await
        .unwrap()
        .unwrap();
    T::try_deserialize(&mut account.data.as_slice()).unwrap()
}

async fn token_amount(context: &mut ProgramTestContext, address: Pubkey) -> u64 {
    let account = context
        .banks_client
        .get_account(address)
        .await
        .unwrap()
        .unwrap();
    TokenAccount::unpack(&account.data).unwrap().amount
}

fn program_instruction(accounts: impl ToAccountMetas, data: impl InstructionData) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts.to_account_metas(None),
        data: data.data(),
    }
}

fn epoch_addresses(id: u64) -> (Pubkey, Pubkey) {
    let bytes = id.to_be_bytes();
    (
        Pubkey::find_program_address(&[EPOCH_SEED, &bytes], &ID).0,
        Pubkey::find_program_address(&[VAULT_SEED, &bytes], &ID).0,
    )
}

fn open_instruction(
    config: Pubkey,
    previous_epoch: Option<Pubkey>,
    epoch: Pubkey,
    vault: Pubkey,
    authority: Pubkey,
    funder_token: Pubkey,
    mint: Pubkey,
    args: OpenEpochArgs,
) -> Instruction {
    if let Some(previous_epoch) = previous_epoch {
        program_instruction(
            accounts::OpenEpoch {
                config,
                authority,
                previous_epoch,
                epoch,
                epoch_vault: vault,
                funder: authority,
                funder_token,
                audio_mint: mint,
                token_program: spl_token::id(),
                system_program: system_program::id(),
                rent: sysvar::rent::id(),
            },
            instruction::OpenEpoch { args },
        )
    } else {
        program_instruction(
            accounts::OpenFirstEpoch {
                config,
                authority,
                epoch,
                epoch_vault: vault,
                funder: authority,
                funder_token,
                audio_mint: mint,
                token_program: spl_token::id(),
                system_program: system_program::id(),
                rent: sysvar::rent::id(),
            },
            instruction::OpenFirstEpoch { args },
        )
    }
}

fn attestation_instructions(
    payer: Pubkey,
    config: Pubkey,
    epoch_address: Pubkey,
    epoch: &EpochState,
    signer_key: &libsecp256k1::SecretKey,
    signer: [u8; 20],
    operator: [u8; 20],
    weight: u64,
    commitment: SnapshotCommitment,
    proof: Vec<[u8; 32]>,
    compute_units: u32,
) -> Vec<Instruction> {
    let attestation =
        Pubkey::find_program_address(&[ATTESTATION_SEED, epoch_address.as_ref(), &signer], &ID).0;
    let message = secp::snapshot_commitment_message(&ID, &config, epoch, &commitment);
    let mut secp_instruction =
        secp256k1_instruction::new_secp256k1_instruction(signer_key, &message);
    // The SDK builder assumes secp is transaction instruction zero. This test
    // prepends a compute-budget instruction, so each self-reference is one.
    secp_instruction.data[3] = 1;
    secp_instruction.data[6] = 1;
    secp_instruction.data[11] = 1;
    vec![
        ComputeBudgetInstruction::set_compute_unit_limit(compute_units),
        secp_instruction,
        program_instruction(
            accounts::AttestSnapshot {
                config,
                epoch: epoch_address,
                attestation,
                payer,
                instructions: sysvar::instructions::id(),
                system_program: system_program::id(),
            },
            instruction::AttestSnapshot {
                commitment,
                eligibility: EligibilityProof {
                    signer,
                    operator,
                    weight,
                    proof,
                },
            },
        ),
    ]
}

#[tokio::test]
async fn full_lifecycle_enforces_quorum_claim_replay_and_expiry() {
    let mint = Keypair::new();
    let funder_token = Keypair::new();
    let wrong_recipient = Keypair::new();
    let claimable_program = Pubkey::new_unique();
    let operator = [3u8; 20];
    let evidence = [4u8; 32];
    let scoring_version = [5u8; 32];
    let signer_key = libsecp256k1::SecretKey::parse(&[7u8; 32]).unwrap();
    let signer_pubkey = libsecp256k1::PublicKey::from_secret_key(&signer_key);
    let signer = secp256k1_instruction::construct_eth_pubkey(&signer_pubkey);
    let weight = 100;
    let eligible_root = merkle::eligible_leaf(&signer, &operator, weight);
    let allocation = EPOCH_BUDGET / 2;
    let reward_root = merkle::reward_leaf(
        0,
        &operator,
        10_000,
        allocation,
        &scoring_version,
        &evidence,
    );

    let claimable_base =
        Pubkey::find_program_address(&[mint.pubkey().as_ref()], &claimable_program).0;
    let claimable_recipient = Pubkey::create_with_seed(
        &claimable_base,
        &bs58::encode(operator).into_string(),
        &spl_token::id(),
    )
    .unwrap();
    let mut recipient_data = vec![0; TokenAccount::LEN];
    TokenAccount::pack(
        TokenAccount {
            mint: mint.pubkey(),
            owner: claimable_base,
            amount: 0,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        },
        &mut recipient_data,
    )
    .unwrap();

    let mut test = ProgramTest::new(
        "performance_rewards",
        ID,
        processor!(performance_rewards::entry),
    );
    test.add_program(
        "spl_token",
        spl_token::id(),
        processor!(spl_token::processor::Processor::process),
    );
    test.add_account(
        claimable_program,
        Account {
            lamports: 1,
            data: vec![],
            owner: bpf_loader::id(),
            executable: true,
            rent_epoch: 0,
        },
    );
    test.add_account(
        claimable_base,
        Account {
            lamports: 1,
            data: vec![],
            owner: claimable_program,
            executable: false,
            rent_epoch: 0,
        },
    );
    test.add_account(
        claimable_recipient,
        Account {
            lamports: 10_000_000,
            data: recipient_data,
            owner: spl_token::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    let mut context = test.start_with_context().await;
    let payer = context.payer.pubkey();
    let rent = context.banks_client.get_rent().await.unwrap();

    send(
        &mut context,
        vec![
            system_instruction::create_account(
                &payer,
                &mint.pubkey(),
                rent.minimum_balance(Mint::LEN),
                Mint::LEN as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_mint(
                &spl_token::id(),
                &mint.pubkey(),
                &payer,
                None,
                8,
            )
            .unwrap(),
        ],
        &[&mint],
    )
    .await;
    send(
        &mut context,
        vec![
            system_instruction::create_account(
                &payer,
                &funder_token.pubkey(),
                rent.minimum_balance(TokenAccount::LEN),
                TokenAccount::LEN as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_account3(
                &spl_token::id(),
                &funder_token.pubkey(),
                &mint.pubkey(),
                &payer,
            )
            .unwrap(),
            spl_token::instruction::mint_to(
                &spl_token::id(),
                &mint.pubkey(),
                &funder_token.pubkey(),
                &payer,
                &[],
                EPOCH_BUDGET * 3,
            )
            .unwrap(),
        ],
        &[&funder_token],
    )
    .await;
    send(
        &mut context,
        vec![
            system_instruction::create_account(
                &payer,
                &wrong_recipient.pubkey(),
                rent.minimum_balance(TokenAccount::LEN),
                TokenAccount::LEN as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_account3(
                &spl_token::id(),
                &wrong_recipient.pubkey(),
                &mint.pubkey(),
                &payer,
            )
            .unwrap(),
        ],
        &[&wrong_recipient],
    )
    .await;

    let config = Pubkey::find_program_address(&[CONFIG_SEED], &ID).0;
    send(
        &mut context,
        vec![program_instruction(
            accounts::Initialize {
                config,
                authority: payer,
                audio_mint: mint.pubkey(),
                claimable_tokens_program: claimable_program,
                system_program: system_program::id(),
            },
            instruction::Initialize {},
        )],
        &[],
    )
    .await;

    let mut clock: Clock = context.banks_client.get_sysvar().await.unwrap();
    let start0 = clock.unix_timestamp.max(0);
    let end0 = start0 + EPOCH_DURATION_SECONDS;
    let (epoch0, vault0) = epoch_addresses(0);
    send(
        &mut context,
        vec![open_instruction(
            config,
            None,
            epoch0,
            vault0,
            payer,
            funder_token.pubkey(),
            mint.pubkey(),
            OpenEpochArgs {
                id: 0,
                start_unix: start0,
                end_unix: end0,
                start_block: 10,
                end_block: 20,
                scoring_version,
                eligible_root,
                total_eligible_weight: weight,
            },
        )],
        &[],
    )
    .await;
    assert_eq!(token_amount(&mut context, vault0).await, EPOCH_BUDGET);

    clock.unix_timestamp = end0;
    context.set_sysvar(&clock);
    send_failing(
        &mut context,
        vec![program_instruction(
            accounts::FinalizeFirstSnapshot {
                config,
                epoch: epoch0,
                epoch_vault: vault0,
                audio_mint: mint.pubkey(),
            },
            instruction::FinalizeFirstSnapshot {},
        )],
    )
    .await;

    let commitment0 = SnapshotCommitment {
        root: reward_root,
        total_score: 10_000,
        total_allocated: allocation,
    };
    let state0: EpochState = get_anchor_account(&mut context, epoch0).await;
    let attest0 = attestation_instructions(
        payer,
        config,
        epoch0,
        &state0,
        &signer_key,
        signer,
        operator,
        weight,
        commitment0,
        vec![],
        300_000,
    );
    send(&mut context, attest0, &[]).await;
    send_failing(
        &mut context,
        attestation_instructions(
            payer,
            config,
            epoch0,
            &state0,
            &signer_key,
            signer,
            operator,
            weight,
            commitment0,
            vec![],
            310_000,
        ),
    )
    .await;
    send(
        &mut context,
        vec![program_instruction(
            accounts::FinalizeFirstSnapshot {
                config,
                epoch: epoch0,
                epoch_vault: vault0,
                audio_mint: mint.pubkey(),
            },
            instruction::FinalizeFirstSnapshot {},
        )],
        &[],
    )
    .await;

    let claim_args = ClaimArgs {
        operator,
        score: 10_000,
        allocation,
        scoring_version,
        evidence_hash: evidence,
        proof: vec![],
    };
    let claim_record =
        Pubkey::find_program_address(&[CLAIM_SEED, epoch0.as_ref(), &operator], &ID).0;
    let claim_accounts = |recipient| accounts::Claim {
        config,
        epoch: epoch0,
        epoch_vault: vault0,
        claim_record,
        claimable_base,
        claimable_recipient: recipient,
        audio_mint: mint.pubkey(),
        payer,
        token_program: spl_token::id(),
        system_program: system_program::id(),
    };
    send_failing(
        &mut context,
        vec![program_instruction(
            claim_accounts(wrong_recipient.pubkey()),
            instruction::Claim {
                args: claim_args.clone(),
            },
        )],
    )
    .await;
    let mut wrong_proof = claim_args.clone();
    wrong_proof.evidence_hash[0] ^= 1;
    send_failing(
        &mut context,
        vec![program_instruction(
            claim_accounts(claimable_recipient),
            instruction::Claim { args: wrong_proof },
        )],
    )
    .await;
    send(
        &mut context,
        vec![program_instruction(
            claim_accounts(claimable_recipient),
            instruction::Claim {
                args: claim_args.clone(),
            },
        )],
        &[],
    )
    .await;
    send_failing(
        &mut context,
        vec![
            ComputeBudgetInstruction::set_compute_unit_limit(310_000),
            program_instruction(
                claim_accounts(claimable_recipient),
                instruction::Claim { args: claim_args },
            ),
        ],
    )
    .await;
    assert_eq!(
        token_amount(&mut context, claimable_recipient).await,
        allocation
    );

    let start1 = end0;
    let end1 = start1 + EPOCH_DURATION_SECONDS;
    let (epoch1, vault1) = epoch_addresses(1);
    send(
        &mut context,
        vec![open_instruction(
            config,
            Some(epoch0),
            epoch1,
            vault1,
            payer,
            funder_token.pubkey(),
            mint.pubkey(),
            OpenEpochArgs {
                id: 1,
                start_unix: start1,
                end_unix: end1,
                start_block: 20,
                end_block: 30,
                scoring_version,
                eligible_root,
                total_eligible_weight: weight,
            },
        )],
        &[],
    )
    .await;
    clock.unix_timestamp = end1;
    context.set_sysvar(&clock);
    let commitment1 = SnapshotCommitment {
        root: [9u8; 32],
        total_score: 0,
        total_allocated: 0,
    };
    let state1: EpochState = get_anchor_account(&mut context, epoch1).await;
    send(
        &mut context,
        attestation_instructions(
            payer,
            config,
            epoch1,
            &state1,
            &signer_key,
            signer,
            operator,
            weight,
            commitment1,
            vec![],
            300_000,
        ),
        &[],
    )
    .await;
    send(
        &mut context,
        vec![program_instruction(
            accounts::FinalizeSnapshot {
                config,
                epoch: epoch1,
                epoch_vault: vault1,
                previous_epoch: epoch0,
                previous_vault: vault0,
                audio_mint: mint.pubkey(),
                token_program: spl_token::id(),
            },
            instruction::FinalizeSnapshot {},
        )],
        &[],
    )
    .await;

    let expired0: EpochState = get_anchor_account(&mut context, epoch0).await;
    assert_eq!(expired0.status, EpochStatus::Expired);
    assert_eq!(expired0.claimed_amount, allocation);
    assert_eq!(expired0.expired_amount, EPOCH_BUDGET - allocation);
    assert_eq!(token_amount(&mut context, vault0).await, 0);
    let cfg: Config = get_anchor_account(&mut context, config).await;
    assert_eq!(cfg.total_funded, EPOCH_BUDGET * 2);
    assert_eq!(cfg.total_claimed, allocation);
    assert_eq!(cfg.total_expired, EPOCH_BUDGET - allocation);
    assert_eq!(cfg.current_claim_epoch, 1);

    let start2 = end1;
    let end2 = start2 + EPOCH_DURATION_SECONDS;
    let (epoch2, vault2) = epoch_addresses(2);
    send(
        &mut context,
        vec![open_instruction(
            config,
            Some(epoch1),
            epoch2,
            vault2,
            payer,
            funder_token.pubkey(),
            mint.pubkey(),
            OpenEpochArgs {
                id: 2,
                start_unix: start2,
                end_unix: end2,
                start_block: 30,
                end_block: 40,
                scoring_version,
                eligible_root,
                total_eligible_weight: weight,
            },
        )],
        &[],
    )
    .await;
    clock.unix_timestamp = end2;
    context.set_sysvar(&clock);
    send_failing(
        &mut context,
        vec![program_instruction(
            accounts::FinalizeSnapshot {
                config,
                epoch: epoch2,
                epoch_vault: vault2,
                previous_epoch: epoch1,
                previous_vault: vault1,
                audio_mint: mint.pubkey(),
                token_program: spl_token::id(),
            },
            instruction::FinalizeSnapshot {},
        )],
    )
    .await;
    let still_open1: EpochState = get_anchor_account(&mut context, epoch1).await;
    assert_eq!(still_open1.status, EpochStatus::ClaimsOpen);
    assert_eq!(token_amount(&mut context, vault1).await, EPOCH_BUDGET);
    let cfg: Config = get_anchor_account(&mut context, config).await;
    assert_eq!(cfg.current_claim_epoch, 1);
    assert_eq!(cfg.total_expired, EPOCH_BUDGET - allocation);
}
