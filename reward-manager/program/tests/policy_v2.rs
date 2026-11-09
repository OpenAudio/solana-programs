//! Native authorization regressions; token movement also requires BPF tests.
use audius_reward_manager::{
    attestation_v2::{policy_address, Policy},
    error::AudiusProgramError,
    instruction::{
        EvaluateAttestationsArgs, Instructions, SetAttestationPolicyArgs, SubmitAttestationsArgs,
    },
    processor::Processor,
    state::RewardManager,
};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo, program_error::ProgramError, program_pack::Pack, pubkey::Pubkey,
    system_program, sysvar,
};

fn account(
    key: Pubkey,
    owner: Pubkey,
    signer: bool,
    writable: bool,
    data: Vec<u8>,
) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(key)),
        signer,
        writable,
        Box::leak(Box::new(1_000_000_000)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
        false,
        0,
    )
}

fn fixture() -> (Pubkey, Vec<AccountInfo<'static>>, SetAttestationPolicyArgs) {
    let program = Pubkey::new_unique();
    let manager = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (policy, _) = policy_address(&program, &manager);
    let state = RewardManager::new(Pubkey::new_unique(), authority, 3);
    let mut state_bytes = vec![0; RewardManager::LEN];
    RewardManager::pack(state, &mut state_bytes).unwrap();
    let current = Policy {
        version: 2,
        reward_manager: manager,
        chain_domain: [1; 32],
        oracle: [2; 20],
        epoch: 5,
        enabled: true,
    };
    let accounts = vec![
        account(manager, program, false, false, state_bytes),
        account(authority, system_program::id(), true, false, vec![]),
        account(policy, program, false, true, current.try_to_vec().unwrap()),
        account(
            Pubkey::new_unique(),
            system_program::id(),
            true,
            true,
            vec![],
        ),
        account(
            system_program::id(),
            system_program::id(),
            false,
            false,
            vec![],
        ),
        account(sysvar::rent::id(), sysvar::id(), false, false, vec![]),
    ];
    (
        program,
        accounts,
        SetAttestationPolicyArgs {
            chain_domain: [1; 32],
            oracle: [3; 20],
            enabled: false,
        },
    )
}

fn update(
    program: &Pubkey,
    accounts: &[AccountInfo],
    args: SetAttestationPolicyArgs,
) -> Result<(), ProgramError> {
    Processor::process_instruction(
        program,
        accounts,
        &Instructions::SetAttestationPolicy(args)
            .try_to_vec()
            .unwrap(),
    )
}

#[test]
fn authorized_update_revokes_outstanding_claims() {
    let (program, accounts, args) = fixture();
    update(&program, &accounts, args).unwrap();
    let policy = Policy::try_from_slice(&accounts[2].data.borrow()).unwrap();
    assert_eq!(policy.epoch, 6);
    assert_eq!(policy.oracle, [3; 20]);
    assert!(!policy.enabled);
    assert!(policy.check(accounts[0].key, &[2; 20], 5, 100, 1).is_err());
}

#[test]
fn requires_current_manager_signature() {
    let (program, mut accounts, args) = fixture();
    accounts[1].is_signer = false;
    assert_eq!(
        update(&program, &accounts, args.clone()),
        Err(ProgramError::MissingRequiredSignature)
    );
    accounts[1] = account(
        Pubkey::new_unique(),
        system_program::id(),
        true,
        false,
        vec![],
    );
    assert!(update(&program, &accounts, args).is_err());
}

#[test]
fn rejects_foreign_manager_owner_and_policy_address() {
    for index in [0, 2] {
        let (program, mut accounts, args) = fixture();
        accounts[index].owner = Box::leak(Box::new(Pubkey::new_unique()));
        assert!(update(&program, &accounts, args).is_err());
    }
    let (program, mut accounts, args) = fixture();
    accounts[2].key = Box::leak(Box::new(Pubkey::new_unique()));
    assert!(update(&program, &accounts, args).is_err());
}

#[test]
fn domain_cannot_change_and_epoch_cannot_wrap() {
    let (program, accounts, mut args) = fixture();
    args.chain_domain = [9; 32];
    assert!(update(&program, &accounts, args).is_err());
    let (program, accounts, args) = fixture();
    let mut policy = Policy::try_from_slice(&accounts[2].data.borrow()).unwrap();
    policy.epoch = u64::MAX;
    policy
        .serialize(&mut &mut accounts[2].data.borrow_mut()[..])
        .unwrap();
    assert_eq!(
        update(&program, &accounts, args),
        Err(AudiusProgramError::MathOverflow.into())
    );
}

#[test]
fn legacy_claims_are_disabled_even_without_a_policy() {
    let data = Instructions::EvaluateAttestations(EvaluateAttestationsArgs {
        amount: 1,
        id: "legacy:claim".into(),
        eth_recipient: [1; 20],
    })
    .try_to_vec()
    .unwrap();
    assert_eq!(
        Processor::process_instruction(&Pubkey::new_unique(), &[], &data),
        Err(AudiusProgramError::LegacyAttestationsDisabled.into())
    );
}

#[test]
fn invalid_id_rejected_before_pda_derivation() {
    for id in [String::new(), "x".repeat(31)] {
        let data = Instructions::SubmitAttestations(SubmitAttestationsArgs { id })
            .try_to_vec()
            .unwrap();
        assert_eq!(
            Processor::process_instruction(&Pubkey::new_unique(), &[], &data),
            Err(ProgramError::InvalidArgument)
        );
    }
}
