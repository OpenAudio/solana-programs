use anchor_lang::prelude::*;
use anchor_lang::solana_program::{secp256k1_program, sysvar::instructions};

use crate::{
    constants::SNAPSHOT_COMMITMENT_DOMAIN,
    error::PerformanceRewardsError,
    state::{EpochState, SnapshotCommitment},
};

const OFFSETS_SIZE: usize = 11;
const DATA_START: usize = 1 + OFFSETS_SIZE;
const ETH_ADDRESS_OFFSET: usize = DATA_START;
const SIGNATURE_OFFSET: usize = ETH_ADDRESS_OFFSET + 20;
const SIGNATURE_SIZE: usize = 65;
const MESSAGE_OFFSET: usize = SIGNATURE_OFFSET + SIGNATURE_SIZE;

pub fn snapshot_commitment_message(
    program_id: &Pubkey,
    config: &Pubkey,
    epoch: &EpochState,
    commitment: &SnapshotCommitment,
) -> Vec<u8> {
    [
        SNAPSHOT_COMMITMENT_DOMAIN,
        program_id.as_ref(),
        config.as_ref(),
        &epoch.id.to_be_bytes(),
        &epoch.start_unix.to_be_bytes(),
        &epoch.end_unix.to_be_bytes(),
        &epoch.start_block.to_be_bytes(),
        &epoch.end_block.to_be_bytes(),
        &epoch.eligible_root,
        &epoch.total_eligible_weight.to_be_bytes(),
        &epoch.scoring_version,
        &commitment.root,
        &commitment.total_score.to_be_bytes(),
        &commitment.total_allocated.to_be_bytes(),
    ]
    .concat()
}

pub fn verify_preceding_secp256k1_instruction(
    instructions_info: &AccountInfo,
    expected_signer: &[u8; 20],
    expected_message: &[u8],
) -> Result<()> {
    require_keys_eq!(
        *instructions_info.key,
        instructions::ID,
        PerformanceRewardsError::InvalidSecpInstruction
    );
    let current = instructions::load_current_index_checked(instructions_info)
        .map_err(|_| error!(PerformanceRewardsError::InvalidSecpInstruction))?;
    require_gt!(current, 0, PerformanceRewardsError::InvalidSecpInstruction);
    let previous = current - 1;
    require!(
        previous <= u8::MAX as u16,
        PerformanceRewardsError::InvalidSecpInstruction
    );
    let instruction =
        instructions::load_instruction_at_checked(previous as usize, instructions_info)
            .map_err(|_| error!(PerformanceRewardsError::InvalidSecpInstruction))?;
    require_keys_eq!(
        instruction.program_id,
        secp256k1_program::ID,
        PerformanceRewardsError::InvalidSecpInstruction
    );
    validate_secp256k1_data(
        &instruction.data,
        previous as u8,
        expected_signer,
        expected_message,
    )
}

pub fn validate_secp256k1_data(
    data: &[u8],
    instruction_index: u8,
    expected_signer: &[u8; 20],
    expected_message: &[u8],
) -> Result<()> {
    require!(
        data.len() == MESSAGE_OFFSET + expected_message.len(),
        PerformanceRewardsError::InvalidSecpInstruction
    );
    require!(
        data.first() == Some(&1),
        PerformanceRewardsError::InvalidSecpInstruction
    );

    let signature_offset = read_u16(data, 1)? as usize;
    let signature_instruction_index = data[3];
    let eth_address_offset = read_u16(data, 4)? as usize;
    let eth_address_instruction_index = data[6];
    let message_offset = read_u16(data, 7)? as usize;
    let message_size = read_u16(data, 9)? as usize;
    let message_instruction_index = data[11];

    require!(
        signature_instruction_index == instruction_index
            && eth_address_instruction_index == instruction_index
            && message_instruction_index == instruction_index,
        PerformanceRewardsError::InvalidSecpInstruction
    );
    require!(
        signature_offset == SIGNATURE_OFFSET
            && eth_address_offset == ETH_ADDRESS_OFFSET
            && message_offset == MESSAGE_OFFSET
            && message_size == expected_message.len(),
        PerformanceRewardsError::InvalidSecpInstruction
    );
    require!(
        signature_offset + SIGNATURE_SIZE <= data.len(),
        PerformanceRewardsError::InvalidSecpInstruction
    );
    require!(
        data[eth_address_offset..eth_address_offset + 20] == expected_signer[..],
        PerformanceRewardsError::WrongEthSigner
    );
    require!(
        data[message_offset..] == expected_message[..],
        PerformanceRewardsError::WrongSignedMessage
    );
    Ok(())
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .ok_or_else(|| error!(PerformanceRewardsError::InvalidSecpInstruction))?
        .try_into()
        .map_err(|_| error!(PerformanceRewardsError::InvalidSecpInstruction))?;
    Ok(u16::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::EpochStatus;
    use anchor_lang::solana_program::keccak;

    fn valid_data(index: u8, signer: [u8; 20], message: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(MESSAGE_OFFSET + message.len());
        data.push(1);
        data.extend_from_slice(&(SIGNATURE_OFFSET as u16).to_le_bytes());
        data.push(index);
        data.extend_from_slice(&(ETH_ADDRESS_OFFSET as u16).to_le_bytes());
        data.push(index);
        data.extend_from_slice(&(MESSAGE_OFFSET as u16).to_le_bytes());
        data.extend_from_slice(&(message.len() as u16).to_le_bytes());
        data.push(index);
        data.extend_from_slice(&signer);
        data.extend_from_slice(&[7u8; SIGNATURE_SIZE]);
        data.extend_from_slice(message);
        data
    }

    #[test]
    fn validates_exact_self_contained_instruction() {
        let signer = [9u8; 20];
        let message = b"snapshot";
        assert!(
            validate_secp256k1_data(&valid_data(4, signer, message), 4, &signer, message).is_ok()
        );
    }

    #[test]
    fn rejects_every_malformed_field() {
        let signer = [9u8; 20];
        let message = b"snapshot";
        for offset in [0usize, 1, 3, 4, 6, 7, 9, 11] {
            let mut data = valid_data(4, signer, message);
            data[offset] ^= 1;
            assert!(
                validate_secp256k1_data(&data, 4, &signer, message).is_err(),
                "offset {offset}"
            );
        }

        let data = valid_data(4, signer, message);
        assert!(validate_secp256k1_data(&data[..data.len() - 1], 4, &signer, message).is_err());
        assert!(validate_secp256k1_data(&data, 3, &signer, message).is_err());
        assert!(validate_secp256k1_data(&data, 4, &[8u8; 20], message).is_err());
        assert!(validate_secp256k1_data(&data, 4, &signer, b"other___").is_err());
    }

    #[test]
    fn cross_language_commitment_golden_vector() {
        let program_id = Pubkey::new_from_array(core::array::from_fn(|i| i as u8));
        let config = Pubkey::new_from_array(core::array::from_fn(|i| (32 + i) as u8));
        let epoch = EpochState {
            config,
            id: 7,
            start_unix: 1_700_000_000,
            end_unix: 1_700_604_800,
            start_block: 100,
            end_block: 200,
            scoring_version: hex::decode(
                "28823611c1c6d274a4d71ab65ade7629644dfc5be8459c8edceda54ae7d01d2b",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            eligible_root: hex::decode(
                "619efdf3ad4bbfad5ca8e6172aa1247fc27e8e5f91465f570b870ef6b3d8fa54",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            total_eligible_weight: 10,
            budget: 10_000_000_000_000,
            snapshot_root: [0; 32],
            total_score: 0,
            total_allocated: 0,
            attested_weight: 0,
            funded_amount: 10_000_000_000_000,
            claimed_amount: 0,
            expired_amount: 0,
            candidate_set: false,
            status: EpochStatus::Pending,
            bump: 1,
            vault_bump: 2,
        };
        let commitment = SnapshotCommitment {
            root: hex::decode("810ce6736b0210076f96a10e7f843acfcf0738d5c897d9257aca392826ccc0bd")
                .unwrap()
                .try_into()
                .unwrap(),
            total_score: 6388,
            total_allocated: 10_000_000_000_000,
        };
        let message = snapshot_commitment_message(&program_id, &config, &epoch, &commitment);
        assert_eq!(message.len(), 251);
        assert_eq!(
            hex::encode(keccak::hash(&message).to_bytes()),
            "8fd92a4a73c4c1d8a7c54ed18fde09408aca9369b5abc58e8d3fafc628240d93"
        );
    }
}
