use anchor_lang::solana_program::keccak;

use crate::constants::{ELIGIBLE_LEAF_DOMAIN, REWARD_LEAF_DOMAIN};

pub fn eligible_leaf(signer: &[u8; 20], operator: &[u8; 20], weight: u64) -> [u8; 32] {
    keccak::hashv(&[
        ELIGIBLE_LEAF_DOMAIN,
        signer,
        operator,
        &weight.to_be_bytes(),
    ])
    .to_bytes()
}

pub fn reward_leaf(
    epoch_id: u64,
    operator: &[u8; 20],
    score: u64,
    allocation: u64,
    scoring_version: &[u8; 32],
    evidence_hash: &[u8; 32],
) -> [u8; 32] {
    keccak::hashv(&[
        REWARD_LEAF_DOMAIN,
        &epoch_id.to_be_bytes(),
        operator,
        &score.to_be_bytes(),
        &allocation.to_be_bytes(),
        scoring_version,
        evidence_hash,
    ])
    .to_bytes()
}

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let (first, second) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    keccak::hashv(&[first, second]).to_bytes()
}

pub fn verify_proof(leaf: [u8; 32], proof: &[[u8; 32]], root: &[u8; 32]) -> bool {
    proof
        .iter()
        .fold(leaf, |node, sibling| hash_pair(&node, sibling))
        == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_language_eligible_and_reward_golden_vectors() {
        let mut operator = [0u8; 20];
        operator[19] = 1;
        let mut signer = [0u8; 20];
        signer[0] = 0x10;
        signer[19] = 1;
        let eligible = eligible_leaf(&signer, &operator, 10);
        assert_eq!(
            hex::encode(eligible),
            "619efdf3ad4bbfad5ca8e6172aa1247fc27e8e5f91465f570b870ef6b3d8fa54"
        );

        let version: [u8; 32] =
            hex::decode("28823611c1c6d274a4d71ab65ade7629644dfc5be8459c8edceda54ae7d01d2b")
                .unwrap()
                .try_into()
                .unwrap();
        let evidence: [u8; 32] =
            hex::decode("5a8cf5249cbd175c9d782d840b3fc6770dd98c8be6f01db5cfc65ec4eec77751")
                .unwrap()
                .try_into()
                .unwrap();
        let reward = reward_leaf(7, &operator, 6388, 10_000_000_000_000, &version, &evidence);
        assert_eq!(
            hex::encode(reward),
            "810ce6736b0210076f96a10e7f843acfcf0738d5c897d9257aca392826ccc0bd"
        );
    }

    #[test]
    fn sorted_pair_proofs_reject_tampering() {
        let a = keccak::hash(b"a").to_bytes();
        let b = keccak::hash(b"b").to_bytes();
        let root = hash_pair(&a, &b);
        assert!(verify_proof(a, &[b], &root));
        assert!(verify_proof(b, &[a], &root));
        assert!(!verify_proof(keccak::hash(b"c").to_bytes(), &[b], &root));
    }
}
