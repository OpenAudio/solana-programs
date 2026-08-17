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
        assert_eq!(
            hex::encode(hash_pair(&eligible, &reward)),
            "805afe76c9354161245bfcf47f809ba6da198ac05237de516a2e6547d74f2be6"
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

    #[test]
    fn cross_language_odd_leaf_root_and_proofs() {
        let leaves = [
            keccak::hash(b"a").to_bytes(),
            keccak::hash(b"b").to_bytes(),
            keccak::hash(b"c").to_bytes(),
        ];
        assert_eq!(
            hex::encode(leaves[0]),
            "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb"
        );
        assert_eq!(
            hex::encode(leaves[1]),
            "b5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510"
        );
        assert_eq!(
            hex::encode(leaves[2]),
            "0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2"
        );

        let left_parent = hash_pair(&leaves[0], &leaves[1]);
        assert_eq!(
            hex::encode(left_parent),
            "805b21d846b189efaeb0377d6bb0d201b3872a363e607c25088f025b0c6ae1f8"
        );
        let root = hash_pair(&left_parent, &leaves[2]);
        assert_eq!(
            hex::encode(root),
            "5842148bc6ebeb52af882a317c765fccd3ae80589b21a9b8cbf21abb630e46a7"
        );
        assert!(verify_proof(leaves[0], &[leaves[1], leaves[2]], &root));
        assert!(verify_proof(leaves[1], &[leaves[0], leaves[2]], &root));
        assert!(verify_proof(leaves[2], &[left_parent], &root));
        assert!(!verify_proof(leaves[2], &[], &root));
        assert!(!verify_proof(leaves[2], &[left_parent, leaves[0]], &root));
    }

    #[test]
    fn property_sweep_rejects_malformed_proofs() {
        for count in 1..=64usize {
            let leaves: Vec<[u8; 32]> = (0..count)
                .map(|index| {
                    keccak::hashv(&[
                        b"OAP_MERKLE_PROPERTY",
                        &(count as u64).to_be_bytes(),
                        &(index as u64).to_be_bytes(),
                    ])
                    .to_bytes()
                })
                .collect();
            for index in 0..count {
                let (root, proof) = root_and_proof(&leaves, index);
                assert!(verify_proof(leaves[index], &proof, &root));

                let mut bad_leaf = leaves[index];
                bad_leaf[index % 32] ^= 1;
                assert!(!verify_proof(bad_leaf, &proof, &root));

                let mut bad_root = root;
                bad_root[(index * 7) % 32] ^= 1;
                assert!(!verify_proof(leaves[index], &proof, &bad_root));

                if !proof.is_empty() {
                    let mut mutated = proof.clone();
                    mutated[0][0] ^= 1;
                    assert!(!verify_proof(leaves[index], &mutated, &root));
                    assert!(!verify_proof(
                        leaves[index],
                        &proof[..proof.len() - 1],
                        &root
                    ));
                }
                let mut appended = proof.clone();
                appended.push([0xee; 32]);
                assert!(!verify_proof(leaves[index], &appended, &root));
            }
        }
    }

    fn root_and_proof(leaves: &[[u8; 32]], mut index: usize) -> ([u8; 32], Vec<[u8; 32]>) {
        let mut level = leaves.to_vec();
        let mut proof = Vec::new();
        while level.len() > 1 {
            let sibling = index ^ 1;
            if sibling < level.len() {
                proof.push(level[sibling]);
            }
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            for pair in level.chunks(2) {
                next.push(if pair.len() == 1 {
                    pair[0]
                } else {
                    hash_pair(&pair[0], &pair[1])
                });
            }
            index /= 2;
            level = next;
        }
        (level[0], proof)
    }
}
