pub const CONFIG_SEED: &[u8] = b"config";
pub const EPOCH_SEED: &[u8] = b"epoch";
pub const VAULT_SEED: &[u8] = b"vault";
pub const ATTESTATION_SEED: &[u8] = b"attestation";
pub const CLAIM_SEED: &[u8] = b"claim";

pub const EPOCH_DURATION_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const AUDIO_BASE_UNITS_PER_TOKEN: u64 = 100_000_000;
pub const EPOCH_BUDGET: u64 = 100_000 * AUDIO_BASE_UNITS_PER_TOKEN;

pub const ELIGIBLE_LEAF_DOMAIN: &[u8] = b"OAP_PERFORMANCE_ELIGIBLE_V1";
pub const REWARD_LEAF_DOMAIN: &[u8] = b"OAP_PERFORMANCE_REWARD_V1";
pub const SNAPSHOT_COMMITMENT_DOMAIN: &[u8] = b"OAP_PERFORMANCE_SNAPSHOT_V1";

pub const ETH_ADDRESS_LEN: usize = 20;
pub const HASH_LEN: usize = 32;
