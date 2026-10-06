# Performance Rewards

This Anchor program distributes an additional fixed pool of 100,000 AUDIO to
Open Audio validator-node operators for each seven-day epoch. Ethereum remains
the identity and registration source. Core computes the performance artifact;
Solana verifies a weighted attestation of that artifact and pays claims through
the existing claimable-token account derivation.

## Lifecycle

1. The immutable config authority opens and funds a pending epoch while its
   time range is active. The epoch fixes an exclusive time range, an exclusive
   block range, a scoring-version hash, a Merkle root of eligible Ethereum
   signer/operator/weight tuples, their total weight, and the fixed budget.
2. After the range ends, eligible Ethereum signers attest one global snapshot
   commitment with Solana's secp256k1 builtin. Eligibility is proven against
   the frozen eligibility root. The first valid attestation fixes the candidate;
   later attestations for a competing root or totals are rejected.
3. Anyone may finalize after strictly more than two thirds of the frozen weight
   attests. Finalizing epoch `N+1` atomically burns the unclaimed balance for
   `N`, records it as expired, closes `N`, and opens claims for `N+1`. Without
   quorum, the pending epoch cannot replace the current claim epoch.
4. A claim proves an operator/score/allocation/version/evidence leaf against the
   finalized root. Its PDA prevents replay and its destination must be the SPL
   token account derived by the configured claimable-token program for that
   exact Ethereum operator.

The config and epoch accounts retain cumulative and per-epoch funded, claimed,
and expired amounts. Direct token donations are burned at expiry but do not
inflate the protocol's recorded expired reward balance.

## Frozen hashes and encoding

All hashes are Keccak-256. Merkle parents hash the lexicographically sorted pair
of child hashes; an odd unpaired node is promoted unchanged. Integers are fixed
width, unsigned, big-endian values. Unix timestamps must be non-negative so the
Go `uint64` and on-chain `i64` encodings are identical.

- eligibility leaf: `OAP_PERFORMANCE_ELIGIBLE_V1 || signer[20] || operator[20] || weight[8]`
- reward leaf: `OAP_PERFORMANCE_REWARD_V1 || epoch[8] || operator[20] || score[8] || allocation[8] || scoring_version[32] || evidence_hash[32]`
- snapshot attestation: `OAP_PERFORMANCE_SNAPSHOT_V1`, program id, config account,
  every frozen epoch field, and the candidate root/total score/total allocation

The Go implementation and the Rust program contain shared golden vectors for
eligibility and reward leaves, sorted pair hashing, odd-leaf promotion, proof
verification, scoring version, evidence, and the full 251-byte snapshot
commitment. Both sides also exercise malformed proofs with property sweeps.

## Core integration boundary

`go-openaudio/pkg/core/performance` contains deterministic V1 scoring, evidence
commitments, allocation, Merkle construction, and the exact bytes to sign.
`cmd/performance-snapshot` is the production batch path: it loads a registered,
versioned finalized-epoch source, verifies mandatory evidence and a weighted
Ethereum-signature quorum over useful-work records, then atomically publishes a
canonical artifact containing the open, attest, finalize, and claim arguments.
Eligible nodes use the same command to validate that artifact and emit their
exact secp256k1 signature plus eligibility proof for a relayer.

Core still does not expose one authoritative per-operator useful-work counter.
The initial production source is therefore an explicitly configured manifest
whose useful-work root must be signed by strictly more than two thirds of the
frozen eligible weight. Missing records, zero opportunity totals, zero evidence
hashes, a different source ID/root, or insufficient signatures abort generation.
This provides a fail-closed collection and storage path without silently
substituting local or unrelated data; a future native consensus counter can
implement the same finalized-source contract without changing on-chain bytes.

The eligibility root is supplied at epoch open by the immutable operational
authority because Solana cannot read Ethereum registration state directly. Its
members and weights are fully committed, disclosed through membership proofs,
and then reused for weighted snapshot quorum. There are deliberately no
governance or configuration-update instructions.

## Verification

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The repository build script uses Solana 1.16.9. Its bundled rustc 1.68 aborts
inside optimized compilation on macOS 26 (a host compiler double-free, including
for unchanged third-party crates). Use the repository's Linux build environment
for the pinned artifact, or Solana 1.18.4+ for a local macOS SBF verification;
neither workaround changes the program's Anchor/Solana dependency versions.
