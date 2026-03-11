use crate::address;
use crate::merkle::sum_node;
use chrono::{DateTime, Duration, Utc};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use std::io::Write;
use std::sync::LazyLock;
use thiserror::Error;

use crate::encoding::{self, SiaDecodable, SiaEncodable};
use crate::types::{Address, BlockID, ChainIndex, Currency, Hash256, SiacoinOutput, Work};

/// Shared blake2b-256 params for all accumulator hashing. Avoids re-allocating
/// a `Params` struct on every call to `proof_root`, `add_leaves`, etc.
static BLAKE2B_256_PARAMS: LazyLock<blake2b_simd::Params> = LazyLock::new(|| {
    let mut p = blake2b_simd::Params::new();
    p.hash_length(32);
    p
});

pub(crate) const LEAF_HASH_PREFIX: u8 = 0x00;

/// Sentinel value for elements not yet added to the accumulator.
pub const UNASSIGNED_LEAF_INDEX: u64 = 10_101_010_101_010_101_010;

/// Errors that can occur during accumulator operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AccumulatorError {
    /// Multiple leaves share the same accumulator index, indicating corrupted
    /// block data or a bug in element extraction.
    #[error("multiple leaves with same accumulator index {0}")]
    DuplicateLeafIndex(u64),
    /// Tree range underflow: j < i in recompute, indicating corrupted leaf
    /// indices or proof lengths.
    #[error("tree range underflow: i={0}, j={1}")]
    TreeRangeUnderflow(u64, u64),
}

/// HardforkDevAddr contains the parameters for a hardfork that changed
/// the developer address.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkDevAddr {
    pub height: u64,
    pub old_address: Address,
    pub new_address: Address,
}

/// HardforkTax contains the parameters for a hardfork that changed the
/// SiaFund file contract tax calculation.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkTax {
    pub height: u64,
}

/// HardforkStorageProof contains the parameters for a hardfork that changed
/// the leaf selection algorithm for storage proofs.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkStorageProof {
    pub height: u64,
}

/// HardforkOak contains the parameters for the Oak hardfork, which replaced
/// the legacy per-1000-block difficulty adjustment with the continuous "Oak"
/// algorithm. Oak tracks a decayed cumulative time (`OakTime`) and adjusts
/// difficulty each block based on how far actual elapsed time deviates from
/// the ideal schedule anchored at `genesis_timestamp`. `fix_height` marks a
/// subsequent correction that fixed a timestamp-accumulation bug in the
/// original Oak implementation.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkOak {
    pub height: u64,
    pub fix_height: u64,
    pub genesis_timestamp: DateTime<Utc>,
}

/// HardforkASIC contains the parameters for a hardfork that changed the mining algorithm
/// to Blake2B-Sia
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkASIC {
    pub height: u64,
    #[serde(with = "crate::types::utils::nano_second_duration")]
    pub oak_time: Duration,
    pub oak_target: BlockID,
}

/// HardforkFoundation contains the parameters for a hardfork that introduced the Foundation
/// subsidy.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkFoundation {
    pub height: u64,
    pub primary_address: Address,
    pub failsafe_address: Address,
}

/// HardforkV2 contains the parameters for the v2 consensus hardfork.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkV2 {
    pub allow_height: u64,
    pub require_height: u64,
}

/// Network contains consensus parameters that are network-specific.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Network {
    pub name: String,

    pub initial_coinbase: Currency,
    pub minimum_coinbase: Currency,
    pub initial_target: BlockID,
    #[serde(with = "crate::types::utils::nano_second_duration")]
    pub block_interval: Duration,
    pub maturity_delay: u64,

    pub hardfork_dev_addr: HardforkDevAddr,
    pub hardfork_tax: HardforkTax,
    pub hardfork_storage_proof: HardforkStorageProof,
    pub hardfork_oak: HardforkOak,
    #[serde(rename = "hardforkASIC")]
    pub hardfork_asic: HardforkASIC,
    pub hardfork_foundation: HardforkFoundation,
    pub hardfork_v2: HardforkV2,
}

/// Convert a Unix timestamp to a `DateTime<Utc>`. Only called with hardcoded
/// constants, so an out-of-range value would be caught at compile time.
const fn unix_timestamp(secs: i64) -> DateTime<Utc> {
    match DateTime::from_timestamp_secs(secs) {
        Some(t) => t,
        None => panic!("invalid timestamp"),
    }
}

impl Network {
    pub fn mainnet() -> Self {
        Network {
            name: "mainnet".to_string(),
            initial_coinbase: Currency::siacoins(300_000),
            minimum_coinbase: Currency::siacoins(30_000),
            initial_target: BlockID::new([
                0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ]),
            block_interval: Duration::minutes(10),
            maturity_delay: 144,

            hardfork_dev_addr: HardforkDevAddr {
                height: 10000,
                old_address: address!(
                    "7d0c44f7664e2d34e53efde0661a6f628ec9264785ae8e3cd7c973e8d190c3c97b5e3ecbc567"
                ),
                new_address: address!(
                    "f371c70bce9eb8979cd5099f599ec4e4fcb14e0afcf31f9791e03e6496a4c0b358c98279730b"
                ),
            },
            hardfork_tax: HardforkTax { height: 21000 },
            hardfork_storage_proof: HardforkStorageProof { height: 100000 },
            hardfork_oak: HardforkOak {
                height: 135000,
                fix_height: 139000,
                genesis_timestamp: unix_timestamp(1433600000), // June 6th, 2015 @ 2:13pm UTC
            },
            hardfork_asic: HardforkASIC {
                height: 179000,
                oak_time: Duration::seconds(120000),
                oak_target: BlockID::new([
                    0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            },
            hardfork_foundation: HardforkFoundation {
                height: 298000,
                primary_address: address!(
                    "053b2def3cbdd078c19d62ce2b4f0b1a3c5e0ffbeeff01280efb1f8969b2f5bb4fdc680f0807"
                ),
                failsafe_address: address!(
                    "27c22a6c6e6645802a3b8fa0e5374657438ef12716d2205d3e866272de1b644dbabd53d6d560"
                ),
            },
            hardfork_v2: HardforkV2 {
                allow_height: 526000,
                require_height: 530000,
            },
        }
    }

    pub fn zen() -> Self {
        Network {
            name: "zen".to_string(),
            initial_coinbase: Currency::siacoins(300_000),
            minimum_coinbase: Currency::siacoins(300_000),
            initial_target: BlockID::new([
                0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            block_interval: Duration::minutes(10),
            maturity_delay: 144,

            hardfork_dev_addr: HardforkDevAddr {
                height: 1,
                old_address: Address::new([0u8; 32]),
                new_address: Address::new([0u8; 32]),
            },
            hardfork_tax: HardforkTax { height: 2 },
            hardfork_storage_proof: HardforkStorageProof { height: 5 },
            hardfork_oak: HardforkOak {
                height: 10,
                fix_height: 12,
                genesis_timestamp: unix_timestamp(1673600000), // January 13, 2023 @ 08:53 GMT
            },
            hardfork_asic: HardforkASIC {
                height: 20,
                oak_time: Duration::seconds(10000),
                oak_target: BlockID::new([
                    0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            },
            hardfork_foundation: HardforkFoundation {
                height: 30,
                primary_address: address!(
                    "053b2def3cbdd078c19d62ce2b4f0b1a3c5e0ffbeeff01280efb1f8969b2f5bb4fdc680f0807"
                ),
                failsafe_address: Address::new([0u8; 32]),
            },
            hardfork_v2: HardforkV2 {
                allow_height: 40,
                require_height: 50,
            },
        }
    }

    pub fn anagami() -> Self {
        Network {
            name: "anagami".to_string(),
            initial_coinbase: Currency::siacoins(300_000),
            minimum_coinbase: Currency::siacoins(300_000),
            initial_target: BlockID::new([
                0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            block_interval: Duration::minutes(10),
            maturity_delay: 144,

            hardfork_dev_addr: HardforkDevAddr {
                height: 1,
                old_address: Address::new([0u8; 32]),
                new_address: Address::new([0u8; 32]),
            },
            hardfork_tax: HardforkTax { height: 2 },
            hardfork_storage_proof: HardforkStorageProof { height: 5 },
            hardfork_oak: HardforkOak {
                height: 10,
                fix_height: 12,
                genesis_timestamp: unix_timestamp(1724284800), // August 22, 2024 @ 0:00 UTC
            },
            hardfork_asic: HardforkASIC {
                height: 20,
                oak_time: Duration::seconds(10000),
                oak_target: BlockID::new([
                    0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            },
            hardfork_foundation: HardforkFoundation {
                height: 30,
                primary_address: address!(
                    "241352c83da002e61f57e96b14f3a5f8b5de22156ce83b753ea495e64f1affebae88736b2347"
                ),
                failsafe_address: Address::new([0u8; 32]),
            },
            hardfork_v2: HardforkV2 {
                allow_height: 2016,
                require_height: 2016 + 288,
            },
        }
    }
}

fn has_tree_at_height(num_leaves: u64, height: usize) -> bool {
    num_leaves & (1u64 << height) != 0
}

#[derive(PartialEq, Debug, Clone)]
pub struct ElementAccumulator {
    pub num_leaves: u64,
    pub trees: [Hash256; 64],
}

impl Default for ElementAccumulator {
    fn default() -> Self {
        ElementAccumulator {
            num_leaves: 0,
            trees: [Hash256::default(); 64],
        }
    }
}

impl SiaEncodable for ElementAccumulator {
    fn encode<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.num_leaves.encode(w)?;
        for (i, root) in self.trees.iter().enumerate() {
            if has_tree_at_height(self.num_leaves, i) {
                root.encode(w)?;
            }
        }
        Ok(())
    }
}

impl SiaDecodable for ElementAccumulator {
    fn decode<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        let num_leaves = u64::decode(r)?;
        let mut trees = [Hash256::default(); 64];
        for (i, root) in trees.iter_mut().enumerate() {
            if has_tree_at_height(num_leaves, i) {
                let h = Hash256::decode(r)?;
                *root = h;
            }
        }
        Ok(ElementAccumulator { num_leaves, trees })
    }
}

impl Serialize for ElementAccumulator {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ElementAccumulator", 2)?;
        state.serialize_field("numLeaves", &self.num_leaves)?;
        let trees: Vec<Hash256> = self
            .trees
            .iter()
            .enumerate()
            .filter(|(i, _)| has_tree_at_height(self.num_leaves, *i))
            .map(|(_, root)| *root)
            .collect();
        state.serialize_field("trees", &trees)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ElementAccumulator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct InterElementAccumulator {
            num_leaves: u64,
            trees: Vec<Hash256>,
        }

        let inter = InterElementAccumulator::deserialize(deserializer)?;

        if inter.trees.len() != inter.num_leaves.count_ones() as usize {
            return Err(serde::de::Error::custom("invalid number of trees"));
        }

        let mut ea = ElementAccumulator {
            num_leaves: inter.num_leaves,
            trees: [Hash256::default(); 64],
        };
        let mut trees_iter = inter.trees.into_iter();
        for i in 0..64 {
            if has_tree_at_height(ea.num_leaves, i) {
                if let Some(root) = trees_iter.next() {
                    ea.trees[i] = root
                } else {
                    return Err(serde::de::Error::custom("missing tree"));
                }
            }
        }
        Ok(ea)
    }
}

/// State represents the state of the chain as of a particular block.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub index: ChainIndex,
    #[serde(with = "crate::types::utils::timestamp_array")]
    pub prev_timestamps: [DateTime<Utc>; 11],
    pub depth: BlockID,
    pub child_target: BlockID,
    pub siafund_pool: Currency,

    // Oak hardfork state
    #[serde(with = "crate::types::utils::nano_second_duration")]
    pub oak_time: Duration,
    pub oak_target: BlockID,

    // Foundation hardfork state
    pub foundation_primary_address: Address,
    pub foundation_failsafe_address: Address,
    // v2 hardfork state
    pub total_work: Work,
    pub difficulty: Work,
    pub oak_work: Work,
    pub elements: ElementAccumulator,
    pub attestations: u64,
}

impl SiaEncodable for State {
    fn encode<W: std::io::Write>(&self, w: &mut W) -> crate::encoding::Result<()> {
        self.index.encode(w)?;
        let timestamps_count = (self.index.child_height() as usize).min(11);
        self.prev_timestamps
            .iter()
            .take(timestamps_count)
            .try_for_each(|ts| ts.encode(w))?;
        self.depth.encode(w)?;
        self.child_target.encode(w)?;
        self.siafund_pool.encode(w)?;
        self.oak_time.encode(w)?;
        self.oak_target.encode(w)?;
        self.foundation_primary_address.encode(w)?;
        self.foundation_failsafe_address.encode(w)?;
        self.total_work.encode(w)?;
        self.difficulty.encode(w)?;
        self.oak_work.encode(w)?;
        self.elements.encode(w)?;
        self.attestations.encode(w)?;
        Ok(())
    }
}

impl SiaDecodable for State {
    fn decode<R: std::io::Read>(r: &mut R) -> crate::encoding::Result<Self> {
        let index = ChainIndex::decode(r)?;
        let timestamps_count = (index.child_height() as usize).min(11);
        let mut prev_timestamps = [DateTime::UNIX_EPOCH; 11];
        prev_timestamps[..timestamps_count]
            .iter_mut()
            .try_for_each(|ts| -> encoding::Result<()> {
                *ts = DateTime::<Utc>::decode(r)?;
                Ok(())
            })?;
        Ok(State {
            index,
            prev_timestamps,
            depth: BlockID::decode(r)?,
            child_target: BlockID::decode(r)?,
            siafund_pool: Currency::decode(r)?,
            oak_time: Duration::decode(r)?,
            oak_target: BlockID::decode(r)?,
            foundation_primary_address: Address::decode(r)?,
            foundation_failsafe_address: Address::decode(r)?,
            total_work: Work::decode(r)?,
            difficulty: Work::decode(r)?,
            oak_work: Work::decode(r)?,
            elements: ElementAccumulator::decode(r)?,
            attestations: u64::decode(r)?,
        })
    }
}

/// ChainState contains the network parameters and the state of the chain.
/// It is used to determine the consensus rules in effect for a particular block.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct ChainState {
    pub network: Network,
    pub state: State,
}

impl ChainState {
    /// child_height returns the height of the next block
    pub fn child_height(&self) -> u64 {
        self.state.index.child_height()
    }

    /// block_reward returns the reward for mining a child block
    pub fn block_reward(&self) -> Currency {
        let reward = self
            .network
            .initial_coinbase
            .checked_sub(Currency::siacoins(self.child_height()));

        match reward {
            Some(reward) if reward >= self.network.minimum_coinbase => reward,
            _ => self.network.minimum_coinbase,
        }
    }

    /// maturity_height is the height at which outputs created by the child block will "mature" (become spendable).
    pub fn maturity_height(&self) -> u64 {
        self.child_height() + self.network.maturity_delay
    }

    /// siafund_count is the number of siafunds in existence
    pub fn siafund_count(&self) -> u64 {
        10000
    }

    /// ancestor_depth is used to determine the target timestamp in the pre-Oak difficulty adjustment algorithm
    pub fn ancestor_depth(&self) -> u64 {
        1000
    }

    /// Estimates the number of blocks expected in a calendar month.
    pub fn blocks_per_month(&self) -> u64 {
        (Duration::days(365).num_milliseconds()
            / 12
            / self.network.block_interval.num_milliseconds()) as u64
    }

    /// foundation_subsidy returns the Foundation subsidy output for the child block.
    /// If no subsidy is due, returns None.
    pub fn foundation_subsidy(&self) -> Option<SiacoinOutput> {
        if self.child_height() < self.network.hardfork_foundation.height {
            return None;
        }
        let blocks_per_month = self.blocks_per_month();
        if !(self.child_height() - self.network.hardfork_foundation.height)
            .is_multiple_of(blocks_per_month)
        {
            return None;
        }

        // 30,000 SC/month; the first payment at the hardfork block is 12x as a
        // one-time retroactive payment covering the 12 months prior to the hardfork.
        let monthly_subsidy = Currency::siacoins(30000);
        Some(SiacoinOutput {
            value: if self.child_height() == self.network.hardfork_foundation.height {
                monthly_subsidy * Currency::new(12)
            } else {
                monthly_subsidy
            },
            address: self.network.hardfork_foundation.primary_address.clone(),
        })
    }

    pub fn replay_prefix(&self) -> &[u8] {
        if self.state.index.height >= self.network.hardfork_v2.allow_height {
            return &[2];
        } else if self.state.index.height >= self.network.hardfork_foundation.height {
            return &[1];
        } else if self.state.index.height >= self.network.hardfork_asic.height {
            return &[0];
        }
        &[]
    }

    pub fn nonce_factor(&self) -> u64 {
        if self.child_height() < self.network.hardfork_asic.height {
            return 1;
        }
        1009
    }

    pub fn max_block_weight(&self) -> u64 {
        2_000_000
    }
}

// ===========================================================================
// Element Accumulator — state proof tracking
// Ported from go.sia.tech/core/consensus/merkle.go
// ===========================================================================

/// SiaHasher wraps blake2b-256 for computing element hashes using the Sia
/// "hashAll" convention: a distinguisher prefix "sia/<name>|" followed by
/// the concatenated V2 encodings of the arguments.
pub struct SiaHasher {
    state: blake2b_simd::State,
}

impl Default for SiaHasher {
    fn default() -> Self {
        SiaHasher {
            state: BLAKE2B_256_PARAMS.to_state(),
        }
    }
}

impl SiaHasher {
    pub fn write_distinguisher(&mut self, s: &str) {
        self.state.update(b"sia/");
        self.state.update(s.as_bytes());
        self.state.update(b"|");
    }

    /// Encode a value into the hasher. This is infallible because
    /// `SiaHasher`'s `Write` impl always succeeds.
    pub fn encode(&mut self, val: &impl encoding::SiaEncodable) {
        val.encode(self).expect("SiaHasher::write is infallible");
    }

    pub fn finalize(self) -> Hash256 {
        self.state.finalize().into()
    }
}

/// `Write` is infallible for `SiaHasher` — it always succeeds and returns
/// `Ok(buf.len())`. Use [`SiaHasher::encode`] instead of calling
/// `SiaEncodable::encode` directly to avoid manual unwraps.
impl Write for SiaHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.state.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Compute the element hash for a siacoin element.
/// hashAll("leaf/siacoin", id, V2SiacoinOutput{value, address}, maturityHeight)
pub fn siacoin_element_hash(
    id: &crate::types::SiacoinOutputID,
    output: &SiacoinOutput,
    maturity_height: u64,
) -> Hash256 {
    let mut h = SiaHasher::default();
    h.write_distinguisher("leaf/siacoin");
    h.encode(id);
    h.encode(output);
    h.encode(&maturity_height);
    h.finalize()
}

/// Compute the element hash for a siafund element.
/// hashAll("leaf/siafund", id, V2SiafundOutput{value, address}, V2Currency(claimStart))
pub fn siafund_element_hash(
    id: &crate::types::SiafundOutputID,
    output: &crate::types::SiafundOutput,
    claim_start: &Currency,
) -> Hash256 {
    let mut h = SiaHasher::default();
    h.write_distinguisher("leaf/siafund");
    h.encode(id);
    h.encode(output);
    h.encode(claim_start);
    h.finalize()
}

/// Compute the element hash for a v2 file contract element.
/// hashAll("leaf/v2filecontract", id, v2FileContract)
pub fn v2_file_contract_element_hash(
    id: &crate::types::FileContractID,
    contract: &crate::types::v2::FileContract,
) -> Hash256 {
    let mut h = SiaHasher::default();
    h.write_distinguisher("leaf/v2filecontract");
    h.encode(id);
    h.encode(contract);
    h.finalize()
}

/// Compute the element hash for a chain index element.
/// hashAll("leaf/chainindex", id, chainIndex)
pub fn chain_index_element_hash(id: &BlockID, chain_index: &ChainIndex) -> Hash256 {
    let mut h = SiaHasher::default();
    h.write_distinguisher("leaf/chainindex");
    h.encode(id);
    h.encode(chain_index);
    h.finalize()
}

/// Compute the element hash for an attestation element.
/// hashAll("leaf/attestation", id, attestation)
pub fn attestation_element_hash(
    id: &crate::types::AttestationID,
    attestation: &crate::types::v2::Attestation,
) -> Hash256 {
    let mut h = SiaHasher::default();
    h.write_distinguisher("leaf/attestation");
    h.encode(id);
    h.encode(attestation);
    h.finalize()
}

/// An ElementLeaf represents a leaf in the ElementAccumulator Merkle tree.
#[derive(Clone)]
pub struct ElementLeaf {
    pub state_element: crate::types::StateElement,
    pub element_hash: Hash256,
    pub spent: bool,
}

impl ElementLeaf {
    /// Compute the leaf's hash for direct use in the Merkle tree.
    /// 42-byte buffer: [0x00 | element_hash(32) | leaf_index_LE(8) | spent_flag(1)]
    pub fn hash(&self) -> Hash256 {
        let mut buf = [0u8; 42];
        buf[0] = LEAF_HASH_PREFIX;
        buf[1..33].copy_from_slice(self.element_hash.as_ref());
        buf[33..41].copy_from_slice(&self.state_element.leaf_index.to_le_bytes());
        if self.spent {
            buf[41] = 1;
        }
        // HashBytes: blake2b-256 of raw bytes (no prefix)
        let hash = BLAKE2B_256_PARAMS.hash(&buf);
        hash.into()
    }

    /// Compute the root obtained from this leaf and its proof.
    pub fn proof_root(&self) -> Hash256 {
        proof_root(
            self.hash(),
            self.state_element.leaf_index,
            &self.state_element.merkle_proof,
        )
    }
}

/// Compute the Merkle root from a leaf hash, its index, and its proof.
pub fn proof_root(mut root: Hash256, leaf_index: u64, proof: &[Hash256]) -> Hash256 {
    for (i, h) in proof.iter().enumerate() {
        if leaf_index & (1 << i) == 0 {
            root = sum_node(&BLAKE2B_256_PARAMS, &root, h);
        } else {
            root = sum_node(&BLAKE2B_256_PARAMS, h, &root);
        }
    }
    root
}

/// Returns the height at which the proof paths of x and y merge.
/// Equivalent to Go's bits.Len64(x ^ y).
fn merge_height(x: u64, y: u64) -> usize {
    64 - (x ^ y).leading_zeros() as usize
}

/// Clears the n least significant bits of x.
fn clear_bits(x: u64, n: usize) -> u64 {
    if n >= 64 { 0 } else { x & !((1u64 << n) - 1) }
}

/// The result of applying a block to the accumulator. Contains the
/// information needed to update proofs of elements not directly involved
/// in the block.
pub struct ElementApplyUpdate {
    pub updated: [Vec<ElementLeaf>; 64],
    pub tree_growth: [Vec<Hash256>; 64],
    pub old_num_leaves: u64,
    pub num_leaves: u64,
}

impl ElementApplyUpdate {
    /// Update the Merkle proof of an element to incorporate the changes made
    /// by this block. The element's proof must be up-to-date (valid for the
    /// accumulator before this block was applied).
    ///
    /// # Panics
    ///
    /// Panics if the element has `leaf_index == UNASSIGNED_LEAF_INDEX`,
    /// indicating it was never added to the accumulator. This is a caller
    /// bug — only elements returned by `apply_block` (with assigned indices)
    /// should be passed here.
    pub fn update_element_proof(&self, e: &mut crate::types::StateElement) {
        if e.leaf_index == UNASSIGNED_LEAF_INDEX {
            panic!("cannot update an ephemeral element");
        } else if e.leaf_index >= self.old_num_leaves {
            return; // newly-added element
        }
        update_proof(e, &self.updated);
        let mh = merge_height(self.num_leaves, e.leaf_index);
        if mh != e.merkle_proof.len() {
            e.merkle_proof
                .extend_from_slice(&self.tree_growth[e.merkle_proof.len()]);
        }
    }
}

/// Update a single element's proof using the closest updated element in the
/// same tree.
fn update_proof(e: &mut crate::types::StateElement, updated: &[Vec<ElementLeaf>; 64]) {
    let updated_in_tree = &updated[e.merkle_proof.len()];
    if updated_in_tree.is_empty() {
        return;
    }
    let mut best = &updated_in_tree[0];
    for ul in &updated_in_tree[1..] {
        if merge_height(e.leaf_index, ul.state_element.leaf_index)
            < merge_height(e.leaf_index, best.state_element.leaf_index)
        {
            best = ul;
        }
    }

    if best.state_element.leaf_index == e.leaf_index {
        // copy over the updated proof in its entirety
        e.merkle_proof
            .copy_from_slice(&best.state_element.merkle_proof);
    } else {
        // copy over the updated proof above the mergeHeight
        let mh = merge_height(e.leaf_index, best.state_element.leaf_index);
        e.merkle_proof[mh..].copy_from_slice(&best.state_element.merkle_proof[mh..]);
        // at the merge point itself, compute the updated sibling hash
        e.merkle_proof[mh - 1] = proof_root(
            best.hash(),
            best.state_element.leaf_index,
            &best.state_element.merkle_proof[..mh - 1],
        );
    }
}

/// Updates the Merkle proofs of each leaf to reflect the changes in all
/// other leaves, and returns the leaves grouped by tree height.
/// Port of Go updateLeaves (merkle.go:312-380).
fn update_leaves(leaves: &mut [ElementLeaf]) -> Result<[Vec<ElementLeaf>; 64], AccumulatorError> {
    fn recompute(i: u64, j: u64, leaves: &mut [ElementLeaf]) -> Result<Hash256, AccumulatorError> {
        if j <= i {
            return Err(AccumulatorError::TreeRangeUnderflow(i, j));
        }
        let height = (j - i).trailing_zeros() as usize;
        if height == 0 {
            if leaves.len() > 1 {
                return Err(AccumulatorError::DuplicateLeafIndex(
                    leaves[0].state_element.leaf_index,
                ));
            }
            return Ok(leaves[0].hash());
        }
        let mid = (i + j) / 2;
        let split = leaves
            .iter()
            .position(|l| l.state_element.leaf_index >= mid)
            .unwrap_or(leaves.len());
        let (left, right) = leaves.split_at_mut(split);

        let left_root;
        let right_root;

        if left.is_empty() {
            left_root = right[0].state_element.merkle_proof[height - 1];
        } else {
            left_root = recompute(i, mid, left)?;
            for e in right.iter_mut() {
                e.state_element.merkle_proof[height - 1] = left_root;
            }
        }

        if right.is_empty() {
            right_root = left[0].state_element.merkle_proof[height - 1];
        } else {
            right_root = recompute(mid, j, right)?;
            for e in left.iter_mut() {
                e.state_element.merkle_proof[height - 1] = right_root;
            }
        }

        Ok(sum_node(&BLAKE2B_256_PARAMS, &left_root, &right_root))
    }

    // Sort by (proof length, leaf index)
    leaves.sort_by(|a, b| {
        a.state_element
            .merkle_proof
            .len()
            .cmp(&b.state_element.merkle_proof.len())
            .then(a.state_element.leaf_index.cmp(&b.state_element.leaf_index))
    });

    // Group leaves by tree (proof length = tree height)
    let mut trees: [Vec<ElementLeaf>; 64] = std::array::from_fn(|_| Vec::new());
    let mut start = 0;
    while start < leaves.len() {
        let height = leaves[start].state_element.merkle_proof.len();
        let mut end = start;
        while end < leaves.len() && leaves[end].state_element.merkle_proof.len() == height {
            end += 1;
        }
        // Recompute proofs within this tree
        let tree_start = clear_bits(leaves[start].state_element.leaf_index, height);
        let tree_end = tree_start + (1u64 << height);
        recompute(tree_start, tree_end, &mut leaves[start..end])?;
        // Clone leaves into the trees array
        trees[height] = leaves[start..end].to_vec();
        start = end;
    }

    Ok(trees)
}

impl ElementAccumulator {
    /// Add leaves to the accumulator, filling in their Merkle proofs and
    /// returning the new node hashes that extend each existing tree.
    /// Port of Go addLeaves (merkle.go:253-308).
    ///
    /// # Safety invariant
    /// The inner loop iterates over tree heights 0..64. The i64 arithmetic
    /// `1i64 << height` would overflow at height >= 63. This is safe because
    /// the loop only continues while `has_tree_at_height` returns true and
    /// the accumulator has exactly 64 trees — so height is bounded to 0..63.
    /// The debug_assert below documents this invariant.
    pub fn add_leaves(&mut self, leaves: &mut [ElementLeaf]) -> [Vec<Hash256>; 64] {
        let initial_leaves = self.num_leaves;
        let mut tree_growth: [Vec<Hash256>; 64] = std::array::from_fn(|_| Vec::new());

        for i in 0..leaves.len() {
            leaves[i].state_element.leaf_index = self.num_leaves;

            let mut h = leaves[i].hash();
            for height in 0..64 {
                if !has_tree_at_height(self.num_leaves, height) {
                    // No tree at this height; insert the new tree
                    self.trees[height] = h;
                    self.num_leaves += 1;
                    break;
                }
                // Another tree exists at this height. Append roots to proofs.
                debug_assert!(height < 63, "height {height} would overflow 1i64 << height");
                let old_root = self.trees[height];
                self.trees[height] = Hash256::default();
                let start_of_new_tree = i as i64 - (1i64 << height);
                let start_of_old_tree = i as i64 - (1i64 << (height + 1));

                let mut j = i as i64;
                while j > start_of_new_tree && j >= 0 {
                    leaves[j as usize].state_element.merkle_proof.push(old_root);
                    j -= 1;
                }
                while j > start_of_old_tree && j >= 0 {
                    leaves[j as usize].state_element.merkle_proof.push(h);
                    j -= 1;
                }

                // Record growth for existing trees
                let cur_tree_index = (self.num_leaves + 1).wrapping_sub(1u64 << height);
                let prev_tree_index = (self.num_leaves + 1).wrapping_sub(1u64 << (height + 1));
                for bit in 0..64 {
                    if initial_leaves & (1u64 << bit) == 0 {
                        continue;
                    }
                    let tree_start_index = clear_bits(initial_leaves, bit + 1);
                    if tree_start_index >= cur_tree_index {
                        tree_growth[bit].push(old_root);
                    } else if tree_start_index >= prev_tree_index {
                        tree_growth[bit].push(h);
                    }
                }

                // Merge: existing root is left sibling, new hash is right
                h = sum_node(&BLAKE2B_256_PARAMS, &old_root, &h);
            }
        }

        tree_growth
    }

    /// Apply a block's updated and added elements to the accumulator,
    /// producing an ElementApplyUpdate that can be used to update proofs
    /// of tracked elements.
    /// Port of Go applyBlock (merkle.go:384-405).
    pub fn apply_block(
        &mut self,
        updated: &mut [ElementLeaf],
        added: &mut [ElementLeaf],
    ) -> Result<ElementApplyUpdate, AccumulatorError> {
        let updated_trees = update_leaves(updated)?;

        // Update tree roots from recomputed proofs
        for (height, es) in updated_trees.iter().enumerate() {
            if !es.is_empty() {
                self.trees[height] = es[0].proof_root();
            }
        }

        let old_num_leaves = self.num_leaves;
        let tree_growth = self.add_leaves(added);

        // Extend updated elements' proofs with tree growth
        for e in updated.iter_mut() {
            let proof_len = e.state_element.merkle_proof.len();
            e.state_element
                .merkle_proof
                .extend_from_slice(&tree_growth[proof_len]);
        }

        Ok(ElementApplyUpdate {
            updated: updated_trees,
            tree_growth,
            old_num_leaves,
            num_leaves: self.num_leaves,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::types::StateElement;
    use crate::{block_id, hash_256};

    use super::*;
    use chrono::FixedOffset;

    #[test]
    fn test_serialize_network() {
        let test_cases = vec![
            (
                Network::anagami(),
                "{\"name\":\"anagami\",\"initialCoinbase\":\"300000000000000000000000000000\",\"minimumCoinbase\":\"300000000000000000000000000000\",\"initialTarget\":\"0000000100000000000000000000000000000000000000000000000000000000\",\"blockInterval\":600000000000,\"maturityDelay\":144,\"hardforkDevAddr\":{\"height\":1,\"oldAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"newAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hardforkTax\":{\"height\":2},\"hardforkStorageProof\":{\"height\":5},\"hardforkOak\":{\"height\":10,\"fixHeight\":12,\"genesisTimestamp\":\"2024-08-22T00:00:00Z\"},\"hardforkASIC\":{\"height\":20,\"oakTime\":10000000000000,\"oakTarget\":\"0000000100000000000000000000000000000000000000000000000000000000\"},\"hardforkFoundation\":{\"height\":30,\"primaryAddress\":\"241352c83da002e61f57e96b14f3a5f8b5de22156ce83b753ea495e64f1affebae88736b2347\",\"failsafeAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hardforkV2\":{\"allowHeight\":2016,\"requireHeight\":2304}}",
            ),
            (
                Network::mainnet(),
                "{\"name\":\"mainnet\",\"initialCoinbase\":\"300000000000000000000000000000\",\"minimumCoinbase\":\"30000000000000000000000000000\",\"initialTarget\":\"0000000020000000000000000000000000000000000000000000000000000000\",\"blockInterval\":600000000000,\"maturityDelay\":144,\"hardforkDevAddr\":{\"height\":10000,\"oldAddress\":\"7d0c44f7664e2d34e53efde0661a6f628ec9264785ae8e3cd7c973e8d190c3c97b5e3ecbc567\",\"newAddress\":\"f371c70bce9eb8979cd5099f599ec4e4fcb14e0afcf31f9791e03e6496a4c0b358c98279730b\"},\"hardforkTax\":{\"height\":21000},\"hardforkStorageProof\":{\"height\":100000},\"hardforkOak\":{\"height\":135000,\"fixHeight\":139000,\"genesisTimestamp\":\"2015-06-06T14:13:20Z\"},\"hardforkASIC\":{\"height\":179000,\"oakTime\":120000000000000,\"oakTarget\":\"0000000000000000200000000000000000000000000000000000000000000000\"},\"hardforkFoundation\":{\"height\":298000,\"primaryAddress\":\"053b2def3cbdd078c19d62ce2b4f0b1a3c5e0ffbeeff01280efb1f8969b2f5bb4fdc680f0807\",\"failsafeAddress\":\"27c22a6c6e6645802a3b8fa0e5374657438ef12716d2205d3e866272de1b644dbabd53d6d560\"},\"hardforkV2\":{\"allowHeight\":526000,\"requireHeight\":530000}}",
            ),
            (
                Network::zen(),
                "{\"name\":\"zen\",\"initialCoinbase\":\"300000000000000000000000000000\",\"minimumCoinbase\":\"300000000000000000000000000000\",\"initialTarget\":\"0000000100000000000000000000000000000000000000000000000000000000\",\"blockInterval\":600000000000,\"maturityDelay\":144,\"hardforkDevAddr\":{\"height\":1,\"oldAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"newAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hardforkTax\":{\"height\":2},\"hardforkStorageProof\":{\"height\":5},\"hardforkOak\":{\"height\":10,\"fixHeight\":12,\"genesisTimestamp\":\"2023-01-13T08:53:20Z\"},\"hardforkASIC\":{\"height\":20,\"oakTime\":10000000000000,\"oakTarget\":\"0000000100000000000000000000000000000000000000000000000000000000\"},\"hardforkFoundation\":{\"height\":30,\"primaryAddress\":\"053b2def3cbdd078c19d62ce2b4f0b1a3c5e0ffbeeff01280efb1f8969b2f5bb4fdc680f0807\",\"failsafeAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hardforkV2\":{\"allowHeight\":40,\"requireHeight\":50}}",
            ),
        ];

        for (network, expected) in test_cases {
            let serialized = serde_json::to_string(&network).unwrap();
            assert_eq!(expected, serialized, "{} failed", network.name);
            let deserialized: Network = serde_json::from_str(&serialized).unwrap();
            assert_eq!(network, deserialized, "{} failed", network.name);
        }
    }

    #[test]
    fn test_serialize_state() {
        let s = State {
            index: ChainIndex {
                height: 0,
                id: block_id!("0000000000000000000000000000000000000000000000000000000000000000"),
            },
            prev_timestamps: [DateTime::UNIX_EPOCH; 11],
            depth: block_id!("0000000000000000000000000000000000000000000000000000000000000000"),
            child_target: block_id!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ),
            siafund_pool: Currency::zero(),
            oak_time: Duration::zero(),
            oak_target: block_id!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ),
            foundation_primary_address: address!(
                "000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
            ),
            foundation_failsafe_address: address!(
                "000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
            ),
            total_work: Work::zero(),
            difficulty: Work::zero(),
            oak_work: Work::zero(),
            elements: ElementAccumulator {
                num_leaves: 0,
                trees: [Hash256::default(); 64],
            },
            attestations: 0,
        };

        const EMPTY_JSON_STR: &str = "{\"index\":{\"height\":0,\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\"},\"prevTimestamps\":[\"1970-01-01T00:00:00+00:00\",\"1970-01-01T00:00:00+00:00\",\"1970-01-01T00:00:00+00:00\",\"1970-01-01T00:00:00+00:00\",\"1970-01-01T00:00:00+00:00\",\"1970-01-01T00:00:00+00:00\",\"1970-01-01T00:00:00+00:00\",\"1970-01-01T00:00:00+00:00\",\"1970-01-01T00:00:00+00:00\",\"1970-01-01T00:00:00+00:00\",\"1970-01-01T00:00:00+00:00\"],\"depth\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"childTarget\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"siafundPool\":\"0\",\"oakTime\":0,\"oakTarget\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"foundationPrimaryAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"foundationFailsafeAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"totalWork\":\"0\",\"difficulty\":\"0\",\"oakWork\":\"0\",\"elements\":{\"numLeaves\":0,\"trees\":[]},\"attestations\":0}";

        let serialized = serde_json::to_string(&s).unwrap();
        assert_eq!(EMPTY_JSON_STR, serialized);
        let deserialized: State = serde_json::from_str(&serialized).unwrap();
        assert_eq!(s, deserialized);

        const EMPTY_BINARY_STR: &str = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        let mut serialized = Vec::new();
        s.encode(&mut serialized).unwrap();
        assert_eq!(EMPTY_BINARY_STR, hex::encode(serialized.clone()));
        let deserialized = State::decode(&mut &serialized[..]).unwrap();
        assert_eq!(s, deserialized);

        let s = State {
            index: ChainIndex {
                height: 16173070238323073115,
                id: block_id!("54b6800181215b654a2b64e8a0f39da6d5ad20f4e6eda87d50d36e93efd9cdb9"),
            },
            prev_timestamps: [
                DateTime::<FixedOffset>::parse_from_rfc3339("2167-03-18T17:08:40-07:00")
                    .unwrap()
                    .to_utc(),
                DateTime::<FixedOffset>::parse_from_rfc3339("1971-03-30T07:40:44-08:00")
                    .unwrap()
                    .to_utc(),
                DateTime::<FixedOffset>::parse_from_rfc3339("2226-11-12T19:51:30-08:00")
                    .unwrap()
                    .to_utc(),
                DateTime::<FixedOffset>::parse_from_rfc3339("2013-09-10T15:07:20-07:00")
                    .unwrap()
                    .to_utc(),
                DateTime::<FixedOffset>::parse_from_rfc3339("2230-05-18T20:13:07-07:00")
                    .unwrap()
                    .to_utc(),
                DateTime::<FixedOffset>::parse_from_rfc3339("1983-10-27T20:37:21-07:00")
                    .unwrap()
                    .to_utc(),
                DateTime::<FixedOffset>::parse_from_rfc3339("2068-03-31T10:25:10-07:00")
                    .unwrap()
                    .to_utc(),
                DateTime::<FixedOffset>::parse_from_rfc3339("2159-06-29T18:46:49-07:00")
                    .unwrap()
                    .to_utc(),
                DateTime::<FixedOffset>::parse_from_rfc3339("2089-05-02T23:45:50-07:00")
                    .unwrap()
                    .to_utc(),
                DateTime::<FixedOffset>::parse_from_rfc3339("2073-02-27T00:01:11-08:00")
                    .unwrap()
                    .to_utc(),
                DateTime::<FixedOffset>::parse_from_rfc3339("2005-07-10T11:50:37-07:00")
                    .unwrap()
                    .to_utc(),
            ],
            depth: block_id!("fb66f6dd0517bd80a57c6fc1dd186eeb25a5f7dc550adc94a996731734f4a478"),
            child_target: block_id!(
                "188d65bc61f7398757be167c70139bc79e2f387551bd0338b81f3938850033c2"
            ),
            siafund_pool: Currency::new(184937863921143879963732603265618430015),
            oak_time: Duration::nanoseconds(5097318764767379519),
            oak_target: block_id!(
                "5e7e960e017d5772f3341bd8d80fc797de245c760a3f9e84f4da66f9e0ee95aa"
            ),
            foundation_primary_address: address!(
                "95ae9eb00188ade3367e57e5bdc522a16e95a8d28e1b940d2d128273aa7a833001a060dec431"
            ),
            foundation_failsafe_address: address!(
                "cfb49736296ae52965fd7d66d55720eeadfc2be586db65699050bce175c56056d3fbc1803e15"
            ),
            total_work: Work::from_dec_str(
                "74729819229046869798018345563024899883189146032533830356652983039509219541660",
            )
            .unwrap(),
            difficulty: Work::from_dec_str(
                "65194889020289389878379369533805235500859175566680960159551424936807420310662",
            )
            .unwrap(),
            oak_work: Work::from_dec_str(
                "57256974569838769713335634640292932580615837804690422146878608831130432685755",
            )
            .unwrap(),
            elements: ElementAccumulator {
                num_leaves: 4899977171010125798,
                trees: [
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("78a9fabda865dafcaf474d48bdb1272595513cf92290917392ff58ca8bea591a"),
                    hash_256!("e6a5ea278d90592e0518fbf2e83f41507486fe57e8e4ffbe152f13250df696bf"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("2488cae3f7046f8b04aec217a09358db22d8ae36f883d1ccae9382edca79c54e"),
                    hash_256!("e498f1adbe88c58bc9dabf487437b8d191a78fbb3d8cfe19a4c1759ae232b4f4"),
                    hash_256!("96130e35228422970057745ef4b92d285434c25187c44110922554d0ae040678"),
                    hash_256!("44f29b39d6e4f509d5d41834db4fd6a831ccca33bb46185a5ad01f2789581337"),
                    hash_256!("75f0b42f9d291c4ff4e57f403893e0ca18fdc64f0723e0f29b6aeed834db1ac2"),
                    hash_256!("4ce129d69c69971497c556d9eeec0de8c1dd9cc4b0750be9fffd9ec3226ce7a3"),
                    hash_256!("f3321bf48aed89100db44b3080f3f350d10b6de213527b19ad57bdd1cd47576a"),
                    hash_256!("724c8bf4c8459625190ae18b2fc1d9353d2d3b34c80d4d4fbcd48258c9a11c97"),
                    hash_256!("062b2371de9dfad15931a1e72c46afe492ad697447680ea43300ed516bcc2742"),
                    hash_256!("b23ca0a83b0367755e2c53c1f7ed9e6d372c220ae0f344082cf5d52c40287893"),
                    hash_256!("9b1b446dd599fd5dab08e83738b92651d8aaa7be072db313d237c68ce1094ea1"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("a03c962c184055ccbf7a42c9a13a0d4c38125535a830832a6fff3029d6deada3"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("df5d9e1e3a220d2429f9064adecb86ecae916619c93e17d237b5972692e558fd"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("2d6315b7a91d62bd31e4738259f56f58075bd14ee2f1e2625738f506a7564176"),
                    hash_256!("26b1d48ab8c3f0707bd5afdf4a3ef757abc9b6a0be75b8a3cecbcd5994473a72"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("f897c92aca8d6ef46a41a3a50aff0527bd09be029355d28c2360ec9cb309b1ae"),
                    hash_256!("f80ff7cbcad8c465278a59588a3a0d000cc3130e96fb56d257229c1a50d93125"),
                    hash_256!("7a84f42433ecd9352e2ffd8bdc8556c87ec93697cf4c4873d4ab51d2b85c44c1"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("00c03e0af90a26d0a4bb4b243f99b2d361de2412d82f357f6224eceb2f19c142"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("e0a8f77abd726e928580656d7ab49dc276603e936e04b9caf53a2a27338e3cd1"),
                    hash_256!("e376ebd2f0c93013cf6c856fb76e7b60e64a300a9a4b839844074cac4da42b8d"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("5fcc77f29cfdb51aac9fff250e1ee7607457ce5a280e946150931d793272593a"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("ad34b2dce6a7136584c5ffea74c66e5613593dddac9eb666ff6a6aef42386968"),
                    hash_256!("3d1afa6b931fea014211bb6b08d9508389dd0a9c47a25670ca110bcc8ce8ead1"),
                    hash_256!("df427b938f6ef07cd67da1ab11ad8fb4e6b0a97c03325c1fc8b1c3b0c4b8f7f4"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("8c3d435fdb6ee44e26155c116a86f4dc2b54b05becb08777a63e1d1ad7c3cbc2"),
                    hash_256!("11671f5bd2856de1b4925ee0b82f9cda6179db132c9930431d26f0ccdbb8a822"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("19dcd3ac59669e10420b36d4e588206ae123a0c8ae64b20e1ede697efc556291"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                    hash_256!("65542a8b2c1bca8d78d6517357853c1d54f6b53f04a8327f28ae2d5d022c5597"),
                    hash_256!("0000000000000000000000000000000000000000000000000000000000000000"),
                ],
            },
            attestations: 4796228701811883082,
        };

        const JSON_STR: &str = "{\"index\":{\"height\":16173070238323073115,\"id\":\"54b6800181215b654a2b64e8a0f39da6d5ad20f4e6eda87d50d36e93efd9cdb9\"},\"prevTimestamps\":[\"2167-03-19T00:08:40+00:00\",\"1971-03-30T15:40:44+00:00\",\"2226-11-13T03:51:30+00:00\",\"2013-09-10T22:07:20+00:00\",\"2230-05-19T03:13:07+00:00\",\"1983-10-28T03:37:21+00:00\",\"2068-03-31T17:25:10+00:00\",\"2159-06-30T01:46:49+00:00\",\"2089-05-03T06:45:50+00:00\",\"2073-02-27T08:01:11+00:00\",\"2005-07-10T18:50:37+00:00\"],\"depth\":\"fb66f6dd0517bd80a57c6fc1dd186eeb25a5f7dc550adc94a996731734f4a478\",\"childTarget\":\"188d65bc61f7398757be167c70139bc79e2f387551bd0338b81f3938850033c2\",\"siafundPool\":\"184937863921143879963732603265618430015\",\"oakTime\":5097318764767379519,\"oakTarget\":\"5e7e960e017d5772f3341bd8d80fc797de245c760a3f9e84f4da66f9e0ee95aa\",\"foundationPrimaryAddress\":\"95ae9eb00188ade3367e57e5bdc522a16e95a8d28e1b940d2d128273aa7a833001a060dec431\",\"foundationFailsafeAddress\":\"cfb49736296ae52965fd7d66d55720eeadfc2be586db65699050bce175c56056d3fbc1803e15\",\"totalWork\":\"74729819229046869798018345563024899883189146032533830356652983039509219541660\",\"difficulty\":\"65194889020289389878379369533805235500859175566680960159551424936807420310662\",\"oakWork\":\"57256974569838769713335634640292932580615837804690422146878608831130432685755\",\"elements\":{\"numLeaves\":4899977171010125798,\"trees\":[\"78a9fabda865dafcaf474d48bdb1272595513cf92290917392ff58ca8bea591a\",\"e6a5ea278d90592e0518fbf2e83f41507486fe57e8e4ffbe152f13250df696bf\",\"2488cae3f7046f8b04aec217a09358db22d8ae36f883d1ccae9382edca79c54e\",\"e498f1adbe88c58bc9dabf487437b8d191a78fbb3d8cfe19a4c1759ae232b4f4\",\"96130e35228422970057745ef4b92d285434c25187c44110922554d0ae040678\",\"44f29b39d6e4f509d5d41834db4fd6a831ccca33bb46185a5ad01f2789581337\",\"75f0b42f9d291c4ff4e57f403893e0ca18fdc64f0723e0f29b6aeed834db1ac2\",\"4ce129d69c69971497c556d9eeec0de8c1dd9cc4b0750be9fffd9ec3226ce7a3\",\"f3321bf48aed89100db44b3080f3f350d10b6de213527b19ad57bdd1cd47576a\",\"724c8bf4c8459625190ae18b2fc1d9353d2d3b34c80d4d4fbcd48258c9a11c97\",\"062b2371de9dfad15931a1e72c46afe492ad697447680ea43300ed516bcc2742\",\"b23ca0a83b0367755e2c53c1f7ed9e6d372c220ae0f344082cf5d52c40287893\",\"9b1b446dd599fd5dab08e83738b92651d8aaa7be072db313d237c68ce1094ea1\",\"a03c962c184055ccbf7a42c9a13a0d4c38125535a830832a6fff3029d6deada3\",\"df5d9e1e3a220d2429f9064adecb86ecae916619c93e17d237b5972692e558fd\",\"2d6315b7a91d62bd31e4738259f56f58075bd14ee2f1e2625738f506a7564176\",\"26b1d48ab8c3f0707bd5afdf4a3ef757abc9b6a0be75b8a3cecbcd5994473a72\",\"f897c92aca8d6ef46a41a3a50aff0527bd09be029355d28c2360ec9cb309b1ae\",\"f80ff7cbcad8c465278a59588a3a0d000cc3130e96fb56d257229c1a50d93125\",\"7a84f42433ecd9352e2ffd8bdc8556c87ec93697cf4c4873d4ab51d2b85c44c1\",\"00c03e0af90a26d0a4bb4b243f99b2d361de2412d82f357f6224eceb2f19c142\",\"e0a8f77abd726e928580656d7ab49dc276603e936e04b9caf53a2a27338e3cd1\",\"e376ebd2f0c93013cf6c856fb76e7b60e64a300a9a4b839844074cac4da42b8d\",\"5fcc77f29cfdb51aac9fff250e1ee7607457ce5a280e946150931d793272593a\",\"ad34b2dce6a7136584c5ffea74c66e5613593dddac9eb666ff6a6aef42386968\",\"3d1afa6b931fea014211bb6b08d9508389dd0a9c47a25670ca110bcc8ce8ead1\",\"df427b938f6ef07cd67da1ab11ad8fb4e6b0a97c03325c1fc8b1c3b0c4b8f7f4\",\"8c3d435fdb6ee44e26155c116a86f4dc2b54b05becb08777a63e1d1ad7c3cbc2\",\"11671f5bd2856de1b4925ee0b82f9cda6179db132c9930431d26f0ccdbb8a822\",\"19dcd3ac59669e10420b36d4e588206ae123a0c8ae64b20e1ede697efc556291\",\"65542a8b2c1bca8d78d6517357853c1d54f6b53f04a8327f28ae2d5d022c5597\"]},\"attestations\":4796228701811883082}";

        let serialized = serde_json::to_string(&s).unwrap();
        assert_eq!(JSON_STR, serialized);
        let deserialized: State = serde_json::from_str(&serialized).unwrap();
        assert_eq!(s, deserialized);

        const BINARY_STR: &str = "5b60b072b14972e054b6800181215b654a2b64e8a0f39da6d5ad20f4e6eda87d50d36e93efd9cdb9086ff17201000000fc13560200000000420d26e30100000018982f5200000000c378c1e901000000f146ff1900000000f6f6ccb80000000089116d64010000009eb377e000000000c79509c200000000fd6dd14200000000fb66f6dd0517bd80a57c6fc1dd186eeb25a5f7dc550adc94a996731734f4a478188d65bc61f7398757be167c70139bc79e2f387551bd0338b81f3938850033c23f48064ca312d68970452ce1abbc218b3f80e4e86850bd465e7e960e017d5772f3341bd8d80fc797de245c760a3f9e84f4da66f9e0ee95aa95ae9eb00188ade3367e57e5bdc522a16e95a8d28e1b940d2d128273aa7a8330cfb49736296ae52965fd7d66d55720eeadfc2be586db65699050bce175c56056a537942b3dcc3fb364ca2cdd33416f2ad78e92cd50081c59c5c9f67c9a64829c9022ffe17973176b934cf5ab04186591c97b2b86f290de9dace84dac6fe2b4867e964c967126699e34e7e3114292eca3140a6f0a94e76e39c047b064bfdbc6bbe6ff949d4637004478a9fabda865dafcaf474d48bdb1272595513cf92290917392ff58ca8bea591ae6a5ea278d90592e0518fbf2e83f41507486fe57e8e4ffbe152f13250df696bf2488cae3f7046f8b04aec217a09358db22d8ae36f883d1ccae9382edca79c54ee498f1adbe88c58bc9dabf487437b8d191a78fbb3d8cfe19a4c1759ae232b4f496130e35228422970057745ef4b92d285434c25187c44110922554d0ae04067844f29b39d6e4f509d5d41834db4fd6a831ccca33bb46185a5ad01f278958133775f0b42f9d291c4ff4e57f403893e0ca18fdc64f0723e0f29b6aeed834db1ac24ce129d69c69971497c556d9eeec0de8c1dd9cc4b0750be9fffd9ec3226ce7a3f3321bf48aed89100db44b3080f3f350d10b6de213527b19ad57bdd1cd47576a724c8bf4c8459625190ae18b2fc1d9353d2d3b34c80d4d4fbcd48258c9a11c97062b2371de9dfad15931a1e72c46afe492ad697447680ea43300ed516bcc2742b23ca0a83b0367755e2c53c1f7ed9e6d372c220ae0f344082cf5d52c402878939b1b446dd599fd5dab08e83738b92651d8aaa7be072db313d237c68ce1094ea1a03c962c184055ccbf7a42c9a13a0d4c38125535a830832a6fff3029d6deada3df5d9e1e3a220d2429f9064adecb86ecae916619c93e17d237b5972692e558fd2d6315b7a91d62bd31e4738259f56f58075bd14ee2f1e2625738f506a756417626b1d48ab8c3f0707bd5afdf4a3ef757abc9b6a0be75b8a3cecbcd5994473a72f897c92aca8d6ef46a41a3a50aff0527bd09be029355d28c2360ec9cb309b1aef80ff7cbcad8c465278a59588a3a0d000cc3130e96fb56d257229c1a50d931257a84f42433ecd9352e2ffd8bdc8556c87ec93697cf4c4873d4ab51d2b85c44c100c03e0af90a26d0a4bb4b243f99b2d361de2412d82f357f6224eceb2f19c142e0a8f77abd726e928580656d7ab49dc276603e936e04b9caf53a2a27338e3cd1e376ebd2f0c93013cf6c856fb76e7b60e64a300a9a4b839844074cac4da42b8d5fcc77f29cfdb51aac9fff250e1ee7607457ce5a280e946150931d793272593aad34b2dce6a7136584c5ffea74c66e5613593dddac9eb666ff6a6aef423869683d1afa6b931fea014211bb6b08d9508389dd0a9c47a25670ca110bcc8ce8ead1df427b938f6ef07cd67da1ab11ad8fb4e6b0a97c03325c1fc8b1c3b0c4b8f7f48c3d435fdb6ee44e26155c116a86f4dc2b54b05becb08777a63e1d1ad7c3cbc211671f5bd2856de1b4925ee0b82f9cda6179db132c9930431d26f0ccdbb8a82219dcd3ac59669e10420b36d4e588206ae123a0c8ae64b20e1ede697efc55629165542a8b2c1bca8d78d6517357853c1d54f6b53f04a8327f28ae2d5d022c55974abc07c197a08f42";

        let mut serialized = Vec::new();
        s.encode(&mut serialized).unwrap();
        assert_eq!(BINARY_STR, hex::encode(serialized.clone()));
        let deserialized = State::decode(&mut &serialized[..]).unwrap();
        assert_eq!(s, deserialized);
    }

    // =========================================================================
    // Test vectors generated by Go program (sia-sdk-rs/sia_sdk/testutil/go-vectors/main.go).
    // Regenerate with:
    //   cd sia_sdk/testutil/go-vectors && go run . > ../../src/test_vectors.json
    // CI generates this automatically (see .github/workflows/main.yml).
    // =========================================================================

    #[derive(serde::Deserialize)]
    struct TestVectors {
        unassigned_leaf_index: u64,
        element_hashes: Vec<ElementHashVec>,
        leaf_hashes: Vec<LeafHashVec>,
        sum_pairs: Vec<SumPairVec>,
        accumulator: Vec<AccumulatorStepVec>,
        proof_roots: Vec<ProofRootVec>,
        chain_index_hashes: Vec<ChainIndexHashVec>,
        miner_output_ids: Vec<MinerOutputIDVec>,
        foundation_output_ids: Vec<FoundationOutputIDVec>,
    }

    #[derive(serde::Deserialize)]
    struct ElementHashVec {
        id_hex: String,
        value_lo: u64,
        value_hi: u64,
        address_hex: String,
        maturity_height: u64,
        result_hex: String,
    }

    #[derive(serde::Deserialize)]
    struct LeafHashVec {
        element_hash_hex: String,
        leaf_index: u64,
        spent: bool,
        result_hex: String,
    }

    #[derive(serde::Deserialize)]
    struct SumPairVec {
        left_hex: String,
        right_hex: String,
        result_hex: String,
    }

    #[derive(serde::Deserialize)]
    struct AccumulatorStepVec {
        leaf_hash_hex: String,
        num_leaves: u64,
        trees_hex: Vec<String>,
    }

    #[derive(serde::Deserialize)]
    struct ProofRootVec {
        leaf_hash_hex: String,
        leaf_index: u64,
        proof_hex: Vec<String>,
        result_hex: String,
    }

    #[derive(serde::Deserialize)]
    struct ChainIndexHashVec {
        id_hex: String,
        index_height: u64,
        index_id_hex: String,
        result_hex: String,
    }

    #[derive(serde::Deserialize)]
    struct MinerOutputIDVec {
        block_id_hex: String,
        index: u64,
        result_hex: String,
    }

    #[derive(serde::Deserialize)]
    struct FoundationOutputIDVec {
        block_id_hex: String,
        result_hex: String,
    }

    fn hex_to_hash(s: &str) -> Hash256 {
        let bytes = hex::decode(s).unwrap();
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        Hash256::from(h)
    }

    fn load_vectors() -> TestVectors {
        let json = include_str!("test_vectors.json");
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn test_unassigned_leaf_index() {
        let v = load_vectors();
        assert_eq!(
            UNASSIGNED_LEAF_INDEX, v.unassigned_leaf_index,
            "UNASSIGNED_LEAF_INDEX mismatch: rust={} go={}",
            UNASSIGNED_LEAF_INDEX, v.unassigned_leaf_index
        );
    }

    #[test]
    fn test_siacoin_element_hash_vectors() {
        let v = load_vectors();
        for (i, tc) in v.element_hashes.iter().enumerate() {
            let id_bytes = hex::decode(&tc.id_hex).unwrap();
            let mut id_arr = [0u8; 32];
            id_arr.copy_from_slice(&id_bytes);
            let id = crate::types::SiacoinOutputID::from(id_arr);

            let value = Currency::new((tc.value_hi as u128) << 64 | tc.value_lo as u128);

            let addr_bytes = hex::decode(&tc.address_hex).unwrap();
            let mut addr_arr = [0u8; 32];
            addr_arr.copy_from_slice(&addr_bytes);
            let address = crate::types::Address::new(addr_arr);

            let output = SiacoinOutput { value, address };

            let result = siacoin_element_hash(&id, &output, tc.maturity_height);
            let expected = hex_to_hash(&tc.result_hex);
            assert_eq!(
                result,
                expected,
                "element_hash case {} mismatch:\n  got:      {}\n  expected: {}",
                i,
                hex::encode(result.as_ref() as &[u8]),
                tc.result_hex
            );
        }
    }

    #[test]
    fn test_leaf_hash_vectors() {
        let v = load_vectors();
        for (i, tc) in v.leaf_hashes.iter().enumerate() {
            let elem_hash = hex_to_hash(&tc.element_hash_hex);
            let leaf = ElementLeaf {
                state_element: StateElement {
                    leaf_index: tc.leaf_index,
                    merkle_proof: Vec::new(),
                },
                element_hash: elem_hash,
                spent: tc.spent,
            };
            let result = leaf.hash();
            let expected = hex_to_hash(&tc.result_hex);
            assert_eq!(
                result,
                expected,
                "leaf_hash case {} mismatch:\n  got:      {}\n  expected: {}",
                i,
                hex::encode(result.as_ref() as &[u8]),
                tc.result_hex
            );
        }
    }

    #[test]
    fn test_sum_pair_vectors() {
        let v = load_vectors();
        for (i, tc) in v.sum_pairs.iter().enumerate() {
            let left = hex_to_hash(&tc.left_hex);
            let right = hex_to_hash(&tc.right_hex);
            let result = sum_node(&BLAKE2B_256_PARAMS, &left, &right);
            let expected = hex_to_hash(&tc.result_hex);
            assert_eq!(
                result,
                expected,
                "sum_pair case {} mismatch:\n  got:      {}\n  expected: {}",
                i,
                hex::encode(result.as_ref() as &[u8]),
                tc.result_hex
            );
        }
    }

    #[test]
    fn test_accumulator_vectors() {
        let v = load_vectors();
        let mut acc = ElementAccumulator::default();

        for (i, step) in v.accumulator.iter().enumerate() {
            let leaf_hash = hex_to_hash(&step.leaf_hash_hex);

            // Manually add the leaf hash (replicating Go's Accumulator.AddLeaf)
            let mut h = leaf_hash;
            let mut height = 0;
            while has_tree_at_height(acc.num_leaves, height) {
                h = sum_node(&BLAKE2B_256_PARAMS, &acc.trees[height], &h);
                height += 1;
            }
            acc.trees[height] = h;
            acc.num_leaves += 1;

            assert_eq!(
                acc.num_leaves, step.num_leaves,
                "accumulator step {} num_leaves mismatch",
                i
            );

            // Check trees
            for tree_entry in &step.trees_hex {
                let parts: Vec<&str> = tree_entry.splitn(2, ':').collect();
                let tree_idx: usize = parts[0].parse().unwrap();
                let expected_hash = hex_to_hash(parts[1]);
                assert_eq!(
                    acc.trees[tree_idx],
                    expected_hash,
                    "accumulator step {} tree[{}] mismatch:\n  got:      {}\n  expected: {}",
                    i,
                    tree_idx,
                    hex::encode(acc.trees[tree_idx].as_ref() as &[u8]),
                    parts[1]
                );
            }
        }
    }

    #[test]
    fn test_proof_root_vectors() {
        let v = load_vectors();
        for (i, tc) in v.proof_roots.iter().enumerate() {
            let leaf_hash = hex_to_hash(&tc.leaf_hash_hex);
            let proof: Vec<Hash256> = tc.proof_hex.iter().map(|h| hex_to_hash(h)).collect();
            let result = proof_root(leaf_hash, tc.leaf_index, &proof);
            let expected = hex_to_hash(&tc.result_hex);
            assert_eq!(
                result,
                expected,
                "proof_root case {} mismatch:\n  got:      {}\n  expected: {}",
                i,
                hex::encode(result.as_ref() as &[u8]),
                tc.result_hex
            );
        }
    }

    #[test]
    fn test_chain_index_hash_vectors() {
        let v = load_vectors();
        for (i, tc) in v.chain_index_hashes.iter().enumerate() {
            let id_bytes = hex::decode(&tc.id_hex).unwrap();
            let mut id = [0u8; 32];
            id.copy_from_slice(&id_bytes);
            let block_id = BlockID::new(id);

            let index_id_bytes = hex::decode(&tc.index_id_hex).unwrap();
            let mut index_id = [0u8; 32];
            index_id.copy_from_slice(&index_id_bytes);
            let chain_index = ChainIndex {
                height: tc.index_height,
                id: BlockID::new(index_id),
            };

            let result = chain_index_element_hash(&block_id, &chain_index);
            let expected = hex_to_hash(&tc.result_hex);
            assert_eq!(
                result,
                expected,
                "chain_index_element_hash case {} mismatch:\n  got:      {}\n  expected: {}",
                i,
                hex::encode(result.as_ref() as &[u8]),
                tc.result_hex
            );
        }
    }

    #[test]
    fn test_miner_output_id_vectors() {
        let v = load_vectors();
        for (i, tc) in v.miner_output_ids.iter().enumerate() {
            let id_bytes = hex::decode(&tc.block_id_hex).unwrap();
            let mut id = [0u8; 32];
            id.copy_from_slice(&id_bytes);
            let block_id = BlockID::new(id);

            let result = block_id.miner_output_id(tc.index as usize);
            let expected_bytes = hex::decode(&tc.result_hex).unwrap();
            let result_ref: &[u8] = result.as_ref();
            assert_eq!(
                result_ref,
                expected_bytes.as_slice(),
                "miner_output_id case {} mismatch:\n  got:      {}\n  expected: {}",
                i,
                hex::encode(result_ref),
                tc.result_hex
            );
        }
    }

    #[test]
    fn test_foundation_output_id_vectors() {
        let v = load_vectors();
        for (i, tc) in v.foundation_output_ids.iter().enumerate() {
            let id_bytes = hex::decode(&tc.block_id_hex).unwrap();
            let mut id = [0u8; 32];
            id.copy_from_slice(&id_bytes);
            let block_id = BlockID::new(id);

            let result = block_id.foundation_output_id();
            let expected_bytes = hex::decode(&tc.result_hex).unwrap();
            let result_ref: &[u8] = result.as_ref();
            assert_eq!(
                result_ref,
                expected_bytes.as_slice(),
                "foundation_output_id case {} mismatch:\n  got:      {}\n  expected: {}",
                i,
                hex::encode(result_ref),
                tc.result_hex
            );
        }
    }
}
