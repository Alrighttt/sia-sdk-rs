use core::fmt;

use crate::encoding_async::{AsyncSiaDecodable, AsyncSiaDecode, AsyncSiaEncodable, AsyncSiaEncode};
use blake2b_simd::Params;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::encoding::{
    self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode, V1SiaDecodable, V1SiaDecode,
    V1SiaEncodable, V1SiaEncode,
};
use crate::macros::impl_hash_id;
use crate::types::currency::Currency;
use crate::types::{v1, v2};

use super::{Specifier, specifier};

impl_hash_id!(Hash256);
impl_hash_id!(SiacoinOutputID);
impl_hash_id!(AttestationID);

impl_hash_id!(SiafundOutputID);

impl SiafundOutputID {
    /// claim_output_id returns the SiacoinOutputID for the claim output of the siafund output
    pub fn claim_output_id(&self) -> SiacoinOutputID {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(self.as_ref());
        state.finalize().into()
    }

    pub fn v2_claim_output_id(&self) -> SiacoinOutputID {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(b"sia/id/v2siacoinclaimoutput|");
        state.update(self.as_ref());
        state.finalize().into()
    }
}

impl_hash_id!(BlockID);

impl BlockID {
    const FOUNDATION_OUTPUT_ID_PREFIX: Specifier = specifier!("foundation");

    pub fn foundation_output_id(&self) -> SiacoinOutputID {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(self.as_ref());
        state.update(Self::FOUNDATION_OUTPUT_ID_PREFIX.as_ref());
        state.finalize().into()
    }

    pub fn miner_output_id(&self, i: usize) -> SiacoinOutputID {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(self.as_ref());
        state.update(&(i as u64).to_le_bytes());
        state.finalize().into()
    }
}

impl_hash_id!(TransactionID);

impl TransactionID {
    const V2_SIACOIN_OUTPUT_PREFIX: &[u8] = b"sia/id/siacoinoutput|";
    const V2_SIAFUND_OUTPUT_PREFIX: &[u8] = b"sia/id/siafundoutput|";
    const V2_FILE_CONTRACT_PREFIX: &[u8] = b"sia/id/filecontract|";
    const V2_ATTESTATION_PREFIX: &[u8] = b"sia/id/attestation|";

    fn derive_v2_child_id<T: From<blake2b_simd::Hash>>(&self, prefix: &[u8], i: usize) -> T {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(prefix.as_ref());
        state.update(self.as_ref());
        state.update(&(i as u64).to_le_bytes());
        state.finalize().into()
    }

    /// v2_siacoin_output_id returns the SiacoinOutputID for the i-th siacoin output of the V2 transaction
    pub fn v2_siacoin_output_id(&self, i: usize) -> SiacoinOutputID {
        self.derive_v2_child_id(Self::V2_SIACOIN_OUTPUT_PREFIX, i)
    }

    /// v2_siafund_output_id returns the SiafundOutputID for the i-th siafund output of the V2 transaction
    pub fn v2_siafund_output_id(&self, i: usize) -> SiafundOutputID {
        self.derive_v2_child_id(Self::V2_SIAFUND_OUTPUT_PREFIX, i)
    }

    /// v2_file_contract_id returns the FileContractID for the i-th file contract of the V2 transaction
    pub fn v2_file_contract_id(&self, i: usize) -> FileContractID {
        self.derive_v2_child_id(Self::V2_FILE_CONTRACT_PREFIX, i)
    }

    /// v2_attestation_id returns the AttestationID for the i-th attestation of the V2 transaction
    pub fn v2_attestation_id(&self, i: usize) -> AttestationID {
        self.derive_v2_child_id(Self::V2_ATTESTATION_PREFIX, i)
    }
}

impl_hash_id!(FileContractID);

impl FileContractID {
    const PROOF_OUTPUT_ID_PREFIX: Specifier = specifier!("storage proof");
    const V2_PROOF_OUTPUT_ID_PREFIX: &'static str = "sia/id/v2filecontractoutput|";
    const V2_FILE_CONTRACT_RENEWAL_PREFIX: &'static str = "sia/id/v2filecontractrenewal|";

    fn derive_proof_output_id<T: From<blake2b_simd::Hash>>(&self, valid: bool, i: usize) -> T {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(Self::PROOF_OUTPUT_ID_PREFIX.as_ref());
        state.update(self.as_ref());
        state.update(&(valid as u8).to_le_bytes());
        state.update(&(i as u64).to_le_bytes());
        state.finalize().into()
    }

    fn derive_v2_proof_output_id<T: From<blake2b_simd::Hash>>(&self, i: usize) -> T {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(Self::V2_PROOF_OUTPUT_ID_PREFIX.as_ref());
        state.update(self.as_ref());
        state.update(&(i as u64).to_le_bytes());
        state.finalize().into()
    }

    /// valid_output_id returns the SiacoinOutputID for the i-th valid output of the contract
    pub fn valid_output_id(&self, i: usize) -> SiacoinOutputID {
        self.derive_proof_output_id(true, i)
    }

    /// missed_output_id returns the SiacoinOutputID for the i-th missed output of the contract
    pub fn missed_output_id(&self, i: usize) -> SiacoinOutputID {
        self.derive_proof_output_id(false, i)
    }

    /// v2_renter_output_id returns the SiacoinOutputID for the renter output of a V2 file contract
    pub fn v2_renter_output_id(&self) -> SiacoinOutputID {
        self.derive_v2_proof_output_id(0)
    }

    /// v2_host_output_id returns the SiacoinOutputID for the host output of a V2 file contract
    pub fn v2_host_output_id(&self) -> SiacoinOutputID {
        self.derive_v2_proof_output_id(1)
    }

    /// v2_renewal_id returns the ID of the new contract created by renewing a V2 contract
    pub fn v2_renewal_id(&self) -> FileContractID {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(Self::V2_FILE_CONTRACT_RENEWAL_PREFIX.as_ref());
        state.update(self.as_ref());
        state.finalize().into()
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    SiaEncode,
    SiaDecode,
    AsyncSiaDecode,
    AsyncSiaEncode,
    Serialize,
    Deserialize,
)]
pub struct ChainIndex {
    pub height: u64,
    pub id: BlockID,
}

impl ChainIndex {
    pub fn child_height(&self) -> u64 {
        self.height + 1
    }
}

impl fmt::Display for ChainIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.height, hex::encode(self.id))
    }
}

/// A BlockHeader contains the core fields of a v2 block.
#[derive(Debug, Clone, PartialEq, SiaEncode, SiaDecode, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    #[serde(rename = "parentID")]
    pub parent_id: BlockID,
    pub nonce: u64,
    pub timestamp: DateTime<Utc>,
    pub commitment: Hash256,
}

impl BlockHeader {
    /// Computes the block ID by hashing the header fields with blake2b-256.
    pub fn id(&self) -> BlockID {
        let mut state = Params::new().hash_length(32).to_state();
        let parent_ref: &[u8] = self.parent_id.as_ref();
        state.update(parent_ref);
        state.update(&self.nonce.to_le_bytes());
        state.update(&(self.timestamp.timestamp() as u64).to_le_bytes());
        let commitment_ref: &[u8] = self.commitment.as_ref();
        state.update(commitment_ref);
        state.finalize().into()
    }
}

/// A Block is a collection of transactions
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    #[serde(rename = "parentID")]
    pub parent_id: BlockID,
    pub nonce: u64,
    pub timestamp: DateTime<Utc>,
    pub miner_payouts: Vec<SiacoinOutput>,
    pub transactions: Vec<v1::Transaction>,
}

impl V1SiaEncodable for Block {
    fn encode_v1<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.parent_id.encode(w)?;
        self.nonce.encode(w)?;
        self.timestamp.encode(w)?;
        self.miner_payouts.encode_v1(w)?;
        self.transactions.encode_v1(w)
    }
}

impl V1SiaDecodable for Block {
    fn decode_v1<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        Ok(Block {
            parent_id: BlockID::decode(r)?,
            nonce: u64::decode(r)?,
            timestamp: DateTime::<Utc>::decode(r)?,
            miner_payouts: Vec::<SiacoinOutput>::decode_v1(r)?,
            transactions: Vec::<v1::Transaction>::decode_v1(r)?,
        })
    }
}

/// encapsulates the various errors that can occur when parsing a Sia object
/// from a string
#[derive(Debug, Error, PartialEq)]
pub enum HexParseError {
    #[error("Missing prefix")]
    MissingPrefix,

    #[error("Unexpected length")]
    InvalidLength(usize),

    #[error("Invalid prefix {0}")]
    InvalidPrefix(String),

    #[error("Invalid checksum")]
    InvalidChecksum, // not every object has a checksum

    #[error("Hex error: {0}")]
    HexError(#[from] hex::FromHexError),
}

/// An address that can be used to receive UTXOs
#[derive(
    Default,
    Debug,
    PartialEq,
    Clone,
    SiaEncode,
    V1SiaEncode,
    SiaDecode,
    V1SiaDecode,
    AsyncSiaEncode,
    AsyncSiaDecode,
)]
pub struct Address([u8; 32]);

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse()
            .map_err(|e| serde::de::Error::custom(format!("{e:?}")))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl Address {
    pub const fn new(addr: [u8; 32]) -> Address {
        Address(addr)
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Address {
    fn from(val: &[u8]) -> Self {
        let mut data = [0u8; 32];
        data.copy_from_slice(val);
        Address(data)
    }
}

impl From<[u8; 32]> for Address {
    fn from(val: [u8; 32]) -> Self {
        Address(val)
    }
}

impl std::str::FromStr for Address {
    type Err = crate::types::HexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 76 {
            return Err(HexParseError::InvalidLength(s.len()));
        }

        let mut data = [0u8; 38];
        hex::decode_to_slice(s, &mut data).map_err(HexParseError::HexError)?;

        let h = Params::new()
            .hash_length(32)
            .to_state()
            .update(&data[..32])
            .finalize();
        let checksum = h.as_bytes();

        if checksum[..6] != data[32..] {
            return Err(HexParseError::InvalidChecksum);
        }

        Ok(data[..32].into())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = [0u8; 32 + 6];
        buf[..32].copy_from_slice(&self.0);

        let h = Params::new()
            .hash_length(32)
            .to_state()
            .update(&self.0)
            .finalize();

        buf[32..].copy_from_slice(&h.as_bytes()[..6]);
        write!(f, "{}", hex::encode(buf))
    }
}

/// A SiacoinOutput is a Siacoin UTXO that can be spent using the unlock conditions
/// for Address
#[derive(
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    AsyncSiaEncode,
    AsyncSiaDecode,
    SiaEncode,
    SiaDecode,
    V1SiaEncode,
    V1SiaDecode,
    Clone,
)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinOutput {
    pub value: Currency,
    pub address: Address,
}

/// A SiafundOutput is a Siafund UTXO that can be spent using the unlock conditions
/// for Address
#[derive(
    Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaEncode, AsyncSiaDecode, Clone,
)]
#[serde(rename_all = "camelCase")]
pub struct SiafundOutput {
    pub value: u64,
    pub address: Address,
}

impl V1SiaEncodable for SiafundOutput {
    fn encode_v1<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        Currency::new(self.value as u128).encode_v1(w)?;
        self.address.encode_v1(w)?;
        Currency::new(0).encode_v1(w) // siad encodes a "claim start," but its an error if it's non-zero.
    }
}

impl V1SiaDecodable for SiafundOutput {
    fn decode_v1<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        let se = SiafundOutput {
            value: Currency::decode_v1(r)?
                .try_into()
                .map_err(|_| encoding::Error::Custom("invalid value".to_string()))?,
            address: Address::decode_v1(r)?,
        };
        Currency::decode_v1(r)?; // ignore claim start
        Ok(se)
    }
}

/// A Leaf is a 64-byte piece of data that is stored in a Merkle tree.
#[derive(
    Debug,
    PartialEq,
    Clone,
    SiaEncode,
    V1SiaEncode,
    SiaDecode,
    V1SiaDecode,
    AsyncSiaEncode,
    AsyncSiaDecode,
)]
pub struct Leaf([u8; 64]);

impl From<[u8; 64]> for Leaf {
    fn from(data: [u8; 64]) -> Self {
        Leaf(data)
    }
}

impl std::str::FromStr for Leaf {
    type Err = crate::types::HexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 128 {
            return Err(HexParseError::InvalidLength(s.len()));
        }

        let mut data = [0u8; 64];
        hex::decode_to_slice(s, &mut data).map_err(HexParseError::HexError)?;
        Ok(Leaf(data))
    }
}

impl fmt::Display for Leaf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Serialize for Leaf {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        String::serialize(&self.to_string(), serializer)
    }
}

impl<'de> Deserialize<'de> for Leaf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let data = hex::decode(s).map_err(|e| serde::de::Error::custom(format!("{e:?}")))?;
        if data.len() != 64 {
            return Err(serde::de::Error::custom("invalid length"));
        }
        Ok(Leaf(data.try_into().unwrap()))
    }
}

/// A StateElement is a generic element within the state accumulator.
#[derive(
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    SiaEncode,
    SiaDecode,
    AsyncSiaDecode,
    AsyncSiaEncode,
    Clone,
)]
#[serde(rename_all = "camelCase")]
pub struct StateElement {
    pub leaf_index: u64,
    #[serde(default)]
    pub merkle_proof: Vec<Hash256>,
}

#[cfg(test)]
mod tests {
    use crate::{
        address, block_id, contract_id, public_key, siacoin_id, siafund_id, transaction_id,
    };

    use super::*;

    #[test]
    fn test_serialize_hash256() {
        let hash_str = "9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6";
        let hash = Hash256(hex::decode(hash_str).unwrap().try_into().unwrap());

        // binary
        let mut hash_serialized: Vec<u8> = Vec::new();
        hash.encode(&mut hash_serialized).unwrap();
        assert_eq!(hash_serialized, hex::decode(hash_str).unwrap());
        let hash_deserialized = Hash256::decode(&mut &hash_serialized[..]).unwrap();
        assert_eq!(hash_deserialized, hash); // deserialize

        // json
        let hash_serialized = serde_json::to_string(&hash).unwrap();
        let hash_deserialized: Hash256 = serde_json::from_str(&hash_serialized).unwrap();
        assert_eq!(hash_serialized, format!("\"{hash_str}\"")); // serialize
        assert_eq!(hash_deserialized, hash); // deserialize
    }

    #[test]
    fn test_serialize_address() {
        let addr_str = "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c";
        let checksum = "df32abee86f0";
        let address = address!(
            "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0"
        );

        // binary
        let mut addr_serialized: Vec<u8> = Vec::new();
        address.encode(&mut addr_serialized).unwrap();
        assert_eq!(addr_serialized, hex::decode(addr_str).unwrap()); // serialize
        let addr_deserialized = Address::decode(&mut &addr_serialized[..]).unwrap();
        assert_eq!(addr_deserialized, address); // deserialize

        // json
        let addr_serialized = serde_json::to_string(&address).unwrap();
        let addr_deserialized: Address = serde_json::from_str(&addr_serialized).unwrap();
        assert_eq!(addr_serialized, format!("\"{addr_str}{checksum}\"")); // serialize
        assert_eq!(addr_deserialized, address); // deserialize
    }

    #[test]
    fn test_serialize_block() {
        let b = Block {
            parent_id: block_id!(
                "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c"
            ),
            nonce: 1236112,
            timestamp: DateTime::UNIX_EPOCH,
            miner_payouts: vec![SiacoinOutput {
                value: Currency::new(57234234623612361),
                address: address!(
                    "000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
                ),
            }],
            transactions: vec![v1::Transaction {
                siacoin_inputs: vec![v1::SiacoinInput {
                    parent_id: siacoin_id!(
                        "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c"
                    ),
                    unlock_conditions: v1::UnlockConditions::standard_unlock_conditions(
                        public_key!(
                            "ed25519:8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c"
                        ),
                    ),
                }],
                siacoin_outputs: vec![SiacoinOutput {
                    value: Currency::new(67856467336433871),
                    address: address!(
                        "000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
                    ),
                }],
                file_contracts: Vec::new(),
                file_contract_revisions: Vec::new(),
                storage_proofs: Vec::new(),
                siafund_inputs: Vec::new(),
                siafund_outputs: Vec::new(),
                miner_fees: Vec::new(),
                arbitrary_data: Vec::new(),
                signatures: Vec::new(),
            }],
        };

        const BINARY_STR: &str = "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c90dc120000000000000000000000000001000000000000000700000000000000cb563bafbb55c90000000000000000000000000000000000000000000000000000000000000000010000000000000001000000000000008fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c000000000000000001000000000000006564323535313900000000000000000020000000000000008fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c010000000000000001000000000000000700000000000000f11318f74d10cf000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let mut serialized = Vec::new();
        b.encode_v1(&mut serialized).unwrap();
        assert_eq!(serialized, hex::decode(BINARY_STR).unwrap());
        let deserialized = Block::decode_v1(&mut &serialized[..]).unwrap();
        assert_eq!(deserialized, b);

        const JSON_STR: &str = "{\"parentID\":\"8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c\",\"nonce\":1236112,\"timestamp\":\"1970-01-01T00:00:00Z\",\"minerPayouts\":[{\"value\":\"57234234623612361\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"}],\"transactions\":[{\"siacoinInputs\":[{\"parentID\":\"8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c\",\"unlockConditions\":{\"timelock\":0,\"publicKeys\":[\"ed25519:8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c\"],\"signaturesRequired\":1}}],\"siacoinOutputs\":[{\"value\":\"67856467336433871\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"}]}]}";
        let serialized = serde_json::to_string(&b).unwrap();
        assert_eq!(serialized, JSON_STR);
        let deserialized: Block = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, b);
    }

    #[test]
    fn test_transaction_derive() {
        const TXN_JSON: &str = r#"{"siacoinInputs":[{"parentID":"750d22eff727689d1d8d1c83e513a30bb68ee7f9125a4dafc882459e34c2069d","unlockConditions":{"timelock":0,"publicKeys":["ed25519:800ed6c2760e3e4ba1ff00128585c8cf8fed2e3dc1e3da1eb92d49f405bd6360"],"signaturesRequired":6312611591377486220}}],"siacoinOutputs":[{"value":"890415399000000000000000000000000","address":"480a064b5fca13002a7fe575845154bbf0b3af4cc4f147cbed387d43cce3568ae2497366eaa7"}],"fileContracts":[{"filesize":0,"fileMerkleRoot":"0000000000000000000000000000000000000000000000000000000000000000","windowStart":10536451586783908586,"windowEnd":9324702155635244357,"payout":"0","validProofOutputs":[{"value":"1933513214000000000000000000000000","address":"944524fff2c49c401e748db37cfda7569fa6df35b704fe716394f2ac3f40ce87b4506e9906f0"}],"missedProofOutputs":[{"value":"2469287901000000000000000000000000","address":"1df67838262d7109ffcd9018f183b1eb33f05659a274b89ea6b52ff3617d34a770e9dd071d2e"}],"unlockHash":"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69","revisionNumber":9657412421282982780}],"fileContractRevisions":[{"parentID":"e4e26d93771d3bbb3d9dd306105d77cfb3a6254d1cc3495903af6e013442c63c","unlockConditions":{"timelock":0,"publicKeys":["ed25519:e6b9cde4eb058f8ecbb083d99779cb0f6d518d5386f019af6ead09fa52de8567"],"signaturesRequired":206644730660526450},"revisionNumber":10595710523108536025,"filesize":0,"fileMerkleRoot":"0000000000000000000000000000000000000000000000000000000000000000","windowStart":4348934140507359445,"windowEnd":14012366839994454386,"validProofOutputs":[{"value":"2435858510000000000000000000000000","address":"543bc0eda69f728d0a0fbce08e5bfc5ed7b961300e0af226949e135f7d12e32f0544e5262d6f"}],"missedProofOutputs":[{"value":"880343701000000000000000000000000","address":"7b7f9aee981fe0d93bb3f49c6233cf847ebdd39d7dc5253f7fc330df2167073b35f035703237"}],"unlockHash":"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"}],"storageProofs":[{"parentID":"c0b9e98c9e03a2740c75d673871c1ee91f36d1bb329ff3ddbf1dfa8c6e1a64eb","leaf":"b78fa521dc62d9ced82bc3b61e0aa5a5c221d6cca5db63d94c9879543fb98c0a971094a89cd4408487ae32902248d321b545f9a051729aa0bb1725b848e3d453","proof":["fe08c0a061475e7e5dec19e717cf98792fa7b555d0b5d3540a05db09f59ab8de"]}],"minerFees":["241119475000000000000000000000000"],"arbitraryData":["2shzIHEUJYwuNHz6c/gPz+aTEWZRTpDTmemX9yYAKlY="],"signatures":[{"parentID":"06d1fca03c5ddd9b09116db1b97c5451f7dc792b05362969f83e3e8dc1007f46","publicKeyIndex":6088345341283457116,"timelock":2014247885072555224,"coveredFields":{"wholeTransaction":true},"signature":"2XNEKGZrl9RhMa2JmGsvcmqQWAIX/uxtMwLnPI6VJPcXqub6qYIuoAThYp9NAwadk+1GG6CXC66g4rOjFYuNSA=="}]}"#;

        const EXPECTED_TRANSACTION_ID: TransactionID =
            transaction_id!("71a10d363f4af09c3fbce499b725067b0b19afe2bc9a8236704e85256f3244a6");
        const EXPECTED_SIACOIN_OUTPUT_ID: SiacoinOutputID =
            siacoin_id!("ea315efdd5914c54e8082d0de90b5afa9d4b92103d60661ec86b2a095413d836");
        const EXPECTED_SIAFUND_OUTPUT_ID: SiafundOutputID =
            siafund_id!("a8190ea7b4d41e08f45f27653b882faf8ff9fd57bb098d7022f105ef142279ec");
        const EXPECTED_FILE_CONTRACT_ID: FileContractID =
            contract_id!("ff7102bb111a64c7ff8a3cd68dbc962a03a8943065c3852a359662c8935fa979");

        let txn: v1::Transaction =
            serde_json::from_str(TXN_JSON).expect("transaction to deserialize");

        assert_eq!(txn.id(), EXPECTED_TRANSACTION_ID, "transaction id");

        assert_eq!(
            txn.siacoin_output_id(678569214627704587),
            EXPECTED_SIACOIN_OUTPUT_ID,
            "siacoin output id"
        );

        assert_eq!(
            txn.siafund_output_id(8940170890223196046),
            EXPECTED_SIAFUND_OUTPUT_ID,
            "siafund output id"
        );

        assert_eq!(
            txn.file_contract_id(3470616158951613631),
            EXPECTED_FILE_CONTRACT_ID,
            "file contract id"
        );
    }

    #[test]
    fn test_transaction_id_v2_derive() {
        const EXPECTED_V2_SIACOIN_OUTPUT_ID: SiacoinOutputID =
            siacoin_id!("f74e0d8eae89ec820184c9bacfcad0181c781c02020f8a3fcbc82fd4ebf2fcf0");
        const EXPECTED_V2_SIAFUND_OUTPUT_ID: SiafundOutputID =
            siafund_id!("f7d9ad77bfe9a102ef9590f97024f3aa8f54877d10447c128b52d5ca18cca983");
        const EXPECTED_V2_FILE_CONTRACT_ID: FileContractID =
            contract_id!("c67764bc06df3dd933e0d4e93c6f7cbe5b56670d1baae156b578d417f08e65cf");

        let txn_id =
            transaction_id!("168ecf3133ae713c26f90fe1790fb7536f12cc2a492985627856b77c6ad99070");

        assert_eq!(
            txn_id.v2_siacoin_output_id(3543556734851495409),
            EXPECTED_V2_SIACOIN_OUTPUT_ID,
            "v2 siacoin output id"
        );

        assert_eq!(
            txn_id.v2_siafund_output_id(4957302981402025980),
            EXPECTED_V2_SIAFUND_OUTPUT_ID,
            "v2 siafund output id"
        );

        assert_eq!(
            txn_id.v2_file_contract_id(5375460735837768427),
            EXPECTED_V2_FILE_CONTRACT_ID,
            "v2 file contract id"
        );
    }

    #[test]
    fn test_block_id_derive() {
        const EXPECTED_FOUNDATION_OUTPUT_ID: SiacoinOutputID =
            siacoin_id!("159e2c4159a112ea9a70242d541a26f49fce41b6126f9105eab9b68dba4cfafb");
        const EXPECTED_MINER_OUTPUT_ID: SiacoinOutputID =
            siacoin_id!("69e68779991392663d808276e6661d94628632354e258d8ab6724de1d9ca6208");

        let block_id =
            block_id!("c56d879b07b27fab3bdd06b833dbd1ad7eb167058851f543a517308b634a80a1");

        assert_eq!(
            block_id.foundation_output_id(),
            EXPECTED_FOUNDATION_OUTPUT_ID,
            "foundation output id"
        );

        assert_eq!(
            block_id.miner_output_id(3072616177397065894),
            EXPECTED_MINER_OUTPUT_ID,
            "miner output id"
        );
    }

    #[test]
    fn test_siafund_output_id_derive() {
        const EXPECTED_CLAIM_ID: SiacoinOutputID =
            siacoin_id!("8eec57722c2ac040e34322ba77cb6b488ac8081f856d93bea1bf1bef42aeaabb");
        const EXPECTED_V2_CLAIM_ID: SiacoinOutputID =
            siacoin_id!("b949006c65c70b5973da46cc783981d701dd854316e7efb1947c0b5f2fdc8db4");

        let siafund_output_id =
            siafund_id!("58ea19fd87ae5e10f928035e1021c3d9ee091fb3c0bbd5a1a6af41eea12e0f85");

        assert_eq!(
            siafund_output_id.claim_output_id(),
            EXPECTED_CLAIM_ID,
            "claim output id"
        );

        assert_eq!(
            siafund_output_id.v2_claim_output_id(),
            EXPECTED_V2_CLAIM_ID,
            "v2 claim output id"
        );
    }

    #[test]
    fn test_deserialize_v2_transactions_json() {
        // Replace this JSON array with the real transactions from the problematic block
        const TXNS_JSON: &str = r#"[
        {
  "id": "1079faa98c13608d8b541285ef736d6c85b42a0322c25d3dc8a3e1ed304c750f",
  "siacoinOutputs": [
    {
      "id": "7131af78d389412e9cdcf2f0eb67ebfc626215a90554d864e7a6ffbcca299dc8",
      "value": "990000000000000000000000000",
      "address": "109b873684a28b6e7b4eef26784c68752c44d51a6d4270ee6831e7c1aae79dc6af11c332cc14"
    }
  ],
  "siafundOutputs": [],
  "siacoinInputs": [
    {
      "parent": {
        "id": "aabb000000000000000000000000000000000000000000000000000000000000",
        "stateElement": {
          "leafIndex": 96844
        },
        "siacoinOutput": {
          "value": "1000000000000000000000000000",
          "address": "109b873684a28b6e7b4eef26784c68752c44d51a6d4270ee6831e7c1aae79dc6af11c332cc14"
        },
        "maturityHeight": 0
      },
      "satisfiedPolicy": {
        "policy": {
          "type": "uc",
          "policy": {
            "timelock": 0,
            "publicKeys": [
              "ed25519:202e30265cd2e791b54dadd74afeda7ece98a9f4c9749e4985bfb79b2bb89869"
            ],
            "signaturesRequired": 1
          }
        },
        "signatures": [
          "dead0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ]
      }
    }
  ],
  "fileContractRevisions": [
    {
      "parent": {
        "id": "ccdd000000000000000000000000000000000000000000000000000000000000",
        "stateElement": {
          "leafIndex": 79799
        },
        "v2FileContract": {
          "capacity": 346092994560,
          "filesize": 346092994560,
          "fileMerkleRoot": "0102030000000000000000000000000000000000000000000000000000000000",
          "proofHeight": 28217,
          "expirationHeight": 28361,
          "renterOutput": {
            "value": "100000000000000000000000000",
            "address": "c812eb804c7656c0a4c90415f979da6ea19f2a52739e1d45eaed0f2994ef306babba6e9d63d0"
          },
          "hostOutput": {
            "value": "500000000000000000000000000",
            "address": "f5c35a20ae3f72484419aa99308fc14dca007fc1575762c1fce33e949e8029fbc2ce14e724d3"
          },
          "missedHostValue": "50000000000000000000000000",
          "totalCollateral": "200000000000000000000000000",
          "renterPublicKey": "ed25519:c3489d97edea95632306a6b93c58809c8a3af855b658ac230f564ea384b61812",
          "hostPublicKey": "ed25519:6d228e5a58b45bf73b09f9ad22952f8adb1dccd5bf086f3b35b8139851423d03",
          "revisionNumber": 0,
          "renterSignature": "01020300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "hostSignature": "04050600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        }
      },
      "revision": {
        "capacity": 347338702848,
        "filesize": 347338702848,
        "fileMerkleRoot": "0405060000000000000000000000000000000000000000000000000000000000",
        "proofHeight": 28217,
        "expirationHeight": 28361,
        "renterOutput": {
          "value": "100000000000000000000000000",
          "address": "c812eb804c7656c0a4c90415f979da6ea19f2a52739e1d45eaed0f2994ef306babba6e9d63d0"
        },
        "hostOutput": {
          "value": "500000000000000000000000000",
          "address": "f5c35a20ae3f72484419aa99308fc14dca007fc1575762c1fce33e949e8029fbc2ce14e724d3"
        },
        "missedHostValue": "50000000000000000000000000",
        "totalCollateral": "200000000000000000000000000",
        "renterPublicKey": "ed25519:c3489d97edea95632306a6b93c58809c8a3af855b658ac230f564ea384b61812",
        "hostPublicKey": "ed25519:6d228e5a58b45bf73b09f9ad22952f8adb1dccd5bf086f3b35b8139851423d03",
        "revisionNumber": 355,
        "renterSignature": "01020300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "hostSignature": "04050600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
      }
    }
  ],
  "arbitraryData": "Tm9uU2lhIHRlc3QgZGF0YQ==",
  "minerFee": "10000000000000000000000"
}
        ]"#;

        let txns: Vec<v2::Transaction> =
            serde_json::from_str(TXNS_JSON).expect("v2 transactions to deserialize from JSON");
        for (i, txn) in txns.iter().enumerate() {
            let json = serde_json::to_string_pretty(txn).expect("re-serialize");
            println!("txn[{i}]:\n{json}");
            let mut buf = Vec::new();
            crate::encoding::SiaEncodable::encode(txn, &mut buf).expect("encode");
            println!("txn[{i}] hex: {}", hex::encode(&buf));
            println!("txn[{i}] id: {}", txn.id());
            println!();
        }
    }

    /// Decode a V1Currency: [u64 len] [N big-endian bytes]
    fn decode_v1_currency<R: std::io::Read>(
        r: &mut R,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut len_buf = [0u8; 8];
        r.read_exact(&mut len_buf)?;
        let len = u64::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)?;
        Ok(())
    }

    /// Skip V1 transactions in the buffer
    fn skip_v1_transactions<R: std::io::Read>(
        r: &mut R,
        count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf8 = [0u8; 8];

        let read_u64 = |r: &mut R| -> Result<u64, Box<dyn std::error::Error>> {
            let mut b = [0u8; 8];
            r.read_exact(&mut b)?;
            Ok(u64::from_le_bytes(b))
        };

        let skip_n = |r: &mut R, n: usize| -> Result<(), Box<dyn std::error::Error>> {
            let mut buf = vec![0u8; n];
            r.read_exact(&mut buf)?;
            Ok(())
        };

        let skip_bytes = |r: &mut R| -> Result<(), Box<dyn std::error::Error>> {
            let n = {
                let mut b = [0u8; 8];
                r.read_exact(&mut b)?;
                u64::from_le_bytes(b) as usize
            };
            let mut buf = vec![0u8; n];
            r.read_exact(&mut buf)?;
            Ok(())
        };

        for _ in 0..count {
            // SiacoinInputs
            r.read_exact(&mut buf8)?;
            let sci_count = u64::from_le_bytes(buf8) as usize;
            for _ in 0..sci_count {
                skip_n(r, 32)?; // ParentID
                // UnlockConditions: timelock + public_keys + sigs_required
                skip_n(r, 8)?; // timelock
                r.read_exact(&mut buf8)?;
                let pk_count = u64::from_le_bytes(buf8) as usize;
                for _ in 0..pk_count {
                    skip_n(r, 16)?; // Specifier
                    skip_bytes(r)?; // Key
                }
                skip_n(r, 8)?; // sigs_required
            }

            // SiacoinOutputs
            r.read_exact(&mut buf8)?;
            let sco_count = u64::from_le_bytes(buf8) as usize;
            for _ in 0..sco_count {
                decode_v1_currency(r)?;
                skip_n(r, 32)?;
            }

            // FileContracts
            r.read_exact(&mut buf8)?;
            let fc_count = u64::from_le_bytes(buf8) as usize;
            for _ in 0..fc_count {
                skip_n(r, 8 + 32 + 8 + 8)?;
                decode_v1_currency(r)?; // Payout
                r.read_exact(&mut buf8)?;
                let vpo = u64::from_le_bytes(buf8) as usize;
                for _ in 0..vpo {
                    decode_v1_currency(r)?;
                    skip_n(r, 32)?;
                }
                r.read_exact(&mut buf8)?;
                let mpo = u64::from_le_bytes(buf8) as usize;
                for _ in 0..mpo {
                    decode_v1_currency(r)?;
                    skip_n(r, 32)?;
                }
                skip_n(r, 32 + 8)?; // UnlockHash + RevisionNumber
            }

            // FileContractRevisions
            r.read_exact(&mut buf8)?;
            let fcr_count = u64::from_le_bytes(buf8) as usize;
            for _ in 0..fcr_count {
                skip_n(r, 32)?; // ParentID
                // UnlockConditions
                skip_n(r, 8)?;
                r.read_exact(&mut buf8)?;
                let pk_count = u64::from_le_bytes(buf8) as usize;
                for _ in 0..pk_count {
                    skip_n(r, 16)?;
                    skip_bytes(r)?;
                }
                skip_n(r, 8)?;
                skip_n(r, 8 + 8 + 32 + 8 + 8)?;
                r.read_exact(&mut buf8)?;
                let vpo = u64::from_le_bytes(buf8) as usize;
                for _ in 0..vpo {
                    decode_v1_currency(r)?;
                    skip_n(r, 32)?;
                }
                r.read_exact(&mut buf8)?;
                let mpo = u64::from_le_bytes(buf8) as usize;
                for _ in 0..mpo {
                    decode_v1_currency(r)?;
                    skip_n(r, 32)?;
                }
                skip_n(r, 32)?; // UnlockHash
            }

            // StorageProofs
            r.read_exact(&mut buf8)?;
            let sp_count = u64::from_le_bytes(buf8) as usize;
            for _ in 0..sp_count {
                skip_n(r, 32 + 64)?;
                r.read_exact(&mut buf8)?;
                let proof_count = u64::from_le_bytes(buf8) as usize;
                skip_n(r, proof_count * 32)?;
            }

            // SiafundInputs
            r.read_exact(&mut buf8)?;
            let sfi_count = u64::from_le_bytes(buf8) as usize;
            for _ in 0..sfi_count {
                skip_n(r, 32)?;
                // UnlockConditions
                skip_n(r, 8)?;
                r.read_exact(&mut buf8)?;
                let pk_count = u64::from_le_bytes(buf8) as usize;
                for _ in 0..pk_count {
                    skip_n(r, 16)?;
                    skip_bytes(r)?;
                }
                skip_n(r, 8)?;
                skip_n(r, 32)?; // ClaimAddress
            }

            // SiafundOutputs
            r.read_exact(&mut buf8)?;
            let sfo_count = u64::from_le_bytes(buf8) as usize;
            for _ in 0..sfo_count {
                decode_v1_currency(r)?;
                skip_n(r, 32)?;
                decode_v1_currency(r)?;
            }

            // MinerFees
            r.read_exact(&mut buf8)?;
            let fee_count = u64::from_le_bytes(buf8) as usize;
            for _ in 0..fee_count {
                decode_v1_currency(r)?;
            }

            // ArbitraryData
            r.read_exact(&mut buf8)?;
            let arb_count = u64::from_le_bytes(buf8) as usize;
            for _ in 0..arb_count {
                skip_bytes(r)?;
            }

            // Signatures
            r.read_exact(&mut buf8)?;
            let sig_count = u64::from_le_bytes(buf8) as usize;
            for _ in 0..sig_count {
                skip_n(r, 32 + 8 + 8)?; // ParentID + PublicKeyIndex + Timelock
                // CoveredFields
                skip_n(r, 1)?; // WholeTransaction
                for _ in 0..10 {
                    r.read_exact(&mut buf8)?;
                    let c = u64::from_le_bytes(buf8) as usize;
                    skip_n(r, c * 8)?;
                }
                skip_bytes(r)?; // Signature
            }
        }

        Ok(())
    }

    const UNASSIGNED_LEAF_INDEX: u64 = 10_101_010_101_010_101_010;

    /// Set merkle proof lengths based on numLeaves (mirrors syncer_wasm set_proof_lengths)
    fn set_proof_lengths(txns: &mut [v2::Transaction], num_leaves: u64) {
        let set_len = |se: &mut super::StateElement| {
            if se.leaf_index != UNASSIGNED_LEAF_INDEX && se.leaf_index < num_leaves {
                let xor = se.leaf_index ^ num_leaves;
                let bits_len = 64 - xor.leading_zeros();
                let proof_len = (bits_len - 1) as usize;
                se.merkle_proof = vec![super::Hash256::default(); proof_len];
            }
        };
        for txn in txns.iter_mut() {
            for input in &mut txn.siacoin_inputs {
                set_len(&mut input.parent.state_element);
            }
            for input in &mut txn.siafund_inputs {
                set_len(&mut input.parent.state_element);
            }
            for rev in &mut txn.file_contract_revisions {
                set_len(&mut rev.parent.state_element);
            }
            for res in &mut txn.file_contract_resolutions {
                set_len(&mut res.parent.state_element);
                if let v2::ContractResolution::StorageProof(ref mut sp) = res.resolution {
                    set_len(&mut sp.proof_index.state_element);
                }
            }
        }
    }

    /// Collect (leaf_index, proof_len) for all StateElements
    fn collect_element_leaves(txns: &[v2::Transaction]) -> Vec<(u64, usize)> {
        let mut leaves = Vec::new();
        let visit = |se: &super::StateElement, leaves: &mut Vec<(u64, usize)>| {
            if se.leaf_index != UNASSIGNED_LEAF_INDEX {
                leaves.push((se.leaf_index, se.merkle_proof.len()));
            }
        };
        for txn in txns {
            for input in &txn.siacoin_inputs {
                visit(&input.parent.state_element, &mut leaves);
            }
            for input in &txn.siafund_inputs {
                visit(&input.parent.state_element, &mut leaves);
            }
            for rev in &txn.file_contract_revisions {
                visit(&rev.parent.state_element, &mut leaves);
            }
            for res in &txn.file_contract_resolutions {
                visit(&res.parent.state_element, &mut leaves);
                if let v2::ContractResolution::StorageProof(ref sp) = res.resolution {
                    visit(&sp.proof_index.state_element, &mut leaves);
                }
            }
        }
        leaves
    }

    /// Compute multiproof size (mirrors syncer_wasm compute_multiproof_size)
    fn compute_multiproof_size(leaves: &[(u64, usize)]) -> usize {
        let mut trees: Vec<Vec<(u64, usize)>> = vec![Vec::new(); 64];
        for &(leaf_index, proof_len) in leaves {
            if proof_len < 64 {
                trees[proof_len].push((leaf_index, proof_len));
            }
        }

        fn proof_size(i: u64, j: u64, leaves: &[(u64, usize)]) -> usize {
            let height = (j.wrapping_sub(i)).trailing_zeros() as usize;
            if leaves.is_empty() {
                return 1;
            } else if height == 0 {
                return 0;
            }
            let mid = i.wrapping_add(j) / 2;
            let split = leaves.partition_point(|&(idx, _)| idx < mid);
            let (left, right) = leaves.split_at(split);
            proof_size(i, mid, left) + proof_size(mid, j, right)
        }

        let clear_bits = |x: u64, n: usize| -> u64 {
            if n >= 64 {
                0
            } else {
                x & !((1u64 << n) - 1)
            }
        };

        let mut size = 0;
        for (height, tree_leaves) in trees.iter_mut().enumerate() {
            if tree_leaves.is_empty() {
                continue;
            }
            tree_leaves.sort_by_key(|&(idx, _)| idx);
            let start = clear_bits(tree_leaves[0].0, height + 1);
            let end = if height >= 64 {
                0
            } else {
                start.wrapping_add(1u64 << height)
            };
            size += proof_size(start, end, tree_leaves);
        }
        size
    }

    fn decode_v2_block(label: &str, hex_str: &str) {
        decode_v2_block_inner(label, hex_str, false);
    }

    fn decode_v2_block_verify_multiproof(label: &str, hex_str: &str) {
        decode_v2_block_inner(label, hex_str, true);
    }

    fn decode_v2_block_inner(label: &str, hex_str: &str, verify_multiproof: bool) {
        let bytes = hex::decode(&hex_str).expect("valid hex");
        let total_len = bytes.len();
        println!("Block bytes: {total_len}");

        let mut r = std::io::Cursor::new(&bytes);

        // --- V1 Block part ---
        // ParentID (32 bytes)
        let mut parent_id = [0u8; 32];
        std::io::Read::read_exact(&mut r, &mut parent_id).expect("parent_id");
        println!("parent_id: {}", hex::encode(parent_id));

        // Nonce
        let nonce = <u64 as crate::encoding::SiaDecodable>::decode(&mut r).expect("nonce");
        println!("nonce: {nonce}");

        // Timestamp
        let timestamp = <u64 as crate::encoding::SiaDecodable>::decode(&mut r).expect("timestamp");
        println!("timestamp: {timestamp}");

        // MinerPayouts (V1SiacoinOutput)
        let payout_count =
            <u64 as crate::encoding::SiaDecodable>::decode(&mut r).expect("payout_count");
        println!("payout_count: {payout_count}");
        for i in 0..payout_count {
            decode_v1_currency(&mut r).expect("v1 currency");
            let mut addr = [0u8; 32];
            std::io::Read::read_exact(&mut r, &mut addr).expect("addr");
            println!("  payout[{i}] addr: {}", hex::encode(addr));
        }

        // V1 Transactions
        let v1_tx_count =
            <u64 as crate::encoding::SiaDecodable>::decode(&mut r).expect("v1_tx_count");
        println!("v1_tx_count: {v1_tx_count}");
        let pos_before_skip = r.position();
        skip_v1_transactions(&mut r, v1_tx_count as usize).expect("skip v1 txns");
        let pos_after_skip = r.position();
        println!(
            "  skipped {} bytes of V1 transactions",
            pos_after_skip - pos_before_skip
        );

        // V2BlockData presence
        let mut presence = [0u8; 1];
        std::io::Read::read_exact(&mut r, &mut presence).expect("presence");
        println!("v2 presence: {}", presence[0]);
        assert_eq!(presence[0], 1, "expected V2 data present");

        // V2BlockData
        let height = <u64 as crate::encoding::SiaDecodable>::decode(&mut r).expect("height");
        println!("v2 height: {height}");

        let mut commitment = [0u8; 32];
        std::io::Read::read_exact(&mut r, &mut commitment).expect("commitment");
        println!("v2 commitment: {}", hex::encode(commitment));

        // V2 Transactions (multiproof format)
        let v2_txn_pos = r.position();
        println!("v2 txn decode starts at byte {v2_txn_pos}");
        let mut txns: Vec<v2::Transaction> =
            crate::encoding::SiaDecodable::decode(&mut r).expect("v2 transactions");
        println!("decoded {} v2 transactions", txns.len());

        // numLeaves
        let num_leaves =
            <u64 as crate::encoding::SiaDecodable>::decode(&mut r).expect("num_leaves");
        println!("num_leaves: {num_leaves}");

        // Set proof lengths and compute multiproof size
        set_proof_lengths(&mut txns, num_leaves);
        let leaves = collect_element_leaves(&txns);
        let mp_size = compute_multiproof_size(&leaves);
        println!("computed multiproof size: {mp_size} hashes ({} bytes)", mp_size * 32);

        if verify_multiproof {
            // Read multiproof hashes
            let mut hash_buf = [0u8; 32];
            for i in 0..mp_size {
                std::io::Read::read_exact(&mut r, &mut hash_buf)
                    .unwrap_or_else(|e| panic!("failed to read multiproof hash {i}/{mp_size}: {e}"));
            }

            // Verify all bytes consumed
            let remaining = total_len as u64 - r.position();
            assert_eq!(
                remaining, 0,
                "[{label}] {remaining} bytes remaining after full decode — multiproof size mismatch!"
            );

            println!("[{label}] V2 Block decode: SUCCESS (all bytes consumed, multiproof verified)");
        } else {
            let remaining = total_len as u64 - r.position();
            println!("[{label}] V2 Block decode: SUCCESS ({remaining} bytes remaining for multiproof)");
        }
    }

    #[test]
    fn test_v2_block_decode_go_encoded() {
        // Test 1: Block with V1 + V2 transactions
        let out = std::process::Command::new("/tmp/v2txnid")
            .arg("encode-block")
            .output()
            .expect("run v2txnid encode-block");
        assert!(out.status.success(), "v2txnid encode-block failed");
        let hex1 = String::from_utf8(out.stdout)
            .expect("utf8")
            .trim()
            .to_string();
        decode_v2_block("v1+v2 block", &hex1);

        // Test 2: Block with NO V1 transactions, multiple V2 txns including FileContractResolution
        let out = std::process::Command::new("/tmp/v2txnid")
            .arg("encode-block-no-v1")
            .output()
            .expect("run v2txnid encode-block-no-v1");
        assert!(out.status.success(), "v2txnid encode-block-no-v1 failed");
        let hex2 = String::from_utf8(out.stdout)
            .expect("utf8")
            .trim()
            .to_string();
        decode_v2_block("v2-only block", &hex2);

        // Test 3: Block with non-empty Merkle proofs (exercises multiproof encoding)
        let out = std::process::Command::new("/tmp/v2txnid")
            .arg("encode-block-multiproof")
            .output()
            .expect("run v2txnid encode-block-multiproof");
        assert!(
            out.status.success(),
            "v2txnid encode-block-multiproof failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let hex3 = String::from_utf8(out.stdout)
            .expect("utf8")
            .trim()
            .to_string();
        decode_v2_block_verify_multiproof("multiproof block", &hex3);
    }

    #[test]
    fn test_v2txn_decode_go_encoded() {
        // Each entry: (name, hex from Go's V2Transaction.EncodeTo)
        // Generated by: go build -o /tmp/v2txnid ./cmd/v2txnid/ && /tmp/v2txnid encode-tests
        let cases: &[(&str, &str)] = &[
            ("miner_fee_only", "020004000000000000000040b2bac9e0191e02000000000000"),
            ("siacoin_outputs_only", "02020000000000000001000000000000000000009ef47ebc89a7e8320300000000dcd7e2459a184a800e26c0b16e4a14ed30d12a3b9a5dcb6de5b4899c6b7f1fb9"),
            ("siacoin_inputs_only", "02010000000000000001000000000000004c7a0100000000000000000000000000aabb000000000000000000000000000000000000000000000000000000000000000000e83c80d09f3c2e3b0300000000dcd7e2459a184a800e26c0b16e4a14ed30d12a3b9a5dcb6de5b4899c6b7f1fb900000000000000000107000000000000000001000000000000006564323535313900000000000000000020000000000000006d6950f32037c80fb07b4a1c5208cfd9c8647a8cb867433f1698cb1105b7bc1101000000000000000100000000000000dead00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            ("file_contract_revisions_only", "0220000000000000000100000000000000b7370100000000000000000000000000ccdd0000000000000000000000000000000000000000000000000000000000000000c094500000000000c094500000000102030000000000000000000000000000000000000000000000000000000000396e000000000000c96e000000000000000000e4d20cc8dcd2b7520000000000c60881da61456adb2fcb088f144a900ef15460f73aea5937a4af242c4f5afdb1000000741e40e84f1e979d0100000000367a6d39fb1d5e6d655fd41b49c58d6cac1e5965b313e561a1184dee9bea41b7000000726906646ee95b290000000000000000c8a51990b9a56fa50000000000d2b9a32e5dd1809cad999731887b796e4d529c6e454a5561c63987b0f5d372e8bcb31a4c0b55ccb8f0582eee95ee09a76ad3278260ae4f52b984d38a90ea959600000000000000000102030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004050600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000df50000000000000df500000000405060000000000000000000000000000000000000000000000000000000000396e000000000000c96e000000000000000000e4d20cc8dcd2b7520000000000c60881da61456adb2fcb088f144a900ef15460f73aea5937a4af242c4f5afdb1000000741e40e84f1e979d0100000000367a6d39fb1d5e6d655fd41b49c58d6cac1e5965b313e561a1184dee9bea41b7000000726906646ee95b290000000000000000c8a51990b9a56fa50000000000d2b9a32e5dd1809cad999731887b796e4d529c6e454a5561c63987b0f5d372e8bcb31a4c0b55ccb8f0582eee95ee09a76ad3278260ae4f52b984d38a90ea959663010000000000000102030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004050600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            ("arbitrary_data_only", "02000100000000000010000000000000004e6f6e53696120746573742064617461"),
            ("attestation_only", "02800000000000000001000000000000006d6950f32037c80fb07b4a1c5208cfd9c8647a8cb867433f1698cb1105b7bc110800000000000000746573742d6b65790a00000000000000746573742d76616c7565aabbcc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            ("new_foundation_address_only", "020002000000000000dcd7e2459a184a800e26c0b16e4a14ed30d12a3b9a5dcb6de5b4899c6b7f1fb9"),
            ("full_transaction", "02230500000000000001000000000000004c7a0100000000000000000000000000aabb000000000000000000000000000000000000000000000000000000000000000000e83c80d09f3c2e3b0300000000dcd7e2459a184a800e26c0b16e4a14ed30d12a3b9a5dcb6de5b4899c6b7f1fb900000000000000000107000000000000000001000000000000006564323535313900000000000000000020000000000000006d6950f32037c80fb07b4a1c5208cfd9c8647a8cb867433f1698cb1105b7bc1101000000000000000100000000000000dead0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000009ef47ebc89a7e8320300000000dcd7e2459a184a800e26c0b16e4a14ed30d12a3b9a5dcb6de5b4899c6b7f1fb90100000000000000b7370100000000000000000000000000ccdd0000000000000000000000000000000000000000000000000000000000000000c094500000000000c094500000000102030000000000000000000000000000000000000000000000000000000000396e000000000000c96e000000000000000000e4d20cc8dcd2b7520000000000c60881da61456adb2fcb088f144a900ef15460f73aea5937a4af242c4f5afdb1000000741e40e84f1e979d0100000000367a6d39fb1d5e6d655fd41b49c58d6cac1e5965b313e561a1184dee9bea41b7000000726906646ee95b290000000000000000c8a51990b9a56fa50000000000d2b9a32e5dd1809cad999731887b796e4d529c6e454a5561c63987b0f5d372e8bcb31a4c0b55ccb8f0582eee95ee09a76ad3278260ae4f52b984d38a90ea959600000000000000000102030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004050600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000df50000000000000df500000000405060000000000000000000000000000000000000000000000000000000000396e000000000000c96e000000000000000000e4d20cc8dcd2b7520000000000c60881da61456adb2fcb088f144a900ef15460f73aea5937a4af242c4f5afdb1000000741e40e84f1e979d0100000000367a6d39fb1d5e6d655fd41b49c58d6cac1e5965b313e561a1184dee9bea41b7000000726906646ee95b290000000000000000c8a51990b9a56fa50000000000d2b9a32e5dd1809cad999731887b796e4d529c6e454a5561c63987b0f5d372e8bcb31a4c0b55ccb8f0582eee95ee09a76ad3278260ae4f52b984d38a90ea95966301000000000000010203000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000405060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000004e6f6e53696120746573742064617461000040b2bac9e0191e02000000000000"),
        ];

        for (name, hex_str) in cases {
            let bytes = hex::decode(hex_str).expect("valid hex");
            let mut cursor = std::io::Cursor::new(&bytes);
            match crate::encoding::SiaDecodable::decode(&mut cursor) {
                Ok(txn) => {
                    let txn: v2::Transaction = txn;
                    // Re-encode and verify round-trip
                    let mut re_encoded = Vec::new();
                    crate::encoding::SiaEncodable::encode(&txn, &mut re_encoded).expect("encode");
                    let re_hex = hex::encode(&re_encoded);
                    assert_eq!(
                        *hex_str, re_hex,
                        "[{name}] round-trip mismatch"
                    );
                    println!("[{name}] OK — decoded and round-tripped");
                }
                Err(e) => {
                    let pos = cursor.position();
                    panic!(
                        "[{name}] FAILED to decode at byte {pos}/{}: {e}",
                        bytes.len()
                    );
                }
            }
        }
    }

    #[test]
    fn test_v2txn_id_go_vs_rust() {
        // SAMPLE JSON — replace with the transaction you want to test
        const TXN_JSON: &str = r#"{
  "id": "1079faa98c13608d8b541285ef736d6c85b42a0322c25d3dc8a3e1ed304c750f",
  "siacoinOutputs": [
    {
      "id": "7131af78d389412e9cdcf2f0eb67ebfc626215a90554d864e7a6ffbcca299dc8",
      "value": "990000000000000000000000000",
      "address": "109b873684a28b6e7b4eef26784c68752c44d51a6d4270ee6831e7c1aae79dc6af11c332cc14"
    }
  ],
  "siafundOutputs": [],
  "siacoinInputs": [
    {
      "parent": {
        "id": "aabb000000000000000000000000000000000000000000000000000000000000",
        "stateElement": {
          "leafIndex": 96844
        },
        "siacoinOutput": {
          "value": "1000000000000000000000000000",
          "address": "109b873684a28b6e7b4eef26784c68752c44d51a6d4270ee6831e7c1aae79dc6af11c332cc14"
        },
        "maturityHeight": 0
      },
      "satisfiedPolicy": {
        "policy": {
          "type": "uc",
          "policy": {
            "timelock": 0,
            "publicKeys": [
              "ed25519:202e30265cd2e791b54dadd74afeda7ece98a9f4c9749e4985bfb79b2bb89869"
            ],
            "signaturesRequired": 1
          }
        },
        "signatures": [
          "dead0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ]
      }
    }
  ],
  "fileContractRevisions": [
    {
      "parent": {
        "id": "ccdd000000000000000000000000000000000000000000000000000000000000",
        "stateElement": {
          "leafIndex": 79799
        },
        "v2FileContract": {
          "capacity": 346092994560,
          "filesize": 346092994560,
          "fileMerkleRoot": "0102030000000000000000000000000000000000000000000000000000000000",
          "proofHeight": 28217,
          "expirationHeight": 28361,
          "renterOutput": {
            "value": "100000000000000000000000000",
            "address": "c812eb804c7656c0a4c90415f979da6ea19f2a52739e1d45eaed0f2994ef306babba6e9d63d0"
          },
          "hostOutput": {
            "value": "500000000000000000000000000",
            "address": "f5c35a20ae3f72484419aa99308fc14dca007fc1575762c1fce33e949e8029fbc2ce14e724d3"
          },
          "missedHostValue": "50000000000000000000000000",
          "totalCollateral": "200000000000000000000000000",
          "renterPublicKey": "ed25519:c3489d97edea95632306a6b93c58809c8a3af855b658ac230f564ea384b61812",
          "hostPublicKey": "ed25519:6d228e5a58b45bf73b09f9ad22952f8adb1dccd5bf086f3b35b8139851423d03",
          "revisionNumber": 0,
          "renterSignature": "01020300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "hostSignature": "04050600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        }
      },
      "revision": {
        "capacity": 347338702848,
        "filesize": 347338702848,
        "fileMerkleRoot": "0405060000000000000000000000000000000000000000000000000000000000",
        "proofHeight": 28217,
        "expirationHeight": 28361,
        "renterOutput": {
          "value": "100000000000000000000000000",
          "address": "c812eb804c7656c0a4c90415f979da6ea19f2a52739e1d45eaed0f2994ef306babba6e9d63d0"
        },
        "hostOutput": {
          "value": "500000000000000000000000000",
          "address": "f5c35a20ae3f72484419aa99308fc14dca007fc1575762c1fce33e949e8029fbc2ce14e724d3"
        },
        "missedHostValue": "50000000000000000000000000",
        "totalCollateral": "200000000000000000000000000",
        "renterPublicKey": "ed25519:c3489d97edea95632306a6b93c58809c8a3af855b658ac230f564ea384b61812",
        "hostPublicKey": "ed25519:6d228e5a58b45bf73b09f9ad22952f8adb1dccd5bf086f3b35b8139851423d03",
        "revisionNumber": 355,
        "renterSignature": "01020300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "hostSignature": "04050600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
      }
    }
  ],
  "arbitraryData": "Tm9uU2lhIHRlc3QgZGF0YQ==",
  "minerFee": "10000000000000000000000"
}"#;

        // Deserialize in Rust
        let txn: v2::Transaction =
            serde_json::from_str(TXN_JSON).expect("deserialize v2 transaction");

        // Encode in Rust
        let mut rust_buf = Vec::new();
        crate::encoding::SiaEncodable::encode(&txn, &mut rust_buf).expect("encode");
        let rust_hex = hex::encode(&rust_buf);
        let rust_id = txn.id();
        println!("Rust TXID: {rust_id}");
        println!("Rust hex:  {rust_hex}");

        // Call Go binary
        let go_binary = "/tmp/v2txnid";
        let output = std::process::Command::new(go_binary)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(TXN_JSON.as_bytes())
                    .unwrap();
                child.wait_with_output()
            })
            .expect("failed to run v2txnid binary — build it first: cd indexd && go build -o /tmp/v2txnid ./cmd/v2txnid/");

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("v2txnid failed: {stderr}");
        }

        let go_output = String::from_utf8(output.stdout).expect("valid utf8");
        let mut lines = go_output.lines();
        let go_id = lines.next().unwrap_or("").trim().to_string();
        let go_hex = lines.next().unwrap_or("").trim().to_string();
        println!("Go   TXID: {go_id}");
        println!("Go   hex:  {go_hex}");

        // Find first byte difference
        let rust_bytes = hex::decode(&rust_hex).unwrap();
        let go_bytes = hex::decode(&go_hex).unwrap();
        for (i, (r, g)) in rust_bytes.iter().zip(go_bytes.iter()).enumerate() {
            if r != g {
                println!("First difference at byte {i}: rust=0x{r:02x} go=0x{g:02x}");
                break;
            }
        }
        if rust_bytes.len() != go_bytes.len() {
            println!(
                "Length mismatch: rust={} go={}",
                rust_bytes.len(),
                go_bytes.len()
            );
        }

        assert_eq!(rust_hex, go_hex, "Encoded bytes must match");
        assert_eq!(
            rust_id.to_string(),
            go_id,
            "Rust and Go transaction IDs must match"
        );
    }
}
