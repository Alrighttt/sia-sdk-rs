use sia::encoding::{SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use sia::types::{BlockHeader, BlockID, ChainIndex, Hash256, Specifier};

// v1 RPCs
pub const RPC_SHARE_NODES: Specifier = sia::specifier!("ShareNodes");
pub const RPC_DISCOVER_IP: Specifier = sia::specifier!("DiscoverIP");

// v2 RPCs
pub const RPC_SEND_HEADERS: Specifier = sia::specifier!("SendHeaders");
pub const RPC_SEND_V2_BLOCKS: Specifier = sia::specifier!("SendV2Blocks");
pub const RPC_SEND_TRANSACTIONS: Specifier = sia::specifier!("SendTransactions");
pub const RPC_SEND_CHECKPOINT: Specifier = sia::specifier!("SendCheckpoint");
pub const RPC_RELAY_V2_HEADER: Specifier = sia::specifier!("RelayV2Header");
pub const RPC_RELAY_V2_BLOCK_OUTLINE: Specifier = sia::specifier!("RelayV2Outline");
pub const RPC_RELAY_V2_TRANSACTION_SET: Specifier = sia::specifier!("RelayV2Txns");

// --- Request types ---

#[derive(Debug, SiaEncode, SiaDecode)]
pub struct SendHeadersRequest {
    pub index: ChainIndex,
    pub max: u64,
}

#[derive(Debug, SiaEncode, SiaDecode)]
pub struct SendV2BlocksRequest {
    pub history: Vec<BlockID>,
    pub max: u64,
}

#[derive(Debug, SiaEncode, SiaDecode)]
pub struct SendTransactionsRequest {
    pub index: ChainIndex,
    pub hashes: Vec<Hash256>,
}

#[derive(Debug, SiaEncode, SiaDecode)]
pub struct SendCheckpointRequest {
    pub index: ChainIndex,
}

#[derive(Debug, SiaEncode, SiaDecode)]
pub struct RelayV2HeaderRequest {
    pub header: BlockHeader,
}

#[derive(Debug, SiaEncode, SiaDecode)]
pub struct RelayV2TransactionSetRequest {
    pub index: ChainIndex,
    pub transactions: Vec<sia::types::v2::Transaction>,
}

// --- Response types ---

#[derive(Debug, SiaEncode, SiaDecode)]
pub struct ShareNodesResponse {
    pub peers: Vec<String>,
}

#[derive(Debug, SiaEncode, SiaDecode)]
pub struct DiscoverIPResponse {
    pub ip: String,
}

#[derive(Debug, SiaEncode, SiaDecode)]
pub struct SendHeadersResponse {
    pub headers: Vec<BlockHeader>,
    pub remaining: u64,
}

// NOTE: SendV2BlocksResponse, SendTransactionsResponse, and SendCheckpointResponse
// require V2 encoding for Block and v1::Transaction, which are not yet implemented
// in the sia_sdk. These will be added once the SDK gains V2Block and V2-encoded
// v1::Transaction support.

// Note: RelayV2Header, RelayV2BlockOutline, and RelayV2TransactionSet have empty responses.

// --- V2BlockOutline types (custom encoding required) ---

/// An OutlineTransaction represents a transaction in a V2BlockOutline.
/// It may contain a full v1 transaction, a full v2 transaction, or just a hash.
#[derive(Debug)]
pub enum OutlineTransaction {
    V1(sia::types::v1::Transaction),
    V2(sia::types::v2::Transaction),
    Hash(Hash256),
}
