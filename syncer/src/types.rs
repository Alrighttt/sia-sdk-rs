use sia::encoding::{V1SiaDecodable, V1SiaDecode, V1SiaEncodable, V1SiaEncode};
use sia::types::BlockID;

/// A UniqueID is a randomly-generated nonce that helps prevent self-connections
/// and double-connections.
pub type UniqueID = [u8; 8];

/// A Header contains peer metadata exchanged during the gateway handshake.
#[derive(Debug, Clone, V1SiaEncode, V1SiaDecode)]
pub struct Header {
    pub genesis_id: BlockID,
    pub unique_id: UniqueID,
    pub net_address: String,
}

/// PeerInfo contains peer metadata received during a gateway handshake.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub version: String,
    pub addr: String,
    pub unique_id: UniqueID,
}
