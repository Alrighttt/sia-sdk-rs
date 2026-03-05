use std::io::{Read, Write};

use sia::encoding::{SiaDecodable, SiaEncodable, V1SiaDecodable, V1SiaEncodable};
use sia::types::Specifier;
use thiserror::Error;

use crate::types::{Header, PeerInfo};

/// The protocol version string used during handshake.
pub const PROTOCOL_VERSION: &str = "2.0.0";

/// Maximum length for version/accept strings in the handshake.
const MAX_STRING_LEN: usize = 128;

/// Maximum length for a handshake header message.
const MAX_HEADER_LEN: usize = 32 + 8 + 128; // GenesisID + UniqueID + NetAddress

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encoding error: {0}")]
    Encoding(#[from] sia::encoding::Error),
    #[error("peer rejected header: {0}")]
    Rejected(String),
    #[error("peer has different genesis block")]
    GenesisIDMismatch,
    #[error("peer has same unique ID as us")]
    SameUniqueID,
    #[error("message too large: {len} > {max}")]
    MessageTooLarge { len: usize, max: usize },
}

pub type Result<T> = std::result::Result<T, Error>;

// --- V1 framing ---
// V1 messages are prefixed with an 8-byte LE length.

/// Write a V1-framed message: [8-byte LE length][payload].
pub fn write_v1<W: Write>(w: &mut W, payload: &[u8]) -> Result<()> {
    w.write_all(&(payload.len() as u64).to_le_bytes())?;
    w.write_all(payload)?;
    Ok(())
}

/// Read a V1-framed message, enforcing max_len on the payload.
pub fn read_v1<R: Read>(r: &mut R, max_len: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 8];
    r.read_exact(&mut len_buf)?;
    let len = u64::from_le_bytes(len_buf) as usize;
    if len > max_len {
        return Err(Error::MessageTooLarge {
            len,
            max: max_len,
        });
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write a V1-framed string: the frame payload is [8-byte LE string len][UTF-8 bytes].
pub fn write_v1_string<W: Write>(w: &mut W, s: &str) -> Result<()> {
    let mut payload = Vec::with_capacity(8 + s.len());
    s.to_string().encode_v1(&mut payload)?;
    write_v1(w, &payload)
}

/// Read a V1-framed string.
pub fn read_v1_string<R: Read>(r: &mut R, max_len: usize) -> Result<String> {
    let payload = read_v1(r, max_len)?;
    let mut cursor = &payload[..];
    let s = String::decode_v1(&mut cursor)?;
    Ok(s)
}

/// Write a V1-framed object using V1 encoding.
pub fn write_v1_object<W: Write, T: V1SiaEncodable>(w: &mut W, obj: &T) -> Result<()> {
    let mut payload = Vec::new();
    obj.encode_v1(&mut payload)?;
    write_v1(w, &payload)
}

/// Read a V1-framed object using V1 decoding.
pub fn read_v1_object<R: Read, T: V1SiaDecodable>(r: &mut R, max_len: usize) -> Result<T> {
    let payload = read_v1(r, max_len)?;
    let mut cursor = &payload[..];
    let obj = T::decode_v1(&mut cursor)?;
    Ok(obj)
}

// --- Handshake ---

pub fn validate_header(ours: &Header, theirs: &Header) -> Result<()> {
    if theirs.genesis_id != ours.genesis_id {
        return Err(Error::GenesisIDMismatch);
    }
    if theirs.unique_id == ours.unique_id {
        return Err(Error::SameUniqueID);
    }
    Ok(())
}

fn read_header_and_accept<S: Read + Write>(
    s: &mut S,
    our_header: &Header,
) -> Result<(String, [u8; 8])> {
    let peer_header: Header = read_v1_object(s, MAX_HEADER_LEN)?;
    if let Err(e) = validate_header(our_header, &peer_header) {
        write_v1_string(s, &e.to_string())?;
        return Err(e);
    }
    write_v1_string(s, "accept")?;

    // Extract the port from the peer's net_address and combine with
    // the actual remote address. For now, just use the peer's net_address
    // since we don't have access to the remote addr at this layer.
    let addr = peer_header.net_address.clone();
    let unique_id = peer_header.unique_id;
    Ok((addr, unique_id))
}

fn write_header_and_wait_accept<S: Read + Write>(s: &mut S, our_header: &Header) -> Result<()> {
    write_v1_object(s, our_header)?;
    let accept = read_v1_string(s, MAX_STRING_LEN)?;
    if accept != "accept" {
        return Err(Error::Rejected(accept));
    }
    Ok(())
}

/// Perform the initiator (dialer) side of the gateway handshake.
///
/// Sequence: write version → read version → write header → read accept →
/// read peer header → write accept
pub fn dial_handshake<S: Read + Write>(s: &mut S, our_header: &Header) -> Result<PeerInfo> {
    // 1. Exchange versions
    write_v1_string(s, PROTOCOL_VERSION)?;
    let peer_version = read_v1_string(s, MAX_STRING_LEN)?;

    // 2. Write our header, wait for accept
    write_header_and_wait_accept(s, our_header)?;

    // 3. Read peer header, send accept
    let (addr, unique_id) = read_header_and_accept(s, our_header)?;

    Ok(PeerInfo {
        version: peer_version,
        addr,
        unique_id,
    })
}

/// Perform the responder (acceptor) side of the gateway handshake.
///
/// Sequence: read version → write version → read peer header → validate →
/// write accept → write our header → read accept
pub fn accept_handshake<S: Read + Write>(s: &mut S, our_header: &Header) -> Result<PeerInfo> {
    // 1. Exchange versions
    let peer_version = read_v1_string(s, MAX_STRING_LEN)?;
    write_v1_string(s, PROTOCOL_VERSION)?;

    // 2. Read peer header, send accept
    let (addr, unique_id) = read_header_and_accept(s, our_header)?;

    // 3. Write our header, wait for accept
    write_header_and_wait_accept(s, our_header)?;

    Ok(PeerInfo {
        version: peer_version,
        addr,
        unique_id,
    })
}

// --- RPC stream helpers ---
// RPC streams use V2 encoding (no V1 length-prefix framing).

/// Write a 16-byte RPC specifier to the stream.
pub fn write_rpc_id<W: Write>(w: &mut W, id: &Specifier) -> Result<()> {
    id.encode(w)?;
    Ok(())
}

/// Read a 16-byte RPC specifier from the stream.
pub fn read_rpc_id<R: Read>(r: &mut R) -> Result<Specifier> {
    let id = Specifier::decode(r)?;
    Ok(id)
}

/// Write an RPC request body using V2 encoding (no frame).
pub fn write_request<W: Write, T: SiaEncodable>(w: &mut W, req: &T) -> Result<()> {
    req.encode(w)?;
    Ok(())
}

/// Read an RPC request body using V2 decoding (no frame).
pub fn read_request<R: Read, T: SiaDecodable>(r: &mut R) -> Result<T> {
    let req = T::decode(r)?;
    Ok(req)
}

/// Write an RPC response body using V2 encoding (no frame).
pub fn write_response<W: Write, T: SiaEncodable>(w: &mut W, resp: &T) -> Result<()> {
    resp.encode(w)?;
    Ok(())
}

/// Read an RPC response body using V2 decoding (no frame).
pub fn read_response<R: Read, T: SiaDecodable>(r: &mut R) -> Result<T> {
    let resp = T::decode(r)?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Header;
    use sia::types::BlockID;

    #[test]
    fn test_v1_string_roundtrip() {
        let mut buf = Vec::new();
        write_v1_string(&mut buf, "hello").unwrap();

        let mut cursor = &buf[..];
        let s = read_v1_string(&mut cursor, 128).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_v1_framing() {
        let payload = b"test data";
        let mut buf = Vec::new();
        write_v1(&mut buf, payload).unwrap();

        // Verify frame structure: 8-byte LE length + payload
        assert_eq!(buf.len(), 8 + payload.len());
        let len = u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize;
        assert_eq!(len, payload.len());
        assert_eq!(&buf[8..], payload);

        let mut cursor = &buf[..];
        let result = read_v1(&mut cursor, 128).unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn test_v1_message_too_large() {
        let payload = vec![0u8; 100];
        let mut buf = Vec::new();
        write_v1(&mut buf, &payload).unwrap();

        let mut cursor = &buf[..];
        let result = read_v1(&mut cursor, 50);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_v1_roundtrip() {
        let header = Header {
            genesis_id: BlockID::default(),
            unique_id: [1, 2, 3, 4, 5, 6, 7, 8],
            net_address: "127.0.0.1:9981".to_string(),
        };

        let mut buf = Vec::new();
        write_v1_object(&mut buf, &header).unwrap();

        let mut cursor = &buf[..];
        let decoded: Header = read_v1_object(&mut cursor, MAX_HEADER_LEN).unwrap();

        assert_eq!(decoded.genesis_id, header.genesis_id);
        assert_eq!(decoded.unique_id, header.unique_id);
        assert_eq!(decoded.net_address, header.net_address);
    }

    #[test]
    fn test_handshake_roundtrip() {
        use std::io::Cursor;

        let initiator_header = Header {
            genesis_id: BlockID::default(),
            unique_id: [1, 0, 0, 0, 0, 0, 0, 0],
            net_address: "1.2.3.4:9981".to_string(),
        };
        let responder_header = Header {
            genesis_id: BlockID::default(),
            unique_id: [2, 0, 0, 0, 0, 0, 0, 0],
            net_address: "5.6.7.8:9981".to_string(),
        };

        // Simulate: initiator writes to a buffer, responder reads from it and writes back.
        // We'll use a two-pass approach: first the initiator writes its part,
        // then the responder processes and writes back.

        // Step 1: initiator writes version + header
        let mut init_to_resp = Vec::new();
        write_v1_string(&mut init_to_resp, PROTOCOL_VERSION).unwrap();
        write_v1_object(&mut init_to_resp, &initiator_header).unwrap();

        // Step 2: responder reads version, writes version, reads header, validates, writes accept, writes header
        let mut resp_cursor = Cursor::new(&init_to_resp);
        let peer_version = read_v1_string(&mut resp_cursor, MAX_STRING_LEN).unwrap();
        assert_eq!(peer_version, PROTOCOL_VERSION);

        let mut resp_to_init = Vec::new();
        write_v1_string(&mut resp_to_init, PROTOCOL_VERSION).unwrap();

        // responder reads initiator header
        let peer_header: Header = read_v1_object(&mut resp_cursor, MAX_HEADER_LEN).unwrap();
        assert!(validate_header(&responder_header, &peer_header).is_ok());
        write_v1_string(&mut resp_to_init, "accept").unwrap();

        // responder writes its header
        write_v1_object(&mut resp_to_init, &responder_header).unwrap();

        // Step 3: initiator reads version, reads accept, reads responder header, sends accept
        let mut init_cursor = Cursor::new(&resp_to_init);
        let server_version = read_v1_string(&mut init_cursor, MAX_STRING_LEN).unwrap();
        assert_eq!(server_version, PROTOCOL_VERSION);

        let accept = read_v1_string(&mut init_cursor, MAX_STRING_LEN).unwrap();
        assert_eq!(accept, "accept");

        let server_header: Header = read_v1_object(&mut init_cursor, MAX_HEADER_LEN).unwrap();
        assert_eq!(server_header.unique_id, responder_header.unique_id);
        assert_eq!(server_header.net_address, responder_header.net_address);
    }

    #[test]
    fn test_rpc_id_roundtrip() {
        use crate::rpc::RPC_DISCOVER_IP;

        let mut buf = Vec::new();
        write_rpc_id(&mut buf, &RPC_DISCOVER_IP).unwrap();
        assert_eq!(buf.len(), 16);

        let mut cursor = &buf[..];
        let id = read_rpc_id(&mut cursor).unwrap();
        assert_eq!(id, RPC_DISCOVER_IP);
    }
}
