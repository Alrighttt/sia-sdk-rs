use std::cell::RefCell;
use std::io;

use js_sys::{Reflect, Uint8Array};
use serde_json::json;
use sia::encoding::{SiaDecodable, SiaEncodable, V1SiaDecodable, V1SiaEncodable};
use sia::types::v1::UnlockConditions;
use sia::types::v2::{self, ContractResolution};
use sia::types::{Address, BlockID, ChainIndex, Currency, Hash256, StateElement};
use sia_syncer::encoding::{self, PROTOCOL_VERSION};
use sia_syncer::rpc::{
    RPC_DISCOVER_IP, RPC_SEND_HEADERS, RPC_SEND_V2_BLOCKS, SendHeadersRequest,
    SendHeadersResponse, SendV2BlocksRequest,
};
use sia_syncer::types::{Header, PeerInfo};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{ReadableStreamDefaultReader, WritableStreamDefaultWriter};

// Cached header IDs from a previous sync, shared between sync_chain and generate_filters.
thread_local! {
    static CACHED_HEADER_IDS: RefCell<Option<Vec<BlockID>>> = RefCell::new(None);
}

// --- IndexedDB persistence for header IDs ---

#[wasm_bindgen(inline_js = "
export function idb_save(key, data) {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open('sia_syncer', 1);
        req.onupgradeneeded = () => req.result.createObjectStore('cache');
        req.onsuccess = () => {
            const tx = req.result.transaction('cache', 'readwrite');
            tx.objectStore('cache').put(data, key);
            tx.oncomplete = () => { req.result.close(); resolve(); };
            tx.onerror = () => { req.result.close(); reject(tx.error); };
        };
        req.onerror = () => reject(req.error);
    });
}

export function idb_load(key) {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open('sia_syncer', 1);
        req.onupgradeneeded = () => req.result.createObjectStore('cache');
        req.onsuccess = () => {
            const tx = req.result.transaction('cache', 'readonly');
            const get = tx.objectStore('cache').get(key);
            get.onsuccess = () => { req.result.close(); resolve(get.result || null); };
            get.onerror = () => { req.result.close(); reject(get.error); };
        };
        req.onerror = () => reject(req.error);
    });
}
")]
extern "C" {
    fn idb_save(key: &str, data: Uint8Array) -> js_sys::Promise;
    fn idb_load(key: &str) -> js_sys::Promise;
}

async fn save_header_ids(ids: &[BlockID]) -> Result<(), JsValue> {
    let mut buf = Vec::with_capacity(ids.len() * 32);
    for id in ids {
        buf.extend_from_slice(id.as_ref());
    }
    let arr = Uint8Array::from(&buf[..]);
    JsFuture::from(idb_save("header_ids", arr)).await?;
    Ok(())
}

async fn load_header_ids() -> Result<Option<Vec<BlockID>>, JsValue> {
    let result = JsFuture::from(idb_load("header_ids")).await?;
    if result.is_null() || result.is_undefined() {
        return Ok(None);
    }
    let arr = Uint8Array::from(result);
    let bytes = arr.to_vec();
    if bytes.len() % 32 != 0 {
        return Ok(None);
    }
    let ids: Vec<BlockID> = bytes
        .chunks_exact(32)
        .map(|chunk| {
            let mut id = [0u8; 32];
            id.copy_from_slice(chunk);
            BlockID::from(id)
        })
        .collect();
    Ok(Some(ids))
}

// --- Block cache (IndexedDB) ---

async fn cache_block(height: u64, raw_bytes: &[u8]) -> Result<(), JsValue> {
    let key = format!("block:{}", height);
    let arr = Uint8Array::from(raw_bytes);
    JsFuture::from(idb_save(&key, arr)).await?;
    Ok(())
}

async fn load_cached_block(height: u64) -> Result<Option<DecodedBlock>, JsValue> {
    let key = format!("block:{}", height);
    let result = JsFuture::from(idb_load(&key)).await?;
    if result.is_null() || result.is_undefined() {
        return Ok(None);
    }
    let arr = Uint8Array::from(result);
    let bytes = arr.to_vec();
    let mut cursor: &[u8] = &bytes;
    let block = decode_v2_block(&mut cursor, bytes.len())
        .map_err(|e| JsValue::from_str(&format!("cached block decode: {:?}", e)))?;
    Ok(Some(block))
}

// --- WebTransport stream wrapper ---

struct WtStream {
    reader: ReadableStreamDefaultReader,
    writer: WritableStreamDefaultWriter,
    read_buf: Vec<u8>,
}

impl WtStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), JsValue> {
        let mut filled = 0;
        while filled < buf.len() {
            if !self.read_buf.is_empty() {
                let n = std::cmp::min(self.read_buf.len(), buf.len() - filled);
                buf[filled..filled + n].copy_from_slice(&self.read_buf[..n]);
                self.read_buf.drain(..n);
                filled += n;
                continue;
            }

            let result = JsFuture::from(self.reader.read()).await?;

            let done = Reflect::get(&result, &JsValue::from_str("done"))?
                .as_bool()
                .unwrap_or(true);
            if done {
                return Err(JsValue::from_str("stream closed unexpectedly"));
            }

            let value = Reflect::get(&result, &JsValue::from_str("value"))?;
            let chunk = Uint8Array::new(&value);
            let mut data = vec![0u8; chunk.length() as usize];
            chunk.copy_to(&mut data);
            self.read_buf.extend_from_slice(&data);
        }
        Ok(())
    }

    async fn read_to_end(&mut self) -> Result<Vec<u8>, JsValue> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.read_buf);
        self.read_buf.clear();
        loop {
            let result = JsFuture::from(self.reader.read()).await?;
            let done = Reflect::get(&result, &JsValue::from_str("done"))?
                .as_bool()
                .unwrap_or(true);
            if done {
                break;
            }
            let value = Reflect::get(&result, &JsValue::from_str("value"))?;
            let chunk = Uint8Array::new(&value);
            let mut data = vec![0u8; chunk.length() as usize];
            chunk.copy_to(&mut data);
            buf.extend_from_slice(&data);
        }
        Ok(buf)
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<(), JsValue> {
        let array = Uint8Array::from(data);
        JsFuture::from(self.writer.write_with_chunk(&array)).await?;
        Ok(())
    }

    async fn close_writer(&mut self) -> Result<(), JsValue> {
        JsFuture::from(self.writer.close()).await?;
        Ok(())
    }
}

/// Open a new bidirectional stream on the WebTransport connection.
async fn open_stream(wt: &web_sys::WebTransport) -> Result<WtStream, JsValue> {
    let bidi = JsFuture::from(wt.create_bidirectional_stream()).await?;
    let bidi = web_sys::WebTransportBidirectionalStream::from(bidi);
    let reader = bidi
        .readable()
        .get_reader()
        .dyn_into::<ReadableStreamDefaultReader>()?;
    let writer = bidi.writable().get_writer()?;
    Ok(WtStream {
        reader,
        writer,
        read_buf: Vec::new(),
    })
}

// --- Async V1 framing helpers (for handshake) ---

async fn async_read_v1_frame(s: &mut WtStream, max_len: usize) -> Result<Vec<u8>, JsValue> {
    let mut len_buf = [0u8; 8];
    s.read_exact(&mut len_buf).await?;
    let len = u64::from_le_bytes(len_buf) as usize;
    if len > max_len {
        return Err(JsValue::from_str(&format!(
            "message too large: {len} > {max_len}"
        )));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn async_write_v1_frame(s: &mut WtStream, payload: &[u8]) -> Result<(), JsValue> {
    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    frame.extend_from_slice(payload);
    s.write_all(&frame).await
}

async fn async_read_v1_string(s: &mut WtStream) -> Result<String, JsValue> {
    let payload = async_read_v1_frame(s, 128).await?;
    let str =
        String::decode_v1(&mut &payload[..]).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(str)
}

async fn async_write_v1_string(s: &mut WtStream, val: &str) -> Result<(), JsValue> {
    let mut payload = Vec::with_capacity(8 + val.len());
    val.to_string()
        .encode_v1(&mut payload)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    async_write_v1_frame(s, &payload).await
}

async fn async_write_v1_object<T: V1SiaEncodable>(
    s: &mut WtStream,
    obj: &T,
) -> Result<(), JsValue> {
    let mut payload = Vec::new();
    obj.encode_v1(&mut payload)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    async_write_v1_frame(s, &payload).await
}

async fn async_read_v1_object<T: V1SiaDecodable>(
    s: &mut WtStream,
    max_len: usize,
) -> Result<T, JsValue> {
    let payload = async_read_v1_frame(s, max_len).await?;
    T::decode_v1(&mut &payload[..]).map_err(|e| JsValue::from_str(&e.to_string()))
}

// --- Async handshake ---

const MAX_HEADER_LEN: usize = 32 + 8 + 128;

async fn dial_handshake(s: &mut WtStream, our_header: &Header) -> Result<PeerInfo, JsValue> {
    async_write_v1_string(s, PROTOCOL_VERSION).await?;
    let peer_version = async_read_v1_string(s).await?;

    async_write_v1_object(s, our_header).await?;
    let accept = async_read_v1_string(s).await?;
    if accept != "accept" {
        return Err(JsValue::from_str(&format!(
            "peer rejected our header: {accept}"
        )));
    }

    let peer_header: Header = async_read_v1_object(s, MAX_HEADER_LEN).await?;
    encoding::validate_header(our_header, &peer_header)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    async_write_v1_string(s, "accept").await?;

    Ok(PeerInfo {
        version: peer_version,
        addr: peer_header.net_address.clone(),
        unique_id: peer_header.unique_id,
    })
}

// --- Async DiscoverIP RPC ---

async fn discover_ip(wt: &web_sys::WebTransport) -> Result<String, JsValue> {
    let mut stream = open_stream(wt).await?;

    let mut id_buf = Vec::new();
    RPC_DISCOVER_IP
        .encode(&mut id_buf)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    stream.write_all(&id_buf).await?;

    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf).await?;
    let len = u64::from_le_bytes(len_buf) as usize;
    let mut ip_buf = vec![0u8; len];
    stream.read_exact(&mut ip_buf).await?;
    let ip = String::from_utf8(ip_buf).map_err(|e| JsValue::from_str(&e.to_string()))?;

    stream.close_writer().await?;
    Ok(ip)
}

// --- Async SendHeaders RPC ---

const BLOCK_HEADER_SIZE: usize = 32 + 8 + 8 + 32;

async fn send_headers_rpc(
    wt: &web_sys::WebTransport,
    index: ChainIndex,
    max: u64,
) -> Result<SendHeadersResponse, JsValue> {
    let mut stream = open_stream(wt).await?;

    let mut id_buf = Vec::new();
    RPC_SEND_HEADERS
        .encode(&mut id_buf)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    stream.write_all(&id_buf).await?;

    let req = SendHeadersRequest { index, max };
    let mut req_buf = Vec::new();
    req.encode(&mut req_buf)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    stream.write_all(&req_buf).await?;

    let mut count_buf = [0u8; 8];
    stream.read_exact(&mut count_buf).await?;
    let count = u64::from_le_bytes(count_buf) as usize;

    if count as u64 > max {
        return Err(JsValue::from_str(&format!(
            "peer sent too many headers: {count} > {max}"
        )));
    }

    let rest_len = count * BLOCK_HEADER_SIZE + 8;
    let mut rest_buf = vec![0u8; rest_len];
    stream.read_exact(&mut rest_buf).await?;

    let mut full_buf = Vec::with_capacity(8 + rest_len);
    full_buf.extend_from_slice(&count_buf);
    full_buf.extend_from_slice(&rest_buf);

    let response = SendHeadersResponse::decode(&mut &full_buf[..])
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Verify PoW chain linkage: each header's parent_id must match the previous header's id()
    if !response.headers.is_empty() {
        let mut expected_parent = index.id;
        for (i, header) in response.headers.iter().enumerate() {
            if header.parent_id != expected_parent {
                return Err(JsValue::from_str(&format!(
                    "PoW verification failed at header {}: parent_id mismatch \
                     (expected {}, got {})",
                    index.height + 1 + i as u64,
                    expected_parent,
                    header.parent_id
                )));
            }
            expected_parent = header.id();
        }
    }

    stream.close_writer().await?;
    Ok(response)
}

// --- V2Block manual decoder ---

const UNASSIGNED_LEAF_INDEX: u64 = u64::MAX;

/// Decoded miner payout from V1SiacoinOutput encoding.
struct MinerPayout {
    value: Currency,
    address: Address,
}

/// Structured V1 transaction data for balance tracking.
struct V1TxnData {
    siacoin_inputs: Vec<Address>,
    siacoin_outputs: Vec<(Address, u128)>,
    total_output_value: u128,
    total_fees: u128,
}

/// Fully decoded V2Block with typed fields.
struct DecodedBlock {
    parent_id: BlockID,
    nonce: u64,
    timestamp: u64,
    miner_payouts: Vec<MinerPayout>,
    v1_addresses: Vec<Address>,
    v1_transactions: Vec<V1TxnData>,
    v2_height: Option<u64>,
    v2_commitment: Option<[u8; 32]>,
    v2_transactions: Vec<v2::Transaction>,
}

impl DecodedBlock {
    /// Compute block ID from the V2 header fields.
    fn id(&self) -> BlockID {
        use blake2b_simd::Params;
        let mut state = Params::new().hash_length(32).to_state();
        let parent_ref: &[u8] = self.parent_id.as_ref();
        state.update(parent_ref);
        state.update(&self.nonce.to_le_bytes());
        state.update(&self.timestamp.to_le_bytes());
        if let Some(commitment) = &self.v2_commitment {
            state.update(commitment);
        } else {
            state.update(&[0u8; 32]);
        }
        state.finalize().into()
    }
}

/// Convert a DecodedBlock to JSON for display.
fn block_to_json(block: &DecodedBlock) -> serde_json::Value {
    let miner_payouts_json: Vec<serde_json::Value> = block
        .miner_payouts
        .iter()
        .map(|p| {
            json!({
                "value": p.value.to_string(),
                "address": p.address.to_string(),
            })
        })
        .collect();

    if let Some(height) = block.v2_height {
        let txns_json = serde_json::to_value(&block.v2_transactions)
            .unwrap_or(json!([]));
        json!({
            "parentID": block.parent_id.to_string(),
            "nonce": block.nonce,
            "timestamp": block.timestamp,
            "minerPayouts": miner_payouts_json,
            "v2": {
                "height": height,
                "commitment": hex::encode(block.v2_commitment.unwrap_or([0u8; 32])),
                "transactionCount": block.v2_transactions.len(),
                "transactions": txns_json,
            }
        })
    } else {
        json!({
            "parentID": block.parent_id.to_string(),
            "nonce": block.nonce,
            "timestamp": block.timestamp,
            "minerPayouts": miner_payouts_json,
        })
    }
}

/// Decode a V1-encoded Currency from a buffer.
/// Format: [u64 LE byte count] [N big-endian bytes]
fn decode_v1_currency(r: &mut &[u8]) -> Result<Currency, JsValue> {
    let io_err = |e: io::Error| JsValue::from_str(&e.to_string());
    let n = u64::decode(r).map_err(|e| JsValue::from_str(&e.to_string()))? as usize;
    if n > 16 {
        return Err(JsValue::from_str(&format!(
            "Currency too large: {n} bytes"
        )));
    }
    let mut buf = [0u8; 16];
    io::Read::read_exact(r, &mut buf[16 - n..]).map_err(io_err)?;
    let hi = u64::from_be_bytes(buf[..8].try_into().unwrap());
    let lo = u64::from_be_bytes(buf[8..].try_into().unwrap());
    Ok(Currency::new((hi as u128) << 64 | lo as u128))
}

/// Collect (leaf_index, proof_len) for all StateElements in transactions.
fn collect_element_leaves(txns: &[v2::Transaction]) -> Vec<(u64, usize)> {
    let mut leaves = Vec::new();
    let visit = |se: &StateElement, leaves: &mut Vec<(u64, usize)>| {
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
            if let ContractResolution::StorageProof(ref sp) = res.resolution {
                visit(&sp.proof_index.state_element, &mut leaves);
            }
        }
    }
    leaves
}

/// Set merkle proof lengths based on numLeaves (for multiproof decoding).
fn set_proof_lengths(txns: &mut [v2::Transaction], num_leaves: u64) {
    let set_len = |se: &mut StateElement| {
        if se.leaf_index != UNASSIGNED_LEAF_INDEX && se.leaf_index < num_leaves {
            let xor = se.leaf_index ^ num_leaves;
            let bits_len = 64 - xor.leading_zeros();
            let proof_len = (bits_len - 1) as usize;
            se.merkle_proof = vec![Hash256::default(); proof_len];
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
            if let ContractResolution::StorageProof(ref mut sp) = res.resolution {
                set_len(&mut sp.proof_index.state_element);
            }
        }
    }
}

/// Compute multiproof size (ported from Go's multiproofSize).
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

/// Parse V1 transactions in the buffer, extracting addresses while skipping
/// all other data. Returns the list of addresses found across all transactions.
fn extract_v1_addresses(
    r: &mut &[u8],
    count: usize,
) -> Result<(Vec<Address>, Vec<V1TxnData>), JsValue> {
    let mut addresses = Vec::new();
    let mut transactions = Vec::new();

    fn read_u64(r: &mut &[u8]) -> Result<u64, JsValue> {
        if r.len() < 8 {
            return Err(JsValue::from_str("unexpected eof in v1 txn"));
        }
        let val = u64::from_le_bytes(r[..8].try_into().unwrap());
        *r = &r[8..];
        Ok(val)
    }

    fn skip_n(r: &mut &[u8], n: usize) -> Result<(), JsValue> {
        if r.len() < n {
            return Err(JsValue::from_str(&format!(
                "unexpected eof in v1 txn: need {n}, have {}",
                r.len()
            )));
        }
        *r = &r[n..];
        Ok(())
    }

    fn read_address(r: &mut &[u8]) -> Result<Address, JsValue> {
        if r.len() < 32 {
            return Err(JsValue::from_str("unexpected eof reading v1 address"));
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&r[..32]);
        *r = &r[32..];
        Ok(Address::from(addr))
    }

    // Length-prefixed bytes: [u64 len] [N bytes]
    fn skip_bytes(r: &mut &[u8]) -> Result<(), JsValue> {
        let n = read_u64(r)? as usize;
        skip_n(r, n)
    }

    // V1Currency: [u64 len] [N big-endian bytes] → read as u128
    fn read_v1_currency(r: &mut &[u8]) -> Result<u128, JsValue> {
        let len = read_u64(r)? as usize;
        if len > 16 {
            return Err(JsValue::from_str(&format!(
                "v1 currency too large: {len} bytes"
            )));
        }
        if r.len() < len {
            return Err(JsValue::from_str("unexpected eof reading v1 currency"));
        }
        let mut buf = [0u8; 16];
        buf[16 - len..].copy_from_slice(&r[..len]);
        *r = &r[len..];
        Ok(u128::from_be_bytes(buf))
    }

    // V1Currency: skip without reading value
    fn skip_v1_currency(r: &mut &[u8]) -> Result<(), JsValue> {
        skip_bytes(r)
    }

    // UnlockKey: [16]Specifier + length-prefixed Key
    fn skip_unlock_key(r: &mut &[u8]) -> Result<(), JsValue> {
        skip_n(r, 16)?;
        skip_bytes(r)
    }

    // UnlockConditions: [8]Timelock + [u64 count][UnlockKey × N] + [8]SigsRequired
    fn skip_unlock_conditions(r: &mut &[u8]) -> Result<(), JsValue> {
        skip_n(r, 8)?; // Timelock
        let pk_count = read_u64(r)? as usize;
        for _ in 0..pk_count {
            skip_unlock_key(r)?;
        }
        skip_n(r, 8) // SignaturesRequired
    }

    // CoveredFields: [1]WholeTransaction + 10 × ([u64 count][u64 × N])
    fn skip_covered_fields(r: &mut &[u8]) -> Result<(), JsValue> {
        skip_n(r, 1)?; // WholeTransaction bool
        for _ in 0..10 {
            let count = read_u64(r)? as usize;
            skip_n(r, count * 8)?;
        }
        Ok(())
    }

    for _ in 0..count {
        let mut txn = V1TxnData {
            siacoin_inputs: Vec::new(),
            siacoin_outputs: Vec::new(),
            total_output_value: 0,
            total_fees: 0,
        };

        // SiacoinInputs: [u64 count] × ([32]ParentID + UnlockConditions)
        let sci_count = read_u64(r)? as usize;
        for _ in 0..sci_count {
            skip_n(r, 32)?; // ParentID
            // Decode UnlockConditions to compute sender address
            let uc = UnlockConditions::decode_v1(r)
                .map_err(|e| JsValue::from_str(&format!("v1 unlock decode: {e}")))?;
            let input_addr = uc.address();
            txn.siacoin_inputs.push(input_addr.clone());
            addresses.push(input_addr);
        }

        // SiacoinOutputs: [u64 count] × (V1Currency + [32]Address)
        let sco_count = read_u64(r)? as usize;
        for _ in 0..sco_count {
            let value = read_v1_currency(r)?;
            let addr = read_address(r)?;
            txn.total_output_value += value;
            txn.siacoin_outputs.push((addr.clone(), value));
            addresses.push(addr);
        }

        // FileContracts
        let fc_count = read_u64(r)? as usize;
        for _ in 0..fc_count {
            skip_n(r, 8 + 32 + 8 + 8)?; // Filesize + FileMerkleRoot + WindowStart + WindowEnd
            skip_v1_currency(r)?; // Payout
            let vpo = read_u64(r)? as usize; // ValidProofOutputs
            for _ in 0..vpo {
                skip_v1_currency(r)?;
                addresses.push(read_address(r)?);
            }
            let mpo = read_u64(r)? as usize; // MissedProofOutputs
            for _ in 0..mpo {
                skip_v1_currency(r)?;
                addresses.push(read_address(r)?);
            }
            addresses.push(read_address(r)?); // UnlockHash
            skip_n(r, 8)?; // RevisionNumber
        }

        // FileContractRevisions
        let fcr_count = read_u64(r)? as usize;
        for _ in 0..fcr_count {
            skip_n(r, 32)?; // ParentID
            skip_unlock_conditions(r)?;
            skip_n(r, 8 + 8 + 32 + 8 + 8)?; // RevisionNumber + Filesize + FileMerkleRoot + WindowStart + WindowEnd
            let vpo = read_u64(r)? as usize;
            for _ in 0..vpo {
                skip_v1_currency(r)?;
                addresses.push(read_address(r)?);
            }
            let mpo = read_u64(r)? as usize;
            for _ in 0..mpo {
                skip_v1_currency(r)?;
                addresses.push(read_address(r)?);
            }
            addresses.push(read_address(r)?); // UnlockHash
        }

        // StorageProofs
        let sp_count = read_u64(r)? as usize;
        for _ in 0..sp_count {
            skip_n(r, 32 + 64)?; // ParentID + Leaf[64]
            let proof_count = read_u64(r)? as usize;
            skip_n(r, proof_count * 32)?; // Proof []Hash256
        }

        // SiafundInputs
        let sfi_count = read_u64(r)? as usize;
        for _ in 0..sfi_count {
            skip_n(r, 32)?; // ParentID
            skip_unlock_conditions(r)?;
            addresses.push(read_address(r)?); // ClaimAddress
        }

        // SiafundOutputs (V1SiafundOutput): V1Currency + [32]Address + V1Currency(ClaimStart)
        let sfo_count = read_u64(r)? as usize;
        for _ in 0..sfo_count {
            skip_v1_currency(r)?; // Value
            addresses.push(read_address(r)?); // Address
            skip_v1_currency(r)?; // ClaimStart
        }

        // MinerFees: [u64 count] × V1Currency
        let fee_count = read_u64(r)? as usize;
        for _ in 0..fee_count {
            let fee = read_v1_currency(r)?;
            txn.total_fees += fee;
        }

        // ArbitraryData: [u64 count] × length-prefixed bytes
        let arb_count = read_u64(r)? as usize;
        for _ in 0..arb_count {
            skip_bytes(r)?;
        }

        // Signatures
        let sig_count = read_u64(r)? as usize;
        for _ in 0..sig_count {
            skip_n(r, 32 + 8 + 8)?; // ParentID + PublicKeyIndex + Timelock
            skip_covered_fields(r)?;
            skip_bytes(r)?; // Signature
        }

        transactions.push(txn);
    }

    Ok((addresses, transactions))
}

/// Decode a single V2Block from a buffer into a DecodedBlock.
/// `buf_start_len` is used for position tracking in error messages.
fn decode_v2_block(r: &mut &[u8], buf_start_len: usize) -> Result<DecodedBlock, JsValue> {
    let pos = || buf_start_len - r.len(); // current byte offset
    let io_err = |e: io::Error| JsValue::from_str(&e.to_string());
    let dec_err = |e: sia::encoding::Error| JsValue::from_str(&e.to_string());

    // --- V1Block part ---
    let mut parent_id_bytes = [0u8; 32];
    io::Read::read_exact(r, &mut parent_id_bytes).map_err(io_err)?;
    let parent_id = BlockID::from(parent_id_bytes);

    let nonce = u64::decode(r).map_err(dec_err)?;
    let timestamp = u64::decode(r).map_err(dec_err)?;

    // MinerPayouts: [u64 count] + N * V1SiacoinOutput (V1Currency + Address)
    let miner_payout_count = u64::decode(r).map_err(dec_err)? as usize;
    if miner_payout_count > 1000 {
        return Err(JsValue::from_str(&format!(
            "suspicious miner_payout_count={miner_payout_count} at pos={}, likely misaligned",
            pos()
        )));
    }
    let mut miner_payouts = Vec::with_capacity(miner_payout_count);
    for _ in 0..miner_payout_count {
        let value = decode_v1_currency(r)?;
        let mut addr = [0u8; 32];
        io::Read::read_exact(r, &mut addr).map_err(io_err)?;
        miner_payouts.push(MinerPayout {
            value,
            address: Address::from(addr),
        });
    }

    // V1 Transactions: extract addresses while skipping
    let v1_tx_count = u64::decode(r).map_err(dec_err)? as usize;
    if v1_tx_count > 100000 {
        return Err(JsValue::from_str(&format!(
            "suspicious v1_tx_count={v1_tx_count} at pos={}, likely misaligned",
            pos()
        )));
    }
    let before_skip = r.len();
    let (v1_addresses, v1_transactions) = if v1_tx_count > 0 {
        extract_v1_addresses(r, v1_tx_count)
            .map_err(|e| JsValue::from_str(&format!(
                "v1 parse failed (v1_tx_count={v1_tx_count}, pos={}, parsed {} bytes so far): {}",
                pos(), before_skip - r.len(), e.as_string().unwrap_or_default()
            )))?
    } else {
        (Vec::new(), Vec::new())
    };

    // --- V2BlockData presence: [u8: 0 or 1] ---
    let mut presence = [0u8; 1];
    io::Read::read_exact(r, &mut presence).map_err(io_err)?;

    if presence[0] != 0 && presence[0] != 1 {
        return Err(JsValue::from_str(&format!(
            "invalid presence byte={} at pos={} (v1_tx_count was {}, {} bytes remaining). \
             first 16 bytes at cursor: {:02x?}",
            presence[0], pos(), v1_tx_count, r.len(),
            &r[..std::cmp::min(16, r.len())]
        )));
    }

    if presence[0] == 0 {
        return Ok(DecodedBlock {
            parent_id,
            nonce,
            timestamp,
            miner_payouts,
            v1_addresses,
            v1_transactions,
            v2_height: None,
            v2_commitment: None,
            v2_transactions: Vec::new(),
        });
    }

    // --- V2BlockData ---
    let height = u64::decode(r).map_err(dec_err)?;

    let mut commitment = [0u8; 32];
    io::Read::read_exact(r, &mut commitment).map_err(io_err)?;

    // V2TransactionsMultiproof
    let v2_txn_pos = pos();
    // Capture context bytes before decode attempt for debugging
    let context_bytes: Vec<u8> = r[..std::cmp::min(64, r.len())].to_vec();
    let mut txns: Vec<v2::Transaction> = Vec::decode(r)
        .map_err(|e| {
            let hex_ctx: String = context_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            JsValue::from_str(&format!(
                "v2 txn decode failed at pos={v2_txn_pos} (v2_height={height}, {} bytes remain): {e}\n\
                 first 64 bytes at decode start: {hex_ctx}",
                context_bytes.len() + r.len()
            ))
        })?;
    let num_leaves = u64::decode(r).map_err(dec_err)?;
    set_proof_lengths(&mut txns, num_leaves);
    let leaves = collect_element_leaves(&txns);
    let mp_size = compute_multiproof_size(&leaves);
    let mut hash_buf = [0u8; 32];
    for _ in 0..mp_size {
        io::Read::read_exact(r, &mut hash_buf).map_err(io_err)?;
    }

    Ok(DecodedBlock {
        parent_id,
        nonce,
        timestamp,
        miner_payouts,
        v1_addresses,
        v1_transactions,
        v2_height: Some(height),
        v2_commitment: Some(commitment),
        v2_transactions: txns,
    })
}

// --- Async SendV2Blocks RPC ---

/// Returns (Vec<(DecodedBlock, raw_bytes)>, remaining_count).
/// raw_bytes is the encoded block data suitable for caching/re-decoding.
async fn send_v2_blocks_rpc(
    wt: &web_sys::WebTransport,
    history: Vec<BlockID>,
    max: u64,
) -> Result<(Vec<(DecodedBlock, Vec<u8>)>, u64), JsValue> {
    let mut stream = open_stream(wt).await?;

    let mut id_buf = Vec::new();
    RPC_SEND_V2_BLOCKS
        .encode(&mut id_buf)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    stream.write_all(&id_buf).await?;

    let req = SendV2BlocksRequest { history, max };
    let mut req_buf = Vec::new();
    req.encode(&mut req_buf)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    stream.write_all(&req_buf).await?;

    let resp_data = stream.read_to_end().await?;
    let mut cursor: &[u8] = &resp_data;
    let total_len = resp_data.len();

    let block_count = u64::decode(&mut cursor)
        .map_err(|e| JsValue::from_str(&e.to_string()))? as usize;

    let mut blocks = Vec::with_capacity(block_count);
    for i in 0..block_count {
        let pre_pos = total_len - cursor.len();
        let block = decode_v2_block(&mut cursor, total_len)
            .map_err(|e| JsValue::from_str(&format!(
                "block {i}/{block_count} (pos={}, {} bytes remaining): {}",
                total_len - cursor.len(), cursor.len(),
                e.as_string().unwrap_or_default()
            )))?;
        let post_pos = total_len - cursor.len();
        let raw = resp_data[pre_pos..post_pos].to_vec();
        blocks.push((block, raw));
    }

    let remaining = u64::decode(&mut cursor)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    stream.close_writer().await?;
    Ok((blocks, remaining))
}

// --- Compact Block Filter (GCS) support ---

use siphasher::sip::SipHasher;
use std::hash::Hasher;

/// A simple bit reader that reads individual bits from a byte slice (MSB-first).
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8, // 0..8
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bit(&mut self) -> Option<bool> {
        if self.byte_pos >= self.data.len() {
            return None;
        }
        let bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Some(bit == 1)
    }

    fn read_bits(&mut self, count: usize) -> Option<u64> {
        let mut value: u64 = 0;
        for _ in 0..count {
            let bit = self.read_bit()?;
            value = (value << 1) | (bit as u64);
        }
        Some(value)
    }
}

/// Map a 64-bit hash uniformly into [0, n) using the multiply-and-shift trick.
fn fast_reduce(hash: u64, n: u64) -> u64 {
    ((hash as u128 * n as u128) >> 64) as u64
}

/// Test if a 32-byte item matches a GCS filter.
///
/// Returns true if the item MIGHT be in the set (with false positive rate 1/2^P),
/// or false if the item is DEFINITELY NOT in the set.
fn gcs_match(filter_data: &[u8], block_id: &[u8; 32], item: &[u8; 32], n: u64, p: u8) -> bool {
    if n == 0 || filter_data.is_empty() {
        return false;
    }

    let m: u64 = 1u64 << p;
    let f = n * m; // filter range

    // SipHash key from block ID (first 16 bytes, little-endian)
    let k0 = u64::from_le_bytes(block_id[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(block_id[8..16].try_into().unwrap());

    // Hash the target item
    let mut hasher = SipHasher::new_with_keys(k0, k1);
    hasher.write(item);
    let hash = hasher.finish();
    let target = fast_reduce(hash, f);

    // Decode Golomb-Rice coded deltas and check if target matches any value
    let mut reader = BitReader::new(filter_data);
    let mut value: u64 = 0;
    for _ in 0..n {
        // Read unary: count zeros until a 1
        let mut quotient: u64 = 0;
        loop {
            match reader.read_bit() {
                Some(false) => quotient += 1,
                Some(true) => break,
                None => return false, // ran out of bits
            }
        }
        // Read P literal bits
        let remainder = reader.read_bits(p as usize).unwrap_or(0);
        let delta = (quotient << p) | remainder;
        value += delta;

        if value == target {
            return true;
        }
        if value > target {
            return false; // values are sorted, no point continuing
        }
    }
    false
}

/// A simple bit writer that writes individual bits to a byte buffer (MSB-first).
struct BitWriter {
    buf: Vec<u8>,
    current: u8,
    bit_pos: u8, // 0..8
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            buf: Vec::new(),
            current: 0,
            bit_pos: 0,
        }
    }

    fn write_bit(&mut self, b: bool) {
        if b {
            self.current |= 1 << (7 - self.bit_pos);
        }
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.buf.push(self.current);
            self.current = 0;
            self.bit_pos = 0;
        }
    }

    fn write_bits(&mut self, val: u64, count: u8) {
        for i in (0..count).rev() {
            self.write_bit((val >> i) & 1 == 1);
        }
    }

    fn into_bytes(mut self) -> Vec<u8> {
        if self.bit_pos > 0 {
            self.buf.push(self.current);
        }
        self.buf
    }
}

/// Build a GCS filter from a set of 32-byte addresses.
/// block_id[0:16] is used as the SipHash-2-4 key.
/// P is the Golomb-Rice parameter (typically 19).
fn build_gcs_filter(addresses: &[[u8; 32]], block_id: &[u8; 32], p: u8) -> Vec<u8> {
    let n = addresses.len() as u64;
    if n == 0 {
        return Vec::new();
    }
    let m: u64 = 1u64 << p;

    // SipHash key from block ID
    let k0 = u64::from_le_bytes(block_id[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(block_id[8..16].try_into().unwrap());

    // Hash each address and map to [0, N*M)
    let mut values: Vec<u64> = addresses
        .iter()
        .map(|addr| {
            let mut hasher = SipHasher::new_with_keys(k0, k1);
            hasher.write(addr);
            fast_reduce(hasher.finish(), n * m)
        })
        .collect();

    values.sort_unstable();

    // Golomb-Rice encode the deltas
    let mut bw = BitWriter::new();
    let mut prev: u64 = 0;
    for v in &values {
        let delta = v - prev;
        prev = *v;
        // Unary: write (delta >> P) zeros, then a 1
        let quotient = delta >> p;
        for _ in 0..quotient {
            bw.write_bit(false);
        }
        bw.write_bit(true);
        // Write low P bits (MSB-first)
        let remainder = delta & (m - 1);
        bw.write_bits(remainder, p);
    }

    bw.into_bytes()
}

// --- Filter file format ---

struct FilterEntry {
    height: u64,
    block_id: [u8; 32],
    address_count: u16,
    filter_data: Vec<u8>,
}

struct FilterFile {
    _version: u32,
    p: u32,
    tip_height: u64,
    entries: Vec<FilterEntry>,
}

fn parse_filter_file(data: &[u8]) -> Result<FilterFile, String> {
    if data.len() < 24 {
        return Err("filter file too small".into());
    }

    // Header: magic(4) + version(4) + count(4) + P(4) + tip_height(8) = 24 bytes
    if &data[0..4] != b"SCBF" {
        return Err("invalid filter file magic".into());
    }
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let count = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let p = u32::from_le_bytes(data[12..16].try_into().unwrap());
    let tip_height = u64::from_le_bytes(data[16..24].try_into().unwrap());

    let mut entries = Vec::with_capacity(count as usize);
    let mut pos = 24usize;

    for _ in 0..count {
        if pos + 46 > data.len() {
            return Err("truncated filter entry header".into());
        }
        let height = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        let mut block_id = [0u8; 32];
        block_id.copy_from_slice(&data[pos + 8..pos + 40]);
        let address_count =
            u16::from_le_bytes(data[pos + 40..pos + 42].try_into().unwrap());
        let filter_len =
            u32::from_le_bytes(data[pos + 42..pos + 46].try_into().unwrap()) as usize;
        pos += 46;

        if pos + filter_len > data.len() {
            return Err("truncated filter data".into());
        }
        let filter_data = data[pos..pos + filter_len].to_vec();
        pos += filter_len;

        entries.push(FilterEntry {
            height,
            block_id,
            address_count,
            filter_data,
        });
    }

    Ok(FilterFile {
        _version: version,
        p,
        tip_height,
        entries,
    })
}

/// Serialize filter entries to SCBF v2 binary format.
fn serialize_filter_file(entries: &[FilterEntry], p: u32, tip_height: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    // Header (24 bytes)
    buf.extend_from_slice(b"SCBF");
    buf.extend_from_slice(&2u32.to_le_bytes()); // version
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    buf.extend_from_slice(&p.to_le_bytes());
    buf.extend_from_slice(&tip_height.to_le_bytes());
    // Per-block entries
    for entry in entries {
        buf.extend_from_slice(&entry.height.to_le_bytes());
        buf.extend_from_slice(&entry.block_id);
        buf.extend_from_slice(&entry.address_count.to_le_bytes());
        buf.extend_from_slice(&(entry.filter_data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&entry.filter_data);
    }
    buf
}

/// Fetch a URL and return the response body as bytes.
async fn fetch_bytes(url: &str) -> Result<Vec<u8>, JsValue> {
    let window = web_sys::window().ok_or(JsValue::from_str("no window"))?;
    let resp_value = JsFuture::from(window.fetch_with_str(url)).await?;
    let resp: web_sys::Response = resp_value.dyn_into()?;
    if !resp.ok() {
        return Err(JsValue::from_str(&format!(
            "filter fetch failed: {} {}",
            resp.status(),
            resp.status_text()
        )));
    }
    let array_buffer = JsFuture::from(
        resp.array_buffer()
            .map_err(|_| JsValue::from_str("failed to get array_buffer"))?,
    )
    .await?;
    let uint8_array = js_sys::Uint8Array::new(&array_buffer);
    let mut data = vec![0u8; uint8_array.length() as usize];
    uint8_array.copy_to(&mut data);
    Ok(data)
}

// --- Balance scanning ---

struct UtxoDetail {
    direction: &'static str, // "received" or "sent"
    amount: u128,
    source: String, // "miner_payout", "v2_output", "v2_input"
    output_id: String,
    counterparty: String, // hex address of the other party in the transaction
}

/// Scan a block for siacoin activity involving the target address.
/// Returns (received, sent, utxo_details).
fn scan_block_balance(block: &DecodedBlock, target: &Address) -> (u128, u128, Vec<UtxoDetail>) {
    let mut received: u128 = 0;
    let mut sent: u128 = 0;
    let mut details = Vec::new();

    // Check miner payouts
    for (i, payout) in block.miner_payouts.iter().enumerate() {
        if payout.address == *target {
            received += *payout.value;
            details.push(UtxoDetail {
                direction: "received",
                amount: *payout.value,
                source: "miner_payout".into(),
                output_id: format!("{}:{}", block.id(), i),
                counterparty: String::new(), // coinbase — no counterparty
            });
        }
    }

    // Check V2 transactions
    for txn in &block.v2_transactions {
        // Pre-compute counterparty for outputs (sender = first input address that isn't target)
        let sender = txn
            .siacoin_inputs
            .iter()
            .map(|i| &i.parent.siacoin_output.address)
            .find(|a| *a != target)
            .or_else(|| txn.siacoin_inputs.first().map(|i| &i.parent.siacoin_output.address))
            .map(|a| a.to_string())
            .unwrap_or_default();

        // Pre-compute counterparty for inputs (recipient = first output address that isn't target)
        let recipient = txn
            .siacoin_outputs
            .iter()
            .map(|o| &o.address)
            .find(|a| *a != target)
            .or_else(|| txn.siacoin_outputs.first().map(|o| &o.address))
            .map(|a| a.to_string())
            .unwrap_or_default();

        for output in &txn.siacoin_outputs {
            if output.address == *target {
                received += *output.value;
                details.push(UtxoDetail {
                    direction: "received",
                    amount: *output.value,
                    source: "v2_output".into(),
                    output_id: String::new(),
                    counterparty: sender.clone(),
                });
            }
        }
        for input in &txn.siacoin_inputs {
            if input.parent.siacoin_output.address == *target {
                sent += *input.parent.siacoin_output.value;
                details.push(UtxoDetail {
                    direction: "sent",
                    amount: *input.parent.siacoin_output.value,
                    source: "v2_input".into(),
                    output_id: input.parent.id.to_string(),
                    counterparty: recipient.clone(),
                });
            }
        }
        // File contract resolutions
        for res in &txn.file_contract_resolutions {
            let fc = &res.parent.v2_file_contract;
            // Counterparty is the other party in the contract
            let other_party = if fc.renter_output.address == *target {
                fc.host_output.address.to_string()
            } else {
                fc.renter_output.address.to_string()
            };
            match &res.resolution {
                ContractResolution::Renewal(renewal) => {
                    if renewal.final_renter_output.address == *target {
                        received += *renewal.final_renter_output.value;
                        details.push(UtxoDetail {
                            direction: "received",
                            amount: *renewal.final_renter_output.value,
                            source: "renewal_final_renter".into(),
                            output_id: res.parent.id.to_string(),
                            counterparty: other_party.clone(),
                        });
                    }
                    if renewal.final_host_output.address == *target {
                        received += *renewal.final_host_output.value;
                        details.push(UtxoDetail {
                            direction: "received",
                            amount: *renewal.final_host_output.value,
                            source: "renewal_final_host".into(),
                            output_id: res.parent.id.to_string(),
                            counterparty: other_party.clone(),
                        });
                    }
                }
                ContractResolution::StorageProof(_) => {
                    if fc.renter_output.address == *target {
                        received += *fc.renter_output.value;
                        details.push(UtxoDetail {
                            direction: "received",
                            amount: *fc.renter_output.value,
                            source: "storageproof_renter".into(),
                            output_id: res.parent.id.to_string(),
                            counterparty: other_party.clone(),
                        });
                    }
                    if fc.host_output.address == *target {
                        received += *fc.host_output.value;
                        details.push(UtxoDetail {
                            direction: "received",
                            amount: *fc.host_output.value,
                            source: "storageproof_host".into(),
                            output_id: res.parent.id.to_string(),
                            counterparty: other_party.clone(),
                        });
                    }
                }
                ContractResolution::Expiration() => {
                    if fc.renter_output.address == *target {
                        received += *fc.renter_output.value;
                        details.push(UtxoDetail {
                            direction: "received",
                            amount: *fc.renter_output.value,
                            source: "expiration_renter".into(),
                            output_id: res.parent.id.to_string(),
                            counterparty: other_party.clone(),
                        });
                    }
                    if fc.host_output.address == *target {
                        received += *fc.missed_host_value;
                        details.push(UtxoDetail {
                            direction: "received",
                            amount: *fc.missed_host_value,
                            source: "expiration_host".into(),
                            output_id: res.parent.id.to_string(),
                            counterparty: other_party.clone(),
                        });
                    }
                }
            }
        }
    }

    // Check V1 transactions
    for txn in &block.v1_transactions {
        let is_sender = txn.siacoin_inputs.iter().any(|a| a == target);

        // Pre-compute counterparties
        let sender_cp = txn
            .siacoin_inputs
            .iter()
            .find(|a| *a != target)
            .or(txn.siacoin_inputs.first())
            .map(|a| a.to_string())
            .unwrap_or_default();

        let recipient_cp = txn
            .siacoin_outputs
            .iter()
            .map(|(a, _)| a)
            .find(|a| *a != target)
            .or(txn.siacoin_outputs.first().map(|(a, _)| a))
            .map(|a| a.to_string())
            .unwrap_or_default();

        // Check outputs for receives
        for (addr, value) in &txn.siacoin_outputs {
            if *addr == *target {
                received += value;
                details.push(UtxoDetail {
                    direction: "received",
                    amount: *value,
                    source: "v1_output".into(),
                    output_id: String::new(),
                    counterparty: sender_cp.clone(),
                });
            }
        }

        // If we're a sender, total sent = sum(all outputs) + fees (by txn balance invariant)
        if is_sender {
            let total_sent = txn.total_output_value + txn.total_fees;
            sent += total_sent;
            details.push(UtxoDetail {
                direction: "sent",
                amount: total_sent,
                source: "v1_input".into(),
                output_id: String::new(),
                counterparty: recipient_cp.clone(),
            });
        }
    }

    (received, sent, details)
}

/// Extract all unique addresses from a decoded block.
fn extract_addresses(block: &DecodedBlock) -> Vec<[u8; 32]> {
    let mut seen = std::collections::HashSet::new();
    let mut add = |addr: &Address| {
        let bytes: [u8; 32] = addr.as_ref().try_into().unwrap();
        seen.insert(bytes);
    };

    // Miner payouts
    for payout in &block.miner_payouts {
        add(&payout.address);
    }

    // V1 transaction addresses
    for addr in &block.v1_addresses {
        add(addr);
    }

    // V2 transactions
    for txn in &block.v2_transactions {
        for output in &txn.siacoin_outputs {
            add(&output.address);
        }
        for input in &txn.siacoin_inputs {
            add(&input.parent.siacoin_output.address);
        }
        for output in &txn.siafund_outputs {
            add(&output.address);
        }
        for input in &txn.siafund_inputs {
            add(&input.claim_address);
        }
        for fc in &txn.file_contracts {
            add(&fc.renter_output.address);
            add(&fc.host_output.address);
        }
        for rev in &txn.file_contract_revisions {
            add(&rev.revision.renter_output.address);
            add(&rev.revision.host_output.address);
        }
        for res in &txn.file_contract_resolutions {
            add(&res.parent.v2_file_contract.renter_output.address);
            add(&res.parent.v2_file_contract.host_output.address);
            if let ContractResolution::Renewal(renewal) = &res.resolution {
                add(&renewal.final_renter_output.address);
                add(&renewal.final_host_output.address);
                add(&renewal.new_contract.renter_output.address);
                add(&renewal.new_contract.host_output.address);
            }
        }
        if let Some(addr) = &txn.new_foundation_address {
            add(addr);
        }
    }

    seen.into_iter().collect()
}

/// Format hastings as SC string (1 SC = 10^24 hastings).
fn format_sc(hastings: u128) -> String {
    let s = hastings.to_string();
    if s.len() <= 24 {
        let decimal = format!("{:0>24}", s);
        format!("0.{} SC", &decimal[..4])
    } else {
        let whole = &s[..s.len() - 24];
        let frac = &s[s.len() - 24..s.len() - 20];
        format!("{whole}.{frac} SC")
    }
}

// --- Connection + handshake helper ---

struct Connection {
    wt: web_sys::WebTransport,
    peer_info: PeerInfo,
}

async fn connect_and_handshake(
    url: &str,
    genesis_id: BlockID,
) -> Result<Connection, JsValue> {
    let mut unique_id = [0u8; 8];
    getrandom::fill(&mut unique_id).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let our_header = Header {
        genesis_id,
        unique_id,
        net_address: "0.0.0.0:0".to_string(),
    };

    let options = web_sys::WebTransportOptions::new();
    let wt = web_sys::WebTransport::new_with_options(url, &options)?;
    JsFuture::from(wt.ready()).await?;

    let mut hs_stream = open_stream(&wt).await?;
    let peer_info = dial_handshake(&mut hs_stream, &our_header).await?;
    hs_stream.close_writer().await?;

    Ok(Connection { wt, peer_info })
}

fn parse_genesis_id(hex: &str) -> Result<BlockID, JsValue> {
    let bytes = hex_to_bytes(hex)?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("genesis_id must be 64 hex characters"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(BlockID::from(arr))
}

/// Parse an address from hex. Accepts either 64-char (raw) or 76-char (with checksum).
fn parse_address(hex: &str) -> Result<Address, JsValue> {
    if hex.len() == 76 {
        // Full address with checksum — use Address::from_str
        hex.parse::<Address>()
            .map_err(|e| JsValue::from_str(&format!("invalid address: {e:?}")))
    } else if hex.len() == 64 {
        // Raw 32-byte hex
        let bytes = hex_to_bytes(hex)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Address::from(arr))
    } else {
        Err(JsValue::from_str(
            "address must be 64 hex chars (raw) or 76 hex chars (with checksum)",
        ))
    }
}

// --- Exported wasm_bindgen functions ---

#[wasm_bindgen]
pub async fn connect_and_discover_ip(
    url: String,
    genesis_id_hex: String,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let conn = connect_and_handshake(&url, genesis_id).await?;
    let ip = discover_ip(&conn.wt).await?;
    conn.wt.close();

    let result = format!(
        r#"{{"version":"{}","addr":"{}","ip":"{}"}}"#,
        conn.peer_info.version, conn.peer_info.addr, ip
    );
    Ok(JsValue::from_str(&result))
}

#[wasm_bindgen]
pub async fn sync_chain(
    url: String,
    genesis_id_hex: String,
    log_fn: js_sys::Function,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;

    log("Connecting...", "info");
    let conn = connect_and_handshake(&url, genesis_id).await?;
    log("WebTransport connected!", "ok");

    log(
        &format!(
            "Handshake complete! Peer version: {}, addr: {}",
            conn.peer_info.version, conn.peer_info.addr
        ),
        "ok",
    );

    let ip = discover_ip(&conn.wt).await?;
    log(&format!("Our IP: {ip}"), "data");

    // Sync headers from genesis to tip
    log("", "info");
    log("Syncing chain headers...", "info");

    let mut current_index = ChainIndex {
        height: 0,
        id: genesis_id,
    };
    let mut total_headers: u64 = 0;
    let max_per_batch: u64 = 2000;
    let mut tip_header = None;
    let mut tip_height: u64 = 0;
    let mut wt = conn.wt;
    let mut retries: u32 = 0;
    let mut header_ids: Vec<BlockID> = Vec::new();
    const MAX_RETRIES: u32 = 3;

    loop {
        let resp = match send_headers_rpc(&wt, current_index, max_per_batch).await {
            Ok(r) => {
                retries = 0;
                r
            }
            Err(_) => {
                retries += 1;
                if retries > MAX_RETRIES {
                    log(
                        &format!("  Failed after {MAX_RETRIES} retries at {total_headers} headers, continuing with what we have"),
                        "info",
                    );
                    break;
                }
                log(
                    &format!(
                        "  Connection lost after {total_headers} headers, reconnecting ({retries}/{MAX_RETRIES})..."
                    ),
                    "info",
                );
                let _ = wt.close();
                let new_conn = connect_and_handshake(&url, genesis_id).await?;
                wt = new_conn.wt;
                log("  Reconnected, resuming...", "ok");
                continue;
            }
        };
        let batch_count = resp.headers.len() as u64;
        total_headers += batch_count;
        let estimated_total = total_headers + resp.remaining;

        if batch_count == 0 {
            log("No more headers to sync.", "info");
            break;
        }

        for header in &resp.headers {
            header_ids.push(header.id());
        }

        let last_header = resp.headers.last().unwrap();
        let last_id = last_header.id();
        tip_height = current_index.height + batch_count;
        tip_header = Some((last_header.clone(), last_id));

        log(
            &format!(
                "  Received {batch_count} headers (total: {total_headers} / ~{estimated_total})"
            ),
            "data",
        );

        if resp.remaining == 0 {
            break;
        }

        current_index = ChainIndex {
            height: tip_height,
            id: last_id,
        };
    }

    // Cache header IDs for generate_filters to reuse (in-memory + IndexedDB)
    if !header_ids.is_empty() {
        log(&format!("Persisting {} header IDs to IndexedDB...", header_ids.len()), "info");
        if let Err(e) = save_header_ids(&header_ids).await {
            log(&format!("Warning: failed to persist header IDs: {:?}", e), "info");
        } else {
            log("Header IDs persisted to IndexedDB.", "ok");
        }
        CACHED_HEADER_IDS.with(|cache| {
            *cache.borrow_mut() = Some(header_ids);
        });
    }

    log("", "info");
    if let Some((header, block_id)) = &tip_header {
        let ts = header.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        log(&format!("Chain tip at height {tip_height}"), "ok");
        log(&format!("  Block ID:   {block_id}"), "data");
        log(&format!("  Parent ID:  {}", header.parent_id), "data");
        log(&format!("  Timestamp:  {ts}"), "data");
        log("", "info");
        log(&format!("Synced {total_headers} headers total."), "ok");

        // Fetch the tip block (may need reconnect after header sync)
        log("", "info");
        log("Fetching tip block via SendV2Blocks...", "info");

        let block_json_value = match send_v2_blocks_rpc(&wt, vec![header.parent_id], 1).await {
            Ok((blocks, remaining)) if !blocks.is_empty() => {
                let block_json = block_to_json(&blocks[0].0);
                log(
                    &format!("Got block! {} remaining on chain.", remaining),
                    "ok",
                );

                let block_str = serde_json::to_string_pretty(&block_json)
                    .unwrap_or_else(|_| "failed to serialize".to_string());
                log("", "info");
                log(&format!("Block JSON ({} bytes):", block_str.len()), "ok");
                log(&block_str, "data");
                block_json
            }
            _ => {
                log("Could not fetch tip block (not yet backfilled)", "info");
                json!(null)
            }
        };

        wt.close();

        let result = json!({
            "version": conn.peer_info.version,
            "addr": conn.peer_info.addr,
            "ip": ip,
            "tipHeight": tip_height,
            "tipBlockID": block_id.to_string(),
            "tipTimestamp": ts,
            "totalHeaders": total_headers,
            "block": block_json_value,
        });
        Ok(JsValue::from_str(&serde_json::to_string(&result).unwrap()))
    } else {
        wt.close();
        log("Chain appears empty.", "err");
        let result = json!({
            "version": conn.peer_info.version,
            "addr": conn.peer_info.addr,
            "ip": ip,
            "tipHeight": 0,
            "totalHeaders": 0,
            "block": null,
        });
        Ok(JsValue::from_str(&serde_json::to_string(&result).unwrap()))
    }
}

#[wasm_bindgen]
pub async fn scan_balance(
    url: String,
    genesis_id_hex: String,
    target_address: String,
    start_height: u64,
    log_fn: js_sys::Function,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let target = parse_address(&target_address)?;

    log("Connecting...", "info");
    let conn = connect_and_handshake(&url, genesis_id).await?;
    log(
        &format!(
            "Connected! Peer version: {}, addr: {}",
            conn.peer_info.version, conn.peer_info.addr
        ),
        "ok",
    );

    // Step 1: If start_height > 0, sync headers to get block ID at start_height - 1
    let mut history: Vec<BlockID> = Vec::new();
    let target_header_height = if start_height > 0 {
        start_height - 1
    } else {
        0
    };

    if start_height > 0 {
        log(
            &format!(
                "Syncing headers to height {target_header_height} to find starting block..."
            ),
            "info",
        );

        let mut current_index = ChainIndex {
            height: 0,
            id: genesis_id,
        };
        let mut headers_synced: u64 = 0;
        let max_per_batch: u64 = 2000;

        loop {
            let remaining_to_target = target_header_height.saturating_sub(headers_synced);
            if remaining_to_target == 0 {
                break;
            }
            let batch_size = std::cmp::min(max_per_batch, remaining_to_target);
            let resp =
                send_headers_rpc(&conn.wt, current_index, batch_size).await?;
            let batch_count = resp.headers.len() as u64;
            if batch_count == 0 {
                return Err(JsValue::from_str(&format!(
                    "chain only has {} headers, cannot start at height {}",
                    headers_synced, start_height
                )));
            }

            headers_synced += batch_count;

            let last_header = resp.headers.last().unwrap();
            let last_id = last_header.id();
            let current_height = current_index.height + batch_count;

            // Check if we've reached the target header height
            // The block ID at height (current_index.height + i + 1) is headers[i].id()
            // We want the block ID at target_header_height
            if current_height >= target_header_height {
                // The header at index (target_header_height - current_index.height - 1) is what we need
                let idx = (target_header_height - current_index.height - 1) as usize;
                if idx < resp.headers.len() {
                    let target_block_id = resp.headers[idx].id();
                    history.push(target_block_id);
                    log(
                        &format!(
                            "  Found block at height {target_header_height}: {}",
                            target_block_id
                        ),
                        "data",
                    );
                }
                break;
            }

            log(
                &format!("  Synced {headers_synced} / {target_header_height} headers"),
                "data",
            );

            current_index = ChainIndex {
                height: current_height,
                id: last_id,
            };
        }
    } else {
        log("Starting from genesis (height 0).", "info");
    }

    // Step 2: Download blocks and scan for address
    log("", "info");
    log(
        &format!(
            "Scanning blocks from height {} for address {}...",
            start_height,
            target.to_string()
        ),
        "info",
    );
    log("", "info");

    let mut total_received: u128 = 0;
    let mut total_sent: u128 = 0;
    let mut blocks_scanned: u64 = 0;
    let mut txns_found: u64 = 0;
    let mut current_height = start_height;
    let blocks_per_batch: u64 = 100;
    let mut wt = conn.wt;

    loop {
        let rpc_result =
            send_v2_blocks_rpc(&wt, history.clone(), blocks_per_batch).await;

        let (blocks_with_raw, remaining) = match rpc_result {
            Ok(result) => result,
            Err(e) => {
                let err_str = format!("{:?}", e);
                // Connection lost — reconnect and retry
                log(
                    &format!("  Connection lost after {blocks_scanned} blocks, reconnecting..."),
                    "info",
                );
                let _ = wt.close();
                let new_conn = connect_and_handshake(&url, genesis_id).await?;
                wt = new_conn.wt;
                log("  Reconnected, resuming scan...", "ok");

                // If we have no history to resume from, we can't continue
                if history.is_empty() {
                    return Err(JsValue::from_str(&format!(
                        "Connection lost and no history to resume from: {err_str}"
                    )));
                }
                // Retry the same batch
                continue;
            }
        };

        if blocks_with_raw.is_empty() {
            break;
        }

        let batch_count = blocks_with_raw.len() as u64;
        let last_block_id = blocks_with_raw.last().unwrap().0.id();

        for (block, _raw) in &blocks_with_raw {
            let height = block.v2_height.unwrap_or(current_height);
            let (received, sent, _details) = scan_block_balance(block, &target);

            if received > 0 || sent > 0 {
                txns_found += 1;
                total_received += received;
                total_sent += sent;
                let net = total_received.saturating_sub(total_sent);

                let mut parts = Vec::new();
                if received > 0 {
                    parts.push(format!("+{}", format_sc(received)));
                }
                if sent > 0 {
                    parts.push(format!("-{}", format_sc(sent)));
                }

                log(
                    &format!(
                        "  Height {}: {} => balance: {}",
                        height,
                        parts.join(", "),
                        format_sc(net),
                    ),
                    "ok",
                );
            }

            current_height += 1;
        }
        blocks_scanned += batch_count;

        // Progress update every batch
        let total_est = blocks_scanned + remaining;
        log(
            &format!(
                "  Scanned {blocks_scanned} / ~{total_est} blocks | received: {} | sent: {} | net: {}",
                format_sc(total_received),
                format_sc(total_sent),
                format_sc(total_received.saturating_sub(total_sent)),
            ),
            "data",
        );

        if remaining == 0 {
            break;
        }

        // Advance: use last block's ID as history for next batch
        history = vec![last_block_id];
    }

    let _ = wt.close();

    let net = total_received.saturating_sub(total_sent);
    log("", "info");
    log("Scan complete!", "ok");
    log(&format!("  Blocks scanned:  {blocks_scanned}"), "data");
    log(&format!("  Transactions:    {txns_found}"), "data");
    log(&format!("  Total received:  {}", format_sc(total_received)), "data");
    log(&format!("  Total sent:      {}", format_sc(total_sent)), "data");
    log(&format!("  Net balance:     {}", format_sc(net)), "ok");

    let result = json!({
        "blocksScanned": blocks_scanned,
        "transactionsFound": txns_found,
        "received": total_received.to_string(),
        "sent": total_sent.to_string(),
        "balance": net.to_string(),
        "receivedSC": format_sc(total_received),
        "sentSC": format_sc(total_sent),
        "balanceSC": format_sc(net),
    });
    Ok(JsValue::from_str(&serde_json::to_string(&result).unwrap()))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, JsValue> {
    if hex.len() % 2 != 0 {
        return Err(JsValue::from_str("hex string must have even length"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| JsValue::from_str(&format!("invalid hex: {e}")))
        })
        .collect()
}

#[wasm_bindgen]
pub async fn generate_filters(
    url: String,
    genesis_id_hex: String,
    log_fn: js_sys::Function,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let p: u8 = 19;

    // Step 1: Connect
    log("Connecting to peer...", "info");
    let conn = connect_and_handshake(&url, genesis_id).await?;
    log(
        &format!(
            "Connected! Peer version: {}, addr: {}",
            conn.peer_info.version, conn.peer_info.addr
        ),
        "ok",
    );

    // Step 2: Sync all headers to discover chain tip and collect block IDs
    // Check in-memory cache first, then IndexedDB, then sync from peer
    let cached = CACHED_HEADER_IDS.with(|cache| cache.borrow().clone());
    let mut wt = conn.wt;

    let header_ids: Vec<BlockID> = if let Some(ids) = cached {
        log(
            &format!("Using {} cached header IDs from memory", ids.len()),
            "ok",
        );
        ids
    } else if let Ok(Some(ids)) = load_header_ids().await {
        log(
            &format!("Loaded {} header IDs from IndexedDB", ids.len()),
            "ok",
        );
        ids
    } else {
        log("Syncing chain headers...", "info");

        let mut current_index = ChainIndex {
            height: 0,
            id: genesis_id,
        };
        let mut total_headers: u64 = 0;
        let max_per_batch: u64 = 2000;
        let mut ids: Vec<BlockID> = Vec::new();
        let mut retries: u32 = 0;
        const MAX_RETRIES: u32 = 3;

        loop {
            let resp = match send_headers_rpc(&wt, current_index, max_per_batch).await {
                Ok(r) => {
                    retries = 0;
                    r
                }
                Err(_) => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        log(
                            &format!("  Failed after {MAX_RETRIES} retries at {total_headers} headers, continuing with what we have"),
                            "info",
                        );
                        break;
                    }
                    log(
                        &format!(
                            "  Connection lost after {total_headers} headers, reconnecting ({retries}/{MAX_RETRIES})..."
                        ),
                        "info",
                    );
                    let _ = wt.close();
                    let new_conn = connect_and_handshake(&url, genesis_id).await?;
                    wt = new_conn.wt;
                    log("  Reconnected, resuming...", "ok");
                    continue;
                }
            };
            let batch_count = resp.headers.len() as u64;

            if batch_count == 0 {
                break;
            }

            for header in &resp.headers {
                ids.push(header.id());
            }

            total_headers += batch_count;
            let estimated_total = total_headers + resp.remaining;
            log(
                &format!("  Headers: {total_headers} / ~{estimated_total}"),
                "data",
            );

            let last_header = resp.headers.last().unwrap();
            let last_id = last_header.id();
            let new_height = current_index.height + batch_count;

            if resp.remaining == 0 {
                break;
            }

            current_index = ChainIndex {
                height: new_height,
                id: last_id,
            };
        }

        log(
            &format!("Header sync complete: {total_headers} headers"),
            "ok",
        );
        ids
    };

    let tip_height = header_ids.len() as u64;

    // Step 3: Download all blocks and build filters
    log("Downloading blocks and building filters...", "info");

    let mut entries: Vec<FilterEntry> = Vec::new();
    let mut history: Vec<BlockID> = Vec::new(); // empty = start from genesis
    let blocks_per_batch: u64 = 100;
    let mut blocks_downloaded: u64 = 0;
    let mut total_addresses: u64 = 0;
    loop {
        let rpc_result = send_v2_blocks_rpc(&wt, history.clone(), blocks_per_batch).await;

        let (blocks_with_raw, remaining) = match rpc_result {
            Ok(result) => result,
            Err(_) => {
                log(
                    &format!(
                        "  Connection lost after {blocks_downloaded} blocks, reconnecting..."
                    ),
                    "info",
                );
                let _ = wt.close();
                let new_conn = connect_and_handshake(&url, genesis_id).await?;
                wt = new_conn.wt;
                log("  Reconnected, resuming...", "ok");
                if history.is_empty() && blocks_downloaded > 0 {
                    break;
                }
                continue;
            }
        };

        if blocks_with_raw.is_empty() {
            break;
        }

        for (block, _raw) in &blocks_with_raw {
            let height = block.v2_height.unwrap_or(blocks_downloaded);
            // Use the header ID (which includes the correct v1 merkle root
            // commitment) instead of DecodedBlock.id() which uses zeros for
            // v1 blocks, producing a different ID than Go computes.
            let block_id_obj = if (blocks_downloaded as usize) < header_ids.len() {
                header_ids[blocks_downloaded as usize].clone()
            } else {
                block.id()
            };
            let block_id_bytes: [u8; 32] = {
                let slice: &[u8] = block_id_obj.as_ref();
                slice.try_into().unwrap()
            };

            let addresses = extract_addresses(block);
            total_addresses += addresses.len() as u64;

            let filter_data = build_gcs_filter(&addresses, &block_id_bytes, p);

            entries.push(FilterEntry {
                height,
                block_id: block_id_bytes,
                address_count: addresses.len() as u16,
                filter_data,
            });

            blocks_downloaded += 1;
        }

        let total_est = blocks_downloaded + remaining;
        let pct = if total_est > 0 {
            (blocks_downloaded as f64 / total_est as f64 * 100.0) as u32
        } else {
            100
        };
        log(
            &format!(
                "  {blocks_downloaded} / ~{total_est} blocks ({pct}%) | {total_addresses} addresses",
            ),
            "data",
        );

        if remaining == 0 {
            break;
        }

        // Use the header ID for the last downloaded block as history.
        // header_ids is 0-indexed where index 0 = height 1.
        let last_header_id = header_ids[(blocks_downloaded - 1) as usize].clone();
        history = vec![last_header_id];
    }

    let _ = wt.close();

    // Step 4: Serialize filter file
    log("Serializing filter file...", "info");
    let file_bytes = serialize_filter_file(&entries, p as u32, tip_height);

    log("", "info");
    log("Filter generation complete!", "ok");
    log(
        &format!("  Blocks processed: {blocks_downloaded}"),
        "data",
    );
    log(
        &format!("  Total addresses:  {total_addresses}"),
        "data",
    );
    log(
        &format!("  Tip height:       {tip_height}"),
        "data",
    );
    log(
        &format!(
            "  File size:        {:.1} KB",
            file_bytes.len() as f64 / 1024.0
        ),
        "data",
    );
    log(
        &format!(
            "  Avg filter size:  {:.0} bytes",
            if entries.is_empty() {
                0.0
            } else {
                file_bytes.len() as f64 / entries.len() as f64
            }
        ),
        "data",
    );

    // Return as Uint8Array
    let uint8_array = Uint8Array::new_with_length(file_bytes.len() as u32);
    uint8_array.copy_from(&file_bytes);
    Ok(uint8_array.into())
}

#[wasm_bindgen]
pub async fn scan_balance_filtered(
    url: String,
    genesis_id_hex: String,
    target_address: String,
    filter_url: String,
    log_fn: js_sys::Function,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let target = parse_address(&target_address)?;
    let target_bytes: [u8; 32] = {
        let slice: &[u8] = target.as_ref();
        slice.try_into().map_err(|_| JsValue::from_str("address must be 32 bytes"))?
    };

    // Step 1: Fetch filter file via HTTP
    log("Downloading compact block filters...", "info");
    let filter_data = fetch_bytes(&filter_url).await?;
    let filter_file = parse_filter_file(&filter_data)
        .map_err(|e| JsValue::from_str(&format!("filter parse error: {e}")))?;
    log(
        &format!(
            "Loaded {} block filters ({:.1} KB, P={})",
            filter_file.entries.len(),
            filter_data.len() as f64 / 1024.0,
            filter_file.p,
        ),
        "ok",
    );

    // Step 2: Test target address against each filter
    log("Scanning filters for matching blocks...", "info");

    let mut matches: Vec<(u64, [u8; 32])> = Vec::new(); // (height, block_id)
    let p = filter_file.p as u8;
    for entry in &filter_file.entries {
        if entry.address_count == 0 {
            continue;
        }
        if gcs_match(
            &entry.filter_data,
            &entry.block_id,
            &target_bytes,
            entry.address_count as u64,
            p,
        ) {
            matches.push((entry.height, entry.block_id));
        }
    }
    log(
        &format!(
            "Filter scan complete: {} potential matches out of {} blocks",
            matches.len(),
            filter_file.entries.len(),
        ),
        "ok",
    );

    if matches.is_empty() {
        log("No filter matches in covered blocks.", "info");
    }

    // Build height → index lookup for getting previous block's ID
    let height_to_idx: std::collections::HashMap<u64, usize> = filter_file
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.height, i))
        .collect();

    // Step 3: Connect to peer and download matching blocks + tail
    log("Connecting to peer...", "info");
    let conn = connect_and_handshake(&url, genesis_id).await?;
    log(
        &format!(
            "Connected! Peer version: {}, addr: {}",
            conn.peer_info.version, conn.peer_info.addr
        ),
        "ok",
    );

    let mut total_received: u128 = 0;
    let mut total_sent: u128 = 0;
    let mut false_positives: u32 = 0;
    let mut blocks_fetched: u32 = 0;
    let mut txns_found: u32 = 0;
    let mut all_utxos: Vec<serde_json::Value> = Vec::new();
    let mut wt = conn.wt;

    for (i, (height, _block_id)) in matches.iter().enumerate() {
        // Try cache first
        if let Ok(Some(cached)) = load_cached_block(*height).await {
            log(
                &format!("  [{}/{}] Height {}: cached", i + 1, matches.len(), height),
                "data",
            );
            let block = &cached;
            let (received, sent, details) = scan_block_balance(block, &target);
            if received > 0 || sent > 0 {
                txns_found += 1;
                total_received += received;
                total_sent += sent;
                let net = total_received.saturating_sub(total_sent);
                for d in &details {
                    all_utxos.push(json!({
                        "height": height,
                        "direction": d.direction,
                        "amount": format_sc(d.amount),
                        "amountHastings": d.amount.to_string(),
                        "source": d.source,
                        "outputId": d.output_id,
                        "counterparty": d.counterparty,
                    }));
                }
                let mut parts = Vec::new();
                if received > 0 { parts.push(format!("+{}", format_sc(received))); }
                if sent > 0 { parts.push(format!("-{}", format_sc(sent))); }
                log(
                    &format!("  [{}/{}] Height {}: {} => balance: {}",
                        i + 1, matches.len(), height, parts.join(", "), format_sc(net)),
                    "ok",
                );
            } else {
                false_positives += 1;
            }
            blocks_fetched += 1;
            continue;
        }

        // Get the PREVIOUS block's ID to use as History
        let prev_block_id = if *height == 0 {
            genesis_id
        } else {
            match height_to_idx.get(&(height - 1)) {
                Some(&idx) => {
                    let mut bid = [0u8; 32];
                    bid.copy_from_slice(&filter_file.entries[idx].block_id);
                    BlockID::from(bid)
                }
                None => {
                    log(
                        &format!("  Warning: no filter entry for height {}, skipping", height - 1),
                        "err",
                    );
                    continue;
                }
            }
        };

        // Fetch 1 block starting after prev_block_id
        let rpc_result = send_v2_blocks_rpc(&wt, vec![prev_block_id], 1).await;
        let blocks_with_raw = match rpc_result {
            Ok((blocks, _remaining)) => blocks,
            Err(_) => {
                // Reconnect and retry
                log(
                    &format!("  Connection lost at block {}, reconnecting...", height),
                    "info",
                );
                let _ = wt.close();
                let new_conn = connect_and_handshake(&url, genesis_id).await?;
                wt = new_conn.wt;
                log("  Reconnected, retrying...", "ok");
                match send_v2_blocks_rpc(&wt, vec![prev_block_id], 1).await {
                    Ok((blocks, _)) => blocks,
                    Err(e) => {
                        log(&format!("  Failed after reconnect: {:?}", e), "err");
                        continue;
                    }
                }
            }
        };

        blocks_fetched += 1;

        if let Some((block, raw)) = blocks_with_raw.first() {
            // Cache the block
            let _ = cache_block(*height, raw).await;
            let (received, sent, details) = scan_block_balance(block, &target);
            if received > 0 || sent > 0 {
                txns_found += 1;
                total_received += received;
                total_sent += sent;
                let net = total_received.saturating_sub(total_sent);

                for d in &details {
                    all_utxos.push(json!({
                        "height": height,
                        "direction": d.direction,
                        "amount": format_sc(d.amount),
                        "amountHastings": d.amount.to_string(),
                        "source": d.source,
                        "outputId": d.output_id,
                        "counterparty": d.counterparty,
                    }));
                }

                let mut parts = Vec::new();
                if received > 0 {
                    parts.push(format!("+{}", format_sc(received)));
                }
                if sent > 0 {
                    parts.push(format!("-{}", format_sc(sent)));
                }

                log(
                    &format!(
                        "  [{}/{}] Height {}: {} => balance: {}",
                        i + 1,
                        matches.len(),
                        height,
                        parts.join(", "),
                        format_sc(net),
                    ),
                    "ok",
                );
            } else {
                false_positives += 1;
                log(
                    &format!(
                        "  [{}/{}] Height {}: false positive (no activity)",
                        i + 1,
                        matches.len(),
                        height,
                    ),
                    "data",
                );
            }
        }
    }

    // Step 4: Tail scan — sequentially scan all blocks after the filter tip
    let filter_tip = filter_file.tip_height;
    let last_filter_block_id = if let Some(last) = filter_file.entries.last() {
        let mut bid = [0u8; 32];
        bid.copy_from_slice(&last.block_id);
        BlockID::from(bid)
    } else {
        genesis_id
    };

    log("", "info");
    log(
        &format!(
            "Scanning blocks after filter tip (height {})...",
            filter_tip,
        ),
        "info",
    );

    let mut tail_history = vec![last_filter_block_id];
    let mut tail_blocks_scanned: u64 = 0;
    let blocks_per_batch: u64 = 100;

    loop {
        let rpc_result =
            send_v2_blocks_rpc(&wt, tail_history.clone(), blocks_per_batch).await;

        let (blocks_with_raw, remaining) = match rpc_result {
            Ok(result) => result,
            Err(_) => {
                log(
                    &format!(
                        "  Connection lost after {} tail blocks, reconnecting...",
                        tail_blocks_scanned
                    ),
                    "info",
                );
                let _ = wt.close();
                let new_conn = connect_and_handshake(&url, genesis_id).await?;
                wt = new_conn.wt;
                log("  Reconnected, resuming tail scan...", "ok");
                if tail_history.is_empty() {
                    break;
                }
                continue;
            }
        };

        if blocks_with_raw.is_empty() {
            break;
        }

        let batch_count = blocks_with_raw.len() as u64;
        let last_block_id = blocks_with_raw.last().unwrap().0.id();

        for (block, raw) in &blocks_with_raw {
            let height = block.v2_height.unwrap_or(filter_tip + 1 + tail_blocks_scanned);
            let _ = cache_block(height, raw).await;
            let (received, sent, details) = scan_block_balance(block, &target);

            if received > 0 || sent > 0 {
                txns_found += 1;
                total_received += received;
                total_sent += sent;
                let net = total_received.saturating_sub(total_sent);

                for d in &details {
                    all_utxos.push(json!({
                        "height": height,
                        "direction": d.direction,
                        "amount": format_sc(d.amount),
                        "amountHastings": d.amount.to_string(),
                        "source": d.source,
                        "outputId": d.output_id,
                        "counterparty": d.counterparty,
                    }));
                }

                let mut parts = Vec::new();
                if received > 0 {
                    parts.push(format!("+{}", format_sc(received)));
                }
                if sent > 0 {
                    parts.push(format!("-{}", format_sc(sent)));
                }

                log(
                    &format!(
                        "  Tail height {}: {} => balance: {}",
                        height,
                        parts.join(", "),
                        format_sc(net),
                    ),
                    "ok",
                );
            }

            tail_blocks_scanned += 1;
        }
        blocks_fetched += batch_count as u32;

        log(
            &format!(
                "  Tail scan: {} blocks after tip | {} remaining",
                tail_blocks_scanned, remaining,
            ),
            "data",
        );

        if remaining == 0 {
            break;
        }

        tail_history = vec![last_block_id];
    }

    if tail_blocks_scanned == 0 {
        log("  No new blocks beyond filter tip.", "info");
    } else {
        log(
            &format!("  Tail scan complete: {} blocks scanned", tail_blocks_scanned),
            "ok",
        );
    }

    let _ = wt.close();

    let net = total_received.saturating_sub(total_sent);
    log("", "info");
    log("Filtered scan complete!", "ok");
    log(
        &format!("  Filters checked:  {}", filter_file.entries.len()),
        "data",
    );
    log(
        &format!("  Filter matches:   {}", matches.len()),
        "data",
    );
    log(&format!("  Blocks fetched:   {blocks_fetched}"), "data");
    log(
        &format!("  Tail blocks:      {tail_blocks_scanned}"),
        "data",
    );
    log(&format!("  False positives:  {false_positives}"), "data");
    log(
        &format!("  Transactions:     {txns_found}"),
        "data",
    );
    log(
        &format!("  Total received:   {}", format_sc(total_received)),
        "data",
    );
    log(
        &format!("  Total sent:       {}", format_sc(total_sent)),
        "data",
    );
    log(
        &format!("  Net balance:      {}", format_sc(net)),
        "ok",
    );

    let result = json!({
        "blocksScanned": blocks_fetched,
        "filtersChecked": filter_file.entries.len(),
        "filterMatches": matches.len(),
        "falsePositives": false_positives,
        "tailBlocksScanned": tail_blocks_scanned,
        "filterTipHeight": filter_tip,
        "transactionsFound": txns_found,
        "received": total_received.to_string(),
        "sent": total_sent.to_string(),
        "balance": net.to_string(),
        "receivedSC": format_sc(total_received),
        "sentSC": format_sc(total_sent),
        "balanceSC": format_sc(net),
        "utxos": all_utxos,
    });
    Ok(JsValue::from_str(&serde_json::to_string(&result).unwrap()))
}

// --- TxID Index Lookup ---

/// Binary search for all entries matching an 8-byte txid prefix.
/// Returns all candidate block heights (usually 1, rarely 2+ on collision).
fn search_txindex(data: &[u8], target_prefix: &[u8; 8]) -> Vec<u32> {
    if data.len() < 16 {
        return Vec::new();
    }
    let count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let entries = &data[16..];
    let entry_size = 12;

    // Binary search to find any matching entry
    let mut lo = 0usize;
    let mut hi = count;
    let mut found = None;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let offset = mid * entry_size;
        let prefix = &entries[offset..offset + 8];
        match prefix.cmp(target_prefix) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => {
                found = Some(mid);
                break;
            }
        }
    }

    let mid = match found {
        Some(m) => m,
        None => return Vec::new(),
    };

    // Scan left and right for all entries with the same prefix
    let mut heights = Vec::new();
    // Scan left (including mid)
    let mut i = mid;
    loop {
        let offset = i * entry_size;
        if &entries[offset..offset + 8] != target_prefix {
            break;
        }
        let h = u32::from_le_bytes(entries[offset + 8..offset + 12].try_into().unwrap());
        heights.push(h);
        if i == 0 { break; }
        i -= 1;
    }
    // Scan right (excluding mid)
    let mut i = mid + 1;
    while i < count {
        let offset = i * entry_size;
        if &entries[offset..offset + 8] != target_prefix {
            break;
        }
        let h = u32::from_le_bytes(entries[offset + 8..offset + 12].try_into().unwrap());
        heights.push(h);
        i += 1;
    }

    heights.sort_unstable();
    heights.dedup();
    heights
}

#[wasm_bindgen]
pub async fn lookup_txid(
    url: String,
    genesis_id_hex: String,
    txid_hex: String,
    txindex_url: String,
    log_fn: js_sys::Function,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;

    // Parse txid
    let txid_bytes = hex_to_bytes(&txid_hex)?;
    if txid_bytes.len() != 32 {
        return Err(JsValue::from_str("txid must be 64 hex characters"));
    }
    let mut txid_prefix = [0u8; 8];
    txid_prefix.copy_from_slice(&txid_bytes[..8]);

    // Fetch txindex file
    log("Downloading transaction index...", "info");
    let index_data = fetch_bytes(&txindex_url).await?;

    // Validate header
    if index_data.len() < 16 || &index_data[0..4] != b"STXI" {
        return Err(JsValue::from_str("invalid txindex file (bad magic)"));
    }
    let version = u32::from_le_bytes(index_data[4..8].try_into().unwrap());
    if version != 1 {
        return Err(JsValue::from_str(&format!("unsupported txindex version: {version}")));
    }
    let count = u32::from_le_bytes(index_data[8..12].try_into().unwrap());
    let tip_height = u32::from_le_bytes(index_data[12..16].try_into().unwrap());
    log(
        &format!(
            "Loaded txindex: {} transactions, tip height {}, {:.1} MB",
            count, tip_height, index_data.len() as f64 / 1024.0 / 1024.0
        ),
        "ok",
    );

    // Binary search — returns all candidate heights (handles prefix collisions)
    log("Searching for transaction...", "info");
    let candidates = search_txindex(&index_data, &txid_prefix);
    if candidates.is_empty() {
        log("Transaction not found in index.", "err");
        return Ok(JsValue::from_str("not_found"));
    }
    if candidates.len() == 1 {
        log(
            &format!("Found transaction in block {}", candidates[0]),
            "ok",
        );
    } else {
        log(
            &format!(
                "Prefix collision: {} candidate blocks {:?}, checking each...",
                candidates.len(), candidates
            ),
            "info",
        );
    }

    // Need header IDs to fetch the block — load from cache or require sync first
    let header_ids = match load_header_ids().await? {
        Some(ids) => ids,
        None => {
            // Also check in-memory cache
            let cached = CACHED_HEADER_IDS.with(|cache| cache.borrow().clone());
            match cached {
                Some(ids) => ids,
                None => {
                    log("Header IDs not available. Please sync chain first.", "err");
                    return Err(JsValue::from_str("header IDs not synced — run sync_chain first"));
                }
            }
        }
    };

    log("Connecting to peer...", "info");
    let conn = connect_and_handshake(&url, genesis_id).await?;
    log(
        &format!("Connected to {}", conn.peer_info.addr),
        "ok",
    );

    // Check each candidate block for the full txid match
    let mut result_json = None;
    for &block_height in &candidates {
        if block_height == 0 || (block_height as usize) >= header_ids.len() {
            log(
                &format!("Block height {} out of range (have {} headers), skipping", block_height, header_ids.len()),
                "info",
            );
            continue;
        }

        let prev_id = header_ids[(block_height - 1) as usize];
        let (blocks_with_raw, _remaining) = send_v2_blocks_rpc(&conn.wt, vec![prev_id], 1).await?;
        if blocks_with_raw.is_empty() {
            log(&format!("Block {} — peer returned no data, skipping", block_height), "info");
            continue;
        }

        let (block, raw) = &blocks_with_raw[0];
        let _ = cache_block(block_height as u64, raw).await;

        // Check V2 transactions for full txid match
        let mut found = false;
        for txn in &block.v2_transactions {
            let tid = txn.id();
            let tid_bytes: &[u8] = tid.as_ref();
            if tid_bytes == &txid_bytes[..] {
                found = true;
                break;
            }
        }

        if found || candidates.len() == 1 {
            // For V1 transactions we can't easily compute txid in WASM,
            // so if there's only one candidate we trust the index.
            // For multiple candidates, V1 txns in non-matching blocks are skipped.
            let block_json = block_to_json(block);
            result_json = Some(json!({
                "txid": txid_hex,
                "blockHeight": block_height,
                "timestamp": block.timestamp,
                "block": block_json,
            }));
            log(
                &format!("Transaction {} confirmed in block {} ({})",
                    &txid_hex[..16], block_height,
                    chrono_timestamp(block.timestamp)),
                "ok",
            );
            break;
        } else {
            log(
                &format!("Block {} — prefix collision, txid not in this block", block_height),
                "info",
            );
        }
    }

    let _ = conn.wt.close();

    match result_json {
        Some(r) => Ok(JsValue::from_str(&serde_json::to_string(&r).unwrap())),
        None => {
            log("Transaction not found in any candidate block (possible V1 collision).", "err");
            Ok(JsValue::from_str("not_found"))
        }
    }
}

fn chrono_timestamp(unix: u64) -> String {
    let secs = unix;
    let days = secs / 86400;
    let year_approx = 1970 + days / 365;
    let month_approx = (days % 365) / 30 + 1;
    let day_approx = (days % 365) % 30 + 1;
    format!("{}-{:02}-{:02}", year_approx, month_approx, day_approx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcs_cross_language() {
        // Test vector from Go: TestGCSEncodeDecode
        let block_id: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let addr0: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let addr1: [u8; 32] = [
            32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
            11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ];
        let addr2: [u8; 32] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0x00,
        ];
        let not_in_set: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let filter_hex = "20d88202d3f472b8";
        let filter_data = hex::decode(filter_hex).unwrap();
        let n: u64 = 3;
        let p: u8 = 19;

        // Verify SipHash key derivation
        let k0 = u64::from_le_bytes(block_id[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(block_id[8..16].try_into().unwrap());
        assert_eq!(k0, 0x0807060504030201);
        assert_eq!(k1, 0x100f0e0d0c0b0a09);

        // Verify SipHash output for addr0 matches Go: e3ebe47ec335e501
        let mut hasher = SipHasher::new_with_keys(k0, k1);
        hasher.write(&addr0);
        assert_eq!(hasher.finish(), 0xe3ebe47ec335e501);

        // Verify mapped value
        let m: u64 = 1u64 << p;
        let v0 = fast_reduce(0xe3ebe47ec335e501, n * m);
        assert_eq!(v0, 1400349);

        // All 3 addresses should match
        assert!(gcs_match(&filter_data, &block_id, &addr0, n, p));
        assert!(gcs_match(&filter_data, &block_id, &addr1, n, p));
        assert!(gcs_match(&filter_data, &block_id, &addr2, n, p));

        // Not-in-set should NOT match
        assert!(!gcs_match(&filter_data, &block_id, &not_in_set, n, p));
    }

    #[test]
    fn test_gcs_empty_filter() {
        let block_id = [0u8; 32];
        let item = [1u8; 32];
        assert!(!gcs_match(&[], &block_id, &item, 0, 19));
        assert!(!gcs_match(&[0xFF], &block_id, &item, 0, 19));
    }

    #[test]
    fn test_parse_filter_file() {
        let mut data = Vec::new();
        // Header: magic + version + count + P + tip_height
        data.extend_from_slice(b"SCBF");
        data.extend_from_slice(&2u32.to_le_bytes()); // version 2
        data.extend_from_slice(&1u32.to_le_bytes()); // count
        data.extend_from_slice(&19u32.to_le_bytes()); // P
        data.extend_from_slice(&100u64.to_le_bytes()); // tip_height
        // Entry
        data.extend_from_slice(&42u64.to_le_bytes());
        data.extend_from_slice(&[0xAA; 32]);
        data.extend_from_slice(&3u16.to_le_bytes());
        let filter = vec![0x20, 0xd8, 0x82, 0x02, 0xd3, 0xf4, 0x72, 0xb8];
        data.extend_from_slice(&(filter.len() as u32).to_le_bytes());
        data.extend_from_slice(&filter);

        let ff = parse_filter_file(&data).unwrap();
        assert_eq!(ff.p, 19);
        assert_eq!(ff.tip_height, 100);
        assert_eq!(ff.entries.len(), 1);
        assert_eq!(ff.entries[0].height, 42);
        assert_eq!(ff.entries[0].address_count, 3);
        assert_eq!(ff.entries[0].filter_data, filter);
    }
}
