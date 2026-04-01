use std::cell::RefCell;
use std::io;

use js_sys::{Reflect, Uint8Array};
use serde_json::json;
use sia::consensus::UNASSIGNED_LEAF_INDEX;
use sia::encoding::{SiaDecodable, SiaEncodable, V1SiaDecodable, V1SiaEncodable};
use sia::types::v1::{self, UnlockConditions};
use sia::types::v2::{self, ContractResolution};
use sia::types::{Address, BlockID, ChainIndex, Currency, Hash256, StateElement};
use sia_syncer::encoding::{self, PROTOCOL_VERSION};
use sia_syncer::rpc::{
    RPC_DISCOVER_IP, RPC_RELAY_V2_BLOCK_OUTLINE, RPC_RELAY_V2_HEADER, RPC_RELAY_V2_TRANSACTION_SET,
    RPC_SEND_CHECKPOINT, RPC_SEND_HEADERS, RPC_SEND_TRANSACTIONS, RPC_SEND_V2_BLOCKS,
    RelayV2HeaderRequest, RelayV2TransactionSetRequest, SendCheckpointRequest, SendHeadersRequest,
    SendHeadersResponse, SendTransactionsRequest, SendV2BlocksRequest,
};
use sia_syncer::types::{Header, PeerInfo};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{ReadableStreamDefaultReader, WritableStreamDefaultWriter};

// Cached header IDs from a previous sync, shared between sync_chain and generate_filters.
// Stored as (network_prefix, ids) to avoid cross-network cache hits.
thread_local! {
    static CACHED_HEADER_IDS: RefCell<Option<(String, Vec<BlockID>)>> = RefCell::new(None);
    static NETWORK_PREFIX: RefCell<String> = RefCell::new(String::new());
}

fn set_network_prefix(genesis_id_hex: &str) {
    let name = if genesis_id_hex.starts_with("25f6e3b9") {
        "mainnet"
    } else if genesis_id_hex.starts_with("172fb3d5") {
        "zen"
    } else {
        // Fallback: use first 8 hex chars
        &genesis_id_hex[..genesis_id_hex.len().min(8)]
    };
    NETWORK_PREFIX.with(|p| *p.borrow_mut() = name.to_string());
}

fn get_network_prefix() -> String {
    NETWORK_PREFIX.with(|p| p.borrow().clone())
}

fn prefixed_key(key: &str) -> String {
    NETWORK_PREFIX.with(|p| {
        let prefix = p.borrow();
        if prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}:{}", *prefix, key)
        }
    })
}

/// Inject cached header IDs from the JS side (e.g. loaded from OPFS).
/// Accepts raw bytes (32 bytes per block ID) and the genesis ID hex to determine network prefix.
#[wasm_bindgen]
pub fn set_cached_header_ids(genesis_id_hex: &str, header_bytes: &[u8]) {
    set_network_prefix(genesis_id_hex);
    let net = get_network_prefix();
    if header_bytes.len() % 32 != 0 {
        return;
    }
    let ids: Vec<BlockID> = header_bytes
        .chunks_exact(32)
        .map(|chunk| {
            let mut id = [0u8; 32];
            id.copy_from_slice(chunk);
            BlockID::new(id)
        })
        .collect();
    CACHED_HEADER_IDS.with(|cache| {
        *cache.borrow_mut() = Some((net, ids));
    });
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

async fn save_header_ids_with_key(key: &str, ids: &[BlockID]) -> Result<(), JsValue> {
    let mut buf = Vec::with_capacity(ids.len() * 32);
    for id in ids {
        buf.extend_from_slice(id.as_ref());
    }
    let arr = Uint8Array::from(&buf[..]);
    JsFuture::from(idb_save(key, arr)).await?;
    Ok(())
}

async fn load_header_ids_with_key(key: &str) -> Result<Option<Vec<BlockID>>, JsValue> {
    let result = JsFuture::from(idb_load(key)).await?;
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

async fn load_header_ids() -> Result<Option<Vec<BlockID>>, JsValue> {
    load_header_ids_with_key(&prefixed_key("header_ids")).await
}

// --- Block cache (IndexedDB) ---

async fn cache_block(height: u64, raw_bytes: &[u8]) -> Result<(), JsValue> {
    let key = prefixed_key(&format!("block:{}", height));
    let arr = Uint8Array::from(raw_bytes);
    JsFuture::from(idb_save(&key, arr)).await?;
    Ok(())
}

async fn load_cached_block(height: u64) -> Result<Option<DecodedBlock>, JsValue> {
    let key = prefixed_key(&format!("block:{}", height));
    let result = JsFuture::from(idb_load(&key)).await?;
    if result.is_null() || result.is_undefined() {
        return Ok(None);
    }
    let arr = Uint8Array::from(result);
    let bytes = arr.to_vec();
    let mut cursor: &[u8] = &bytes;
    let block = decode_v2_block(&mut cursor, bytes.len())
        .map_err(|e| JsValue::from_str(&format!("cached block decode: {:?}", e)))?;
    // Validate cached block's v2_height matches requested height
    // (stale blocks from previous off-by-one bugs may be at wrong height)
    if let Some(v2h) = block.v2_height {
        if v2h != height {
            // Wrong block cached at this height — discard
            let _ = JsFuture::from(idb_save(&key, Uint8Array::new_with_length(0))).await;
            return Ok(None);
        }
    }
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

/// Decoded miner payout from V1SiacoinOutput encoding.
struct MinerPayout {
    value: Currency,
    address: Address,
}

// V1 transactions use the SDK's v1::Transaction type directly,
// which provides id(), siacoin_output_id(), and full encoding support.

/// Fully decoded V2Block with typed fields.
struct DecodedBlock {
    parent_id: BlockID,
    nonce: u64,
    timestamp: u64,
    miner_payouts: Vec<MinerPayout>,
    v1_addresses: Vec<Address>,
    v1_transactions: Vec<v1::Transaction>,
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

    let v1_txns_json: Vec<serde_json::Value> = block.v1_transactions.iter().map(|txn| {
        let tid = txn.id();
        let inputs_json: Vec<serde_json::Value> = txn.siacoin_inputs.iter().map(|input| {
            json!({
                "parentID": input.parent_id.to_string(),
                "address": input.unlock_conditions.address().to_string(),
            })
        }).collect();
        let outputs_json: Vec<serde_json::Value> = txn.siacoin_outputs.iter().enumerate().map(|(i, output)| {
            json!({
                "value": format!("{}", output.value),
                "address": output.address.to_string(),
                "outputID": txn.siacoin_output_id(i).to_string(),
            })
        }).collect();
        let fees_json: Vec<serde_json::Value> = txn.miner_fees.iter().map(|f| {
            json!(format!("{}", f))
        }).collect();

        let sc_output_to_json = |o: &SiacoinOutput| -> serde_json::Value {
            json!({ "value": format!("{}", o.value), "address": o.address.to_string() })
        };

        let file_contracts_json: Vec<serde_json::Value> = txn.file_contracts.iter().map(|fc| {
            json!({
                "filesize": fc.file_size,
                "fileMerkleRoot": fc.file_merkle_root.to_string(),
                "windowStart": fc.window_start,
                "windowEnd": fc.window_end,
                "payout": format!("{}", fc.payout),
                "validProofOutputs": fc.valid_proof_outputs.iter().map(&sc_output_to_json).collect::<Vec<_>>(),
                "missedProofOutputs": fc.missed_proof_outputs.iter().map(&sc_output_to_json).collect::<Vec<_>>(),
                "unlockHash": fc.unlock_hash.to_string(),
                "revisionNumber": fc.revision_number,
            })
        }).collect();

        let file_contract_revisions_json: Vec<serde_json::Value> = txn.file_contract_revisions.iter().map(|rev| {
            json!({
                "parentID": rev.parent_id.to_string(),
                "filesize": rev.file_size,
                "fileMerkleRoot": rev.file_merkle_root.to_string(),
                "windowStart": rev.window_start,
                "windowEnd": rev.window_end,
                "validProofOutputs": rev.valid_proof_outputs.iter().map(&sc_output_to_json).collect::<Vec<_>>(),
                "missedProofOutputs": rev.missed_proof_outputs.iter().map(&sc_output_to_json).collect::<Vec<_>>(),
                "unlockHash": rev.unlock_hash.to_string(),
                "revisionNumber": rev.revision_number,
            })
        }).collect();

        let storage_proofs_json: Vec<serde_json::Value> = txn.storage_proofs.iter().map(|sp| {
            json!({
                "parentID": sp.parent_id.to_string(),
            })
        }).collect();

        let arb_data_json: Vec<serde_json::Value> = txn.arbitrary_data.iter().map(|d| {
            // Try UTF-8 first, fall back to hex
            match std::str::from_utf8(d) {
                Ok(s) => json!(s),
                Err(_) => json!(hex::encode(d)),
            }
        }).collect();

        let mut obj = json!({
            "txid": tid.to_string(),
            "siacoinInputs": inputs_json,
            "siacoinOutputs": outputs_json,
            "minerFees": fees_json,
        });
        if !file_contracts_json.is_empty() {
            obj["fileContracts"] = json!(file_contracts_json);
        }
        if !file_contract_revisions_json.is_empty() {
            obj["fileContractRevisions"] = json!(file_contract_revisions_json);
        }
        if !storage_proofs_json.is_empty() {
            obj["storageProofs"] = json!(storage_proofs_json);
        }
        if !arb_data_json.is_empty() {
            obj["arbitraryData"] = json!(arb_data_json);
        }
        obj
    }).collect();

    if let Some(height) = block.v2_height {
        let v2_txns_json: Vec<serde_json::Value> = block
            .v2_transactions
            .iter()
            .map(|txn| {
                let mut val = serde_json::to_value(txn).unwrap_or(json!({}));
                if let serde_json::Value::Object(ref mut map) = val {
                    let tid = txn.id();
                    let tid_bytes: &[u8] = tid.as_ref();
                    map.insert("txid".to_string(), json!(hex::encode(tid_bytes)));
                }
                val
            })
            .collect();
        json!({
            "parentID": block.parent_id.to_string(),
            "nonce": block.nonce,
            "timestamp": block.timestamp,
            "minerPayouts": miner_payouts_json,
            "v1TransactionCount": block.v1_transactions.len(),
            "v1Transactions": v1_txns_json,
            "v2": {
                "height": height,
                "commitment": hex::encode(block.v2_commitment.unwrap_or([0u8; 32])),
                "transactionCount": block.v2_transactions.len(),
                "transactions": v2_txns_json,
            }
        })
    } else {
        json!({
            "parentID": block.parent_id.to_string(),
            "nonce": block.nonce,
            "timestamp": block.timestamp,
            "minerPayouts": miner_payouts_json,
            "v1TransactionCount": block.v1_transactions.len(),
            "v1Transactions": v1_txns_json,
        })
    }
}

/// Decode a V1-encoded Currency from a buffer.
/// Format: [u64 LE byte count] [N big-endian bytes]
fn decode_v1_currency(r: &mut &[u8]) -> Result<Currency, JsValue> {
    let io_err = |e: io::Error| JsValue::from_str(&e.to_string());
    let n = u64::decode(r).map_err(|e| JsValue::from_str(&e.to_string()))? as usize;
    if n > 16 {
        return Err(JsValue::from_str(&format!("Currency too large: {n} bytes")));
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

    let clear_bits = |x: u64, n: usize| -> u64 { if n >= 64 { 0 } else { x & !((1u64 << n) - 1) } };

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

/// A multiproof leaf: leaf_index, element_hash, proof_len.
/// We track which leaves are in each group so we can write back proof values.
#[derive(Clone)]
struct MultiproofLeaf {
    leaf_index: u64,
    element_hash: Hash256,
    proof_len: usize,
}

impl MultiproofLeaf {
    fn hash(&self) -> Hash256 {
        // Same as ElementLeaf::hash() but always spent=false for multiproofs
        let mut buf = [0u8; 42];
        buf[0] = 0x00; // LEAF_HASH_PREFIX
        buf[1..33].copy_from_slice(self.element_hash.as_ref());
        buf[33..41].copy_from_slice(&self.leaf_index.to_le_bytes());
        // buf[41] = 0; // spent always false for multiproofs
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .to_state()
            .update(&buf)
            .finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        Hash256::from(result)
    }
}

/// Describes where a proof hash should be written back in the transaction data.
/// (txn_index, element_type, element_index_within_type, proof_level)
#[derive(Clone)]
enum ElementRef {
    SiacoinInput { txn: usize, input: usize },
    SiafundInput { txn: usize, input: usize },
    FileContractRevision { txn: usize, rev: usize },
    FileContractResolution { txn: usize, res: usize },
    StorageProofIndex { txn: usize, res: usize },
}

/// Collect multiproof leaves with back-references into transactions.
fn collect_multiproof_leaves(txns: &[v2::Transaction]) -> Vec<(MultiproofLeaf, ElementRef)> {
    use sia::consensus::{
        chain_index_element_hash, siacoin_element_hash, siafund_element_hash,
        v2_file_contract_element_hash,
    };
    use sia::types::SiacoinOutput;

    let mut result = Vec::new();
    for (ti, txn) in txns.iter().enumerate() {
        for (ii, input) in txn.siacoin_inputs.iter().enumerate() {
            let se = &input.parent.state_element;
            if se.leaf_index == UNASSIGNED_LEAF_INDEX {
                continue;
            }
            let elem_hash = siacoin_element_hash(
                &input.parent.id,
                &SiacoinOutput {
                    value: input.parent.siacoin_output.value,
                    address: input.parent.siacoin_output.address.clone(),
                },
                input.parent.maturity_height,
            );
            result.push((
                MultiproofLeaf {
                    leaf_index: se.leaf_index,
                    element_hash: elem_hash,
                    proof_len: se.merkle_proof.len(),
                },
                ElementRef::SiacoinInput { txn: ti, input: ii },
            ));
        }
        for (ii, input) in txn.siafund_inputs.iter().enumerate() {
            let se = &input.parent.state_element;
            if se.leaf_index == UNASSIGNED_LEAF_INDEX {
                continue;
            }
            let elem_hash = siafund_element_hash(
                &input.parent.id,
                &input.parent.siafund_output,
                &input.parent.claim_start,
            );
            result.push((
                MultiproofLeaf {
                    leaf_index: se.leaf_index,
                    element_hash: elem_hash,
                    proof_len: se.merkle_proof.len(),
                },
                ElementRef::SiafundInput { txn: ti, input: ii },
            ));
        }
        for (ri, rev) in txn.file_contract_revisions.iter().enumerate() {
            let se = &rev.parent.state_element;
            if se.leaf_index == UNASSIGNED_LEAF_INDEX {
                continue;
            }
            let elem_hash =
                v2_file_contract_element_hash(&rev.parent.id, &rev.parent.v2_file_contract);
            result.push((
                MultiproofLeaf {
                    leaf_index: se.leaf_index,
                    element_hash: elem_hash,
                    proof_len: se.merkle_proof.len(),
                },
                ElementRef::FileContractRevision { txn: ti, rev: ri },
            ));
        }
        for (ri, res) in txn.file_contract_resolutions.iter().enumerate() {
            let se = &res.parent.state_element;
            if se.leaf_index == UNASSIGNED_LEAF_INDEX {
                continue;
            }
            let elem_hash =
                v2_file_contract_element_hash(&res.parent.id, &res.parent.v2_file_contract);
            result.push((
                MultiproofLeaf {
                    leaf_index: se.leaf_index,
                    element_hash: elem_hash,
                    proof_len: se.merkle_proof.len(),
                },
                ElementRef::FileContractResolution { txn: ti, res: ri },
            ));
            if let v2::ContractResolution::StorageProof(ref sp) = res.resolution {
                let se2 = &sp.proof_index.state_element;
                if se2.leaf_index == UNASSIGNED_LEAF_INDEX {
                    continue;
                }
                let ci_hash =
                    chain_index_element_hash(&sp.proof_index.id, &sp.proof_index.chain_index);
                result.push((
                    MultiproofLeaf {
                        leaf_index: se2.leaf_index,
                        element_hash: ci_hash,
                        proof_len: se2.merkle_proof.len(),
                    },
                    ElementRef::StorageProofIndex { txn: ti, res: ri },
                ));
            }
        }
    }
    result
}

/// Write a proof hash value to the appropriate StateElement in the transaction.
fn set_proof_value(txns: &mut [v2::Transaction], eref: &ElementRef, level: usize, value: Hash256) {
    match eref {
        ElementRef::SiacoinInput { txn, input } => {
            txns[*txn].siacoin_inputs[*input]
                .parent
                .state_element
                .merkle_proof[level] = value;
        }
        ElementRef::SiafundInput { txn, input } => {
            txns[*txn].siafund_inputs[*input]
                .parent
                .state_element
                .merkle_proof[level] = value;
        }
        ElementRef::FileContractRevision { txn, rev } => {
            txns[*txn].file_contract_revisions[*rev]
                .parent
                .state_element
                .merkle_proof[level] = value;
        }
        ElementRef::FileContractResolution { txn, res } => {
            txns[*txn].file_contract_resolutions[*res]
                .parent
                .state_element
                .merkle_proof[level] = value;
        }
        ElementRef::StorageProofIndex { txn, res } => {
            if let v2::ContractResolution::StorageProof(ref mut sp) =
                txns[*txn].file_contract_resolutions[*res].resolution
            {
                sp.proof_index.state_element.merkle_proof[level] = value;
            }
        }
    }
}

/// Expand a multiproof into individual per-element Merkle proofs.
/// Ported from Go's expandMultiproof (types/multiproof.go).
fn expand_multiproof(txns: &mut [v2::Transaction], multiproof: &[Hash256]) {
    let all_leaves = collect_multiproof_leaves(txns);
    if all_leaves.is_empty() {
        return;
    }

    // Group by tree height (proof_len)
    let mut trees: Vec<Vec<usize>> = vec![Vec::new(); 64]; // indices into all_leaves
    for (idx, (leaf, _)) in all_leaves.iter().enumerate() {
        if leaf.proof_len < 64 {
            trees[leaf.proof_len].push(idx);
        }
    }

    let clear_bits = |x: u64, n: usize| -> u64 { if n >= 64 { 0 } else { x & !((1u64 << n) - 1) } };

    let blake_params = blake2b_simd::Params::new().hash_length(32).clone();
    let sum_pair = |left: &Hash256, right: &Hash256| -> Hash256 {
        let h = blake_params
            .to_state()
            .update(&[0x01]) // NODE_HASH_PREFIX
            .update(left.as_ref())
            .update(right.as_ref())
            .finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(h.as_bytes());
        Hash256::from(result)
    };

    // proof_cursor tracks our position in the multiproof
    let mut proof_cursor = 0usize;

    // Recursive expand: returns the subtree root hash
    // `leaf_indices` is a sorted slice of indices into `all_leaves`
    fn visit(
        i: u64,
        j: u64,
        leaf_indices: &[usize],
        all_leaves: &[(MultiproofLeaf, ElementRef)],
        txns: &mut [v2::Transaction],
        multiproof: &[Hash256],
        proof_cursor: &mut usize,
        sum_pair: &dyn Fn(&Hash256, &Hash256) -> Hash256,
    ) -> Hash256 {
        let height = (j.wrapping_sub(i)).trailing_zeros() as usize;
        if leaf_indices.is_empty() {
            let h = multiproof[*proof_cursor];
            *proof_cursor += 1;
            return h;
        } else if height == 0 {
            return all_leaves[leaf_indices[0]].0.hash();
        }
        let mid = i.wrapping_add(j) / 2;
        let split = leaf_indices.partition_point(|&idx| all_leaves[idx].0.leaf_index < mid);
        let (left_indices, right_indices) = leaf_indices.split_at(split);

        let left_root = visit(
            i,
            mid,
            left_indices,
            all_leaves,
            txns,
            multiproof,
            proof_cursor,
            sum_pair,
        );
        let right_root = visit(
            mid,
            j,
            right_indices,
            all_leaves,
            txns,
            multiproof,
            proof_cursor,
            sum_pair,
        );

        // Set proof values: right leaves get left_root at this height, left get right_root
        for &idx in right_indices {
            set_proof_value(txns, &all_leaves[idx].1, height - 1, left_root);
        }
        for &idx in left_indices {
            set_proof_value(txns, &all_leaves[idx].1, height - 1, right_root);
        }

        sum_pair(&left_root, &right_root)
    }

    for (height, tree_indices) in trees.iter_mut().enumerate() {
        if tree_indices.is_empty() {
            continue;
        }
        // Sort by leaf_index
        tree_indices.sort_by_key(|&idx| all_leaves[idx].0.leaf_index);
        let start = clear_bits(all_leaves[tree_indices[0]].0.leaf_index, height + 1);
        let end = if height >= 64 {
            0
        } else {
            start.wrapping_add(1u64 << height)
        };
        visit(
            start,
            end,
            tree_indices,
            &all_leaves,
            txns,
            multiproof,
            &mut proof_cursor,
            &sum_pair,
        );
    }
}

/// Decode V1 transactions from the buffer using the SDK's V1SiaDecode.
/// Returns extracted addresses (for block filters) and the full transactions.
fn decode_v1_transactions(
    r: &mut &[u8],
    count: usize,
) -> Result<(Vec<Address>, Vec<v1::Transaction>), JsValue> {
    let mut addresses = Vec::new();
    let mut transactions = Vec::with_capacity(count);

    for _ in 0..count {
        let txn = v1::Transaction::decode_v1(r)
            .map_err(|e| JsValue::from_str(&format!("v1 txn decode: {e}")))?;

        // Extract addresses for block filter generation
        for input in &txn.siacoin_inputs {
            addresses.push(input.unlock_conditions.address());
        }
        for output in &txn.siacoin_outputs {
            addresses.push(output.address.clone());
        }
        for fc in &txn.file_contracts {
            for o in &fc.valid_proof_outputs {
                addresses.push(o.address.clone());
            }
            for o in &fc.missed_proof_outputs {
                addresses.push(o.address.clone());
            }
            addresses.push(fc.unlock_hash.clone());
        }
        for fcr in &txn.file_contract_revisions {
            for o in &fcr.valid_proof_outputs {
                addresses.push(o.address.clone());
            }
            for o in &fcr.missed_proof_outputs {
                addresses.push(o.address.clone());
            }
            addresses.push(fcr.unlock_hash.clone());
        }
        for sfi in &txn.siafund_inputs {
            addresses.push(sfi.claim_address.clone());
        }
        for sfo in &txn.siafund_outputs {
            addresses.push(sfo.address.clone());
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
    let (v1_addresses, v1_transactions) =
        if v1_tx_count > 0 {
            decode_v1_transactions(r, v1_tx_count)
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
            presence[0],
            pos(),
            v1_tx_count,
            r.len(),
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
    let mut txns: Vec<v2::Transaction> = Vec::decode(r).map_err(|e| {
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
    let mut multiproof = Vec::with_capacity(mp_size);
    for _ in 0..mp_size {
        let mut hash_buf = [0u8; 32];
        io::Read::read_exact(r, &mut hash_buf).map_err(io_err)?;
        multiproof.push(Hash256::from(hash_buf));
    }
    if !multiproof.is_empty() {
        expand_multiproof(&mut txns, &multiproof);
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
    include_raw: bool,
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

    let block_count =
        u64::decode(&mut cursor).map_err(|e| JsValue::from_str(&e.to_string()))? as usize;

    let mut blocks = Vec::with_capacity(block_count);
    for i in 0..block_count {
        let pre_pos = total_len - cursor.len();
        let block = decode_v2_block(&mut cursor, total_len).map_err(|e| {
            JsValue::from_str(&format!(
                "block {i}/{block_count} (pos={}, {} bytes remaining): {}",
                total_len - cursor.len(),
                cursor.len(),
                e.as_string().unwrap_or_default()
            ))
        })?;
        let raw = if include_raw {
            let post_pos = total_len - cursor.len();
            resp_data[pre_pos..post_pos].to_vec()
        } else {
            Vec::new()
        };
        blocks.push((block, raw));
    }

    let remaining = u64::decode(&mut cursor).map_err(|e| JsValue::from_str(&e.to_string()))?;

    stream.close_writer().await?;
    Ok((blocks, remaining))
}

/// Send a checkpoint request to the peer, returning the block + consensus state
/// at the requested chain index.
async fn send_checkpoint_rpc(
    wt: &web_sys::WebTransport,
    index: ChainIndex,
) -> Result<(DecodedBlock, sia::consensus::State), JsValue> {
    let mut stream = open_stream(wt).await?;

    // Write RPC specifier
    let mut id_buf = Vec::new();
    RPC_SEND_CHECKPOINT
        .encode(&mut id_buf)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    stream.write_all(&id_buf).await?;

    // Write request (ChainIndex)
    let req = SendCheckpointRequest { index };
    let mut req_buf = Vec::new();
    req.encode(&mut req_buf)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    stream.write_all(&req_buf).await?;

    // Read entire response
    let resp_data = stream.read_to_end().await?;
    let total_len = resp_data.len();
    let mut cursor: &[u8] = &resp_data;

    // Decode V2Block
    let block = decode_v2_block(&mut cursor, total_len).map_err(|e| {
        JsValue::from_str(&format!(
            "checkpoint block decode failed ({} bytes remaining of {}): {}",
            cursor.len(),
            total_len,
            e.as_string().unwrap_or_default()
        ))
    })?;

    // Decode consensus.State
    let state = sia::consensus::State::decode(&mut cursor).map_err(|e| {
        JsValue::from_str(&format!(
            "checkpoint state decode failed ({} bytes remaining): {}",
            cursor.len(),
            e
        ))
    })?;

    stream.close_writer().await?;
    Ok((block, state))
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

// =============================================================================
// SCBF — Sia Compact Block Filters
// =============================================================================
//
// Motivation
// ----------
// A light client that only cares about a few addresses shouldn't need to
// download every block on the chain. SCBF files contain one Golomb-Coded Set
// (GCS) filter per block, encoding the set of addresses that appear in that
// block's transactions. A client downloads the compact filter file once, tests
// each filter against its own addresses locally, and only fetches the handful
// of blocks that actually match. This reduces bandwidth by orders of magnitude
// compared to a full chain scan.
//
// The GCS construction follows BIP-158 conventions adapted for Sia:
//   - Each address is a 32-byte Sia address (Blake2b-256 hash).
//   - The SipHash-2-4 key is derived from the block ID: k0 = LE64(blockID[0:8]),
//     k1 = LE64(blockID[8:16]).
//   - Each address is hashed to a value in [0, N*M) via SipHash then fast_reduce,
//     where N = number of addresses in the block and M = 2^P.
//   - The sorted hashed values are delta-encoded and compressed with Golomb-Rice
//     coding at parameter P (typically 19, giving M = 524288).
//   - Golomb-Rice encoding: for each delta d, write (d >> P) zeros followed by
//     a 1-bit (unary quotient), then the low P bits of d in MSB-first order.
//   - The resulting bitstream is packed into bytes (MSB-first, zero-padded).
//
// To test membership, the client hashes its target address with the same
// SipHash key, then decodes the Golomb-Rice stream looking for a match. False
// positive rate is approximately 1/M per block (≈ 1 in 524,288 at P=19).
//
// Wire Format — Version 1
// -----------------------
// All integers are unsigned little-endian.
//
//   Header (24 bytes):
//     [0:4]    magic       "SCBF" (0x53 0x43 0x42 0x46)
//     [4:8]    version     uint32 = 1
//     [8:12]   count       uint32, number of block entries
//     [12:16]  P           uint32, Golomb-Rice parameter
//     [16:24]  tipHeight   uint64, chain height at time of generation
//
//   Entries (repeated `count` times, variable length):
//     [0:8]    height      uint64, block height
//     [8:40]   blockID     [32]byte, block ID (hash)
//     [40:42]  addrCount   uint16, number of addresses in the filter
//     [42:46]  dataLen     uint32, byte length of the GCS filter data
//     [46:46+dataLen]      GCS filter bitstream (Golomb-Rice encoded)
//
//   Total size: 24 + sum(46 + dataLen_i) for each entry
//
// Wire Format — Version 2 (compact)
// ----------------------------------
// V2 is designed for contiguous block ranges (e.g. V2-only sync starting at a
// known activation height). Heights are implicit: entry i has height =
// startHeight + i. Filter data lengths use uint16 instead of uint32, which is
// safe because individual block filters are well under 64 KB.
//
//   Header (32 bytes):
//     [0:4]    magic       "SCBF"
//     [4:8]    version     uint32 = 2
//     [8:12]   count       uint32, number of block entries
//     [12:16]  P           uint32, Golomb-Rice parameter
//     [16:24]  tipHeight   uint64, chain height at time of generation
//     [24:32]  startHeight uint64, height of the first entry
//
//   Entries (repeated `count` times, variable length):
//     [0:32]   blockID     [32]byte, block ID
//     [32:34]  addrCount   uint16, number of addresses
//     [34:36]  dataLen     uint16, byte length of GCS data
//     [36:36+dataLen]      GCS filter bitstream
//
//   Entry height = startHeight + entry_index
//   Total size: 32 + sum(36 + dataLen_i) for each entry
//
// Usage
// -----
// 1. Obtain: retrieve filters from a peer via the planned Syncer RPC command,
//    or generate locally from downloaded blocks for stronger trust guarantees,
//    or load from a static file.
// 2. Scan: test each block's filter against target addresses. Collect matching
//    block heights.
// 3. Fetch: download only the matching blocks from a peer and extract
//    transaction details.
// 4. Cache: store in IndexedDB for offline use across page reloads.
//
// =============================================================================

// =============================================================================
// STXI — Sia Transaction Index
// =============================================================================
//
// Motivation
// ----------
// Looking up a transaction by its ID on Sia normally requires either a full
// node index or scanning the entire chain. The STXI format provides a compact
// index that maps transaction ID prefixes to block heights. A client can
// binary-search the sorted index to find which block contains a transaction,
// then fetch only that block from a peer. Like SCBF, the index can be
// retrieved from peers via a planned Syncer RPC or generated locally.
//
// The index stores only the first 8 bytes of each 32-byte transaction ID. This
// is sufficient for practical uniqueness — with ~1M transactions, the
// probability of an 8-byte prefix collision is roughly 1 in 10^13 (birthday
// bound at 2^64). In the unlikely event of a collision, the client fetches a
// small number of candidate blocks and checks the full transaction IDs.
//
// Wire Format — Version 1
// -----------------------
// All integers are unsigned little-endian. Entries MUST be sorted by prefix
// in ascending lexicographic (byte) order to enable binary search.
//
//   Header (16 bytes):
//     [0:4]    magic       "STXI" (0x53 0x54 0x58 0x49)
//     [4:8]    version     uint32 = 1
//     [8:12]   count       uint32, number of entries
//     [12:16]  tipHeight   uint32, chain height at time of generation
//
//   Entries (repeated `count` times, fixed 12 bytes each):
//     [0:8]    prefix      [8]byte, first 8 bytes of the transaction ID
//     [8:12]   height      uint32, block height containing this transaction
//
//   Total size: 16 + (count * 12) bytes
//
// Usage
// -----
// 1. Generate: sync chain blocks, collect (txid_prefix, height) for each V2
//    transaction, sort by prefix, serialize to STXI file.
// 2. Lookup: binary search the sorted entries for the target txid prefix.
//    Multiple matches are possible (prefix collisions) — collect all
//    candidate heights.
// 3. Fetch: download candidate blocks from a peer, scan for the full
//    transaction ID, and return the matching transaction.
//
// Size estimate: ~1M transactions × 12 bytes = ~12 MB. Fits comfortably in
// browser IndexedDB or as a static download.
//
// =============================================================================

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

    if version == 2 {
        // V2 compact format: header has extra startHeight(8) = 32 byte header
        // Per entry: blockID(32) + addressCount(2) + dataLength(2, uint16) + data(N) = 36+N
        if data.len() < 32 {
            return Err("v2 filter file too small".into());
        }
        let start_height = u64::from_le_bytes(data[24..32].try_into().unwrap());
        let mut pos = 32usize;

        for i in 0..count {
            if pos + 36 > data.len() {
                return Err("truncated v2 filter entry header".into());
            }
            let mut block_id = [0u8; 32];
            block_id.copy_from_slice(&data[pos..pos + 32]);
            let address_count = u16::from_le_bytes(data[pos + 32..pos + 34].try_into().unwrap());
            let filter_len =
                u16::from_le_bytes(data[pos + 34..pos + 36].try_into().unwrap()) as usize;
            pos += 36;

            if pos + filter_len > data.len() {
                return Err(format!(
                    "truncated v2 filter data: entry {}, pos {}, filter_len {}, data_len {}, address_count {}",
                    i,
                    pos,
                    filter_len,
                    data.len(),
                    address_count,
                ));
            }
            let filter_data = data[pos..pos + filter_len].to_vec();
            pos += filter_len;

            entries.push(FilterEntry {
                height: start_height + i as u64,
                block_id,
                address_count,
                filter_data,
            });
        }
    } else {
        // V1 format: per entry: height(8) + blockID(32) + addressCount(2) + dataLength(4) + data(N) = 46+N
        let mut pos = 24usize;

        for _ in 0..count {
            if pos + 46 > data.len() {
                return Err("truncated filter entry header".into());
            }
            let height = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            let mut block_id = [0u8; 32];
            block_id.copy_from_slice(&data[pos + 8..pos + 40]);
            let address_count = u16::from_le_bytes(data[pos + 40..pos + 42].try_into().unwrap());
            let filter_len =
                u32::from_le_bytes(data[pos + 42..pos + 46].try_into().unwrap()) as usize;
            pos += 46;

            if pos + filter_len > data.len() {
                return Err(format!(
                    "truncated filter data: entry at height {}, pos {}, filter_len {}, data_len {}, address_count {}",
                    height,
                    pos,
                    filter_len,
                    data.len(),
                    address_count,
                ));
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
    }

    Ok(FilterFile {
        _version: version,
        p,
        tip_height,
        entries,
    })
}

/// Serialize filter entries to SCBF v1 binary format.
fn serialize_filter_file(entries: &[FilterEntry], p: u32, tip_height: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    // Header (24 bytes)
    buf.extend_from_slice(b"SCBF");
    buf.extend_from_slice(&1u32.to_le_bytes()); // version
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

/// Serialize filter entries to SCBF v2 compact format (implicit heights, uint16 data lengths).
fn serialize_filter_file_v2(
    entries: &[FilterEntry],
    p: u32,
    tip_height: u64,
    start_height: u64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    // Header (32 bytes)
    buf.extend_from_slice(b"SCBF");
    buf.extend_from_slice(&2u32.to_le_bytes()); // version 2
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    buf.extend_from_slice(&p.to_le_bytes());
    buf.extend_from_slice(&tip_height.to_le_bytes());
    buf.extend_from_slice(&start_height.to_le_bytes());
    // Per-block entries (no height field, uint16 data length)
    for entry in entries {
        buf.extend_from_slice(&entry.block_id);
        buf.extend_from_slice(&entry.address_count.to_le_bytes());
        buf.extend_from_slice(&(entry.filter_data.len() as u16).to_le_bytes());
        buf.extend_from_slice(&entry.filter_data);
    }
    buf
}

/// Append new filter entries to an already-serialized SCBF byte blob in-place,
/// updating the count and tip_height header fields without re-serializing.
/// Supports both SCBF v1 (46-byte entries with height) and v2 (36-byte compact).
fn append_entries_to_filter_bytes(
    bytes: &mut Vec<u8>,
    new_entries: &[FilterEntry],
    tip_height: u64,
) {
    if new_entries.is_empty() || bytes.len() < 24 {
        return;
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    // Update count
    let old_count = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let new_count = old_count + new_entries.len() as u32;
    bytes[8..12].copy_from_slice(&new_count.to_le_bytes());
    // Update tip_height
    bytes[16..24].copy_from_slice(&tip_height.to_le_bytes());
    // Append entries
    if version == 2 {
        for e in new_entries {
            bytes.extend_from_slice(&e.block_id);
            bytes.extend_from_slice(&e.address_count.to_le_bytes());
            bytes.extend_from_slice(&(e.filter_data.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&e.filter_data);
        }
    } else {
        for e in new_entries {
            bytes.extend_from_slice(&e.height.to_le_bytes());
            bytes.extend_from_slice(&e.block_id);
            bytes.extend_from_slice(&e.address_count.to_le_bytes());
            bytes.extend_from_slice(&(e.filter_data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&e.filter_data);
        }
    }
}

/// Scan a serialized SCBF blob and return (last_height, tip_height, last_block_id, total_addresses)
/// without allocating FilterEntry structs. Used to resume from a cached file.
fn filter_file_resume_info(data: &[u8]) -> Option<(u64, u64, [u8; 32], u64)> {
    if data.len() < 24 || &data[0..4] != b"SCBF" {
        return None;
    }
    let version = u32::from_le_bytes(data[4..8].try_into().ok()?);
    let count = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
    let tip_height = u64::from_le_bytes(data[16..24].try_into().ok()?);
    if count == 0 {
        return None;
    }
    let mut last_block_id = [0u8; 32];
    let mut last_height = 0u64;
    let mut total_addresses = 0u64;
    if version == 2 {
        if data.len() < 32 {
            return None;
        }
        let start_height = u64::from_le_bytes(data[24..32].try_into().ok()?);
        let mut pos = 32usize;
        for i in 0..count {
            if pos + 36 > data.len() {
                return None;
            }
            let addr = u16::from_le_bytes(data[pos + 32..pos + 34].try_into().ok()?);
            let flen = u16::from_le_bytes(data[pos + 34..pos + 36].try_into().ok()?) as usize;
            last_block_id.copy_from_slice(&data[pos..pos + 32]);
            last_height = start_height + i as u64;
            total_addresses += addr as u64;
            pos += 36 + flen;
        }
    } else {
        let mut pos = 24usize;
        for _ in 0..count {
            if pos + 46 > data.len() {
                return None;
            }
            let height = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
            let addr = u16::from_le_bytes(data[pos + 40..pos + 42].try_into().ok()?);
            let flen = u32::from_le_bytes(data[pos + 42..pos + 46].try_into().ok()?) as usize;
            last_block_id.copy_from_slice(&data[pos + 8..pos + 40]);
            last_height = height;
            total_addresses += addr as u64;
            pos += 46 + flen;
        }
    }
    Some((last_height, tip_height, last_block_id, total_addresses))
}

/// TxIndex entry: 8-byte txid prefix + 4-byte block height.
#[derive(Clone)]
struct TxIndexEntry {
    prefix: [u8; 8],
    height: u32,
}

/// Serialize txindex entries to STXI binary format.
fn serialize_txindex(entries: &[TxIndexEntry], tip_height: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + entries.len() * 12);
    // Header (16 bytes)
    buf.extend_from_slice(b"STXI");
    buf.extend_from_slice(&1u32.to_le_bytes()); // version
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    buf.extend_from_slice(&tip_height.to_le_bytes());
    // Per-entry (12 bytes each)
    for e in entries {
        buf.extend_from_slice(&e.prefix);
        buf.extend_from_slice(&e.height.to_le_bytes());
    }
    buf
}

/// Parse a serialized txindex file (STXI format) back into entries + tip_height.
fn parse_txindex_file(data: &[u8]) -> Result<(Vec<TxIndexEntry>, u32), String> {
    if data.len() < 16 {
        return Err("txindex file too small".into());
    }
    if &data[0..4] != b"STXI" {
        return Err("invalid txindex file magic".into());
    }
    let _version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let count = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let tip_height = u32::from_le_bytes(data[12..16].try_into().unwrap());

    let expected_len = 16 + count as usize * 12;
    if data.len() < expected_len {
        return Err(format!(
            "txindex file truncated: expected {} bytes, got {}",
            expected_len,
            data.len()
        ));
    }

    let mut entries = Vec::with_capacity(count as usize);
    let mut offset = 16;
    for _ in 0..count {
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&data[offset..offset + 8]);
        let height = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap());
        entries.push(TxIndexEntry { prefix, height });
        offset += 12;
    }

    Ok((entries, tip_height))
}

/// Fetch a URL and return the response body as bytes.
async fn fetch_bytes(url: &str) -> Result<Vec<u8>, JsValue> {
    // Use global fetch() which works in both window and worker contexts
    let global = js_sys::global();
    let fetch_fn = js_sys::Reflect::get(&global, &JsValue::from_str("fetch"))?;
    let fetch_fn: js_sys::Function = fetch_fn.dyn_into()?;
    let resp_value = JsFuture::from(js_sys::Promise::from(
        fetch_fn.call1(&JsValue::NULL, &JsValue::from_str(url))?,
    ))
    .await?;
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
    txid: String,
    addresses: Vec<String>, // all other addresses involved in the transaction
}

/// Scan a block for siacoin activity involving the target address.
/// Returns (received, sent, utxo_details).
///
/// `block_id` must be the correct block ID (from header sync or filter entries).
/// `DecodedBlock::id()` is wrong for v1 blocks (uses zero commitment instead of
/// the v1 merkle root), so callers must provide the authoritative ID.
fn scan_block_balance(
    block: &DecodedBlock,
    block_id: &BlockID,
    target: &Address,
) -> (u128, u128, Vec<UtxoDetail>) {
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
                output_id: block_id.miner_output_id(i).to_string(),
                txid: String::new(),
                addresses: Vec::new(), // coinbase — no other addresses
            });
        }
    }

    // Check V2 transactions
    for txn in &block.v2_transactions {
        let txid = txn.id();
        let txid_str = txid.to_string();

        // Collect all unique addresses in this transaction (excluding target)
        let mut txn_addrs = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut add_addr = |addr: &Address| {
            if addr != target {
                let s = addr.to_string();
                if seen.insert(s.clone()) {
                    txn_addrs.push(s);
                }
            }
        };
        for input in &txn.siacoin_inputs {
            add_addr(&input.parent.siacoin_output.address);
        }
        for output in &txn.siacoin_outputs {
            add_addr(&output.address);
        }
        for res in &txn.file_contract_resolutions {
            let fc = &res.parent.v2_file_contract;
            add_addr(&fc.renter_output.address);
            add_addr(&fc.host_output.address);
        }

        for (i, output) in txn.siacoin_outputs.iter().enumerate() {
            if output.address == *target {
                received += *output.value;
                details.push(UtxoDetail {
                    direction: "received",
                    amount: *output.value,
                    source: "v2_output".into(),
                    output_id: txid.v2_siacoin_output_id(i).to_string(),
                    txid: txid_str.clone(),
                    addresses: txn_addrs.clone(),
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
                    txid: txid_str.clone(),
                    addresses: txn_addrs.clone(),
                });
            }
        }
        // File contract resolutions
        for res in &txn.file_contract_resolutions {
            let fc = &res.parent.v2_file_contract;
            let contract_id = &res.parent.id;
            match &res.resolution {
                ContractResolution::Renewal(renewal) => {
                    if renewal.final_renter_output.address == *target {
                        received += *renewal.final_renter_output.value;
                        details.push(UtxoDetail {
                            direction: "received",
                            amount: *renewal.final_renter_output.value,
                            source: "renewal_final_renter".into(),
                            output_id: contract_id.v2_renter_output_id().to_string(),
                            txid: txid_str.clone(),
                            addresses: txn_addrs.clone(),
                        });
                    }
                    if renewal.final_host_output.address == *target {
                        received += *renewal.final_host_output.value;
                        details.push(UtxoDetail {
                            direction: "received",
                            amount: *renewal.final_host_output.value,
                            source: "renewal_final_host".into(),
                            output_id: contract_id.v2_host_output_id().to_string(),
                            txid: txid_str.clone(),
                            addresses: txn_addrs.clone(),
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
                            output_id: contract_id.v2_renter_output_id().to_string(),
                            txid: txid_str.clone(),
                            addresses: txn_addrs.clone(),
                        });
                    }
                    if fc.host_output.address == *target {
                        received += *fc.host_output.value;
                        details.push(UtxoDetail {
                            direction: "received",
                            amount: *fc.host_output.value,
                            source: "storageproof_host".into(),
                            output_id: contract_id.v2_host_output_id().to_string(),
                            txid: txid_str.clone(),
                            addresses: txn_addrs.clone(),
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
                            output_id: contract_id.v2_renter_output_id().to_string(),
                            txid: txid_str.clone(),
                            addresses: txn_addrs.clone(),
                        });
                    }
                    if fc.host_output.address == *target {
                        received += *fc.missed_host_value;
                        details.push(UtxoDetail {
                            direction: "received",
                            amount: *fc.missed_host_value,
                            source: "expiration_host".into(),
                            output_id: contract_id.v2_host_output_id().to_string(),
                            txid: txid_str.clone(),
                            addresses: txn_addrs.clone(),
                        });
                    }
                }
            }
        }
    }

    // Check V1 transactions
    for txn in &block.v1_transactions {
        let txid = txn.id();
        let txid_str = txid.to_string();

        let is_sender = txn
            .siacoin_inputs
            .iter()
            .any(|input| input.unlock_conditions.address() == *target);

        // Collect all unique addresses (excluding target)
        let mut v1_addrs = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for input in &txn.siacoin_inputs {
            let addr = input.unlock_conditions.address();
            if addr != *target {
                let s = addr.to_string();
                if seen.insert(s.clone()) {
                    v1_addrs.push(s);
                }
            }
        }
        for output in &txn.siacoin_outputs {
            if output.address != *target {
                let s = output.address.to_string();
                if seen.insert(s.clone()) {
                    v1_addrs.push(s);
                }
            }
        }

        // Check outputs for receives
        for (i, output) in txn.siacoin_outputs.iter().enumerate() {
            if output.address == *target {
                let value: u128 = *output.value;
                received += value;
                details.push(UtxoDetail {
                    direction: "received",
                    amount: value,
                    source: "v1_output".into(),
                    output_id: txn.siacoin_output_id(i).to_string(),
                    txid: txid_str.clone(),
                    addresses: v1_addrs.clone(),
                });
            }
        }

        // If we're a sender, track each input's parent_id to mark UTXOs as spent.
        // V1 inputs don't carry their value inline, so we compute the total from
        // outputs + fees and split it across matching inputs.
        if is_sender {
            let total_output_value: u128 = txn.siacoin_outputs.iter().map(|o| *o.value).sum();
            let total_fees: u128 = txn.miner_fees.iter().map(|f| **f).sum();
            let total_sent = total_output_value + total_fees;

            // Count how many inputs belong to the target address
            let matching_inputs: Vec<_> = txn
                .siacoin_inputs
                .iter()
                .filter(|input| input.unlock_conditions.address() == *target)
                .collect();
            let num_matching = matching_inputs.len() as u128;

            if num_matching > 0 {
                // Split total evenly across inputs; assign remainder to the last one
                let per_input = total_sent / num_matching;
                let remainder = total_sent % num_matching;

                for (i, input) in matching_inputs.iter().enumerate() {
                    let amount = if i as u128 == num_matching - 1 {
                        per_input + remainder
                    } else {
                        per_input
                    };
                    details.push(UtxoDetail {
                        direction: "sent",
                        amount,
                        source: "v1_input".into(),
                        output_id: input.parent_id.to_string(),
                        txid: txid_str.clone(),
                        addresses: v1_addrs.clone(),
                    });
                }
                sent += total_sent;
            }
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
    cert_hash: Option<&[u8]>,
) -> Result<Connection, JsValue> {
    let mut unique_id = [0u8; 8];
    getrandom::fill(&mut unique_id).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let our_header = Header {
        genesis_id,
        unique_id,
        net_address: "0.0.0.0:0".to_string(),
    };

    let options = web_sys::WebTransportOptions::new();
    if let Some(hash_bytes) = cert_hash {
        let wt_hash = web_sys::WebTransportHash::new();
        wt_hash.set_algorithm("sha-256");
        let hash_array = js_sys::Uint8Array::from(hash_bytes);
        wt_hash.set_value_u8_array(&hash_array);
        options.set_server_certificate_hashes(&[wt_hash]);
    }
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

/// Parse an optional cert hash hex string into bytes.
fn parse_cert_hash(cert_hash_hex: &Option<String>) -> Result<Option<Vec<u8>>, JsValue> {
    match cert_hash_hex {
        Some(h) if !h.is_empty() => {
            let bytes = hex_to_bytes(h)?;
            if bytes.len() != 32 {
                return Err(JsValue::from_str(
                    "cert_hash must be 64 hex characters (SHA-256)",
                ));
            }
            Ok(Some(bytes))
        }
        _ => Ok(None),
    }
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
    cert_hash_hex: Option<String>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    set_network_prefix(&genesis_id_hex);

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
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
    cert_hash_hex: Option<String>,
    start_height: Option<u64>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };
    set_network_prefix(&genesis_id_hex);

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;

    // V2 checkpoint block IDs (block before V2 require height)
    const V2_CHECKPOINT_MAINNET: &str =
        "0000000000000000b3b69b56214c974ce293a310d5fcfedb85f2e6b039e5bac0"; // height 529999
    const V2_CHECKPOINT_ZEN: &str =
        "0000000863c1e1191775e601ead23feeae6f5bab166eb1da538b091c6613be72"; // height 49

    log("Connecting...", "info");
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
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

    // Determine starting chain index
    let start_index = if let Some(sh) = start_height {
        let checkpoint_hex = if genesis_id_hex
            == "25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c"
        {
            V2_CHECKPOINT_MAINNET
        } else {
            V2_CHECKPOINT_ZEN
        };
        let checkpoint_bytes = hex::decode(checkpoint_hex)
            .map_err(|e| JsValue::from_str(&format!("bad checkpoint hex: {e}")))?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&checkpoint_bytes);
        log(
            &format!("Starting header sync from V2 require height (height {sh})"),
            "info",
        );
        ChainIndex {
            height: sh.saturating_sub(1),
            id: BlockID::new(id),
        }
    } else {
        ChainIndex {
            height: 0,
            id: genesis_id,
        }
    };

    // Sync headers
    log("", "info");
    if start_height.is_some() {
        log("Syncing V2 headers...", "info");
    } else {
        log("Syncing all chain headers from genesis...", "info");
    }

    let mut current_index = start_index;
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
                        &format!(
                            "  Failed after {MAX_RETRIES} retries at {total_headers} headers, continuing with what we have"
                        ),
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
                let new_conn =
                    connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
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
        // Header ID IndexedDB save disabled — Chrome can't reliably read
        // back large binary values. Headers re-download from peer on refresh (~30s).
        if start_height.is_none() {
            // Only cache full header IDs in memory (used by tx lookup etc.)
            let net = get_network_prefix();
            CACHED_HEADER_IDS.with(|cache| {
                *cache.borrow_mut() = Some((net, header_ids));
            });
        }
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

        let block_json_value = match send_v2_blocks_rpc(&wt, vec![header.parent_id], 1, false).await
        {
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
            "v2Only": start_height.is_some(),
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
            "v2Only": start_height.is_some(),
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
    cert_hash_hex: Option<String>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };
    set_network_prefix(&genesis_id_hex);

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;
    let target = parse_address(&target_address)?;

    log("Connecting...", "info");
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
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
            &format!("Syncing headers to height {target_header_height} to find starting block..."),
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
            let resp = send_headers_rpc(&conn.wt, current_index, batch_size).await?;
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
        let rpc_result = send_v2_blocks_rpc(&wt, history.clone(), blocks_per_batch, false).await;

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
                let new_conn =
                    connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
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
            let block_id = block.id(); // correct for v2; v1 miner payouts will have wrong output IDs
            let (received, sent, _details) = scan_block_balance(block, &block_id, &target);

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
    log(
        &format!("  Total received:  {}", format_sc(total_received)),
        "data",
    );
    log(
        &format!("  Total sent:      {}", format_sc(total_sent)),
        "data",
    );
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

/// Sync chain headers and return packed header IDs (32 bytes each).
/// Results are cached in IndexedDB and memory for reuse.
#[wasm_bindgen]
pub async fn sync_headers(
    url: String,
    genesis_id_hex: String,
    log_fn: js_sys::Function,
    cert_hash_hex: Option<String>,
) -> Result<Uint8Array, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };
    set_network_prefix(&genesis_id_hex);

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;

    // Load cached header IDs (memory cache or IndexedDB) as starting point
    let net = get_network_prefix();
    let mut synced_ids: Vec<BlockID> = CACHED_HEADER_IDS
        .with(|cache| {
            cache.borrow().as_ref().and_then(
                |(n, ids)| {
                    if *n == net { Some(ids.clone()) } else { None }
                },
            )
        })
        .unwrap_or_default();

    if synced_ids.is_empty() {
        if let Ok(Some(ids)) = load_header_ids().await {
            synced_ids = ids;
        }
    }

    if !synced_ids.is_empty() {
        log(
            &format!("Loaded {} header IDs from cache", synced_ids.len()),
            "ok",
        );
    }

    // Connect to peer and fetch any new headers beyond what we have
    log("Connecting to peer for header sync...", "info");
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
    log(
        &format!(
            "Connected! Peer version: {}, addr: {}",
            conn.peer_info.version, conn.peer_info.addr
        ),
        "ok",
    );
    let mut wt = conn.wt;

    // Resume from the last cached header (or genesis if none)
    let mut current_index = if let Some(last_id) = synced_ids.last() {
        ChainIndex {
            height: synced_ids.len() as u64,
            id: *last_id,
        }
    } else {
        ChainIndex {
            height: 0,
            id: genesis_id,
        }
    };

    let mut total_headers = synced_ids.len() as u64;
    let max_per_batch: u64 = 2000;
    let mut retries: u32 = 0;
    const MAX_RETRIES: u32 = 3;
    let mut new_headers: u64 = 0;

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
                        &format!("Failed after {MAX_RETRIES} retries at {total_headers} headers"),
                        "err",
                    );
                    break;
                }
                log(
                    &format!(
                        "Connection lost after {total_headers} headers, reconnecting ({retries}/{MAX_RETRIES})..."
                    ),
                    "info",
                );
                let _ = wt.close();
                let new_conn =
                    connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
                wt = new_conn.wt;
                log("Reconnected, resuming...", "ok");
                continue;
            }
        };
        let batch_count = resp.headers.len() as u64;

        if batch_count == 0 {
            break;
        }

        for header in &resp.headers {
            synced_ids.push(header.id());
        }

        total_headers += batch_count;
        new_headers += batch_count;
        let estimated_total = total_headers + resp.remaining;
        log(
            &format!("  Headers: {total_headers} / ~{estimated_total}"),
            "data",
        );

        if resp.remaining == 0 {
            break;
        }

        let last_header = resp.headers.last().unwrap();
        current_index = ChainIndex {
            height: total_headers,
            id: last_header.id(),
        };
    }

    let _ = wt.close();

    if new_headers > 0 {
        log(
            &format!("Fetched {new_headers} new headers (total: {total_headers})"),
            "ok",
        );
        // Save updated headers to cache
        CACHED_HEADER_IDS
            .with(|cache| *cache.borrow_mut() = Some((net.clone(), synced_ids.clone())));
    } else {
        log(
            &format!("{total_headers} headers synced, already at tip"),
            "ok",
        );
        CACHED_HEADER_IDS
            .with(|cache| *cache.borrow_mut() = Some((net.clone(), synced_ids.clone())));
    }

    let ids = synced_ids;

    // Pack into bytes (32 bytes per ID)
    let mut packed = Vec::with_capacity(ids.len() * 32);
    for id in &ids {
        let bytes: &[u8] = id.as_ref();
        packed.extend_from_slice(bytes);
    }

    Ok(Uint8Array::from(&packed[..]))
}

/// Process a chunk of blocks: download, build filters + txindex entries.
/// Used by Web Workers for parallel full-chain sync.
///
/// Returns a binary blob:
///   filter_count (u32 LE)
///   [filter entries: height(u64) + block_id(32) + addr_count(u16) + data_len(u32) + data(N)]
///   txindex_count (u32 LE)
///   [txindex entries: prefix(8) + height(u32)]
#[wasm_bindgen]
pub async fn generate_filters_chunk(
    url: String,
    genesis_id_hex: String,
    cert_hash_hex: Option<String>,
    history_block_id_hex: String,
    chunk_start: u64,
    max_blocks: u64,
    header_ids_bytes: Uint8Array,
    log_fn: js_sys::Function,
) -> Result<Uint8Array, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };
    set_network_prefix(&genesis_id_hex);

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;
    let p: u8 = 19;

    // Parse header IDs for this chunk
    let hid_bytes = header_ids_bytes.to_vec();
    let num_headers = hid_bytes.len() / 32;
    let mut header_ids: Vec<BlockID> = Vec::with_capacity(num_headers);
    for i in 0..num_headers {
        let mut id = [0u8; 32];
        id.copy_from_slice(&hid_bytes[i * 32..(i + 1) * 32]);
        header_ids.push(BlockID::new(id));
    }

    // Parse starting block ID for history
    let mut history: Vec<BlockID> = if history_block_id_hex.is_empty() {
        Vec::new() // genesis
    } else {
        let bytes = hex_to_bytes(&history_block_id_hex)?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        vec![BlockID::new(id)]
    };

    // Connect
    log("Connecting...", "info");
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
    log(&format!("Connected (peer {})", conn.peer_info.addr), "ok");
    let mut wt = conn.wt;

    let mut filter_entries: Vec<FilterEntry> = Vec::new();
    let mut txindex_entries: Vec<TxIndexEntry> = Vec::new();
    let mut utxo_created: Vec<([u8; 8], [u8; 8], u32)> = Vec::new(); // (addr_prefix, oid_prefix, height)
    let mut utxo_spent: Vec<([u8; 8], [u8; 8])> = Vec::new(); // (addr_prefix, oid_prefix)
    let mut attestation_entries: Vec<([u8; 32], [u8; 8], u32)> = Vec::new(); // (pubkey, key_hash, height)
    let mut blocks_processed: u64 = 0;
    let mut total_addresses: u64 = 0;
    let blocks_per_batch: u64 = 100;

    loop {
        if blocks_processed >= max_blocks {
            break;
        }

        let batch_max = std::cmp::min(blocks_per_batch, max_blocks - blocks_processed);

        let rpc_result = send_v2_blocks_rpc(&wt, history.clone(), batch_max, false).await;
        let (blocks_with_raw, _remaining) = match rpc_result {
            Ok(r) => r,
            Err(_) => {
                log("Connection lost, reconnecting...", "info");
                let _ = wt.close();
                let new_conn =
                    connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
                wt = new_conn.wt;
                log("Reconnected", "ok");
                continue;
            }
        };

        if blocks_with_raw.is_empty() {
            break;
        }

        for (i, (block, _raw)) in blocks_with_raw.iter().enumerate() {
            let block_index = blocks_processed + i as u64;
            let height = chunk_start + block_index + 1;

            // Get block ID from header_ids (correct for both v1 and v2 blocks)
            let block_id_obj = if (block_index as usize) < header_ids.len() {
                header_ids[block_index as usize].clone()
            } else {
                block.id()
            };
            let block_id_bytes: [u8; 32] = {
                let slice: &[u8] = block_id_obj.as_ref();
                slice.try_into().unwrap()
            };

            // Build GCS filter
            let addresses = extract_addresses(&block);
            total_addresses += addresses.len() as u64;
            let filter_data = build_gcs_filter(&addresses, &block_id_bytes, p);

            filter_entries.push(FilterEntry {
                height,
                block_id: block_id_bytes,
                address_count: addresses.len() as u16,
                filter_data,
            });

            // Build txindex entries (v1 + v2 transactions)
            for txn in &block.v1_transactions {
                let tid = txn.id();
                let tid_bytes: &[u8] = tid.as_ref();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&tid_bytes[..8]);
                txindex_entries.push(TxIndexEntry {
                    prefix,
                    height: height as u32,
                });
            }
            for txn in &block.v2_transactions {
                let tid = txn.id();
                let tid_bytes: &[u8] = tid.as_ref();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&tid_bytes[..8]);
                txindex_entries.push(TxIndexEntry {
                    prefix,
                    height: height as u32,
                });
            }

            // Build UTXO index entries
            let h32 = height as u32;

            // Miner payouts → created
            for (i, payout) in block.miner_payouts.iter().enumerate() {
                let addr_bytes: &[u8] = payout.address.as_ref();
                let mut ap = [0u8; 8];
                ap.copy_from_slice(&addr_bytes[..8]);
                let oid = block_id_obj.miner_output_id(i);
                let oid_bytes: &[u8] = oid.as_ref();
                let mut op = [0u8; 8];
                op.copy_from_slice(&oid_bytes[..8]);
                utxo_created.push((ap, op, h32));
            }

            // V1 transaction outputs → created, inputs → spent
            for txn in &block.v1_transactions {
                for (i, output) in txn.siacoin_outputs.iter().enumerate() {
                    let addr_bytes: &[u8] = output.address.as_ref();
                    let mut ap = [0u8; 8];
                    ap.copy_from_slice(&addr_bytes[..8]);
                    let oid = txn.siacoin_output_id(i);
                    let oid_bytes: &[u8] = oid.as_ref();
                    let mut op = [0u8; 8];
                    op.copy_from_slice(&oid_bytes[..8]);
                    utxo_created.push((ap, op, h32));
                }

                for input in &txn.siacoin_inputs {
                    let addr = input.unlock_conditions.address();
                    let addr_bytes: &[u8] = addr.as_ref();
                    let mut ap = [0u8; 8];
                    ap.copy_from_slice(&addr_bytes[..8]);
                    let oid_bytes: &[u8] = input.parent_id.as_ref();
                    let mut op = [0u8; 8];
                    op.copy_from_slice(&oid_bytes[..8]);
                    utxo_spent.push((ap, op));
                }
            }

            // V2 transaction outputs → created, inputs → spent
            for txn in &block.v2_transactions {
                let txid = txn.id();

                for (i, output) in txn.siacoin_outputs.iter().enumerate() {
                    let addr_bytes: &[u8] = output.address.as_ref();
                    let mut ap = [0u8; 8];
                    ap.copy_from_slice(&addr_bytes[..8]);
                    let oid = txid.v2_siacoin_output_id(i);
                    let oid_bytes: &[u8] = oid.as_ref();
                    let mut op = [0u8; 8];
                    op.copy_from_slice(&oid_bytes[..8]);
                    utxo_created.push((ap, op, h32));
                }

                for input in &txn.siacoin_inputs {
                    let addr_bytes: &[u8] = input.parent.siacoin_output.address.as_ref();
                    let mut ap = [0u8; 8];
                    ap.copy_from_slice(&addr_bytes[..8]);
                    let oid_bytes: &[u8] = input.parent.id.as_ref();
                    let mut op = [0u8; 8];
                    op.copy_from_slice(&oid_bytes[..8]);
                    utxo_spent.push((ap, op));
                }

                // File contract resolutions → created outputs
                for res in &txn.file_contract_resolutions {
                    let fc = &res.parent.v2_file_contract;
                    let contract_id = &res.parent.id;
                    match &res.resolution {
                        ContractResolution::Renewal(renewal) => {
                            // Renter final output
                            let addr_bytes: &[u8] = renewal.final_renter_output.address.as_ref();
                            let mut ap = [0u8; 8];
                            ap.copy_from_slice(&addr_bytes[..8]);
                            let oid = contract_id.v2_renter_output_id();
                            let oid_bytes: &[u8] = oid.as_ref();
                            let mut op = [0u8; 8];
                            op.copy_from_slice(&oid_bytes[..8]);
                            utxo_created.push((ap, op, h32));
                            // Host final output
                            let addr_bytes: &[u8] = renewal.final_host_output.address.as_ref();
                            let mut ap = [0u8; 8];
                            ap.copy_from_slice(&addr_bytes[..8]);
                            let oid = contract_id.v2_host_output_id();
                            let oid_bytes: &[u8] = oid.as_ref();
                            let mut op = [0u8; 8];
                            op.copy_from_slice(&oid_bytes[..8]);
                            utxo_created.push((ap, op, h32));
                        }
                        ContractResolution::StorageProof(_) | ContractResolution::Expiration() => {
                            // Renter output
                            let addr_bytes: &[u8] = fc.renter_output.address.as_ref();
                            let mut ap = [0u8; 8];
                            ap.copy_from_slice(&addr_bytes[..8]);
                            let oid = contract_id.v2_renter_output_id();
                            let oid_bytes: &[u8] = oid.as_ref();
                            let mut op = [0u8; 8];
                            op.copy_from_slice(&oid_bytes[..8]);
                            utxo_created.push((ap, op, h32));
                            // Host output
                            let addr_bytes: &[u8] = fc.host_output.address.as_ref();
                            let mut ap = [0u8; 8];
                            ap.copy_from_slice(&addr_bytes[..8]);
                            let oid = contract_id.v2_host_output_id();
                            let oid_bytes: &[u8] = oid.as_ref();
                            let mut op = [0u8; 8];
                            op.copy_from_slice(&oid_bytes[..8]);
                            utxo_created.push((ap, op, h32));
                        }
                    }
                }

                // Attestations → attestation index entries
                for att in &txn.attestations {
                    let pk_bytes: &[u8] = att.public_key.as_ref();
                    let mut pubkey = [0u8; 32];
                    pubkey.copy_from_slice(&pk_bytes[..32]);
                    let key_hash_full = blake2b_simd::Params::new()
                        .hash_length(32)
                        .hash(att.key.as_bytes());
                    let mut key_hash = [0u8; 8];
                    key_hash.copy_from_slice(&key_hash_full.as_bytes()[..8]);
                    attestation_entries.push((pubkey, key_hash, h32));
                }
            }
        }

        blocks_processed += blocks_with_raw.len() as u64;

        let pct = if max_blocks > 0 {
            (blocks_processed as f64 / max_blocks as f64 * 100.0) as u32
        } else {
            100
        };
        log(
            &format!("  {blocks_processed}/{max_blocks} ({pct}%) | {total_addresses} addrs"),
            "data",
        );

        // Update history for next batch
        let last_entry = filter_entries.last().unwrap();
        history = vec![BlockID::new(last_entry.block_id)];
    }

    let _ = wt.close();

    // Sort txindex by prefix for efficient k-way merge in JS
    txindex_entries.sort_by(|a, b| a.prefix.cmp(&b.prefix));

    // Serialize result
    let mut result = Vec::new();

    // Filter entries
    result.extend_from_slice(&(filter_entries.len() as u32).to_le_bytes());
    for entry in &filter_entries {
        result.extend_from_slice(&entry.height.to_le_bytes());
        result.extend_from_slice(&entry.block_id);
        result.extend_from_slice(&entry.address_count.to_le_bytes());
        result.extend_from_slice(&(entry.filter_data.len() as u32).to_le_bytes());
        result.extend_from_slice(&entry.filter_data);
    }

    // TxIndex entries
    result.extend_from_slice(&(txindex_entries.len() as u32).to_le_bytes());
    for entry in &txindex_entries {
        result.extend_from_slice(&entry.prefix);
        result.extend_from_slice(&entry.height.to_le_bytes());
    }

    // UTXO created entries
    result.extend_from_slice(&(utxo_created.len() as u32).to_le_bytes());
    for (ap, op, h) in &utxo_created {
        result.extend_from_slice(ap);
        result.extend_from_slice(op);
        result.extend_from_slice(&h.to_le_bytes());
    }

    // UTXO spent entries
    result.extend_from_slice(&(utxo_spent.len() as u32).to_le_bytes());
    for (ap, op) in &utxo_spent {
        result.extend_from_slice(ap);
        result.extend_from_slice(op);
    }

    // Attestation entries
    result.extend_from_slice(&(attestation_entries.len() as u32).to_le_bytes());
    for (pubkey, key_hash, h) in &attestation_entries {
        result.extend_from_slice(pubkey);
        result.extend_from_slice(key_hash);
        result.extend_from_slice(&h.to_le_bytes());
    }

    log(
        &format!(
            "Chunk done: {} filters, {} txindex, {} utxo created, {} utxo spent, {} attestations, {} addresses",
            filter_entries.len(),
            txindex_entries.len(),
            utxo_created.len(),
            utxo_spent.len(),
            attestation_entries.len(),
            total_addresses
        ),
        "ok",
    );

    Ok(Uint8Array::from(&result[..]))
}

#[wasm_bindgen]
pub async fn generate_filters(
    url: String,
    genesis_id_hex: String,
    log_fn: js_sys::Function,
    cert_hash_hex: Option<String>,
    start_height: Option<u64>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };
    set_network_prefix(&genesis_id_hex);

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;
    let p: u8 = 19;

    // Step 1: Connect
    log("Connecting to peer...", "info");
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
    log(
        &format!(
            "Connected! Peer version: {}, addr: {}",
            conn.peer_info.version, conn.peer_info.addr
        ),
        "ok",
    );

    // Hardcoded checkpoint block IDs for V2-only mode (block before V2 require height)
    // These allow skipping the full header sync by jumping directly to V2 blocks.
    const V2_CHECKPOINT_MAINNET: &str =
        "0000000000000000b3b69b56214c974ce293a310d5fcfedb85f2e6b039e5bac0"; // height 529999
    const V2_CHECKPOINT_ZEN: &str =
        "0000000863c1e1191775e601ead23feeae6f5bab166eb1da538b091c6613be72"; // height 49

    let cache_key = prefixed_key(if start_height.is_some() {
        "filter_entries_v2"
    } else {
        "filter_entries"
    });
    let start_offset: u64 = start_height.map(|h| h.saturating_sub(1)).unwrap_or(0);
    let mut wt = conn.wt;
    let mut tip_height: u64 = 0;

    // Step 2: Get header IDs (skip entirely for V2-only mode)
    let header_ids: Vec<BlockID> = if start_height.is_some() {
        log(
            &format!(
                "V2-only mode: skipping header sync, starting from height {}",
                start_offset + 1
            ),
            "info",
        );
        Vec::new() // not needed — v2 blocks have correct block.id()
    } else {
        // Full mode: load cached headers and sync new ones from peer
        let net = get_network_prefix();
        let mut synced_ids: Vec<BlockID> = CACHED_HEADER_IDS
            .with(|cache| {
                cache.borrow().as_ref().and_then(
                    |(n, ids)| {
                        if *n == net { Some(ids.clone()) } else { None }
                    },
                )
            })
            .unwrap_or_default();

        if synced_ids.is_empty() {
            if let Ok(Some(ids)) = load_header_ids().await {
                synced_ids = ids;
            }
        }

        if !synced_ids.is_empty() {
            log(
                &format!("Loaded {} header IDs from cache", synced_ids.len()),
                "ok",
            );
        }

        // Resume from last cached header (or genesis)
        let mut current_index = if let Some(last_id) = synced_ids.last() {
            ChainIndex {
                height: synced_ids.len() as u64,
                id: *last_id,
            }
        } else {
            ChainIndex {
                height: 0,
                id: genesis_id,
            }
        };

        let mut total_headers = synced_ids.len() as u64;
        let max_per_batch: u64 = 2000;
        let mut retries: u32 = 0;
        const MAX_RETRIES: u32 = 3;
        let mut new_headers: u64 = 0;

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
                            &format!(
                                "  Failed after {MAX_RETRIES} retries at {total_headers} headers, continuing with what we have"
                            ),
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
                    let new_conn =
                        connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
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
                synced_ids.push(header.id());
            }

            total_headers += batch_count;
            new_headers += batch_count;
            let estimated_total = total_headers + resp.remaining;
            log(
                &format!("  Headers: {total_headers} / ~{estimated_total}"),
                "data",
            );

            if resp.remaining == 0 {
                break;
            }

            let last_header = resp.headers.last().unwrap();
            current_index = ChainIndex {
                height: total_headers,
                id: last_header.id(),
            };
        }

        if new_headers > 0 {
            log(
                &format!("Fetched {new_headers} new headers (total: {total_headers})"),
                "ok",
            );
            CACHED_HEADER_IDS
                .with(|cache| *cache.borrow_mut() = Some((net.clone(), synced_ids.clone())));
        } else {
            log(
                &format!("{total_headers} headers synced, already at tip"),
                "ok",
            );
            CACHED_HEADER_IDS
                .with(|cache| *cache.borrow_mut() = Some((net.clone(), synced_ids.clone())));
        }

        tip_height = synced_ids.len() as u64;
        synced_ids
    };

    // Step 3: Load cached filters from IndexedDB and resume.
    // We keep a flat `idb_bytes: Vec<u8>` (the serialized SCBF blob) instead of
    // deserializing all entries into Vec<FilterEntry>.  This bounds memory to one
    // compact binary buffer regardless of how many blocks have been indexed.
    let mut current_entries: Vec<FilterEntry> = Vec::new();
    let mut blocks_downloaded: u64 = start_offset;
    let mut total_addresses: u64 = 0;
    let mut idb_bytes: Vec<u8> = Vec::new();
    // After each periodic save current_entries[0] is a kept-over entry from the
    // previous batch; entries_offset tracks how many leading entries to skip when
    // computing "new entries since last save".
    let mut entries_offset: usize = 0;
    let mut resume_block_id: Option<[u8; 32]> = None;

    if let Ok(result) = JsFuture::from(idb_load(&cache_key)).await {
        if !result.is_null() && !result.is_undefined() {
            let arr = Uint8Array::from(result);
            let raw = arr.to_vec();
            if raw.len() >= 24 && &raw[0..4] == b"SCBF" {
                let cached_count = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as u64;
                if let Some((last_height, cached_tip, last_bid, addr_total)) =
                    filter_file_resume_info(&raw)
                {
                    // Corruption detection
                    let expected_count = last_height.saturating_sub(start_offset);
                    let height_too_high =
                        start_height.is_some() && last_height > start_offset + 200_000;
                    if cached_count > expected_count + 1000 || height_too_high {
                        log(
                            &format!(
                                "Filter cache corrupted: {} entries, max height {} (start {}) — discarding",
                                cached_count, last_height, start_offset
                            ),
                            "err",
                        );
                        let _ =
                            JsFuture::from(idb_save(&cache_key, Uint8Array::new_with_length(0)))
                                .await;
                    } else {
                        log(
                            &format!(
                                "Loaded {cached_count} cached filter entries from IndexedDB (up to height {})",
                                last_height
                            ),
                            "ok",
                        );
                        total_addresses = addr_total;
                        blocks_downloaded = last_height;
                        tip_height = if cached_tip > 0 {
                            cached_tip
                        } else if last_height > 0 {
                            last_height
                        } else {
                            tip_height
                        };
                        idb_bytes = raw;
                        resume_block_id = Some(last_bid);
                    }
                }
            }
        }
    }

    log("Downloading blocks and building filters...", "info");

    // Build initial history for block download
    let mut history: Vec<BlockID> = if let Some(bid) = resume_block_id {
        vec![BlockID::new(bid)]
    } else if start_height.is_some() {
        // V2-only: use hardcoded checkpoint to skip to V2 require height
        let checkpoint_hex = if genesis_id_hex
            == "25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c"
        {
            V2_CHECKPOINT_MAINNET
        } else {
            V2_CHECKPOINT_ZEN
        };
        let checkpoint_bytes = hex::decode(checkpoint_hex)
            .map_err(|e| JsValue::from_str(&format!("bad checkpoint hex: {e}")))?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&checkpoint_bytes);
        vec![BlockID::new(id)]
    } else if blocks_downloaded > 0 {
        // Full mode resume: use header ID
        vec![header_ids[(blocks_downloaded - 1) as usize].clone()]
    } else {
        Vec::new() // start from genesis
    };

    let blocks_per_batch: u64 = 100;
    let save_interval: u64 = 1000;
    loop {
        let rpc_result = send_v2_blocks_rpc(&wt, history.clone(), blocks_per_batch, false).await;

        let (blocks_with_raw, remaining) = match rpc_result {
            Ok(result) => result,
            Err(_) => {
                log(
                    &format!(
                        "  Connection lost after {} blocks, reconnecting...",
                        blocks_downloaded.saturating_sub(start_offset)
                    ),
                    "info",
                );
                let _ = wt.close();
                let new_conn =
                    connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
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

        // Save attach height before processing batch
        let attach_height = blocks_downloaded;

        for (i, (block, _raw)) in blocks_with_raw.iter().enumerate() {
            // Compute expected height from batch index (server sends from attach+1)
            let expected_height = attach_height + i as u64 + 1;
            let height = block.v2_height.unwrap_or(expected_height);
            // For v2 blocks, block.id() is correct.
            // For v1 blocks, use the header ID (which includes the correct v1 merkle root).
            let block_id_obj = if start_height.is_some() {
                // V2-only mode: block.id() is always correct for v2 blocks
                block.id()
            } else if (expected_height as usize) < header_ids.len() {
                header_ids[expected_height as usize].clone()
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

            current_entries.push(FilterEntry {
                height,
                block_id: block_id_bytes,
                address_count: addresses.len() as u16,
                filter_data,
            });
        }

        // Update blocks_downloaded from last block's actual v2_height (self-corrects
        // any mismatch between start_offset and actual checkpoint height)
        if let Some((last_block, _)) = blocks_with_raw.last() {
            if let Some(v2h) = last_block.v2_height {
                blocks_downloaded = v2h;
            } else {
                blocks_downloaded = attach_height + blocks_with_raw.len() as u64;
            }
        }

        // Update tip_height from remaining count (always update — the network may have advanced)
        if start_height.is_some() {
            tip_height = blocks_downloaded + remaining;
        }

        let processed = blocks_downloaded.saturating_sub(start_offset);
        let total_est = processed + remaining;
        let pct = if total_est > 0 {
            (processed as f64 / total_est as f64 * 100.0) as u32
        } else {
            100
        };
        log(
            &format!("  Blocks: {processed} / ~{total_est} ({pct}%) | {total_addresses} addresses",),
            "data",
        );

        // Periodically flush current_entries to idb_bytes and free them.
        // This keeps memory proportional to save_interval rather than total blocks.
        if processed % save_interval == 0 && processed > 0 {
            let new_entries = &current_entries[entries_offset..];
            if idb_bytes.is_empty() {
                // First save — initialize the blob from all current entries
                idb_bytes = if let Some(sh) = start_height {
                    serialize_filter_file_v2(new_entries, p as u32, tip_height, sh)
                } else {
                    serialize_filter_file(new_entries, p as u32, tip_height)
                };
            } else {
                // Subsequent save — binary-append only the new entries
                append_entries_to_filter_bytes(&mut idb_bytes, new_entries, tip_height);
            }
            let arr = Uint8Array::from(&idb_bytes[..]);
            let _ = JsFuture::from(idb_save(&cache_key, arr)).await;
            log("  (progress saved to IndexedDB)", "info");
            // Free old entries; keep only the last one as the anchor for next batch
            let last = current_entries.pop().unwrap();
            current_entries.clear();
            current_entries.push(last);
            entries_offset = 1; // current_entries[0] is the kept-over anchor
        }

        if remaining == 0 {
            break;
        }

        // Use block ID from last processed block as history
        let last_id = current_entries.last().unwrap().block_id;
        history = vec![BlockID::new(last_id)];
    }

    let _ = wt.close();

    // Step 4: Append any remaining entries and save final result to IndexedDB.
    // At this point current_entries holds at most save_interval+1 entries.
    log("Serializing filter file...", "info");
    let new_entries = &current_entries[entries_offset..];
    if idb_bytes.is_empty() {
        // Fewer than save_interval total blocks — never saved yet
        idb_bytes = if let Some(sh) = start_height {
            serialize_filter_file_v2(new_entries, p as u32, tip_height, sh)
        } else {
            serialize_filter_file(new_entries, p as u32, tip_height)
        };
    } else {
        append_entries_to_filter_bytes(&mut idb_bytes, new_entries, tip_height);
    }
    let arr = Uint8Array::from(&idb_bytes[..]);
    let _ = JsFuture::from(idb_save(&cache_key, arr)).await;

    // Read total entry count from the header for stats
    let total_entries = if idb_bytes.len() >= 12 {
        u32::from_le_bytes(idb_bytes[8..12].try_into().unwrap()) as u64
    } else {
        0
    };

    log("", "info");
    log("Filter generation complete!", "ok");
    let total_processed = blocks_downloaded.saturating_sub(start_offset);
    log(&format!("  Blocks processed: {total_processed}"), "data");
    log(&format!("  Total addresses:  {total_addresses}"), "data");
    log(&format!("  Tip height:       {tip_height}"), "data");
    log(
        &format!(
            "  File size:        {:.1} KB",
            idb_bytes.len() as f64 / 1024.0
        ),
        "data",
    );
    log(
        &format!(
            "  Avg filter size:  {:.0} bytes",
            if total_entries == 0 {
                0.0
            } else {
                idb_bytes.len() as f64 / total_entries as f64
            }
        ),
        "data",
    );

    // Return as Uint8Array
    let uint8_array = Uint8Array::new_with_length(idb_bytes.len() as u32);
    uint8_array.copy_from(&idb_bytes);
    Ok(uint8_array.into())
}

#[wasm_bindgen]
pub async fn generate_txindex(
    url: String,
    genesis_id_hex: String,
    log_fn: js_sys::Function,
    cert_hash_hex: Option<String>,
    start_height: Option<u64>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };
    set_network_prefix(&genesis_id_hex);

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;

    // V2 checkpoint block IDs (block before V2 require height)
    const V2_CHECKPOINT_MAINNET: &str =
        "0000000000000000b3b69b56214c974ce293a310d5fcfedb85f2e6b039e5bac0"; // height 529999
    const V2_CHECKPOINT_ZEN: &str =
        "0000000863c1e1191775e601ead23feeae6f5bab166eb1da538b091c6613be72"; // height 49

    log("Connecting to peer...", "info");
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
    log(
        &format!(
            "Connected! Peer version: {}, addr: {}",
            conn.peer_info.version, conn.peer_info.addr
        ),
        "ok",
    );

    let cache_key = prefixed_key(if start_height.is_some() {
        "txindex_entries_v2"
    } else {
        "txindex_entries"
    });
    let checkpoint_key = format!("{}_checkpoint", cache_key);
    let start_offset: u64 = start_height.map(|h| h.saturating_sub(1)).unwrap_or(0);
    let mut wt = conn.wt;
    let mut tip_height: u64 = 0;
    let mut entries: Vec<TxIndexEntry> = Vec::new();
    let mut blocks_downloaded: u64 = start_offset;
    let mut total_txns: u64 = 0;
    let mut max_cached_height: u64 = 0;

    // Try to load cached txindex entries from IndexedDB for resume
    if let Ok(result) = JsFuture::from(idb_load(&cache_key)).await {
        if !result.is_null() && !result.is_undefined() {
            let arr = Uint8Array::from(result);
            let cached_bytes = arr.to_vec();
            if let Ok((cached_entries, cached_tip)) = parse_txindex_file(&cached_bytes) {
                let cached_count = cached_entries.len() as u64;
                max_cached_height = cached_entries
                    .iter()
                    .map(|e| e.height as u64)
                    .max()
                    .unwrap_or(0);
                // Corruption detection: max height unreasonably far from start
                // (bogus heights from count-based era). Note: count-based check
                // doesn't work for txindex since there can be many txns per block.
                let height_too_high =
                    start_height.is_some() && max_cached_height > start_offset + 200_000;
                if height_too_high {
                    log(
                        &format!(
                            "Txindex cache corrupted: {} entries, max height {} (start {}) — discarding",
                            cached_count, max_cached_height, start_offset
                        ),
                        "err",
                    );
                    max_cached_height = 0;
                    let _ =
                        JsFuture::from(idb_save(&cache_key, Uint8Array::new_with_length(0))).await;
                    let _ =
                        JsFuture::from(idb_save(&checkpoint_key, Uint8Array::new_with_length(0)))
                            .await;
                } else {
                    log(
                        &format!(
                            "Loaded {} cached txindex entries from IndexedDB (up to height {}, tip {})",
                            cached_count, max_cached_height, cached_tip
                        ),
                        "ok",
                    );
                    total_txns = cached_count;
                    entries = cached_entries;
                    blocks_downloaded = max_cached_height;
                    if cached_tip > 0 {
                        tip_height = cached_tip as u64;
                    } else if max_cached_height > 0 {
                        tip_height = max_cached_height;
                    }
                }
            }
        }
    }

    // Try to load resume checkpoint (last block ID) for continuing block download
    let mut resume_block_id: Option<BlockID> = None;
    if blocks_downloaded > start_offset {
        if let Ok(result) = JsFuture::from(idb_load(&checkpoint_key)).await {
            if !result.is_null() && !result.is_undefined() {
                let arr = Uint8Array::from(result);
                let ckpt_bytes = arr.to_vec();
                // Checkpoint format: blocks_downloaded(8) + last_block_id(32) = 40 bytes
                if ckpt_bytes.len() == 40 {
                    let ckpt_blocks = u64::from_le_bytes(ckpt_bytes[0..8].try_into().unwrap());
                    let mut bid = [0u8; 32];
                    bid.copy_from_slice(&ckpt_bytes[8..40]);
                    // Only trust checkpoint if its height is reasonable
                    // (between max_cached_height and max_cached_height + a reasonable gap)
                    if ckpt_blocks >= max_cached_height && ckpt_blocks <= max_cached_height + 10000
                    {
                        blocks_downloaded = ckpt_blocks;
                        log(
                            &format!(
                                "Resuming from checkpoint: height {}, last block ID {}..{}",
                                blocks_downloaded,
                                &hex::encode(&bid)[..8],
                                &hex::encode(&bid)[56..]
                            ),
                            "ok",
                        );
                        resume_block_id = Some(BlockID::new(bid));
                    } else {
                        log(
                            &format!(
                                "Ignoring stale checkpoint (height {} vs cached {})",
                                ckpt_blocks, max_cached_height
                            ),
                            "info",
                        );
                    }
                }
            }
        }
    }

    // If no valid checkpoint but we have cached entries, try to get a resume block_id
    // from the filter cache (filter entries store block_ids by height)
    if resume_block_id.is_none() && max_cached_height > 0 {
        let filter_key = prefixed_key(if start_height.is_some() {
            "filter_entries_v2"
        } else {
            "filter_entries"
        });
        if let Ok(result) = JsFuture::from(idb_load(&filter_key)).await {
            if !result.is_null() && !result.is_undefined() {
                let arr = Uint8Array::from(result);
                let filter_bytes = arr.to_vec();
                if let Ok(filter_file) = parse_filter_file(&filter_bytes) {
                    // Find the filter entry closest to max_cached_height
                    if let Some(entry) = filter_file
                        .entries
                        .iter()
                        .rev()
                        .find(|e| e.height <= max_cached_height)
                    {
                        resume_block_id = Some(BlockID::new(entry.block_id));
                        blocks_downloaded = entry.height;
                        log(
                            &format!(
                                "Resuming from filter entry at height {} (block {}..{})",
                                entry.height,
                                &hex::encode(&entry.block_id)[..8],
                                &hex::encode(&entry.block_id)[56..]
                            ),
                            "ok",
                        );
                    }
                }
            }
        }
    }

    // Build initial history
    let mut history: Vec<BlockID> = if let Some(bid) = resume_block_id {
        vec![bid]
    } else if start_height.is_some() {
        let checkpoint_hex = if genesis_id_hex
            == "25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c"
        {
            V2_CHECKPOINT_MAINNET
        } else {
            V2_CHECKPOINT_ZEN
        };
        let checkpoint_bytes = hex::decode(checkpoint_hex)
            .map_err(|e| JsValue::from_str(&format!("bad checkpoint hex: {e}")))?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&checkpoint_bytes);
        // Reset blocks_downloaded to start_offset since we're starting from V2 checkpoint
        blocks_downloaded = start_offset;
        log(
            &format!("V2-only mode: starting from height {}", start_offset + 1),
            "info",
        );
        vec![BlockID::new(id)]
    } else {
        Vec::new()
    };

    log(
        "Downloading blocks and building transaction index...",
        "info",
    );

    let blocks_per_batch: u64 = 100;
    let save_interval: u64 = 1000;
    let mut last_block_id: Option<BlockID> = None;

    loop {
        let rpc_result = send_v2_blocks_rpc(&wt, history.clone(), blocks_per_batch, false).await;

        let (blocks_with_raw, remaining) = match rpc_result {
            Ok(result) => result,
            Err(_) => {
                log(
                    &format!(
                        "  Connection lost after {} blocks, reconnecting...",
                        blocks_downloaded.saturating_sub(start_offset)
                    ),
                    "info",
                );
                let _ = wt.close();
                let new_conn =
                    connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
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

        // Save attach height before processing — server sends blocks from attach+1
        let attach_height = blocks_downloaded;

        for (i, (block, _raw)) in blocks_with_raw.iter().enumerate() {
            // Compute expected height from batch index (independent of blocks_downloaded)
            let expected_height = attach_height + i as u64 + 1;
            let height = block.v2_height.unwrap_or(expected_height);

            last_block_id = Some(block.id());

            // Skip blocks we've already indexed (can happen when resuming without checkpoint)
            if height <= max_cached_height && max_cached_height > 0 {
                continue;
            }

            // Collect V2 transaction ID prefixes
            for txn in &block.v2_transactions {
                let tid = txn.id();
                let tid_bytes: &[u8] = tid.as_ref();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&tid_bytes[..8]);
                entries.push(TxIndexEntry {
                    prefix,
                    height: height as u32,
                });
                total_txns += 1;
            }
        }

        // Update blocks_downloaded from last block's actual v2_height (self-corrects
        // any mismatch between start_offset and actual checkpoint height)
        if let Some((last_block, _)) = blocks_with_raw.last() {
            if let Some(v2h) = last_block.v2_height {
                blocks_downloaded = v2h;
            } else {
                blocks_downloaded = attach_height + blocks_with_raw.len() as u64;
            }
        }

        // Update tip_height from remaining count (always update — the network may have advanced)
        if start_height.is_some() {
            tip_height = blocks_downloaded + remaining;
        }

        let processed = blocks_downloaded.saturating_sub(start_offset);
        let total_est = processed + remaining;
        let pct = if total_est > 0 {
            (processed as f64 / total_est as f64 * 100.0) as u32
        } else {
            100
        };
        log(
            &format!("  Blocks: {processed} / ~{total_est} ({pct}%) | {total_txns} transactions",),
            "data",
        );

        // Save progress periodically
        if processed % save_interval == 0 && processed > 0 {
            let mut sorted = entries.clone();
            sorted.sort_by(|a, b| a.prefix.cmp(&b.prefix));
            let checkpoint = serialize_txindex(&sorted, tip_height as u32);
            let arr = Uint8Array::from(&checkpoint[..]);
            let _ = JsFuture::from(idb_save(&cache_key, arr)).await;
            // Save resume checkpoint (blocks_downloaded + last_block_id)
            if let Some(ref bid) = last_block_id {
                let mut ckpt = Vec::with_capacity(40);
                ckpt.extend_from_slice(&blocks_downloaded.to_le_bytes());
                ckpt.extend_from_slice(bid.as_ref());
                let ckpt_arr = Uint8Array::from(&ckpt[..]);
                let _ = JsFuture::from(idb_save(&checkpoint_key, ckpt_arr)).await;
            }
            log("  (progress saved to IndexedDB)", "info");
        }

        if remaining == 0 {
            break;
        }

        history = vec![last_block_id.unwrap()];
    }

    let _ = wt.close();

    // Sort entries by txid prefix for binary search
    log("Sorting transaction index...", "info");
    entries.sort_by(|a, b| a.prefix.cmp(&b.prefix));

    // Serialize and save
    log("Serializing transaction index...", "info");
    let file_bytes = serialize_txindex(&entries, tip_height as u32);
    let arr = Uint8Array::from(&file_bytes[..]);
    let _ = JsFuture::from(idb_save(&cache_key, arr)).await;
    // Save final resume checkpoint
    if let Some(ref bid) = last_block_id {
        let mut ckpt = Vec::with_capacity(40);
        ckpt.extend_from_slice(&blocks_downloaded.to_le_bytes());
        ckpt.extend_from_slice(bid.as_ref());
        let ckpt_arr = Uint8Array::from(&ckpt[..]);
        let _ = JsFuture::from(idb_save(&checkpoint_key, ckpt_arr)).await;
    }

    log("", "info");
    log("Transaction index generation complete!", "ok");
    let total_processed = blocks_downloaded.saturating_sub(start_offset);
    log(&format!("  Blocks processed: {total_processed}"), "data");
    log(&format!("  Transactions:     {total_txns}"), "data");
    log(&format!("  Tip height:       {tip_height}"), "data");
    log(
        &format!(
            "  File size:        {:.1} KB ({:.1} MB)",
            file_bytes.len() as f64 / 1024.0,
            file_bytes.len() as f64 / 1024.0 / 1024.0
        ),
        "data",
    );
    log(
        &format!("  Entries:          {} (12 bytes each)", entries.len()),
        "data",
    );

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
    cert_hash_hex: Option<String>,
    max_matches: Option<u32>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };
    set_network_prefix(&genesis_id_hex);

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;
    let target = parse_address(&target_address)?;
    let target_bytes: [u8; 32] = {
        let slice: &[u8] = target.as_ref();
        slice
            .try_into()
            .map_err(|_| JsValue::from_str("address must be 32 bytes"))?
    };

    // Step 1: Load filter file
    log("Loading block filters...", "info");
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

    // If max_matches is set and exceeded, return early with match count
    if let Some(limit) = max_matches {
        if matches.len() > limit as usize {
            let result = format!(
                r#"{{"tooManyMatches": true, "matchCount": {}}}"#,
                matches.len()
            );
            return Ok(JsValue::from_str(&result));
        }
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
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
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

    for (i, (height, match_block_id)) in matches.iter().enumerate() {
        let block_id = BlockID::from(*match_block_id);
        // Try cache first
        if let Ok(Some(cached)) = load_cached_block(*height).await {
            log(
                &format!("  [{}/{}] Height {}: cached", i + 1, matches.len(), height),
                "data",
            );
            let block = &cached;
            let (received, sent, details) = scan_block_balance(block, &block_id, &target);
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
                        "txid": d.txid,
                        "addresses": d.addresses,
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
                        format_sc(net)
                    ),
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
                        &format!(
                            "  Warning: no filter entry for height {}, skipping",
                            height - 1
                        ),
                        "err",
                    );
                    continue;
                }
            }
        };

        // Fetch 1 block starting after prev_block_id
        let mut blocks_with_raw = Vec::new();
        let max_retries = 3;
        for attempt in 0..=max_retries {
            match send_v2_blocks_rpc(&wt, vec![prev_block_id], 1, true).await {
                Ok((blocks, _remaining)) => {
                    blocks_with_raw = blocks;
                    break;
                }
                Err(e) => {
                    if attempt == max_retries {
                        log(
                            &format!(
                                "  Failed after {} retries at height {}: {:?}",
                                max_retries, height, e
                            ),
                            "err",
                        );
                        break;
                    }
                    log(
                        &format!(
                            "  Connection lost at height {} (attempt {}/{}), reconnecting...",
                            height,
                            attempt + 1,
                            max_retries
                        ),
                        "info",
                    );
                    let _ = wt.close();
                    match connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await {
                        Ok(new_conn) => {
                            wt = new_conn.wt;
                            log("  Reconnected.", "ok");
                        }
                        Err(ce) => {
                            log(&format!("  Reconnect failed: {:?}. Retrying...", ce), "err");
                        }
                    }
                }
            }
        }
        if blocks_with_raw.is_empty() {
            continue;
        }

        blocks_fetched += 1;

        if let Some((block, raw)) = blocks_with_raw.first() {
            // Cache the block
            let _ = cache_block(*height, raw).await;
            let (received, sent, details) = scan_block_balance(block, &block_id, &target);
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
                        "txid": d.txid,
                        "addresses": d.addresses,
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

    // Step 4: Tail scan — sequentially scan all blocks after the filter tip.
    // Use header IDs to find the correct block ID for the filter tip, since
    // the last filter entry may not be at the filter tip height (blocks with
    // no addresses are skipped in the filter file).
    let filter_tip = filter_file.tip_height;

    // Get cached headers to resolve the block ID at the filter tip
    let (cached_ids, header_offset) = load_headers_with_offset(&genesis_id_hex).await?;
    let tail_start_id = if let Some(ref ids) = cached_ids {
        let tip_idx = filter_tip.saturating_sub(header_offset as u64) as usize;
        if tip_idx > 0 && tip_idx <= ids.len() {
            ids[tip_idx - 1]
        } else if let Some(last) = filter_file.entries.last() {
            let mut bid = [0u8; 32];
            bid.copy_from_slice(&last.block_id);
            BlockID::from(bid)
        } else {
            genesis_id
        }
    } else if let Some(last) = filter_file.entries.last() {
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

    let mut tail_history = vec![tail_start_id];
    let mut tail_blocks_scanned: u64 = 0;
    let blocks_per_batch: u64 = 100;

    loop {
        let rpc_result =
            send_v2_blocks_rpc(&wt, tail_history.clone(), blocks_per_batch, true).await;

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
                let new_conn =
                    connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
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
            let height = block
                .v2_height
                .unwrap_or(filter_tip + 1 + tail_blocks_scanned);
            let _ = cache_block(height, raw).await;
            let block_id = block.id(); // tail blocks are v2, id() is correct
            let (received, sent, details) = scan_block_balance(block, &block_id, &target);

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
                        "txid": d.txid,
                        "addresses": d.addresses,
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
            &format!(
                "  Tail scan complete: {} blocks scanned",
                tail_blocks_scanned
            ),
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
    log(&format!("  Filter matches:   {}", matches.len()), "data");
    log(&format!("  Blocks fetched:   {blocks_fetched}"), "data");
    log(
        &format!("  Tail blocks:      {tail_blocks_scanned}"),
        "data",
    );
    log(&format!("  False positives:  {false_positives}"), "data");
    log(&format!("  Transactions:     {txns_found}"), "data");
    log(
        &format!("  Total received:   {}", format_sc(total_received)),
        "data",
    );
    log(
        &format!("  Total sent:       {}", format_sc(total_sent)),
        "data",
    );
    log(&format!("  Net balance:      {}", format_sc(net)), "ok");

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
        if i == 0 {
            break;
        }
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
    cert_hash_hex: Option<String>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };
    set_network_prefix(&genesis_id_hex);

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;

    // Parse txid
    let txid_bytes = hex_to_bytes(&txid_hex)?;
    if txid_bytes.len() != 32 {
        return Err(JsValue::from_str("txid must be 64 hex characters"));
    }
    let mut txid_prefix = [0u8; 8];
    txid_prefix.copy_from_slice(&txid_bytes[..8]);

    // Fetch txindex file
    log("Loading transaction index...", "info");
    let index_data = fetch_bytes(&txindex_url).await?;

    // Validate header
    if index_data.len() < 16 || &index_data[0..4] != b"STXI" {
        return Err(JsValue::from_str("invalid txindex file (bad magic)"));
    }
    let version = u32::from_le_bytes(index_data[4..8].try_into().unwrap());
    if version != 1 {
        return Err(JsValue::from_str(&format!(
            "unsupported txindex version: {version}"
        )));
    }
    let count = u32::from_le_bytes(index_data[8..12].try_into().unwrap());
    let tip_height = u32::from_le_bytes(index_data[12..16].try_into().unwrap());
    log(
        &format!(
            "Loaded txindex: {} transactions, tip height {}, {:.1} MB",
            count,
            tip_height,
            index_data.len() as f64 / 1024.0 / 1024.0
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
                candidates.len(),
                candidates
            ),
            "info",
        );
    }

    // Need header IDs to fetch the block — load from cache, memory, or sync on-the-fly
    // Track the height offset: full-chain headers start at height 1 (offset=0),
    // V2-only headers start at V2_REQUIRE_HEIGHT (offset=V2_REQUIRE_HEIGHT).
    let net = get_network_prefix();
    let mut header_offset: u32 = 0;
    let cached_ids = match load_header_ids().await? {
        Some(ids) => Some(ids), // full-chain: offset stays 0
        None => {
            match load_header_ids_with_key(&prefixed_key("header_ids_v2")).await? {
                Some(ids) => {
                    // V2 headers start at V2_REQUIRE_HEIGHT
                    // Detect network from genesis ID
                    header_offset = if genesis_id_hex
                        == "25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c"
                    {
                        530000 // mainnet
                    } else {
                        50 // zen
                    };
                    Some(ids)
                }
                None => CACHED_HEADER_IDS.with(|cache| {
                    cache
                        .borrow()
                        .as_ref()
                        .and_then(|(n, ids)| if *n == net { Some(ids.clone()) } else { None })
                }),
            }
        }
    };

    log("Connecting to peer...", "info");
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
    log(&format!("Connected to {}", conn.peer_info.addr), "ok");

    let header_ids = match cached_ids {
        Some(ids) => {
            log(
                &format!(
                    "Using {} cached header IDs (offset {})",
                    ids.len(),
                    header_offset
                ),
                "ok",
            );
            ids
        }
        None => {
            log("Header IDs not cached, syncing headers...", "info");
            let max_height = *candidates.iter().max().unwrap_or(&0) as u64;
            let mut current_index = ChainIndex {
                height: 0,
                id: genesis_id,
            };
            let mut synced_ids: Vec<BlockID> = Vec::new();
            let max_per_batch: u64 = 2000;
            header_offset = 0; // syncing from genesis
            loop {
                let resp = send_headers_rpc(&conn.wt, current_index, max_per_batch).await?;
                let batch_count = resp.headers.len() as u64;
                if batch_count == 0 {
                    break;
                }
                for header in &resp.headers {
                    synced_ids.push(header.id());
                }
                let total = synced_ids.len() as u64;
                log(
                    &format!("  Headers: {total} / ~{}", total + resp.remaining),
                    "data",
                );
                let last_header = resp.headers.last().unwrap();
                current_index = ChainIndex {
                    height: current_index.height + batch_count,
                    id: last_header.id(),
                };
                if current_index.height > max_height && resp.remaining == 0 {
                    break;
                }
                if resp.remaining == 0 {
                    break;
                }
            }
            // Cache for future use
            CACHED_HEADER_IDS.with(|cache| {
                *cache.borrow_mut() = Some((net.clone(), synced_ids.clone()));
            });
            log(&format!("Synced {} header IDs", synced_ids.len()), "ok");
            synced_ids
        }
    };

    // Check each candidate block for the full txid match
    // header_ids[0] corresponds to height (header_offset + 1)
    // So block at height H is at index (H - header_offset - 1)
    let mut result_json = None;
    for &block_height in &candidates {
        if block_height <= header_offset {
            log(
                &format!(
                    "Block height {} is before header offset {}, skipping",
                    block_height, header_offset
                ),
                "info",
            );
            continue;
        }
        let idx = (block_height - header_offset - 1) as usize;
        if idx >= header_ids.len() {
            log(
                &format!(
                    "Block height {} out of range (have {} headers from offset {}), skipping",
                    block_height,
                    header_ids.len(),
                    header_offset
                ),
                "info",
            );
            continue;
        }

        let prev_id = if idx == 0 {
            // First block after offset — use genesis or V2 checkpoint as parent
            if header_offset == 0 {
                genesis_id
            } else {
                // For V2 headers, the parent of the first block is the checkpoint block
                let checkpoint_hex = if genesis_id_hex
                    == "25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c"
                {
                    "0000000000000000b3b69b56214c974ce293a310d5fcfedb85f2e6b039e5bac0"
                } else {
                    "0000000863c1e1191775e601ead23feeae6f5bab166eb1da538b091c6613be72"
                };
                let bytes = hex::decode(checkpoint_hex).unwrap();
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                BlockID::new(id)
            }
        } else {
            header_ids[idx - 1]
        };
        let (blocks_with_raw, _remaining) =
            send_v2_blocks_rpc(&conn.wt, vec![prev_id], 1, true).await?;
        if blocks_with_raw.is_empty() {
            log(
                &format!("Block {} — peer returned no data, skipping", block_height),
                "info",
            );
            continue;
        }

        let (block, raw) = &blocks_with_raw[0];
        let _ = cache_block(block_height as u64, raw).await;

        // Check V1 transactions for full txid match
        let mut found = false;
        let mut matched_v1_tx_index: Option<usize> = None;
        for (i, txn) in block.v1_transactions.iter().enumerate() {
            let tid = txn.id();
            let tid_bytes_v1: &[u8] = tid.as_ref();
            if tid_bytes_v1 == &txid_bytes[..] {
                found = true;
                matched_v1_tx_index = Some(i);
                break;
            }
        }

        // Check V2 transactions for full txid match
        let mut matched_tx_index: Option<usize> = None;
        if !found {
            for (i, txn) in block.v2_transactions.iter().enumerate() {
                let tid = txn.id();
                let tid_bytes_v2: &[u8] = tid.as_ref();
                if tid_bytes_v2 == &txid_bytes[..] {
                    found = true;
                    matched_tx_index = Some(i);
                    break;
                }
            }
        }

        if found || candidates.len() == 1 {
            let block_json = block_to_json(block);
            let mut result = json!({
                "txid": txid_hex,
                "blockHeight": block_height,
                "timestamp": block.timestamp,
                "block": block_json,
            });
            if let Some(idx) = matched_v1_tx_index {
                result["v1TxIndex"] = json!(idx);
            }
            if let Some(idx) = matched_tx_index {
                result["txIndex"] = json!(idx);
            }
            result_json = Some(result);
            log(
                &format!(
                    "Transaction {} confirmed in block {} ({})",
                    &txid_hex[..16],
                    block_height,
                    chrono_timestamp(block.timestamp)
                ),
                "ok",
            );
            break;
        } else {
            log(
                &format!(
                    "Block {} — prefix collision, txid not in this block",
                    block_height
                ),
                "info",
            );
        }
    }

    let _ = conn.wt.close();

    match result_json {
        Some(r) => Ok(JsValue::from_str(&serde_json::to_string(&r).unwrap())),
        None => {
            log(
                "Transaction not found in any candidate block (possible V1 collision).",
                "err",
            );
            Ok(JsValue::from_str("not_found"))
        }
    }
}

/// Unified explorer query — accepts block height, block ID, transaction ID, or address.
/// Returns JSON with a `type` field: "block", "transaction", or "address".
#[wasm_bindgen]
pub async fn explore_query(
    url: String,
    genesis_id_hex: String,
    query: String,
    txindex_url: Option<String>,
    log_fn: js_sys::Function,
    cert_hash_hex: Option<String>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };
    set_network_prefix(&genesis_id_hex);

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;
    let query = query.trim().to_string();

    // Detect input type
    let is_numeric = query.chars().all(|c| c.is_ascii_digit()) && !query.is_empty();
    let is_hex = query.chars().all(|c| c.is_ascii_hexdigit()) && !query.is_empty();

    // Address: 76 hex chars (32-byte hash + 6-byte checksum)
    if is_hex && query.len() == 76 {
        log("Detected address input", "info");
        return Ok(JsValue::from_str(
            &serde_json::to_string(&json!({
                "type": "address",
                "address": query,
            }))
            .unwrap(),
        ));
    }

    // Block height: pure numeric
    if is_numeric {
        let height: u64 = query
            .parse()
            .map_err(|_| JsValue::from_str("invalid block height"))?;
        log(&format!("Looking up block at height {}...", height), "info");
        let result = fetch_block_by_height(
            &url,
            genesis_id,
            &genesis_id_hex,
            cert_hash.as_deref(),
            height as u32,
            &log,
        )
        .await?;
        return Ok(JsValue::from_str(&serde_json::to_string(&result).unwrap()));
    }

    // 64 hex chars: could be txid or block ID
    if is_hex && query.len() == 64 {
        // Try txindex first if available
        if let Some(ref txindex) = txindex_url {
            if !txindex.is_empty() {
                log("Searching transaction index...", "info");
                let txid_bytes = hex_to_bytes(&query)?;
                let mut txid_prefix = [0u8; 8];
                txid_prefix.copy_from_slice(&txid_bytes[..8]);

                let index_data = fetch_bytes(txindex).await?;
                if index_data.len() >= 16 && &index_data[0..4] == b"STXI" {
                    let candidates = search_txindex(&index_data, &txid_prefix);
                    if !candidates.is_empty() {
                        log(
                            &format!("Found {} candidate block(s) in txindex", candidates.len()),
                            "ok",
                        );
                        // Fetch block and match txid — reuse lookup_txid logic
                        let result = fetch_block_with_txid_match(
                            &url,
                            genesis_id,
                            &genesis_id_hex,
                            cert_hash.as_deref(),
                            &txid_bytes,
                            &query,
                            &candidates,
                            &log,
                        )
                        .await?;
                        if let Some(r) = result {
                            return Ok(JsValue::from_str(&serde_json::to_string(&r).unwrap()));
                        }
                        // Fall through to try as block ID
                        log("Not found as txid, trying as block ID...", "info");
                    } else {
                        log("Not found in txindex, trying as block ID...", "info");
                    }
                }
            }
        }

        // Try as block ID — search header IDs
        log("Searching for block ID...", "info");
        let result = fetch_block_by_id(
            &url,
            genesis_id,
            &genesis_id_hex,
            cert_hash.as_deref(),
            &query,
            &log,
        )
        .await?;
        if let Some(r) = result {
            return Ok(JsValue::from_str(&serde_json::to_string(&r).unwrap()));
        }

        return Err(JsValue::from_str("Not found as transaction ID or block ID"));
    }

    Err(JsValue::from_str(&format!(
        "Unrecognized query format (got {} chars). Expected: block height (number), block/tx ID (64 hex), or address (76 hex).",
        query.len()
    )))
}

/// Load cached header IDs and determine the offset.
/// Returns (header_ids, header_offset).
async fn load_headers_with_offset(
    genesis_id_hex: &str,
) -> Result<(Option<Vec<BlockID>>, u32), JsValue> {
    let net = get_network_prefix();
    let mut header_offset: u32 = 0;
    let cached_ids = match load_header_ids().await? {
        Some(ids) => Some(ids),
        None => match load_header_ids_with_key(&prefixed_key("header_ids_v2")).await? {
            Some(ids) => {
                header_offset = if genesis_id_hex
                    == "25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c"
                {
                    530000
                } else {
                    50
                };
                Some(ids)
            }
            None => CACHED_HEADER_IDS.with(|cache| {
                cache.borrow().as_ref().and_then(
                    |(n, ids)| {
                        if *n == net { Some(ids.clone()) } else { None }
                    },
                )
            }),
        },
    };
    Ok((cached_ids, header_offset))
}

/// Resolve the parent block ID needed to call SendV2Blocks for a given height.
fn resolve_prev_id(
    header_ids: &[BlockID],
    header_offset: u32,
    height: u32,
    genesis_id: BlockID,
    genesis_id_hex: &str,
) -> Result<BlockID, JsValue> {
    if height <= header_offset {
        return Err(JsValue::from_str(&format!(
            "Block height {} is before header offset {}",
            height, header_offset
        )));
    }
    let idx = (height - header_offset - 1) as usize;
    if idx >= header_ids.len() {
        return Err(JsValue::from_str(&format!(
            "Block height {} out of range (have {} headers from offset {})",
            height,
            header_ids.len(),
            header_offset
        )));
    }
    if idx == 0 {
        if header_offset == 0 {
            Ok(genesis_id)
        } else {
            let checkpoint_hex = if genesis_id_hex
                == "25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c"
            {
                "0000000000000000b3b69b56214c974ce293a310d5fcfedb85f2e6b039e5bac0"
            } else {
                "0000000863c1e1191775e601ead23feeae6f5bab166eb1da538b091c6613be72"
            };
            let bytes = hex::decode(checkpoint_hex).unwrap();
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            Ok(BlockID::new(id))
        }
    } else {
        Ok(header_ids[idx - 1])
    }
}

/// Fetch a block at a specific height and return it as a "block" result.
async fn fetch_block_by_height(
    url: &str,
    genesis_id: BlockID,
    genesis_id_hex: &str,
    cert_hash: Option<&[u8]>,
    height: u32,
    log: &dyn Fn(&str, &str),
) -> Result<serde_json::Value, JsValue> {
    // Check block cache first
    if let Some(block) = load_cached_block(height as u64).await? {
        log(&format!("Block {} loaded from cache", height), "ok");
        let block_json = block_to_json(&block);
        return Ok(json!({
            "type": "block",
            "blockHeight": height,
            "timestamp": block.timestamp,
            "block": block_json,
        }));
    }

    let (cached_ids, header_offset) = load_headers_with_offset(genesis_id_hex).await?;
    let mut header_ids = match cached_ids {
        Some(ids) => {
            log(&format!("Using {} cached header IDs", ids.len()), "ok");
            ids
        }
        None => {
            // Sync headers up to the requested height
            log("Header IDs not cached, syncing headers...", "info");
            let conn = connect_and_handshake(url, genesis_id, cert_hash).await?;
            let mut current_index = ChainIndex {
                height: 0,
                id: genesis_id,
            };
            let mut synced_ids: Vec<BlockID> = Vec::new();
            loop {
                let resp = send_headers_rpc(&conn.wt, current_index, 2000).await?;
                if resp.headers.is_empty() {
                    break;
                }
                let batch_count = resp.headers.len() as u64;
                for header in &resp.headers {
                    synced_ids.push(header.id());
                }
                let total = synced_ids.len() as u64;
                log(
                    &format!("  Headers: {total} / ~{}", total + resp.remaining),
                    "data",
                );
                let last_header = resp.headers.last().unwrap();
                current_index = ChainIndex {
                    height: current_index.height + batch_count,
                    id: last_header.id(),
                };
                if current_index.height > height as u64 && resp.remaining == 0 {
                    break;
                }
                if resp.remaining == 0 {
                    break;
                }
            }
            let net = get_network_prefix();
            CACHED_HEADER_IDS.with(|cache| {
                *cache.borrow_mut() = Some((net, synced_ids.clone()));
            });
            log(&format!("Synced {} header IDs", synced_ids.len()), "ok");
            let _ = conn.wt.close();
            synced_ids
        }
    };

    // If the requested height is beyond cached headers, fetch the missing ones
    let total_height = header_offset as u64 + header_ids.len() as u64;
    if height as u64 >= total_height {
        log(
            &format!(
                "Fetching headers beyond cache ({} -> {})...",
                total_height,
                height + 1
            ),
            "info",
        );
        let last_id = if header_ids.is_empty() {
            genesis_id
        } else {
            *header_ids.last().unwrap()
        };
        let conn = connect_and_handshake(url, genesis_id, cert_hash).await?;
        let mut current_index = ChainIndex {
            height: total_height,
            id: last_id,
        };
        loop {
            let resp = send_headers_rpc(&conn.wt, current_index, 2000).await?;
            if resp.headers.is_empty() {
                break;
            }
            let batch_count = resp.headers.len() as u64;
            for header in &resp.headers {
                header_ids.push(header.id());
            }
            let last_header = resp.headers.last().unwrap();
            current_index = ChainIndex {
                height: current_index.height + batch_count,
                id: last_header.id(),
            };
            if current_index.height > height as u64 {
                break;
            }
            if resp.remaining == 0 {
                break;
            }
        }
        let net = get_network_prefix();
        CACHED_HEADER_IDS.with(|cache| {
            *cache.borrow_mut() = Some((net, header_ids.clone()));
        });
        log(
            &format!("Extended to {} header IDs", header_ids.len()),
            "ok",
        );
        let _ = conn.wt.close();
    }

    let prev_id = resolve_prev_id(
        &header_ids,
        header_offset,
        height,
        genesis_id,
        genesis_id_hex,
    )?;

    log("Connecting to peer...", "info");
    let conn = connect_and_handshake(url, genesis_id, cert_hash).await?;
    log(&format!("Connected to {}", conn.peer_info.addr), "ok");

    let (blocks_with_raw, _) = send_v2_blocks_rpc(&conn.wt, vec![prev_id], 1, true).await?;
    let _ = conn.wt.close();

    if blocks_with_raw.is_empty() {
        return Err(JsValue::from_str(&format!(
            "Peer returned no data for block {}",
            height
        )));
    }

    let (block, raw) = &blocks_with_raw[0];
    let _ = cache_block(height as u64, raw).await;
    let block_json = block_to_json(block);

    log(
        &format!(
            "Block {} loaded ({} v1 + {} v2 transactions, {})",
            height,
            block.v1_transactions.len(),
            block.v2_transactions.len(),
            chrono_timestamp(block.timestamp)
        ),
        "ok",
    );

    Ok(json!({
        "type": "block",
        "blockHeight": height,
        "timestamp": block.timestamp,
        "block": block_json,
    }))
}

/// Fetch a block by its ID (search cached header IDs for height).
async fn fetch_block_by_id(
    url: &str,
    genesis_id: BlockID,
    genesis_id_hex: &str,
    cert_hash: Option<&[u8]>,
    block_id_hex: &str,
    log: &dyn Fn(&str, &str),
) -> Result<Option<serde_json::Value>, JsValue> {
    let target_bytes = hex_to_bytes(block_id_hex)?;
    let mut target_id = [0u8; 32];
    target_id.copy_from_slice(&target_bytes);

    let (cached_ids, header_offset) = load_headers_with_offset(genesis_id_hex).await?;
    let header_ids = match cached_ids {
        Some(ids) => ids,
        None => {
            log(
                "No cached header IDs — cannot search by block ID without syncing first",
                "err",
            );
            return Ok(None);
        }
    };

    // Linear search for the block ID
    let mut found_height: Option<u32> = None;
    for (i, id) in header_ids.iter().enumerate() {
        let id_bytes: &[u8] = id.as_ref();
        if id_bytes == &target_id[..] {
            found_height = Some(header_offset + 1 + i as u32);
            break;
        }
    }

    match found_height {
        Some(height) => {
            log(&format!("Block ID found at height {}", height), "ok");
            let result =
                fetch_block_by_height(url, genesis_id, genesis_id_hex, cert_hash, height, log)
                    .await?;
            Ok(Some(result))
        }
        None => {
            log("Block ID not found in cached headers", "info");
            Ok(None)
        }
    }
}

/// Fetch block at candidate heights and match a full txid. Returns a "transaction" result.
async fn fetch_block_with_txid_match(
    url: &str,
    genesis_id: BlockID,
    genesis_id_hex: &str,
    cert_hash: Option<&[u8]>,
    txid_bytes: &[u8],
    txid_hex: &str,
    candidates: &[u32],
    log: &dyn Fn(&str, &str),
) -> Result<Option<serde_json::Value>, JsValue> {
    let (cached_ids, header_offset) = load_headers_with_offset(genesis_id_hex).await?;
    let header_ids = match cached_ids {
        Some(ids) => {
            log(&format!("Using {} cached header IDs", ids.len()), "ok");
            ids
        }
        None => {
            log("Header IDs not cached, syncing...", "info");
            let conn = connect_and_handshake(url, genesis_id, cert_hash).await?;
            let max_height = *candidates.iter().max().unwrap_or(&0) as u64;
            let mut current_index = ChainIndex {
                height: 0,
                id: genesis_id,
            };
            let mut synced_ids: Vec<BlockID> = Vec::new();
            loop {
                let resp = send_headers_rpc(&conn.wt, current_index, 2000).await?;
                if resp.headers.is_empty() {
                    break;
                }
                let batch_count = resp.headers.len() as u64;
                for header in &resp.headers {
                    synced_ids.push(header.id());
                }
                let total = synced_ids.len() as u64;
                log(
                    &format!("  Headers: {total} / ~{}", total + resp.remaining),
                    "data",
                );
                let last_header = resp.headers.last().unwrap();
                current_index = ChainIndex {
                    height: current_index.height + batch_count,
                    id: last_header.id(),
                };
                if current_index.height > max_height && resp.remaining == 0 {
                    break;
                }
                if resp.remaining == 0 {
                    break;
                }
            }
            let net = get_network_prefix();
            CACHED_HEADER_IDS.with(|cache| {
                *cache.borrow_mut() = Some((net, synced_ids.clone()));
            });
            let _ = conn.wt.close();
            synced_ids
        }
    };

    log("Connecting to peer...", "info");
    let conn = connect_and_handshake(url, genesis_id, cert_hash).await?;
    log(&format!("Connected to {}", conn.peer_info.addr), "ok");

    for &block_height in candidates {
        let prev_id = match resolve_prev_id(
            &header_ids,
            header_offset,
            block_height,
            genesis_id,
            genesis_id_hex,
        ) {
            Ok(id) => id,
            Err(_) => continue,
        };
        let (blocks_with_raw, _) = send_v2_blocks_rpc(&conn.wt, vec![prev_id], 1, true).await?;
        if blocks_with_raw.is_empty() {
            continue;
        }

        let (block, raw) = &blocks_with_raw[0];
        let _ = cache_block(block_height as u64, raw).await;

        let mut matched_tx_index: Option<usize> = None;
        let mut matched_v1_tx_index: Option<usize> = None;
        for (i, txn) in block.v2_transactions.iter().enumerate() {
            let tid = txn.id();
            let tid_bytes: &[u8] = tid.as_ref();
            if tid_bytes == txid_bytes {
                matched_tx_index = Some(i);
                break;
            }
        }
        if matched_tx_index.is_none() {
            for (i, txn) in block.v1_transactions.iter().enumerate() {
                let tid = txn.id();
                let tid_bytes_v1: &[u8] = tid.as_ref();
                if tid_bytes_v1 == txid_bytes {
                    matched_v1_tx_index = Some(i);
                    break;
                }
            }
        }

        if matched_tx_index.is_some() || matched_v1_tx_index.is_some() || candidates.len() == 1 {
            let block_json = block_to_json(block);
            let mut result = json!({
                "type": "transaction",
                "txid": txid_hex,
                "blockHeight": block_height,
                "timestamp": block.timestamp,
                "block": block_json,
            });
            if let Some(idx) = matched_tx_index {
                result["txIndex"] = json!(idx);
            }
            if let Some(idx) = matched_v1_tx_index {
                result["v1TxIndex"] = json!(idx);
            }
            log(
                &format!(
                    "Transaction found in block {} ({})",
                    block_height,
                    chrono_timestamp(block.timestamp)
                ),
                "ok",
            );
            let _ = conn.wt.close();
            return Ok(Some(result));
        }
    }

    let _ = conn.wt.close();
    Ok(None)
}

/// Look up unspent outputs for an address using the SUXI index.
/// Binary-searches the index for the address prefix, then fetches blocks
/// at matched heights to extract full UTXO details.
#[wasm_bindgen]
pub async fn lookup_utxos(
    url: String,
    genesis_id_hex: String,
    address_hex: String,
    utxoindex_url: String,
    log_fn: js_sys::Function,
    cert_hash_hex: Option<String>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };
    set_network_prefix(&genesis_id_hex);

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;
    let target = parse_address(&address_hex)?;
    let target_bytes: [u8; 32] = {
        let slice: &[u8] = target.as_ref();
        slice
            .try_into()
            .map_err(|_| JsValue::from_str("address must be 32 bytes"))?
    };
    let mut addr_prefix = [0u8; 8];
    addr_prefix.copy_from_slice(&target_bytes[..8]);

    // Fetch SUXI index
    log("Loading UTXO index...", "info");
    let index_data = fetch_bytes(&utxoindex_url).await?;
    if index_data.len() < 16 || &index_data[0..4] != b"SUXI" {
        return Err(JsValue::from_str("invalid UTXO index (bad magic)"));
    }
    let version = u32::from_le_bytes(index_data[4..8].try_into().unwrap());
    if version != 1 {
        return Err(JsValue::from_str(&format!(
            "unsupported UTXO index version: {version}"
        )));
    }
    let count = u32::from_le_bytes(index_data[8..12].try_into().unwrap()) as usize;
    let tip_height = u32::from_le_bytes(index_data[12..16].try_into().unwrap());
    log(
        &format!(
            "Loaded UTXO index: {} entries, tip height {}",
            count, tip_height
        ),
        "ok",
    );

    // Binary search for first entry matching address prefix
    const HEADER_SIZE: usize = 16;
    const ENTRY_SIZE: usize = 20;
    let mut lo: usize = 0;
    let mut hi: usize = count;
    while lo < hi {
        let mid = (lo + hi) / 2;
        let off = HEADER_SIZE + mid * ENTRY_SIZE;
        let entry_prefix = &index_data[off..off + 8];
        if entry_prefix < &addr_prefix[..] {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    // Collect all matching entries
    let mut matches: Vec<(u32, [u8; 8])> = Vec::new(); // (height, oid_prefix)
    while lo < count {
        let off = HEADER_SIZE + lo * ENTRY_SIZE;
        if &index_data[off..off + 8] != &addr_prefix[..] {
            break;
        }
        let mut oid_prefix = [0u8; 8];
        oid_prefix.copy_from_slice(&index_data[off + 8..off + 16]);
        let height = u32::from_le_bytes(index_data[off + 16..off + 20].try_into().unwrap());
        matches.push((height, oid_prefix));
        lo += 1;
    }

    if matches.is_empty() {
        log("No unspent outputs found for this address.", "info");
        return Ok(JsValue::from_str("[]"));
    }
    log(
        &format!(
            "Found {} UTXO index entries, fetching block details...",
            matches.len()
        ),
        "ok",
    );

    // Get unique heights
    let mut unique_heights: Vec<u32> = matches.iter().map(|(h, _)| *h).collect();
    unique_heights.sort();
    unique_heights.dedup();

    // Load header IDs
    let net = get_network_prefix();
    let mut header_offset: u32 = 0;
    let cached_ids = match load_header_ids().await? {
        Some(ids) => Some(ids),
        None => match load_header_ids_with_key(&prefixed_key("header_ids_v2")).await? {
            Some(ids) => {
                header_offset = if genesis_id_hex
                    == "25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c"
                {
                    530000
                } else {
                    50
                };
                Some(ids)
            }
            None => CACHED_HEADER_IDS.with(|cache| {
                cache.borrow().as_ref().and_then(
                    |(n, ids)| {
                        if *n == net { Some(ids.clone()) } else { None }
                    },
                )
            }),
        },
    };

    let header_ids = match cached_ids {
        Some(ids) => {
            log(
                &format!(
                    "Using {} cached header IDs (offset {})",
                    ids.len(),
                    header_offset
                ),
                "ok",
            );
            ids
        }
        None => {
            // Need to sync headers up to max height
            log("Header IDs not cached, syncing headers...", "info");
            let max_height = *unique_heights.iter().max().unwrap_or(&0) as u64;
            let conn_tmp = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
            let mut current_index = ChainIndex {
                height: 0,
                id: genesis_id,
            };
            let mut synced_ids: Vec<BlockID> = Vec::new();
            let max_per_batch: u64 = 2000;
            loop {
                let resp = send_headers_rpc(&conn_tmp.wt, current_index, max_per_batch).await?;
                let batch_count = resp.headers.len() as u64;
                if batch_count == 0 {
                    break;
                }
                for header in &resp.headers {
                    synced_ids.push(header.id());
                }
                let total = synced_ids.len() as u64;
                log(&format!("  Headers: {total}"), "data");
                let last_header = resp.headers.last().unwrap();
                current_index = ChainIndex {
                    height: current_index.height + batch_count,
                    id: last_header.id(),
                };
                if current_index.height > max_height && resp.remaining == 0 {
                    break;
                }
                if resp.remaining == 0 {
                    break;
                }
            }
            CACHED_HEADER_IDS.with(|cache| {
                *cache.borrow_mut() = Some((net.clone(), synced_ids.clone()));
            });
            let _ = conn_tmp.wt.close();
            log(&format!("Synced {} header IDs", synced_ids.len()), "ok");
            synced_ids
        }
    };

    // Connect to peer
    log("Connecting to peer...", "info");
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
    log(&format!("Connected to {}", conn.peer_info.addr), "ok");
    let mut wt = conn.wt;

    // Fetch blocks and scan for UTXOs
    let mut results: Vec<serde_json::Value> = Vec::new();
    for (i, &block_height) in unique_heights.iter().enumerate() {
        // Try cache first
        let block = if let Ok(Some(cached)) = load_cached_block(block_height as u64).await {
            log(
                &format!(
                    "  [{}/{}] Height {}: cached",
                    i + 1,
                    unique_heights.len(),
                    block_height
                ),
                "data",
            );
            cached
        } else {
            if block_height <= header_offset {
                log(
                    &format!(
                        "  Height {} before header offset {}, skipping",
                        block_height, header_offset
                    ),
                    "info",
                );
                continue;
            }
            let idx = (block_height - header_offset - 1) as usize;
            if idx >= header_ids.len() {
                log(
                    &format!("  Height {} out of range, skipping", block_height),
                    "info",
                );
                continue;
            }
            let prev_id = if idx == 0 {
                if header_offset == 0 {
                    genesis_id
                } else {
                    let checkpoint_hex = if genesis_id_hex
                        == "25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c"
                    {
                        "0000000000000000b3b69b56214c974ce293a310d5fcfedb85f2e6b039e5bac0"
                    } else {
                        "0000000863c1e1191775e601ead23feeae6f5bab166eb1da538b091c6613be72"
                    };
                    let bytes = hex::decode(checkpoint_hex).unwrap();
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&bytes);
                    BlockID::new(id)
                }
            } else {
                header_ids[idx - 1]
            };

            let rpc_result = send_v2_blocks_rpc(&wt, vec![prev_id], 1, true).await;
            let blocks_with_raw = match rpc_result {
                Ok((blocks, _)) => blocks,
                Err(_) => {
                    log(
                        &format!(
                            "  Connection lost at height {}, reconnecting...",
                            block_height
                        ),
                        "info",
                    );
                    let _ = wt.close();
                    let new_conn =
                        connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
                    wt = new_conn.wt;
                    match send_v2_blocks_rpc(&wt, vec![prev_id], 1, true).await {
                        Ok((blocks, _)) => blocks,
                        Err(e) => {
                            log(&format!("  Failed after reconnect: {:?}", e), "err");
                            continue;
                        }
                    }
                }
            };

            match blocks_with_raw.into_iter().next() {
                Some((block, raw)) => {
                    let _ = cache_block(block_height as u64, &raw).await;
                    log(
                        &format!(
                            "  [{}/{}] Height {}: fetched",
                            i + 1,
                            unique_heights.len(),
                            block_height
                        ),
                        "data",
                    );
                    block
                }
                None => {
                    log(&format!("  Height {}: no block data", block_height), "info");
                    continue;
                }
            }
        };

        // Scan block for outputs matching the full target address
        // Use header_ids for correct block ID (handles both v1 and v2 blocks)
        let block_id = {
            let bh = block_height as u32;
            if bh > header_offset {
                let idx = (bh - header_offset - 1) as usize;
                if idx < header_ids.len() {
                    header_ids[idx]
                } else {
                    block.id()
                }
            } else {
                block.id()
            }
        };
        let (received, _sent, details) = scan_block_balance(&block, &block_id, &target);
        for d in &details {
            if d.direction == "received" {
                results.push(json!({
                    "outputId": d.output_id,
                    "height": block_height,
                    "amount": format_sc(d.amount),
                    "amountHastings": d.amount.to_string(),
                    "source": d.source,
                    "txid": d.txid,
                }));
            }
        }
    }

    let _ = wt.close();

    log(
        &format!(
            "UTXO lookup complete: {} unspent outputs found",
            results.len()
        ),
        if results.is_empty() { "info" } else { "ok" },
    );

    let json_str = serde_json::to_string(&results).unwrap();
    Ok(JsValue::from_str(&json_str))
}

fn chrono_timestamp(unix: u64) -> String {
    let secs = unix;
    let days = secs / 86400;
    let year_approx = 1970 + days / 365;
    let month_approx = (days % 365) / 30 + 1;
    let day_approx = (days % 365) % 30 + 1;
    format!("{}-{:02}-{:02}", year_approx, month_approx, day_approx)
}

// --- Wallet functions ---

#[wasm_bindgen]
pub fn generate_mnemonic(word_count: u32) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    let m = sia::hd::HdMnemonic::generate(word_count as usize)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(m.phrase())
}

#[wasm_bindgen]
pub fn mnemonic_to_entropy(phrase: &str) -> Result<String, JsValue> {
    let m =
        sia::hd::HdMnemonic::from_phrase(phrase).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(hex::encode(m.entropy()))
}

#[wasm_bindgen]
pub fn entropy_to_mnemonic(entropy_hex: &str) -> Result<String, JsValue> {
    let entropy = hex::decode(entropy_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let m = sia::hd::HdMnemonic::from_entropy(&entropy)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(m.phrase())
}

#[wasm_bindgen]
pub fn encrypt_entropy(entropy_hex: &str, password: &str) -> Result<String, JsValue> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512;

    let entropy = hex::decode(entropy_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Generate random salt and nonce
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|e| JsValue::from_str(&e.to_string()))?;
    getrandom::fill(&mut nonce_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Derive key via PBKDF2
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(password.as_bytes(), &salt, 600_000, &mut key);

    // Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, entropy.as_ref())
        .map_err(|e| JsValue::from_str(&format!("encryption error: {e}")))?;

    // Output: salt(16) || nonce(12) || ciphertext
    let mut output = Vec::with_capacity(16 + 12 + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(hex::encode(output))
}

#[wasm_bindgen]
pub fn decrypt_entropy(encrypted_hex: &str, password: &str) -> Result<String, JsValue> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512;

    let data = hex::decode(encrypted_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if data.len() < 16 + 12 + 16 {
        // salt + nonce + minimum tag
        return Err(JsValue::from_str("encrypted data too short"));
    }

    let salt = &data[..16];
    let nonce_bytes = &data[16..28];
    let ciphertext = &data[28..];

    // Derive key via PBKDF2
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(password.as_bytes(), salt, 600_000, &mut key);

    // Decrypt
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| JsValue::from_str("decryption failed: wrong password or corrupted data"))?;

    Ok(hex::encode(plaintext))
}

/// Compute the SiacoinOutputID for the i-th output of a V2 transaction.
#[wasm_bindgen]
pub fn v2_output_id(txid_hex: &str, index: u32) -> Result<String, JsValue> {
    use sia::types::TransactionID;
    let txid_bytes = hex::decode(txid_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if txid_bytes.len() != 32 {
        return Err(JsValue::from_str("txid must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&txid_bytes);
    let txid = TransactionID::new(arr);
    Ok(txid.v2_siacoin_output_id(index as usize).to_string())
}

/// Compute the SAPI key hash (first 8 bytes of Blake2b-256) for an attestation key string.
/// Returns a 16-character hex string.
#[wasm_bindgen]
pub fn attestation_key_hash(key: &str) -> String {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(key.as_bytes());
    hex::encode(&hash.as_bytes()[..8])
}

#[wasm_bindgen]
pub fn derive_addresses(entropy_hex: &str, start: u32, count: u32) -> Result<String, JsValue> {
    use sia::hd::{ExtendedPrivateKey, HdMnemonic};
    use sia::types::v2::SpendPolicy;

    let entropy = hex::decode(entropy_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mnemonic =
        HdMnemonic::from_entropy(&entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::from_bip39_seed(&seed);

    // Derive m/44'/1991'/0'/0' (1991 = SC coin type)
    let account = master
        .derive_path("m/44'/1991'/0'/0'")
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut results = Vec::with_capacity(count as usize);
    for i in start..start + count {
        let child = account
            .derive_child(i)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let pk = child.public_key();
        let address = SpendPolicy::PublicKey(pk).address();
        results.push(serde_json::json!({
            "index": i,
            "address": address.to_string(),
            "public_key": format!("ed25519:{}", hex::encode(pk.as_ref())),
        }));
    }

    serde_json::to_string(&results).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Helper to build a minimal ChainState at a post-v2 height for the given network.
/// This is sufficient for computing attestation sig hashes (only the replay prefix matters).
fn manifest_chain_state(network: &str) -> Result<sia::consensus::ChainState, JsValue> {
    use sia::consensus::{ChainState, ElementAccumulator, Network, State};
    use sia::types::Work;

    let net = match network {
        "mainnet" => Network::mainnet(),
        "zen" => Network::zen(),
        _ => return Err(JsValue::from_str(&format!("unknown network: {}", network))),
    };
    let height = net.hardfork_v2.require_height + 1;
    let addr = net.hardfork_foundation.primary_address.clone();
    let epoch = ::chrono::DateTime::<::chrono::Utc>::UNIX_EPOCH;
    Ok(ChainState {
        state: State {
            index: ChainIndex {
                height,
                id: BlockID::default(),
            },
            prev_timestamps: [epoch; 11],
            depth: BlockID::default(),
            child_target: BlockID::default(),
            siafund_pool: Currency::zero(),
            oak_time: ::chrono::TimeDelta::zero(),
            oak_target: BlockID::default(),
            foundation_primary_address: addr.clone(),
            foundation_failsafe_address: addr,
            total_work: Work::zero(),
            difficulty: Work::zero(),
            oak_work: Work::zero(),
            elements: ElementAccumulator::default(),
            attestations: 0,
        },
        network: net,
    })
}

/// Derive the manifest public key and HD path info for a private manifest.
///
/// Returns JSON: `{ publicKey, account, path }`
#[wasm_bindgen]
pub fn derive_manifest_info(
    entropy_hex: &str,
    account: u32,
    index: u32,
) -> Result<String, JsValue> {
    use sia::hd::HdMnemonic;
    use sia::manifest::derive_manifest;

    let entropy = hex::decode(entropy_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mnemonic =
        HdMnemonic::from_entropy(&entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let master = mnemonic.to_extended_key("");

    let (_enc_key, signing_key) =
        derive_manifest(&master, account, index).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let pk = signing_key.public_key();
    let result = serde_json::json!({
        "publicKey": format!("ed25519:{}", hex::encode(pk.as_ref())),
        "account": account,
        "index": index,
        "path": format!("m/44'/19911'/{}'/0'/{}'", account, index),
    });

    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build a private manifest attestation transaction.
///
/// Returns the unsigned transaction as pretty-printed JSON.
/// The caller must add siacoin inputs to cover the miner fee and sign them.
#[wasm_bindgen]
pub fn build_private_manifest_transaction(
    entropy_hex: &str,
    account: u32,
    index: u32,
    url: &str,
    miner_fee_hastings: &str,
    network: &str,
) -> Result<String, JsValue> {
    use sia::hd::HdMnemonic;
    use sia::manifest;
    use std::str::FromStr;

    let entropy = hex::decode(entropy_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mnemonic =
        HdMnemonic::from_entropy(&entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let master = mnemonic.to_extended_key("");

    let (enc_key, signing_key) = manifest::derive_manifest(&master, account, index)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let miner_fee = Currency::from_str(miner_fee_hastings)
        .map_err(|_| JsValue::from_str("invalid miner fee"))?;
    let cs = manifest_chain_state(network)?;

    let txn = manifest::private_manifest_transaction(&signing_key, &enc_key, url, miner_fee, &cs);

    serde_json::to_string_pretty(&txn).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build a public manifest attestation transaction.
///
/// Uses the wallet key at the given address index as the publisher identity.
#[wasm_bindgen]
pub fn build_public_manifest_transaction(
    entropy_hex: &str,
    account: u32,
    address_index: u32,
    url: &str,
    miner_fee_hastings: &str,
    network: &str,
) -> Result<String, JsValue> {
    use sia::hd::{ExtendedPrivateKey, HdMnemonic};
    use sia::manifest;
    use std::str::FromStr;

    let entropy = hex::decode(entropy_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mnemonic =
        HdMnemonic::from_entropy(&entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::from_bip39_seed(&seed);
    let signing_key = master
        .derive_path(&format!("m/44'/1991'/{}'/0'/{}'", account, address_index))
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .private_key();

    let miner_fee = Currency::from_str(miner_fee_hastings)
        .map_err(|_| JsValue::from_str("invalid miner fee"))?;
    let cs = manifest_chain_state(network)?;

    let txn = manifest::public_manifest_transaction(&signing_key, url, miner_fee, &cs);

    serde_json::to_string_pretty(&txn).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build a channel manifest attestation transaction.
#[wasm_bindgen]
pub fn build_channel_manifest_transaction(
    entropy_hex: &str,
    account: u32,
    address_index: u32,
    channel_name: &str,
    channel_key_hex: &str,
    url: &str,
    miner_fee_hastings: &str,
    network: &str,
) -> Result<String, JsValue> {
    use sia::encryption::EncryptionKey;
    use sia::hd::{ExtendedPrivateKey, HdMnemonic};
    use sia::manifest;
    use std::str::FromStr;

    let entropy = hex::decode(entropy_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mnemonic =
        HdMnemonic::from_entropy(&entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::from_bip39_seed(&seed);
    let signing_key = master
        .derive_path(&format!("m/44'/1991'/{}'/0'/{}'", account, address_index))
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .private_key();

    let channel_key_bytes: [u8; 32] = hex::decode(channel_key_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .try_into()
        .map_err(|_| JsValue::from_str("channel key must be 32 bytes"))?;
    let channel_key = EncryptionKey::from(channel_key_bytes);

    let miner_fee = Currency::from_str(miner_fee_hastings)
        .map_err(|_| JsValue::from_str("invalid miner fee"))?;
    let cs = manifest_chain_state(network)?;

    let txn = manifest::channel_manifest_transaction(
        &signing_key,
        channel_name,
        &channel_key,
        url,
        miner_fee,
        &cs,
    );

    serde_json::to_string_pretty(&txn).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build a group manifest attestation transaction.
#[wasm_bindgen]
pub fn build_group_manifest_transaction(
    entropy_hex: &str,
    account: u32,
    address_index: u32,
    group_secret_hex: &str,
    url: &str,
    miner_fee_hastings: &str,
    network: &str,
) -> Result<String, JsValue> {
    use sia::encryption::EncryptionKey;
    use sia::hd::{ExtendedPrivateKey, HdMnemonic};
    use sia::manifest;
    use std::str::FromStr;

    let entropy = hex::decode(entropy_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mnemonic =
        HdMnemonic::from_entropy(&entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::from_bip39_seed(&seed);
    let signing_key = master
        .derive_path(&format!("m/44'/1991'/{}'/0'/{}'", account, address_index))
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .private_key();

    let group_bytes: [u8; 32] = hex::decode(group_secret_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .try_into()
        .map_err(|_| JsValue::from_str("group secret must be 32 bytes"))?;
    let group_secret = EncryptionKey::from(group_bytes);

    let miner_fee = Currency::from_str(miner_fee_hastings)
        .map_err(|_| JsValue::from_str("invalid miner fee"))?;
    let cs = manifest_chain_state(network)?;

    let txn =
        manifest::group_manifest_transaction(&signing_key, &group_secret, url, miner_fee, &cs);

    serde_json::to_string_pretty(&txn).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Decrypt a private manifest attestation value.
///
/// Returns the URL string, or an error if decryption fails.
#[wasm_bindgen]
pub fn open_private_manifest(
    entropy_hex: &str,
    account: u32,
    index: u32,
    value_hex: &str,
) -> Result<String, JsValue> {
    use sia::hd::HdMnemonic;
    use sia::manifest;

    let entropy = hex::decode(entropy_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mnemonic =
        HdMnemonic::from_entropy(&entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let master = mnemonic.to_extended_key("");

    let (enc_key, _) = manifest::derive_manifest(&master, account, index)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let value = hex::decode(value_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;

    manifest::open_private_url(&enc_key, &value)
        .ok_or_else(|| JsValue::from_str("decryption failed"))
}

/// Decrypt a channel manifest attestation value.
#[wasm_bindgen]
pub fn open_channel_manifest(channel_key_hex: &str, value_hex: &str) -> Result<String, JsValue> {
    use sia::encryption::EncryptionKey;
    use sia::manifest;

    let key_bytes: [u8; 32] = hex::decode(channel_key_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .try_into()
        .map_err(|_| JsValue::from_str("channel key must be 32 bytes"))?;
    let key = EncryptionKey::from(key_bytes);

    let value = hex::decode(value_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;

    manifest::open_channel_url(&key, &value).ok_or_else(|| JsValue::from_str("decryption failed"))
}

/// Decrypt a group manifest attestation value.
#[wasm_bindgen]
pub fn open_group_manifest(group_secret_hex: &str, value_hex: &str) -> Result<String, JsValue> {
    use sia::encryption::EncryptionKey;
    use sia::manifest;

    let key_bytes: [u8; 32] = hex::decode(group_secret_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .try_into()
        .map_err(|_| JsValue::from_str("group secret must be 32 bytes"))?;
    let key = EncryptionKey::from(key_bytes);

    let value = hex::decode(value_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;

    manifest::open_group_url(&key, &value).ok_or_else(|| JsValue::from_str("decryption failed"))
}

/// Build, sign, and return a V2 siacoin transaction as JSON.
///
/// # Arguments
/// - `entropy_hex`: wallet entropy (hex-encoded)
/// - `account`: HD account index
/// - `inputs_json`: JSON array of UTXOs: `[{id, value, maturityHeight, leafIndex, merkleProof, addressIndex}]`
/// - `outputs_json`: JSON array of recipients: `[{address, value}]`
/// - `miner_fee_hastings`: miner fee in hastings (decimal string)
/// - `change_address`: address for change output (76-char hex); ignored if no change
/// - `attestations_json`: optional JSON array of pre-signed attestations to include
#[wasm_bindgen]
pub fn build_v2_transaction(
    entropy_hex: &str,
    account: u32,
    inputs_json: &str,
    outputs_json: &str,
    miner_fee_hastings: &str,
    change_address: &str,
    attestations_json: Option<String>,
) -> Result<String, JsValue> {
    use sia::hd::{ExtendedPrivateKey, HdMnemonic};
    use sia::transaction_builder::V2TransactionBuilder;
    use sia::types::v2::{SiacoinElement, SpendPolicy};
    use sia::types::{Address, Currency, Hash256, SiacoinOutput, StateElement};
    use std::str::FromStr;

    let entropy = hex::decode(entropy_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mnemonic =
        HdMnemonic::from_entropy(&entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::from_bip39_seed(&seed);
    let account_key = master
        .derive_path(&format!("m/44'/1991'/{}'/0'", account))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let inputs: Vec<serde_json::Value> = serde_json::from_str(inputs_json)
        .map_err(|e| JsValue::from_str(&format!("invalid inputs JSON: {}", e)))?;
    let outputs: Vec<serde_json::Value> = serde_json::from_str(outputs_json)
        .map_err(|e| JsValue::from_str(&format!("invalid outputs JSON: {}", e)))?;
    let miner_fee = Currency::from_str(miner_fee_hastings)
        .map_err(|_| JsValue::from_str("invalid miner fee"))?;

    let mut builder = V2TransactionBuilder::new();
    builder.miner_fee(miner_fee);

    let mut total_input = Currency::zero();
    let mut signing_keys = Vec::new();

    for input in &inputs {
        let id_hex = input["id"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("input missing 'id'"))?;
        let value_str = input["value"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("input missing 'value'"))?;
        let maturity_height = input["maturityHeight"].as_u64().unwrap_or(0);
        let leaf_index = input["leafIndex"].as_u64().unwrap_or_else(|| {
            input["leafIndex"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
        });
        let address_index = input["addressIndex"]
            .as_u64()
            .ok_or_else(|| JsValue::from_str("input missing 'addressIndex'"))?
            as u32;

        let id_bytes: [u8; 32] = hex::decode(id_hex)
            .map_err(|e| JsValue::from_str(&format!("invalid input id: {}", e)))?
            .try_into()
            .map_err(|_| JsValue::from_str("input id must be 32 bytes"))?;

        let value = Currency::from_str(value_str)
            .map_err(|_| JsValue::from_str(&format!("invalid input value: {}", value_str)))?;
        total_input = total_input + value;

        // Parse optional merkle proof
        let merkle_proof: Vec<Hash256> = if let Some(proof_arr) = input["merkleProof"].as_array() {
            proof_arr
                .iter()
                .map(|v| {
                    let h = v.as_str().ok_or_else(|| {
                        JsValue::from_str("merkle proof element must be hex string")
                    })?;
                    let bytes: [u8; 32] = hex::decode(h)
                        .map_err(|e| JsValue::from_str(&format!("bad merkle proof hex: {}", e)))?
                        .try_into()
                        .map_err(|_| JsValue::from_str("merkle proof element must be 32 bytes"))?;
                    Ok(Hash256::from(bytes))
                })
                .collect::<Result<Vec<_>, JsValue>>()?
        } else {
            Vec::new()
        };

        // Derive the child key for this UTXO
        let child = account_key
            .derive_child(address_index)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let pk = child.public_key();
        let address = SpendPolicy::PublicKey(pk).address();

        let element = SiacoinElement {
            state_element: StateElement {
                leaf_index,
                merkle_proof,
            },
            id: sia::types::SiacoinOutputID::from(id_bytes),
            siacoin_output: SiacoinOutput { value, address },
            maturity_height,
        };

        builder.add_siacoin_input(element, SpendPolicy::PublicKey(pk));
        signing_keys.push(child.private_key());
    }

    // Add recipient outputs
    let mut total_output = Currency::zero();
    for output in &outputs {
        let addr_str = output["address"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("output missing 'address'"))?;
        let value_str = output["value"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("output missing 'value'"))?;

        let address = Address::from_str(addr_str)
            .map_err(|e| JsValue::from_str(&format!("invalid output address: {}", e)))?;
        let value = Currency::from_str(value_str)
            .map_err(|_| JsValue::from_str(&format!("invalid output value: {}", value_str)))?;
        total_output = total_output + value;

        builder.add_siacoin_output(SiacoinOutput { value, address });
    }

    // Change output
    let total_spend = total_output + miner_fee;
    if total_input < total_spend {
        return Err(JsValue::from_str(&format!(
            "insufficient funds: inputs={} < outputs+fee={}",
            total_input, total_spend
        )));
    }
    let change = total_input - total_spend;
    if change > Currency::zero() {
        let change_addr = Address::from_str(change_address)
            .map_err(|e| JsValue::from_str(&format!("invalid change address: {}", e)))?;
        builder.add_siacoin_output(SiacoinOutput {
            value: change,
            address: change_addr,
        });
    }

    // Add pre-signed attestations before signing inputs (input sigs cover attestations)
    if let Some(ref att_json) = attestations_json {
        let attestations: Vec<v2::Attestation> = serde_json::from_str(att_json)
            .map_err(|e| JsValue::from_str(&format!("invalid attestations JSON: {}", e)))?;
        builder.attestations(attestations);
    }

    let key_refs: Vec<&sia::signing::PrivateKey> = signing_keys.iter().collect();
    builder.sign_simple(&key_refs);

    let txn = builder.build();
    serde_json::to_string_pretty(&txn).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Broadcast a signed V2 transaction to a peer via the Syncer protocol.
///
/// Connects to the peer, discovers the chain tip via SendHeaders, then
/// relays a V2 transaction set with the current tip index.
///
/// # Arguments
/// - `url`: WebTransport peer URL
/// - `genesis_id_hex`: genesis block ID (hex)
/// - `txn_set_json`: JSON array of signed V2 transactions. The last transaction
///   is the "primary" one whose txid is returned. Earlier transactions are
///   dependencies (e.g. parent transactions whose outputs are spent by the primary).
/// - `cert_hash_hex`: optional TLS certificate hash (hex)
#[wasm_bindgen]
pub async fn broadcast_v2_transaction(
    url: String,
    genesis_id_hex: String,
    txn_set_json: String,
    cert_hash_hex: Option<String>,
) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;

    let txns: Vec<sia::types::v2::Transaction> = serde_json::from_str(&txn_set_json)
        .map_err(|e| JsValue::from_str(&format!("invalid transaction set JSON: {}", e)))?;
    if txns.is_empty() {
        return Err(JsValue::from_str("transaction set is empty"));
    }

    // The last transaction is the primary one
    let primary_txid = hex::encode(txns.last().unwrap().id().as_ref() as &[u8]);
    let primary_leaf_hash = txns.last().unwrap().merkle_leaf_hash();

    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;

    // Discover the chain tip by requesting headers in batches
    let mut tip_index = ChainIndex {
        height: 0,
        id: genesis_id,
    };
    loop {
        let resp = send_headers_rpc(&conn.wt, tip_index, 10000).await?;
        if resp.headers.is_empty() {
            break;
        }
        let last = resp.headers.last().unwrap();
        tip_index = ChainIndex {
            height: tip_index.height + resp.headers.len() as u64,
            id: last.id(),
        };
        if resp.headers.len() < 10000 {
            break;
        }
    }

    // Relay the transaction set (fire-and-forget).
    {
        let mut stream = open_stream(&conn.wt)
            .await
            .map_err(|e| JsValue::from_str(&format!("failed to open relay stream: {:?}", e)))?;

        let mut buf = Vec::new();
        RPC_RELAY_V2_TRANSACTION_SET
            .encode(&mut buf)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let req = RelayV2TransactionSetRequest {
            index: tip_index,
            transactions: txns,
        };
        req.encode(&mut buf)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        stream.write_all(&buf).await.map_err(|e| {
            JsValue::from_str(&format!(
                "failed to write relay request ({} bytes): {:?}",
                buf.len(),
                e
            ))
        })?;
        stream
            .close_writer()
            .await
            .map_err(|e| JsValue::from_str(&format!("failed to close relay writer: {:?}", e)))?;
    }

    // Verify the transaction reached the peer's mempool via SendTransactions.
    // Use a zero ChainIndex so the peer falls through to txpool lookup.
    {
        let mut stream = open_stream(&conn.wt).await.map_err(|e| {
            JsValue::from_str(&format!("failed to open verification stream: {:?}", e))
        })?;

        let mut buf = Vec::new();
        RPC_SEND_TRANSACTIONS
            .encode(&mut buf)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let req = SendTransactionsRequest {
            index: ChainIndex {
                height: 0,
                id: BlockID::default(),
            },
            hashes: vec![primary_leaf_hash],
        };
        req.encode(&mut buf)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        stream.write_all(&buf).await?;
        stream.close_writer().await?;

        let resp_data = stream
            .read_to_end()
            .await
            .map_err(|e| JsValue::from_str(&format!("verification failed: {:?}", e)))?;

        // Response: len(v1_txns) as u64 + encoded txns + len(v2_txns) as u64 + encoded txns
        if resp_data.len() >= 16 {
            let v1_count = u64::from_le_bytes(resp_data[0..8].try_into().unwrap());
            // Skip past v1 txns to read v2 count
            // For simplicity, just check if we got any data beyond the two length prefixes
            if v1_count == 0 {
                let v2_count = u64::from_le_bytes(resp_data[8..16].try_into().unwrap());
                if v2_count == 0 {
                    let _ = conn.wt.close();
                    return Err(JsValue::from_str(&format!(
                        "transaction {} was not accepted into the peer's mempool",
                        primary_txid
                    )));
                }
            }
            // v1_count > 0 or v2_count > 0 — transaction is in the mempool
        } else {
            let _ = conn.wt.close();
            return Err(JsValue::from_str(&format!(
                "peer returned empty response when verifying transaction {}",
                primary_txid
            )));
        }
    }

    let _ = conn.wt.close();
    Ok(primary_txid)
}

#[wasm_bindgen]
pub async fn scan_wallet_utxos(
    entropy_hex: String,
    account: u32,
    url: String,
    genesis_id_hex: String,
    filter_url: String,
    utxoindex_url: Option<String>,
    log_fn: js_sys::Function,
    cert_hash_hex: Option<String>,
) -> Result<JsValue, JsValue> {
    use sia::hd::{ExtendedPrivateKey, HdMnemonic};
    use sia::types::v2::SpendPolicy;
    use std::collections::BTreeMap;

    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };
    set_network_prefix(&genesis_id_hex);

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;

    // Derive account key from entropy
    let entropy = hex::decode(&entropy_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mnemonic =
        HdMnemonic::from_entropy(&entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::from_bip39_seed(&seed);
    let account_key = master
        .derive_path(&format!("m/44'/1991'/{}'/0'", account))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    const GAP_LIMIT: u32 = 20;
    let mut gap = 0u32;
    let mut index = 0u32;

    // Per-address results
    struct AddrResult {
        index: u32,
        address: Address,
        public_key: String,
        received: u128,
        sent: u128,
        utxos: Vec<serde_json::Value>,
    }

    let mut addr_results: Vec<AddrResult> = Vec::new();
    let mut block_addrs: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    let mut active_addresses: Vec<(usize, Address)> = Vec::new();

    // Track whether we used SUXI (affects Phase 2 block fetching and Phase 3 tail scan)
    let mut used_suxi = false;
    let mut data_tip_height: u64 = 0;
    // SUXI entries: (addr_idx, output_id_prefix_8bytes, height) — used to validate unspent UTXOs
    let mut suxi_entries: Vec<(usize, [u8; 8], u64)> = Vec::new();

    // Try SUXI-based scanning first (O(log N) per address, no page freeze)
    let has_suxi = utxoindex_url.as_ref().map_or(false, |u| !u.is_empty());
    // Also keep filter data around for Phase 2 block fetching (filter path only)
    let mut filter_file_opt: Option<FilterFile> = None;
    let mut height_to_idx: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();

    if has_suxi {
        let suxi_url = utxoindex_url.as_ref().unwrap();
        log("Loading UTXO index...", "info");
        let index_data = fetch_bytes(suxi_url).await?;
        if index_data.len() < 16 || &index_data[0..4] != b"SUXI" {
            return Err(JsValue::from_str("invalid UTXO index (bad magic)"));
        }
        let version = u32::from_le_bytes(index_data[4..8].try_into().unwrap());
        if version != 1 {
            return Err(JsValue::from_str(&format!(
                "unsupported UTXO index version: {version}"
            )));
        }
        let count = u32::from_le_bytes(index_data[8..12].try_into().unwrap()) as usize;
        let tip_height = u32::from_le_bytes(index_data[12..16].try_into().unwrap());
        data_tip_height = tip_height as u64;
        log(
            &format!(
                "Loaded UTXO index: {} entries, tip height {}",
                count, tip_height
            ),
            "ok",
        );

        const HEADER_SIZE: usize = 16;
        const ENTRY_SIZE: usize = 20;

        log("Scanning addresses against UTXO index...", "info");

        // Phase 1: SUXI binary search for each derived address
        loop {
            if gap >= GAP_LIMIT {
                break;
            }

            let child = account_key
                .derive_child(index)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let pk = child.public_key();
            let address = SpendPolicy::PublicKey(pk).address();
            let addr_bytes: [u8; 32] = {
                let slice: &[u8] = address.as_ref();
                slice
                    .try_into()
                    .map_err(|_| JsValue::from_str("address must be 32 bytes"))?
            };
            let mut addr_prefix = [0u8; 8];
            addr_prefix.copy_from_slice(&addr_bytes[..8]);

            let addr_idx = addr_results.len();
            addr_results.push(AddrResult {
                index,
                address: address.clone(),
                public_key: format!("ed25519:{}", hex::encode(pk.as_ref())),
                received: 0,
                sent: 0,
                utxos: Vec::new(),
            });

            // Binary search SUXI for this address prefix
            let mut lo: usize = 0;
            let mut hi: usize = count;
            while lo < hi {
                let mid = (lo + hi) / 2;
                let off = HEADER_SIZE + mid * ENTRY_SIZE;
                let entry_prefix = &index_data[off..off + 8];
                if entry_prefix < &addr_prefix[..] {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }

            // Collect all matching entries
            let mut has_matches = false;
            while lo < count {
                let off = HEADER_SIZE + lo * ENTRY_SIZE;
                if &index_data[off..off + 8] != &addr_prefix[..] {
                    break;
                }
                has_matches = true;
                let mut oid_prefix = [0u8; 8];
                oid_prefix.copy_from_slice(&index_data[off + 8..off + 16]);
                let height =
                    u32::from_le_bytes(index_data[off + 16..off + 20].try_into().unwrap()) as u64;
                suxi_entries.push((addr_idx, oid_prefix, height));
                block_addrs
                    .entry(height)
                    .and_modify(|indices| {
                        if !indices.contains(&addr_idx) {
                            indices.push(addr_idx);
                        }
                    })
                    .or_insert_with(|| vec![addr_idx]);
                lo += 1;
            }

            let addr_hex = hex::encode(addr_bytes);
            let addr_short = format!("{}...{}", &addr_hex[..8], &addr_hex[56..]);

            if has_matches {
                active_addresses.push((addr_idx, address));
                log(
                    &format!("  Address {}: {} — UTXOs found", index, addr_short),
                    "ok",
                );
                gap = 0;
            } else {
                log(
                    &format!(
                        "  Address {}: {} — no UTXOs (gap {})",
                        index,
                        addr_short,
                        gap + 1
                    ),
                    "data",
                );
                gap += 1;
            }

            index += 1;
        }

        used_suxi = true;

        // Scan filters only for SUXI-active addresses (not all derived addresses).
        // This is much faster (~2s vs 30s) while still finding spent history for
        // addresses that currently hold funds.
        if !active_addresses.is_empty() && !filter_url.is_empty() {
            log("Loading block filters for transaction history...", "info");
            let filter_data = fetch_bytes(&filter_url).await?;
            match parse_filter_file(&filter_data) {
                Ok(ff) => {
                    let p = ff.p as u8;
                    log(
                        &format!(
                            "Scanning {} active address(es) against {} filters...",
                            active_addresses.len(),
                            ff.entries.len()
                        ),
                        "ok",
                    );
                    if ff.tip_height < data_tip_height {
                        data_tip_height = ff.tip_height;
                    }
                    // Only scan addresses that had SUXI matches
                    for &(addr_idx, ref address) in &active_addresses {
                        let addr_bytes: [u8; 32] = {
                            let slice: &[u8] = address.as_ref();
                            slice.try_into().unwrap()
                        };
                        let mut match_count = 0u32;
                        for entry in &ff.entries {
                            if entry.address_count == 0 {
                                continue;
                            }
                            if gcs_match(
                                &entry.filter_data,
                                &entry.block_id,
                                &addr_bytes,
                                entry.address_count as u64,
                                p,
                            ) {
                                match_count += 1;
                                block_addrs
                                    .entry(entry.height)
                                    .and_modify(|indices| {
                                        if !indices.contains(&addr_idx) {
                                            indices.push(addr_idx);
                                        }
                                    })
                                    .or_insert_with(|| vec![addr_idx]);
                            }
                        }
                        let ar = &addr_results[addr_idx];
                        let addr_hex = hex::encode(&addr_bytes);
                        log(
                            &format!(
                                "  Address {}: {}...{} — {} filter matches",
                                ar.index,
                                &addr_hex[..8],
                                &addr_hex[56..],
                                match_count
                            ),
                            "ok",
                        );
                    }
                    height_to_idx = ff
                        .entries
                        .iter()
                        .enumerate()
                        .map(|(i, e)| (e.height, i))
                        .collect();
                    filter_file_opt = Some(ff);
                    log(
                        &format!("Filter scan: {} blocks to fetch", block_addrs.len()),
                        "ok",
                    );
                }
                Err(e) => {
                    log(&format!("Failed to parse filter file: {}", e), "err");
                }
            }
        }
    } else {
        // Fallback: filter-based scanning (original Phase 1)
        log("Loading block filters...", "info");
        let filter_data = fetch_bytes(&filter_url).await?;
        log(
            &format!(
                "Loaded {} bytes, magic: {:?}",
                filter_data.len(),
                if filter_data.len() >= 4 {
                    std::str::from_utf8(&filter_data[..4]).unwrap_or("???")
                } else {
                    "???"
                }
            ),
            "data",
        );
        let filter_file = parse_filter_file(&filter_data)
            .map_err(|e| JsValue::from_str(&format!("filter parse error: {e}")))?;
        let p = filter_file.p as u8;
        data_tip_height = filter_file.tip_height;
        log(
            &format!(
                "Loaded {} block filters ({:.1} KB)",
                filter_file.entries.len(),
                filter_data.len() as f64 / 1024.0
            ),
            "ok",
        );

        height_to_idx = filter_file
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| (e.height, i))
            .collect();

        log("Scanning addresses for filter matches...", "info");

        loop {
            if gap >= GAP_LIMIT {
                break;
            }

            let child = account_key
                .derive_child(index)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let pk = child.public_key();
            let address = SpendPolicy::PublicKey(pk).address();
            let addr_bytes: [u8; 32] = {
                let slice: &[u8] = address.as_ref();
                slice
                    .try_into()
                    .map_err(|_| JsValue::from_str("address must be 32 bytes"))?
            };

            let addr_idx = addr_results.len();
            addr_results.push(AddrResult {
                index,
                address: address.clone(),
                public_key: format!("ed25519:{}", hex::encode(pk.as_ref())),
                received: 0,
                sent: 0,
                utxos: Vec::new(),
            });

            let mut has_matches = false;
            for entry in &filter_file.entries {
                if entry.address_count == 0 {
                    continue;
                }
                if gcs_match(
                    &entry.filter_data,
                    &entry.block_id,
                    &addr_bytes,
                    entry.address_count as u64,
                    p,
                ) {
                    has_matches = true;
                    block_addrs
                        .entry(entry.height)
                        .and_modify(|indices| indices.push(addr_idx))
                        .or_insert_with(|| vec![addr_idx]);
                }
            }

            let addr_hex_fb = hex::encode(addr_bytes);
            let addr_short_fb = format!("{}...{}", &addr_hex_fb[..8], &addr_hex_fb[56..]);

            if has_matches {
                active_addresses.push((addr_idx, address));
                log(
                    &format!(
                        "  Address {}: {} — filter matches found",
                        index, addr_short_fb
                    ),
                    "ok",
                );
                gap = 0;
            } else {
                gap += 1;
            }

            index += 1;
        }

        filter_file_opt = Some(filter_file);
    }

    let total_scanned = index;
    let addresses_with_activity = active_addresses.len();
    log(
        &format!(
            "Address scan complete: {} scanned, {} with activity, stopped after {} gap",
            total_scanned, addresses_with_activity, GAP_LIMIT,
        ),
        "ok",
    );

    if block_addrs.is_empty() && active_addresses.is_empty() {
        let result = json!({
            "addresses": [],
            "totalBalance": "0",
            "totalBalanceSC": format_sc(0),
            "totalReceived": "0",
            "totalSent": "0",
            "totalReceivedSC": format_sc(0),
            "totalSentSC": format_sc(0),
            "addressesScanned": total_scanned,
            "addressesWithActivity": 0,
            "gapLimit": GAP_LIMIT,
        });
        return Ok(JsValue::from_str(&serde_json::to_string(&result).unwrap()));
    }

    // Phase 2: Load header IDs for block fetching (needed for SUXI path;
    // filter path uses height_to_idx from filter entries)
    let mut header_ids: Vec<BlockID> = Vec::new();
    let mut header_offset: u32 = 0;
    if used_suxi {
        let net = get_network_prefix();
        let cached_ids = match load_header_ids().await? {
            Some(ids) => Some(ids),
            None => match load_header_ids_with_key(&prefixed_key("header_ids_v2")).await? {
                Some(ids) => {
                    header_offset = if genesis_id_hex
                        == "25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c"
                    {
                        530000
                    } else {
                        50
                    };
                    Some(ids)
                }
                None => CACHED_HEADER_IDS.with(|cache| {
                    cache
                        .borrow()
                        .as_ref()
                        .and_then(|(n, ids)| if *n == net { Some(ids.clone()) } else { None })
                }),
            },
        };

        header_ids = match cached_ids {
            Some(ids) => {
                log(
                    &format!(
                        "Using {} cached header IDs (offset {})",
                        ids.len(),
                        header_offset
                    ),
                    "ok",
                );
                ids
            }
            None => {
                log("Header IDs not cached, syncing headers...", "info");
                let max_height = block_addrs.keys().last().copied().unwrap_or(0);
                let conn_tmp =
                    connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
                let mut current_index = ChainIndex {
                    height: 0,
                    id: genesis_id,
                };
                let mut synced_ids: Vec<BlockID> = Vec::new();
                let max_per_batch: u64 = 2000;
                loop {
                    let resp = send_headers_rpc(&conn_tmp.wt, current_index, max_per_batch).await?;
                    let batch_count = resp.headers.len() as u64;
                    if batch_count == 0 {
                        break;
                    }
                    for header in &resp.headers {
                        synced_ids.push(header.id());
                    }
                    let total = synced_ids.len() as u64;
                    log(
                        &format!("  Syncing headers: {} / ~{}", total, total + resp.remaining),
                        "progress",
                    );
                    let last_header = resp.headers.last().unwrap();
                    current_index = ChainIndex {
                        height: current_index.height + batch_count,
                        id: last_header.id(),
                    };
                    if current_index.height > max_height && resp.remaining == 0 {
                        break;
                    }
                    if resp.remaining == 0 {
                        break;
                    }
                }
                CACHED_HEADER_IDS.with(|cache| {
                    *cache.borrow_mut() = Some((net.clone(), synced_ids.clone()));
                });
                let _ = conn_tmp.wt.close();
                log(&format!("Synced {} header IDs", synced_ids.len()), "ok");
                synced_ids
            }
        };
    }

    // Connect and fetch matched blocks
    log("Connecting to peer...", "info");
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
    log(&format!("Connected! Peer: {}", conn.peer_info.addr), "ok");
    let mut wt = conn.wt;

    let total_blocks = block_addrs.len();
    let mut blocks_fetched = 0u32;
    for (i, (height, addr_indices)) in block_addrs.iter().enumerate() {
        let block = if let Ok(Some(cached)) = load_cached_block(*height).await {
            log(
                &format!("  [{}/{}] Height {}: cached", i + 1, total_blocks, height),
                "data",
            );
            cached
        } else {
            // Get previous block ID — use header IDs (SUXI) or filter entries (filter)
            let prev_block_id = if *height == 0 {
                genesis_id
            } else if used_suxi {
                let h = *height as u32;
                if h <= header_offset {
                    log(
                        &format!(
                            "  Height {} before header offset {}, skipping",
                            height, header_offset
                        ),
                        "info",
                    );
                    continue;
                }
                let idx = (h - header_offset - 1) as usize;
                if idx >= header_ids.len() {
                    log(
                        &format!("  Height {} out of range, skipping", height),
                        "info",
                    );
                    continue;
                }
                if idx == 0 && header_offset > 0 {
                    let checkpoint_hex = if genesis_id_hex
                        == "25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c"
                    {
                        "0000000000000000b3b69b56214c974ce293a310d5fcfedb85f2e6b039e5bac0"
                    } else {
                        "0000000863c1e1191775e601ead23feeae6f5bab166eb1da538b091c6613be72"
                    };
                    let bytes = hex::decode(checkpoint_hex).unwrap();
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&bytes);
                    BlockID::new(id)
                } else {
                    header_ids[idx - 1]
                }
            } else {
                match height_to_idx.get(&(height - 1)) {
                    Some(&idx) => {
                        let ff = filter_file_opt.as_ref().unwrap();
                        let mut bid = [0u8; 32];
                        bid.copy_from_slice(&ff.entries[idx].block_id);
                        BlockID::from(bid)
                    }
                    None => {
                        log(
                            &format!(
                                "  Warning: no filter entry for height {}, skipping",
                                height - 1
                            ),
                            "err",
                        );
                        continue;
                    }
                }
            };

            let rpc_result = send_v2_blocks_rpc(&wt, vec![prev_block_id], 1, true).await;
            let blocks_with_raw = match rpc_result {
                Ok((blocks, _)) => blocks,
                Err(_) => {
                    log(
                        &format!("  Connection lost at block {}, reconnecting...", height),
                        "info",
                    );
                    let _ = wt.close();
                    let new_conn =
                        connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
                    wt = new_conn.wt;
                    match send_v2_blocks_rpc(&wt, vec![prev_block_id], 1, true).await {
                        Ok((blocks, _)) => blocks,
                        Err(e) => {
                            log(&format!("  Failed after reconnect: {:?}", e), "err");
                            continue;
                        }
                    }
                }
            };

            if let Some((block, raw)) = blocks_with_raw.into_iter().next() {
                let _ = cache_block(*height, &raw).await;
                block
            } else {
                continue;
            }
        };

        blocks_fetched += 1;

        // Compute correct block ID from header IDs or filter entries
        let block_id = if used_suxi {
            let h = *height as u32;
            if h > header_offset {
                let idx = (h - header_offset - 1) as usize;
                if idx < header_ids.len() {
                    header_ids[idx]
                } else {
                    block.id()
                }
            } else {
                block.id()
            }
        } else {
            match height_to_idx.get(height) {
                Some(&idx) => {
                    let ff = filter_file_opt.as_ref().unwrap();
                    BlockID::from(ff.entries[idx].block_id)
                }
                None => block.id(),
            }
        };

        // Scan block for ALL active addresses (not just the ones that triggered
        // the fetch). A block may contain spends of addresses that didn't match
        // the filter/SUXI for this block — e.g., address #0 spent as input in a
        // block that only matched address #3 as output.
        for &(addr_idx, _) in &active_addresses {
            let (received, sent, details) =
                scan_block_balance(&block, &block_id, &addr_results[addr_idx].address);
            if received > 0 || sent > 0 {
                addr_results[addr_idx].received += received;
                addr_results[addr_idx].sent += sent;
                for d in &details {
                    addr_results[addr_idx].utxos.push(json!({
                        "height": height,
                        "direction": d.direction,
                        "amount": format_sc(d.amount),
                        "amountHastings": d.amount.to_string(),
                        "source": d.source,
                        "outputId": d.output_id,
                        "txid": d.txid,
                        "addresses": d.addresses,
                    }));
                }
            }
        }

        if (i + 1) % 10 == 0 || i + 1 == total_blocks {
            log(
                &format!("  Fetched {}/{} blocks", i + 1, total_blocks),
                "data",
            );
        }
    }

    // Phase 3: Tail scan for blocks after the index/filter tip
    // When using SUXI, scan ALL derived addresses (not just active ones)
    // since new UTXOs could appear for any address in recent blocks.
    let tail_tip = data_tip_height;
    let last_known_block_id = if used_suxi {
        // Use the header ID at the SUXI tip height as anchor for tail scan
        let tip_idx = (tail_tip as usize).saturating_sub(header_offset as usize + 1);
        if tip_idx < header_ids.len() {
            header_ids[tip_idx]
        } else if !header_ids.is_empty() {
            header_ids[header_ids.len() - 1]
        } else {
            genesis_id
        }
    } else if let Some(ref ff) = filter_file_opt {
        if let Some(last) = ff.entries.last() {
            let mut bid = [0u8; 32];
            bid.copy_from_slice(&last.block_id);
            BlockID::from(bid)
        } else {
            genesis_id
        }
    } else {
        genesis_id
    };

    // Tail-scan all derived addresses (any could have new UTXOs in recent blocks)
    let tail_addresses: Vec<(usize, Address)> = addr_results
        .iter()
        .enumerate()
        .map(|(i, ar)| (i, ar.address.clone()))
        .collect();

    log(
        &format!(
            "Scanning {} addresses in blocks after tip (height {})...",
            tail_addresses.len(),
            tail_tip
        ),
        "info",
    );
    log(
        &format!(
            "  Tail anchor: {}",
            hex::encode(last_known_block_id.as_ref() as &[u8])
        ),
        "data",
    );

    let mut tail_history = vec![last_known_block_id];
    let mut tail_blocks_scanned: u64 = 0;
    let blocks_per_batch: u64 = 100;

    loop {
        let rpc_result =
            send_v2_blocks_rpc(&wt, tail_history.clone(), blocks_per_batch, true).await;
        let (blocks_with_raw, remaining) = match rpc_result {
            Ok(result) => {
                log(
                    &format!(
                        "  Tail RPC: {} blocks, {} remaining",
                        result.0.len(),
                        result.1
                    ),
                    "data",
                );
                result
            }
            Err(e) => {
                log(&format!("  Tail RPC error: {:?}", e), "err");
                log(
                    &format!(
                        "  Connection lost after {} tail blocks, reconnecting...",
                        tail_blocks_scanned
                    ),
                    "info",
                );
                let _ = wt.close();
                let new_conn =
                    connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
                wt = new_conn.wt;
                if tail_history.is_empty() {
                    break;
                }
                continue;
            }
        };

        if blocks_with_raw.is_empty() {
            break;
        }

        let last_block_id = blocks_with_raw.last().unwrap().0.id();

        for (block, raw) in &blocks_with_raw {
            let height = block
                .v2_height
                .unwrap_or(tail_tip + 1 + tail_blocks_scanned);
            let _ = cache_block(height, raw).await;
            let block_id = block.id(); // tail blocks are v2, id() is correct

            for &(addr_idx, ref address) in &tail_addresses {
                let (received, sent, details) = scan_block_balance(block, &block_id, address);
                if received > 0 || sent > 0 {
                    addr_results[addr_idx].received += received;
                    addr_results[addr_idx].sent += sent;
                    for d in &details {
                        addr_results[addr_idx].utxos.push(json!({
                            "height": height,
                            "direction": d.direction,
                            "amount": format_sc(d.amount),
                            "amountHastings": d.amount.to_string(),
                            "source": d.source,
                            "outputId": d.output_id,
                            "txid": d.txid,
                            "addresses": d.addresses,
                        }));
                    }
                }
            }
            tail_blocks_scanned += 1;
        }
        blocks_fetched += blocks_with_raw.len() as u32;

        log(
            &format!(
                "  Tail scan: {} blocks after tip | {} remaining",
                tail_blocks_scanned, remaining
            ),
            "data",
        );

        if remaining == 0 {
            break;
        }
        tail_history = vec![last_block_id];
    }

    let _ = wt.close();

    // Cross-reference UTXOs with SUXI to determine truly unspent outputs.
    // When SUXI is used, some spend blocks may not be fetched (if the filter
    // file is missing them), leaving stale "received" UTXOs with no matching
    // "sent" entry. The SUXI tells us definitively which outputs are unspent.
    let mut unspent_output_ids: Vec<String> = Vec::new();
    let mut suxi_balance: u128 = 0;
    if used_suxi && !suxi_entries.is_empty() {
        for (addr_idx, ar) in addr_results.iter().enumerate() {
            for utxo in &ar.utxos {
                if utxo.get("direction").and_then(|v| v.as_str()) != Some("received") {
                    continue;
                }
                let oid = match utxo.get("outputId").and_then(|v| v.as_str()) {
                    Some(s) if !s.is_empty() => s,
                    _ => continue,
                };
                let height = utxo.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
                // Check if this received UTXO matches a SUXI entry
                let oid_bytes = hex::decode(oid.replace(":", "")).unwrap_or_default();
                let matches_suxi = suxi_entries.iter().any(|(si, oid_prefix, sh)| {
                    *si == addr_idx
                        && *sh == height
                        && oid_bytes.len() >= 8
                        && oid_bytes[..8] == oid_prefix[..]
                });
                if matches_suxi {
                    unspent_output_ids.push(oid.to_string());
                    if let Some(amt_str) = utxo.get("amountHastings").and_then(|v| v.as_str()) {
                        suxi_balance += amt_str.parse::<u128>().unwrap_or(0);
                    }
                }
            }
        }
    }

    // Build result
    let mut total_received: u128 = 0;
    let mut total_sent: u128 = 0;
    let mut addr_json: Vec<serde_json::Value> = Vec::new();

    for ar in &addr_results {
        if ar.received == 0 && ar.sent == 0 && ar.utxos.is_empty() {
            continue; // Only include addresses with activity
        }
        let balance = ar.received.saturating_sub(ar.sent);
        total_received += ar.received;
        total_sent += ar.sent;
        addr_json.push(json!({
            "index": ar.index,
            "address": ar.address.to_string(),
            "publicKey": ar.public_key,
            "received": ar.received.to_string(),
            "sent": ar.sent.to_string(),
            "balance": balance.to_string(),
            "receivedSC": format_sc(ar.received),
            "sentSC": format_sc(ar.sent),
            "balanceSC": format_sc(balance),
            "utxos": ar.utxos,
        }));
    }

    // When SUXI is available, use the sum of confirmed-unspent UTXOs as the
    // balance (more accurate than received-minus-sent when blocks are missing)
    let total_balance = if used_suxi && suxi_balance > 0 {
        suxi_balance
    } else {
        total_received.saturating_sub(total_sent)
    };
    log("", "info");
    log("Wallet scan complete!", "ok");
    log(
        &format!("  Addresses scanned:     {}", total_scanned),
        "data",
    );
    log(
        &format!("  Addresses with activity: {}", addresses_with_activity),
        "data",
    );
    log(
        &format!("  Blocks fetched:        {}", blocks_fetched),
        "data",
    );
    log(
        &format!("  Total balance:         {}", format_sc(total_balance)),
        "ok",
    );

    let result = json!({
        "addresses": addr_json,
        "totalReceived": total_received.to_string(),
        "totalSent": total_sent.to_string(),
        "totalBalance": total_balance.to_string(),
        "totalReceivedSC": format_sc(total_received),
        "totalSentSC": format_sc(total_sent),
        "totalBalanceSC": format_sc(total_balance),
        "addressesScanned": total_scanned,
        "addressesWithActivity": addresses_with_activity,
        "gapLimit": GAP_LIMIT,
        "unspentOutputIds": if used_suxi { Some(unspent_output_ids) } else { None },
    });
    Ok(JsValue::from_str(&serde_json::to_string(&result).unwrap()))
}

// =============================================================================
// compute_utxo_proofs — state accumulator tracking for UTXO merkle proofs
// =============================================================================

use sia::consensus::{
    ElementLeaf, attestation_element_hash, chain_index_element_hash, siacoin_element_hash,
    siafund_element_hash, v2_file_contract_element_hash,
};
use sia::types::SiacoinOutput;
use std::collections::HashMap;

/// Determine the V2 require height for a given genesis block ID.
/// We use the require height (not allow height) as the checkpoint because
/// between allow and require heights, V1 transactions can still exist.
/// We don't have V1BlockSupplement data needed to process V1 txns, but
/// the checkpoint accumulator at the require height already includes them.
fn v2_require_height(genesis_id_hex: &str) -> u64 {
    if genesis_id_hex.starts_with("25f6e3b9") {
        // mainnet
        530_000
    } else if genesis_id_hex.starts_with("172fb3d5") {
        // zen
        50
    } else {
        // anagami
        2016 + 288
    }
}

/// Determine the maturity delay for a given genesis block ID.
fn maturity_delay(_genesis_id_hex: &str) -> u64 {
    144 // same for all networks
}

/// Extract updated and added ElementLeaf arrays from a decoded V2 block,
/// replicating the exact element ordering from Go's MidState.ApplyBlock +
/// forEachAppliedElement.
///
/// The ordering is: all siacoin elements, then all siafund elements,
/// then all v2 file contract elements, then all attestation elements,
/// then the chain index element.
///
/// Within each type, elements appear in block processing order:
/// per-transaction (inputs then outputs), then miner payouts, then foundation.
fn id_to_bytes<T: AsRef<[u8; 32]>>(id: &T) -> [u8; 32] {
    *id.as_ref()
}

/// Compute the V2 file contract siafund tax.
/// Matches Go's V2FileContract.Tax(): (renter+host)/25 rounded down to
/// a multiple of 10000 (the siafund count).
fn v2_fc_tax(renter_value: Currency, host_value: Currency) -> Currency {
    let tax = (renter_value + host_value) / Currency::new(25);
    tax - (tax % Currency::new(10_000))
}

fn extract_block_elements(
    block: &DecodedBlock,
    block_height: u64,
    genesis_id_hex: &str,
    siafund_pool: &Currency,
) -> (Vec<ElementLeaf>, Vec<ElementLeaf>) {
    let mat_height = block_height + 1 + maturity_delay(genesis_id_hex);
    let block_id = block.id();

    // Go's MidState uses map-based deduplication: each element ID maps to an
    // index in the element diff slice. If the same element appears multiple
    // times (e.g. a file contract revised then resolved), only one entry
    // exists. We replicate this with per-type Vecs + HashMap<element_id_bytes, index>.

    // --- Siacoin elements (first in forEachAppliedElement) ---
    let mut siacoin_elems: Vec<ElementLeaf> = Vec::new();
    let mut sce_index: HashMap<[u8; 32], usize> = HashMap::new();
    // --- Siafund elements ---
    let mut siafund_elems: Vec<ElementLeaf> = Vec::new();
    let mut sfe_index: HashMap<[u8; 32], usize> = HashMap::new();
    // --- V2 file contract elements ---
    let mut v2fc_elems: Vec<ElementLeaf> = Vec::new();
    let mut v2fce_index: HashMap<[u8; 32], usize> = HashMap::new();
    // --- Attestation elements ---
    let mut attestation_elems: Vec<ElementLeaf> = Vec::new();

    // Helper: record or retrieve a siacoin element by ID
    let record_sce = |id_bytes: [u8; 32],
                      elems: &mut Vec<ElementLeaf>,
                      index: &mut HashMap<[u8; 32], usize>|
     -> usize {
        if let Some(&idx) = index.get(&id_bytes) {
            idx
        } else {
            let idx = elems.len();
            elems.push(ElementLeaf {
                state_element: StateElement {
                    leaf_index: UNASSIGNED_LEAF_INDEX,
                    merkle_proof: Vec::new(),
                },
                element_hash: Hash256::default(),
                spent: false,
            });
            index.insert(id_bytes, idx);
            idx
        }
    };

    // Helper: record or retrieve a v2 file contract element by ID
    let record_v2fce = |id_bytes: [u8; 32],
                        elems: &mut Vec<ElementLeaf>,
                        index: &mut HashMap<[u8; 32], usize>|
     -> usize {
        if let Some(&idx) = index.get(&id_bytes) {
            idx
        } else {
            let idx = elems.len();
            elems.push(ElementLeaf {
                state_element: StateElement {
                    leaf_index: UNASSIGNED_LEAF_INDEX,
                    merkle_proof: Vec::new(),
                },
                element_hash: Hash256::default(),
                spent: false,
            });
            index.insert(id_bytes, idx);
            idx
        }
    };

    for txn in &block.v2_transactions {
        let txid = txn.id();

        // 1. Siacoin inputs (spent, updated)
        for sci in &txn.siacoin_inputs {
            let id_bytes: [u8; 32] = id_to_bytes(&sci.parent.id);
            let idx = record_sce(id_bytes, &mut siacoin_elems, &mut sce_index);
            siacoin_elems[idx].state_element = sci.parent.state_element.clone();
            siacoin_elems[idx].element_hash = siacoin_element_hash(
                &sci.parent.id,
                &sci.parent.siacoin_output,
                sci.parent.maturity_height,
            );
            siacoin_elems[idx].spent = true;
        }

        // 2. Siacoin outputs (created, added)
        for (i, sco) in txn.siacoin_outputs.iter().enumerate() {
            let id = txid.v2_siacoin_output_id(i);
            let id_bytes: [u8; 32] = id_to_bytes(&id);
            let idx = record_sce(id_bytes, &mut siacoin_elems, &mut sce_index);
            // Created element — leaf_index stays UNASSIGNED
            siacoin_elems[idx].element_hash = siacoin_element_hash(&id, sco, 0);
        }

        // 3. Siafund inputs (spent) + claim siacoin outputs (immature, added)
        for sfi in &txn.siafund_inputs {
            // Spend siafund element
            let sf_id_bytes: [u8; 32] = id_to_bytes(&sfi.parent.id);
            if let Some(&idx) = sfe_index.get(&sf_id_bytes) {
                siafund_elems[idx].state_element = sfi.parent.state_element.clone();
                siafund_elems[idx].element_hash = siafund_element_hash(
                    &sfi.parent.id,
                    &sfi.parent.siafund_output,
                    &sfi.parent.claim_start,
                );
                siafund_elems[idx].spent = true;
            } else {
                let idx = siafund_elems.len();
                siafund_elems.push(ElementLeaf {
                    state_element: sfi.parent.state_element.clone(),
                    element_hash: siafund_element_hash(
                        &sfi.parent.id,
                        &sfi.parent.siafund_output,
                        &sfi.parent.claim_start,
                    ),
                    spent: true,
                });
                sfe_index.insert(sf_id_bytes, idx);
            }

            // Create immature claim siacoin output
            let claim_portion = siafund_pool
                .checked_sub(sfi.parent.claim_start)
                .unwrap_or(Currency::new(0))
                * Currency::new(sfi.parent.siafund_output.value as u128)
                / Currency::new(10000);
            let claim_id = sfi.parent.id.v2_claim_output_id();
            let claim_output = SiacoinOutput {
                value: claim_portion,
                address: sfi.claim_address.clone(),
            };
            let claim_id_bytes: [u8; 32] = id_to_bytes(&claim_id);
            let cidx = record_sce(claim_id_bytes, &mut siacoin_elems, &mut sce_index);
            siacoin_elems[cidx].element_hash =
                siacoin_element_hash(&claim_id, &claim_output, mat_height);
        }

        // 4. Siafund outputs (created, added)
        for (i, sfo) in txn.siafund_outputs.iter().enumerate() {
            let id = txid.v2_siafund_output_id(i);
            let id_bytes: [u8; 32] = id_to_bytes(&id);
            if sfe_index.contains_key(&id_bytes) {
                // Already exists — update
                let idx = sfe_index[&id_bytes];
                siafund_elems[idx].element_hash = siafund_element_hash(&id, sfo, siafund_pool);
            } else {
                let idx = siafund_elems.len();
                siafund_elems.push(ElementLeaf {
                    state_element: StateElement {
                        leaf_index: UNASSIGNED_LEAF_INDEX,
                        merkle_proof: Vec::new(),
                    },
                    element_hash: siafund_element_hash(&id, sfo, siafund_pool),
                    spent: false,
                });
                sfe_index.insert(id_bytes, idx);
            }
        }

        // 5. File contracts (created, added)
        for (i, fc) in txn.file_contracts.iter().enumerate() {
            let id = txid.v2_file_contract_id(i);
            let id_bytes: [u8; 32] = id_to_bytes(&id);
            let idx = record_v2fce(id_bytes, &mut v2fc_elems, &mut v2fce_index);
            v2fc_elems[idx].element_hash = v2_file_contract_element_hash(&id, fc);
        }

        // 6. File contract revisions (updated — dedup with existing entry)
        for fcr in &txn.file_contract_revisions {
            let id_bytes: [u8; 32] = id_to_bytes(&fcr.parent.id);
            let idx = record_v2fce(id_bytes, &mut v2fc_elems, &mut v2fce_index);
            // Use the revision for the hash (Go: if rev != nil { fc = *rev })
            v2fc_elems[idx].state_element = fcr.parent.state_element.clone();
            v2fc_elems[idx].element_hash =
                v2_file_contract_element_hash(&fcr.parent.id, &fcr.revision);
            // Don't mark spent — only resolution marks spent
        }

        // 7. File contract resolutions (resolved + payout outputs)
        for fcr in &txn.file_contract_resolutions {
            let fc = &fcr.parent.v2_file_contract;
            let id_bytes: [u8; 32] = id_to_bytes(&fcr.parent.id);
            let idx = record_v2fce(id_bytes, &mut v2fc_elems, &mut v2fce_index);

            // If already revised, keep the revised hash; otherwise use original
            if v2fc_elems[idx].element_hash == Hash256::default() {
                v2fc_elems[idx].element_hash = v2_file_contract_element_hash(&fcr.parent.id, fc);
            }
            v2fc_elems[idx].state_element = fcr.parent.state_element.clone();
            v2fc_elems[idx].spent = true; // resolved = spent

            // Determine renter/host outputs based on resolution type
            let (renter_output, host_output) = match &fcr.resolution {
                ContractResolution::Renewal(renewal) => {
                    // Create renewal contract (new element, different ID)
                    let renewal_id = fcr.parent.id.v2_renewal_id();
                    let rid_bytes: [u8; 32] = id_to_bytes(&renewal_id);
                    let ridx = record_v2fce(rid_bytes, &mut v2fc_elems, &mut v2fce_index);
                    v2fc_elems[ridx].element_hash =
                        v2_file_contract_element_hash(&renewal_id, &renewal.new_contract);
                    (
                        renewal.final_renter_output.clone(),
                        renewal.final_host_output.clone(),
                    )
                }
                ContractResolution::StorageProof(_) => {
                    (fc.renter_output.clone(), fc.host_output.clone())
                }
                ContractResolution::Expiration() => {
                    let host = SiacoinOutput {
                        value: fc.missed_host_value,
                        address: fc.host_output.address.clone(),
                    };
                    (fc.renter_output.clone(), host)
                }
            };

            // Create immature renter payout
            let renter_id = fcr.parent.id.v2_renter_output_id();
            let rid_bytes: [u8; 32] = id_to_bytes(&renter_id);
            let ridx = record_sce(rid_bytes, &mut siacoin_elems, &mut sce_index);
            siacoin_elems[ridx].element_hash =
                siacoin_element_hash(&renter_id, &renter_output, mat_height);

            // Create immature host payout
            let host_id = fcr.parent.id.v2_host_output_id();
            let hid_bytes: [u8; 32] = id_to_bytes(&host_id);
            let hidx = record_sce(hid_bytes, &mut siacoin_elems, &mut sce_index);
            siacoin_elems[hidx].element_hash =
                siacoin_element_hash(&host_id, &host_output, mat_height);
        }

        // 8. Attestations (created, added — always unique)
        for (i, att) in txn.attestations.iter().enumerate() {
            let id = txid.v2_attestation_id(i);
            let att_hash = attestation_element_hash(&id, att);
            attestation_elems.push(ElementLeaf {
                state_element: StateElement {
                    leaf_index: UNASSIGNED_LEAF_INDEX,
                    merkle_proof: Vec::new(),
                },
                element_hash: att_hash,
                spent: false,
            });
        }
    }

    // Miner payouts (immature siacoin elements)
    for (i, mp) in block.miner_payouts.iter().enumerate() {
        let id = block_id.miner_output_id(i);
        let output = SiacoinOutput {
            value: mp.value,
            address: mp.address.clone(),
        };
        let id_bytes: [u8; 32] = id_to_bytes(&id);
        let idx = record_sce(id_bytes, &mut siacoin_elems, &mut sce_index);
        siacoin_elems[idx].element_hash = siacoin_element_hash(&id, &output, mat_height);
    }

    // Foundation subsidy (if applicable)
    {
        let (foundation_height, primary_address, blocks_per_month) =
            if genesis_id_hex.starts_with("25f6e3b9") {
                (
                    298_000u64,
                    "053b2def3cbdd078c19d62ce2b4f0b1a3c5e0ffbeeff01280efb1f8969b2f5bb4fdc680f0807",
                    4380u64,
                )
            } else if genesis_id_hex.starts_with("172fb3d5") {
                (
                    30u64,
                    "053b2def3cbdd078c19d62ce2b4f0b1a3c5e0ffbeeff01280efb1f8969b2f5bb4fdc680f0807",
                    4380u64,
                )
            } else {
                (
                    30u64,
                    "241352c83da002e61f57e96b14f3a5f8b5de22156ce83b753ea495e64f1affebae88736b2347",
                    4380u64,
                )
            };

        let child_height = block_height + 1;
        if child_height >= foundation_height
            && (child_height - foundation_height) % blocks_per_month == 0
        {
            let subsidy_value = if child_height == foundation_height {
                Currency::siacoins(30000) * Currency::new(12)
            } else {
                Currency::siacoins(30000)
            };
            let addr: Address = primary_address.parse().unwrap_or(Address::new([0u8; 32]));
            let id = block_id.foundation_output_id();
            let output = SiacoinOutput {
                value: subsidy_value,
                address: addr,
            };
            let id_bytes: [u8; 32] = id_to_bytes(&id);
            let idx = record_sce(id_bytes, &mut siacoin_elems, &mut sce_index);
            siacoin_elems[idx].element_hash = siacoin_element_hash(&id, &output, mat_height);
        }
    }

    // Chain index element (always added, always last)
    let cie_index = ChainIndex {
        height: block_height + 1,
        id: block_id,
    };
    let cie_hash = chain_index_element_hash(&block_id, &cie_index);
    let cie_leaf = ElementLeaf {
        state_element: StateElement {
            leaf_index: UNASSIGNED_LEAF_INDEX,
            merkle_proof: Vec::new(),
        },
        element_hash: cie_hash,
        spent: false,
    };

    // Iterate in forEachAppliedElement order and split into updated vs added
    let mut updated = Vec::new();
    let mut added = Vec::new();

    let all_elems = siacoin_elems
        .into_iter()
        .chain(siafund_elems)
        .chain(v2fc_elems)
        .chain(attestation_elems)
        .chain(std::iter::once(cie_leaf));

    for leaf in all_elems {
        if leaf.state_element.leaf_index == UNASSIGNED_LEAF_INDEX {
            added.push(leaf);
        } else {
            updated.push(leaf);
        }
    }

    (updated, added)
}

/// Compute UTXO merkle proofs by tracking the state accumulator from a checkpoint.
///
/// Takes a list of UTXO output IDs from the wallet scan, connects to the peer,
/// fetches the checkpoint at the V2 allow height, then processes ALL blocks
/// forward through the accumulator to compute merkle proofs for wallet UTXOs.
#[wasm_bindgen]
pub async fn compute_utxo_proofs(
    utxos_json: String,
    url: String,
    genesis_id_hex: String,
    log_fn: js_sys::Function,
    cert_hash_hex: Option<String>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let log = |msg: &str, cls: &str| {
        let _ = log_fn.call2(
            &JsValue::NULL,
            &JsValue::from_str(msg),
            &JsValue::from_str(cls),
        );
    };
    set_network_prefix(&genesis_id_hex);

    // Parse UTXO list
    let utxos: Vec<serde_json::Value> = serde_json::from_str(&utxos_json)
        .map_err(|e| JsValue::from_str(&format!("invalid utxos JSON: {}", e)))?;

    // Build map: output_id_hex -> utxo index
    let mut utxo_ids: HashMap<String, usize> = HashMap::new();
    for (i, utxo) in utxos.iter().enumerate() {
        if let Some(id) = utxo.get("outputId").and_then(|v| v.as_str()) {
            utxo_ids.insert(id.to_string(), i);
        }
    }
    log(
        &format!("Computing proofs for {} UTXOs", utxo_ids.len()),
        "info",
    );

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;

    // Find the earliest UTXO height so we can pick a nearby checkpoint
    let min_v2_height = v2_require_height(&genesis_id_hex);
    let mut earliest_utxo_height: u64 = u64::MAX;
    for utxo in &utxos {
        if let Some(h) = utxo.get("height").and_then(|v| v.as_u64()) {
            if h < earliest_utxo_height {
                earliest_utxo_height = h;
            }
        }
    }

    // Connect to peer
    log("Connecting to peer...", "info");
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
    log(&format!("Connected to {}", conn.peer_info.addr), "ok");

    // Sync headers to get the block ID at checkpoint height
    log("Syncing headers...", "info");
    let net = get_network_prefix();

    let mut synced_ids: Vec<BlockID> = CACHED_HEADER_IDS
        .with(|cache| {
            cache.borrow().as_ref().and_then(
                |(n, ids)| {
                    if *n == net { Some(ids.clone()) } else { None }
                },
            )
        })
        .unwrap_or_default();

    if synced_ids.is_empty() {
        if let Ok(Some(ids)) = load_header_ids().await {
            synced_ids = ids;
        }
    }

    // Sync remaining headers
    let mut current_index = if synced_ids.is_empty() {
        ChainIndex {
            height: 0,
            id: genesis_id,
        }
    } else {
        ChainIndex {
            height: synced_ids.len() as u64,
            id: *synced_ids.last().unwrap(),
        }
    };

    loop {
        let resp = send_headers_rpc(&conn.wt, current_index, 2000).await?;
        if resp.headers.is_empty() {
            break;
        }
        for header in &resp.headers {
            synced_ids.push(header.id());
        }
        let count = resp.headers.len() as u64;
        current_index = ChainIndex {
            height: current_index.height + count,
            id: resp.headers.last().unwrap().id(),
        };
        log(
            &format!("  Syncing headers: {}", synced_ids.len()),
            "progress",
        );
        if resp.remaining == 0 {
            break;
        }
    }

    let tip_height = synced_ids.len() as u64;
    log(&format!("Chain tip: height {}", tip_height), "ok");

    // Cache header IDs
    CACHED_HEADER_IDS.with(|cache| {
        *cache.borrow_mut() = Some((net.clone(), synced_ids.clone()));
    });

    // Pick checkpoint as close to the earliest UTXO as possible.
    // Must be >= V2 allow height and before the earliest UTXO.
    // Use a small buffer (20 blocks) before the UTXO for safety.
    let checkpoint_height =
        if earliest_utxo_height != u64::MAX && earliest_utxo_height > min_v2_height + 20 {
            earliest_utxo_height - 20
        } else {
            min_v2_height
        };
    // Clamp to valid range
    let checkpoint_height = checkpoint_height.max(min_v2_height).min(tip_height);
    log(
        &format!(
            "Checkpoint height: {} (earliest UTXO at {})",
            checkpoint_height,
            if earliest_utxo_height == u64::MAX {
                "unknown".to_string()
            } else {
                earliest_utxo_height.to_string()
            }
        ),
        "info",
    );

    if checkpoint_height == 0 || checkpoint_height > tip_height {
        return Err(JsValue::from_str(&format!(
            "checkpoint height {} out of range (tip={})",
            checkpoint_height, tip_height
        )));
    }

    // Track wallet UTXOs: output_id_hex -> StateElement (once we find them)
    let mut tracked_utxos: HashMap<String, StateElement> = HashMap::new();

    // Try to load cached accumulator state
    let cache_key = prefixed_key("acc_cache");
    let mut acc;
    let mut siafund_pool;
    let mut start_height;
    let mut loaded_from_cache = false;

    if let Ok(result) = JsFuture::from(idb_load(&cache_key)).await {
        if !result.is_null() && !result.is_undefined() {
            let bytes = js_sys::Uint8Array::new(&result).to_vec();
            // Format: height(8) + num_leaves(8) + trees(64*32) + siafund_pool(16) = 2080 bytes
            if bytes.len() >= 2080 {
                let cached_height = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
                if cached_height >= checkpoint_height && cached_height <= tip_height {
                    let num_leaves = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
                    let mut trees = [Hash256::default(); 64];
                    for i in 0..64 {
                        let offset = 16 + i * 32;
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&bytes[offset..offset + 32]);
                        trees[i] = Hash256::from(h);
                    }
                    let pool_lo = u64::from_le_bytes(bytes[2064..2072].try_into().unwrap());
                    let pool_hi = u64::from_le_bytes(bytes[2072..2080].try_into().unwrap());

                    acc = sia::consensus::ElementAccumulator { num_leaves, trees };
                    siafund_pool = Currency::from(pool_lo as u128 | ((pool_hi as u128) << 64));
                    start_height = cached_height + 1;
                    loaded_from_cache = true;

                    let blocks_remaining = tip_height - cached_height;
                    log(
                        &format!(
                            "Loaded cached accumulator at height {} ({} blocks to process)",
                            cached_height, blocks_remaining
                        ),
                        "ok",
                    );
                } else {
                    log(
                        &format!(
                            "Cached accumulator at height {} out of range (tip={}), rebuilding",
                            cached_height, tip_height
                        ),
                        "info",
                    );
                    acc = sia::consensus::ElementAccumulator::default();
                    siafund_pool = Currency::zero();
                    start_height = checkpoint_height;
                }
            } else {
                acc = sia::consensus::ElementAccumulator::default();
                siafund_pool = Currency::zero();
                start_height = checkpoint_height;
            }
        } else {
            acc = sia::consensus::ElementAccumulator::default();
            siafund_pool = Currency::zero();
            start_height = checkpoint_height;
        }
    } else {
        acc = sia::consensus::ElementAccumulator::default();
        siafund_pool = Currency::zero();
        start_height = checkpoint_height;
    }

    // If starting from checkpoint (no cache), fetch and apply it
    if !loaded_from_cache {
        let checkpoint_id = synced_ids[(checkpoint_height - 1) as usize];
        let checkpoint_index = ChainIndex {
            height: checkpoint_height,
            id: checkpoint_id,
        };

        log(
            &format!("Fetching checkpoint at height {}...", checkpoint_height),
            "info",
        );
        let (checkpoint_block, checkpoint_state) =
            send_checkpoint_rpc(&conn.wt, checkpoint_index).await?;
        log(
            &format!(
                "Checkpoint loaded. Accumulator num_leaves: {}",
                checkpoint_state.elements.num_leaves
            ),
            "ok",
        );

        acc = checkpoint_state.elements.clone();
        siafund_pool = checkpoint_state.siafund_pool;

        // Apply the checkpoint block itself
        {
            let block_height = checkpoint_height - 1;
            let (mut updated, mut added) = extract_block_elements(
                &checkpoint_block,
                block_height,
                &genesis_id_hex,
                &siafund_pool,
            );
            acc.apply_block(&mut updated, &mut added).map_err(|e| {
                JsValue::from_str(&format!("apply_block on checkpoint block failed: {e}"))
            })?;
            for txn in &checkpoint_block.v2_transactions {
                for fc in &txn.file_contracts {
                    siafund_pool =
                        siafund_pool + v2_fc_tax(fc.renter_output.value, fc.host_output.value);
                }
                for fcr in &txn.file_contract_resolutions {
                    if let ContractResolution::Renewal(renewal) = &fcr.resolution {
                        siafund_pool = siafund_pool
                            + v2_fc_tax(
                                renewal.new_contract.renter_output.value,
                                renewal.new_contract.host_output.value,
                            );
                    }
                }
            }
        }

        start_height = checkpoint_height + 1;
    }

    // Process blocks from start_height to tip
    let total_blocks = tip_height - start_height + 1;
    log(
        &format!(
            "Processing {} blocks ({} to {})...",
            total_blocks, start_height, tip_height
        ),
        "info",
    );

    let mut blocks_processed: u64 = 0;
    let mut next_height = start_height;

    while next_height <= tip_height {
        // Build history for SendV2Blocks: use the previous block's ID
        let prev_id = if next_height == 1 {
            genesis_id
        } else {
            synced_ids[(next_height - 2) as usize]
        };

        let batch_max: u64 = 100;
        let (blocks, _remaining) =
            send_v2_blocks_rpc(&conn.wt, vec![prev_id], batch_max, false).await?;

        if blocks.is_empty() {
            break;
        }

        for (bi, (block, _raw)) in blocks.iter().enumerate() {
            // block_height here is the "base index height" (parent height),
            // so child_height = block_height + 1 = actual block height
            let block_height = next_height + bi as u64 - 1;

            // Verify block ID matches header sync
            let actual_block_height = block_height + 1;
            let block_bid = block.id();
            if actual_block_height <= tip_height {
                let expected_id = synced_ids[(actual_block_height - 1) as usize];
                if block_bid != expected_id {
                    let msg = format!(
                        "BLOCK ID MISMATCH at height {}: computed={} expected={}",
                        actual_block_height,
                        hex::encode(block_bid.as_ref() as &[u8]),
                        hex::encode(expected_id.as_ref() as &[u8]),
                    );
                    web_sys::console::log_1(&format!("[compute_utxo_proofs] {}", msg).into());
                }
            }

            // Collect output IDs for added siacoin elements in this block,
            // in the same order they appear in the added array.
            let mut added_sc_ids: Vec<String> = Vec::new();

            for txn in &block.v2_transactions {
                let txid = txn.id();
                // siacoin outputs
                for i in 0..txn.siacoin_outputs.len() {
                    let id = txid.v2_siacoin_output_id(i);
                    added_sc_ids.push(hex::encode(id.as_ref() as &[u8]));
                }
                // siafund claim outputs
                for sfi in &txn.siafund_inputs {
                    let id = sfi.parent.id.v2_claim_output_id();
                    added_sc_ids.push(hex::encode(id.as_ref() as &[u8]));
                }
                // file contract resolution renter/host outputs
                for fcr in &txn.file_contract_resolutions {
                    if let ContractResolution::Renewal(_) = &fcr.resolution {
                        // renewal contract is a v2fc, not siacoin — skip here
                    }
                    let renter_id = fcr.parent.id.v2_renter_output_id();
                    added_sc_ids.push(hex::encode(renter_id.as_ref() as &[u8]));
                    let host_id = fcr.parent.id.v2_host_output_id();
                    added_sc_ids.push(hex::encode(host_id.as_ref() as &[u8]));
                }
            }
            // miner payouts
            for i in 0..block.miner_payouts.len() {
                let id = block_bid.miner_output_id(i);
                added_sc_ids.push(hex::encode(id.as_ref() as &[u8]));
            }
            // foundation subsidy (if applicable)
            {
                let (foundation_height, blocks_per_month) =
                    if genesis_id_hex.starts_with("25f6e3b9") {
                        (298_000u64, 4380u64)
                    } else {
                        (30u64, 4380u64)
                    };
                let child_height = block_height + 1;
                if child_height >= foundation_height
                    && (child_height - foundation_height) % blocks_per_month == 0
                {
                    let id = block_bid.foundation_output_id();
                    added_sc_ids.push(hex::encode(id.as_ref() as &[u8]));
                }
            }

            // Extract and apply block elements
            let (mut updated, mut added) =
                extract_block_elements(block, block_height, &genesis_id_hex, &siafund_pool);

            let update = acc.apply_block(&mut updated, &mut added).map_err(|e| {
                JsValue::from_str(&format!("apply_block at height {block_height} failed: {e}"))
            })?;

            // After apply_block, added elements have their leaf_index and
            // merkle_proof filled in. Match siacoin elements against our UTXO IDs.
            // The added array contains elements in forEachAppliedElement order:
            // siacoin first, then siafund, then v2fc, then attestations, then chain index.
            // We need to match only the siacoin ones against added_sc_ids.
            let mut sc_idx = 0;
            for leaf in &added {
                // Check if this is a siacoin element by matching against our ID list
                if sc_idx < added_sc_ids.len() {
                    let id_hex = &added_sc_ids[sc_idx];
                    if utxo_ids.contains_key(id_hex) {
                        tracked_utxos.insert(id_hex.clone(), leaf.state_element.clone());
                    }
                    sc_idx += 1;
                }
                // Once we've exhausted siacoin IDs, remaining added elements
                // are siafund/v2fc/attestation/chain_index — skip them
            }

            // Update proofs for already-tracked UTXOs
            for (_id, se) in tracked_utxos.iter_mut() {
                if se.leaf_index != UNASSIGNED_LEAF_INDEX && se.leaf_index < update.old_num_leaves {
                    update.update_element_proof(se);
                }
            }

            // Check if any spent siacoin inputs match tracked UTXOs (remove them)
            for txn in &block.v2_transactions {
                for sci in &txn.siacoin_inputs {
                    let id_hex = hex::encode(sci.parent.id.as_ref() as &[u8]);
                    tracked_utxos.remove(&id_hex);
                }
            }

            // Update siafund pool: add tax from new file contracts and renewals
            for txn in &block.v2_transactions {
                for fc in &txn.file_contracts {
                    siafund_pool =
                        siafund_pool + v2_fc_tax(fc.renter_output.value, fc.host_output.value);
                }
                for fcr in &txn.file_contract_resolutions {
                    if let ContractResolution::Renewal(renewal) = &fcr.resolution {
                        siafund_pool = siafund_pool
                            + v2_fc_tax(
                                renewal.new_contract.renter_output.value,
                                renewal.new_contract.host_output.value,
                            );
                    }
                }
            }

            blocks_processed += 1;
        }

        next_height += blocks.len() as u64;

        if blocks_processed % 100 == 0 || next_height > tip_height {
            log(
                &format!(
                    "  Processed {}/{} blocks (tracked {} UTXOs)",
                    blocks_processed,
                    total_blocks,
                    tracked_utxos.len()
                ),
                "progress",
            );
        }
    }

    let _ = conn.wt.close();

    // Save accumulator state for next run
    {
        let mut cache_bytes = Vec::with_capacity(2080);
        cache_bytes.extend_from_slice(&tip_height.to_le_bytes()); // 8 bytes
        cache_bytes.extend_from_slice(&acc.num_leaves.to_le_bytes()); // 8 bytes
        for tree in &acc.trees {
            let h: &[u8] = tree.as_ref();
            cache_bytes.extend_from_slice(h); // 64 * 32 bytes
        }
        let pool_val: u128 = *siafund_pool;
        cache_bytes.extend_from_slice(&(pool_val as u64).to_le_bytes()); // lo 8 bytes
        cache_bytes.extend_from_slice(&((pool_val >> 64) as u64).to_le_bytes()); // hi 8 bytes
        let arr = js_sys::Uint8Array::from(&cache_bytes[..]);
        let _ = JsFuture::from(idb_save(&cache_key, arr)).await;
        log(
            &format!("Saved accumulator state at height {}", tip_height),
            "ok",
        );
    }

    log(
        &format!(
            "Done! {} UTXOs with proofs, final acc.num_leaves={}",
            tracked_utxos.len(),
            acc.num_leaves
        ),
        "ok",
    );

    // Build result — include verification data
    let mut result: Vec<serde_json::Value> = Vec::new();
    for (id_hex, se) in &tracked_utxos {
        let proof_hex: Vec<String> = se
            .merkle_proof
            .iter()
            .map(|h| hex::encode(h.as_ref() as &[u8]))
            .collect();
        result.push(json!({
            "outputId": id_hex,
            "leafIndex": se.leaf_index,
            "merkleProof": proof_hex,
        }));
    }

    Ok(JsValue::from_str(&serde_json::to_string(&result).unwrap()))
}

// =============================================================================
// listen_for_relays — persistent connection that accepts relay RPCs from peer
// =============================================================================

#[wasm_bindgen]
pub async fn listen_for_relays(
    url: String,
    genesis_id_hex: String,
    on_event: js_sys::Function,
    cert_hash_hex: Option<String>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let emit = |event_type: &str, event_json: &str| {
        let _ = on_event.call2(
            &JsValue::NULL,
            &JsValue::from_str(event_type),
            &JsValue::from_str(event_json),
        );
    };

    let genesis_id = parse_genesis_id(&genesis_id_hex)?;
    let cert_hash = parse_cert_hash(&cert_hash_hex)?;

    emit("status", "connecting");
    let conn = connect_and_handshake(&url, genesis_id, cert_hash.as_deref()).await?;
    emit(
        "status",
        &format!(
            "{{\"connected\":true,\"version\":\"{}\",\"addr\":\"{}\"}}",
            conn.peer_info.version, conn.peer_info.addr
        ),
    );

    // Get the incoming bidirectional streams reader
    let incoming = conn.wt.incoming_bidirectional_streams();
    let reader = incoming
        .get_reader()
        .dyn_into::<ReadableStreamDefaultReader>()
        .map_err(|_| JsValue::from_str("failed to get incoming streams reader"))?;

    // Keepalive: send a WebTransport datagram every 10s to prevent QUIC idle timeout.
    // Datagrams are fire-and-forget — they don't create streams, so the server's
    // RPC handler won't try to process them.
    // We use raw JS interop since web_sys doesn't expose WebTransport.datagrams yet.
    let wt_ref: JsValue = conn.wt.clone().into();
    let keepalive_closure = Closure::wrap(Box::new(move || {
        let wt = wt_ref.clone();
        wasm_bindgen_futures::spawn_local(async move {
            // wt.datagrams.writable.getWriter().write(new Uint8Array(1))
            if let Ok(datagrams) = Reflect::get(&wt, &"datagrams".into()) {
                if let Ok(writable) = Reflect::get(&datagrams, &"writable".into()) {
                    if let Ok(get_writer) = Reflect::get(&writable, &"getWriter".into()) {
                        if let Some(get_writer_fn) = get_writer.dyn_ref::<js_sys::Function>() {
                            if let Ok(writer) = get_writer_fn.call0(&writable) {
                                let data = js_sys::Uint8Array::new_with_length(1);
                                if let Ok(write_fn) = Reflect::get(&writer, &"write".into()) {
                                    if let Some(write_fn) = write_fn.dyn_ref::<js_sys::Function>() {
                                        if let Ok(promise) = write_fn.call1(&writer, &data) {
                                            let _ = JsFuture::from(js_sys::Promise::from(promise))
                                                .await;
                                        }
                                    }
                                }
                                // release lock
                                if let Ok(release_fn) = Reflect::get(&writer, &"releaseLock".into())
                                {
                                    if let Some(release_fn) =
                                        release_fn.dyn_ref::<js_sys::Function>()
                                    {
                                        let _ = release_fn.call0(&writer);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }) as Box<dyn Fn()>);
    let keepalive_id = web_sys::window()
        .unwrap()
        .set_interval_with_callback_and_timeout_and_arguments_0(
            keepalive_closure.as_ref().unchecked_ref(),
            10_000, // 10 seconds
        )
        .unwrap_or(0);
    keepalive_closure.forget(); // prevent the closure from being dropped

    // Loop accepting incoming streams from the peer
    emit(
        "debug",
        "entering relay loop, waiting for incoming streams...",
    );
    loop {
        emit("debug", "calling reader.read() for next incoming stream...");
        let read_result = JsFuture::from(reader.read()).await;
        let result = match read_result {
            Ok(r) => r,
            Err(e) => {
                let err_str = format!("{:?}", e);
                emit("status", &format!("disconnected (read error: {})", err_str));
                break;
            }
        };

        let done = Reflect::get(&result, &"done".into())
            .map(|v| v.as_bool().unwrap_or(true))
            .unwrap_or(true);
        if done {
            emit("status", "disconnected (stream done)");
            break;
        }

        emit("debug", "got incoming stream, setting up...");
        let stream_value = Reflect::get(&result, &"value".into())
            .map_err(|_| JsValue::from_str("missing stream value"))?;
        let bidi = web_sys::WebTransportBidirectionalStream::from(stream_value);
        let stream_reader = bidi
            .readable()
            .get_reader()
            .dyn_into::<ReadableStreamDefaultReader>()
            .map_err(|_| JsValue::from_str("failed to get stream reader"))?;
        let stream_writer = bidi
            .writable()
            .get_writer()
            .map_err(|_| JsValue::from_str("failed to get stream writer"))?;
        let mut stream = WtStream {
            reader: stream_reader,
            writer: stream_writer,
            read_buf: Vec::new(),
        };

        // Read 16-byte RPC ID
        let mut rpc_id = [0u8; 16];
        if stream.read_exact(&mut rpc_id).await.is_err() {
            emit("debug", "stream closed before RPC ID could be read");
            continue;
        }
        let specifier = sia::types::Specifier::new(rpc_id);
        let rpc_name = String::from_utf8_lossy(&rpc_id)
            .trim_end_matches('\0')
            .to_string();
        emit("debug", &format!("received RPC: {}", rpc_name));

        if specifier == RPC_RELAY_V2_HEADER {
            // Decode BlockHeader from stream
            let data = match stream.read_to_end().await {
                Ok(d) => d,
                Err(_) => continue,
            };
            let mut cursor = io::Cursor::new(&data);
            match RelayV2HeaderRequest::decode(&mut cursor) {
                Ok(req) => {
                    let header = req.header;
                    let bid = header.id();
                    let block_id = hex::encode(<BlockID as AsRef<[u8]>>::as_ref(&bid));
                    let parent_id =
                        hex::encode(<BlockID as AsRef<[u8]>>::as_ref(&header.parent_id));
                    emit(
                        "relay_header",
                        &format!(
                            "{{\"blockId\":\"{}\",\"parentId\":\"{}\"}}",
                            block_id, parent_id
                        ),
                    );
                }
                Err(e) => {
                    emit("error", &format!("failed to decode relay header: {}", e));
                }
            }
        } else if specifier == RPC_RELAY_V2_BLOCK_OUTLINE {
            // Block outline has complex encoding — just drain and notify
            let data = match stream.read_to_end().await {
                Ok(d) => d,
                Err(_) => continue,
            };
            emit("relay_block", &format!("{{\"size\":{}}}", data.len()));
        } else if specifier == RPC_RELAY_V2_TRANSACTION_SET {
            // Decode transaction set and emit full transaction details
            let data = match stream.read_to_end().await {
                Ok(d) => d,
                Err(_) => continue,
            };
            let mut cursor = io::Cursor::new(&data);
            match RelayV2TransactionSetRequest::decode(&mut cursor) {
                Ok(req) => {
                    let mut txns_json = Vec::new();
                    for txn in &req.transactions {
                        let txid = txn.id().to_string();
                        let mut inputs_json = Vec::new();
                        for input in &txn.siacoin_inputs {
                            inputs_json.push(format!(
                                "{{\"address\":\"{}\",\"value\":\"{}\",\"outputId\":\"{}\"}}",
                                input.parent.siacoin_output.address,
                                input.parent.siacoin_output.value,
                                input.parent.id,
                            ));
                        }
                        let mut outputs_json = Vec::new();
                        for (i, output) in txn.siacoin_outputs.iter().enumerate() {
                            outputs_json.push(format!(
                                "{{\"address\":\"{}\",\"value\":\"{}\",\"outputId\":\"{}\"}}",
                                output.address,
                                output.value,
                                txn.id().v2_siacoin_output_id(i),
                            ));
                        }
                        let miner_fee: u128 = *txn.miner_fee;
                        let attestations_str = if txn.attestations.is_empty() {
                            String::new()
                        } else {
                            let att_json = serde_json::to_string(&txn.attestations)
                                .unwrap_or_else(|_| "[]".to_string());
                            format!(",\"attestations\":{}", att_json)
                        };
                        txns_json.push(format!(
                            "{{\"id\":\"{}\",\"inputs\":[{}],\"outputs\":[{}],\"minerFee\":\"{}\"{}}}",
                            txid,
                            inputs_json.join(","),
                            outputs_json.join(","),
                            miner_fee,
                            attestations_str,
                        ));
                    }
                    emit(
                        "relay_txns",
                        &format!(
                            "{{\"count\":{},\"height\":{},\"blockId\":\"{}\",\"transactions\":[{}]}}",
                            req.transactions.len(),
                            req.index.height,
                            req.index.id,
                            txns_json.join(","),
                        ),
                    );
                }
                Err(e) => {
                    emit("error", &format!("failed to decode relay txns: {}", e));
                }
            }
        } else if specifier == RPC_SEND_HEADERS {
            // Peer is requesting headers from us — read request and respond with empty headers.
            // SendHeadersRequest = ChainIndex(u64 + BlockID[32]) + max(u64) = 48 bytes.
            // IMPORTANT: do NOT use read_to_end() here — the peer keeps the stream open
            // waiting for our response, so read_to_end() would deadlock.
            let mut req_buf = [0u8; 48];
            if stream.read_exact(&mut req_buf).await.is_err() {
                emit("debug", "SendHeaders: failed to read request");
                continue;
            }
            // Respond with 0 headers + 0 remaining
            let resp = SendHeadersResponse {
                headers: vec![],
                remaining: 0,
            };
            let mut resp_buf = Vec::new();
            if let Ok(()) = resp.encode(&mut resp_buf) {
                let _ = stream.write_all(&resp_buf).await;
            }
            emit("debug", "SendHeaders: responded with 0 headers");
        } else {
            // Unknown RPC — read and discard
            let rpc_name = String::from_utf8_lossy(&rpc_id)
                .trim_end_matches('\0')
                .to_string();
            emit("unknown_rpc", &format!("{{\"id\":\"{}\"}}", rpc_name));
            let _ = stream.read_to_end().await;
        }

        // Stream is dropped here, closing it (no response needed for relay RPCs)
    }

    // Stop keepalive timer
    let _ = web_sys::window()
        .unwrap()
        .clear_interval_with_handle(keepalive_id);

    let _ = conn.wt.close();
    Ok(JsValue::from_str("disconnected"))
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
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let addr1: [u8; 32] = [
            32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
            10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ];
        let addr2: [u8; 32] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0x00,
        ];
        let not_in_set: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
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
        data.extend_from_slice(&1u32.to_le_bytes()); // version 1
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
