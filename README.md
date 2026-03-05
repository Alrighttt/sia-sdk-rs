# Sia SDK RS

A Rust SDK for interacting with the Sia decentralized storage network. Supports both native (QUIC) and browser (WebTransport/WASM) environments.

## Workspace Crates

| Crate | Description |
|-------|-------------|
| `sia_sdk` | Core Sia types, encoding, signing, and cryptography |
| `sia_derive` | Procedural macros for Sia binary encoding |
| `indexd` | Indexer client — upload, download, host management, erasure coding |
| `indexd_ffi` | C FFI bindings for `indexd` (used by mobile/desktop apps) |
| `indexd_wasm` | WASM bindings for `indexd` (browser-based uploads and downloads) |
| `syncer` | Sia blockchain sync protocol — handshake, RPC types, encoding |
| `syncer_wasm` | WASM bindings for `syncer` (browser-based chain sync with IndexedDB) |

## WASM Support

The SDK runs in the browser via WebAssembly, using WebTransport to communicate directly with Sia hosts (no server proxy required).

### Building

```bash
cd indexd_wasm
RUSTFLAGS='--cfg=web_sys_unstable_apis' wasm-pack build --target web
```

### WASM API

The `indexd_wasm` crate exposes JavaScript bindings for:

**Authentication**
- `Builder` — connect to an indexer, authenticate via app key
- `AppKey` — Ed25519 keypair from a BIP-39 seed

**Uploads**
- `sdk.upload(data, options, onProgress)` — in-memory upload
- `sdk.streamingUpload(totalSize, options)` — JS-driven streaming with backpressure
- `sdk.uploadSlab(data, dataKey, streamOffset, options)` — individual slab upload for Web Worker parallelism
- `sdk.assembleObject(dataKey, slabsJson)` — combine slabs from parallel workers into a stored object

**Downloads**
- `sdk.download(object, options, onProgress)` — full download to memory
- `sdk.downloadStreaming(object, options, onChunk, onProgress)` — streaming with chunk callbacks
- `sdk.downloadSlabByIndex(object, index, options, onHostActive)` — individual slab download for Web Worker parallelism

**Objects**
- `sdk.listObjects()` — list stored objects
- `sdk.object(key)` / `sdk.sharedObject(siaUrl)` — retrieve object metadata
- `sdk.shareUrl(object)` — generate `sia://` share URL

### WASM Compatibility

The SDK handles WASM platform differences transparently:

| Native | WASM | Purpose |
|--------|------|---------|
| QUIC (quinn) | WebTransport | Host connections |
| `tokio::time::Instant` | `js_sys::Date::now()` | Timing |
| `tokio::task::spawn_blocking` | Inline execution | CPU-bound work |
| `JoinSet::spawn` | `JoinSet::spawn_local` | Async task spawning |
| `tokio::time::timeout` | `tokio::select!` + `sleep` | Timeouts |
| 20 max inflight | 8 max inflight | Concurrency limits |

## Architecture

### Host Communication

All host communication uses the RHP4 (Renter-Host Protocol v4) protocol. The `RHP4Client` trait abstracts the transport layer:

- **Native**: QUIC via `quinn` with TLS certificate hashing
- **WASM**: WebTransport with connection pooling and automatic reconnection

Both implementations cache host prices and account tokens, refreshing them on expiry.

### Download Pipeline

1. Object metadata provides the list of slabs (erasure-coded shards distributed across hosts)
2. For each slab, sectors are downloaded from hosts in parallel (up to `max_inflight`)
3. Hosts are prioritized by a performance-weighted priority queue — faster hosts get more work
4. Failed downloads trigger automatic failover to backup hosts with a total failure limit
5. A 1-second "slow racer" timer spawns additional downloads from alternative hosts to mitigate stragglers
6. Erasure coding reconstructs each slab from `min_shards` successful downloads
7. Progress is reported via channels: `slab_downloaded` (bytes per slab) and `host_active` (full `Host` struct per sector)

### Upload Pipeline

1. Data is split into slabs, each erasure-coded into `data_shards + parity_shards` sectors
2. Sectors are uploaded to hosts in parallel with exponential backoff on failure (15s base, 2s per attempt, 120s max)
3. Failed hosts are deprioritized in the priority queue
4. Successful uploads return sector roots used to construct the object metadata

### Host Management

The `Hosts` manager maintains a priority queue of known hosts, ranked by a composite metric:

- **Latency** — exponentially weighted moving average of response times
- **Failure rate** — recent failures reduce priority
- **Upload capability** — hosts report whether they accept uploads

The `prioritize()` method sorts download/upload task lists so the best hosts are tried first.

## Syncer

The `syncer` and `syncer_wasm` crates implement the Sia syncer protocol, enabling a browser to act as a trustless blockchain client — connecting directly to Sia nodes via WebTransport with no intermediary server.

### Building

```bash
cd syncer_wasm
RUSTFLAGS='--cfg=web_sys_unstable_apis' wasm-pack build --target web
```

### Connecting to a Node

All functions connect to a Sia node via WebTransport using the syncer protocol URL (e.g. `https://host:9984/sia/syncer`). Connection involves a version-negotiated handshake with genesis ID validation to ensure both sides are on the same network.

```javascript
import init, { connect_and_discover_ip, sync_chain, scan_balance_filtered, generate_filters, lookup_txid } from './pkg/syncer_wasm.js';

await init();

const url = 'https://your-sia-node:9984/sia/syncer';
const genesisHex = '25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c'; // mainnet
```

### API

**Quick Connect** — handshake + IP discovery:
```javascript
const resultJson = await connect_and_discover_ip(url, genesisHex);
const { version, addr, ip } = JSON.parse(resultJson);
```

**Chain Sync** — sync all block headers from genesis to tip, verify PoW chain linkage, and fetch the tip block:
```javascript
const resultJson = await sync_chain(url, genesisHex, (msg, cls) => {
  console.log(`[${cls}] ${msg}`);
});
const { tipHeight, tipBlockID, tipTimestamp, totalHeaders, block } = JSON.parse(resultJson);
```

Headers are persisted in IndexedDB and reused on subsequent syncs, so only new headers need to be fetched. The tip block is fully decoded with miner payouts, V1/V2 transactions, and file contracts.

**Generate Compact Block Filters** — download all blocks from a peer and build Golomb-Rice coded (GCS) filters:
```javascript
const filterBytes = await generate_filters(url, genesisHex, (msg, cls) => {
  console.log(`[${cls}] ${msg}`);
});
// filterBytes is a Uint8Array — save as filters.bin
```

This produces a compact filter file that enables address scanning without downloading the full blockchain. The file can be pre-generated and served statically (with Brotli compression for efficient delivery).

**Address Explorer** — scan filters locally, fetch only matching blocks from the peer:
```javascript
const resultJson = await scan_balance_filtered(url, genesisHex, address, filterUrl, (msg, cls) => {
  console.log(`[${cls}] ${msg}`);
});
const { balance, received, sent, transactions } = JSON.parse(resultJson);
```

The filter scan runs entirely in the browser. Only blocks that match the filter are fetched from the peer, minimizing bandwidth. False positives are detected and discarded after block decoding.

**Transaction Lookup** — binary search a sorted transaction index file:
```javascript
const resultJson = await lookup_txid(url, genesisHex, txidHex, txindexUrl, (msg, cls) => {
  console.log(`[${cls}] ${msg}`);
});
const { txid, blockHeight, timestamp, block } = JSON.parse(resultJson);
```

### Network IDs

| Network | Genesis ID |
|---------|-----------|
| Mainnet | `25f6e3b9295a61f69fcb956aca9f0076234ecf2e02d399db5448b6e22f26e81c` |
| Zen Testnet | `172fb3d508c86ac628f93c3362ba60312251466c77d63a8c99ea87717e4112c3` |

### How It Works

1. **WebTransport connection** — the browser opens a WebTransport session to the node's `/sia/syncer` endpoint
2. **Handshake** — version strings and headers (genesis ID, unique ID, address) are exchanged using V1 framing (length-prefixed messages). Both sides validate the genesis ID matches
3. **DiscoverIP** — a single RPC that returns the browser's public IP as seen by the node
4. **SendHeaders** — requests block headers in batches of 2000. Each batch is verified: every header's `parent_id` must equal the previous header's computed `id()` (Blake2b-256 hash), forming a valid proof-of-work chain
5. **SendV2Blocks** — fetches full blocks by height for decoding transactions, miner payouts, and contract data
6. **IndexedDB caching** — synced header IDs and fetched blocks are cached in the browser's IndexedDB, enabling incremental sync across page reloads

## Binary Formats

The syncer WASM crate defines two compact binary formats for client-side blockchain data. Light clients can retrieve these from peers via a planned Syncer RPC command, generate them locally from downloaded blocks for stronger trust guarantees, or load them from static files. Once obtained, they are cached in IndexedDB for offline use.

### SCBF — Sia Compact Block Filters

SCBF files enable light clients to find blocks relevant to their addresses without downloading the full chain. Each block gets a Golomb-Coded Set (GCS) filter encoding the set of addresses that appear in that block's transactions. A client tests each filter locally and only fetches the few blocks that actually match — reducing bandwidth by orders of magnitude compared to a full chain scan.

**GCS Construction**

- Each address is a 32-byte Sia address (Blake2b-256 hash)
- SipHash-2-4 key derived from block ID: `k0 = LE64(blockID[0:8])`, `k1 = LE64(blockID[8:16])`
- Each address is hashed to `[0, N*M)` via SipHash + fast\_reduce, where `N` = address count, `M = 2^P`
- Sorted hashed values are delta-encoded with Golomb-Rice coding at parameter `P` (typically 19)
- Golomb-Rice: for each delta `d`, write `(d >> P)` zeros + one 1-bit (unary quotient), then the low `P` bits MSB-first
- False positive rate ≈ `1/M` per block (≈ 1 in 524,288 at P=19)

**Version 1 Wire Format**

All integers are unsigned little-endian.

```
Header (24 bytes):
  [0:4]    magic       "SCBF" (0x53 0x43 0x42 0x46)
  [4:8]    version     uint32 = 1
  [8:12]   count       uint32, number of block entries
  [12:16]  P           uint32, Golomb-Rice parameter
  [16:24]  tipHeight   uint64, chain height at time of generation

Entries (repeated `count` times, variable length):
  [0:8]    height      uint64, block height
  [8:40]   blockID     [32]byte, block ID (hash)
  [40:42]  addrCount   uint16, number of addresses in the filter
  [42:46]  dataLen     uint32, byte length of the GCS filter data
  [46:46+dataLen]      GCS filter bitstream (Golomb-Rice encoded)
```

**Version 2 Wire Format (compact)**

Designed for contiguous block ranges (e.g. V2-only sync from a known activation height). Heights are implicit: entry `i` has height = `startHeight + i`. Data lengths use uint16 (individual block filters are well under 64 KB).

```
Header (32 bytes):
  [0:4]    magic       "SCBF"
  [4:8]    version     uint32 = 2
  [8:12]   count       uint32, number of block entries
  [12:16]  P           uint32, Golomb-Rice parameter
  [16:24]  tipHeight   uint64, chain height at time of generation
  [24:32]  startHeight uint64, height of the first entry

Entries (repeated `count` times, variable length):
  [0:32]   blockID     [32]byte, block ID
  [32:34]  addrCount   uint16, number of addresses
  [34:36]  dataLen     uint16, byte length of GCS data
  [36:36+dataLen]      GCS filter bitstream
```

**Workflow**

1. **Generate** — sync chain blocks, extract addresses per block, build GCS filter for each, serialize to SCBF. Can be hosted as a static file (Brotli-compressed) or stored in IndexedDB.
2. **Scan** — load SCBF, test each block's filter against target addresses. Collect matching block heights.
3. **Fetch** — download only matching blocks from a peer and extract transaction details.

### STXI — Sia Transaction Index

STXI files provide compact transaction lookup by ID. The index maps 8-byte transaction ID prefixes to block heights, sorted for binary search. A client searches the index to find which block contains a transaction, then fetches only that block.

The 8-byte prefix is sufficient for practical uniqueness — with ~1M transactions, the probability of a prefix collision is roughly 1 in 10^13 (birthday bound at 2^64). On a collision, the client fetches the small number of candidate blocks and checks full transaction IDs.

**Version 1 Wire Format**

All integers are unsigned little-endian. Entries MUST be sorted by prefix in ascending lexicographic (byte) order to enable binary search.

```
Header (16 bytes):
  [0:4]    magic       "STXI" (0x53 0x54 0x58 0x49)
  [4:8]    version     uint32 = 1
  [8:12]   count       uint32, number of entries
  [12:16]  tipHeight   uint32, chain height at time of generation

Entries (repeated `count` times, fixed 12 bytes each):
  [0:8]    prefix      [8]byte, first 8 bytes of the transaction ID
  [8:12]   height      uint32, block height containing this transaction
```

Total size: `16 + (count * 12)` bytes. ~1M transactions ≈ 12 MB.

**Workflow**

1. **Generate** — sync chain blocks, collect `(txid_prefix, height)` for each V2 transaction, sort by prefix, serialize.
2. **Lookup** — binary search for the target txid prefix. Multiple matches are possible (prefix collisions) — collect all candidate heights.
3. **Fetch** — download candidate blocks from a peer, scan for the full transaction ID.

## Core Types (`sia_sdk`)

- BIP-39 seed generation and key derivation
- Ed25519 signing and verification
- Sia v1/v2 binary encoding via `SiaEncode`/`SiaDecode` derive macros
- V1 unlock conditions and transaction signing
- V2 spend policies, file contracts, and contract renewals
- `BlockHeader` with Blake2b-256 block ID computation
- `Currency` (u128) and `Address` types

## License

This project makes use of the `webpki-roots` crate which contains data from
Common CA Database (CCADB) and is used under the CDLA-2.0-Permissive license.
The remaining code in this project is licensed under the MIT License.
