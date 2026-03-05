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

The `syncer` crate implements the Sia syncer protocol for blockchain synchronization:

- Handshake with version negotiation and genesis ID validation
- V1-framed message encoding (length-prefixed)
- RPC types: `SendHeaders`, `SendV2Blocks`, `SendTransactions`, `SendCheckpoint`, `DiscoverIP`

The `syncer_wasm` crate adds browser support with:

- WebTransport streaming for syncer connections
- IndexedDB persistence for block headers and caches
- Proof-of-work verification for received headers
- V2 block decoding (miner payouts, V1/V2 transactions, file contracts)
- Golomb-Rice coded compact block filters (GCS) for lightweight filtering

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
