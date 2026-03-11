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

### SUXI — Sia UTXO Index

SUXI files provide a compact index of all unspent transaction outputs (UTXOs) on the chain. The index maps 8-byte address prefixes to output ID prefixes and block heights, sorted for binary search. A wallet can search the index to instantly find which blocks contain unspent outputs for its addresses, then fetch only those blocks for full details.

The index is built during filter generation (same pass as SCBF filters and STXI txindex). For each block, created outputs (miner payouts, v2 siacoin outputs, file contract resolution payouts) are tracked alongside spent inputs. After processing the full chain, spent outputs are subtracted from the created set, leaving only unspent outputs in the final index.

The 8-byte address prefix combined with the 8-byte output ID prefix provides sufficient uniqueness — with ~20k UTXOs, collisions are astronomically unlikely. On a match, the client fetches the block at the indicated height and scans for the full address and output ID.

**Version 1 Wire Format**

All integers are unsigned little-endian. Entries MUST be sorted by address prefix in ascending lexicographic (byte) order, then by output ID prefix, to enable binary search.

```
Header (16 bytes):
  [0:4]    magic       "SUXI" (0x53 0x55 0x58 0x49)
  [4:8]    version     uint32 = 1
  [8:12]   count       uint32, number of entries
  [12:16]  tipHeight   uint32, chain height at time of generation

Entries (repeated `count` times, fixed 20 bytes each):
  [0:8]    addrPrefix  [8]byte, first 8 bytes of the address hash
  [8:16]   oidPrefix   [8]byte, first 8 bytes of the output ID
  [16:20]  height      uint32, block height where the output was created
```

Total size: `16 + (count * 20)` bytes. ~20k unspent outputs ≈ 400 KB.

**Chunk Wire Format (internal)**

During parallel filter generation, each chunk produces UTXO created and spent entries appended after the txindex section:

```
UTXO Created Section:
  [0:4]    count       uint32, number of created entries
  Per entry (20 bytes):
    [0:8]    addrPrefix  [8]byte
    [8:16]   oidPrefix   [8]byte
    [16:20]  height      uint32

UTXO Spent Section:
  [0:4]    count       uint32, number of spent entries
  Per entry (16 bytes):
    [0:8]    addrPrefix  [8]byte
    [8:16]   oidPrefix   [8]byte
```

**Output Sources**

The following output types are tracked as created UTXOs:
- **Miner payouts** — `BlockID.miner_output_id(index)` for each block's miner payouts
- **V2 siacoin outputs** — `TransactionID.v2_siacoin_output_id(index)` for each transaction output
- **File contract resolution payouts** — `FileContractID.v2_renter_output_id()` and `FileContractID.v2_host_output_id()` for renewal final outputs, storage proof outputs, and expiration outputs

Spent outputs are identified by the `parent.id` field of each V2 siacoin input.

**Workflow**

1. **Generate** — during full-chain filter generation, extract created and spent outputs per block chunk. After all chunks complete, collect all created outputs, build a spent set, filter to unspent only, sort by address prefix then output ID prefix, serialize to SUXI.
2. **Lookup** — binary search for a target address prefix. Collect all matching entries to get a list of `(oidPrefix, height)` pairs representing unspent outputs for that address.
3. **Fetch** — download blocks at the matched heights from a peer (or IndexedDB cache), scan for the full address to extract output amounts and details.

**Wallet Integration**

For HD wallets, the UTXO index replaces the need to scan all GCS filters per derived address:
1. Derive addresses along the HD path (`m/44'/1991'/account'/0'/index'`)
2. For each address, binary search the UTXO index — entries indicate unspent outputs exist
3. Gap limit: count consecutive addresses with no UTXO index entries
4. For active addresses, fetch blocks from cache or peer to get full UTXO details (amounts, output IDs)

This is dramatically faster than the filter-based approach which requires O(addresses × filter_entries) work.

### UTXO Pre-Filter (Sorted Prefix Array)

The SUXI index enables an in-memory pre-filter that provides **O(log N) exact rejection** of addresses with no unspent outputs — without any WASM calls or network requests. This is especially valuable for HD wallet gap detection, where hundreds of derived addresses are tested and the vast majority have zero UTXOs.

**How It Works**

When the SUXI index is loaded, the unique 8-byte address prefixes are extracted and packed into a flat sorted `Uint8Array`. Since SUXI entries are already sorted by address prefix, extraction is a single linear pass with deduplication. The result is a compact lookup table (~400 KB for ~50K unique addresses) that stays in JavaScript memory.

To check an address, its first 8 bytes are binary-searched against the sorted prefix array. A miss means the address has **definitively** no unspent outputs in the SUXI — no false positives, no false negatives. A hit means the address *may* have UTXOs and the full WASM-based SUXI lookup should proceed.

```javascript
import { checkUtxoPrefilter, getUtxoPrefixCount } from './chain.js';

// Instant reject — no WASM, no network
if (!checkUtxoPrefilter(addressHex)) {
  console.log('No unspent outputs for this address');
  return;
}

// Pre-filter passed — proceed with full SUXI lookup + block fetch
const utxos = await lookupUtxos(addressHex, ...);
```

**Properties**

| Property | Value |
|----------|-------|
| Time complexity | O(log N) binary search |
| Space | ~8 bytes per unique address (~400 KB for 50K addresses) |
| False positives | Possible if two different addresses share the same 8-byte prefix (~1/2^64 per pair) |
| False negatives | None — every SUXI address prefix is in the array |
| Dependencies | None — pure JavaScript, no WASM or network |

**HD Wallet Scanning**

For an HD wallet deriving addresses along `m/44'/1991'/account'/0'/index'`:

1. Derive the next address in the HD path
2. `checkUtxoPrefilter(address)` — if `false`, skip immediately (most addresses)
3. If `true`, call the full SUXI lookup + block fetch to get UTXO details
4. Repeat until the gap limit is reached (consecutive addresses with no UTXOs)

Without the pre-filter, every address requires a WASM call into the SUXI binary search. With the pre-filter, only addresses that actually have UTXOs reach WASM — typically a handful out of hundreds tested.

### SAPI — Sia Attestation Pubkey Index

SAPI files provide a compact index of all attestations on the chain. Attestations are identity-linked key-value pairs embedded in V2 transactions — for example, hosts attest to their network address by setting `key` to `"HostAnnouncement"` and `value` to their address. Every attestation is stored; the client determines which is "latest" for a given `(public_key, key)` pair by comparing block heights at query time.

The index is built during filter generation (same pass as SCBF, STXI, and SUXI). For each block, all attestations from V2 transactions are collected and stored.

The full 32-byte public key is stored to prevent collision attacks — an attacker cannot grind a key that shadows a legitimate identity. The attestation key string is hashed to a fixed 8-byte prefix; on lookup, the client fetches the block and verifies the full key string, so a rare hash collision just means an extra block fetch.

**Version 1 Wire Format**

All integers are unsigned little-endian. Entries MUST be sorted by public key in ascending lexicographic (byte) order, then by key hash, to enable binary search.

```
Header (16 bytes):
  [0:4]    magic       "SAPI" (0x53 0x41 0x50 0x49)
  [4:8]    version     uint32 = 1
  [8:12]   count       uint32, number of entries
  [12:16]  tipHeight   uint32, chain height at time of generation

Entries (repeated `count` times, fixed 44 bytes each):
  [0:32]   pubkey      [32]byte, full attesting public key
  [32:40]  keyHash     [8]byte, first 8 bytes of Blake2b-256(attestation.key)
  [40:44]  height      uint32, block height of the latest attestation
```

Total size: `16 + (count * 44)` bytes. ~10k attestations ≈ 430 KB.

**Chunk Wire Format (internal)**

During parallel filter generation, each chunk produces attestation entries appended after the UTXO sections:

```
Attestation Section:
  [0:4]    count       uint32, number of entries
  Per entry (44 bytes):
    [0:32]   pubkey      [32]byte
    [32:40]  keyHash     [8]byte
    [40:44]  height      uint32
```

**Workflow**

1. **Generate** — during full-chain filter generation, extract attestations from V2 transactions per block chunk. After all chunks complete, collect all entries, sort by pubkey then key hash then height, serialize to SAPI.
2. **Lookup by pubkey** — binary search for a target public key. Collect all matching entries to get a list of `(keyHash, height)` pairs representing that identity's attestations.
3. **Lookup by key** — linear scan (index is small), filter by `keyHash`. Collect all matching `(pubkey, height)` pairs to discover all attestors for a given key (e.g. all hosts).
4. **Lookup by (pubkey, key)** — binary search for `(pubkey, keyHash)`. Multiple entries may exist; the one with the highest `height` is the latest attestation.
5. **Fetch** — download the block at the matched height from a peer (or IndexedDB cache), scan for the full attestation to extract the key string and value.

**Supported Queries**

| Query | Method | Use case |
|-------|--------|----------|
| All keys for pubkey P | Binary search by pubkey | Profile — what has this identity attested to? |
| All pubkeys for key K | Linear scan, filter by keyHash | Discovery — find all hosts, all publishers |
| Pubkey P's latest attestation for key K | Binary search by (pubkey, keyHash) | Resolve a specific identity claim |

## Manifest Pointers

Manifest pointers use the Sia blockchain's UTXO set as a mutable, decentralized key-value store. A user's seed phrase deterministically derives a manifest address. Broadcasting a v2 transaction to that address with an encrypted payload in `arbitrary_data` creates an on-chain pointer to an off-chain resource (e.g. a share URL for a file manifest). The pointer can be updated at any time by broadcasting a new transaction to the same address.

### How It Works

1. **Derive a manifest address** from the user's seed via HD key derivation:
   ```
   m/44'/19911'/{account}'/0'/{hash(".sia/manifest")}'
   ```
   The path uses the Sia storage coin type (`19911`) and a deterministic child index computed by hashing the well-known name `".sia/manifest"` with Blake2b-256. This produces both an encryption key and a standard Sia address.

2. **Encrypt the payload** (e.g. a `sia://` share URL) with XChaCha20-Poly1305 using the derived encryption key. The sealed data is prefixed with a `"manifest"` specifier and version byte for identification.

3. **Build a v2 transaction** with:
   - A **0 SC output** to the manifest address (creates a UTXO that scanners will find)
   - The encrypted payload in the transaction's `arbitrary_data` field
   - A miner fee (the only cost — the pointer output itself carries no value)

4. **Recovery**: scan the chain for transactions to the manifest address (using compact block filters for efficiency). Attempt to decrypt each transaction's `arbitrary_data` with the manifest key. AEAD authentication ensures only transactions created by the seed holder will decrypt — spam and unrelated transactions are silently rejected. The most recent successful decryption is the current pointer.

### Why This Works

- **Deterministic**: anyone with the seed phrase can derive the same address and key — no out-of-band coordination needed
- **Updatable**: broadcasting a new transaction to the same address updates the pointer. The UTXO set always contains the latest version
- **Spam-resistant**: XChaCha20-Poly1305 AEAD authentication means only the seed holder can create payloads that decrypt successfully
- **Scannable**: compact block filters (SCBF) allow light clients to find matching blocks without downloading the full chain
- **Zero value**: the pointer output carries 0 SC, so no funds are locked — only the miner fee is spent

### API

```rust
use sia_sdk::hd_encryption::{derive_manifest, seal_manifest_url, open_manifest_url, manifest_pointer_transaction};

// Derive manifest key + address from seed
let (key, address) = derive_manifest(&master_key, account)?;

// Encrypt a share URL
let sealed = seal_manifest_url(&key, "sia://example.com/objects/abc123/shared");

// Build an unsigned v2 transaction (caller adds inputs + signature)
let txn = manifest_pointer_transaction(address, sealed, miner_fee);

// On recovery: decrypt arbitrary_data from a scanned transaction
if let Some(url) = open_manifest_url(&key, &txn.arbitrary_data) {
    // url == "sia://example.com/objects/abc123/shared"
}
```

## V2 Transaction Builder

The `V2TransactionBuilder` provides a builder pattern for constructing, signing, and finalizing Sia V2 siacoin transactions. It is available in both Rust and WASM.

### Rust API

```rust
use sia_sdk::transaction_builder::V2TransactionBuilder;
use sia_sdk::types::v2::{SpendPolicy, SiacoinElement};
use sia_sdk::types::{Currency, SiacoinOutput};

let mut builder = V2TransactionBuilder::new();
builder
    .add_siacoin_input(utxo_element, SpendPolicy::PublicKey(pk))
    .add_siacoin_output(SiacoinOutput { value: amount, address: recipient })
    .miner_fee(Currency::new(10_000_000_000_000_000_000));

// Sign with a ChainState (native)
builder.sign_simple(&chain_state, &[&private_key]);

// Or sign with hardcoded V2 replay prefix (no ChainState needed — ideal for WASM)
builder.sign_simple_v2(&[&private_key]);

let txn = builder.build();
```

**Builder Methods**

| Method | Description |
|--------|-------------|
| `add_siacoin_input(element, policy)` | Add a UTXO input with its spend policy |
| `add_siacoin_output(output)` | Add a recipient output |
| `miner_fee(fee)` | Set the miner fee |
| `arbitrary_data(data)` | Set arbitrary data (e.g. encrypted manifest pointer) |
| `siacoin_inputs(inputs)` | Set all inputs at once (replaces any previously added) |
| `siacoin_outputs(outputs)` | Set all outputs at once (replaces any previously added) |
| `input_sig_hash(cs)` | Compute the signature hash using a `ChainState` |
| `input_sig_hash_v2()` | Compute the signature hash with hardcoded V2 replay prefix |
| `sign_simple(cs, keys)` | Sign all `PublicKey` and `UnlockConditions` inputs using `ChainState` |
| `sign_simple_v2(keys)` | Sign all inputs using V2 replay prefix (no `ChainState` needed) |
| `build()` | Consume the builder and produce a `v2::Transaction` |

**Signing**

`sign_simple` / `sign_simple_v2` match each provided key against each input's spend policy:
- `SpendPolicy::PublicKey(pk)` — direct public key comparison
- `SpendPolicy::UnlockConditions(uc)` — compares against each key in the unlock conditions

V2 transactions always use replay prefix `[2]`. The `_v2` variants hardcode this, avoiding the need to construct a `ChainState` — particularly useful in WASM where `ChainState` has many fields that are irrelevant to signing.

### WASM API

The `build_v2_transaction` function in `syncer_wasm` provides a complete transaction building pipeline: HD key derivation, UTXO construction, change calculation, signing, and JSON serialization.

```javascript
import init, { build_v2_transaction } from './pkg/syncer_wasm.js';

await init();

const signedTxnJson = build_v2_transaction(
  entropyHex,          // Wallet entropy (hex-encoded)
  0,                   // HD account index
  JSON.stringify([     // Inputs (UTXOs from SUXI lookup + block fetch)
    {
      id: 'abc123...',          // 64-char hex SiacoinOutputID
      value: '1000000000...',   // Hastings (decimal string)
      maturityHeight: 500000,
      leafIndex: 0,
      merkleProof: [],          // Array of 64-char hex hashes (optional)
      addressIndex: 3           // HD child index that owns this UTXO
    }
  ]),
  JSON.stringify([     // Outputs (recipients)
    {
      address: 'def456...',     // 76-char hex Sia address
      value: '500000000...'     // Hastings (decimal string)
    }
  ]),
  '10000000000000000000',       // Miner fee in hastings
  'aabbcc...'                   // 76-char hex change address
);

const txn = JSON.parse(signedTxnJson);
// txn is a fully signed v2::Transaction ready for broadcast
```

**Flow**

1. Derive HD keys from entropy at `m/44'/1991'/{account}'/0'/{addressIndex}'`
2. Construct `SiacoinElement` for each input UTXO
3. Calculate change: `sum(inputs) - sum(outputs) - miner_fee`
4. Add change output if change > 0
5. Sign all inputs with `sign_simple_v2` (V2 replay prefix, no `ChainState`)
6. Return JSON of the signed transaction

Returns an error if inputs are insufficient to cover outputs + fee.

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
