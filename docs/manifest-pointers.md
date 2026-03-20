# Manifest Pointers

## Problem

Applications built on Sia need a way to persist and recover state using only the user's seed phrase.

The question is: **given only a seed phrase, how can an application recover its state?**

A related problem: share URLs on Sia are immutable — they point to a specific version of the content. If a publisher shares a URL for their website and later updates it, anyone with the old URL still sees the old version. There is no built-in way to follow a publisher and always get their latest content.

The question is: **given only a publisher's public key, how can anyone find their latest content?**

## Solution

Manifest pointers use Sia v2 **attestations** as a decentralized, mutable key-value store. Each attestation contains:

- **Public key** — the ed25519 key of the publisher
- **Key** — a string identifying the manifest type and purpose
- **Value** — the payload (a URL, possibly encrypted)

Attestations are included in v2 transactions at zero cost (no miner fee beyond the transaction itself). The SAPI (Sia Attestation Pubkey Index) enables efficient lookup by public key or key hash.

There are four types of manifest pointers, each serving different visibility and access control needs:

| Type | Discoverable by | Readable by | Who publishes | Use case |
|------|----------------|-------------|---------------|----------|
| **Private** | Seed holder only | Seed holder only | Seed holder | App-specific data recovery from seed |
| **Public** | Anyone with publisher's public key | Anyone | Publisher (verified by pubkey) | Open content distribution |
| **Channel** | Anyone with publisher's public key | Channel key holders | Publisher (verified by pubkey) | Paid or restricted content |
| **Group** | Group key holders only | Group key holders only | Any group member | Community collaboration |

## Manifest Types

### Private Manifests

Private manifests allow Sia-based applications to store arbitrary data on the blockchain, recoverable from the user's seed phrase alone. Each application chooses a well-known path string, and the HD derivation produces a unique key and address for that path. This enables any app to bootstrap its state from nothing but the seed.

**Key derivation**: From the user's BIP39 seed phrase, derive a manifest-specific keypair using HD key derivation:

```
m/44'/19911'/{account}'/0'/{hash(path)}'
```

The `path` is an application-chosen string that determines which manifest is being stored or recovered. The well-known default is `".sia/manifest"`, but applications are free to use any path.

- **Coin type `19911`**: Sia storage branch (separate from the wallet coin type `1991` to avoid key reuse)
- **Purpose `0`**: Encryption keys (as opposed to purpose `1` for contract signing keys)
- **Child index**: Deterministic — computed by hashing the path string with Blake2b-256, then taking the first 4 bytes as a little-endian u32 masked to < 2^31

This derivation produces:
- An **encryption key** (the raw 32-byte private key material, used with XChaCha20-Poly1305)
- A **signing key** (the corresponding ed25519 private key, used to author attestations)
- A **public key** (used as the attestation pubkey and as the SAPI lookup key)

Different path strings produce completely independent keys, allowing multiple applications to coexist on the same seed without interference.

**Attestation key derivation**: The attestation `key` field is an opaque hash, not the plaintext path string. This prevents on-chain observers from identifying private manifest attestations by their key string.

```
key = hex(blake2b-256("sia/manifest/key" || path))
```

The distinguisher prefix `"sia/manifest/key"` namespaces the hash to avoid collisions with other uses of Blake2b. The seed holder can recompute the key from the path string; to everyone else it appears as a random 64-character hex string.

**Attestation structure**:

| Field | Value |
|-------|-------|
| `public_key` | Derived from `m/44'/19911'/{account}'/0'/{hash(path)}'` |
| `key` | `hex(blake2b-256("sia/manifest/key" \|\| path))` |
| `value` | Encrypted URL (XChaCha20-Poly1305 AEAD) |

**Payload format** (in the `value` field):

```
[version:    1 byte ]  0x01
[nonce:     24 bytes]  random XChaCha20 nonce
[ciphertext + tag   ]  encrypted URL + 16-byte Poly1305 authentication tag
```

The AEAD tag ensures that only the seed holder can produce payloads that decrypt successfully — other attestations from different keys at the same key string fail authentication and are silently rejected. Combined with the opaque key and HD-derived pubkey, private manifest attestations are indistinguishable from any other attestation on-chain.

**Example use cases**:

- **Personal file recovery** — A user backs up documents to Sia at the default path `".sia/manifest"`. They lose their device, enter their seed phrase on a new one, derive the pubkey, query the SAPI index, and recover the manifest URL — no server, no account, no out-of-band coordination.

- **Multi-app state** — An application stores its manifest at a distinct path:
  ```
  ".sia/manifest/ETH"  → Ethereum node data manifest
  ".sia/manifest/BTC"  → Bitcoin node data manifest
  ".sia/manifest/SC"   → Sia chain data manifest
  ```
  Each path produces a different HD-derived keypair and therefore a different pubkey in the SAPI index. On a fresh install, the app derives each key from the seed, queries SAPI for each pubkey, and recovers each manifest independently.

### Public Manifests

Public manifests are for open content distribution. Anyone who knows the publisher's public key can find and read the manifest.

**Key**: The publisher uses their wallet public key (or any known identity key). The attestation key string is a well-known convention, e.g. `".sia/manifest"`.

**Attestation structure**:

| Field | Value |
|-------|-------|
| `public_key` | Publisher's known public key |
| `key` | `".sia/manifest"` |
| `value` | Plaintext URL (UTF-8) |

**Spam resistance**: The attestation's public key is inherently the publisher's identity — only the holder of the corresponding private key can sign the attestation. No additional verification is needed. Anyone scanning the SAPI index for the publisher's pubkey will only find attestations actually signed by them.

**Example use case**: An open-source project publishes documentation and release artifacts to Sia. Anyone who knows the project's public key can query SAPI, find the `".sia/manifest"` attestation, and access the files — no website or DNS required.

### Channel Manifests

Channel manifests are for single-publisher, restricted-access content. The publisher's identity is public (anyone can find the attestation), but the payload is encrypted with a channel key that only subscribers possess.

**Attestation structure**:

| Field | Value |
|-------|-------|
| `public_key` | Publisher's known public key |
| `key` | `".sia/channel/{channel_name}"` |
| `value` | Encrypted URL (XChaCha20-Poly1305 AEAD with channel key) |

**Payload format** (in the `value` field):

```
[version:    1 byte ]  0x01
[nonce:     24 bytes]  random XChaCha20 nonce
[ciphertext + tag   ]  encrypted URL + 16-byte Poly1305 authentication tag
```

**Spam resistance**: Two layers:
1. **Publisher identity**: Only the private key holder can author the attestation — SAPI lookups by pubkey only return genuine attestations
2. **AEAD authentication**: Only channel key holders can decrypt the payload

**Key rotation**: The publisher distributes a new channel key to authorized subscribers. Old key holders can still find new attestations (same pubkey in SAPI), but can't decrypt them.

**Example use case**: A creator sells access to their content library. Purchasers receive the channel key. The creator updates their manifest attestation as they add new content. All key holders query SAPI for the publisher's pubkey, find the channel attestation, and decrypt the latest catalog URL.

### Group Manifests

Group manifests are for collaborative sharing where multiple members can publish. Each member posts their own attestation using a shared key convention. Members discover each other by querying the SAPI index for the shared key hash.

**Key convention**: All group members agree on a key string derived from the group secret:

```
key = ".sia/group/" + hex(blake2b(group_secret)[0..8])
```

The group secret also serves as the encryption key for payloads.

**Attestation structure** (each member posts their own):

| Field | Value |
|-------|-------|
| `public_key` | Individual member's public key |
| `key` | `".sia/group/{group_hash}"` |
| `value` | Encrypted URL (XChaCha20-Poly1305 AEAD with group secret) |

**Discovery**: Group members query the SAPI index by key hash. The index returns all pubkeys that have posted attestations with the matching key hash, along with the block heights. Members then fetch those blocks and decrypt the values.

**Privacy note**: The SAPI index reveals that multiple pubkeys share the same key hash, making group membership visible to anyone who knows the group secret (or who observes the key hash pattern). This is an acceptable tradeoff for the simplicity of attestation-based discovery — if group membership privacy is critical, an alternative approach would be needed.

**Key rotation**: Changing the group secret produces a new key hash. Old members who don't receive the new secret can't discover new attestations (different key hash) or decrypt them (different encryption key).

**Example use case**: A photography collective shares a group secret among members. Each photographer publishes their portfolio manifest as an attestation. Members query SAPI for the shared key hash and discover each other's work.

## Recovery

### Private manifest recovery

1. Derive the manifest keypair from the seed phrase using the known path string
2. Compute the expected attestation key: `hex(blake2b-256("sia/manifest/key" || path))`
3. Query the SAPI index for the derived public key
4. For each matching attestation whose key matches the expected hash, fetch the block and extract the value
5. Decrypt the value with the derived encryption key — AEAD rejects tampered or unrelated data
6. The most recent successfully decrypted URL is the current manifest pointer

An application that uses multiple paths simply repeats this process for each one.

### Public manifest recovery

1. Obtain the publisher's public key
2. Query the SAPI index for that public key, filtering for key = `".sia/manifest"`
3. Fetch the block containing the most recent matching attestation
4. Read the plaintext URL directly from the value field

### Channel manifest recovery

1. Obtain the publisher's public key and the channel key
2. Query the SAPI index for the publisher's public key, filtering for key = `".sia/channel/{channel_name}"`
3. Fetch the block containing the most recent matching attestation
4. Decrypt the value with the channel key — AEAD rejects wrong keys
5. The most recent successfully decrypted URL is the current manifest pointer

### Group manifest recovery

1. Derive the key hash from the group secret
2. Query the SAPI index for all pubkeys with the matching key hash
3. For each matching attestation, fetch the block and decrypt the value with the group secret
4. AEAD authentication rejects payloads from rotated keys or outsiders
5. Collect all successfully decrypted URLs — each represents a group member's manifest

## Properties

| Property | Description |
|----------|-------------|
| **Deterministic** | Private: seed phrase derives the pubkey. Public/Channel: publisher's known pubkey. Group: shared secret derives the key hash. No out-of-band coordination needed for discovery. |
| **Updatable** | Broadcasting a new attestation with the same key updates the pointer. Recovery always finds the latest one (by block height). |
| **Spam-resistant** | Attestations are signed by the publisher's private key — only the key holder can author them. Private, channel, and group manifests add AEAD encryption on top. |
| **Efficient discovery** | The SAPI index enables O(1) lookups by public key or key hash, without scanning the full chain or using compact block filters. |
| **Zero-cost** | Attestations are included in v2 transactions at no additional cost beyond the transaction's miner fee. No 0 SC UTXOs needed. |
| **Self-contained** | The entire system requires nothing beyond the blockchain, a key, and a SAPI index. No DNS, no DHT, no central server. |

## HD Path Summary

```
m/44'/1991'/{account}'/0'/{i}'    → Wallet addresses (standard Sia)
m/44'/19911'/{account}'/0'/{i}'   → File encryption keys (Sia storage)
m/44'/19911'/{account}'/1'/{i}'   → Contract signing keys (Sia storage)
m/44'/19911'/{account}'/0'/{H}'   → Private manifest key + pubkey (H = hash(path))
```

The child index `H` is derived from the application's chosen path string (e.g. `".sia/manifest"`, `".sia/manifest/ETH"`). Different paths produce independent keys:

```
hash(".sia/manifest")     → H₁ → m/44'/19911'/0'/0'/{H₁}'  (default file manifest)
hash(".sia/manifest/ETH") → H₂ → m/44'/19911'/0'/0'/{H₂}'  (Ethereum node data)
hash(".sia/manifest/BTC") → H₃ → m/44'/19911'/0'/0'/{H₃}'  (Bitcoin node data)
```

Public and channel manifests use the publisher's wallet public key directly — no HD derivation or key tweaking needed.

Group manifests use a shared key string derived from the group secret, discoverable via the SAPI key hash index.

## Implementation

The implementation lives in:
- [`sia_sdk/src/hd_encryption.rs`](../sia_sdk/src/hd_encryption.rs) — manifest derivation, encryption, payload sealing/opening
- [`sia_sdk/src/signing.rs`](../sia_sdk/src/signing.rs) — ed25519 signing (attestations are signed like any other v2 transaction element)
