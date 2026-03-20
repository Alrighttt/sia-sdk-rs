//! On-chain manifest pointers for Sia storage using v2 attestations.
//!
//! Manifest pointers use attestations as a decentralized, mutable key-value
//! store. Each attestation contains a public key, a key string, and a value
//! (the manifest URL, possibly encrypted).
//!
//! Four manifest variants are supported:
//!
//! - **Private** (`derive_manifest`): encrypted with an HD-derived key; only the
//!   seed holder can discover and decrypt. Discovered via SAPI pubkey lookup.
//! - **Public** (`public_manifest_attestation`): plaintext URL signed by the
//!   publisher's key, discoverable by anyone who knows the pubkey.
//! - **Channel** (`channel_manifest_attestation`): encrypted with a per-channel
//!   key distributed to subscribers; publisher identity verified by attestation signature.
//! - **Group** (`group_manifest_attestation`): encrypted with a shared group key;
//!   discovered via SAPI key-hash lookup.

use blake2b_simd::Params;
use chacha20poly1305::aead::{Aead, OsRng};
use chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305};

use crate::consensus::ChainState;
use crate::encryption::EncryptionKey;
use crate::hd::{ExtendedPrivateKey, HdError};
use crate::hd_encryption::{derive_account, PURPOSE_ENCRYPTION};
use crate::signing::{PrivateKey, Signature};
use crate::types::Currency;
use crate::types::v2::{self, Attestation};

const NONCE_SIZE: usize = 24;

/// Current manifest pointer payload version.
pub const MANIFEST_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Key strings for attestation types
// ---------------------------------------------------------------------------

/// Well-known path string for private manifests.
pub const PRIVATE_MANIFEST_PATH: &str = ".sia/manifest";

/// Distinguisher prefix for private manifest attestation key derivation.
const MANIFEST_KEY_PREFIX: &[u8] = b"sia/manifest/key";

/// Well-known key string for public manifests.
pub const PUBLIC_MANIFEST_KEY: &str = ".sia/manifest";

/// Derive the opaque attestation key string for a private manifest path.
///
/// ```text
/// key = hex(blake2b-256("sia/manifest/key" || path))
/// ```
pub fn private_attestation_key(path: &str) -> String {
    let hash = Params::new()
        .hash_length(32)
        .to_state()
        .update(MANIFEST_KEY_PREFIX)
        .update(path.as_bytes())
        .finalize();
    hex::encode(hash.as_bytes())
}

/// Prefix for channel manifest key strings.
pub const CHANNEL_KEY_PREFIX: &str = ".sia/channel/";

/// Prefix for group manifest key strings.
pub const GROUP_KEY_PREFIX: &str = ".sia/group/";

// ---------------------------------------------------------------------------
// Private manifests — discoverable and readable only with the seed
// ---------------------------------------------------------------------------

/// Derive a manifest signing key and encryption key at a sequential index.
///
/// Path: `m/44'/19911'/{account}'/0'/{index}'`
///
/// Each attestation should use a fresh index to avoid pubkey reuse.
/// Scan the attestation index for existing keys (i=0,1,2...) until a gap
/// is found to determine the next unused index.
///
/// Returns (encryption_key, signing_key) — the public key for SAPI lookup
/// is `signing_key.public_key()`.
pub fn derive_manifest(
    master: &ExtendedPrivateKey,
    account: u32,
    index: u32,
) -> Result<(EncryptionKey, PrivateKey), HdError> {
    let key = derive_account(master, account)?
        .derive_child(PURPOSE_ENCRYPTION)?
        .derive_child(index)?;

    let encryption_key = EncryptionKey::from(*key.raw_private_key());
    let signing_key = key.private_key();

    Ok((encryption_key, signing_key))
}

/// Encrypt a URL for a private manifest attestation (XChaCha20-Poly1305).
///
/// Payload format:
/// ```text
/// [version: 1 byte] [nonce: 24 bytes] [ciphertext + 16-byte Poly1305 tag]
/// ```
pub fn seal_private_url(key: &EncryptionKey, url: &str) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, url.as_bytes())
        .expect("encryption failed");

    let mut out = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
    out.push(MANIFEST_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt a URL from a private manifest attestation value.
///
/// Returns `None` if the version is unsupported or decryption fails.
pub fn open_private_url(key: &EncryptionKey, value: &[u8]) -> Option<String> {
    if value.len() < 1 + NONCE_SIZE + 16 {
        return None;
    }
    if value[0] != MANIFEST_VERSION {
        return None;
    }
    let (nonce_bytes, ciphertext) = value[1..].split_at(NONCE_SIZE);
    let nonce_arr: [u8; NONCE_SIZE] = nonce_bytes.try_into().ok()?;
    let nonce = chacha20poly1305::XNonce::from(nonce_arr);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plaintext = cipher.decrypt(&nonce, ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}

/// Build a signed private manifest attestation.
pub fn private_manifest_attestation(
    signing_key: &PrivateKey,
    encryption_key: &EncryptionKey,
    url: &str,
    cs: &ChainState,
) -> Attestation {
    let sealed = seal_private_url(encryption_key, url);
    let mut att = Attestation {
        public_key: signing_key.public_key(),
        key: private_attestation_key(PRIVATE_MANIFEST_PATH),
        value: sealed,
        signature: Signature::default(),
    };
    let sig_hash = att.sig_hash(cs);
    att.signature = signing_key.sign(sig_hash.as_ref());
    att
}

/// Build a v2 transaction containing a private manifest attestation.
///
/// The caller must add `siacoin_inputs` (to cover `miner_fee`) and sign them.
pub fn private_manifest_transaction(
    signing_key: &PrivateKey,
    encryption_key: &EncryptionKey,
    url: &str,
    miner_fee: Currency,
    cs: &ChainState,
) -> v2::Transaction {
    let att = private_manifest_attestation(signing_key, encryption_key, url, cs);
    v2::Transaction {
        attestations: vec![att],
        miner_fee,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Public manifests — discoverable by anyone who knows the publisher's pubkey
// ---------------------------------------------------------------------------

/// Build a signed public manifest attestation.
///
/// The URL is stored in plaintext. Anyone who knows the publisher's public key
/// can query SAPI and read the value directly.
pub fn public_manifest_attestation(
    signing_key: &PrivateKey,
    url: &str,
    cs: &ChainState,
) -> Attestation {
    let mut att = Attestation {
        public_key: signing_key.public_key(),
        key: PUBLIC_MANIFEST_KEY.to_string(),
        value: url.as_bytes().to_vec(),
        signature: Signature::default(),
    };
    let sig_hash = att.sig_hash(cs);
    att.signature = signing_key.sign(sig_hash.as_ref());
    att
}

/// Build a v2 transaction containing a public manifest attestation.
pub fn public_manifest_transaction(
    signing_key: &PrivateKey,
    url: &str,
    miner_fee: Currency,
    cs: &ChainState,
) -> v2::Transaction {
    let att = public_manifest_attestation(signing_key, url, cs);
    v2::Transaction {
        attestations: vec![att],
        miner_fee,
        ..Default::default()
    }
}

/// Read a plaintext URL from a public manifest attestation value.
pub fn read_public_url(value: &[u8]) -> Option<String> {
    String::from_utf8(value.to_vec()).ok()
}

// ---------------------------------------------------------------------------
// Channel manifests — single publisher, multiple subscribers
// ---------------------------------------------------------------------------

/// Build the key string for a channel manifest.
pub fn channel_key_string(channel_name: &str) -> String {
    format!("{}{}", CHANNEL_KEY_PREFIX, channel_name)
}

/// Encrypt a URL for a channel manifest attestation.
pub fn seal_channel_url(channel_key: &EncryptionKey, url: &str) -> Vec<u8> {
    seal_private_url(channel_key, url) // same encryption format
}

/// Decrypt a URL from a channel manifest attestation value.
pub fn open_channel_url(channel_key: &EncryptionKey, value: &[u8]) -> Option<String> {
    open_private_url(channel_key, value) // same decryption format
}

/// Build a signed channel manifest attestation.
///
/// The publisher signs with their identity key. The value is encrypted with
/// the channel key. Subscribers find the attestation via SAPI (publisher pubkey)
/// and decrypt with the channel key.
pub fn channel_manifest_attestation(
    signing_key: &PrivateKey,
    channel_name: &str,
    channel_key: &EncryptionKey,
    url: &str,
    cs: &ChainState,
) -> Attestation {
    let sealed = seal_channel_url(channel_key, url);
    let mut att = Attestation {
        public_key: signing_key.public_key(),
        key: channel_key_string(channel_name),
        value: sealed,
        signature: Signature::default(),
    };
    let sig_hash = att.sig_hash(cs);
    att.signature = signing_key.sign(sig_hash.as_ref());
    att
}

/// Build a v2 transaction containing a channel manifest attestation.
pub fn channel_manifest_transaction(
    signing_key: &PrivateKey,
    channel_name: &str,
    channel_key: &EncryptionKey,
    url: &str,
    miner_fee: Currency,
    cs: &ChainState,
) -> v2::Transaction {
    let att = channel_manifest_attestation(signing_key, channel_name, channel_key, url, cs);
    v2::Transaction {
        attestations: vec![att],
        miner_fee,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Group manifests — multiple publishers, shared key
// ---------------------------------------------------------------------------

/// Compute the group key hash (first 8 bytes of Blake2b-256) for use in the
/// attestation key string.
pub fn group_key_hash(group_secret: &[u8]) -> [u8; 8] {
    let hash = Params::new()
        .hash_length(32)
        .to_state()
        .update(group_secret)
        .finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash.as_bytes()[..8]);
    out
}

/// Build the key string for a group manifest.
pub fn group_key_string(group_secret: &[u8]) -> String {
    let hash = group_key_hash(group_secret);
    format!("{}{}", GROUP_KEY_PREFIX, hex::encode(hash))
}

/// Encrypt a URL for a group manifest attestation.
///
/// The group secret is used as both the encryption key and the key-hash
/// for discovery.
pub fn seal_group_url(group_secret: &EncryptionKey, url: &str) -> Vec<u8> {
    seal_private_url(group_secret, url) // same encryption format
}

/// Decrypt a URL from a group manifest attestation value.
pub fn open_group_url(group_secret: &EncryptionKey, value: &[u8]) -> Option<String> {
    open_private_url(group_secret, value) // same decryption format
}

/// Build a signed group manifest attestation.
///
/// Each group member posts their own attestation using their own signing key.
/// The key string includes a hash of the group secret, enabling SAPI key-hash
/// lookup. The value is encrypted with the group secret.
pub fn group_manifest_attestation(
    signing_key: &PrivateKey,
    group_secret: &EncryptionKey,
    url: &str,
    cs: &ChainState,
) -> Attestation {
    let sealed = seal_group_url(group_secret, url);
    let mut att = Attestation {
        public_key: signing_key.public_key(),
        key: group_key_string(group_secret.as_ref()),
        value: sealed,
        signature: Signature::default(),
    };
    let sig_hash = att.sig_hash(cs);
    att.signature = signing_key.sign(sig_hash.as_ref());
    att
}

/// Build a v2 transaction containing a group manifest attestation.
pub fn group_manifest_transaction(
    signing_key: &PrivateKey,
    group_secret: &EncryptionKey,
    url: &str,
    miner_fee: Currency,
    cs: &ChainState,
) -> v2::Transaction {
    let att = group_manifest_attestation(signing_key, group_secret, url, cs);
    v2::Transaction {
        attestations: vec![att],
        miner_fee,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Attestation key hash — for SAPI lookups
// ---------------------------------------------------------------------------

/// Compute the SAPI key hash (first 8 bytes of Blake2b-256) for any
/// attestation key string. This is what the attestation index stores.
pub fn attestation_key_hash(key: &str) -> [u8; 8] {
    let hash = Params::new()
        .hash_length(32)
        .to_state()
        .update(key.as_bytes())
        .finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash.as_bytes()[..8]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Network, State, ElementAccumulator};
    use crate::hd::HdMnemonic;
    use crate::types::{BlockID, ChainIndex, Work};
    use chrono::{DateTime, TimeDelta, Utc};

    fn test_master() -> ExtendedPrivateKey {
        let m = HdMnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        m.to_extended_key("")
    }

    fn test_chain_state() -> ChainState {
        let network = Network::mainnet();
        let addr = network.hardfork_foundation.primary_address.clone();
        ChainState {
            network,
            state: State {
                index: ChainIndex { height: 1, id: BlockID::default() },
                prev_timestamps: [DateTime::<Utc>::UNIX_EPOCH; 11],
                depth: BlockID::default(),
                child_target: BlockID::default(),
                siafund_pool: Currency::zero(),
                oak_time: TimeDelta::zero(),
                oak_target: BlockID::default(),
                foundation_primary_address: addr.clone(),
                foundation_failsafe_address: addr,
                total_work: Work::default(),
                difficulty: Work::default(),
                oak_work: Work::default(),
                elements: ElementAccumulator::default(),
                attestations: 0,
            },
        }
    }

    // --- Private manifest tests ---

    #[test]
    fn test_derive_manifest_deterministic() {
        let master = test_master();
        let (key1, sk1) = derive_manifest(&master, 0, 0).unwrap();
        let (key2, sk2) = derive_manifest(&master, 0, 0).unwrap();
        assert_eq!(key1.as_ref(), key2.as_ref());
        assert_eq!(sk1.public_key(), sk2.public_key());
    }

    #[test]
    fn test_derive_manifest_different_indices() {
        let master = test_master();
        let (_, sk0) = derive_manifest(&master, 0, 0).unwrap();
        let (_, sk1) = derive_manifest(&master, 0, 1).unwrap();
        assert_ne!(sk0.public_key(), sk1.public_key());
    }

    #[test]
    fn test_private_manifest_seal_open() {
        let master = test_master();
        let (key, _) = derive_manifest(&master, 0, 0).unwrap();

        let url = "sia://indexd.example.com/objects/abc123/shared?sv=2026-12-31";
        let sealed = seal_private_url(&key, url);

        assert_eq!(sealed[0], MANIFEST_VERSION);
        assert_eq!(sealed.len(), 1 + NONCE_SIZE + url.len() + 16);

        let opened = open_private_url(&key, &sealed).unwrap();
        assert_eq!(opened, url);
    }

    #[test]
    fn test_private_manifest_wrong_key() {
        let master = test_master();
        let (key0, _) = derive_manifest(&master, 0, 0).unwrap();
        let (key1, _) = derive_manifest(&master, 0, 1).unwrap();

        let sealed = seal_private_url(&key0, "sia://example.com");
        assert!(open_private_url(&key1, &sealed).is_none());
    }

    #[test]
    fn test_private_manifest_attestation() {
        let master = test_master();
        let (enc_key, sign_key) = derive_manifest(&master, 0, 0).unwrap();
        let cs = test_chain_state();

        let url = "sia://indexd.example.com/objects/abc123/shared";
        let att = private_manifest_attestation(&sign_key, &enc_key, url, &cs);

        assert_eq!(att.public_key, sign_key.public_key());
        assert_eq!(att.key, private_attestation_key(PRIVATE_MANIFEST_PATH));
        assert_ne!(att.signature, Signature::default());

        let recovered = open_private_url(&enc_key, &att.value).unwrap();
        assert_eq!(recovered, url);
    }

    #[test]
    fn test_private_manifest_transaction() {
        let master = test_master();
        let (enc_key, sign_key) = derive_manifest(&master, 0, 0).unwrap();
        let cs = test_chain_state();

        let url = "sia://example.com/shared";
        let txn = private_manifest_transaction(&sign_key, &enc_key, url, Currency::zero(), &cs);

        assert_eq!(txn.attestations.len(), 1);
        assert!(txn.siacoin_inputs.is_empty());
        assert!(txn.siacoin_outputs.is_empty());
        assert!(txn.arbitrary_data.is_empty());

        let recovered = open_private_url(&enc_key, &txn.attestations[0].value).unwrap();
        assert_eq!(recovered, url);
    }

    // --- Public manifest tests ---

    #[test]
    fn test_public_manifest_attestation() {
        let master = test_master();
        let sk = master.derive_path("m/44'/1991'/0'/0'/0'").unwrap().private_key();
        let cs = test_chain_state();

        let url = "sia://provider.example/objects/abc123/shared";
        let att = public_manifest_attestation(&sk, url, &cs);

        assert_eq!(att.public_key, sk.public_key());
        assert_eq!(att.key, PUBLIC_MANIFEST_KEY);
        assert_eq!(read_public_url(&att.value).unwrap(), url);
        assert_ne!(att.signature, Signature::default());
    }

    #[test]
    fn test_public_manifest_transaction() {
        let master = test_master();
        let sk = master.derive_path("m/44'/1991'/0'/0'/0'").unwrap().private_key();
        let cs = test_chain_state();

        let url = "sia://example.com/shared";
        let txn = public_manifest_transaction(&sk, url, Currency::zero(), &cs);

        assert_eq!(txn.attestations.len(), 1);
        assert!(txn.arbitrary_data.is_empty());
        assert_eq!(read_public_url(&txn.attestations[0].value).unwrap(), url);
    }

    // --- Channel manifest tests ---

    fn test_channel_key() -> EncryptionKey {
        EncryptionKey::from([0x42u8; 32])
    }

    #[test]
    fn test_channel_manifest_roundtrip() {
        let channel_key = test_channel_key();
        let url = "sia://provider.example/objects/premium/shared";

        let sealed = seal_channel_url(&channel_key, url);
        let recovered = open_channel_url(&channel_key, &sealed).unwrap();
        assert_eq!(recovered, url);
    }

    #[test]
    fn test_channel_manifest_wrong_key() {
        let channel_key = test_channel_key();
        let wrong_key = EncryptionKey::from([0xFFu8; 32]);

        let sealed = seal_channel_url(&channel_key, "sia://example.com");
        assert!(open_channel_url(&wrong_key, &sealed).is_none());
    }

    #[test]
    fn test_channel_manifest_attestation() {
        let master = test_master();
        let sk = master.derive_path("m/44'/1991'/0'/0'/0'").unwrap().private_key();
        let channel_key = test_channel_key();
        let cs = test_chain_state();

        let url = "sia://provider.example/premium";
        let att = channel_manifest_attestation(&sk, "premium", &channel_key, url, &cs);

        assert_eq!(att.public_key, sk.public_key());
        assert_eq!(att.key, ".sia/channel/premium");
        assert_ne!(att.signature, Signature::default());

        let recovered = open_channel_url(&channel_key, &att.value).unwrap();
        assert_eq!(recovered, url);
    }

    #[test]
    fn test_channel_key_string() {
        assert_eq!(channel_key_string("premium"), ".sia/channel/premium");
        assert_eq!(channel_key_string("photos"), ".sia/channel/photos");
    }

    // --- Group manifest tests ---

    fn test_group_secret() -> EncryptionKey {
        EncryptionKey::from([0xABu8; 32])
    }

    #[test]
    fn test_group_manifest_roundtrip() {
        let secret = test_group_secret();
        let url = "sia://provider.example/community/shared";

        let sealed = seal_group_url(&secret, url);
        let recovered = open_group_url(&secret, &sealed).unwrap();
        assert_eq!(recovered, url);
    }

    #[test]
    fn test_group_manifest_wrong_key() {
        let secret = test_group_secret();
        let wrong = EncryptionKey::from([0xCDu8; 32]);

        let sealed = seal_group_url(&secret, "sia://example.com");
        assert!(open_group_url(&wrong, &sealed).is_none());
    }

    #[test]
    fn test_group_manifest_attestation() {
        let master = test_master();
        let sk = master.derive_path("m/44'/1991'/0'/0'/0'").unwrap().private_key();
        let secret = test_group_secret();
        let cs = test_chain_state();

        let url = "sia://provider.example/alice/portfolio";
        let att = group_manifest_attestation(&sk, &secret, url, &cs);

        assert_eq!(att.public_key, sk.public_key());
        assert!(att.key.starts_with(GROUP_KEY_PREFIX));
        assert_ne!(att.signature, Signature::default());

        let recovered = open_group_url(&secret, &att.value).unwrap();
        assert_eq!(recovered, url);
    }

    #[test]
    fn test_group_key_string_deterministic() {
        let secret = test_group_secret();
        let key1 = group_key_string(secret.as_ref());
        let key2 = group_key_string(secret.as_ref());
        assert_eq!(key1, key2);
        assert!(key1.starts_with(GROUP_KEY_PREFIX));
    }

    #[test]
    fn test_group_key_string_differs_by_secret() {
        let s1 = EncryptionKey::from([0xABu8; 32]);
        let s2 = EncryptionKey::from([0xCDu8; 32]);
        assert_ne!(group_key_string(s1.as_ref()), group_key_string(s2.as_ref()));
    }

    #[test]
    fn test_group_multi_publisher() {
        let master = test_master();
        let sk_a = master.derive_path("m/44'/1991'/0'/0'/0'").unwrap().private_key();
        let sk_b = master.derive_path("m/44'/1991'/0'/0'/1'").unwrap().private_key();
        let secret = test_group_secret();
        let cs = test_chain_state();

        let att_a = group_manifest_attestation(&sk_a, &secret, "sia://alice", &cs);
        let att_b = group_manifest_attestation(&sk_b, &secret, "sia://bob", &cs);

        // Different publishers, same key string
        assert_ne!(att_a.public_key, att_b.public_key);
        assert_eq!(att_a.key, att_b.key);

        // Both decryptable with group secret
        assert_eq!(open_group_url(&secret, &att_a.value).unwrap(), "sia://alice");
        assert_eq!(open_group_url(&secret, &att_b.value).unwrap(), "sia://bob");
    }

    // --- Attestation key hash tests ---

    #[test]
    fn test_attestation_key_hash_deterministic() {
        let h1 = attestation_key_hash(".sia/manifest");
        let h2 = attestation_key_hash(".sia/manifest");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_attestation_key_hash_differs() {
        let h1 = attestation_key_hash(".sia/manifest");
        let h2 = attestation_key_hash(".sia/channel/premium");
        assert_ne!(h1, h2);
    }
}
