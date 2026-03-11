//! On-chain manifest pointers for Sia storage.
//!
//! A manifest pointer is a v2 transaction that stores a share URL (pointing
//! to the user's file manifest) directly on chain. This allows wallet recovery
//! from seed alone: scan the chain for transactions to the manifest address
//! and decrypt the latest one.
//!
//! Four manifest variants are supported:
//!
//! - **Private** (`derive_manifest`): encrypted with an HD-derived key; only the
//!   seed holder can discover and decrypt.
//! - **Public** (`public_manifest_address`): plaintext URL at a tweaked key
//!   address, discoverable by anyone who knows the publisher's public key.
//! - **Group** (`group_manifest_address`): encrypted with a shared group key;
//!   any member with the key can discover and decrypt.
//! - **Channel** (`seal_channel_manifest_url`): encrypted with a per-channel key
//!   distributed to subscribers; publisher identity is verified by input checking.

use chacha20poly1305::aead::{Aead, OsRng};
use chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305};

use crate::encryption::EncryptionKey;
use crate::hd::{ExtendedPrivateKey, HdError};
use crate::hd_encryption::{derive_account, name_to_index, PURPOSE_ENCRYPTION};
use crate::signing::PrivateKey;
use crate::types::v1::UnlockConditions;
use crate::types::{Address, Currency, SiacoinOutput, Specifier, SPECIFIER_SIZE};
use crate::types::v2;
use crate::specifier;

const NONCE_SIZE: usize = 24;
/// Minimum size of a valid manifest pointer payload:
/// specifier (16) + version (1) + nonce (24) + poly1305 tag (16) + at least 1 byte ciphertext.
const MANIFEST_HEADER_SIZE: usize = SPECIFIER_SIZE + 1 + NONCE_SIZE;

// ---------------------------------------------------------------------------
// Private manifests — discoverable and readable only with the seed
// ---------------------------------------------------------------------------

/// Well-known name used to derive the manifest key and address.
pub const MANIFEST_NAME: &str = ".sia/manifest";

/// Specifier identifying manifest pointer data in `arbitrary_data`.
pub const MANIFEST_SPECIFIER: Specifier = specifier!["manifest"];

/// Current manifest pointer format version.
pub const MANIFEST_VERSION: u8 = 1;

/// Derive the manifest encryption key and address.
///
/// The encryption key encrypts/decrypts the share URL stored in `arbitrary_data`.
/// The address receives the pointer transaction (0 SC output).
///
/// Path: `m/44'/19911'/{account}'/0'/{hash(".sia/manifest")}'`
pub fn derive_manifest(
    master: &ExtendedPrivateKey,
    account: u32,
) -> Result<(EncryptionKey, Address), HdError> {
    let index = name_to_index(MANIFEST_NAME);
    let key = derive_account(master, account)?
        .derive_child(PURPOSE_ENCRYPTION)?
        .derive_child(index)?;

    let encryption_key = EncryptionKey::from(*key.raw_private_key());
    let private_key = key.private_key();
    let address = UnlockConditions::standard_unlock_conditions(private_key.public_key()).address();

    Ok((encryption_key, address))
}

/// Check whether `arbitrary_data` begins with the manifest pointer specifier.
pub fn is_manifest_pointer(data: &[u8]) -> bool {
    data.len() > MANIFEST_HEADER_SIZE
        && data[..SPECIFIER_SIZE] == *MANIFEST_SPECIFIER.as_ref()
}

/// Encrypt a share URL with the manifest encryption key (XChaCha20-Poly1305).
///
/// Wire format:
/// ```text
/// [specifier: 16 bytes "manifest\0..."] [version: 1 byte] [nonce: 24 bytes] [ciphertext + tag]
/// ```
///
/// AEAD authentication ensures that only transactions created by the seed
/// holder will decrypt successfully, allowing recovery to skip spam.
pub fn seal_manifest_url(key: &EncryptionKey, url: &str) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, url.as_bytes())
        .expect("encryption failed");

    let mut out = Vec::with_capacity(MANIFEST_HEADER_SIZE + ciphertext.len());
    out.extend_from_slice(MANIFEST_SPECIFIER.as_ref());
    out.push(MANIFEST_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt a share URL from `arbitrary_data` using the manifest encryption key.
///
/// Validates the specifier header and version before attempting decryption.
/// Returns `None` if the data is not a manifest pointer, the version is
/// unsupported, or decryption fails (wrong key, tampered data, spam).
pub fn open_manifest_url(key: &EncryptionKey, data: &[u8]) -> Option<String> {
    if !is_manifest_pointer(data) {
        return None;
    }
    let version = data[SPECIFIER_SIZE];
    if version != MANIFEST_VERSION {
        return None;
    }
    let payload = &data[SPECIFIER_SIZE + 1..];
    let (nonce_bytes, ciphertext) = payload.split_at(NONCE_SIZE);
    let nonce_arr: [u8; NONCE_SIZE] = nonce_bytes.try_into().ok()?;
    let nonce = chacha20poly1305::XNonce::from(nonce_arr);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plaintext = cipher.decrypt(&nonce, ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}

/// Build a v2 manifest pointer transaction.
///
/// Creates a transaction with:
/// - A 0 SC output to the manifest address
/// - The encrypted share URL in `arbitrary_data`
///
/// The caller must add `siacoin_inputs` (to cover `miner_fee`) and sign.
pub fn manifest_pointer_transaction(
    manifest_address: Address,
    encrypted_url: Vec<u8>,
    miner_fee: Currency,
) -> v2::Transaction {
    v2::Transaction {
        siacoin_outputs: vec![SiacoinOutput {
            value: Currency::zero(),
            address: manifest_address,
        }],
        arbitrary_data: encrypted_url,
        miner_fee,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Public manifests — discoverable by anyone who knows the publisher's public key
// ---------------------------------------------------------------------------

/// Specifier identifying public manifest pointer data in `arbitrary_data`.
pub const PUBLIC_MANIFEST_SPECIFIER: Specifier = specifier!["pubmanifest"];

/// Topic bytes used for the additive key tweak.
pub const PUBLIC_MANIFEST_TOPIC: &[u8] = b".sia/manifest";

/// Derive the public manifest address from any ed25519 public key.
///
/// Computes `P' = P + H(P || ".sia/manifest") * G` and returns the
/// standard v2 address for the tweaked key. Anyone who knows the
/// original public key can compute this independently.
pub fn public_manifest_address(
    public_key: &crate::signing::PublicKey,
) -> Option<Address> {
    let tweaked = public_key.tweak(PUBLIC_MANIFEST_TOPIC)?;
    Some(v2::SpendPolicy::PublicKey(tweaked).address())
}

/// Build a public manifest pointer transaction.
///
/// The payload is stored in **plaintext** (prefixed with the `"pubmanifest"`
/// specifier and a version byte for identification). The caller must add
/// `siacoin_inputs` (to cover `miner_fee`) and sign with `sign_tweaked`.
pub fn public_manifest_pointer_transaction(
    manifest_address: Address,
    url: &str,
    miner_fee: Currency,
) -> v2::Transaction {
    let mut payload = Vec::with_capacity(SPECIFIER_SIZE + 1 + url.len());
    payload.extend_from_slice(PUBLIC_MANIFEST_SPECIFIER.as_ref());
    payload.push(MANIFEST_VERSION);
    payload.extend_from_slice(url.as_bytes());

    v2::Transaction {
        siacoin_outputs: vec![SiacoinOutput {
            value: Currency::zero(),
            address: manifest_address,
        }],
        arbitrary_data: payload,
        miner_fee,
        ..Default::default()
    }
}

/// Check whether `arbitrary_data` begins with the public manifest specifier.
pub fn is_public_manifest_pointer(data: &[u8]) -> bool {
    data.len() > SPECIFIER_SIZE + 1
        && data[..SPECIFIER_SIZE] == *PUBLIC_MANIFEST_SPECIFIER.as_ref()
}

/// Extract the URL from a public manifest pointer's `arbitrary_data`.
///
/// Returns `None` if the data is not a valid public manifest pointer.
pub fn read_public_manifest_url(data: &[u8]) -> Option<String> {
    if !is_public_manifest_pointer(data) {
        return None;
    }
    let version = data[SPECIFIER_SIZE];
    if version != MANIFEST_VERSION {
        return None;
    }
    String::from_utf8(data[SPECIFIER_SIZE + 1..].to_vec()).ok()
}

/// Verify that a public manifest transaction was authored by the publisher.
///
/// Checks that at least one siacoin input comes from `address(P)` — the
/// standard unlock address of the publisher's known public key. This proves
/// authorship without requiring an extra signature in the payload.
///
/// Returns the URL if verification passes, `None` otherwise.
pub fn verify_public_manifest(
    publisher_key: &crate::signing::PublicKey,
    txn: &v2::Transaction,
) -> Option<String> {
    let url = read_public_manifest_url(&txn.arbitrary_data)?;

    let publisher_address = v2::SpendPolicy::PublicKey(*publisher_key).address();
    let has_publisher_input = txn.siacoin_inputs.iter().any(|input| {
        input.parent.siacoin_output.address == publisher_address
    });

    if has_publisher_input {
        Some(url)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Group manifests — discoverable and readable only with the group key
// ---------------------------------------------------------------------------

/// Specifier identifying group-encrypted manifest pointer data.
pub const GROUP_MANIFEST_SPECIFIER: Specifier = specifier!["grpmanifest"];

/// Derive the group manifest address from a group key.
///
/// The group key is treated as an ed25519 seed — its corresponding public key
/// determines the on-chain address. The group key alone is sufficient for both
/// discovery (deriving the address) and decryption (unlocking the payload).
///
/// Multiple publishers can post to the same group address if they all have
/// the group key. Rotating the key produces a new address — old key holders
/// can still read historical posts but won't find new ones.
pub fn group_manifest_address(group_key: &EncryptionKey) -> Address {
    let sk = PrivateKey::from_seed(group_key.as_ref());
    let pk = sk.public_key();
    v2::SpendPolicy::PublicKey(pk).address()
}

/// Encrypt a share URL with a group key (XChaCha20-Poly1305).
///
/// Wire format:
/// ```text
/// [specifier: 16 bytes "grpmanifest\0.."] [version: 1 byte] [nonce: 24 bytes] [ciphertext + tag]
/// ```
///
/// The on-chain address is derived from the same group key via
/// `group_manifest_address`. The group key alone is sufficient for both
/// discovery and decryption.
pub fn seal_group_manifest_url(group_key: &EncryptionKey, url: &str) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(group_key.as_ref().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, url.as_bytes())
        .expect("encryption failed");

    let mut out = Vec::with_capacity(SPECIFIER_SIZE + 1 + NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(GROUP_MANIFEST_SPECIFIER.as_ref());
    out.push(MANIFEST_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt a share URL from group-encrypted `arbitrary_data`.
///
/// Returns `None` if the data is not a group manifest pointer, the version
/// is unsupported, or decryption fails (wrong key).
pub fn open_group_manifest_url(group_key: &EncryptionKey, data: &[u8]) -> Option<String> {
    if !is_group_manifest_pointer(data) {
        return None;
    }
    let version = data[SPECIFIER_SIZE];
    if version != MANIFEST_VERSION {
        return None;
    }
    let payload = &data[SPECIFIER_SIZE + 1..];
    let (nonce_bytes, ciphertext) = payload.split_at(NONCE_SIZE);
    let nonce_arr: [u8; NONCE_SIZE] = nonce_bytes.try_into().ok()?;
    let nonce = chacha20poly1305::XNonce::from(nonce_arr);
    let cipher = XChaCha20Poly1305::new(group_key.as_ref().into());
    let plaintext = cipher.decrypt(&nonce, ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}

/// Check whether `arbitrary_data` begins with the group manifest specifier.
pub fn is_group_manifest_pointer(data: &[u8]) -> bool {
    data.len() > MANIFEST_HEADER_SIZE
        && data[..SPECIFIER_SIZE] == *GROUP_MANIFEST_SPECIFIER.as_ref()
}

/// Build a group manifest pointer transaction.
///
/// Takes pre-sealed (encrypted) data from `seal_group_manifest_url`.
/// Use `group_manifest_address` to derive the destination address from
/// the group key. The caller must add `siacoin_inputs` and sign.
pub fn group_manifest_pointer_transaction(
    manifest_address: Address,
    sealed_url: Vec<u8>,
    miner_fee: Currency,
) -> v2::Transaction {
    v2::Transaction {
        siacoin_outputs: vec![SiacoinOutput {
            value: Currency::zero(),
            address: manifest_address,
        }],
        arbitrary_data: sealed_url,
        miner_fee,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Channel manifests — single publisher, multiple subscribers (paid content)
// ---------------------------------------------------------------------------

/// Specifier identifying channel-encrypted manifest pointer data.
pub const CHANNEL_MANIFEST_SPECIFIER: Specifier = specifier!["chnmanifest"];

/// Encrypt a share URL with a channel key (XChaCha20-Poly1305).
///
/// Wire format:
/// ```text
/// [specifier: 16 bytes "chnmanifest\0.."] [version: 1 byte] [nonce: 24 bytes] [ciphertext + tag]
/// ```
///
/// The on-chain address is the publisher's tweaked address (same as public
/// manifests), derived via `public_manifest_address`. Only the publisher can
/// post (verified via input checking), but any channel key holder can decrypt.
pub fn seal_channel_manifest_url(channel_key: &EncryptionKey, url: &str) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(channel_key.as_ref().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, url.as_bytes())
        .expect("encryption failed");

    let mut out = Vec::with_capacity(SPECIFIER_SIZE + 1 + NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(CHANNEL_MANIFEST_SPECIFIER.as_ref());
    out.push(MANIFEST_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt a share URL from channel-encrypted `arbitrary_data`.
///
/// Returns `None` if the data is not a channel manifest pointer, the version
/// is unsupported, or decryption fails (wrong key).
pub fn open_channel_manifest_url(channel_key: &EncryptionKey, data: &[u8]) -> Option<String> {
    if !is_channel_manifest_pointer(data) {
        return None;
    }
    let version = data[SPECIFIER_SIZE];
    if version != MANIFEST_VERSION {
        return None;
    }
    let payload = &data[SPECIFIER_SIZE + 1..];
    let (nonce_bytes, ciphertext) = payload.split_at(NONCE_SIZE);
    let nonce_arr: [u8; NONCE_SIZE] = nonce_bytes.try_into().ok()?;
    let nonce = chacha20poly1305::XNonce::from(nonce_arr);
    let cipher = XChaCha20Poly1305::new(channel_key.as_ref().into());
    let plaintext = cipher.decrypt(&nonce, ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}

/// Check whether `arbitrary_data` begins with the channel manifest specifier.
pub fn is_channel_manifest_pointer(data: &[u8]) -> bool {
    data.len() > MANIFEST_HEADER_SIZE
        && data[..SPECIFIER_SIZE] == *CHANNEL_MANIFEST_SPECIFIER.as_ref()
}

/// Build a channel manifest pointer transaction.
///
/// Uses the publisher's tweaked address (from `public_manifest_address`) as
/// the destination. The payload is encrypted with the channel key. The caller
/// must add `siacoin_inputs` from the publisher's identity address and sign
/// with `sign_tweaked`.
pub fn channel_manifest_pointer_transaction(
    manifest_address: Address,
    sealed_url: Vec<u8>,
    miner_fee: Currency,
) -> v2::Transaction {
    v2::Transaction {
        siacoin_outputs: vec![SiacoinOutput {
            value: Currency::zero(),
            address: manifest_address,
        }],
        arbitrary_data: sealed_url,
        miner_fee,
        ..Default::default()
    }
}

/// Verify and decrypt a channel manifest transaction.
///
/// Combines publisher verification (at least one input from `address(P)`)
/// with channel key decryption. Returns the URL only if:
/// 1. The payload has the channel manifest specifier
/// 2. At least one siacoin input comes from the publisher's address
/// 3. The payload decrypts successfully with the channel key
pub fn verify_channel_manifest(
    publisher_key: &crate::signing::PublicKey,
    channel_key: &EncryptionKey,
    txn: &v2::Transaction,
) -> Option<String> {
    if !is_channel_manifest_pointer(&txn.arbitrary_data) {
        return None;
    }

    let publisher_address = v2::SpendPolicy::PublicKey(*publisher_key).address();
    let has_publisher_input = txn.siacoin_inputs.iter().any(|input| {
        input.parent.siacoin_output.address == publisher_address
    });

    if !has_publisher_input {
        return None;
    }

    open_channel_manifest_url(channel_key, &txn.arbitrary_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::HdMnemonic;

    fn test_master() -> crate::hd::ExtendedPrivateKey {
        let m = HdMnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        m.to_extended_key("")
    }

    #[test]
    fn test_manifest_deterministic() {
        let master = test_master();
        let (key1, addr1) = derive_manifest(&master, 0).unwrap();
        let (key2, addr2) = derive_manifest(&master, 0).unwrap();
        assert_eq!(key1.as_ref(), key2.as_ref());
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_manifest_different_accounts() {
        let master = test_master();
        let (_, addr0) = derive_manifest(&master, 0).unwrap();
        let (_, addr1) = derive_manifest(&master, 1).unwrap();
        assert_ne!(addr0, addr1);
    }

    #[test]
    fn test_seal_open_manifest_url() {
        let master = test_master();
        let (key, _) = derive_manifest(&master, 0).unwrap();

        let url = "sia://indexd.example.com/objects/abc123/shared?sv=2026-12-31";
        let sealed = seal_manifest_url(&key, url);

        // Verify header structure
        assert!(is_manifest_pointer(&sealed));
        assert_eq!(sealed[SPECIFIER_SIZE], MANIFEST_VERSION);
        // specifier(16) + version(1) + nonce(24) + ciphertext + tag(16)
        assert_eq!(sealed.len(), MANIFEST_HEADER_SIZE + url.len() + 16);

        let opened = open_manifest_url(&key, &sealed).unwrap();
        assert_eq!(opened, url);
    }

    #[test]
    fn test_is_manifest_pointer() {
        let master = test_master();
        let (key, _) = derive_manifest(&master, 0).unwrap();

        let sealed = seal_manifest_url(&key, "sia://example.com");
        assert!(is_manifest_pointer(&sealed));

        // Random data should not match
        assert!(!is_manifest_pointer(b"not a manifest pointer"));
        assert!(!is_manifest_pointer(&[]));
    }

    #[test]
    fn test_open_manifest_url_wrong_key() {
        let master = test_master();
        let (key0, _) = derive_manifest(&master, 0).unwrap();
        let (key1, _) = derive_manifest(&master, 1).unwrap();

        let sealed = seal_manifest_url(&key0, "sia://example.com/share/abc");
        // Wrong key must fail (AEAD auth check)
        assert!(open_manifest_url(&key1, &sealed).is_none());
    }

    #[test]
    fn test_open_manifest_url_tampered() {
        let master = test_master();
        let (key, _) = derive_manifest(&master, 0).unwrap();

        let mut sealed = seal_manifest_url(&key, "sia://example.com/share/abc");
        // Flip a byte in the ciphertext
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(open_manifest_url(&key, &sealed).is_none());
    }

    #[test]
    fn test_manifest_pointer_transaction() {
        let master = test_master();
        let (key, addr) = derive_manifest(&master, 0).unwrap();

        let url = "sia://indexd.example.com/objects/abc123/shared";
        let sealed = seal_manifest_url(&key, url);
        let txn = manifest_pointer_transaction(
            addr.clone(),
            sealed.clone(),
            Currency::zero(),
        );

        assert_eq!(txn.siacoin_outputs.len(), 1);
        assert_eq!(txn.siacoin_outputs[0].value, Currency::zero());
        assert_eq!(txn.siacoin_outputs[0].address, addr);
        assert_eq!(txn.arbitrary_data, sealed);
        assert!(txn.siacoin_inputs.is_empty());

        // Verify we can decrypt the URL from the transaction
        let recovered = open_manifest_url(&key, &txn.arbitrary_data).unwrap();
        assert_eq!(recovered, url);
    }

    // --- Public manifest tests ---

    #[test]
    fn test_public_manifest_address_deterministic() {
        let master = test_master();
        let pk = master
            .derive_path("m/44'/1991'/0'/0'/0'")
            .unwrap()
            .public_key();

        let addr1 = public_manifest_address(&pk).unwrap();
        let addr2 = public_manifest_address(&pk).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_public_manifest_address_differs_from_original() {
        let master = test_master();
        let child = master.derive_path("m/44'/1991'/0'/0'/0'").unwrap();
        let pk = child.public_key();
        let original_addr = crate::types::v2::SpendPolicy::PublicKey(pk).address();
        let manifest_addr = public_manifest_address(&pk).unwrap();
        assert_ne!(original_addr, manifest_addr);
    }

    #[test]
    fn test_public_manifest_roundtrip() {
        let master = test_master();
        let child = master.derive_path("m/44'/1991'/0'/0'/0'").unwrap();
        let pk = child.public_key();
        let sk = child.private_key();

        let addr = public_manifest_address(&pk).unwrap();
        let url = "sia://provider.example/objects/abc123/shared";

        let txn = public_manifest_pointer_transaction(addr.clone(), url, Currency::zero());

        // Payload is plaintext — anyone can read it
        assert!(is_public_manifest_pointer(&txn.arbitrary_data));
        let recovered = read_public_manifest_url(&txn.arbitrary_data).unwrap();
        assert_eq!(recovered, url);

        // The transaction can be signed with the tweaked key
        let sig_hash = b"test signing hash";
        let sig = sk.sign_tweaked(PUBLIC_MANIFEST_TOPIC, sig_hash);
        let tweaked_pk = pk.tweak(PUBLIC_MANIFEST_TOPIC).unwrap();
        assert!(tweaked_pk.verify(sig_hash, &sig));
    }

    #[test]
    fn test_public_manifest_different_keys() {
        let master = test_master();
        let pk0 = master
            .derive_path("m/44'/1991'/0'/0'/0'")
            .unwrap()
            .public_key();
        let pk1 = master
            .derive_path("m/44'/1991'/0'/0'/1'")
            .unwrap()
            .public_key();

        let addr0 = public_manifest_address(&pk0).unwrap();
        let addr1 = public_manifest_address(&pk1).unwrap();
        assert_ne!(addr0, addr1);
    }

    #[test]
    fn test_verify_public_manifest() {
        use crate::types::{StateElement, SiacoinOutputID};

        let master = test_master();
        let child = master.derive_path("m/44'/1991'/0'/0'/0'").unwrap();
        let pk = child.public_key();

        let addr = public_manifest_address(&pk).unwrap();
        let url = "sia://provider.example/objects/abc123/shared";

        let mut txn = public_manifest_pointer_transaction(addr.clone(), url, Currency::zero());

        // Without any inputs, verification should fail (no proof of authorship)
        assert!(verify_public_manifest(&pk, &txn).is_none());

        // Add an input from the publisher's address
        let publisher_address = v2::SpendPolicy::PublicKey(pk).address();
        txn.siacoin_inputs.push(v2::SiacoinInput {
            parent: v2::SiacoinElement {
                state_element: StateElement {
                    leaf_index: 0,
                    merkle_proof: vec![],
                },
                id: SiacoinOutputID::default(),
                siacoin_output: SiacoinOutput {
                    value: Currency::zero(),
                    address: publisher_address,
                },
                maturity_height: 0,
            },
            satisfied_policy: v2::SatisfiedPolicy {
                policy: v2::SpendPolicy::PublicKey(pk),
                signatures: vec![],
                preimages: vec![],
            },
        });

        // Now verification should pass
        let recovered = verify_public_manifest(&pk, &txn).unwrap();
        assert_eq!(recovered, url);

        // A different key should fail verification (wrong publisher)
        let other_pk = master
            .derive_path("m/44'/1991'/0'/0'/1'")
            .unwrap()
            .public_key();
        assert!(verify_public_manifest(&other_pk, &txn).is_none());
    }

    #[test]
    fn test_public_manifest_not_private_manifest() {
        // Public manifest specifier should not match private manifest checks
        let url = "sia://example.com/shared";
        let master = test_master();
        let pk = master
            .derive_path("m/44'/1991'/0'/0'/0'")
            .unwrap()
            .public_key();
        let addr = public_manifest_address(&pk).unwrap();
        let txn = public_manifest_pointer_transaction(addr, url, Currency::zero());

        assert!(is_public_manifest_pointer(&txn.arbitrary_data));
        assert!(!is_manifest_pointer(&txn.arbitrary_data));
    }

    // --- Group manifest tests ---

    fn test_group_key() -> EncryptionKey {
        // A shared group key (in practice distributed out-of-band)
        EncryptionKey::from([0xABu8; 32])
    }

    #[test]
    fn test_group_manifest_address_deterministic() {
        let group_key = test_group_key();
        let addr1 = group_manifest_address(&group_key);
        let addr2 = group_manifest_address(&group_key);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_group_manifest_address_differs_by_key() {
        let key1 = EncryptionKey::from([0xABu8; 32]);
        let key2 = EncryptionKey::from([0xCDu8; 32]);
        assert_ne!(group_manifest_address(&key1), group_manifest_address(&key2));
    }

    #[test]
    fn test_group_manifest_roundtrip() {
        let group_key = test_group_key();
        let url = "sia://provider.example/objects/community/shared";

        let sealed = seal_group_manifest_url(&group_key, url);
        assert!(is_group_manifest_pointer(&sealed));
        assert!(!is_public_manifest_pointer(&sealed));
        assert!(!is_manifest_pointer(&sealed));

        let recovered = open_group_manifest_url(&group_key, &sealed).unwrap();
        assert_eq!(recovered, url);
    }

    #[test]
    fn test_group_manifest_wrong_key_fails() {
        let group_key = test_group_key();
        let wrong_key = EncryptionKey::from([0xCDu8; 32]);
        let url = "sia://example.com/shared";

        let sealed = seal_group_manifest_url(&group_key, url);
        assert!(open_group_manifest_url(&wrong_key, &sealed).is_none());
    }

    #[test]
    fn test_group_manifest_tampered_fails() {
        let group_key = test_group_key();
        let mut sealed = seal_group_manifest_url(&group_key, "sia://example.com");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(open_group_manifest_url(&group_key, &sealed).is_none());
    }

    #[test]
    fn test_group_manifest_full_flow() {
        // Two community members publish to the same group address
        let group_key = test_group_key();
        let addr = group_manifest_address(&group_key);

        // Publisher A posts their manifest
        let url_a = "sia://provider.example/alice/portfolio";
        let sealed_a = seal_group_manifest_url(&group_key, url_a);
        let txn_a = group_manifest_pointer_transaction(addr.clone(), sealed_a, Currency::zero());

        // Publisher B posts their manifest to the same address
        let url_b = "sia://provider.example/bob/portfolio";
        let sealed_b = seal_group_manifest_url(&group_key, url_b);
        let txn_b = group_manifest_pointer_transaction(addr.clone(), sealed_b, Currency::zero());

        // Same destination address for both
        assert_eq!(
            txn_a.siacoin_outputs[0].address,
            txn_b.siacoin_outputs[0].address,
        );

        // Any group member can decrypt both
        let recovered_a = open_group_manifest_url(&group_key, &txn_a.arbitrary_data).unwrap();
        let recovered_b = open_group_manifest_url(&group_key, &txn_b.arbitrary_data).unwrap();
        assert_eq!(recovered_a, url_a);
        assert_eq!(recovered_b, url_b);

        // Outsider with wrong key can't decrypt either
        let outsider_key = EncryptionKey::from([0xFFu8; 32]);
        assert!(open_group_manifest_url(&outsider_key, &txn_a.arbitrary_data).is_none());
    }

    #[test]
    fn test_group_manifest_key_rotation() {
        // Rotating the group key produces a new address
        let old_key = EncryptionKey::from([0xABu8; 32]);
        let new_key = EncryptionKey::from([0xCDu8; 32]);

        let old_addr = group_manifest_address(&old_key);
        let new_addr = group_manifest_address(&new_key);
        assert_ne!(old_addr, new_addr);

        // Old key holders can still read old posts
        let url = "sia://example.com/shared";
        let sealed = seal_group_manifest_url(&old_key, url);
        assert_eq!(open_group_manifest_url(&old_key, &sealed).unwrap(), url);

        // But they won't find new posts (different address)
        // and can't decrypt new posts (different key)
        let new_sealed = seal_group_manifest_url(&new_key, "sia://example.com/new");
        assert!(open_group_manifest_url(&old_key, &new_sealed).is_none());
    }

    // --- Channel manifest tests ---

    fn test_channel_key() -> EncryptionKey {
        EncryptionKey::from([0x42u8; 32])
    }

    #[test]
    fn test_channel_manifest_roundtrip() {
        let channel_key = test_channel_key();
        let url = "sia://provider.example/objects/premium/shared";

        let sealed = seal_channel_manifest_url(&channel_key, url);
        assert!(is_channel_manifest_pointer(&sealed));
        assert!(!is_public_manifest_pointer(&sealed));
        assert!(!is_group_manifest_pointer(&sealed));
        assert!(!is_manifest_pointer(&sealed));

        let recovered = open_channel_manifest_url(&channel_key, &sealed).unwrap();
        assert_eq!(recovered, url);
    }

    #[test]
    fn test_channel_manifest_wrong_key_fails() {
        let channel_key = test_channel_key();
        let wrong_key = EncryptionKey::from([0xFFu8; 32]);
        let url = "sia://example.com/shared";

        let sealed = seal_channel_manifest_url(&channel_key, url);
        assert!(open_channel_manifest_url(&wrong_key, &sealed).is_none());
    }

    #[test]
    fn test_channel_manifest_tampered_fails() {
        let channel_key = test_channel_key();
        let mut sealed = seal_channel_manifest_url(&channel_key, "sia://example.com");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(open_channel_manifest_url(&channel_key, &sealed).is_none());
    }

    #[test]
    fn test_verify_channel_manifest() {
        use crate::types::{StateElement, SiacoinOutputID};

        let master = test_master();
        let child = master.derive_path("m/44'/1991'/0'/0'/0'").unwrap();
        let pk = child.public_key();
        let channel_key = test_channel_key();

        let addr = public_manifest_address(&pk).unwrap();
        let url = "sia://provider.example/objects/premium/shared";

        let sealed = seal_channel_manifest_url(&channel_key, url);
        let mut txn = channel_manifest_pointer_transaction(addr.clone(), sealed, Currency::zero());

        // Without publisher input, verification fails
        assert!(verify_channel_manifest(&pk, &channel_key, &txn).is_none());

        // Add publisher input
        let publisher_address = v2::SpendPolicy::PublicKey(pk).address();
        txn.siacoin_inputs.push(v2::SiacoinInput {
            parent: v2::SiacoinElement {
                state_element: StateElement {
                    leaf_index: 0,
                    merkle_proof: vec![],
                },
                id: SiacoinOutputID::default(),
                siacoin_output: SiacoinOutput {
                    value: Currency::zero(),
                    address: publisher_address,
                },
                maturity_height: 0,
            },
            satisfied_policy: v2::SatisfiedPolicy {
                policy: v2::SpendPolicy::PublicKey(pk),
                signatures: vec![],
                preimages: vec![],
            },
        });

        // Now verification passes
        let recovered = verify_channel_manifest(&pk, &channel_key, &txn).unwrap();
        assert_eq!(recovered, url);

        // Wrong publisher key fails
        let other_pk = master
            .derive_path("m/44'/1991'/0'/0'/1'")
            .unwrap()
            .public_key();
        assert!(verify_channel_manifest(&other_pk, &channel_key, &txn).is_none());

        // Wrong channel key fails
        let wrong_channel_key = EncryptionKey::from([0xFFu8; 32]);
        assert!(verify_channel_manifest(&pk, &wrong_channel_key, &txn).is_none());
    }

    #[test]
    fn test_channel_manifest_uses_public_address() {
        // Channel uses the same tweaked address as public manifests
        let master = test_master();
        let pk = master
            .derive_path("m/44'/1991'/0'/0'/0'")
            .unwrap()
            .public_key();
        let channel_key = test_channel_key();

        let public_addr = public_manifest_address(&pk).unwrap();
        let channel_addr = public_manifest_address(&pk).unwrap(); // same derivation

        assert_eq!(public_addr, channel_addr);

        // But the payloads are different (encrypted vs plaintext)
        let pub_txn = public_manifest_pointer_transaction(
            public_addr.clone(),
            "sia://example.com",
            Currency::zero(),
        );
        let sealed = seal_channel_manifest_url(&channel_key, "sia://example.com");
        let chn_txn = channel_manifest_pointer_transaction(
            channel_addr,
            sealed,
            Currency::zero(),
        );

        assert!(is_public_manifest_pointer(&pub_txn.arbitrary_data));
        assert!(!is_channel_manifest_pointer(&pub_txn.arbitrary_data));
        assert!(is_channel_manifest_pointer(&chn_txn.arbitrary_data));
        assert!(!is_public_manifest_pointer(&chn_txn.arbitrary_data));
    }
}
