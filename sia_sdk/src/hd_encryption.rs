//! HD-derived encryption keys for Sia storage.
//!
//! Bridges BIP39/SLIP-0010 key derivation with Sia's XChaCha20 encryption.
//! A single seed phrase can produce wallet addresses and file encryption keys
//! from different HD path branches:
//!
//! ```text
//! m/44'/1991'/{account}'/0'/{i}'   → wallet addresses (standard Sia)
//! m/44'/19911'/{account}'/0'/{i}'  → file encryption keys (Sia storage)
//! ```

use crate::blake2::{Blake2b256, Digest};
use crate::encryption::EncryptionKey;
use crate::hd::{ExtendedPrivateKey, HdError};

/// BIP44 coin type for Sia wallet addresses.
pub const SIA_COIN_TYPE: u32 = 1991;

/// BIP44 coin type for Sia storage (encryption keys, contract keys).
/// Separate from wallet coin type to avoid key reuse across domains.
pub const SIA_STORAGE_COIN_TYPE: u32 = 19911;

/// HD path purpose index for file encryption keys within the storage branch.
pub const PURPOSE_ENCRYPTION: u32 = 0;

/// Derive the storage account-level extended key: `m/44'/19911'/{account}'`.
pub fn derive_account(
    master: &ExtendedPrivateKey,
    account: u32,
) -> Result<ExtendedPrivateKey, HdError> {
    master
        .derive_child(44)?
        .derive_child(SIA_STORAGE_COIN_TYPE)?
        .derive_child(account)
}

/// Derive a file encryption key at `m/44'/19911'/{account}'/0'/{index}'`.
///
/// The returned key is ready for use with `encrypt_shards`, `CipherReader`,
/// and `CipherWriter`.
pub fn derive_file_key(
    master: &ExtendedPrivateKey,
    account: u32,
    index: u32,
) -> Result<EncryptionKey, HdError> {
    let key = derive_account(master, account)?
        .derive_child(PURPOSE_ENCRYPTION)?
        .derive_child(index)?;
    Ok(EncryptionKey::from(*key.raw_private_key()))
}

/// Derive a file encryption key from a filename.
///
/// Hashes the name with Blake2b-256, takes the first 4 bytes as a
/// little-endian u32 masked to `< 2^31`, and uses that as the index.
/// The same filename always produces the same key.
///
/// Path: `m/44'/19911'/{account}'/0'/{hash(name) % 2^31}'`
pub fn derive_file_key_by_name(
    master: &ExtendedPrivateKey,
    account: u32,
    name: &str,
) -> Result<EncryptionKey, HdError> {
    let index = name_to_index(name);
    derive_file_key(master, account, index)
}

/// Batch-derive file encryption keys for indices `start..start+count`.
///
/// More efficient than calling `derive_file_key` in a loop — the intermediate
/// key at `m/44'/19911'/{account}'/1'` is derived once and reused.
pub fn derive_file_keys(
    master: &ExtendedPrivateKey,
    account: u32,
    start: u32,
    count: u32,
) -> Result<Vec<EncryptionKey>, HdError> {
    let purpose_key = derive_account(master, account)?.derive_child(PURPOSE_ENCRYPTION)?;
    let mut keys = Vec::with_capacity(count as usize);
    for i in 0..count {
        let child = purpose_key.derive_child(start + i)?;
        keys.push(EncryptionKey::from(*child.raw_private_key()));
    }
    Ok(keys)
}

/// Hash a filename to a deterministic child index (< 2^31).
///
/// Used by both `derive_file_key_by_name` and the manifest module's
/// `derive_manifest` to map well-known names to HD path indices.
// FIXME Alright - remove this - its from a previous implementation of manifests that is no longer
// applicable
pub(crate) fn name_to_index(name: &str) -> u32 {
    let mut hasher = Blake2b256::new();
    hasher.update(name.as_bytes());
    let hash = hasher.finalize();
    let idx = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
    idx & 0x7FFF_FFFF // mask to < 2^31 (valid for hardened derivation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::encrypt_shard;
    use crate::hd::HdMnemonic;

    fn test_master() -> ExtendedPrivateKey {
        let m = HdMnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        m.to_extended_key("")
    }

    #[test]
    fn test_deterministic() {
        let master = test_master();
        let k1 = derive_file_key(&master, 0, 0).unwrap();
        let k2 = derive_file_key(&master, 0, 0).unwrap();
        assert_eq!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn test_different_indices() {
        let master = test_master();
        let k0 = derive_file_key(&master, 0, 0).unwrap();
        let k1 = derive_file_key(&master, 0, 1).unwrap();
        assert_ne!(k0.as_ref(), k1.as_ref());
    }

    #[test]
    fn test_different_accounts() {
        let master = test_master();
        let k0 = derive_file_key(&master, 0, 0).unwrap();
        let k1 = derive_file_key(&master, 1, 0).unwrap();
        assert_ne!(k0.as_ref(), k1.as_ref());
    }

    #[test]
    fn test_encrypt_roundtrip() {
        let master = test_master();
        let key = derive_file_key(&master, 0, 0).unwrap();

        let original = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut data = original.clone();

        encrypt_shard(&key, 0, 0, &mut data);
        assert_ne!(data, original);

        encrypt_shard(&key, 0, 0, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_name_hashing_consistent() {
        let master = test_master();
        let k1 = derive_file_key_by_name(&master, 0, "photos/vacation.jpg").unwrap();
        let k2 = derive_file_key_by_name(&master, 0, "photos/vacation.jpg").unwrap();
        assert_eq!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn test_name_hashing_different_names() {
        let master = test_master();
        let k1 = derive_file_key_by_name(&master, 0, "file_a.txt").unwrap();
        let k2 = derive_file_key_by_name(&master, 0, "file_b.txt").unwrap();
        assert_ne!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn test_batch_matches_individual() {
        let master = test_master();
        let batch = derive_file_keys(&master, 0, 0, 5).unwrap();

        for i in 0..5u32 {
            let individual = derive_file_key(&master, 0, i).unwrap();
            assert_eq!(batch[i as usize].as_ref(), individual.as_ref());
        }
    }

    #[test]
    fn test_known_vector() {
        // Pin the output for "abandon..." seed, account 0, file key index 0
        // so future changes don't silently break derivation.
        let master = test_master();
        let key = derive_file_key(&master, 0, 0).unwrap();
        // If this ever changes, all previously encrypted files become unrecoverable.
        assert_eq!(
            hex::encode(key.as_ref()),
            // Derived: m/44'/19911'/0'/0'/0' from "abandon..." with empty passphrase
            "a6f828e10b8b0dc6165007bae8eb60fe24b0f1f11f07c73db1f2a8e93e51cf93",
        );
    }

    #[test]
    fn test_name_to_index_range() {
        // Verify index is always < 2^31
        for name in ["", "a", "test.txt", "very/long/path/to/file.dat", "🎉"] {
            let idx = name_to_index(name);
            assert!(idx < 0x80000000, "index {idx} >= 2^31 for name '{name}'");
        }
    }
}
