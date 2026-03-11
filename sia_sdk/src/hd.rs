use std::fmt;

use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use thiserror::Error;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::signing::{PrivateKey, PublicKey};

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, PartialEq, Error)]
pub enum HdError {
    #[error("invalid word count: {0} (must be 12, 15, 18, 21, or 24)")]
    InvalidWordCount(usize),

    #[error("failed to parse mnemonic: {0}")]
    MnemonicError(#[from] bip39::Error),

    #[error("invalid derivation path: {0}")]
    InvalidPath(String),

    #[error("ed25519 only supports hardened derivation, segment {0} is not hardened")]
    UnhardenedDerivation(u32),

    #[error("child index overflow (must be < 2^31)")]
    IndexOverflow,
}

/// A BIP39 mnemonic phrase that can produce a standard 512-bit seed.
///
/// This is distinct from [`crate::seed::Seed`] which uses Sia's custom
/// Blake2b-based key derivation. This type follows the BIP39 standard:
/// mnemonic → PBKDF2-HMAC-SHA512 → 512-bit seed.
#[derive(ZeroizeOnDrop)]
pub struct HdMnemonic {
    mnemonic: Mnemonic,
}

impl HdMnemonic {
    /// Generate a new BIP39 mnemonic with the specified word count.
    ///
    /// Supported word counts: 12, 15, 18, 21, 24.
    pub fn generate(word_count: usize) -> Result<Self, HdError> {
        if ![12, 15, 18, 21, 24].contains(&word_count) {
            return Err(HdError::InvalidWordCount(word_count));
        }
        let entropy_bytes = (word_count / 3) * 4;
        let mut entropy = Zeroizing::new(vec![0u8; entropy_bytes]);
        rand::fill(&mut entropy[..]);
        let mnemonic = Mnemonic::from_entropy(&entropy)?;
        Ok(Self { mnemonic })
    }

    /// Parse an existing BIP39 mnemonic phrase.
    pub fn from_phrase(phrase: &str) -> Result<Self, HdError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)?;
        Ok(Self { mnemonic })
    }

    /// Create an HdMnemonic from raw entropy bytes.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, HdError> {
        let mnemonic = Mnemonic::from_entropy(entropy)?;
        Ok(Self { mnemonic })
    }

    /// Derive the 512-bit BIP39 seed using PBKDF2-HMAC-SHA512.
    ///
    /// Pass `""` for no passphrase.
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        self.mnemonic.to_seed(passphrase)
    }

    /// Derive a SLIP-0010 master extended private key for ed25519.
    pub fn to_extended_key(&self, passphrase: &str) -> ExtendedPrivateKey {
        let seed = Zeroizing::new(self.to_seed(passphrase));
        ExtendedPrivateKey::from_bip39_seed(&seed)
    }

    /// Return the mnemonic phrase as a string.
    pub fn phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Return the raw entropy bytes.
    pub fn entropy(&self) -> Vec<u8> {
        self.mnemonic.to_entropy()
    }
}

impl fmt::Display for HdMnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mnemonic)
    }
}

/// A SLIP-0010 extended private key for ed25519.
///
/// Contains a 32-byte private key (ed25519 seed) and a 32-byte chain code.
/// Only hardened derivation is supported (as required by SLIP-0010 for ed25519).
#[derive(Clone, ZeroizeOnDrop)]
pub struct ExtendedPrivateKey {
    private_key: [u8; 32],
    chain_code: [u8; 32],
}

impl ExtendedPrivateKey {
    /// Derive a SLIP-0010 master key from an arbitrary-length seed.
    ///
    /// Computes: `HMAC-SHA512(key="ed25519 seed", data=seed)`
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut mac =
            HmacSha512::new_from_slice(b"ed25519 seed").expect("HMAC can take key of any size");
        mac.update(seed);
        let ga = mac.finalize().into_bytes();
        let mut result = Zeroizing::new([0u8; 64]);
        result.copy_from_slice(&ga);

        let mut private_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        private_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        Self {
            private_key,
            chain_code,
        }
    }

    /// Derive a SLIP-0010 master key from a standard 512-bit BIP39 seed.
    pub fn from_bip39_seed(seed: &[u8; 64]) -> Self {
        Self::from_seed(seed)
    }

    /// Derive a hardened child key at the given index.
    ///
    /// The hardened bit (`0x80000000`) is automatically set. The `index` must
    /// be less than `2^31`.
    ///
    /// Computes: `HMAC-SHA512(key=chain_code, data=0x00 || private_key || (index | 0x80000000))`
    pub fn derive_child(&self, index: u32) -> Result<Self, HdError> {
        if index >= 0x80000000 {
            return Err(HdError::IndexOverflow);
        }
        let hardened_index = index | 0x80000000;

        let mut mac = HmacSha512::new_from_slice(&self.chain_code)
            .expect("HMAC can take key of any size");
        mac.update(&[0x00]);
        mac.update(&self.private_key);
        mac.update(&hardened_index.to_be_bytes());
        let ga = mac.finalize().into_bytes();
        let mut result = Zeroizing::new([0u8; 64]);
        result.copy_from_slice(&ga);

        let mut private_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        private_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        Ok(Self {
            private_key,
            chain_code,
        })
    }

    /// Derive a key from a path string like `"m/44'/93'/0'/0'/0'"`.
    ///
    /// All segments must be hardened (indicated by `'` or `h` suffix).
    /// The `"m/"` prefix is optional.
    pub fn derive_path(&self, path: &str) -> Result<Self, HdError> {
        let path = path.strip_prefix("m/").unwrap_or(path);

        let mut current: Option<Self> = None;
        for segment in path.split('/') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }

            let (index_str, is_hardened) = if let Some(s) = segment.strip_suffix('\'') {
                (s, true)
            } else if let Some(s) = segment.strip_suffix('h') {
                (s, true)
            } else {
                (segment, false)
            };

            let index: u32 = index_str
                .parse()
                .map_err(|_| HdError::InvalidPath(format!("invalid segment: {segment}")))?;

            if !is_hardened {
                return Err(HdError::UnhardenedDerivation(index));
            }

            let parent = current.as_ref().unwrap_or(self);
            current = Some(parent.derive_child(index)?);
        }

        Ok(current.unwrap_or_else(|| self.clone()))
    }

    /// Convert to a [`PrivateKey`] for signing.
    pub fn private_key(&self) -> PrivateKey {
        PrivateKey::from_seed(&self.private_key)
    }

    /// Get the ed25519 public key.
    ///
    /// Uses `SigningKey` directly to avoid creating a full 64-byte `PrivateKey`
    /// keypair just to extract the 32-byte public key.
    pub fn public_key(&self) -> PublicKey {
        let sk = SigningKey::from_bytes(&self.private_key);
        PublicKey::new(sk.verifying_key().to_bytes())
    }

    /// Get the raw 32-byte private key (ed25519 seed).
    pub fn raw_private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    /// Get the 32-byte chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SLIP-0010 Test Vector 1
    // Seed: 000102030405060708090a0b0c0d0e0f
    #[test]
    fn test_slip0010_vector1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed);

        // Chain m
        assert_eq!(
            hex::encode(master.raw_private_key()),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            hex::encode(master.chain_code()),
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
        );
        // Public key (SLIP-0010 spec prefixes with 0x00, we just check the 32-byte key)
        assert_eq!(
            hex::encode(master.public_key().as_ref()),
            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
        );

        // Chain m/0'
        let child0 = master.derive_child(0).unwrap();
        assert_eq!(
            hex::encode(child0.raw_private_key()),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
        assert_eq!(
            hex::encode(child0.chain_code()),
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"
        );
        assert_eq!(
            hex::encode(child0.public_key().as_ref()),
            "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"
        );

        // Chain m/0'/1'
        let child1 = child0.derive_child(1).unwrap();
        assert_eq!(
            hex::encode(child1.raw_private_key()),
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"
        );
        assert_eq!(
            hex::encode(child1.chain_code()),
            "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"
        );
        assert_eq!(
            hex::encode(child1.public_key().as_ref()),
            "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"
        );

        // Chain m/0'/1'/2'
        let child2 = child1.derive_child(2).unwrap();
        assert_eq!(
            hex::encode(child2.raw_private_key()),
            "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"
        );
        assert_eq!(
            hex::encode(child2.chain_code()),
            "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c"
        );
        assert_eq!(
            hex::encode(child2.public_key().as_ref()),
            "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"
        );

        // Chain m/0'/1'/2'/2'
        let child3 = child2.derive_child(2).unwrap();
        assert_eq!(
            hex::encode(child3.raw_private_key()),
            "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662"
        );
        assert_eq!(
            hex::encode(child3.chain_code()),
            "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc"
        );
        assert_eq!(
            hex::encode(child3.public_key().as_ref()),
            "8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"
        );

        // Chain m/0'/1'/2'/2'/1000000000'
        let child4 = child3.derive_child(1000000000).unwrap();
        assert_eq!(
            hex::encode(child4.raw_private_key()),
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"
        );
        assert_eq!(
            hex::encode(child4.chain_code()),
            "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230"
        );
        assert_eq!(
            hex::encode(child4.public_key().as_ref()),
            "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"
        );
    }

    // SLIP-0010 Test Vector 1 via derive_path
    #[test]
    fn test_slip0010_vector1_path() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed);

        let child = master.derive_path("m/0'/1'/2'/2'/1000000000'").unwrap();
        assert_eq!(
            hex::encode(child.raw_private_key()),
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"
        );
        assert_eq!(
            hex::encode(child.chain_code()),
            "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230"
        );
    }

    // SLIP-0010 Test Vector 2
    // Seed: fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    #[test]
    fn test_slip0010_vector2() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
             9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        )
        .unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed);

        // Chain m
        assert_eq!(
            hex::encode(master.raw_private_key()),
            "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012"
        );
        assert_eq!(
            hex::encode(master.chain_code()),
            "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b"
        );
        assert_eq!(
            hex::encode(master.public_key().as_ref()),
            "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a"
        );

        // Chain m/0'
        let child0 = master.derive_child(0).unwrap();
        assert_eq!(
            hex::encode(child0.raw_private_key()),
            "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635"
        );
        assert_eq!(
            hex::encode(child0.chain_code()),
            "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d"
        );
        assert_eq!(
            hex::encode(child0.public_key().as_ref()),
            "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037"
        );

        // Chain m/0'/2147483647'
        let child1 = child0.derive_child(2147483647).unwrap();
        assert_eq!(
            hex::encode(child1.raw_private_key()),
            "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4"
        );
        assert_eq!(
            hex::encode(child1.chain_code()),
            "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f"
        );
        assert_eq!(
            hex::encode(child1.public_key().as_ref()),
            "5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d"
        );

        // Chain m/0'/2147483647'/1'
        let child2 = child1.derive_child(1).unwrap();
        assert_eq!(
            hex::encode(child2.raw_private_key()),
            "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c"
        );
        assert_eq!(
            hex::encode(child2.chain_code()),
            "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90"
        );
        assert_eq!(
            hex::encode(child2.public_key().as_ref()),
            "2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45"
        );

        // Chain m/0'/2147483647'/1'/2147483646'
        let child3 = child2.derive_child(2147483646).unwrap();
        assert_eq!(
            hex::encode(child3.raw_private_key()),
            "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72"
        );
        assert_eq!(
            hex::encode(child3.chain_code()),
            "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a"
        );
        assert_eq!(
            hex::encode(child3.public_key().as_ref()),
            "e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b"
        );

        // Chain m/0'/2147483647'/1'/2147483646'/2'
        let child4 = child3.derive_child(2).unwrap();
        assert_eq!(
            hex::encode(child4.raw_private_key()),
            "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d"
        );
        assert_eq!(
            hex::encode(child4.chain_code()),
            "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4"
        );
        assert_eq!(
            hex::encode(child4.public_key().as_ref()),
            "47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0"
        );
    }

    #[test]
    fn test_bip39_seed_derivation() {
        let phrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = HdMnemonic::from_phrase(phrase).unwrap();
        assert_eq!(mnemonic.phrase(), phrase);

        // Known BIP39 test vector: empty passphrase
        let seed = mnemonic.to_seed("");
        let expected = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        )
        .unwrap();
        assert_eq!(seed.to_vec(), expected);
    }

    #[test]
    fn test_generate_mnemonic_12() {
        let m = HdMnemonic::generate(12).unwrap();
        let phrase = m.phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        // Re-parse should succeed
        let m2 = HdMnemonic::from_phrase(&phrase).unwrap();
        assert_eq!(m.entropy(), m2.entropy());
    }

    #[test]
    fn test_generate_mnemonic_24() {
        let m = HdMnemonic::generate(24).unwrap();
        let phrase = m.phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_generate_invalid_word_count() {
        assert!(HdMnemonic::generate(11).is_err());
        assert!(HdMnemonic::generate(13).is_err());
        assert!(HdMnemonic::generate(25).is_err());
    }

    #[test]
    fn test_path_equivalence() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed);

        let a = master.derive_path("m/0'").unwrap();
        let b = master.derive_path("0'").unwrap();
        let c = master.derive_path("m/0h").unwrap();
        assert_eq!(a.raw_private_key(), b.raw_private_key());
        assert_eq!(a.raw_private_key(), c.raw_private_key());
        assert_eq!(a.chain_code(), b.chain_code());
    }

    #[test]
    fn test_unhardened_path_rejected() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed);

        let result = master.derive_path("m/44/0'");
        assert!(matches!(result, Err(HdError::UnhardenedDerivation(44))));
    }

    #[test]
    fn test_index_overflow() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed);

        let result = master.derive_child(0x80000000);
        assert!(matches!(result, Err(HdError::IndexOverflow)));
    }

    #[test]
    fn test_sign_verify_with_derived_key() {
        let mnemonic = HdMnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let master = mnemonic.to_extended_key("");
        let child = master.derive_path("m/44'/1991'/0'/0'/0'").unwrap();

        let pk = child.private_key();
        let pubkey = child.public_key();

        let message = b"test message";
        let sig = pk.sign(message);
        assert!(pubkey.verify(message, &sig));
    }

    #[test]
    fn test_empty_path() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed);

        let same = master.derive_path("m/").unwrap();
        assert_eq!(master.raw_private_key(), same.raw_private_key());
        assert_eq!(master.chain_code(), same.chain_code());
    }
}
