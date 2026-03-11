use core::fmt;

use crate::encoding::{self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use crate::encoding_async::{AsyncSiaDecodable, AsyncSiaDecode, AsyncSiaEncodable, AsyncSiaEncode};
use crate::types::{Hash256, HexParseError};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature as ED25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use zeroize::ZeroizeOnDrop;

/// An ed25519 public key that can be used to verify a signature
#[derive(
    Debug, Eq, Hash, PartialEq, Clone, Copy, SiaEncode, SiaDecode, AsyncSiaDecode, AsyncSiaEncode,
)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    const PREFIX: &'static str = "ed25519:";
}

impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        String::serialize(&self.to_string(), serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let result = s.parse().map_err(|e| Error::custom(format!("{e:?}")))?;
        Ok(result)
    }
}

impl std::str::FromStr for PublicKey {
    type Err = crate::types::HexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(Self::PREFIX)
            .ok_or(HexParseError::MissingPrefix)?;
        let mut pk = [0; 32];
        hex::decode_to_slice(s, &mut pk)?;
        Ok(Self::new(pk))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", Self::PREFIX, hex::encode(self.0))
    }
}

impl PublicKey {
    pub const fn new(buf: [u8; 32]) -> Self {
        PublicKey(buf)
    }

    /// Verifies a message against the signature using this public key.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        let pk = VerifyingKey::from_bytes(&self.0).unwrap();
        pk.verify(msg, &ED25519Signature::from_bytes(signature.as_ref()))
            .is_ok()
    }

    /// Compute an additive key tweak: `P' = P + H(P || topic) * G`.
    ///
    /// Anyone who knows the original public key and the topic string can
    /// independently derive the same tweaked key — no private key needed.
    /// Returns `None` if the public key bytes are not a valid curve point.
    pub fn tweak(&self, topic: &[u8]) -> Option<PublicKey> {
        let t = self.tweak_scalar(topic);
        let point = CompressedEdwardsY(self.0).decompress()?;
        let tweaked = point + curve25519_dalek::constants::ED25519_BASEPOINT_POINT * t;
        Some(PublicKey(tweaked.compress().to_bytes()))
    }

    /// Compute the tweak scalar: `t = Blake2b-256(pk_bytes || topic)` reduced mod l.
    ///
    /// Domain-separated with `"sia/tweak|"` to avoid collisions with other hash uses.
    pub fn tweak_scalar(&self, topic: &[u8]) -> Scalar {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .to_state()
            .update(b"sia/tweak|")
            .update(&self.0)
            .update(topic)
            .finalize();
        let mut t = [0u8; 32];
        t.copy_from_slice(hash.as_bytes());
        Scalar::from_bytes_mod_order(t)
    }
}

impl From<PublicKey> for [u8; 32] {
    fn from(val: PublicKey) -> Self {
        val.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An ed25519 private key that can be used to sign a hash
#[derive(Debug, PartialEq, Clone, ZeroizeOnDrop)]
pub struct PrivateKey([u8; 64]);

impl PrivateKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(seed);
        PrivateKey(sk.to_keypair_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.0[32..]);
        PublicKey::new(buf)
    }

    pub fn sign(&self, h: &[u8]) -> Signature {
        let sk = SigningKey::from_bytes(&self.0[..32].try_into().unwrap());
        Signature::new(sk.sign(h).to_bytes())
    }

    /// Sign a message using an additively-tweaked private key.
    ///
    /// The tweaked keypair is `(a' = a + t, A' = A + t*G)` where
    /// `t = H(A || topic)`. The resulting signature verifies against
    /// `public_key().tweak(topic)`.
    ///
    /// Internally performs the SHA-512 expansion and ed25519 clamping that
    /// dalek normally hides, then adds the tweak scalar before signing.
    pub fn sign_tweaked(&self, topic: &[u8], msg: &[u8]) -> Signature {
        let seed: [u8; 32] = self.0[..32].try_into().unwrap();
        let pk = self.public_key();

        // SHA-512 expand the seed (replicating dalek's internal expansion)
        let h = Sha512::digest(&seed);
        let mut scalar_bytes: [u8; 32] = h[..32].try_into().unwrap();
        // Ed25519 clamping
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;
        let a = Scalar::from_bytes_mod_order(scalar_bytes);
        let nonce_prefix = &h[32..64];

        // Compute tweak: t = H(A || topic)
        let t = pk.tweak_scalar(topic);

        // Tweaked scalar and public key
        let a_prime = a + t;
        let a_prime_point = CompressedEdwardsY(pk.0).decompress().unwrap()
            + curve25519_dalek::constants::ED25519_BASEPOINT_POINT * t;
        let a_prime_bytes = a_prime_point.compress().to_bytes();

        // Deterministic nonce: r = SHA-512(nonce_prefix || msg) mod l
        let r_hash = Sha512::new()
            .chain_update(nonce_prefix)
            .chain_update(msg)
            .finalize();
        let r = Scalar::from_bytes_mod_order_wide(r_hash[..64].try_into().unwrap());

        // R = r * G
        let r_point = (curve25519_dalek::constants::ED25519_BASEPOINT_POINT * r).compress();

        // k = SHA-512(R || A' || msg) mod l
        let k_hash = Sha512::new()
            .chain_update(r_point.as_bytes())
            .chain_update(&a_prime_bytes)
            .chain_update(msg)
            .finalize();
        let k = Scalar::from_bytes_mod_order_wide(k_hash[..64].try_into().unwrap());

        // S = (r + k * a') mod l
        let s = r + k * a_prime;

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(r_point.as_bytes());
        sig[32..].copy_from_slice(s.as_bytes());
        Signature(sig)
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 64]> for PrivateKey {
    fn from(key: [u8; 64]) -> Self {
        PrivateKey(key)
    }
}

impl From<Hash256> for PrivateKey {
    fn from(hash: Hash256) -> Self {
        PrivateKey::from_seed(hash.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, SiaEncode, SiaDecode, AsyncSiaEncode, AsyncSiaDecode)]
pub struct Signature([u8; 64]);

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        String::serialize(&hex::encode(self.0), serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf = hex::decode(String::deserialize(deserializer)?)
            .map_err(|e| D::Error::custom(format!("{e:?}")))?;
        if buf.len() != 64 {
            return Err(D::Error::custom("Invalid signature length"));
        }
        Ok(Signature(buf.try_into().unwrap()))
    }
}

impl Signature {
    pub const fn new(sig: [u8; 64]) -> Self {
        Signature(sig)
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature([0; 64])
    }
}

impl AsRef<[u8; 64]> for Signature {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl From<[u8; 64]> for Signature {
    fn from(buf: [u8; 64]) -> Self {
        Signature(buf)
    }
}

impl std::str::FromStr for Signature {
    type Err = crate::types::HexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = hex::decode(s).map_err(HexParseError::HexError)?;
        if data.len() != 64 {
            return Err(HexParseError::InvalidLength(data.len()));
        }

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data);
        Ok(Signature(sig))
    }
}

/// Converts a slice of bytes into a Signature.
/// # Errors
/// Returns an error if the slice is not exactly 64 bytes long.
impl TryFrom<&[u8]> for Signature {
    type Error = encoding::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 64 {
            return Err(encoding::Error::InvalidLength(value.len()));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(value);
        Ok(Signature(sig))
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_publickey() {
        let public_key_str = "9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6";
        let public_key = PublicKey::new(hex::decode(public_key_str).unwrap().try_into().unwrap());

        // binary
        let mut public_key_serialized = Vec::new();
        public_key.encode(&mut public_key_serialized).unwrap();
        assert_eq!(public_key_serialized, hex::decode(public_key_str).unwrap());
        let public_key_deserialized =
            PublicKey::decode(&mut public_key_serialized.as_slice()).unwrap();
        assert_eq!(public_key_deserialized, public_key);

        // json
        let public_key_serialized = serde_json::to_string(&public_key).unwrap();
        let public_key_deserialized: PublicKey =
            serde_json::from_str(&public_key_serialized).unwrap();
        assert_eq!(
            public_key_serialized,
            format!("\"ed25519:{public_key_str}\"")
        );
        assert_eq!(public_key_deserialized, public_key);
    }

    #[test]
    fn test_tweak_deterministic() {
        let seed = [42u8; 32];
        let sk = PrivateKey::from_seed(&seed);
        let pk = sk.public_key();

        let tweaked1 = pk.tweak(b".sia/manifest").unwrap();
        let tweaked2 = pk.tweak(b".sia/manifest").unwrap();
        assert_eq!(tweaked1, tweaked2);
    }

    #[test]
    fn test_tweak_different_topics() {
        let seed = [42u8; 32];
        let sk = PrivateKey::from_seed(&seed);
        let pk = sk.public_key();

        let t1 = pk.tweak(b".sia/manifest").unwrap();
        let t2 = pk.tweak(b".sia/profile").unwrap();
        assert_ne!(t1, t2);
        // Both differ from the original
        assert_ne!(t1, pk);
        assert_ne!(t2, pk);
    }

    #[test]
    fn test_sign_tweaked_verifies() {
        let seed = [42u8; 32];
        let sk = PrivateKey::from_seed(&seed);
        let pk = sk.public_key();
        let topic = b".sia/manifest";
        let msg = b"hello world";

        let sig = sk.sign_tweaked(topic, msg);
        let tweaked_pk = pk.tweak(topic).unwrap();

        // Signature must verify against the tweaked public key
        assert!(tweaked_pk.verify(msg, &sig));

        // Must NOT verify against the original public key
        assert!(!pk.verify(msg, &sig));
    }

    #[test]
    fn test_sign_tweaked_wrong_topic_fails() {
        let seed = [42u8; 32];
        let sk = PrivateKey::from_seed(&seed);
        let pk = sk.public_key();

        let sig = sk.sign_tweaked(b".sia/manifest", b"hello");
        let wrong_tweaked = pk.tweak(b".sia/profile").unwrap();

        assert!(!wrong_tweaked.verify(b"hello", &sig));
    }

    #[test]
    fn test_sign_tweaked_wrong_message_fails() {
        let seed = [42u8; 32];
        let sk = PrivateKey::from_seed(&seed);
        let pk = sk.public_key();
        let topic = b".sia/manifest";

        let sig = sk.sign_tweaked(topic, b"hello");
        let tweaked_pk = pk.tweak(topic).unwrap();

        assert!(!tweaked_pk.verify(b"goodbye", &sig));
    }

    #[test]
    fn test_tweak_from_hd_key() {
        // Verify tweaking works with HD-derived keys (the real use case)
        use crate::hd::HdMnemonic;
        let m = HdMnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        let master = m.to_extended_key("");
        let child = master.derive_path("m/44'/1991'/0'/0'/0'").unwrap();
        let sk = child.private_key();
        let pk = child.public_key();

        let topic = b".sia/manifest";
        let msg = b"test message";

        let sig = sk.sign_tweaked(topic, msg);
        let tweaked_pk = pk.tweak(topic).unwrap();

        assert!(tweaked_pk.verify(msg, &sig));
    }
}
