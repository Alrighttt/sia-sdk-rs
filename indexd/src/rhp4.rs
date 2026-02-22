use async_trait::async_trait;
use bytes::Bytes;
use sia::encoding;
use sia::rhp::{self, HostPrices};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encoding error: {0}")]
    Encoding(#[from] encoding::Error),

    #[error("rhp error: {0}")]
    Rhp(#[from] rhp::Error),

    #[error("invalid prices")]
    InvalidPrices,

    #[error("invalid signature")]
    InvalidSignature,

    #[cfg(not(target_arch = "wasm32"))]
    #[error("timeout error: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("transport error: {0}")]
    Transport(String),
}

/// Conditional Send + Sync bound: required on native (for spawning across
/// threads), trivially satisfied on WASM (single-threaded).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait MaybeSendSync: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> MaybeSendSync for T {}

#[cfg(target_arch = "wasm32")]
pub(crate) trait MaybeSendSync {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSendSync for T {}

/// Trait defining the operations that can be performed on a host.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub(crate) trait RHP4Client: MaybeSendSync {
    async fn host_prices(&self, host_key: PublicKey, refresh: bool) -> Result<HostPrices, Error>;
    async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, Error>;
    async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, Error>;
}
