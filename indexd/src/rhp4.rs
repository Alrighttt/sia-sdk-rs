use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use sia::encoding;
use sia::rhp::{self, HostPrices};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use thiserror::Error;
use tokio::time::error::Elapsed;

use crate::Hosts;

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

    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),

    #[error("transport error: {0}")]
    Transport(String),
}

/// Trait defining the operations that can be performed on a host.
#[async_trait]
pub(crate) trait RHP4Client: Send + Sync {
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

/// An RHP4Client that declares which protocol(s) it supports.
/// Used by `MultiTransport` to route host connections to the
/// appropriate transport based on the host's advertised addresses.
pub(crate) trait RHP4Transport: RHP4Client {
    fn supported_protocols(&self) -> &[&str];
}

/// A composite transport that routes RHP4 calls to the appropriate transport
/// based on the host's advertised protocol strings.
pub(crate) struct MultiTransport {
    hosts: Hosts,
    transports: Vec<Arc<dyn RHP4Transport>>,
}

impl MultiTransport {
    /// Creates a new MultiTransport. The order of `transports` determines
    /// protocol preference — earlier transports are tried first when a host
    /// advertises multiple protocols. For example, `vec![quic, siamux]`
    /// will prefer QUIC over siamux when a host supports both.
    pub fn new(hosts: Hosts, transports: Vec<Arc<dyn RHP4Transport>>) -> Self {
        Self { hosts, transports }
    }

    /// Finds the first registered transport that supports one of the host's
    /// advertised protocols.
    fn transport_for_host(&self, host_key: &PublicKey) -> Result<&dyn RHP4Transport, Error> {
        let addresses = self
            .hosts
            .addresses(host_key)
            .ok_or_else(|| Error::Transport("unknown host".into()))?;
        for t in &self.transports {
            for addr in &addresses {
                if t.supported_protocols().contains(&addr.protocol.as_str()) {
                    return Ok(t.as_ref());
                }
            }
        }
        Err(Error::Transport(
            "no transport supports this host's protocols".into(),
        ))
    }
}

#[async_trait]
impl RHP4Client for MultiTransport {
    async fn host_prices(&self, host_key: PublicKey, refresh: bool) -> Result<HostPrices, Error> {
        self.transport_for_host(&host_key)?
            .host_prices(host_key, refresh)
            .await
    }

    async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, Error> {
        self.transport_for_host(&host_key)?
            .write_sector(host_key, account_key, sector)
            .await
    }

    async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, Error> {
        self.transport_for_host(&host_key)?
            .read_sector(host_key, account_key, root, offset, length)
            .await
    }
}
