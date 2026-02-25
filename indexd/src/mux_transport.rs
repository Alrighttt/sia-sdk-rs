use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use log::debug;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

use crate::rhp4::Error as RHP4Error;
use crate::{Hosts, RHP4Client};
use mux::{self, DialError, Mux, MuxError};
use sia::encoding_async::AsyncDecoder;
use sia::rhp::{
    self, AccountToken, HostPrices, RPCReadSector, RPCSettings, RPCWriteSector, Transport,
};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use sia::types::v2::Protocol;

struct MuxStream(mux::Stream);

impl AsyncDecoder for MuxStream {
    type Error = RHP4Error;
    async fn decode_buf(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        use tokio::io::AsyncReadExt;
        self.0
            .read_exact(buf)
            .await
            .map(|_| ())
            .map_err(|e| RHP4Error::Transport(e.to_string()))
    }
}

impl Transport for MuxStream {
    type Error = RHP4Error;

    async fn write_request<R: rhp::RPCRequest>(&mut self, req: &R) -> Result<(), Self::Error> {
        req.encode_request(&mut self.0).await?;
        Ok(())
    }

    async fn write_bytes(&mut self, data: Bytes) -> Result<(), Self::Error> {
        use tokio::io::AsyncWriteExt;
        self.0
            .write_all(&data)
            .await
            .map_err(|e| RHP4Error::Transport(e.to_string()))
    }

    async fn read_response<R: rhp::RPCResponse>(&mut self) -> Result<R, Self::Error> {
        R::decode_response(self).await
    }

    async fn write_response<RR: rhp::RPCResponse>(&mut self, resp: &RR) -> Result<(), Self::Error> {
        resp.encode_response(&mut self.0).await?;
        Ok(())
    }
}

#[derive(Debug, Error)]
enum ConnectError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("dial error: {0}")]
    Dial(#[from] DialError),

    #[error("mux error: {0}")]
    Mux(#[from] MuxError),

    #[error("unknown host: {0}")]
    UnknownHost(PublicKey),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),

    #[error("invalid host key: {0}")]
    InvalidKey(#[from] ed25519_dalek::SignatureError),
}

/// A Client manages multiplexed TCP connections to Sia hosts.
/// Connections are cached for reuse — each host gets a single
/// persistent Mux over which many streams are multiplexed.
pub struct Client {
    hosts: Hosts,
    open_conns: RwLock<HashMap<PublicKey, Arc<Mux>>>,
    cached_prices: RwLock<HashMap<PublicKey, HostPrices>>,
    cached_tokens: RwLock<HashMap<PublicKey, AccountToken>>,
}

impl Client {
    pub fn new(hosts: Hosts) -> Self {
        Self {
            hosts,
            open_conns: RwLock::new(HashMap::new()),
            cached_prices: RwLock::new(HashMap::new()),
            cached_tokens: RwLock::new(HashMap::new()),
        }
    }

    fn get_cached_prices(&self, host_key: &PublicKey) -> Option<HostPrices> {
        let cache = self.cached_prices.read().unwrap();
        match cache.get(host_key) {
            Some(prices) if prices.valid_until > Utc::now() => Some(prices.clone()),
            _ => None,
        }
    }

    fn set_cached_prices(&self, host_key: &PublicKey, prices: HostPrices) {
        self.cached_prices
            .write()
            .unwrap()
            .insert(*host_key, prices);
    }

    fn evict_connection(&self, host_key: &PublicKey) {
        self.open_conns.write().unwrap().remove(host_key);
    }

    fn evict_prices(&self, host_key: &PublicKey) {
        self.cached_prices.write().unwrap().remove(host_key);
    }

    fn account_token(&self, account_key: &PrivateKey, host_key: PublicKey) -> AccountToken {
        let cached_token = {
            let cache = self.cached_tokens.read().unwrap();
            cache.get(&host_key).cloned()
        };
        match cached_token {
            Some(token) if token.valid_until > Utc::now() => token,
            _ => {
                let token = AccountToken::new(account_key, host_key);
                self.cached_tokens
                    .write()
                    .unwrap()
                    .insert(host_key, token.clone());
                token
            }
        }
    }

    fn existing_conn(&self, host: &PublicKey) -> Option<Arc<Mux>> {
        self.open_conns.read().unwrap().get(host).cloned()
    }

    async fn new_conn(&self, host: PublicKey) -> Result<Arc<Mux>, ConnectError> {
        let addresses = self
            .hosts
            .addresses(&host)
            .ok_or(ConnectError::UnknownHost(host))?;
        let verifying_key = VerifyingKey::from_bytes(&<[u8; 32]>::from(host))?;

        let mut last_err = None;
        for addr in addresses {
            if addr.protocol != Protocol::SiaMux {
                continue;
            }
            match TcpStream::connect(&addr.address).await {
                Ok(tcp) => match mux::dial(tcp, &verifying_key).await {
                    Ok(m) => {
                        let m = Arc::new(m);
                        self.open_conns.write().unwrap().insert(host, m.clone());
                        debug!("established mux connection to {host} via {}", addr.address);
                        return Ok(m);
                    }
                    Err(e) => {
                        debug!("mux handshake to {host} at {} failed: {e}", addr.address);
                        last_err = Some(ConnectError::Dial(e));
                    }
                },
                Err(e) => {
                    debug!("TCP connect to {host} at {} failed: {e}", addr.address);
                    last_err = Some(ConnectError::Io(e));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            ConnectError::InvalidAddress(format!("no siamux addresses for {host}"))
        }))
    }

    async fn host_stream(&self, host: PublicKey) -> Result<MuxStream, ConnectError> {
        // Try existing connection first
        if let Some(mux) = self.existing_conn(&host) {
            match mux.dial_stream() {
                Ok(stream) => return Ok(MuxStream(stream)),
                Err(MuxError::ClosedConn) => {
                    debug!("existing mux connection to {host} is closed, reconnecting");
                    self.evict_connection(&host);
                }
                Err(e) => return Err(ConnectError::Mux(e)),
            }
        }

        // Establish new connection
        let mux: Arc<Mux> = timeout(Duration::from_secs(30), self.new_conn(host)).await??;
        let stream = mux.dial_stream()?;
        Ok(MuxStream(stream))
    }

    async fn fetch_host_prices(&self, host_key: PublicKey) -> Result<HostPrices, RHP4Error> {
        let stream = self
            .host_stream(host_key)
            .await
            .map_err(|e| RHP4Error::Transport(e.to_string()))?;
        let resp = RPCSettings::send_request(stream).await?.complete().await?;
        self.set_cached_prices(&host_key, resp.settings.prices.clone());
        Ok(resp.settings.prices)
    }

    async fn do_write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        prices: HostPrices,
        sector: Bytes,
    ) -> Result<Hash256, RHP4Error> {
        let stream = self
            .host_stream(host_key)
            .await
            .map_err(|e| RHP4Error::Transport(e.to_string()))?;
        let token = self.account_token(account_key, host_key);
        let resp = RPCWriteSector::send_request(stream, prices, token, sector)
            .await?
            .complete()
            .await?;
        Ok(resp.root)
    }

    async fn do_read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        prices: HostPrices,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, RHP4Error> {
        let stream = self
            .host_stream(host_key)
            .await
            .map_err(|e| RHP4Error::Transport(e.to_string()))?;
        let token = self.account_token(account_key, host_key);
        let resp = RPCReadSector::send_request(stream, prices, token, root, offset, length)
            .await?
            .complete()
            .await?;
        Ok(resp.data)
    }
}

#[async_trait]
impl RHP4Client for Client {
    async fn host_prices(
        &self,
        host_key: PublicKey,
        refresh: bool,
    ) -> Result<HostPrices, RHP4Error> {
        if !refresh && let Some(prices) = self.get_cached_prices(&host_key) {
            return Ok(prices);
        }
        let result = self.fetch_host_prices(host_key).await;
        if result.is_err() {
            self.evict_connection(&host_key);
            self.hosts.add_failure(&host_key);
        }
        result
    }

    async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, RHP4Error> {
        let prices = self.host_prices(host_key, false).await?;
        let start = Instant::now();
        let result = self
            .do_write_sector(host_key, account_key, prices, sector)
            .await;
        if result.is_err() {
            self.evict_connection(&host_key);
            self.evict_prices(&host_key);
            self.hosts.add_failure(&host_key);
        } else {
            self.hosts.add_write_sample(&host_key, start.elapsed());
        }
        result
    }

    async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, RHP4Error> {
        let prices = self.host_prices(host_key, false).await?;
        let start = Instant::now();
        let result = self
            .do_read_sector(host_key, account_key, prices, root, offset, length)
            .await;
        if result.is_err() {
            self.evict_connection(&host_key);
            self.evict_prices(&host_key);
            self.hosts.add_failure(&host_key);
        } else {
            self.hosts.add_read_sample(&host_key, start.elapsed());
        }
        result
    }
}
