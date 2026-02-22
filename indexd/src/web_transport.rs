use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
static PENDING_SESSIONS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_SESSIONS: AtomicUsize = AtomicUsize::new(0);

use bytes::Bytes;
use chrono::Utc;
use js_sys::{Reflect, Uint8Array};
use log::debug;
use sia::encoding_async::{AsyncDecoder, AsyncEncoder};
use sia::rhp::{
    self, AccountToken, HostPrices, RPCReadSector, RPCSettings, RPCWriteSector, Transport,
};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use sia::types::v2::Protocol;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{ReadableStreamDefaultReader, WritableStreamDefaultWriter};

use sia::rhp::HostSettings;

use crate::rhp4::Error;
use crate::{Hosts, RHP4Client};

/// Wraps a `!Send` future to satisfy `Send` bounds.
///
/// # Safety
/// Only used on WASM where execution is single-threaded and `Send` is meaningless.
struct SendFuture<F>(F);

// SAFETY: WASM is single-threaded.
unsafe impl<F> Send for SendFuture<F> {}

impl<F: Future> Future for SendFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We never move the inner future after pinning. The outer
        // Pin guarantees structural pinning for the single field.
        unsafe { self.map_unchecked_mut(|s| &mut s.0).poll(cx) }
    }
}

/// A WebTransport connection to a host. Supports opening multiple
/// bidirectional streams for sequential RPCs without reconnecting.
struct Connection {
    transport: web_sys::WebTransport,
    /// Whether this connection completed the WebTransport handshake.
    /// Only active connections decrement ACTIVE_SESSIONS on drop.
    active: bool,
}

// SAFETY: WASM is single-threaded; these types are never actually shared across threads.
unsafe impl Send for Connection {}
unsafe impl Sync for Connection {}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("active", &self.active)
            .finish()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.transport.close();
        if self.active {
            let active = ACTIVE_SESSIONS.fetch_sub(1, Ordering::Relaxed) - 1;
            let pending = PENDING_SESSIONS.load(Ordering::Relaxed);
            debug!("[WT] connection dropped (pending={pending}, active={active})");
        }
    }
}

impl Connection {
    /// Opens a new bidirectional stream on this connection.
    async fn open_stream(&self) -> Result<Stream, Error> {
        let bidi_stream = JsFuture::from(self.transport.create_bidirectional_stream())
            .await
            .map_err(|e| Error::Transport(format!("createBidirectionalStream error: {:?}", e)))?;

        let bidi = web_sys::WebTransportBidirectionalStream::from(bidi_stream);
        let reader = bidi
            .readable()
            .get_reader()
            .dyn_into::<ReadableStreamDefaultReader>()
            .map_err(|e| Error::Transport(format!("get_reader error: {:?}", e)))?;
        let writer = bidi
            .writable()
            .get_writer()
            .map_err(|e| Error::Transport(format!("get_writer error: {:?}", e)))?;

        Ok(Stream {
            reader,
            writer,
            read_buf: Vec::new(),
        })
    }
}

/// A bidirectional stream on a WebTransport connection, used for a
/// single RHP4 RPC. The stream does not own the underlying connection —
/// the [`Connection`] must be kept alive for the stream's lifetime.
struct Stream {
    reader: ReadableStreamDefaultReader,
    writer: WritableStreamDefaultWriter,
    read_buf: Vec<u8>,
}

impl Stream {
    /// Read exactly `buf.len()` bytes from the stream, buffering as needed.
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let mut filled = 0;
        while filled < buf.len() {
            // drain internal buffer first
            if !self.read_buf.is_empty() {
                let n = std::cmp::min(self.read_buf.len(), buf.len() - filled);
                buf[filled..filled + n].copy_from_slice(&self.read_buf[..n]);
                self.read_buf.drain(..n);
                filled += n;
                continue;
            }

            // read a chunk from the JS ReadableStream
            let result = JsFuture::from(self.reader.read())
                .await
                .map_err(|e| Error::Transport(format!("read error: {:?}", e)))?;

            let done = Reflect::get(&result, &JsValue::from_str("done"))
                .map_err(|e| Error::Transport(format!("reflect error: {:?}", e)))?
                .as_bool()
                .unwrap_or(true);

            if done {
                return Err(Error::Transport("stream closed unexpectedly".into()));
            }

            let value = Reflect::get(&result, &JsValue::from_str("value"))
                .map_err(|e| Error::Transport(format!("reflect error: {:?}", e)))?;

            let chunk = Uint8Array::new(&value);
            let mut data = vec![0u8; chunk.length() as usize];
            chunk.copy_to(&mut data);
            self.read_buf.extend_from_slice(&data);
        }
        Ok(())
    }

    /// Write all bytes to the JS WritableStream.
    async fn write_all(&mut self, data: &[u8]) -> Result<(), Error> {
        let array = Uint8Array::from(data);
        JsFuture::from(self.writer.write_with_chunk(&array))
            .await
            .map_err(|e| Error::Transport(format!("write error: {:?}", e)))?;
        Ok(())
    }
}

impl AsyncEncoder for Stream {
    type Error = Error;

    async fn encode_buf(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.write_all(buf).await
    }
}

impl AsyncDecoder for Stream {
    type Error = Error;

    async fn decode_buf(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.read_exact(buf).await
    }
}

impl Transport for Stream {
    type Error = Error;

    async fn write_request<R: rhp::RPCRequest>(&mut self, req: &R) -> Result<(), Self::Error> {
        req.encode_request(self).await?;
        Ok(())
    }

    async fn write_bytes(&mut self, data: Bytes) -> Result<(), Self::Error> {
        self.write_all(&data).await
    }

    async fn read_response<R: rhp::RPCResponse>(&mut self) -> Result<R, Self::Error> {
        R::decode_response(self).await
    }

    async fn write_response<RR: rhp::RPCResponse>(&mut self, resp: &RR) -> Result<(), Self::Error> {
        resp.encode_response(self).await?;
        Ok(())
    }
}

/// Suppresses the unhandled promise rejection from `WebTransport.closed`.
///
/// When a WebTransport connection is rejected, both the `ready` and
/// `closed` promises reject. If nobody catches `closed`, the browser
/// logs an unhandled rejection warning.
fn suppress_closed_rejection(wt: &web_sys::WebTransport) {
    let closed = wt.closed();
    let handler: Closure<dyn FnMut(JsValue)> = Closure::once(|_: JsValue| {});
    let _ = closed.catch(&handler);
    handler.forget(); // leak intentionally — called at most once per connection attempt
}

/// The WebTransport URL path for the RHP4 protocol.
const RHP4_PATH: &str = "/sia/rhp/v4";

/// Opens a WebTransport connection to the given address. The connection
/// can be used to open multiple bidirectional streams via
/// [`Connection::open_stream`].
async fn connect(address: &str) -> Result<Connection, Error> {
    let url = if address.starts_with("https://") {
        address.to_string()
    } else if address.contains('/') {
        // Already has a path component (e.g. host:port/sia/rhp/v4)
        format!("https://{address}")
    } else {
        // Bare host:port — append the RHP4 path
        format!("https://{address}{RHP4_PATH}")
    };
    let pending = PENDING_SESSIONS.fetch_add(1, Ordering::Relaxed) + 1;
    let active = ACTIVE_SESSIONS.load(Ordering::Relaxed);
    debug!("[WT] connecting to {url} (pending={pending}, active={active})");

    let options = web_sys::WebTransportOptions::new();
    let wt = web_sys::WebTransport::new_with_options(&url, &options).map_err(|e| {
        let pending = PENDING_SESSIONS.fetch_sub(1, Ordering::Relaxed) - 1;
        debug!(
            "[WT] constructor failed (pending={pending}, active={active}): {:?}",
            e
        );
        Error::Transport(format!("WebTransport constructor error: {:?}", e))
    })?;

    suppress_closed_rejection(&wt);

    // Wrap immediately so .close() is called if ready() fails or
    // the future is cancelled (e.g. by a timeout in tokio::select!).
    // active starts false — only set to true after successful handshake,
    // so Drop won't decrement ACTIVE_SESSIONS for failed connections.
    let mut conn = Connection {
        transport: wt,
        active: false,
    };
    let ready_promise = conn.transport.ready();

    match JsFuture::from(ready_promise).await {
        Ok(_) => {
            conn.active = true;
            let pending = PENDING_SESSIONS.fetch_sub(1, Ordering::Relaxed) - 1;
            let active = ACTIVE_SESSIONS.fetch_add(1, Ordering::Relaxed) + 1;
            debug!("[WT] connected to {url} (pending={pending}, active={active})");
            Ok(conn)
        }
        Err(e) => {
            // conn.active is false, so Drop won't decrement ACTIVE_SESSIONS
            let pending = PENDING_SESSIONS.fetch_sub(1, Ordering::Relaxed) - 1;
            debug!(
                "[WT] ready failed for {url} (pending={pending}, active={active}): {:?}",
                e
            );
            Err(Error::Transport(format!(
                "WebTransport ready error: {:?}",
                e
            )))
        }
    }
}

/// Connects to a host at the given address via WebTransport and fetches
/// its settings using the RHP4 settings RPC.
pub async fn fetch_host_settings(address: &str) -> Result<HostSettings, Error> {
    let conn = connect(address).await?;
    let stream = conn.open_stream().await?;
    let resp = RPCSettings::send_request(stream).await?.complete().await?;
    Ok(resp.settings)
}

#[derive(Clone, Debug)]
pub struct Client {
    hosts: Hosts,
    cached_prices: Arc<RwLock<HashMap<PublicKey, HostPrices>>>,
    cached_tokens: Arc<RwLock<HashMap<PublicKey, AccountToken>>>,
    connection_pool: Arc<RwLock<HashMap<PublicKey, Arc<Connection>>>>,
}

impl Client {
    pub fn new(hosts: Hosts) -> Client {
        Client {
            hosts,
            cached_prices: Arc::new(RwLock::new(HashMap::new())),
            cached_tokens: Arc::new(RwLock::new(HashMap::new())),
            connection_pool: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn evict_connection(&self, host_key: &PublicKey) {
        self.connection_pool.write().unwrap().remove(host_key);
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

    fn account_token(&self, account_key: &PrivateKey, host_key: PublicKey) -> AccountToken {
        let cached = {
            let cache = self.cached_tokens.read().unwrap();
            cache.get(&host_key).cloned()
        };
        match cached {
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

    async fn host_connection(&self, host_key: PublicKey) -> Result<Arc<Connection>, Error> {
        // Check pool first
        if let Some(conn) = self.connection_pool.read().unwrap().get(&host_key).cloned() {
            return Ok(conn);
        }

        // No pooled connection — create new one
        let addresses = self
            .hosts
            .addresses(&host_key)
            .ok_or_else(|| Error::Transport(format!("unknown host: {host_key}")))?;

        let mut last_err = None;
        for addr in addresses {
            if addr.protocol != Protocol::QUIC {
                continue;
            }

            match connect(&addr.address).await {
                Ok(conn) => {
                    let conn = Arc::new(conn);
                    self.connection_pool
                        .write()
                        .unwrap()
                        .insert(host_key, conn.clone());
                    return Ok(conn);
                }
                Err(e) => {
                    debug!(
                        "host_connection({host_key}): connect to {} failed: {e}",
                        addr.address
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            Error::Transport(format!(
                "no QUIC/WebTransport address found for host {host_key}"
            ))
        }))
    }

    /// Fetches host prices, either from cache or by running the settings
    /// RPC on the provided connection. This avoids opening a second
    /// WebTransport session just for the price fetch.
    async fn get_or_fetch_prices(
        &self,
        host_key: &PublicKey,
        conn: &Connection,
        refresh: bool,
    ) -> Result<HostPrices, Error> {
        if !refresh {
            if let Some(prices) = self.get_cached_prices(host_key) {
                debug!("get_or_fetch_prices: using cached prices for {host_key}");
                return Ok(prices);
            }
        }

        debug!("get_or_fetch_prices: fetching prices from {host_key}");
        let stream = conn.open_stream().await?;
        let resp = RPCSettings::send_request(stream).await?.complete().await?;
        self.set_cached_prices(host_key, resp.settings.prices.clone());
        Ok(resp.settings.prices)
    }
}

/// Manual `RHP4Client` implementation that wraps `!Send` WASM futures in
/// [`SendFuture`] so they satisfy the `Send` bound required by `#[async_trait]`.
impl RHP4Client for Client {
    fn host_prices<'life0, 'async_trait>(
        &'life0 self,
        host_key: PublicKey,
        refresh: bool,
    ) -> Pin<Box<dyn Future<Output = Result<HostPrices, Error>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(SendFuture(async move {
            if !refresh {
                if let Some(prices) = self.get_cached_prices(&host_key) {
                    debug!("host_prices: using cached prices for {host_key}");
                    return Ok(prices);
                }
            }

            debug!("host_prices: fetching prices from {host_key}");
            let conn = self.host_connection(host_key).await?;
            let result: Result<HostPrices, Error> = async {
                let stream = conn.open_stream().await?;
                let resp = RPCSettings::send_request(stream).await?.complete().await?;
                debug!("host_prices: got prices from {host_key}");
                self.set_cached_prices(&host_key, resp.settings.prices.clone());
                Ok(resp.settings.prices)
            }
            .await;
            if result.is_err() {
                self.evict_connection(&host_key);
            }
            result
        }))
    }

    fn write_sector<'life0, 'life1, 'async_trait>(
        &'life0 self,
        host_key: PublicKey,
        account_key: &'life1 PrivateKey,
        sector: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<Hash256, Error>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(SendFuture(async move {
            let conn = self.host_connection(host_key).await?;
            let result: Result<Hash256, Error> = async {
                let prices = self.get_or_fetch_prices(&host_key, &conn, false).await?;
                let stream = conn.open_stream().await?;
                let token = self.account_token(account_key, host_key);
                debug!("write_sector: sending {} bytes to {host_key}", sector.len());
                let resp = RPCWriteSector::send_request(stream, prices, token, sector)
                    .await?
                    .complete()
                    .await?;
                debug!("write_sector: completed for {host_key}");
                Ok(resp.root)
            }
            .await;
            if result.is_err() {
                self.evict_connection(&host_key);
            }
            result
        }))
    }

    fn read_sector<'life0, 'life1, 'async_trait>(
        &'life0 self,
        host_key: PublicKey,
        account_key: &'life1 PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Bytes, Error>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(SendFuture(async move {
            let conn = self.host_connection(host_key).await?;
            let result: Result<Bytes, Error> = async {
                let prices = self.get_or_fetch_prices(&host_key, &conn, false).await?;
                let stream = conn.open_stream().await?;
                let token = self.account_token(account_key, host_key);
                let resp = RPCReadSector::send_request(stream, prices, token, root, offset, length)
                    .await?
                    .complete()
                    .await?;
                Ok(resp.data)
            }
            .await;
            if result.is_err() {
                self.evict_connection(&host_key);
            }
            result
        }))
    }
}
