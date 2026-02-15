use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tokio::sync::Semaphore;

use bytes::Bytes;
use chrono::Utc;
use js_sys::{Reflect, Uint8Array};
use log::debug;
use sia::encoding_async::{AsyncDecoder, AsyncEncoder};
use sia::rhp::{self, AccountToken, HostPrices, RPCReadSector, RPCSettings, RPCWriteSector, Transport};
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

/// Wraps the browser's WebTransport bidirectional stream for use with
/// the sia RHP4 protocol.
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

    async fn write_response<RR: rhp::RPCResponse>(
        &mut self,
        resp: &RR,
    ) -> Result<(), Self::Error> {
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

/// Opens a WebTransport connection to the given address and creates
/// a bidirectional stream. If the address is a bare `host:port`, the
/// RHP4 path (`/sia/rhp/v4`) is appended automatically.
async fn connect_stream(address: &str) -> Result<Stream, Error> {
    let url = if address.starts_with("https://") {
        address.to_string()
    } else if address.contains('/') {
        // Already has a path component (e.g. host:port/sia/rhp/v4)
        format!("https://{address}")
    } else {
        // Bare host:port — append the RHP4 path
        format!("https://{address}{RHP4_PATH}")
    };
    debug!("connecting via WebTransport at {url}");

    let options = web_sys::WebTransportOptions::new();
    let wt = web_sys::WebTransport::new_with_options(&url, &options)
        .map_err(|e| Error::Transport(format!("WebTransport constructor error: {:?}", e)))?;

    suppress_closed_rejection(&wt);

    JsFuture::from(wt.ready())
        .await
        .map_err(|e| Error::Transport(format!("WebTransport ready error: {:?}", e)))?;

    debug!("WebTransport connected to {url}");

    let bidi_stream = JsFuture::from(wt.create_bidirectional_stream())
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

/// Connects to a host at the given address via WebTransport and fetches
/// its settings using the RHP4 settings RPC.
pub async fn fetch_host_settings(address: &str) -> Result<HostSettings, Error> {
    let stream = connect_stream(address).await?;
    let resp = RPCSettings::send_request(stream)
        .await?
        .complete()
        .await?;
    Ok(resp.settings)
}

#[derive(Clone, Debug)]
pub struct Client {
    hosts: Hosts,
    cached_prices: std::sync::Arc<RwLock<HashMap<PublicKey, HostPrices>>>,
    cached_tokens: std::sync::Arc<RwLock<HashMap<PublicKey, AccountToken>>>,
}

impl Client {
    pub fn new(hosts: Hosts, max_price_fetches: usize) -> Client {
        Client {
            hosts,
            cached_prices: std::sync::Arc::new(RwLock::new(HashMap::new())),
            cached_tokens: std::sync::Arc::new(RwLock::new(HashMap::new())),
            // Limit concurrent price fetches to prevent browser connection overload
            price_fetch_semaphore: std::sync::Arc::new(Semaphore::new(max_price_fetches)),
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

    /// Connects to a host via WebTransport and opens a bidirectional stream.
    /// Tries all QUIC addresses for a host before giving up.
    async fn host_stream(&self, host_key: PublicKey) -> Result<Stream, Error> {
        let addresses = self
            .hosts
            .addresses(&host_key)
            .ok_or_else(|| Error::Transport(format!("unknown host: {host_key}")))?;

        let mut last_err = None;
        for addr in addresses {
            if addr.protocol != Protocol::QUIC {
                continue;
            }

            match connect_stream(&addr.address).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    debug!("connection to {host_key} at {} failed: {e}", addr.address);
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

            // Acquire semaphore permit to limit concurrent price fetches
            let _permit = self.price_fetch_semaphore.acquire().await
                .map_err(|e| Error::Transport(format!("semaphore error: {}", e)))?;

            // Check cache again in case another task fetched while we were waiting
            if !refresh {
                if let Some(prices) = self.get_cached_prices(&host_key) {
                    debug!("host_prices: using cached prices for {host_key} (fetched by other task)");
                    return Ok(prices);
                }
            }

            debug!("host_prices: fetching prices from {host_key}");
            let stream = self.host_stream(host_key).await?;
            let resp = RPCSettings::send_request(stream)
                .await?
                .complete()
                .await?;

            debug!("host_prices: got prices from {host_key}");
            self.set_cached_prices(&host_key, resp.settings.prices.clone());
            Ok(resp.settings.prices)
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
            debug!("write_sector: getting prices for {host_key}");
            let prices = self.host_prices(host_key, false).await?;
            debug!("write_sector: connecting to {host_key}");
            let stream = self.host_stream(host_key).await?;
            let token = self.account_token(account_key, host_key);
            debug!("write_sector: sending {} bytes to {host_key}", sector.len());
            let resp = RPCWriteSector::send_request(stream, prices, token, sector)
                .await?
                .complete()
                .await?;
            debug!("write_sector: completed for {host_key}");
            Ok(resp.root)
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
            let prices = self.host_prices(host_key, false).await?;
            let stream = self.host_stream(host_key).await?;
            let token = self.account_token(account_key, host_key);
            let resp =
                RPCReadSector::send_request(stream, prices, token, root, offset, length)
                    .await?
                    .complete()
                    .await?;
            Ok(resp.data)
        }))
    }
}
