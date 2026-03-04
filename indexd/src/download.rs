use std::collections::VecDeque;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use crate::sleep;
use log::debug;
use sia::encryption::{EncryptionKey, encrypt_shard};
use sia::erasure_coding::{self, ErasureCoder};
use sia::rhp::{HostPrices, SEGMENT_SIZE};
use sia::signing::PrivateKey;
use sia::types::Currency;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinSet;
#[cfg(not(target_arch = "wasm32"))]
use tokio::time::error::Elapsed;

use sia::signing::PublicKey;
use sia::types::v2::Protocol;

use crate::rhp4::RHP4Client;
use crate::{Hosts, Object, Sector};

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encoder error: {0}")]
    Encoder(#[from] erasure_coding::Error),

    #[error("not enough shards: {0}/{1}")]
    NotEnoughShards(u8, u8),

    #[error("invalid range: {0}-{1}")]
    OutOfRange(usize, usize),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),

    #[error("semaphore error: {0}")]
    SemaphoreError(#[from] tokio::sync::AcquireError),

    #[error("join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("invalid slab: {0}")]
    InvalidSlab(String),

    #[error("rhp4 error: {0}")]
    Rhp4(#[from] crate::rhp4::Error),

    #[error("custom error: {0}")]
    Custom(String),
}

pub struct DownloadOptions {
    /// Maximum number of concurrent sector downloads.
    pub max_inflight: usize,
    pub offset: u64,
    pub length: Option<u64>,

    /// Optional channel to notify when each slab is downloaded.
    /// This can be used to implement progress reporting.
    pub slab_downloaded: Option<mpsc::UnboundedSender<()>>,

    /// Optional channel to report which host is being actively downloaded from.
    /// Sends the host's address URL (e.g. "https://1.2.3.4:4820/sia/rhp/v4")
    /// each time a sector download is initiated.
    pub host_active: Option<mpsc::UnboundedSender<String>>,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            #[cfg(target_arch = "wasm32")]
            max_inflight: 8, // Browsers can't handle many concurrent WebTransport connections
            #[cfg(not(target_arch = "wasm32"))]
            max_inflight: 20,
            offset: 0,
            length: None,
            slab_downloaded: None,
            host_active: None,
        }
    }
}

/// Per-host account balance and pricing information.
pub struct HostAccountInfo {
    pub host_key: PublicKey,
    pub balance: Result<Currency, DownloadError>,
    pub prices: Result<HostPrices, DownloadError>,
}

#[derive(Clone)]
pub(crate) struct Downloader {
    account_key: Arc<PrivateKey>,
    hosts: Hosts,
    transport: Arc<dyn RHP4Client>,
}

struct SectorDownloadTask {
    sector: Sector,
    offset: u64,
    length: u64,
    index: usize,
}

impl Downloader {
    // helper to pair a sector with its erasure-coded index.
    // Required because [FuturesUnordered.push] does not
    // preserve ordering and doesn't play nice with closures.
    async fn try_download_sector(
        _permit: OwnedSemaphorePermit,
        transport: Arc<dyn RHP4Client>,
        account_key: Arc<PrivateKey>,
        task: SectorDownloadTask,
    ) -> (PublicKey, Result<(usize, Vec<u8>), DownloadError>) {
        let host_key = task.sector.host_key;
        let result = transport
            .read_sector(
                host_key,
                &account_key,
                task.sector.root,
                task.offset as usize,
                task.length as usize,
            )
            .await
            .map(|data| (task.index, data.to_vec()))
            .map_err(DownloadError::from);
        (host_key, result)
    }

    pub fn new(hosts: Hosts, transport: Arc<dyn RHP4Client>, account_key: Arc<PrivateKey>) -> Self {
        Self {
            account_key,
            hosts,
            transport,
        }
    }

    /// Resolves a host's public key to its WebTransport/HTTPS URL.
    fn host_url(&self, host_key: &PublicKey) -> String {
        self.hosts
            .addresses(host_key)
            .and_then(|addrs| {
                addrs
                    .into_iter()
                    .find(|a| a.protocol == Protocol::QUIC)
                    .map(|a| {
                        let addr = &a.address;
                        if addr.starts_with("https://") {
                            addr.clone()
                        } else if addr.contains('/') {
                            format!("https://{addr}")
                        } else {
                            format!("https://{addr}")
                        }
                    })
            })
            .unwrap_or_else(|| host_key.to_string())
    }

    /// Returns the public keys of all known hosts.
    pub(crate) fn known_hosts(&self) -> Vec<PublicKey> {
        self.hosts.hosts()
    }

    /// Queries a single host for account balance and prices.
    pub(crate) async fn host_account_info(&self, host_key: PublicKey) -> HostAccountInfo {
        let balance = self
            .transport
            .account_balance(host_key, &self.account_key)
            .await;
        let prices = self.transport.host_prices(host_key, false).await;
        HostAccountInfo {
            host_key,
            balance: balance.map_err(DownloadError::from),
            prices: prices.map_err(DownloadError::from),
        }
    }

    /// Downloads the shards of an erasure-coded slab.
    /// Successful shards will be decrypted using the
    /// encryption_key.
    ///
    /// offset and limit are the byte range to download
    /// from each sector.
    /// Sends a host-active notification if the channel is present.
    fn notify_host_active(
        &self,
        host_active: &Option<mpsc::UnboundedSender<String>>,
        host_key: &PublicKey,
    ) {
        if let Some(tx) = host_active {
            let _ = tx.send(self.host_url(host_key));
        }
    }

    async fn download_slab_shards(
        &self,
        encryption_key: &EncryptionKey,
        sectors: &[Sector],
        min_shards: u8,
        offset: u64,
        length: u64,
        max_inflight: usize,
        host_active: &Option<mpsc::UnboundedSender<String>>,
    ) -> Result<Vec<Option<Vec<u8>>>, DownloadError> {
        let total_shards = sectors.len();
        let zero_key = PublicKey::new([0u8; 32]);

        // Filter out unassigned sectors (zero host key),
        // preserving original indices for erasure coding
        let semaphore = Arc::new(Semaphore::new(max_inflight));
        let mut sectors = sectors
            .iter()
            .enumerate()
            .filter(|(_, s)| s.host_key != zero_key)
            .map(|(index, s)| SectorDownloadTask {
                sector: s.clone(),
                offset,
                length,
                index,
            })
            .collect::<Vec<_>>();

        if sectors.len() < min_shards as usize {
            return Err(DownloadError::NotEnoughShards(0, min_shards));
        }
        self.hosts
            .prioritize(&mut sectors, |task| &task.sector.host_key);
        let mut sectors = VecDeque::from(sectors);
        let mut download_tasks = JoinSet::new();
        for _ in 0..min_shards {
            match sectors.pop_front() {
                Some(task) => {
                    let permit = semaphore.clone().acquire_owned().await?;
                    self.notify_host_active(host_active, &task.sector.host_key);
                    let transport = self.transport.clone();
                    let account_key = self.account_key.clone();
                    join_set_spawn!(
                        download_tasks,
                        Self::try_download_sector(permit, transport, account_key, task,)
                    );
                }
                None => {
                    return Err(DownloadError::InvalidSlab(format!(
                        "not enough sectors to satisfy min_shards: have {}, need {}",
                        total_shards, min_shards
                    )));
                }
            };
        }

        let mut successful: u8 = 0;
        let mut shards = vec![None; total_shards];
        let mut total_failures: usize = 0;
        const MAX_TOTAL_FAILURES: usize = 30; // Give up after 30 failed attempts total

        loop {
            // If no tasks are in-flight and we still need more shards, give up.
            // This prevents an infinite loop when all tasks have completed but
            // min_shards was not reached.
            if download_tasks.is_empty() {
                let rem = min_shards.saturating_sub(successful);
                if rem == 0 {
                    return Ok(shards);
                }
                if sectors.is_empty() {
                    return Err(DownloadError::NotEnoughShards(successful, min_shards));
                }
                // Still have sectors to try — spawn them
                while download_tasks.len() < rem as usize {
                    if let Some(task) = sectors.pop_front() {
                        let permit = semaphore.clone().acquire_owned().await?;
                        self.notify_host_active(host_active, &task.sector.host_key);
                        let transport = self.transport.clone();
                        let account_key = self.account_key.clone();
                        join_set_spawn!(
                            download_tasks,
                            Self::try_download_sector(permit, transport, account_key, task,)
                        );
                    } else {
                        break;
                    }
                }
            }

            tokio::select! {
                biased;
                Some(res) = download_tasks.join_next() => {
                    let (host_key, result) = res?; // safe because tasks are never cancelled
                    match result {
                        Ok((index, mut data)) => {
                            let encryption_key = encryption_key.clone();
                            let data = maybe_spawn_blocking!({
                                encrypt_shard(&encryption_key, index as u8, offset as usize, &mut data);
                                data
                            });
                            shards[index] = Some(data);
                            successful += 1;
                            if successful >= min_shards {
                               return Ok(shards);
                            }
                        }
                        Err(e) => {
                            self.hosts.add_failure(&host_key);
                            total_failures += 1;
                            debug!("sector download from {} failed ({total_failures}/{MAX_TOTAL_FAILURES}): {:?}", host_key, e);

                            if total_failures >= MAX_TOTAL_FAILURES {
                                return Err(DownloadError::NotEnoughShards(successful, min_shards));
                            }

                            let rem = min_shards.saturating_sub(successful);
                            if rem == 0 {
                                return Ok(shards); // sanity check
                            } else if download_tasks.len() + sectors.len() < rem as usize {
                                return Err(DownloadError::NotEnoughShards(successful, min_shards));
                            } else if download_tasks.len() <= rem as usize && let Some(task) = sectors.pop_front() {
                                let transport = self.transport.clone();
                                let account_key = self.account_key.clone();
                                let permit = semaphore.clone().acquire_owned().await?;
                                self.notify_host_active(host_active, &task.sector.host_key);
                                // only spawn additional download tasks if there
                                // are not enough to satisfy the required number
                                // of shards. The sleep arm will handle slow
                                // hosts.
                                join_set_spawn!(download_tasks, Self::try_download_sector(
                                    permit,
                                    transport,
                                    account_key,
                                    task,
                                ));
                            }
                        }
                    }
                },
                _ = sleep(Duration::from_secs(1)) => {
                    if let Ok(racer_permit) = semaphore.clone().try_acquire_owned()
                        && let Some(task) = sectors.pop_front() {
                            self.notify_host_active(host_active, &task.sector.host_key);
                            let transport = self.transport.clone();
                            let account_key = self.account_key.clone();
                            join_set_spawn!(download_tasks, Self::try_download_sector(
                                racer_permit,
                                transport,
                                account_key,
                                task,
                            ));
                        }
                }
            }
        }
    }

    /// Downloads the provided slabs and writes the decrypted data to the
    /// provided writer.
    pub async fn download<W: AsyncWriteExt + Unpin>(
        &self,
        w: &mut W,
        object: &Object,
        options: DownloadOptions,
    ) -> Result<(), DownloadError> {
        let mut w = object.writer(w, options.offset as usize);
        let mut offset = options.offset;
        let max_length = object.size();
        let mut length = options.length.unwrap_or(max_length);
        if offset > max_length || length == 0 {
            return Ok(());
        }

        for slab in object.slabs() {
            if length == 0 {
                break;
            }

            let slab_length = slab.length as u64;
            if offset >= slab_length {
                offset -= slab_length;
                continue;
            }

            // adjust slab range based on offset and length
            let slab_offset = slab.offset as u64 + offset;
            let slab_length = (slab_length - offset).min(length);
            offset = 0;

            // compute the sector aligned region to download
            let chunk_size = SEGMENT_SIZE as u64 * slab.min_shards as u64;
            let start = (slab_offset / chunk_size) * SEGMENT_SIZE as u64;
            let end = (slab_offset + slab_length).div_ceil(chunk_size) * SEGMENT_SIZE as u64;
            let shard_offset = start;
            let shard_length = end - start;

            let mut shards = self
                .download_slab_shards(
                    &slab.encryption_key,
                    &slab.sectors,
                    slab.min_shards,
                    shard_offset,
                    shard_length,
                    options.max_inflight,
                    &options.host_active,
                )
                .await?;
            let data_shards = slab.min_shards as usize;
            let parity_shards = slab.sectors.len() - slab.min_shards as usize;
            let shards = maybe_spawn_blocking!({
                let rs = ErasureCoder::new(data_shards, parity_shards)?;
                rs.reconstruct_data_shards(&mut shards)?;
                Ok::<_, erasure_coding::Error>(shards)
            })?;
            ErasureCoder::write_data_shards(
                &mut w,
                &shards[..data_shards],
                slab_offset as usize % (SEGMENT_SIZE * slab.min_shards as usize),
                slab_length as usize,
            )
            .await?;
            length -= slab_length;
            if let Some(ref tx) = options.slab_downloaded {
                let _ = tx.send(());
            }
        }
        w.flush().await?;
        Ok(())
    }
}
