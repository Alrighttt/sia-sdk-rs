use std::io::Cursor;
use std::sync::{Arc, Mutex};

use indexd::app_client::{RegisterAppRequest, RegisterAppResponse};
use js_sys::Uint8Array;
use sia::seed::Seed;
use sia::signing::{PrivateKey, Signature};
use sia::types::Hash256;
use std::str::FromStr;
use std::time::SystemTime;
use wasm_bindgen::prelude::*;

/// Install a panic hook and logging bridge so that Rust panics show a proper
/// stack trace and `log::debug!()` / `log::info!()` etc. appear in the browser
/// console.
#[wasm_bindgen(start)]
fn init_panic_hook() {
    console_error_panic_hook::set_once();
    console_log::init_with_level(log::Level::Debug).ok();
}

/// Converts a JsValue error context into a JsError.
fn to_js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

// ── AppKey ──────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct AppKey(PrivateKey);

#[wasm_bindgen]
impl AppKey {
    /// Imports an AppKey from a 64-byte ed25519 keypair or a 32-byte seed.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8]) -> Result<AppKey, JsError> {
        match key.len() {
            64 => {
                let mut keypair = [0u8; 64];
                keypair.copy_from_slice(key);
                Ok(AppKey(PrivateKey::from(keypair)))
            }
            32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(key);
                Ok(AppKey(PrivateKey::from_seed(&seed)))
            }
            _ => Err(JsError::new("app key must be 64 bytes (keypair) or 32 bytes (seed)")),
        }
    }

    /// Exports the full 64-byte ed25519 keypair.
    pub fn export(&self) -> Uint8Array {
        Uint8Array::from(self.0.as_ref())
    }

    /// Returns the hex-encoded public key.
    #[wasm_bindgen(js_name = "publicKey")]
    pub fn public_key(&self) -> String {
        self.0.public_key().to_string()
    }

    /// Signs a message, returning the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Uint8Array {
        let sig = self.0.sign(message);
        Uint8Array::from(sig.as_ref() as &[u8])
    }

    /// Verifies a signature against a message.
    #[wasm_bindgen(js_name = "verifySignature")]
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
        if signature.len() != 64 {
            return Err(JsError::new("signatures must be 64 bytes"));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        Ok(self
            .0
            .public_key()
            .verify(message, &Signature::from(sig_bytes)))
    }
}

// ── PinnedObject ────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct PinnedObject {
    inner: Arc<Mutex<indexd::Object>>,
}

#[wasm_bindgen]
impl PinnedObject {
    /// Opens a sealed object (JSON) using the provided app key.
    pub fn open(app_key: &AppKey, sealed_json: &str) -> Result<PinnedObject, JsError> {
        let sealed: indexd::SealedObject =
            serde_json::from_str(sealed_json).map_err(to_js_err)?;
        let obj = sealed.open(&app_key.0).map_err(to_js_err)?;
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(obj)),
        })
    }

    /// Seals the object for offline storage, returning JSON.
    pub fn seal(&self, app_key: &AppKey) -> Result<String, JsError> {
        let inner = self.inner.lock().map_err(to_js_err)?;
        let sealed = inner.seal(&app_key.0);
        serde_json::to_string(&sealed).map_err(to_js_err)
    }

    /// Returns the object's ID as a hex string.
    pub fn id(&self) -> Result<String, JsError> {
        let inner = self.inner.lock().map_err(to_js_err)?;
        Ok(inner.id().to_string())
    }

    /// Returns the total size of the object in bytes.
    pub fn size(&self) -> Result<f64, JsError> {
        let inner = self.inner.lock().map_err(to_js_err)?;
        Ok(inner.size() as f64)
    }

    /// Returns the metadata as a Uint8Array.
    pub fn metadata(&self) -> Result<Uint8Array, JsError> {
        let inner = self.inner.lock().map_err(to_js_err)?;
        Ok(Uint8Array::from(inner.metadata.as_slice()))
    }

    /// Updates the metadata.
    #[wasm_bindgen(js_name = "updateMetadata")]
    pub fn update_metadata(&self, metadata: &[u8]) -> Result<(), JsError> {
        let mut inner = self.inner.lock().map_err(to_js_err)?;
        inner.metadata = metadata.to_vec();
        Ok(())
    }
}

// ── SDK ─────────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct SDK {
    inner: indexd::SDK,
}

#[wasm_bindgen]
impl SDK {
    /// Returns the app key used by this SDK instance.
    #[wasm_bindgen(js_name = "appKey")]
    pub fn app_key(&self) -> AppKey {
        AppKey(self.inner.app_key().clone())
    }

    /// Uploads a Uint8Array to the Sia network.
    ///
    /// Returns a PinnedObject containing the metadata needed to download the data.
    pub async fn upload(&self, data: &[u8]) -> Result<PinnedObject, JsError> {
        log::info!("upload: starting ({} bytes)", data.len());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(to_js_err)?;
        let _guard = rt.enter();
        let local = tokio::task::LocalSet::new();
        let cursor = Cursor::new(data.to_vec());
        let object: indexd::Object = local
            .run_until(self.inner.upload(cursor, indexd::UploadOptions::default()))
            .await
            .map_err(to_js_err)?;
        log::info!("upload: complete");
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(object)),
        })
    }

    /// Downloads an object's data, returning a Uint8Array.
    pub async fn download(&self, object: &PinnedObject) -> Result<Uint8Array, JsError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(to_js_err)?;
        let _guard = rt.enter();
        let local = tokio::task::LocalSet::new();
        let obj = object.inner.lock().map_err(to_js_err)?.clone();
        let size = obj.size() as usize;
        let mut buf = vec![0u8; size];
        local
            .run_until(async {
                self.inner.download(
                    &mut Cursor::new(&mut buf),
                    &obj,
                    indexd::DownloadOptions::default(),
                ).await
            })
            .await
            .map_err(to_js_err)?;
        Ok(Uint8Array::from(buf.as_slice()))
    }

    /// Uploads a Uint8Array with per-shard progress reporting.
    ///
    /// The `on_progress` callback receives `(current_shards, total_shards)`.
    #[wasm_bindgen(js_name = "uploadWithProgress")]
    pub async fn upload_with_progress(
        &self,
        data: &[u8],
        on_progress: &js_sys::Function,
    ) -> Result<PinnedObject, JsError> {
        log::info!("upload_with_progress: starting ({} bytes)", data.len());
        let slab_data_size = 10usize * 4_194_304; // data_shards(10) * SECTOR_SIZE(4 MiB)
        let num_slabs = if data.is_empty() { 0 } else { data.len().div_ceil(slab_data_size) };
        let total_shards = (num_slabs as u32) * 30; // 30 shards per slab (10 data + 20 parity)

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let options = indexd::UploadOptions {
            shard_uploaded: Some(tx),
            ..Default::default()
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(to_js_err)?;
        let _guard = rt.enter();
        let local = tokio::task::LocalSet::new();
        let cursor = Cursor::new(data.to_vec());
        let on_progress = on_progress.clone();
        let object: indexd::Object = local
            .run_until(async {
                tokio::task::spawn_local(async move {
                    let mut count: u32 = 0;
                    while rx.recv().await.is_some() {
                        count += 1;
                        let _ = on_progress.call2(
                            &JsValue::NULL,
                            &JsValue::from(count),
                            &JsValue::from(total_shards),
                        );
                    }
                });
                self.inner.upload(cursor, options).await
            })
            .await
            .map_err(to_js_err)?;
        log::info!("upload_with_progress: complete");
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(object)),
        })
    }

    /// Downloads an object's data with per-slab progress reporting.
    ///
    /// The `on_progress` callback receives `(current_slabs, total_slabs)`.
    #[wasm_bindgen(js_name = "downloadWithProgress")]
    pub async fn download_with_progress(
        &self,
        object: &PinnedObject,
        on_progress: &js_sys::Function,
    ) -> Result<Uint8Array, JsError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(to_js_err)?;
        let _guard = rt.enter();
        let local = tokio::task::LocalSet::new();
        let obj = object.inner.lock().map_err(to_js_err)?.clone();
        let size = obj.size() as usize;
        let total_slabs = obj.slabs().len() as u32;
        let mut buf = vec![0u8; size];

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let options = indexd::DownloadOptions {
            slab_downloaded: Some(tx),
            ..Default::default()
        };

        let on_progress = on_progress.clone();
        local
            .run_until(async {
                tokio::task::spawn_local(async move {
                    let mut count: u32 = 0;
                    while rx.recv().await.is_some() {
                        count += 1;
                        let _ = on_progress.call2(
                            &JsValue::NULL,
                            &JsValue::from(count),
                            &JsValue::from(total_slabs),
                        );
                    }
                });
                self.inner
                    .download(&mut Cursor::new(&mut buf), &obj, options)
                    .await
            })
            .await
            .map_err(to_js_err)?;
        Ok(Uint8Array::from(buf.as_slice()))
    }

    /// Returns hosts as a JSON array.
    pub async fn hosts(&self) -> Result<JsValue, JsError> {
        let hosts = self
            .inner
            .hosts(Default::default())
            .await
            .map_err(to_js_err)?;
        serde_wasm_bindgen::to_value(&hosts).map_err(to_js_err)
    }

    /// Returns account information as a JS object.
    pub async fn account(&self) -> Result<JsValue, JsError> {
        let a = self.inner.account().await.map_err(to_js_err)?;
        let obj = serde_json::json!({
            "accountKey": a.account_key.to_string(),
            "connectKey": a.connect_key,
            "maxPinnedData": a.max_pinned_data,
            "pinnedData": a.pinned_data,
            "app": {
                "id": a.app.id.to_string(),
                "description": a.app.description,
                "serviceUrl": a.app.service_url,
                "logoUrl": a.app.logo_url,
            },
            "lastUsed": a.last_used.timestamp_millis(),
        });
        serde_wasm_bindgen::to_value(&obj).map_err(to_js_err)
    }

    /// Retrieves a pinned object by its hex-encoded key.
    pub async fn object(&self, key: &str) -> Result<PinnedObject, JsError> {
        let key = Hash256::from_str(key).map_err(to_js_err)?;
        let obj = self.inner.object(&key).await.map_err(to_js_err)?;
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(obj)),
        })
    }

    /// Pins an object to the indexer.
    #[wasm_bindgen(js_name = "pinObject")]
    pub async fn pin_object(&self, object: &PinnedObject) -> Result<(), JsError> {
        let obj = object.inner.lock().map_err(to_js_err)?.clone();
        self.inner.pin_object(&obj).await.map_err(to_js_err)
    }

    /// Updates the metadata of an object already stored in the indexer.
    #[wasm_bindgen(js_name = "updateObjectMetadata")]
    pub async fn update_object_metadata(&self, object: &PinnedObject) -> Result<(), JsError> {
        let obj = object.inner.lock().map_err(to_js_err)?.clone();
        self.inner
            .update_object_metadata(&obj)
            .await
            .map_err(to_js_err)
    }

    /// Deletes an object from the indexer by its hex-encoded key.
    #[wasm_bindgen(js_name = "deleteObject")]
    pub async fn delete_object(&self, key: &str) -> Result<(), JsError> {
        let key = Hash256::from_str(key).map_err(to_js_err)?;
        self.inner.delete_object(&key).await.map_err(to_js_err)
    }

    /// Prunes unused slabs from the indexer.
    #[wasm_bindgen(js_name = "pruneSlabs")]
    pub async fn prune_slabs(&self) -> Result<(), JsError> {
        self.inner.prune_slabs().await.map_err(to_js_err)
    }

    /// Creates a share URL for an object, valid until the given timestamp (ms since epoch).
    #[wasm_bindgen(js_name = "shareObject")]
    pub fn share_object(
        &self,
        object: &PinnedObject,
        valid_until_ms: f64,
    ) -> Result<String, JsError> {
        let obj = object.inner.lock().map_err(to_js_err)?.clone();
        let duration = std::time::Duration::from_millis(valid_until_ms as u64);
        let valid_until = SystemTime::UNIX_EPOCH + duration;
        let url = self
            .inner
            .share_object(&obj, valid_until.into())
            .map_err(to_js_err)?;
        Ok(url.to_string())
    }

    /// Retrieves a shared object from a signed share URL.
    /// Accepts both `https://` and `sia://` schemes.
    #[wasm_bindgen(js_name = "sharedObject")]
    pub async fn shared_object(&self, share_url: &str) -> Result<PinnedObject, JsError> {
        let url = if share_url.starts_with("sia://") {
            format!("https://{}", &share_url[6..])
        } else {
            share_url.to_string()
        };
        let obj = self
            .inner
            .shared_object(url)
            .await
            .map_err(to_js_err)?;
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(obj)),
        })
    }
}

// ── Builder ─────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct Builder {
    state: Arc<Mutex<Option<BuilderState>>>,
}

enum BuilderState {
    Disconnected(indexd::Builder<indexd::DisconnectedState>),
    RequestingApproval(indexd::Builder<indexd::RequestingApprovalState>),
    Approved(indexd::Builder<indexd::ApprovedState>),
    Finalized,
}

#[wasm_bindgen]
impl Builder {
    /// Creates a new SDK builder for the given indexer URL.
    #[wasm_bindgen(constructor)]
    pub fn new(indexer_url: &str) -> Result<Builder, JsError> {
        let builder = indexd::Builder::new(indexer_url).map_err(to_js_err)?;
        Ok(Builder {
            state: Arc::new(Mutex::new(Some(BuilderState::Disconnected(builder)))),
        })
    }

    /// Attempts to connect using an existing app key.
    ///
    /// Returns the SDK if authenticated, or null if the key is not recognized.
    /// Call `requestConnection` if null is returned.
    pub async fn connected(&self, app_key: &AppKey) -> Result<JsValue, JsError> {
        let state = self
            .state
            .lock()
            .map_err(to_js_err)?
            .take()
            .ok_or_else(|| JsError::new("invalid builder state"))?;

        match state {
            BuilderState::Disconnected(builder) => {
                match builder.connected(&app_key.0).await.map_err(to_js_err)? {
                    Some(sdk) => {
                        *self.state.lock().map_err(to_js_err)? = Some(BuilderState::Finalized);
                        Ok(SDK { inner: sdk }.into())
                    }
                    None => {
                        *self.state.lock().map_err(to_js_err)? =
                            Some(BuilderState::Disconnected(builder));
                        Ok(JsValue::NULL)
                    }
                }
            }
            other => {
                *self.state.lock().map_err(to_js_err)? = Some(other);
                Err(JsError::new("invalid state: expected Disconnected"))
            }
        }
    }

    /// Requests a new app connection. Pass app metadata as a JSON object:
    /// ```json
    /// {
    ///   "app_id": [32 bytes as hex],
    ///   "name": "My App",
    ///   "description": "...",
    ///   "service_url": "https://...",
    ///   "logo_url": "https://..." (optional),
    ///   "callback_url": "https://..." (optional)
    /// }
    /// ```
    #[wasm_bindgen(js_name = "requestConnection")]
    pub async fn request_connection(&self, app_meta_json: &str) -> Result<(), JsError> {
        let meta: RegisterAppRequest =
            serde_json::from_str(app_meta_json).map_err(to_js_err)?;

        let state = self
            .state
            .lock()
            .map_err(to_js_err)?
            .take()
            .ok_or_else(|| JsError::new("invalid builder state"))?;

        match state {
            BuilderState::Disconnected(builder) => {
                let builder = builder
                    .request_connection(&meta)
                    .await
                    .map_err(to_js_err)?;
                *self.state.lock().map_err(to_js_err)? =
                    Some(BuilderState::RequestingApproval(builder));
                Ok(())
            }
            other => {
                *self.state.lock().map_err(to_js_err)? = Some(other);
                Err(JsError::new("invalid state: expected Disconnected"))
            }
        }
    }

    /// Transitions the builder using a pre-fetched connection response.
    /// Use this when the `POST /auth/connect` call was made out-of-band
    /// (e.g. via curl) to work around CORS restrictions.
    ///
    /// `app_id_hex` is the hex-encoded app ID used in the request.
    /// `response_json` is the JSON response from `POST /auth/connect`.
    #[wasm_bindgen(js_name = "setConnectionResponse")]
    pub fn set_connection_response(
        &self,
        app_id_hex: &str,
        response_json: &str,
    ) -> Result<(), JsError> {
        let app_id = Hash256::from_str(app_id_hex).map_err(to_js_err)?;
        let response: RegisterAppResponse =
            serde_json::from_str(response_json).map_err(to_js_err)?;

        let state = self
            .state
            .lock()
            .map_err(to_js_err)?
            .take()
            .ok_or_else(|| JsError::new("invalid builder state"))?;

        match state {
            BuilderState::Disconnected(builder) => {
                let builder = builder
                    .with_connection_response(app_id, response)
                    .map_err(to_js_err)?;
                *self.state.lock().map_err(to_js_err)? =
                    Some(BuilderState::RequestingApproval(builder));
                Ok(())
            }
            other => {
                *self.state.lock().map_err(to_js_err)? = Some(other);
                Err(JsError::new("invalid state: expected Disconnected"))
            }
        }
    }

    /// Returns the response URL the user must visit to authorize the connection.
    #[wasm_bindgen(js_name = "responseUrl")]
    pub fn response_url(&self) -> Result<String, JsError> {
        let state = self.state.lock().map_err(to_js_err)?;
        match state.as_ref() {
            Some(BuilderState::RequestingApproval(builder)) => {
                Ok(builder.response_url().to_owned())
            }
            _ => Err(JsError::new(
                "invalid state: expected RequestingApproval",
            )),
        }
    }

    /// Polls for approval. Resolves when the user approves.
    #[wasm_bindgen(js_name = "waitForApproval")]
    pub async fn wait_for_approval(&self) -> Result<(), JsError> {
        let state = self
            .state
            .lock()
            .map_err(to_js_err)?
            .take()
            .ok_or_else(|| JsError::new("invalid builder state"))?;

        match state {
            BuilderState::RequestingApproval(builder) => {
                let builder = builder.wait_for_approval().await.map_err(to_js_err)?;
                *self.state.lock().map_err(to_js_err)? = Some(BuilderState::Approved(builder));
                Ok(())
            }
            other => {
                *self.state.lock().map_err(to_js_err)? = Some(other);
                Err(JsError::new(
                    "invalid state: expected RequestingApproval",
                ))
            }
        }
    }

    /// Registers the app using the user's recovery phrase and returns the SDK.
    pub async fn register(&self, mnemonic: &str) -> Result<SDK, JsError> {
        let state = self
            .state
            .lock()
            .map_err(to_js_err)?
            .take()
            .ok_or_else(|| JsError::new("invalid builder state"))?;

        match state {
            BuilderState::Approved(builder) => {
                let sdk = builder.register(mnemonic).await.map_err(to_js_err)?;
                *self.state.lock().map_err(to_js_err)? = Some(BuilderState::Finalized);
                Ok(SDK { inner: sdk })
            }
            other => {
                *self.state.lock().map_err(to_js_err)? = Some(other);
                Err(JsError::new("invalid state: expected Approved"))
            }
        }
    }
}

// ── Free functions ──────────────────────────────────────────────────────

/// Generates a new 12-word BIP-32 recovery phrase.
#[wasm_bindgen(js_name = "generateRecoveryPhrase")]
pub fn generate_recovery_phrase() -> String {
    let seed: [u8; 16] = rand::random();
    Seed::from_seed(seed).to_string()
}

/// Validates a BIP-32 recovery phrase.
#[wasm_bindgen(js_name = "validateRecoveryPhrase")]
pub fn validate_recovery_phrase(phrase: &str) -> Result<(), JsError> {
    Seed::new(phrase).map_err(to_js_err)?;
    Ok(())
}

/// Connects to a host via WebTransport and fetches its settings/prices.
///
/// `address` should be a host address like `host.example.com:9883`.
/// Returns the host settings as a JS object.
#[wasm_bindgen(js_name = "fetchHostSettings")]
pub async fn fetch_host_settings(address: &str) -> Result<JsValue, JsError> {
    let settings = indexd::web_transport::fetch_host_settings(address)
        .await
        .map_err(to_js_err)?;
    serde_wasm_bindgen::to_value(&settings).map_err(to_js_err)
}
