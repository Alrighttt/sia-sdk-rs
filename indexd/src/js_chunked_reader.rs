/// JavaScript-backed chunked reader for streaming large file uploads in WASM
///
/// This module provides a bridge between JavaScript's File API and Rust's AsyncRead trait,
/// allowing large files to be uploaded without loading the entire file into WASM memory.
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::io::AsyncRead;

/// State shared between the reader and the WASM binding layer
pub struct ReaderState {
    /// Queue of data chunks received from JavaScript
    pub chunks: VecDeque<Vec<u8>>,
    /// Current chunk being read
    pub(crate) current_chunk: Option<Vec<u8>>,
    /// Current read position within the current chunk
    pub(crate) position: usize,
    /// Whether EOF has been reached
    pub eof: bool,
    /// Waker to notify when new data arrives (for the upload pipeline)
    pub waker: Option<Waker>,
    /// Error from JavaScript side
    pub error: Option<String>,
}

/// A reader that receives chunks from JavaScript on-demand
pub struct JsChunkedReader {
    /// Shared state for this reader
    state: Arc<Mutex<ReaderState>>,
}

impl JsChunkedReader {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ReaderState {
                chunks: VecDeque::new(),
                current_chunk: None,
                position: 0,
                eof: false,
                waker: None,
                error: None,
            })),
        }
    }

    /// Returns a reference to the reader state for external access
    pub fn state(&self) -> &Arc<Mutex<ReaderState>> {
        &self.state
    }
}

impl AsyncRead for JsChunkedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.state.lock().expect("WASM is single-threaded; mutex cannot be poisoned");

        // Check for error first
        if let Some(error) = &state.error {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, error.clone())));
        }

        loop {
            // Try to read from current chunk if available
            if let Some(chunk) = &state.current_chunk {
                let available = chunk.len() - state.position;

                if available > 0 {
                    let to_read = available.min(buf.remaining());
                    let start = state.position;
                    let end = start + to_read;

                    buf.put_slice(&chunk[start..end]);
                    state.position = end;

                    if state.position >= chunk.len() {
                        state.current_chunk = None;
                        state.position = 0;
                    }

                    return Poll::Ready(Ok(()));
                }
            }

            // Current chunk is exhausted or doesn't exist, try to get the next one
            if let Some(next_chunk) = state.chunks.pop_front() {
                state.current_chunk = Some(next_chunk);
                state.position = 0;
                continue;
            }

            // No chunks available
            if state.eof {
                // No more data and EOF reached
                return Poll::Ready(Ok(()));
            } else {
                // No data available yet, register waker and wait
                state.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
    }
}

// WASM is single-threaded, so Send is safe
unsafe impl Send for JsChunkedReader {}
