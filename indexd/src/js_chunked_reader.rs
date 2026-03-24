/// JavaScript-backed chunked reader for streaming large file uploads in WASM.
///
/// Uses a tokio mpsc channel as the bridge between JavaScript's File API and
/// Rust's AsyncRead trait. JavaScript sends chunks via the channel sender,
/// and the upload pipeline reads from the receiver via AsyncRead.
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncRead;
use tokio::sync::mpsc;

/// A reader that receives chunks from JavaScript via a tokio mpsc channel.
pub struct JsChunkedReader {
    rx: mpsc::Receiver<Bytes>,
    /// Remaining bytes from a partially-read chunk
    current: Option<Bytes>,
}

impl JsChunkedReader {
    /// Creates a new reader and returns it along with the sender.
    /// JavaScript pushes `Bytes` into the sender; call `drop(tx)` or
    /// let it go out of scope to signal EOF.
    pub fn new(buffer: usize) -> (Self, mpsc::Sender<Bytes>) {
        let (tx, rx) = mpsc::channel(buffer);
        (
            Self {
                rx,
                current: None,
            },
            tx,
        )
    }
}

impl AsyncRead for JsChunkedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // Drain the current chunk first
            if let Some(ref mut chunk) = self.current {
                let to_read = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..to_read]);
                *chunk = chunk.slice(to_read..);
                if chunk.is_empty() {
                    self.current = None;
                }
                return Poll::Ready(Ok(()));
            }

            // Try to receive the next chunk
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    self.current = Some(chunk);
                    continue;
                }
                Poll::Ready(None) => {
                    // Channel closed = EOF
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}
