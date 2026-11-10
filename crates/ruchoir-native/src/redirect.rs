//! The browser's part of a sign-in. The app opens the authorization request in the system browser
//! ([`Browser`]) and receives the browser back ([`Redirect`]). On the desktop the redirect is a
//! loopback address (RFC 8252, section 7.3): [`Loopback`] listens on `127.0.0.1` on a port the
//! system picks, for one request to its path.

use std::future::Future;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Opens an address in the person's browser (the `opener` plugin of Tauri, for instance).
pub trait Browser: Send + Sync {
    fn open(&self, url: &str) -> Result<(), String>;
}

/// Receives the browser back from Propolis.
pub trait Redirect: Send {
    /// The address Propolis sends the browser back to, registered for the app.
    fn redirect_uri(&self) -> String;
    /// The address the browser came back to, query included.
    fn receive(self) -> impl Future<Output = Result<String, String>> + Send;
}

/// The longest request line and headers the listener reads.
const MAX_REQUEST: usize = 16 * 1024;

/// A one-shot listener on `http://127.0.0.1:<port>/callback`.
pub struct Loopback {
    listener: TcpListener,
    port: u16,
    page: String,
    timeout: Duration,
}

impl Loopback {
    /// Listen on a free port of `127.0.0.1`. `page` is the HTML the browser shows once it is back
    /// (in the person's language: the app knows it), and `timeout` how long the sign-in may take.
    pub async fn bind(page: impl Into<String>, timeout: Duration) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        Ok(Self {
            listener,
            port,
            page: page.into(),
            timeout,
        })
    }

    async fn wait(self) -> Result<String, String> {
        loop {
            let (mut stream, _) = self.listener.accept().await.map_err(|e| e.to_string())?;
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 2048];
            while !buffer.windows(4).any(|w| w == b"\r\n\r\n") && buffer.len() < MAX_REQUEST {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                }
            }
            let head = String::from_utf8_lossy(&buffer);
            let mut line = head.lines().next().unwrap_or_default().split(' ');
            let (method, target) = (line.next(), line.next().unwrap_or_default());
            let path = target.split('?').next().unwrap_or_default();
            if method != Some("GET") || path != "/callback" {
                // A favicon or a stray request: answer and keep waiting.
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                continue;
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                self.page.len(),
                self.page
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
            return Ok(format!("http://127.0.0.1:{}{target}", self.port));
        }
    }
}

impl Redirect for Loopback {
    fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}/callback", self.port)
    }

    async fn receive(self) -> Result<String, String> {
        let timeout = self.timeout;
        tokio::time::timeout(timeout, self.wait())
            .await
            .map_err(|_| "the sign-in took too long".to_owned())?
    }
}
