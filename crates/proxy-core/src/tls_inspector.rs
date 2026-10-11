//! `tls_inspector` listener filter: peeks the TLS
//! ClientHello off an accepted connection *without consuming it* and extracts
//! SNI + ALPN so filter-chain matching (`crate::filter_chain`) can key on
//! `server_names`/`application_protocols`/`transport_protocol`. Does not
//! terminate TLS -- the real handshake (or the terminal filter)
//! still sees every byte, undisturbed.

use std::time::Duration;

use tls_parser::nom;
use tokio::net::TcpStream;

/// First byte of a TLS record whose content type is `handshake` (0x16). Any
/// other first byte means "not TLS" and we bail out immediately -- Envoy's
/// `tls_inspector` discriminates on exactly this byte, without waiting for
/// more data, so plaintext connections aren't delayed.
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;

/// Wall-clock bound on the whole inspect operation. Envoy's
/// `listener_filters_timeout` defaults to 15s; that's too slow for tests and
/// still a reasonable production bound, so we use a shorter default here.
// TODO: honor `listener_filters_timeout` once that field exists on
// `ListenerConfig`'s IR; today every listener gets this fixed timeout.
const INSPECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Backoff applied when a peek returns exactly as many bytes as the previous
/// one and the ClientHello is still incomplete -- see the Rust note in
/// [`peek_client_hello`] for why this is necessary.
const STALL_BACKOFF: Duration = Duration::from_millis(5);

/// Smallest peek buffer we start with; grown (doubled, capped at
/// `max_client_hello_size`) as needed.
const INITIAL_PEEK_LEN: usize = 4096;

/// What the TLS inspector learned about a connection by peeking its first
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedTls {
    /// SNI host, lowercased to match the case-insensitive SNI matcher in
    /// `filter_chain.rs`. `None` if the ClientHello carried no SNI extension.
    pub server_name: Option<String>,
    /// ALPN protocol IDs, in the client's offered order. Empty if the
    /// ClientHello carried no ALPN extension.
    pub application_protocols: Vec<String>,
}

/// Peek (without consuming) the ClientHello on `stream` and extract SNI+ALPN.
///
/// Returns `Ok(None)` when the connection is NOT TLS (first byte isn't a TLS
/// handshake record) or the ClientHello can't be parsed within limits (either
/// `max_client_hello_size` or the internal wall-clock timeout) -- the caller
/// then treats it as plaintext, matching Envoy's default
/// `close_connection_on_client_hello_parsing_errors=false` behavior (the
/// `true` variant is rejected at config load, so `false` is the only
/// behavior this function needs to implement).
///
/// `Err` is reserved for real socket errors (not parse failures).
pub async fn inspect_client_hello(
    stream: &TcpStream,
    max_client_hello_size: u32,
) -> std::io::Result<Option<InspectedTls>> {
    match tokio::time::timeout(
        INSPECT_TIMEOUT,
        peek_client_hello(stream, max_client_hello_size as usize),
    )
    .await
    {
        Ok(result) => result,
        // Rust note: `tokio::time::timeout`'s `Err` is the *timeout itself*
        // firing, not an I/O error -- from the caller's point of view that's
        // indistinguishable from "couldn't parse in time", so it collapses to
        // `Ok(None)` (treat as plaintext) rather than propagating an error.
        Err(_elapsed) => Ok(None),
    }
}

/// The actual peek loop, run under `inspect_client_hello`'s timeout.
async fn peek_client_hello(
    stream: &TcpStream,
    max_client_hello_size: usize,
) -> std::io::Result<Option<InspectedTls>> {
    let cap = max_client_hello_size.max(1);
    let mut buf = vec![0u8; INITIAL_PEEK_LEN.min(cap)];
    // Tracks the byte count from the previous *non-growing* iteration, so we
    // can tell "no new bytes arrived" apart from "we just grew the buffer".
    let mut last_incomplete_n: Option<usize> = None;

    loop {
        // Rust note: `TcpStream::peek` reads from the front of the kernel
        // receive buffer *without* draining it, so whatever we read here is
        // still there for the real TLS handshake (or the stub handler) to
        // read again later. It's also already `async`: on a socket with zero
        // bytes buffered it registers interest and waits for the first byte,
        // same as `read().await` would.
        let n = stream.peek(&mut buf).await?;
        if n == 0 {
            // Peer closed before sending anything.
            return Ok(None);
        }
        if buf[0] != TLS_HANDSHAKE_CONTENT_TYPE {
            return Ok(None);
        }

        match tls_parser::parse_tls_plaintext(&buf[..n]) {
            Ok((_rest, plaintext)) => return Ok(extract_client_hello(&plaintext)),
            Err(nom::Err::Incomplete(_)) => {
                if n >= cap {
                    // Exceeded max_client_hello_size without a complete
                    // record: give up, treat as unparseable.
                    return Ok(None);
                }
                if n == buf.len() {
                    // The peek buffer was fully saturated -- there may
                    // already be more bytes sitting in the kernel than we
                    // asked to peek, so grow and retry immediately rather
                    // than waiting.
                    let new_len = (buf.len() * 2).min(cap);
                    buf.resize(new_len, 0);
                    last_incomplete_n = None;
                } else if last_incomplete_n == Some(n) {
                    // Rust note: because `peek` never drains the socket, a
                    // second `.await` on it can return *instantly* with the
                    // exact same bytes as before if the kernel still reports
                    // the fd readable -- readiness here is level-triggered on
                    // "there is unread data", not edge-triggered on "new data
                    // arrived". Without this check we'd hot-loop calling
                    // `peek` as fast as the executor can schedule us, pinning
                    // a CPU while genuinely waiting on the peer. Back off
                    // briefly instead; the outer `INSPECT_TIMEOUT` bounds how
                    // long this can go on for.
                    tokio::time::sleep(STALL_BACKOFF).await;
                } else {
                    last_incomplete_n = Some(n);
                }
            }
            Err(_) => return Ok(None), // not a valid ClientHello record
        }
    }
}

/// Pull SNI + ALPN out of a parsed `TlsPlaintext` record, if (and only if) it
/// contains a ClientHello handshake message. `None` means "this TLS record
/// isn't a ClientHello" -- treated the same as a parse failure by the caller.
fn extract_client_hello(plaintext: &tls_parser::TlsPlaintext<'_>) -> Option<InspectedTls> {
    let client_hello = plaintext.msg.iter().find_map(|msg| match msg {
        tls_parser::TlsMessage::Handshake(tls_parser::TlsMessageHandshake::ClientHello(ch)) => {
            Some(ch)
        }
        _ => None,
    })?;

    let mut server_name = None;
    let mut application_protocols = Vec::new();

    if let Some(ext_bytes) = client_hello.ext {
        // Rust note: extension parsing is best-effort -- a ClientHello with
        // extensions we can't fully parse still counts as "this connection
        // is TLS", it just may be missing SNI/ALPN. `unwrap_or_default`
        // rather than propagating an error keeps that distinction.
        let (_, extensions) =
            tls_parser::parse_tls_client_hello_extensions(ext_bytes).unwrap_or_default();
        for ext in extensions {
            match ext {
                tls_parser::TlsExtension::SNI(names) => {
                    // First `host_name`-typed entry, lowercased to match the
                    // case-insensitive SNI matcher in `filter_chain.rs`.
                    server_name = names
                        .into_iter()
                        .find(|(ty, _)| *ty == tls_parser::SNIType::HostName)
                        .and_then(|(_, raw)| std::str::from_utf8(raw).ok())
                        .map(|s| s.to_ascii_lowercase());
                }
                tls_parser::TlsExtension::ALPN(protocols) => {
                    application_protocols = protocols
                        .into_iter()
                        .filter_map(|p| std::str::from_utf8(p).ok())
                        .map(str::to_string)
                        .collect();
                }
                _ => {}
            }
        }
    }

    Some(InspectedTls {
        server_name,
        application_protocols,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Drive a `rustls::ClientConnection` far enough to produce its first
    /// flight (the ClientHello) without touching the network, then hand back
    /// the raw bytes it would have written to the wire.
    fn client_hello_bytes(server_name: &str, alpn: &[&str]) -> Vec<u8> {
        let root_store = rustls::RootCertStore::empty();
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        let server_name: rustls::pki_types::ServerName<'static> =
            server_name.to_string().try_into().unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();

        let mut bytes = Vec::new();
        // Rust note: `write_tls` serializes whatever handshake flight rustls
        // currently has queued (just the ClientHello, at this point) into an
        // in-memory buffer implementing `std::io::Write` -- no socket needed.
        conn.write_tls(&mut bytes).unwrap();
        bytes
    }

    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn extracts_sni_and_alpn() {
        let (mut client, server) = loopback_pair().await;
        let hello = client_hello_bytes("example.com", &["h2", "http/1.1"]);
        client.write_all(&hello).await.unwrap();

        let result = inspect_client_hello(&server, 16384).await.unwrap();
        let inspected = result.expect("should recognize TLS ClientHello");
        assert_eq!(inspected.server_name.as_deref(), Some("example.com"));
        assert_eq!(inspected.application_protocols, vec!["h2", "http/1.1"]);
    }

    #[tokio::test]
    async fn non_tls_first_byte_returns_none_promptly() {
        let (mut client, server) = loopback_pair().await;
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            inspect_client_hello(&server, 16384),
        )
        .await
        .expect("should return promptly, not wait for the timeout")
        .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn client_hello_without_sni_has_none_server_name() {
        let (mut client, server) = loopback_pair().await;
        // No server_name extension: use a bare IP `ServerName`, which rustls
        // never sends as an SNI extension per RFC 6066.
        let root_store = rustls::RootCertStore::empty();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::IpAddress(
            rustls::pki_types::IpAddr::from(std::net::IpAddr::from([127, 0, 0, 1])),
        );
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut hello = Vec::new();
        conn.write_tls(&mut hello).unwrap();
        client.write_all(&hello).await.unwrap();

        let result = inspect_client_hello(&server, 16384).await.unwrap();
        let inspected = result.expect("should still recognize TLS ClientHello");
        assert_eq!(inspected.server_name, None);
    }

    #[tokio::test]
    async fn peek_does_not_consume_client_hello_bytes() {
        let (mut client, server) = loopback_pair().await;
        let hello = client_hello_bytes("example.com", &["h2"]);
        client.write_all(&hello).await.unwrap();

        let result = inspect_client_hello(&server, 16384).await.unwrap();
        assert!(result.is_some());

        // Every byte we peeked must still be readable afterwards.
        let mut readback = vec![0u8; hello.len()];
        server.readable().await.unwrap();
        let mut total = 0;
        let mut server = server;
        while total < hello.len() {
            total += server.read(&mut readback[total..]).await.unwrap();
        }
        assert_eq!(readback, hello);
    }

    #[test]
    fn client_hello_bytes_helper_produces_handshake_record() {
        // Sanity check the test helper itself, independent of tokio: the
        // bytes it hands back really do start with a TLS handshake record.
        let hello = client_hello_bytes("example.com", &[]);
        assert_eq!(hello[0], TLS_HANDSHAKE_CONTENT_TYPE);
    }
}
