#![forbid(unsafe_code)]

//! Low-level HTTP framing helpers shared by the `call()` implementations of
//! the three transports (SSE, Noise, QUIC).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Error;

/// Hard cap on response bodies carried by `call()` — prevents an adversarial
/// server from making the client allocate unbounded memory.
pub const MAX_CALL_BODY: usize = 8 * 1024 * 1024; // 8 MiB

/// Hard cap on HTTP response header bytes.
pub const MAX_HTTP_HEADERS: usize = 16 * 1024;

/// Write a minimal HTTP/1.1 POST with a CBOR body and read back one response.
///
/// Requires the server to set `Content-Length` (no chunked transfer-encoding
/// support) and to close the connection or respect `Connection: close` — the
/// client always sends `Connection: close`.
///
/// Returns `(status_code, body_bytes)`.
pub async fn http_unary_cbor<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if body.len() > MAX_CALL_BODY {
        return Err(Error::Connect(format!(
            "request body too large: {} > {}",
            body.len(),
            MAX_CALL_BODY
        )));
    }

    let header = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/cbor\r\n\
         Accept: application/cbor\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        len = body.len(),
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|e| Error::Connect(format!("write headers: {e}")))?;
    stream
        .write_all(body)
        .await
        .map_err(|e| Error::Connect(format!("write body: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::Connect(format!("flush: {e}")))?;

    read_http_response(stream).await
}

/// Write a minimal HTTP/1.1 POST with a JSON body and read back one response.
///
/// Used by legacy JSON APIs when the outer transport is Noise/QUIC. Direct
/// reqwest remains the only path for ordinary HTTP/HTTPS SSE mode.
pub async fn http_unary_json<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if body.len() > MAX_CALL_BODY {
        return Err(Error::Connect(format!(
            "request body too large: {} > {}",
            body.len(),
            MAX_CALL_BODY
        )));
    }

    let header = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Accept: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        len = body.len(),
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|e| Error::Connect(format!("write headers: {e}")))?;
    stream
        .write_all(body)
        .await
        .map_err(|e| Error::Connect(format!("write body: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::Connect(format!("flush: {e}")))?;

    read_http_response(stream).await
}

/// Write a minimal HTTP/1.1 GET and read back one response.
pub async fn http_get<S>(stream: &mut S, host: &str, path: &str) -> Result<(u16, Vec<u8>), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let header = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|e| Error::Connect(format!("write headers: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::Connect(format!("flush: {e}")))?;

    read_http_response(stream).await
}

async fn read_http_response<S>(stream: &mut S) -> Result<(u16, Vec<u8>), Error>
where
    S: AsyncRead + Unpin,
{
    let mut header_buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| Error::Connect(format!("read header byte: {e}")))?;
        header_buf.push(byte[0]);
        if header_buf.len() > MAX_HTTP_HEADERS {
            return Err(Error::Sse(format!(
                "HTTP response headers exceed {MAX_HTTP_HEADERS} bytes"
            )));
        }
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header_str = std::str::from_utf8(&header_buf)
        .map_err(|_| Error::Sse("non-UTF-8 HTTP headers".into()))?;

    let mut lines = header_str.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| Error::Sse("empty HTTP response".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Sse(format!("invalid HTTP status line: {status_line:?}")))?;

    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = rest.trim().parse().ok();
            break;
        }
    }
    let content_length = content_length.ok_or_else(|| {
        Error::Sse("HTTP response missing Content-Length (chunked not supported)".into())
    })?;
    if content_length > MAX_CALL_BODY {
        return Err(Error::Sse(format!(
            "response Content-Length {content_length} > {MAX_CALL_BODY}"
        )));
    }

    let mut resp = vec![0u8; content_length];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| Error::Connect(format!("read body: {e}")))?;
    Ok((status, resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn http_unary_cbor_parses_response() {
        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            // Read until \r\n\r\n
            let mut hdrs = Vec::new();
            let mut b = [0u8; 1];
            loop {
                server.read_exact(&mut b).await.unwrap();
                hdrs.push(b[0]);
                if hdrs.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            // Read body
            let hdr_str = std::str::from_utf8(&hdrs).unwrap();
            let body_len: usize = hdr_str
                .lines()
                .filter_map(|l| l.strip_prefix("Content-Length: "))
                .next()
                .unwrap()
                .parse()
                .unwrap();
            let mut body = vec![0u8; body_len];
            server.read_exact(&mut body).await.unwrap();
            assert_eq!(body, b"req-body");

            let reply = b"response-body";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\n\r\n",
                reply.len()
            );
            server.write_all(resp.as_bytes()).await.unwrap();
            server.write_all(reply).await.unwrap();
            server.flush().await.unwrap();
        });

        let (status, body) = http_unary_cbor(&mut client, "test", "/api/v1/control", b"req-body")
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"response-body");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn http_unary_cbor_rejects_missing_content_length() {
        let (mut client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            // Read request headers
            let mut hdrs = Vec::new();
            let mut b = [0u8; 1];
            loop {
                server.read_exact(&mut b).await.unwrap();
                hdrs.push(b[0]);
                if hdrs.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            // Parse Content-Length from request so we read exactly that many
            // body bytes and avoid a read_to_end deadlock on a still-open
            // client half.
            let hdr_str = std::str::from_utf8(&hdrs).unwrap();
            let body_len: usize = hdr_str
                .lines()
                .filter_map(|l| l.strip_prefix("Content-Length: "))
                .next()
                .unwrap()
                .parse()
                .unwrap();
            let mut body = vec![0u8; body_len];
            server.read_exact(&mut body).await.unwrap();

            // Respond without Content-Length (chunked-equivalent omitted too).
            let resp = b"HTTP/1.1 200 OK\r\n\r\n";
            server.write_all(resp).await.unwrap();
            server.flush().await.unwrap();
        });
        let err = http_unary_cbor(&mut client, "test", "/", b"x")
            .await
            .unwrap_err();
        match err {
            Error::Sse(s) => assert!(s.contains("Content-Length")),
            other => panic!("expected Sse error, got {other:?}"),
        }
        server_task.await.unwrap();
    }
}
