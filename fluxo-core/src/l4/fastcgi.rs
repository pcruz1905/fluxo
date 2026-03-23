//! `FastCGI` proxy — forwards HTTP requests to `FastCGI` backends (e.g., PHP-FPM).
//!
//! Nginx equivalent: `fastcgi_pass`. Translates incoming HTTP requests into the
//! `FastCGI` binary protocol (records with type, request ID, content).
//!
//! Supports `FCGI_PARAMS` (environment variables), `FCGI_STDIN` (request body),
//! and reads `FCGI_STDOUT/FCGI_STDERR` from the backend.

use std::collections::HashMap;
use std::io;

use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// `FastCGI` record types.
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_ABORT_REQUEST: u8 = 2;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;

/// `FastCGI` roles.
const FCGI_RESPONDER: u16 = 1;

/// `FastCGI` protocol version.
const FCGI_VERSION_1: u8 = 1;

/// Maximum record content length.
const FCGI_MAX_CONTENT_LEN: usize = 65535;

/// Configuration for `FastCGI` upstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastCgiConfig {
    /// `FastCGI` backend address (e.g., "127.0.0.1:9000" or "/var/run/php-fpm.sock").
    pub address: String,

    /// Document root for `SCRIPT_FILENAME`. Example: "/var/www/html".
    pub document_root: String,

    /// Default index file. Default: "index.php".
    #[serde(default = "default_index")]
    pub index: String,

    /// Extra `FastCGI` params to pass to the backend.
    #[serde(default)]
    pub params: HashMap<String, String>,

    /// Connection timeout. Default: "5s".
    #[serde(default = "default_fcgi_timeout")]
    pub connect_timeout: String,
}

fn default_index() -> String {
    "index.php".to_string()
}

fn default_fcgi_timeout() -> String {
    "5s".to_string()
}

/// A parsed `FastCGI` record header (8 bytes).
#[derive(Debug)]
struct FcgiRecord {
    record_type: u8,
    #[allow(dead_code)]
    request_id: u16,
    content_length: u16,
    padding_length: u8,
}

/// Build a `FastCGI` record header.
fn build_record_header(record_type: u8, request_id: u16, content_length: u16) -> [u8; 8] {
    let padding = (8 - (content_length as usize % 8)) % 8;
    [
        FCGI_VERSION_1,
        record_type,
        (request_id >> 8) as u8,
        (request_id & 0xff) as u8,
        (content_length >> 8) as u8,
        (content_length & 0xff) as u8,
        padding as u8,
        0, // reserved
    ]
}

/// Encode a single `FastCGI` name-value pair.
fn encode_param(buf: &mut BytesMut, name: &str, value: &str) {
    let name_len = name.len();
    let val_len = value.len();

    // Name length encoding (1 or 4 bytes)
    if name_len < 128 {
        buf.put_u8(name_len as u8);
    } else {
        buf.put_u32((name_len as u32) | 0x8000_0000);
    }

    // Value length encoding (1 or 4 bytes)
    if val_len < 128 {
        buf.put_u8(val_len as u8);
    } else {
        buf.put_u32((val_len as u32) | 0x8000_0000);
    }

    buf.extend_from_slice(name.as_bytes());
    buf.extend_from_slice(value.as_bytes());
}

/// Read a single `FastCGI` record header from the stream.
async fn read_record_header(stream: &mut TcpStream) -> io::Result<FcgiRecord> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await?;

    if header[0] != FCGI_VERSION_1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported FastCGI version: {}", header[0]),
        ));
    }

    Ok(FcgiRecord {
        record_type: header[1],
        request_id: u16::from_be_bytes([header[2], header[3]]),
        content_length: u16::from_be_bytes([header[4], header[5]]),
        padding_length: header[6],
    })
}

/// Send a `FastCGI` request and read the response.
///
/// Returns `(status_code, response_headers, response_body)`.
pub async fn send_fastcgi_request(
    config: &FastCgiConfig,
    method: &str,
    uri: &str,
    host: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let timeout = crate::config::parse_duration(&config.connect_timeout)
        .unwrap_or(std::time::Duration::from_secs(5));

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&config.address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "FastCGI connect timeout"))?
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

    let request_id: u16 = 1;

    // --- FCGI_BEGIN_REQUEST ---
    let begin_header = build_record_header(FCGI_BEGIN_REQUEST, request_id, 8);
    let mut begin_body = [0u8; 8];
    begin_body[0] = (FCGI_RESPONDER >> 8) as u8;
    begin_body[1] = (FCGI_RESPONDER & 0xff) as u8;
    // flags: FCGI_KEEP_CONN = 0 (close after request)
    stream.write_all(&begin_header).await?;
    stream.write_all(&begin_body).await?;

    // --- FCGI_PARAMS ---
    let mut params_buf = BytesMut::new();

    // Parse URI into script name and query string
    let (script_name, query_string) = uri.split_once('?').unwrap_or((uri, ""));

    // Build SCRIPT_FILENAME
    let script_filename = if script_name.ends_with('/') {
        format!("{}{}{}", config.document_root, script_name, config.index)
    } else {
        format!("{}{script_name}", config.document_root)
    };

    // Standard CGI/FastCGI params
    encode_param(&mut params_buf, "REQUEST_METHOD", method);
    encode_param(&mut params_buf, "SCRIPT_NAME", script_name);
    encode_param(&mut params_buf, "SCRIPT_FILENAME", &script_filename);
    encode_param(&mut params_buf, "QUERY_STRING", query_string);
    encode_param(&mut params_buf, "REQUEST_URI", uri);
    encode_param(&mut params_buf, "DOCUMENT_ROOT", &config.document_root);
    encode_param(&mut params_buf, "SERVER_PROTOCOL", "HTTP/1.1");
    encode_param(&mut params_buf, "SERVER_SOFTWARE", "fluxo");
    encode_param(&mut params_buf, "GATEWAY_INTERFACE", "CGI/1.1");
    encode_param(&mut params_buf, "SERVER_NAME", host);
    encode_param(&mut params_buf, "CONTENT_LENGTH", &body.len().to_string());

    // Map HTTP headers to CGI env vars
    for (name, value) in headers {
        let upper = name.to_uppercase().replace('-', "_");
        if upper == "CONTENT_TYPE" {
            encode_param(&mut params_buf, "CONTENT_TYPE", value);
        } else {
            encode_param(&mut params_buf, &format!("HTTP_{upper}"), value);
        }
    }

    // Extra config params
    for (name, value) in &config.params {
        encode_param(&mut params_buf, name, value);
    }

    // Send params in chunks (max 65535 bytes per record)
    let params_bytes = params_buf.freeze();
    let mut offset = 0;
    while offset < params_bytes.len() {
        let chunk_len = (params_bytes.len() - offset).min(FCGI_MAX_CONTENT_LEN);
        let header = build_record_header(FCGI_PARAMS, request_id, chunk_len as u16);
        stream.write_all(&header).await?;
        stream
            .write_all(&params_bytes[offset..offset + chunk_len])
            .await?;
        // Write padding
        let padding = (8 - (chunk_len % 8)) % 8;
        if padding > 0 {
            stream.write_all(&vec![0u8; padding]).await?;
        }
        offset += chunk_len;
    }

    // Empty FCGI_PARAMS to signal end
    let empty_params = build_record_header(FCGI_PARAMS, request_id, 0);
    stream.write_all(&empty_params).await?;

    // --- FCGI_STDIN ---
    if !body.is_empty() {
        let mut offset = 0;
        while offset < body.len() {
            let chunk_len = (body.len() - offset).min(FCGI_MAX_CONTENT_LEN);
            let header = build_record_header(FCGI_STDIN, request_id, chunk_len as u16);
            stream.write_all(&header).await?;
            stream.write_all(&body[offset..offset + chunk_len]).await?;
            let padding = (8 - (chunk_len % 8)) % 8;
            if padding > 0 {
                stream.write_all(&vec![0u8; padding]).await?;
            }
            offset += chunk_len;
        }
    }

    // Empty FCGI_STDIN to signal end
    let empty_stdin = build_record_header(FCGI_STDIN, request_id, 0);
    stream.write_all(&empty_stdin).await?;

    stream.flush().await?;

    // --- Read response ---
    let mut stdout_data = Vec::new();

    loop {
        let record = read_record_header(&mut stream).await?;
        let content_len = record.content_length as usize;

        let mut content = vec![0u8; content_len];
        if content_len > 0 {
            stream.read_exact(&mut content).await?;
        }

        // Skip padding
        if record.padding_length > 0 {
            let mut pad = vec![0u8; record.padding_length as usize];
            stream.read_exact(&mut pad).await?;
        }

        match record.record_type {
            FCGI_STDOUT => {
                if content_len == 0 {
                    // End of stdout
                    continue;
                }
                stdout_data.extend_from_slice(&content);
            }
            FCGI_STDERR => {
                if content_len > 0 {
                    if let Ok(msg) = std::str::from_utf8(&content) {
                        tracing::warn!(fastcgi_stderr = msg, "FastCGI stderr output");
                    }
                }
            }
            FCGI_END_REQUEST => {
                break;
            }
            FCGI_ABORT_REQUEST => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "FastCGI request aborted by backend",
                ));
            }
            _ => {
                // Unknown record type, skip
            }
        }
    }

    // Parse the CGI response from stdout
    // Format: HTTP headers, blank line, body
    parse_cgi_response(&stdout_data)
}

/// Parse CGI-style response from `FastCGI` stdout.
/// Returns (`status_code`, headers, body).
fn parse_cgi_response(data: &[u8]) -> io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    // Find the header/body boundary (\r\n\r\n or \n\n)
    let header_end = find_header_end(data).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no header/body boundary in FastCGI response",
        )
    })?;

    let header_bytes = &data[..header_end.0];
    let body = data[header_end.1..].to_vec();

    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut headers = Vec::new();
    let mut status = 200u16;

    for line in header_str.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("Status") {
                // CGI Status header: "200 OK" or just "200"
                if let Some(code_str) = value.split_whitespace().next() {
                    if let Ok(code) = code_str.parse::<u16>() {
                        status = code;
                    }
                }
            } else {
                headers.push((name.to_string(), value.to_string()));
            }
        }
    }

    Ok((status, headers, body))
}

/// Find the end of HTTP headers in a byte slice.
/// Returns (`end_of_headers`, `start_of_body`).
fn find_header_end(data: &[u8]) -> Option<(usize, usize)> {
    // Look for \r\n\r\n
    if let Some(pos) = memchr::memmem::find(data, b"\r\n\r\n") {
        return Some((pos, pos + 4));
    }
    // Fall back to \n\n
    if let Some(pos) = memchr::memmem::find(data, b"\n\n") {
        return Some((pos, pos + 2));
    }
    None
}

// Suppress unused constant warnings for protocol spec completeness
const _: u8 = FCGI_ABORT_REQUEST;
const _: u8 = FCGI_END_REQUEST;
const _: u8 = FCGI_STDERR;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn encode_short_param() {
        let mut buf = BytesMut::new();
        encode_param(&mut buf, "KEY", "value");
        // name_len(1) + val_len(1) + "KEY"(3) + "value"(5) = 10
        assert_eq!(buf.len(), 10);
        assert_eq!(buf[0], 3); // KEY length
        assert_eq!(buf[1], 5); // value length
    }

    #[test]
    fn encode_long_param() {
        let long_name = "A".repeat(200);
        let mut buf = BytesMut::new();
        encode_param(&mut buf, &long_name, "v");
        // name_len(4 bytes, high bit set) + val_len(1) + name(200) + value(1) = 206
        assert_eq!(buf.len(), 206);
        // First byte should have high bit set
        assert!(buf[0] & 0x80 != 0);
    }

    #[test]
    fn parse_cgi_response_basic() {
        let data = b"Status: 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Hello</h1>";
        let (status, headers, body) = parse_cgi_response(data).unwrap();
        assert_eq!(status, 200);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Content-Type");
        assert_eq!(body, b"<h1>Hello</h1>");
    }

    #[test]
    fn parse_cgi_response_no_status_header() {
        let data = b"Content-Type: text/plain\r\n\r\nHello";
        let (status, headers, body) = parse_cgi_response(data).unwrap();
        assert_eq!(status, 200); // default
        assert_eq!(headers.len(), 1);
        assert_eq!(body, b"Hello");
    }

    #[test]
    fn parse_cgi_response_lf_only() {
        let data = b"Status: 404\nContent-Type: text/plain\n\nNot Found";
        let (status, _, body) = parse_cgi_response(data).unwrap();
        assert_eq!(status, 404);
        assert_eq!(body, b"Not Found");
    }

    #[test]
    fn build_record_header_sizes() {
        let header = build_record_header(FCGI_PARAMS, 1, 100);
        assert_eq!(header[0], FCGI_VERSION_1);
        assert_eq!(header[1], FCGI_PARAMS);
        // request_id = 1
        assert_eq!(header[2], 0);
        assert_eq!(header[3], 1);
        // content_length = 100
        assert_eq!(header[4], 0);
        assert_eq!(header[5], 100);
        // padding = (8 - 100%8) % 8 = 4
        assert_eq!(header[6], 4);
    }

    #[test]
    fn find_header_end_crlf() {
        let data = b"Header: value\r\n\r\nBody";
        let (end, body_start) = find_header_end(data).unwrap();
        // "Header: value" is 13 bytes; \r\n\r\n starts at index 13
        assert_eq!(end, 13);
        assert_eq!(body_start, 17);
    }

    #[test]
    fn find_header_end_lf() {
        let data = b"Header: value\n\nBody";
        let (end, body_start) = find_header_end(data).unwrap();
        // "Header: value" is 13 bytes; \n\n starts at index 13
        assert_eq!(end, 13);
        assert_eq!(body_start, 15);
    }

    #[test]
    fn find_header_end_none() {
        let data = b"No boundary here";
        assert!(find_header_end(data).is_none());
    }
}
