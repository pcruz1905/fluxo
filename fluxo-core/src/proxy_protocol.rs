//! PROXY protocol V1/V2 parsing utilities.
//!
//! Provides helpers to extract the real client IP from a PROXY protocol header
//! (`HAProxy` specification). Uses the `ppp` crate for parsing.
//!
//! **Note:** Pingora 0.8 does not expose transport-layer hooks for intercepting
//! the PROXY protocol header before HTTP parsing. This module provides the parsing
//! infrastructure so it's ready when Pingora adds support or when a custom
//! transport wrapper is used.

use std::net::{IpAddr, SocketAddr};

/// Information extracted from a PROXY protocol header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyProtocolInfo {
    /// The real client IP address (source address from the PROXY header).
    pub source_addr: SocketAddr,
    /// The destination address from the PROXY header.
    pub dest_addr: SocketAddr,
    /// Which version of the PROXY protocol was used.
    pub version: ProxyProtocolVersion,
}

/// PROXY protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
    V1,
    V2,
}

/// Parse a PROXY protocol header from raw bytes.
///
/// Returns `Ok(Some(info))` if a valid PROXY header was found,
/// `Ok(None)` if the data doesn't start with a PROXY header prefix,
/// or `Err` if the header is malformed.
pub fn parse_proxy_header(input: &[u8]) -> Result<Option<ProxyProtocolInfo>, ProxyProtocolError> {
    use ppp::{HeaderResult, PartialResult};

    let result = HeaderResult::parse(input);

    match result {
        HeaderResult::V1(Ok(header)) => match header.addresses {
            ppp::v1::Addresses::Tcp4(addrs) => Ok(Some(ProxyProtocolInfo {
                source_addr: SocketAddr::new(IpAddr::V4(addrs.source_address), addrs.source_port),
                dest_addr: SocketAddr::new(
                    IpAddr::V4(addrs.destination_address),
                    addrs.destination_port,
                ),
                version: ProxyProtocolVersion::V1,
            })),
            ppp::v1::Addresses::Tcp6(addrs) => Ok(Some(ProxyProtocolInfo {
                source_addr: SocketAddr::new(IpAddr::V6(addrs.source_address), addrs.source_port),
                dest_addr: SocketAddr::new(
                    IpAddr::V6(addrs.destination_address),
                    addrs.destination_port,
                ),
                version: ProxyProtocolVersion::V1,
            })),
            ppp::v1::Addresses::Unknown => Ok(None),
        },
        HeaderResult::V2(Ok(header)) => match header.addresses {
            ppp::v2::Addresses::IPv4(addrs) => Ok(Some(ProxyProtocolInfo {
                source_addr: SocketAddr::new(IpAddr::V4(addrs.source_address), addrs.source_port),
                dest_addr: SocketAddr::new(
                    IpAddr::V4(addrs.destination_address),
                    addrs.destination_port,
                ),
                version: ProxyProtocolVersion::V2,
            })),
            ppp::v2::Addresses::IPv6(addrs) => Ok(Some(ProxyProtocolInfo {
                source_addr: SocketAddr::new(IpAddr::V6(addrs.source_address), addrs.source_port),
                dest_addr: SocketAddr::new(
                    IpAddr::V6(addrs.destination_address),
                    addrs.destination_port,
                ),
                version: ProxyProtocolVersion::V2,
            })),
            ppp::v2::Addresses::Unspecified | ppp::v2::Addresses::Unix(_) => Ok(None),
        },
        HeaderResult::V1(Err(ref e)) => {
            if result.is_incomplete() {
                Err(ProxyProtocolError::Incomplete)
            } else {
                Err(ProxyProtocolError::V1(format!("{e}")))
            }
        }
        HeaderResult::V2(Err(ref e)) => {
            if result.is_incomplete() {
                Err(ProxyProtocolError::Incomplete)
            } else {
                Err(ProxyProtocolError::V2(format!("{e}")))
            }
        }
    }
}

/// Errors that can occur while parsing a PROXY protocol header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProtocolError {
    /// Not enough data to parse the header — more bytes needed.
    Incomplete,
    /// V1 header parse error.
    V1(String),
    /// V2 header parse error.
    V2(String),
}

impl std::fmt::Display for ProxyProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete => write!(f, "incomplete PROXY protocol header"),
            Self::V1(e) => write!(f, "PROXY protocol V1 error: {e}"),
            Self::V2(e) => write!(f, "PROXY protocol V2 error: {e}"),
        }
    }
}

impl std::error::Error for ProxyProtocolError {}

/// Calculate the byte length of a PROXY protocol header in the given buffer.
///
/// Returns `Some(len)` if a valid header prefix is detected, `None` otherwise.
/// This allows callers to consume exactly the header bytes and pass the rest
/// as application data.
pub fn proxy_header_len(input: &[u8]) -> Option<usize> {
    // V2 binary format: 12-byte signature + version/command(1) + family(1) + length(2) + payload
    if input.len() >= 16 && input[..12] == ppp::v2::PROTOCOL_PREFIX[..] {
        let payload_len = u16::from_be_bytes([input[14], input[15]]) as usize;
        return Some(16 + payload_len);
    }
    // V1 text format: "PROXY " ... "\r\n"
    if input.starts_with(b"PROXY ") {
        if let Some(pos) = memchr::memmem::find(input, b"\r\n") {
            return Some(pos + 2);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parse_v1_tcp4() {
        let input = b"PROXY TCP4 192.168.1.100 10.0.0.1 56324 443\r\n";
        let info = parse_proxy_header(input).unwrap().unwrap();

        assert_eq!(info.version, ProxyProtocolVersion::V1);
        assert_eq!(
            info.source_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 56324)
        );
        assert_eq!(
            info.dest_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)
        );
    }

    #[test]
    fn parse_v1_tcp6() {
        let input = b"PROXY TCP6 ::1 ::2 12345 80\r\n";
        let info = parse_proxy_header(input).unwrap().unwrap();

        assert_eq!(info.version, ProxyProtocolVersion::V1);
        assert_eq!(
            info.source_addr,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 12345)
        );
    }

    #[test]
    fn parse_v1_unknown_returns_none() {
        let input = b"PROXY UNKNOWN\r\n";
        let result = parse_proxy_header(input).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_v2_tcp4() {
        // Build a valid V2 PROXY protocol header
        let mut header = Vec::from(ppp::v2::PROTOCOL_PREFIX);
        // Version 2 + PROXY command = 0x21
        // Stream + IPv4 = 0x11
        // Length = 12 (IPv4 addresses payload)
        header.extend([0x21, 0x11, 0x00, 0x0C]);
        // Source: 192.168.1.100
        header.extend([192, 168, 1, 100]);
        // Dest: 10.0.0.1
        header.extend([10, 0, 0, 1]);
        // Source port: 56324 (0xDC04)
        header.extend(56324u16.to_be_bytes());
        // Dest port: 443 (0x01BB)
        header.extend(443u16.to_be_bytes());

        let info = parse_proxy_header(&header).unwrap().unwrap();

        assert_eq!(info.version, ProxyProtocolVersion::V2);
        assert_eq!(
            info.source_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 56324)
        );
        assert_eq!(
            info.dest_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)
        );
    }

    #[test]
    fn header_len_v1() {
        let input = b"PROXY TCP4 192.168.1.100 10.0.0.1 56324 443\r\nGET / HTTP/1.1\r\n";
        let len = proxy_header_len(input).unwrap();
        assert_eq!(len, 47); // Up to and including \r\n
        // Verify the remaining bytes are the HTTP request
        assert_eq!(&input[len..], b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn header_len_v2() {
        let mut header = Vec::from(ppp::v2::PROTOCOL_PREFIX);
        header.extend([0x21, 0x11, 0x00, 0x0C]); // version=2, command=PROXY, IPv4, length=12
        header.extend([192, 168, 1, 100]); // source
        header.extend([10, 0, 0, 1]); // dest
        header.extend(56324u16.to_be_bytes()); // source port
        header.extend(443u16.to_be_bytes()); // dest port
        header.extend(b"application data"); // app data after header

        let len = proxy_header_len(&header).unwrap();
        assert_eq!(len, 28); // 16 (fixed) + 12 (payload)
        assert_eq!(&header[len..], b"application data");
    }

    #[test]
    fn header_len_not_proxy_protocol() {
        let input = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert!(proxy_header_len(input).is_none());
    }

    #[test]
    fn parse_garbage_returns_error() {
        let input = b"GET / HTTP/1.1\r\n";
        let result = parse_proxy_header(input);
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_returns_error() {
        let result = parse_proxy_header(b"");
        assert!(result.is_err());
    }
}
