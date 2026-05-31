//! PROXY protocol v2 header parsing.
//!
//! Single responsibility: read the 12-byte signature + 4-byte
//! version/family/length prefix and the variable-length address
//! block from a byte slice, return the original client's source IP,
//! and fail closed on any deviation from the spec. The IP is the
//! daemon's only source of client identity (AGENTS.md invariant #7),
//! so parsing is intentionally strict.
//!
//! Streaming contract: `parse` may be called on a partial buffer; it
//! returns `Err(Incomplete { .. })` while bytes are missing. The
//! daemon is expected to keep reading and retry, and to impose its
//! own buffer cap so a declared address-block length of up to
//! `u16::MAX` cannot cause unbounded growth.
//!
//! Only PROXY v2 with TCP/IPv4 (`0x11`) or TCP/IPv6 (`0x21`) is
//! supported. v1 (ASCII) headers, LOCAL, and other address families
//! fail closed. TLVs trailing the core address block are consumed
//! and discarded — stunnel emits none, but the spec permits them.
//!
//! Reference:
//! <https://www.haproxy.org/download/2.4/doc/proxy-protocol.txt>.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

const FIXED_HEADER_LEN: usize = 16;
const ADDR_V4_CORE: usize = 12;
const ADDR_V6_CORE: usize = 36;

const FAMILY_TCP_V4: u8 = 0x11;
const FAMILY_TCP_V6: u8 = 0x21;
const CMD_LOCAL: u8 = 0x0;
const CMD_PROXY: u8 = 0x1;
const EXPECTED_VERSION: u8 = 0x2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub source_ip: IpAddr,
    pub header_len: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyProtocolError {
    #[error("incomplete header: have {have} bytes, need {need_total}")]
    Incomplete { have: usize, need_total: usize },
    #[error("invalid 12-byte signature")]
    InvalidSignature,
    #[error("unsupported version: high nibble 0x{0:x}, expected 0x2")]
    InvalidVersion(u8),
    #[error("LOCAL command rejected: PROXY v2 LOCAL carries no source IP")]
    LocalCommand,
    #[error("unsupported command nibble: 0x{0:x}")]
    UnknownCommand(u8),
    #[error("unsupported address family/transport byte: 0x{0:x}")]
    UnknownFamily(u8),
    #[error("address-block length {len} too short for family 0x{family:x}")]
    AddressBlockTooShort { family: u8, len: u16 },
}

pub fn parse(input: &[u8]) -> Result<Parsed, ProxyProtocolError> {
    // Streaming contract: at fewer than 12 bytes, do not peek at the
    // signature — a slow socket read must not be misclassified as
    // `InvalidSignature`. Once 12 bytes are present, signature
    // mismatch is fatal.
    if input.len() < SIGNATURE.len() {
        return Err(ProxyProtocolError::Incomplete {
            have: input.len(),
            need_total: FIXED_HEADER_LEN,
        });
    }
    if input[..SIGNATURE.len()] != SIGNATURE {
        return Err(ProxyProtocolError::InvalidSignature);
    }
    if input.len() < FIXED_HEADER_LEN {
        return Err(ProxyProtocolError::Incomplete {
            have: input.len(),
            need_total: FIXED_HEADER_LEN,
        });
    }

    let ver_cmd = input[12];
    let version = ver_cmd >> 4;
    if version != EXPECTED_VERSION {
        return Err(ProxyProtocolError::InvalidVersion(version));
    }
    let command = ver_cmd & 0x0F;
    match command {
        CMD_LOCAL => return Err(ProxyProtocolError::LocalCommand),
        CMD_PROXY => {}
        other => return Err(ProxyProtocolError::UnknownCommand(other)),
    }

    let family = input[13];
    let core_len = match family {
        FAMILY_TCP_V4 => ADDR_V4_CORE,
        FAMILY_TCP_V6 => ADDR_V6_CORE,
        _ => return Err(ProxyProtocolError::UnknownFamily(family)),
    };

    let addr_block_len = u16::from_be_bytes([input[14], input[15]]);
    if (addr_block_len as usize) < core_len {
        return Err(ProxyProtocolError::AddressBlockTooShort {
            family,
            len: addr_block_len,
        });
    }

    let header_len = FIXED_HEADER_LEN + addr_block_len as usize;
    if input.len() < header_len {
        return Err(ProxyProtocolError::Incomplete {
            have: input.len(),
            need_total: header_len,
        });
    }

    let source_ip = match family {
        FAMILY_TCP_V4 => {
            let mut o = [0u8; 4];
            o.copy_from_slice(&input[16..20]);
            IpAddr::V4(Ipv4Addr::from(o))
        }
        FAMILY_TCP_V6 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&input[16..32]);
            IpAddr::V6(Ipv6Addr::from(o))
        }
        _ => unreachable!("family already validated"),
    };

    Ok(Parsed {
        source_ip,
        header_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VER_CMD_PROXY_V2: u8 = (EXPECTED_VERSION << 4) | CMD_PROXY; // 0x21

    fn build_v4(src: [u8; 4], extra_tlvs: &[u8]) -> Vec<u8> {
        let mut buf = SIGNATURE.to_vec();
        buf.push(VER_CMD_PROXY_V2);
        buf.push(FAMILY_TCP_V4);
        let len = (ADDR_V4_CORE + extra_tlvs.len()) as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&[10, 0, 0, 1]); // dst IP
        buf.extend_from_slice(&[0x12, 0x34]); // src port
        buf.extend_from_slice(&[0x56, 0x78]); // dst port
        buf.extend_from_slice(extra_tlvs);
        buf
    }

    fn build_v6(src: [u8; 16], extra_tlvs: &[u8]) -> Vec<u8> {
        let mut buf = SIGNATURE.to_vec();
        buf.push(VER_CMD_PROXY_V2);
        buf.push(FAMILY_TCP_V6);
        let len = (ADDR_V6_CORE + extra_tlvs.len()) as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // dst IP
        buf.extend_from_slice(&[0x12, 0x34]);
        buf.extend_from_slice(&[0x56, 0x78]);
        buf.extend_from_slice(extra_tlvs);
        buf
    }

    #[test]
    fn parse_minimal_ipv4_no_tlvs() {
        let buf = build_v4([192, 168, 122, 10], &[]);
        let parsed = parse(&buf).unwrap();
        assert_eq!(
            parsed.source_ip,
            IpAddr::V4(Ipv4Addr::new(192, 168, 122, 10))
        );
        assert_eq!(parsed.header_len, 28);
    }

    #[test]
    fn parse_minimal_ipv6_no_tlvs() {
        let src = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let buf = build_v6(src, &[]);
        let parsed = parse(&buf).unwrap();
        assert_eq!(parsed.source_ip, IpAddr::V6(Ipv6Addr::from(src)));
        assert_eq!(parsed.header_len, 52);
    }

    #[test]
    fn parse_ipv4_with_trailing_tlvs_discarded() {
        let tlvs = [0xCC; 8];
        let buf = build_v4([10, 0, 0, 5], &tlvs);
        let parsed = parse(&buf).unwrap();
        assert_eq!(parsed.source_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(parsed.header_len, 36);
    }

    #[test]
    fn parse_ipv6_with_trailing_tlvs_discarded() {
        let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
        let tlvs = [0xCC; 8];
        let buf = build_v6(src, &tlvs);
        let parsed = parse(&buf).unwrap();
        assert_eq!(parsed.source_ip, IpAddr::V6(Ipv6Addr::from(src)));
        assert_eq!(parsed.header_len, 60);
    }

    #[test]
    fn parse_returns_header_len_excluding_payload() {
        let mut buf = build_v4([192, 168, 1, 1], &[]);
        let payload = b"protocol=https\nhost=github.com\npath=p\n\n";
        buf.extend_from_slice(payload);
        let parsed = parse(&buf).unwrap();
        assert_eq!(parsed.header_len, 28);
        assert_eq!(&buf[parsed.header_len..], payload);
    }

    #[test]
    fn reject_invalid_magic() {
        let mut buf = build_v4([1, 2, 3, 4], &[]);
        buf[3] ^= 0xFF;
        assert!(matches!(
            parse(&buf).unwrap_err(),
            ProxyProtocolError::InvalidSignature
        ));
    }

    #[test]
    fn reject_invalid_version() {
        let mut buf = build_v4([1, 2, 3, 4], &[]);
        buf[12] = 0x31; // version=3, command=1
        assert!(matches!(
            parse(&buf).unwrap_err(),
            ProxyProtocolError::InvalidVersion(0x3)
        ));
    }

    #[test]
    fn reject_local_command() {
        let mut buf = build_v4([1, 2, 3, 4], &[]);
        buf[12] = 0x20; // version=2, command=0 (LOCAL)
        assert!(matches!(
            parse(&buf).unwrap_err(),
            ProxyProtocolError::LocalCommand
        ));
    }

    #[test]
    fn reject_unknown_command_nibble() {
        let mut buf = build_v4([1, 2, 3, 4], &[]);
        buf[12] = 0x22; // version=2, command=2 (unknown)
        assert!(matches!(
            parse(&buf).unwrap_err(),
            ProxyProtocolError::UnknownCommand(0x2)
        ));
    }

    #[test]
    fn reject_unknown_family_byte() {
        let mut buf = build_v4([1, 2, 3, 4], &[]);
        buf[13] = 0x99;
        assert!(matches!(
            parse(&buf).unwrap_err(),
            ProxyProtocolError::UnknownFamily(0x99)
        ));
    }

    #[test]
    fn reject_ipv4_addr_block_too_short() {
        let mut buf = build_v4([1, 2, 3, 4], &[]);
        // Force length to 11, one byte short of the v4 core size.
        buf[14] = 0x00;
        buf[15] = 0x0B;
        assert!(matches!(
            parse(&buf).unwrap_err(),
            ProxyProtocolError::AddressBlockTooShort {
                family: FAMILY_TCP_V4,
                len: 11
            }
        ));
    }

    #[test]
    fn reject_ipv6_addr_block_too_short() {
        let src = [0u8; 16];
        let mut buf = build_v6(src, &[]);
        // Force length to 35, one byte short of the v6 core size.
        buf[14] = 0x00;
        buf[15] = 0x23;
        assert!(matches!(
            parse(&buf).unwrap_err(),
            ProxyProtocolError::AddressBlockTooShort {
                family: FAMILY_TCP_V6,
                len: 35
            }
        ));
    }

    #[test]
    fn reject_zero_length_addr_block_v4() {
        let mut buf = build_v4([1, 2, 3, 4], &[]);
        buf[14] = 0x00;
        buf[15] = 0x00;
        assert!(matches!(
            parse(&buf).unwrap_err(),
            ProxyProtocolError::AddressBlockTooShort {
                family: FAMILY_TCP_V4,
                len: 0
            }
        ));
    }

    #[test]
    fn incomplete_empty_input() {
        assert!(matches!(
            parse(b"").unwrap_err(),
            ProxyProtocolError::Incomplete {
                have: 0,
                need_total: 16
            }
        ));
    }

    #[test]
    fn incomplete_partial_signature_returns_incomplete_not_invalid() {
        // 8 bytes of garbage that doesn't match the signature prefix.
        // At have < 12 we must NOT classify this as InvalidSignature
        // — the daemon may still be reading.
        let buf = [0u8; 8];
        assert!(matches!(
            parse(&buf).unwrap_err(),
            ProxyProtocolError::Incomplete {
                have: 8,
                need_total: 16
            }
        ));
    }

    #[test]
    fn incomplete_exactly_15_bytes() {
        let mut buf = SIGNATURE.to_vec();
        buf.push(VER_CMD_PROXY_V2);
        buf.push(FAMILY_TCP_V4);
        buf.push(0x00); // first byte of length, length high
        assert_eq!(buf.len(), 15);
        assert!(matches!(
            parse(&buf).unwrap_err(),
            ProxyProtocolError::Incomplete {
                have: 15,
                need_total: 16
            }
        ));
    }

    #[test]
    fn incomplete_after_fixed_header() {
        // Full 16-byte fixed header announcing a v4 address block
        // (len=12). We provide 0 bytes of the address block.
        let mut buf = SIGNATURE.to_vec();
        buf.push(VER_CMD_PROXY_V2);
        buf.push(FAMILY_TCP_V4);
        buf.extend_from_slice(&(ADDR_V4_CORE as u16).to_be_bytes());
        assert_eq!(buf.len(), 16);
        assert!(matches!(
            parse(&buf).unwrap_err(),
            ProxyProtocolError::Incomplete {
                have: 16,
                need_total: 28
            }
        ));
    }

    #[test]
    fn incomplete_addr_block_partial() {
        let full = build_v4([192, 168, 1, 1], &[]);
        let partial = &full[..20]; // 16 fixed + 4 of the 12-byte block
        assert!(matches!(
            parse(partial).unwrap_err(),
            ProxyProtocolError::Incomplete {
                have: 20,
                need_total: 28
            }
        ));
    }

    #[test]
    fn big_endian_length_parsed_correctly() {
        // Length bytes 0x01 0x00 = 256 (big-endian) for a v6 header.
        // A little-endian misread would produce need_total = 17.
        let mut buf = SIGNATURE.to_vec();
        buf.push(VER_CMD_PROXY_V2);
        buf.push(FAMILY_TCP_V6);
        buf.push(0x01);
        buf.push(0x00);
        assert_eq!(buf.len(), 16);
        assert!(matches!(
            parse(&buf).unwrap_err(),
            ProxyProtocolError::Incomplete {
                have: 16,
                need_total: 272
            }
        ));
    }
}
