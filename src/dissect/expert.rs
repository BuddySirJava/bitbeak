//! Expert info (checksums, TCP anomalies, HTTP errors).

use crate::dissect::packet::{LinkType, PacketSummary, ProtocolFlags};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExpertSeverity {
    Comment,
    Note,
    Warn,
    Error,
}

impl ExpertSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Comment => "Comment",
            Self::Note => "Note",
            Self::Warn => "Warn",
            Self::Error => "Error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExpertInfo {
    pub severity: ExpertSeverity,
    pub group: String,
    pub message: String,
}

pub fn collect_expert(
    data: &[u8],
    link_type: LinkType,
    flags: &ProtocolFlags,
    summary: &PacketSummary,
) -> Vec<ExpertInfo> {
    let mut out = Vec::new();

    if flags.http {
        if let Some(code) = extract_http_status(&summary.info) {
            if code >= 400 {
                out.push(ExpertInfo {
                    severity: if code >= 500 {
                        ExpertSeverity::Error
                    } else {
                        ExpertSeverity::Warn
                    },
                    group: "HTTP".into(),
                    message: format!("HTTP status {code}"),
                });
            }
        }
    }

    // IPv4 header checksum
    if let Some(ip_off) = find_ipv4_offset(data, link_type) {
        if data.len() >= ip_off + 20 {
            let ihl = (data[ip_off] & 0x0f) as usize * 4;
            if ihl >= 20 && data.len() >= ip_off + ihl {
                let expected = ipv4_checksum(&data[ip_off..ip_off + ihl]);
                let actual = u16::from_be_bytes([data[ip_off + 10], data[ip_off + 11]]);
                if expected != actual && actual != 0 {
                    out.push(ExpertInfo {
                        severity: ExpertSeverity::Error,
                        group: "Checksum".into(),
                        message: format!(
                            "IPv4 checksum bad (got {actual:#06x}, expected {expected:#06x})"
                        ),
                    });
                }
            }
        }
    }

    out
}

fn extract_http_status(info: &str) -> Option<u16> {
    // "HTTP 404 Not Found" or similar
    let parts: Vec<_> = info.split_whitespace().collect();
    if parts.len() >= 2 && parts[0] == "HTTP" {
        parts[1].parse().ok()
    } else {
        None
    }
}

fn find_ipv4_offset(data: &[u8], link_type: LinkType) -> Option<usize> {
    match link_type {
        LinkType::Ethernet => {
            if data.len() < 14 {
                return None;
            }
            let mut off = 14;
            let mut et = u16::from_be_bytes([data[12], data[13]]);
            if et == 0x8100 && data.len() >= 18 {
                et = u16::from_be_bytes([data[16], data[17]]);
                off = 18;
            }
            if et == 0x0800 {
                Some(off)
            } else {
                None
            }
        }
        LinkType::LinuxSll if data.len() >= 16 => {
            let et = u16::from_be_bytes([data[14], data[15]]);
            if et == 0x0800 {
                Some(16)
            } else {
                None
            }
        }
        LinkType::Null if data.len() >= 4 => Some(4),
        LinkType::Raw => Some(0),
        _ => None,
    }
}

fn ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in (0..hdr.len()).step_by(2) {
        let word = if i == 10 {
            0u16
        } else if i + 1 < hdr.len() {
            u16::from_be_bytes([hdr[i], hdr[i + 1]])
        } else {
            u16::from_be_bytes([hdr[i], 0])
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
