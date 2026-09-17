//! Packet capture: backends, filters, file I/O, disk ring.

pub mod backend;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod bpf;
pub mod cap_filter;
pub mod disp_filter;
pub mod file_io;
pub mod ring;
pub mod rpcap;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod npcap_install;
#[cfg(windows)]
pub mod windows;

pub use backend::{list_interfaces, CaptureHandle, CapturePacket, IfaceInfo, LiveCapture};
pub use cap_filter::{parse_capture_filter, CaptureFilter};
pub use disp_filter::{parse_display_filter, DisplayFilter};
pub use file_io::{open_capture_file, save_packets_pcap, save_packets_pcapng};
pub use ring::DiskRing;
pub use rpcap::{
    encode_header, parse_header, parse_packet_body, probe, read_packet_payload, RpcapCapture,
};
