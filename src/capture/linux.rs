//! Linux AF_PACKET live capture with optional TPACKET_V3 mmap ring.

use std::fs;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use libc::{
    c_int, c_void, sockaddr, sockaddr_ll, socket, AF_PACKET, ETH_P_ALL, MAP_SHARED,
    PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC, PROT_READ, PROT_WRITE, SOCK_CLOEXEC, SOCK_NONBLOCK,
    SOCK_RAW, SOL_PACKET, SOL_SOCKET, SO_ATTACH_FILTER, SO_DETACH_FILTER,
};

/// `linux/if_packet.h` — not all exposed by libc.
const PACKET_VERSION: c_int = 10;
const PACKET_RX_RING: c_int = 5;
const TPACKET_V3: c_int = 2;
const TP_STATUS_KERNEL: u32 = 0;
const TP_STATUS_USER: u32 = 1;

use crate::capture::backend::{CapturePacket, IfaceInfo, LiveCapture};
use crate::capture::bpf::{compile_simple_bpf, SockFilter, SockFprog};
use crate::capture::cap_filter::CaptureFilter;
use crate::dissect::packet::LinkType;

#[repr(C)]
#[derive(Clone, Copy)]
struct TpacketReq3 {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
    tp_retire_blk_tov: u32,
    tp_sizeof_priv: u32,
    tp_feature_req_word: u32,
}

#[repr(C)]
struct TpacketBdTs {
    ts_sec: u32,
    ts_usec: u32,
}

#[repr(C)]
struct TpacketHdrV1 {
    block_status: u32,
    num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u32,
    ts_first_pkt: TpacketBdTs,
    ts_last_pkt: TpacketBdTs,
}

#[repr(C)]
struct TpacketBlockDesc {
    version: u32,
    offset_to_priv: u32,
    hdr: TpacketHdrV1,
}

#[repr(C)]
struct Tpacket3Hdr {
    tp_next_offset: u32,
    tp_sec: u32,
    tp_nsec: u32,
    tp_snaplen: u32,
    tp_len: u32,
    tp_status: u32,
    tp_mac: u16,
    tp_net: u16,
    // remainder unused for our reader
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
    tp_padding: [u8; 8],
}

pub fn list_interfaces() -> Result<Vec<IfaceInfo>> {
    let mut out = Vec::new();
    out.push(IfaceInfo {
        name: "any".into(),
        description: "All interfaces (Linux cooked)".into(),
        is_up: true,
        mac: None,
    });
    let entries = fs::read_dir("/sys/class/net").context("read /sys/class/net")?;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name == "any" {
            continue;
        }
        let operstate = fs::read_to_string(e.path().join("operstate"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let mac = fs::read_to_string(e.path().join("address"))
            .ok()
            .and_then(|s| parse_mac(s.trim()));
        out.push(IfaceInfo {
            name: name.clone(),
            description: name,
            is_up: operstate == "up" || operstate == "unknown",
            mac,
        });
    }
    Ok(out)
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut m = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        m[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(m)
}

struct RingState {
    map: *mut u8,
    map_len: usize,
    block_size: usize,
    block_nr: usize,
    current_block: usize,
    offset_in_block: usize,
}

// SAFETY: ring mmap is exclusive to this capture instance.
unsafe impl Send for RingState {}

pub struct LinuxCapture {
    fd: OwnedFd,
    iface: String,
    ifindex: i32,
    link_type: LinkType,
    buf: Vec<u8>,
    bpf_prog: Option<Vec<SockFilter>>,
    tpacket_v3_available: bool,
    use_ring: bool,
    ring: Option<RingState>,
}

impl LinuxCapture {
    pub fn open(name: &str, snaplen: i32, promiscuous: bool) -> Result<Self> {
        Self::open_with_filter(name, snaplen, promiscuous, None)
    }

    pub fn open_with_filter(
        name: &str,
        snaplen: i32,
        promiscuous: bool,
        filter: Option<&CaptureFilter>,
    ) -> Result<Self> {
        let proto = (ETH_P_ALL as u16).to_be() as c_int;
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, proto) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) || err.raw_os_error() == Some(libc::EACCES) {
                bail!(
                    "permission denied opening AF_PACKET — need CAP_NET_RAW (sudo or setcap cap_net_raw,cap_net_admin=eip): {err}"
                );
            }
            return Err(err).context("socket(AF_PACKET)");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let (ifindex, link_type) = if name == "any" {
            (0, LinkType::LinuxSll)
        } else {
            let idx = if_nametoindex(name)?;
            (idx, LinkType::Ethernet)
        };

        let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = AF_PACKET as u16;
        addr.sll_protocol = (ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = ifindex;
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const _ as *const sockaddr,
                mem::size_of::<sockaddr_ll>() as u32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("bind AF_PACKET");
        }

        if promiscuous && ifindex > 0 {
            let mut mreq: libc::packet_mreq = unsafe { mem::zeroed() };
            mreq.mr_ifindex = ifindex;
            mreq.mr_type = PACKET_MR_PROMISC as u16;
            let _ = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    SOL_PACKET,
                    PACKET_ADD_MEMBERSHIP,
                    &mreq as *const _ as *const c_void,
                    mem::size_of_val(&mreq) as u32,
                )
            };
        }

        let (tpacket_v3_available, ring) = try_setup_tpacket_v3_ring(fd.as_raw_fd());
        let use_ring = ring.is_some();

        let snap = snaplen.clamp(64, 65535) as usize;
        let mut cap = Self {
            fd,
            iface: name.to_string(),
            ifindex,
            link_type,
            buf: vec![0u8; snap],
            bpf_prog: None,
            tpacket_v3_available,
            use_ring,
            ring,
        };
        if let Some(f) = filter {
            cap.set_filter(f)?;
        }
        Ok(cap)
    }

    pub fn set_filter(&mut self, filter: &CaptureFilter) -> Result<()> {
        self.detach_bpf()?;
        if matches!(filter, CaptureFilter::True) {
            return Ok(());
        }
        if let Some(prog) = compile_simple_bpf(filter, self.link_type) {
            self.attach_bpf(&prog)?;
            self.bpf_prog = Some(prog);
        }
        Ok(())
    }

    fn attach_bpf(&self, prog: &[SockFilter]) -> Result<()> {
        let fprog = SockFprog {
            len: prog.len() as u16,
            filter: prog.as_ptr(),
        };
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                SOL_SOCKET,
                SO_ATTACH_FILTER,
                &fprog as *const _ as *const c_void,
                mem::size_of::<SockFprog>() as u32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("SO_ATTACH_FILTER");
        }
        Ok(())
    }

    fn detach_bpf(&mut self) -> Result<()> {
        if self.bpf_prog.is_none() {
            return Ok(());
        }
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                SOL_SOCKET,
                SO_DETACH_FILTER,
                std::ptr::null(),
                0,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("SO_DETACH_FILTER");
        }
        self.bpf_prog = None;
        Ok(())
    }

    pub fn tpacket_v3_available(&self) -> bool {
        self.tpacket_v3_available
    }

    pub fn uses_ring(&self) -> bool {
        self.use_ring
    }

    fn next_from_ring(&mut self) -> Result<Option<CapturePacket>> {
        let ring = match self.ring.as_mut() {
            Some(r) => r,
            None => return Ok(None),
        };
        let link_type = if self.ifindex == 0 {
            LinkType::LinuxSll
        } else {
            self.link_type
        };
        let iface = self.iface.clone();

        for _ in 0..ring.block_nr {
            let block_ptr = unsafe { ring.map.add(ring.current_block * ring.block_size) };
            let desc = unsafe { &*(block_ptr as *const TpacketBlockDesc) };
            if desc.hdr.block_status & TP_STATUS_USER == 0 {
                ring.current_block = (ring.current_block + 1) % ring.block_nr;
                ring.offset_in_block = 0;
                continue;
            }

            if ring.offset_in_block == 0 {
                ring.offset_in_block = desc.hdr.offset_to_first_pkt as usize;
            }

            if ring.offset_in_block == 0 || ring.offset_in_block >= ring.block_size {
                unsafe {
                    let hdr_status = block_ptr.add(8) as *mut u32;
                    *hdr_status = TP_STATUS_KERNEL;
                }
                ring.current_block = (ring.current_block + 1) % ring.block_nr;
                ring.offset_in_block = 0;
                continue;
            }

            let hdr = unsafe { &*(block_ptr.add(ring.offset_in_block) as *const Tpacket3Hdr) };
            let snap = hdr.tp_snaplen as usize;
            let mac = hdr.tp_mac as usize;
            let pkt_off = ring.offset_in_block + mac;
            if pkt_off + snap > ring.block_size {
                unsafe {
                    let hdr_status = block_ptr.add(8) as *mut u32;
                    *hdr_status = TP_STATUS_KERNEL;
                }
                ring.current_block = (ring.current_block + 1) % ring.block_nr;
                ring.offset_in_block = 0;
                continue;
            }

            let data = unsafe {
                Bytes::copy_from_slice(std::slice::from_raw_parts(block_ptr.add(pkt_off), snap))
            };
            let next = hdr.tp_next_offset as usize;
            if next == 0 {
                unsafe {
                    let hdr_status = block_ptr.add(8) as *mut u32;
                    *hdr_status = TP_STATUS_KERNEL;
                }
                ring.current_block = (ring.current_block + 1) % ring.block_nr;
                ring.offset_in_block = 0;
            } else {
                ring.offset_in_block += next;
            }

            return Ok(Some(CapturePacket {
                data,
                link_type,
                interface: iface,
                orig_len: hdr.tp_len,
                wall: SystemTime::now(),
            }));
        }
        Ok(None)
    }
}

impl Drop for LinuxCapture {
    fn drop(&mut self) {
        let _ = self.detach_bpf();
        if let Some(ring) = self.ring.take() {
            unsafe {
                libc::munmap(ring.map as *mut c_void, ring.map_len);
            }
        }
    }
}

/// Set PACKET_VERSION=TPACKET_V3 and mmap RX ring. Returns (version_ok, ring).
fn try_setup_tpacket_v3_ring(fd: c_int) -> (bool, Option<RingState>) {
    let ver = TPACKET_V3;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            SOL_PACKET,
            PACKET_VERSION,
            &ver as *const _ as *const c_void,
            mem::size_of::<c_int>() as u32,
        )
    };
    if rc != 0 {
        return (false, None);
    }
    let version_ok = true;

    let block_size: u32 = 1 << 18; // 256 KiB
    let block_nr: u32 = 16;
    let frame_size: u32 = 2048;
    let frame_nr = (block_size / frame_size) * block_nr;
    let req = TpacketReq3 {
        tp_block_size: block_size,
        tp_block_nr: block_nr,
        tp_frame_size: frame_size,
        tp_frame_nr: frame_nr,
        tp_retire_blk_tov: 50,
        tp_sizeof_priv: 0,
        tp_feature_req_word: 0,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            SOL_PACKET,
            PACKET_RX_RING,
            &req as *const _ as *const c_void,
            mem::size_of::<TpacketReq3>() as u32,
        )
    };
    if rc != 0 {
        return (version_ok, None);
    }
    let map_len = (block_size as usize) * (block_nr as usize);
    let map = unsafe {
        libc::mmap(
            ptr::null_mut(),
            map_len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            0,
        )
    };
    if map == libc::MAP_FAILED || map.is_null() {
        return (version_ok, None);
    }
    (
        version_ok,
        Some(RingState {
            map: map as *mut u8,
            map_len,
            block_size: block_size as usize,
            block_nr: block_nr as usize,
            current_block: 0,
            offset_in_block: 0,
        }),
    )
}

impl LiveCapture for LinuxCapture {
    fn next_packet(&mut self) -> Result<Option<CapturePacket>> {
        if self.use_ring {
            if let Some(pkt) = self.next_from_ring()? {
                return Ok(Some(pkt));
            }
            // No packet in ring — also try not to spin; return None for nonblocking
            return Ok(None);
        }
        let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
        let mut addrlen = mem::size_of::<sockaddr_ll>() as u32;
        let n = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                self.buf.as_mut_ptr() as *mut c_void,
                self.buf.len(),
                0,
                &mut addr as *mut _ as *mut sockaddr,
                &mut addrlen,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(err).context("recvfrom");
        }
        let n = n as usize;
        let link_type = if self.ifindex == 0 {
            LinkType::LinuxSll
        } else {
            self.link_type
        };
        Ok(Some(CapturePacket {
            data: Bytes::copy_from_slice(&self.buf[..n]),
            link_type,
            interface: self.iface.clone(),
            orig_len: n as u32,
            wall: SystemTime::now(),
        }))
    }

    fn inject(&mut self, frame: &[u8]) -> Result<()> {
        if self.ifindex == 0 {
            bail!("cannot inject on 'any' — pick a specific interface");
        }
        let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = AF_PACKET as u16;
        addr.sll_ifindex = self.ifindex;
        addr.sll_halen = 6;
        if frame.len() >= 6 {
            addr.sll_addr[..6].copy_from_slice(&frame[..6]);
        }
        let n = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                frame.as_ptr() as *const c_void,
                frame.len(),
                0,
                &addr as *const _ as *const sockaddr,
                mem::size_of::<sockaddr_ll>() as u32,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error()).context("sendto inject");
        }
        Ok(())
    }

    fn interface(&self) -> &str {
        &self.iface
    }

    fn link_type(&self) -> LinkType {
        self.link_type
    }
}

fn if_nametoindex(name: &str) -> Result<i32> {
    let c = std::ffi::CString::new(name).context("iface name")?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        bail!("unknown interface {name}");
    }
    Ok(idx as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn tpacket_v3_setsockopt_smoke() {
        let proto = (ETH_P_ALL as u16).to_be() as c_int;
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, proto) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) || err.raw_os_error() == Some(libc::EACCES) {
                return;
            }
            panic!("socket(AF_PACKET): {err}");
        }
        let ver = TPACKET_V3;
        let _ = unsafe {
            libc::setsockopt(
                fd,
                SOL_PACKET,
                PACKET_VERSION,
                &ver as *const _ as *const c_void,
                mem::size_of::<c_int>() as u32,
            )
        };
        unsafe {
            libc::close(fd);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tpacket_v3_ring_init_smoke() {
        let proto = (ETH_P_ALL as u16).to_be() as c_int;
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, proto) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) || err.raw_os_error() == Some(libc::EACCES) {
                return;
            }
            panic!("socket(AF_PACKET): {err}");
        }
        let (ver_ok, ring) = try_setup_tpacket_v3_ring(fd);
        if let Some(r) = ring {
            unsafe {
                libc::munmap(r.map as *mut c_void, r.map_len);
            }
        }
        unsafe {
            libc::close(fd);
        }
        let _ = ver_ok;
    }
}
