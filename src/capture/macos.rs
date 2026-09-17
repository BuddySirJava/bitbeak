//! macOS BPF live capture.

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use libc::{
    c_uint, c_ulong, c_void, ifreq, ioctl, BIOCGBLEN, BIOCIMMEDIATE, BIOCPROMISC, BIOCSBLEN,
    BIOCSETF, BIOCSETIF, BIOCVERSION,
};

use crate::capture::backend::{CapturePacket, IfaceInfo, LiveCapture};
use crate::capture::bpf::{compile_simple_bpf, SockFilter};
use crate::capture::cap_filter::CaptureFilter;
use crate::dissect::packet::LinkType;

pub fn list_interfaces() -> Result<Vec<IfaceInfo>> {
    let mut out = Vec::new();
    out.push(IfaceInfo {
        name: "any".into(),
        description: "All interfaces (fan-in)".into(),
        is_up: true,
        mac: None,
    });
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Err(io::Error::last_os_error()).context("getifaddrs");
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let name = std::ffi::CStr::from_ptr((*cur).ifa_name)
                .to_string_lossy()
                .into_owned();
            if !out.iter().any(|i| i.name == name) {
                let flags = (*cur).ifa_flags;
                out.push(IfaceInfo {
                    name: name.clone(),
                    description: name,
                    is_up: flags & (libc::IFF_UP as u32) != 0,
                    mac: None,
                });
            }
            cur = (*cur).ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    Ok(out)
}

pub struct MacCapture {
    /// One or more BPF devices (fan-in for "any").
    devices: Vec<BpfDev>,
    iface: String,
    link_type: LinkType,
    rr: usize,
}

struct BpfDev {
    file: std::fs::File,
    buf: Vec<u8>,
    pending: Vec<CapturePacket>,
    iface: String,
    link_type: LinkType,
}

impl MacCapture {
    pub fn open(name: &str, snaplen: i32, promiscuous: bool) -> Result<Self> {
        let ifaces: Vec<String> = if name == "any" {
            list_interfaces()?
                .into_iter()
                .filter(|i| i.name != "any" && i.is_up)
                .map(|i| i.name)
                .collect()
        } else {
            vec![name.to_string()]
        };
        if ifaces.is_empty() {
            bail!("no interfaces to capture");
        }
        let mut devices = Vec::new();
        let mut last_err = None;
        for iface in &ifaces {
            match open_bpf(iface, snaplen, promiscuous) {
                Ok(d) => devices.push(d),
                Err(e) => last_err = Some(e),
            }
        }
        if devices.is_empty() {
            return Err(last_err.unwrap_or_else(|| anyhow::anyhow!("failed to open BPF")));
        }
        let link_type = devices[0].link_type;
        Ok(Self {
            devices,
            iface: name.to_string(),
            link_type,
            rr: 0,
        })
    }

    /// Attach classic BPF via BIOCSETF when the expression compiles; else leave userspace-only.
    pub fn set_filter(&mut self, filter: &CaptureFilter) -> Result<()> {
        let Some(prog) = compile_simple_bpf(filter, self.link_type) else {
            return Ok(());
        };
        for dev in &self.devices {
            attach_biocsetf(dev.file.as_raw_fd(), &prog)?;
        }
        Ok(())
    }
}

#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *mut SockFilter,
}

fn attach_biocsetf(fd: i32, prog: &[SockFilter]) -> Result<()> {
    let mut insns = prog.to_vec();
    let mut bp = BpfProgram {
        bf_len: insns.len() as u32,
        bf_insns: insns.as_mut_ptr(),
    };
    let rc = unsafe { ioctl(fd, BIOCSETF, &mut bp) };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("BIOCSETF");
    }
    Ok(())
}

fn open_bpf(iface: &str, snaplen: i32, promiscuous: bool) -> Result<BpfDev> {
    let mut file = None;
    let mut last = None;
    for i in 0..256 {
        let path = format!("/dev/bpf{i}");
        match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(f) => {
                file = Some(f);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let file = file.ok_or_else(|| {
        last.map(|e| anyhow::Error::new(e))
            .unwrap_or_else(|| anyhow::anyhow!("no /dev/bpf* available — need root or BPF group"))
    })?;

    let fd = file.as_raw_fd();
    let mut blen: c_uint = (snaplen.clamp(64, 65535) as c_uint).max(4096);
    unsafe {
        if ioctl(fd, BIOCSBLEN, &mut blen) < 0 {
            return Err(io::Error::last_os_error()).context("BIOCSBLEN");
        }
        let mut ifr: ifreq = mem::zeroed();
        let cname = CString::new(iface).context("iface")?;
        let bytes = cname.as_bytes_with_nul();
        if bytes.len() > ifr.ifr_name.len() {
            bail!("iface name too long");
        }
        ifr.ifr_name[..bytes.len()].copy_from_slice(std::slice::from_raw_parts(
            bytes.as_ptr() as *const libc::c_char,
            bytes.len(),
        ));
        if ioctl(fd, BIOCSETIF, &ifr) < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                bail!("permission denied on BPF — run as root or join BPF group: {err}");
            }
            return Err(err).context("BIOCSETIF");
        }
        let yes: c_uint = 1;
        let _ = ioctl(fd, BIOCIMMEDIATE, &yes);
        if promiscuous {
            // BIOCPROMISC is `c_uint` in libc; ioctl's request is `c_ulong` on Darwin.
            let _ = ioctl(fd, BIOCPROMISC as c_ulong, std::ptr::null::<c_void>());
        }
        let _ = BIOCVERSION; // silence unused on some targets
    }

    // Detect DLT
    let link_type = if iface.starts_with("lo") || iface.starts_with("utun") {
        LinkType::Null
    } else {
        LinkType::Ethernet
    };

    let mut actual: c_uint = 0;
    unsafe {
        let _ = ioctl(fd, BIOCGBLEN, &mut actual);
    }
    let buflen = if actual > 0 {
        actual as usize
    } else {
        blen as usize
    };

    Ok(BpfDev {
        file,
        buf: vec![0u8; buflen],
        pending: Vec::new(),
        iface: iface.to_string(),
        link_type,
    })
}

impl LiveCapture for MacCapture {
    fn next_packet(&mut self) -> Result<Option<CapturePacket>> {
        let n = self.devices.len();
        if n == 0 {
            return Ok(None);
        }
        let idx = self.rr % n;
        if let Some(p) = self.devices[idx].pending.pop() {
            return Ok(Some(p));
        }
        for _ in 0..n {
            let idx = self.rr % n;
            self.rr += 1;
            let dev = &mut self.devices[idx];
            match fill_pending(dev) {
                Ok(true) => {
                    if let Some(p) = dev.pending.pop() {
                        return Ok(Some(p));
                    }
                }
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    fn inject(&mut self, frame: &[u8]) -> Result<()> {
        let dev = self
            .devices
            .get_mut(0)
            .ok_or_else(|| anyhow::anyhow!("no BPF device"))?;
        dev.file.write_all(frame).context("BPF write inject")?;
        Ok(())
    }

    fn interface(&self) -> &str {
        &self.iface
    }

    fn link_type(&self) -> LinkType {
        self.link_type
    }
}

fn fill_pending(dev: &mut BpfDev) -> Result<bool> {
    let n = match dev.file.read(&mut dev.buf) {
        Ok(0) => return Ok(false),
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
        Err(e) => return Err(e).context("BPF read"),
    };
    // Parse BPF header frames
    let mut off = 0usize;
    while off + 18 <= n {
        // bpf_hdr: timeval(8 or 16) + caplen + datalen + hdrlen
        // macOS: struct bpf_hdr { struct timeval bh_tstamp; uint32 bh_caplen; uint32 bh_datalen; uint16 bh_hdrlen; }
        // timeval is 16 bytes on 64-bit
        let caplen = u32::from_ne_bytes(dev.buf[off + 16..off + 20].try_into().unwrap()) as usize;
        let hdrlen = u16::from_ne_bytes(dev.buf[off + 24..off + 26].try_into().unwrap()) as usize;
        let data_off = off + hdrlen;
        let data_end = data_off + caplen;
        if data_end > n {
            break;
        }
        let data = Bytes::copy_from_slice(&dev.buf[data_off..data_end]);
        dev.pending.push(CapturePacket {
            data,
            link_type: dev.link_type,
            interface: dev.iface.clone(),
            orig_len: caplen as u32,
            wall: SystemTime::now(),
        });
        // Align to word boundary
        let next = (data_end + 3) & !3;
        off = next;
    }
    Ok(!dev.pending.is_empty())
}
