//! Windows Npcap (wpcap.dll) runtime-loaded capture.

use std::ffi::CStr;
use std::ptr;
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use libloading::{Library, Symbol};

use crate::capture::backend::{CapturePacket, IfaceInfo, LiveCapture};
use crate::capture::npcap_install;
use crate::dissect::packet::LinkType;

type PcapT = *mut std::ffi::c_void;
type PcapIfT = *mut PcapIf;

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut i8,
    description: *mut i8,
    addresses: *mut std::ffi::c_void,
    flags: u32,
}

#[repr(C)]
struct PcapPkthdr {
    ts_sec: libc_time,
    ts_usec: libc_time,
    caplen: u32,
    len: u32,
}

#[cfg(target_pointer_width = "64")]
type libc_time = i64;
#[cfg(not(target_pointer_width = "64"))]
type libc_time = i32;

#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *mut std::ffi::c_void,
}

struct Wpcap {
    _lib: Library,
    findalldevs: Symbol<'static, unsafe extern "C" fn(*mut PcapIfT, *mut i8) -> i32>,
    freealldevs: Symbol<'static, unsafe extern "C" fn(PcapIfT)>,
    open_live: Symbol<'static, unsafe extern "C" fn(*const i8, i32, i32, i32, *mut i8) -> PcapT>,
    next_ex:
        Symbol<'static, unsafe extern "C" fn(PcapT, *mut *mut PcapPkthdr, *mut *const u8) -> i32>,
    close: Symbol<'static, unsafe extern "C" fn(PcapT)>,
    sendpacket: Symbol<'static, unsafe extern "C" fn(PcapT, *const u8, i32) -> i32>,
    compile:
        Symbol<'static, unsafe extern "C" fn(PcapT, *mut BpfProgram, *const i8, i32, u32) -> i32>,
    setfilter: Symbol<'static, unsafe extern "C" fn(PcapT, *mut BpfProgram) -> i32>,
    freecode: Symbol<'static, unsafe extern "C" fn(*mut BpfProgram)>,
}

// SAFETY: we only call from one capture thread.
unsafe impl Send for Wpcap {}

fn load_wpcap() -> Result<Wpcap> {
    let lib = unsafe { Library::new("wpcap.dll") }
        .or_else(|_| unsafe { Library::new("C:\\Windows\\System32\\Npcap\\wpcap.dll") })
        .context("load wpcap.dll")?;

    unsafe {
        let findalldevs = lib.get(b"pcap_findalldevs\0")?;
        let freealldevs = lib.get(b"pcap_freealldevs\0")?;
        let open_live = lib.get(b"pcap_open_live\0")?;
        let next_ex = lib.get(b"pcap_next_ex\0")?;
        let close = lib.get(b"pcap_close\0")?;
        let sendpacket = lib.get(b"pcap_sendpacket\0")?;
        let compile = lib.get(b"pcap_compile\0")?;
        let setfilter = lib.get(b"pcap_setfilter\0")?;
        let freecode = lib.get(b"pcap_freecode\0")?;
        let w = Wpcap {
            findalldevs: std::mem::transmute(findalldevs),
            freealldevs: std::mem::transmute(freealldevs),
            open_live: std::mem::transmute(open_live),
            next_ex: std::mem::transmute(next_ex),
            close: std::mem::transmute(close),
            sendpacket: std::mem::transmute(sendpacket),
            compile: std::mem::transmute(compile),
            setfilter: std::mem::transmute(setfilter),
            freecode: std::mem::transmute(freecode),
            _lib: lib,
        };
        Ok(w)
    }
}

pub fn list_interfaces() -> Result<Vec<IfaceInfo>> {
    let w = match load_wpcap() {
        Ok(w) => w,
        Err(_) => {
            // Offer empty list; open will trigger install
            return Ok(vec![IfaceInfo {
                name: "any".into(),
                description: "All interfaces (requires Npcap)".into(),
                is_up: true,
                mac: None,
            }]);
        }
    };
    let mut all: PcapIfT = ptr::null_mut();
    let mut errbuf = [0i8; 256];
    let rc = unsafe { (w.findalldevs)(&mut all, errbuf.as_mut_ptr()) };
    if rc != 0 {
        let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        bail!("pcap_findalldevs: {msg}");
    }
    let mut out = Vec::new();
    out.push(IfaceInfo {
        name: "any".into(),
        description: "All interfaces (fan-in)".into(),
        is_up: true,
        mac: None,
    });
    unsafe {
        let mut cur = all;
        while !cur.is_null() {
            let name = if (*cur).name.is_null() {
                String::new()
            } else {
                CStr::from_ptr((*cur).name).to_string_lossy().into_owned()
            };
            let desc = if (*cur).description.is_null() {
                name.clone()
            } else {
                CStr::from_ptr((*cur).description)
                    .to_string_lossy()
                    .into_owned()
            };
            out.push(IfaceInfo {
                name,
                description: desc,
                is_up: true,
                mac: None,
            });
            cur = (*cur).next;
        }
        (w.freealldevs)(all);
    }
    Ok(out)
}

struct WinHandle {
    pcap: PcapT,
    name: String,
    bpf: Option<BpfProgram>,
}

pub struct WinCapture {
    wpcap: Wpcap,
    handles: Vec<WinHandle>,
    iface: String,
    rr: usize,
}

impl WinCapture {
    pub fn open(name: &str, snaplen: i32, promiscuous: bool, filter: Option<&str>) -> Result<Self> {
        let wpcap = match load_wpcap() {
            Ok(w) => w,
            Err(_) => {
                npcap_install::ensure_npcap()?;
                load_wpcap().context("wpcap.dll still missing after Npcap install")?
            }
        };

        let names: Vec<String> = if name == "any" {
            list_interfaces()?
                .into_iter()
                .filter(|i| i.name != "any")
                .map(|i| i.name)
                .collect()
        } else {
            vec![name.to_string()]
        };
        if names.is_empty() {
            bail!("no Npcap interfaces found");
        }

        let mut handles = Vec::new();
        let mut errbuf = [0i8; 256];
        let promisc = if promiscuous { 1 } else { 0 };
        for n in &names {
            let cname = std::ffi::CString::new(n.as_str())?;
            let h = unsafe {
                (wpcap.open_live)(cname.as_ptr(), snaplen, promisc, 100, errbuf.as_mut_ptr())
            };
            if h.is_null() {
                continue;
            }
            let mut wh = WinHandle {
                pcap: h,
                name: n.clone(),
                bpf: None,
            };
            if let Some(f) = filter {
                if !f.is_empty() {
                    apply_pcap_filter(&wpcap, &mut wh, f)?;
                }
            }
            handles.push(wh);
        }
        if handles.is_empty() {
            let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            bail!("pcap_open_live failed: {msg}");
        }
        Ok(Self {
            wpcap,
            handles,
            iface: name.to_string(),
            rr: 0,
        })
    }
}

fn apply_pcap_filter(wpcap: &Wpcap, handle: &mut WinHandle, expr: &str) -> Result<()> {
    let cexpr = std::ffi::CString::new(expr)?;
    let mut prog = BpfProgram {
        bf_len: 0,
        bf_insns: ptr::null_mut(),
    };
    let rc = unsafe { (wpcap.compile)(handle.pcap, &mut prog, cexpr.as_ptr(), 1, 0) };
    if rc != 0 {
        bail!("pcap_compile failed for filter `{expr}`");
    }
    let rc = unsafe { (wpcap.setfilter)(handle.pcap, &mut prog) };
    if rc != 0 {
        unsafe { (wpcap.freecode)(&mut prog) };
        bail!("pcap_setfilter failed");
    }
    handle.bpf = Some(prog);
    Ok(())
}

impl Drop for WinCapture {
    fn drop(&mut self) {
        for mut h in self.handles.drain(..) {
            if let Some(mut prog) = h.bpf.take() {
                unsafe { (self.wpcap.freecode)(&mut prog) };
            }
            unsafe { (self.wpcap.close)(h.pcap) };
        }
    }
}

impl LiveCapture for WinCapture {
    fn next_packet(&mut self) -> Result<Option<CapturePacket>> {
        let n = self.handles.len();
        for _ in 0..n {
            let idx = self.rr % n;
            self.rr += 1;
            let handle = &self.handles[idx];
            let mut hdr: *mut PcapPkthdr = ptr::null_mut();
            let mut data: *const u8 = ptr::null();
            let rc = unsafe { (self.wpcap.next_ex)(handle.pcap, &mut hdr, &mut data) };
            if rc == 1 && !hdr.is_null() && !data.is_null() {
                let caplen = unsafe { (*hdr).caplen } as usize;
                let len = unsafe { (*hdr).len };
                let slice = unsafe { std::slice::from_raw_parts(data, caplen) };
                return Ok(Some(CapturePacket {
                    data: Bytes::copy_from_slice(slice),
                    link_type: LinkType::Ethernet,
                    interface: handle.name.clone(),
                    orig_len: len,
                    wall: SystemTime::now(),
                }));
            }
        }
        Ok(None)
    }

    fn inject(&mut self, frame: &[u8]) -> Result<()> {
        let h = self
            .handles
            .first()
            .ok_or_else(|| anyhow::anyhow!("no handle"))?;
        let rc = unsafe { (self.wpcap.sendpacket)(h.pcap, frame.as_ptr(), frame.len() as i32) };
        if rc != 0 {
            bail!("pcap_sendpacket failed ({rc})");
        }
        Ok(())
    }

    fn interface(&self) -> &str {
        &self.iface
    }

    fn link_type(&self) -> LinkType {
        LinkType::Ethernet
    }
}

// Minimal libc time types without depending on libc on Windows.
mod libc {
    #![allow(dead_code)]
}
