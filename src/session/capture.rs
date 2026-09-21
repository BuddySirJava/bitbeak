//! Capture session: live sniff / open file, three-pane packet UI state.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;

use crate::capture::backend::{self, CaptureHandle};
use crate::capture::cap_filter::{parse_capture_filter, CaptureFilter};
use crate::capture::disp_filter::{parse_display_filter, DisplayFilter};
use crate::capture::file_io::{self, default_capture_path};
use crate::capture::ring::DiskRing;
use crate::dissect::analysis::CaptureStats;
use crate::dissect::decrypt::KeyLog;
use crate::dissect::follow::{follow_http, follow_tcp, follow_udp, FollowResult};
use crate::dissect::names::NameResolver;
use crate::dissect::packet::{PacketRecord, PacketStore};
use crate::session::{ConnStatus, PaneFocus, SessionKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureSource {
    Live,
    File,
}

pub struct CaptureSession {
    pub title_iface: String,
    pub source: CaptureSource,
    pub status: ConnStatus,
    pub status_msg: String,
    pub store: PacketStore,
    pub stats: CaptureStats,
    pub names: NameResolver,
    pub selected: usize,
    pub tree_selected: usize,
    pub follow: bool,
    pub focus: PaneFocus,
    pub display_filter_str: String,
    pub display_filter: DisplayFilter,
    pub capture_filter_str: String,
    pub capturing: bool,
    pub keylog: Arc<Option<KeyLog>>,
    pub keylog_path: Option<PathBuf>,
    pub overlay_row: usize,
    pub ring: Option<DiskRing>,
    pub follow_view: Option<FollowResult>,
    pub marked: Vec<u64>,
    /// Last open/start error (privilege, device missing, …).
    pub last_error: Option<String>,
    /// Whether the active capture filter is attached as kernel BPF.
    pub filter_kernel_bpf: bool,
    packet_rx: Option<Receiver<PacketRecord>>,
    stop_tx: Option<Sender<()>>,
    join: Option<JoinHandle<()>>,
    inject_tx: Option<Sender<Bytes>>,
}

impl CaptureSession {
    pub fn new_live(iface: &str, max_packets: usize) -> Self {
        Self {
            title_iface: iface.to_string(),
            source: CaptureSource::Live,
            status: ConnStatus::Idle,
            status_msg: format!("ready · {}", backend::capture_hint()),
            store: PacketStore::new(max_packets),
            stats: CaptureStats {
                io: crate::dissect::analysis::IoGraph::new(120),
                ..Default::default()
            },
            names: NameResolver::new(),
            selected: 0,
            tree_selected: 0,
            follow: true,
            focus: PaneFocus::Log,
            display_filter_str: String::new(),
            display_filter: DisplayFilter::True,
            capture_filter_str: String::new(),
            capturing: false,
            keylog: Arc::new(None),
            keylog_path: None,
            overlay_row: 0,
            ring: None,
            follow_view: None,
            marked: Vec::new(),
            last_error: None,
            filter_kernel_bpf: true,
            packet_rx: None,
            stop_tx: None,
            join: None,
            inject_tx: None,
        }
    }

    pub fn open_file(path: &std::path::Path, max_packets: usize) -> Result<Self> {
        let opened = file_io::open_capture_file(path)?;
        let file_count = opened.packets.len();
        let mut s = Self::new_live(path.display().to_string().as_str(), max_packets);
        s.source = CaptureSource::File;
        s.status = ConnStatus::Connected;
        for (data, link, orig, wall) in opened.packets {
            let id = s.push_dissected(data, link, path.display().to_string(), orig, wall);
            if let Some(pkt) = s.store.get_by_id(id).cloned() {
                s.stats.ingest(&pkt);
            }
        }
        let kept = s.store.len();
        let dropped = s.store.dropped;
        s.status_msg = if dropped > 0 {
            format!(
                "FILE · showing {kept}/{file_count} (ring max {max_packets}; oldest dropped) · {}",
                path.display()
            )
        } else {
            format!("FILE · {kept} packets · {}", path.display())
        };
        if !s.store.is_empty() {
            s.selected = s.store.len() - 1;
        }
        Ok(s)
    }

    pub fn set_display_filter(&mut self, q: &str) -> Result<(), String> {
        match parse_display_filter(q) {
            Ok(f) => {
                self.display_filter = f;
                self.display_filter_str = q.to_string();
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn set_capture_filter(&mut self, q: &str) -> Result<(), String> {
        if self.source == CaptureSource::File {
            return Err(
                "capture filter applies to live sniff only — use F8 display filter on files"
                    .into(),
            );
        }
        match parse_capture_filter(q) {
            Ok(_) => {
                self.capture_filter_str = q.to_string();
                if self.capturing {
                    self.stop_capture();
                    self.start_capture().map_err(|e| e.to_string())?;
                }
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn load_keylog(&mut self, path: &std::path::Path) -> Result<()> {
        let kl = KeyLog::load(path)?;
        self.keylog_path = Some(path.to_path_buf());
        self.keylog = Arc::new(Some(kl));
        self.redigest_all();
        self.status_msg = format!("keylog loaded {}", path.display());
        Ok(())
    }

    fn push_dissected(
        &mut self,
        data: Bytes,
        link_type: crate::dissect::packet::LinkType,
        interface: String,
        orig_len: u32,
        wall: std::time::SystemTime,
    ) -> u64 {
        let kl = self.keylog.as_ref().as_ref();
        let d = crate::dissect::dissect(&data, link_type, kl);
        let rec = PacketRecord {
            id: 0,
            at: std::time::Instant::now(),
            wall,
            interface,
            link_type,
            orig_len: if orig_len == 0 {
                data.len() as u32
            } else {
                orig_len
            },
            data,
            summary: d.summary,
            flags: d.flags,
            expert: d.expert,
            tree: Some(d.tree),
            decrypted: d.decrypted,
            fields: d.fields,
        };
        self.store.push(rec)
    }

    fn redigest_all(&mut self) {
        let kl = self.keylog.as_ref().as_ref();
        for i in 0..self.store.len() {
            let Some(data) = self.store.get(i).map(|p| (p.data.clone(), p.link_type)) else {
                continue;
            };
            let d = crate::dissect::dissect(&data.0, data.1, kl);
            if let Some(pkt) = self.store.get_mut(i) {
                pkt.summary = d.summary;
                pkt.flags = d.flags;
                pkt.expert = d.expert;
                pkt.tree = Some(d.tree);
                pkt.decrypted = d.decrypted;
                pkt.fields = d.fields;
            }
        }
    }

    pub fn filtered_indices(&self) -> Vec<usize> {
        self.store
            .iter()
            .enumerate()
            .filter(|(_, p)| self.display_filter.matches(p))
            .map(|(i, _)| i)
            .collect()
    }

    pub fn visible_packet(&self) -> Option<&PacketRecord> {
        let idx = self.filtered_indices();
        if idx.is_empty() {
            return None;
        }
        let sel = self.selected.min(idx.len() - 1);
        self.store.get(idx[sel])
    }

    pub fn drain_packets(&mut self) {
        let Some(rx) = self.packet_rx.as_ref() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(pkt) => {
                    if let Some(ring) = self.ring.as_mut() {
                        let _ = ring.write_packet(&pkt);
                    }
                    self.stats.ingest(&pkt);
                    let follow = self.follow;
                    self.store.push(pkt);
                    if follow {
                        let n = self.filtered_indices().len();
                        if n > 0 {
                            self.selected = n - 1;
                        }
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.capturing = false;
                    self.status = ConnStatus::Disconnected;
                    self.status_msg = "capture ended".into();
                    break;
                }
            }
        }
    }

    pub fn start_capture(&mut self) -> Result<()> {
        if self.source != CaptureSource::Live {
            anyhow::bail!("cannot live-capture a file session");
        }
        if self.capturing {
            return Ok(());
        }
        let iface = self.title_iface.clone();
        let cap_filter =
            parse_capture_filter(&self.capture_filter_str).unwrap_or(CaptureFilter::True);
        self.filter_kernel_bpf = cap_filter.is_kernel_simple();
        let handle = match backend::open_live_filtered(&iface, 65535, true, Some(&cap_filter)) {
            Ok(h) => h,
            Err(e) => {
                self.last_error = Some(e.to_string());
                self.status = ConnStatus::Error;
                self.status_msg = format!("{e:#} · {}", backend::capture_hint());
                return Err(e);
            }
        };
        let (tx, rx) = mpsc::sync_channel::<PacketRecord>(4096);
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let (inj_tx, inj_rx) = mpsc::channel::<Bytes>();
        let keylog = Arc::clone(&self.keylog);

        let join = thread::spawn(move || {
            capture_loop(handle, cap_filter, keylog, tx, stop_rx, inj_rx);
        });

        self.packet_rx = Some(rx);
        self.stop_tx = Some(stop_tx);
        self.inject_tx = Some(inj_tx);
        self.join = Some(join);
        self.capturing = true;
        self.last_error = None;
        self.status = ConnStatus::Connected;
        let filt = if self.capture_filter_str.is_empty() {
            "none".into()
        } else if self.filter_kernel_bpf {
            format!("{} (kernel BPF)", self.capture_filter_str)
        } else {
            format!("{} (userspace)", self.capture_filter_str)
        };
        self.status_msg = format!("capturing on {iface} · filter {filt}");
        Ok(())
    }

    pub fn stop_capture(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
        self.packet_rx = None;
        self.inject_tx = None;
        self.capturing = false;
        self.status = ConnStatus::Disconnected;
        self.status_msg = "capture stopped".into();
    }

    pub fn toggle_capture(&mut self) -> Result<()> {
        if self.capturing {
            self.stop_capture();
            Ok(())
        } else {
            self.start_capture()
        }
    }

    pub fn inject_selected(&mut self) -> Result<()> {
        let data = self
            .visible_packet()
            .map(|p| p.data.clone())
            .ok_or_else(|| anyhow::anyhow!("no packet selected"))?;
        let tx = self
            .inject_tx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("not capturing"))?;
        tx.send(data).map_err(|e| anyhow::anyhow!("inject: {e}"))?;
        self.status_msg = "inject queued".into();
        Ok(())
    }

    pub fn follow_selected_tcp(&mut self) -> bool {
        let Some(sel) = self.visible_packet().cloned() else {
            return false;
        };
        let all: Vec<_> = self.store.all();
        let mut r = follow_tcp(&all, &sel);
        r.label.push_str(" · snapshot (re-run to refresh)");
        self.follow_view = Some(r);
        true
    }

    pub fn follow_selected_udp(&mut self) -> bool {
        let Some(sel) = self.visible_packet().cloned() else {
            return false;
        };
        let all: Vec<_> = self.store.all();
        let mut r = follow_udp(&all, &sel);
        r.label.push_str(" · snapshot (re-run to refresh)");
        self.follow_view = Some(r);
        true
    }

    pub fn follow_selected_http(&mut self) -> bool {
        let Some(sel) = self.visible_packet().cloned() else {
            return false;
        };
        let all: Vec<_> = self.store.all();
        let mut r = follow_http(&all, &sel);
        r.label.push_str(" · snapshot (re-run to refresh)");
        self.follow_view = Some(r);
        true
    }

    pub fn save_all(&self, path: &std::path::Path) -> Result<()> {
        let pkts = self.store.all();
        if path.extension().and_then(|e| e.to_str()) == Some("pcap") {
            file_io::save_packets_pcap(path, &pkts)
        } else {
            file_io::save_packets_pcapng(path, &pkts)
        }
    }

    pub fn save_displayed(&self, path: &std::path::Path) -> Result<()> {
        let idx = self.filtered_indices();
        let pkts: Vec<_> = idx.iter().filter_map(|&i| self.store.get(i)).collect();
        if path.extension().and_then(|e| e.to_str()) == Some("pcap") {
            file_io::save_packets_pcap(path, &pkts)
        } else {
            file_io::save_packets_pcapng(path, &pkts)
        }
    }

    pub fn default_save_path(&self) -> PathBuf {
        default_capture_path(&self.title_iface.replace('/', "_"))
    }

    pub fn selected_payload_for_composer(&self) -> Option<Bytes> {
        if let Some(f) = &self.follow_view {
            return Some(f.raw.clone());
        }
        self.visible_packet().map(|p| {
            if let Some(dec) = &p.decrypted {
                dec.clone()
            } else {
                // Prefer L4 payload if we can strip headers — fall back to full frame
                p.data.clone()
            }
        })
    }

    pub fn kind(&self) -> SessionKind {
        SessionKind::Capture
    }

    pub fn title(&self) -> String {
        format!("CAPTURE {}", self.title_iface)
    }

    pub fn nav(&mut self, delta: isize) {
        let n = self.filtered_indices().len();
        if n == 0 {
            self.selected = 0;
            return;
        }
        let cur = self.selected.min(n - 1);
        if delta < 0 {
            self.selected = cur.saturating_sub((-delta) as usize);
        } else {
            self.selected = (cur + delta as usize).min(n - 1);
        }
        self.follow = self.selected + 1 >= n;
        self.tree_selected = 0;
    }

    pub fn enable_ring(&mut self, dir: PathBuf, max_mb: u64, max_files: usize) -> Result<()> {
        self.ring = Some(DiskRing::new(dir, "capture", max_mb, max_files)?);
        Ok(())
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        self.stop_capture();
    }
}

fn capture_loop(
    mut handle: CaptureHandle,
    filter: CaptureFilter,
    keylog: Arc<Option<KeyLog>>,
    tx: mpsc::SyncSender<PacketRecord>,
    stop_rx: Receiver<()>,
    inj_rx: Receiver<Bytes>,
) {
    let iface = handle.interface().to_string();
    let link = handle.link_type();
    loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }
        while let Ok(frame) = inj_rx.try_recv() {
            let _ = handle.inject(&frame);
        }
        match handle.next_packet() {
            Ok(Some(pkt)) => {
                if !filter.matches_raw(&pkt.data) {
                    continue;
                }
                let kl = keylog.as_ref().as_ref();
                let d = crate::dissect::dissect(&pkt.data, pkt.link_type, kl);
                let rec = PacketRecord {
                    id: 0,
                    at: std::time::Instant::now(),
                    wall: pkt.wall,
                    interface: pkt.interface.clone(),
                    link_type: pkt.link_type,
                    orig_len: pkt.orig_len,
                    data: pkt.data,
                    summary: d.summary,
                    flags: d.flags,
                    expert: d.expert,
                    tree: Some(d.tree),
                    decrypted: d.decrypted,
                    fields: d.fields,
                };
                if tx.send(rec).is_err() {
                    break;
                }
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(50));
            }
        }
        let _ = (&iface, link);
    }
}
