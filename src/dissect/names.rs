//! Name resolution: reverse DNS, ports, MAC OUI.

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::dissect::geoip::GeoDb;

#[derive(Debug)]
pub struct NameResolver {
    pub enabled: bool,
    reverse: Arc<Mutex<HashMap<IpAddr, String>>>,
    ports: HashMap<u16, String>,
    oui: HashMap<[u8; 3], String>,
    pub geo: GeoDb,
}

impl Default for NameResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl NameResolver {
    pub fn new() -> Self {
        let mut n = Self {
            enabled: false,
            reverse: Arc::new(Mutex::new(HashMap::new())),
            ports: builtin_ports(),
            oui: builtin_oui(),
            geo: GeoDb::open_default(),
        };
        n.load_services();
        n.load_manuf();
        n
    }

    fn load_services(&mut self) {
        #[cfg(unix)]
        {
            if let Ok(text) = fs::read_to_string("/etc/services") {
                for line in text.lines() {
                    let line = line.split('#').next().unwrap_or("").trim();
                    if line.is_empty() {
                        continue;
                    }
                    let parts: Vec<_> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Some((port, _)) = parts[1].split_once('/') {
                            if let Ok(p) = port.parse::<u16>() {
                                self.ports.entry(p).or_insert_with(|| parts[0].to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    fn load_manuf(&mut self) {
        let path = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("bitbeak")
            .join("manuf");
        if let Ok(text) = fs::read_to_string(path) {
            for line in text.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                let mut parts = line.split_whitespace();
                if let (Some(mac), Some(name)) = (parts.next(), parts.next()) {
                    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                    if hex.len() >= 6 {
                        if let (Ok(a), Ok(b), Ok(c)) = (
                            u8::from_str_radix(&hex[0..2], 16),
                            u8::from_str_radix(&hex[2..4], 16),
                            u8::from_str_radix(&hex[4..6], 16),
                        ) {
                            self.oui.insert([a, b, c], name.to_string());
                        }
                    }
                }
            }
        }
    }

    pub fn oui_count(&self) -> usize {
        self.oui.len()
    }

    pub fn reload_manuf(&mut self) -> usize {
        self.load_manuf();
        self.oui.len()
    }

    pub fn port_name(&self, port: u16) -> Option<&str> {
        self.ports.get(&port).map(|s| s.as_str())
    }

    pub fn oui_vendor(&self, mac: &[u8]) -> Option<&str> {
        if mac.len() < 3 {
            return None;
        }
        self.oui.get(&[mac[0], mac[1], mac[2]]).map(|s| s.as_str())
    }

    pub fn cached_reverse(&self, ip: IpAddr) -> Option<String> {
        self.reverse.lock().ok()?.get(&ip).cloned()
    }

    /// Spawn a non-blocking reverse lookup (best-effort).
    pub fn request_reverse(&self, ip: IpAddr) {
        if !self.enabled {
            return;
        }
        let cache = Arc::clone(&self.reverse);
        std::thread::spawn(move || {
            if let Ok(guard) = cache.lock() {
                if guard.contains_key(&ip) {
                    return;
                }
            }
            let name = dns_lookup_host(ip);
            if let Ok(mut guard) = cache.lock() {
                if let Some(n) = name {
                    guard.insert(ip, n);
                }
            }
        });
    }

    pub fn geo_status(&self) -> String {
        self.geo.geo_status()
    }

    pub fn format_addr(&self, addr: &str) -> String {
        if let Some(mac) = parse_mac_addr(addr) {
            if let Some(vendor) = self.oui_vendor(&mac) {
                return format!("{addr} ({vendor})");
            }
            return addr.to_string();
        }

        let host = addr
            .rsplit_once(':')
            .map(|(h, p)| {
                if p.parse::<u16>().is_ok() && !h.contains(':') {
                    h
                } else {
                    addr
                }
            })
            .unwrap_or(addr);
        let ip = host.parse::<IpAddr>().ok();
        let geo_suffix = ip
            .and_then(|ip| self.geo.lookup(ip))
            .map(|g| format!(" ({g})"))
            .unwrap_or_default();

        if !self.enabled {
            if geo_suffix.is_empty() {
                return addr.to_string();
            }
            return format!("{addr}{geo_suffix}");
        }

        if let Some(ip) = ip {
            self.request_reverse(ip);
            if let Some(n) = self.cached_reverse(ip) {
                let base = if let Some((_, port)) = addr.rsplit_once(':') {
                    if port.parse::<u16>().is_ok() {
                        format!("{n}:{port}")
                    } else {
                        n
                    }
                } else {
                    n
                };
                return format!("{base}{geo_suffix}");
            }
        }
        if geo_suffix.is_empty() {
            addr.to_string()
        } else {
            format!("{addr}{geo_suffix}")
        }
    }
}

fn parse_mac_addr(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return None;
        }
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

fn dns_lookup_host(ip: IpAddr) -> Option<String> {
    #[cfg(unix)]
    {
        if let Some(name) = reverse_getnameinfo(ip) {
            return Some(name);
        }
    }
    reverse_hickory(ip)
}

#[cfg(unix)]
fn reverse_getnameinfo(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;
    use std::mem;
    use std::os::raw::c_char;

    let mut host = [0u8; 256];
    let rc = unsafe {
        match ip {
            IpAddr::V4(v4) => {
                let mut sa: libc::sockaddr_in = mem::zeroed();
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_addr.s_addr = u32::from(v4).to_be();
                libc::getnameinfo(
                    &sa as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr() as *mut c_char,
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                )
            }
            IpAddr::V6(v6) => {
                let mut sa: libc::sockaddr_in6 = mem::zeroed();
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_addr.s6_addr = v6.octets();
                libc::getnameinfo(
                    &sa as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr() as *mut c_char,
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                )
            }
        }
    };
    if rc != 0 {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(host.as_ptr() as *const c_char) };
    let s = cstr.to_string_lossy().into_owned();
    if s.is_empty() || s == ip.to_string() {
        None
    } else {
        Some(s)
    }
}

fn reverse_hickory(ip: IpAddr) -> Option<String> {
    use hickory_resolver::config::{LookupIpStrategy, ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(async {
        let mut opts = ResolverOpts::default();
        opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);
        let name = resolver.reverse_lookup(ip).await.ok()?;
        let host = name.iter().next()?.to_utf8();
        if host.is_empty() || host == ip.to_string() {
            None
        } else {
            Some(host)
        }
    })
}

fn builtin_ports() -> HashMap<u16, String> {
    [
        (20, "ftp-data"),
        (21, "ftp"),
        (22, "ssh"),
        (23, "telnet"),
        (25, "smtp"),
        (53, "domain"),
        (67, "bootps"),
        (68, "bootpc"),
        (80, "http"),
        (110, "pop3"),
        (123, "ntp"),
        (143, "imap"),
        (443, "https"),
        (445, "microsoft-ds"),
        (993, "imaps"),
        (995, "pop3s"),
        (3306, "mysql"),
        (5353, "mdns"),
        (5355, "llmnr"),
        (8080, "http-alt"),
    ]
    .into_iter()
    .map(|(p, n)| (p, n.to_string()))
    .collect()
}

fn builtin_oui() -> HashMap<[u8; 3], String> {
    [
        ([0x00, 0x00, 0x0c], "Cisco"),
        ([0x00, 0x01, 0x42], "Cisco"),
        ([0x00, 0x0c, 0x29], "VMware"),
        ([0x00, 0x1a, 0x2b], "Ayecom"),
        ([0x00, 0x1b, 0x21], "Intel"),
        ([0x00, 0x12, 0xfb], "Samsung"),
        ([0x00, 0x14, 0x22], "Dell"),
        ([0x00, 0x1e, 0xbd], "Cisco"),
        ([0x00, 0x25, 0x00], "Apple"),
        ([0x00, 0x50, 0x56], "VMware"),
        ([0x00, 0xe0, 0xfc], "Huawei"),
        ([0x08, 0x00, 0x27], "PCS Systemtechnik (VirtualBox)"),
        ([0x14, 0xcf, 0x92], "TP-Link"),
        ([0x3c, 0x5a, 0xb4], "Google"),
        ([0x52, 0x54, 0x00], "QEMU/KVM"),
        ([0x94, 0xeb, 0x2c], "Google"),
        ([0xb8, 0x27, 0xeb], "Raspberry Pi"),
        ([0xdc, 0xa6, 0x32], "Raspberry Pi"),
        ([0xe4, 0x5f, 0x01], "Raspberry Pi"),
        ([0xf0, 0x18, 0x98], "Apple"),
        ([0xf4, 0xf5, 0xe8], "Google"),
        ([0xf8, 0xff, 0xc2], "Apple"),
        ([0xac, 0xde, 0x48], "Private"),
    ]
    .into_iter()
    .map(|(o, n)| (o, n.to_string()))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manuf_parse_line() {
        let mut n = NameResolver::new();
        let before = n.oui_count();
        assert!(before >= 8);
        n.oui.insert([0xaa, 0xbb, 0xcc], "TestVendor".into());
        assert_eq!(
            n.oui_vendor(&[0xaa, 0xbb, 0xcc, 0, 0, 0]),
            Some("TestVendor")
        );
    }

    #[test]
    fn format_addr_mac_vendor() {
        let n = NameResolver::new();
        let out = n.format_addr("f0:18:98:00:00:01");
        assert!(out.contains("Apple"), "{out}");
    }
}
