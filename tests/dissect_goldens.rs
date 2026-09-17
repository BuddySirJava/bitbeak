//! On-disk packet golden fixtures for dissect.

use std::path::PathBuf;

use bitbeak::dissect::dissect;
use bitbeak::dissect::packet::LinkType;

fn fixture(name: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/packets");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn golden_eth_tcp_syn() {
    let pkt = fixture("eth_ipv4_tcp_syn.bin");
    let d = dissect(&pkt, LinkType::Ethernet, None);
    assert!(d.flags.ethernet && d.flags.ipv4 && d.flags.tcp);
}

#[test]
fn golden_eth_udp_dns() {
    let pkt = fixture("eth_ipv4_udp_dns.bin");
    let d = dissect(&pkt, LinkType::Ethernet, None);
    assert!(d.flags.udp && d.flags.dns);
}

#[test]
fn golden_eth_udp_sip() {
    let pkt = fixture("eth_ipv4_udp_sip.bin");
    let d = dissect(&pkt, LinkType::Ethernet, None);
    assert!(d.flags.udp && d.flags.sip);
    assert_eq!(d.summary.protocol, "SIP");
}

#[test]
fn golden_radiotap_beacon() {
    let pkt = fixture("radiotap_beacon.bin");
    let d = dissect(&pkt, LinkType::Ieee80211Radio, None);
    assert!(d.flags.wifi || d.summary.info.contains("SSID") || d.summary.protocol.contains("802"));
}
