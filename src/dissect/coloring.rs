//! Packet list coloring rules (Envoke 256-color indices).

use ratatui::style::{Color, Style};

use crate::dissect::expert::ExpertSeverity;
use crate::dissect::packet::PacketRecord;

#[derive(Debug, Clone)]
pub struct ColorRule {
    pub name: &'static str,
    pub style: Style,
}

pub fn color_for_packet(pkt: &PacketRecord) -> Style {
    // Expert errors first
    if pkt
        .expert
        .iter()
        .any(|e| e.severity == ExpertSeverity::Error)
    {
        return Style::default().fg(Color::Indexed(196)); // red
    }
    if pkt
        .expert
        .iter()
        .any(|e| e.severity == ExpertSeverity::Warn)
    {
        return Style::default().fg(Color::Indexed(214)); // orange
    }
    if pkt.flags.dns || pkt.flags.mdns || pkt.flags.llmnr {
        return Style::default().fg(Color::Indexed(81)); // cyan
    }
    if pkt.flags.http2 {
        return Style::default().fg(Color::Indexed(141)); // purple
    }
    if pkt.flags.http {
        return Style::default().fg(Color::Indexed(114)); // green
    }
    if pkt.flags.tls {
        return Style::default().fg(Color::Indexed(176)); // pink
    }
    if pkt.flags.tcp {
        let info = pkt.summary.info.as_str();
        if info.contains("SYN") && !info.contains("ACK") {
            return Style::default().fg(Color::Indexed(228)); // yellow
        }
        return Style::default().fg(Color::Indexed(252));
    }
    if pkt.flags.udp {
        return Style::default().fg(Color::Indexed(117));
    }
    if pkt.flags.arp {
        return Style::default().fg(Color::Indexed(180));
    }
    Style::default().fg(Color::Indexed(250))
}

pub fn builtin_rules() -> Vec<ColorRule> {
    vec![
        ColorRule {
            name: "Expert Error",
            style: Style::default().fg(Color::Indexed(196)),
        },
        ColorRule {
            name: "DNS",
            style: Style::default().fg(Color::Indexed(81)),
        },
        ColorRule {
            name: "HTTP",
            style: Style::default().fg(Color::Indexed(114)),
        },
        ColorRule {
            name: "HTTP/2",
            style: Style::default().fg(Color::Indexed(141)),
        },
        ColorRule {
            name: "TLS",
            style: Style::default().fg(Color::Indexed(176)),
        },
        ColorRule {
            name: "TCP SYN",
            style: Style::default().fg(Color::Indexed(228)),
        },
    ]
}
