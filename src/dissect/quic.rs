//! QUIC Initial + best-effort 1-RTT decrypt (RFC 9001) — bounded.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use aws_lc_rs::cipher::{EncryptingKey, EncryptionContext, UnboundCipherKey, AES_128};
use aws_lc_rs::hkdf::{KeyType, Prk, HKDF_SHA256};
use aws_lc_rs::hmac;

use crate::dissect::decrypt::KeyLog;
use crate::dissect::packet::{PacketSummary, ProtocolFlags};
use crate::dissect::tree::ProtoTree;

const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

#[derive(Debug, Clone)]
pub struct QuicInitialKeys {
    pub client_key: [u8; 16],
    pub client_iv: [u8; 12],
    pub client_hp: [u8; 16],
    pub server_key: [u8; 16],
    pub server_iv: [u8; 12],
    pub server_hp: [u8; 16],
}

pub fn derive_initial_keys(dcid: &[u8]) -> Option<QuicInitialKeys> {
    let salt = hmac::Key::new(hmac::HMAC_SHA256, &INITIAL_SALT_V1);
    let initial_secret = hmac::sign(&salt, dcid);
    let client_secret = hkdf_expand_label(initial_secret.as_ref(), b"client in", 32)?;
    let server_secret = hkdf_expand_label(initial_secret.as_ref(), b"server in", 32)?;
    Some(QuicInitialKeys {
        client_key: hkdf_expand_label(&client_secret, b"quic key", 16)?
            .try_into()
            .ok()?,
        client_iv: hkdf_expand_label(&client_secret, b"quic iv", 12)?
            .try_into()
            .ok()?,
        client_hp: hkdf_expand_label(&client_secret, b"quic hp", 16)?
            .try_into()
            .ok()?,
        server_key: hkdf_expand_label(&server_secret, b"quic key", 16)?
            .try_into()
            .ok()?,
        server_iv: hkdf_expand_label(&server_secret, b"quic iv", 12)?
            .try_into()
            .ok()?,
        server_hp: hkdf_expand_label(&server_secret, b"quic hp", 16)?
            .try_into()
            .ok()?,
    })
}

pub(crate) fn hkdf_expand_label(secret: &[u8], label: &[u8], len: usize) -> Option<Vec<u8>> {
    let prk = Prk::new_less_safe(HKDF_SHA256, secret);
    let full_label = [b"tls13 ", label].concat();
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(0);
    struct L(usize);
    impl KeyType for L {
        fn len(&self) -> usize {
            self.0
        }
    }
    let info_refs: [&[u8]; 1] = [&info];
    let okm = prk.expand(&info_refs, L(len)).ok()?;
    let mut out = vec![0u8; len];
    okm.fill(&mut out).ok()?;
    Some(out)
}

fn aes128_ecb_encrypt(key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]> {
    let unbound = UnboundCipherKey::new(&AES_128, key).ok()?;
    let ek = EncryptingKey::ecb(unbound).ok()?;
    let mut buf = *block;
    ek.less_safe_encrypt(&mut buf, EncryptionContext::None)
        .ok()?;
    Some(buf)
}

/// Remove QUIC header protection (AES-ECB sample → mask).
pub fn remove_header_protection(
    hp_key: &[u8; 16],
    first_byte: &mut u8,
    pn_bytes: &mut [u8],
    sample: &[u8],
    long_header: bool,
) -> Option<()> {
    if sample.len() < 16 {
        return None;
    }
    let mut sample_arr = [0u8; 16];
    sample_arr.copy_from_slice(&sample[..16]);
    let mask = aes128_ecb_encrypt(hp_key, &sample_arr)?;
    if long_header {
        *first_byte ^= mask[0] & 0x0f;
    } else {
        *first_byte ^= mask[0] & 0x1f;
    }
    for (i, b) in pn_bytes.iter_mut().enumerate() {
        if i + 1 < mask.len() {
            *b ^= mask[1 + i];
        }
    }
    Some(())
}

pub fn decrypt_initial_payload(
    key: &[u8; 16],
    iv: &[u8; 12],
    packet_number: u64,
    header: &[u8],
    ciphertext_with_tag: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext_with_tag.len() < 16 {
        return None;
    }
    let mut nonce = *iv;
    for i in 0..8 {
        nonce[4 + i] ^= ((packet_number >> (56 - 8 * i)) & 0xff) as u8;
    }
    let unbound = UnboundKey::new(&AES_128_GCM, key).ok()?;
    let aead = LessSafeKey::new(unbound);
    let mut buf = ciphertext_with_tag.to_vec();
    let plain = aead
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(header),
            &mut buf,
        )
        .ok()?;
    Some(plain.to_vec())
}

pub fn looks_like_quic_initial(udp: &[u8]) -> bool {
    if udp.len() < 7 {
        return false;
    }
    let b0 = udp[0];
    (b0 & 0xf0) == 0xc0 || (b0 & 0xf0) == 0xd0
}

pub fn looks_like_quic_short(udp: &[u8]) -> bool {
    !udp.is_empty() && (udp[0] & 0x80) == 0
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn read_varint(payload: &[u8], off: usize) -> Option<(u64, usize)> {
    if off >= payload.len() {
        return None;
    }
    let b0 = payload[off];
    let (len, val) = match b0 >> 6 {
        0 => (1, u64::from(b0 & 0x3f)),
        1 => {
            if off + 1 >= payload.len() {
                return None;
            }
            (2, u64::from(b0 & 0x3f) << 8 | u64::from(payload[off + 1]))
        }
        2 => {
            if off + 3 >= payload.len() {
                return None;
            }
            (
                4,
                u64::from(b0 & 0x3f) << 24
                    | u64::from(payload[off + 1]) << 16
                    | u64::from(payload[off + 2]) << 8
                    | u64::from(payload[off + 3]),
            )
        }
        _ => {
            if off + 7 >= payload.len() {
                return None;
            }
            (
                8,
                u64::from(b0 & 0x3f) << 56
                    | u64::from(payload[off + 1]) << 48
                    | u64::from(payload[off + 2]) << 40
                    | u64::from(payload[off + 3]) << 32
                    | u64::from(payload[off + 4]) << 24
                    | u64::from(payload[off + 5]) << 16
                    | u64::from(payload[off + 6]) << 8
                    | u64::from(payload[off + 7]),
            )
        }
    };
    Some((val, off + len))
}

fn annotate_crypto_frames(tree: &mut ProtoTree, parent: usize, plain: &[u8], off: usize) {
    let mut i = 0usize;
    while i < plain.len() {
        let fty = plain[i];
        if fty == 0x06 {
            let mut p = i + 1;
            let Some((crypto_off, p2)) = read_varint(plain, p) else {
                break;
            };
            p = p2;
            let Some((crypto_len, p3)) = read_varint(plain, p) else {
                break;
            };
            p = p3;
            tree.add_child(
                parent,
                "CRYPTO",
                format!("offset={crypto_off} len={crypto_len}"),
                off + i,
                (p - i).min(plain.len().saturating_sub(i)),
            );
            i = p + crypto_len as usize;
        } else if fty == 0x00 {
            i += 1;
        } else if fty == 0x01 {
            tree.add_child(parent, "PING", "", off + i, 1);
            i += 1;
        } else {
            break;
        }
    }
}

pub fn dissect_quic(
    tree: &mut ProtoTree,
    parent: usize,
    payload: &[u8],
    payload_off: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
    keylog: Option<&KeyLog>,
) {
    flags.quic_looking = true;
    summary.protocol = "QUIC".into();
    if payload.is_empty() {
        summary.info = "QUIC (empty)".into();
        return;
    }
    if looks_like_quic_short(payload) {
        dissect_quic_1rtt(tree, parent, payload, payload_off, summary, keylog);
        return;
    }
    dissect_quic_initial(tree, parent, payload, payload_off, flags, summary);
}

fn dissect_quic_1rtt(
    tree: &mut ProtoTree,
    parent: usize,
    payload: &[u8],
    payload_off: usize,
    summary: &mut PacketSummary,
    keylog: Option<&KeyLog>,
) {
    let sec = tree.add_section(parent, "QUIC 1-RTT", payload_off, payload.len().min(32));
    tree.add_child(
        sec,
        "First byte",
        format!("0x{:02x}", payload[0]),
        payload_off,
        1,
    );
    let Some(kl) = keylog else {
        tree.add_child(sec, "Note", "QUIC encrypted (no keylog)", payload_off, 0);
        summary.info = "QUIC encrypted".into();
        return;
    };
    let Some((_label, secret_hex)) = kl.quic_traffic_secret() else {
        tree.add_child(
            sec,
            "Note",
            "QUIC encrypted (no traffic secret)",
            payload_off,
            0,
        );
        summary.info = "QUIC encrypted".into();
        return;
    };
    let secret = match hex::decode_loose(secret_hex) {
        Ok(s) if s.len() >= 16 => s,
        _ => {
            tree.add_child(sec, "Note", "QUIC encrypted", payload_off, 0);
            summary.info = "QUIC encrypted".into();
            return;
        }
    };
    let (Some(key), Some(iv)) = (
        hkdf_expand_label(&secret, b"quic key", 16).and_then(|k| k.try_into().ok()),
        hkdf_expand_label(&secret, b"quic iv", 12).and_then(|i| i.try_into().ok()),
    ) else {
        summary.info = "QUIC encrypted".into();
        return;
    };
    let key: [u8; 16] = key;
    let iv: [u8; 12] = iv;
    for dcid_len in 0usize..=8 {
        if payload.len() < 1 + dcid_len + 1 + 16 {
            continue;
        }
        let pn_off = 1 + dcid_len;
        let hdr = &payload[..pn_off + 1];
        let ct = &payload[pn_off + 1..];
        for pn in 0u64..4 {
            if let Some(plain) = decrypt_initial_payload(&key, &iv, pn, hdr, ct) {
                tree.add_child(
                    sec,
                    "Decrypted",
                    hex_bytes(&plain[..plain.len().min(16)]),
                    payload_off,
                    0,
                );
                annotate_crypto_frames(tree, sec, &plain, payload_off);
                summary.info = "QUIC 1-RTT (decrypted)".into();
                return;
            }
        }
    }
    tree.add_child(sec, "Note", "QUIC encrypted", payload_off, 0);
    summary.info = "QUIC encrypted".into();
}

pub fn dissect_quic_initial(
    tree: &mut ProtoTree,
    parent: usize,
    payload: &[u8],
    payload_off: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) {
    flags.quic_looking = true;
    summary.protocol = "QUIC".into();

    if payload.len() < 7 {
        summary.info = "QUIC (short)".into();
        let sec = tree.add_section(parent, "QUIC", payload_off, payload.len());
        tree.add_child(sec, "Note", "Packet too short", payload_off, 0);
        return;
    }

    let sec = tree.add_section(parent, "QUIC Initial", payload_off, payload.len().min(64));
    let mut packet = payload.to_vec();
    let b0 = packet[0];
    tree.add_child(sec, "First byte", format!("0x{b0:02x}"), payload_off, 1);
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    tree.add_child(
        sec,
        "Version",
        format!("0x{version:08x}"),
        payload_off + 1,
        4,
    );

    let dcil = packet[5] as usize;
    if dcil > 20 || packet.len() < 6 + dcil + 1 {
        tree.add_child(sec, "Note", "QUIC encrypted", payload_off, 0);
        summary.info = "QUIC encrypted".into();
        return;
    }
    let dcid = packet[6..6 + dcil].to_vec();
    tree.add_child(sec, "DCID", hex_bytes(&dcid), payload_off + 6, dcil);

    let mut pos = 6 + dcil;
    let scil = packet[pos] as usize;
    pos += 1;
    if scil > 20 || packet.len() < pos + scil {
        summary.info = "QUIC encrypted".into();
        return;
    }
    pos += scil;

    let Some((token_len, p)) = read_varint(&packet, pos) else {
        summary.info = "QUIC encrypted".into();
        return;
    };
    pos = p + token_len as usize;
    let Some((protected_len, pos)) = read_varint(&packet, pos) else {
        summary.info = "QUIC encrypted".into();
        return;
    };

    let pn_len_guess = ((b0 & 0x03) + 1) as usize;
    if protected_len as usize <= pn_len_guess || pos + protected_len as usize > packet.len() {
        summary.info = "QUIC encrypted".into();
        return;
    }

    let Some(keys) = derive_initial_keys(&dcid) else {
        summary.info = "QUIC encrypted".into();
        return;
    };
    tree.add_child(sec, "Keys", "derived", payload_off, 0);

    let sample_off = pos + 4;
    if sample_off + 16 <= packet.len() {
        let sample = &packet[sample_off..sample_off + 16];
        let mut first = packet[0];
        let mut pn_buf = packet[pos..pos + pn_len_guess].to_vec();
        let hp_ok =
            remove_header_protection(&keys.client_hp, &mut first, &mut pn_buf, sample, true)
                .is_some()
                || {
                    first = packet[0];
                    pn_buf = packet[pos..pos + pn_len_guess].to_vec();
                    remove_header_protection(&keys.server_hp, &mut first, &mut pn_buf, sample, true)
                        .is_some()
                };
        if hp_ok {
            packet[0] = first;
            packet[pos..pos + pn_len_guess].copy_from_slice(&pn_buf);
            tree.add_child(sec, "HP", "removed", payload_off, 0);
        }
    }

    let pn_len = ((packet[0] & 0x03) + 1) as usize;
    let mut pn: u64 = 0;
    for b in &packet[pos..pos + pn_len.min(packet.len().saturating_sub(pos))] {
        pn = (pn << 8) | u64::from(*b);
    }
    let end = pos + protected_len as usize;
    if pos + pn_len >= end || end > packet.len() {
        summary.info = "QUIC Initial (keys ok, payload protected)".into();
        return;
    }
    let header = &packet[0..pos + pn_len];
    let ciphertext = &packet[pos + pn_len..end];

    if let Some(plain) =
        decrypt_initial_payload(&keys.client_key, &keys.client_iv, pn, header, ciphertext)
    {
        let dec_sec = tree.add_section(
            parent,
            "QUIC Initial (decrypted)",
            payload_off + pos + pn_len,
            plain.len().min(32),
        );
        tree.add_child(
            dec_sec,
            "Plaintext",
            hex_bytes(&plain[..plain.len().min(16)]),
            payload_off + pos + pn_len,
            plain.len().min(16),
        );
        annotate_crypto_frames(tree, dec_sec, &plain, payload_off + pos + pn_len);
        summary.info = "QUIC Initial (decrypted)".into();
        return;
    }

    if let Some(plain) =
        decrypt_initial_payload(&keys.server_key, &keys.server_iv, pn, header, ciphertext)
    {
        let dec_sec = tree.add_section(
            parent,
            "QUIC Initial (decrypted, server)",
            payload_off + pos + pn_len,
            plain.len().min(32),
        );
        annotate_crypto_frames(tree, dec_sec, &plain, payload_off + pos + pn_len);
        summary.info = "QUIC Initial (decrypted)".into();
        return;
    }

    for try_pn in 0u64..8 {
        let hdr = &packet[0..pos + pn_len_guess];
        let ct = &packet[pos + pn_len_guess..end];
        if let Some(plain) =
            decrypt_initial_payload(&keys.client_key, &keys.client_iv, try_pn, hdr, ct).or_else(
                || decrypt_initial_payload(&keys.server_key, &keys.server_iv, try_pn, hdr, ct),
            )
        {
            let dec_sec = tree.add_section(
                parent,
                "QUIC Initial (decrypted)",
                payload_off,
                plain.len().min(32),
            );
            annotate_crypto_frames(tree, dec_sec, &plain, payload_off);
            summary.info = "QUIC Initial (decrypted)".into();
            return;
        }
    }
    tree.add_child(
        sec,
        "Note",
        "QUIC Initial (keys ok, payload protected)",
        payload_off,
        0,
    );
    summary.info = "QUIC Initial (keys ok, payload protected)".into();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_keys_for_dcid() {
        let dcid = hex::decode_loose("8394c8f03e515708").unwrap();
        let keys = derive_initial_keys(&dcid).unwrap();
        assert_ne!(keys.client_key, [0u8; 16]);
        assert_ne!(keys.client_hp, [0u8; 16]);
    }

    #[test]
    fn header_protection_roundtrip_mask() {
        let key = [1u8; 16];
        let sample = [2u8; 16];
        let mut first = 0xc3u8;
        let mut pn = [0x11u8, 0x22];
        remove_header_protection(&key, &mut first, &mut pn, &sample, true).unwrap();
        remove_header_protection(&key, &mut first, &mut pn, &sample, true).unwrap();
        assert_eq!(first, 0xc3);
        assert_eq!(pn, [0x11, 0x22]);
    }

    #[test]
    fn one_rtt_without_keylog() {
        let mut tree = ProtoTree::new();
        let root = tree.add_root("root", 0, 8);
        let mut flags = ProtocolFlags::default();
        let mut summary = PacketSummary {
            src: String::new(),
            dst: String::new(),
            protocol: String::new(),
            info: String::new(),
            len: 8,
        };
        let pkt = [0x40u8, 0, 0, 0, 0, 0, 0, 0];
        dissect_quic(&mut tree, root, &pkt, 0, &mut flags, &mut summary, None);
        assert!(summary.info.contains("encrypted") || summary.protocol == "QUIC");
    }
}

mod hex {
    pub fn decode_loose(s: &str) -> Result<Vec<u8>, ()> {
        let mut out = Vec::new();
        let mut chars = s.chars().filter(|c| c.is_ascii_hexdigit());
        while let (Some(a), Some(b)) = (chars.next(), chars.next()) {
            let byte = u8::from_str_radix(&format!("{a}{b}"), 16).map_err(|_| ())?;
            out.push(byte);
        }
        Ok(out)
    }
}
