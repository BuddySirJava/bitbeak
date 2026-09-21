//! Local-debug TLS MITM CA and leaf certificate minting.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

use crate::collections::config_dir;

pub struct MitmCa {
    pub ca_pem_path: PathBuf,
    ca_cert_pem: String,
    ca_key: KeyPair,
    ca_cert: rcgen::Certificate,
}

impl MitmCa {
    pub fn ca_dir() -> PathBuf {
        config_dir().join("ca")
    }

    pub fn load_or_create() -> Result<Self> {
        let dir = Self::ca_dir();
        fs::create_dir_all(&dir).context("create ca dir")?;
        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca.key.pem");
        if cert_path.exists() && key_path.exists() {
            let ca_cert_pem = fs::read_to_string(&cert_path).context("read ca.pem")?;
            let key_pem = fs::read_to_string(&key_path).context("read ca.key.pem")?;
            let ca_key = KeyPair::from_pem(&key_pem).context("parse ca key")?;
            let params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)
                .context("parse ca cert params")?;
            let ca_cert = params.self_signed(&ca_key).context("rebuild ca cert")?;
            return Ok(Self {
                ca_pem_path: cert_path,
                ca_cert_pem,
                ca_key,
                ca_cert,
            });
        }

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "BitBeak Local Debug CA");
        dn.push(DnType::OrganizationName, "BitBeak");
        params.distinguished_name = dn;
        let ca_key = KeyPair::generate().context("generate ca key")?;
        let ca_cert = params.self_signed(&ca_key).context("self-sign ca")?;
        let ca_cert_pem = ca_cert.pem();
        let key_pem = ca_key.serialize_pem();
        fs::write(&cert_path, &ca_cert_pem).context("write ca.pem")?;
        fs::write(&key_path, &key_pem).context("write ca.key.pem")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            ca_pem_path: cert_path,
            ca_cert_pem,
            ca_key,
            ca_cert,
        })
    }

    pub fn mint_server_config(&self, hostname: &str) -> Result<Arc<ServerConfig>> {
        let mut params =
            CertificateParams::new(vec![hostname.to_string()]).context("leaf cert params")?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        params.distinguished_name = dn;
        let leaf_key = KeyPair::generate().context("leaf key")?;
        let leaf = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .context("sign leaf")?;

        let cert_der = CertificateDer::from(leaf.der().as_ref().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let ca_der = CertificateDer::from(self.ca_cert.der().as_ref().to_vec());

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der, ca_der], key_der)
            .context("server config")?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    pub fn ca_pem_path(&self) -> &Path {
        &self.ca_pem_path
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_cert_pem
    }
}

/// Extract SNI hostname from a TLS ClientHello record (bytes may include record header).
pub fn parse_sni_from_client_hello(data: &[u8]) -> Option<String> {
    let payload = if data.len() >= 5 && data[0] == 0x16 {
        let len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + len {
            return None;
        }
        &data[5..5 + len]
    } else {
        data
    };
    // HandshakeType client_hello (1) + length(3) + ...
    if payload.first().copied() != Some(0x01) || payload.len() < 38 {
        return None;
    }
    let mut i = 4; // skip type + length
    i += 2; // version
    i += 32; // random
    if i >= payload.len() {
        return None;
    }
    let session_len = payload[i] as usize;
    i += 1 + session_len;
    if i + 2 > payload.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
    i += 2 + cipher_len;
    if i >= payload.len() {
        return None;
    }
    let comp_len = payload[i] as usize;
    i += 1 + comp_len;
    if i + 2 > payload.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
    i += 2;
    let end = (i + ext_len).min(payload.len());
    while i + 4 <= end {
        let typ = u16::from_be_bytes([payload[i], payload[i + 1]]);
        let len = u16::from_be_bytes([payload[i + 2], payload[i + 3]]) as usize;
        i += 4;
        if i + len > end {
            break;
        }
        if typ == 0 {
            // server_name
            return parse_server_name_extension(&payload[i..i + len]);
        }
        i += len;
    }
    None
}

fn parse_server_name_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    let mut i = 2; // list length
    while i + 3 <= data.len() {
        let name_type = data[i];
        let name_len = u16::from_be_bytes([data[i + 1], data[i + 2]]) as usize;
        i += 3;
        if i + name_len > data.len() {
            break;
        }
        if name_type == 0 {
            return String::from_utf8(data[i..i + name_len].to_vec()).ok();
        }
        i += name_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_create_mints_leaf() {
        let ca = MitmCa::load_or_create().expect("ca");
        let cfg = ca.mint_server_config("localhost").expect("leaf");
        assert!(ca.ca_pem_path().exists());
        let _ = cfg;
    }

    #[test]
    fn parse_sni_from_fixture_like_hello() {
        // Minimal synthetic: record header + handshake with SNI "example.com"
        let host = b"example.com";
        let mut ext = Vec::new();
        let mut list = Vec::new();
        list.push(0u8); // host_name
        list.extend_from_slice(&(host.len() as u16).to_be_bytes());
        list.extend_from_slice(host);
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0u16.to_be_bytes()); // type server_name
        exts.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(0x01); // client_hello
        let body_len_pos = hs.len();
        hs.extend_from_slice(&[0, 0, 0]); // length placeholder
        hs.extend_from_slice(&[0x03, 0x03]); // version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session id len
        hs.extend_from_slice(&2u16.to_be_bytes()); // cipher len
        hs.extend_from_slice(&[0x00, 0x2f]);
        hs.push(1); // compression len
        hs.push(0);
        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);
        let body_len = hs.len() - 4;
        hs[body_len_pos] = ((body_len >> 16) & 0xff) as u8;
        hs[body_len_pos + 1] = ((body_len >> 8) & 0xff) as u8;
        hs[body_len_pos + 2] = (body_len & 0xff) as u8;

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        assert_eq!(
            parse_sni_from_client_hello(&rec).as_deref(),
            Some("example.com")
        );
    }
}
