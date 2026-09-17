//! GeoIP lookup via MaxMind GeoLite2-City (optional).

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use maxminddb::geoip2::City;
use maxminddb::Reader;

#[derive(Debug)]
pub struct GeoDb {
    reader: Option<Reader<Vec<u8>>>,
    path: PathBuf,
}

impl Default for GeoDb {
    fn default() -> Self {
        Self::open_default()
    }
}

impl GeoDb {
    pub fn open_default() -> Self {
        let path = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("bitbeak")
            .join("GeoLite2-City.mmdb");
        Self::open(&path)
    }

    pub fn open(path: &Path) -> Self {
        let reader = Reader::open_readfile(path).ok();
        Self {
            reader,
            path: path.to_path_buf(),
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.reader.is_some()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn geo_status(&self) -> String {
        if self.is_loaded() {
            format!("GeoIP loaded: {}", self.path.display())
        } else {
            format!(
                "GeoIP missing: {} (place GeoLite2-City.mmdb in ~/.config/bitbeak/)",
                self.path.display()
            )
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;
        let city: City = reader.lookup(ip).ok()?;
        let country = city
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .or_else(|| city.registered_country.as_ref().and_then(|c| c.iso_code))?;
        let place = city
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en").copied())
            .or_else(|| {
                city.subdivisions
                    .as_ref()
                    .and_then(|subs| subs.first())
                    .and_then(|s| s.names.as_ref())
                    .and_then(|n| n.get("en").copied())
            })?;
        Some(format!("{country}/{place}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_skip_if_missing_file() {
        let db = GeoDb::open_default();
        if !db.is_loaded() {
            return;
        }
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let loc = db.lookup(ip);
        assert!(loc.is_some(), "expected geo for 8.8.8.8 when db loaded");
    }
}
