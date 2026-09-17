//! Load / replay bench.

use std::time::{Duration, Instant};

use crate::http::{send_request, HttpRequestSpec};

#[derive(Debug, Clone)]
pub struct BenchConfig {
    pub count: u32,
    pub concurrency: u32,
    pub duration: Option<Duration>,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            count: 10,
            concurrency: 1,
            duration: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BenchResult {
    pub ok: u32,
    pub err: u32,
    pub bytes: u64,
    pub rtts_ms: Vec<u64>,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub elapsed_ms: u64,
}

impl BenchResult {
    pub fn finalize(&mut self) {
        self.rtts_ms.sort_unstable();
        self.p50 = percentile(&self.rtts_ms, 50);
        self.p95 = percentile(&self.rtts_ms, 95);
        self.p99 = percentile(&self.rtts_ms, 99);
    }

    pub fn sparkline(&self, width: usize) -> String {
        const BARS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        if self.rtts_ms.is_empty() || width == 0 {
            return String::new();
        }
        let max = self.rtts_ms.iter().copied().max().unwrap_or(1).max(1);
        let step = (self.rtts_ms.len() as f64 / width as f64).max(1.0);
        let mut out = String::new();
        for i in 0..width {
            let idx = ((i as f64) * step) as usize;
            let v = self.rtts_ms.get(idx).copied().unwrap_or(0);
            let bi = ((v as f64 / max as f64) * (BARS.len() - 1) as f64) as usize;
            out.push(BARS[bi.min(BARS.len() - 1)]);
        }
        out
    }
}

fn percentile(sorted: &[u64], p: u8) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p as f64 / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Bench an HTTP request spec sequentially (concurrency >1 uses join_set).
pub async fn bench_http(spec: &HttpRequestSpec, config: &BenchConfig) -> BenchResult {
    let start = Instant::now();
    let mut result = BenchResult::default();
    let conc = config.concurrency.max(1) as usize;
    let mut remaining = config.count;
    let deadline = config.duration.map(|d| start + d);

    while remaining > 0 {
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                break;
            }
        }
        let batch = remaining.min(conc as u32) as usize;
        let mut handles = Vec::new();
        for _ in 0..batch {
            let s = spec.clone();
            handles.push(tokio::spawn(async move {
                let t0 = Instant::now();
                let r = send_request(&s).await;
                (t0.elapsed().as_millis() as u64, r)
            }));
        }
        for h in handles {
            remaining = remaining.saturating_sub(1);
            match h.await {
                Ok((rtt, Ok(resp))) => {
                    result.ok += 1;
                    result.bytes += resp.body.len() as u64;
                    result.rtts_ms.push(rtt);
                }
                Ok((rtt, Err(_))) => {
                    result.err += 1;
                    result.rtts_ms.push(rtt);
                }
                Err(_) => result.err += 1,
            }
        }
    }
    result.elapsed_ms = start.elapsed().as_millis() as u64;
    result.finalize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles() {
        let mut r = BenchResult {
            rtts_ms: vec![10, 20, 30, 40, 50],
            ..Default::default()
        };
        r.finalize();
        assert_eq!(r.p50, 30);
    }
}
