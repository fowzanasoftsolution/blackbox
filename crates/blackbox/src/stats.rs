//! Latency recording + percentile reporting for the Phase 1 benchmarks.

/// Single-threaded latency sampler (nanoseconds).
pub struct Latency {
    samples: Vec<u64>,
}

impl Latency {
    pub fn new() -> Self {
        Latency { samples: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Latency { samples: Vec::with_capacity(cap) }
    }

    #[inline]
    pub fn push(&mut self, ns: u64) {
        self.samples.push(ns);
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Borrow the raw samples (ns) for merging across tasks.
    pub fn samples(&self) -> &[u64] {
        &self.samples
    }

    pub fn percentile(&self, p: f64) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    pub fn mean(&self) -> u64 {
        if self.samples.is_empty() {
            0
        } else {
            self.samples.iter().sum::<u64>() / self.samples.len() as u64
        }
    }

    pub fn max(&self) -> u64 {
        self.samples.iter().copied().max().unwrap_or(0)
    }

    /// Human string: `p50=1.2ms p99=3.4ms p999=5.6ms max=9.9ms mean=1.5ms`.
    pub fn summary(&self) -> String {
        format!(
            "p50={} p99={} p999={} max={} mean={}",
            fmt_ns(self.percentile(50.0)),
            fmt_ns(self.percentile(99.0)),
            fmt_ns(self.percentile(99.9)),
            fmt_ns(self.max()),
            fmt_ns(self.mean()),
        )
    }
}

impl Default for Latency {
    fn default() -> Self {
        Self::new()
    }
}

/// Format nanoseconds for humans (µs below 1 ms, ms below 1 s, else s).
pub fn fmt_ns(ns: u64) -> String {
    if ns < 1_000 {
        format!("{ns}ns")
    } else if ns < 1_000_000 {
        format!("{:.2}µs", ns as f64 / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.2}ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:.2}s", ns as f64 / 1_000_000_000.0)
    }
}

/// Format bytes/sec for humans.
pub fn fmt_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1}GB/s", bytes_per_sec / (1024.0 * 1024.0 * 1024.0))
    } else if bytes_per_sec >= 1024.0 * 1024.0 {
        format!("{:.1}MB/s", bytes_per_sec / (1024.0 * 1024.0))
    } else if bytes_per_sec >= 1024.0 {
        format!("{:.1}KB/s", bytes_per_sec / 1024.0)
    } else {
        format!("{bytes_per_sec:.0}B/s")
    }
}

/// Format byte counts for humans.
pub fn fmt_bytes(b: u64) -> String {
    fmt_rate(b as f64).replace("/s", "")
}

/// Format op/frame rates for humans (K/M suffix, no "B" confusion).
pub fn fmt_ops(per_sec: f64) -> String {
    if per_sec >= 1_000_000.0 {
        format!("{:.2}M/s", per_sec / 1_000_000.0)
    } else if per_sec >= 1_000.0 {
        format!("{:.1}K/s", per_sec / 1_000.0)
    } else {
        format!("{:.0}/s", per_sec)
    }
}
