//! Prometheus-style metric primitives: Counter, Gauge, Histogram.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc,
    },
};

use parking_lot::RwLock;

// Counter

#[derive(Clone)]
pub struct Counter {
    inner: Arc<CounterInner>,
}

struct CounterInner {
    name: String,
    value: AtomicU64,
}

impl Counter {
    fn new(name: &str) -> Self {
        Self {
            inner: Arc::new(CounterInner {
                name: name.to_owned(),
                value: AtomicU64::new(0),
            }),
        }
    }

    #[inline]
    pub fn inc(&self) { self.inner.value.fetch_add(1, Ordering::Relaxed); }

    #[inline]
    pub fn add(&self, n: u64) { self.inner.value.fetch_add(n, Ordering::Relaxed); }

    #[inline]
    pub fn get(&self) -> u64 { self.inner.value.load(Ordering::Relaxed) }

    pub(crate) fn name(&self) -> &str { &self.inner.name }
}

// Gauge

#[derive(Clone)]
pub struct Gauge {
    inner: Arc<GaugeInner>,
}

struct GaugeInner {
    name: String,
    millis: AtomicI64,
}

impl Gauge {
    fn new(name: &str) -> Self {
        Self {
            inner: Arc::new(GaugeInner {
                name: name.to_owned(),
                millis: AtomicI64::new(0),
            }),
        }
    }

    #[inline]
    pub fn set(&self, v: f64) {
        self.inner.millis.store((v * 1_000.0) as i64, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc(&self, delta: f64) {
        self.inner.millis.fetch_add((delta * 1_000.0) as i64, Ordering::Relaxed);
    }

    #[inline]
    pub fn dec(&self, delta: f64) {
        self.inner.millis.fetch_sub((delta * 1_000.0) as i64, Ordering::Relaxed);
    }

    #[inline]
    pub fn get(&self) -> f64 { self.inner.millis.load(Ordering::Relaxed) as f64 / 1_000.0 }

    pub(crate) fn name(&self) -> &str { &self.inner.name }
}

// Histogram

#[derive(Debug, Clone)]
pub struct HistogramSnapshot {
    pub count: u64,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
}

#[derive(Clone)]
pub struct Histogram {
    inner: Arc<HistogramInner>,
}

struct HistogramInner {
    name: String,
    count: AtomicU64,
    sum_millis: AtomicI64,
    min_millis: AtomicI64,
    max_millis: AtomicI64,
}

impl Histogram {
    fn new(name: &str) -> Self {
        Self {
            inner: Arc::new(HistogramInner {
                name: name.to_owned(),
                count: AtomicU64::new(0),
                sum_millis: AtomicI64::new(0),
                min_millis: AtomicI64::new(i64::MAX),
                max_millis: AtomicI64::new(i64::MIN),
            }),
        }
    }

    #[inline]
    pub fn observe(&self, value: f64) {
        let millis = (value * 1_000.0) as i64;
        self.inner.count.fetch_add(1, Ordering::Relaxed);
        self.inner.sum_millis.fetch_add(millis, Ordering::Relaxed);
        let mut cur = self.inner.min_millis.load(Ordering::Relaxed);
        while millis < cur {
            match self.inner.min_millis.compare_exchange_weak(cur, millis, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
        let mut cur = self.inner.max_millis.load(Ordering::Relaxed);
        while millis > cur {
            match self.inner.max_millis.compare_exchange_weak(cur, millis, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
    }

    pub fn snapshot(&self) -> HistogramSnapshot {
        let count = self.inner.count.load(Ordering::Relaxed);
        let sum = self.inner.sum_millis.load(Ordering::Relaxed) as f64 / 1_000.0;
        let min = if count == 0 { 0.0 } else { self.inner.min_millis.load(Ordering::Relaxed) as f64 / 1_000.0 };
        let max = if count == 0 { 0.0 } else { self.inner.max_millis.load(Ordering::Relaxed) as f64 / 1_000.0 };
        HistogramSnapshot { count, sum, min, max }
    }

    pub(crate) fn name(&self) -> &str { &self.inner.name }
}

// Registry

pub struct Registry {
    counters: RwLock<HashMap<String, Counter>>,
    gauges: RwLock<HashMap<String, Gauge>>,
    histograms: RwLock<HashMap<String, Histogram>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
        }
    }

    pub fn counter(&self, name: &str) -> Counter {
        { let r = self.counters.read(); if let Some(c) = r.get(name) { return c.clone(); } }
        let mut w = self.counters.write();
        w.entry(name.to_owned()).or_insert_with(|| Counter::new(name)).clone()
    }

    pub fn gauge(&self, name: &str) -> Gauge {
        { let r = self.gauges.read(); if let Some(g) = r.get(name) { return g.clone(); } }
        let mut w = self.gauges.write();
        w.entry(name.to_owned()).or_insert_with(|| Gauge::new(name)).clone()
    }

    pub fn histogram(&self, name: &str) -> Histogram {
        { let r = self.histograms.read(); if let Some(h) = r.get(name) { return h.clone(); } }
        let mut w = self.histograms.write();
        w.entry(name.to_owned()).or_insert_with(|| Histogram::new(name)).clone()
    }

    pub fn export_prometheus(&self) -> String {
        let mut out = String::with_capacity(4096);
        for c in self.counters.read().values() {
            out.push_str(&format!(
                "# HELP {n} wafrift counter
# TYPE {n} counter
{n} {v}
",
                n = c.name(), v = c.get(),
            ));
        }
        for g in self.gauges.read().values() {
            out.push_str(&format!(
                "# HELP {n} wafrift gauge
# TYPE {n} gauge
{n} {v}
",
                n = g.name(), v = g.get(),
            ));
        }
        for h in self.histograms.read().values() {
            let s = h.snapshot();
            out.push_str(&format!(
                "# HELP {n} wafrift histogram
# TYPE {n} summary
{n}_count {c}
{n}_sum {su}
{n}_min {mi}
{n}_max {ma}
",
                n = h.name(), c = s.count, su = s.sum, mi = s.min, ma = s.max,
            ));
        }
        out
    }
}

impl Default for Registry {
    fn default() -> Self { Self::new() }
}
