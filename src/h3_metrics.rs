//! QUIC proxy observations. These do not imply completed TLS handshakes.

use prometheus::{Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry};

pub(crate) struct Metrics {
    pub registry: Registry,
    pub paths: IntCounter,
    pub active_paths: IntGauge,
    pub pending: IntGauge,
    pub pending_bytes: IntGauge,
    pub sni: IntCounterVec,
    pub routing_latency: Histogram,
    pub client: Traffic,
    pub backend: Traffic,
    pub drops: IntCounterVec,
    pub errors: IntCounterVec,
    pub cid_limit: IntCounter,
}

pub(crate) struct Traffic {
    pub datagrams: IntCounter,
    pub bytes: IntCounter,
}

impl Traffic {
    pub fn received(&self, bytes: usize) {
        self.datagrams.inc();
        self.bytes.inc_by(bytes as u64);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        let registry = Registry::new();
        macro_rules! register {
            ($metric:expr) => {{
                let metric = $metric.unwrap();
                registry.register(Box::new(metric.clone())).unwrap();
                metric
            }};
        }
        let datagrams = register!(IntCounterVec::new(
            Opts::new(
                "quic_received_datagrams_total",
                "UDP datagrams received by the router"
            ),
            &["source"]
        ));
        let bytes = register!(IntCounterVec::new(
            Opts::new(
                "quic_received_bytes_total",
                "UDP payload bytes received by the router"
            ),
            &["source"]
        ));
        Self {
            paths: register!(IntCounter::new(
                "quic_paths_total",
                "UDP backend paths created"
            )),
            active_paths: register!(IntGauge::new(
                "quic_active_paths",
                "Retained UDP backend paths"
            )),
            pending: register!(IntGauge::new(
                "quic_pending_initials",
                "ClientHello reassemblies awaiting routing"
            )),
            pending_bytes: register!(IntGauge::new(
                "quic_pending_initial_bytes",
                "Buffered Initial datagram bytes across pending handshakes"
            )),
            sni: register!(IntCounterVec::new(
                Opts::new(
                    "sni",
                    "Routed ClientHellos by configured SNI, <unknown>, <missing>, or <other>"
                ),
                &["sni"]
            )),
            routing_latency: register!(Histogram::with_opts(
                HistogramOpts::new(
                    "quic_routing_latency_ms",
                    "Time from first buffered Initial to SNI routing; not TLS handshake latency"
                )
                .buckets(prometheus::exponential_buckets(1.0, 2.0f64.sqrt(), 40).unwrap())
            )),
            client: Traffic {
                datagrams: datagrams.with_label_values(&["client"]),
                bytes: bytes.with_label_values(&["client"]),
            },
            backend: Traffic {
                datagrams: datagrams.with_label_values(&["backend"]),
                bytes: bytes.with_label_values(&["backend"]),
            },
            drops: register!(IntCounterVec::new(
                Opts::new(
                    "quic_routing_dropped_datagrams_total",
                    "Datagrams discarded by routing; excludes socket and send queue losses"
                ),
                &["reason"]
            )),
            errors: register!(IntCounterVec::new(
                Opts::new("quic_errors_total", "Datagram handling and receive errors"),
                &["source"]
            )),
            cid_limit: register!(IntCounter::new(
                "quic_cid_limit_total",
                "CID registration attempts rejected by the per-path limit"
            )),
            registry,
        }
    }
}

impl Metrics {
    pub fn dropped(&self, reason: &str, count: usize) {
        self.drops.with_label_values(&[reason]).inc_by(count as u64);
    }
}
