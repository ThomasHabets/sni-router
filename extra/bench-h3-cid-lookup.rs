// Run without rebuilding dependencies:
// rustc -O extra/bench-h3-cid-lookup.rs -o /tmp/h3-cid-bench
// /tmp/h3-cid-bench
#[path = "../src/h3_cid_routes.rs"]
mod cid_routes;

use std::{collections::HashMap, hint::black_box, time::Instant};

use cid_routes::CidRoutes;

fn main() {
    println!("routes,scan_ns,indexed_ns");
    for count in [1_000usize, 10_000, 100_000] {
        let mut old = HashMap::new();
        let mut indexed = CidRoutes::default();
        for id in 0..count {
            let cid = (id as u64).to_be_bytes().to_vec();
            old.insert(cid.clone(), id);
            indexed.insert(cid, id);
        }
        let mut packet = ((count - 1) as u64).to_be_bytes().to_vec();
        packet.extend_from_slice(&[0; 32]);
        assert_eq!(indexed.get(&packet[..8]), Some(&(count - 1)));
        assert_eq!(indexed.match_prefix(&packet), Some(count - 1));
        let iterations = 2_000;
        let started = Instant::now();
        for _ in 0..iterations {
            black_box(
                black_box(&old)
                    .iter()
                    .filter(|(cid, _)| {
                        !cid.is_empty() && black_box(&packet).starts_with(cid.as_slice())
                    })
                    .max_by_key(|(cid, _)| cid.len())
                    .map(|(_, id)| *id),
            );
        }
        let scan = started.elapsed().as_nanos() / iterations;
        let started = Instant::now();
        for _ in 0..iterations {
            black_box(indexed.match_prefix(black_box(&packet)));
        }
        let lookup = started.elapsed().as_nanos() / iterations;
        println!("{count},{scan},{lookup}");
        assert_eq!(indexed.remove(&packet[..8]), Some(count - 1));
    }
}
