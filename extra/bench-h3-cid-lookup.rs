// Run without rebuilding dependencies:
// rustc -O extra/bench-h3-cid-lookup.rs -o /tmp/h3-cid-bench
// /tmp/h3-cid-bench
#[path = "../src/h3_cid_routes.rs"]
mod cid_routes;

use std::{collections::HashMap, hint::black_box, time::Instant};

use cid_routes::CidRoutes;

fn scan(routes: &HashMap<Vec<u8>, usize>, bytes: &[u8]) -> Option<usize> {
    routes
        .iter()
        .filter(|(cid, _)| !cid.is_empty() && bytes.starts_with(cid.as_slice()))
        .max_by_key(|(cid, _)| cid.len())
        .map(|(_, id)| *id)
}

fn main() {
    println!("routes,cid_lengths,scan_ns,indexed_ns");
    for lengths in [&[8usize][..], &[8, 12, 16, 20][..]] {
        for count in [1_000usize, 10_000, 100_000] {
            let mut old = HashMap::new();
            let mut indexed = CidRoutes::default();
            for id in 0..count {
                let mut cid = (id as u64).to_be_bytes().to_vec();
                cid.resize(lengths[id % lengths.len()], 0xa5);
                old.insert(cid.clone(), id);
                indexed.insert(cid, id);
            }
            // Match the shortest length, requiring all longer lengths to be probed.
            let mut packet = 0u64.to_be_bytes().to_vec();
            packet.extend_from_slice(&[0x5a; 32]);
            assert_eq!(indexed.get(&packet[..8]), Some(&0));
            assert_eq!(scan(&old, &packet), indexed.match_prefix(&packet));
            let iterations = 2_000;
            let started = Instant::now();
            for _ in 0..iterations {
                black_box(scan(black_box(&old), black_box(&packet)));
            }
            let scan = started.elapsed().as_nanos() / iterations;
            let lookup_iterations = 1_000_000;
            let started = Instant::now();
            for _ in 0..lookup_iterations {
                black_box(black_box(&indexed).match_prefix(black_box(&packet)));
            }
            let lookup = started.elapsed().as_nanos() / lookup_iterations;
            println!("{count},{},{scan},{lookup}", lengths.len());
            assert_eq!(indexed.remove(&packet[..8]), Some(0));
        }
    }
}
