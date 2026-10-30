use std::collections::{BTreeMap, HashMap};

/// Index CIDs by length so short-header lookups do not scan every connection.
#[derive(Default)]
pub(crate) struct CidRoutes {
    by_length: BTreeMap<usize, HashMap<Vec<u8>, usize>>,
}

impl CidRoutes {
    /// Register a CID without replacing another connection's ownership.
    pub(crate) fn insert(&mut self, cid: Vec<u8>, conn_id: usize) -> bool {
        if cid.is_empty() {
            return false;
        }
        match self.by_length.entry(cid.len()).or_default().entry(cid) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(conn_id);
                true
            }
            std::collections::hash_map::Entry::Occupied(entry) => *entry.get() == conn_id,
        }
    }

    pub(crate) fn get(&self, cid: &[u8]) -> Option<&usize> {
        self.by_length.get(&cid.len())?.get(cid)
    }

    pub(crate) fn remove(&mut self, cid: &[u8]) -> Option<usize> {
        let routes = self.by_length.get_mut(&cid.len())?;
        let removed = routes.remove(cid);
        if routes.is_empty() {
            self.by_length.remove(&cid.len());
        }
        removed
    }

    pub(crate) fn match_prefix(&self, bytes: &[u8]) -> Option<usize> {
        self.by_length
            .range(..=bytes.len())
            .rev()
            .find_map(|(len, routes)| routes.get(&bytes[..*len]).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_matching_cid_wins() {
        let mut routes = CidRoutes::default();
        routes.insert(b"abc".to_vec(), 1);
        routes.insert(b"abcdef".to_vec(), 2);
        routes.insert(b"unrelated".to_vec(), 3);
        assert_eq!(routes.match_prefix(b"abcdef-payload"), Some(2));
        assert_eq!(routes.match_prefix(b"abc-other"), Some(1));
        assert_eq!(routes.match_prefix(b"ab"), None);
        assert_eq!(routes.match_prefix(b"unknown"), None);
        routes.remove(b"abcdef");
        assert_eq!(routes.match_prefix(b"abcdef-payload"), Some(1));
        assert!(!routes.by_length.contains_key(&6));
    }

    #[test]
    fn collisions_preserve_ownership_and_removal_keeps_lengths_consistent() {
        let mut routes = CidRoutes::default();
        routes.insert(b"abc".to_vec(), 1);
        routes.insert(b"def".to_vec(), 2);
        assert!(routes.insert(b"abc".to_vec(), 1));
        assert!(!routes.insert(b"abc".to_vec(), 3));
        assert_eq!(routes.get(b"abc"), Some(&1));
        assert_eq!(routes.match_prefix(b"abc-payload"), Some(1));
        assert_eq!(routes.remove(b"abc"), Some(1));
        assert_eq!(routes.match_prefix(b"def-data"), Some(2));
        routes.remove(b"def");
        assert!(routes.by_length.is_empty());
        assert!(!routes.insert(vec![], 4));
        assert_eq!(routes.match_prefix(b"anything"), None);
    }
}
