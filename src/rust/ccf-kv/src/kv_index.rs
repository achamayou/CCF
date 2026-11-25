// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use crate::engine::{Address, Bytes};
use crate::radix::{RadixRoot, RadixRow, SingleRadix, address_key, map_prefix};

pub(crate) struct Binding<V> {
    address: Address,
    value: V,
}

/// Persistent storage over the engine's map/key addresses, scanned in
/// ascending packed-address byte order.
pub struct AddressIndex<V>(SingleRadix<Binding<V>>);

impl<V> AddressIndex<V> {
    pub fn new() -> Self {
        Self(SingleRadix::new())
    }

    pub fn empty_root(&self) -> RadixRoot {
        self.0.empty_root()
    }

    pub fn retain_root(&mut self, root: RadixRoot) {
        self.0.retain_root(root);
    }

    pub fn release_root(&mut self, root: RadixRoot) {
        self.0.release_root(root);
    }

    pub fn retire_budget(&mut self, budget: usize) -> usize {
        self.0.retire_budget(budget)
    }

    pub(crate) fn batch_row(address: Address, value: V) -> RadixRow<Binding<V>> {
        let key = address_key(address.map.as_slice(), address.key.as_slice());
        RadixRow {
            key,
            value: Binding { address, value },
        }
    }

    pub(crate) fn build_sorted_batch(
        &mut self,
        rows: Vec<Option<RadixRow<Binding<V>>>>,
    ) -> RadixRoot {
        self.0.build_sorted_batch(rows)
    }

    pub fn get(&self, root: RadixRoot, address: &Address) -> Option<&V> {
        let key = address_key(address.map.as_slice(), address.key.as_slice());
        match self.0.get(root, &key) {
            Some(binding) => Some(&binding.value),
            None => None,
        }
    }

    pub fn put(&mut self, root: RadixRoot, address: Address, value: V) -> RadixRoot {
        self.0.put(root, Self::batch_row(address, value))
    }

    pub fn remove(&mut self, root: RadixRoot, address: &Address) -> RadixRoot {
        let key = address_key(address.map.as_slice(), address.key.as_slice());
        self.0.remove(root, &key)
    }

    pub fn scan_links(&self, root: RadixRoot) -> Vec<u32> {
        self.0.scan_links(root)
    }

    pub fn scan_links_up_to(&self, root: RadixRoot, limit: usize) -> Vec<u32> {
        self.0.scan_links_up_to(root, limit)
    }

    pub fn scan_map_links(&self, root: RadixRoot, map: &Bytes) -> Vec<u32> {
        let prefix = map_prefix(map.as_slice());
        self.0.scan_prefix_links(root, &prefix)
    }

    pub fn scan_row(&self, link: u32) -> (&Address, &V) {
        let (_, binding) = self.0.scan_row(link);
        (&binding.address, &binding.value)
    }
}

impl<V> Default for AddressIndex<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Bytes;

    fn address(map: &[u8], key: &[u8]) -> Address {
        Address {
            map: Bytes::copy_from(map),
            key: Bytes::copy_from(key),
        }
    }

    #[test]
    fn ordered_roots_preserve_independent_map_key_pairs() {
        let mut data = AddressIndex::new();
        let empty = data.empty_root();
        let left = address(b"a", b"\0\xff");
        let right = address(b"a\0", b"\xff");
        let base = data.put(empty, left.clone(), 1);
        let base = data.put(base, right.clone(), 2);
        let replacement = data.put(base, left.clone(), 3);
        let fork = data.remove(replacement, &right);
        assert_eq!(data.get(base, &left), Some(&1));
        assert_eq!(data.get(fork, &left), Some(&3));
        assert_eq!(data.get(base, &right), Some(&2));
        assert_eq!(data.get(fork, &right), None);
        let ordered = |root| {
            data.scan_links(root)
                .into_iter()
                .map(|link| {
                    let (a, v) = data.scan_row(link);
                    (a.map.as_slice(), a.key.as_slice(), *v)
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ordered(replacement),
            [
                (b"a".as_slice(), b"\0\xff".as_slice(), 3),
                (b"a\0", b"\xff", 2)
            ]
        );
        assert_eq!(
            ordered(base),
            [
                (b"a".as_slice(), b"\0\xff".as_slice(), 1),
                (b"a\0", b"\xff", 2)
            ]
        );
        let for_map = |root, map: &[u8]| {
            data.scan_map_links(root, &Bytes::copy_from(map))
                .into_iter()
                .map(|link| {
                    let (a, v) = data.scan_row(link);
                    (a.key.as_slice(), *v)
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(for_map(base, b"a"), [(b"\0\xff".as_slice(), 1)]);
        assert_eq!(for_map(base, b"a\0"), [(b"\xff".as_slice(), 2)]);
        assert_eq!(for_map(base, b""), []);
        assert_eq!(for_map(fork, b"a\0"), []);
    }
}
