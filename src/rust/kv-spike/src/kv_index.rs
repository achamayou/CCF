// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use crate::engine::Address;
use crate::radix::{DualRadix, DualRoot, RadixRow, address_key};

struct Binding<V> {
    address: Address,
    value: V,
}

/// Persistent storage over the engine's map/key addresses. The sequence
/// returned by a scan is the order of the model association list.
pub struct AddressIndex<V>(DualRadix<Binding<V>>);

impl<V> AddressIndex<V> {
    pub fn new() -> Self {
        Self(DualRadix::new())
    }

    pub fn empty_root(&self) -> DualRoot {
        self.0.empty_root()
    }

    pub fn get(&self, root: DualRoot, address: &Address) -> Option<&V> {
        let key = address_key(address.map.as_slice(), address.key.as_slice());
        match self.0.get(root, &key) {
            Some(binding) => Some(&binding.value),
            None => None,
        }
    }

    pub fn put(&mut self, root: DualRoot, address: Address, value: V) -> DualRoot {
        let key = address_key(address.map.as_slice(), address.key.as_slice());
        self.0.put(
            root,
            RadixRow {
                key,
                value: Binding { address, value },
            },
        )
    }

    pub fn remove(&mut self, root: DualRoot, address: &Address) -> DualRoot {
        let key = address_key(address.map.as_slice(), address.key.as_slice());
        self.0.remove(root, &key)
    }

    pub fn scan_links(&self, root: DualRoot) -> Vec<u32> {
        self.0.scan_links(root)
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
                (b"a\0".as_slice(), b"\xff".as_slice(), 2),
                (b"a", b"\0\xff", 1)
            ]
        );
    }
}
