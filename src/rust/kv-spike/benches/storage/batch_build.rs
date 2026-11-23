// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use super::{Key, Value, measure_seeded, sorted_keys};
use ccf_kv_spike::radix::{
    RADIX_LEAF_TAG, RadixDir, RadixRow, address_key, build_sorted, get, link_at, put,
    reverse_stamp_key, scan_leaves,
};

struct Arena<V> {
    dirs: Vec<Option<RadixDir>>,
    rows: Vec<Option<RadixRow<V>>>,
    free_dirs: Vec<usize>,
    free_rows: Vec<usize>,
    path: Vec<(u32, usize)>,
}

impl<V> Default for Arena<V> {
    fn default() -> Self {
        Self {
            dirs: Vec::new(),
            rows: Vec::new(),
            free_dirs: Vec::new(),
            free_rows: Vec::new(),
            path: Vec::new(),
        }
    }
}

impl<V> Arena<V> {
    fn put(&mut self, root: u32, row: RadixRow<V>) -> (u32, u32) {
        let (next, leaf, old) = put(
            &mut self.dirs,
            &mut self.free_dirs,
            &mut self.rows,
            &mut self.free_rows,
            &mut self.path,
            root,
            row,
        );
        assert!(old.is_none());
        (next, leaf)
    }

    fn row(&self, leaf: u32) -> &RadixRow<V> {
        self.rows[(leaf - RADIX_LEAF_TAG - 1) as usize]
            .as_ref()
            .unwrap()
    }

    fn push(&mut self, row: RadixRow<V>) -> u32 {
        let link = link_at(self.rows.len(), true);
        self.rows.push(Some(row));
        link
    }

    fn build_sorted(&mut self, sorted: &[u32]) -> u32 {
        build_sorted(&mut self.dirs, &mut self.free_dirs, &self.rows, sorted)
    }
}

#[derive(Clone, Copy)]
struct Roots {
    values: u32,
    order: u32,
}

#[derive(Default)]
struct BatchIndex {
    values: Arena<(Key, Value)>,
    order: Arena<u32>,
    last: u64,
}

impl BatchIndex {
    fn publish(&mut self, writes: &[Key], value: Value, bulk: bool) -> Roots {
        let mut values = 0;
        let mut order = 0;
        let mut value_links = Vec::new();
        let mut order_links = Vec::new();
        for &key in writes {
            self.last += 1;
            let row = RadixRow {
                key: address_key(b"public:benchmark", &key),
                value: (key, value),
            };
            let leaf = if bulk {
                let leaf = self.values.push(row);
                value_links.push(leaf);
                leaf
            } else {
                let (next, leaf) = self.values.put(values, row);
                values = next;
                leaf
            };
            let stamp = RadixRow {
                key: reverse_stamp_key(self.last),
                value: leaf,
            };
            if bulk {
                order_links.push(self.order.push(stamp));
            } else {
                order = self.order.put(order, stamp).0;
            }
        }
        if bulk {
            value_links
                .sort_unstable_by(|a, b| self.values.row(*a).key.cmp(&self.values.row(*b).key));
            order_links.reverse();
            values = self.values.build_sorted(&value_links);
            order = self.order.build_sorted(&order_links);
        }
        Roots { values, order }
    }

    fn check(&self, root: Roots, writes: &[Key], value: Value) {
        let links = scan_leaves(&self.order.dirs, root.order);
        assert_eq!(links.len(), writes.len());
        for (link, key) in links.into_iter().zip(writes.iter().rev()) {
            assert_eq!(
                self.values.row(self.order.row(link).value).value,
                (*key, value)
            );
            assert_eq!(
                get(
                    &self.values.dirs,
                    &self.values.rows,
                    root.values,
                    &address_key(b"public:benchmark", key)
                ),
                Some(&(*key, value))
            );
        }
    }
}

pub(super) fn measure() {
    println!("backend,workload,entries,operations,median_ns_per_operation,min_ns,max_ns");
    for (workload, shuffled) in [("batch_sequential", false), ("batch_shuffled", true)] {
        for entries in [512_usize, 2048, 8192] {
            let mut keys = sorted_keys(entries, shuffled);
            if shuffled {
                // A fixed permutation: all input sizes are powers of two.
                keys = (0..entries).map(|i| keys[(i * 17) % entries]).collect();
            }
            let prepare = || {
                let mut index = BatchIndex::default();
                let prior = index.publish(&keys, [1; 64], false);
                (index, prior)
            };
            for (backend, bulk) in [("path_copy", false), ("bulk_sorted_build", true)] {
                let (mut index, prior) = prepare();
                let before = index.values.dirs.len() + index.order.dirs.len();
                let next = index.publish(&keys, [2; 64], bulk);
                index.check(prior, &keys, [1; 64]);
                index.check(next, &keys, [2; 64]);
                let allocated = index.values.dirs.len() + index.order.dirs.len() - before;
                eprintln!("{backend},{workload},{entries}: {allocated} added directories");
                measure_seeded(backend, workload, entries, 1, prepare, |arena, prior| {
                    (prior, arena.publish(&keys, [2; 64], bulk))
                });
            }
        }
    }
}
