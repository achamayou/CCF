// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use super::{Key, Value, measure_seeded, sorted_keys};
use ccf_kv_spike::radix::{DualRadix, DualRoot, RadixRow, address_key};

fn publish(
    index: &mut DualRadix<(Key, Value)>,
    writes: &[Key],
    value: Value,
    bulk: bool,
) -> DualRoot {
    let rows = writes.iter().map(|&key| RadixRow {
        key: address_key(b"public:benchmark", &key),
        value: (key, value),
    });
    if !bulk {
        return rows.fold(index.empty_root(), |root, row| index.put(root, row));
    }

    let mut lookup = Vec::with_capacity(writes.len());
    let mut order = Vec::with_capacity(writes.len());
    for row in rows {
        let (leaf, stamp) = index.stage_batch_leaf(row);
        lookup.push(leaf);
        order.push(stamp);
    }
    lookup.sort_unstable_by(|&a, &b| index.scan_row(a).0.cmp(index.scan_row(b).0));
    order.reverse();
    index.publish_batch_leaves(&lookup, &order)
}

fn check(index: &DualRadix<(Key, Value)>, root: DualRoot, writes: &[Key], value: Value) {
    let links = index.scan_links(root);
    assert_eq!(links.len(), writes.len());
    for (link, key) in links.into_iter().zip(writes.iter().rev()) {
        assert_eq!(index.scan_row(link).1, &(*key, value));
        assert_eq!(
            index.get(root, &address_key(b"public:benchmark", key)),
            Some(&(*key, value))
        );
    }
}

pub(super) fn measure() {
    println!("backend,workload,entries,operations,median_ns_per_operation,min_ns,max_ns");
    for (workload, shuffled) in [("batch_sequential", false), ("batch_shuffled", true)] {
        for entries in [512_usize, 2048, 8192] {
            let mut keys = sorted_keys(entries, shuffled);
            if shuffled {
                keys = (0..entries).map(|i| keys[(i * 17) % entries]).collect();
            }
            let prepare = || {
                let mut index = DualRadix::new();
                let prior = publish(&mut index, &keys, [1; 64], false);
                (index, prior)
            };
            for (backend, bulk) in [("path_copy", false), ("bulk_sorted_build", true)] {
                let (mut index, prior) = prepare();
                let next = publish(&mut index, &keys, [2; 64], bulk);
                check(&index, prior, &keys, [1; 64]);
                check(&index, next, &keys, [2; 64]);
                measure_seeded(backend, workload, entries, 1, prepare, |arena, prior| {
                    (prior, publish(arena, &keys, [2; 64], bulk))
                });
            }
        }
    }
}
