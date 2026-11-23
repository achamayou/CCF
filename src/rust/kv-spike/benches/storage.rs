// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

#[path = "storage/byte_radix.rs"]
mod byte_radix;
#[path = "storage/radix.rs"]
mod radix;

const PAGE: usize = 32;
const SAMPLES: usize = 9;
type Key = [u8; 8];
type Value = [u8; 64];
type Rows = Vec<(Key, Value)>;

trait Index: Default {
    type Root: Clone + Default;

    fn get<'a>(&'a self, root: &'a Self::Root, key: &Key) -> Option<&'a Value>;
    fn put(&mut self, root: &mut Self::Root, key: Key, value: Value);
    fn range(&self, root: &Self::Root, first: &Key, last: &Key) -> usize;
}

#[derive(Default)]
struct WholeMap;

impl Index for WholeMap {
    type Root = Arc<BTreeMap<Key, Value>>;

    fn get<'a>(&self, root: &'a Self::Root, key: &Key) -> Option<&'a Value> {
        root.get(key)
    }

    fn put(&mut self, root: &mut Self::Root, key: Key, value: Value) {
        Arc::make_mut(root).insert(key, value);
    }

    fn range(&self, root: &Self::Root, first: &Key, last: &Key) -> usize {
        root.range(*first..*last)
            .map(|(_, value)| usize::from(black_box(value)[0]))
            .sum()
    }
}

#[derive(Clone)]
struct Leaf {
    last: Key,
    rows: Arc<Rows>,
}

// Benchmark-only two-level ordered index. Copy an array of leaf handles
// instead of cloning every binding when an older root is pinned.
#[derive(Default)]
struct Paged;

impl Paged {
    fn page(leaves: &[Leaf], key: &Key) -> usize {
        leaves.partition_point(|leaf| leaf.last < *key)
    }
}

impl Index for Paged {
    type Root = Arc<Vec<Leaf>>;

    fn get<'a>(&self, root: &'a Self::Root, key: &Key) -> Option<&'a Value> {
        let leaf = root.get(Self::page(root, key))?;
        let row = leaf.rows.binary_search_by_key(key, |row| row.0).ok()?;
        Some(&leaf.rows[row].1)
    }

    fn put(&mut self, root: &mut Self::Root, key: Key, value: Value) {
        let page = Self::page(root, &key);
        let directory = Arc::make_mut(root);
        if directory.is_empty() {
            directory.push(Leaf {
                last: key,
                rows: Arc::new(vec![(key, value)]),
            });
            return;
        }
        let at = page.min(directory.len() - 1);
        let leaf = &mut directory[at];
        let rows = Arc::make_mut(&mut leaf.rows);
        match rows.binary_search_by_key(&key, |row| row.0) {
            Ok(i) => rows[i].1 = value,
            Err(i) => rows.insert(i, (key, value)),
        }
        leaf.last = leaf.last.max(key);
        if rows.len() > PAGE {
            let right = rows.split_off(PAGE / 2);
            let last = right.last().unwrap().0;
            leaf.last = rows.last().unwrap().0;
            directory.insert(
                at + 1,
                Leaf {
                    last,
                    rows: Arc::new(right),
                },
            );
        }
    }

    fn range(&self, root: &Self::Root, first: &Key, last: &Key) -> usize {
        root[Self::page(root, first)..]
            .iter()
            .flat_map(|leaf| leaf.rows.iter())
            .skip_while(|row| row.0 < *first)
            .take_while(|row| row.0 < *last)
            .map(|(_, value)| usize::from(black_box(value)[0]))
            .sum()
    }
}

impl Index for radix::Radix {
    type Root = radix::Root;

    fn get<'a>(&'a self, root: &Self::Root, key: &Key) -> Option<&'a Value> {
        self.get(*root, key)
    }

    fn put(&mut self, root: &mut Self::Root, key: Key, value: Value) {
        *root = self.put(*root, key, value);
    }

    fn range(&self, root: &Self::Root, first: &Key, last: &Key) -> usize {
        self.range(*root, first, last)
    }
}

impl Index for byte_radix::ByteRadix {
    type Root = byte_radix::Root;

    fn get<'a>(&'a self, root: &Self::Root, key: &Key) -> Option<&'a Value> {
        self.get(*root, key)
    }

    fn put(&mut self, root: &mut Self::Root, key: Key, value: Value) {
        *root = self.put(*root, &key, value);
    }

    fn range(&self, root: &Self::Root, first: &Key, last: &Key) -> usize {
        let mut sum = 0;
        self.range(*root, first, last, |_, value| {
            sum += usize::from(black_box(value)[0]);
        });
        sum
    }
}

fn seed<T: Index>(keys: &[Key]) -> (T, T::Root) {
    let mut index = T::default();
    let mut root = T::Root::default();
    for key in keys {
        index.put(&mut root, *key, [1; 64]);
    }
    (index, root)
}

fn measure<T: Index, R>(
    backend: &str,
    workload: &str,
    keys: &[Key],
    operations: usize,
    mut run: impl FnMut(&mut T, T::Root) -> R,
) {
    let (mut index, root) = seed::<T>(keys);
    black_box(run(&mut index, root));
    let mut values = [0.0; SAMPLES];
    for value in &mut values {
        let (mut index, root) = seed::<T>(keys);
        let start = Instant::now();
        let retained = run(&mut index, root);
        *value = start.elapsed().as_secs_f64() * 1e9 / operations as f64;
        black_box(retained);
    }
    values.sort_unstable_by(f64::total_cmp);
    let entries = keys.len();
    println!(
        "{backend},{workload},{entries},{operations},{:.1},{:.1},{:.1}",
        values[SAMPLES / 2],
        values[0],
        values[SAMPLES - 1],
    );
}

fn suite<T: Index>(backend: &str) {
    const WRITES: usize = 128;
    for entries in [64_usize, 512, 2048, 8192] {
        let keys: Vec<Key> = (0..entries as u64).map(u64::to_be_bytes).collect();
        measure::<T, _>(backend, "point_read", &keys, entries, |index, root| {
            for key in &keys {
                assert_eq!(black_box(index.get(&root, key).unwrap())[0], 1);
            }
            root
        });
        measure::<T, _>(
            backend,
            "write_with_pinned_root",
            &keys,
            WRITES,
            |index, mut root| {
                let mut history = Vec::with_capacity(WRITES);
                history.push(root.clone());
                for i in 0..WRITES {
                    let key = keys[(17 * i) % entries];
                    index.put(&mut root, key, [2; 64]);
                    history.push(root.clone());
                }
                assert_eq!(index.get(&history[0], &keys[0]).unwrap()[0], 1);
                assert_eq!(index.get(&root, &keys[0]).unwrap()[0], 2);
                (history, root)
            },
        );
        measure::<T, _>(backend, "range", &keys, entries, |index, root| {
            for i in 0..entries {
                let start = i % (entries - 8);
                assert_eq!(index.range(&root, &keys[start], &keys[start + 8]), 8);
            }
            root
        });
    }
}

fn check_persistence<T: Index>() {
    let mut index = T::default();
    let mut root = T::Root::default();
    let mut expected = BTreeMap::new();
    let mut checkpoints = Vec::new();
    for i in 0_u64..517 {
        let key = if i % 2 == 0 {
            (i * 37 % 127).to_be_bytes()
        } else {
            (u64::MAX - i * 37 % 127).to_be_bytes()
        };
        let value = [i as u8; 64];
        index.put(&mut root, key, value);
        expected.insert(key, value);
        if i % 41 == 0 {
            checkpoints.push((root.clone(), expected.clone()));
        }
    }
    checkpoints.push((root, expected));
    for (mut root, mut expected) in checkpoints {
        let old = root.clone();
        let key = 700_u64.to_be_bytes();
        index.put(&mut root, key, [1; 64]);
        assert_eq!(index.get(&old, &key), None);
        expected.insert(key, [1; 64]);
        for (key, value) in &expected {
            assert_eq!(index.get(&root, key), Some(value));
        }
        for (first, last) in [(0, 64), (0, 800), (64, u64::MAX), (u64::MAX - 89, u64::MAX)] {
            let (first, last) = (first.to_be_bytes(), last.to_be_bytes());
            let expected = expected
                .range(first..last)
                .map(|(_, v)| usize::from(v[0]))
                .sum();
            assert_eq!(index.range(&root, &first, &last), expected);
        }
    }
}

fn main() {
    check_persistence::<Paged>();
    check_persistence::<radix::Radix>();
    check_persistence::<byte_radix::ByteRadix>();
    byte_radix::check();
    println!("backend,workload,entries,operations,median_ns_per_operation,min_ns,max_ns");
    suite::<WholeMap>("arc_btree");
    suite::<Paged>("paged");
    suite::<radix::Radix>("radix_arena");
    suite::<byte_radix::ByteRadix>("byte_radix");
    byte_radix::measure_churn();
}
