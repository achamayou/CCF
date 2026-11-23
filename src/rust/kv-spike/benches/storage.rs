// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use ccf_kv_spike::radix::{OrderedRadix, RadixRow, Root as OrderedRoot};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

#[path = "storage/byte_radix.rs"]
mod byte_radix;
#[path = "storage/nibble_radix.rs"]
mod nibble_radix;
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

impl<T: byte_radix::ByteIndex> Index for T {
    type Root = <T as byte_radix::ByteIndex>::Root;

    fn get<'a>(&'a self, root: &Self::Root, key: &Key) -> Option<&'a Value> {
        byte_radix::ByteIndex::get(self, *root, key)
    }

    fn put(&mut self, root: &mut Self::Root, key: Key, value: Value) {
        *root = byte_radix::ByteIndex::put(self, *root, &key, value);
    }

    fn range(&self, root: &Self::Root, first: &Key, last: &Key) -> usize {
        let mut sum = 0;
        byte_radix::ByteIndex::range(self, *root, first, last, |_, value| {
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
    run: impl FnMut(&mut T, T::Root) -> R,
) {
    measure_seeded(
        backend,
        workload,
        keys.len(),
        operations,
        || seed::<T>(keys),
        run,
    );
}

fn measure_seeded<T, Root, R>(
    backend: &str,
    workload: &str,
    entries: usize,
    operations: usize,
    mut prepare: impl FnMut() -> (T, Root),
    mut run: impl FnMut(&mut T, Root) -> R,
) {
    let (mut index, root) = prepare();
    black_box(run(&mut index, root));
    let mut values = [0.0; SAMPLES];
    for value in &mut values {
        let (mut index, root) = prepare();
        let start = Instant::now();
        let retained = run(&mut index, root);
        *value = start.elapsed().as_secs_f64() * 1e9 / operations as f64;
        black_box(retained);
    }
    values.sort_unstable_by(f64::total_cmp);
    println!(
        "{backend},{workload},{entries},{operations},{:.1},{:.1},{:.1}",
        values[SAMPLES / 2],
        values[0],
        values[SAMPLES - 1],
    );
}

fn sorted_keys(entries: usize, scrambled: bool) -> Vec<Key> {
    let mut keys: Vec<Key> = (0..entries as u64)
        .map(|i| {
            if scrambled {
                i.wrapping_mul(0x9e37_79b9_7f4a_7c15)
            } else {
                i
            }
            .to_be_bytes()
        })
        .collect();
    keys.sort_unstable();
    keys
}

fn suite<T: Index>(backend: &str, scrambled: bool) {
    const WRITES: usize = 128;
    for entries in [64_usize, 512, 2048, 8192] {
        let keys = sorted_keys(entries, scrambled);
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

trait OrderedIndex: Default {
    type Root: Copy;

    fn empty_root(&self) -> Self::Root;
    fn put(&mut self, root: Self::Root, key: &Key, value: Value) -> Self::Root;
    fn get(&self, root: Self::Root, key: &Key) -> Option<&Value>;
    fn scan(&self, root: Self::Root, visit: impl FnMut(&[u8], &Value));
}

impl OrderedIndex for OrderedRadix<Value> {
    type Root = OrderedRoot;

    fn empty_root(&self) -> Self::Root {
        self.empty_root()
    }

    fn put(&mut self, root: Self::Root, key: &Key, value: Value) -> Self::Root {
        self.put(
            root,
            RadixRow {
                key: key.as_slice().into(),
                value,
            },
        )
    }

    fn get(&self, root: Self::Root, key: &Key) -> Option<&Value> {
        self.get(root, key)
    }

    fn scan(&self, root: Self::Root, mut visit: impl FnMut(&[u8], &Value)) {
        for i in 0..self.scan_len(root) {
            let row = self.scan_at(root, i).unwrap();
            visit(&row.key, &row.value);
        }
    }
}

impl OrderedIndex for nibble_radix::StampedRadix {
    type Root = nibble_radix::Link;

    fn empty_root(&self) -> Self::Root {
        Self::Root::default()
    }

    fn put(&mut self, root: Self::Root, key: &Key, value: Value) -> Self::Root {
        self.put(root, key, value)
    }

    fn get(&self, root: Self::Root, key: &Key) -> Option<&Value> {
        self.get(root, key)
    }

    fn scan(&self, root: Self::Root, visit: impl FnMut(&[u8], &Value)) {
        self.scan(root, visit);
    }
}

fn ordered_suite<T: OrderedIndex>(name: &str, scrambled: bool) {
    for entries in [512_usize, 2048, 8192] {
        let keys = sorted_keys(entries, scrambled);
        let prepare = || {
            let mut arena = T::default();
            let mut root = arena.empty_root();
            for key in &keys {
                root = arena.put(root, key, [1; 64]);
            }
            (arena, root)
        };
        let (mut arena, prior) = prepare();
        let next = arena.put(prior, &keys[0], [2; 64]);
        let mut position = 0;
        arena.scan(prior, |key, value| {
            assert_eq!(key, &keys[entries - position - 1]);
            assert_eq!(value[0], 1);
            position += 1;
        });
        assert_eq!(position, entries);
        position = 0;
        arena.scan(next, |key, value| {
            assert_eq!(
                key,
                &keys[if position == 0 { 0 } else { entries - position }]
            );
            assert_eq!(value[0], if position == 0 { 2 } else { 1 });
            position += 1;
        });
        assert_eq!(position, entries);
        drop(arena);
        let measure = |workload, operations, run: &dyn Fn(&mut T, T::Root)| {
            measure_seeded(name, workload, entries, operations, prepare, run);
        };
        measure("point_read", entries, &|arena, root| {
            for key in &keys {
                assert_eq!(black_box(arena.get(root, key).unwrap())[0], 1);
            }
        });
        measure("write_with_pinned_root", 128, &|arena, prior| {
            let mut root = prior;
            for i in 0..128 {
                root = arena.put(root, &keys[(17 * i) % entries], [2; 64]);
            }
            assert_eq!(arena.get(prior, &keys[0]).unwrap()[0], 1);
            assert_eq!(arena.get(root, &keys[0]).unwrap()[0], 2);
            black_box(root);
        });
        measure("ordered_full_scan", 128, &|arena, root| {
            for _ in 0..128 {
                let mut sum = 0;
                arena.scan(black_box(root), |_, value| {
                    sum += usize::from(black_box(value)[0])
                });
                assert_eq!(sum, entries);
            }
        });
    }
}

fn main() {
    let mode = std::env::args().nth(1);
    if mode.as_deref() == Some("retirement") {
        nibble_radix::retirement::check();
        for i in 0..4 {
            let sweep = || byte_radix::measure_churn::<nibble_radix::NibbleRadix>("nibble_radix");
            let budgeted = nibble_radix::retirement::measure_churn;
            if i % 2 == 0 {
                sweep();
                budgeted();
            } else {
                budgeted();
                sweep();
            }
        }
        return;
    }
    if mode.as_deref() == Some("ordered") {
        nibble_radix::check_stamp_reuse();
        println!("backend,workload,entries,operations,median_ns_per_operation,min_ns,max_ns");
        ordered_suite::<OrderedRadix<Value>>("ordered_nibble_radix", false);
        ordered_suite::<nibble_radix::StampedRadix>("stamped_nibble_radix", false);
        ordered_suite::<nibble_radix::StampedRadix>("stamped_nibble_radix_scrambled", true);
        ordered_suite::<OrderedRadix<Value>>("ordered_nibble_radix_scrambled", true);
        return;
    }
    check_persistence::<Paged>();
    check_persistence::<radix::Radix>();
    check_persistence::<byte_radix::ByteRadix>();
    byte_radix::check::<byte_radix::ByteRadix>();
    byte_radix::check::<nibble_radix::NibbleRadix>();
    println!("backend,workload,entries,operations,median_ns_per_operation,min_ns,max_ns");
    suite::<WholeMap>("arc_btree", false);
    suite::<Paged>("paged", false);
    suite::<radix::Radix>("radix_arena", false);
    suite::<byte_radix::ByteRadix>("byte_radix", false);
    suite::<nibble_radix::NibbleRadix>("nibble_radix", false);
    suite::<nibble_radix::NibbleRadix>("nibble_radix_scrambled", true);
    byte_radix::measure_churn::<byte_radix::ByteRadix>("byte_radix");
    byte_radix::measure_churn::<nibble_radix::NibbleRadix>("nibble_radix");
}
