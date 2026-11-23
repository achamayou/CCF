// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use super::Value;
use ccf_kv_spike::radix::{RadixRow, allocate};
use std::fmt::Debug;

pub(super) trait ByteIndex: Default {
    type Root: Copy + Debug + Default + Eq;

    fn get(&self, root: Self::Root, key: &[u8]) -> Option<&Value>;
    fn put(&mut self, root: Self::Root, key: &[u8], value: Value) -> Self::Root;
    fn remove(&mut self, root: Self::Root, key: &[u8]) -> Self::Root;
    fn range(&self, root: Self::Root, first: &[u8], last: &[u8], visit: impl FnMut(&[u8], &Value));
    fn collect(&mut self, roots: &[Self::Root]);
    fn live_allocations(&self) -> (usize, usize);
    fn allocated_slots(&self) -> (usize, usize);
}

pub type Root = Option<usize>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Split {
    byte: usize,
    bit: u32,
}

impl Split {
    // A zero symbol terminates the key. The 9-bit symbols 1..=256 encode
    // actual bytes and keep a prefix strictly below its extensions.
    fn symbol(key: &[u8], at: usize) -> u16 {
        key.get(at).map_or(0, |b| 1 + u16::from(*b))
    }

    fn between(a: &[u8], b: &[u8]) -> Option<Self> {
        let byte = a
            .iter()
            .zip(b)
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| a.len().min(b.len()));
        let delta = Self::symbol(a, byte) ^ Self::symbol(b, byte);
        (delta != 0).then(|| Self {
            byte,
            bit: delta.leading_zeros(),
        })
    }

    fn right(self, key: &[u8]) -> bool {
        Self::symbol(key, self.byte) & (0x8000 >> self.bit) != 0
    }
}

#[derive(Clone, Copy)]
enum Node {
    Leaf(usize),
    Branch {
        split: Split,
        left: usize,
        right: usize,
        first_row: usize,
    },
}

impl Node {
    fn first_row(self) -> usize {
        match self {
            Self::Leaf(row) | Self::Branch { first_row: row, .. } => row,
        }
    }
}

pub(super) struct Pool<T> {
    slots: Vec<Option<T>>,
    free: Vec<usize>,
}

impl<T> Default for Pool<T> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }
}

impl<T> Pool<T> {
    pub(super) fn add(&mut self, value: T) -> usize {
        allocate(&mut self.slots, &mut self.free, value)
    }

    pub(super) fn get(&self, i: usize) -> &T {
        self.slots[i].as_ref().expect("live arena slot")
    }

    pub(super) fn sweep(&mut self, live: &[bool]) {
        for (i, (slot, marked)) in self.slots.iter_mut().zip(live).enumerate() {
            if !marked && slot.take().is_some() {
                self.free.push(i);
            }
        }
    }

    pub(super) fn live(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    pub(super) fn slots(&self) -> usize {
        self.slots.len()
    }

    pub(super) fn as_slice(&self) -> &[Option<T>] {
        &self.slots
    }
}

pub(super) type Row = RadixRow<Value>;

#[derive(Default)]
pub struct ByteRadix {
    nodes: Pool<Node>,
    rows: Pool<Row>,
    path: Vec<(Split, usize, bool)>,
}

impl ByteRadix {
    fn find_row(&self, mut node: usize, key: &[u8]) -> usize {
        loop {
            match *self.nodes.get(node) {
                Node::Leaf(row) => return row,
                Node::Branch {
                    split, left, right, ..
                } => node = if split.right(key) { right } else { left },
            }
        }
    }

    fn branch(&mut self, split: Split, left: usize, right: usize) -> usize {
        self.nodes.add(Node::Branch {
            split,
            left,
            right,
            first_row: self.nodes.get(left).first_row(),
        })
    }

    fn rebuild(&mut self, mut next: usize) -> Root {
        while let Some((split, sibling, went_right)) = self.path.pop() {
            next = if went_right {
                self.branch(split, sibling, next)
            } else {
                self.branch(split, next, sibling)
            };
        }
        Some(next)
    }

    fn save_path(&mut self, root: usize, key: &[u8], stop: Option<Split>) -> usize {
        self.path.clear();
        let mut node = root;
        while let Node::Branch {
            split, left, right, ..
        } = *self.nodes.get(node)
        {
            if stop.is_some_and(|stop| split >= stop) {
                break;
            }
            let went_right = split.right(key);
            let (next, sibling) = if went_right {
                (right, left)
            } else {
                (left, right)
            };
            self.path.push((split, sibling, went_right));
            node = next;
        }
        node
    }
}

impl ByteIndex for ByteRadix {
    type Root = Root;

    fn get(&self, root: Root, key: &[u8]) -> Option<&Value> {
        let row = self.rows.get(self.find_row(root?, key));
        (row.key.as_ref() == key).then_some(&row.value)
    }

    fn put(&mut self, root: Root, key: &[u8], value: Value) -> Root {
        let row = self.rows.add(Row {
            key: key.into(),
            value,
        });
        let leaf = self.nodes.add(Node::Leaf(row));
        let Some(root) = root else {
            return Some(leaf);
        };
        let old = self.rows.get(self.find_row(root, key));
        let split = Split::between(&old.key, key);
        let stem = self.save_path(root, key, split);
        let next = match split {
            Some(split) if split.right(key) => self.branch(split, stem, leaf),
            Some(split) => self.branch(split, leaf, stem),
            None => leaf,
        };
        self.rebuild(next)
    }

    fn remove(&mut self, root: Root, key: &[u8]) -> Root {
        let root = root?;
        let leaf = self.save_path(root, key, None);
        let old = self.rows.get(self.nodes.get(leaf).first_row());
        if old.key.as_ref() != key {
            return Some(root);
        }
        let (_, sibling, _) = self.path.pop()?;
        self.rebuild(sibling)
    }

    fn range(&self, root: Root, first: &[u8], last: &[u8], mut visit: impl FnMut(&[u8], &Value)) {
        if first >= last {
            return;
        }
        let mut stack: Vec<_> = root.into_iter().collect();
        while let Some(at) = stack.pop() {
            match *self.nodes.get(at) {
                Node::Leaf(row) => {
                    let Row { key, value } = self.rows.get(row);
                    if first <= key.as_ref() && key.as_ref() < last {
                        visit(key, value);
                    }
                }
                Node::Branch { left, right, .. } => {
                    let cut = self.rows.get(self.nodes.get(right).first_row());
                    if cut.key.as_ref() < last {
                        stack.push(right);
                    }
                    if first < cut.key.as_ref() {
                        stack.push(left);
                    }
                }
            }
        }
    }

    // The caller supplies every live root. Slots from omitted roots may be
    // reused immediately; the experiment does not expose such stale handles.
    fn collect(&mut self, roots: &[Root]) {
        let mut live = vec![false; self.nodes.slots.len()];
        let mut live_rows = vec![false; self.rows.slots.len()];
        let mut stack: Vec<_> = roots.iter().copied().flatten().collect();
        while let Some(at) = stack.pop() {
            if live[at] {
                continue;
            }
            live[at] = true;
            match *self.nodes.get(at) {
                Node::Leaf(row) => live_rows[row] = true,
                Node::Branch { left, right, .. } => stack.extend([left, right]),
            }
        }
        self.nodes.sweep(&live);
        self.rows.sweep(&live_rows);
    }

    fn live_allocations(&self) -> (usize, usize) {
        (self.nodes.live(), self.rows.live())
    }

    fn allocated_slots(&self) -> (usize, usize) {
        (self.nodes.slots.len(), self.rows.slots.len())
    }
}

pub(super) fn check<T: ByteIndex>() {
    use std::collections::BTreeMap;

    let mut index = T::default();
    let empty = T::Root::default();
    let empty_key = index.put(empty, &[], [1; 64]);
    let prefix = index.put(empty_key, &[0], [2; 64]);
    let first_fork = index.put(prefix, &[0, 0], [3; 64]);
    let second_fork = index.remove(first_fork, &[]);
    index.collect(&[first_fork, second_fork]);
    assert_eq!(index.get(first_fork, &[]), Some(&[1; 64]));
    assert_eq!(index.get(second_fork, &[]), None);
    let mut range = Vec::new();
    index.range(second_fork, &[0], &[1], |k, _| range.push(k.to_vec()));
    assert_eq!(range, [vec![0], vec![0, 0]]);
    index.range(second_fork, &[1], &[0], |_, _| panic!("reversed range"));
    index.collect(&[]);

    let mut head = empty;
    let mut expected = BTreeMap::new();
    let keys: Vec<_> = (0..=260)
        .map(|n| match n {
            0 => Vec::new(),
            1..=128 => vec![0; n],
            129..=256 => {
                let mut k = vec![0; n - 129];
                k.push(255);
                k
            }
            _ => vec![255; n - 255],
        })
        .chain((0..=255).map(|byte| vec![byte, 255]))
        .collect();

    fn assert_rows<T: ByteIndex>(index: &T, root: T::Root, expected: &BTreeMap<Vec<u8>, Value>) {
        let mut rows = Vec::new();
        index.range(root, &[], &[255; 6], |k, v| rows.push((k.to_vec(), *v)));
        let want = expected
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect::<Vec<_>>();
        assert_eq!(rows, want);
        for (k, v) in expected {
            assert_eq!(index.get(root, k), Some(v));
        }
    }

    let mut checkpoints = Vec::new();
    for i in 0..1_040 {
        let key = &keys[(i * 37) % keys.len()];
        if i % 3 == 0 {
            head = index.remove(head, key);
            expected.remove(key);
        } else {
            let value = [i as u8; 64];
            head = index.put(head, key, value);
            expected.insert(key.clone(), value);
        }
        if i % 71 == 0 {
            checkpoints.push((head, expected.clone()));
        }
        if i % 101 == 0 {
            let roots: Vec<_> = checkpoints
                .iter()
                .map(|(root, _)| *root)
                .chain([head])
                .collect();
            index.collect(&roots);
            assert_rows(&index, head, &expected);
            for (root, expected) in &checkpoints {
                assert_rows(&index, *root, expected);
            }
        }
    }
    assert_rows(&index, head, &expected);

    // Fork a retained root, delete a prefix and leave its longer keys present.
    let (older, mut old_rows) = checkpoints.pop().unwrap();
    let fork = index.remove(older, &[]);
    old_rows.remove(&Vec::new());
    index.collect(&[head, fork]);
    assert_rows(&index, head, &expected);
    assert_rows(&index, fork, &old_rows);

    index.collect(&[head]);
    assert_eq!(index.live_allocations().1, expected.len());
    index.collect(&[]);
    assert_eq!(index.live_allocations(), (0, 0));
    let slots = index.allocated_slots();
    head = index.put(empty, &[0], [9; 64]);
    assert_eq!(index.get(head, &[0]), Some(&[9; 64]));
    assert_eq!(index.remove(head, &[]), head);
    assert_eq!(index.remove(head, &[0]), empty);
    assert_eq!(index.allocated_slots(), slots);
}

pub(super) fn measure_churn<T: ByteIndex>(backend: &str) {
    use std::time::Instant;

    const KEYS: usize = 2_048;
    const MUTATIONS: usize = 8_192;
    const WINDOW: usize = 32;

    let keys: Vec<_> = (0..KEYS)
        .map(|i| {
            let mut key = vec![b'a'; i % 17];
            key.push(0);
            key.extend_from_slice(&i.to_be_bytes());
            key
        })
        .collect();
    let mut index = T::default();
    let mut head = T::Root::default();
    for (i, key) in keys.iter().enumerate() {
        head = index.put(head, key, [1; 64]);
        if (i + 1) % WINDOW == 0 {
            index.collect(&[head]);
        }
    }
    let mut held = [head; WINDOW + 1];
    let mut mutation = Vec::with_capacity(MUTATIONS);
    let mut collection = Vec::with_capacity(MUTATIONS / WINDOW);
    let start = Instant::now();
    for i in 0..MUTATIONS {
        let key = &keys[((i / 2) * 17) % KEYS];
        let step = Instant::now();
        head = if i % 2 == 0 {
            index.remove(head, key)
        } else {
            index.put(head, key, [2; 64])
        };
        held[1 + i % WINDOW] = head;
        mutation.push(step.elapsed().as_nanos());
        if (i + 1) % WINDOW == 0 {
            let at = Instant::now();
            index.collect(&held);
            collection.push(at.elapsed().as_nanos());
        }
    }
    let ns = start.elapsed().as_nanos() as f64 / MUTATIONS as f64;
    assert_eq!(index.get(held[0], &keys[0]), Some(&[1; 64]));
    assert_eq!(index.get(head, &keys[0]), Some(&[2; 64]));
    let (nodes, rows) = index.live_allocations();
    let (node_slots, row_slots) = index.allocated_slots();
    // Up to two full images, plus replacements still referenced by the
    // old window or created before the next sweep.
    assert!(row_slots <= 2 * KEYS + WINDOW);
    index.collect(&[head]);
    assert_eq!(index.live_allocations().1, KEYS);
    mutation.sort_unstable();
    collection.sort_unstable();
    eprintln!(
        "{backend} churn: {ns:.1} ns/mutation including GC; mutation p99 {} ns, GC p99 {} ns; \
         {nodes}/{node_slots} live/allocated nodes, {rows}/{row_slots} live/allocated rows",
        mutation[MUTATIONS * 99 / 100],
        collection[collection.len() * 99 / 100],
    );
}
