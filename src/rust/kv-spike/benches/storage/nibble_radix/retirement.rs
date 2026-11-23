// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use super::{ByteIndex, Link, NibbleRadix, Value};
use ccf_kv_spike::radix::{RadixDir, link_at, recycle_slot, retain_reference};
use ccf_kv_spike::retire_queue::{RetireQueue, RetireStep, release_owner, retire_at_most};
use std::collections::VecDeque;
use std::time::Instant;

const BUDGET: usize = 32;

struct Pin(Link);

/// Benchmark an explicitly retained root and count incoming child edges once
/// per live directory. Releasing a pin schedules work, rather than recursing.
#[derive(Default)]
struct Arena {
    tree: NibbleRadix,
    dir_refs: Vec<u32>,
    row_refs: Vec<u32>,
    activation: Vec<Link>,
    retired: RetireQueue,
}

fn children(dir: RadixDir) -> impl Iterator<Item = Link> {
    let mut used = dir.mask;
    std::iter::from_fn(move || {
        if used == 0 {
            return None;
        }
        let slot = used.trailing_zeros() as usize;
        used &= used - 1;
        Some(Link(dir.children[slot]))
    })
}

impl Arena {
    fn count(&mut self, link: Link) -> &mut u32 {
        if link.leaf() {
            &mut self.row_refs[link.index()]
        } else {
            &mut self.dir_refs[link.index()]
        }
    }

    fn retain(&mut self, root: Link) -> Pin {
        self.dir_refs.resize(self.tree.dirs.slots(), 0);
        self.row_refs.resize(self.tree.rows.slots(), 0);
        if !root.empty() {
            self.activation.push(root);
        }
        while let Some(node) = self.activation.pop() {
            let unpublished = retain_reference(self.count(node));
            // Only new directories activate their edges. Existing children
            // of a retained root already have incoming references.
            if unpublished && !node.leaf() {
                self.activation
                    .extend(children(*self.tree.dirs.get(node.index())));
            }
        }
        Pin(root)
    }

    fn drop_ref(&mut self, node: Link) {
        if node.empty() {
            return;
        }
        let count = if node.leaf() {
            &mut self.row_refs[node.index()]
        } else {
            &mut self.dir_refs[node.index()]
        };
        release_owner(count, &mut self.retired, node.0);
    }

    fn release(&mut self, pin: Pin) {
        self.drop_ref(pin.0);
    }

    fn collect(&mut self, budget: usize) -> usize {
        retire_at_most(self, budget)
    }

    fn get(&self, pin: &Pin, key: &[u8]) -> Option<&Value> {
        self.tree.get(pin.0, key)
    }

    fn put(&mut self, pin: &Pin, key: &[u8], value: Value) -> Pin {
        let next = self.tree.put(pin.0, key, value);
        self.retain(next)
    }

    fn remove(&mut self, pin: &Pin, key: &[u8]) -> Pin {
        let next = self.tree.remove(pin.0, key);
        self.retain(next)
    }
}

impl RetireStep for Arena {
    fn retire_one(&mut self) -> bool {
        let Some(raw) = self.retired.pop_front() else {
            return false;
        };
        let link = Link(raw);
        assert_eq!(*self.count(link), 0);
        let i = link.index();
        if link.leaf() {
            recycle_slot(&mut self.tree.rows.slots, &mut self.tree.rows.free, i);
        } else {
            let dir = recycle_slot(&mut self.tree.dirs.slots, &mut self.tree.dirs.free, i);
            for child in children(dir) {
                self.drop_ref(child);
            }
        }
        true
    }
}

fn check_accounting(arena: &Arena, pins: &[&Pin]) {
    let mut dir_refs = vec![0; arena.tree.dirs.slots()];
    let mut row_refs = vec![0; arena.tree.rows.slots()];
    let edges = arena
        .tree
        .dirs
        .slots
        .iter()
        .flatten()
        .flat_map(|dir| dir.children.iter().copied().map(Link));
    for link in pins
        .iter()
        .map(|pin| pin.0)
        .chain(edges)
        .filter(|link| !link.empty())
    {
        if link.leaf() {
            arena.tree.rows.get(link.index());
            row_refs[link.index()] += 1;
        } else {
            arena.tree.dirs.get(link.index());
            dir_refs[link.index()] += 1;
        }
    }
    assert_eq!(dir_refs, arena.dir_refs);
    assert_eq!(row_refs, arena.row_refs);
    let unreferenced = |refs: &[u32], live: &[bool], leaf| {
        refs.iter()
            .zip(live)
            .enumerate()
            .filter(|(_, (n, used))| **n == 0 && **used)
            .map(|(i, _)| link_at(i, leaf))
            .collect::<Vec<_>>()
    };
    let mut retired = unreferenced(
        &dir_refs,
        &arena
            .tree
            .dirs
            .slots
            .iter()
            .map(Option::is_some)
            .collect::<Vec<_>>(),
        false,
    );
    retired.extend(unreferenced(
        &row_refs,
        &arena
            .tree
            .rows
            .slots
            .iter()
            .map(Option::is_some)
            .collect::<Vec<_>>(),
        true,
    ));
    retired.sort_unstable();
    let mut queued: Vec<_> = (0..arena.retired.len())
        .map(|i| arena.retired.get(i).unwrap())
        .collect();
    queued.sort_unstable();
    assert_eq!(queued, retired);
}

pub(crate) fn check() {
    let mut arena = Arena::default();
    let empty = arena.retain(Link::default());
    let one = arena.put(&empty, b"a", [1; 64]);
    let two = arena.put(&one, b"aa", [2; 64]);
    let old = arena.put(&two, b"", [3; 64]);
    let fork = arena.remove(&old, b"a");
    let same = arena.remove(&fork, b"missing");
    let stem = arena.put(&old, b"\xff", [4; 64]);
    for pinned in [empty, one, two, old, fork] {
        arena.release(pinned);
    }
    check_accounting(&arena, &[&same, &stem]);
    assert_eq!(arena.collect(0), 0);
    while arena.collect(1) != 0 {
        check_accounting(&arena, &[&same, &stem]);
        assert_eq!(arena.get(&stem, b"a"), Some(&[1; 64]));
        assert_eq!(arena.get(&stem, b"aa"), Some(&[2; 64]));
        assert_eq!(arena.get(&stem, b""), Some(&[3; 64]));
        assert_eq!(arena.get(&same, b"aa"), Some(&[2; 64]));
        assert_eq!(arena.get(&same, b"a"), None);
    }
    let slots = arena.tree.allocated_slots();
    arena.release(stem);
    arena.release(same);
    while arena.collect(1) != 0 {}
    assert_eq!(arena.tree.live_allocations(), (0, 0));
    let empty = arena.retain(Link::default());
    let fresh = arena.put(&empty, b"", [5; 64]);
    assert_eq!(arena.get(&fresh, b""), Some(&[5; 64]));
    assert_eq!(arena.tree.allocated_slots(), slots);
    check_accounting(&arena, &[&fresh]);

    let mut head = fresh;
    let history = arena.retain(head.0);
    for i in 0_u8..64 {
        let next = arena.put(&head, &[i], [i; 64]);
        arena.release(head);
        head = next;
    }
    let next = arena.remove(&head, &[43]);
    arena.release(head);
    head = next;
    assert!(arena.retired.len() > BUDGET);
    assert_eq!(arena.collect(BUDGET), BUDGET);
    let next = arena.put(&head, &[255], [6; 64]);
    arena.release(head);
    check_accounting(&arena, &[&history, &next]);
    while arena.collect(1) != 0 {
        check_accounting(&arena, &[&history, &next]);
    }
    assert_eq!(arena.get(&history, b""), Some(&[5; 64]));
    assert_eq!(arena.get(&history, &[0]), None);
    assert_eq!(arena.get(&next, &[43]), None);
    assert_eq!(arena.get(&next, &[63]), Some(&[63; 64]));
    assert_eq!(arena.get(&next, &[255]), Some(&[6; 64]));
    arena.release(history);
    arena.release(next);
    while arena.collect(BUDGET) != 0 {}
    assert_eq!(arena.tree.live_allocations(), (0, 0));
}

pub(crate) fn measure_churn() {
    use super::super::byte_radix::{
        CHURN_KEYS as KEYS, CHURN_MUTATIONS as MUTATIONS, CHURN_WINDOW as WINDOW, churn_keys,
    };

    let keys = churn_keys();
    let mut arena = Arena::default();
    let mut head = arena.retain(Link::default());
    for key in &keys {
        let next = arena.put(&head, key, [1; 64]);
        arena.release(head);
        arena.collect(BUDGET);
        head = next;
    }
    let base = arena.retain(head.0);
    let mut recent = VecDeque::with_capacity(WINDOW);
    let mut timings = Vec::with_capacity(MUTATIONS);
    let mut collection = Vec::with_capacity(MUTATIONS);
    let mut peak_pending = 0;
    let start = Instant::now();
    for i in 0..MUTATIONS {
        let step = Instant::now();
        let key = &keys[((i / 2) * 17) % KEYS];
        let next = if i % 2 == 0 {
            arena.remove(&head, key)
        } else {
            arena.put(&head, key, [2; 64])
        };
        recent.push_back(head);
        head = next;
        if recent.len() >= WINDOW {
            arena.release(recent.pop_front().unwrap());
        }
        let at = Instant::now();
        arena.collect(BUDGET);
        collection.push(at.elapsed().as_nanos());
        timings.push(step.elapsed().as_nanos());
        peak_pending = peak_pending.max(arena.retired.len());
    }
    let ns = start.elapsed().as_nanos() as f64 / MUTATIONS as f64;
    assert_eq!(arena.get(&base, &keys[0]), Some(&[1; 64]));
    for key in &keys {
        assert_eq!(arena.get(&head, key), Some(&[2; 64]));
    }
    let (nodes, rows) = arena.tree.live_allocations();
    let (node_slots, row_slots) = arena.tree.allocated_slots();
    assert!(row_slots <= 2 * KEYS + WINDOW);
    for old in recent {
        arena.release(old);
    }
    arena.release(base);
    while arena.collect(BUDGET) != 0 {}
    assert_eq!(arena.tree.live_allocations().1, KEYS);
    arena.release(head);
    while arena.collect(BUDGET) != 0 {}
    assert_eq!(arena.tree.live_allocations(), (0, 0));
    timings.sort_unstable();
    collection.sort_unstable();
    eprintln!(
        "budgeted_nibble_radix churn: {ns:.1} ns/mutation including GC; end-to-end mutation p99 {} ns, \
         GC p99 {} ns; {nodes}/{node_slots} live/allocated nodes, {rows}/{row_slots} live/allocated rows; \
         {peak_pending} peak pending links after GC",
        timings[MUTATIONS * 99 / 100],
        collection[MUTATIONS * 99 / 100],
    );
}
