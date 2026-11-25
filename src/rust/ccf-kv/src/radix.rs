// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//! Routing and persistent arena storage for the radix index.

use crate::retire_queue::{RetireQueue, release_owner};

/// Prefix shared by every packed address belonging to `map`.
pub fn map_prefix(map: &[u8]) -> Vec<u8> {
    let length = (map.len() as u64).to_le_bytes();
    let mut encoded = Vec::with_capacity(8 + map.len());
    encoded.extend_from_slice(&length);
    encoded.extend_from_slice(map);
    encoded
}

/// Separate the map and key without reserving any byte value in either.
pub fn address_key(map: &[u8], key: &[u8]) -> Vec<u8> {
    let length = (map.len() as u64).to_le_bytes();
    let mut encoded = Vec::with_capacity(8 + map.len() + key.len());
    encoded.extend_from_slice(&length);
    encoded.extend_from_slice(map);
    encoded.extend_from_slice(key);
    encoded
}

/// Zero is the end-of-key symbol; the high and low nibbles occupy 1..=16.
#[inline]
pub fn symbol(key: &[u8], digit: usize) -> usize {
    let at = digit / 2;
    if at >= key.len() {
        return 0;
    }
    let byte = key[at];
    if digit % 2 == 0 {
        1 + (byte / 16) as usize
    } else {
        1 + (byte % 16) as usize
    }
}

fn byte_difference(index: usize, a: u8, b: u8) -> usize {
    if a / 16 != b / 16 {
        2 * index
    } else {
        2 * index + 1
    }
}

/// The first differing routing digit, including a shorter key's terminator.
#[inline]
pub fn first_difference(a: &[u8], b: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < a.len() && i < b.len() {
        if a[i] != b[i] {
            return Some(byte_difference(i, a[i], b[i]));
        }
        i += 1;
    }
    if a.len() == b.len() {
        None
    } else {
        Some(2 * i)
    }
}

pub const RADIX_FANOUT: usize = 17;
pub const RADIX_LEAF_TAG: u32 = 0x8000_0000;

#[inline]
pub fn link_at(index: usize, leaf: bool) -> u32 {
    assert!(index < 0x7fff_ffff, "radix arena capacity");
    let slot = index as u32 + 1;
    if leaf { RADIX_LEAF_TAG + slot } else { slot }
}

#[derive(Clone, Copy)]
pub struct RadixDir {
    pub digit: usize,
    pub first: u32,
    pub mask: u32,
    pub children: [u32; RADIX_FANOUT],
}

impl RadixDir {
    pub fn empty(digit: usize) -> Self {
        Self {
            digit,
            first: 0,
            mask: 0,
            children: [0; RADIX_FANOUT],
        }
    }

    #[inline]
    pub fn set_child(&mut self, slot: usize, child: u32) {
        self.children[slot] = child;
        if child == 0 {
            self.mask &= !(1_u32 << slot);
        } else {
            self.mask |= 1_u32 << slot;
        }
    }

    #[inline]
    pub fn first_child(&self) -> u32 {
        let mut i = 0;
        while i < RADIX_FANOUT {
            let child = self.children[i];
            if child != 0 {
                return child;
            }
            i += 1;
        }
        0
    }
}

pub struct RadixRow<V> {
    pub key: Vec<u8>,
    pub value: V,
}

/// Add a row or directory, reusing only a vacant slot from the free list.
#[inline]
pub fn allocate<T>(slots: &mut Vec<Option<T>>, free: &mut Vec<usize>, value: T) -> usize {
    let count = free.len();
    if count == 0 {
        let index = slots.len();
        slots.push(Some(value));
        index
    } else {
        let last = count - 1;
        let index = free[last];
        assert!(slots[index].is_none(), "radix free list names a live slot");
        free.resize(last, 0);
        slots[index] = Some(value);
        index
    }
}

/// Return an unreachable live slot to the free list. The caller must establish
/// that no retained root or other live slot refers to this slot.
#[inline]
pub fn recycle_slot<T>(slots: &mut Vec<Option<T>>, free: &mut Vec<usize>, index: usize) -> T {
    let value = match slots[index].take() {
        Some(value) => value,
        None => panic!("recycling a vacant radix slot"),
    };
    free.push(index);
    value
}

/// Return whether the new reference is the first owner of this live slot.
#[inline]
pub fn retain_reference(count: &mut u32) -> bool {
    let first = *count == 0;
    assert!(*count < u32::MAX, "radix reference count exhausted");
    *count += 1;
    first
}

/// Return whether releasing one owner leaves this slot ready for retirement.
#[inline]
pub fn release_reference(count: &mut u32) -> bool {
    assert!(*count > 0, "release of unpinned radix link");
    *count -= 1;
    *count == 0
}

fn directory(dirs: &[Option<RadixDir>], link: u32) -> &RadixDir {
    let index = (link - 1) as usize;
    match &dirs[index] {
        Some(dir) => dir,
        None => panic!("missing radix directory"),
    }
}

pub fn add_directory(
    dirs: &mut Vec<Option<RadixDir>>,
    free: &mut Vec<usize>,
    mut dir: RadixDir,
) -> u32 {
    let first = dir.first_child();
    assert!(first != 0, "cannot publish an empty radix directory");
    dir.first = if first >= RADIX_LEAF_TAG {
        first
    } else {
        directory(dirs, first).first
    };
    link_at(allocate(dirs, free, dir), false)
}

fn copy_parent(
    dirs: &mut Vec<Option<RadixDir>>,
    free: &mut Vec<usize>,
    parent: u32,
    slot: usize,
    child: u32,
) -> u32 {
    let mut dir = *directory(dirs, parent);
    dir.set_child(slot, child);
    if dir.mask.is_power_of_two() {
        dir.first_child()
    } else {
        add_directory(dirs, free, dir)
    }
}

/// Replace the chosen child at each directory, from the innermost one out.
/// The original directories and their links remain in the arena.
pub fn rebuild_path(
    dirs: &mut Vec<Option<RadixDir>>,
    free: &mut Vec<usize>,
    path: &[(u32, usize)],
    mut child: u32,
) -> u32 {
    let mut end = path.len();
    while end > 0 {
        end -= 1;
        let (parent, slot) = path[end];
        child = copy_parent(dirs, free, parent, slot, child);
    }
    child
}

/// Record the traversed parent slots, stopping before a directory at `split`.
#[inline]
pub fn record_path(
    dirs: &[Option<RadixDir>],
    path: &mut Vec<(u32, usize)>,
    root: u32,
    key: &[u8],
    split: Option<usize>,
) -> u32 {
    path.resize(0, (0, 0));
    let mut node = root;
    while node != 0 && node < RADIX_LEAF_TAG {
        let dir = directory(dirs, node);
        if let Some(digit) = split {
            if dir.digit >= digit {
                return node;
            }
        }
        let slot = symbol(key, dir.digit);
        path.push((node, slot));
        node = dir.children[slot];
    }
    node
}

pub fn remove<V>(
    dirs: &mut Vec<Option<RadixDir>>,
    free: &mut Vec<usize>,
    rows: &[Option<RadixRow<V>>],
    path: &mut Vec<(u32, usize)>,
    root: u32,
    key: &[u8],
) -> u32 {
    let leaf = record_path(dirs, path, root, key, None);
    if leaf == 0 {
        return root;
    }
    if check_leaf(rows, leaf, key).is_none() {
        return root;
    }
    rebuild_path(dirs, free, path, 0)
}

fn representative(dirs: &[Option<RadixDir>], mut node: u32, key: &[u8]) -> u32 {
    while node < RADIX_LEAF_TAG {
        let dir = directory(dirs, node);
        let child = dir.children[symbol(key, dir.digit)];
        if child == 0 {
            return dir.first;
        }
        node = child;
    }
    node
}

struct InsertionSplit {
    digit: usize,
    old_slot: usize,
    new_slot: usize,
}

fn prepare_insert<V>(
    dirs: &[Option<RadixDir>],
    rows: &[Option<RadixRow<V>>],
    path: &mut Vec<(u32, usize)>,
    root: u32,
    key: &[u8],
) -> (u32, Option<InsertionSplit>) {
    let previous = row_at(rows, representative(dirs, root, key));
    let difference = first_difference(&previous.key, key);
    let stem = record_path(dirs, path, root, key, difference);
    let split = match difference {
        None => None,
        Some(digit) => Some(InsertionSplit {
            digit,
            old_slot: symbol(&previous.key, digit),
            new_slot: symbol(key, digit),
        }),
    };
    (stem, split)
}

fn split_directory(dirs: &[Option<RadixDir>], stem: u32, split: &InsertionSplit) -> RadixDir {
    if stem < RADIX_LEAF_TAG {
        let existing = directory(dirs, stem);
        if existing.digit == split.digit {
            return *existing;
        }
    }
    let mut dir = RadixDir::empty(split.digit);
    dir.set_child(split.old_slot, stem);
    dir
}

/// Return the new root, the inserted leaf, and any leaf it replaced.
pub fn put<V>(
    dirs: &mut Vec<Option<RadixDir>>,
    free_dirs: &mut Vec<usize>,
    rows: &mut Vec<Option<RadixRow<V>>>,
    free_rows: &mut Vec<usize>,
    path: &mut Vec<(u32, usize)>,
    root: u32,
    row: RadixRow<V>,
) -> (u32, u32, Option<u32>) {
    if root == 0 {
        let leaf = link_at(allocate(rows, free_rows, row), true);
        return (leaf, leaf, None);
    }
    let (stem, split) = prepare_insert(dirs, rows, path, root, &row.key);
    let leaf = link_at(allocate(rows, free_rows, row), true);
    let (child, replaced) = match split {
        None => (leaf, Some(stem)),
        Some(split) => {
            let mut dir = split_directory(dirs, stem, &split);
            dir.set_child(split.new_slot, leaf);
            (add_directory(dirs, free_dirs, dir), None)
        }
    };
    (rebuild_path(dirs, free_dirs, path, child), leaf, replaced)
}

#[derive(Clone, Copy)]
struct BuildFrame {
    end: usize,
    cursor: usize,
    dir: RadixDir,
    parent_slot: usize,
}

fn sorted_frame<V>(
    rows: &[Option<RadixRow<V>>],
    sorted: &[u32],
    begin: usize,
    end: usize,
    parent_slot: usize,
) -> BuildFrame {
    let first = row_at(rows, sorted[begin]);
    let last = row_at(rows, sorted[end - 1]);
    let digit = match first_difference(&first.key, &last.key) {
        Some(digit) => digit,
        None => panic!("bulk radix input must have distinct keys"),
    };
    BuildFrame {
        end,
        cursor: begin,
        dir: RadixDir::empty(digit),
        parent_slot,
    }
}

fn sorted_group_end<V>(
    rows: &[Option<RadixRow<V>>],
    sorted: &[u32],
    begin: usize,
    end: usize,
    digit: usize,
    slot: usize,
) -> usize {
    let mut next = begin + 1;
    while next < end {
        if symbol(&row_at(rows, sorted[next]).key, digit) != slot {
            break;
        }
        next += 1;
    }
    next
}

/// Build one radix from live leaf links in strictly increasing key order.
/// The explicit stack keeps key depth from limiting the native call stack.
pub fn build_sorted<V>(
    dirs: &mut Vec<Option<RadixDir>>,
    free: &mut Vec<usize>,
    rows: &[Option<RadixRow<V>>],
    sorted: &[u32],
) -> u32 {
    let end = sorted.len();
    if end == 0 {
        return 0;
    }
    if end == 1 {
        return sorted[0];
    }
    let mut parents = Vec::new();
    let mut frame = sorted_frame(rows, sorted, 0, end, 0);
    loop {
        if frame.cursor == frame.end {
            let completed = add_directory(dirs, free, frame.dir);
            if parents.is_empty() {
                return completed;
            }
            let depth = parents.len() - 1;
            let mut parent: BuildFrame = parents[depth];
            parents.resize(depth, frame);
            parent.dir.set_child(frame.parent_slot, completed);
            frame = parent;
        } else {
            let begin = frame.cursor;
            let slot = symbol(&row_at(rows, sorted[begin]).key, frame.dir.digit);
            let end = sorted_group_end(rows, sorted, begin, frame.end, frame.dir.digit, slot);
            frame.cursor = end;
            if end == begin + 1 {
                frame.dir.set_child(slot, sorted[begin]);
            } else {
                parents.push(frame);
                frame = sorted_frame(rows, sorted, begin, end, slot);
            }
        }
    }
}

/// Follow directory links until either a leaf or a missing child is reached.
/// The caller owns the arena and keeps all directories reachable from `root` live.
#[inline]
pub fn find_leaf(dirs: &[Option<RadixDir>], root: u32, key: &[u8]) -> u32 {
    let mut node = root;
    while node != 0 && node < RADIX_LEAF_TAG {
        let dir = directory(dirs, node);
        node = dir.children[symbol(key, dir.digit)];
    }
    node
}

fn push_children(stack: &mut Vec<u32>, dir: &RadixDir) {
    let mut slot = RADIX_FANOUT;
    while slot > 0 {
        slot -= 1;
        let child = dir.children[slot];
        if child != 0 {
            stack.push(child);
        }
    }
}

/// Enumerate a compressed root's leaf links in byte-key order.
pub fn scan_leaves(dirs: &[Option<RadixDir>], root: u32) -> Vec<u32> {
    scan_leaves_up_to(dirs, root, usize::MAX)
}

fn has_prefix(key: &[u8], prefix: &[u8]) -> bool {
    if key.len() < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if key[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Descend to the unique subtree containing every key starting with `prefix`.
pub fn find_prefix_subtree<V>(
    dirs: &[Option<RadixDir>],
    rows: &[Option<RadixRow<V>>],
    root: u32,
    prefix: &[u8],
) -> u32 {
    let prefix_digits = 2 * prefix.len();
    let mut node = root;
    while node != 0 && node < RADIX_LEAF_TAG {
        let dir = directory(dirs, node);
        if dir.digit >= prefix_digits {
            break;
        }
        node = dir.children[symbol(prefix, dir.digit)];
    }
    if node == 0 {
        return 0;
    }
    let rep = if node < RADIX_LEAF_TAG {
        directory(dirs, node).first
    } else {
        node
    };
    if has_prefix(&row_at(rows, rep).key, prefix) {
        node
    } else {
        0
    }
}

/// Enumerate every leaf whose key starts with `prefix`, in ascending byte-key order.
pub fn scan_prefix_leaves<V>(
    dirs: &[Option<RadixDir>],
    rows: &[Option<RadixRow<V>>],
    root: u32,
    prefix: &[u8],
) -> Vec<u32> {
    let subtree = find_prefix_subtree(dirs, rows, root, prefix);
    scan_leaves(dirs, subtree)
}

fn scan_leaves_up_to(dirs: &[Option<RadixDir>], root: u32, limit: usize) -> Vec<u32> {
    let mut leaves = Vec::new();
    if root == 0 {
        return leaves;
    }
    let mut stack = Vec::new();
    stack.push(root);
    while stack.len() > 0 && leaves.len() < limit {
        let last = stack.len() - 1;
        let node = stack[last];
        stack.resize(last, 0);
        if node < RADIX_LEAF_TAG {
            push_children(&mut stack, directory(dirs, node));
        } else {
            leaves.push(node);
        }
    }
    leaves
}

/// Borrow a matching row from a live arena. A compressed prefix may route
/// an absent key to an unrelated leaf, so always check the full bytes.
#[inline]
pub fn get<'a, V>(
    dirs: &[Option<RadixDir>],
    rows: &'a [Option<RadixRow<V>>],
    root: u32,
    key: &[u8],
) -> Option<&'a V> {
    let leaf = find_leaf(dirs, root, key);
    if leaf == 0 {
        return None;
    }
    check_leaf(rows, leaf, key)
}

fn row_at<V>(rows: &[Option<RadixRow<V>>], leaf: u32) -> &RadixRow<V> {
    let index = (leaf - RADIX_LEAF_TAG - 1) as usize;
    match &rows[index] {
        Some(row) => row,
        None => panic!("missing radix row"),
    }
}

fn check_leaf<'a, V>(rows: &'a [Option<RadixRow<V>>], leaf: u32, key: &[u8]) -> Option<&'a V> {
    let row = row_at(rows, leaf);
    if <[u8]>::eq(&row.key, key) {
        Some(&row.value)
    } else {
        None
    }
}

struct Arena<V> {
    dirs: Vec<Option<RadixDir>>,
    rows: Vec<Option<RadixRow<V>>>,
    free_dirs: Vec<usize>,
    free_rows: Vec<usize>,
    path: Vec<(u32, usize)>,
}

impl<V> Arena<V> {
    fn new() -> Self {
        Self {
            dirs: Vec::new(),
            rows: Vec::new(),
            free_dirs: Vec::new(),
            free_rows: Vec::new(),
            path: Vec::new(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct RadixRoot(pub(crate) u32);

impl RadixRoot {
    pub(crate) fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[inline]
fn alloc_counted<T>(
    slots: &mut Vec<Option<T>>,
    refs: &mut Vec<u32>,
    free: &mut Vec<usize>,
    value: T,
) -> usize {
    let index = allocate(slots, free, value);
    if index == refs.len() {
        refs.push(0);
    } else {
        assert!(refs[index] == 0, "recycled radix slot still referenced");
    }
    index
}

#[inline]
fn retain_link(dir_refs: &mut Vec<u32>, row_refs: &mut Vec<u32>, link: u32) {
    if link == 0 {
        return;
    }
    if link < RADIX_LEAF_TAG {
        let index = (link - 1) as usize;
        retain_reference(&mut dir_refs[index]);
    } else {
        let index = (link - RADIX_LEAF_TAG - 1) as usize;
        retain_reference(&mut row_refs[index]);
    }
}

#[inline]
fn release_link(
    dir_refs: &mut Vec<u32>,
    row_refs: &mut Vec<u32>,
    retired: &mut RetireQueue,
    link: u32,
) {
    if link == 0 {
        return;
    }
    if link < RADIX_LEAF_TAG {
        let index = (link - 1) as usize;
        release_owner(&mut dir_refs[index], retired, link);
    } else {
        let index = (link - RADIX_LEAF_TAG - 1) as usize;
        release_owner(&mut row_refs[index], retired, link);
    }
}

fn retain_children(dir_refs: &mut Vec<u32>, row_refs: &mut Vec<u32>, dir: &RadixDir) {
    let mut slot = 0;
    while slot < RADIX_FANOUT {
        let child = dir.children[slot];
        if child != 0 {
            retain_link(dir_refs, row_refs, child);
        }
        slot += 1;
    }
}

fn add_directory_counted(
    dirs: &mut Vec<Option<RadixDir>>,
    dir_refs: &mut Vec<u32>,
    row_refs: &mut Vec<u32>,
    free: &mut Vec<usize>,
    mut dir: RadixDir,
) -> u32 {
    let first = dir.first_child();
    assert!(first != 0, "cannot publish an empty radix directory");
    dir.first = if first >= RADIX_LEAF_TAG {
        first
    } else {
        directory(dirs, first).first
    };
    retain_children(dir_refs, row_refs, &dir);
    link_at(alloc_counted(dirs, dir_refs, free, dir), false)
}

fn copy_parent_counted(
    dirs: &mut Vec<Option<RadixDir>>,
    dir_refs: &mut Vec<u32>,
    row_refs: &mut Vec<u32>,
    free: &mut Vec<usize>,
    parent: u32,
    slot: usize,
    child: u32,
) -> u32 {
    let mut dir = *directory(dirs, parent);
    dir.set_child(slot, child);
    if dir.mask.is_power_of_two() {
        dir.first_child()
    } else {
        add_directory_counted(dirs, dir_refs, row_refs, free, dir)
    }
}

fn rebuild_path_counted(
    dirs: &mut Vec<Option<RadixDir>>,
    dir_refs: &mut Vec<u32>,
    row_refs: &mut Vec<u32>,
    free: &mut Vec<usize>,
    path: &[(u32, usize)],
    mut child: u32,
) -> u32 {
    let mut end = path.len();
    while end > 0 {
        end -= 1;
        let (parent, slot) = path[end];
        child = copy_parent_counted(dirs, dir_refs, row_refs, free, parent, slot, child);
    }
    child
}

fn build_sorted_counted<V>(
    dirs: &mut Vec<Option<RadixDir>>,
    dir_refs: &mut Vec<u32>,
    row_refs: &mut Vec<u32>,
    free: &mut Vec<usize>,
    rows: &[Option<RadixRow<V>>],
    sorted: &[u32],
) -> u32 {
    let end = sorted.len();
    if end == 0 {
        return 0;
    }
    if end == 1 {
        return sorted[0];
    }
    let mut parents = Vec::new();
    let mut frame = sorted_frame(rows, sorted, 0, end, 0);
    loop {
        if frame.cursor == frame.end {
            let completed = add_directory_counted(dirs, dir_refs, row_refs, free, frame.dir);
            if parents.is_empty() {
                return completed;
            }
            let depth = parents.len() - 1;
            let mut parent: BuildFrame = parents[depth];
            parents.resize(depth, frame);
            parent.dir.set_child(frame.parent_slot, completed);
            frame = parent;
        } else {
            let begin = frame.cursor;
            let slot = symbol(&row_at(rows, sorted[begin]).key, frame.dir.digit);
            let end = sorted_group_end(rows, sorted, begin, frame.end, frame.dir.digit, slot);
            frame.cursor = end;
            if end == begin + 1 {
                frame.dir.set_child(slot, sorted[begin]);
            } else {
                parents.push(frame);
                frame = sorted_frame(rows, sorted, begin, end, slot);
            }
        }
    }
}

/// Persistent single-arena radix storage ordered by ascending byte key, with
/// exact root/edge reference counting and bounded FIFO retirement.
pub struct SingleRadix<V> {
    values: Arena<V>,
    dir_refs: Vec<u32>,
    row_refs: Vec<u32>,
    retired: RetireQueue,
}

impl<V> SingleRadix<V> {
    pub fn new() -> Self {
        Self {
            values: Arena::new(),
            dir_refs: Vec::new(),
            row_refs: Vec::new(),
            retired: RetireQueue::new(),
        }
    }

    pub fn empty_root(&self) -> RadixRoot {
        RadixRoot(0)
    }

    pub fn retain_root(&mut self, root: RadixRoot) {
        retain_link(&mut self.dir_refs, &mut self.row_refs, root.0);
    }

    pub fn release_root(&mut self, root: RadixRoot) {
        release_link(
            &mut self.dir_refs,
            &mut self.row_refs,
            &mut self.retired,
            root.0,
        );
    }

    /// Reclaim at most one retired directory or leaf back to its free list.
    pub fn retire_one(&mut self) -> bool {
        let Some(link) = self.retired.pop_front() else {
            return false;
        };
        if link < RADIX_LEAF_TAG {
            let index = (link - 1) as usize;
            let dir = recycle_slot(&mut self.values.dirs, &mut self.values.free_dirs, index);
            let mut slot = 0;
            while slot < RADIX_FANOUT {
                let child = dir.children[slot];
                if child != 0 {
                    release_link(
                        &mut self.dir_refs,
                        &mut self.row_refs,
                        &mut self.retired,
                        child,
                    );
                }
                slot += 1;
            }
        } else {
            let index = (link - RADIX_LEAF_TAG - 1) as usize;
            let _ = recycle_slot(&mut self.values.rows, &mut self.values.free_rows, index);
        }
        true
    }

    /// Reclaim up to `budget` retired slots in bounded time.
    pub fn retire_budget(&mut self, budget: usize) -> usize {
        let mut completed = 0;
        while completed < budget {
            if !self.retire_one() {
                break;
            }
            completed += 1;
        }
        completed
    }

    /// Stage one leaf without publishing directories.
    pub fn stage_batch_leaf(&mut self, row: RadixRow<V>) -> u32 {
        link_at(
            alloc_counted(
                &mut self.values.rows,
                &mut self.row_refs,
                &mut self.values.free_rows,
                row,
            ),
            true,
        )
    }

    /// Publish staged leaves given in strictly increasing byte-key order.
    pub fn publish_batch_leaves(&mut self, lookup: &[u32]) -> RadixRoot {
        let root = build_sorted_counted(
            &mut self.values.dirs,
            &mut self.dir_refs,
            &mut self.row_refs,
            &mut self.values.free_dirs,
            &self.values.rows,
            lookup,
        );
        retain_link(&mut self.dir_refs, &mut self.row_refs, root);
        RadixRoot(root)
    }

    /// Publish an unpublished image whose rows are present and in strictly
    /// increasing byte-key order. Returns an owned root.
    pub fn build_sorted_batch(&mut self, mut rows: Vec<Option<RadixRow<V>>>) -> RadixRoot {
        let n = rows.len();
        let mut lookup = Vec::with_capacity(n);
        let mut i = 0;
        while i < n {
            let row = match rows[i].take() {
                Some(row) => row,
                None => panic!("missing sorted batch row"),
            };
            let leaf = self.stage_batch_leaf(row);
            lookup.push(leaf);
            i += 1;
        }
        self.publish_batch_leaves(&lookup)
    }

    pub fn get(&self, root: RadixRoot, key: &[u8]) -> Option<&V> {
        get(&self.values.dirs, &self.values.rows, root.0, key)
    }

    /// Insert or replace `row` on `root` without consuming `root`. Returns an owned root.
    pub fn put(&mut self, root: RadixRoot, row: RadixRow<V>) -> RadixRoot {
        if root.0 == 0 {
            let leaf = link_at(
                alloc_counted(
                    &mut self.values.rows,
                    &mut self.row_refs,
                    &mut self.values.free_rows,
                    row,
                ),
                true,
            );
            retain_link(&mut self.dir_refs, &mut self.row_refs, leaf);
            return RadixRoot(leaf);
        }
        let (stem, split) = prepare_insert(
            &self.values.dirs,
            &self.values.rows,
            &mut self.values.path,
            root.0,
            &row.key,
        );
        let leaf = link_at(
            alloc_counted(
                &mut self.values.rows,
                &mut self.row_refs,
                &mut self.values.free_rows,
                row,
            ),
            true,
        );
        let child = match split {
            None => leaf,
            Some(split) => {
                let mut dir = split_directory(&self.values.dirs, stem, &split);
                dir.set_child(split.new_slot, leaf);
                add_directory_counted(
                    &mut self.values.dirs,
                    &mut self.dir_refs,
                    &mut self.row_refs,
                    &mut self.values.free_dirs,
                    dir,
                )
            }
        };
        let next = rebuild_path_counted(
            &mut self.values.dirs,
            &mut self.dir_refs,
            &mut self.row_refs,
            &mut self.values.free_dirs,
            &self.values.path,
            child,
        );
        retain_link(&mut self.dir_refs, &mut self.row_refs, next);
        RadixRoot(next)
    }

    /// Remove `key` on `root` without consuming `root`. Returns an owned root.
    pub fn remove(&mut self, root: RadixRoot, key: &[u8]) -> RadixRoot {
        let leaf = record_path(
            &self.values.dirs,
            &mut self.values.path,
            root.0,
            key,
            None,
        );
        if leaf == 0 || check_leaf(&self.values.rows, leaf, key).is_none() {
            retain_link(&mut self.dir_refs, &mut self.row_refs, root.0);
            return root;
        }
        let next = rebuild_path_counted(
            &mut self.values.dirs,
            &mut self.dir_refs,
            &mut self.row_refs,
            &mut self.values.free_dirs,
            &self.values.path,
            0,
        );
        retain_link(&mut self.dir_refs, &mut self.row_refs, next);
        RadixRoot(next)
    }

    pub fn scan_links(&self, root: RadixRoot) -> Vec<u32> {
        scan_leaves(&self.values.dirs, root.0)
    }

    pub fn scan_links_up_to(&self, root: RadixRoot, limit: usize) -> Vec<u32> {
        scan_leaves_up_to(&self.values.dirs, root.0, limit)
    }

    pub fn scan_prefix_links(&self, root: RadixRoot, prefix: &[u8]) -> Vec<u32> {
        scan_prefix_leaves(&self.values.dirs, &self.values.rows, root.0, prefix)
    }

    pub fn scan_row(&self, link: u32) -> (&[u8], &V) {
        let row = row_at(&self.values.rows, link);
        (&row.key, &row.value)
    }
}

impl<V> Default for SingleRadix<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorted_batch_handles_prefixes_and_keeps_the_old_root() {
        let mut arena = Arena::new();
        let (old, _, _) = put(
            &mut arena.dirs,
            &mut arena.free_dirs,
            &mut arena.rows,
            &mut arena.free_rows,
            &mut arena.path,
            0,
            RadixRow {
                key: b"a".to_vec(),
                value: 10,
            },
        );
        let keys: [&[u8]; 6] = [b"", b"\0", b"a", b"a\0", b"aa", b"\xff"];
        let links = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let link = link_at(arena.rows.len(), true);
                arena.rows.push(Some(RadixRow {
                    key: key.to_vec(),
                    value: i,
                }));
                link
            })
            .collect::<Vec<_>>();
        let empty = build_sorted(&mut arena.dirs, &mut arena.free_dirs, &arena.rows, &[]);
        assert_eq!(empty, 0);
        let singleton = build_sorted(
            &mut arena.dirs,
            &mut arena.free_dirs,
            &arena.rows,
            &links[..1],
        );
        assert_eq!(singleton, links[0]);
        let root = build_sorted(&mut arena.dirs, &mut arena.free_dirs, &arena.rows, &links);
        assert_eq!(scan_leaves(&arena.dirs, root), links);
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(get(&arena.dirs, &arena.rows, root, key), Some(&i));
        }
        assert_eq!(get(&arena.dirs, &arena.rows, root, b"ab"), None);
        assert_eq!(get(&arena.dirs, &arena.rows, old, b"a"), Some(&10));
        assert_eq!(get(&arena.dirs, &arena.rows, old, b""), None);
    }

    #[test]
    fn address_encoding_distinguishes_empty_maps_and_prefix_boundaries() {
        assert_eq!(address_key(b"", b""), [0; 8]);
        assert_eq!(
            address_key(b"a\0", b"\xff"),
            [2, 0, 0, 0, 0, 0, 0, 0, b'a', 0, 255]
        );
        assert_ne!(address_key(b"a\0", b"\xff"), address_key(b"a", b"\0\xff"));
        assert_ne!(address_key(b"", b"\0"), address_key(b"\0", b""));
    }

    /// Test every pair of byte values, both at the root and below a common prefix.
    #[test]
    fn split_is_the_first_digit_that_differs() {
        fn check(a: &[u8], b: &[u8]) {
            let end = 2 * a.len().max(b.len());
            let expected = (0..=end).find(|&digit| symbol(a, digit) != symbol(b, digit));
            assert_eq!(first_difference(a, b), expected);
        }
        for a in 0..=255 {
            check(&[], &[a]);
            check(&[a, 0], &[a]);
            for b in 0..=255 {
                check(&[a], &[b]);
                check(&[0, 255, a], &[0, 255, b]);
            }
        }
    }

    #[test]
    fn lookup_checks_the_full_key_after_a_compressed_prefix() {
        let left = RADIX_LEAF_TAG + 1;
        let right = RADIX_LEAF_TAG + 2;
        let mut children = [0; RADIX_FANOUT];
        children[symbol(&[0x50], 1)] = left;
        children[symbol(&[0x51], 1)] = right;
        let dirs = [Some(RadixDir {
            digit: 1,
            first: left,
            mask: 0b110,
            children,
        })];
        let rows = [
            Some(RadixRow {
                key: vec![0x50],
                value: 1,
            }),
            Some(RadixRow {
                key: vec![0x51],
                value: 2,
            }),
        ];
        assert_eq!(get(&dirs, &rows, 1, &[0x50]), Some(&1));
        assert_eq!(get(&dirs, &rows, 1, &[0x51]), Some(&2));
        assert_eq!(get(&dirs, &rows, 1, &[0x52]), None);
        assert_eq!(get(&dirs, &rows, 1, &[0x60]), None);
        assert_eq!(get(&dirs, &rows, 1, &[0x50, 0]), None);
        assert_eq!(get(&dirs, &rows, 1, &[]), None);
        assert_eq!(get(&dirs, &rows, 0, &[0x50]), None);
    }

    #[test]
    fn allocation_fills_vacant_slots_without_changing_live_entries() {
        let mut slots = vec![Some(1), None, Some(3), None];
        let mut free = vec![1, 3];
        assert_eq!(allocate(&mut slots, &mut free, 4), 3);
        assert_eq!(allocate(&mut slots, &mut free, 2), 1);
        assert_eq!(allocate(&mut slots, &mut free, 5), 4);
        assert_eq!(slots, [Some(1), Some(2), Some(3), Some(4), Some(5)]);
        assert!(free.is_empty());
    }

    #[test]
    fn path_copy_can_collapse_a_child_without_changing_the_old_root() {
        let rows = [
            Some(RadixRow {
                key: vec![0x10],
                value: 1,
            }),
            Some(RadixRow {
                key: vec![0x11],
                value: 2,
            }),
            Some(RadixRow {
                key: vec![0x20],
                value: 3,
            }),
        ];
        let mut dirs = vec![None];
        let mut free = vec![0];
        let mut low = RadixDir::empty(1);
        low.set_child(symbol(&[0x10], 1), link_at(0, true));
        low.set_child(symbol(&[0x11], 1), link_at(1, true));
        let low_link = add_directory(&mut dirs, &mut free, low);
        let mut high = RadixDir::empty(0);
        high.set_child(symbol(&[0x10], 0), low_link);
        high.set_child(symbol(&[0x20], 0), link_at(2, true));
        let old = add_directory(&mut dirs, &mut free, high);
        let key = &[0x10];
        let mut path = vec![(u32::MAX, usize::MAX)];
        let new = remove(&mut dirs, &mut free, &rows, &mut path, old, key);

        assert_eq!(dirs.len(), 3);
        assert_eq!(path, [(old, symbol(key, 0)), (low_link, symbol(key, 1))]);
        assert_eq!(get(&dirs, &rows, old, key), Some(&1));
        assert_eq!(get(&dirs, &rows, new, key), None);
        assert_eq!(get(&dirs, &rows, old, &[0x11]), Some(&2));
        assert_eq!(get(&dirs, &rows, new, &[0x11]), Some(&2));
        assert_eq!(get(&dirs, &rows, new, &[0x20]), Some(&3));
        let absent = remove(&mut dirs, &mut free, &rows, &mut path, new, &[0x12]);
        assert_eq!(absent, new);
        assert_eq!(dirs.len(), 3);
    }

    #[test]
    fn insertion_preserves_empty_prefixes_and_branches() {
        let mut dirs = Vec::new();
        let mut free_dirs = Vec::new();
        let mut rows = Vec::new();
        let mut free_rows = Vec::new();
        let mut path = Vec::new();
        let mut insert = |root, key: &[u8], value| {
            put(
                &mut dirs,
                &mut free_dirs,
                &mut rows,
                &mut free_rows,
                &mut path,
                root,
                RadixRow {
                    key: key.into(),
                    value,
                },
            )
            .0
        };
        let empty = insert(0, &[], 1);
        let prefix = insert(empty, &[0], 2);
        let extended = insert(prefix, &[0, 0], 3);
        let wide = insert(extended, &[255], 4);
        let newer = insert(wide, &[0], 5);
        let fork = insert(prefix, &[0, 255], 6);
        assert_eq!(get(&dirs, &rows, empty, &[0]), None);
        assert_eq!(get(&dirs, &rows, wide, &[]), Some(&1));
        assert_eq!(get(&dirs, &rows, wide, &[0]), Some(&2));
        assert_eq!(get(&dirs, &rows, newer, &[0]), Some(&5));
        assert_eq!(get(&dirs, &rows, newer, &[0, 0]), Some(&3));
        assert_eq!(get(&dirs, &rows, fork, &[0, 0]), None);
        assert_eq!(get(&dirs, &rows, fork, &[0, 255]), Some(&6));
        assert_eq!(get(&dirs, &rows, fork, &[255]), None);
        assert!(scan_leaves(&dirs, 0).is_empty());
        let leaves = |root| {
            scan_leaves(&dirs, root)
                .into_iter()
                .map(|link| row_at(&rows, link).value)
                .collect::<Vec<_>>()
        };
        assert_eq!(leaves(wide), [1, 2, 3, 4]);
        assert_eq!(leaves(newer), [1, 5, 3, 4]);
        assert_eq!(leaves(fork), [1, 2, 6]);
    }
}
