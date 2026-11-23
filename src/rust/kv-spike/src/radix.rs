// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//! Routing for the experimental persistent radix index.

/// Separate the map and key without reserving any byte value in either.
pub fn address_key(map: &[u8], key: &[u8]) -> Vec<u8> {
    let length = (map.len() as u64).to_le_bytes();
    let mut encoded = Vec::with_capacity(8 + map.len() + key.len());
    encoded.extend_from_slice(&length);
    encoded.extend_from_slice(map);
    encoded.extend_from_slice(key);
    encoded
}

/// Lexicographic enumeration of these keys visits newer stamps first.
pub fn reverse_stamp_key(stamp: u64) -> Vec<u8> {
    (!stamp).to_be_bytes().to_vec()
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
/// Transaction scans still need the model's write order.
pub fn scan_leaves(dirs: &[Option<RadixDir>], root: u32) -> Vec<u32> {
    let mut leaves = Vec::new();
    if root == 0 {
        return leaves;
    }
    let mut stack = Vec::new();
    stack.push(root);
    while stack.len() > 0 {
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

fn matching_leaf<V>(
    dirs: &[Option<RadixDir>],
    rows: &[Option<RadixRow<V>>],
    root: u32,
    key: &[u8],
) -> Option<u32> {
    let leaf = find_leaf(dirs, root, key);
    if leaf == 0 || check_leaf(rows, leaf, key).is_none() {
        None
    } else {
        Some(leaf)
    }
}

fn edit_order(order: &[u32], removed: Option<u32>, added: Option<u32>) -> Vec<u32> {
    let mut next = Vec::new();
    if let Some(leaf) = added {
        next.push(leaf);
    }
    let mut i = 0;
    while i < order.len() {
        let leaf = order[i];
        let keep = match removed {
            None => true,
            Some(old) => old != leaf,
        };
        if keep {
            next.push(leaf);
        }
        i += 1;
    }
    next
}

#[derive(Clone, Copy)]
pub struct Root(usize);

struct OrderedRoot {
    lookup: u32,
    order: Vec<u32>,
}

/// Persistent lookup and scan roots. Pass handles only to their issuing arena.
/// This prototype retains every version without reclamation.
pub struct OrderedRadix<V> {
    dirs: Vec<Option<RadixDir>>,
    rows: Vec<Option<RadixRow<V>>>,
    free_dirs: Vec<usize>,
    free_rows: Vec<usize>,
    path: Vec<(u32, usize)>,
    roots: Vec<OrderedRoot>,
}

impl<V> OrderedRadix<V> {
    pub fn new() -> Self {
        let mut roots = Vec::new();
        roots.push(OrderedRoot {
            lookup: 0,
            order: Vec::new(),
        });
        Self {
            dirs: Vec::new(),
            rows: Vec::new(),
            free_dirs: Vec::new(),
            free_rows: Vec::new(),
            path: Vec::new(),
            roots,
        }
    }

    pub fn empty_root(&self) -> Root {
        Root(0)
    }

    pub fn get(&self, root: Root, key: &[u8]) -> Option<&V> {
        get(&self.dirs, &self.rows, self.roots[root.0].lookup, key)
    }

    pub fn put(&mut self, root: Root, row: RadixRow<V>) -> Root {
        let prior = &self.roots[root.0];
        let (lookup, added, removed) = put(
            &mut self.dirs,
            &mut self.free_dirs,
            &mut self.rows,
            &mut self.free_rows,
            &mut self.path,
            prior.lookup,
            row,
        );
        let order = edit_order(&prior.order, removed, Some(added));
        self.add_root(lookup, order)
    }

    pub fn remove(&mut self, root: Root, key: &[u8]) -> Root {
        let prior = &self.roots[root.0];
        let removed = matching_leaf(&self.dirs, &self.rows, prior.lookup, key);
        if removed.is_none() {
            return root;
        }
        let lookup = remove(
            &mut self.dirs,
            &mut self.free_dirs,
            &self.rows,
            &mut self.path,
            prior.lookup,
            key,
        );
        let order = edit_order(&prior.order, removed, None);
        self.add_root(lookup, order)
    }

    pub fn scan_len(&self, root: Root) -> usize {
        self.roots[root.0].order.len()
    }

    pub fn scan_at(&self, root: Root, i: usize) -> Option<&RadixRow<V>> {
        let order = &self.roots[root.0].order;
        if i >= order.len() {
            return None;
        }
        Some(row_at(&self.rows, order[i]))
    }

    fn add_root(&mut self, lookup: u32, order: Vec<u32>) -> Root {
        let index = self.roots.len();
        self.roots.push(OrderedRoot { lookup, order });
        Root(index)
    }
}

impl<V> Default for OrderedRadix<V> {
    fn default() -> Self {
        Self::new()
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

    fn put(&mut self, root: u32, row: RadixRow<V>) -> (u32, u32, Option<u32>) {
        put(
            &mut self.dirs,
            &mut self.free_dirs,
            &mut self.rows,
            &mut self.free_rows,
            &mut self.path,
            root,
            row,
        )
    }

    fn remove(&mut self, root: u32, key: &[u8]) -> u32 {
        remove(
            &mut self.dirs,
            &mut self.free_dirs,
            &self.rows,
            &mut self.path,
            root,
            key,
        )
    }
}

#[derive(Clone, Copy)]
pub struct DualRoot {
    lookup: u32,
    order: u32,
}

struct Stamped<V> {
    stamp: u64,
    value: V,
}

/// Persistent ordered storage with a byte-key radix and a write-stamp radix.
/// The two roots refer to the issuing arena, which is currently append-only.
pub struct DualRadix<V> {
    values: Arena<Stamped<V>>,
    order: Arena<u32>,
    last: u64,
}

impl<V> DualRadix<V> {
    pub fn new() -> Self {
        Self {
            values: Arena::new(),
            order: Arena::new(),
            last: 0,
        }
    }

    pub fn empty_root(&self) -> DualRoot {
        DualRoot {
            lookup: 0,
            order: 0,
        }
    }

    pub fn get(&self, root: DualRoot, key: &[u8]) -> Option<&V> {
        match get(&self.values.dirs, &self.values.rows, root.lookup, key) {
            Some(cell) => Some(&cell.value),
            None => None,
        }
    }

    pub fn put(&mut self, root: DualRoot, row: RadixRow<V>) -> DualRoot {
        assert!(self.last < u64::MAX, "radix stamp capacity");
        let stamp = self.last + 1;
        let (lookup, leaf, old) = self.values.put(
            root.lookup,
            RadixRow {
                key: row.key,
                value: Stamped {
                    stamp,
                    value: row.value,
                },
            },
        );
        let mut order = root.order;
        if let Some(old) = old {
            let previous = row_at(&self.values.rows, old).value.stamp;
            order = self.order.remove(order, &reverse_stamp_key(previous));
        }
        let (order, _, _) = self.order.put(
            order,
            RadixRow {
                key: reverse_stamp_key(stamp),
                value: leaf,
            },
        );
        self.last = stamp;
        DualRoot { lookup, order }
    }

    pub fn remove(&mut self, root: DualRoot, key: &[u8]) -> DualRoot {
        match get(&self.values.dirs, &self.values.rows, root.lookup, key) {
            None => root,
            Some(row) => {
                let order = self.order.remove(root.order, &reverse_stamp_key(row.stamp));
                let lookup = self.values.remove(root.lookup, key);
                DualRoot { lookup, order }
            }
        }
    }

    pub fn scan_links(&self, root: DualRoot) -> Vec<u32> {
        let mut links = scan_leaves(&self.order.dirs, root.order);
        let mut i = 0;
        while i < links.len() {
            links[i] = row_at(&self.order.rows, links[i]).value;
            i += 1;
        }
        links
    }

    /// Otherwise private link decoding for the storage benchmark.
    pub fn scan_row(&self, link: u32) -> (&[u8], &V) {
        let row = row_at(&self.values.rows, link);
        (&row.key, &row.value.value)
    }
}

impl<V> Default for DualRadix<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_radix_keeps_write_order_after_fork_and_removal() {
        let mut arena = DualRadix::new();
        let mut write = |root, key: &[u8], value| {
            arena.put(
                root,
                RadixRow {
                    key: key.into(),
                    value,
                },
            )
        };
        let first = DualRoot {
            lookup: 0,
            order: 0,
        };
        let base = write(first, b"a", 1);
        let base = write(base, b"", 2);
        let base = write(base, b"aa", 3);
        let replaced = write(base, b"a", 4);
        let fork = write(base, b"\xff", 5);
        let removed = arena.remove(replaced, b"");
        let unchanged = arena.remove(removed, b"absent");
        let scan = |root| {
            arena
                .scan_links(root)
                .into_iter()
                .map(|link| {
                    let (key, value) = arena.scan_row(link);
                    (key, *value)
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(scan(first), []);
        assert_eq!(scan(base), [(b"aa".as_slice(), 3), (b"", 2), (b"a", 1)]);
        assert_eq!(scan(replaced), [(b"a".as_slice(), 4), (b"aa", 3), (b"", 2)]);
        assert_eq!(scan(removed), [(b"a".as_slice(), 4), (b"aa", 3)]);
        assert_eq!(
            scan(fork),
            [(b"\xff".as_slice(), 5), (b"aa", 3), (b"", 2), (b"a", 1)]
        );
        assert_eq!(scan(unchanged), scan(removed));
        assert_eq!(arena.get(removed, b""), None);
        assert_eq!(arena.get(base, b""), Some(&2));
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

    #[test]
    fn ordered_roots_preserve_write_order_across_replacement_and_forks() {
        let mut arena = OrderedRadix::new();
        let empty = arena.empty_root();
        let mut insert = |root, key: &[u8], value| {
            arena.put(
                root,
                RadixRow {
                    key: key.into(),
                    value,
                },
            )
        };
        let old = insert(empty, b"a", 1);
        let old = insert(old, b"", 2);
        let old = insert(old, b"aa", 3);
        let replaced = insert(old, b"a", 4);
        let fork = arena.remove(old, b"");
        let unchanged = arena.remove(fork, b"missing");
        assert_eq!(unchanged.0, fork.0);
        let scan = |root| {
            (0..arena.scan_len(root))
                .map(|i| {
                    let row = arena.scan_at(root, i).unwrap();
                    (row.key.as_ref(), row.value)
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(scan(empty), []);
        assert_eq!(scan(old), [(b"aa".as_slice(), 3), (b"", 2), (b"a", 1)]);
        assert_eq!(scan(replaced), [(b"a".as_slice(), 4), (b"aa", 3), (b"", 2)]);
        assert_eq!(scan(fork), [(b"aa".as_slice(), 3), (b"a", 1)]);
        assert!(arena.scan_at(old, 3).is_none());
        assert_eq!(arena.get(replaced, b"a"), Some(&4));
        assert_eq!(arena.get(old, b"a"), Some(&1));
        assert_eq!(arena.get(fork, b""), None);
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
