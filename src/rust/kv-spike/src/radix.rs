// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//! Routing for the experimental persistent radix index.

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
    pub key: Box<[u8]>,
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

pub fn put<V>(
    dirs: &mut Vec<Option<RadixDir>>,
    free_dirs: &mut Vec<usize>,
    rows: &mut Vec<Option<RadixRow<V>>>,
    free_rows: &mut Vec<usize>,
    path: &mut Vec<(u32, usize)>,
    root: u32,
    row: RadixRow<V>,
) -> u32 {
    if root == 0 {
        return link_at(allocate(rows, free_rows, row), true);
    }
    let (stem, split) = prepare_insert(dirs, rows, path, root, &row.key);
    let leaf = link_at(allocate(rows, free_rows, row), true);
    let child = match split {
        None => leaf,
        Some(split) => {
            let mut dir = split_directory(dirs, stem, &split);
            dir.set_child(split.new_slot, leaf);
            add_directory(dirs, free_dirs, dir)
        }
    };
    rebuild_path(dirs, free_dirs, path, child)
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

#[cfg(test)]
mod tests {
    use super::*;

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
                key: Box::new([0x50]),
                value: 1,
            }),
            Some(RadixRow {
                key: Box::new([0x51]),
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
                key: Box::new([0x10]),
                value: 1,
            }),
            Some(RadixRow {
                key: Box::new([0x11]),
                value: 2,
            }),
            Some(RadixRow {
                key: Box::new([0x20]),
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
    }
}
