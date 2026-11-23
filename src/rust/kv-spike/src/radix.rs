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

/// Follow directory links until either a leaf or a missing child is reached.
/// The caller owns the arena and keeps all directories reachable from `root` live.
#[inline]
pub fn find_leaf(dirs: &[Option<RadixDir>], root: u32, key: &[u8]) -> u32 {
    let mut node = root;
    while node != 0 && node < RADIX_LEAF_TAG {
        let index = (node - 1) as usize;
        let dir = match &dirs[index] {
            Some(dir) => dir,
            None => panic!("missing radix directory"),
        };
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

fn check_leaf<'a, V>(rows: &'a [Option<RadixRow<V>>], leaf: u32, key: &[u8]) -> Option<&'a V> {
    let index = (leaf - RADIX_LEAF_TAG - 1) as usize;
    let row = match &rows[index] {
        Some(row) => row,
        None => panic!("missing radix row"),
    };
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
}
