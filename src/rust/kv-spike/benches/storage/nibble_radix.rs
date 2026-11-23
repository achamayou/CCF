// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use super::Value;
use super::byte_radix::{ByteIndex, Pool, Row};
use ccf_kv_spike::radix::{RADIX_LEAF_TAG as LEAF, RadixDir, get, put, remove};

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Link(u32);

impl Link {
    fn empty(self) -> bool {
        self.0 == 0
    }

    fn leaf(self) -> bool {
        self.0 & LEAF != 0
    }

    fn index(self) -> usize {
        ((self.0 & !LEAF) - 1) as usize
    }
}

trait DirectoryOps {
    fn child(&self, symbol: usize) -> Link;
}

impl DirectoryOps for RadixDir {
    fn child(&self, symbol: usize) -> Link {
        Link(self.children[symbol])
    }
}

#[derive(Default)]
pub struct NibbleRadix {
    dirs: Pool<RadixDir>,
    rows: Pool<Row>,
    path: Vec<(u32, usize)>,
}

impl NibbleRadix {
    fn first_leaf(&self, node: Link) -> Link {
        if node.leaf() {
            node
        } else {
            Link(self.dirs.get(node.index()).first)
        }
    }
}

impl ByteIndex for NibbleRadix {
    type Root = Link;

    fn get(&self, root: Link, key: &[u8]) -> Option<&Value> {
        get(self.dirs.as_slice(), self.rows.as_slice(), root.0, key)
    }

    fn put(&mut self, root: Link, key: &[u8], value: Value) -> Link {
        Link(put(
            &mut self.dirs.slots,
            &mut self.dirs.free,
            &mut self.rows.slots,
            &mut self.rows.free,
            &mut self.path,
            root.0,
            Row {
                key: key.into(),
                value,
            },
        ))
    }

    fn remove(&mut self, root: Link, key: &[u8]) -> Link {
        Link(remove(
            &mut self.dirs.slots,
            &mut self.dirs.free,
            self.rows.as_slice(),
            &mut self.path,
            root.0,
            key,
        ))
    }

    fn range(&self, root: Link, first: &[u8], last: &[u8], mut visit: impl FnMut(&[u8], &Value)) {
        if root.empty() || first >= last {
            return;
        }
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.leaf() {
                let Row { key, value } = self.rows.get(node.index());
                if first <= key.as_ref() && key.as_ref() < last {
                    visit(key, value);
                }
                continue;
            }
            let dir = self.dirs.get(node.index());
            let mut mask = dir.mask;
            while mask != 0 {
                let sym = 31 - mask.leading_zeros() as usize;
                mask ^= 1 << sym;
                let child = dir.child(sym);
                let key = &self.rows.get(self.first_leaf(child).index()).key;
                if key.as_ref() < last {
                    stack.push(child);
                    // All earlier children end before this child's first key.
                    if key.as_ref() <= first {
                        break;
                    }
                }
            }
        }
    }

    fn collect(&mut self, roots: &[Link]) {
        let mut dirs = vec![false; self.dirs.slots()];
        let mut rows = vec![false; self.rows.slots()];
        let mut stack: Vec<_> = roots.iter().copied().filter(|r| !r.empty()).collect();
        while let Some(node) = stack.pop() {
            if node.leaf() {
                rows[node.index()] = true;
            } else if !dirs[node.index()] {
                dirs[node.index()] = true;
                let dir = self.dirs.get(node.index());
                stack.extend(
                    dir.children
                        .iter()
                        .copied()
                        .filter(|&link| link != 0)
                        .map(Link),
                );
            }
        }
        self.dirs.sweep(&dirs);
        self.rows.sweep(&rows);
    }

    fn live_allocations(&self) -> (usize, usize) {
        (self.dirs.live(), self.rows.live())
    }

    fn allocated_slots(&self) -> (usize, usize) {
        (self.dirs.slots(), self.rows.slots())
    }
}
