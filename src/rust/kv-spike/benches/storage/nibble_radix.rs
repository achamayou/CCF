// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use super::Value;
use super::byte_radix::{ByteIndex, Pool, Row};
use ccf_kv_spike::radix::{RADIX_LEAF_TAG as LEAF, RadixDir, first_difference, get, symbol};

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Link(u32);

impl Link {
    fn new(index: usize, leaf: bool) -> Self {
        assert!(index < LEAF as usize - 1, "benchmark arena capacity");
        Self((index as u32 + 1) | if leaf { LEAF } else { 0 })
    }

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
    fn first_child(&self) -> Link;
}

impl DirectoryOps for RadixDir {
    fn child(&self, symbol: usize) -> Link {
        Link(self.children[symbol])
    }

    fn first_child(&self) -> Link {
        self.child(self.mask.trailing_zeros() as usize)
    }
}

#[derive(Default)]
pub struct NibbleRadix {
    dirs: Pool<RadixDir>,
    rows: Pool<Row>,
    path: Vec<(Link, usize)>,
}

impl NibbleRadix {
    fn first_leaf(&self, node: Link) -> Link {
        if node.leaf() {
            node
        } else {
            Link(self.dirs.get(node.index()).first)
        }
    }

    fn closest(&self, mut node: Link, key: &[u8]) -> Link {
        while !node.leaf() {
            let dir = self.dirs.get(node.index());
            let child = dir.child(symbol(key, dir.digit));
            if child.empty() {
                return Link(dir.first);
            }
            node = child;
        }
        node
    }

    fn add_dir(&mut self, mut dir: RadixDir) -> Link {
        dir.first = self.first_leaf(dir.first_child()).0;
        Link::new(self.dirs.add(dir), false)
    }

    fn rebuild(&mut self, mut child: Link) -> Link {
        while let Some((node, sym)) = self.path.pop() {
            let mut dir = *self.dirs.get(node.index());
            dir.set_child(sym, child.0);
            child = if dir.mask.is_power_of_two() {
                dir.first_child()
            } else {
                self.add_dir(dir)
            };
        }
        child
    }
}

impl ByteIndex for NibbleRadix {
    type Root = Link;

    fn get(&self, root: Link, key: &[u8]) -> Option<&Value> {
        get(self.dirs.as_slice(), self.rows.as_slice(), root.0, key)
    }

    fn put(&mut self, root: Link, key: &[u8], value: Value) -> Link {
        let leaf = Link::new(
            self.rows.add(Row {
                key: key.into(),
                value,
            }),
            true,
        );
        if root.empty() {
            return leaf;
        }
        let old = &self.rows.get(self.closest(root, key).index()).key;
        let diff = first_difference(old, key);
        let old_sym = diff.map(|at| symbol(old, at));
        self.path.clear();
        let mut stem = root;
        while !stem.leaf() {
            let dir = self.dirs.get(stem.index());
            if diff.is_some_and(|diff| dir.digit >= diff) {
                break;
            }
            let sym = symbol(key, dir.digit);
            self.path.push((stem, sym));
            stem = dir.child(sym);
        }
        let next = if let Some(at) = diff {
            let mut dir = if !stem.leaf() && self.dirs.get(stem.index()).digit == at {
                *self.dirs.get(stem.index())
            } else {
                let mut dir = RadixDir::empty(at);
                dir.set_child(old_sym.unwrap(), stem.0);
                dir
            };
            dir.set_child(symbol(key, at), leaf.0);
            self.add_dir(dir)
        } else {
            leaf
        };
        self.rebuild(next)
    }

    fn remove(&mut self, root: Link, key: &[u8]) -> Link {
        self.path.clear();
        let mut node = root;
        while !node.empty() {
            if node.leaf() {
                if self.rows.get(node.index()).key.as_ref() == key {
                    return self.rebuild(Link::default());
                }
                break;
            }
            let dir = self.dirs.get(node.index());
            let sym = symbol(key, dir.digit);
            self.path.push((node, sym));
            node = dir.child(sym);
        }
        root
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
