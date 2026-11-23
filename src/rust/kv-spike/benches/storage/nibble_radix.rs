// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use super::Value;
use super::byte_radix::{ByteIndex, Pool, Row};

// Compact benchmark arena links: zero is absent, and high bit tags leaf rows.
const LEAF: u32 = 1 << 31;
const FANOUT: usize = 17;

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

#[derive(Clone, Copy)]
struct Dir {
    at: usize,
    first: Link,
    mask: u32,
    children: [Link; FANOUT],
}

impl Dir {
    fn new(at: usize) -> Self {
        Self {
            at,
            first: Link::default(),
            mask: 0,
            children: [Link::default(); FANOUT],
        }
    }

    fn set(&mut self, symbol: usize, child: Link) {
        self.children[symbol] = child;
        if child.empty() {
            self.mask &= !(1 << symbol);
        } else {
            self.mask |= 1 << symbol;
        }
    }

    fn first_child(&self) -> Link {
        self.children[self.mask.trailing_zeros() as usize]
    }
}

fn symbol(key: &[u8], at: usize) -> usize {
    match key.get(at >> 1) {
        None => 0,
        Some(b) => 1 + usize::from(if at & 1 == 0 { b >> 4 } else { b & 15 }),
    }
}

fn differing_nibble(a: &[u8], b: &[u8]) -> Option<usize> {
    for (i, (a, b)) in a.iter().zip(b).enumerate() {
        let x = a ^ b;
        if x != 0 {
            return Some(i * 2 + usize::from(x < 16));
        }
    }
    (a.len() != b.len()).then(|| a.len().min(b.len()) * 2)
}

#[derive(Default)]
pub struct NibbleRadix {
    dirs: Pool<Dir>,
    rows: Pool<Row>,
    path: Vec<(Link, usize)>,
}

impl NibbleRadix {
    fn first_leaf(&self, node: Link) -> Link {
        if node.leaf() {
            node
        } else {
            self.dirs.get(node.index()).first
        }
    }

    fn closest(&self, mut node: Link, key: &[u8]) -> Link {
        while !node.leaf() {
            let dir = self.dirs.get(node.index());
            let child = dir.children[symbol(key, dir.at)];
            if child.empty() {
                return dir.first;
            }
            node = child;
        }
        node
    }

    fn add_dir(&mut self, mut dir: Dir) -> Link {
        dir.first = self.first_leaf(dir.first_child());
        Link::new(self.dirs.add(dir), false)
    }

    fn rebuild(&mut self, mut child: Link) -> Link {
        while let Some((node, sym)) = self.path.pop() {
            let mut dir = *self.dirs.get(node.index());
            dir.set(sym, child);
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

    fn get(&self, mut node: Link, key: &[u8]) -> Option<&Value> {
        while !node.empty() {
            if node.leaf() {
                let row = self.rows.get(node.index());
                return (row.key.as_ref() == key).then_some(&row.value);
            }
            let dir = self.dirs.get(node.index());
            node = dir.children[symbol(key, dir.at)];
        }
        None
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
        let diff = differing_nibble(old, key);
        let old_sym = diff.map(|at| symbol(old, at));
        self.path.clear();
        let mut stem = root;
        while !stem.leaf() {
            let dir = self.dirs.get(stem.index());
            if diff.is_some_and(|diff| dir.at >= diff) {
                break;
            }
            let sym = symbol(key, dir.at);
            self.path.push((stem, sym));
            stem = dir.children[sym];
        }
        let next = if let Some(at) = diff {
            let mut dir = if !stem.leaf() && self.dirs.get(stem.index()).at == at {
                *self.dirs.get(stem.index())
            } else {
                let mut dir = Dir::new(at);
                dir.set(old_sym.unwrap(), stem);
                dir
            };
            dir.set(symbol(key, at), leaf);
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
            let sym = symbol(key, dir.at);
            self.path.push((node, sym));
            node = dir.children[sym];
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
                let child = dir.children[sym];
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
                stack.extend(dir.children.iter().filter(|link| !link.empty()));
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
