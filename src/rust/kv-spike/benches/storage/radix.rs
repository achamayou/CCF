// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use super::{Key, Value};

pub type Root = Option<usize>;

#[derive(Clone, Copy)]
enum Node {
    Leaf(usize),
    Branch {
        bit: u32,
        mid: u64,
        left: usize,
        right: usize,
    },
}

// Append-only storage keeps old roots valid without atomics or per-node
// allocation. The experiment does not reclaim nodes before dropping the arena.
#[derive(Default)]
pub struct Radix {
    nodes: Vec<Node>,
    rows: Vec<(Key, Value)>,
}

impl Radix {
    fn add(&mut self, node: Node) -> usize {
        let slot = self.nodes.len();
        self.nodes.push(node);
        slot
    }

    fn right(key: u64, bit: u32) -> bool {
        key & (1 << (63 - bit)) != 0
    }

    fn find(&self, mut node: usize, key: u64) -> usize {
        loop {
            match self.nodes[node] {
                Node::Leaf(row) => return row,
                Node::Branch {
                    bit, left, right, ..
                } => {
                    node = if Self::right(key, bit) { right } else { left };
                }
            }
        }
    }

    pub fn get(&self, root: Root, key: &Key) -> Option<&Value> {
        let node = root?;
        let (found, value) = &self.rows[self.find(node, u64::from_be_bytes(*key))];
        (found == key).then_some(value)
    }

    pub fn put(&mut self, root: Root, key: Key, value: Value) -> Root {
        let bits = u64::from_be_bytes(key);
        let split = root.map_or(64, |node| {
            let found = u64::from_be_bytes(self.rows[self.find(node, bits)].0);
            (bits ^ found).leading_zeros()
        });
        let row = self.rows.len();
        self.rows.push((key, value));
        let leaf = self.add(Node::Leaf(row));
        let Some(mut node) = root else {
            return Some(leaf);
        };

        // Branches are ordered by increasing bit offset on each path.
        let mut path = [(0, 0, node, false); 64];
        let mut depth = 0;
        while let Node::Branch {
            bit,
            mid,
            left,
            right,
        } = self.nodes[node]
        {
            if bit >= split {
                break;
            }
            let go_right = Self::right(bits, bit);
            path[depth] = (bit, mid, if go_right { left } else { right }, go_right);
            depth += 1;
            node = if go_right { right } else { left };
        }
        let mut next = if split == 64 {
            leaf
        } else {
            let mask = 1 << (63 - split);
            let mid = (bits & !(mask - 1)) | mask;
            let (left, right) = if Self::right(bits, split) {
                (node, leaf)
            } else {
                (leaf, node)
            };
            self.add(Node::Branch {
                bit: split,
                mid,
                left,
                right,
            })
        };
        for &(bit, mid, sibling, go_right) in path[..depth].iter().rev() {
            let (left, right) = if go_right {
                (sibling, next)
            } else {
                (next, sibling)
            };
            next = self.add(Node::Branch {
                bit,
                mid,
                left,
                right,
            });
        }
        Some(next)
    }

    pub fn range(&self, root: Root, first: &Key, last: &Key) -> usize {
        root.map_or(0, |node| {
            self.sum_node(node, u64::from_be_bytes(*first), u64::from_be_bytes(*last))
        })
    }

    fn sum_node(&self, node: usize, first: u64, last: u64) -> usize {
        match self.nodes[node] {
            Node::Leaf(row) => {
                let (key, value) = &self.rows[row];
                let key = u64::from_be_bytes(*key);
                if first <= key && key < last {
                    usize::from(std::hint::black_box(value)[0])
                } else {
                    0
                }
            }
            Node::Branch {
                mid, left, right, ..
            } => {
                let lower = if first < mid {
                    self.sum_node(left, first, last)
                } else {
                    0
                };
                let upper = if mid < last {
                    self.sum_node(right, first, last)
                } else {
                    0
                };
                lower + upper
            }
        }
    }
}
