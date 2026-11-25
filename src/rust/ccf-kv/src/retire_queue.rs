// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use crate::radix::release_reference;

/// FIFO for pending retirements, with an explicit representation for extraction.
pub struct RetireQueue {
    slots: Vec<u32>,
    head: usize,
    len: usize,
}

impl RetireQueue {
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            head: 0,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn slot(&self, offset: usize) -> usize {
        let suffix = self.slots.len() - self.head;
        if offset < suffix {
            self.head + offset
        } else {
            offset - suffix
        }
    }

    pub fn get(&self, offset: usize) -> Option<u32> {
        if offset < self.len {
            Some(self.slots[self.slot(offset)])
        } else {
            None
        }
    }

    fn grow(&mut self) {
        let capacity = 2 * self.slots.len() + 1;
        let mut slots = Vec::with_capacity(capacity);
        let mut i = 0;
        while i < self.len {
            slots.push(self.slots[self.slot(i)]);
            i += 1;
        }
        slots.resize(capacity, 0);
        self.slots = slots;
        self.head = 0;
    }

    pub fn push_back(&mut self, link: u32) {
        if self.len == self.slots.len() {
            self.grow();
        }
        let index = self.slot(self.len);
        self.slots[index] = link;
        self.len += 1;
    }

    pub fn pop_front(&mut self) -> Option<u32> {
        if self.len == 0 {
            return None;
        }
        let link = self.slots[self.head];
        self.head = self.slot(1);
        self.len -= 1;
        Some(link)
    }
}

impl Default for RetireQueue {
    fn default() -> Self {
        Self::new()
    }
}

pub fn release_owner(count: &mut u32, retired: &mut RetireQueue, link: u32) {
    if release_reference(count) {
        retired.push_back(link);
    }
}

pub trait RetireStep {
    fn retire_one(&mut self) -> bool;
}

pub fn retire_at_most<T: RetireStep>(worker: &mut T, budget: usize) -> usize {
    let mut completed = 0;
    while completed < budget {
        if !worker.retire_one() {
            break;
        }
        completed += 1;
    }
    completed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn wrap_grow_and_drain_match_fifo_order() {
        let mut queue = RetireQueue::new();
        let mut expected = VecDeque::new();
        for wave in 1..64 {
            for value in 0..wave {
                let link = 100 * wave + value;
                queue.push_back(link);
                expected.push_back(link);
            }
            for _ in 0..wave / 2 {
                assert_eq!(queue.pop_front(), expected.pop_front());
            }
            assert_eq!(queue.len(), expected.len());
            for (i, link) in expected.iter().enumerate() {
                assert_eq!(queue.get(i), Some(*link));
            }
            assert_eq!(queue.get(expected.len()), None);
        }
        while let Some(link) = expected.pop_front() {
            assert_eq!(queue.pop_front(), Some(link));
        }
        assert!(queue.is_empty());
        assert_eq!(queue.pop_front(), None);
        queue.push_back(0);
        assert_eq!(queue.pop_front(), Some(0));
    }
}
