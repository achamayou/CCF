// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/// Bounded ring-buffered active branch storage.
/// Logical offsets `0..self.len` map to occupied slots starting at `self.head`
/// modulo `self.slots.len()`; all other slots are `None`.
pub struct BranchLog<T> {
    slots: Vec<Option<T>>,
    head: usize,
    len: usize,
}

impl<T> BranchLog<T> {
    pub fn new(base: T) -> Self {
        let mut slots = Vec::new();
        slots.push(Some(base));
        Self {
            slots,
            head: 0,
            len: 1,
        }
    }

    pub fn active_len(&self) -> usize {
        self.len
    }

    fn slot(&self, offset: usize) -> usize {
        let suffix = self.slots.len() - self.head;
        if offset < suffix {
            self.head + offset
        } else {
            offset - suffix
        }
    }

    fn reallocate(&mut self, capacity: usize) {
        let mut next = Vec::with_capacity(capacity);
        let mut i = 0;
        while i < self.len {
            let idx = self.slot(i);
            next.push(self.slots[idx].take());
            i += 1;
        }
        while next.len() < capacity {
            next.push(None);
        }
        self.slots = next;
        self.head = 0;
    }

    fn grow(&mut self) {
        let capacity = 2 * self.slots.len() + 1;
        self.reallocate(capacity);
    }

    pub fn shrink_if_sparse(&mut self) {
        if self.slots.len() <= 64 || self.len >= self.slots.len() / 4 {
            return;
        }
        let capacity = 2 * self.len + 1;
        self.reallocate(capacity);
    }

    pub fn append(&mut self, frame: T) {
        if self.len == self.slots.len() {
            self.grow();
        }
        let idx = self.slot(self.len);
        self.slots[idx] = Some(frame);
        self.len += 1;
    }

    pub fn active_at(&self, offset: usize) -> &T {
        let idx = self.slot(offset);
        match &self.slots[idx] {
            Some(frame) => frame,
            None => panic!("branch slot missing"),
        }
    }

    pub(crate) fn replace_active_at(&mut self, offset: usize, frame: T) -> T {
        let idx = self.slot(offset);
        let mut replacement = Some(frame);
        core::mem::swap(&mut self.slots[idx], &mut replacement);
        match replacement {
            Some(old) => old,
            None => panic!("branch slot missing"),
        }
    }

    pub fn at_cut(&self, offset: u64) -> usize {
        let head = self.len - 1;
        if offset < head as u64 {
            offset as usize
        } else {
            head
        }
    }

    pub fn pop_front(&mut self) -> T {
        let idx = self.head;
        let item = match self.slots[idx].take() {
            Some(frame) => frame,
            None => panic!("branch slot missing"),
        };
        self.head = self.slot(1);
        self.len -= 1;
        item
    }

    pub fn pop_back(&mut self) -> T {
        let idx = self.slot(self.len - 1);
        let item = match self.slots[idx].take() {
            Some(frame) => frame,
            None => panic!("branch slot missing"),
        };
        self.len -= 1;
        item
    }

    pub(crate) fn reset_branch(&mut self, base: T) {
        let mut slots = Vec::new();
        slots.push(Some(base));
        self.slots = slots;
        self.head = 0;
        self.len = 1;
    }

    #[cfg(test)]
    pub(crate) fn slot_capacity(&self) -> usize {
        self.slots.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_wraps_grows_pops_and_shrinks() {
        let mut log = BranchLog::new(0u64);
        assert_eq!(log.active_len(), 1);
        assert_eq!(*log.active_at(0), 0);

        // Steady-state append + pop_front wraps without growing capacity.
        for v in 1..=200u64 {
            log.append(v);
            assert_eq!(log.pop_front(), v - 1);
            assert_eq!(log.active_len(), 1);
            assert_eq!(*log.active_at(0), v);
        }
        assert!(log.slot_capacity() <= 3);

        // Burst growth followed by rollback and shrink.
        for v in 201..=300u64 {
            log.append(v);
        }
        assert_eq!(log.active_len(), 101);
        assert!(log.slot_capacity() > 64);
        assert_eq!(log.at_cut(50), 50);
        assert_eq!(log.at_cut(u64::MAX), 100);
        while log.active_len() > 2 {
            log.pop_back();
        }
        log.shrink_if_sparse();
        assert_eq!(log.active_len(), 2);
        assert_eq!(*log.active_at(0), 200);
        assert_eq!(*log.active_at(1), 201);
        assert!(log.slot_capacity() <= 5);
    }
}
