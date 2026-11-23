// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#[derive(Clone, Copy)]
pub struct FrameId(usize);

/// Experimental snapshot storage. Rollback truncates the active branch, not
/// the immutable frames; IDs are local to the issuing log and are never reused.
pub struct BranchLog<T> {
    frames: Vec<T>,
    branch: Vec<usize>,
}

impl<T> BranchLog<T> {
    pub fn new(base: T) -> Self {
        let mut frames = Vec::new();
        frames.push(base);
        let mut branch = Vec::new();
        branch.push(0);
        Self { frames, branch }
    }

    pub fn append(&mut self, frame: T) -> FrameId {
        let id = self.frames.len();
        self.frames.push(frame);
        self.branch.push(id);
        FrameId(id)
    }

    pub fn resolve(&self, offset: usize) -> Option<FrameId> {
        if offset < self.branch.len() {
            Some(FrameId(self.branch[offset]))
        } else {
            None
        }
    }

    pub fn at_cut(&self, offset: u64) -> FrameId {
        let head = self.branch.len() - 1;
        let i = if offset < head as u64 {
            offset as usize
        } else {
            head
        };
        FrameId(self.branch[i])
    }

    pub fn read(&self, id: FrameId) -> &T {
        &self.frames[id.0]
    }

    pub fn rewind(&mut self, offset: usize) -> bool {
        if offset >= self.branch.len() {
            return false;
        }
        self.branch.resize(offset + 1, 0);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_can_be_reused_but_old_frame_ids_keep_their_contents() {
        let mut log = BranchLog::new("base");
        let first = log.append("first");
        let discarded = log.append("discarded");
        let pinned = log.resolve(2).unwrap();
        assert!(!log.rewind(3));
        assert_eq!(*log.read(log.resolve(2).unwrap()), "discarded");
        assert!(log.rewind(1));
        assert!(log.resolve(2).is_none());
        assert_eq!(log.at_cut(u64::MAX).0, first.0);
        let replacement = log.append("replacement");
        assert_ne!(replacement.0, discarded.0);
        assert_eq!(log.at_cut(2).0, replacement.0);
        assert_eq!(*log.read(log.resolve(0).unwrap()), "base");
        assert_eq!(*log.read(log.resolve(2).unwrap()), "replacement");
        assert_eq!(*log.read(first), "first");
        assert_eq!(*log.read(pinned), "discarded");
        assert!(log.rewind(0));
        assert_eq!(*log.read(replacement), "replacement");
    }
}
