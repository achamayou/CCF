// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//! A Rust KV prototype, with the original fixed-size extraction spike retained for comparison.

pub mod branch_log;
pub mod engine;
pub mod radix;

#[derive(Clone, Copy)]
pub enum Map {
    A,
    B,
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum Value {
    Empty,
    Byte(u8),
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Cell {
    pub value: Value,
    pub version: u64,
}

#[derive(Clone, Copy)]
enum Write {
    Keep,
    Remove,
    Put(Value),
}

impl Write {
    fn pending(self) -> bool {
        !matches!(self, Self::Keep)
    }

    fn publish(self, before: Option<Cell>, version: u64) -> Option<Cell> {
        match self {
            Self::Keep => before,
            Self::Remove => None,
            Self::Put(value) => Some(Cell { value, version }),
        }
    }
}

struct Slot {
    snapshot: Option<Cell>,
    read_snapshot: bool,
    write: Write,
}

impl Slot {
    fn new(snapshot: Option<Cell>) -> Self {
        Self {
            snapshot,
            read_snapshot: false,
            write: Write::Keep,
        }
    }

    fn read(&mut self) -> Option<Value> {
        match self.write {
            Write::Keep => {
                self.read_snapshot = true;
                match self.snapshot {
                    Some(cell) => Some(cell.value),
                    None => None,
                }
            }
            Write::Remove => None,
            Write::Put(value) => Some(value),
        }
    }

    fn validates(&self, head: Option<Cell>) -> bool {
        if !self.read_snapshot {
            return true;
        }
        match (self.snapshot, head) {
            (None, None) => true,
            (Some(snapshot), Some(head)) => {
                snapshot.version == head.version
                    && match (snapshot.value, head.value) {
                        (Value::Empty, Value::Empty) => true,
                        (Value::Byte(a), Value::Byte(b)) => a == b,
                        _ => false,
                    }
            }
            _ => false,
        }
    }
}

pub struct Tx {
    a: Slot,
    b: Slot,
}

impl Tx {
    pub fn get(&mut self, map: Map) -> Option<Value> {
        match map {
            Map::A => self.a.read(),
            Map::B => self.b.read(),
        }
    }

    pub fn put(&mut self, map: Map, value: Value) {
        self.write(map, Write::Put(value));
    }

    pub fn remove(&mut self, map: Map) {
        self.write(map, Write::Remove);
    }

    fn write(&mut self, map: Map, write: Write) {
        match map {
            Map::A => self.a.write = write,
            Map::B => self.b.write = write,
        }
    }
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum Apply {
    ReadOnly,
    Applied(u64),
    Conflict,
    VersionExhausted,
}

pub struct Store {
    version: u64,
    a: Option<Cell>,
    b: Option<Cell>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub const fn new() -> Self {
        Self {
            version: 0,
            a: None,
            b: None,
        }
    }

    pub fn snapshot(&self) -> Tx {
        Tx {
            a: Slot::new(self.a),
            b: Slot::new(self.b),
        }
    }

    pub fn head(&self, map: Map) -> Option<Cell> {
        match map {
            Map::A => self.a,
            Map::B => self.b,
        }
    }

    pub fn apply(&mut self, tx: Tx) -> Apply {
        if !tx.a.write.pending() && !tx.b.write.pending() {
            return Apply::ReadOnly;
        }
        if !tx.a.validates(self.a) || !tx.b.validates(self.b) {
            return Apply::Conflict;
        }
        if self.version == u64::MAX {
            return Apply::VersionExhausted;
        }
        let version = self.version + 1;
        *self = Self {
            version,
            a: tx.a.write.publish(self.a, version),
            b: tx.b.write.publish(self.b, version),
        };
        Apply::Applied(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishes_both_maps_and_rejects_a_stale_absence_read() {
        let mut store = Store::new();
        let mut stale = store.snapshot();
        assert_eq!(stale.get(Map::A), None);
        stale.put(Map::B, Value::Byte(42));

        let mut writer = store.snapshot();
        writer.put(Map::A, Value::Byte(255));
        writer.put(Map::B, Value::Empty);
        assert_eq!(writer.get(Map::B), Some(Value::Empty));
        assert_eq!(store.apply(writer), Apply::Applied(1));

        assert_eq!(store.apply(stale), Apply::Conflict);
        assert_eq!(
            store.head(Map::A),
            Some(Cell {
                value: Value::Byte(255),
                version: 1,
            })
        );
        assert_eq!(
            store.head(Map::B),
            Some(Cell {
                value: Value::Empty,
                version: 1,
            })
        );
    }

    #[test]
    fn removing_masks_the_snapshot_without_adding_a_read_dependency() {
        let mut store = Store::new();
        let mut seed = store.snapshot();
        seed.put(Map::A, Value::Empty);
        assert_eq!(store.apply(seed), Apply::Applied(1));

        let mut remove = store.snapshot();
        remove.remove(Map::A);
        assert_eq!(remove.get(Map::A), None);

        let mut writer = store.snapshot();
        writer.put(Map::A, Value::Byte(42));
        assert_eq!(store.apply(writer), Apply::Applied(2));
        assert_eq!(store.apply(remove), Apply::Applied(3));
        assert_eq!(store.head(Map::A), None);
        assert_eq!(store.apply(store.snapshot()), Apply::ReadOnly);
        assert_eq!(store.version, 3);
    }

    #[test]
    fn same_value_at_a_new_version_invalidates_a_read() {
        let mut store = Store::new();
        let mut seed = store.snapshot();
        seed.put(Map::A, Value::Empty);
        assert_eq!(store.apply(seed), Apply::Applied(1));

        let mut stale = store.snapshot();
        assert_eq!(stale.get(Map::A), Some(Value::Empty));
        stale.put(Map::B, Value::Byte(42));

        let mut writer = store.snapshot();
        writer.put(Map::A, Value::Empty);
        assert_eq!(store.apply(writer), Apply::Applied(2));
        assert_eq!(store.apply(stale), Apply::Conflict);
        assert_eq!(store.head(Map::B), None);
        assert_eq!(store.version, 2);
    }

    #[test]
    fn version_exhaustion_does_not_publish() {
        let mut store = Store {
            version: u64::MAX,
            ..Store::new()
        };
        let mut writer = store.snapshot();
        writer.put(Map::A, Value::Empty);
        assert_eq!(store.apply(writer), Apply::VersionExhausted);
        assert_eq!(store.head(Map::A), None);
        assert_eq!(store.version, u64::MAX);
    }
}
