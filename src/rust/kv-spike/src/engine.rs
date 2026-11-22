// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//! A single-store KV state machine over finite association lists.

pub type Version = u64;
pub type Term = u64;
pub type Attempt = u64;

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn copy_from(bytes: &[u8]) -> Self {
        let mut result = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            result.push(bytes[i]);
            i += 1;
        }
        Self(result)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn compare(&self, other: &Self) -> i8 {
        let mut i = 0;
        while i < self.0.len() && i < other.0.len() {
            if self.0[i] < other.0[i] {
                return -1;
            }
            if self.0[i] > other.0[i] {
                return 1;
            }
            i += 1;
        }
        if self.0.len() < other.0.len() {
            -1
        } else if self.0.len() > other.0.len() {
            1
        } else {
            0
        }
    }
}

trait Key {
    fn same(&self, other: &Self) -> bool;
}

impl Key for Bytes {
    fn same(&self, other: &Self) -> bool {
        self.compare(other) == 0
    }
}

impl Key for Attempt {
    fn same(&self, other: &Self) -> bool {
        *self == *other
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Address {
    pub map: Bytes,
    pub key: Bytes,
}

impl Key for Address {
    fn same(&self, other: &Self) -> bool {
        self.map.same(&other.map) && self.key.same(&other.key)
    }
}

#[derive(Clone)]
struct Assoc<K, V>(Vec<(K, V)>);

impl<K, V> Assoc<K, V> {
    fn new() -> Self {
        Self(Vec::new())
    }
}

impl<K: Key, V> Assoc<K, V> {
    fn index(&self, key: &K) -> Option<usize> {
        let mut i = 0;
        while i < self.0.len() {
            if self.0[i].0.same(key) {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

impl<K: Key + Clone, V: Clone> Assoc<K, V> {
    fn get(&self, key: &K) -> Option<V> {
        match self.index(key) {
            Some(i) => Some(self.0[i].1.clone()),
            None => None,
        }
    }

    fn erase(&self, key: &K) -> Self {
        let mut out = Vec::new();
        self.copy_other_rows(key, &mut out);
        Self(out)
    }

    fn copy_other_rows(&self, key: &K, out: &mut Vec<(K, V)>) {
        let mut i = 0;
        while i < self.0.len() {
            copy_if_different(out, &self.0[i], key);
            i += 1;
        }
    }

    fn set(&mut self, key: K, value: V) {
        let mut next = Vec::new();
        next.push((key.clone(), value));
        self.copy_other_rows(&key, &mut next);
        self.0 = next;
    }
}

fn copy_if_different<K: Key + Clone, V: Clone>(out: &mut Vec<(K, V)>, row: &(K, V), key: &K) {
    if !row.0.same(key) {
        out.push((row.0.clone(), row.1.clone()));
    }
}

#[derive(Clone)]
struct Cell {
    value: Bytes,
    version: Version,
}

impl Cell {
    fn same(&self, other: &Self) -> bool {
        self.version == other.version && self.value.same(&other.value)
    }
}

#[derive(Clone, Copy)]
struct Stamp {
    version: Version,
    identity: u64,
}

impl Stamp {
    fn zero() -> Self {
        Self {
            version: 0,
            identity: 0,
        }
    }

    fn same(self, other: Self) -> bool {
        self.version == other.version && self.identity == other.identity
    }
}

#[derive(Clone)]
enum Write {
    Put(Bytes),
    Remove,
}

impl Write {
    fn from_option(value: Option<Bytes>) -> Self {
        match value {
            Some(v) => Self::Put(v),
            None => Self::Remove,
        }
    }
}

type Data = Assoc<Address, Cell>;
type Pending = Assoc<Address, Write>;
type Image = Assoc<Bytes, Cell>;
pub type Entries = Vec<(Bytes, Bytes)>;

fn publish(mut data: Data, pending: &Pending, version: Version) -> Data {
    // The reference model folds the ordered write list right-to-left.
    let mut i = pending.0.len();
    while i > 0 {
        i -= 1;
        let row = &pending.0[i];
        match &row.1 {
            Write::Put(v) => data.set(
                row.0.clone(),
                Cell {
                    value: v.clone(),
                    version,
                },
            ),
            Write::Remove => data = data.erase(&row.0),
        }
    }
    data
}

fn image(data: &Data, map: &Bytes) -> Image {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.0.len() {
        copy_if_on_map(&mut out, &data.0[i], map);
        i += 1;
    }
    Assoc(out)
}

fn copy_if_on_map(out: &mut Vec<(Bytes, Cell)>, row: &(Address, Cell), map: &Bytes) {
    if row.0.map.same(map) {
        out.push((row.0.key.clone(), row.1.clone()));
    }
}

fn same_image(a: &Image, b: &Image) -> bool {
    if a.0.len() != b.0.len() {
        return false;
    }
    let mut i = 0;
    while i < a.0.len() {
        if !a.0[i].0.same(&b.0[i].0) || !a.0[i].1.same(&b.0[i].1) {
            return false;
        }
        i += 1;
    }
    true
}

#[derive(Clone)]
struct Frame {
    version: Version,
    data: Data,
    revisions: Assoc<Bytes, Stamp>,
    births: Assoc<Bytes, Stamp>,
}

impl Frame {
    fn empty() -> Self {
        Self {
            version: 0,
            data: Assoc::new(),
            revisions: Assoc::new(),
            births: Assoc::new(),
        }
    }

    fn revision(&self, map: &Bytes) -> Stamp {
        match self.revisions.get(map) {
            Some(stamp) => stamp,
            None => Stamp::zero(),
        }
    }

    fn matches_lineage(&self, map: &Bytes, birth: Option<Stamp>, revision: Stamp) -> bool {
        let same_birth = match (self.births.get(map), birth) {
            (Some(a), Some(b)) => a.same(b),
            (None, None) => true,
            _ => false,
        };
        same_birth && self.revision(map).same(revision)
    }

    fn advance(&self, version: Version, identity: u64, pending: &Pending) -> Self {
        let mut next = self.clone();
        next.version = version;
        let stamp = Stamp { version, identity };
        let mut i = 0;
        while i < pending.0.len() {
            let row = &pending.0[i];
            if matches!(row.1, Write::Put(_)) || self.data.index(&row.0).is_some() {
                next.revisions.set(row.0.map.clone(), stamp);
            }
            if next.births.index(&row.0.map).is_none() {
                next.births.set(row.0.map.clone(), stamp);
            }
            i += 1;
        }
        next.data = publish(next.data, pending, version);
        next
    }
}

#[derive(Clone)]
struct History {
    // Oldest first. The frame at index i has version i, including version zero.
    frames: Vec<Frame>,
    global: Version,
    term: Term,
    next_identity: u64,
}

impl History {
    fn new(term: Term) -> Self {
        let mut frames = Vec::new();
        frames.push(Frame::empty());
        Self {
            frames,
            global: 0,
            term,
            next_identity: 1,
        }
    }

    fn head(&self) -> &Frame {
        &self.frames[self.frames.len() - 1]
    }

    fn at_cut(&self, cut: Version) -> &Frame {
        let head = self.frames.len() - 1;
        if cut < head as Version {
            &self.frames[cut as usize]
        } else {
            &self.frames[head]
        }
    }

    fn map_lineage(&self, map: &Bytes, birth: Option<Stamp>, revision: Stamp) -> bool {
        let mut i = 0;
        while i < self.frames.len() {
            if self.frames[i].matches_lineage(map, birth, revision) {
                return true;
            }
            i += 1;
        }
        false
    }

    fn compact(&mut self, requested: Version) -> Version {
        self.global = compact_cut(self.global, self.head().version, requested);
        self.global
    }

    fn rollback(&mut self, requested: Version, term: Term) -> Result<Output, Error> {
        if requested < self.global {
            return Ok(Output::RollbackRejected);
        }
        if term < self.term {
            return Err(Error::Disabled);
        }
        let head = self.head().version;
        let cut = rollback_cut(self.global, head, requested);
        if cut < head {
            // The cast is lossless: cut is strictly below the head's vector index.
            self.frames.resize(cut as usize + 1, Frame::empty());
        }
        self.term = term;
        Ok(Output::RolledBack(cut))
    }
}

fn compact_cut(global: Version, head: Version, requested: Version) -> Version {
    if requested <= head && global < requested {
        requested
    } else {
        global
    }
}

fn rollback_cut(global: Version, head: Version, requested: Version) -> Version {
    let bounded = if requested < head { requested } else { head };
    if global < bounded { bounded } else { global }
}

#[derive(Clone, Copy)]
struct Snapshot {
    version: Version,
    term: Term,
}

struct View {
    birth: Option<Stamp>,
    revision: Stamp,
    local: Image,
    global: Image,
}

impl Clone for View {
    fn clone(&self) -> Self {
        Self {
            birth: self.birth,
            revision: self.revision,
            local: self.local.clone(),
            global: self.global.clone(),
        }
    }
}

enum Dependency {
    Key(Address, Option<Cell>),
    Map(Bytes, Image),
}

impl Clone for Dependency {
    fn clone(&self) -> Self {
        match self {
            Self::Key(a, cell) => Self::Key(a.clone(), copy_cell(cell)),
            Self::Map(map, image) => Self::Map(map.clone(), image.clone()),
        }
    }
}

fn copy_cell(cell: &Option<Cell>) -> Option<Cell> {
    match cell {
        Some(c) => Some(c.clone()),
        None => None,
    }
}

impl Dependency {
    fn holds(&self, db: &Data) -> bool {
        match self {
            Self::Key(a, expected) => match (db.get(a), expected) {
                (None, None) => true,
                (Some(current), Some(old)) => current.same(old),
                _ => false,
            },
            Self::Map(map, expected) => same_image(&image(db, map), expected),
        }
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Active,
    Committing,
    Applied(Version),
    Finished,
}

struct Tx {
    snapshot: Option<Snapshot>,
    views: Assoc<Bytes, View>,
    pending: Pending,
    deps: Vec<Dependency>,
    unavailable: bool,
    phase: Phase,
}

impl Clone for Tx {
    fn clone(&self) -> Self {
        Self {
            snapshot: self.snapshot,
            views: self.views.clone(),
            pending: self.pending.clone(),
            deps: self.deps.clone(),
            unavailable: self.unavailable,
            phase: self.phase,
        }
    }
}

impl Tx {
    fn new() -> Self {
        Self {
            snapshot: None,
            views: Assoc::new(),
            pending: Assoc::new(),
            deps: Vec::new(),
            unavailable: false,
            phase: Phase::Active,
        }
    }

    fn acquire(&mut self, history: &History, map: Bytes) -> Result<Output, Error> {
        let Some(snapshot) = self.snapshot else {
            return Err(Error::Disabled);
        };
        if !matches!(self.phase, Phase::Active) || self.views.index(&map).is_some() {
            return Err(Error::Disabled);
        }
        let local = history.at_cut(snapshot.version);
        let birth = local.births.get(&map);
        if birth.is_none() {
            self.views.set(
                map,
                View {
                    birth: None,
                    revision: Stamp::zero(),
                    local: Assoc::new(),
                    global: Assoc::new(),
                },
            );
            return Ok(Output::Acquired(0, 0));
        }
        let global = history.at_cut(history.global);
        let revision = local.revision(&map);
        let global_revision = global.revision(&map);
        // This local frame is on the surviving branch, so its lineage is present.
        if revision.version < global_revision.version {
            self.unavailable = true;
            return Ok(Output::Unavailable);
        }
        let pinned = View {
            birth,
            revision,
            local: image(&local.data, &map),
            global: image(&global.data, &map),
        };
        self.views.set(map, pinned);
        Ok(Output::Acquired(revision.version, global_revision.version))
    }

    fn observe(&mut self, a: &Address, view: &View, global: bool) -> Option<Bytes> {
        if global {
            return cell_value(view.global.get(&a.key));
        }
        if let Some(write) = self.pending.get(a) {
            return match write {
                Write::Put(v) => Some(v),
                Write::Remove => None,
            };
        }
        let cell = view.local.get(&a.key);
        let value = cell_value(copy_cell(&cell));
        self.deps.push(Dependency::Key(a.clone(), cell));
        value
    }

    fn scan(&mut self, map: &Bytes, view: &View) -> Entries {
        self.deps
            .push(Dependency::Map(map.clone(), view.local.clone()));
        let mut rows = Assoc::new();
        let mut i = 0;
        while i < view.local.0.len() {
            let row = &view.local.0[i];
            rows.0.push((row.0.clone(), row.1.value.clone()));
            i += 1;
        }
        i = self.pending.0.len();
        while i > 0 {
            i -= 1;
            let row = &self.pending.0[i];
            if row.0.map.same(map) {
                match &row.1 {
                    Write::Put(v) => rows.set(row.0.key.clone(), v.clone()),
                    Write::Remove => rows = rows.erase(&row.0.key),
                }
            }
        }
        rows.0
    }

    fn operate(&mut self, map: Bytes, op: Operation) -> Result<Output, Error> {
        if !matches!(self.phase, Phase::Active) {
            return Err(Error::Disabled);
        }
        let Some(view) = self.views.get(&map) else {
            return Err(Error::Disabled);
        };
        match op {
            Operation::Get(key, global) => Ok(Output::Value(self.observe(
                &Address { map, key },
                &view,
                global,
            ))),
            Operation::Has(key, global) => Ok(Output::Presence(
                self.observe(&Address { map, key }, &view, global).is_some(),
            )),
            Operation::Previous(key) => {
                let cell = view.local.get(&key);
                let version = match &cell {
                    Some(c) => Some(c.version),
                    None => None,
                };
                self.deps.push(Dependency::Key(Address { map, key }, cell));
                Ok(Output::Previous(version))
            }
            Operation::Write(key, value) => {
                self.pending
                    .set(Address { map, key }, Write::from_option(value));
                Ok(Output::Unit)
            }
            Operation::Scan => Ok(Output::Entries(self.scan(&map, &view))),
            Operation::Size => Ok(Output::Size(self.scan(&map, &view).len())),
            Operation::Clear => {
                let entries = self.scan(&map, &view);
                let mut i = 0;
                while i < entries.len() {
                    self.pending.set(
                        Address {
                            map: map.clone(),
                            key: entries[i].0.clone(),
                        },
                        Write::Remove,
                    );
                    i += 1;
                }
                Ok(Output::Unit)
            }
            Operation::Range(lower, upper) => {
                if let (Some(l), Some(u)) = (&lower, &upper) {
                    if l.compare(u) >= 0 {
                        return Ok(Output::Entries(Vec::new()));
                    }
                }
                Ok(Output::Entries(ordered_range(
                    &self.scan(&map, &view),
                    &lower,
                    &upper,
                )))
            }
        }
    }

    fn can_apply(&self, history: &History) -> bool {
        if self.unavailable {
            return false;
        }
        if let Some(snapshot) = self.snapshot {
            if snapshot.term != history.term {
                return false;
            }
        }
        self.valid_lineage(history) && self.valid_dependencies(&history.head().data)
    }

    fn valid_lineage(&self, history: &History) -> bool {
        let mut i = 0;
        while i < self.views.0.len() {
            let row = &self.views.0[i];
            if !history.map_lineage(&row.0, row.1.birth, row.1.revision) {
                return false;
            }
            i += 1;
        }
        true
    }

    fn valid_dependencies(&self, data: &Data) -> bool {
        let mut i = 0;
        while i < self.deps.len() {
            if !self.deps[i].holds(data) {
                return false;
            }
            i += 1;
        }
        true
    }
}

fn cell_value(cell: Option<Cell>) -> Option<Bytes> {
    match cell {
        Some(c) => Some(c.value),
        None => None,
    }
}

fn insertion_index(entries: &Entries, key: &Bytes) -> usize {
    let mut pos = 0;
    while pos < entries.len() && entries[pos].0.compare(key) < 0 {
        pos += 1;
    }
    pos
}

fn ordered_range(entries: &Entries, lower: &Option<Bytes>, upper: &Option<Bytes>) -> Entries {
    let mut out: Entries = Vec::new();
    let mut i = 0;
    while i < entries.len() {
        let row = &entries[i];
        let above_lower = match lower {
            Some(l) => l.compare(&row.0) <= 0,
            None => true,
        };
        let below_upper = match upper {
            Some(u) => row.0.compare(u) < 0,
            None => true,
        };
        if above_lower && below_upper {
            let pos = insertion_index(&out, &row.0);
            // The pinned Aeneas Vec model only supports insert below len.
            if pos == out.len() {
                out.push(row.clone());
            } else {
                out.insert(pos, row.clone());
            }
        }
        i += 1;
    }
    out
}

pub enum Operation {
    Get(Bytes, bool),
    Has(Bytes, bool),
    Previous(Bytes),
    Write(Bytes, Option<Bytes>),
    Scan,
    Size,
    Clear,
    Range(Option<Bytes>, Option<Bytes>),
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum Outcome {
    Success,
    Conflict,
    NoReplicate,
}

pub enum Action {
    Begin(Attempt),
    End(Attempt),
    SetTerm(Term),
    Snapshot(Attempt),
    Acquire(Attempt, Bytes),
    Operate(Attempt, Bytes, Operation),
    CommitBegin(Attempt),
    Apply(Attempt),
    CommitResult(Attempt, Outcome),
    Compact(Version),
    Rollback(Version, Term),
}

#[cfg_attr(test, derive(Debug))]
pub enum Output {
    Unit,
    Snapshot(Version, Version, Term),
    Acquired(Version, Version),
    Unavailable,
    Value(Option<Bytes>),
    Presence(bool),
    Previous(Option<Version>),
    Entries(Entries),
    Size(usize),
    Applied(Version, Term, Vec<(Address, Option<Bytes>)>),
    Committed(Outcome, Version),
    Compacted(Version),
    RolledBack(Version),
    RollbackRejected,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The action is not enabled in the current state.
    Disabled,
    /// Publication would overflow the version or application identity.
    Exhausted,
}

pub struct Store {
    history: History,
    txs: Assoc<Attempt, Tx>,
}

impl Store {
    pub fn new(term: Term) -> Self {
        Self {
            history: History::new(term),
            txs: Assoc::new(),
        }
    }

    /// Execute one transition. A returned error leaves the store and attempt state unchanged.
    pub fn execute(&mut self, action: Action) -> Result<Output, Error> {
        match action {
            Action::Begin(tx) => {
                if self.txs.index(&tx).is_some() {
                    return Err(Error::Disabled);
                }
                self.txs.set(tx, Tx::new());
                Ok(Output::Unit)
            }
            Action::End(tx) => {
                self.tx_index(tx)?;
                self.txs = self.txs.erase(&tx);
                Ok(Output::Unit)
            }
            Action::SetTerm(term) => {
                if term < self.history.term {
                    return Err(Error::Disabled);
                }
                self.history.term = term;
                Ok(Output::Unit)
            }
            Action::Snapshot(tx) => {
                let i = self.tx_index(tx)?;
                let phase = self.txs.0[i].1.phase;
                if !matches!(phase, Phase::Active) || self.txs.0[i].1.snapshot.is_some() {
                    return Err(Error::Disabled);
                }
                let version = self.history.head().version;
                let term = self.history.term;
                self.txs.0[i].1.snapshot = Some(Snapshot { version, term });
                Ok(Output::Snapshot(version, self.history.global, term))
            }
            Action::Acquire(tx, map) => {
                let i = self.tx_index(tx)?;
                self.txs.0[i].1.acquire(&self.history, map)
            }
            Action::Operate(tx, map, op) => {
                let i = self.tx_index(tx)?;
                self.txs.0[i].1.operate(map, op)
            }
            Action::CommitBegin(tx) => {
                let i = self.tx_index(tx)?;
                let t = &mut self.txs.0[i].1;
                if !matches!(t.phase, Phase::Active) {
                    return Err(Error::Disabled);
                }
                t.phase = Phase::Committing;
                Ok(Output::Unit)
            }
            Action::Apply(tx) => self.apply(tx),
            Action::CommitResult(tx, result) => self.finish(tx, result),
            Action::Compact(version) => Ok(Output::Compacted(self.history.compact(version))),
            Action::Rollback(version, term) => self.history.rollback(version, term),
        }
    }

    fn tx_index(&self, tx: Attempt) -> Result<usize, Error> {
        match self.txs.index(&tx) {
            Some(i) => Ok(i),
            None => Err(Error::Disabled),
        }
    }

    fn apply(&mut self, tx: Attempt) -> Result<Output, Error> {
        let i = self.tx_index(tx)?;
        let t = &self.txs.0[i].1;
        if !matches!(t.phase, Phase::Committing)
            || t.pending.0.is_empty()
            || !t.can_apply(&self.history)
        {
            return Err(Error::Disabled);
        }
        let head = self.history.head();
        if head.version == u64::MAX || self.history.next_identity == u64::MAX {
            return Err(Error::Exhausted);
        }
        let version = head.version + 1;
        let next = head.advance(version, self.history.next_identity, &t.pending);
        let writes = reported_writes(&t.pending);
        self.history.frames.push(next);
        self.history.next_identity += 1;
        self.txs.0[i].1.phase = Phase::Applied(version);
        Ok(Output::Applied(version, self.history.term, writes))
    }

    fn finish(&mut self, tx: Attempt, outcome: Outcome) -> Result<Output, Error> {
        let i = self.tx_index(tx)?;
        let t = &mut self.txs.0[i].1;
        let assigned = match t.phase {
            Phase::Applied(v) if !matches!(outcome, Outcome::Conflict) => v,
            Phase::Committing
                if !matches!(outcome, Outcome::Success)
                    || (t.pending.0.is_empty() && !t.unavailable) =>
            {
                0
            }
            _ => return Err(Error::Disabled),
        };
        t.phase = Phase::Finished;
        Ok(Output::Committed(outcome, assigned))
    }
}

fn reported_writes(pending: &Pending) -> Vec<(Address, Option<Bytes>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < pending.0.len() {
        out.push(reported_write(&pending.0[i]));
        i += 1;
    }
    out
}

fn reported_write(row: &(Address, Write)) -> (Address, Option<Bytes>) {
    let value = match &row.1 {
        Write::Put(v) => Some(v.clone()),
        Write::Remove => None,
    };
    (row.0.clone(), value)
}

#[cfg(test)]
mod tests;
