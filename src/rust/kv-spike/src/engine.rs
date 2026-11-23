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
        Self(bytes.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn same_slice(&self, other: &Self) -> bool {
        <[u8]>::eq(self.as_slice(), other.as_slice())
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
        self.same_slice(other)
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
        self.key.same_slice(&other.key) && self.map.same_slice(&other.map)
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
        self.index_from(key, 0)
    }

    fn index_from(&self, key: &K, mut i: usize) -> Option<usize> {
        while i < self.0.len() {
            if self.0[i].0.same(key) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn get_ref(&self, key: &K) -> Option<&V> {
        match self.index(key) {
            Some(i) => Some(&self.0[i].1),
            None => None,
        }
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
        if let Some(first) = self.index(&key) {
            let end = first + 1;
            if self.index_from(&key, end).is_some() {
                self.replace_and_prepend(key, value);
            } else {
                self.rotate_replacement((key, value), end);
            }
        } else if self.0.is_empty() {
            self.0.push((key, value));
        } else {
            self.0.insert(0, (key, value));
        }
    }

    fn rotate_replacement(&mut self, mut carry: (K, V), end: usize) {
        let mut i = 0;
        while i < end {
            core::mem::swap(&mut self.0[i], &mut carry);
            i += 1;
        }
    }

    fn replace_and_prepend(&mut self, key: K, value: V) {
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

fn publish(data: &Data, pending: &Pending, version: Version) -> Data {
    if pending.0.len() >= 64 {
        if let Some(next) = publish_batch(data, pending, version) {
            return next;
        }
    }
    publish_sequential(data.clone(), pending, version)
}

fn publish_sequential(mut data: Data, pending: &Pending, version: Version) -> Data {
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

type Buckets = Vec<Vec<usize>>;

fn empty_buckets() -> Buckets {
    let mut buckets = Vec::new();
    let mut i = 0_usize;
    while i < 256 {
        buckets.push(Vec::new());
        i += 1;
    }
    buckets
}

fn bucket_for(address: &Address) -> usize {
    let key = &address.key.0;
    if key.is_empty() {
        0
    } else {
        key[key.len() - 1] as usize
    }
}

fn bucket_contains(bucket: &Vec<usize>, pending: &Pending, address: &Address) -> bool {
    let mut i = 0;
    while i < bucket.len() {
        if pending.0[bucket[i]].0.same(address) {
            return true;
        }
        i += 1;
    }
    false
}

fn stage_batch(pending: &Pending, version: Version) -> Option<(Data, Buckets)> {
    let mut buckets = empty_buckets();
    let mut data = Assoc::new();
    let mut i = 0;
    while i < pending.0.len() {
        let row = &pending.0[i];
        let bucket = &mut buckets[bucket_for(&row.0)];
        if bucket.len() >= 64 {
            return None;
        }
        if bucket_contains(bucket, pending, &row.0) {
            // The general fold supports repeats; only the unique write set
            // can be assembled directly in observation order.
            return None;
        }
        bucket.push(i);
        append_batch_put(&mut data, row, version);
        i += 1;
    }
    Some((data, buckets))
}

fn append_batch_put(data: &mut Data, row: &(Address, Write), version: Version) {
    if let Write::Put(value) = &row.1 {
        data.0.push((
            row.0.clone(),
            Cell {
                value: value.clone(),
                version,
            },
        ));
    }
}

fn append_untouched(data: &mut Data, row: &(Address, Cell), pending: &Pending, buckets: &Buckets) {
    if !bucket_contains(&buckets[bucket_for(&row.0)], pending, &row.0) {
        data.0.push((row.0.clone(), row.1.clone()));
    }
}

fn publish_batch(data: &Data, pending: &Pending, version: Version) -> Option<Data> {
    let Some((mut next, buckets)) = stage_batch(pending, version) else {
        return None;
    };
    let mut i = 0;
    while i < data.0.len() {
        append_untouched(&mut next, &data.0[i], pending, &buckets);
        i += 1;
    }
    Some(next)
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

fn same_image(data: &Data, map: &Bytes, expected: &Image) -> bool {
    let mut i = 0;
    let mut matched = 0;
    while i < data.0.len() {
        let row = &data.0[i];
        if row.0.map.same(map) {
            if matched >= expected.0.len() {
                return false;
            }
            let old = &expected.0[matched];
            if !row.0.key.same(&old.0) || !row.1.same(&old.1) {
                return false;
            }
            matched += 1;
        }
        i += 1;
    }
    matched == expected.0.len()
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
        let stamp = Stamp { version, identity };
        let mut revisions = self.revisions.clone();
        let mut births = self.births.clone();
        let mut i = 0;
        while i < pending.0.len() {
            let row = &pending.0[i];
            update_revision(&mut revisions, &self.data, row, stamp);
            update_birth(&mut births, &row.0.map, stamp);
            i += 1;
        }
        Self {
            version,
            data: publish(&self.data, pending, version),
            revisions,
            births,
        }
    }
}

fn update_revision(
    revisions: &mut Assoc<Bytes, Stamp>,
    data: &Data,
    row: &(Address, Write),
    stamp: Stamp,
) {
    if matches!(row.1, Write::Put(_)) || data.index(&row.0).is_some() {
        revisions.set(row.0.map.clone(), stamp);
    }
}

fn update_birth(births: &mut Assoc<Bytes, Stamp>, map: &Bytes, stamp: Stamp) {
    if births.index(map).is_none() {
        births.set(map.clone(), stamp);
    }
}

#[derive(Clone)]
struct History {
    // Oldest first. Versions are contiguous from the first retained frame.
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

    fn relative_cut(&self, cut: Version) -> Version {
        let base = self.frames[0].version;
        if cut < base { 0 } else { cut - base }
    }

    fn at_cut(&self, cut: Version) -> &Frame {
        let offset = self.relative_cut(cut);
        let head = self.frames.len() - 1;
        if offset < head as Version {
            &self.frames[offset as usize]
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
            // The cut's offset is below the last retained frame's index.
            let offset = self.relative_cut(cut);
            self.frames.resize(offset as usize + 1, Frame::empty());
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
    // None means both reads use the already-pinned local image.
    global: Option<Image>,
}

impl View {
    fn global_image(&self) -> &Image {
        match &self.global {
            Some(image) => image,
            None => &self.local,
        }
    }
}

fn pin_global(
    global: &Frame,
    map: &Bytes,
    local_cut: Version,
    global_cut: Version,
) -> Option<Image> {
    if local_cut == global_cut {
        None
    } else {
        Some(image(&global.data, map))
    }
}

#[derive(Clone)]
struct RecoveryView {
    revision: Version,
    image: Image,
}

impl Clone for View {
    fn clone(&self) -> Self {
        Self {
            birth: self.birth,
            revision: self.revision,
            local: self.local.clone(),
            global: match &self.global {
                Some(image) => Some(image.clone()),
                None => None,
            },
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
            Self::Map(map, expected) => same_image(db, map, expected),
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
                    global: None,
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
            global: pin_global(global, &map, snapshot.version, history.global),
        };
        self.views.set(map, pinned);
        Ok(Output::Acquired(revision.version, global_revision.version))
    }

    fn observe(
        pending: &Pending,
        deps: &mut Vec<Dependency>,
        a: &Address,
        view: &View,
        global: bool,
    ) -> Option<Bytes> {
        if global {
            return cell_value(view.global_image().get(&a.key));
        }
        if let Some(write) = pending.get(a) {
            return match write {
                Write::Put(v) => Some(v),
                Write::Remove => None,
            };
        }
        let cell = view.local.get(&a.key);
        let value = cell_value(copy_cell(&cell));
        deps.push(Dependency::Key(a.clone(), cell));
        value
    }

    fn scan(pending: &Pending, deps: &mut Vec<Dependency>, map: &Bytes, view: &View) -> Entries {
        deps.push(Dependency::Map(map.clone(), view.local.clone()));
        let mut rows = Assoc::new();
        let mut i = 0;
        while i < view.local.0.len() {
            let row = &view.local.0[i];
            rows.0.push((row.0.clone(), row.1.value.clone()));
            i += 1;
        }
        i = pending.0.len();
        while i > 0 {
            i -= 1;
            let row = &pending.0[i];
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
        let Some(view) = self.views.get_ref(&map) else {
            return Err(Error::Disabled);
        };
        match op {
            Operation::Get(key, global) => Ok(Output::Value(Self::observe(
                &self.pending,
                &mut self.deps,
                &Address { map, key },
                view,
                global,
            ))),
            Operation::Has(key, global) => Ok(Output::Presence(
                Self::observe(
                    &self.pending,
                    &mut self.deps,
                    &Address { map, key },
                    view,
                    global,
                )
                .is_some(),
            )),
            Operation::Previous(key) => {
                let cell = view.local.get(&key);
                let version = cell_version(&cell);
                self.deps.push(Dependency::Key(Address { map, key }, cell));
                Ok(Output::Previous(version))
            }
            Operation::Write(key, value) => {
                self.pending
                    .set(Address { map, key }, Write::from_option(value));
                Ok(Output::Unit)
            }
            Operation::Scan => Ok(Output::Entries(Self::scan(
                &self.pending,
                &mut self.deps,
                &map,
                view,
            ))),
            Operation::Size => Ok(Output::Size(
                Self::scan(&self.pending, &mut self.deps, &map, view).len(),
            )),
            Operation::Clear => {
                let entries = Self::scan(&self.pending, &mut self.deps, &map, view);
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
                    &Self::scan(&self.pending, &mut self.deps, &map, view),
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

    fn has_concurrent_map_creation(&self, head: &Frame) -> bool {
        let mut i = 0;
        while i < self.views.0.len() {
            let (map, view) = &self.views.0[i];
            if view.birth.is_none() && head.births.index(map).is_some() {
                return true;
            }
            i += 1;
        }
        false
    }
}

fn cell_value(cell: Option<Cell>) -> Option<Bytes> {
    match cell {
        Some(c) => Some(c.value),
        None => None,
    }
}

fn cell_version(cell: &Option<Cell>) -> Option<Version> {
    match cell {
        Some(c) => Some(c.version),
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

pub type WriteSet = Vec<(Address, Option<Bytes>)>;

pub struct SnapshotMap {
    pub name: Bytes,
    pub revision: Version,
    pub cells: Vec<(Bytes, Version, Bytes)>,
}

fn keep_other_map(out: &mut Vec<(Address, Cell)>, row: &(Address, Cell), map: &Bytes) {
    if !row.0.map.same(map) {
        out.push((row.0.clone(), row.1.clone()));
    }
}

fn without_map(data: &Data, map: &Bytes) -> Data {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.0.len() {
        keep_other_map(&mut out, &data.0[i], map);
        i += 1;
    }
    Assoc(out)
}

fn add_snapshot_map(frame: &mut Frame, map: &SnapshotMap, identity: u64) -> bool {
    if map.revision > frame.version {
        return false;
    }
    if let Some(previous) = frame.births.get(&map.name) {
        if previous.identity == identity {
            return false;
        }
    }
    // A snapshot updates each included map. An omitted map is not a deletion.
    frame.data = without_map(&frame.data, &map.name);
    let stamp = Stamp {
        version: map.revision,
        identity,
    };
    frame.births.set(map.name.clone(), stamp);
    if map.revision == 0 {
        frame.revisions = frame.revisions.erase(&map.name);
    } else {
        frame.revisions.set(map.name.clone(), stamp);
    }
    let mut j = 0;
    while j < map.cells.len() {
        let (key, written, value) = &map.cells[j];
        let address = Address {
            map: map.name.clone(),
            key: key.clone(),
        };
        if *written == 0 || *written > map.revision || frame.data.index(&address).is_some() {
            return false;
        }
        frame.data.0.push((
            address,
            Cell {
                version: *written,
                value: value.clone(),
            },
        ));
        j += 1;
    }
    true
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The action is not enabled in the current state.
    Disabled,
    /// Publication would overflow the version or application identity.
    Exhausted,
}

pub enum CommitPreparation {
    ReadOnly,
    Rejected(Outcome),
    Applied(Version, Term, WriteSet),
}

pub struct Store {
    history: History,
    txs: Assoc<Attempt, Tx>,
    recovery_views: Assoc<Bytes, RecoveryView>,
}

impl Store {
    pub fn new(term: Term) -> Self {
        Self {
            history: History::new(term),
            txs: Assoc::new(),
            recovery_views: Assoc::new(),
        }
    }

    pub fn clear_idle(&mut self) -> Result<(), Error> {
        if !self.txs.0.is_empty() {
            return Err(Error::Disabled);
        }
        self.history = History::new(0);
        self.recovery_views = Assoc::new();
        Ok(())
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

    /// CCF commit preparation. Submitting a locally applied write set and
    /// recording its final outcome remain separate operations.
    pub fn prepare_ccf_commit(&mut self, tx: Attempt) -> Result<CommitPreparation, Error> {
        let i = self.tx_index(tx)?;
        let t = &self.txs.0[i].1;
        if !matches!(t.phase, Phase::Committing) {
            return Err(Error::Disabled);
        }
        // CCF reserves map names conservatively, even for an absent map that
        // the attempt only acquired. The abstract model permits this conflict.
        if t.unavailable || t.has_concurrent_map_creation(self.history.head()) {
            return Ok(CommitPreparation::Rejected(Outcome::Conflict));
        }
        if t.pending.0.is_empty() {
            return Ok(CommitPreparation::ReadOnly);
        }
        if let Some(snapshot) = t.snapshot {
            if snapshot.term != self.history.term {
                // CCF checks conflicts before requesting a version in the
                // current term, so lineage or dependency failure takes priority.
                let outcome = if t.valid_lineage(&self.history)
                    && t.valid_dependencies(&self.history.head().data)
                {
                    Outcome::NoReplicate
                } else {
                    Outcome::Conflict
                };
                return Ok(CommitPreparation::Rejected(outcome));
            }
        }
        match self.apply(tx) {
            Ok(Output::Applied(version, term, writes)) => {
                Ok(CommitPreparation::Applied(version, term, writes))
            }
            Err(Error::Disabled) => Ok(CommitPreparation::Rejected(Outcome::Conflict)),
            Err(Error::Exhausted) => Err(Error::Exhausted),
            Ok(_) => Err(Error::Disabled),
        }
    }

    pub fn acquire_ccf(&mut self, tx: Attempt, map: Bytes) -> Result<Output, Error> {
        let i = self.tx_index(tx)?;
        let t = &mut self.txs.0[i].1;
        let Some(snapshot) = t.snapshot else {
            return Err(Error::Disabled);
        };
        if !matches!(t.phase, Phase::Active) || t.views.index(&map).is_some() {
            return Err(Error::Disabled);
        }
        if snapshot.version < self.history.frames[0].version {
            t.unavailable = true;
            return Ok(Output::Unavailable);
        }
        if let Some(global) = self.recovery_views.get(&map) {
            let local = self.history.at_cut(snapshot.version);
            let birth = local.births.get(&map);
            if birth.is_some() {
                let revision = local.revision(&map);
                if revision.version < global.revision {
                    t.unavailable = true;
                    return Ok(Output::Unavailable);
                }
                let local_image = image(&local.data, &map);
                t.views.set(
                    map,
                    View {
                        birth,
                        revision,
                        local: local_image,
                        global: Some(global.image),
                    },
                );
                return Ok(Output::Acquired(revision.version, global.revision));
            }
        }
        t.acquire(&self.history, map)
    }

    pub fn compact_ccf(&mut self, version: Version) -> Output {
        let previous = self.history.global;
        let cut = self.history.compact(version);
        if previous <= version && cut == version {
            let frame = self.history.at_cut(cut);
            let mut retained = Assoc::new();
            let mut i = 0;
            while i < self.recovery_views.0.len() {
                Self::retain_recovery_view(&mut retained, frame, &self.recovery_views.0[i]);
                i += 1;
            }
            self.recovery_views = retained;
        }
        Output::Compacted(cut)
    }

    /// Swap the selected map histories during recovery. Both stores must be
    /// quiescent. The receiving store keeps its own global cut; the swapped
    /// maps keep the per-map committed images from their original store.
    pub fn swap_recovery_maps(
        &mut self,
        source: &mut Store,
        names: Vec<Bytes>,
    ) -> Result<(), Error> {
        if !self.txs.0.is_empty()
            || !source.txs.0.is_empty()
            || source.history.head().version > self.history.head().version
        {
            return Err(Error::Disabled);
        }
        let my_identity = self.history.next_identity;
        let their_identity = source.history.next_identity;
        if my_identity == u64::MAX || their_identity == u64::MAX {
            return Err(Error::Exhausted);
        }
        let my_frames = Self::recovery_frames(&self.history, &source.history, &names, my_identity);
        let their_frames =
            Self::recovery_frames(&source.history, &self.history, &names, their_identity);
        let mut my_views = self.recovery_views.clone();
        let mut their_views = source.recovery_views.clone();
        let mut i = 0;
        while i < names.len() {
            let name = &names[i];
            my_views.set(name.clone(), source.recovery_view(name));
            their_views.set(name.clone(), self.recovery_view(name));
            i += 1;
        }
        self.history.frames = my_frames;
        source.history.frames = their_frames;
        self.history.next_identity = my_identity + 1;
        source.history.next_identity = their_identity + 1;
        self.recovery_views = my_views;
        source.recovery_views = their_views;
        Ok(())
    }

    fn recovery_view(&self, name: &Bytes) -> RecoveryView {
        if let Some(view) = self.recovery_views.get(name) {
            return view;
        }
        let frame = self.history.at_cut(self.history.global);
        RecoveryView {
            revision: frame.revision(name).version,
            image: image(&frame.data, name),
        }
    }

    pub fn snapshot_at_ccf(&mut self, tx: Attempt, version: Version) -> Result<Output, Error> {
        let i = self.tx_index(tx)?;
        let t = &mut self.txs.0[i].1;
        if !matches!(t.phase, Phase::Active)
            || t.snapshot.is_some()
            || version < self.history.frames[0].version
            || version > self.history.head().version
        {
            return Err(Error::Disabled);
        }
        let term = self.history.term;
        t.snapshot = Some(Snapshot { version, term });
        Ok(Output::Snapshot(version, self.history.global, term))
    }

    /// Observe an already acquired handle after successful CCF commit.
    /// Evaluating on a temporary attempt cannot change dependencies or stage writes.
    pub fn inspect_finished(
        &self,
        tx: Attempt,
        map: Bytes,
        op: Operation,
    ) -> Result<Output, Error> {
        let i = self.tx_index(tx)?;
        let t = &self.txs.0[i].1;
        if !matches!(t.phase, Phase::Finished)
            || matches!(op, Operation::Write(..) | Operation::Clear)
        {
            return Err(Error::Disabled);
        }
        let mut view = t.clone();
        view.phase = Phase::Active;
        view.operate(map, op)
    }

    pub fn pending_writes(&self, tx: Attempt) -> Result<WriteSet, Error> {
        let i = self.tx_index(tx)?;
        let t = &self.txs.0[i].1;
        if !matches!(t.phase, Phase::Active) {
            return Err(Error::Disabled);
        }
        Ok(reported_writes(&t.pending))
    }

    pub fn map_revision_at(&self, version: Version, map: &Bytes) -> Option<Version> {
        let frame = self.history.at_cut(version);
        if frame.births.index(map).is_none() {
            return None;
        }
        Some(frame.revision(map).version)
    }

    pub fn snapshot_maps(&self, version: Version) -> Result<Vec<SnapshotMap>, Error> {
        if version < self.history.global || version > self.history.head().version {
            return Err(Error::Disabled);
        }
        let frame = self.history.at_cut(version);
        let mut maps = Vec::new();
        let mut i = 0;
        while i < frame.births.0.len() {
            let name = &frame.births.0[i].0;
            let mut cells = Vec::new();
            let mut j = 0;
            while j < frame.data.0.len() {
                let (address, cell) = &frame.data.0[j];
                if address.map.same(name) {
                    cells.push((address.key.clone(), cell.version, cell.value.clone()));
                }
                j += 1;
            }
            maps.push(SnapshotMap {
                name: name.clone(),
                revision: frame.revision(name).version,
                cells,
            });
            i += 1;
        }
        Ok(maps)
    }

    /// Install a snapshot as a new irrevocable history base. The image is
    /// validated completely before discarding any current frames.
    pub fn install_snapshot(
        &mut self,
        version: Version,
        maps: Vec<SnapshotMap>,
    ) -> Result<(), Error> {
        if version < self.history.global {
            return Err(Error::Disabled);
        }
        let identity = self.history.next_identity;
        if identity == u64::MAX {
            return Err(Error::Exhausted);
        }

        let mut frame = self.history.at_cut(version).clone();
        frame.version = version;
        let mut i = 0;
        while i < maps.len() {
            if !add_snapshot_map(&mut frame, &maps[i], identity) {
                return Err(Error::Disabled);
            }
            i += 1;
        }
        let mut frames = Vec::new();
        frames.push(frame);
        self.history.frames = frames;
        self.history.next_identity = identity + 1;
        self.history.global = version;
        let mut i = 0;
        while i < maps.len() {
            self.recovery_views = self.recovery_views.erase(&maps[i].name);
            i += 1;
        }
        Ok(())
    }

    fn retain_recovery_view(
        out: &mut Assoc<Bytes, RecoveryView>,
        frame: &Frame,
        row: &(Bytes, RecoveryView),
    ) {
        if frame.revision(&row.0).version < row.1.revision {
            out.0.push((row.0.clone(), row.1.clone()));
        }
    }

    fn copy_recovery_map(dst: &mut Frame, src: &Frame, name: &Bytes, identity: u64) {
        dst.data = without_map(&dst.data, name);
        if let Some(birth) = src.births.get(name) {
            dst.births.set(
                name.clone(),
                Stamp {
                    version: birth.version,
                    identity,
                },
            );
        } else {
            dst.births = dst.births.erase(name);
        }
        if let Some(revision) = src.revisions.get(name) {
            dst.revisions.set(
                name.clone(),
                Stamp {
                    version: revision.version,
                    identity,
                },
            );
        } else {
            dst.revisions = dst.revisions.erase(name);
        }
        let mut i = 0;
        while i < src.data.0.len() {
            Self::append_recovery_row(&mut dst.data, &src.data.0[i], name);
            i += 1;
        }
    }

    fn append_recovery_row(data: &mut Data, row: &(Address, Cell), name: &Bytes) {
        if row.0.map.same(name) {
            data.0.push((row.0.clone(), row.1.clone()));
        }
    }

    fn recovery_frame(base: &Frame, source: &History, names: &Vec<Bytes>, identity: u64) -> Frame {
        let mut next = base.clone();
        let donor = source.at_cut(base.version);
        let mut i = 0;
        while i < names.len() {
            Self::copy_recovery_map(&mut next, donor, &names[i], identity);
            i += 1;
        }
        next
    }

    fn recovery_frames(
        destination: &History,
        source: &History,
        names: &Vec<Bytes>,
        identity: u64,
    ) -> Vec<Frame> {
        let mut frames = Vec::new();
        let mut i = 0;
        while i < destination.frames.len() {
            frames.push(Self::recovery_frame(
                &destination.frames[i],
                source,
                names,
                identity,
            ));
            i += 1;
        }
        frames
    }

    /// Apply an already validated ordinary ledger entry at the next version.
    /// Import does not set the term for subsequent locally authored commits.
    pub fn replay_next(&mut self, version: Version, writes: WriteSet) -> Result<(), Error> {
        let head = self.history.head();
        let identity = self.history.next_identity;
        if head.version == u64::MAX || identity == u64::MAX {
            return Err(Error::Exhausted);
        }
        if version != head.version + 1 {
            return Err(Error::Disabled);
        }
        let mut pending = Assoc::new();
        let mut i = 0;
        while i < writes.len() {
            let (address, value) = &writes[i];
            if pending.index(address).is_some() {
                return Err(Error::Disabled);
            }
            let write = match value {
                Some(bytes) => Write::Put(bytes.clone()),
                None => Write::Remove,
            };
            pending.0.push((address.clone(), write));
            i += 1;
        }
        let next = head.advance(version, identity, &pending);
        self.history.frames.push(next);
        self.history.next_identity += 1;
        Ok(())
    }

    /// CCF historical queries can replay a single later entry into an empty
    /// store. Missing-key deletions may be visible to a historical diff.
    pub fn replay_ccf(
        &mut self,
        version: Version,
        writes: WriteSet,
        track_deletes: bool,
    ) -> Result<(), Error> {
        if version != 0 && version <= self.history.head().version {
            // Replacement of a provisional suffix is atomic even if the
            // replacement write set fails validation.
            let mut replacement = Store::new(self.history.term);
            replacement.history = self.history.clone();
            if !matches!(
                replacement
                    .history
                    .rollback(version - 1, self.history.term)?,
                Output::RolledBack(_)
            ) {
                return Err(Error::Disabled);
            }
            replacement.replay_ccf_next(version, writes, track_deletes)?;
            self.history = replacement.history;
            return Ok(());
        }
        self.replay_ccf_next(version, writes, track_deletes)
    }

    fn replay_ccf_next(
        &mut self,
        version: Version,
        writes: WriteSet,
        track_deletes: bool,
    ) -> Result<(), Error> {
        let mut maps = Vec::new();
        if track_deletes {
            let mut i = 0;
            while i < writes.len() {
                maps.push(writes[i].0.map.clone());
                i += 1;
            }
        }
        if version > 1 && self.history.head().version == 0 {
            if !self.txs.0.is_empty() {
                return Err(Error::Disabled);
            }
            let mut isolated = Store::new(self.history.term);
            isolated.history.next_identity = self.history.next_identity;
            isolated.install_snapshot(version - 1, Vec::new())?;
            isolated.replay_next(version, writes)?;
            self.history = isolated.history;
        } else {
            self.replay_next(version, writes)?;
        }
        self.stamp_historical_maps(version, &maps);
        Ok(())
    }

    fn stamp_historical_maps(&mut self, version: Version, maps: &Vec<Bytes>) {
        let identity = self.history.next_identity - 1;
        let at = self.history.frames.len() - 1;
        let revisions = &mut self.history.frames[at].revisions;
        let mut i = 0;
        while i < maps.len() {
            revisions.set(maps[i].clone(), Stamp { version, identity });
            i += 1;
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
