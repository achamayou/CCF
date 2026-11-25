// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//! A single-store KV state machine over finite association lists.

use crate::branch_log::{BranchLog, FrameId};
use crate::kv_index::{AddressIndex, Binding};
use crate::radix::{RadixRoot, RadixRow};

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

    fn same_key(&self, other: &Self) -> bool {
        let len = self.0.len();
        if len != other.0.len() {
            return false;
        }
        if len == 0 {
            return true;
        }
        if self.0[len - 1] != other.0[len - 1] {
            return false;
        }
        self.same_slice(other)
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
        self.key.same_key(&other.key) && self.map.same_slice(&other.map)
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

fn pending_key_order(a: &Address, b: &Address) -> i8 {
    let order = a.key.compare(&b.key);
    if order != 0 {
        return order;
    }
    a.map.compare(&b.map)
}

fn stage_write(pending: &mut Pending, address: Address, write: Write) {
    // Keep keys descending so the bulk publisher can consume a single map
    // in ascending order without a separate sort.
    let mut lo = 0;
    let mut hi = pending.0.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let order = pending_key_order(&pending.0[mid].0, &address);
        if order == 0 {
            pending.0[mid].1 = write;
            return;
        }
        if order > 0 {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == pending.0.len() {
        pending.0.push((address, write));
    } else {
        pending.0.insert(lo, (address, write));
    }
}

#[allow(dead_code)]
fn publish(data: &Data, pending: &Pending, version: Version) -> Data {
    if pending.0.len() >= 64 {
        if let Some(next) = publish_batch(data, pending, version) {
            return next;
        }
    }
    publish_sequential(data.clone(), pending, version)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
type Buckets = Vec<Vec<usize>>;

#[allow(dead_code)]
fn empty_buckets() -> Buckets {
    let mut buckets = Vec::new();
    let mut i = 0_usize;
    while i < 256 {
        buckets.push(Vec::new());
        i += 1;
    }
    buckets
}

#[allow(dead_code)]
fn bucket_for(address: &Address) -> usize {
    let key = &address.key.0;
    if key.is_empty() {
        0
    } else {
        key[key.len() - 1] as usize
    }
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
fn append_untouched(data: &mut Data, row: &(Address, Cell), pending: &Pending, buckets: &Buckets) {
    if !bucket_contains(&buckets[bucket_for(&row.0)], pending, &row.0) {
        data.0.push((row.0.clone(), row.1.clone()));
    }
}

#[allow(dead_code)]
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

#[allow(dead_code)]
fn image(data: &Data, map: &Bytes) -> Image {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.0.len() {
        copy_if_on_map(&mut out, &data.0[i], map);
        i += 1;
    }
    Assoc(out)
}

#[allow(dead_code)]
fn copy_if_on_map(out: &mut Vec<(Bytes, Cell)>, row: &(Address, Cell), map: &Bytes) {
    if row.0.map.same(map) {
        out.push((row.0.key.clone(), row.1.clone()));
    }
}

#[allow(dead_code)]
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
    data: RadixRoot,
    revisions: Assoc<Bytes, Stamp>,
    births: Assoc<Bytes, Stamp>,
    meta_live: bool,
}

impl Frame {
    fn empty(data: RadixRoot) -> Self {
        Self {
            version: 0,
            data,
            revisions: Assoc::new(),
            births: Assoc::new(),
            meta_live: true,
        }
    }

    fn revision(&self, map: &Bytes) -> Stamp {
        match self.revisions.get(map) {
            Some(stamp) => stamp,
            None => Stamp::zero(),
        }
    }

    fn matches_lineage(&self, map: &Bytes, birth: Option<Stamp>, revision: Stamp) -> bool {
        if !self.meta_live {
            return false;
        }
        let same_birth = match (self.births.get(map), birth) {
            (Some(a), Some(b)) => a.same(b),
            (None, None) => true,
            _ => false,
        };
        same_birth && self.revision(map).same(revision)
    }

    fn advance(
        &self,
        index: &mut AddressIndex<Cell>,
        version: Version,
        identity: u64,
        pending: &Pending,
    ) -> Self {
        let stamp = Stamp { version, identity };
        let mut revisions = self.revisions.clone();
        let mut births = self.births.clone();
        let mut i = 0;
        while i < pending.0.len() {
            advance_stamps(
                &mut revisions,
                &mut births,
                index,
                self.data,
                &pending.0[i],
                stamp,
            );
            i += 1;
        }
        let base = publication_base(index, self.data, pending);
        Self {
            version,
            data: publish_selected(index, base, pending, version),
            revisions,
            births,
            meta_live: true,
        }
    }
}

fn advance_stamps(
    revisions: &mut Assoc<Bytes, Stamp>,
    births: &mut Assoc<Bytes, Stamp>,
    index: &AddressIndex<Cell>,
    root: RadixRoot,
    row: &(Address, Write),
    stamp: Stamp,
) {
    let (a, w) = row;
    if matches!(w, Write::Put(_)) || index.get(root, a).is_some() {
        revisions.set(a.map.clone(), stamp);
    }
    update_birth(births, &a.map, stamp);
}

fn publication_base(index: &AddressIndex<Cell>, root: RadixRoot, pending: &Pending) -> RadixRoot {
    let count = pending.0.len();
    if count < 256 || count == usize::MAX {
        return root;
    }
    // Fail cheaply on sparse batches, without scanning the rest of the store.
    let links = index.scan_links_up_to(root, count + 1);
    if links.len() != count {
        return root;
    }
    let mut i = 0;
    while i < count {
        let row = index.scan_row(links[i]);
        if !row.0.same(&pending.0[count - 1 - i].0) {
            return root;
        }
        i += 1;
    }
    index.empty_root()
}

fn single_map_increasing(a: &Address, b: &Address) -> bool {
    a.map.same(&b.map) && a.key.compare(&b.key) == -1
}

fn prepare_sorted_batch(
    pending: &Pending,
    version: Version,
) -> Option<Vec<Option<RadixRow<Binding<Cell>>>>> {
    let len = pending.0.len();
    let mut batch = Vec::with_capacity(len);
    let mut i = len;
    while i > 0 {
        let prior = i;
        i -= 1;
        let (address, write) = &pending.0[i];
        if prior < len && !single_map_increasing(&pending.0[prior].0, address) {
            return None;
        }
        let Write::Put(value) = write else {
            return None;
        };
        let row = AddressIndex::batch_row(
            address.clone(),
            Cell {
                value: value.clone(),
                version,
            },
        );
        // Keep the bulk directory bound below the ordinary publication bound.
        if row.key.len() > 56 {
            return None;
        }
        batch.push(Some(row));
    }
    Some(batch)
}

fn publish_selected(
    index: &mut AddressIndex<Cell>,
    base: RadixRoot,
    pending: &Pending,
    version: Version,
) -> RadixRoot {
    if base.is_empty() && pending.0.len() >= 256 {
        if let Some(rows) = prepare_sorted_batch(pending, version) {
            return index.build_sorted_batch(rows);
        }
    }
    publish_indexed(index, base, pending, version)
}

const RETIRE_BUDGET: usize = 16;

fn publish_indexed(
    index: &mut AddressIndex<Cell>,
    base: RadixRoot,
    pending: &Pending,
    version: Version,
) -> RadixRoot {
    let mut root = base;
    let mut owned = false;
    let mut i = pending.0.len();
    while i > 0 {
        i -= 1;
        let next = publish_indexed_row(index, root, &pending.0[i], version);
        if owned {
            index.release_root(root);
        }
        root = next;
        owned = true;
    }
    if !owned {
        index.retain_root(root);
    }
    root
}

fn publish_indexed_row(
    index: &mut AddressIndex<Cell>,
    root: RadixRoot,
    row: &(Address, Write),
    version: Version,
) -> RadixRoot {
    let (address, write) = row;
    match write {
        Write::Put(value) => index.put(
            root,
            address.clone(),
            Cell {
                value: value.clone(),
                version,
            },
        ),
        Write::Remove => index.remove(root, address),
    }
}

fn indexed_data(index: &AddressIndex<Cell>, root: RadixRoot) -> Data {
    let links = index.scan_links(root);
    let mut rows = Vec::with_capacity(links.len());
    let mut i = 0;
    while i < links.len() {
        let (address, cell) = index.scan_row(links[i]);
        rows.push((address.clone(), cell.clone()));
        i += 1;
    }
    Assoc(rows)
}

fn indexed_image(index: &AddressIndex<Cell>, root: RadixRoot, map: &Bytes) -> Image {
    let links = index.scan_map_links(root, map);
    let mut rows = Vec::with_capacity(links.len());
    let mut i = 0;
    while i < links.len() {
        let (address, cell) = index.scan_row(links[i]);
        append_image_row(&mut rows, address, cell, map);
        i += 1;
    }
    Assoc(rows)
}

fn append_image_row(rows: &mut Vec<(Bytes, Cell)>, address: &Address, cell: &Cell, map: &Bytes) {
    if address.map.same(map) {
        rows.push((address.key.clone(), cell.clone()));
    }
}

fn append_snapshot_cell(
    cells: &mut Vec<(Bytes, Version, Bytes)>,
    address: &Address,
    cell: &Cell,
    map: &Bytes,
) {
    if address.map.same(map) {
        cells.push((address.key.clone(), cell.version, cell.value.clone()));
    }
}

fn index_from_rows(index: &mut AddressIndex<Cell>, rows: Data) -> RadixRoot {
    let mut root = index.empty_root();
    let mut owned = false;
    let mut i = rows.0.len();
    while i > 0 {
        i -= 1;
        let (address, cell) = &rows.0[i];
        let next = index.put(root, address.clone(), cell.clone());
        if owned {
            index.release_root(root);
        }
        root = next;
        owned = true;
    }
    root
}

fn update_birth(births: &mut Assoc<Bytes, Stamp>, map: &Bytes, stamp: Stamp) {
    if births.index(map).is_none() {
        births.set(map.clone(), stamp);
    }
}

struct History {
    // The active branch is oldest first and contiguous in version.
    log: BranchLog<Frame>,
    index: AddressIndex<Cell>,
    global: Version,
    term: Term,
    next_identity: u64,
    // Imported metadata does not yet carry the verified revision-history invariant.
    reuse_compacted_images: bool,
}

impl History {
    fn new(term: Term) -> Self {
        let index = AddressIndex::new();
        Self {
            log: BranchLog::new(Frame::empty(index.empty_root())),
            index,
            global: 0,
            term,
            next_identity: 1,
            reuse_compacted_images: true,
        }
    }

    fn head(&self) -> &Frame {
        self.log.active_at(self.log.active_len() - 1)
    }

    fn relative_cut(&self, cut: Version) -> Version {
        let base = self.log.active_at(0).version;
        if cut < base { 0 } else { cut - base }
    }

    fn at_cut(&self, cut: Version) -> &Frame {
        self.log.read(self.pin_cut(cut))
    }

    fn retained_data(&self, cut: Version, fallback: RadixRoot) -> RadixRoot {
        if self.reuse_compacted_images && cut < self.global {
            self.at_cut(self.global).data
        } else {
            fallback
        }
    }

    fn prepare_frame(&mut self, version: Version, identity: u64, pending: &Pending) -> Frame {
        let head = self.log.active_at(self.log.active_len() - 1);
        head.advance(&mut self.index, version, identity, pending)
    }

    fn pin_cut(&self, cut: Version) -> FrameId {
        self.log.at_cut(self.relative_cut(cut))
    }

    fn map_lineage(&self, map: &Bytes, birth: Option<Stamp>, revision: Stamp) -> bool {
        let mut i = self.log.active_len();
        while i > 0 {
            i -= 1;
            if self.log.active_at(i).matches_lineage(map, birth, revision) {
                return true;
            }
        }
        false
    }

    fn release_active_range(&mut self, start: usize, end: usize) {
        let mut i = start;
        while i < end {
            if let Some(id) = self.log.resolve(i) {
                let old = self.log.read(id).data;
                if !old.is_empty() {
                    self.log.read_mut(id).data = self.index.empty_root();
                    self.index.release_root(old);
                }
                let slot = self.log.read_mut(id);
                slot.revisions = Assoc::new();
                slot.births = Assoc::new();
                slot.meta_live = false;
            }
            i += 1;
        }
    }

    fn release_compacted_range(
        &mut self,
        start: usize,
        end: usize,
        global_id: FrameId,
        txs: &Assoc<Attempt, Tx>,
    ) {
        let mut i = start;
        while i < end {
            if let Some(id) = self.log.resolve(i) {
                let old = self.log.read(id).data;
                if !old.is_empty() {
                    self.log.read_mut(id).data = self.index.empty_root();
                    self.index.release_root(old);
                }
                let elide = !txs_need_frame(txs, self.log.read(id), self.log.read(global_id));
                if elide {
                    let slot = self.log.read_mut(id);
                    slot.revisions = Assoc::new();
                    slot.births = Assoc::new();
                    slot.meta_live = false;
                }
            }
            i += 1;
        }
    }

    fn try_elide_compacted_version(&mut self, version: Version, txs: &Assoc<Attempt, Tx>) {
        if !self.reuse_compacted_images || version >= self.global {
            return;
        }
        let offset = self.relative_cut(version) as usize;
        let global_id = self.pin_cut(self.global);
        if let Some(id) = self.log.resolve(offset) {
            let elide = !txs_need_frame(txs, self.log.read(id), self.log.read(global_id));
            if elide {
                let slot = self.log.read_mut(id);
                slot.revisions = Assoc::new();
                slot.births = Assoc::new();
                slot.meta_live = false;
            }
        }
    }

    fn compact(&mut self, requested: Version, txs: &Assoc<Attempt, Tx>) -> Version {
        let old_global = self.global;
        let next = compact_cut(old_global, self.head().version, requested);
        self.global = next;
        if self.reuse_compacted_images && old_global < next {
            let start = self.relative_cut(old_global) as usize;
            let end = self.relative_cut(next) as usize;
            let global_id = self.pin_cut(next);
            self.release_compacted_range(start, end, global_id, txs);
            self.index.retire_budget(RETIRE_BUDGET);
        }
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
            let offset = self.relative_cut(cut) as usize;
            let active_len = self.log.active_len();
            self.release_active_range(offset + 1, active_len);
            assert!(self.log.rewind(offset));
            self.index.retire_budget(RETIRE_BUDGET);
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

#[derive(Clone)]
enum PinnedImage {
    Empty,
    Root(RadixRoot),
    Recovered(Image),
}

impl PinnedImage {
    fn point(&self, history: &History, address: &Address) -> Option<Cell> {
        match self {
            Self::Empty => None,
            Self::Root(root) => match history.index.get(*root, address) {
                Some(cell) => Some(cell.clone()),
                None => None,
            },
            Self::Recovered(image) => image.get(&address.key),
        }
    }

    #[allow(dead_code)]
    fn materialize(&self, history: &History, map: &Bytes) -> Image {
        match self {
            Self::Empty => Assoc::new(),
            Self::Root(root) => indexed_image(&history.index, *root, map),
            Self::Recovered(rows) => rows.clone(),
        }
    }

    fn entries(&self, history: &History, map: &Bytes) -> Entries {
        match self {
            Self::Empty => Vec::new(),
            Self::Root(root) => indexed_entries(&history.index, *root, map),
            Self::Recovered(rows) => {
                let mut out = Vec::with_capacity(rows.0.len());
                let mut i = 0;
                while i < rows.0.len() {
                    let row = &rows.0[i];
                    out.push((row.0.clone(), row.1.value.clone()));
                    i += 1;
                }
                out
            }
        }
    }

    fn size(&self, history: &History, map: &Bytes) -> usize {
        match self {
            Self::Empty => 0,
            Self::Root(root) => history.index.scan_map_links(*root, map).len(),
            Self::Recovered(rows) => rows.0.len(),
        }
    }

    fn range(
        &self,
        history: &History,
        map: &Bytes,
        lower: &Option<Bytes>,
        upper: &Option<Bytes>,
    ) -> Entries {
        match self {
            Self::Empty => Vec::new(),
            Self::Root(root) => indexed_range(&history.index, *root, map, lower, upper),
            Self::Recovered(rows) => ordered_range(&rows.0, lower, upper),
        }
    }
}

fn append_entry_row(rows: &mut Entries, address: &Address, cell: &Cell, map: &Bytes) {
    if address.map.same(map) {
        rows.push((address.key.clone(), cell.value.clone()));
    }
}

fn indexed_entries(index: &AddressIndex<Cell>, root: RadixRoot, map: &Bytes) -> Entries {
    let links = index.scan_map_links(root, map);
    let mut rows = Vec::with_capacity(links.len());
    let mut i = 0;
    while i < links.len() {
        let (address, cell) = index.scan_row(links[i]);
        append_entry_row(&mut rows, address, cell, map);
        i += 1;
    }
    rows
}

fn append_range_row(
    out: &mut Entries,
    address: &Address,
    cell: &Cell,
    map: &Bytes,
    lower: &Option<Bytes>,
    upper: &Option<Bytes>,
) {
    if !address.map.same(map) {
        return;
    }
    let above_lower = match lower {
        Some(l) => l.compare(&address.key) <= 0,
        None => true,
    };
    let below_upper = match upper {
        Some(u) => address.key.compare(u) < 0,
        None => true,
    };
    if above_lower && below_upper {
        out.push((address.key.clone(), cell.value.clone()));
    }
}

fn indexed_range(
    index: &AddressIndex<Cell>,
    root: RadixRoot,
    map: &Bytes,
    lower: &Option<Bytes>,
    upper: &Option<Bytes>,
) -> Entries {
    let links = index.scan_map_links(root, map);
    let mut out = Vec::new();
    let mut i = 0;
    while i < links.len() {
        let (address, cell) = index.scan_row(links[i]);
        append_range_row(&mut out, address, cell, map, lower, upper);
        i += 1;
    }
    out
}

fn release_pin(index: &mut AddressIndex<Cell>, pin: &PinnedImage) {
    if let PinnedImage::Root(root) = pin {
        index.release_root(*root);
    }
}

fn view_needs_frame(row: &(Bytes, View), frame: &Frame, global_frame: &Frame) -> bool {
    let (map, view) = row;
    frame.matches_lineage(map, view.birth, view.revision)
        && !global_frame.matches_lineage(map, view.birth, view.revision)
}

fn tx_needs_frame(tx: &Tx, frame: &Frame, global_frame: &Frame) -> bool {
    if let Some(snap) = tx.snapshot {
        if snap.version == frame.version {
            return true;
        }
    }
    let mut i = 0;
    while i < tx.views.0.len() {
        if view_needs_frame(&tx.views.0[i], frame, global_frame) {
            return true;
        }
        i += 1;
    }
    false
}

fn txs_need_frame(txs: &Assoc<Attempt, Tx>, frame: &Frame, global_frame: &Frame) -> bool {
    let mut i = 0;
    while i < txs.0.len() {
        if tx_needs_frame(&txs.0[i].1, frame, global_frame) {
            return true;
        }
        i += 1;
    }
    false
}

fn release_tx_pins(index: &mut AddressIndex<Cell>, tx: &Tx) {
    let mut i = 0;
    while i < tx.views.0.len() {
        let view = &tx.views.0[i].1;
        release_pin(index, &view.local);
        if let Some(global) = &view.global {
            release_pin(index, global);
        }
        i += 1;
    }
}

struct View {
    birth: Option<Stamp>,
    revision: Stamp,
    local: PinnedImage,
    // None means both reads use the already-pinned local image.
    global: Option<PinnedImage>,
}

impl View {
    fn global_image(&self) -> &PinnedImage {
        match &self.global {
            Some(image) => image,
            None => &self.local,
        }
    }
}

fn pin_maps(
    history: &mut History,
    local: FrameId,
    global: FrameId,
    local_cut: Version,
) -> (PinnedImage, Option<PinnedImage>) {
    if history.reuse_compacted_images && local_cut < history.global {
        let root = history.log.read(global).data;
        history.index.retain_root(root);
        return (PinnedImage::Root(root), None);
    }
    let local_root = history.log.read(local).data;
    history.index.retain_root(local_root);
    let global_pin = if local_cut == history.global {
        None
    } else {
        let global_root = history.log.read(global).data;
        history.index.retain_root(global_root);
        Some(PinnedImage::Root(global_root))
    };
    (PinnedImage::Root(local_root), global_pin)
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
    Map(Bytes, PinnedImage),
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

fn indexed_same_image(
    index: &AddressIndex<Cell>,
    root: RadixRoot,
    map: &Bytes,
    expected: &Image,
) -> bool {
    let links = index.scan_map_links(root, map);
    if links.len() != expected.0.len() {
        return false;
    }
    let mut i = 0;
    let mut matched = 0;
    while i < links.len() {
        let (address, cell) = index.scan_row(links[i]);
        let Some(next) = match_indexed_row(address, cell, map, expected, matched) else {
            return false;
        };
        matched = next;
        i += 1;
    }
    matched == expected.0.len()
}

fn same_map_link(index: &AddressIndex<Cell>, left: u32, right: u32) -> bool {
    if left == right {
        return true;
    }
    let (la, lc) = index.scan_row(left);
    let (ra, rc) = index.scan_row(right);
    la.key.same(&ra.key) && lc.same(rc)
}

fn indexed_same_map_roots(
    index: &AddressIndex<Cell>,
    left_root: RadixRoot,
    right_root: RadixRoot,
    map: &Bytes,
) -> bool {
    if left_root.0 == right_root.0 {
        return true;
    }
    let left = index.scan_map_links(left_root, map);
    let right = index.scan_map_links(right_root, map);
    if left.len() != right.len() {
        return false;
    }
    let mut i = 0;
    while i < left.len() {
        if !same_map_link(index, left[i], right[i]) {
            return false;
        }
        i += 1;
    }
    true
}

impl Dependency {
    fn holds(&self, index: &AddressIndex<Cell>, root: RadixRoot) -> bool {
        match self {
            Self::Key(a, expected) => match (index.get(root, a), expected) {
                (None, None) => true,
                (Some(current), Some(old)) => current.same(old),
                _ => false,
            },
            Self::Map(map, expected) => match expected {
                PinnedImage::Empty => index.scan_map_links(root, map).is_empty(),
                PinnedImage::Root(pinned) => indexed_same_map_roots(index, root, *pinned, map),
                PinnedImage::Recovered(rows) => indexed_same_image(index, root, map, rows),
            },
        }
    }
}

fn match_indexed_row(
    address: &Address,
    cell: &Cell,
    map: &Bytes,
    expected: &Image,
    at: usize,
) -> Option<usize> {
    if !address.map.same(map) {
        return Some(at);
    }
    if at >= expected.0.len() {
        return None;
    }
    let (key, old) = &expected.0[at];
    if !address.key.same(key) || !cell.same(old) {
        return None;
    }
    Some(at + 1)
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

    fn acquire(&mut self, history: &mut History, map: Bytes) -> Result<Output, Error> {
        let Some(snapshot) = self.snapshot else {
            return Err(Error::Disabled);
        };
        if !matches!(self.phase, Phase::Active) || self.views.index(&map).is_some() {
            return Err(Error::Disabled);
        }
        let local_id = history.pin_cut(snapshot.version);
        let local = history.log.read(local_id);
        let birth = local.births.get(&map);
        if birth.is_none() {
            self.views.set(
                map,
                View {
                    birth: None,
                    revision: Stamp::zero(),
                    local: PinnedImage::Empty,
                    global: None,
                },
            );
            return Ok(Output::Acquired(0, 0));
        }
        let global_id = history.pin_cut(history.global);
        let global = history.log.read(global_id);
        let revision = local.revision(&map);
        let global_revision = global.revision(&map);
        // This local frame is on the surviving branch, so its lineage is present.
        if revision.version < global_revision.version {
            self.unavailable = true;
            return Ok(Output::Unavailable);
        }
        let (local_image, global_image) = pin_maps(history, local_id, global_id, snapshot.version);
        let pinned = View {
            birth,
            revision,
            local: local_image,
            global: global_image,
        };
        self.views.set(map, pinned);
        Ok(Output::Acquired(revision.version, global_revision.version))
    }

    fn observe(
        history: &History,
        pending: &Pending,
        deps: &mut Vec<Dependency>,
        a: &Address,
        view: &View,
        global: bool,
    ) -> Option<Bytes> {
        if global {
            return cell_value(view.global_image().point(history, a));
        }
        if let Some(write) = pending.get(a) {
            return match write {
                Write::Put(v) => Some(v),
                Write::Remove => None,
            };
        }
        let cell = view.local.point(history, a);
        let value = cell_value(copy_cell(&cell));
        deps.push(Dependency::Key(a.clone(), cell));
        value
    }

    fn scan(
        history: &History,
        pending: &Pending,
        deps: &mut Vec<Dependency>,
        map: &Bytes,
        view: &View,
    ) -> Entries {
        deps.push(Dependency::Map(map.clone(), view.local.clone()));
        let mut rows = Assoc(view.local.entries(history, map));
        let mut i = pending.0.len();
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

    fn operate(&mut self, history: &History, map: Bytes, op: Operation) -> Result<Output, Error> {
        if !matches!(self.phase, Phase::Active) {
            return Err(Error::Disabled);
        }
        let Some(view) = self.views.get_ref(&map) else {
            return Err(Error::Disabled);
        };
        match op {
            Operation::Get(key, global) => Ok(Output::Value(Self::observe(
                history,
                &self.pending,
                &mut self.deps,
                &Address { map, key },
                view,
                global,
            ))),
            Operation::Has(key, global) => Ok(Output::Presence(
                Self::observe(
                    history,
                    &self.pending,
                    &mut self.deps,
                    &Address { map, key },
                    view,
                    global,
                )
                .is_some(),
            )),
            Operation::Previous(key) => {
                let address = Address { map, key };
                let cell = view.local.point(history, &address);
                let version = cell_version(&cell);
                self.deps.push(Dependency::Key(address, cell));
                Ok(Output::Previous(version))
            }
            Operation::Write(key, value) => {
                stage_write(
                    &mut self.pending,
                    Address { map, key },
                    Write::from_option(value),
                );
                Ok(Output::Unit)
            }
            Operation::Scan => Ok(Output::Entries(Self::scan(
                history,
                &self.pending,
                &mut self.deps,
                &map,
                view,
            ))),
            Operation::Size => {
                if self.pending.0.is_empty() {
                    let count = view.local.size(history, &map);
                    self.deps.push(Dependency::Map(map, view.local.clone()));
                    return Ok(Output::Size(count));
                }
                Ok(Output::Size(
                    Self::scan(history, &self.pending, &mut self.deps, &map, view).len(),
                ))
            }
            Operation::Clear => {
                let entries = Self::scan(history, &self.pending, &mut self.deps, &map, view);
                let mut i = 0;
                while i < entries.len() {
                    stage_write(
                        &mut self.pending,
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
                if self.pending.0.is_empty() {
                    let rows = view.local.range(history, &map, &lower, &upper);
                    self.deps.push(Dependency::Map(map, view.local.clone()));
                    return Ok(Output::Entries(rows));
                }
                Ok(Output::Entries(ordered_range(
                    &Self::scan(history, &self.pending, &mut self.deps, &map, view),
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
        self.valid_lineage(history) && self.valid_dependencies(history)
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

    fn valid_dependencies(&self, history: &History) -> bool {
        let mut i = 0;
        while i < self.deps.len() {
            if !self.deps[i].holds(&history.index, history.head().data) {
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

trait RangeValue {
    fn range_value(&self) -> &Bytes;
}

impl RangeValue for Bytes {
    fn range_value(&self) -> &Bytes {
        self
    }
}

impl RangeValue for Cell {
    fn range_value(&self) -> &Bytes {
        &self.value
    }
}

fn ordered_range<V: RangeValue>(
    entries: &Vec<(Bytes, V)>,
    lower: &Option<Bytes>,
    upper: &Option<Bytes>,
) -> Entries {
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
            let selected = (row.0.clone(), row.1.range_value().clone());
            // The pinned Aeneas Vec model only supports insert below len.
            if pos == out.len() {
                out.push(selected);
            } else {
                out.insert(pos, selected);
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

fn add_snapshot_map(frame: &mut Frame, rows: &mut Data, map: &SnapshotMap, identity: u64) -> bool {
    if map.revision > frame.version {
        return false;
    }
    if let Some(previous) = frame.births.get(&map.name) {
        if previous.identity == identity {
            return false;
        }
    }
    // A snapshot updates each included map. An omitted map is not a deletion.
    *rows = without_map(rows, &map.name);
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
        if *written == 0 || *written > map.revision || rows.index(&address).is_some() {
            return false;
        }
        rows.0.push((
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
    Applied(Version, Term),
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
                let i = self.tx_index(tx)?;
                let snap = self.txs.0[i].1.snapshot;
                release_tx_pins(&mut self.history.index, &self.txs.0[i].1);
                erase_attempt(&mut self.txs, tx);
                if let Some(s) = snap {
                    self.history.try_elide_compacted_version(s.version, &self.txs);
                }
                self.history.index.retire_budget(RETIRE_BUDGET);
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
                self.txs.0[i].1.acquire(&mut self.history, map)
            }
            Action::Operate(tx, map, op) => {
                let i = self.tx_index(tx)?;
                self.txs.0[i].1.operate(&self.history, map, op)
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
            Action::Apply(tx) => self.apply(tx, true),
            Action::CommitResult(tx, result) => self.finish(tx, result),
            Action::Compact(version) => {
                Ok(Output::Compacted(self.history.compact(version, &self.txs)))
            }
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
                let outcome =
                    if t.valid_lineage(&self.history) && t.valid_dependencies(&self.history) {
                        Outcome::NoReplicate
                    } else {
                        Outcome::Conflict
                    };
                return Ok(CommitPreparation::Rejected(outcome));
            }
        }
        // The CCF adapter has already collected the pending writes while
        // holding the store lock. It only needs the assigned transaction ID.
        match self.apply(tx, false) {
            Ok(Output::Applied(version, term, _)) => Ok(CommitPreparation::Applied(version, term)),
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
        if snapshot.version < self.history.log.active_at(0).version {
            t.unavailable = true;
            return Ok(Output::Unavailable);
        }
        if let Some(global) = self.recovery_views.get(&map) {
            let local_id = self.history.pin_cut(snapshot.version);
            let local = self.history.log.read(local_id);
            let birth = local.births.get(&map);
            if birth.is_some() {
                let revision = local.revision(&map);
                let local_data = local.data;
                if revision.version < global.revision {
                    t.unavailable = true;
                    return Ok(Output::Unavailable);
                }
                let local_root = self.history.retained_data(snapshot.version, local_data);
                self.history.index.retain_root(local_root);
                t.views.set(
                    map,
                    View {
                        birth,
                        revision,
                        local: PinnedImage::Root(local_root),
                        global: Some(PinnedImage::Recovered(global.image)),
                    },
                );
                return Ok(Output::Acquired(revision.version, global.revision));
            }
        }
        t.acquire(&mut self.history, map)
    }

    pub fn compact_ccf(&mut self, version: Version) -> Output {
        let previous = self.history.global;
        let cut = self.history.compact(version, &self.txs);
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
        let (my_frames, my_index) =
            Self::recovery_frames(&self.history, &source.history, &names, my_identity);
        let (their_frames, their_index) =
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
        self.history.log = my_frames;
        source.history.log = their_frames;
        self.history.index = my_index;
        source.history.index = their_index;
        self.history.next_identity = my_identity + 1;
        source.history.next_identity = their_identity + 1;
        self.history.reuse_compacted_images = false;
        source.history.reuse_compacted_images = false;
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
            image: indexed_image(&self.history.index, frame.data, name),
        }
    }

    pub fn snapshot_at_ccf(&mut self, tx: Attempt, version: Version) -> Result<Output, Error> {
        let i = self.tx_index(tx)?;
        let t = &mut self.txs.0[i].1;
        if !matches!(t.phase, Phase::Active)
            || t.snapshot.is_some()
            || version < self.history.log.active_at(0).version
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
        view.operate(&self.history, map, op)
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
        if !frame.meta_live {
            let global_frame = self.history.at_cut(self.history.global);
            if let Some(birth) = global_frame.births.get(map) {
                if birth.version <= version {
                    let rev = global_frame.revision(map).version;
                    return Some(if rev <= version { rev } else { version });
                }
            }
            return None;
        }
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
            let links = self.history.index.scan_map_links(frame.data, name);
            let mut cells = Vec::with_capacity(links.len());
            let mut j = 0;
            while j < links.len() {
                let (address, cell) = self.history.index.scan_row(links[j]);
                append_snapshot_cell(&mut cells, address, cell, name);
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
        let mut rows = indexed_data(&self.history.index, frame.data);
        frame.version = version;
        let mut i = 0;
        while i < maps.len() {
            if !add_snapshot_map(&mut frame, &mut rows, &maps[i], identity) {
                return Err(Error::Disabled);
            }
            i += 1;
        }
        frame.data = index_from_rows(&mut self.history.index, rows);
        let active_len = self.history.log.active_len();
        self.history.release_active_range(0, active_len);
        self.history.log.reset_branch(frame);
        self.history.index.retire_budget(RETIRE_BUDGET);
        self.history.next_identity = identity + 1;
        self.history.global = version;
        self.history.reuse_compacted_images = false;
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

    fn copy_recovery_map(
        dst: &mut Frame,
        rows: &mut Data,
        src: &Frame,
        source_rows: &Data,
        name: &Bytes,
        identity: u64,
    ) {
        *rows = without_map(rows, name);
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
        while i < source_rows.0.len() {
            Self::append_recovery_row(rows, &source_rows.0[i], name);
            i += 1;
        }
    }

    fn append_recovery_row(data: &mut Data, row: &(Address, Cell), name: &Bytes) {
        if row.0.map.same(name) {
            data.0.push((row.0.clone(), row.1.clone()));
        }
    }

    fn recovery_frame(
        output: &mut AddressIndex<Cell>,
        base: &Frame,
        destination: &History,
        source: &History,
        names: &Vec<Bytes>,
        identity: u64,
    ) -> Frame {
        let mut next = base.clone();
        let base_data = destination.retained_data(base.version, base.data);
        let donor = source.at_cut(base.version);
        let donor_data = source.retained_data(donor.version, donor.data);
        let mut rows = indexed_data(&destination.index, base_data);
        let donor_rows = indexed_data(&source.index, donor_data);
        let mut i = 0;
        while i < names.len() {
            Self::copy_recovery_map(
                &mut next,
                &mut rows,
                donor,
                &donor_rows,
                &names[i],
                identity,
            );
            i += 1;
        }
        next.data = index_from_rows(output, rows);
        next
    }

    fn recovery_frames(
        destination: &History,
        source: &History,
        names: &Vec<Bytes>,
        identity: u64,
    ) -> (BranchLog<Frame>, AddressIndex<Cell>) {
        let mut index = AddressIndex::new();
        let mut frames = BranchLog::new(Self::recovery_frame(
            &mut index,
            destination.log.active_at(0),
            destination,
            source,
            names,
            identity,
        ));
        let mut i = 1;
        while i < destination.log.active_len() {
            frames.append(Self::recovery_frame(
                &mut index,
                destination.log.active_at(i),
                destination,
                source,
                names,
                identity,
            ));
            i += 1;
        }
        (frames, index)
    }

    /// Apply an already validated ordinary ledger entry at the next version.
    /// Import does not set the term for subsequent locally authored commits.
    pub fn replay_next(&mut self, version: Version, writes: WriteSet) -> Result<(), Error> {
        self.replay_indexed(version, &writes, false)
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
            let previous = version - 1;
            if previous < self.history.global {
                return Err(Error::Disabled);
            }
            // Validate before cutting back the active branch. The index and
            // all frame IDs stay in the same arena.
            let pending = Self::prepare_replay(
                self.history.at_cut(previous).version,
                self.history.next_identity,
                version,
                &writes,
            )?;
            if !matches!(
                self.history.rollback(previous, self.history.term)?,
                Output::RolledBack(_)
            ) {
                return Err(Error::Disabled);
            }
            self.append_replay(version, &pending, track_deletes);
            return Ok(());
        }
        if version > 1 && self.history.head().version == 0 {
            if !self.txs.0.is_empty() {
                return Err(Error::Disabled);
            }
            let mut isolated = Store::new(self.history.term);
            isolated.history.next_identity = self.history.next_identity;
            isolated.install_snapshot(version - 1, Vec::new())?;
            isolated.replay_indexed(version, &writes, track_deletes)?;
            self.history = isolated.history;
            Ok(())
        } else {
            self.replay_indexed(version, &writes, track_deletes)
        }
    }

    fn replay_indexed(
        &mut self,
        version: Version,
        writes: &WriteSet,
        track_deletes: bool,
    ) -> Result<(), Error> {
        let pending = Self::prepare_replay(
            self.history.head().version,
            self.history.next_identity,
            version,
            writes,
        )?;
        self.append_replay(version, &pending, track_deletes);
        Ok(())
    }

    fn append_replay(&mut self, version: Version, pending: &Pending, track_deletes: bool) {
        let identity = self.history.next_identity;
        let mut next = self.history.prepare_frame(version, identity, pending);
        if track_deletes {
            let mut i = 0;
            while i < pending.0.len() {
                next.revisions
                    .set(pending.0[i].0.map.clone(), Stamp { version, identity });
                i += 1;
            }
        }
        self.history.log.append(next);
        self.history.next_identity += 1;
        self.history.reuse_compacted_images = false;
    }

    fn tx_index(&self, tx: Attempt) -> Result<usize, Error> {
        match self.txs.index(&tx) {
            Some(i) => Ok(i),
            None => Err(Error::Disabled),
        }
    }

    fn prepare_replay(
        previous: Version,
        identity: u64,
        version: Version,
        writes: &WriteSet,
    ) -> Result<Pending, Error> {
        if previous == u64::MAX || identity == u64::MAX {
            return Err(Error::Exhausted);
        }
        if version != previous + 1 {
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
        Ok(pending)
    }

    fn apply(&mut self, tx: Attempt, include_report: bool) -> Result<Output, Error> {
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
        let next = self
            .history
            .prepare_frame(version, self.history.next_identity, &t.pending);
        let writes = if include_report {
            reported_writes(&t.pending)
        } else {
            Vec::new()
        };
        self.history.log.append(next);
        self.history.next_identity += 1;
        self.history.index.retire_budget(RETIRE_BUDGET);
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

fn erase_attempt(rows: &mut Assoc<Attempt, Tx>, id: Attempt) {
    let mut kept = Vec::with_capacity(rows.0.len());
    let mut i = 0;
    while i < rows.0.len() {
        move_other_attempt(&mut kept, &mut rows.0[i], id);
        i += 1;
    }
    rows.0 = kept;
}

fn move_other_attempt(kept: &mut Vec<(Attempt, Tx)>, row: &mut (Attempt, Tx), id: Attempt) {
    if row.0 != id {
        let mut tx = Tx::new();
        core::mem::swap(&mut tx, &mut row.1);
        kept.push((row.0, tx));
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
