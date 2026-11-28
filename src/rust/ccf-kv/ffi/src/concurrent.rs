// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//! Concurrency layer for `ccf_kv::Store`: writer-preferring sharded rwlock,
//! 64-slot hazard table, and structurally enforced hazard synchronization.

use ccf_kv::engine::{
    Action, Address, Bytes, CommitPreparation, DetachedTx, Error, Operation, Outcome, Output,
    PendingLookup, SnapshotMap, Store, ViewLookup, WriteSet,
};
use std::cell::{Cell, UnsafeCell};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

const NUM_STRIPES: usize = 8;
const WRITER_BIT: u32 = 0x8000_0000;
const READER_MASK: u32 = 0x7fff_ffff;
const SPIN_LIMIT: u32 = 512;

const NUM_HAZARD_SLOTS: usize = 64;
const ROOTS_PER_HAZARD: usize = 12;

static NEXT_STRIPE: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static THREAD_STRIPE: Cell<usize> = Cell::new(usize::MAX);
}

#[inline]
fn current_thread_stripe() -> usize {
    THREAD_STRIPE.with(|cell| {
        let mut idx = cell.get();
        if idx == usize::MAX {
            idx = NEXT_STRIPE.fetch_add(1, Ordering::Relaxed) & (NUM_STRIPES - 1);
            cell.set(idx);
        }
        idx
    })
}

#[repr(align(64))]
struct Stripe {
    state: AtomicU32,
}

impl Stripe {
    const fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
        }
    }
}

#[repr(align(64))]
struct AlignedBool(AtomicBool);

#[cfg(ccf_tsan)]
unsafe extern "C" {
    fn __tsan_acquire(addr: *mut std::ffi::c_void);
    fn __tsan_release(addr: *mut std::ffi::c_void);
}

#[inline]
fn tsan_acquire<T>(ptr: *const T) {
    #[cfg(ccf_tsan)]
    unsafe {
        __tsan_acquire(ptr as *mut std::ffi::c_void);
    }
    #[cfg(not(ccf_tsan))]
    let _ = ptr;
}

#[inline]
fn tsan_release<T>(ptr: *const T) {
    #[cfg(ccf_tsan)]
    unsafe {
        __tsan_release(ptr as *mut std::ffi::c_void);
    }
    #[cfg(not(ccf_tsan))]
    let _ = ptr;
}

/// Writer-preferring sharded reader-writer lock.
///
/// Readers only touch their thread-local stripe cache line, while writers set
/// `WRITER_BIT` across all 8 stripes and wait for active readers to drain.
pub(crate) struct ShardedRwLock<T> {
    write_gate: AlignedBool,
    stripes: [Stripe; NUM_STRIPES],
    value: UnsafeCell<T>,
}

// SAFETY: `ShardedRwLock` enforces standard RwLock aliasing rules: `&T` for
// concurrent `ReadGuard`s (`T: Sync`) and exclusive `&mut T` for `WriteGuard`
// (`T: Send`).
unsafe impl<T: Send + Sync> Sync for ShardedRwLock<T> {}
unsafe impl<T: Send> Send for ShardedRwLock<T> {}

pub(crate) struct ReadGuard<'a, T> {
    stripe: &'a AtomicU32,
    value: &'a T,
}

impl<T> Deref for ReadGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        self.value
    }
}

impl<T> Drop for ReadGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        tsan_release(self.stripe);
        self.stripe.fetch_sub(1, Ordering::Release);
    }
}

pub(crate) struct WriteGuard<'a, T> {
    lock: &'a ShardedRwLock<T>,
}

impl<T> Deref for WriteGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: `WriteGuard` holds exclusive access across all stripes.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for WriteGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: `WriteGuard` holds exclusive access across all stripes.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for WriteGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        tsan_release(&self.lock.write_gate);
        for i in (0..NUM_STRIPES).rev() {
            self.lock.stripes[i]
                .state
                .fetch_and(!WRITER_BIT, Ordering::Release);
        }
        self.lock.write_gate.0.store(false, Ordering::Release);
    }
}

impl<T> ShardedRwLock<T> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            write_gate: AlignedBool(AtomicBool::new(false)),
            stripes: [const { Stripe::new() }; NUM_STRIPES],
            value: UnsafeCell::new(value),
        }
    }

    #[inline]
    fn lock_write_gate(&self) {
        let mut spins = 0u32;
        loop {
            if !self.write_gate.0.load(Ordering::Relaxed)
                && !self.write_gate.0.swap(true, Ordering::Acquire)
            {
                return;
            }
            spins += 1;
            if spins < SPIN_LIMIT {
                std::hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        }
    }

    #[inline]
    pub(crate) fn read(&self) -> ReadGuard<'_, T> {
        let stripe = &self.stripes[current_thread_stripe()].state;
        let mut spins = 0u32;
        loop {
            if (stripe.load(Ordering::Relaxed) & WRITER_BIT) == 0 {
                let prev = stripe.fetch_add(1, Ordering::AcqRel);
                if (prev & WRITER_BIT) == 0 {
                    tsan_acquire(&self.write_gate);
                    // SAFETY: No writer can observe READER_MASK == 0 while our
                    // increment is live.
                    let value = unsafe { &*self.value.get() };
                    return ReadGuard { stripe, value };
                }
                stripe.fetch_sub(1, Ordering::Release);
            }
            spins += 1;
            if spins < SPIN_LIMIT {
                std::hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        }
    }

    #[inline]
    pub(crate) fn write(&self) -> WriteGuard<'_, T> {
        self.lock_write_gate();
        for stripe in &self.stripes {
            stripe.state.fetch_or(WRITER_BIT, Ordering::AcqRel);
        }
        for stripe in &self.stripes {
            let mut spins = 0u32;
            while (stripe.state.load(Ordering::Acquire) & READER_MASK) != 0 {
                spins += 1;
                if spins < SPIN_LIMIT {
                    std::hint::spin_loop();
                } else {
                    std::thread::yield_now();
                }
            }
            tsan_acquire(&stripe.state);
        }
        tsan_acquire(&self.write_gate);
        WriteGuard { lock: self }
    }
}

#[repr(align(64))]
struct HazardSlot {
    snap_plus_one: AtomicU64,
    roots: [AtomicU32; ROOTS_PER_HAZARD],
}

impl HazardSlot {
    const fn new() -> Self {
        Self {
            snap_plus_one: AtomicU64::new(0),
            roots: [const { AtomicU32::new(0) }; ROOTS_PER_HAZARD],
        }
    }
}

#[repr(align(64))]
struct AlignedMask(AtomicU64);

struct HazardTable {
    claimed_mask: AlignedMask,
    slots: [HazardSlot; NUM_HAZARD_SLOTS],
}

impl HazardTable {
    fn new() -> Self {
        Self {
            claimed_mask: AlignedMask(AtomicU64::new(0)),
            slots: [const { HazardSlot::new() }; NUM_HAZARD_SLOTS],
        }
    }

    #[inline]
    fn try_claim(&self) -> Option<usize> {
        let start = ((current_thread_stripe() * 8) % NUM_HAZARD_SLOTS) as u32;
        let mut mask = self.claimed_mask.0.load(Ordering::Relaxed);
        loop {
            let free = !mask;
            if free == 0 {
                return None;
            }
            let rot = free.rotate_right(start);
            let idx = ((rot.trailing_zeros() + start) % (NUM_HAZARD_SLOTS as u32)) as usize;
            let bit = 1u64 << idx;
            match self.claimed_mask.0.compare_exchange_weak(
                mask,
                mask | bit,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(idx),
                Err(actual) => mask = actual,
            }
        }
    }

    #[inline]
    fn release(&self, slot_idx: usize) {
        let slot = &self.slots[slot_idx];
        for r in &slot.roots {
            if r.load(Ordering::Relaxed) != 0 {
                r.store(0, Ordering::Release);
            }
        }
        if slot.snap_plus_one.load(Ordering::Relaxed) != 0 {
            slot.snap_plus_one.store(0, Ordering::Release);
        }
        let bit = 1u64 << slot_idx;
        self.claimed_mask.0.fetch_and(!bit, Ordering::Release);
    }

    #[inline]
    fn free_root_entries(&self, slot_idx: usize) -> usize {
        let mut count = 0;
        for r in &self.slots[slot_idx].roots {
            if r.load(Ordering::Relaxed) == 0 {
                count += 1;
            }
        }
        count
    }

    #[inline]
    fn publish_roots(&self, slot_idx: usize, r0: u32, r1: u32, snap_version: u64) {
        let slot = &self.slots[slot_idx];
        for root in [r0, r1] {
            if root == 0 {
                continue;
            }
            for entry in &slot.roots {
                let cur = entry.load(Ordering::Relaxed);
                if cur == root {
                    break;
                }
                if cur == 0 {
                    entry.store(root, Ordering::Release);
                    break;
                }
            }
        }
        if slot.snap_plus_one.load(Ordering::Relaxed) == 0 {
            slot.snap_plus_one
                .store(snap_version.saturating_add(1), Ordering::Release);
        }
    }
}

struct HazardBookkeeping {
    retained_roots: Vec<u32>,
    pinned_snaps: Vec<(u64, u64)>,
    next_pin_id: u64,
}

impl HazardBookkeeping {
    fn new() -> Self {
        Self {
            retained_roots: Vec::new(),
            pinned_snaps: Vec::new(),
            next_pin_id: 1u64 << 63,
        }
    }
}

struct StoreState {
    store: Store,
    hazards: HazardBookkeeping,
}

fn sync_hazards_locked(state: &mut StoreState, table: &HazardTable) {
    let mut mask = table.claimed_mask.0.load(Ordering::Acquire);
    if mask == 0 && state.hazards.retained_roots.is_empty() && state.hazards.pinned_snaps.is_empty()
    {
        return;
    }

    let mut active_roots = [0u32; NUM_HAZARD_SLOTS * ROOTS_PER_HAZARD];
    let mut active_root_count = 0usize;
    let mut active_snaps = [0u64; NUM_HAZARD_SLOTS];
    let mut active_snap_count = 0usize;

    while mask != 0 {
        let idx = mask.trailing_zeros() as usize;
        mask &= mask - 1;
        let slot = &table.slots[idx];

        let sp = slot.snap_plus_one.load(Ordering::Acquire);
        if sp != 0 {
            let ver = sp - 1;
            if !active_snaps[..active_snap_count].contains(&ver) {
                active_snaps[active_snap_count] = ver;
                active_snap_count += 1;
            }
        }
        for r in &slot.roots {
            let root = r.load(Ordering::Acquire);
            if root != 0 && !active_roots[..active_root_count].contains(&root) {
                active_roots[active_root_count] = root;
                active_root_count += 1;
            }
        }
    }

    let active_roots = &active_roots[..active_root_count];
    let active_snaps = &active_snaps[..active_snap_count];

    for &root in active_roots {
        if !state.hazards.retained_roots.contains(&root) {
            state.store.retain_root_raw(root);
            state.hazards.retained_roots.push(root);
        }
    }
    let mut i = 0;
    while i < state.hazards.retained_roots.len() {
        let root = state.hazards.retained_roots[i];
        if !active_roots.contains(&root) {
            state.store.release_root_raw(root);
            state.hazards.retained_roots.swap_remove(i);
        } else {
            i += 1;
        }
    }

    for &ver in active_snaps {
        if !state
            .hazards
            .pinned_snaps
            .iter()
            .any(|(existing, _)| *existing == ver)
        {
            let pin_id = state.hazards.next_pin_id;
            state.hazards.next_pin_id = pin_id.wrapping_add(1);
            state.store.pin_snapshot_stub(pin_id, ver);
            state.hazards.pinned_snaps.push((ver, pin_id));
        }
    }
    let mut i = 0;
    while i < state.hazards.pinned_snaps.len() {
        let (ver, pin_id) = state.hazards.pinned_snaps[i];
        if !active_snaps.contains(&ver) {
            state.store.unpin_snapshot_stub(pin_id);
            state.hazards.pinned_snaps.swap_remove(i);
        } else {
            i += 1;
        }
    }
}

/// Thread-private transaction handle owned by a single transaction at a time.
pub(crate) struct NativeTx {
    tx: DetachedTx,
    hazard_slot: Option<usize>,
}

impl NativeTx {
    pub(crate) fn new(attempt: u64) -> Self {
        Self {
            tx: DetachedTx::new(attempt),
            hazard_slot: None,
        }
    }

    pub(crate) fn stage_write_bytes(
        &mut self,
        map: &[u8],
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.tx.stage_write_bytes(map, key, value)
    }

    pub(crate) fn pending_writes(&self) -> Result<WriteSet, Error> {
        self.tx.pending_writes()
    }

    pub(crate) fn finish(&mut self, outcome: Outcome) -> Result<Output, Error> {
        self.tx.finish(outcome)
    }
}

/// Thread-safe wrapper around `ccf_kv::Store` that owns `ShardedRwLock` and
/// `HazardTable`.
///
/// Every method that can drop or replace active frames, recycle radix slots,
/// or release roots goes through `write_synced`, making it structurally
/// impossible to mutate the branch without first promoting active hazard pins.
pub(crate) struct ConcurrentStore {
    lock: ShardedRwLock<StoreState>,
    hazards: HazardTable,
}

impl ConcurrentStore {
    pub(crate) fn new(term: u64) -> Self {
        Self {
            lock: ShardedRwLock::new(StoreState {
                store: Store::new(term),
                hazards: HazardBookkeeping::new(),
            }),
            hazards: HazardTable::new(),
        }
    }

    #[inline]
    fn write_synced<R>(&self, post_sync: bool, f: impl FnOnce(&mut Store) -> R) -> R {
        let mut guard = self.lock.write();
        sync_hazards_locked(&mut guard, &self.hazards);
        let res = f(&mut guard.store);
        if post_sync {
            sync_hazards_locked(&mut guard, &self.hazards);
        }
        res
    }

    /// Release a transaction's hazard slot (lock-free) and, if registered,
    /// unregister it from the store under a synced write guard.
    pub(crate) fn delete_tx(&self, mut tx: NativeTx) {
        if let Some(slot_idx) = tx.hazard_slot.take() {
            self.hazards.release(slot_idx);
        }
        if tx.tx.is_registered() {
            self.write_synced(false, |store| store.end_detached(&mut tx.tx));
        }
    }

    pub(crate) fn acquire_map(
        &self,
        tx: &mut NativeTx,
        map: Bytes,
        explicit_version: Option<u64>,
        on_locked: impl FnOnce(&Result<(u64, u64, Output), Error>),
    ) -> Result<(u64, u64, Output), Error> {
        if !tx.tx.is_registered() && explicit_version.is_none() {
            if tx.hazard_slot.is_none() {
                tx.hazard_slot = self.hazards.try_claim();
            }
            if let Some(slot_idx) = tx.hazard_slot {
                if self.hazards.free_root_entries(slot_idx) >= 2 {
                    let guard = self.lock.read();
                    let raw = guard.store.snapshot_and_acquire_readonly(&mut tx.tx, map);
                    let res = match raw {
                        Ok((ver, term, out, r0, r1)) => {
                            if matches!(out, Output::Acquired(..)) {
                                self.hazards.publish_roots(slot_idx, r0, r1, ver);
                            }
                            Ok((ver, term, out))
                        }
                        Err(e) => Err(e),
                    };
                    on_locked(&res);
                    return res;
                }
                // Per-transaction hazard slot full: promote under write lock.
                let mut guard = self.lock.write();
                guard.store.promote_detached_tx(&mut tx.tx)?;
                self.hazards.release(slot_idx);
                tx.hazard_slot = None;
                let res = guard
                    .store
                    .snapshot_and_acquire_detached(&mut tx.tx, map, None);
                on_locked(&res);
                return res;
            }
        }

        // Fallback: already registered, explicit snapshot version, or all 64
        // hazard slots are currently claimed.
        let mut guard = self.lock.write();
        if let Some(slot_idx) = tx.hazard_slot.take() {
            guard.store.promote_detached_tx(&mut tx.tx)?;
            self.hazards.release(slot_idx);
        }
        let res = guard
            .store
            .snapshot_and_acquire_detached(&mut tx.tx, map, explicit_version);
        on_locked(&res);
        res
    }

    pub(crate) fn tx_get<R>(
        &self,
        tx: &mut NativeTx,
        inspect_finished: bool,
        read_only: bool,
        global: bool,
        map: &[u8],
        key: &[u8],
        on_val: impl FnOnce(Option<&[u8]>) -> R,
    ) -> Result<R, Error> {
        if !global && !read_only {
            match tx.tx.lookup_pending_bytes(map, key, inspect_finished)? {
                PendingLookup::Put(val) => return Ok(on_val(Some(val))),
                PendingLookup::Remove => return Ok(on_val(None)),
                PendingLookup::Miss => {}
            }
        }
        let guard = self.lock.read();
        let view = tx
            .tx
            .lookup_view_bytes(map, key, global, inspect_finished)?;
        let cell = match view {
            ViewLookup::Empty => None,
            ViewLookup::Root(root) => guard.store.get_cell_bytes(root, map, key),
            ViewLookup::Recovered(c) => c,
        };
        let out = on_val(cell.map(|(_, val)| val));
        if !global && !inspect_finished && !read_only {
            let dep = cell.map(|(v, b)| (v, Bytes::copy_from(b)));
            tx.tx.record_key_dep_bytes(map, key, dep);
        }
        Ok(out)
    }

    pub(crate) fn tx_has(
        &self,
        tx: &mut NativeTx,
        inspect_finished: bool,
        read_only: bool,
        global: bool,
        map: &[u8],
        key: &[u8],
    ) -> Result<bool, Error> {
        if !global && !read_only {
            match tx.tx.lookup_pending_bytes(map, key, inspect_finished)? {
                PendingLookup::Put(_) => return Ok(true),
                PendingLookup::Remove => return Ok(false),
                PendingLookup::Miss => {}
            }
        }
        let guard = self.lock.read();
        let view = tx
            .tx
            .lookup_view_bytes(map, key, global, inspect_finished)?;
        let cell = match view {
            ViewLookup::Empty => None,
            ViewLookup::Root(root) => guard.store.get_cell_bytes(root, map, key),
            ViewLookup::Recovered(c) => c,
        };
        let present = cell.is_some();
        if !global && !inspect_finished && !read_only {
            let dep = cell.map(|(v, b)| (v, Bytes::copy_from(b)));
            tx.tx.record_key_dep_bytes(map, key, dep);
        }
        Ok(present)
    }

    pub(crate) fn tx_previous(
        &self,
        tx: &mut NativeTx,
        inspect_finished: bool,
        read_only: bool,
        map: &[u8],
        key: &[u8],
    ) -> Result<Option<u64>, Error> {
        let guard = self.lock.read();
        let view = tx.tx.lookup_view_bytes(map, key, false, inspect_finished)?;
        let cell = match view {
            ViewLookup::Empty => None,
            ViewLookup::Root(root) => guard.store.get_cell_bytes(root, map, key),
            ViewLookup::Recovered(c) => c,
        };
        let version = cell.map(|(v, _)| v);
        if !inspect_finished && !read_only {
            let dep = cell.map(|(v, b)| (v, Bytes::copy_from(b)));
            tx.tx.record_key_dep_bytes(map, key, dep);
        }
        Ok(version)
    }

    pub(crate) fn tx_operate(
        &self,
        tx: &mut NativeTx,
        inspect_finished: bool,
        map: Bytes,
        op: Operation,
    ) -> Result<Output, Error> {
        if !inspect_finished {
            if let Operation::Write(key, value) = op {
                return tx.tx.stage_write(map, key, value).map(|()| Output::Unit);
            }
        }
        let guard = self.lock.read();
        if inspect_finished {
            tx.tx.inspect_finished(&guard.store, map, op)
        } else {
            tx.tx.operate(&guard.store, map, op)
        }
    }

    /// Append-only normal commit: never drops or replaces existing active
    /// frames, so pre-existing hazard roots remain pinned by `activeFrames`
    /// or prior `retained_roots`.
    pub(crate) fn prepare_commit(
        &self,
        tx: &mut NativeTx,
        on_locked: impl FnOnce(&Result<CommitPreparation, Error>),
    ) -> Result<CommitPreparation, Error> {
        let mut guard = self.lock.write();
        let res = guard.store.prepare_ccf_commit_detached(&mut tx.tx);
        on_locked(&res);
        res
    }

    /// Append-only placeholder reservation: retains head root and appends one
    /// frame without releasing any existing root.
    pub(crate) fn reserve_version(&self) -> Result<u64, Error> {
        let mut guard = self.lock.write();
        guard.store.reserve_placeholder_ccf()
    }

    /// Reserved-slot backfill replaces active frames and releases their old
    /// roots, so hazard synchronization is enforced unconditionally.
    pub(crate) fn commit_reserved(
        &self,
        tx: &mut NativeTx,
        version: u64,
    ) -> Result<CommitPreparation, Error> {
        self.write_synced(false, |store| {
            store.backfill_reserved_ccf(&mut tx.tx, version)
        })
    }

    pub(crate) fn snapshot_maps(&self, version: u64) -> Result<Vec<SnapshotMap>, Error> {
        let guard = self.lock.read();
        guard.store.snapshot_maps(version)
    }

    pub(crate) fn map_revision_at(&self, version: u64, map: &Bytes) -> Option<u64> {
        let guard = self.lock.read();
        guard.store.map_revision_at(version, map)
    }

    pub(crate) fn clear_idle(&self) -> Result<(), Error> {
        let mut guard = self.lock.write();
        sync_hazards_locked(&mut guard, &self.hazards);
        guard.store.clear_idle()?;
        guard.hazards.retained_roots.clear();
        guard.hazards.pinned_snaps.clear();
        Ok(())
    }

    pub(crate) fn replay(
        &self,
        version: u64,
        writes: Vec<(Address, Option<Bytes>)>,
        track_deletes: bool,
    ) -> Result<(), Error> {
        self.write_synced(true, |store| {
            store.replay_ccf(version, writes, track_deletes)
        })
    }

    pub(crate) fn install_snapshot(
        &self,
        version: u64,
        maps: Vec<SnapshotMap>,
    ) -> Result<(), Error> {
        self.write_synced(false, |store| store.install_snapshot(version, maps))
    }

    pub(crate) fn swap_recovery_maps(
        &self,
        source: &ConcurrentStore,
        names: Vec<Bytes>,
    ) -> Result<(), Error> {
        let self_ptr = self as *const ConcurrentStore as usize;
        let source_ptr = source as *const ConcurrentStore as usize;
        if self_ptr == source_ptr {
            return Err(Error::Disabled);
        }
        if self_ptr < source_ptr {
            let mut target_guard = self.lock.write();
            let mut source_guard = source.lock.write();
            sync_hazards_locked(&mut target_guard, &self.hazards);
            sync_hazards_locked(&mut source_guard, &source.hazards);
            target_guard
                .store
                .swap_recovery_maps(&mut source_guard.store, names)
        } else {
            let mut source_guard = source.lock.write();
            let mut target_guard = self.lock.write();
            sync_hazards_locked(&mut target_guard, &self.hazards);
            sync_hazards_locked(&mut source_guard, &source.hazards);
            target_guard
                .store
                .swap_recovery_maps(&mut source_guard.store, names)
        }
    }

    pub(crate) fn execute_synced<R>(&self, post_sync: bool, f: impl FnOnce(&mut Store) -> R) -> R {
        self.write_synced(post_sync, f)
    }

    pub(crate) fn execute_set_term(&self, term: u64) -> Result<Output, Error> {
        let mut guard = self.lock.write();
        guard.store.execute(Action::SetTerm(term))
    }

    pub(crate) fn is_valid_map_name(map: &[u8]) -> bool {
        if map.is_empty() {
            return false;
        }
        let Ok(name) = std::str::from_utf8(map) else {
            return false;
        };
        let stripped = name.strip_prefix("public:").unwrap_or(name);
        if stripped.starts_with("ccf.")
            && !stripped.starts_with("ccf.internal.")
            && !stripped.starts_with("ccf.gov.")
        {
            return false;
        }
        true
    }

    fn ensure_direct_map(
        &self,
        tx: &mut NativeTx,
        map: &[u8],
        snap_ver: &mut u64,
        commit_view: &mut u64,
        has_snap: &mut u8,
    ) -> Result<bool, Error> {
        match self.acquire_map(tx, Bytes::copy_from(map), None, |_| {})? {
            (ver, term, Output::Acquired(..)) => {
                if *has_snap == 0 {
                    *snap_ver = ver;
                    *commit_view = term;
                    *has_snap = 1;
                }
                Ok(true)
            }
            (ver, term, Output::Unavailable) => {
                if *has_snap == 0 {
                    *snap_ver = ver;
                    *commit_view = term;
                    *has_snap = 1;
                }
                Ok(false)
            }
            _ => Err(Error::Disabled),
        }
    }

    pub(crate) fn direct_get<R>(
        &self,
        tx: &mut NativeTx,
        read_only: bool,
        map: &[u8],
        key: &[u8],
        snap_ver: &mut u64,
        commit_view: &mut u64,
        has_snap: &mut u8,
        on_val: impl FnOnce(Option<&[u8]>) -> R,
    ) -> Result<Option<R>, Error> {
        let mut on_val = Some(on_val);
        match self.tx_get(tx, false, read_only, false, map, key, |v| {
            (on_val.take().unwrap())(v)
        }) {
            Ok(res) => Ok(Some(res)),
            Err(Error::Disabled) => {
                if !self.ensure_direct_map(tx, map, snap_ver, commit_view, has_snap)? {
                    return Ok(None);
                }
                let res = self.tx_get(tx, false, read_only, false, map, key, |v| {
                    (on_val.take().unwrap())(v)
                })?;
                Ok(Some(res))
            }
            Err(e) => Err(e),
        }
    }

    pub(crate) fn direct_has(
        &self,
        tx: &mut NativeTx,
        read_only: bool,
        map: &[u8],
        key: &[u8],
        snap_ver: &mut u64,
        commit_view: &mut u64,
        has_snap: &mut u8,
    ) -> Result<Option<bool>, Error> {
        match self.tx_has(tx, false, read_only, false, map, key) {
            Ok(present) => Ok(Some(present)),
            Err(Error::Disabled) => {
                if !self.ensure_direct_map(tx, map, snap_ver, commit_view, has_snap)? {
                    return Ok(None);
                }
                let present = self.tx_has(tx, false, read_only, false, map, key)?;
                Ok(Some(present))
            }
            Err(e) => Err(e),
        }
    }

    pub(crate) fn direct_write(
        &self,
        tx: &mut NativeTx,
        map: &[u8],
        key: &[u8],
        value: Option<&[u8]>,
        snap_ver: &mut u64,
        commit_view: &mut u64,
        has_snap: &mut u8,
    ) -> Result<bool, Error> {
        match tx.stage_write_bytes(map, key, value) {
            Ok(()) => Ok(true),
            Err(Error::Disabled) => {
                if !self.ensure_direct_map(tx, map, snap_ver, commit_view, has_snap)? {
                    return Ok(false);
                }
                tx.stage_write_bytes(map, key, value)?;
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn b(s: &str) -> Bytes {
        Bytes::copy_from(s.as_bytes())
    }

    fn seed_store(store: &ConcurrentStore, num_maps: usize, keys_per_map: usize) {
        assert!(store.execute_set_term(2).is_ok());
        let mut tx = NativeTx::new(1);
        for m in 0..num_maps {
            let map_name = format!("public:m{m}");
            let res = store.acquire_map(&mut tx, b(&map_name), None, |_| {});
            assert!(res.is_ok());
            for k in 0..keys_per_map {
                let key = format!("k{k:04}");
                let val = format!("v0_{m}_{k}");
                tx.stage_write_bytes(map_name.as_bytes(), key.as_bytes(), Some(val.as_bytes()))
                    .unwrap();
            }
        }
        match store.prepare_commit(&mut tx, |_| {}).unwrap() {
            CommitPreparation::Applied(1, 2) => {}
            _ => panic!("unexpected commit prep"),
        }
        tx.finish(Outcome::Success).unwrap();
        store.delete_tx(tx);
    }

    #[test]
    fn hazard_slot_saturation_and_promotion_stress() {
        // 80 concurrent readers (> 64 hazard slots) holding snapshots across
        // concurrent normal writes, reserved backfills, and compactions.
        let store = Arc::new(ConcurrentStore::new(2));
        seed_store(&store, 2, 16);

        let stop = Arc::new(AtomicBool::new(false));
        let next_attempt = Arc::new(AtomicU64::new(100));

        // Pin 70 long-lived read transactions to saturate all 64 hazard slots
        // and force the registered fallback path for the remaining 6.
        let mut pinned = Vec::new();
        for _ in 0..70 {
            let mut rtx = NativeTx::new(next_attempt.fetch_add(1, Ordering::Relaxed));
            store
                .acquire_map(&mut rtx, b("public:m0"), None, |_| {})
                .unwrap();
            pinned.push(rtx);
        }

        let mut handles = Vec::new();
        for r in 0..8 {
            let st = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            let na = Arc::clone(&next_attempt);
            handles.push(thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let mut rtx = NativeTx::new(na.fetch_add(1, Ordering::Relaxed));
                    if st
                        .acquire_map(&mut rtx, b("public:m0"), None, |_| {})
                        .is_ok()
                    {
                        let key = format!("k{:04}", r % 16);
                        let v1 = st
                            .tx_get(
                                &mut rtx,
                                false,
                                true,
                                false,
                                b"public:m0",
                                key.as_bytes(),
                                |v| v.map(|s| s.to_vec()),
                            )
                            .unwrap();
                        thread::yield_now();
                        let v2 = st
                            .tx_get(
                                &mut rtx,
                                false,
                                true,
                                false,
                                b"public:m0",
                                key.as_bytes(),
                                |v| v.map(|s| s.to_vec()),
                            )
                            .unwrap();
                        assert_eq!(v1, v2, "snapshot non-repeatable read");
                    }
                    st.delete_tx(rtx);
                }
            }));
        }

        // Normal writers advancing the active branch.
        for w in 0..2 {
            let st = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            let na = Arc::clone(&next_attempt);
            handles.push(thread::spawn(move || {
                let mut iter = 0u64;
                while !stop.load(Ordering::Acquire) {
                    let mut tx = NativeTx::new(na.fetch_add(1, Ordering::Relaxed));
                    if st
                        .acquire_map(&mut tx, b("public:m0"), None, |_| {})
                        .is_ok()
                    {
                        let key = format!("k{:04}", (w * 8 + (iter as usize % 8)) % 16);
                        let val = format!("w{w}_{iter}");
                        let _ = tx.stage_write_bytes(
                            b"public:m0",
                            key.as_bytes(),
                            Some(val.as_bytes()),
                        );
                        if let Ok(CommitPreparation::Applied(..)) =
                            st.prepare_commit(&mut tx, |_| {})
                        {
                            let _ = tx.finish(Outcome::Success);
                        }
                    }
                    st.delete_tx(tx);
                    iter += 1;
                }
            }));
        }

        // Reserved backfill + compaction loop on the main thread.
        for i in 0..40u64 {
            let reserved_ver = store.reserve_version().unwrap();
            thread::yield_now();
            let mut rtx = NativeTx::new(next_attempt.fetch_add(1, Ordering::Relaxed));
            store
                .acquire_map(&mut rtx, b("public:m1"), Some(reserved_ver - 1), |_| {})
                .unwrap();
            let val = format!("sig_{i}");
            rtx.stage_write_bytes(b"public:m1", b"k0000", Some(val.as_bytes()))
                .unwrap();
            match store.commit_reserved(&mut rtx, reserved_ver).unwrap() {
                CommitPreparation::Applied(v, 2) => assert_eq!(v, reserved_ver),
                _ => panic!("unexpected reserved commit"),
            }
            rtx.finish(Outcome::Success).unwrap();
            store.delete_tx(rtx);
            if i % 4 == 3 {
                store.execute_synced(true, |s| s.compact_ccf(reserved_ver));
            }
        }

        stop.store(true, Ordering::Release);
        for h in handles {
            h.join().unwrap();
        }

        // Every one of the 70 pinned readers must still see its original v0 snapshot.
        for mut rtx in pinned {
            let v = store
                .tx_get(
                    &mut rtx,
                    false,
                    true,
                    false,
                    b"public:m0",
                    b"k0000",
                    |val| val.map(|s| s.to_vec()),
                )
                .unwrap();
            assert_eq!(v.as_deref(), Some(b"v0_0_0".as_slice()));
            store.delete_tx(rtx);
        }

        // After all readers drop, sync must drain all hazard pins cleanly.
        store.execute_synced(true, |s| s.compact_ccf(u64::MAX));
        let guard = store.lock.write();
        assert_eq!(store.hazards.claimed_mask.0.load(Ordering::Acquire), 0);
        assert!(guard.hazards.retained_roots.is_empty());
        assert!(guard.hazards.pinned_snaps.is_empty());
    }

    #[test]
    fn multi_map_hazard_overflow_promotion_stress() {
        // Trigger > ROOTS_PER_HAZARD (12) distinct roots inside a single
        // transaction by advancing `global` via compactions between map
        // acquisitions, forcing mid-transaction promotion from hazard slot to
        // registered tx under concurrent writers and compactions.
        let store = Arc::new(ConcurrentStore::new(2));
        seed_store(&store, 20, 4);

        let next_attempt = Arc::new(AtomicU64::new(100));

        // Open a long-lived reader at v = 1, then advance and compact 15 times
        // while acquiring a fresh map after each compaction so `global_data`
        // yields > 12 distinct roots in one transaction.
        let mut long_tx = NativeTx::new(next_attempt.fetch_add(1, Ordering::Relaxed));
        store
            .acquire_map(&mut long_tx, b("public:m0"), None, |_| {})
            .unwrap();
        assert!(!long_tx.tx.is_registered());
        assert!(long_tx.hazard_slot.is_some());

        for i in 1..16usize {
            // Commit a write to an unrelated map and compact so `global_data`
            // gets a new distinct radix root without invalidating `public:m{i}`.
            let mut wtx = NativeTx::new(next_attempt.fetch_add(1, Ordering::Relaxed));
            store
                .acquire_map(&mut wtx, b("public:m19"), None, |_| {})
                .unwrap();
            let val = format!("upd_{i}");
            wtx.stage_write_bytes(b"public:m19", b"k0000", Some(val.as_bytes()))
                .unwrap();
            let v = match store.prepare_commit(&mut wtx, |_| {}).unwrap() {
                CommitPreparation::Applied(v, _) => v,
                _ => panic!("expected commit"),
            };
            wtx.finish(Outcome::Success).unwrap();
            store.delete_tx(wtx);
            store.execute_synced(true, |s| s.compact_ccf(v));

            let map_name = format!("public:m{i}");
            let res = store.acquire_map(&mut long_tx, b(&map_name), None, |_| {});
            assert!(res.is_ok());
            let val = store
                .tx_get(
                    &mut long_tx,
                    false,
                    true,
                    false,
                    map_name.as_bytes(),
                    b"k0000",
                    |v| v.map(|s| s.to_vec()),
                )
                .unwrap();
            assert_eq!(val.as_deref(), Some(format!("v0_{i}_0").as_bytes()));
        }

        // Acquiring > 12 distinct global roots must have promoted the tx.
        assert!(long_tx.tx.is_registered());
        assert!(long_tx.hazard_slot.is_none());

        // Verify earlier maps remain readable after promotion + compaction.
        for i in 0..16usize {
            let map_name = format!("public:m{i}");
            let val = store
                .tx_get(
                    &mut long_tx,
                    false,
                    true,
                    false,
                    map_name.as_bytes(),
                    b"k0000",
                    |v| v.map(|s| s.to_vec()),
                )
                .unwrap();
            assert_eq!(val.as_deref(), Some(format!("v0_{i}_0").as_bytes()));
        }
        store.delete_tx(long_tx);

        store.execute_synced(true, |s| s.compact_ccf(u64::MAX));
        let guard = store.lock.write();
        assert_eq!(store.hazards.claimed_mask.0.load(Ordering::Acquire), 0);
        assert!(guard.hazards.retained_roots.is_empty());
        assert!(guard.hazards.pinned_snaps.is_empty());
    }

    #[test]
    fn concurrent_rollback_replay_and_snapshot_install_stress() {
        let store = Arc::new(ConcurrentStore::new(2));
        seed_store(&store, 2, 8);

        let stop = Arc::new(AtomicBool::new(false));
        let next_attempt = Arc::new(AtomicU64::new(100));

        let mut handles = Vec::new();
        for r in 0..4 {
            let st = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            let na = Arc::clone(&next_attempt);
            handles.push(thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let mut rtx = NativeTx::new(na.fetch_add(1, Ordering::Relaxed));
                    if let Ok((_, _, Output::Acquired(..))) =
                        st.acquire_map(&mut rtx, b("public:m0"), None, |_| {})
                    {
                        let key = format!("k{:04}", r % 8);
                        let v1 = st
                            .tx_get(
                                &mut rtx,
                                false,
                                true,
                                false,
                                b"public:m0",
                                key.as_bytes(),
                                |v| v.map(|s| s.to_vec()),
                            )
                            .unwrap();
                        thread::yield_now();
                        let v2 = st
                            .tx_get(
                                &mut rtx,
                                false,
                                true,
                                false,
                                b"public:m0",
                                key.as_bytes(),
                                |v| v.map(|s| s.to_vec()),
                            )
                            .unwrap();
                        assert_eq!(v1, v2, "snapshot changed across rollback/replay/install");
                    }
                    st.delete_tx(rtx);
                }
            }));
        }

        let mut head = 1u64;
        for round in 0..10u64 {
            // Replay 3 versions ahead, then roll back 2, then install a snapshot.
            for step in 1..=3u64 {
                let v = head + step;
                let writes = vec![(
                    Address {
                        map: b("public:m0"),
                        key: b("k0000"),
                    },
                    Some(b(&format!("r{round}_{step}"))),
                )];
                store.replay(v, writes, false).unwrap();
            }
            store
                .execute_synced(true, |s| s.execute(Action::Rollback(head + 1, 2 + round)))
                .unwrap();
            head += 1;

            let snap_ver = head + 1;
            let snap_maps = vec![SnapshotMap {
                name: b("public:m0"),
                revision: snap_ver,
                cells: (0..8)
                    .map(|k| {
                        (
                            b(&format!("k{k:04}")),
                            snap_ver,
                            b(&format!("snap_{round}_{k}")),
                        )
                    })
                    .collect(),
            }];
            store.install_snapshot(snap_ver, snap_maps).unwrap();
            head = snap_ver;
        }

        stop.store(true, Ordering::Release);
        for h in handles {
            h.join().unwrap();
        }

        store.execute_synced(true, |s| s.compact_ccf(u64::MAX));
        let guard = store.lock.write();
        assert_eq!(store.hazards.claimed_mask.0.load(Ordering::Acquire), 0);
        assert!(guard.hazards.retained_roots.is_empty());
        assert!(guard.hazards.pinned_snaps.is_empty());
    }

    #[test]
    fn swap_recovery_maps_canonical_lock_order() {
        let a = Arc::new(ConcurrentStore::new(1));
        let b_store = Arc::new(ConcurrentStore::new(1));
        seed_store(&a, 1, 4);
        seed_store(&b_store, 1, 4);

        let a1 = Arc::clone(&a);
        let b1 = Arc::clone(&b_store);
        let t1 = thread::spawn(move || {
            for _ in 0..20 {
                let _ = a1.swap_recovery_maps(&b1, vec![b("public:m0")]);
            }
        });
        let a2 = Arc::clone(&a);
        let b2 = Arc::clone(&b_store);
        let t2 = thread::spawn(move || {
            for _ in 0..20 {
                let _ = b2.swap_recovery_maps(&a2, vec![b("public:m0")]);
            }
        });
        t1.join().unwrap();
        t2.join().unwrap();
    }

    #[test]
    fn direct_kv_fast_path_and_validation() {
        let store = ConcurrentStore::new(2);
        seed_store(&store, 2, 4);

        // Map name validation matches C++ parse_map_name.
        assert!(ConcurrentStore::is_valid_map_name(b"records"));
        assert!(ConcurrentStore::is_valid_map_name(b"public:records"));
        assert!(ConcurrentStore::is_valid_map_name(
            b"public:ccf.gov.members"
        ));
        assert!(ConcurrentStore::is_valid_map_name(b"ccf.internal.tree"));
        assert!(!ConcurrentStore::is_valid_map_name(b""));
        assert!(!ConcurrentStore::is_valid_map_name(b"ccf.reserved"));
        assert!(!ConcurrentStore::is_valid_map_name(b"public:ccf.reserved"));
        assert!(!ConcurrentStore::is_valid_map_name(&[0xff, 0xfe]));

        // Read-write direct put/get/has/empty/remove + commit.
        let mut tx = NativeTx::new(10);
        let (mut snap_ver, mut commit_view, mut has_snap) = (0u64, 0u64, 0u8);
        assert_eq!(
            store
                .direct_has(
                    &mut tx,
                    false,
                    b"public:m0",
                    b"k0000",
                    &mut snap_ver,
                    &mut commit_view,
                    &mut has_snap,
                )
                .unwrap(),
            Some(true)
        );
        assert_eq!(has_snap, 1);
        assert_eq!(snap_ver, 1);
        assert_eq!(commit_view, 2);

        // Put a new key, an empty value, and remove an existing key.
        assert!(
            store
                .direct_write(
                    &mut tx,
                    b"public:m0",
                    b"new_k",
                    Some(b"hello"),
                    &mut snap_ver,
                    &mut commit_view,
                    &mut has_snap,
                )
                .unwrap()
        );
        assert!(
            store
                .direct_write(
                    &mut tx,
                    b"public:m0",
                    b"empty_k",
                    Some(b""),
                    &mut snap_ver,
                    &mut commit_view,
                    &mut has_snap,
                )
                .unwrap()
        );
        assert!(
            store
                .direct_write(
                    &mut tx,
                    b"public:m0",
                    b"k0000",
                    None,
                    &mut snap_ver,
                    &mut commit_view,
                    &mut has_snap,
                )
                .unwrap()
        );

        let got_new = store
            .direct_get(
                &mut tx,
                false,
                b"public:m0",
                b"new_k",
                &mut snap_ver,
                &mut commit_view,
                &mut has_snap,
                |v| v.map(|s| s.to_vec()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(got_new.as_deref(), Some(b"hello".as_slice()));
        let got_empty = store
            .direct_get(
                &mut tx,
                false,
                b"public:m0",
                b"empty_k",
                &mut snap_ver,
                &mut commit_view,
                &mut has_snap,
                |v| v.map(|s| s.to_vec()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(got_empty.as_deref(), Some(b"".as_slice()));
        assert_eq!(
            store
                .direct_has(
                    &mut tx,
                    false,
                    b"public:m0",
                    b"k0000",
                    &mut snap_ver,
                    &mut commit_view,
                    &mut has_snap,
                )
                .unwrap(),
            Some(false)
        );

        match store.prepare_commit(&mut tx, |_| {}).unwrap() {
            CommitPreparation::Applied(2, 2) => {}
            _ => panic!("expected commit at v=2"),
        }
        tx.finish(Outcome::Success).unwrap();
        store.delete_tx(tx);

        // Compaction conflict: reader fixes snapshot on m0 at v=2, writer
        // updates m1 at v=3 and compacts to v=3, then reader acquires m1.
        let mut rtx = NativeTx::new(11);
        let (mut rsnap, mut rview, mut rhas) = (0u64, 0u64, 0u8);
        assert_eq!(
            store
                .direct_has(
                    &mut rtx,
                    true,
                    b"public:m0",
                    b"new_k",
                    &mut rsnap,
                    &mut rview,
                    &mut rhas,
                )
                .unwrap(),
            Some(true)
        );
        assert_eq!(rsnap, 2);

        let mut wtx = NativeTx::new(12);
        let (mut wsnap, mut wview, mut whas) = (0u64, 0u64, 0u8);
        assert!(
            store
                .direct_write(
                    &mut wtx,
                    b"public:m1",
                    b"k0000",
                    Some(b"after_compact"),
                    &mut wsnap,
                    &mut wview,
                    &mut whas,
                )
                .unwrap()
        );
        match store.prepare_commit(&mut wtx, |_| {}).unwrap() {
            CommitPreparation::Applied(3, 2) => {}
            _ => panic!("expected commit at v=3"),
        }
        wtx.finish(Outcome::Success).unwrap();
        store.delete_tx(wtx);
        store.execute_synced(true, |s| s.compact_ccf(3));

        // Acquiring compacted m1 at snapshot v=2 must report Unavailable (Ok(None)).
        assert_eq!(
            store
                .direct_has(
                    &mut rtx,
                    true,
                    b"public:m1",
                    b"k0000",
                    &mut rsnap,
                    &mut rview,
                    &mut rhas,
                )
                .unwrap(),
            None
        );
        store.delete_tx(rtx);
    }

    #[test]
    fn sharded_rwlock_mutual_exclusion_and_visibility() {
        let lock = Arc::new(ShardedRwLock::new((0u64, 1u64)));
        let active_readers = Arc::new(AtomicUsize::new(0));
        let active_writers = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let lock = Arc::clone(&lock);
            let ar = Arc::clone(&active_readers);
            let aw = Arc::clone(&active_writers);
            let stop = Arc::clone(&stop);
            handles.push(thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let g = lock.read();
                    ar.fetch_add(1, Ordering::AcqRel);
                    assert_eq!(
                        aw.load(Ordering::Acquire),
                        0,
                        "reader entered while writer active"
                    );
                    let (a, b) = *g;
                    assert_eq!(b, a + 1, "torn read under ShardedRwLock");
                    ar.fetch_sub(1, Ordering::Release);
                }
            }));
        }

        for _ in 0..4 {
            let lock = Arc::clone(&lock);
            let ar = Arc::clone(&active_readers);
            let aw = Arc::clone(&active_writers);
            handles.push(thread::spawn(move || {
                for _ in 0..200 {
                    let mut g = lock.write();
                    let prev_w = aw.fetch_add(1, Ordering::AcqRel);
                    assert_eq!(prev_w, 0, "two writers active concurrently");
                    assert_eq!(
                        ar.load(Ordering::Acquire),
                        0,
                        "writer entered while readers active"
                    );
                    let next = g.0 + 1;
                    g.0 = next;
                    thread::yield_now();
                    g.1 = next + 1;
                    aw.fetch_sub(1, Ordering::Release);
                }
            }));
        }

        for h in handles.drain(8..) {
            h.join().unwrap();
        }
        stop.store(true, Ordering::Release);
        for h in handles {
            h.join().unwrap();
        }
        let g = lock.read();
        assert_eq!(*g, (800, 801));
    }

    #[test]
    fn exhaustive_hazard_sync_interleavings() {
        // Deterministically enumerate every interleaving of 2 hazard readers
        // (acquire -> read -> verify -> drop) and 1 writer performing
        // 2 overwrites + compactions + final hazard drain.
        // Total schedules: (3+3+3)! / (3!*3!*3!) = 1680 distinct interleavings.
        const STEPS_PER_ACTOR: usize = 3;

        fn run_schedule(schedule: &[u8]) {
            let store = ConcurrentStore::new(2);
            seed_store(&store, 1, 2);

            let mut r_tx: [Option<NativeTx>; 2] = [None, None];
            let mut r_expected: [Option<Vec<u8>>; 2] = [None, None];
            let mut r_step = [0usize; 2];
            let mut w_step = 0usize;
            let mut next_id = 10u64;

            for &actor in schedule {
                match actor {
                    0 | 1 => {
                        let idx = actor as usize;
                        match r_step[idx] {
                            0 => {
                                let mut tx = NativeTx::new(next_id);
                                next_id += 1;
                                store
                                    .acquire_map(&mut tx, b("public:m0"), None, |_| {})
                                    .unwrap();
                                let v = store
                                    .tx_get(
                                        &mut tx,
                                        false,
                                        true,
                                        false,
                                        b"public:m0",
                                        b"k0000",
                                        |val| val.map(|s| s.to_vec()),
                                    )
                                    .unwrap();
                                assert!(v.is_some());
                                r_expected[idx] = v;
                                r_tx[idx] = Some(tx);
                            }
                            1 => {
                                let tx = r_tx[idx].as_mut().unwrap();
                                let v = store
                                    .tx_get(tx, false, true, false, b"public:m0", b"k0000", |val| {
                                        val.map(|s| s.to_vec())
                                    })
                                    .unwrap();
                                assert_eq!(
                                    v, r_expected[idx],
                                    "hazard-pinned snapshot drifted across interleaving"
                                );
                            }
                            2 => {
                                let tx = r_tx[idx].take().unwrap();
                                store.delete_tx(tx);
                            }
                            _ => unreachable!(),
                        }
                        r_step[idx] += 1;
                    }
                    2 => {
                        let mut wtx = NativeTx::new(next_id);
                        next_id += 1;
                        store
                            .acquire_map(&mut wtx, b("public:m0"), None, |_| {})
                            .unwrap();
                        let val = format!("w_{w_step}");
                        wtx.stage_write_bytes(b"public:m0", b"k0000", Some(val.as_bytes()))
                            .unwrap();
                        let ver = match store.prepare_commit(&mut wtx, |_| {}).unwrap() {
                            CommitPreparation::Applied(v, _) => v,
                            _ => panic!("expected commit"),
                        };
                        wtx.finish(Outcome::Success).unwrap();
                        store.delete_tx(wtx);
                        store.execute_synced(true, |s| s.compact_ccf(ver));
                        w_step += 1;
                    }
                    _ => unreachable!(),
                }
            }

            // Final hazard drain must release every slot and root.
            store.execute_synced(true, |s| s.compact_ccf(u64::MAX));
            let guard = store.lock.write();
            assert_eq!(store.hazards.claimed_mask.0.load(Ordering::Acquire), 0);
            assert!(guard.hazards.retained_roots.is_empty());
            assert!(guard.hazards.pinned_snaps.is_empty());
        }

        fn dfs(rem: [usize; 3], cur: &mut Vec<u8>, count: &mut usize) {
            if rem == [0, 0, 0] {
                run_schedule(cur);
                *count += 1;
                return;
            }
            for actor in 0..3 {
                if rem[actor] > 0 {
                    let mut next = rem;
                    next[actor] -= 1;
                    cur.push(actor as u8);
                    dfs(next, cur, count);
                    cur.pop();
                }
            }
        }

        let mut cur = Vec::with_capacity(STEPS_PER_ACTOR * 3);
        let mut count = 0usize;
        dfs(
            [STEPS_PER_ACTOR, STEPS_PER_ACTOR, STEPS_PER_ACTOR],
            &mut cur,
            &mut count,
        );
        assert_eq!(count, 1680);
    }
}
