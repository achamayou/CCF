// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//! C ABI for the opt-in C++ tests. This crate is not part of Aeneas extraction.

use ccf_kv::engine::{
    Action, Address, Bytes, CommitPreparation, DetachedTx, Error, Operation, Outcome, Output,
    SnapshotMap, Store, WriteSet,
};
use std::{
    ptr, slice,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

struct SharedStore {
    inner: RwLock<Store>,
}

impl SharedStore {
    fn new(term: u64) -> Self {
        Self {
            inner: RwLock::new(Store::new(term)),
        }
    }

    fn read(&self) -> RwLockReadGuard<'_, Store> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, Store> {
        self.inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

// These wire types correspond to src/kv/test/rust_kv_ffi.h.
#[repr(C)]
#[derive(Clone, Copy)]
struct ByteView {
    data: *const u8,
    size: usize,
}

impl ByteView {
    unsafe fn optional(self) -> Result<Option<Bytes>, ()> {
        if self.data.is_null() {
            return if self.size == 0 { Ok(None) } else { Err(()) };
        }
        if self.size > isize::MAX as usize {
            return Err(());
        }
        // The caller retains readable storage for the duration of execute.
        Ok(Some(Bytes::copy_from(unsafe {
            slice::from_raw_parts(self.data, self.size)
        })))
    }
}

#[repr(C)]
struct Request {
    op: u8,
    inspect_finished: bool,
    attempt: u64,
    number: u64,
    map: ByteView,
    key: ByteView,
    value: ByteView,
}

impl Request {
    unsafe fn action(self) -> Result<Action, ()> {
        let t = self.attempt;
        let n = self.number;
        let operation = match self.op {
            0 => return Ok(Action::Begin(t)),
            1 => return Ok(Action::End(t)),
            2 => return Ok(Action::SetTerm(n)),
            3 => return Ok(Action::Snapshot(t)),
            4 => {
                return Ok(Action::Acquire(
                    t,
                    unsafe { self.map.optional()? }.ok_or(())?,
                ));
            }
            5 => return Ok(Action::CommitBegin(t)),
            6 => return Ok(Action::Apply(t)),
            7 => {
                return Ok(Action::CommitResult(
                    t,
                    match n {
                        0 => Outcome::Success,
                        1 => Outcome::Conflict,
                        2 => Outcome::NoReplicate,
                        _ => return Err(()),
                    },
                ));
            }
            8 => return Ok(Action::Compact(n)),
            9 => return Ok(Action::Rollback(n, t)),
            10 => Operation::Get(unsafe { self.key.optional()? }.ok_or(())?, n != 0),
            11 => Operation::Has(unsafe { self.key.optional()? }.ok_or(())?, n != 0),
            12 => Operation::Previous(unsafe { self.key.optional()? }.ok_or(())?),
            13 => Operation::Write(unsafe { self.key.optional()? }.ok_or(())?, unsafe {
                self.value.optional()?
            }),
            14 => Operation::Scan,
            15 => Operation::Size,
            16 => Operation::Clear,
            17 => Operation::Range(unsafe { self.key.optional()? }, unsafe {
                self.value.optional()?
            }),
            _ => return Err(()),
        };
        Ok(Action::Operate(
            t,
            unsafe { self.map.optional()? }.ok_or(())?,
            operation,
        ))
    }
}

#[repr(u8)]
enum Status {
    Ok,
    Disabled,
    Exhausted,
    InvalidRequest,
    Unavailable,
    RollbackRejected,
    Missing,
    ReadOnly,
    Conflict,
    StaleTerm,
}

enum Data {
    Value(Bytes),
    Entries(Vec<(Bytes, Bytes)>),
    Writes(WriteSet),
    Snapshot(Vec<SnapshotMap>),
}

#[repr(C)]
struct Reply {
    status: Status,
    number: u64,
    detail: u64,
    size: usize,
    data: *mut Data,
}

impl Reply {
    fn status(status: Status) -> Self {
        Self {
            status,
            number: 0,
            detail: 0,
            size: 0,
            data: ptr::null_mut(),
        }
    }

    fn writes(reply: &mut Self, writes: WriteSet) {
        reply.size = writes.len();
        reply.data = Box::into_raw(Box::new(Data::Writes(writes)));
    }

    fn output(result: Result<Output, Error>) -> Self {
        let mut reply = Self::status(Status::Ok);
        match result {
            Err(Error::Disabled) => reply.status = Status::Disabled,
            Err(Error::Exhausted) => reply.status = Status::Exhausted,
            Ok(Output::Unavailable) => reply.status = Status::Unavailable,
            Ok(Output::RollbackRejected) => reply.status = Status::RollbackRejected,
            Ok(Output::Value(None) | Output::Previous(None)) => reply.status = Status::Missing,
            Ok(Output::Value(Some(value))) => {
                reply.data = Box::into_raw(Box::new(Data::Value(value)));
            }
            Ok(Output::Entries(rows)) => {
                reply.size = rows.len();
                reply.data = Box::into_raw(Box::new(Data::Entries(rows)));
            }
            Ok(Output::Presence(present)) => reply.number = u64::from(present),
            Ok(Output::Size(size)) => reply.size = size,
            Ok(
                Output::Previous(Some(v))
                | Output::Committed(_, v)
                | Output::Compacted(v)
                | Output::RolledBack(v),
            ) => reply.number = v,
            Ok(Output::Snapshot(v, _, term)) => {
                reply.number = v;
                reply.detail = term;
            }
            Ok(Output::Applied(v, term, writes)) => {
                reply.number = v;
                reply.detail = term;
                Self::writes(&mut reply, writes);
            }
            Ok(Output::Unit | Output::Acquired(..)) => {}
        }
        reply
    }
}

#[unsafe(no_mangle)]
extern "C" fn ccf_rust_kv_new(term: u64) -> *mut SharedStore {
    Box::into_raw(Box::new(SharedStore::new(term)))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_delete(store: *mut SharedStore) {
    // The caller transfers back the unique pointer returned by new.
    drop(unsafe { Box::from_raw(store) });
}

#[unsafe(no_mangle)]
extern "C" fn ccf_rust_kv_tx_new(attempt: u64) -> *mut DetachedTx {
    Box::into_raw(Box::new(DetachedTx::new(attempt)))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_delete(store: *const SharedStore, tx: *mut DetachedTx) {
    // The caller transfers back the unique pointer returned by tx_new.
    let mut tx = unsafe { Box::from_raw(tx) };
    if tx.is_registered() {
        let store = unsafe { &*store };
        store.write().end_detached(&mut tx);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_write(
    tx: *mut DetachedTx,
    map: ByteView,
    key: ByteView,
    value: ByteView,
) -> Status {
    let tx = unsafe { &mut *tx };
    let (Ok(Some(map)), Ok(Some(key)), Ok(value)) = (
        unsafe { map.optional() },
        unsafe { key.optional() },
        unsafe { value.optional() },
    ) else {
        return Status::InvalidRequest;
    };
    match tx.stage_write(map, key, value) {
        Ok(()) => Status::Ok,
        Err(Error::Disabled) => Status::Disabled,
        Err(Error::Exhausted) => Status::Exhausted,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_pending_writes(tx: *const DetachedTx) -> Reply {
    let tx = unsafe { &*tx };
    match tx.pending_writes() {
        Ok(writes) => {
            let mut reply = Reply::status(Status::Ok);
            Reply::writes(&mut reply, writes);
            reply
        }
        Err(error) => Reply::output(Err(error)),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_finish(tx: *mut DetachedTx, outcome: u64) -> Reply {
    let tx = unsafe { &mut *tx };
    let outcome = match outcome {
        0 => Outcome::Success,
        1 => Outcome::Conflict,
        2 => Outcome::NoReplicate,
        _ => return Reply::status(Status::InvalidRequest),
    };
    Reply::output(tx.finish(outcome))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_snapshot_and_acquire(
    store: *const SharedStore,
    tx: *mut DetachedTx,
    map: ByteView,
    has_reserved: bool,
    reserved_version: u64,
) -> Reply {
    let store = unsafe { &*store };
    let tx = unsafe { &mut *tx };
    let Ok(Some(map)) = (unsafe { map.optional() }) else {
        return Reply::status(Status::InvalidRequest);
    };
    let reserved = if has_reserved {
        Some(reserved_version)
    } else {
        None
    };
    match store
        .write()
        .snapshot_and_acquire_detached(tx, map, reserved)
    {
        Ok((version, term, Output::Acquired(..))) => {
            let mut reply = Reply::status(Status::Ok);
            reply.number = version;
            reply.detail = term;
            reply
        }
        Ok((_, _, other)) => Reply::output(Ok(other)),
        Err(error) => Reply::output(Err(error)),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_reserve_version(store: *const SharedStore) -> Reply {
    let store = unsafe { &*store };
    match store.write().reserve_placeholder_ccf() {
        Ok(version) => {
            let mut reply = Reply::status(Status::Ok);
            reply.number = version;
            reply
        }
        Err(error) => Reply::output(Err(error)),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_commit_reserved(
    store: *const SharedStore,
    tx: *mut DetachedTx,
    version: u64,
) -> Reply {
    let store = unsafe { &*store };
    let tx = unsafe { &mut *tx };
    match store.write().backfill_reserved_ccf(tx, version) {
        Ok(CommitPreparation::ReadOnly) => Reply::status(Status::ReadOnly),
        Ok(CommitPreparation::Rejected(Outcome::Conflict)) => Reply::status(Status::Conflict),
        Ok(CommitPreparation::Rejected(Outcome::NoReplicate)) => Reply::status(Status::StaleTerm),
        Ok(CommitPreparation::Rejected(Outcome::Success)) => Reply::status(Status::InvalidRequest),
        Ok(CommitPreparation::Applied(v, term)) => {
            let mut reply = Reply::status(Status::Ok);
            reply.number = v;
            reply.detail = term;
            reply
        }
        Err(error) => Reply::output(Err(error)),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_prepare_commit(
    store: *const SharedStore,
    tx: *mut DetachedTx,
) -> Reply {
    let store = unsafe { &*store };
    let tx = unsafe { &mut *tx };
    match store.write().prepare_ccf_commit_detached(tx) {
        Ok(CommitPreparation::ReadOnly) => Reply::status(Status::ReadOnly),
        Ok(CommitPreparation::Rejected(Outcome::Conflict)) => Reply::status(Status::Conflict),
        Ok(CommitPreparation::Rejected(Outcome::NoReplicate)) => Reply::status(Status::StaleTerm),
        Ok(CommitPreparation::Rejected(Outcome::Success)) => Reply::status(Status::InvalidRequest),
        Ok(CommitPreparation::Applied(version, term)) => {
            let mut reply = Reply::status(Status::Ok);
            reply.number = version;
            reply.detail = term;
            reply
        }
        Err(error) => Reply::output(Err(error)),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_operate(
    store: *const SharedStore,
    tx: *mut DetachedTx,
    request: Request,
) -> Reply {
    let store = unsafe { &*store };
    let tx = unsafe { &mut *tx };
    let inspect_finished = request.inspect_finished;
    let Ok(Action::Operate(_, map, op)) = (unsafe { request.action() }) else {
        return Reply::status(Status::InvalidRequest);
    };
    if !inspect_finished {
        if let Operation::Write(key, value) = op {
            return match tx.stage_write(map, key, value) {
                Ok(()) => Reply::status(Status::Ok),
                Err(error) => Reply::output(Err(error)),
            };
        }
    }
    let guard = store.read();
    if inspect_finished {
        Reply::output(tx.inspect_finished(&guard, map, op))
    } else {
        Reply::output(tx.operate(&guard, map, op))
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_execute(store: *const SharedStore, request: Request) -> Reply {
    let store = unsafe { &*store };
    if request.op == 22 {
        return Reply::output(store.write().clear_idle().map(|()| Output::Unit));
    }
    if request.op == 20 {
        return match store.read().snapshot_maps(request.number) {
            Ok(maps) => {
                let mut reply = Reply::status(Status::Ok);
                reply.size = maps.len();
                reply.data = Box::into_raw(Box::new(Data::Snapshot(maps)));
                reply
            }
            Err(error) => Reply::output(Err(error)),
        };
    }
    if request.op == 19 {
        return match unsafe { request.map.optional() } {
            Ok(Some(map)) => Reply::output(Ok(Output::Previous(
                store.read().map_revision_at(request.number, &map),
            ))),
            _ => Reply::status(Status::InvalidRequest),
        };
    }
    let mut guard = store.write();
    if request.op == 21 {
        return Reply::output(guard.snapshot_at_ccf(request.attempt, request.number));
    }
    if request.op == 18 {
        return match guard.pending_writes(request.attempt) {
            Ok(writes) => {
                let mut reply = Reply::status(Status::Ok);
                Reply::writes(&mut reply, writes);
                reply
            }
            Err(error) => Reply::output(Err(error)),
        };
    }
    if request.op == 6 {
        return match guard.prepare_ccf_commit(request.attempt) {
            Ok(CommitPreparation::ReadOnly) => Reply::status(Status::ReadOnly),
            Ok(CommitPreparation::Rejected(Outcome::Conflict)) => Reply::status(Status::Conflict),
            Ok(CommitPreparation::Rejected(Outcome::NoReplicate)) => {
                Reply::status(Status::StaleTerm)
            }
            Ok(CommitPreparation::Rejected(Outcome::Success)) => {
                Reply::status(Status::InvalidRequest)
            }
            Ok(CommitPreparation::Applied(version, term)) => {
                let mut reply = Reply::status(Status::Ok);
                reply.number = version;
                reply.detail = term;
                reply
            }
            Err(error) => Reply::output(Err(error)),
        };
    }
    let inspect_finished = request.inspect_finished;
    match unsafe { request.action() } {
        Ok(Action::Operate(t, m, op)) if inspect_finished => {
            Reply::output(guard.inspect_finished(t, m, op))
        }
        Ok(_) if inspect_finished => Reply::status(Status::InvalidRequest),
        Ok(Action::Acquire(t, m)) => Reply::output(guard.acquire_ccf(t, m)),
        Ok(Action::Compact(version)) => Reply::output(Ok(guard.compact_ccf(version))),
        Ok(action) => Reply::output(guard.execute(action)),
        Err(()) => Reply::status(Status::InvalidRequest),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_reply_delete(data: *mut Data) {
    // The caller transfers back the unique pointer from the reply.
    drop(unsafe { Box::from_raw(data) });
}

fn view(bytes: &Bytes) -> ByteView {
    let bytes = bytes.as_slice();
    ByteView {
        data: bytes.as_ptr(),
        size: bytes.len(),
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Entry {
    map: ByteView,
    key: ByteView,
    value: ByteView,
}

#[repr(C)]
struct SnapshotCell {
    key: ByteView,
    value: ByteView,
    version: u64,
}

#[repr(C)]
struct SnapshotMapView {
    name: ByteView,
    revision: u64,
    size: usize,
}

#[repr(C)]
struct SnapshotInput {
    map: SnapshotMapView,
    cells: *const SnapshotCell,
}

unsafe fn borrow_array<'a, T>(data: *const T, size: usize) -> Result<&'a [T], ()> {
    if size > isize::MAX as usize / std::mem::size_of::<T>() {
        return Err(());
    }
    if size == 0 {
        return Ok(&[]);
    }
    if data.is_null() {
        return Err(());
    }
    // The caller owns the live array until this ABI call returns.
    Ok(unsafe { slice::from_raw_parts(data, size) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_install_snapshot(
    store: *const SharedStore,
    version: u64,
    maps: *const SnapshotInput,
    size: usize,
) -> Status {
    let Ok(input) = (unsafe { borrow_array(maps, size) }) else {
        return Status::InvalidRequest;
    };
    let mut maps = Vec::with_capacity(input.len());
    for map in input {
        let Ok(Some(name)) = (unsafe { map.map.name.optional() }) else {
            return Status::InvalidRequest;
        };
        let Ok(rows) = (unsafe { borrow_array(map.cells, map.map.size) }) else {
            return Status::InvalidRequest;
        };
        let mut cells = Vec::with_capacity(rows.len());
        for row in rows {
            let (Ok(Some(key)), Ok(Some(value))) = (unsafe { row.key.optional() }, unsafe {
                row.value.optional()
            }) else {
                return Status::InvalidRequest;
            };
            cells.push((key, row.version, value));
        }
        maps.push(SnapshotMap {
            name,
            revision: map.map.revision,
            cells,
        });
    }
    match unsafe { &*store }.write().install_snapshot(version, maps) {
        Ok(()) => Status::Ok,
        Err(Error::Disabled) => Status::Disabled,
        Err(Error::Exhausted) => Status::Exhausted,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_swap_recovery_maps(
    target: *const SharedStore,
    source: *const SharedStore,
    names: *const ByteView,
    size: usize,
) -> Status {
    if target == source || target.is_null() || source.is_null() {
        return Status::InvalidRequest;
    }
    let Ok(input) = (unsafe { borrow_array(names, size) }) else {
        return Status::InvalidRequest;
    };
    let mut names = Vec::with_capacity(input.len());
    for name in input {
        let Ok(Some(name)) = (unsafe { name.optional() }) else {
            return Status::InvalidRequest;
        };
        names.push(name);
    }
    // Lock in canonical pointer order to prevent AB/BA deadlock.
    let result = if (target as usize) < (source as usize) {
        let mut target_guard = unsafe { &*target }.write();
        let mut source_guard = unsafe { &*source }.write();
        target_guard.swap_recovery_maps(&mut source_guard, names)
    } else {
        let mut source_guard = unsafe { &*source }.write();
        let mut target_guard = unsafe { &*target }.write();
        target_guard.swap_recovery_maps(&mut source_guard, names)
    };
    match result {
        Ok(()) => Status::Ok,
        Err(Error::Disabled) => Status::Disabled,
        Err(Error::Exhausted) => Status::Exhausted,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_snapshot_map(data: *const Data, index: usize) -> SnapshotMapView {
    if let Some(Data::Snapshot(maps)) = unsafe { data.as_ref() } {
        if let Some(map) = maps.get(index) {
            return SnapshotMapView {
                name: view(&map.name),
                revision: map.revision,
                size: map.cells.len(),
            };
        }
    }
    SnapshotMapView {
        name: empty_view(),
        revision: 0,
        size: 0,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_snapshot_cell(
    data: *const Data,
    map: usize,
    cell: usize,
) -> SnapshotCell {
    if let Some(Data::Snapshot(maps)) = unsafe { data.as_ref() } {
        if let Some((key, version, value)) = maps.get(map).and_then(|m| m.cells.get(cell)) {
            return SnapshotCell {
                key: view(key),
                value: view(value),
                version: *version,
            };
        }
    }
    SnapshotCell {
        key: empty_view(),
        value: empty_view(),
        version: 0,
    }
}

fn empty_view() -> ByteView {
    ByteView {
        data: ptr::null(),
        size: 0,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_replay(
    store: *const SharedStore,
    version: u64,
    entries: *const Entry,
    size: usize,
    track_deletes: bool,
) -> Status {
    let Ok(entries) = (unsafe { borrow_array(entries, size) }) else {
        return Status::InvalidRequest;
    };
    let mut writes = Vec::with_capacity(entries.len());
    for entry in entries {
        let (Ok(Some(map)), Ok(Some(key)), Ok(value)) = (
            unsafe { entry.map.optional() },
            unsafe { entry.key.optional() },
            unsafe { entry.value.optional() },
        ) else {
            return Status::InvalidRequest;
        };
        writes.push((Address { map, key }, value));
    }
    match unsafe { &*store }
        .write()
        .replay_ccf(version, writes, track_deletes)
    {
        Ok(()) => Status::Ok,
        Err(Error::Disabled) => Status::Disabled,
        Err(Error::Exhausted) => Status::Exhausted,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_reply_entry(data: *const Data, index: usize) -> Entry {
    // Views borrow the reply and must not outlive it.
    let absent = empty_view();
    match unsafe { data.as_ref() } {
        Some(Data::Value(value)) if index == 0 => Entry {
            map: absent,
            key: absent,
            value: view(value),
        },
        Some(Data::Entries(rows)) if index < rows.len() => {
            let (key, value) = &rows[index];
            Entry {
                map: absent,
                key: view(key),
                value: view(value),
            }
        }
        Some(Data::Writes(rows)) if index < rows.len() => {
            let (address, value) = &rows[index];
            Entry {
                map: view(&address.map),
                key: view(&address.key),
                value: value.as_ref().map_or(absent, view),
            }
        }
        _ => Entry {
            map: absent,
            key: absent,
            value: absent,
        },
    }
}
