// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//! C ABI and thread-safe concurrency wrapper for `ccf-kv`.
//! This crate is not part of Aeneas extraction.

mod concurrent;

use ccf_kv::engine::{
    Action, Address, Bytes, CommitPreparation, Error, Operation, Outcome, Output, SnapshotMap,
    WriteSet,
};
use concurrent::{ConcurrentStore, NativeTx};
use std::{ffi::c_void, ptr, slice};

// These wire types correspond to src/kv/test/rust_kv_ffi.h.
#[repr(C)]
#[derive(Clone, Copy)]
struct ByteView {
    data: *const u8,
    size: usize,
}

impl ByteView {
    unsafe fn as_opt_slice<'a>(self) -> Result<Option<&'a [u8]>, ()> {
        if self.data.is_null() {
            return if self.size == 0 { Ok(None) } else { Err(()) };
        }
        if self.size > isize::MAX as usize {
            return Err(());
        }
        // The caller retains readable storage for the duration of the FFI call.
        Ok(Some(unsafe { slice::from_raw_parts(self.data, self.size) }))
    }

    unsafe fn optional(self) -> Result<Option<Bytes>, ()> {
        Ok(unsafe { self.as_opt_slice()? }.map(Bytes::copy_from))
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
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
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
extern "C" fn ccf_rust_kv_new(term: u64) -> *mut ConcurrentStore {
    Box::into_raw(Box::new(ConcurrentStore::new(term)))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_delete(store: *mut ConcurrentStore) {
    // The caller transfers back the unique pointer returned by new.
    drop(unsafe { Box::from_raw(store) });
}

#[unsafe(no_mangle)]
extern "C" fn ccf_rust_kv_tx_new(attempt: u64) -> *mut NativeTx {
    Box::into_raw(Box::new(NativeTx::new(attempt)))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_delete(store: *const ConcurrentStore, tx: *mut NativeTx) {
    // The caller transfers back the unique pointer returned by tx_new.
    let tx = unsafe { *Box::from_raw(tx) };
    if !store.is_null() {
        let store = unsafe { &*store };
        store.delete_tx(tx);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_direct_get(
    store: *const c_void,
    tx: *mut c_void,
    read_only: u8,
    map_data: *const u8,
    map_len: usize,
    key_data: *const u8,
    key_len: usize,
    out_ctx: *mut c_void,
    copy_cb: CopyValueFn,
    snap_ver: *mut u64,
    commit_view: *mut u64,
    has_snap: *mut u8,
) -> u8 {
    if store.is_null()
        || tx.is_null()
        || snap_ver.is_null()
        || commit_view.is_null()
        || has_snap.is_null()
    {
        return Status::InvalidRequest as u8;
    }
    let store = unsafe { &*store.cast::<ConcurrentStore>() };
    let tx = unsafe { &mut *tx.cast::<NativeTx>() };
    let map = ByteView {
        data: map_data,
        size: map_len,
    };
    let key = ByteView {
        data: key_data,
        size: key_len,
    };
    let (Ok(Some(map)), Ok(Some(key))) =
        (unsafe { map.as_opt_slice() }, unsafe { key.as_opt_slice() })
    else {
        return Status::InvalidRequest as u8;
    };
    if !ConcurrentStore::is_valid_map_name(map) {
        return Status::InvalidRequest as u8;
    }
    let snap_ver = unsafe { &mut *snap_ver };
    let commit_view = unsafe { &mut *commit_view };
    let has_snap = unsafe { &mut *has_snap };
    let status = match store.direct_get(
        tx,
        read_only != 0,
        map,
        key,
        snap_ver,
        commit_view,
        has_snap,
        |val| match val {
            Some(bytes) => {
                unsafe { copy_cb(out_ctx, bytes.as_ptr(), bytes.len()) };
                Status::Ok
            }
            None => Status::Missing,
        },
    ) {
        Ok(Some(status)) => status,
        Ok(None) => Status::Unavailable,
        Err(Error::Disabled) => Status::Disabled,
        Err(Error::Exhausted) => Status::Exhausted,
    };
    status as u8
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_direct_has(
    store: *const c_void,
    tx: *mut c_void,
    read_only: u8,
    map_data: *const u8,
    map_len: usize,
    key_data: *const u8,
    key_len: usize,
    out_present: *mut i32,
    snap_ver: *mut u64,
    commit_view: *mut u64,
    has_snap: *mut u8,
) -> u8 {
    if store.is_null()
        || tx.is_null()
        || out_present.is_null()
        || snap_ver.is_null()
        || commit_view.is_null()
        || has_snap.is_null()
    {
        return Status::InvalidRequest as u8;
    }
    let store = unsafe { &*store.cast::<ConcurrentStore>() };
    let tx = unsafe { &mut *tx.cast::<NativeTx>() };
    let map = ByteView {
        data: map_data,
        size: map_len,
    };
    let key = ByteView {
        data: key_data,
        size: key_len,
    };
    let (Ok(Some(map)), Ok(Some(key))) =
        (unsafe { map.as_opt_slice() }, unsafe { key.as_opt_slice() })
    else {
        return Status::InvalidRequest as u8;
    };
    if !ConcurrentStore::is_valid_map_name(map) {
        return Status::InvalidRequest as u8;
    }
    let snap_ver = unsafe { &mut *snap_ver };
    let commit_view = unsafe { &mut *commit_view };
    let has_snap = unsafe { &mut *has_snap };
    let status = match store.direct_has(
        tx,
        read_only != 0,
        map,
        key,
        snap_ver,
        commit_view,
        has_snap,
    ) {
        Ok(Some(present)) => {
            unsafe { *out_present = i32::from(present) };
            Status::Ok
        }
        Ok(None) => Status::Unavailable,
        Err(Error::Disabled) => Status::Disabled,
        Err(Error::Exhausted) => Status::Exhausted,
    };
    status as u8
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_direct_write(
    store: *const c_void,
    tx: *mut c_void,
    read_only: u8,
    map_data: *const u8,
    map_len: usize,
    key_data: *const u8,
    key_len: usize,
    value_data: *const u8,
    value_len: usize,
    snap_ver: *mut u64,
    commit_view: *mut u64,
    has_snap: *mut u8,
) -> u8 {
    if store.is_null()
        || tx.is_null()
        || snap_ver.is_null()
        || commit_view.is_null()
        || has_snap.is_null()
    {
        return Status::InvalidRequest as u8;
    }
    if read_only != 0 {
        return Status::ReadOnly as u8;
    }
    let store = unsafe { &*store.cast::<ConcurrentStore>() };
    let tx = unsafe { &mut *tx.cast::<NativeTx>() };
    let map = ByteView {
        data: map_data,
        size: map_len,
    };
    let key = ByteView {
        data: key_data,
        size: key_len,
    };
    let value = ByteView {
        data: value_data,
        size: value_len,
    };
    let (Ok(Some(map)), Ok(Some(key)), Ok(value)) = (
        unsafe { map.as_opt_slice() },
        unsafe { key.as_opt_slice() },
        unsafe { value.as_opt_slice() },
    ) else {
        return Status::InvalidRequest as u8;
    };
    if !ConcurrentStore::is_valid_map_name(map) {
        return Status::InvalidRequest as u8;
    }
    let snap_ver = unsafe { &mut *snap_ver };
    let commit_view = unsafe { &mut *commit_view };
    let has_snap = unsafe { &mut *has_snap };
    let status = match store.direct_write(tx, map, key, value, snap_ver, commit_view, has_snap) {
        Ok(true) => Status::Ok,
        Ok(false) => Status::Unavailable,
        Err(Error::Disabled) => Status::Disabled,
        Err(Error::Exhausted) => Status::Exhausted,
    };
    status as u8
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_write(
    tx: *mut NativeTx,
    map: ByteView,
    key: ByteView,
    value: ByteView,
) -> Status {
    let tx = unsafe { &mut *tx };
    let (Ok(Some(map)), Ok(Some(key)), Ok(value)) = (
        unsafe { map.as_opt_slice() },
        unsafe { key.as_opt_slice() },
        unsafe { value.as_opt_slice() },
    ) else {
        return Status::InvalidRequest;
    };
    match tx.stage_write_bytes(map, key, value) {
        Ok(()) => Status::Ok,
        Err(Error::Disabled) => Status::Disabled,
        Err(Error::Exhausted) => Status::Exhausted,
    }
}

type CopyValueFn = unsafe extern "C" fn(*mut c_void, *const u8, usize);
type AcquireTraceFn = unsafe extern "C" fn(*mut c_void, Reply, u64, u64);
type ReplyTraceFn = unsafe extern "C" fn(*mut c_void, Reply);

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_get(
    store: *const ConcurrentStore,
    tx: *mut NativeTx,
    inspect_finished: bool,
    read_only: bool,
    global: bool,
    map: ByteView,
    key: ByteView,
    out_ctx: *mut c_void,
    copy_cb: CopyValueFn,
) -> Status {
    let store = unsafe { &*store };
    let tx = unsafe { &mut *tx };
    let (Ok(Some(map)), Ok(Some(key))) =
        (unsafe { map.as_opt_slice() }, unsafe { key.as_opt_slice() })
    else {
        return Status::InvalidRequest;
    };
    match store.tx_get(
        tx,
        inspect_finished,
        read_only,
        global,
        map,
        key,
        |val| match val {
            Some(bytes) => {
                unsafe { copy_cb(out_ctx, bytes.as_ptr(), bytes.len()) };
                Status::Ok
            }
            None => Status::Missing,
        },
    ) {
        Ok(status) => status,
        Err(Error::Disabled) => Status::Disabled,
        Err(Error::Exhausted) => Status::Exhausted,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_has(
    store: *const ConcurrentStore,
    tx: *mut NativeTx,
    inspect_finished: bool,
    read_only: bool,
    global: bool,
    map: ByteView,
    key: ByteView,
) -> Reply {
    let store = unsafe { &*store };
    let tx = unsafe { &mut *tx };
    let (Ok(Some(map)), Ok(Some(key))) =
        (unsafe { map.as_opt_slice() }, unsafe { key.as_opt_slice() })
    else {
        return Reply::status(Status::InvalidRequest);
    };
    match store.tx_has(tx, inspect_finished, read_only, global, map, key) {
        Ok(present) => {
            let mut r = Reply::status(Status::Ok);
            r.number = u64::from(present);
            r
        }
        Err(error) => Reply::output(Err(error)),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_previous(
    store: *const ConcurrentStore,
    tx: *mut NativeTx,
    inspect_finished: bool,
    read_only: bool,
    map: ByteView,
    key: ByteView,
) -> Reply {
    let store = unsafe { &*store };
    let tx = unsafe { &mut *tx };
    let (Ok(Some(map)), Ok(Some(key))) =
        (unsafe { map.as_opt_slice() }, unsafe { key.as_opt_slice() })
    else {
        return Reply::status(Status::InvalidRequest);
    };
    match store.tx_previous(tx, inspect_finished, read_only, map, key) {
        Ok(Some(v)) => {
            let mut r = Reply::status(Status::Ok);
            r.number = v;
            r
        }
        Ok(None) => Reply::status(Status::Missing),
        Err(error) => Reply::output(Err(error)),
    }
}

fn acquire_reply(res: &Result<(u64, u64, Output), Error>) -> (Reply, u64, u64) {
    match res {
        Ok((version, term, Output::Acquired(local_rev, global_rev))) => {
            let mut reply = Reply::status(Status::Ok);
            reply.number = *version;
            reply.detail = *term;
            (reply, *local_rev, *global_rev)
        }
        Ok((version, term, Output::Unavailable)) => {
            let mut reply = Reply::status(Status::Unavailable);
            reply.number = *version;
            reply.detail = *term;
            (reply, 0, 0)
        }
        Ok((_, _, _)) => (Reply::status(Status::InvalidRequest), 0, 0),
        Err(Error::Disabled) => (Reply::status(Status::Disabled), 0, 0),
        Err(Error::Exhausted) => (Reply::status(Status::Exhausted), 0, 0),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_acquire(
    store: *const ConcurrentStore,
    tx: *mut NativeTx,
    map: ByteView,
    has_explicit_version: bool,
    explicit_version: u64,
    trace_ctx: *mut c_void,
    trace_cb: Option<AcquireTraceFn>,
) -> Reply {
    let store = unsafe { &*store };
    let tx = unsafe { &mut *tx };
    let Ok(Some(map)) = (unsafe { map.optional() }) else {
        return Reply::status(Status::InvalidRequest);
    };
    let explicit = if has_explicit_version {
        Some(explicit_version)
    } else {
        None
    };
    let res = store.acquire_map(tx, map, explicit, |locked_res| {
        if let Some(cb) = trace_cb {
            let (reply, local_rev, global_rev) = acquire_reply(locked_res);
            unsafe { cb(trace_ctx, reply, local_rev, global_rev) };
        }
    });
    acquire_reply(&res).0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_pending_writes(tx: *const NativeTx) -> Reply {
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
unsafe extern "C" fn ccf_rust_kv_tx_finish(tx: *mut NativeTx, outcome: u64) -> Reply {
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
unsafe extern "C" fn ccf_rust_kv_reserve_version(store: *const ConcurrentStore) -> Reply {
    let store = unsafe { &*store };
    match store.reserve_version() {
        Ok(version) => {
            let mut reply = Reply::status(Status::Ok);
            reply.number = version;
            reply
        }
        Err(error) => Reply::output(Err(error)),
    }
}

fn commit_prep_reply(res: &Result<CommitPreparation, Error>) -> Reply {
    match res {
        Ok(CommitPreparation::ReadOnly) => Reply::status(Status::ReadOnly),
        Ok(CommitPreparation::Rejected(Outcome::Conflict)) => Reply::status(Status::Conflict),
        Ok(CommitPreparation::Rejected(Outcome::NoReplicate)) => Reply::status(Status::StaleTerm),
        Ok(CommitPreparation::Rejected(Outcome::Success)) => Reply::status(Status::InvalidRequest),
        Ok(CommitPreparation::Applied(v, term)) => {
            let mut reply = Reply::status(Status::Ok);
            reply.number = *v;
            reply.detail = *term;
            reply
        }
        Err(Error::Disabled) => Reply::status(Status::Disabled),
        Err(Error::Exhausted) => Reply::status(Status::Exhausted),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_commit_reserved(
    store: *const ConcurrentStore,
    tx: *mut NativeTx,
    version: u64,
) -> Reply {
    let store = unsafe { &*store };
    let tx = unsafe { &mut *tx };
    commit_prep_reply(&store.commit_reserved(tx, version))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_prepare_commit(
    store: *const ConcurrentStore,
    tx: *mut NativeTx,
    trace_ctx: *mut c_void,
    trace_cb: Option<ReplyTraceFn>,
) -> Reply {
    let store = unsafe { &*store };
    let tx = unsafe { &mut *tx };
    let res = store.prepare_commit(tx, |locked_res| {
        if let Some(cb) = trace_cb {
            unsafe { cb(trace_ctx, commit_prep_reply(locked_res)) };
        }
    });
    commit_prep_reply(&res)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_tx_operate(
    store: *const ConcurrentStore,
    tx: *mut NativeTx,
    request: Request,
) -> Reply {
    let store = unsafe { &*store };
    let tx = unsafe { &mut *tx };
    let inspect_finished = request.inspect_finished;
    let Ok(Action::Operate(_, map, op)) = (unsafe { request.action() }) else {
        return Reply::status(Status::InvalidRequest);
    };
    Reply::output(store.tx_operate(tx, inspect_finished, map, op))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_execute_read(
    store: *const ConcurrentStore,
    request: Request,
) -> Reply {
    let store = unsafe { &*store };
    if request.op == 20 {
        return match store.snapshot_maps(request.number) {
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
                store.map_revision_at(request.number, &map),
            ))),
            _ => Reply::status(Status::InvalidRequest),
        };
    }
    Reply::status(Status::InvalidRequest)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_execute(
    store: *const ConcurrentStore,
    request: Request,
    trace_ctx: *mut c_void,
    trace_cb: Option<ReplyTraceFn>,
) -> Reply {
    let store = unsafe { &*store };
    if request.op == 22 {
        return Reply::output(store.clear_idle().map(|()| Output::Unit));
    }
    if request.op == 20 {
        return match store.snapshot_maps(request.number) {
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
                store.map_revision_at(request.number, &map),
            ))),
            _ => Reply::status(Status::InvalidRequest),
        };
    }
    if request.op == 21 {
        return store.execute_synced(false, |s| {
            Reply::output(s.snapshot_at_ccf(request.attempt, request.number))
        });
    }
    if request.op == 18 {
        return store.execute_synced(false, |s| match s.pending_writes(request.attempt) {
            Ok(writes) => {
                let mut reply = Reply::status(Status::Ok);
                Reply::writes(&mut reply, writes);
                reply
            }
            Err(error) => Reply::output(Err(error)),
        });
    }
    if request.op == 6 {
        return store.execute_synced(false, |s| {
            commit_prep_reply(&s.prepare_ccf_commit(request.attempt))
        });
    }
    let inspect_finished = request.inspect_finished;
    match unsafe { request.action() } {
        Ok(Action::SetTerm(term)) => Reply::output(store.execute_set_term(term)),
        Ok(Action::Compact(version)) => store.execute_synced(true, |s| {
            let reply = Reply::output(Ok(s.compact_ccf(version)));
            if let Some(cb) = trace_cb {
                unsafe { cb(trace_ctx, reply) };
            }
            reply
        }),
        Ok(Action::Rollback(version, term)) => store.execute_synced(true, |s| {
            let reply = Reply::output(s.execute(Action::Rollback(version, term)));
            if let Some(cb) = trace_cb {
                unsafe { cb(trace_ctx, reply) };
            }
            reply
        }),
        Ok(Action::Operate(t, m, op)) if inspect_finished => {
            store.execute_synced(false, |s| Reply::output(s.inspect_finished(t, m, op)))
        }
        Ok(_) if inspect_finished => Reply::status(Status::InvalidRequest),
        Ok(Action::Acquire(t, m)) => {
            store.execute_synced(false, |s| Reply::output(s.acquire_ccf(t, m)))
        }
        Ok(action) => store.execute_synced(false, |s| Reply::output(s.execute(action))),
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
    store: *const ConcurrentStore,
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
    match unsafe { &*store }.install_snapshot(version, maps) {
        Ok(()) => Status::Ok,
        Err(Error::Disabled) => Status::Disabled,
        Err(Error::Exhausted) => Status::Exhausted,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ccf_rust_kv_swap_recovery_maps(
    target: *const ConcurrentStore,
    source: *const ConcurrentStore,
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
    let target = unsafe { &*target };
    let source = unsafe { &*source };
    match target.swap_recovery_maps(source, names) {
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
    store: *const ConcurrentStore,
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
    match unsafe { &*store }.replay(version, writes, track_deletes) {
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
