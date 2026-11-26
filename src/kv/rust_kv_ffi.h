// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>
#include <cstdint>

namespace ccf::kv::rust_ffi
{
  // Keep the wire layout and discriminants in sync with
  // src/rust/ccf-kv/ffi/src/lib.rs.
  enum class Opcode : uint8_t
  {
    BEGIN,
    END,
    SET_TERM,
    SNAPSHOT,
    ACQUIRE,
    COMMIT_BEGIN,
    APPLY,
    COMMIT_RESULT,
    COMPACT,
    ROLLBACK,
    GET,
    HAS,
    PREVIOUS,
    WRITE,
    SCAN,
    SIZE,
    CLEAR,
    RANGE,
    PENDING_WRITES,
    MAP_REVISION,
    SNAPSHOT_MAPS,
    SNAPSHOT_AT,
    CLEAR_STORE,
  };

  enum class Status : uint8_t
  {
    OK,
    DISABLED,
    EXHAUSTED,
    INVALID_REQUEST,
    UNAVAILABLE,
    ROLLBACK_REJECTED,
    MISSING,
    READ_ONLY,
    CONFLICT,
    STALE_TERM,
  };

  enum class Outcome : uint64_t
  {
    SUCCESS,
    CONFLICT,
    NO_REPLICATE,
  };

  struct NativeStore;
  struct NativeTx;
  struct ReplyData;

  struct ByteView
  {
    // Null means absent, even when the size is zero.
    const uint8_t* data;
    size_t size;
  };

  struct Request
  {
    Opcode op;
    bool inspect_finished = false;
    uint64_t attempt = 0;
    uint64_t number = 0;
    ByteView map{};
    ByteView key{};
    ByteView value{};
  };

  struct Reply
  {
    Status status;
    uint64_t number;
    uint64_t detail;
    size_t size;
    ReplyData* data;
  };

  struct Entry
  {
    ByteView map;
    ByteView key;
    ByteView value;
  };

  struct SnapshotCell
  {
    ByteView key;
    ByteView value;
    uint64_t version;
  };

  struct SnapshotMapView
  {
    ByteView name;
    uint64_t revision;
    size_t size;
  };

  struct SnapshotInput
  {
    SnapshotMapView map;
    const SnapshotCell* cells;
  };

  extern "C"
  {
    NativeStore* ccf_rust_kv_new(uint64_t term);
    void ccf_rust_kv_delete(NativeStore* store);
    NativeTx* ccf_rust_kv_tx_new(uint64_t attempt);
    void ccf_rust_kv_tx_delete(NativeStore* store, NativeTx* tx);
    using CopyValueFn = void (*)(void*, const uint8_t*, size_t);
    Status ccf_rust_kv_tx_write(
      NativeTx* tx, ByteView map, ByteView key, ByteView value);
    Status ccf_rust_kv_tx_get(
      const NativeStore* store,
      NativeTx* tx,
      bool inspect_finished,
      bool read_only,
      bool global,
      ByteView map,
      ByteView key,
      void* out_ctx,
      CopyValueFn copy_cb);
    Reply ccf_rust_kv_tx_has(
      const NativeStore* store,
      NativeTx* tx,
      bool inspect_finished,
      bool read_only,
      bool global,
      ByteView map,
      ByteView key);
    Reply ccf_rust_kv_tx_previous(
      const NativeStore* store,
      NativeTx* tx,
      bool inspect_finished,
      bool read_only,
      ByteView map,
      ByteView key);
    Reply ccf_rust_kv_tx_ro_acquire(
      const NativeStore* store,
      NativeTx* tx,
      ByteView map,
      uint32_t* out_root0,
      uint32_t* out_root1,
      uint64_t* out_local_rev,
      uint64_t* out_global_rev);
    Status ccf_rust_kv_tx_promote(NativeStore* store, NativeTx* tx);
    void ccf_rust_kv_retain_root(NativeStore* store, uint32_t root);
    void ccf_rust_kv_release_root(NativeStore* store, uint32_t root);
    void ccf_rust_kv_pin_snapshot(
      NativeStore* store, uint64_t id, uint64_t version);
    void ccf_rust_kv_unpin_snapshot(NativeStore* store, uint64_t id);
    Reply ccf_rust_kv_tx_pending_writes(const NativeTx* tx);
    Reply ccf_rust_kv_tx_finish(NativeTx* tx, uint64_t outcome);
    Reply ccf_rust_kv_tx_snapshot_and_acquire(
      NativeStore* store,
      NativeTx* tx,
      ByteView map,
      bool has_reserved,
      uint64_t reserved_version,
      uint64_t* out_local_rev,
      uint64_t* out_global_rev);
    Reply ccf_rust_kv_reserve_version(NativeStore* store);
    Reply ccf_rust_kv_tx_commit_reserved(
      NativeStore* store, NativeTx* tx, uint64_t version);
    Reply ccf_rust_kv_tx_prepare_commit(NativeStore* store, NativeTx* tx);
    Reply ccf_rust_kv_tx_operate(
      const NativeStore* store, NativeTx* tx, Request request);
    Reply ccf_rust_kv_execute_read(const NativeStore* store, Request request);
    Reply ccf_rust_kv_execute(NativeStore* store, Request request);
    Status ccf_rust_kv_replay(
      NativeStore* store,
      uint64_t version,
      const Entry* entries,
      size_t size,
      bool track_deletes);
    Status ccf_rust_kv_install_snapshot(
      NativeStore* store,
      uint64_t version,
      const SnapshotInput* maps,
      size_t size);
    Status ccf_rust_kv_swap_recovery_maps(
      NativeStore* target,
      NativeStore* source,
      const ByteView* names,
      size_t size);
    void ccf_rust_kv_reply_delete(ReplyData* data);
    Entry ccf_rust_kv_reply_entry(const ReplyData* data, size_t index);
    SnapshotMapView ccf_rust_kv_snapshot_map(
      const ReplyData* data, size_t index);
    SnapshotCell ccf_rust_kv_snapshot_cell(
      const ReplyData* data, size_t map, size_t cell);
  }
}
