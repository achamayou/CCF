// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>
#include <cstdint>

namespace ccf::kv::rust_test
{
  // Keep the wire layout and discriminants in sync with cpp-test/src/lib.rs.
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
