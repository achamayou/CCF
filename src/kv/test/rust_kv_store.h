// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/rust_kv_store_impl.h"

#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <typeindex>
#include <utility>
#include <vector>

namespace ccf::kv::untyped
{
  class Map;
}

namespace ccf::kv::rust_test
{
  using namespace ccf::kv::rust_ffi;
  using namespace ccf::kv::rust_detail;

  class Tx;
  class TxDiff;
  class ReadOnlyTx;
  class MapAccess;

  // Thin test/benchmark wrapper around ccf::kv::RustStore that provides
  // standalone Tx/ReadOnlyTx/TxDiff handles so Rust KV can be instantiated
  // alongside C++ ccf::kv::Store in interop tests and benchmarks.
  class Store : public ccf::kv::RustStore
  {
    friend class MapAccess;
    friend class Tx;

  public:
    using ccf::kv::RustStore::RustStore;

    Tx create_tx();
    Tx create_reserved_tx(const TxID& version);
    TxDiff create_tx_diff();
    ReadOnlyTx create_read_only_tx();
  };

  template <typename M>
  struct MapTypes
  {
    using Key = typename M::Key;
    using Value = typename M::Value;
    using Keys = typename M::KeySerialiser;
    using Values = typename M::ValueSerialiser;
  };

  template <>
  struct MapTypes<untyped::Map>
  {
    struct Identity
    {
      static const Bytes& to_serialised(const Bytes& b)
      {
        return b;
      }

      static const Bytes& from_serialised(const Bytes& b)
      {
        return b;
      }
    };

    using Key = Bytes;
    using Value = Bytes;
    using Keys = Identity;
    using Values = Identity;
  };

  struct HandleBase
  {
    virtual ~HandleBase() = default;
  };

  class MapAccess : public HandleBase
  {
    Store& store;
    NativeTx* native_tx;
    std::string name;
    const bool& committed;
    bool read_only;
#ifdef CCF_KV_TRACING
    trace::MapMetadata& trace_metadata;
#endif

  public:
    MapAccess(
      Store& store_,
      NativeTx* native_tx_,
      const std::string& name_,
      const bool& committed_,
      bool read_only_
#ifdef CCF_KV_TRACING
      ,
      trace::MapMetadata& trace_metadata_
#endif
      ) :
      store(store_),
      native_tx(native_tx_),
      name(name_),
      committed(committed_),
      read_only(read_only_)
#ifdef CCF_KV_TRACING
      ,
      trace_metadata(trace_metadata_)
#endif
    {}

    const std::string& map_name() const
    {
      return name;
    }

#ifdef CCF_KV_TRACING
    trace::MapMetadata& trace_meta()
    {
      return trace_metadata;
    }
#endif

    void write(ByteView key, ByteView value = {})
    {
      if (committed)
      {
        throw std::logic_error("Unexpected Rust KV status 1");
      }
      const auto status =
        ccf_rust_kv_tx_write(native_tx, bytes(name), key, value);
      if (status != Status::OK)
      {
        throw std::logic_error(
          "Unexpected Rust KV status " +
          std::to_string(static_cast<unsigned>(status)));
      }
      KV_TRACE(
        const auto k = copy(key); if (value.data != nullptr) {
          const auto v = copy(value);
          trace::operation(
            trace_metadata,
            "put",
            name,
            {{"key", ccf::ds::to_hex(k)}, {"value", ccf::ds::to_hex(v)}});
        } else {
          trace::operation(
            trace_metadata, "remove", name, {{"key", ccf::ds::to_hex(k)}});
        });
    }

    std::optional<Bytes> get_bytes(ByteView key, bool global)
    {
      Bytes out;
      const auto status = ccf_rust_kv_tx_get(
        store.native.get(),
        native_tx,
        committed,
        read_only,
        global,
        bytes(name),
        key,
        &out,
        +[](void* ctx, const uint8_t* ptr, size_t len) {
          auto* dst = static_cast<Bytes*>(ctx);
          if (len != 0)
          {
            *dst = Bytes(ptr, ptr + len);
          }
        });
      if (status == Status::MISSING)
      {
        KV_TRACE(
          const auto k = copy(key); trace::operation(
            trace_metadata,
            global ? "get_global" : "get",
            name,
            {{"key", ccf::ds::to_hex(k)}, {"value", trace::Json(nullptr)}}));
        return std::nullopt;
      }
      if (status != Status::OK)
      {
        throw std::logic_error(
          "Unexpected Rust KV status " +
          std::to_string(static_cast<unsigned>(status)));
      }
      KV_TRACE(const auto k = copy(key); trace::operation(
                 trace_metadata,
                 global ? "get_global" : "get",
                 name,
                 {{"key", ccf::ds::to_hex(k)}, {"value", trace::bytes(&out)}}));
      return out;
    }

    bool has_bytes(ByteView key, bool global)
    {
      auto r = wrap_reply(ccf_rust_kv_tx_has(
        store.native.get(),
        native_tx,
        committed,
        read_only,
        global,
        bytes(name),
        key));
      r.require();
      const bool found = r.number != 0;
      KV_TRACE(const auto k = copy(key); trace::operation(
                 trace_metadata,
                 global ? "has_global" : "has",
                 name,
                 {{"key", ccf::ds::to_hex(k)}, {"value", found}}));
      return found;
    }

    std::optional<Version> previous_bytes(ByteView key)
    {
      auto r = wrap_reply(ccf_rust_kv_tx_previous(
        store.native.get(), native_tx, committed, read_only, bytes(name), key));
      if (r.status == Status::MISSING)
      {
        KV_TRACE(
          const auto k = copy(key); trace::operation(
            trace_metadata,
            "previous_write",
            name,
            {{"key", ccf::ds::to_hex(k)}, {"value", trace::Json(nullptr)}}));
        return std::nullopt;
      }
      r.require();
      KV_TRACE(
        const auto k = copy(key); trace::operation(
          trace_metadata,
          "previous_write",
          name,
          {{"key", ccf::ds::to_hex(k)}, {"value", trace::Json(r.number)}}));
      return r.number;
    }

    Response operate(
      Opcode op, ByteView key = {}, ByteView value = {}, bool global = false)
    {
      return wrap_reply(ccf_rust_kv_tx_operate(
        store.native.get(),
        native_tx,
        {.op = op,
         .inspect_finished = committed,
         .attempt = 0,
         .number = global,
         .map = bytes(name),
         .key = key,
         .value = value}));
    }
  };

  template <typename M>
  class ReadHandle
  {
    using Key = typename MapTypes<M>::Key;
    using Value = typename MapTypes<M>::Value;
    using Keys = typename MapTypes<M>::Keys;
    using Values = typename MapTypes<M>::Values;

    MapAccess& access;

    std::optional<Value> get_at(const Key& key, bool global)
    {
      auto raw = access.get_bytes(bytes(Keys::to_serialised(key)), global);
      if (!raw.has_value())
      {
        return std::nullopt;
      }
      return Values::from_serialised(*raw);
    }

    bool has_at(const Key& key, bool global)
    {
      return access.has_bytes(bytes(Keys::to_serialised(key)), global);
    }

  public:
    explicit ReadHandle(MapAccess& access_) : access(access_) {}

    std::optional<Value> get(const Key& key)
    {
      return get_at(key, false);
    }

    std::optional<Value> get_globally_committed(const Key& key)
    {
      return get_at(key, true);
    }

    bool has(const Key& key)
    {
      return has_at(key, false);
    }

    bool has_globally_committed(const Key& key)
    {
      return has_at(key, true);
    }

    std::optional<Version> get_version_of_previous_write(const Key& key)
    {
      return access.previous_bytes(bytes(Keys::to_serialised(key)));
    }

    size_t size()
    {
      auto r = access.operate(Opcode::SIZE);
      r.require();
      KV_TRACE(trace::operation(
        access.trace_meta(), "size", access.map_name(), {{"value", r.size}}));
      return r.size;
    }

    template <typename F>
    void foreach_raw(F&& f)
    {
      auto r = access.operate(Opcode::SCAN);
      r.require();
#ifdef CCF_KV_TRACING
      if (trace::enabled() && access.trace_meta().suppressed == 0)
      {
        auto& metadata = access.trace_meta();
        const auto iteration = ++metadata.iteration;
        trace::operation(
          metadata,
          "foreach_begin",
          access.map_name(),
          {{"iteration", iteration}});
        try
        {
          for (size_t i = 0; i < r.size; ++i)
          {
            const auto row = r.entry(i);
            const auto k = copy(row.key);
            const auto v = copy(row.value);
            trace::operation(
              metadata,
              "foreach_entry",
              access.map_name(),
              {{"iteration", iteration},
               {"key", ccf::ds::to_hex(k)},
               {"value", ccf::ds::to_hex(v)}});
            const auto cont = f(row);
            trace::operation(
              metadata,
              "foreach_continue",
              access.map_name(),
              {{"iteration", iteration}, {"value", cont}});
            if (!cont)
            {
              break;
            }
          }
        }
        catch (...)
        {
          trace::transaction(
            metadata.id,
            "unsupported",
            {{"operation", "foreach callback exception"}});
          throw;
        }
        trace::operation(
          metadata,
          "foreach_end",
          access.map_name(),
          {{"iteration", iteration}});
        return;
      }
#endif
      // The Rust reply owns the scan image, even if f modifies this map.
      for (size_t i = 0; i < r.size; ++i)
      {
        const auto row = r.entry(i);
        if (!f(row))
        {
          break;
        }
      }
    }

    template <typename F>
    void foreach(F&& f)
    {
      foreach_raw([&](const Entry& row) {
        return f(
          Keys::from_serialised(copy(row.key)),
          Values::from_serialised(copy(row.value)));
      });
    }

    template <typename F>
    void foreach_key(F&& f)
    {
      foreach_raw([&](const Entry& row) {
        return f(Keys::from_serialised(copy(row.key)));
      });
    }

    template <typename F>
    void foreach_value(F&& f)
    {
      foreach_raw([&](const Entry& row) {
        return f(Values::from_serialised(copy(row.value)));
      });
    }

    template <typename F>
    void range(
      F&& f, const std::optional<Key>& lower, const std::optional<Key>& upper)
    {
      auto run = [&](ByteView from, ByteView to) {
        auto r = access.operate(Opcode::RANGE, from, to);
        r.require();
#ifdef CCF_KV_TRACING
        if (trace::enabled())
        {
          auto observed = trace::Json::array();
          for (size_t i = 0; i < r.size; ++i)
          {
            const auto row = r.entry(i);
            const auto k = copy(row.key);
            const auto v = copy(row.value);
            observed.push_back(
              {{"key", ccf::ds::to_hex(k)}, {"value", ccf::ds::to_hex(v)}});
          }
          const auto from_b = from.data != nullptr ?
            std::make_optional(copy(from)) :
            std::nullopt;
          const auto to_b =
            to.data != nullptr ? std::make_optional(copy(to)) : std::nullopt;
          trace::operation(
            access.trace_meta(),
            "range",
            access.map_name(),
            {{"from", trace::bytes(from_b.has_value() ? &*from_b : nullptr)},
             {"to", trace::bytes(to_b.has_value() ? &*to_b : nullptr)},
             {"entries", std::move(observed)}});
        }
#endif
        for (size_t i = 0; i < r.size; ++i)
        {
          const auto row = r.entry(i);
          f(Keys::from_serialised(copy(row.key)),
            Values::from_serialised(copy(row.value)));
        }
      };
      if (lower && upper)
      {
        const auto& from = Keys::to_serialised(*lower);
        const auto& to = Keys::to_serialised(*upper);
        run(bytes(from), bytes(to));
      }
      else if (lower)
      {
        const auto& from = Keys::to_serialised(*lower);
        run(bytes(from), ByteView{});
      }
      else if (upper)
      {
        const auto& to = Keys::to_serialised(*upper);
        run(ByteView{}, bytes(to));
      }
      else
      {
        run(ByteView{}, ByteView{});
      }
    }
  };

  template <typename M>
  class WriteHandle
  {
    using Key = typename MapTypes<M>::Key;
    using Value = typename MapTypes<M>::Value;
    using Keys = typename MapTypes<M>::Keys;
    using Values = typename MapTypes<M>::Values;

    MapAccess& access;

  public:
    explicit WriteHandle(MapAccess& access_) : access(access_) {}

    void put(const Key& key, const Value& value)
    {
      access.write(
        bytes(Keys::to_serialised(key)), bytes(Values::to_serialised(value)));
    }

    void remove(const Key& key)
    {
      access.write(bytes(Keys::to_serialised(key)));
    }

    void clear()
    {
      KV_TRACE(
        trace::operation(access.trace_meta(), "clear", access.map_name()));
      access.operate(Opcode::CLEAR).require();
    }
  };

  template <typename M>
  class Handle : public MapAccess, public ReadHandle<M>, public WriteHandle<M>
  {
  public:
    Handle(
      Store& store,
      NativeTx* native_tx,
      const std::string& name,
      const bool& committed,
      bool read_only
#ifdef CCF_KV_TRACING
      ,
      trace::MapMetadata& trace_metadata
#endif
      ) :
      MapAccess(
        store,
        native_tx,
        name,
        committed,
        read_only
#ifdef CCF_KV_TRACING
        ,
        trace_metadata
#endif
        ),
      ReadHandle<M>(static_cast<MapAccess&>(*this)),
      WriteHandle<M>(static_cast<MapAccess&>(*this))
    {}
  };

  template <typename M>
  struct HandleFamily
  {
    using Full = Handle<M>;
    using Read = ReadHandle<M>;
    using Write = WriteHandle<M>;
  };

  class Tx
  {
    friend class Store;

    struct HandleSlot
    {
      std::string name;
      std::type_index type;
      std::unique_ptr<HandleBase> handle;
    };

    struct State
    {
      Store& store;
      uint64_t id;
      NativeTx* native_tx;
      std::vector<HandleSlot> handles;
      View commit_view = 0;
      std::optional<TxID> read_txid;
      std::optional<TxID> reserved;
      size_t reserve_epoch = 0;
      bool read_only = false;
      bool committing = false;
      bool committed = false;
      bool success = false;
      bool aborted = false;
      std::optional<Version> version;
      CommittableTx::TxFlags flags = 0;
#ifdef CCF_KV_TRACING
      trace::Attempt trace_attempt;
      std::map<std::string, trace::MapMetadata> map_trace_metadata;
#endif

      State(Store& store_, uint64_t id_, bool read_only_) :
        store(store_),
        id(id_),
        native_tx(ccf_rust_kv_tx_new(id_)),
        read_only(read_only_)
      {
        KV_TRACE(trace_attempt.bind(&store));
      }

      ~State()
      {
        store.release_tx_resources(native_tx);
        native_tx = nullptr;
      }
    };

    std::unique_ptr<State> state;

    PendingTxInfo commit_impl(
      const ClaimsDigest& claims,
      const CommittableTx::WriteSetObserver& observer,
      bool reserved)
    {
      auto& s = *state;
      Version v = NoVersion;
      ccf::kv::RustStore::TxCommitParams params{
        .rust_tx = s.native_tx,
        .reserved = s.reserved,
        .reserve_epoch = s.reserve_epoch,
        .claims = claims,
        .observer = observer,
        .is_reserved = reserved,
        .has_any_changes = true,
        .has_snapshot = s.read_txid.has_value(),
        .committing = s.committing,
        .committed = s.committed,
        .success = s.success,
        .aborted = s.aborted,
        .version = v,
        .commit_view = s.commit_view,
        .flags = s.flags
#ifdef CCF_KV_TRACING
        ,
        .trace_id = s.trace_attempt.id
#endif
      };
      auto info = s.store.commit_tx_impl(params);
      if (s.committed || s.aborted)
      {
        s.version = v;
      }
      return info;
    }

  public:
    Tx(Store& store, uint64_t id, bool read_only = false) :
      state(std::make_unique<State>(store, id, read_only))
    {}

    template <typename M>
    typename HandleFamily<M>::Full* rw(const std::string& name)
    {
      auto& s = *state;
      using Full = typename HandleFamily<M>::Full;
      const auto type = std::type_index(typeid(Full));
      bool map_acquired = false;
      for (const auto& slot : s.handles)
      {
        if (slot.name == name)
        {
          map_acquired = true;
          if (slot.type == type)
          {
            if (s.committing && !s.committed)
            {
              throw std::logic_error("Transaction did not commit successfully");
            }
            return static_cast<Full*>(slot.handle.get());
          }
        }
      }
      if (s.committing)
      {
        throw std::logic_error("Cannot acquire a new handle after commit");
      }
      parse_map_name(name);
      // Typed and untyped handles share the single native acquisition.
      if (!map_acquired)
      {
        if (!s.store.acquire_map_for_tx(
              s.native_tx,
              name,
              s.reserved,
              /*explicit_read_txid=*/false,
              s.read_txid,
              s.commit_view
#ifdef CCF_KV_TRACING
              ,
              s.trace_attempt.id
#endif
              ))
        {
          throw CompactedVersionConflict(
            "Cannot acquire a compacted Rust KV map: " + name);
        }
      }
#ifdef CCF_KV_TRACING
      auto& meta = s.map_trace_metadata[name];
      meta.id = s.trace_attempt.id;
#endif
      auto handle = std::make_unique<Full>(
        s.store,
        s.native_tx,
        name,
        s.committed,
        s.read_only
#ifdef CCF_KV_TRACING
        ,
        meta
#endif
      );
      auto* raw = handle.get();
      s.handles.push_back({name, type, std::move(handle)});
      return raw;
    }

    template <typename M>
    typename HandleFamily<M>::Full* rw(const M& map)
    {
      return rw<M>(map.get_name());
    }

    template <typename M>
    typename HandleFamily<M>::Read* ro(const M& map)
    {
      return rw(map);
    }

    template <typename M>
    typename HandleFamily<M>::Read* ro(const std::string& name)
    {
      return rw<M>(name);
    }

    template <typename M>
    typename HandleFamily<M>::Write* wo(const M& map)
    {
      return rw(map);
    }

    template <typename M>
    typename HandleFamily<M>::Write* wo(const std::string& name)
    {
      return rw<M>(name);
    }

    CommitResult commit(
      const ClaimsDigest& claims = empty_claims(),
      const CommittableTx::WriteSetObserver& observer = nullptr)
    {
      return commit_impl(claims, observer, false).success;
    }

    PendingTxInfo commit_reserved()
    {
      return commit_impl(empty_claims(), nullptr, true);
    }

    void set_tx_flag(CommittableTx::TxFlag flag)
    {
      state->flags |= static_cast<CommittableTx::TxFlags>(flag);
    }

    void unset_tx_flag(CommittableTx::TxFlag flag)
    {
      state->flags &= ~static_cast<CommittableTx::TxFlags>(flag);
    }

    bool tx_flag_enabled(CommittableTx::TxFlag flag) const
    {
      return (state->flags & static_cast<CommittableTx::TxFlags>(flag)) != 0;
    }

    Version commit_version() const
    {
      if (!state->version.has_value())
      {
        throw std::logic_error("Transaction not yet committed");
      }
      if (state->aborted)
      {
        throw std::logic_error("Transaction aborted");
      }
      return *state->version;
    }

    View commit_term() const
    {
      static_cast<void>(commit_version());
      return state->commit_view;
    }

    std::optional<TxID> get_txid() const
    {
      const auto version = commit_version();
      if (version == NoVersion || !state->read_txid.has_value())
      {
        return state->read_txid;
      }
      return TxID{state->commit_view, version};
    }
  };

  class ReadOnlyTx
  {
    Tx tx;

  public:
    explicit ReadOnlyTx(Tx&& tx_) : tx(std::move(tx_)) {}

    template <typename M>
    typename HandleFamily<M>::Read* ro(const M& map)
    {
      return tx.ro(map);
    }

    template <typename M>
    typename HandleFamily<M>::Read* ro(const std::string& name)
    {
      return tx.ro<M>(name);
    }
  };

  inline Tx Store::create_tx()
  {
    return Tx(*this, allocate_attempt_id());
  }

  inline Tx Store::create_reserved_tx(const TxID& version)
  {
    if (version.seqno == NoVersion)
    {
      throw std::logic_error("Reserved transaction needs a version");
    }
    auto tx = create_tx();
    std::lock_guard lock(state_lock);
    tx.state->reserved = version;
    tx.state->reserve_epoch = rollback_count;
    return tx;
  }

  inline ReadOnlyTx Store::create_read_only_tx()
  {
    return ReadOnlyTx(Tx(*this, allocate_attempt_id(), /*read_only=*/true));
  }
}
