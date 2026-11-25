// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/map.h"
#include "ccf/kv/set.h"
#include "ccf/kv/unit_value.h"
#include "ccf/kv/value.h"
#include "kv/test/rust_kv_store.h"

namespace ccf::kv::rust_test
{
  using Identity = MapTypes<untyped::Map>::Identity;

  template <typename Read, typename Write>
  class TypedHandle : public MapAccess, public Read, public Write
  {
  public:
    TypedHandle(
      Store& store,
      NativeTx* native_tx,
      const std::string& name,
      const bool& committed) :
      MapAccess(store, native_tx, name, committed),
      Read(static_cast<MapAccess&>(*this)),
      Write(static_cast<MapAccess&>(*this))
    {}
  };

  template <typename K, typename KS, typename Unit>
  struct HandleFamily<TypedSet<K, KS, Unit>>
  {
    using Map = TypedMap<K, Bytes, KS, Identity>;
    using ReadBase = ReadHandle<Map>;
    using WriteBase = WriteHandle<Map>;

    class Read : private ReadBase
    {
    public:
      using ReadBase::get_version_of_previous_write;
      using ReadBase::ReadBase;
      using ReadBase::size;

      bool contains(const K& key)
      {
        return ReadBase::has(key);
      }

      bool contains_globally_committed(const K& key)
      {
        return ReadBase::has_globally_committed(key);
      }

      template <typename F>
      void foreach(F&& f)
      {
        ReadBase::foreach_key(std::forward<F>(f));
      }
    };

    class Write : private WriteBase
    {
    public:
      using WriteBase::clear;
      using WriteBase::remove;
      using WriteBase::WriteBase;

      void insert(const K& key)
      {
        WriteBase::put(key, Unit::get());
      }
    };

    using Full = TypedHandle<Read, Write>;
  };

  template <typename V, typename VS, typename Unit>
  struct HandleFamily<TypedValue<V, VS, Unit>>
  {
    using Map = TypedMap<Bytes, V, Identity, VS>;
    using ReadBase = ReadHandle<Map>;
    using WriteBase = WriteHandle<Map>;

    class Read : private ReadBase
    {
    public:
      using ReadBase::ReadBase;

      std::optional<V> get()
      {
        return ReadBase::get(Unit::get());
      }

      std::optional<V> get_globally_committed()
      {
        return ReadBase::get_globally_committed(Unit::get());
      }

      bool has()
      {
        return ReadBase::has(Unit::get());
      }

      std::optional<Version> get_version_of_previous_write()
      {
        return ReadBase::get_version_of_previous_write(Unit::get());
      }
    };

    class Write : private WriteBase
    {
    public:
      using WriteBase::clear;
      using WriteBase::WriteBase;

      void put(const V& value)
      {
        WriteBase::put(Unit::get(), value);
      }
    };

    using Full = TypedHandle<Read, Write>;
  };

  template <typename Unit>
  struct HandleFamily<UnitValue<Unit>>
  {
    using ValueFamily = HandleFamily<TypedValue<Bytes, Identity, Unit>>;
    using ReadBase = typename ValueFamily::Read;
    using WriteBase = typename ValueFamily::Write;

    class Read : private ReadBase
    {
    public:
      using ReadBase::get_version_of_previous_write;
      using ReadBase::has;
      using ReadBase::ReadBase;
    };

    class Write : private WriteBase
    {
    public:
      using WriteBase::clear;
      using WriteBase::WriteBase;

      void touch()
      {
        WriteBase::put(Unit::get());
      }
    };

    using Full = TypedHandle<Read, Write>;
  };
}
