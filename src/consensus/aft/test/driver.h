// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "consensus/aft/raft.h"
#include "logging_stub.h"

#include <chrono>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#ifdef CCF_RAFT_TRACING
#  define RAFT_DRIVER_PRINT(...) \
    std::cout << "<RaftDriver>  " << fmt::format(__VA_ARGS__) \
              << fmt::format(" (ts={})", logger::logical_clock) << std::endl;
#else
#  define RAFT_DRIVER_PRINT(...) \
    std::cout << "<RaftDriver>  " << fmt::format(__VA_ARGS__) << std::endl;
#endif

std::string stringify(const std::vector<uint8_t>& v, size_t max_size = 15ul)
{
  auto size = std::min(v.size(), max_size);
  return fmt::format(
    "[{} bytes] {}", v.size(), std::string(v.begin(), v.begin() + size));
}

std::string stringify(const std::optional<std::vector<uint8_t>>& o)
{
  if (o.has_value())
  {
    return stringify(*o);
  }

  return "MISSING";
}

struct LedgerStubProxy_Mermaid : public aft::LedgerStubProxy
{
  using LedgerStubProxy::LedgerStubProxy;

  void put_entry(
    const std::vector<uint8_t>& data,
    bool globally_committable,
    kv::Term term,
    kv::Version index) override
  {
    RAFT_DRIVER_PRINT(
      "{}->>{}: [ledger] appending: {}.{}={}",
      _id,
      _id,
      term,
      index,
      stringify(data));
    aft::LedgerStubProxy::put_entry(data, globally_committable, term, index);
  }

  void truncate(aft::Index idx) override
  {
    RAFT_DRIVER_PRINT("{}->>{}: [ledger] truncating to {}", _id, _id, idx);
    aft::LedgerStubProxy::truncate(idx);
  }
};

struct LoggingStubStore_Mermaid : public aft::LoggingStubStoreConfig
{
  using LoggingStubStoreConfig::LoggingStubStoreConfig;

  void compact(aft::Index idx) override
  {
    RAFT_DRIVER_PRINT("{}->>{}: [KV] compacting to {}", _id, _id, idx);
    aft::LoggingStubStoreConfig::compact(idx);
  }

  void rollback(const kv::TxID& tx_id, aft::Term t) override
  {
    RAFT_DRIVER_PRINT(
      "{}->>{}: [KV] rolling back to {}.{}, in term {}",
      _id,
      _id,
      tx_id.term,
      tx_id.version,
      t);
    aft::LoggingStubStoreConfig::rollback(tx_id, t);
  }

  void initialise_term(aft::Term t) override
  {
    RAFT_DRIVER_PRINT("{}->>{}: [KV] initialising in term {}", _id, _id, t);
    aft::LoggingStubStoreConfig::initialise_term(t);
  }
};

using ms = std::chrono::milliseconds;
using TRaft = aft::Aft<LedgerStubProxy_Mermaid>;
using Store = LoggingStubStore_Mermaid;
using Adaptor = aft::Adaptor<Store>;

aft::ChannelStubProxy* channel_stub_proxy(const TRaft& r)
{
  return (aft::ChannelStubProxy*)r.channels.get();
}

class RaftDriver
{
private:
  struct NodeDriver
  {
    std::shared_ptr<Store> kv;
    std::shared_ptr<TRaft> raft;
  };

  std::map<ccf::NodeId, NodeDriver> _nodes;
  std::set<std::pair<ccf::NodeId, ccf::NodeId>> _connections;

  void _replicate(
    const std::string& term_s,
    std::vector<uint8_t> data,
    const size_t lineno,
    bool committable = false,
    const std::optional<kv::Configuration::Nodes>& configuration = std::nullopt,
    const std::optional<kv::Configuration::Nodes>& retired_committed =
      std::nullopt)
  {
    const auto opt = find_primary_in_term(term_s, lineno);
    if (!opt.has_value())
    {
      RAFT_DRIVER_PRINT(
        "Note left of {}: No primary to replicate {}",
        _nodes.begin()->first,
        stringify(data));
      return;
    }
    const auto& [term, node_id] = *opt;
    auto& raft = _nodes.at(node_id).raft;
    const auto idx = raft->get_last_idx() + 1;
    RAFT_DRIVER_PRINT(
      "{}->>{}: replicate {}.{} = {} [{}]",
      node_id,
      node_id,
      term_s,
      idx,
      stringify(data),
      configuration.has_value() ? "reconfiguration" : "raw");

    aft::ReplicatedDataType type = aft::ReplicatedDataType::raw;
    auto hooks = std::make_shared<kv::ConsensusHookPtrs>();
    if (configuration.has_value() && retired_committed.has_value())
    {
      throw std::logic_error(
        "Cannot replicate both configuration and retired_committed in the same "
        "entry");
    }
    if (configuration.has_value())
    {
      auto hook = std::make_unique<aft::ConfigurationChangeHook>(
        configuration.value(), idx);
      hooks->push_back(std::move(hook));
      type = aft::ReplicatedDataType::reconfiguration;
      auto c = nlohmann::json(configuration).dump();

      // If the entry is a reconfiguration, the replicated data is overwritten
      // with the serialised configuration.
      data = std::vector<uint8_t>(c.begin(), c.end());
    }
    if (retired_committed.has_value())
    {
      // Update the node's own retired committed entries collection when
      // replicating There is no direct equivalent in a real node, but this is
      // necessary to emulate the global commit hook effectively.
      _nodes.at(node_id).kv->retired_committed_entries.emplace_back(
        idx, retired_committed.value());

      type = aft::ReplicatedDataType::retired_committed;
      auto c = nlohmann::json(retired_committed).dump();
      data = std::vector<uint8_t>(c.begin(), c.end());
    }

    auto s = nlohmann::json(aft::ReplicatedData{type, data}).dump();
    auto d = std::make_shared<std::vector<uint8_t>>(s.begin(), s.end());
    raft->replicate(kv::BatchVector{{idx, d, committable, hooks}}, term);
  }

  void add_node(ccf::NodeId node_id)
  {
    auto kv = std::make_shared<Store>(node_id);
    const consensus::Configuration settings{{"10ms"}, {"100ms"}};
    auto raft = std::make_shared<TRaft>(
      settings,
      std::make_unique<Adaptor>(kv),
      std::make_unique<LedgerStubProxy_Mermaid>(node_id),
      std::make_shared<aft::ChannelStubProxy>(),
      std::make_shared<aft::State>(node_id),
      nullptr);
    kv->set_set_retired_committed_hook(
      [raft](aft::Index idx, const std::vector<kv::NodeId>& nodes) {
        std::cout << raft << " idx: " << idx << std::endl;
        raft->set_retired_committed(idx, nodes);
      });
    raft->start_ticking();

    if (_nodes.find(node_id) != _nodes.end())
    {
      throw std::logic_error(fmt::format("Node {} already exists", node_id));
    }

    _nodes.emplace(node_id, NodeDriver{kv, raft});
  }

public:
  RaftDriver() = default;

  // Note: deprecated, to be removed when the last scenario using it is removed
  void create_new_nodes(std::vector<std::string> node_ids)
  {
    // Unrealistic way to create network. Initial configuration is automatically
    // added to all nodes.
    kv::Configuration::Nodes configuration;
    for (auto const& n : node_ids)
    {
      add_node(n);
      configuration.try_emplace(n);
    }

    for (auto& node : _nodes)
    {
      node.second.raft->add_configuration(0, configuration);
    }
  }

  // Note: deprecated, to be removed when the last scenario using it is removed
  void create_new_node(std::string node_id_s)
  {
    ccf::NodeId node_id(node_id_s);
    add_node(node_id);
    RAFT_DRIVER_PRINT("Note over {}: Node {} created", node_id, node_id);
  }

  // Note: deprecated, to be removed when the last scenario using it is removed
  void create_start_node(const std::string& start_node_id, const size_t lineno)
  {
    if (!_nodes.empty())
    {
      throw std::logic_error("Start node already exists");
    }
    kv::Configuration::Nodes configuration;
    add_node(start_node_id);
    configuration.try_emplace(start_node_id);
    _nodes[start_node_id].raft->force_become_primary();
    _replicate("2", {}, lineno, false, configuration);
    RAFT_DRIVER_PRINT(
      "Note over {}: Node {} created",
      ccf::NodeId(start_node_id),
      start_node_id);
  }

  void cleanup_nodes(
    const std::string& term,
    const std::vector<std::string>& node_ids,
    const size_t lineno)
  {
    kv::Configuration::Nodes retired_committed;
    for (const auto& id : node_ids)
    {
      if (_nodes.find(id) == _nodes.end())
      {
        throw std::runtime_error(fmt::format(
          "Attempted to clean up unknown node {} on line {}", id, lineno));
      }
      retired_committed.try_emplace(id);
    }
    _replicate(term, {}, lineno, false, std::nullopt, retired_committed);
  }

  void trust_nodes(
    const std::string& term,
    const std::vector<std::string>& node_ids,
    const size_t lineno)
  {
    for (const auto& node_id : node_ids)
    {
      add_node(node_id);
      RAFT_DRIVER_PRINT(
        "Note over {}: Node {} trusted", ccf::NodeId(node_id), node_id);
    }
    kv::Configuration::Nodes configuration;
    for (const auto& [id, node] : _nodes)
    {
      configuration.try_emplace(id);
    }
    for (const auto& node_id : node_ids)
    {
      for (const auto& [id, node] : _nodes)
      {
        if (id != node_id)
        {
          connect(id, node_id);
        }
      }
    }
    _replicate(term, {}, lineno, false, configuration);
  }

  void swap_nodes(
    const std::string& term,
    const std::vector<std::string>& nodes_out,
    const std::vector<std::string>& nodes_in,
    const size_t lineno)
  {
    for (auto node_in : nodes_in)
    {
      add_node(node_in);
      RAFT_DRIVER_PRINT(
        "Note over {}: Node {} trusted", ccf::NodeId(node_in), node_in);
    }
    for (auto node_out : nodes_out)
    {
      RAFT_DRIVER_PRINT(
        "Note over {}: Node {} retired", ccf::NodeId(node_out), node_out);
    }
    std::set<std::string> out(nodes_out.begin(), nodes_out.end());

    kv::Configuration::Nodes configuration;
    for (const auto& [id, node] : _nodes)
    {
      if (out.find(id) == out.end())
      {
        configuration.try_emplace(id);
      }
    }
    for (const auto& [id, node] : _nodes)
    {
      for (auto& node_in : nodes_in)
      {
        if (id != node_in)
        {
          connect(id, node_in);
        }
      }
    }
    _replicate(term, {}, lineno, false, configuration);
  }

  // Note: deprecated, to be removed when the last scenario using it is removed
  void replicate_new_configuration(
    const std::string& term_s,
    std::vector<std::string> node_ids,
    const size_t lineno)
  {
    kv::Configuration::Nodes configuration;
    for (const auto& node_id_s : node_ids)
    {
      ccf::NodeId node_id(node_id_s);

      if (_nodes.find(node_id) == _nodes.end())
      {
        create_new_node(node_id_s);
      }

      configuration.try_emplace(node_id);
    }

    _replicate(term_s, {}, lineno, false, configuration);
  }

  void log(
    ccf::NodeId first,
    ccf::NodeId second,
    const std::string& message,
    bool dropped = false)
  {
    RAFT_DRIVER_PRINT(
      "{}-{}{}: {}", first, (dropped ? "X" : ">>"), second, message);
  }

  void rlog(
    ccf::NodeId first,
    ccf::NodeId second,
    const std::string& message,
    bool dropped = false)
  {
    RAFT_DRIVER_PRINT(
      "{}--{}{}: {}", first, (dropped ? "X" : ">>"), second, message);
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    aft::RequestVote rv,
    bool dropped)
  {
    const auto s = fmt::format(
      "request_vote for term {}, at tx {}.{}",
      rv.term,
      rv.term_of_last_committable_idx,
      rv.last_committable_idx);
    log(node_id, tgt_node_id, s, dropped);
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    aft::RequestVoteResponse rv,
    bool dropped)
  {
    const auto s = fmt::format(
      "request_vote_response for term {} = {}",
      rv.term,
      (rv.vote_granted ? "Y" : "N"));
    rlog(node_id, tgt_node_id, s, dropped);
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    aft::AppendEntries ae,
    bool dropped)
  {
    const auto s = fmt::format(
      "append_entries ({}.{}, {}.{}] (term {}, commit {})",
      ae.prev_term,
      ae.prev_idx,
      ae.term_of_idx,
      ae.idx,
      ae.term,
      ae.leader_commit_idx);
    log(node_id, tgt_node_id, s, dropped);
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    aft::AppendEntriesResponse aer,
    bool dropped)
  {
    char const* success = "UNHANDLED";
    switch (aer.success)
    {
      case (aft::AppendEntriesResponseType::OK):
      {
        success = "ACK";
        break;
      }
      case (aft::AppendEntriesResponseType::FAIL):
      {
        success = "NACK";
        break;
      }
    }
    const auto s = fmt::format(
      "append_entries_response {} for {}.{}",
      success,
      aer.term,
      aer.last_log_idx);
    rlog(node_id, tgt_node_id, s, dropped);
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    aft::ProposeRequestVote prv,
    bool dropped)
  {
    const auto s = fmt::format("propose_request_vote for term {}", prv.term);
    log(node_id, tgt_node_id, s, dropped);
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    const std::vector<uint8_t>& contents,
    bool dropped = false)
  {
    const uint8_t* data = contents.data();
    size_t size = contents.size();

    const auto msg_type = serialized::peek<aft::RaftMsgType>(data, size);
    switch (msg_type)
    {
      case (aft::RaftMsgType::raft_request_vote):
      {
        auto rv = *(aft::RequestVote*)data;
        log_msg_details(node_id, tgt_node_id, rv, dropped);
        break;
      }
      case (aft::RaftMsgType::raft_request_vote_response):
      {
        auto rvr = *(aft::RequestVoteResponse*)data;
        log_msg_details(node_id, tgt_node_id, rvr, dropped);
        break;
      }
      case (aft::RaftMsgType::raft_append_entries):
      {
        auto ae = *(aft::AppendEntries*)data;
        log_msg_details(node_id, tgt_node_id, ae, dropped);
        break;
      }
      case (aft::RaftMsgType::raft_append_entries_response):
      {
        auto aer = *(aft::AppendEntriesResponse*)data;
        log_msg_details(node_id, tgt_node_id, aer, dropped);
        break;
      }
      case (aft::RaftMsgType::raft_propose_request_vote):
      {
        auto prv = *(aft::ProposeRequestVote*)data;
        log_msg_details(node_id, tgt_node_id, prv, dropped);
        break;
      }
      default:
      {
        throw std::runtime_error(
          fmt::format("Unhandled RaftMsgType: {}", msg_type));
      }
    }
  }

  void connect(ccf::NodeId first, ccf::NodeId second)
  {
    RAFT_DRIVER_PRINT("{}-->{}: connect", first, second);
    _connections.insert(std::make_pair(first, second));
    _connections.insert(std::make_pair(second, first));
  }

  void periodic_one(ccf::NodeId node_id, ms ms_)
  {
    std::ostringstream s;
    s << "periodic for " << std::to_string(ms_.count()) << " ms";
    log(node_id, node_id, s.str());
    _nodes.at(node_id).raft->periodic(ms_);
  }

  void periodic_all(ms ms_)
  {
    for (auto& node : _nodes)
    {
      periodic_one(node.first, ms_);
    }
  }

  std::string get_ledger_summary(TRaft& r)
  {
    std::vector<std::string> entries;
    for (auto i = 1; i <= r.get_last_idx(); ++i)
    {
      const auto t = r.get_view(i);
      auto s = fmt::format("{}.{}", t, i);
      if (i == r.get_committed_seqno())
      {
        s = fmt::format("[{}]", s);
      }
      entries.push_back(s);
    }
    return fmt::format("{}", fmt::join(entries, ", "));
  }

  void summarise_log(ccf::NodeId node_id)
  {
    RAFT_DRIVER_PRINT(
      "{}: {}", node_id, get_ledger_summary(*_nodes.at(node_id).raft));
  }

  void summarise_logs_all()
  {
    for (auto& [node_id, _] : _nodes)
    {
      summarise_log(node_id);
    }
  }

  void state_one(ccf::NodeId node_id)
  {
    auto raft = _nodes.at(node_id).raft;
    RAFT_DRIVER_PRINT(
      "Note right of {}: leadership {} membership {} @{}.{} (committed "
      "{})",
      node_id,
      raft->is_backup() ?
        "F" :
        (raft->is_candidate() ? "C" : (raft->is_primary() ? "P" : "?")),
      raft->is_retired() ? "R" : "A",
      raft->get_view(),
      raft->get_last_idx(),
      raft->get_committed_seqno());
  }

  void state_all()
  {
    for (auto& node : _nodes)
    {
      state_one(node.first);
    }
  }

  void shuffle_messages_one(ccf::NodeId node_id)
  {
    auto raft = _nodes.at(node_id).raft;
    auto& messages = channel_stub_proxy(*raft)->messages;

    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(messages.begin(), messages.end(), g);
  }

  void shuffle_messages_all()
  {
    for (auto& node : _nodes)
    {
      shuffle_messages_one(node.first);
    }
  }

  // Returns true if actually sent
  bool dispatch_single_message(
    ccf::NodeId src, ccf::NodeId dst, std::vector<uint8_t> contents)
  {
    if (_connections.find(std::make_pair(src, dst)) != _connections.end())
    {
      // If this is an AppendEntries, then append the corresponding entry from
      // the sender's ledger
      const uint8_t* data = contents.data();
      auto size = contents.size();
      auto msg_type = serialized::peek<aft::RaftMsgType>(data, size);
      bool should_send = true;
      if (msg_type == aft::raft_append_entries)
      {
        // Parse the indices to be sent to the recipient.
        auto ae = *(aft::AppendEntries*)data;

        auto& sender_raft = _nodes.at(src).raft;
        const auto payload_opt =
          sender_raft->ledger->get_append_entries_payload(ae);

        if (!payload_opt.has_value())
        {
          // While trying to construct an AppendEntries, we asked for an
          // entry that doesn't exist. This is a valid situation - we queued
          // the AppendEntries, but rolled back before it was dispatched!
          // We abandon this operation here.
          // We could log this in Mermaid with the line below, but since
          // this does not occur in a real node it is silently ignored. In a
          // real node, the AppendEntries and truncate messages are ordered
          // and processed by the host in that order. All AppendEntries
          // referencing a specific index will be processed before any
          // truncation that removes that index.
          // RAFT_DRIVER_PRINT(
          //        "Note right of {}: Abandoning AppendEntries"
          //        "containing {} - no longer in ledger",
          //        node_id,
          //        idx);
          should_send = false;
        }
        else
        {
          contents.insert(
            contents.end(), payload_opt->begin(), payload_opt->end());
        }
      }

      if (should_send)
      {
        log_msg_details(src, dst, contents);
        _nodes.at(dst).raft->recv_message(
          src, contents.data(), contents.size());
        return true;
      }
    }

    return false;
  }

  template <class Messages>
  size_t dispatch_one_queue(
    ccf::NodeId node_id,
    Messages& messages,
    const std::optional<size_t>& max_count = std::nullopt)
  {
    size_t count = 0;

    while (messages.size() && (!max_count.has_value() || count < *max_count))
    {
      auto [tgt_node_id, contents] = messages.front();
      messages.pop_front();

      if (dispatch_single_message(node_id, tgt_node_id, contents))
      {
        ++count;
      }
    }

    return count;
  }

  void dispatch_one(
    ccf::NodeId node_id, const std::optional<size_t>& max_count = std::nullopt)
  {
    auto raft = _nodes.at(node_id).raft;
    dispatch_one_queue(node_id, channel_stub_proxy(*raft)->messages, max_count);
  }

  void dispatch_all_once()
  {
    // The intent is to dispatch all _current_ messages, but no new ones. If we
    // simply iterated, then we may dispatch new messages that are produced on
    // later nodes, in response to messages from earlier-processed nodes. To
    // avoid that, we count how many messages are present initially, and cap to
    // only processing that many
    std::map<ccf::NodeId, size_t> initial_message_counts;
    for (auto& [node_id, driver] : _nodes)
    {
      initial_message_counts[node_id] =
        channel_stub_proxy(*driver.raft)->messages.size();
    }

    for (auto& node : _nodes)
    {
      dispatch_one(node.first, initial_message_counts[node.first]);
    }
  }

  void dispatch_all()
  {
    size_t iterations = 0;
    while (std::accumulate(
             _nodes.begin(),
             _nodes.end(),
             0,
             [](int acc, auto& node) {
               return channel_stub_proxy(*node.second.raft)->messages.size() +
                 acc;
             }) &&
           iterations++ < 5)
    {
      dispatch_all_once();
    }
  }

  void dispatch_single(ccf::NodeId src, ccf::NodeId dst)
  {
    auto& messages = channel_stub_proxy(*_nodes.at(src).raft)->messages;
    auto it = messages.begin();
    while (it != messages.end())
    {
      auto [target, contents] = *it;
      if (target == dst)
      {
        dispatch_single_message(src, dst, contents);
        it = messages.erase(it);
        break;
      }
      else
      {
        ++it;
      }
    }
  }

  std::optional<std::pair<aft::Term, ccf::NodeId>> find_primary_in_term(
    const std::string& term_s, const size_t lineno)
  {
    std::vector<std::pair<aft::Term, ccf::NodeId>> primaries;
    for (const auto& [node_id, node_driver] : _nodes)
    {
      if (node_driver.raft->is_primary())
      {
        primaries.emplace_back(node_driver.raft->get_view(), node_id);
      }
    }

    if (term_s == "latest")
    {
      if (!primaries.empty())
      {
        std::sort(primaries.begin(), primaries.end());
        return primaries.back();
      }
      else
      {
        // Having no 'latest' term is valid, and may result in scenario steps
        // being ignored
        return std::nullopt;
      }
    }
    else
    {
      const auto desired_term = atoi(term_s.c_str());
      for (const auto& pair : primaries)
      {
        if (pair.first == desired_term)
        {
          return pair;
        }
      }
    }

    throw std::runtime_error(
      fmt::format("Found no primary in term {} on line {}", term_s, lineno));
  }

  void replicate(
    const std::string& term_s,
    std::shared_ptr<std::vector<uint8_t>> data,
    const size_t lineno)
  {
    _replicate(term_s, *data, lineno);
  }

  void emit_signature(const std::string& term_s, const size_t lineno)
  {
    std::string sig_s = "signature";
    std::vector<uint8_t> sig(sig_s.data(), sig_s.data() + sig_s.size());
    _replicate(term_s, sig, lineno, true);
  }

  void disconnect(ccf::NodeId left, ccf::NodeId right)
  {
    bool noop = true;
    auto ltr = std::make_pair(left, right);
    auto rtl = std::make_pair(right, left);
    if (_connections.find(ltr) != _connections.end())
    {
      _connections.erase(ltr);
      noop = false;
    }
    if (_connections.find(rtl) != _connections.end())
    {
      _connections.erase(rtl);
      noop = false;
    }
    if (!noop)
    {
      RAFT_DRIVER_PRINT("{}-->{}: disconnect", left, right);
    }
  }

  void disconnect_node(ccf::NodeId node_id)
  {
    for (auto& node : _nodes)
    {
      if (node.first != node_id)
      {
        disconnect(node_id, node.first);
      }
    }
  }

  void reconnect(ccf::NodeId left, ccf::NodeId right)
  {
    RAFT_DRIVER_PRINT("{}-->{}: reconnect", left, right);
    _connections.insert(std::make_pair(left, right));
    _connections.insert(std::make_pair(right, left));
  }

  void reconnect_node(ccf::NodeId node_id)
  {
    for (auto& node : _nodes)
    {
      if (node.first != node_id)
      {
        reconnect(node_id, node.first);
      }
    }
  }

  void drop_pending_to(ccf::NodeId from, ccf::NodeId to)
  {
    auto from_raft = _nodes.at(from).raft;
    auto& messages = channel_stub_proxy(*from_raft)->messages;
    auto it = messages.begin();
    while (it != messages.end())
    {
      if (it->first == to)
      {
        log_msg_details(from, to, it->second, true);
        it = messages.erase(it);
      }
      else
      {
        ++it;
      }
    }
  }

  void drop_pending(ccf::NodeId from)
  {
    for (auto& [to, _] : _nodes)
    {
      drop_pending_to(from, to);
    }
  }

  void assert_is_backup(ccf::NodeId node_id, const size_t lineno)
  {
    if (!_nodes.at(node_id).raft->is_backup())
    {
      RAFT_DRIVER_PRINT(
        "Note over {}: Node is not in expected state: backup", node_id);
      throw std::runtime_error(fmt::format(
        "Node not in expected state backup on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_isnot_backup(ccf::NodeId node_id, const size_t lineno)
  {
    if (_nodes.at(node_id).raft->is_backup())
    {
      RAFT_DRIVER_PRINT(
        "Note over {}: Node is in unexpected state: backup", node_id);
      throw std::runtime_error(fmt::format(
        "Node in unexpected state backup on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_is_primary(ccf::NodeId node_id, const size_t lineno)
  {
    if (!_nodes.at(node_id).raft->is_primary())
    {
      RAFT_DRIVER_PRINT(
        "Note over {}: Node is not in expected state: primary", node_id);
      throw std::runtime_error(fmt::format(
        "Node not in expected state primary on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_isnot_primary(ccf::NodeId node_id, const size_t lineno)
  {
    if (_nodes.at(node_id).raft->is_primary())
    {
      RAFT_DRIVER_PRINT(
        "Note over {}: Node is in unexpected state: primary", node_id);
      throw std::runtime_error(fmt::format(
        "Node in unexpected state primary on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_is_candidate(ccf::NodeId node_id, const size_t lineno)
  {
    if (!_nodes.at(node_id).raft->is_candidate())
    {
      RAFT_DRIVER_PRINT(
        "Note over {}: Node is not in expected state: candidate", node_id);
      throw std::runtime_error(fmt::format(
        "Node not in expected state candidate on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_isnot_candidate(ccf::NodeId node_id, const size_t lineno)
  {
    if (_nodes.at(node_id).raft->is_candidate())
    {
      RAFT_DRIVER_PRINT(
        "Note over {}: Node is in unexpected state: candidate", node_id);
      throw std::runtime_error(fmt::format(
        "Node in unexpected state candidate on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_is_retired(ccf::NodeId node_id, const size_t lineno)
  {
    if (!_nodes.at(node_id).raft->is_retired())
    {
      RAFT_DRIVER_PRINT(
        "Note over {}: Node is not in expected state: retired", node_id);
      throw std::runtime_error(fmt::format(
        "Node not in expected state retired on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_is_active(ccf::NodeId node_id, const size_t lineno)
  {
    if (!_nodes.at(node_id).raft->is_active())
    {
      RAFT_DRIVER_PRINT(
        "Note over {}: Node is not in expected state: active", node_id);
      throw std::runtime_error(fmt::format(
        "Node not in expected state active on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_state_sync(const size_t lineno)
  {
    auto [target_id, nd] = *_nodes.begin();
    auto& target_raft = nd.raft;
    const auto target_term = target_raft->get_view();
    const auto target_last_idx = target_raft->get_last_idx();
    const auto target_commit_idx = target_raft->get_committed_seqno();

    bool all_match = true;
    for (auto it = std::next(_nodes.begin()); it != _nodes.end(); ++it)
    {
      const auto& node_id = it->first;
      auto& raft = it->second.raft;

      if (raft->get_view() != target_term)
      {
        RAFT_DRIVER_PRINT(
          "Note over {}: Term {} doesn't match term {} on {}",
          node_id,
          raft->get_view(),
          target_term,
          target_id);
        all_match = false;
      }

      if (raft->get_last_idx() != target_last_idx)
      {
        RAFT_DRIVER_PRINT(
          "Note over {}: Last index {} doesn't match "
          "last index {} on {}",
          node_id,
          raft->get_last_idx(),
          target_last_idx,
          target_id);
        all_match = false;
      }
      else
      {
        // Check that the every ledger entry matches
        for (auto idx = 1; idx <= target_last_idx; ++idx)
        {
          const auto target_entry = target_raft->ledger->get_entry_by_idx(idx);
          if (!target_entry.has_value())
          {
            RAFT_DRIVER_PRINT(
              "Note over {}: Missing ledger entry at {}", target_id, idx);
            all_match = false;
            break;
          }
          else
          {
            const auto entry = raft->ledger->get_entry_by_idx(idx);
            if (!entry.has_value())
            {
              RAFT_DRIVER_PRINT(
                "Note over {}: Missing ledger entry at {}", node_id, idx);
              all_match = false;
              break;
            }
            else if (entry != target_entry)
            {
              RAFT_DRIVER_PRINT(
                "Note over {}: Entry at index {} "
                "doesn't match entry on {}: {} != {}",
                node_id,
                idx,
                target_id,
                stringify(entry.value()),
                stringify(target_entry.value()));
              all_match = false;
              break;
            }
          }
        }
      }

      if (raft->get_committed_seqno() != target_commit_idx)
      {
        RAFT_DRIVER_PRINT(
          "Note over {}: Commit index {} doesn't "
          "match commit index {} on {}",
          node_id,
          raft->get_committed_seqno(),
          target_commit_idx,
          target_id);
        all_match = false;
      }
    }

    if (!all_match)
    {
      throw std::runtime_error(fmt::format(
        "States not in sync on line {}", std::to_string((int)lineno)));
    }
  }

  void assert_commit_safety(ccf::NodeId node_id, const size_t lineno)
  {
    // Confirm that the index this node considers committed, is present on a
    // majority of nodes (ledger matches exactly up to and including this
    // seqno).
    // Similar to the QuorumLogInv invariant from the TLA spec.
    // NB: This currently assumes a single configuration, as it checks a quorum
    // of all nodes rather than within each configuration
    const auto& raft = _nodes.at(node_id).raft;
    const auto committed_seqno = raft->get_committed_seqno();

    auto get_ledger_prefix = [this](ccf::NodeId id, ccf::SeqNo seqno) {
      std::vector<std::vector<uint8_t>> prefix;
      auto& ledger = _nodes.at(id).raft->ledger;
      for (auto i = 1; i <= seqno; ++i)
      {
        auto entry = ledger->get_entry_by_idx(i);
        if (!entry.has_value())
        {
          // Early-out!
          return prefix;
        }
        prefix.push_back(entry.value());
      }
      return prefix;
    };
    const auto committed_prefix = get_ledger_prefix(node_id, committed_seqno);

    auto is_present = [&](const auto& it) {
      const auto& [id, _] = it;
      return get_ledger_prefix(id, committed_seqno) == committed_prefix;
    };

    const auto present_count =
      std::count_if(_nodes.begin(), _nodes.end(), is_present);

    const auto quorum = (_nodes.size() / 2) + 1;
    if (present_count < quorum)
    {
      RAFT_DRIVER_PRINT(
        "Note over {}: Node has advanced commit to {}, "
        "yet this entry is only present on {}/{} nodes "
        "(need at least {} for safety)",
        node_id,
        committed_seqno,
        present_count,
        _nodes.size(),
        quorum);
      throw std::runtime_error(fmt::format(
        "Node ({}) at unsafe commit idx ({}) on line {}",
        node_id,
        committed_seqno,
        lineno));
    }
  }

  void assert_commit_idx(
    ccf::NodeId node_id, const std::string& idx_s, const size_t lineno)
  {
    auto idx = std::stol(idx_s);
    if (_nodes.at(node_id).raft->get_committed_seqno() != idx)
    {
      RAFT_DRIVER_PRINT(
        "Note over {}: Node is not at expected commit idx {}", node_id, idx);
      throw std::runtime_error(fmt::format(
        "Node {} not at expected commit idx ({}) on line {} : {}",
        node_id,
        idx,
        std::to_string((int)lineno),
        _nodes.at(node_id).raft->get_committed_seqno()));
    }
  }

  void assert_detail(
    ccf::NodeId node_id,
    const std::string& detail,
    const std::string& expected,
    const size_t lineno)
  {
    auto details = _nodes.at(node_id).raft->get_details();
    nlohmann::json d = details;
    if (d.find(detail) == d.end())
    {
      RAFT_DRIVER_OUT << fmt::format(
                           "  Note over {}: Node does not have detail {}",
                           node_id,
                           detail)
                      << std::endl;
      throw std::runtime_error(fmt::format(
        "Node {} does not have detail {} on line {}",
        node_id,
        detail,
        std::to_string((int)lineno)));
    }

    std::string value = d[detail];
    if (value != expected)
    {
      RAFT_DRIVER_OUT
        << fmt::format(
             "  Note over {}: Node detail {} is not as expected: {} != {}",
             node_id,
             detail,
             value,
             expected)
        << std::endl;
      throw std::runtime_error(fmt::format(
        "Node {} detail {} is not as expected: {} != {} on line {}",
        node_id,
        detail,
        value,
        expected,
        std::to_string((int)lineno)));
    }
  }
};