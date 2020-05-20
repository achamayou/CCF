// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "consensus/pbft/libbyz/libbyz.h"
#include "consensus/pbft/libbyz/pbft_assert.h"
#include "enclave/rpc_handler.h"
#include "enclave/rpc_map.h"
#include "pbft_deps.h"

namespace pbft
{
  class AbstractPbftConfig
  {
  public:
    static char* service_mem;
    virtual ~AbstractPbftConfig() = default;
    virtual void set_service_mem(char* sm) = 0;
    virtual void set_receiver(IMessageReceiveBase* message_receive_base_) = 0;
    virtual ExecCommand get_exec_command() = 0;
    virtual ReceiptOps* get_receipts_ops() = 0;
  };

  class PbftConfigCcf : public AbstractPbftConfig, public ReceiptOps
  {
  public:
    PbftConfigCcf(
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      std::shared_ptr<pbft::PbftStore> store_) :
      rpc_map(rpc_map_),
      store(store_)
    {}

    ~PbftConfigCcf() = default;

    void set_service_mem(char* sm) override
    {
      service_mem = sm;
    }

    void set_receiver(IMessageReceiveBase* message_receive_base_) override
    {
      message_receive_base = message_receive_base_;
    }

    ExecCommand get_exec_command() override
    {
      return exec_command;
    }

    ReceiptOps* get_receipts_ops() override
    {
      return this;
    }

    std::vector<uint8_t> get_receipt(kv::Version index) override
    {
      return store->get_receipt(index);
    }

  private:
    std::shared_ptr<enclave::RPCMap> rpc_map;
    std::shared_ptr<pbft::PbftStore> store;

    IMessageReceiveBase* message_receive_base;

    struct ExecutionCtx
    {
      ExecutionCtx(
        std::unique_ptr<ExecCommandMsg> msg_,
        ByzInfo& info_,
        PbftConfigCcf* self_,
        bool is_first_request_,
        uint64_t nonce_,
        kv::Version commit_version_) :
        msg(std::move(msg_)),
        info(info_),
        self(self_),
        is_first_request(is_first_request_),
        did_exec_gov_req(false),
        nonce(nonce_),
        commit_version(commit_version_)
      {}

      std::unique_ptr<ExecCommandMsg> msg;
      ByzInfo& info;
      kv::Version version;
      std::shared_ptr<enclave::RpcHandler> frontend;
      PbftConfigCcf* self;
      bool is_first_request;
      bool did_exec_gov_req;
      uint64_t nonce;
      kv::Version commit_version;
    };

    static void ExecuteCb(std::unique_ptr<enclave::Tmsg<ExecutionCtx>> c)
    {
      ExecutionCtx& execution_ctx = c->data;
      ByzInfo& info = execution_ctx.info;
      std::shared_ptr<enclave::RpcHandler> frontend = execution_ctx.frontend;

      ExecCommandMsg& exec_msg = *execution_ctx.msg.get();

      bool did_conflict_occur = execution_ctx.self->store->did_conflict_occur();

      info.ctx = execution_ctx.version;
      execution_ctx.msg->cb(exec_msg, info, did_conflict_occur);

      --info.pending_cmd_callbacks;

      try
      {
        frontend->update_merkle_tree();
      }
      catch (const std::exception& e)
      {
        LOG_TRACE_FMT("Failed to insert into merkle tree", e.what());
        abort();
      }

      if (info.pending_cmd_callbacks == 0)
      {
        static_assert(
          sizeof(info.replicated_state_merkle_root) ==
          sizeof(crypto::Sha256Hash));
        crypto::Sha256Hash root = frontend->get_merkle_root();
        std::copy(
          std::begin(root.h),
          std::end(root.h),
          std::begin(info.replicated_state_merkle_root));

        info.did_exec_gov_req = execution_ctx.did_exec_gov_req;
        info.version_after_execution =
          execution_ctx.self->store->set_store_last_valid_version();
        if (info.cb != nullptr)
        {
          info.cb(info.cb_ctx);
        }
      }
    }

    static void Execute(std::unique_ptr<enclave::Tmsg<ExecutionCtx>> c)
    {
      ExecutionCtx& execution_ctx = c->data;
      std::unique_ptr<ExecCommandMsg>& msg = execution_ctx.msg;
      PbftConfigCcf* self = execution_ctx.self;
      ByzInfo& info = execution_ctx.info;

      Byz_req* inb = &msg->inb;
      Byz_rep& outb = msg->outb;
      int client = msg->client;
      Request_id rid = msg->rid;
      uint8_t* req_start = msg->req_start;
      size_t req_size = msg->req_size;
      ccf::Store::Tx* tx = msg->tx;
      int replier = msg->replier;
      uint16_t reply_thread = msg->reply_thread;

      pbft::Request request;
      request.deserialise((uint8_t*)inb->contents, inb->size);

      auto session = std::make_shared<enclave::SessionContext>(
        enclave::InvalidSessionId, request.caller_id, request.caller_cert);

      auto ctx = enclave::make_fwd_rpc_context(
        session,
        request.raw,
        (enclave::FrameFormat)request.frame_format,
        {req_start, req_start + req_size});
      ctx->is_create_request = c->data.is_first_request;
      ctx->set_apply_writes(true);

      const auto actor_opt = http::extract_actor(*ctx);
      if (!actor_opt.has_value())
      {
        throw std::logic_error(fmt::format(
          "Failed to extract actor from PBFT request. Method is '{}'",
          ctx->get_method()));
      }

      const auto& actor_s = actor_opt.value();
      const auto actor = self->rpc_map->resolve(actor_s);
      auto handler = self->rpc_map->find(actor);
      if (!handler.has_value())
        throw std::logic_error(
          fmt::format("No frontend associated with actor {}", actor_s));

      auto frontend = handler.value();
      c->data.did_exec_gov_req =
        (c->data.did_exec_gov_req || frontend->is_members_frontend());

      execution_ctx.frontend = frontend;

      enclave::RpcHandler::ProcessPbftResp rep;
      if (tx != nullptr)
      {
        rep = frontend->process_pbft(ctx, *tx, true);
      }
      else
      {
        if (execution_ctx.commit_version == kv::NoVersion)
        {
          rep = frontend->process_pbft(ctx);
        }
        else
        {
          ccf::Store::Tx tx(execution_ctx.commit_version);
          rep = frontend->process_pbft(ctx, tx, false);
        }
      }
      execution_ctx.version = rep.version;

      outb.contents = self->message_receive_base->create_response_message(
        client, rid, rep.version, rep.result.size(), execution_ctx.nonce);

      outb.size = rep.result.size();
      auto outb_ptr = (uint8_t*)outb.contents;
      size_t outb_size = (size_t)outb.size;

      serialized::write(
        outb_ptr, outb_size, rep.result.data(), rep.result.size());

      if (info.cb != nullptr)
      {
        enclave::ThreadMessaging::thread_messaging
          .ChangeTmsgCallback<ExecutionCtx>(c, &ExecuteCb);
        enclave::ThreadMessaging::thread_messaging.add_task<ExecutionCtx>(
          enclave::ThreadMessaging::main_thread, std::move(c));
      }
      else
      {
        ExecuteCb(std::move(c));
      }
    };

    bool is_first_request = true;
    ExecCommand exec_command =
      [this](
        std::array<std::unique_ptr<ExecCommandMsg>, Max_requests_in_batch>&
          msgs,
        ByzInfo& info,
        uint32_t num_requests,
        uint64_t nonce,
        bool executed_single_threaded,
        bool is_primary) {
        info.pending_cmd_callbacks = num_requests;
        info.version_before_execution_start =
          store->set_store_last_valid_version();
        for (uint32_t i = 0; i < num_requests; ++i)
        {
          kv::Version commit_version = kv::NoVersion;
          if (!is_primary && !executed_single_threaded)
          {
            commit_version = info.version_before_execution_start + i + 1;
          }

          std::unique_ptr<ExecCommandMsg>& msg = msgs[i];
          uint16_t reply_thread = msg->reply_thread;
          auto execution_ctx = std::make_unique<enclave::Tmsg<ExecutionCtx>>(
            &Execute,
            std::move(msg),
            info,
            this,
            is_first_request,
            nonce,
            commit_version);
          is_first_request = false;

          if (info.cb != nullptr)
          {
            int tid = reply_thread;
            if (executed_single_threaded && tid > 1)
            {
              tid = 1;
            }
            enclave::ThreadMessaging::thread_messaging.add_task<ExecutionCtx>(
              tid, std::move(execution_ctx));
          }
          else
          {
            Execute(std::move(execution_ctx));
          }
        }
        return 0;
      };
  };
};