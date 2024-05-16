// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// CCF
#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/ds/hash.h"
#include "ccf/http_query.h"
#include "ccf/json_handler.h"
#include "ccf/version.h"

#include <charconv>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

// Custom Endpoints
#include "ccf/bundle.h"
#include "ccf/endpoints/authentication/js.h"
#include "ccf/service/tables/modules.h"
#include "endpoint.h"
#include "js/interpreter_cache_interface.h"

using namespace nlohmann;

namespace basicapp
{
  class CustomJSEndpointRegistry : public ccf::UserEndpointRegistry
  {
  public:
    CustomJSEndpointRegistry(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      auto put_custom_endpoints = [this](ccf::endpoints::EndpointContext& ctx) {
        const auto& caller_identity =
          ctx.template get_caller<ccf::UserCOSESign1AuthnIdentity>();

        // Authorization Check
        nlohmann::json user_data = nullptr;
        auto result =
          get_user_data_v1(ctx.tx, caller_identity.user_id, user_data);
        if (result == ccf::ApiResult::InternalError)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to get user data for user {}: {}",
              caller_identity.user_id,
              ccf::api_result_to_str(result)));
          return;
        }
        const auto is_admin_it = user_data.find("isAdmin");

        // Not every user gets to define custom endpoints, only users with
        // isAdmin
        if (
          !user_data.is_object() || is_admin_it == user_data.end() ||
          !is_admin_it.value().get<bool>())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Only admins may access this endpoint.");
          return;
        }
        // End of Authorization Check

        const auto j = nlohmann::json::parse(
          caller_identity.content.begin(), caller_identity.content.end());
        const auto wrapper = j.get<ccf::js::BundleWrapper>();

        auto endpoints = ctx.tx.template rw<ccf::endpoints::EndpointsMap>(
          "custom_endpoints.metadata");
        // Similar to set_js_app
        for (const auto& [url, methods] : wrapper.bundle.metadata.endpoints)
        {
          for (const auto& [method, metadata] : methods)
          {
            std::string method_upper = method;
            nonstd::to_upper(method_upper);
            const auto key = ccf::endpoints::EndpointKey{url, method_upper};
            endpoints->put(key, metadata);
          }
        }

        auto modules =
          ctx.tx.template rw<ccf::Modules>("custom_endpoints.modules");
        for (const auto& [name, module] : wrapper.bundle.modules)
        {
          modules->put(name, module);
        }
        // TBD: Bytecode compilation support

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
      };

      make_endpoint(
        "custom_endpoints",
        HTTP_PUT,
        put_custom_endpoints,
        {ccf::user_cose_sign1_auth_policy})
        .set_auto_schema<void, void>()
        .install();
    }

    // Custom Endpoints

    ccf::endpoints::EndpointDefinitionPtr find_endpoint(
      kv::Tx& tx, ccf::RpcContext& rpc_ctx) override
    {
      // Look up the endpoint definition
      // First in the user-defined endpoints, and then fall-back to built-ins
      const auto method = rpc_ctx.get_method();
      const auto verb = rpc_ctx.get_request_verb();

      auto endpoints =
        tx.ro<ccf::endpoints::EndpointsMap>("custom_endpoints.metadata");
      const auto key = ccf::endpoints::EndpointKey{method, verb};

      // Look for a direct match of the given path
      const auto it = endpoints->get(key);
      if (it.has_value())
      {
        auto endpoint_def = std::make_shared<CustomJSEndpoint>();
        endpoint_def->dispatch = key;
        endpoint_def->properties = it.value();
        endpoint_def->full_uri_path =
          fmt::format("/{}{}", method_prefix, endpoint_def->dispatch.uri_path);
        ccf::instantiate_authn_policies(*endpoint_def);
        return endpoint_def;
      }

      // TBD: templated endpoints
      return ccf::endpoints::EndpointRegistry::find_endpoint(tx, rpc_ctx);
    }

    using PreExecutionHook = std::function<void(ccf::js::core::Context&)>;

    void do_execute_request(
      const CustomJSEndpoint* endpoint,
      ccf::endpoints::EndpointContext& endpoint_ctx,
      const std::optional<PreExecutionHook>& pre_exec_hook = std::nullopt)
    {
      // TBD: interpreter re-use logic
      // TBD: runtime options
      const auto interpreter_cache =
        context.get_subsystem<ccf::js::AbstractInterpreterCache>();

      // TBD: private headers
      //   const auto rw_access =
      //     endpoint->properties.mode == ccf::endpoints::Mode::ReadWrite ?
      //     js::TxAccess::APP_RW :
      //     js::TxAccess::APP_RO;

      //   std::shared_ptr<js::core::Context> interpreter =
      //     interpreter_cache->get_interpreter(rw_access, *endpoint,
      //     flush_marker);
      //   if (interpreter == nullptr)
      //   {
      //     throw std::logic_error("Cache failed to produce interpreter");
      //   }
      //   js::core::Context& ctx = *interpreter;

      // TBD: Run fetched endpoint
      CCF_APP_INFO("CUSTOM ENDPOINT: {}", endpoint->dispatch.uri_path);
    }

    void execute_request(
      const CustomJSEndpoint* endpoint,
      ccf::endpoints::EndpointContext& endpoint_ctx)
    {
      // TBD: historical queries
      do_execute_request(endpoint, endpoint_ctx);
    }

    void execute_endpoint(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::EndpointContext& endpoint_ctx) override
    {
      // Handle endpoint execution
      auto endpoint = dynamic_cast<const CustomJSEndpoint*>(e.get());
      if (endpoint != nullptr)
      {
        execute_request(endpoint, endpoint_ctx);
        return;
      }

      ccf::endpoints::EndpointRegistry::execute_endpoint(e, endpoint_ctx);
    }

    void execute_request_locally_committed(
      const CustomJSEndpoint* endpoint,
      ccf::endpoints::CommandEndpointContext& endpoint_ctx,
      const ccf::TxID& tx_id)
    {
      ccf::endpoints::default_locally_committed_func(endpoint_ctx, tx_id);
    }

    void execute_endpoint_locally_committed(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::CommandEndpointContext& endpoint_ctx,
      const ccf::TxID& tx_id) override
    {
      auto endpoint = dynamic_cast<const CustomJSEndpoint*>(e.get());
      if (endpoint != nullptr)
      {
        execute_request_locally_committed(endpoint, endpoint_ctx, tx_id);
        return;
      }

      ccf::endpoints::EndpointRegistry::execute_endpoint_locally_committed(
        e, endpoint_ctx, tx_id);
    }
  };
}
