// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/openapi.h"
#include "ccf/endpoint_context.h"
#include "ccf/http_consts.h"
#include "ccf/rest_verb.h"
#include "ccf/service/map.h"

#include <string>
#include <utility>

namespace ccf::endpoints
{
  using URI = std::string;

  struct EndpointKey
  {
    /// URI path to endpoint
    URI uri_path;
    /// HTTP Verb
    RESTVerb verb = HTTP_POST;
  };

  DECLARE_JSON_TYPE(EndpointKey);
  DECLARE_JSON_REQUIRED_FIELDS(EndpointKey, uri_path, verb);

  enum class ForwardingRequired
  {
    Sometimes,
    Always,
    Never
  };

  enum class ExecuteOutsideConsensus
  {
    Never,
    Locally,
    Primary
  };

  enum class Mode
  {
    ReadWrite,
    ReadOnly,
    Historical
  };

  enum QueryParamPresence
  {
    RequiredParameter,
    OptionalParameter,
  };

  DECLARE_JSON_ENUM(
    ForwardingRequired,
    {{ForwardingRequired::Sometimes, "sometimes"},
     {ForwardingRequired::Always, "always"},
     {ForwardingRequired::Never, "never"}});

  DECLARE_JSON_ENUM(
    ExecuteOutsideConsensus,
    {{ExecuteOutsideConsensus::Never, "never"},
     {ExecuteOutsideConsensus::Locally, "locally"},
     {ExecuteOutsideConsensus::Primary, "primary"}});

  DECLARE_JSON_ENUM(
    Mode,
    {{Mode::ReadWrite, "readwrite"},
     {Mode::ReadOnly, "readonly"},
     {Mode::Historical, "historical"}});

  struct EndpointProperties
  {
    /// Endpoint mode
    Mode mode = Mode::ReadWrite;
    /// Endpoint forwarding policy
    ForwardingRequired forwarding_required = ForwardingRequired::Always;
    /// Execution policy
    ExecuteOutsideConsensus execute_outside_consensus =
      ExecuteOutsideConsensus::Never;
    /// Authentication policies
    std::vector<std::string> authn_policies = {};
    /// OpenAPI schema for endpoint
    nlohmann::json openapi;
    //// Whether to include endpoint schema in frontend schema
    bool openapi_hidden = false;
    /// JavaScript module
    std::string js_module;
    /// JavaScript function name
    std::string js_function;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(EndpointProperties);
  DECLARE_JSON_REQUIRED_FIELDS(
    EndpointProperties, forwarding_required, authn_policies);
  DECLARE_JSON_OPTIONAL_FIELDS(
    EndpointProperties, openapi, openapi_hidden, mode, js_module, js_function);

  struct EndpointDefinition
  {
    virtual ~EndpointDefinition() = default;

    EndpointKey dispatch;

    /// Full URI path to endpoint, including method prefix
    URI full_uri_path;

    EndpointProperties properties;

    /** List of authentication policies which will be checked before executing
     * this endpoint.
     *
     * When multiple policies are specified, any single successful check is
     * sufficient to grant access, even if others fail. If all policies fail,
     * the last will set an error status on the response, and the endpoint
     * will not be invoked. If no policies are specified then the default
     * behaviour is that the endpoint accepts all requests, without any
     * authentication checks.
     *
     * If an auth policy passes, it may construct an object describing the
     * Identity of the caller to be used by the endpoint. This can be
     * retrieved inside the endpoint with ctx.get_caller<IdentType>(),
     * @see ccf::UserCertAuthnIdentity
     * @see ccf::JwtAuthnIdentity
     * @see ccf::UserSignatureAuthnIdentity
     *
     * @see ccf::empty_auth_policy
     * @see ccf::user_cert_auth_policy
     * @see ccf::user_signature_auth_policy
     */
    AuthnPolicies authn_policies;
  };

  using EndpointDefinitionPtr = std::shared_ptr<const EndpointDefinition>;

  using EndpointsMap = ccf::ServiceMap<EndpointKey, EndpointProperties>;
  namespace Tables
  {
    static constexpr auto ENDPOINTS = "public:ccf.gov.endpoints";
  }

  /** An Endpoint represents a user-defined resource that can be invoked by
   * authorised users via HTTP requests, over TLS. An Endpoint is accessible
   * at a specific verb and URI, e.g. POST /app/accounts or GET /app/records.
   *
   * Endpoints can read from and mutate the state of the replicated key-value
   * store.
   *
   * A CCF application is a collection of Endpoints recorded in the
   * application's EndpointRegistry.
   */
  struct Endpoint : public EndpointDefinition
  {
    // Functor which is invoked to process requests for this Endpoint
    EndpointFunction func = {};

    struct Installer
    {
      virtual void install(Endpoint&) = 0;
    };
    Installer* installer;

    using SchemaBuilderFn =
      std::function<void(nlohmann::json&, const Endpoint&)>;
    std::vector<SchemaBuilderFn> schema_builders = {};

    bool openapi_hidden = false;

    http_status success_status = HTTP_STATUS_OK;
    nlohmann::json params_schema = nullptr;
    nlohmann::json result_schema = nullptr;

    /** Whether the endpoint should be omitted from the OpenAPI document.
     *
     * @return This Endpoint for further modification
     */
    Endpoint& set_openapi_hidden(bool hidden);

    /** Sets the JSON schema that the request parameters must comply with.
     *
     * @param j Request parameters JSON schema
     * @return This Endpoint for further modification
     */
    Endpoint& set_params_schema(const nlohmann::json& j);

    /** Sets the JSON schema that the request response must comply with.
     *
     * @param j Request response JSON schema
     * @param status Request response status code
     * @return This Endpoint for further modification
     */
    Endpoint& set_result_schema(
      const nlohmann::json& j,
      std::optional<http_status> status = std::nullopt);

    /** Sets the schema that the request and response bodies should comply
     * with. These are used to populate the generated OpenAPI document, but do
     * not introduce any constraints on the actual types that are parsed or
     * produced by the handling functor.
     *
     * \verbatim embed:rst:leading-asterisk
     * .. note::
     *  See ``DECLARE_JSON_`` serialisation macros for serialising
     *  user-defined data structures.
     * \endverbatim
     *
     * @tparam In Request body JSON-serialisable data structure
     * @tparam Out Response body JSON-serialisable data structure
     * @param status Response status code
     * @return This Endpoint for further modification
     */
    template <typename In, typename Out>
    Endpoint& set_auto_schema(std::optional<http_status> status = std::nullopt)
    {
      if constexpr (!std::is_same_v<In, void>)
      {
        params_schema = ds::json::build_schema<In>();

        schema_builders.push_back(
          [](nlohmann::json& document, const Endpoint& endpoint) {
            const auto http_verb = endpoint.dispatch.verb.get_http_method();
            if (!http_verb.has_value())
            {
              // Non-HTTP endpoints are not documented
              return;
            }

            ds::openapi::add_request_body_schema<In>(
              document, endpoint.full_uri_path, http_verb.value());
          });
      }
      else
      {
        params_schema = nullptr;
      }

      if constexpr (!std::is_same_v<Out, void>)
      {
        success_status = status.value_or(HTTP_STATUS_OK);

        result_schema = ds::json::build_schema<Out>();

        schema_builders.push_back(
          [](nlohmann::json& document, const Endpoint& endpoint) {
            const auto http_verb = endpoint.dispatch.verb.get_http_method();
            if (!http_verb.has_value())
            {
              return;
            }

            ds::openapi::add_response_schema<Out>(
              document,
              endpoint.full_uri_path,
              http_verb.value(),
              endpoint.success_status);
          });
      }
      else
      {
        success_status = status.value_or(HTTP_STATUS_NO_CONTENT);
        result_schema = nullptr;
      }

      return *this;
    }

    /** Sets schemas for request and response bodies using typedefs within T.
     * @see set_auto_schema
     *
     * \verbatim embed:rst:leading-asterisk
     * .. note::
     *   ``T`` data structure should contain two nested ``In`` and ``Out``
     *   structures for request parameters and response format, respectively.
     * \endverbatim
     *
     * @tparam T Type containing ``In`` and ``Out`` typedefs with JSON-schema
     * description specialisations
     * @param status Request response status code
     * @return This Endpoint for further modification
     */
    template <typename T>
    Endpoint& set_auto_schema(std::optional<http_status> status = std::nullopt)
    {
      return set_auto_schema<typename T::In, typename T::Out>(status);
    }

    /** Add OpenAPI documentation for a query parameter which can be passed to
     * this endpoint.
     *
     * @tparam T Type with appropriate ``ds::json`` specialisations to
     * generate a JSON schema description
     * @param param_name Name to be used for the query parameter to this
     * Endpoint
     * @param presence Enum value indicating whether this parameter is
     * required or optional
     * @return This Endpoint for further modification
     */
    template <typename T>
    Endpoint& add_query_parameter(
      const std::string& param_name,
      QueryParamPresence presence = RequiredParameter)
    {
      schema_builders.push_back(
        [param_name,
         presence](nlohmann::json& document, const Endpoint& endpoint) {
          const auto http_verb = endpoint.dispatch.verb.get_http_method();
          if (!http_verb.has_value())
          {
            // Non-HTTP endpoints are not documented
            return;
          }

          const auto schema_name = ds::json::schema_name<T>();
          const auto query_schema = ds::json::build_schema<T>();

          auto parameter = nlohmann::json::object();
          parameter["name"] = param_name;
          parameter["in"] = "query";
          parameter["required"] = presence == RequiredParameter;
          parameter["schema"] = ds::openapi::add_schema_to_components(
            document, schema_name, query_schema);
          ds::openapi::add_request_parameter_schema(
            document, endpoint.full_uri_path, http_verb.value(), parameter);
        });

      return *this;
    }

    /** Overrides whether a Endpoint is always forwarded, or whether it is
     * safe to sometimes execute on followers.
     *
     * @param fr Enum value with desired status
     * @return This Endpoint for further modification
     */
    Endpoint& set_forwarding_required(ForwardingRequired fr);

    /** Indicates that the execution of the Endpoint does not require
     * consensus from other nodes in the network.
     *
     * By default, endpoints are not executed locally.
     *
     * \verbatim embed:rst:leading-asterisk
     * .. warning::
     *  Use with caution. This should only be used for non-critical endpoints
     *  that do not read or mutate the state of the key-value store.
     * \endverbatim
     *
     * @param v Enum indicating whether the Endpoint is executed locally,
     * on the node receiving the request, locally on the primary or via the
     * consensus.
     * @return This Endpoint for further modification
     */
    Endpoint& set_execute_outside_consensus(ExecuteOutsideConsensus v);

    void install()
    {
      if (installer == nullptr)
      {
        LOG_FATAL_FMT(
          "Can't install this endpoint ({}) - it is not associated with an "
          "installer",
          full_uri_path);
      }
      else
      {
        installer->install(*this);
      }
    }
  };

  using EndpointPtr = std::shared_ptr<const Endpoint>;
}
