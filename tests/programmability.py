# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.checker
import infra.jwt_issuer
import infra.proc
import http
from infra.runner import ConcurrentRunner
from governance_js import action, proposal, ballot_yes


TESTJS = """
export function content(request) {
    return {
        statusCode: 200,
        body: {
        payload: "Test content",
        },
    };
}
"""

TESTJS_ROLE = """
export function content(request) {
  let raw_id = ccf.strToBuf(request.caller.id);
  let user_info = ccf.kv["public:ccf.gov.users.info"].get(raw_id);
  if (user_info !== undefined) {
    user_info = ccf.bufToJsonCompatible(user_info);
    let roles = user_info?.user_data?.roles || [];

    for (const [_, role] of roles.entries()) {
        let role_map = ccf.kv[`public:ccf.gov.roles.${role}`];
        let endpoint_name = request.url.split("/")[2];
        if (role_map?.has(ccf.strToBuf(`/${endpoint_name}/read`)))
        {
            return {
                statusCode: 200,
                body: {
                    payload: "Test content",
                },
            };
        }
    }
  }

  return {
    statusCode: 403
  };
}
"""


def test_custom_endpoints(network, args):
    primary, _ = network.find_primary()

    # Make user0 admin, so it can install custom endpoints
    user = network.users[0]
    network.consortium.set_user_data(
        primary, user.service_id, user_data={"isAdmin": True}
    )

    content_endpoint_def = {
        "get": {
            "js_module": "test.js",
            "js_function": "content",
            "forwarding_required": "never",
            "redirection_strategy": "none",
            "authn_policies": ["no_auth"],
            "mode": "readonly",
            "openapi": {},
        }
    }

    bundle_with_content = {
        "metadata": {"endpoints": {"/content": content_endpoint_def}},
        "modules": {"test.js": TESTJS},
    }

    bundle_with_other_content = {
        "metadata": {"endpoints": {"/other_content": content_endpoint_def}},
        "modules": {"test.js": TESTJS},
    }

    with primary.client(None, None, user.local_id) as c:
        r = c.put("/app/custom_endpoints", body={"bundle": bundle_with_content})
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    with primary.client() as c:
        r = c.get("/app/not_content")
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code

        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

    with primary.client(None, None, user.local_id) as c:
        r = c.put("/app/custom_endpoints", body={"bundle": bundle_with_other_content})
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    with primary.client() as c:
        r = c.get("/app/other_content")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code

    return network


def test_custom_role_definitions(network, args):
    primary, _ = network.find_primary()
    member = network.consortium.get_any_active_member()

    # Assign a role to user0
    user = network.users[0]
    network.consortium.set_user_data(
        primary,
        user.service_id,
        user_data={"isAdmin": True, "roles": ["ContentGetter"]},
    )

    content_endpoint_def = {
        "get": {
            "js_module": "test.js",
            "js_function": "content",
            "forwarding_required": "never",
            "redirection_strategy": "none",
            "authn_policies": ["user_cert"],
            "mode": "readonly",
            "openapi": {},
        }
    }

    bundle_with_auth = {
        "metadata": {"endpoints": {"/content": content_endpoint_def}},
        "modules": {"test.js": TESTJS_ROLE},
    }

    # Install app with auth/role support
    with primary.client(None, None, user.local_id) as c:
        r = c.put("/app/custom_endpoints", body={"bundle": bundle_with_auth})
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    # Add role definition
    prop = member.propose(
        primary,
        proposal(
            action(
                "set_role_definition", role="ContentGetter", actions=["/content/read"]
            )
        ),
    )
    member.vote(primary, prop, ballot_yes)

    # user0 has "ContentGetter" role, which has "/content/read" should be able to access "/content"
    with primary.client("user0") as c:
        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

    # But user1 does not
    with primary.client("user1") as c:
        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.FORBIDDEN, r.status_code

    # And unauthenticated users definitely don't
    with primary.client() as c:
        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code

    # Delete role definition
    prop = member.propose(
        primary,
        proposal(action("set_role_definition", role="ContentGetter", actions=[])),
    )
    member.vote(primary, prop, ballot_yes)

    # Now user0 can't access /content anymore
    with primary.client("user0") as c:
        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.FORBIDDEN, r.status_code

    # Multiple definitions
    prop = member.propose(
        primary,
        proposal(
            action(
                "set_role_definition", role="ContentGetter", actions=["/content/read"]
            ),
            action(
                "set_role_definition",
                role="AllContentGetter",
                actions=["/content/read", "/other_content/read"],
            ),
        ),
    )
    member.vote(primary, prop, ballot_yes)

    bundle_with_auth_both = {
        "metadata": {
            "endpoints": {
                "/content": content_endpoint_def,
                "/other_content": content_endpoint_def,
            }
        },
        "modules": {"test.js": TESTJS_ROLE},
    }

    # Install two endpoints with role auth
    with primary.client(None, None, user.local_id) as c:
        r = c.put("/app/custom_endpoints", body={"bundle": bundle_with_auth_both})
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    # Assign the new role to user0
    user = network.users[0]
    network.consortium.set_user_data(
        primary,
        user.service_id,
        user_data={"isAdmin": True, "roles": ["ContentGetter", "AllContentGetter"]},
    )

    # user0 has access both now
    with primary.client("user0") as c:
        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()
        r = c.get("/app/other_content")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

    return network


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)
        test_custom_endpoints(network, args)
        test_custom_role_definitions(network, args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "basic",
        run,
        package="samples/apps/basic/libbasic",
        js_app_bundle=None,
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        initial_user_count=2,
        initial_member_count=1,
    )

    cr.run()
