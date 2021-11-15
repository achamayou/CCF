import http

def test_missing_signature_header(network):
    node = network.find_node_by_role()
    member = network.consortium.get_any_active_member()
    with node.client(member.local_id) as mc:
        r = mc.post("/gov/proposals")
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code
        www_auth = "www-authenticate"
        assert www_auth in r.headers, r.headers
        auth_header = r.headers[www_auth]
        assert auth_header.startswith("Signature"), auth_header
        elements = {
            e[0].strip(): e[1]
            for e in (element.split("=") for element in auth_header.split(","))
        }
        assert "headers" in elements, elements
        required_headers = elements["headers"]
        assert required_headers.startswith('"'), required_headers
        assert required_headers.endswith('"'), required_headers
        assert "(request-target)" in required_headers, required_headers
        assert "digest" in required_headers, required_headers
