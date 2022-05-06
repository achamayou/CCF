The OpenSSL TLS client is not able to verify the server cert presented by login.microsoftonline.com, which means automated JWT refresh doesn't work.

### Repro steps

Spin up a sandbox with a short JWT refresh interval:

```
../tests/sandbox/sandbox.sh -p libjs_generic --jwt-key-refresh-interval-s 5
```

Get your proposals and certs etc somewhere easily reachable:
```
cd workspace/sandbox_common/
cp ../../set_ca_cert_bundle.json ../../set_jwt_issuer.json ../../vote_for.json .
```

Submit 2 proposals, first to set the CA cert bundle, second to add an auto-refreshed JWT issuer. Need to vote for these, or fiddle with your constitution to accept them automatically. Hot-tip: once you've done this once, find it quickly again with `Ctrl-R: @set_ca`. NB: You need to manually replace the proposal ID for each vote.

```
$ scurl.sh https://127.0.0.1:8000/gov/proposals --cacert service_cert.pem --signing-cert member0_cert.pem --signing-key member0_privk.pem -X POST --data-binary @set_ca_cert_bundle.json
{"ballot_count":0,"proposal_id":"ed27ee2c78c2bc478a4ff63aca4fb372d6bdbeffabe91d2e77fb013bb839d604","proposer_id":"0c2d4c514623acad628c7417f75f7f6ca5764140fc46c3681ef7ac97ed0cf0f2","state":"Open"}

$ scurl.sh https://127.0.0.1:8000/gov/proposals/ed27ee2c78c2bc478a4ff63aca4fb372d6bdbeffabe91d2e77fb013bb839d604/ballots --cacert service_cert.pem --signing-cert member0_cert.pem --signing-key member0_privk.pem -X POST --data-binary @vote_for.json
{"ballot_count":1,"proposal_id":"ed27ee2c78c2bc478a4ff63aca4fb372d6bdbeffabe91d2e77fb013bb839d604","proposer_id":"0c2d4c514623acad628c7417f75f7f6ca5764140fc46c3681ef7ac97ed0cf0f2","state":"Accepted","votes":{"0c2d4c514623acad628c7417f75f7f6ca5764140fc46c3681ef7ac97ed0cf0f2":true}}

$ scurl.sh https://127.0.0.1:8000/gov/proposals --cacert service_cert.pem --signing-cert member0_cert.pem --signing-key member0_privk.pem -X POST --data-binary @set_jwt_issuer.json
{"ballot_count":0,"proposal_id":"3849db181fe03162c4f1c2eebed495fecd79666c5247e174b8cdec3b033939b2","proposer_id":"0c2d4c514623acad628c7417f75f7f6ca5764140fc46c3681ef7ac97ed0cf0f2","state":"Open"}

$ scurl.sh https://127.0.0.1:8000/gov/proposals/3849db181fe03162c4f1c2eebed495fecd79666c5247e174b8cdec3b033939b2/ballots --cacert service_cert.pem --signing-cert member0_cert.pem --signing-key member0_privk.pem -X POST --data-binary @vote_for.json
{"ballot_count":1,"proposal_id":"3849db181fe03162c4f1c2eebed495fecd79666c5247e174b8cdec3b033939b2","proposer_id":"0c2d4c514623acad628c7417f75f7f6ca5764140fc46c3681ef7ac97ed0cf0f2","state":"Accepted","votes":{"0c2d4c514623acad628c7417f75f7f6ca5764140fc46c3681ef7ac97ed0cf0f2":true}}
```

Then check if it succeeded with `curl https://127.0.0.1:8000/gov/jwt_keys/all -k`. Note that as I write this, this will succeed because I've hacked the code to continue the TLS connection despite the verification failing. If you get an empty body, the JWT keys haven't been auto-refreshed. The e2e test should do the above steps, and then poll this endpoint until it contains some plausible keys.

There's also some debug spam for this auth process in the logs:
```
2022-05-06T09:08:44.526493Z -0.001 0   [info ] /src/node/jwt_key_auto_refresh.h:291 | JWT key auto-refresh: Refreshing keys for issuer 'https://login.microsoftonline.com/common/v2.0'
2022-05-06T09:08:44.526540Z -0.001 0   [info ] /src/node/jwt_key_auto_refresh.h:319 | JWT key auto-refresh: Requesting OpenID metadata at https://login.microsoftonline.com:443/common/v2.0/.well-known/openid-configuration
2022-05-06T09:08:44.526546Z -0.001 0   [info ] ../src/tls/cert.h:58                 | Cert::use()
2022-05-06T09:08:44.526550Z -0.001 0   [info ] ../src/tls/cert.h:67                 | We have a peer ca, using it
2022-05-06T09:08:44.526554Z -0.001 0   [info ] ../src/tls/cert.h:73                 | Auth required
2022-05-06T09:08:44.526562Z        100 [debug] ../src/host/rpc_connections.h:235    | rpc connect request from enclave -31 (to login.microsoftonline.com:443)
2022-05-06T09:08:44.526597Z -0.001 0   [info ] ./src/node/jwt_key_auto_refresh.h:69 | JWT key auto-refresh: Scheduling in 5s
2022-05-06T09:08:44.526607Z        100 [debug] ../src/host/rpc_connections.h:225    | rpc write from enclave -31: 364
2022-05-06T09:08:44.529076Z        100 [debug] ../src/host/tcp.h:534                | Reached connect_resolved
2022-05-06T09:08:44.529113Z        100 [debug] ../src/host/tcp.h:551                | CONNECTING, working out resolved address
2022-05-06T09:08:44.529123Z        100 [info ] ../src/host/tcp.h:589                | Connecting to: 20.190.154.136
2022-05-06T09:08:44.593912Z        100 [debug] ../src/host/tcp.h:771                | CONNECTED
2022-05-06T09:08:44.593946Z        100 [debug] ../src/host/tcp.h:780                | Sending pending write of 364 bytes
2022-05-06T09:08:44.656716Z        100 [debug] ../src/host/rpc_connections.h:40     | rpc read -31: 3741
-----BEGIN CERTIFICATE-----
MIIE6DCCA9CgAwIBAgIQAnQuqhfKjiHHF7sf/P0MoDANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0yMDA5MjMwMDAwMDBaFw0zMDA5MjIyMzU5NTlaME0xCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg
U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83
nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd
KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f
/ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX
kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0
/RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAa4wggGqMB0GA1UdDgQWBBQPgGEcgjFh
1S8o541GOLQs4cbZ4jAfBgNVHSMEGDAWgBQD3lA1VtFMu2bwo+IbG8OXsj3RVTAO
BgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIG
A1UdEwEB/wQIMAYBAf8CAQAwdgYIKwYBBQUHAQEEajBoMCQGCCsGAQUFBzABhhho
dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKGNGh0dHA6Ly9jYWNl
cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcnQwewYDVR0f
BHQwcjA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xv
YmFsUm9vdENBLmNybDA3oDWgM4YxaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0Rp
Z2lDZXJ0R2xvYmFsUm9vdENBLmNybDAwBgNVHSAEKTAnMAcGBWeBDAEBMAgGBmeB
DAECATAIBgZngQwBAgIwCAYGZ4EMAQIDMA0GCSqGSIb3DQEBCwUAA4IBAQB3MR8I
l9cSm2PSEWUIpvZlubj6kgPLoX7hyA2MPrQbkb4CCF6fWXF7Ef3gwOOPWdegUqHQ
S1TSSJZI73fpKQbLQxCgLzwWji3+HlU87MOY7hgNI+gH9bMtxKtXc1r2G1O6+x/6
vYzTUVEgR17vf5irF0LKhVyfIjc0RXbyQ14AniKDrN+v0ebHExfppGlkTIBn6rak
f4994VH6npdn6mkus5CkHBXIrMtPKex6XF2firjUDLuU7tC8y7WlHgjPxEEDDb0G
w6D0yDdVSvG/5XlCNatBmO/8EznDu1vr72N8gJzISUZwa6CCUD7QBLbKJcXBBVVf
8nwvV9GvlW+sbXlr
-----END CERTIFICATE-----
2022-05-06T09:08:44.657809Z -0.001 0   [info ] ../src/tls/cert.h:76                 | peer certificate verified: 0
2022-05-06T09:08:44.657826Z -0.001 0   [fail ] ../src/tls/cert.h:86                 | Pre-verify failed (20) at depth 1: unable to get local issuer certificate
```

Note that the certificate is printed out-of-order, because that's coming from `PEM_write_X509(stdout, err_cert)` (ie - a direct write to stdout, rather than ringbuffer'd, so it overtakes other enclave logging).

### How do we construct the CA cert?

Fetch the server's presented cert chain with `openssl s_client -showcerts -connect login.microsoftonline.com:443`. Extract the actual certs by sed or by hand. Put that in `set_ca_cert_bundle.json`. I believe I've tried every variation of the certs in this chain (just the root, just the intermediate, flipping the order), but this has been scattered over several days so maybe I missed something here.

### TODO
- Confirm this works on 1.x. We believe this is introduced by the OpenSSL migration, so we should confirm that this auto-refresh worked on 1.x, and check exactly what cert chain mbedTLS wanted.
- Add an e2e test. Probably need to fetch the CA cert chain in Python, then submit both proposals then poll `/jwt_keys/all`.
- Build a simpler repo. Can we build a unit test that uses these classes and see if it's able to connect, or at least see the same error faster?