#!/usr/bin/env bash

# SRCPATH is where the JSON files are
# This is the root CCF git repository
if [ "$SRCPATH" == "" ]; then
  if [ -f set_ca_cert_bundle.json ] && \
     [ -f vote_for.json ] && \
     [ -f set_jwt_issuer.json ]; then
    SRCPATH=.
  else
    echo "JSON files not found. Export SRCPATH"
    exit 1
  fi
else
  if [ ! -f set_ca_cert_bundle.json ] || \
     [ ! -f vote_for.json ] || \
     [ ! -f set_jwt_issuer.json ]; then
    echo "JSON files not found in '$SRCPATH'"
    exit 1
  fi
fi

# WORKPATH is where the keys are, after the network is running
# This is usually in the build directory workspace/sandbox_common
if [ "$1" != "" ]; then
  WORKPATH=$1
fi
if [ "$WORKPATH" == "" ]; then
  echo "Export WORKPATH or pass as first argument"
  exit 1
fi

# If you're using a sandbox, this is where the requests go
SERVER=https://127.0.0.1:8000
PROPOSAL_URL=$SERVER/gov/proposals
STATUS_URL=$SERVER/gov/jwt_keys/all

# Get Microsoft's keys
CERT=$(openssl s_client -showcerts -connect login.microsoftonline.com:443 < /dev/null 2>&1 | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' | sed ':a;N;$!ba;s/\n/\\n/g')

CERT="-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----"

# Replace new keys into existing bundle
cat set_ca_cert_bundle.json | jq ".actions[] |= (.args.cert_bundle=\"$CERT\")" > set_ca_cert_bundle_ms_key.json

# Check initial status
echo "============= Check initial cert status"
STATUS=$(curl $STATUS_URL -k -s)
echo "STATUS=$STATUS"

# Set new CA bundle
echo "============= Set CA bundle"
BUNDLE=$(scurl.sh $PROPOSAL_URL \
          --cacert $WORKPATH/service_cert.pem \
          --signing-cert $WORKPATH/member0_cert.pem \
          --signing-key $WORKPATH/member0_privk.pem \
          -s -X POST \
          --data-binary @set_ca_cert_bundle_ms_key.json)
PROPOSAL=$(echo $BUNDLE | jq '.proposal_id' | sed 's/"//g')
echo "PROPOSAL=$PROPOSAL"

# Vote for that proposal
echo "============= Vote for bundle"
VOTE=$(scurl.sh $PROPOSAL_URL/$PROPOSAL/ballots \
          --cacert $WORKPATH/service_cert.pem \
          --signing-cert $WORKPATH/member0_cert.pem \
          --signing-key $WORKPATH/member0_privk.pem \
          -s -X POST \
          --data-binary @vote_for.json)
echo "VOTE=$VOTE"

# Set the JWT issuer
echo "============= Set JWT Issuer"
ISSUER=$(scurl.sh $PROPOSAL_URL \
          --cacert $WORKPATH/service_cert.pem \
          --signing-cert $WORKPATH/member0_cert.pem \
          --signing-key $WORKPATH/member0_privk.pem \
          -s -X POST \
          --data-binary @set_jwt_issuer.json)
PROPOSAL=$(echo $ISSUER | jq '.proposal_id' | sed 's/"//g')
echo "PROPOSAL=$PROPOSAL"

# Vote for that proposal
echo "============= Vote for bundle"
VOTE=$(scurl.sh $PROPOSAL_URL/$PROPOSAL/ballots \
          --cacert $WORKPATH/service_cert.pem \
          --signing-cert $WORKPATH/member0_cert.pem \
          --signing-key $WORKPATH/member0_privk.pem \
          -s -X POST \
          --data-binary @vote_for.json)
echo "VOTE=$VOTE"

# Check if succeeded
echo "============= Check final cert status"
STATUS=$(curl $STATUS_URL -k -s)
echo "STATUS=$STATUS"
