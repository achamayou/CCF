actions.set(
    "set_member",
    new Action(
      function (args) {
        checkX509CertBundle(args.cert, "cert");
        checkType(args.member_data, "object?", "member_data");
        // Also check that public encryption key is well formed, if it exists

        // Check if member exists
        // if not, check there is no enc pub key
        // if it does, check it doesn't have an enc pub key in ledger
      },

      function (args) {
        const memberId = ccf.pemToId(args.cert);
        const rawMemberId = ccf.strToBuf(memberId);

        ccf.kv["public:ccf.gov.members.certs"].set(
          rawMemberId,
          ccf.strToBuf(args.cert)
        );

        if (args.encryption_pub_key == null) {
          ccf.kv["public:ccf.gov.members.encryption_public_keys"].delete(
            rawMemberId
          );
        } else {
          ccf.kv["public:ccf.gov.members.encryption_public_keys"].set(
            rawMemberId,
            ccf.strToBuf(args.encryption_pub_key)
          );
        }

        let member_info = {};
        member_info.member_data = args.member_data;
        member_info.status = "Accepted";
        ccf.kv["public:ccf.gov.members.info"].set(
          rawMemberId,
          ccf.jsonCompatibleToBuf(member_info)
        );

        const rawSignature = ccf.kv["public:ccf.internal.signatures"].get(
          getSingletonKvKey()
        );
        if (rawSignature === undefined) {
          ccf.kv["public:ccf.gov.members.acks"].set(rawMemberId);
        } else {
          const signature = ccf.bufToJsonCompatible(rawSignature);
          const ack = {};
          ack.state_digest = signature.root;
          ccf.kv["public:ccf.gov.members.acks"].set(
            rawMemberId,
            ccf.jsonCompatibleToBuf(ack)
          );
        }
      }
    )
  );