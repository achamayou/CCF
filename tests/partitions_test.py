# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import contextlib
import copy
import http
import os
import pprint
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import ccf.ledger
import infra.e2e_args
import infra.interfaces
import infra.logging_app as app
import infra.net
import infra.network
import infra.partitions
import suite.test_requirements as reqs
from ccf.tx_id import TxID
from e2e_logging import verify_receipt
from infra.checker import check_can_progress, check_does_not_progress
from infra.log_capture import flush_info
from infra.tx_status import TxStatus
from loguru import logger as LOG
from reconfiguration import test_ledger_invariants

# Arbitrary high record id, chosen to avoid clashing with ids used by other
# tests sharing the same network/ledger.
UNCOMMITTABLE_RECORD_ID_START = 420000
COMMITTED_RECORD_ID = UNCOMMITTABLE_RECORD_ID_START - 1
# Each uncommittable record repeats the test message this many times, so that
# a handful of records comfortably exceed the small chunk size below and
# reliably force a new ledger chunk to be written to disk while isolated.
UNCOMMITTABLE_MESSAGE_REPEAT = 1024
# Small chunk size so that the writes made while the primary is isolated are
# guaranteed to roll over into new (uncommitted) ledger chunks quickly.
UNCOMMITTABLE_TEST_LEDGER_CHUNK_BYTES = "16KB"


@reqs.description("Invalid partitions are not allowed")
def test_invalid_partitions(network, args):
    nodes = network.get_joined_nodes()

    try:
        network.partitioner.partition(
            [nodes[0], nodes[2]],
            [nodes[1], nodes[2]],
        )
        assert False, "Node should not appear in two or more partitions"
    except ValueError:
        pass

    try:
        network.partitioner.partition()
        assert False, "At least one partition should be specified"
    except ValueError:
        pass

    invalid_local_node_id = -1
    new_node = infra.node.Node(
        invalid_local_node_id, infra.interfaces.HostSpec().with_args(args)
    )
    try:
        network.partitioner.partition([new_node])
        assert False, "All nodes should belong to network"
    except ValueError:
        pass

    return network


@reqs.description("Partition primary + f nodes")
def test_partition_majority(network, args):
    primary, backups = network.find_nodes()

    # Create a partition with primary + half remaining nodes (i.e. majority)
    partition = [primary]
    partition.extend(backups[len(backups) // 2 :])

    # Wait for all nodes to be have reached the same level of commit, so that
    # nodes outside of partition can become primary after this one is dropped
    network.wait_for_all_nodes_to_commit(primary=primary)

    # The primary should remain stable while the partition is active
    # Note: Context manager
    initial_view = None
    with network.partitioner.partition(partition):
        try:
            network.wait_for_new_primary(
                primary,
                timeout_multiplier=3,
            )
            assert False, "No new primary should be elected when partitioning majority"
        except TimeoutError:
            LOG.info("No new primary, as expected")
            with primary.client() as c:
                res = c.get("/node/network")  # Well-known read-only endpoint
                body = res.body.json()
                initial_view = body["current_view"]

    # The partitioned nodes will have called elections, but due to not having a majority, will be unable to increase their view.
    # When the partition is lifted, this may cause a new election.
    network.wait_for_primary_unanimity(min_view=initial_view)

    return network


@reqs.description("Isolate primary from one backup")
@reqs.exactly_n_nodes(3)
def test_isolate_primary_from_one_backup(network, args):
    p, backups = network.find_nodes()
    b_0, _b_1 = backups

    # Issue one transaction, waiting for all nodes to be have reached
    # the same level of commit, so that nodes outside of partition can
    # become primary after this one is dropped
    # Note: Because of https://github.com/microsoft/CCF/issues/2224, we need to
    # issue a write transaction instead of just reading the TxID of the latest entry
    initial_txid = network.txs.issue(network, send_private=False)

    # Isolate first backup from primary so that first backup becomes candidate
    # in a new term and wins the election
    # Note: Managed manually
    rules = network.partitioner.isolate_node(p, b_0)

    # This is what we expect to happen:
    # - b_0 first times out and calls an election
    # - As it is up to date with b_1, it will win that election,
    #   and after being elected emit a signature.
    # - p will then step down via CheckQuorum
    # - p will then try to call multiple elections but at most become a PreVoteCandidate,
    #   and not disrupt the cluster, as it cannot pass pre-vote due to missing the signature
    #   from b_0's leadership election

    LOG.info(
        f"Check that primary {p.local_node_id} reports increasing last ack time for partitioned backup {b_0.local_node_id} and the partitioned backup's election timeout also increases"
    )

    last_ack = 0
    timeout = time.time() + 2 * network.args.election_timeout_ms / 1000
    while True:
        with p.client() as c:
            r = c.get("/node/consensus", log_capture=[]).body.json()["details"]
            ack = r["acks"][b_0.node_id]["last_received_ms"]
            has_stepped_down = r["leadership_state"] in {"Follower", "PreVoteCandidate"}
            if not has_stepped_down:
                assert (
                    ack >= last_ack
                ), f"Nodes {p.local_node_id} and {b_0.local_node_id} are no longer partitioned"
                last_ack = ack
        with b_0.client() as c:
            r = c.get("/node/consensus", log_capture=[]).body.json()["details"]
            if r["leadership_state"] == "Leader":
                LOG.info(
                    f"Backup {b_0.local_node_id} has become primary in new view {r['current_view']}"
                )
                new_view = r["current_view"]
                break
        if time.time() > timeout:
            raise RuntimeError(
                f"Backup {b_0.local_node_id} did not become primary within timeout"
            )

        time.sleep(0.1)

    p.wait_for_leadership_state(
        initial_txid.view,
        ["Follower", "PreVoteCandidate"],
        timeout=4 * network.args.election_timeout_ms / 1000,
    )

    # Verify that b_0 is stably the primary, and that p is a Follower/PreVoteCandidate
    timeout = time.time() + 2 * network.args.election_timeout_ms / 1000
    while time.time() < timeout:
        with b_0.client() as c:
            r = c.get("/node/consensus", log_capture=[]).body.json()["details"]
            assert (
                r["leadership_state"] == "Leader" and r["current_view"] == new_view
            ), f"Backup {b_0.local_node_id} is no longer primary for {new_view}"
        with p.client() as c:
            r = c.get("/node/consensus", log_capture=[]).body.json()["details"]
            assert r["leadership_state"] in {
                "Follower",
                "PreVoteCandidate",
            }, f"Primary {p.local_node_id} is no longer follower"
        time.sleep(0.1)

    # Explicitly drop rules before continuing
    rules.drop()

    # primary should now observe partitioned backup as primary
    network.wait_for_new_primary_in({b_0}, nodes=[p])

    LOG.info(f"Check that new primary {b_0.local_node_id} reports stable acks")
    last_ack = 0
    end_time = time.time() + 2 * network.args.election_timeout_ms // 1000
    while time.time() < end_time:
        with b_0.client() as c:
            acks = c.get("/node/consensus", log_capture=[]).body.json()["details"][
                "acks"
            ]
            delayed_acks = [
                ack
                for ack in acks.values()
                if ack["last_received_ms"] > args.election_timeout_ms
            ]
            if delayed_acks:
                raise RuntimeError(f"New primary reported some delayed acks: {acks}")
        time.sleep(0.1)

    return network


@reqs.description("Isolate and reconnect primary")
def test_isolate_and_reconnect_primary(network, args, **kwargs):
    primary, backups = network.find_nodes()

    with primary.client() as c:
        primary_view = c.get("/node/consensus").body.json()["details"]["current_view"]

    with network.partitioner.partition(backups):
        lost_tx_resp = check_does_not_progress(primary)

        new_primary, _ = network.wait_for_new_primary(primary, nodes=backups)
        new_tx_resp = check_can_progress(new_primary)

        # CheckQuorum: the primary node should automatically step
        # down if it has not heard back from a majority of backups.
        # However, it is not guaranteed that the transient follower state
        # will be observed, so wait for candidate state instead.
        # The isolated primary will stay in follower state once Pre-Vote
        # is implemented. https://github.com/microsoft/CCF/issues/2577
        primary.wait_for_leadership_state(
            # We want view >= primary_view, but comparison is > so subtract 1
            primary_view - 1,
            ["Follower", "PreVoteCandidate"],
            timeout=2 * args.election_timeout_ms / 1000,
        )

    # Check reconnected former primary has caught up
    with primary.client() as c:
        try:
            # There will be at least one full election cycle for nothing, where the
            # re-joining node fails to get elected but causes others to rev up their
            # term. After that, a successful election needs to take place, and we
            # arbitrarily allow 3 time periods to avoid being too brittle when
            # raft timeouts line up badly.
            c.wait_for_commit(new_tx_resp, timeout=(network.election_duration * 4))
        except TimeoutError:
            details = c.get("/node/consensus").body.json()
            assert (
                False
            ), f"Stuck before {new_tx_resp.view}.{new_tx_resp.seqno}: {pprint.pformat(details)}"

        # Check it has dropped anything submitted while partitioned
        r = c.get(f"/node/tx?transaction_id={lost_tx_resp.view}.{lost_tx_resp.seqno}")
        status = TxStatus(r.body.json()["status"])
        assert status == TxStatus.Invalid, r


@reqs.description("New joiner helps liveness")
@reqs.exactly_n_nodes(3)
def test_new_joiner_helps_liveness(network, args):
    primary, backups = network.find_nodes()

    # Issue some transactions, so there is a ledger history that a new node must receive
    network.txs.issue(network, number_txs=10, send_private=False)

    # Remove a node, leaving the network frail
    network.retire_node(primary, backups[-1])
    backups[-1].stop()

    primary, backups = network.find_nodes()

    with contextlib.ExitStack() as stack:
        # Add a new node, but partition them before trusting them
        new_node = network.create_node()
        network.join_node(
            new_node,
            args.package,
            args,
            from_snapshot=False,
            fetch_recent_snapshot=True,
        )
        new_joiner_partition = [new_node]
        new_joiner_rules = stack.enter_context(
            network.partitioner.partition([primary, *backups], new_joiner_partition)
        )

        # Trust the new node, and wait for commit of this (but don't ask the new node itself, which doesn't know this yet)
        network.trust_node(new_node, args, no_wait=True)
        check_can_progress(primary)

        # Partition the primary, temporarily creating a minority service that cannot make progress
        minority_partition = backups[len(backups) // 2 :] + new_joiner_partition
        minority_rules = stack.enter_context(
            network.partitioner.partition(minority_partition)
        )
        # This is an unusual situation, where we've actually produced a dead partitioned node.
        # Initially any write requests will timeout (failed attempt at forwarding), and then
        # the node transitions to a candidate with nobody to talk to. Rather than trying to
        # catch the errors of these states quickly, we just sleep until the latter state is
        # reached, and then confirm it was reached.
        time.sleep(network.observed_election_duration)
        with backups[0].client("user0") as c:
            r = c.post("/app/log/public", {"id": 42, "msg": "Hello world"})
            assert r.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE

        # Restore the new node to the service
        new_joiner_rules.drop()

        # Confirm that the new node catches up, and progress can be made in this majority partition
        network.wait_for_new_primary(primary, minority_partition)
        check_can_progress(new_node)

        # Explicitly drop rules before continuing
        minority_rules.drop()

        network.wait_for_primary_unanimity()
        primary, _ = network.find_nodes()
        network.wait_for_all_nodes_to_commit(primary=primary)


@reqs.description("Test node-to-node channel behaviour once certs have expired")
@reqs.exactly_n_nodes(3)
def test_expired_certs(network, args):
    primary, (backup_a, backup_b) = network.find_nodes()

    def set_certs(from_days_diff, validity_period_days, nodes):
        valid_from = str(
            infra.crypto.datetime_to_X509time(
                datetime.now(timezone.utc) + timedelta(days=from_days_diff)
            )
        )
        for node in nodes:
            network.consortium.set_node_certificate_validity(
                primary,
                node,
                valid_from=valid_from,
                validity_period_days=validity_period_days,
            )
            node.set_certificate_validity_period(
                valid_from,
                validity_period_days,
            )
            # Wait for this node to receive this updated cert, and start advertising it
            timeout = 2
            end_time = time.time() + timeout
            while True:
                try:
                    node.verify_certificate_validity_period()
                    LOG.info("Successfully updated cert")
                    break
                except ValueError as ve:
                    LOG.warning(f"Cert is still old value: {ve}")
                    assert (
                        time.time() < end_time
                    ), f"Cert has not been updated after {timeout}s"
                    time.sleep(0.2)

    # Expired cert is only an issue on channel creation.
    # Force channel creation by partitioning to cause controlled election.
    with contextlib.ExitStack() as stack:
        # Partition backup_b from others
        with network.partitioner.partition([backup_b]):
            # Advance state, committed by presence on primary and backup_a
            with primary.client("user0") as c:
                r = c.post("/app/log/public", {"id": 42, "msg": "hello world"})
                assert r.status_code == http.HTTPStatus.OK, r
                c.wait_for_commit(r)

            # Expire the certs of primary and backup_a - these are the only viable
            # candidates due to the newly committed suffix
            # NB: Once we start doing this, speaking to these nodes is tricky, because
            # client auth will also fail => disable ca verification
            primary.verify_ca_by_default = False
            backup_a.verify_ca_by_default = False
            set_certs(
                from_days_diff=-30, validity_period_days=7, nodes=(primary, backup_a)
            )

            # Partition primary, so that backup_a is only viable candidate, and must try
            # to create channels to backup_b
            stack.enter_context(network.partitioner.partition([primary]))

        # Restore connectivity between backups and wait for election
        network.wait_for_primary_unanimity(
            nodes=[backup_a, backup_b], min_view=r.view + 1
        )

        # Should now be able to make progress
        check_can_progress(backup_a)

    # Restore connectivity with primary, an election may or may not happen
    network.wait_for_primary_unanimity(min_view=r.view + 1)

    # Dropped partition, and even primary unanimity, do not mean node connectivity has been instantaneously restored.
    # Sleep through potential delays in reconnection.
    time.sleep(3)

    # Set valid node certs so that future clients can speak to these nodes
    set_certs(from_days_diff=-1, validity_period_days=7, nodes=(primary, backup_a))

    # Can now speak to these again
    primary.verify_ca_by_default = True
    backup_a.verify_ca_by_default = True

    return network


@reqs.description("A node can use a rolled-back certificate renewal")
@reqs.exactly_n_nodes(3)
def test_rolled_back_node_certificate(network, args):
    renewed_node, backups = network.find_nodes()
    network.wait_for_all_nodes_to_commit(primary=renewed_node)

    def get_stored_certificate(remote_node):
        with remote_node.api_versioned_client(api_version=args.gov_api_version) as c:
            r = c.get(f"/gov/service/nodes/{renewed_node.node_id}")
            assert r.status_code == http.HTTPStatus.OK, r
            return r.body.json()["certificate"]

    original_cert = get_stored_certificate(renewed_node)

    LOG.info("Renew the primary's certificate while it is isolated")
    with network.partitioner.partition(
        [renewed_node], name="isolate primary during certificate renewal"
    ):
        renewal = network.consortium.set_node_certificate_validity(
            renewed_node,
            renewed_node,
            valid_from=str(
                infra.crypto.datetime_to_X509time(
                    datetime.now(timezone.utc) - timedelta(days=1)
                )
            ),
            validity_period_days=args.maximum_node_certificate_validity_days - 1,
            wait_for_commit=False,
        )

        uncommitted_cert = get_stored_certificate(renewed_node)
        assert uncommitted_cert != original_cert
        assert (
            infra.crypto.compute_public_key_der_hash_hex_from_pem(uncommitted_cert)
            == renewed_node.node_id
        )

        new_primary, _ = network.wait_for_new_primary(renewed_node, nodes=backups)
        rollback_tx = check_can_progress(new_primary)

    LOG.info("Confirm the certificate renewal was rolled back")
    new_primary = network.wait_for_primary_unanimity(nodes=backups)
    with renewed_node.client() as c:
        c.wait_for_commit(
            rollback_tx,
            timeout=network.election_duration * 4,
        )
    network.wait_for_node_commit_sync()
    assert get_stored_certificate(renewed_node) == original_cert

    with new_primary.client() as c:
        r = c.get(
            f"/node/tx?transaction_id="
            f"{renewal.completed_view}.{renewal.completed_seqno}"
        )
        assert TxStatus(r.body.json()["status"]) == TxStatus.Invalid, r

    LOG.info("Confirm the re-elected node can use the rolled-back certificate")
    force_become_primary(network, args, renewed_node)
    with renewed_node.client("user0") as c:
        r = c.post(
            "/app/log/public",
            {"id": 7059, "msg": "Signed after certificate renewal rollback"},
        )
        assert r.status_code == http.HTTPStatus.OK, r
        c.wait_for_commit(r)

    receipt = renewed_node.get_receipt(
        view=r.view,
        seqno=r.seqno,
    ).json()
    assert receipt["node_id"] == renewed_node.node_id
    assert receipt["cert"] == uncommitted_cert
    verify_receipt(receipt, network.cert)

    return network


@reqs.description("Test election while reconfiguration is in flight")
@reqs.at_least_n_nodes(3)
def test_election_reconfiguration(network, args):
    # Test for issue described in https://github.com/microsoft/CCF/issues/3948
    # Note: this test makes use of node-endorsed secondary RPC interface since
    # new nodes never observe commit of their configuration and thus never
    # open their service-endorsed primary RPC interface.
    primary, backups = network.find_nodes()

    LOG.info("Join new nodes without trusting them just yet")
    new_nodes = []
    # Start N+1 new nodes to make sure they cannot elect one of them as a primary
    # without approval from the original configuration
    for _ in range(len(network.nodes) + 1):
        rpc_interfaces = {
            infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                host="localhost"
            )
        }
        rpc_interfaces.update(infra.interfaces.make_secondary_interface())
        new_node = network.create_node(infra.interfaces.HostSpec(rpc_interfaces))
        network.join_node(new_node, args.package, args, from_snapshot=False)
        new_nodes.append(new_node)

    # Wait until all backups know about these joins, so they have an equal chance of
    # becoming primary afterwards
    network.wait_for_node_commit_sync()

    LOG.info("Isolate original backups and issue reconfiguration of another quorum")
    # Partition backups _from each other_
    with network.partitioner.partitions([backup] for backup in backups):
        LOG.info("Trust all new nodes in one single proposal")
        # Note: Commit is stuck since a majority of backups in initial configuration
        # are isolated
        network.consortium.trust_nodes(
            primary,
            [n.node_id for n in new_nodes],
            valid_from=datetime.now(timezone.utc),
            wait_for_commit=False,
        )

        for node in new_nodes:
            node.wait_for_node_to_join(
                interface_name=infra.interfaces.SECONDARY_RPC_INTERFACE
            )
            # Wait for configuration tx to be replicated to new node
            network.wait_for_node_in_store(
                node,
                node.node_id,
                ccf.ledger.NodeStatus.TRUSTED,
                interface_name=infra.interfaces.SECONDARY_RPC_INTERFACE,
            )

        LOG.info(f"Stop primary node {primary.local_node_id} to trigger election")
        primary.stop()

        LOG.info(
            "Make sure that new nodes cannot elect a primary node among themselves"
        )
        try:
            network.wait_for_new_primary(
                primary,
                nodes=new_nodes,
                interface_name=infra.interfaces.SECONDARY_RPC_INTERFACE,
                timeout_multiplier=3,
            )
        except infra.network.PrimaryNotFound:
            LOG.info(
                "As expected, new primary could not be elected as old configuration could not make progress"
            )
        else:
            assert False, "No new primary should be elected while partition is up"

        LOG.info("Stop all new nodes")
        for node in new_nodes:
            node.stop()

    LOG.info(
        "As partition is lifted, check that isolated original backups elect primary"
    )
    network.wait_for_primary_unanimity(nodes=backups)

    LOG.info("Retire former primary and add new node")
    network.retire_node(backups[0], primary)
    new_node = network.create_node()
    network.join_node(new_node, args.package, args, from_snapshot=False)
    network.trust_node(new_node, args)

    return network


@reqs.description("Join rollback after primary isolation")
@reqs.exactly_n_nodes(3)
def test_join_rollback_on_primary_isolation(network, args):
    primary, backups = network.find_nodes()
    network.wait_for_all_nodes_to_commit(primary=primary)

    LOG.info("Join a pending node on an isolated primary")
    with network.partitioner.partition([primary], name="isolate primary during join"):
        pending_node = network.create_node()
        network.setup_join_node(
            pending_node,
            args.package,
            args,
            target_node=primary,
            from_snapshot=False,
        )
        pending_node.complete_join()
        # This deliberately checks the isolated primary's local state: the
        # pending join has been accepted there, but cannot be committed and must
        # be rolled back once the backups elect a new primary.
        network.wait_for_node_in_store(
            primary, pending_node.node_id, ccf.ledger.NodeStatus.PENDING
        )

        network.wait_for_new_primary(primary, nodes=backups)

    LOG.info("Check the pending join is retried after rollback")
    primary = network.wait_for_primary_unanimity(nodes=backups)
    network.wait_for_node_in_store(
        primary,
        pending_node.node_id,
        ccf.ledger.NodeStatus.PENDING,
        timeout=args.ledger_recovery_timeout,
    )
    valid_from = datetime.now(timezone.utc)
    network.consortium.trust_node(
        primary,
        pending_node.node_id,
        valid_from=valid_from,
        timeout=args.ledger_recovery_timeout,
    )
    pending_node.wait_for_node_to_join(timeout=args.ledger_recovery_timeout)
    pending_node.set_certificate_validity_period(
        valid_from, args.maximum_node_certificate_validity_days
    )
    network.wait_for_all_nodes_to_commit(primary=primary)
    check_can_progress(primary)

    LOG.info("Trust a pending node on an isolated primary")
    primary, backups = network.find_nodes()
    host_spec = infra.interfaces.HostSpec()
    host_spec.rpc_interfaces.update(infra.interfaces.make_secondary_interface())
    trusted_node = network.create_node(host_spec)
    network.join_node(
        trusted_node,
        args.package,
        args,
        target_node=primary,
        from_snapshot=False,
    )
    network.wait_for_all_nodes_to_commit(primary=primary)

    with network.partitioner.partition(
        [primary, trusted_node], name="isolate primary and joiner during trust"
    ):
        network.consortium.trust_node(
            primary,
            trusted_node.node_id,
            valid_from=datetime.now(timezone.utc),
            wait_for_commit=False,
        )
        trusted_node.wait_for_node_to_join(
            interface_name=infra.interfaces.SECONDARY_RPC_INTERFACE,
            timeout=args.ledger_recovery_timeout,
        )
        # This deliberately checks the isolated primary's local state: the
        # trusted transition has been observed by the joiner, but cannot be
        # committed and must be rolled back once the backups elect a new primary.
        network.wait_for_node_in_store(
            primary, trusted_node.node_id, ccf.ledger.NodeStatus.TRUSTED
        )

        network.wait_for_new_primary(primary, nodes=backups)

    LOG.info("Check the trusted transition is rolled back and can be retried")
    primary = network.wait_for_primary_unanimity(nodes=backups)
    network.wait_for_node_in_store(
        primary,
        trusted_node.node_id,
        ccf.ledger.NodeStatus.PENDING,
        timeout=args.ledger_recovery_timeout,
    )
    valid_from = datetime.now(timezone.utc)
    network.consortium.trust_node(
        primary,
        trusted_node.node_id,
        valid_from=valid_from,
        timeout=args.ledger_recovery_timeout,
    )
    trusted_node.wait_for_node_to_join(timeout=args.ledger_recovery_timeout)
    trusted_node.set_certificate_validity_period(
        valid_from, args.maximum_node_certificate_validity_days
    )
    network.wait_for_all_nodes_to_commit(primary=primary)
    check_can_progress(primary)

    return network


@reqs.description("Forwarding across a partition may trigger a timeout")
@reqs.at_least_n_nodes(3)
def test_forwarding_timeout(network, args):
    primary, backups = network.find_nodes()
    backup = backups[0]
    key = 42
    val_a = "Hello"
    val_b = "Goodbye"

    with backup.client("user0") as c:
        LOG.info("Initial write request is forwarded and succeeds")
        r = c.post("/app/log/public", {"id": key, "msg": val_a})
        assert r.status_code == http.HTTPStatus.OK

        network.wait_for_all_nodes_to_commit(primary=primary)

    LOG.info("Cross-partition write request is forwarded and times out")
    with network.partitioner.partition(backups):
        with backup.client("user0") as c:
            # NB: Only fails if request happens soon after partition - eventually
            # partitioned backups will have an election, and then requests will
            # succeed again
            r = c.post("/app/log/public", {"id": key, "msg": val_b})
            assert r.status_code == http.HTTPStatus.GATEWAY_TIMEOUT, r

            network.wait_for_new_primary(primary, nodes=backups)

        with backup.client("user0") as c:
            r = c.get(f"/app/log/public?id={key}")
            assert r.status_code == http.HTTPStatus.OK, r
            assert r.body.json()["msg"] == val_a, r

    LOG.info("Drop partition and wait for reunification")
    network.wait_for_primary_unanimity()
    primary, backups = network.find_nodes()
    with primary.client() as c:
        view = c.get("/node/network").body.json()["current_view"]

    backup = backups[0]
    check_can_progress(primary)
    check_can_progress(backup)

    LOG.info("One-way partition may lead to misleading response")
    # Construct a partial partition, where the backup forwards but does not hear responses
    rules = network.partitioner.isolate_node(
        backup,
        isolation_dir=infra.partitions.IsolationDir.INBOUND_REQUESTS
        | infra.partitions.IsolationDir.OUTBOUND_RESPONSES,
    )
    with backup.client("user0") as c:
        # NB: Although this backup reports a timeout, the operation was actually
        # successfully forwarded!
        r = c.post("/app/log/public", {"id": key, "msg": val_b})
        assert r.status_code == http.HTTPStatus.GATEWAY_TIMEOUT, r

    with primary.client("user0") as c:
        r = c.get(f"/app/log/public?id={key}")
        assert r.status_code == http.HTTPStatus.OK, r
        assert r.body.json()["msg"] == val_b, r

    rules.drop()

    network.wait_for_primary_unanimity(min_view=view)


@reqs.description(
    "Respond-on-commit requests get an error response if the operation is lost in an election"
)
@reqs.at_least_n_nodes(3)
def test_invalidated_blocking_calls(network, args):
    for path in ["/app/log/blocking/private", "/app/log/blocking/private/receipt"]:
        _test_invalidated_blocking_call(network, args, path)


def _test_invalidated_blocking_call(network, args, blocking_path):
    primary, backups = network.find_nodes()
    key = 42
    val_a = "Hello"

    ready_to_go = threading.Event()
    partition_created = threading.Event()

    def blocking_send():
        LOG.info(
            f"Make a blocking respond-on-commit call to {blocking_path} on a partitioned primary"
        )
        with primary.client("user0") as c:
            ready_to_go.set()
            partition_created.wait()
            r = c.post(blocking_path, {"id": key, "msg": val_a}, timeout=10)
            assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR
            tx_id = r.headers[infra.clients.CCF_TX_ID_HEADER]
            body = r.body.json()
            assert (
                body["error"]["message"]
                == f"While waiting for TxID {tx_id} to commit, it was invalidated"
            )

    send_thread = threading.Thread(target=blocking_send, name="blocking")
    send_thread.start()

    with network.partitioner.partition(backups):
        ready_to_go.wait()
        partition_created.set()

        new_primary, new_term = network.wait_for_new_primary(
            old_primary=primary, nodes=backups
        )

        LOG.info(f"Polling for commit in {new_term}")
        with new_primary.client() as c:
            timeout = 3
            end_time = time.time() + timeout
            while True:
                logs = []
                r = c.get("/node/commit", log_capture=logs)
                assert r.status_code == http.HTTPStatus.OK, r

                commit_tx_id = TxID.from_str(r.body.json()["transaction_id"])
                if commit_tx_id.view >= new_term:
                    flush_info(logs)
                    break

                if time.time() > end_time:
                    flush_info(logs)
                    raise AssertionError(
                        f"New primary made no commit progress after {timeout}s"
                    )

    LOG.info("Drop partition and wait for reunification")
    send_thread.join()
    network.wait_for_primary_unanimity()


@reqs.description(
    "Session consistency is provided, and inconsistencies after elections are replaced by errors"
)
@reqs.supports_methods("/app/log/public")
@reqs.no_http2()
def test_session_consistency(network, args):
    # Ensure we have 5 nodes
    original_size = network.resize(5, args)

    primary, backups = network.find_nodes()
    backup = backups[0]

    with contextlib.ExitStack() as stack:
        client_primary_A = stack.enter_context(
            primary.client(
                "user0",
                description_suffix="A",
                impl_type=infra.clients.RawSocketClient,
            )
        )
        client_primary_B = stack.enter_context(
            primary.client(
                "user0",
                description_suffix="B",
                impl_type=infra.clients.RawSocketClient,
            )
        )
        client_backup_C = stack.enter_context(
            backup.client(
                "user0",
                description_suffix="C",
                impl_type=infra.clients.RawSocketClient,
            )
        )
        client_backup_D = stack.enter_context(
            backup.client(
                "user0",
                description_suffix="D",
                impl_type=infra.clients.RawSocketClient,
            )
        )

        # Create some new state
        msg_id = 42
        msg_a = "First write, to primary"
        r = client_primary_A.post(
            "/app/log/public",
            {
                "id": msg_id,
                "msg": msg_a,
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r

        # Read this state on a second session
        r = client_primary_B.get(f"/app/log/public?id={msg_id}")
        assert r.status_code == http.HTTPStatus.OK, r
        assert r.body.json()["msg"] == msg_a, r

        # Wait for that to be committed on all backups
        network.wait_for_all_nodes_to_commit(primary)

        # Write on backup, resulting in a forwarded request.
        # Confirm that this session can read that write, since it remains forwarded.
        # Meanwhile a separate session to the same backup node may not see it.
        # NB: The latter property is not possible to test systematically, as it
        # relies on a race - does the read on the second session happen before consensus
        # update's the backup's state. Solution is to try in a loop, with a high probability
        # that we observe the desired ordering after just a few iterations.
        n_attempts = 20
        for i in range(n_attempts):
            last_message = f"Second write, via backup ({i})"
            r = client_backup_C.post(
                "/app/log/public",
                {
                    "id": msg_id,
                    "msg": last_message,
                },
            )
            # Note: No assert on response status code code here as forwarded response
            # may be dropped by primary node in debug builds (https://github.com/microsoft/CCF/issues/4625)

            r = client_backup_D.get(f"/app/log/public?id={msg_id}")
            assert r.status_code == http.HTTPStatus.OK, r
            if r.body.json()["msg"] != last_message:
                LOG.info(
                    f"Successfully saw a different value on second session after {i} attempts"
                )
                break
        else:
            raise RuntimeError(
                f"Failed to observe evidence of session forwarding after {n_attempts} attempts"
            )

        def check_sessions_alive(sessions):
            for client in sessions:
                try:
                    r = client.get(f"/app/log/public?id={msg_id}")
                    assert r.status_code == http.HTTPStatus.OK, r
                except ConnectionResetError as e:
                    raise AssertionError(
                        f"Session {client.description} was killed unexpectedly: {e}"
                    ) from e

        def check_sessions_dead(
            sessions,
        ):
            for client in sessions:
                try:
                    r = client.get(f"/app/log/public?id={msg_id}")
                    assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r
                    assert r.body.json()["error"]["code"] == "SessionConsistencyLost", r
                except ConnectionResetError as e:
                    raise AssertionError(
                        f"Session {client.description} was killed without first returning an error: {e}"
                    ) from e

                # After returning error, session should be terminated, so all subsequent requests should fail
                try:
                    client.get("/node/commit")
                    raise AssertionError(
                        f"Session {client.description} survived unexpectedly"
                    )
                except ConnectionResetError:
                    LOG.info(f"Session {client.description} was terminated as expected")

        # Partition primary and forwarding backup from other backups
        with network.partitioner.partition([primary, backup]):
            # Write on partitioned primary
            msg0 = "Hello world"
            r0 = client_primary_A.post(
                "/app/log/public",
                {
                    "id": msg_id,
                    "msg": msg0,
                },
            )
            assert r0.status_code == http.HTTPStatus.OK

            # Read from partitioned backup, over forwarded session to primary
            r1 = client_backup_C.get(f"/app/log/public?id={msg_id}")
            assert r1.status_code == http.HTTPStatus.OK
            assert r1.body.json()["msg"] == msg0, r1

            # Despite partition, these sessions remain live
            check_sessions_alive((client_primary_A, client_backup_C))

            # Once CheckQuorum takes effect and the primary stands down, all sessions
            # on the primary report a risk of inconsistency
            primary.wait_for_leadership_state(
                r0.view - 1,
                ["Follower", "PreVoteCandidate", "Candidate"],
                timeout=2 * args.election_timeout_ms / 1000,
            )

        # Once we remove the network partition, a new primary will be elected in a higher term,
        network.wait_for_primary_unanimity(min_view=r0.view + 1)

        # This will break all of the previous sessions
        check_sessions_dead(
            (
                # This session wrote state to the partitioned primary which was at risk of being lost
                client_primary_A,
                # These sessions only read old state which is still valid
                client_primary_B,
                client_backup_C,
                client_backup_D,
            )
        )

    # Restore original network size
    network.resize(original_size, args)

    return network


@reqs.supports_methods("/app/log/public")
def test_recovery_elections(orig_network, args):
    # Ensure we have 3 nodes
    original_size = orig_network.resize(3, args)

    old_primary, _ = orig_network.find_nodes()
    with old_primary.client("user0") as c:
        LOG.warning("Writing some initial state")
        for _ in range(300):
            r = c.post(
                "/app/log/public",
                {
                    "id": 42,
                    "msg": "Uninteresting recoverable transactions",
                },
            )
            assert r.status_code == 200, r

        r = c.get("/node/network")
        assert r.status_code == 200, r
        previous_identity = orig_network.save_service_identity(args)
        c.wait_for_commit(
            orig_network.consortium.set_recovery_threshold(old_primary, 1)
        )
    orig_network.stop_all_nodes(skip_verification=True)
    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()

    # Create a recovery network, where we will manually take the recovery steps (transition to open and submit share)
    network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        existing_network=orig_network,
    )
    # Make the backup which is not stalled below an unlikely election winner.
    network.per_node_args_override[2] = {
        "election_timeout_ms": args.election_timeout_ms * 10
    }
    network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
    )
    new_primary, new_backups = network.find_nodes()
    network.consortium.transition_service_to_open(
        new_primary, previous_service_identity=previous_identity
    )

    with new_primary.client("user0") as c:
        previous_identity = network.save_service_identity(args)

    member = network.consortium.get_active_recovery_participants()[0]

    # We need to delay a backup's private recovery process until:
    # - The primary has completed its private recovery, and fully opened the network
    # - The backup has called and won an election
    # So that the backup node _is primary_ at the point it completes private recovery.
    # We force the delay by injecting a delay into the file operations of the backup,
    # and force an election (after the primary has completed its recovery) by killing
    # the original primary node.
    backup = new_backups[0]
    LOG.info(f"Using strace to inject delays in file IO of {backup}")
    assert not backup.remote.check_done(timeout=0)

    strace_command = [
        "strace",
        f"--attach={backup.remote.remote.proc.pid}",
        "--inject=lseek:delay_exit=10s",
        "-tt",
        "--trace=lseek,read,open,openat",
        "--decode-fds=all",
        "--output=strace_output.txt",
    ]
    LOG.warning(f"About to run strace: {strace_command}")
    strace_process = subprocess.Popen(
        strace_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    member.get_and_submit_recovery_share(new_primary)
    network.recovery_count += 1

    LOG.info("Confirming that primary completes private recovery")
    network.wait_for_state(
        new_primary,
        infra.node.State.PART_OF_NETWORK.value,
        timeout=30,
    )

    election_s = args.election_timeout_ms / 1000
    LOG.info(
        f"Holding backup stalled via strace for {election_s}, to trigger an election"
    )
    time.sleep(election_s)

    # If strace failed to stall the node, the rest of the test is meaningless.
    try:
        strace_process.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        assert strace_process.returncode is None, strace_process.returncode
    else:
        assert (
            False
        ), f"strace must not have been completed yet (retcode: {strace_process.returncode})"

    LOG.info("Ending strace, and terminating primary node")
    strace_process.terminate()
    strace_process.communicate()

    new_primary.stop()

    LOG.info(
        f"Give {backup} time to finish its recovery (including becoming primary), and confirm that it dies in the process"
    )
    time.sleep(election_s)
    # The result of all of that is that this node, which had become primary while it
    # completed its private recovery, crashed at the end of recovery (rather than)
    # producing an invalid ledger).
    done_timeout_s = 15
    done = backup.remote.check_done(timeout=done_timeout_s)
    if not done:
        LOG.error(
            f"Backup node {backup} did not terminate within {done_timeout_s}s after recovery/election"
        )
        try:
            LOG.error(f"Backup node output path: {backup.remote.out}")
        except Exception as e:
            LOG.warning(f"Could not retrieve backup output path: {e}")
        try:
            network.log_stack_traces()
        except Exception as e:
            LOG.warning(f"Failed to log stack traces: {e}")
        try:
            backup.stop()
        except Exception as e:
            LOG.warning(f"Failed to stop backup node: {e}")
    assert backup.remote.check_done(
        timeout=0
    ), f"Backup node {backup} did not terminate after recovery/election period"

    network.ignore_errors_on_shutdown()
    network.stop_all_nodes(skip_verification=True)
    current_ledger_dir, committed_ledger_dirs = backup.get_ledger()

    LOG.info(
        "Trying a further recovery, to confirm that the ledger is in a recoverable state"
    )
    recovery_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        existing_network=network,
    )
    recovery_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
    )
    recovery_network.recover(args)

    # Restore original network size
    recovery_network.resize(original_size, args)

    return recovery_network


def force_become_primary(network, args, target_node):
    network.wait_for_node_commit_sync()
    primary, backups = network.find_nodes()

    if primary != target_node:
        # In a fully sync'd cluster this will cause the following:
        # target times out
        # target starts election and wins
        # target becomes primary and emits signature
        # target replicates signature
        # then we can remove the partition
        rules = network.partitioner.isolate_node(primary, target_node)
        target_node.wait_for_leadership_state(
            0, "Leader", timeout=2 * args.election_timeout_ms / 1000
        )
        network.wait_for_node_commit_sync(nodes=backups)
        rules.drop()
        # Wait for the old primary to observe the new one
        network.wait_for_new_primary_in({target_node}, nodes=[primary])
        network.wait_for_primary_unanimity()
        primary = target_node

    # Ensure a signature has been produced in the new term
    with target_node.client("user0") as c:
        r = c.get("/node/consensus", log_capture=[]).body.json()["details"]
        assert (
            r["leadership_state"] == "Leader"
        ), f"Node {target_node.node_id} is not leader: {r}"
        sig_interval = args.sig_ms_interval / 1000
        t0 = time.time()
        timeout = 3 * sig_interval
        while time.time() - t0 < timeout:
            r = c.get("/node/commit")
            assert r.status_code == http.HTTPStatus.OK, r
            tx_id = TxID.from_str(r.body.json()["transaction_id"])
            receipt = target_node.get_receipt(view=tx_id.view, seqno=tx_id.seqno)
            receipt_issuer = receipt.json()["node_id"]
            if receipt_issuer == target_node.node_id:
                return tx_id
            time.sleep(sig_interval / 2)
        raise TimeoutError(
            f"Node {target_node.node_id} did not produce signature (and receipt) in current term after {timeout}s"
        )


def _uncommitted_ledger_files(node):
    ledger_dir = node.remote.current_ledger_path()
    return {
        f
        for f in os.listdir(ledger_dir)
        if f.startswith("ledger_")
        and not f.endswith(ccf.ledger.COMMITTED_FILE_SUFFIX)
        and not f.endswith(ccf.ledger.IGNORED_FILE_SUFFIX)
    }


def _wait_for_new_uncommitted_ledger_files(node, previous_files, timeout=10):
    end_time = time.time() + timeout
    while time.time() < end_time:
        uncommitted_files = _uncommitted_ledger_files(node)
        new_uncommitted_files = uncommitted_files - previous_files
        if new_uncommitted_files:
            LOG.info(
                f"Found new uncommitted ledger file(s) on {node.local_node_id}: {sorted(new_uncommitted_files)}"
            )
            return new_uncommitted_files
        time.sleep(0.1)

    raise TimeoutError(
        f"Node {node.local_node_id} did not write a new uncommitted ledger file"
    )


def _assert_ledger_files_contain_payload(ledger_dir, ledger_files, payload):
    for ledger_file in ledger_files:
        with open(os.path.join(ledger_dir, ledger_file), "rb") as f:
            if payload in f.read():
                return

    raise AssertionError(
        f"Expected to find payload in {sorted(ledger_files)} under {ledger_dir}"
    )


@reqs.description(
    "Restart a retired primary in place with uncommitted and uncommittable ledger files"
)
@reqs.exactly_n_nodes(3)
def test_in_place_restart_with_uncommittable_ledger(network, args):
    old_primary, backups = network.find_nodes()

    committed_msg = "Committed before primary isolation"
    with old_primary.client("user0") as c:
        r = c.post(
            "/app/log/public",
            {"id": COMMITTED_RECORD_ID, "msg": committed_msg},
        )
        assert r.status_code == http.HTTPStatus.OK, r
        c.wait_for_commit(r)

    network.consortium.force_ledger_chunk(old_primary)
    network.wait_for_all_nodes_to_commit(primary=old_primary)
    previous_uncommitted_files = _uncommitted_ledger_files(old_primary)

    uncommitted_records = [UNCOMMITTABLE_RECORD_ID_START + i for i in range(3)]
    uncommitted_msg = "Uncommittable while primary is isolated"
    uncommitted_payload = (uncommitted_msg * UNCOMMITTABLE_MESSAGE_REPEAT).encode()

    with network.partitioner.partition([old_primary]):
        with old_primary.client("user0") as c:
            for record_id in uncommitted_records:
                r = c.post(
                    "/app/log/public",
                    {
                        "id": record_id,
                        "msg": uncommitted_payload.decode(),
                    },
                )
                assert r.status_code == http.HTTPStatus.OK, r

        new_uncommitted_files = _wait_for_new_uncommitted_ledger_files(
            old_primary, previous_uncommitted_files
        )
        _assert_ledger_files_contain_payload(
            old_primary.remote.current_ledger_path(),
            new_uncommitted_files,
            uncommitted_payload,
        )

        new_primary, _ = network.wait_for_new_primary(old_primary, nodes=backups)
        network.retire_node(new_primary, old_primary)
        old_node_id = old_primary.node_id
        old_primary.stop()

    ledger_dir, read_only_ledger_dirs = old_primary.remote.get_ledger(
        f"{old_primary.local_node_id}.ledger_in_place"
    )
    assert _uncommitted_ledger_files(old_primary), (
        "Expected the stopped primary's persisted ledger to contain "
        "uncommitted files before restart"
    )
    _assert_ledger_files_contain_payload(
        ledger_dir,
        new_uncommitted_files,
        uncommitted_payload,
    )

    network.join_node(
        old_primary,
        args.package,
        args,
        target_node=new_primary,
        ledger_dir=ledger_dir,
        read_only_ledger_dirs=read_only_ledger_dirs,
        copy_ledger=False,
        from_snapshot=False,
        timeout=args.ledger_recovery_timeout,
    )
    assert old_primary.node_id != old_node_id

    # Confirm that the infra has not deleted (or otherwise lost) the
    # uncommitted ledger files that were present before the in-place restart.
    restarted_uncommitted_files = _uncommitted_ledger_files(old_primary)
    missing_uncommitted_files = new_uncommitted_files - restarted_uncommitted_files
    assert not missing_uncommitted_files, (
        "Uncommitted ledger files were unexpectedly missing after the "
        f"in-place restart: {sorted(missing_uncommitted_files)}"
    )
    _assert_ledger_files_contain_payload(
        old_primary.remote.current_ledger_path(),
        new_uncommitted_files,
        uncommitted_payload,
    )

    network.trust_node(old_primary, args)

    new_primary, _ = network.find_primary()
    with new_primary.client("user0") as c:
        r = c.get(f"/app/log/public?id={COMMITTED_RECORD_ID}")
        assert r.status_code == http.HTTPStatus.OK, r
        assert r.body.json() == {"msg": committed_msg}, r

        for record_id in uncommitted_records:
            r = c.get(f"/app/log/public?id={record_id}")
            assert r.status_code == http.HTTPStatus.NOT_FOUND, r

    check_can_progress(new_primary)
    network.stop_all_nodes(check_file_invariants=True)

    return network


def _tx_status(node, tx_id):
    with node.client() as c:
        r = c.get(
            f"/node/tx?transaction_id={tx_id.view}.{tx_id.seqno}",
            log_capture=[],
        )
        assert r.status_code == http.HTTPStatus.OK, r
        return TxStatus(r.body.json()["status"])


def _commit_txid(node):
    with node.client() as c:
        r = c.get("/node/commit", log_capture=[])
        assert r.status_code == http.HTTPStatus.OK, r
        return TxID.from_str(r.body.json()["transaction_id"])


def _wait_for_tx_status(node, tx_id, expected, timeout):
    end_time = time.time() + timeout
    last = None
    while time.time() < end_time:
        last = _tx_status(node, tx_id)
        if last == expected:
            return last
        time.sleep(0.05)
    raise TimeoutError(
        f"Node {node.local_node_id} did not observe {tx_id} as {expected.value}: {last}"
    )


def _post_public(node, record_id, msg):
    last = None
    for _ in range(10):
        with node.client("user0") as c:
            r = c.post("/app/log/public", {"id": record_id, "msg": msg})
        last = r
        if r.status_code == http.HTTPStatus.OK:
            return TxID(r.view, r.seqno)
        time.sleep(0.2)
    assert last.status_code == http.HTTPStatus.OK, last


def _consensus_details(node):
    with node.client() as c:
        r = c.get("/node/consensus", log_capture=[])
        assert r.status_code == http.HTTPStatus.OK, r
        return r.body.json()["details"]


def _consensus_view(node):
    return _consensus_details(node)["current_view"]


def _block_receive(network, node, other):
    # Drop only packets node receives from other. node can still send,
    # so a NACK written by other stays in TCP retransmit until this is
    # lifted. That is the delayed-NACK stand-in for dispatch_single.
    return network.partitioner.isolate_node(
        node,
        other,
        isolation_dir=infra.partitions.IsolationDir.INBOUND_REQUESTS
        | infra.partitions.IsolationDir.OUTBOUND_RESPONSES,
    )


def _collect_rules(*rule_sets, name):
    rules = []
    for rule_set in rule_sets:
        if rule_set is not None:
            rules.extend(rule_set.rules)
    return infra.partitions.Rules(rules, name)


def _block_send(network, node, other, payload_only=False):
    # Drop everything node sends to other, leaving other->node open.
    # A DROP does not reset the session, so bytes node has already written
    # stay in its TCP retransmit queue and are delivered verbatim, in the
    # order they were written, whenever the rule is lifted.
    #
    # payload_only lets bare acks through. A node pair shares one socket, so
    # dropping every packet in one direction also starves the other of acks
    # and the peer's window closes within a couple of round trips, which stops
    # the traffic that is meant to keep flowing.
    return network.partitioner.isolate_node(
        node,
        other,
        isolation_dir=infra.partitions.IsolationDir.INBOUND_RESPONSES
        | infra.partitions.IsolationDir.OUTBOUND_REQUESTS,
        length=infra.partitions.PAYLOAD_LENGTHS if payload_only else None,
    )


def _wait_for_entry(node, tx_id, timeout):
    end_time = time.time() + timeout
    last = None
    while time.time() < end_time:
        last = _tx_status(node, tx_id)
        if last in (TxStatus.Pending, TxStatus.Committed):
            return last
        time.sleep(0.05)
    raise TimeoutError(f"Node {node.local_node_id} never held {tx_id}: {last}")


def _grep_log(node, needle):
    out_path, _ = node.get_logs()
    if out_path is None or not os.path.exists(out_path):
        return []
    with open(out_path, "r", encoding="utf-8", errors="replace") as f:
        return [line.rstrip() for line in f if needle in line]


def _ack_age_ms(node, other):
    return _consensus_details(node)["acks"][other.node_id]["last_received_ms"]


def _client_ack_age_ms(client, other):
    # Same as _ack_age_ms, but over a connection the caller keeps open. The
    # window between n0 consuming the retained NACK and it writing the next
    # message to n2 is one periodic, so a fresh TLS session per poll is a
    # significant part of the budget.
    r = client.get("/node/consensus", log_capture=[])
    assert r.status_code == http.HTTPStatus.OK, r
    acks = r.body.json()["details"]["acks"]
    return acks[other.node_id]["last_received_ms"]


def _dump_counters(tag):
    # iptc.easy.dump_chain() does not report the per-rule counters, and those
    # are the only way to tell a rule that is not matching from one that is
    # matching but on traffic we did not expect.
    proc = subprocess.run(
        ["iptables", "-L", infra.partitions.CCF_IPTABLES_CHAIN, "-n", "-v", "-x"],
        check=False,
        capture_output=True,
        text=True,
    )
    LOG.info(
        f"iptables counters ({tag}):\n{proc.stdout.strip() or proc.stderr.strip()}"
    )


def _sessions_of(node, other):
    # The node-to-node sessions node holds towards other, as
    # (description, send queue). A node dials out from its node_client_host to
    # the peer's n2n interface, so the pair has at most two sessions and each
    # node holds one end of each. Send-Q is what a DROP rule has held back.
    mine = {
        "out": (
            node.node_client_host,
            f"{other.n2n_interface.host}:{other.n2n_interface.port}",
        ),
        "in": (
            f"{node.n2n_interface.host}:{node.n2n_interface.port}",
            other.node_client_host,
        ),
    }
    proc = subprocess.run(
        ["ss", "-tnH", "state", "established"],
        check=False,
        capture_output=True,
        text=True,
    )
    found = []
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        send_q, local, peer = int(fields[-3]), fields[-2], fields[-1]
        if (local.rsplit(":", 1)[0], peer) == mine["out"]:
            found.append((f"out {local} -> {peer}", send_q))
        elif (local, peer.rsplit(":", 1)[0]) == mine["in"]:
            found.append((f"in {peer} -> {local}", send_q))
    return found


def _send_q(node, other):
    return max([send_q for _, send_q in _sessions_of(node, other)], default=0)


def _reject_acks(network, node, other):
    # As _block_send, but the kernel answers with a RST instead of dropping,
    # so the session is torn down rather than delayed, and node_connections
    # then discards the connection and everything queued on it.
    #
    # Only node's own direction is matched, so anything other is sending still
    # arrives: the RST goes back to whoever sent the packet that matched. Only
    # bare acks are matched, so the trigger is node acknowledging what it has
    # just been sent, rather than a retransmission of its own backlog, which
    # would fire at some arbitrary earlier point in the exponential backoff.
    return network.partitioner.isolate_node(
        node,
        other,
        isolation_dir=infra.partitions.IsolationDir.INBOUND_RESPONSES
        | infra.partitions.IsolationDir.OUTBOUND_REQUESTS,
        length=infra.partitions.ACK_LENGTHS,
        target={"REJECT": {"reject-with": "tcp-reset"}},
    )


@reqs.description(
    "A follower must not commit a divergent suffix from a matching prefix AE"
)
@reqs.exactly_n_nodes(5)
def test_divergent_suffix_not_committed_from_prefix_ae(network, args):
    # Partition version of raft_scenarios/divergent_suffix_commit.
    #
    # send_append_entries splits at term boundaries, so a leader whose log is
    # <prefix>@A, [..]@B, [..]@C sends two messages, and both carry
    # leader_commit_idx = the leader's own commit index. Delivering only the
    # first to a follower that already holds that @B range takes the skip path
    # in recv_append_entries: nothing after r.idx is re-applied or term-checked,
    # yet execute_append_entries_finish still calls
    # commit_if_possible(r.leader_commit_idx). A follower holding its own
    # divergent committable @B suffix therefore commits it.
    #
    # Three things have to line up for the leader to send that first message,
    # and each one dictates a phase below:
    #
    #  - sent_idx[n2] has to land inside n0's @B range. Only a NACK moves it
    #    there, and NACKs only ever lower it
    #        sent_idx = max(min(this_match, sent_idx), match_idx)
    #    so it must be one n2 wrote while it was still short, and it must
    #    arrive after n0 wins term C, since become_leader resets sent_idx. A
    #    one-way DROP gives exactly that: TCP retransmits the NACK, unchanged,
    #    until the rule is lifted.
    #
    #  - n2's commit_idx must be no higher than the index that NACK reports,
    #    or recv_append_entries discards the message at
    #        r.prev_idx < state->commit_idx
    #    A bare NACK reports {current_view, last_idx}, so n2 needs a log that
    #    runs past its own commit index at the point the NACK is written. n1
    #    leads term B, commits once, then permanently loses its quorum, so
    #    everything it replicates after that extends n2's log and nothing
    #    moves any commit index again.
    #
    #  - n0 must still be in term A when that NACK is written, or it is not
    #    the leader that sends the AE which provokes it. Whoever first tells
    #    n0 about term B demotes it, and a NACK from n2 does exactly that
    #    (recv_append_entries_response calls become_aware_of_new_term), so n2
    #    stays muted until its log is long enough and the retaining rule is
    #    already in place.
    #
    #  - n2 must not see n0's term-C entries before that message. They are
    #    ahead of it in n0's send queue, and a DROP only delays traffic, so the
    #    socket has to be reset once the NACK has been consumed.
    nodes = network.get_joined_nodes()
    assert len(nodes) == 5, nodes

    n0, _ = network.find_primary()
    n1, n2, n3, n4 = [node for node in nodes if node != n0]
    # The election timeout overrides in run_divergent_suffix_commit_check are
    # keyed by local node id, and every ordering below depends on them.
    assert [n.local_node_id for n in (n0, n1, n2, n3, n4)] == [0, 1, 2, 3, 4], [
        n.local_node_id for n in (n0, n1, n2, n3, n4)
    ]
    beat_s = max(args.consensus_update_timeout_ms / 1000, 0.02)
    n0_beat_s = (
        network.per_node_args_override.get(0, {}).get(
            "consensus_update_timeout_ms", args.consensus_update_timeout_ms
        )
        / 1000
    )
    election_s = args.election_timeout_ms / 1000

    network.wait_for_all_nodes_to_commit(primary=n0)
    prefix = _commit_txid(n0)
    term_a = _consensus_view(n0)
    LOG.info(f"Common prefix {prefix}, n0 leads term {term_a}")

    live = []

    def hold(rules):
        live.append(rules)
        return rules

    def release(rules):
        if rules in live:
            live.remove(rules)
            rules.drop()

    try:
        # (1) n0 hears nothing from n1, is never told about the new term by n3
        # or n4, and does not talk to n2 at all, so it stays leader in term A
        # throughout (1) to (5) without ever learning that term B exists.
        # Muting n0 -> n2 matters as much as the rest: the moment n2 hears a
        # term-A AppendEntries while it is in term B it answers with a NACK
        # carrying term B, and recv_append_entries_response demotes n0 on the
        # spot. n2 is the one node that must not be able to tell it.
        deaf = hold(
            _collect_rules(
                network.partitioner.isolate_node(n0, n1),
                name="n0 and n1 cannot talk, so n1 is the only node to time out",
            )
        )
        muted0 = hold(
            _collect_rules(
                _block_send(network, n0, n2, payload_only=True),
                name="n2 cannot tell n0 about term B, because it never hears it",
            )
        )
        quiet = hold(
            _collect_rules(
                _block_send(network, n3, n0, payload_only=True),
                _block_send(network, n4, n0, payload_only=True),
                name="n3 and n4 do not tell n0 about term B",
            )
        )

        n1.wait_for_leadership_state(term_a, ["Leader"], timeout=3 * election_s)
        term_b = _consensus_view(n1)
        assert term_b > term_a, (term_b, term_a)
        LOG.info(f"n1 leads term {term_b}")

        # (2) The last thing n1 ever commits, and so the last time any node's
        # commit index moves. n2 has to reach it before (5) retains a NACK,
        # because that NACK reports n2's last_idx and the message it produces
        # is discarded if it points below n2's commit index.
        frozen = _replicate_range(n1, 740000, "frozen", term_b)
        _wait_for_tx_status(n1, frozen, TxStatus.Committed, timeout=6 * election_s)
        for node in (n2, n3, n4):
            _wait_for_commit(node, frozen.seqno, timeout=6 * election_s)
        LOG.info(f"n1 committed {frozen} on n1, n2, n3 and n4")

        # (3) n1 loses its quorum. It is still leader and can still replicate,
        # but nothing is ever committed again, so every commit index in the
        # test is now pinned where it is.
        hold(
            _collect_rules(
                _block_send(network, n2, n1, payload_only=True),
                network.partitioner.isolate_node(n1, n3),
                network.partitioner.isolate_node(n1, n4),
                name="n1 keeps n0 and n2 but can never commit again",
            )
        )
        time.sleep(max(2 * beat_s, 1.0))
        n2_frozen = _commit_txid(n2)
        assert n2_frozen.seqno >= frozen.seqno, (n2_frozen, frozen)
        LOG.info(f"n2's commit index is pinned at {n2_frozen}")

        # (4) Extend n2's log without extending its commit index. This is the
        # margin the retained NACK needs: it will report gap, which is above
        # n2's commit index and, once (6) has run, strictly inside n0's @B
        # range.
        gap = _replicate_range(n1, 745000, "gap", term_b)
        _wait_for_entry(n2, gap, timeout=6 * election_s)
        assert _commit_txid(n2).seqno == n2_frozen.seqno, _commit_txid(n2)
        LOG.info(f"n2's log runs to {gap}, still committed only to {n2_frozen}")

        # (5) Retain everything n2 sends n0 for the rest of the test, then let
        # n0 talk to n2 again. n0 is still leader in term A, so every AE it
        # delivers is answered with a bare stale-term NACK reporting
        # {term B, gap}, and every one of them sits in n2's TCP retransmit
        # queue. Bare acks are let through, or n0's window closes and it stops
        # sending the heartbeats that provoke the NACKs in the first place.
        seen = len(_grep_log(n2, "but our term is later"))
        held = hold(_block_send(network, n2, n0, payload_only=True))
        release(muted0)
        retained = _wait_for_log(
            n2, "but our term is later", seen + 2, timeout=6 * election_s
        )
        assert _consensus_view(n0) == term_a, _consensus_view(n0)
        LOG.info(f"n2 retained {retained - seen} NACKs, all reporting {gap}")

        # (6) n1 extends the @B range onto n0 as well as n2, which is also how
        # n0 finally learns about term B. The retained NACK now points strictly
        # inside that range on both nodes. n3 and n4 are unblocked at the same
        # time, since n0 needs their votes in (8).
        release(deaf)
        release(quiet)
        shared = _replicate_range(n1, 750000, "shared", term_b)
        for node in (n0, n2):
            _wait_for_entry(node, shared, timeout=6 * election_s)
        assert _commit_txid(n2).seqno == n2_frozen.seqno, _commit_txid(n2)
        assert n2_frozen.seqno <= gap.seqno < shared.seqno, (n2_frozen, gap, shared)
        LOG.info(f"n0 and n2 hold the shared @B range through {shared}")

        # (7) n1 keeps only n2, and gives it a signed suffix that no other node
        # will ever hold. n1 is then quarantined outright: left connected to
        # n2 it would campaign once CheckQuorum demotes it and drag n2 into a
        # term above n0's.
        hold(
            _collect_rules(
                network.partitioner.isolate_node(n1, n0),
                name="the divergent suffix goes to n2 alone",
            )
        )
        old_branch = _replicate_range(n1, 760000, "old-branch", term_b)
        _wait_for_entry(n2, old_branch, timeout=6 * election_s)
        hold(
            _collect_rules(
                network.partitioner.isolate_node(n1, n2),
                name="n1 is quarantined so it cannot raise n2's term",
            )
        )
        LOG.info(f"n2 alone holds the divergent @B suffix through {old_branch}")

        # (8) n0 takes term C with n3 and n4 and commits a conflicting suffix
        # over the same indices. n0 -> n2 has to be muted throughout: those
        # entries have prev = the end of the shared @B range, which n2 has, so
        # n2 would match, roll its own suffix back and converge.
        muted = hold(_block_send(network, n0, n2, payload_only=True))
        new_branch = _term_c_commit(n0, term_b, old_branch, election_s)
        assert _tx_status(n2, old_branch) == TxStatus.Pending, old_branch
        LOG.info(f"n0 committed {new_branch}, n2 still holds {old_branch}")
        _dump_counters("term C committed")

        # (9) Release the retained NACK. n0 walks sent_idx[n2] back inside the
        # @B range, and from then on everything it sends n2 starts with the
        # matching-prefix message. Its term-C messages are ahead of that in the
        # session, and a DROP only delays them, so the session has to go.
        #
        # ss -K cannot do that here: WSL builds its kernel without
        # CONFIG_INET_DIAG_DESTROY, so it reports RTNETLINK answers: Invalid
        # argument and changes nothing. Arm a REJECT on the bare acks n0 sends
        # n2 instead, before the NACK is let through, because the packet that
        # triggers the RST is n0's own ack for that NACK. Nothing n2 sends is
        # matched, so the NACK still arrives, and the host reads it off the
        # socket long before the delayed ack goes back out.
        LOG.info(f"n0 sessions towards n2 before the reset: {_sessions_of(n0, n2)}")
        reset = _reject_acks(network, n0, n2)
        LOG.info("Releasing the retained NACK")
        try:
            with n0.client() as c:
                before = _client_ack_age_ms(c, n2)
                released = time.time()
                release(held)

                deadline = time.time() + 12 * election_s
                landed = False
                next_report = 0
                while time.time() < deadline:
                    if _client_ack_age_ms(c, n2) < before:
                        landed = True
                        break
                    if time.time() > next_report:
                        LOG.info(f"n0 ack age for n2 {_client_ack_age_ms(c, n2)}ms")
                        next_report = time.time() + 5
                    time.sleep(0.002)
            if not landed:
                _dump_counters("NACK never arrived")
                raise TimeoutError("n0 never received the retained NACK from n2")
            LOG.info(
                f"n0 consumed the retained NACK after {time.time() - released:.3f}s"
            )

            # The RST follows within a round trip of that ack. Waiting for the
            # session to actually go keeps the window in which n0 could write
            # its next message into a refused connection down to the delete
            # below, rather than a whole periodic.
            gone_by = time.time() + 4 * n0_beat_s
            while time.time() < gone_by and _sessions_of(n0, n2):
                time.sleep(0.005)
            still_up = _sessions_of(n0, n2)
        finally:
            reset.drop()
        if still_up:
            _dump_counters("session survived the reset")
            raise TimeoutError(f"n0 -> n2 session was still up: {still_up}")
        LOG.info("n0 -> n2 session reset, its term C queue is gone")

        # n0 reconnects on its next periodic and writes the split pair into a
        # session that has nothing else on it. Send-Q growing on that session
        # is that write landing in the mute, and is the earliest point at which
        # lifting the mute delivers the matching prefix first.
        deadline = time.time() + 4 * n0_beat_s + 10
        while time.time() < deadline and _send_q(n0, n2) == 0:
            time.sleep(0.01)
        LOG.info(
            f"n0 holds {_send_q(n0, n2)} bytes for n2 on {_sessions_of(n0, n2)}, "
            "unmuting n0 -> n2"
        )
        release(muted)

        deadline = time.time() + 12 * election_s
        observed = None
        next_report = 0
        while time.time() < deadline:
            observed = _tx_status(n2, old_branch)
            if observed in (TxStatus.Committed, TxStatus.Invalid):
                break
            if time.time() > next_report:
                LOG.info(
                    f"waiting: n2 has {old_branch} as {observed.value}, "
                    f"commit {_commit_txid(n2)}"
                )
                next_report = time.time() + 5
            time.sleep(0.05)

        n2_commit = _commit_txid(n2)
        LOG.info(
            f"n2 has {old_branch} as {observed.value}, commit {n2_commit}; "
            f"n0 committed {new_branch}"
        )
        for needle in (
            "Dropping conflicting branch",
            "Ignoring conflicting AppendEntries",
        ):
            for line in _grep_log(n2, needle):
                LOG.warning(f"n2: {line}")

        assert _tx_status(n0, new_branch) == TxStatus.Committed
        assert observed != TxStatus.Committed, (
            f"n2 committed divergent {old_branch} while {new_branch} is "
            f"committed on the term-C branch"
        )
        if n2_commit.seqno >= old_branch.seqno:
            assert n2_commit.view != old_branch.view, n2_commit
    finally:
        for rules in reversed(live):
            rules.drop()

    # No reunification: this is a one-sided safety check on n2.
    return network


def _replicate_range(node, first_id, msg, term, count=4):
    # `count` entries, then the signature the next index always carries when
    # nothing else is being written. The signature is what makes the range a
    # committable index on whoever receives it.
    last = None
    for i in range(count):
        last = _post_public(node, first_id + i, f"{msg}-{i}")
        assert last.view == term, (last, term)
    sig = TxID(term, last.seqno + 1)
    _wait_for_entry(node, sig, timeout=10)
    return sig


def _wait_for_commit(node, seqno, timeout):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = _commit_txid(node)
        if last.seqno >= seqno:
            return last
        time.sleep(0.05)
    raise TimeoutError(f"Node {node.local_node_id} did not commit {seqno}: {last}")


def _wait_for_log(node, needle, count, timeout):
    deadline = time.time() + timeout
    found = 0
    while time.time() < deadline:
        found = len(_grep_log(node, needle))
        if found >= count:
            return found
        time.sleep(0.1)
    raise TimeoutError(
        f"Node {node.local_node_id} logged {needle!r} {found} times, wanted {count}"
    )


def _term_c_commit(n0, term_b, old_branch, election_s):
    n0.wait_for_leadership_state(term_b, ["Leader"], timeout=6 * election_s)
    term_c = _consensus_view(n0)
    assert term_c > term_b, (term_c, term_b)
    # The conflicting suffix has to reach at least as far as n2's divergent
    # signature, or leader_commit_idx will not be high enough to select it.
    # n0 starts one index short of the shared range (become_leader writes a
    # new-view signature there), and n2's suffix is 4 entries plus whatever
    # signatures the timer interleaved, so 16 is comfortably past it.
    new_branch = _replicate_range(n0, 770000, "new-branch", term_c, count=16)
    assert new_branch.seqno >= old_branch.seqno, (new_branch, old_branch)
    _wait_for_tx_status(n0, new_branch, TxStatus.Committed, timeout=6 * election_s)
    LOG.info(f"n0 leads term {term_c} and committed {new_branch}")
    return new_branch


def run_divergent_suffix_commit_check(const_args):
    LOG.info(
        "Confirm a follower does not commit a divergent suffix from a "
        "matching prefix AppendEntries"
    )
    args = copy.deepcopy(const_args)
    args.label += "_divergent_suffix"
    args.nodes = infra.e2e_args.nodes(args, 5)
    # The periodic decides how long there is between n0 consuming the retained
    # NACK and it writing the next message to n2. The socket has to be reset in
    # that window, so this is deliberately much longer than it needs to be.
    args.consensus_update_timeout_ms = 1000
    # This is node 1's timeout. It has to cover the term-B election, and then,
    # as its CheckQuorum window, everything from (3) to (7).
    args.election_timeout_ms = 25000
    # Signatures must be frequent, so each replicated range becomes committable
    # promptly.
    args.sig_ms_interval = 100

    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=app.LoggingTxs("user0"),
        init_partitioner=True,
    ) as network:
        # An iptables DROP does not reset the session, but TCP_USER_TIMEOUT
        # does: the host sets it to client_connection_timeout on every
        # node-to-node socket, and at its 2s default the kernel destroys the
        # socket - and the NACK retained on it - long before the test is ready
        # to deliver it.
        args.client_connection_timeout_s = 600
        # election_timeout_ms doubles as the CheckQuorum window, and the
        # ratios here are what make the orderings reliable:
        #  - node 1 is the only node that can time out in phase (1), and its
        #    window then has to cover phases (3) to (7);
        #  - node 0 hears nothing at all from phase (1), so its window has to
        #    cover everything up to (6), where it learns term B from node 1
        #    and becomes the first node to campaign for term C;
        #  - nodes 2, 3 and 4 only ever vote. Node 2 in particular hears
        #    nothing from phase (7) onwards and must not campaign.
        network.per_node_args_override[0] = {
            "election_timeout_ms": 60000,
            # Node 0's periodic is the whole budget for resetting the session
            # between it consuming the retained NACK and it writing the next
            # message to node 2, so give it room. Nothing else waits on it:
            # the replication in (2), (6) and (7) is node 1's, and node 0's
            # own responses are sent as soon as a message arrives.
            "consensus_update_timeout_ms": 4000,
        }
        network.per_node_args_override[2] = {"election_timeout_ms": 400000}
        for local_id in (3, 4):
            network.per_node_args_override[local_id] = {"election_timeout_ms": 150000}
        network.start_and_open(args)
        # Node 0's periodic is long, so give the cluster more than the default
        # three seconds to line up before anything starts asserting on it.
        network.wait_for_node_commit_sync(timeout=30)
        # node 0 opens the service and so is already primary; this only
        # confirms it and waits for a signature in its own term.
        force_become_primary(network, args, network.nodes[0])
        test_divergent_suffix_not_committed_from_prefix_ae(network, args)


def run_in_place_restart_uncommittable_ledger_check(const_args):
    LOG.info(
        "Confirm that in-place restart ignores uncommitted and uncommittable ledger files"
    )
    args = copy.deepcopy(const_args)
    args.label += "_in_place_restart_uncommitted"
    args.nodes = infra.e2e_args.nodes(args, 3)

    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=app.LoggingTxs("user0"),
        init_partitioner=True,
    ) as network:
        # Keep chunks small so isolated writes quickly create uncommitted files.
        for i in range(3):
            network.per_node_args_override[i] = {
                "ledger_chunk_bytes": UNCOMMITTABLE_TEST_LEDGER_CHUNK_BYTES
            }

        network.start_and_open(args)
        test_in_place_restart_with_uncommittable_ledger(network, args)


def run_ledger_chunk_bytes_check(const_args):
    LOG.info("Confirm that ledger chunks are determined by the primary")
    args = copy.deepcopy(const_args)

    args.label += "_ledger_chunks"

    # Don't emit snapshots
    args.snapshot_tx_interval = 10000000

    # Don't sign too-often; give time to store many entries in a single chunk
    args.sig_ms_interval = 1000

    args.nodes = infra.e2e_args.nodes(args, 3)

    with infra.network.network(
        args.nodes, args.binary_dir, init_partitioner=True
    ) as network:
        # Start each node with a different chunk size
        unit_size = 16384
        size_0 = unit_size
        size_1 = unit_size * 3
        size_2 = unit_size * 9

        def overhead(num_transactions, num_signatures):
            # From checking a sample run, the overhead consists of:
            # - 24 bytes of header + footer
            # - 202 bytes of framing/encoding for each of our transactions
            #   - Comes from
            #      16384 content
            #      + table name
            #      + JSON quoting
            #      + size prefixes
            #      + transaction header
            #      = 16586
            # - ~2100 bytes per signature transaction
            #   - Some variation from cert sizes
            #   - Increasing over time as the mini-tree grows
            #   - Adding 2400 bytes here to be safe
            return 24 + (202 * num_transactions) + (2400 * num_signatures)

        network.per_node_args_override[0] = {"ledger_chunk_bytes": f"{size_0}B"}
        network.per_node_args_override[1] = {"ledger_chunk_bytes": f"{size_1}B"}
        network.per_node_args_override[2] = {"ledger_chunk_bytes": f"{size_2}B"}

        network.start_and_open(args)

        primary, backups = network.find_nodes()

        nodes_and_sizes = [
            (primary, size_0),
            (backups[0], size_1),
            (backups[1], size_2),
        ]

        chunks_per_node = 2

        chunk_ends_by_size = defaultdict(list)

        for node, chunk_size in nodes_and_sizes:
            force_become_primary(network, args, node)
            with node.client("user0") as c:
                for _ in range(chunks_per_node):
                    written = 0
                    while written < chunk_size:
                        r = c.post(
                            "/app/log/public",
                            {"id": chunk_size, "msg": "X" * unit_size},
                        )
                        assert r.status_code == http.HTTPStatus.OK, r
                        written += unit_size
                    c.wait_for_commit(r)
                    r = c.get("/node/commit")
                    assert r.status_code == http.HTTPStatus.OK, r
                    chunk_ends_by_size[chunk_size].append(
                        TxID.from_str(r.body.json()["transaction_id"])
                    )

        # When a node becomes primary, it may discover the current chunk is already over
        # the local chunk threshold, and should immediately terminate this chunk.
        # Confirm it has been correctly tracking chunk sizes while it was backup in this case.
        smallest_node, _smallest_size = nodes_and_sizes[0]
        for node, chunk_size in nodes_and_sizes[1:]:
            force_become_primary(network, args, node)
            with node.client("user0") as c:
                written = 0
                # Stop just before this node completes the chunk
                target_chunk_size = chunk_size - unit_size
                while written < target_chunk_size:
                    r = c.post(
                        "/app/log/public",
                        {"id": chunk_size, "msg": "X" * unit_size},
                    )
                    assert r.status_code == http.HTTPStatus.OK, r
                    written += unit_size
                c.wait_for_commit(r)

            force_become_primary(network, args, smallest_node)
            # Sleep long enough that this new primary node can produce a new time-based signature,
            # if they want to, to ensure they're tracking chunk sizes accurately
            time.sleep(args.sig_ms_interval / 1000)
            with smallest_node.client("user0") as c:
                r = c.get("/node/commit")
                assert r.status_code == http.HTTPStatus.OK, r
                chunk_ends_by_size[target_chunk_size].append(
                    TxID.from_str(r.body.json()["transaction_id"])
                )

        # Add a further write to trigger .committed rename of all chunks above
        with primary.client("user0") as c:
            r = c.post(
                "/app/log/public",
                {"id": 42, "msg": "Make a new chunk"},
            )
            assert r.status_code == http.HTTPStatus.OK, r
            c.wait_for_commit(r)

        # This explicitly checks that ledger chunks match on each node, which is the critical property
        network.stop_all_nodes(check_file_invariants=True)

        # Confirm that at least one ledger chunk of each expected size was produced
        current, committeds = primary.get_ledger()
        chunks = [
            os.path.join(ledger_dir, basename)
            for ledger_dir in (current, *committeds)
            for basename in os.listdir(ledger_dir)
        ]
        actual_chunk_sizes = {chunk: os.path.getsize(chunk) for chunk in chunks}

        chunk_ends_to_expected_size = {
            tx_id.seqno: size
            for size, tx_ids in chunk_ends_by_size.items()
            for tx_id in tx_ids
        }

        for path, actual_size in actual_chunk_sizes.items():
            start, end = ccf.ledger.range_from_filename(path)
            if end in chunk_ends_to_expected_size:
                chunk_size = chunk_ends_to_expected_size[end]
                num_transactions = 1 + end - start
                min_expected = chunk_size + overhead(num_transactions, num_signatures=0)
                max_expected = chunk_size + overhead(num_transactions, num_signatures=4)

                r = range(min_expected, max_expected)
                if actual_size not in r:
                    LOG.warning("About to fail. Giving some verbose logging output")
                    for ledger_dir in (current, *committeds):
                        cmd = f"ls -alv {ledger_dir}"
                        LOG.warning(f"{cmd}")
                        subprocess.run(cmd.split(" "), check=False)

                    ccf.read_ledger.run(
                        paths=[path],
                        print_mode=ccf.read_ledger.PrintMode.Contents,
                        insecure_skip_verification=True,
                    )

                assert (
                    actual_size in r
                ), f"Expected {os.path.basename(path)} (produced by a node with chunk-size {chunk_size:,}) to be between {min_expected:,} and {max_expected:,} bytes. It is actually {actual_size:,} bytes"

                del chunk_ends_to_expected_size[end]

        # Confirm we've seen all expected chunk ends
        assert len(chunk_ends_to_expected_size) == 0


def run(args):
    txs = app.LoggingTxs("user0")

    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=txs,
        init_partitioner=True,
    ) as network:
        network.start_and_open(args)

        test_invalid_partitions(network, args)
        test_partition_majority(network, args)
        test_isolate_primary_from_one_backup(network, args)
        test_new_joiner_helps_liveness(network, args)
        test_expired_certs(network, args)
        test_rolled_back_node_certificate(network, args)
        for n in range(5):
            test_isolate_and_reconnect_primary(network, args, iteration=n)
        test_join_rollback_on_primary_isolation(network, args)
        test_election_reconfiguration(network, args)
        test_forwarding_timeout(network, args)
        test_invalidated_blocking_calls(network, args)
        # HTTP2 doesn't support forwarding
        if not args.http2:
            test_session_consistency(network, args)
        network = test_recovery_elections(network, args)
        test_ledger_invariants(network, args)
    run_ledger_chunk_bytes_check(args)
    run_in_place_restart_uncommittable_ledger_check(args)
    run_divergent_suffix_commit_check(args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.package = "samples/apps/logging/logging"
    args.snapshot_tx_interval = (
        20  # Increase snapshot frequency for faster reconfigurations
    )

    loops = int(os.getenv("CCF_DIVERGENT_SUFFIX_LOOPS", "1"))
    if os.getenv("CCF_DIVERGENT_SUFFIX_ONLY"):
        failures = 0
        for i in range(loops):
            LOG.info(f"Divergent-suffix partition attempt {i + 1}/{loops}")
            try:
                run_divergent_suffix_commit_check(args)
            except Exception:
                failures += 1
                LOG.exception(f"Attempt {i + 1} failed")
        if failures:
            raise SystemExit(
                f"{failures}/{loops} divergent-suffix partition attempts failed"
            )
    else:
        run(args)
