# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import tempfile
import os
import shutil

import infra.logging_app as app
import infra.e2e_args
import infra.network
import ccf.ledger
import suite.test_requirements as reqs
import infra.crypto
import ipaddress
import infra.interfaces
import infra.path
import infra.proc
import random
import json
import subprocess
import time

from loguru import logger as LOG


@reqs.description("Move committed ledger files to read-only directory")
def test_save_committed_ledger_files(network, args):
    # Issue txs in a loop to force a signature and a new ledger chunk
    # each time. Record log messages at the same key (repeat=True) so
    # that CCF makes use of historical queries when verifying messages
    for _ in range(1, 5):
        network.txs.issue(network, 1, repeat=True)

    LOG.info(f"Moving committed ledger files to {args.common_read_only_ledger_dir}")
    primary, _ = network.find_primary()
    for ledger_dir in primary.remote.ledger_paths():
        for ledger_file_path in os.listdir(ledger_dir):
            if infra.node.is_file_committed(ledger_file_path):
                shutil.move(
                    os.path.join(ledger_dir, ledger_file_path),
                    os.path.join(args.common_read_only_ledger_dir, ledger_file_path),
                )

    network.txs.verify(network)
    return network


def test_parse_snapshot_file(network, args):
    primary, _ = network.find_primary()
    network.txs.issue(network, number_txs=args.snapshot_tx_interval * 2)
    committed_snapshots_dir = network.get_committed_snapshots(primary)
    for snapshot in os.listdir(committed_snapshots_dir):
        with ccf.ledger.Snapshot(os.path.join(committed_snapshots_dir, snapshot)) as s:
            assert len(
                s.get_public_domain().get_tables()
            ), "No public table in snapshot"
    return network


def find_ledger_chunk_for_seqno(ledger, seqno):
    for chunk in ledger:
        first, last = chunk.get_seqnos()
        next_signature = None
        for tx in chunk:
            pd = tx.get_public_domain()
            tables = pd.get_tables()
            if (
                pd.get_seqno() >= seqno
                and next_signature is None
                and ccf.ledger.SIGNATURE_TX_TABLE_NAME in tables
            ):
                next_signature = pd.get_seqno()
        if first <= seqno and seqno <= last:
            return chunk, first, last, next_signature
    return None, None, None, None


@reqs.description("Forced ledger chunk")
@app.scoped_txs()
def test_forced_ledger_chunk(network, args):
    primary, _ = network.find_primary()

    # Submit some dummy transactions
    network.txs.issue(network, number_txs=3)

    # Submit a proposal to force a ledger chunk at the following signature
    proposal = network.consortium.force_ledger_chunk(primary)

    # Issue some more transactions
    network.txs.issue(network, number_txs=5)

    ledger_dirs = primary.remote.ledger_paths()

    # Check that there is indeed a ledger chunk that ends at the
    # first signature after proposal.completed_seqno
    ledger = ccf.ledger.Ledger(ledger_dirs)
    chunk, _, last, next_signature = find_ledger_chunk_for_seqno(
        ledger, proposal.completed_seqno
    )
    LOG.info(
        f"Found ledger chunk {chunk.filename()} with chunking proposal @{proposal.completed_seqno} and signature @{next_signature}"
    )
    assert chunk.is_complete and chunk.is_committed()
    assert last == next_signature
    assert next_signature - proposal.completed_seqno < args.sig_tx_interval
    return network


@reqs.description("Forced snapshot")
@app.scoped_txs()
def test_forced_snapshot(network, args):
    primary, _ = network.find_primary()

    # Submit some dummy transactions
    network.txs.issue(network, number_txs=3)

    # Submit a proposal to force a snapshot at the following signature
    proposal_body, careful_vote = network.consortium.make_proposal(
        "trigger_snapshot", node_id=primary.node_id
    )
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )

    proposal = network.consortium.vote_using_majority(
        primary,
        proposal,
        careful_vote,
    )

    # Issue some more transactions
    network.txs.issue(network, number_txs=5)

    ledger_dirs = primary.remote.ledger_paths()

    # Find first signature after proposal.completed_seqno
    ledger = ccf.ledger.Ledger(ledger_dirs)
    chunk, _, _, next_signature = find_ledger_chunk_for_seqno(
        ledger, proposal.completed_seqno
    )

    assert chunk.is_complete and chunk.is_committed()
    LOG.info(f"Expecting snapshot at {next_signature}")

    snapshots_dir = network.get_committed_snapshots(primary)
    for s in os.listdir(snapshots_dir):
        with ccf.ledger.Snapshot(os.path.join(snapshots_dir, s)) as snapshot:
            snapshot_seqno = snapshot.get_public_domain().get_seqno()
            if snapshot_seqno == next_signature:
                LOG.info(f"Found expected forced snapshot at {next_signature}")
                return network

    raise RuntimeError("Could not find matching snapshot file")


# https://github.com/microsoft/CCF/issues/1858
@reqs.description("Generate snapshot larger than ring buffer max message size")
def test_large_snapshot(network, args):
    primary, _ = network.find_primary()

    # Submit some dummy transactions
    entry_size = 10000  # Lower bound on serialised write set size
    iterations = int(args.max_msg_size_bytes) // entry_size
    LOG.debug(f"Recording {iterations} large entries")
    with primary.client(identity="user0") as c:
        for idx in range(iterations):
            c.post(
                "/app/log/public?scope=test_large_snapshot",
                body={"id": idx, "msg": "X" * entry_size},
                log_capture=[],
            )

    # Submit a proposal to force a snapshot at the following signature
    proposal_body, careful_vote = network.consortium.make_proposal(
        "trigger_snapshot", node_id=primary.node_id
    )
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    proposal = network.consortium.vote_using_majority(
        primary,
        proposal,
        careful_vote,
    )

    # Check that there is at least a snapshot larger than args.max_msg_size_bytes
    snapshots_dir = network.get_committed_snapshots(primary)
    extra_data_size_bytes = 10000  # Upper bound on additional snapshot data (e.g. receipt) that is passed separately from the snapshot
    for s in os.listdir(snapshots_dir):
        snapshot_size = os.stat(os.path.join(snapshots_dir, s)).st_size
        if snapshot_size > int(args.max_msg_size_bytes) + extra_data_size_bytes:
            # Make sure that large snapshot can be parsed
            snapshot = ccf.ledger.Snapshot(os.path.join(snapshots_dir, s))
            assert snapshot.get_len() == snapshot_size
            LOG.info(
                f"Found snapshot [{snapshot_size}] larger than ring buffer max msg size {args.max_msg_size_bytes}"
            )
            return network

    raise RuntimeError(
        f"Could not find any snapshot file larger than {args.max_msg_size_bytes}"
    )


def split_all_ledger_files_in_dir(input_dir, output_dir):
    # A ledger file can only be split at a seqno that contains a signature
    # (so that all files end on a signature that verifies their integrity).
    # We first detect all signature transactions in a ledger file and truncate
    # at any one (but not the last one, which would have no effect) at random.
    for ledger_file in os.listdir(input_dir):
        sig_seqnos = []

        if ledger_file.endswith(ccf.ledger.RECOVERY_FILE_SUFFIX):
            # Ignore recovery files
            continue

        ledger_file_path = os.path.join(input_dir, ledger_file)
        ledger_chunk = ccf.ledger.LedgerChunk(ledger_file_path, ledger_validator=None)
        for transaction in ledger_chunk:
            public_domain = transaction.get_public_domain()
            if ccf.ledger.SIGNATURE_TX_TABLE_NAME in public_domain.get_tables().keys():
                sig_seqnos.append(public_domain.get_seqno())

        if len(sig_seqnos) <= 1:
            # A chunk may not contain enough signatures to be worth truncating
            continue

        # Ignore last signature, which would result in a no-op split
        split_seqno = random.choice(sig_seqnos[:-1])

        assert ccf.split_ledger.run(
            [ledger_file_path, str(split_seqno), f"--output-dir={output_dir}"]
        ), f"Ledger file {ledger_file_path} was not split at {split_seqno}"
        LOG.info(
            f"Ledger file {ledger_file_path} was successfully split at {split_seqno}"
        )
        LOG.debug(f"Deleting input ledger file {ledger_file_path}")
        os.remove(ledger_file_path)


@reqs.description("Split ledger")
def test_split_ledger_on_stopped_network(primary, args):
    # Test that ledger files can be arbitrarily split.
    # Note: For real operations, it would be best practice to use a separate
    # output directory

    current_ledger_dir, committed_ledger_dirs = primary.get_ledger()
    split_all_ledger_files_in_dir(current_ledger_dir, current_ledger_dir)
    if committed_ledger_dirs:
        split_all_ledger_files_in_dir(
            committed_ledger_dirs[0], committed_ledger_dirs[0]
        )

    # Check that the split ledger can be read successfully
    ccf.ledger.Ledger(
        [current_ledger_dir] + committed_ledger_dirs, committed_only=False
    )


def run_file_operations(args):
    with tempfile.NamedTemporaryFile(mode="w+") as ntf:
        service_data = {"the owls": "are not", "what": "they seem"}
        json.dump(service_data, ntf)
        ntf.flush()

        args.max_msg_size_bytes = f"{100 * 1024}"  # 100KB

        with tempfile.TemporaryDirectory() as tmp_dir:
            txs = app.LoggingTxs("user0")
            with infra.network.network(
                args.nodes,
                args.binary_dir,
                args.debug_nodes,
                args.perf_nodes,
                pdb=args.pdb,
                txs=txs,
            ) as network:
                args.common_read_only_ledger_dir = tmp_dir
                network.start_and_open(args, service_data_json_file=ntf.name)

                LOG.info("Check that service data has been set")
                primary, _ = network.find_primary()
                with primary.client() as c:
                    r = c.get("/node/network").body.json()
                    assert r["service_data"] == service_data

                test_save_committed_ledger_files(network, args)
                test_parse_snapshot_file(network, args)
                test_forced_ledger_chunk(network, args)
                test_forced_snapshot(network, args)
                test_large_snapshot(network, args)

                primary, _ = network.find_primary()
                # Scoped transactions are not handled by historical range queries
                network.stop_all_nodes(skip_verification=True)

                test_split_ledger_on_stopped_network(primary, args)


def run_tls_san_checks(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        args.common_read_only_ledger_dir = None  # Reset from previous test
        network.start_and_open(args)
        network.verify_service_certificate_validity_period(
            args.initial_service_cert_validity_days
        )

        LOG.info("Check SAN value in TLS certificate")
        dummy_san = "*.dummy.com"
        new_node = network.create_node(
            infra.interfaces.HostSpec(
                rpc_interfaces={
                    infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                        endorsement=infra.interfaces.Endorsement(
                            authority=infra.interfaces.EndorsementAuthority.Node
                        )
                    )
                }
            )
        )
        args.subject_alt_names = [f"dNSName:{dummy_san}"]
        network.join_node(new_node, args.package, args)
        sans = infra.crypto.get_san_from_pem_cert(new_node.get_tls_certificate_pem())
        assert len(sans) == 1, "Expected exactly one SAN"
        assert sans[0].value == dummy_san

        LOG.info("A node started with no specified SAN defaults to public RPC host")
        dummy_public_rpc_host = "123.123.123.123"
        args.subject_alt_names = []

        new_node = network.create_node(
            infra.interfaces.HostSpec(
                rpc_interfaces={
                    infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                        public_host=dummy_public_rpc_host,
                        endorsement=infra.interfaces.Endorsement(
                            authority=infra.interfaces.EndorsementAuthority.Node
                        ),
                    )
                }
            )
        )
        network.join_node(new_node, args.package, args)
        # Cannot trust the node here as client cannot authenticate dummy public IP in cert
        with open(
            os.path.join(network.common_dir, f"{new_node.local_node_id}.pem"),
            encoding="utf-8",
        ) as self_signed_cert:
            sans = infra.crypto.get_san_from_pem_cert(self_signed_cert.read())
        assert len(sans) == 1, "Expected exactly one SAN"
        assert sans[0].value == ipaddress.ip_address(dummy_public_rpc_host)


def run_config_timeout_check(args):
    with infra.network.network(
        ["local://localhost"],
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        args.common_read_only_ledger_dir = None  # Reset from previous test
        network.start_and_open(args)
    # This is relatively direct test to make sure the config timeout feature
    # works as intended. It is difficult to do with the existing framework
    # as is because of the indirections and the fact that start() is a
    # synchronous call.
    start_node_path = network.nodes[0].remote.remote.root
    # Remove ledger and pid file to allow a restart
    shutil.rmtree(os.path.join(start_node_path, "0.ledger"))
    os.remove(os.path.join(start_node_path, "node.pid"))
    os.remove(os.path.join(start_node_path, "service_cert.pem"))
    # Move configuration
    shutil.move(
        os.path.join(start_node_path, "0.config.json"),
        os.path.join(start_node_path, "0.config.json.bak"),
    )
    LOG.info("No config at all")
    assert not os.path.exists(os.path.join(start_node_path, "0.config.json"))
    LOG.info(f"Attempt to start node without a config under {start_node_path}")
    proc = subprocess.Popen(
        ["./cchost", "--config", "0.config.json", "--config-timeout", "10s"],
        cwd=start_node_path,
        env={"ASAN_OPTIONS": "alloc_dealloc_mismatch=0"},
    )
    time.sleep(2)
    LOG.info("Copy a partial config")
    # Replace it with a prefix
    with open(os.path.join(start_node_path, "0.config.json"), "w") as f:
        f.write("{")
    time.sleep(2)
    LOG.info("Move a full config back")
    shutil.copy(
        os.path.join(start_node_path, "0.config.json.bak"),
        os.path.join(start_node_path, "0.config.json"),
    )
    time.sleep(10)
    LOG.info("Wait out the rest of the timeout")
    assert proc.poll() is None, "Node process should still be running"
    assert os.path.exists(os.path.join(start_node_path, "service_cert.pem"))
    proc.terminate()
    proc.wait()


def run_sighup_check(args):
    with infra.network.network(
        ["local://localhost"],
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        args.common_read_only_ledger_dir = None  # Reset from previous test
        network.start_and_open(args)
        network.nodes[0].remote.remote.hangup()
        time.sleep(1)
        assert network.nodes[0].remote.check_done(), "Node should have exited"
        out, _ = network.nodes[0].remote.get_logs()
        with open(out, "r") as outf:
            lines = outf.readlines()
        assert any("Hangup: " in line for line in lines), "Hangup should be logged"


def run_configuration_file_checks(args):
    LOG.info(
        f"Verifying JSON configuration samples in {args.config_samples_dir} directory"
    )
    CCHOST_BINARY_NAME = "cchost"

    bin_path = infra.path.build_bin_path(CCHOST_BINARY_NAME, binary_dir=args.binary_dir)

    config_files_to_check = [
        os.path.join(args.config_samples_dir, c)
        for c in os.listdir(args.config_samples_dir)
    ]

    for config in config_files_to_check:
        cmd = [bin_path, f"--config={config}", "--check"]
        rc = infra.proc.ccall(
            *cmd, env={"ASAN_OPTIONS": "alloc_dealloc_mismatch=0"}
        ).returncode
        assert rc == 0, f"Failed to check configuration: {rc}"


def run_pid_file_check(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        args.common_read_only_ledger_dir = None  # Reset from previous test
        network.start_and_open(args)
        LOG.info("Check that pid file exists")
        node = network.nodes[0]
        node.stop()
        # Delete ledger directory, since that too would prevent a restart
        shutil.rmtree(
            os.path.join(node.remote.remote.root, node.remote.ledger_dir_name)
        )
        node.remote.start()
        timeout = 10
        start = time.time()
        LOG.info("Wait for node to shut down")
        while time.time() - start < timeout:
            if node.remote.check_done():
                break
            time.sleep(0.1)
        out, _ = node.remote.get_logs()
        with open(out, "r") as outf:
            last_line = outf.readlines()[-1].strip()
        assert last_line.endswith(
            "PID file node.pid already exists. Exiting."
        ), last_line
        LOG.info("Node shut down for the right reason")
        network.ignoring_shutdown_errors = True


def run(args):
    run_file_operations(args)
    run_tls_san_checks(args)
    run_config_timeout_check(args)
    run_configuration_file_checks(args)
    run_pid_file_check(args)
    run_sighup_check(args)
