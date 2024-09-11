# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import reconfiguration
import json
import time

from loguru import logger as LOG


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        # Replace primary repeatedly and check the network still operates
        LOG.info(f"Retiring primary {args.rotation_retirements} times")
        for i in range(args.rotation_retirements):
            LOG.warning(f"Retirement {i}")
            reconfiguration.test_add_node(network, args)
            reconfiguration.test_retire_primary(network, args)


def add_nodes_preopen(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start(args)
        for i in range(20):
            LOG.warning(f"Adding node {i}")
            operator_rpc_interface = "operator_rpc_interface"
            host = infra.net.expand_localhost()
            new_node = network.create_node(
                infra.interfaces.HostSpec(
                    rpc_interfaces={
                        infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                            host=host
                        ),
                        operator_rpc_interface: infra.interfaces.RPCInterface(
                            host=host,
                            endorsement=infra.interfaces.Endorsement(
                                authority=infra.interfaces.EndorsementAuthority.Node
                            ),
                        ),
                    }
                )
            )
            network.join_node(new_node, args.package, args, from_snapshot=False)

        def local_node_id(node_id):
            for node in network.nodes:
                if node.node_id == node_id:
                    return node.local_node_id

        acks = None
        for i in range(100):
            with network.nodes[0].client() as c:
                r = c.get("/node/consensus", log_capture=[])
                acks = r.body.json()["details"]["acks"]
                time.sleep(0.01)
                for node_id, ack in acks.items():
                    if ack["seqno"] < 6:
                        LOG.error(f"Node {local_node_id(node_id)} ({node_id}) is behind: {ack['seqno']} < 6")
        for node_id, ack in acks.items():
            assert not ack["seqno"] < 6, f"Node {local_node_id(node_id)} ({node_id}) is behind: {ack['seqno']} < 6"
        LOG.info("All nodes are caught up")
        


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--rotation-retirements",
            help="Number of times to retire the primary",
            type=int,
            default=2,
        )

    args = infra.e2e_args.cli_args(add=add)
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_member_count = 1
    add_nodes_preopen(args)
