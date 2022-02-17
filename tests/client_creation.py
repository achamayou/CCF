# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.node
import infra.logging_app as app
import infra.checker
import suite.test_requirements as reqs
import ccf.split_ledger
import ccf.ledger
import os
import random
import time

from loguru import logger as LOG

def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_join(args)

        primary, _ = network.find_primary()

        start = time.time()
        it = 1000
        for i in range(it):
            with primary.client() as nc:
                #nc.get("/node/commit", log_capture=[]).body.text
                nc.get("/foo", log_capture=[]).body.text
        end = time.time()
        print(f"Elapsed: {end - start} seconds")
        print(f"{(end - start) / it} avg rtt")
        print(f"{it / (end - start)} connections/sec")

if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=0)


    run(args)
