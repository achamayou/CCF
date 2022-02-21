# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.proc
import infra.net
import suite.test_requirements as reqs
import infra.e2e_args
import subprocess
import os
import difflib
import re


def compare_golden():
    script_path = os.path.realpath(__file__)
    script_dir = os.path.dirname(script_path)
    golden_file = os.path.join(script_dir, "tls_report.csv")
    print(f"Comparing output to golden file: {golden_file}")

    # Read both files into arrays
    with open(golden_file, encoding="utf-8") as g:
        golden = g.readlines()
    with open("tls_report.csv", encoding="utf-8") as o:
        output = o.readlines()

    # Golden file is clean of random output (IP address, hashes)
    # New log needs to clean of random output
    reIPADDR = re.compile(r"\d+\.\d+\.\d+\.\d+")
    reIPPORT = re.compile(r"\d+\.\d+\.\d+\.\d+/\d+\.\d+\.\d+\.\d+\",\"\d+")
    reDATETIME = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}")
    reHASH = re.compile(r"[0-9A-F]{30,}")
    reCERT = re.compile(r"BEGIN CERTIFICATE.*END CERTIFICATE")
    reSERIAL = re.compile(r".*cert_serialNumberLen.*")
    filtered = []
    for line in output:
        line = re.sub(reIPPORT, "", line)
        line = re.sub(reIPADDR, "", line)
        line = re.sub(reDATETIME, "", line)
        line = re.sub(reHASH, "", line)
        line = re.sub(reCERT, "", line)
        if re.match(reSERIAL, line):
            # Length of serial number may vary if last bytes are zeros
            # so ignore it altogether
            line = re.sub(r"[1-9][0-9]", "", line)
        filtered.append(line)

    # Diff stable output on both files
    success = True
    for line in difflib.unified_diff(
        golden, filtered, fromfile="Golden", tofile="Output", lineterm=""
    ):
        print(line)
        success = False

    # If not the same, write to a new report
    # to make it easier to update the golden file
    if success:
        print("Comparison successful")
    else:
        dump_file = "new_tls_report.csv"
        print(f"Comparison failed. Dumping the current output to {dump_file}")
        with open(dump_file, "w+", encoding="UTF-8") as out:
            print(f"To update the golden file, run: mv {dump_file} {golden_file}")
            out.writelines(filtered)

    return success


def cond_removal(file):
    if os.path.exists(file):
        os.remove(file)


@reqs.description("Running TLS test against CCF")
@reqs.at_least_n_nodes(1)
def test(network, args):
    node = network.nodes[0]
    endpoint = f"https://{node.get_public_rpc_host()}:{node.get_public_rpc_port()}"
    cond_removal("tls_report.csv")
    cond_removal("tls_report.html")
    cond_removal("tls_report.json")
    cond_removal("tls_report.log")
    r = subprocess.run(
        ["testssl/testssl.sh", "--outfile", "tls_report", endpoint], check=False
    )
    assert r.returncode == 0
    assert compare_golden()


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        test(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.nodes(args, 1)
    run(args)
