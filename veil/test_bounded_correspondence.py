#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import pathlib
import tempfile
import unittest

from bounded_correspondence import (
    CorrespondenceError,
    compare_graphs,
    parse_tlc_dot,
    parse_veil_output,
    render_runner_source,
    render_veil_source,
)


class BoundedCorrespondenceTests(unittest.TestCase):
    def test_renders_action_aligned_internal_model(self):
        source = (
            pathlib.Path(__file__)
            .with_name("CCFConsistency.lean")
            .read_text(encoding="utf-8")
        )

        generated = render_veil_source(source)

        self.assertNotIn("action AppendOtherTxnAction", generated)
        self.assertIn("set_option veil.__modelCheckCompileMode true", generated)
        self.assertIn("tx := Fin 3", generated)
        self.assertIn("view := Fin 2", generated)
        self.assertIn("histEvent := Fin 3", generated)
        self.assertIn("(maxDepth := 8)", generated)
        self.assertNotIn("end CCFConsistency", generated)

    def test_renders_parallel_runner(self):
        generated = render_runner_source("Generated.CCFConsistencyCorrespondence", 12)

        self.assertIn("numSubTasks := 12", generated)
        self.assertIn("getProgress instanceId", generated)
        self.assertIn("IO.println output.compress", generated)

    def test_compares_matching_graph_summaries(self):
        dot = """strict digraph DiskGraph {
1 [label="init",style = filled]
1 -> 2 [label="MCRwTxRequestAction"];
2 [label="request"];
2 -> 3 [label="MCTruncateLedgerAction"];
3 [label="view"];
}
"""
        veil = {
            "result": {
                "result": "no_violation_found",
                "termination_reason": {"kind": "explored_all_reachable_states"},
                "explored_states": 3,
            },
            "progress": {
                "statesFound": 3,
                "distinctStates": 3,
                "history": [
                    {"diameter": 1, "distinctStates": 2},
                    {"diameter": 2, "distinctStates": 3},
                    {"diameter": 3, "distinctStates": 3},
                ],
                "actionStats": [
                    {
                        "name": ("CCFConsistency.Label.RwTxRequestAction 0 0"),
                        "statesGenerated": 1,
                    },
                    {
                        "name": (
                            "CCFConsistency.Label." "TruncateLedgerToEmptyAction 0 1"
                        ),
                        "statesGenerated": 1,
                    },
                ],
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            dot_path = root / "graph.dot"
            veil_path = root / "veil.json"
            dot_path.write_text(dot, encoding="utf-8")
            veil_path.write_text(json.dumps(veil), encoding="utf-8")

            tlc_stats = parse_tlc_dot(dot_path)
            veil_stats = parse_veil_output(veil_path)
            compare_graphs(tlc_stats, veil_stats)

    def test_reports_graph_difference(self):
        dot = """strict digraph DiskGraph {
1 [label="init",style = filled]
}
"""
        veil = {
            "result": {
                "result": "no_violation_found",
                "termination_reason": {"kind": "explored_all_reachable_states"},
            },
            "progress": {
                "statesFound": 2,
                "distinctStates": 2,
                "history": [],
                "actionStats": [],
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            dot_path = root / "graph.dot"
            veil_path = root / "veil.json"
            dot_path.write_text(dot, encoding="utf-8")
            veil_path.write_text(json.dumps(veil), encoding="utf-8")

            with self.assertRaisesRegex(CorrespondenceError, "generated states"):
                compare_graphs(parse_tlc_dot(dot_path), parse_veil_output(veil_path))


if __name__ == "__main__":
    unittest.main()
