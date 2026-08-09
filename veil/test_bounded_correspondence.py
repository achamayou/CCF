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
    parse_tlc_output,
    parse_veil_output,
    render_runner_source,
    render_tlc_config,
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
        self.assertIn("tx := Fin 4", generated)
        self.assertIn("view := Fin 3", generated)
        self.assertIn("histEvent := Fin 4", generated)
        self.assertIn("(maxDepth := 12)", generated)
        self.assertNotIn("end CCFConsistency", generated)

    def test_renders_bounded_tlc_config_from_canonical_config(self):
        source = (
            pathlib.Path(__file__).parent.parent
            / "tla"
            / "consistency"
            / "MCMultiNodeReads.cfg"
        ).read_text(encoding="utf-8")

        generated = render_tlc_config(source)

        self.assertIn("HistoryLimit = 4", generated)
        self.assertIn("ViewLimit = 3", generated)
        self.assertNotIn("HistoryLimit = 6", generated)
        self.assertNotIn("ViewLimit = 2", generated)
        self.assertIn("CommittedRwSerializableInv", generated)

    def test_renders_parallel_runner(self):
        generated = render_runner_source("Generated.CCFConsistencyCorrespondence", 12)

        self.assertIn("numSubTasks := 12", generated)
        self.assertIn("IO.asTask (prio := .dedicated)", generated)
        self.assertIn("let finished <- IO.hasFinished checkerTask", generated)
        self.assertIn("Veil progress:", generated)
        self.assertIn("getProgress instanceId", generated)
        self.assertIn("IO.println output.compress", generated)

    def test_compares_matching_graph_summaries(self):
        tlc = """Model checking completed. No error has been found.
3 states generated, 3 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 3.
<MCRwTxRequestAction line 1, col 1 to line 1, col 1 of module Test>: 1:1
<MCTruncateLedgerAction line 2, col 1 to line 2, col 1 of module Test>: 1:1
"""
        depths = {
            1: "1 states generated, 1 distinct states found.\n",
            2: "2 states generated, 2 distinct states found.\n",
            3: "3 states generated, 3 distinct states found.\n",
        }
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
            veil_path = root / "veil.json"
            veil_path.write_text(json.dumps(veil), encoding="utf-8")

            tlc_stats = parse_tlc_output(tlc, depths)
            veil_stats = parse_veil_output(veil_path)
            compare_graphs(tlc_stats, veil_stats)

    def test_reports_graph_difference(self):
        tlc = """Model checking completed. No error has been found.
1 states generated, 1 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 1.
"""
        depths = {1: "1 states generated, 1 distinct states found.\n"}
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
            veil_path = root / "veil.json"
            veil_path.write_text(json.dumps(veil), encoding="utf-8")

            with self.assertRaisesRegex(CorrespondenceError, "generated states"):
                compare_graphs(
                    parse_tlc_output(tlc, depths),
                    parse_veil_output(veil_path),
                )


if __name__ == "__main__":
    unittest.main()
