# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import pathlib
import unittest

from invariant_proofs import InvariantProofError, action_names, render_proof_source


class InvariantProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (
            pathlib.Path(__file__).with_name("CCFConsistency.lean").read_text(
                encoding="utf-8"
            )
        )

    def test_discovers_model_actions(self):
        actions = action_names(self.source)

        self.assertIn("RwTxExecuteAction", actions)
        self.assertIn("TruncateLedgerAction", actions)
        self.assertNotIn("nextLedgerSlot", actions)

    def test_renders_one_action_with_reconstructed_proofs(self):
        generated = render_proof_source(
            self.source, "RwTxExecuteAction", smt_timeout=90
        )

        self.assertIn("set_option synthInstance.maxHeartbeats 200000", generated)
        self.assertIn("set_option veil.violationIsError true", generated)
        self.assertIn("set_option veil.smt.trust false", generated)
        self.assertIn("set_option veil.printCounterexamples false", generated)
        self.assertIn("set_option veil.smt.timeout 90", generated)
        self.assertIn("#check_action RwTxExecuteAction", generated)
        self.assertNotIn("#gen_theorems", generated)
        self.assertNotIn("Lean.collectAxioms", generated)
        self.assertNotIn("#model_check compiled", generated)

    def test_renders_complete_induction_check(self):
        generated = render_proof_source(self.source)

        self.assertIn("#check_invariants", generated)
        self.assertIn("#gen_theorems", generated)
        self.assertIn("Lean.collectAxioms", generated)
        self.assertIn("axioms.contains ``sorryAx", generated)
        self.assertNotIn("#check_action", generated)

    def test_renders_counterexample_diagnostics(self):
        generated = render_proof_source(
            self.source, "StatusInvalidResponseAction", diagnose=True
        )

        self.assertIn("set_option veil.smt.trust true", generated)
        self.assertIn("set_option veil.printCounterexamples true", generated)
        self.assertIn("#check_action StatusInvalidResponseAction", generated)

    def test_diagnostics_never_generate_theorems(self):
        generated = render_proof_source(self.source, diagnose=True)

        self.assertIn("#check_invariants", generated)
        self.assertNotIn("#gen_theorems", generated)
        self.assertNotIn("Lean.collectAxioms", generated)

    def test_rejects_unknown_action(self):
        with self.assertRaisesRegex(InvariantProofError, "unknown action"):
            render_proof_source(self.source, "MissingAction")

    def test_rejects_non_positive_timeout(self):
        with self.assertRaisesRegex(InvariantProofError, "must be positive"):
            render_proof_source(self.source, smt_timeout=0)


if __name__ == "__main__":
    unittest.main()
