# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import pathlib
import unittest


class InvariantProofSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (
            pathlib.Path(__file__)
            .with_name("CCFConsistency.lean")
            .read_text(encoding="utf-8")
        )
        before, begin, remainder = cls.source.partition(
            "-- BEGIN CCF VEIL BOUNDED CHECK"
        )
        proof, end, _ = remainder.partition("-- END CCF VEIL BOUNDED CHECK")
        if not begin or not end:
            raise AssertionError("direct proof block is missing")
        cls.before_proof = before
        cls.proof = proof

    def test_checks_every_invariant_directly(self):
        self.assertIn("#check_invariants", self.proof)
        self.assertIn("#gen_theorems", self.proof)
        self.assertNotIn("#check_action", self.proof)
        self.assertNotIn("#model_check", self.proof)

    def test_reconstructs_proofs_without_trusting_smt(self):
        self.assertIn("set_option veil.violationIsError true", self.before_proof)
        self.assertIn("set_option veil.smt.trust false", self.before_proof)
        self.assertIn("set_option veil.printCounterexamples false", self.before_proof)
        self.assertNotIn("trusted invariant", self.source)

    def test_lake_build_loads_cvc5_portably(self):
        lakefile = (
            pathlib.Path(__file__)
            .with_name("lakefile.toml")
            .read_text(encoding="utf-8")
        )
        self.assertIn('dynlibs = ["@cvc5/cvc5:shared"]', lakefile)
        self.assertNotIn("--load-dynlib", lakefile)

    def test_audits_generated_theorems_for_sorry(self):
        self.assertIn("Lean.collectAxioms", self.proof)
        self.assertIn("axioms.contains ``sorryAx", self.proof)
        self.assertIn("no CCFConsistency theorems were audited", self.proof)


if __name__ == "__main__":
    unittest.main()
