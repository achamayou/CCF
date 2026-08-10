# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import unittest

import trace_validation


def _event(**fields):
    return json.dumps(fields)


def _plan(*events):
    return trace_validation.SHARED.plan_trace(
        trace_validation.SHARED.parse_trace(events)
    )


class PureLeanTraceValidationTests(unittest.TestCase):
    def test_renders_replay_and_reachability_proof(self):
        plan = _plan(
            _event(action="RwTxRequestAction", type="RwTxRequest", tx=0),
            _event(
                action="RwTxExecuteAction",
                type="RwTxExecute",
                tx=0,
                tx_id=[2, 10],
            ),
            _event(
                action="RwTxResponseAction",
                type="RwTxResponse",
                tx=0,
                tx_id=[2, 10],
            ),
            _event(
                action="StatusCommittedResponseAction",
                type="TxStatusReceived",
                tx_id=[2, 10],
                status="CommittedStatus",
            ),
        )

        source = trace_validation.render_trace_source(plan)

        self.assertIn("abbrev Tx := Fin 1", source)
        self.assertIn("abbrev Event := Fin 3", source)
        self.assertIn(
            ".rwTxRequest (traceTx 0) (traceEvent 0), "
            "-- NDJSON line 1: RwTxRequestAction",
            source,
        )
        self.assertIn(
            ".rwTxExecute (traceEvent 0) (traceView 0) (traceSeqno 0)",
            source,
        )
        self.assertIn(
            ".rwTxResponse (traceEvent 0) (traceView 0) "
            "(traceSeqno 0) (traceEvent 1)",
            source,
        )
        self.assertIn(
            ".statusCommittedResponse (traceEvent 1) " "(traceEvent 2) (traceView 0)",
            source,
        )
        self.assertIn("theorem replaySucceeded", source)
        self.assertIn("  decide +kernel", source)
        self.assertNotIn("native_decide", source)
        self.assertIn("replay_from_initial replaySucceeded", source)
        self.assertIn(
            "abbrev initial : State Tx View Seqno Event := initialState",
            source,
        )
        self.assertNotIn("ConcreteState", source)
        self.assertNotIn("ProvedBundle", source)
        self.assertNotIn("reachableProved", source)
        self.assertNotIn("CCFConsistency.Proofs", source)
        self.assertIn("Lean.collectAxioms", source)
        self.assertIn("``implementationTraceReachable", source)
        self.assertIn("Lean.ofReduceBool", source)

    def test_renders_generated_backfill_and_truncation(self):
        plan = _plan(
            _event(action="RwTxRequestAction", type="RwTxRequest", tx=0),
            _event(
                action="RwTxExecuteAction",
                type="RwTxExecute",
                tx=0,
                tx_id=[2, 10],
            ),
            _event(
                action="RwTxResponseAction",
                type="RwTxResponse",
                tx=0,
                tx_id=[2, 10],
            ),
            _event(
                action="StatusCommittedResponseAction",
                type="TxStatusReceived",
                tx_id=[2, 10],
                status="CommittedStatus",
            ),
            _event(action="RwTxRequestAction", type="RwTxRequest", tx=1),
            _event(
                action="RwTxExecuteAction",
                type="RwTxExecute",
                tx=1,
                tx_id=[3, 11],
            ),
        )

        source = trace_validation.render_trace_source(plan)

        self.assertIn(
            ".truncateLedger (traceView 0) (traceSeqno 0) (traceView 1), "
            "-- NDJSON line 6: TruncateLedgerAction",
            source,
        )
        self.assertIn(
            ".rwTxExecute (traceEvent 3) (traceView 1) (traceSeqno 1)",
            source,
        )

    def test_renders_invalid_status_action(self):
        plan = _plan(
            _event(action="RwTxRequestAction", type="RwTxRequest", tx=0),
            _event(
                action="RwTxExecuteAction",
                type="RwTxExecute",
                tx=0,
                tx_id=[2, 10],
            ),
            _event(
                action="RwTxResponseAction",
                type="RwTxResponse",
                tx=0,
                tx_id=[2, 10],
            ),
            _event(action="RwTxRequestAction", type="RwTxRequest", tx=1),
            _event(
                action="RwTxExecuteAction",
                type="RwTxExecute",
                tx=1,
                tx_id=[2, 11],
            ),
            _event(
                action="RwTxResponseAction",
                type="RwTxResponse",
                tx=1,
                tx_id=[2, 11],
            ),
            _event(
                action="StatusCommittedResponseAction",
                type="TxStatusReceived",
                tx_id=[2, 10],
                status="CommittedStatus",
            ),
            _event(
                action="StatusInvalidResponseAction",
                type="TxStatusReceived",
                tx_id=[2, 11],
                status="InvalidStatus",
            ),
        )

        source = trace_validation.render_trace_source(plan)

        self.assertIn(
            ".statusInvalidResponse (traceEvent 3) (traceEvent 5)",
            source,
        )


if __name__ == "__main__":
    unittest.main()
