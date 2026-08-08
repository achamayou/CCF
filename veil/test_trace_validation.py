# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import pathlib
import unittest

from trace_validation import (
    TraceValidationError,
    parse_trace,
    plan_trace,
    render_trace_source,
)


def _event(**fields):
    return json.dumps(fields)


def _plan(*events):
    return plan_trace(parse_trace(events))


class TraceValidationTests(unittest.TestCase):
    def test_rank_normalises_sparse_write_transaction_ids(self):
        plan = _plan(
            _event(action="RwTxRequestAction", type="RwTxRequest", tx=0),
            _event(
                action="RwTxExecuteAction",
                type="RwTxExecute",
                tx=0,
                tx_id=[2, 197],
            ),
            _event(
                action="RwTxResponseAction",
                type="RwTxResponse",
                tx=0,
                tx_id=[2, 197],
            ),
            _event(
                action="StatusCommittedResponseAction",
                type="TxStatusReceived",
                tx_id=[2, 197],
                status="CommittedStatus",
            ),
            _event(action="RwTxRequestAction", type="RwTxRequest", tx=1),
            _event(
                action="RwTxExecuteAction",
                type="RwTxExecute",
                tx=1,
                tx_id=[2, 199],
            ),
            _event(
                action="RwTxResponseAction",
                type="RwTxResponse",
                tx=1,
                tx_id=[2, 199],
            ),
            _event(
                action="StatusCommittedResponseAction",
                type="TxStatusReceived",
                tx_id=[2, 199],
                status="CommittedStatus",
            ),
        )

        self.assertEqual(plan.tx_count, 2)
        self.assertEqual(plan.view_count, 1)
        self.assertEqual(plan.seqno_count, 2)
        self.assertEqual(plan.history_event_count, 6)
        self.assertFalse(any(step.kind == "filler" for step in plan.steps))
        execute_steps = [
            step for step in plan.steps if step.action == "RwTxExecuteAction"
        ]
        self.assertEqual(execute_steps[0].fields["seqno"], 0)
        self.assertEqual(execute_steps[1].fields["seqno"], 1)

    def test_backfills_read_only_response_head(self):
        plan = _plan(
            _event(action="RwTxRequestAction", type="RwTxRequest", tx=0),
            _event(
                action="RwTxExecuteAction",
                type="RwTxExecute",
                tx=0,
                tx_id=[2, 197],
            ),
            _event(
                action="RwTxResponseAction",
                type="RwTxResponse",
                tx=0,
                tx_id=[2, 197],
            ),
            _event(
                action="StatusCommittedResponseAction",
                type="TxStatusReceived",
                tx_id=[2, 197],
                status="CommittedStatus",
            ),
            _event(action="RoTxRequestAction", type="RoTxRequest", tx=1),
            _event(
                action="RoTxResponseAction",
                type="RoTxResponse",
                tx=1,
                tx_id=[2, 198],
            ),
        )

        fillers = [step for step in plan.steps if step.kind == "filler"]
        self.assertEqual(len(fillers), 1)
        self.assertEqual(fillers[0].action, "AppendOtherTxnAction")
        self.assertEqual(fillers[0].fields, {"view": 0, "seqno": 1})

    def test_copies_current_branch_for_new_view(self):
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
            _event(
                action="RwTxResponseAction",
                type="RwTxResponse",
                tx=1,
                tx_id=[3, 11],
            ),
        )

        fillers = [step for step in plan.steps if step.kind == "filler"]
        self.assertEqual(len(fillers), 1)
        self.assertEqual(fillers[0].action, "TruncateLedgerAction")
        self.assertEqual(
            fillers[0].fields,
            {"source_view": 0, "cut_seqno": 0, "new_view": 1},
        )

    def test_rejects_invalid_status_without_enabling_condition(self):
        events = parse_trace(
            (
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
                _event(
                    action="StatusInvalidResponseAction",
                    type="TxStatusReceived",
                    tx_id=[2, 10],
                    status="InvalidStatus",
                ),
            )
        )
        with self.assertRaisesRegex(
            TraceValidationError, "invalid status is not enabled"
        ):
            plan_trace(events)

    def test_rejects_schema_mismatch(self):
        with self.assertRaisesRegex(TraceValidationError, "requires type"):
            parse_trace(
                (
                    _event(
                        action="RwTxRequestAction",
                        type="RoTxRequest",
                        tx=0,
                    ),
                )
            )

    def test_rejects_response_without_request(self):
        with self.assertRaisesRegex(TraceValidationError, "has no request"):
            _plan(
                _event(
                    action="RoTxResponseAction",
                    type="RoTxResponse",
                    tx=7,
                    tx_id=[2, 10],
                )
            )

    def test_renders_trace_inside_scratch_copy(self):
        plan = _plan(
            _event(action="RwTxRequestAction", type="RwTxRequest", tx=0),
            _event(
                action="RwTxExecuteAction",
                type="RwTxExecute",
                tx=0,
                tx_id=[2, 197],
            ),
            _event(
                action="RwTxResponseAction",
                type="RwTxResponse",
                tx=0,
                tx_id=[2, 197],
            ),
            _event(
                action="StatusCommittedResponseAction",
                type="TxStatusReceived",
                tx_id=[2, 197],
                status="CommittedStatus",
            ),
        )
        source = (
            pathlib.Path(__file__)
            .with_name("CCFConsistency.lean")
            .read_text(encoding="utf-8")
        )

        generated = render_trace_source(source, plan, "sample_trace")

        self.assertIn("theory ghost relation traceEventRank2", generated)
        self.assertIn("def elabCcfTraceBmc", generated)
        self.assertIn("set_option maxHeartbeats 5000000", generated)
        self.assertIn("sat trace [sample_trace] {", generated)
        self.assertIn("  RwTxExecuteAction", generated)
        self.assertIn("assert (", generated)
        self.assertNotIn("action TraceTruncateLedgerAction", generated)
        self.assertNotIn("#model_check compiled", generated)
        self.assertEqual(generated.count("end CCFConsistency"), 1)

    def test_renders_finite_view_copy_for_trace_validation(self):
        testdata = pathlib.Path(__file__).with_name("testdata")
        with (testdata / "valid_trace.ndjson").open(encoding="utf-8") as trace:
            plan = plan_trace(parse_trace(trace))
        source = (
            pathlib.Path(__file__)
            .with_name("CCFConsistency.lean")
            .read_text(encoding="utf-8")
        )

        generated = render_trace_source(source, plan, "view_copy_trace")

        self.assertIn("action TraceTruncateLedgerAction", generated)
        self.assertIn("require traceSeqnoRank2 slot2", generated)
        self.assertIn("if (seqOrder.le slot2 cut) then", generated)
        self.assertIn("entryView newView slot2 := viewOrder.zero", generated)
        self.assertIn("entryTx newView slot2 := txOrder.zero", generated)
        self.assertIn("\n  TraceTruncateLedgerAction\n", generated)
        self.assertNotIn("\n  TruncateLedgerAction\n", generated)


if __name__ == "__main__":
    unittest.main()
