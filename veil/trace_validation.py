# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import dataclasses
import hashlib
import json
import pathlib
import re
import sys
from collections.abc import Iterable
from typing import Any, TextIO

REQUEST_ACTIONS = {
    "RwTxRequestAction": ("RwTxRequest", "rw"),
    "RoTxRequestAction": ("RoTxRequest", "ro"),
}
RESPONSE_ACTIONS = {
    "RwTxResponseAction": ("RwTxResponse", "rw"),
    "RoTxResponseAction": ("RoTxResponse", "ro"),
}
STATUS_ACTIONS = {
    "StatusCommittedResponseAction": ("CommittedStatus", "CommittedStatus"),
    "StatusInvalidResponseAction": ("InvalidStatus", "InvalidStatus"),
}
EXECUTE_ACTION = "RwTxExecuteAction"
TRACE_TRUNCATE_ACTION = "TraceTruncateLedgerAction"
MODEL_CHECK_BEGIN = "-- BEGIN CCF VEIL BOUNDED CHECK"
MODEL_CHECK_END = "-- END CCF VEIL BOUNDED CHECK"
TRACE_BMC_MAX_STEPS = 1_000_000
TRACE_MAX_HEARTBEATS = 5_000_000
EXISTS = chr(0x2203)
FOR_ALL = chr(0x2200)
LEFT_ARROW = chr(0x2190)
SIMPROC = chr(0x2193)


class TraceValidationError(ValueError):
    """Raised when a consistency trace cannot be represented by the Veil model."""


@dataclasses.dataclass(frozen=True)
class TraceEvent:
    """A schema-checked implementation trace event."""

    line_number: int
    action: str
    event_type: str
    tx: int | None = None
    tx_id: tuple[int, int] | None = None
    status: str | None = None


@dataclasses.dataclass(frozen=True)
class LedgerEntry:
    """A rank-normalised ledger entry used while planning trace backfill."""

    entry_view: int
    client_tx: int | None


@dataclasses.dataclass(frozen=True)
class PlanStep:
    """A logged or generated action in a normalised trace plan."""

    kind: str
    action: str
    source_line: int | None
    fields: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class TracePlan:
    """Finite-domain sizes and actions needed to replay a trace."""

    tx_count: int
    view_count: int
    seqno_count: int
    history_event_count: int
    steps: tuple[PlanStep, ...]

    def to_json(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of this plan."""

        return dataclasses.asdict(self)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_int(value: object, field: str, line_number: int, *, minimum: int) -> int:
    if not _is_int(value) or value < minimum:
        raise TraceValidationError(
            f"line {line_number}: {field} must be an integer >= {minimum}"
        )
    return value


def _parse_tx_id(value: object, line_number: int) -> tuple[int, int]:
    if not isinstance(value, list) or len(value) != 2:
        raise TraceValidationError(
            f"line {line_number}: tx_id must be a two-element array"
        )
    return (
        _require_int(value[0], "tx_id view", line_number, minimum=1),
        _require_int(value[1], "tx_id seqno", line_number, minimum=1),
    )


def _check_keys(value: dict[str, object], expected: set[str], line_number: int) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing {missing}")
        if unexpected:
            details.append(f"unexpected {unexpected}")
        raise TraceValidationError(
            f"line {line_number}: invalid fields ({', '.join(details)})"
        )


def _require_string(value: object, field: str, line_number: int) -> str:
    if not isinstance(value, str):
        raise TraceValidationError(f"line {line_number}: {field} must be a string")
    return value


def _parse_event(value: object, line_number: int) -> TraceEvent:
    if not isinstance(value, dict):
        raise TraceValidationError(f"line {line_number}: expected a JSON object")

    action = _require_string(value.get("action"), "action", line_number)
    if action in REQUEST_ACTIONS:
        _check_keys(value, {"action", "type", "tx"}, line_number)
        expected_type, _ = REQUEST_ACTIONS[action]
        event_type = _require_string(value["type"], "type", line_number)
        if event_type != expected_type:
            raise TraceValidationError(
                f"line {line_number}: {action} requires type {expected_type}"
            )
        return TraceEvent(
            line_number=line_number,
            action=action,
            event_type=event_type,
            tx=_require_int(value["tx"], "tx", line_number, minimum=0),
        )

    if action == EXECUTE_ACTION:
        _check_keys(value, {"action", "type", "tx", "tx_id"}, line_number)
        event_type = _require_string(value["type"], "type", line_number)
        if event_type != "RwTxExecute":
            raise TraceValidationError(
                f"line {line_number}: {action} requires type RwTxExecute"
            )
        return TraceEvent(
            line_number=line_number,
            action=action,
            event_type=event_type,
            tx=_require_int(value["tx"], "tx", line_number, minimum=0),
            tx_id=_parse_tx_id(value["tx_id"], line_number),
        )

    if action in RESPONSE_ACTIONS:
        _check_keys(value, {"action", "type", "tx", "tx_id"}, line_number)
        expected_type, _ = RESPONSE_ACTIONS[action]
        event_type = _require_string(value["type"], "type", line_number)
        if event_type != expected_type:
            raise TraceValidationError(
                f"line {line_number}: {action} requires type {expected_type}"
            )
        return TraceEvent(
            line_number=line_number,
            action=action,
            event_type=event_type,
            tx=_require_int(value["tx"], "tx", line_number, minimum=0),
            tx_id=_parse_tx_id(value["tx_id"], line_number),
        )

    if action in STATUS_ACTIONS:
        _check_keys(value, {"action", "type", "tx_id", "status"}, line_number)
        expected_status, status = STATUS_ACTIONS[action]
        event_type = _require_string(value["type"], "type", line_number)
        if event_type != "TxStatusReceived":
            raise TraceValidationError(
                f"line {line_number}: {action} requires type TxStatusReceived"
            )
        actual_status = _require_string(value["status"], "status", line_number)
        if actual_status != expected_status:
            raise TraceValidationError(
                f"line {line_number}: {action} requires status {expected_status}"
            )
        return TraceEvent(
            line_number=line_number,
            action=action,
            event_type=event_type,
            tx_id=_parse_tx_id(value["tx_id"], line_number),
            status=status,
        )

    raise TraceValidationError(f"line {line_number}: unsupported action {action!r}")


def parse_trace(lines: Iterable[str]) -> tuple[TraceEvent, ...]:
    """Parse and schema-check an NDJSON consistency trace."""

    events = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            raise TraceValidationError(f"line {line_number}: blank lines are not valid")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TraceValidationError(
                f"line {line_number}: invalid JSON: {exc.msg}"
            ) from exc
        events.append(_parse_event(value, line_number))
    if not events:
        raise TraceValidationError("trace is empty")
    return tuple(events)


def _normalise_domains(
    events: tuple[TraceEvent, ...],
) -> tuple[dict[int, int], dict[int, int], dict[int, int]]:
    request_txs = [event.tx for event in events if event.action in REQUEST_ACTIONS]
    if len(request_txs) != len(set(request_txs)):
        raise TraceValidationError("transaction request IDs must be unique")

    tx_rank = {tx: rank for rank, tx in enumerate(request_txs)}
    tx_ids = [event.tx_id for event in events if event.tx_id is not None]
    views = sorted({tx_id[0] for tx_id in tx_ids})
    seqnos = sorted({tx_id[1] for tx_id in tx_ids})
    return (
        tx_rank,
        {view: rank for rank, view in enumerate(views)},
        {seqno: rank for rank, seqno in enumerate(seqnos)},
    )


class _Planner:
    def __init__(
        self,
        tx_rank: dict[int, int],
        view_rank: dict[int, int],
        seqno_rank: dict[int, int],
    ) -> None:
        self.tx_rank = tx_rank
        self.view_rank = view_rank
        self.seqno_rank = seqno_rank
        self.steps: list[PlanStep] = []
        self.branches: list[list[LedgerEntry]] = [[]]
        self.requests: dict[int, str] = {}
        self.executed: set[int] = set()
        self.responded: set[int] = set()
        self.rw_response_tx_ids: set[tuple[int, int]] = set()
        self.committed: set[tuple[int, int]] = set()
        self.invalid: set[tuple[int, int]] = set()

    def _normalised_tx(self, event: TraceEvent) -> int:
        assert event.tx is not None
        try:
            return self.tx_rank[event.tx]
        except KeyError as exc:
            raise TraceValidationError(
                f"line {event.line_number}: transaction {event.tx} has no request"
            ) from exc

    def _normalised_tx_id(self, event: TraceEvent) -> tuple[int, int]:
        assert event.tx_id is not None
        return (
            self.view_rank[event.tx_id[0]],
            self.seqno_rank[event.tx_id[1]],
        )

    def _add_filler(self, action: str, source_line: int, **fields: Any) -> None:
        self.steps.append(
            PlanStep(
                kind="filler",
                action=action,
                source_line=source_line,
                fields=fields,
            )
        )

    def _ensure_view(self, target: int, source_line: int) -> None:
        while len(self.branches) <= target:
            source = len(self.branches) - 1
            new_view = len(self.branches)
            source_branch = self.branches[source]
            if source_branch:
                self._add_filler(
                    "TruncateLedgerAction",
                    source_line,
                    source_view=source,
                    cut_seqno=len(source_branch) - 1,
                    new_view=new_view,
                )
            else:
                if self.committed:
                    raise TraceValidationError(
                        f"line {source_line}: cannot create an empty view after commit"
                    )
                self._add_filler(
                    "TruncateLedgerToEmptyAction",
                    source_line,
                    source_view=source,
                    new_view=new_view,
                )
            self.branches.append(list(source_branch))

    def _ensure_length(self, view: int, target_length: int, source_line: int) -> None:
        branch = self.branches[view]
        if len(branch) > target_length:
            raise TraceValidationError(
                f"line {source_line}: view rank {view} already has length "
                f"{len(branch)}, expected at most {target_length}"
            )
        while len(branch) < target_length:
            slot = len(branch)
            branch.append(LedgerEntry(entry_view=view, client_tx=None))
            self._add_filler(
                "AppendOtherTxnAction",
                source_line,
                view=view,
                seqno=slot,
            )

    def _add_trace_step(self, event: TraceEvent, **fields: Any) -> None:
        self.steps.append(
            PlanStep(
                kind="trace",
                action=event.action,
                source_line=event.line_number,
                fields=fields,
            )
        )

    def _plan_request(self, event: TraceEvent) -> None:
        tx = self._normalised_tx(event)
        expected_rank = len(self.requests)
        if tx != expected_rank:
            raise TraceValidationError(
                f"line {event.line_number}: requests do not follow transaction order"
            )
        _, request_kind = REQUEST_ACTIONS[event.action]
        self.requests[tx] = request_kind
        self._add_trace_step(event, tx=tx)

    def _plan_execute(self, event: TraceEvent) -> None:
        tx = self._normalised_tx(event)
        if self.requests.get(tx) != "rw":
            raise TraceValidationError(
                f"line {event.line_number}: write execution has no write request"
            )
        if tx in self.executed:
            raise TraceValidationError(
                f"line {event.line_number}: transaction was already executed"
            )
        view, seqno = self._normalised_tx_id(event)
        self._ensure_view(view, event.line_number)
        self._ensure_length(view, seqno, event.line_number)
        if any(entry.client_tx == tx for branch in self.branches for entry in branch):
            raise TraceValidationError(
                f"line {event.line_number}: transaction already appears in a ledger"
            )
        self._add_trace_step(event, tx=tx, view=view, seqno=seqno)
        self.branches[view].append(LedgerEntry(entry_view=view, client_tx=tx))
        self.executed.add(tx)

    def _plan_rw_response(self, event: TraceEvent) -> None:
        tx = self._normalised_tx(event)
        if self.requests.get(tx) != "rw" or tx not in self.executed:
            raise TraceValidationError(
                f"line {event.line_number}: write response has no execution"
            )
        if tx in self.responded:
            raise TraceValidationError(
                f"line {event.line_number}: transaction already has a response"
            )
        view, seqno = self._normalised_tx_id(event)
        if not any(
            len(branch) > seqno
            and branch[seqno].entry_view == view
            and branch[seqno].client_tx == tx
            for branch in self.branches
        ):
            raise TraceValidationError(
                f"line {event.line_number}: response transaction ID is not in a ledger"
            )
        self.responded.add(tx)
        self.rw_response_tx_ids.add((view, seqno))
        self._add_trace_step(event, tx=tx, view=view, seqno=seqno)

    def _plan_ro_response(self, event: TraceEvent) -> None:
        tx = self._normalised_tx(event)
        if self.requests.get(tx) != "ro":
            raise TraceValidationError(
                f"line {event.line_number}: read response has no read request"
            )
        if tx in self.responded:
            raise TraceValidationError(
                f"line {event.line_number}: transaction already has a response"
            )
        view, seqno = self._normalised_tx_id(event)
        self._ensure_view(view, event.line_number)
        self._ensure_length(view, seqno + 1, event.line_number)
        if self.branches[view][seqno].entry_view != view:
            raise TraceValidationError(
                f"line {event.line_number}: read response head has another view"
            )
        self.responded.add(tx)
        self._add_trace_step(event, tx=tx, view=view, seqno=seqno)

    def _plan_committed_status(self, event: TraceEvent) -> None:
        tx_id = self._normalised_tx_id(event)
        if tx_id not in self.rw_response_tx_ids:
            raise TraceValidationError(
                f"line {event.line_number}: committed status has no write response"
            )
        view, seqno = tx_id
        latest = self.branches[-1]
        if len(latest) <= seqno or latest[seqno].entry_view != view:
            raise TraceValidationError(
                f"line {event.line_number}: transaction cannot commit on latest view"
            )
        if any(
            invalid_view == view and invalid_seqno <= seqno
            for invalid_view, invalid_seqno in self.invalid
        ):
            raise TraceValidationError(
                f"line {event.line_number}: prior invalid status blocks commit"
            )
        self.committed.add(tx_id)
        self._add_trace_step(event, view=view, seqno=seqno)

    def _plan_invalid_status(self, event: TraceEvent) -> None:
        tx_id = self._normalised_tx_id(event)
        if tx_id not in self.rw_response_tx_ids:
            raise TraceValidationError(
                f"line {event.line_number}: invalid status has no write response"
            )
        view, seqno = tx_id
        current_view = len(self.branches) - 1
        latest = self.branches[current_view]
        commit_seqno = max((s for _, s in self.committed), default=-1)
        commit_passed_with_other_view = (
            commit_seqno >= seqno
            and len(latest) > seqno
            and latest[seqno].entry_view != view
        )
        commit_is_in_newer_view = (
            0 <= commit_seqno < seqno
            and len(latest) > commit_seqno
            and latest[commit_seqno].entry_view > view
        )
        current_suffix = view == current_view and seqno > commit_seqno
        if not (
            commit_passed_with_other_view or commit_is_in_newer_view or current_suffix
        ):
            raise TraceValidationError(
                f"line {event.line_number}: invalid status is not enabled"
            )
        self.invalid.add(tx_id)
        self._add_trace_step(event, view=view, seqno=seqno)

    def plan_event(self, event: TraceEvent) -> None:
        if event.action in REQUEST_ACTIONS:
            self._plan_request(event)
        elif event.action == EXECUTE_ACTION:
            self._plan_execute(event)
        elif event.action == "RwTxResponseAction":
            self._plan_rw_response(event)
        elif event.action == "RoTxResponseAction":
            self._plan_ro_response(event)
        elif event.action == "StatusCommittedResponseAction":
            self._plan_committed_status(event)
        elif event.action == "StatusInvalidResponseAction":
            self._plan_invalid_status(event)
        else:
            raise AssertionError(f"unhandled action {event.action}")


def plan_trace(events: tuple[TraceEvent, ...]) -> TracePlan:
    """Rank-normalise a trace and plan the exact unlogged backfill actions."""

    tx_rank, view_rank, seqno_rank = _normalise_domains(events)
    planner = _Planner(tx_rank, view_rank, seqno_rank)
    for event in events:
        planner.plan_event(event)
    history_event_count = sum(event.action != EXECUTE_ACTION for event in events)
    return TracePlan(
        tx_count=max(1, len(tx_rank)),
        view_count=max(1, len(view_rank)),
        seqno_count=max(1, len(seqno_rank)),
        history_event_count=max(1, history_event_count),
        steps=tuple(planner.steps),
    )


def _conjoin(parts: list[str]) -> str:
    if not parts:
        raise ValueError("a conjunction must contain at least one term")
    result = parts[-1]
    for part in reversed(parts[:-1]):
        result = f"And ({part}) ({result})"
    return result


def _disjoin(parts: list[str]) -> str:
    if not parts:
        raise ValueError("a disjunction must contain at least one term")
    result = parts[-1]
    for part in reversed(parts[:-1]):
        result = f"Or ({part}) ({result})"
    return result


def _rank(prefix: str, rank: int, value: str) -> str:
    return f"trace{prefix}Rank{rank} {value}"


def _rank_helpers(
    type_name: str,
    prefix: str,
    order_name: str,
    less_than_name: str,
    count: int,
) -> list[str]:
    helpers = [
        (
            f"theory ghost relation trace{prefix}Rank0 "
            f"(value : {type_name}) :=\n"
            f"  value = {order_name}.zero"
        )
    ]
    for rank in range(1, count):
        body = f"{EXISTS} previous, " + _conjoin(
            [
                _rank(prefix, rank - 1, "previous"),
                f"{less_than_name} previous value",
                (
                    f"{FOR_ALL} candidate, "
                    f"{less_than_name} previous candidate -> "
                    f"{order_name}.le value candidate"
                ),
            ]
        )
        helpers.append(
            f"theory ghost relation trace{prefix}Rank{rank} "
            f"(value : {type_name}) :=\n"
            f"  {body}"
        )
    return helpers


def _exists(bindings: str, body: str) -> str:
    return f"{EXISTS} {bindings}, {body}"


def _for_all(bindings: str, body: str) -> str:
    return f"{FOR_ALL} {bindings}, {body}"


def _assert_line(formula: str) -> str:
    return f"  assert ({formula})"


def _event_assertion(history_rank: int, relation: str, fields: dict[str, Any]) -> str:
    terms = [_rank("Event", history_rank, "e"), f"{relation} e"]
    if "tx" in fields:
        terms.append(_rank("Tx", fields["tx"], "(eventTx e)"))
    if "view" in fields:
        terms.append(_rank("View", fields["view"], "(eventView e)"))
    if "seqno" in fields:
        terms.append(_rank("Seqno", fields["seqno"], "(eventSeqno e)"))
    return _exists("e", _conjoin(terms))


def _append_other_lines(step: PlanStep) -> list[str]:
    view = step.fields["view"]
    seqno = step.fields["seqno"]
    identity = [
        _rank("View", view, "branch"),
        _rank("Seqno", seqno, "slot"),
    ]
    return [
        _assert_line(
            _exists(
                "branch slot",
                _conjoin(identity + ["Not (ledgerEntry branch slot)"]),
            )
        ),
        f"  {step.action}",
        _assert_line(
            _exists(
                "branch slot",
                _conjoin(
                    identity
                    + [
                        "ledgerEntry branch slot",
                        "Not (clientEntry branch slot)",
                        "entryView branch slot = branch",
                    ]
                ),
            )
        ),
    ]


def _truncate_lines(step: PlanStep) -> list[str]:
    source_view = step.fields["source_view"]
    new_view = step.fields["new_view"]
    source_terms = [
        _rank("View", source_view, "source"),
        _rank("View", new_view, "newView"),
        "currentView source",
        "Not (activeView newView)",
    ]
    if step.action == "TruncateLedgerAction":
        cut_seqno = step.fields["cut_seqno"]
        before = _exists(
            "source newView cut",
            _conjoin(
                source_terms
                + [
                    _rank("Seqno", cut_seqno, "cut"),
                    "lastLedgerSlot source cut",
                ]
            ),
        )
        rows_match = _for_all(
            "slot",
            _conjoin(
                [
                    "ledgerEntry newView slot = ledgerEntry source slot",
                    "clientEntry newView slot = clientEntry source slot",
                    (
                        "ledgerEntry newView slot -> "
                        + _conjoin(
                            [
                                "entryView newView slot = entryView source slot",
                                "entryTx newView slot = entryTx source slot",
                            ]
                        )
                    ),
                ]
            ),
        )
        after_terms = [
            _rank("View", source_view, "source"),
            _rank("View", new_view, "newView"),
            "activeView newView",
            rows_match,
        ]
    else:
        before = _exists("source newView", _conjoin(source_terms))
        empty = _for_all("slot", "Not (ledgerEntry newView slot)")
        after_terms = [
            _rank("View", new_view, "newView"),
            "activeView newView",
            empty,
        ]

    return [
        _assert_line(before),
        (
            f"  {TRACE_TRUNCATE_ACTION}"
            if step.action == "TruncateLedgerAction"
            else f"  {step.action}"
        ),
        _assert_line(_exists("source newView", _conjoin(after_terms))),
    ]


def _execute_lines(step: PlanStep) -> list[str]:
    tx = step.fields["tx"]
    view = step.fields["view"]
    seqno = step.fields["seqno"]
    before = _exists(
        "t branch slot",
        _conjoin(
            [
                _rank("Tx", tx, "t"),
                _rank("View", view, "branch"),
                _rank("Seqno", seqno, "slot"),
                "activeView branch",
                "nextLedgerSlot branch slot",
                "Not (txInLedger t)",
            ]
        ),
    )
    after = _exists("t", _conjoin([_rank("Tx", tx, "t"), "txInLedger t"]))
    return [_assert_line(before), f"  {step.action}", _assert_line(after)]


def _ro_response_precondition(step: PlanStep) -> str:
    return _exists(
        "branch slot",
        _conjoin(
            [
                _rank("View", step.fields["view"], "branch"),
                _rank("Seqno", step.fields["seqno"], "slot"),
                "lastLedgerSlot branch slot",
            ]
        ),
    )


def _render_trace_query(plan: TracePlan, trace_name: str) -> str:
    relation_by_action = {
        "RwTxRequestAction": "rwRequestEvent",
        "RoTxRequestAction": "roRequestEvent",
        "RwTxResponseAction": "rwResponseEvent",
        "RoTxResponseAction": "roResponseEvent",
        "StatusCommittedResponseAction": "committedStatusEvent",
        "StatusInvalidResponseAction": "invalidStatusEvent",
    }
    lines = [f"sat trace [{trace_name}] {{"]
    history_rank = 0
    for step in plan.steps:
        if step.kind == "filler":
            if step.action == "AppendOtherTxnAction":
                lines.extend(_append_other_lines(step))
            else:
                lines.extend(_truncate_lines(step))
            continue

        if step.action == EXECUTE_ACTION:
            lines.extend(_execute_lines(step))
            continue

        if step.action == "RoTxResponseAction":
            lines.append(_assert_line(_ro_response_precondition(step)))
        lines.append(f"  {step.action}")
        lines.append(
            _assert_line(
                _event_assertion(
                    history_rank,
                    relation_by_action[step.action],
                    step.fields,
                )
            )
        )
        history_rank += 1

    if history_rank != plan.history_event_count:
        raise AssertionError("planned history event count is inconsistent")
    lines.append(_assert_line(_for_all("e", "eventUsed e")))
    lines.append("}")
    return "\n".join(lines)


def _trace_bmc_override() -> str:
    return f"""open Lean Elab Tactic

@[tactic Veil.veil_bmc]
def elabCcfTraceBmc : Tactic := fun stx => do
  let result : Veil.DesugarTacticM Unit := Veil.veilWithMainContext do
    let dsimpLemmas := #[
      mkIdent ``Inhabited.default,
      Veil.fieldAbstractDispatcher,
      Veil.fieldLabelToDomain Veil.stateName,
      Veil.fieldLabelToCodomain Veil.stateName]
    let dsimpTac {LEFT_ARROW} `(tactic| try dsimp [$[$dsimpLemmas:ident],*])
    let nextSimp := mkIdent `nextSimp
    let existsQuantifierSimpGuarded :=
      mkIdent ``Veil.existsQuantifierSimpGuarded
    let smtSimp := mkIdent `smtSimp
    let tac {LEFT_ARROW} `(tacticSeq|
      skip
      veil_simp
        (config := {{ maxSteps := {TRACE_BMC_MAX_STEPS}, failIfUnchanged := false }})
        only [$nextSimp:ident]
      veil_simp
        (config := {{ maxSteps := {TRACE_BMC_MAX_STEPS}, failIfUnchanged := false }})
        only [{SIMPROC} $existsQuantifierSimpGuarded:ident]
      veil_intros
      skip
      veil_destruct
      $dsimpTac:tactic
      veil_simp
        (config := {{ maxSteps := {TRACE_BMC_MAX_STEPS}, failIfUnchanged := false }})
        only [$smtSimp:ident]
      $dsimpTac:tactic
      veil_smt)
    Veil.veilEvalTactic tac
  result.runByOption stx"""


def _trace_truncate_action(seqno_count: int) -> str:
    slots = [f"slot{rank}" for rank in range(seqno_count)]
    parameters = " ".join(f"({slot} : seqno)" for slot in slots)
    exhaustive = _disjoin([f"slot = {slot}" for slot in slots])
    lines = [
        f"action {TRACE_TRUNCATE_ACTION}",
        "    (source : view) (cut : seqno) (newView : view)",
        f"    {parameters} {{",
        "  require activeView source",
        "  require ledgerEntry source cut",
        "  require validTruncationSource source cut",
        "  require nextView newView",
    ]
    lines.extend(
        f"  require traceSeqnoRank{rank} {slot}" for rank, slot in enumerate(slots)
    )
    lines.extend(
        [
            f"  require {FOR_ALL} slot, {exhaustive}",
            "",
            "  activeView newView := true",
        ]
    )
    for slot in slots:
        lines.extend(
            [
                "",
                f"  if (seqOrder.le {slot} cut) then",
                f"    ledgerEntry newView {slot} := ledgerEntry source {slot}",
                f"    clientEntry newView {slot} := clientEntry source {slot}",
                f"    entryView newView {slot} := entryView source {slot}",
                f"    entryTx newView {slot} := entryTx source {slot}",
                "  else",
                f"    ledgerEntry newView {slot} := false",
                f"    clientEntry newView {slot} := false",
                f"    entryView newView {slot} := viewOrder.zero",
                f"    entryTx newView {slot} := txOrder.zero",
            ]
        )
    lines.append("}")
    return "\n".join(lines)


def render_trace_source(
    source: str, plan: TracePlan, trace_name: str | None = None
) -> str:
    """Inject a planned `sat trace` query into a scratch copy of the Veil spec."""

    if source.count("#gen_spec") != 1:
        raise TraceValidationError("Veil source must contain exactly one #gen_spec")
    if source.count(MODEL_CHECK_BEGIN) != 1 or source.count(MODEL_CHECK_END) != 1:
        raise TraceValidationError("Veil source is missing bounded-check markers")
    import_marker = "import Veil\n"
    if source.count(import_marker) != 1:
        raise TraceValidationError("Veil source must contain exactly one Veil import")

    if trace_name is None:
        encoded_plan = json.dumps(
            plan.to_json(), sort_keys=True, separators=(",", ":")
        ).encode()
        trace_name = f"ndjson_{hashlib.sha256(encoded_plan).hexdigest()[:12]}"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", trace_name) is None:
        raise TraceValidationError(
            f"trace name {trace_name!r} is not a valid Lean identifier"
        )

    helper_groups = [
        _rank_helpers("tx", "Tx", "txOrder", "txLt", plan.tx_count),
        _rank_helpers("view", "View", "viewOrder", "viewLt", plan.view_count),
        _rank_helpers("seqno", "Seqno", "seqOrder", "seqLt", plan.seqno_count),
        _rank_helpers(
            "histEvent",
            "Event",
            "eventOrder",
            "eventLt",
            plan.history_event_count,
        ),
    ]
    helpers = "\n\n".join(
        declaration for group in helper_groups for declaration in group
    )
    declarations = [helpers]
    if any(step.action == "TruncateLedgerAction" for step in plan.steps):
        declarations.append(_trace_truncate_action(plan.seqno_count))
    generated_declarations = "\n\n".join(declarations)
    source = source.replace(
        "#gen_spec",
        (
            f"set_option maxHeartbeats {TRACE_MAX_HEARTBEATS}\n\n"
            f"{generated_declarations}\n\n#gen_spec"
        ),
        1,
    )
    source = source.replace(
        import_marker,
        f"{import_marker}\n{_trace_bmc_override()}\n\n",
        1,
    )

    before, marker, remainder = source.partition(MODEL_CHECK_BEGIN)
    if not marker:
        raise TraceValidationError("bounded-check start marker was not found")
    _, marker, after = remainder.partition(MODEL_CHECK_END)
    if not marker:
        raise TraceValidationError("bounded-check end marker was not found")
    query = _render_trace_query(plan, trace_name)
    return (
        before
        + "-- Generated implementation trace query.\n"
        + "set_option veil.smt.trust true\n"
        + f"set_option maxHeartbeats {TRACE_MAX_HEARTBEATS}\n\n"
        + query
        + "\n"
        + after.lstrip("\n")
    )


def _write_plan(plan: TracePlan, output: TextIO) -> None:
    json.dump(plan.to_json(), output, indent=2)
    output.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Schema-check and rank-normalise a CCF consistency NDJSON trace, "
            "including the unlogged ledger/view backfill needed by the Veil model"
        )
    )
    parser.add_argument("trace", type=pathlib.Path, help="input NDJSON trace")
    parser.add_argument(
        "-o", "--output", type=pathlib.Path, help="output JSON plan (default: stdout)"
    )
    parser.add_argument(
        "--lean-output",
        type=pathlib.Path,
        help="write a scratch Veil source containing a build-gated sat trace",
    )
    parser.add_argument(
        "--spec",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("CCFConsistency.lean"),
        help="source Veil specification to copy when using --lean-output",
    )
    parser.add_argument(
        "--trace-name",
        help="Lean identifier for the generated trace query (default: plan hash)",
    )
    args = parser.parse_args()

    try:
        with args.trace.open(encoding="utf-8") as trace_file:
            plan = plan_trace(parse_trace(trace_file))
        if args.lean_output is not None:
            source = args.spec.read_text(encoding="utf-8")
            generated = render_trace_source(source, plan, args.trace_name)
            args.lean_output.parent.mkdir(parents=True, exist_ok=True)
            args.lean_output.write_text(generated, encoding="utf-8", newline="\n")
        if args.output is None and args.lean_output is None:
            _write_plan(plan, sys.stdout)
        elif args.output is not None:
            with args.output.open("w", encoding="utf-8", newline="\n") as output:
                _write_plan(plan, output)
    except (OSError, TraceValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
