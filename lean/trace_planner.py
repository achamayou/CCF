# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Parse and plan a CCF consistency implementation trace.

The implementation logs only client-visible events. Replaying a trace against
the model additionally needs the internal actions the implementation never
logs: ledger appends for transactions it did not report, and the view changes
implied by a jump in transaction identifiers.

A model checker can search for those actions. A proof assistant replaying a
fixed sequence cannot, so this module reconstructs them deterministically and
emits an exact list of steps for `trace_validation.py` to render as Lean.

Parsing is strict: any unexpected field, malformed transaction identifier or
out-of-order event is an error rather than a silently skipped line.
"""

import dataclasses
import json
import re
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


class TraceValidationError(ValueError):
    """Raised when a consistency trace cannot be parsed or planned."""


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

    def _ensure_view(self, target: int, copy_length: int, source_line: int) -> None:
        while len(self.branches) <= target:
            minimum_length = max((seqno + 1 for _, seqno in self.committed), default=0)
            if copy_length < minimum_length:
                raise TraceValidationError(
                    f"line {source_line}: new view would truncate below committed "
                    f"sequence rank {minimum_length - 1}"
                )
            source = len(self.branches) - 1
            new_view = len(self.branches)
            source_branch = self.branches[source]
            copied_branch = source_branch[:copy_length]
            if copied_branch:
                self._add_filler(
                    "TruncateLedgerAction",
                    source_line,
                    source_view=source,
                    cut_seqno=len(copied_branch) - 1,
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
            self.branches.append(list(copied_branch))

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
        self._ensure_view(view, seqno, event.line_number)
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
        self._ensure_view(view, seqno, event.line_number)
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


def _write_plan(plan: TracePlan, output: TextIO) -> None:
    json.dump(plan.to_json(), output, indent=2)
    output.write("\n")
