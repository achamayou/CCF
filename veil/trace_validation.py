# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import dataclasses
import json
import pathlib
import re
import subprocess
import sys
from collections.abc import Iterable
from typing import Any, TextIO

from bounded_correspondence import render_runner_source

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
TRACE_MAX_HEARTBEATS = 5_000_000
TRACE_REPLAY_STEP = "traceReplayStep"
TRACE_REPLAY_ACTION_PREFIX = "TraceReplayStep"
BASE_ACTIONS = (
    "RwTxRequestAction",
    "RoTxRequestAction",
    "RwTxExecuteAction",
    "AppendOtherTxnAction",
    "RwTxResponseAction",
    "RoTxResponseAction",
    "StatusCommittedResponseAction",
    "StatusInvalidResponseAction",
    "TruncateLedgerAction",
    "TruncateLedgerToEmptyAction",
)
LEAN_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


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


def _trace_constant(prefix: str, rank: int) -> str:
    return f"(trace{prefix} {rank})"


def _trace_function(type_name: str, prefix: str) -> str:
    return f"immutable function trace{prefix} : Nat -> {type_name}"


def _trace_truncate_action(cut_rank: int) -> str:
    slots = [f"slot{rank}" for rank in range(cut_rank + 1)]
    parameters = " ".join(f"({slot} : seqno)" for slot in slots)
    lines = [
        f"procedure {TRACE_TRUNCATE_ACTION}Rank{cut_rank}",
        "    (source : view) (cut : seqno) (newView : view)",
        f"    {parameters} {{",
        "  require activeView source",
        "  require ledgerEntry source cut",
        "  require validTruncationSource source cut",
        "  require nextView newView",
        "  activeView newView := true",
    ]
    for slot in slots:
        lines.extend(
            [
                "",
                f"  ledgerEntry newView {slot} := ledgerEntry source {slot}",
                f"  clientEntry newView {slot} := clientEntry source {slot}",
                f"  entryView newView {slot} := entryView source {slot}",
                f"  entryTx newView {slot} := entryTx source {slot}",
            ]
        )
    lines.append("}")
    return "\n".join(lines)


def _replay_step_body(
    step: PlanStep,
    history_rank: int | None,
    request_event_ranks: dict[int, int],
    response_event_ranks: dict[tuple[int, int], int],
    current_view: int,
) -> list[str]:
    fields = step.fields

    if step.action in REQUEST_ACTIONS:
        assert history_rank is not None
        return [
            f"{step.action} "
            f"{_trace_constant('Tx', fields['tx'])} "
            f"{_trace_constant('Event', history_rank)}"
        ]
    if step.action == EXECUTE_ACTION:
        return [
            f"{step.action} "
            f"{_trace_constant('Event', request_event_ranks[fields['tx']])} "
            f"{_trace_constant('View', fields['view'])} "
            f"{_trace_constant('Seqno', fields['seqno'])}"
        ]
    if step.action in ("RwTxResponseAction", "RoTxResponseAction"):
        assert history_rank is not None
        return [
            f"{step.action} "
            f"{_trace_constant('Event', request_event_ranks[fields['tx']])} "
            f"{_trace_constant('View', fields['view'])} "
            f"{_trace_constant('Seqno', fields['seqno'])} "
            f"{_trace_constant('Event', history_rank)}"
        ]
    if step.action in (
        "StatusCommittedResponseAction",
        "StatusInvalidResponseAction",
    ):
        assert history_rank is not None
        tx_id = (fields["view"], fields["seqno"])
        response = _trace_constant("Event", response_event_ranks[tx_id])
        status = _trace_constant("Event", history_rank)
        if step.action == "StatusCommittedResponseAction":
            return [
                f"{step.action} {response} {status} "
                f"{_trace_constant('View', current_view)}"
            ]
        return [f"{step.action} {response} {status}"]
    if step.action == "AppendOtherTxnAction":
        return [
            f"{step.action} "
            f"{_trace_constant('View', fields['view'])} "
            f"{_trace_constant('Seqno', fields['seqno'])}"
        ]
    if step.action == "TruncateLedgerAction":
        cut_rank = fields["cut_seqno"]
        arguments = [
            _trace_constant("View", fields["source_view"]),
            _trace_constant("Seqno", cut_rank),
            _trace_constant("View", fields["new_view"]),
        ]
        arguments.extend(_trace_constant("Seqno", rank) for rank in range(cut_rank + 1))
        return [f"{TRACE_TRUNCATE_ACTION}Rank{cut_rank} {' '.join(arguments)}"]
    if step.action == "TruncateLedgerToEmptyAction":
        return [
            f"{step.action} "
            f"{_trace_constant('View', fields['source_view'])} "
            f"{_trace_constant('View', fields['new_view'])}"
        ]
    raise AssertionError(f"unhandled planned action {step.action}")


def _trace_replay_actions(plan: TracePlan) -> list[str]:
    declarations = []
    request_event_ranks: dict[int, int] = {}
    response_event_ranks: dict[tuple[int, int], int] = {}
    history_rank = 0
    current_view = 0

    for step_index, step in enumerate(plan.steps):
        uses_history = step.kind == "trace" and step.action != EXECUTE_ACTION
        step_history_rank = history_rank if uses_history else None
        lines = [
            f"action {TRACE_REPLAY_ACTION_PREFIX}{step_index} {{",
            f"  require {TRACE_REPLAY_STEP} = {step_index}",
        ]
        if step.source_line is None:
            lines.append(f"  -- Generated {step.action}.")
        else:
            lines.append(f"  -- NDJSON line {step.source_line}: {step.action}.")
        lines.extend(
            f"  {line}"
            for line in _replay_step_body(
                step,
                step_history_rank,
                request_event_ranks,
                response_event_ranks,
                current_view,
            )
        )
        lines.extend([f"  {TRACE_REPLAY_STEP} := {step_index + 1}", "}"])
        declarations.append("\n".join(lines))

        if step.action in REQUEST_ACTIONS:
            assert step_history_rank is not None
            request_event_ranks[step.fields["tx"]] = step_history_rank
        elif step.action == "RwTxResponseAction":
            assert step_history_rank is not None
            response_event_ranks[
                (step.fields["view"], step.fields["seqno"])
            ] = step_history_rank
        if uses_history:
            history_rank += 1
        if step.action in ("TruncateLedgerAction", "TruncateLedgerToEmptyAction"):
            current_view = step.fields["new_view"]

    if history_rank != plan.history_event_count:
        raise AssertionError("planned history event count is inconsistent")
    return declarations


def _convert_actions_to_procedures(source: str) -> str:
    for action in BASE_ACTIONS:
        pattern = re.compile(rf"^action {re.escape(action)}(?=[\s(])", re.MULTILINE)
        source, count = pattern.subn(f"procedure {action}", source)
        if count != 1:
            raise TraceValidationError(
                f"Veil source must contain exactly one {action} action"
            )
    return source


def render_trace_source(source: str, plan: TracePlan) -> str:
    """Create a finite, deterministic Veil replay of a planned trace."""

    if source.count("#gen_spec") != 1:
        raise TraceValidationError("Veil source must contain exactly one #gen_spec")
    if source.count("#gen_state") != 1:
        raise TraceValidationError("Veil source must contain exactly one #gen_state")
    if source.count("after_init {\n") != 1:
        raise TraceValidationError(
            "Veil source must contain exactly one after_init block"
        )
    if source.count(MODEL_CHECK_BEGIN) != 1 or source.count(MODEL_CHECK_END) != 1:
        raise TraceValidationError("Veil source is missing bounded-check markers")
    import_marker = "import Veil\n"
    if source.count(import_marker) != 1:
        raise TraceValidationError("Veil source must contain exactly one Veil import")
    module_marker = "veil module CCFConsistency\n"
    if source.count(module_marker) != 1:
        raise TraceValidationError(
            "Veil source must contain exactly one CCFConsistency module"
        )

    trace_functions = "\n".join(
        (
            _trace_function("tx", "Tx"),
            _trace_function("view", "View"),
            _trace_function("seqno", "Seqno"),
            _trace_function("histEvent", "Event"),
        )
    )
    source = source.replace(
        "#gen_state",
        f"{trace_functions}\nindividual {TRACE_REPLAY_STEP} : Nat\n\n#gen_state",
        1,
    )
    declarations = []
    truncation_ranks = sorted(
        {
            step.fields["cut_seqno"]
            for step in plan.steps
            if step.action == "TruncateLedgerAction"
        }
    )
    declarations.extend(_trace_truncate_action(rank) for rank in truncation_ranks)
    declarations.extend(_trace_replay_actions(plan))
    declarations.append(
        f"termination [trace_replay_complete] "
        f"{TRACE_REPLAY_STEP} = {len(plan.steps)}"
    )
    generated_declarations = "\n\n".join(declarations)
    source = _convert_actions_to_procedures(source)
    source = source.replace(
        "after_init {\n",
        f"after_init {{\n  {TRACE_REPLAY_STEP} := 0\n",
        1,
    )
    source = source.replace(
        "#gen_spec",
        f"{generated_declarations}\n\n#gen_spec",
        1,
    )
    source = source.replace(
        import_marker,
        f"{import_marker}\nset_option veil.__modelCheckCompileMode true\n",
        1,
    )
    source = source.replace(
        module_marker,
        f"{module_marker}\nset_option maxHeartbeats {TRACE_MAX_HEARTBEATS}\n",
        1,
    )

    before, marker, remainder = source.partition(MODEL_CHECK_BEGIN)
    if not marker:
        raise TraceValidationError("bounded-check start marker was not found")
    _, marker, after = remainder.partition(MODEL_CHECK_END)
    if not marker:
        raise TraceValidationError("bounded-check end marker was not found")
    theory_assignments = ",\n".join(
        f"  trace{prefix} := fun rank => Fin.ofNat {count} rank"
        for prefix, count in (
            ("Tx", plan.tx_count),
            ("View", plan.view_count),
            ("Seqno", plan.seqno_count),
            ("Event", plan.history_event_count),
        )
    )
    model_check = f"""-- Generated deterministic implementation trace replay.
#model_check compiled {{
  tx := Fin {plan.tx_count},
  view := Fin {plan.view_count},
  seqno := Fin {plan.seqno_count},
  histEvent := Fin {plan.history_event_count}
}} {{
{theory_assignments}
}}
"""
    source = before + model_check + after.lstrip("\n")
    module_end = "\nend CCFConsistency\n"
    if not source.endswith(module_end):
        raise TraceValidationError("expected CCFConsistency module end")
    return source[: -len(module_end)] + "\n"


def _run_command(
    command: list[str], cwd: pathlib.Path, *, stream_stderr: bool = False
) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=None if stream_stderr else subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        output = result.stdout + (result.stderr or "")
        raise TraceValidationError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{output}"
        )
    return result.stdout


def validate_replay_result(payload: object, plan: TracePlan) -> None:
    """Require a complete, single-path replay with no Veil violation."""

    if not isinstance(payload, dict):
        raise TraceValidationError("Veil replay output is not a JSON object")
    result = payload.get("result")
    if not isinstance(result, dict) or result.get("result") != "no_violation_found":
        raise TraceValidationError(
            f"Veil rejected the implementation trace: {result!r}"
        )
    termination = result.get("termination_reason")
    if not isinstance(termination, dict) or termination.get("kind") != (
        "explored_all_reachable_states"
    ):
        raise TraceValidationError(f"Veil replay did not finish: {termination!r}")

    expected_states = len(plan.steps) + 1
    if result.get("explored_states") != expected_states:
        raise TraceValidationError(
            "Veil replay was not a single complete path: "
            f"expected {expected_states} states, got {result.get('explored_states')!r}"
        )
    progress = payload.get("progress")
    if not isinstance(progress, dict):
        raise TraceValidationError("Veil replay output has no progress summary")
    if progress.get("distinctStates") != expected_states:
        raise TraceValidationError(
            "Veil replay reported an unexpected number of distinct states: "
            f"expected {expected_states}, got {progress.get('distinctStates')!r}"
        )
    if progress.get("statesFound") != expected_states:
        raise TraceValidationError(
            "Veil replay generated more than one successor for a trace step: "
            f"expected {expected_states} states, got {progress.get('statesFound')!r}"
        )


def validate_trace(
    source: str,
    plan: TracePlan,
    generated_dir: pathlib.Path,
    *,
    lake: str = "lake",
) -> dict[str, object]:
    """Compile and execute a deterministic Veil replay."""

    veil_dir = pathlib.Path(__file__).resolve().parent
    generated_dir = generated_dir.resolve()
    try:
        generated_relative = generated_dir.relative_to(veil_dir)
    except ValueError as exc:
        raise TraceValidationError(
            "generated directory must be inside the veil directory"
        ) from exc
    if not generated_relative.parts or any(
        LEAN_IDENTIFIER.fullmatch(part) is None for part in generated_relative.parts
    ):
        raise TraceValidationError(
            "generated directory components must be valid Lean identifiers"
        )

    generated_dir.mkdir(parents=True, exist_ok=True)
    model_stem = "CCFConsistencyImplementationTrace"
    runner_stem = "RunCCFConsistencyImplementationTrace"
    model_path = generated_dir / f"{model_stem}.lean"
    runner_path = generated_dir / f"{runner_stem}.lean"
    module_prefix = ".".join(generated_relative.parts)
    module_name = f"{module_prefix}.{model_stem}"
    model_path.write_text(
        render_trace_source(source, plan), encoding="utf-8", newline="\n"
    )
    runner_path.write_text(
        render_runner_source(module_name, 1),
        encoding="utf-8",
        newline="\n",
    )

    model_relative = model_path.relative_to(veil_dir)
    runner_relative = runner_path.relative_to(veil_dir)
    olean_path = (
        veil_dir
        / ".lake"
        / "build"
        / "lib"
        / "lean"
        / model_relative.with_suffix(".olean")
    )
    olean_path.parent.mkdir(parents=True, exist_ok=True)
    _run_command(
        [
            lake,
            "env",
            "lean",
            model_relative.as_posix(),
            "-o",
            str(olean_path),
        ],
        veil_dir,
    )
    output = _run_command(
        [lake, "env", "lean", "--run", runner_relative.as_posix()],
        veil_dir,
        stream_stderr=True,
    )
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise TraceValidationError(
            f"Veil replay returned invalid JSON: {exc.msg}"
        ) from exc
    validate_replay_result(payload, plan)
    return payload


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
        help="write a scratch Veil source containing deterministic trace replay",
    )
    parser.add_argument(
        "--spec",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("CCFConsistency.lean"),
        help="source Veil specification to use for generated replay validation",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="compile and execute the deterministic replay with Veil",
    )
    parser.add_argument(
        "--generated-dir",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("Generated"),
        help="scratch Lean module directory used by --validate",
    )
    parser.add_argument(
        "--lake",
        default="lake",
        help="Lake executable used by --validate (default: lake)",
    )
    args = parser.parse_args()

    try:
        with args.trace.open(encoding="utf-8") as trace_file:
            plan = plan_trace(parse_trace(trace_file))
        source = None
        if args.lean_output is not None:
            source = args.spec.read_text(encoding="utf-8")
            generated = render_trace_source(source, plan)
            args.lean_output.parent.mkdir(parents=True, exist_ok=True)
            args.lean_output.write_text(generated, encoding="utf-8", newline="\n")
        if args.validate:
            if source is None:
                source = args.spec.read_text(encoding="utf-8")
            validate_trace(source, plan, args.generated_dir, lake=args.lake)
            print(
                f"Veil validated {len(plan.steps)} replay steps "
                f"across {len(plan.steps) + 1} states."
            )
        if args.output is None and args.lean_output is None and not args.validate:
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
