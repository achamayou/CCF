# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import pathlib
import re
import subprocess
import sys
from typing import TextIO

import trace_planner
from trace_planner import TracePlan, TraceValidationError

LEAN_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
GENERATED_MODULE = "CCFConsistencyImplementationTrace"


class LeanTraceValidationError(ValueError):
    """Raised when a planned trace cannot be validated by pure Lean."""


def _trace_constant(prefix: str, rank: int) -> str:
    return f"(trace{prefix} {rank})"


def _render_action(
    step,
    history_rank: int | None,
    request_event_ranks: dict[int, int],
    response_event_ranks: dict[tuple[int, int], int],
    current_view: int,
) -> str:
    fields = step.fields

    if step.action in trace_planner.REQUEST_ACTIONS:
        assert history_rank is not None
        constructor = (
            "rwTxRequest" if step.action == "RwTxRequestAction" else "roTxRequest"
        )
        return (
            f".{constructor} "
            f"{_trace_constant('Tx', fields['tx'])} "
            f"{_trace_constant('Event', history_rank)}"
        )
    if step.action == trace_planner.EXECUTE_ACTION:
        return (
            ".rwTxExecute "
            f"{_trace_constant('Event', request_event_ranks[fields['tx']])} "
            f"{_trace_constant('View', fields['view'])} "
            f"{_trace_constant('Seqno', fields['seqno'])}"
        )
    if step.action in ("RwTxResponseAction", "RoTxResponseAction"):
        assert history_rank is not None
        constructor = (
            "rwTxResponse" if step.action == "RwTxResponseAction" else "roTxResponse"
        )
        return (
            f".{constructor} "
            f"{_trace_constant('Event', request_event_ranks[fields['tx']])} "
            f"{_trace_constant('View', fields['view'])} "
            f"{_trace_constant('Seqno', fields['seqno'])} "
            f"{_trace_constant('Event', history_rank)}"
        )
    if step.action in (
        "StatusCommittedResponseAction",
        "StatusInvalidResponseAction",
    ):
        assert history_rank is not None
        tx_id = (fields["view"], fields["seqno"])
        response = _trace_constant("Event", response_event_ranks[tx_id])
        status = _trace_constant("Event", history_rank)
        if step.action == "StatusCommittedResponseAction":
            return (
                f".statusCommittedResponse {response} {status} "
                f"{_trace_constant('View', current_view)}"
            )
        return f".statusInvalidResponse {response} {status}"
    if step.action == "AppendOtherTxnAction":
        return (
            ".appendOtherTxn "
            f"{_trace_constant('View', fields['view'])} "
            f"{_trace_constant('Seqno', fields['seqno'])}"
        )
    if step.action == "TruncateLedgerAction":
        return (
            ".truncateLedger "
            f"{_trace_constant('View', fields['source_view'])} "
            f"{_trace_constant('Seqno', fields['cut_seqno'])} "
            f"{_trace_constant('View', fields['new_view'])}"
        )
    if step.action == "TruncateLedgerToEmptyAction":
        return (
            ".truncateLedgerToEmpty "
            f"{_trace_constant('View', fields['source_view'])} "
            f"{_trace_constant('View', fields['new_view'])}"
        )
    raise AssertionError(f"unhandled planned action {step.action}")


def _render_actions(plan) -> str:
    rendered = []
    request_event_ranks: dict[int, int] = {}
    response_event_ranks: dict[tuple[int, int], int] = {}
    history_rank = 0
    current_view = 0

    for step in plan.steps:
        uses_history = step.kind == "trace" and step.action != trace_planner.EXECUTE_ACTION
        step_history_rank = history_rank if uses_history else None
        action = _render_action(
            step,
            step_history_rank,
            request_event_ranks,
            response_event_ranks,
            current_view,
        )
        if step.source_line is None:
            comment = f"generated {step.action}"
        else:
            comment = f"NDJSON line {step.source_line}: {step.action}"
        rendered.append(f"  {action}, -- {comment}")

        if step.action in trace_planner.REQUEST_ACTIONS:
            assert step_history_rank is not None
            request_event_ranks[step.fields["tx"]] = step_history_rank
        elif step.action == "RwTxResponseAction":
            assert step_history_rank is not None
            response_event_ranks[(step.fields["view"], step.fields["seqno"])] = (
                step_history_rank
            )
        if uses_history:
            history_rank += 1
        if step.action in ("TruncateLedgerAction", "TruncateLedgerToEmptyAction"):
            current_view = step.fields["new_view"]

    if history_rank != plan.history_event_count:
        raise AssertionError("planned history event count is inconsistent")
    return "\n".join(rendered)


def render_trace_source(plan) -> str:
    """Render a kernel-checked replay proof for a planned trace."""

    actions = _render_actions(plan)
    return f"""-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

-- Generated by lean/trace_validation.py. Do not edit.
import CCFConsistency.Trace

set_option autoImplicit false

namespace CCFConsistency.GeneratedImplementationTrace

abbrev Tx := Fin {plan.tx_count}
abbrev View := Fin {plan.view_count}
abbrev Seqno := Fin {plan.seqno_count}
abbrev Event := Fin {plan.history_event_count}

private def traceTx (rank : Nat) : Tx := Fin.ofNat {plan.tx_count} rank
private def traceView (rank : Nat) : View := Fin.ofNat {plan.view_count} rank
private def traceSeqno (rank : Nat) : Seqno := Fin.ofNat {plan.seqno_count} rank
private def traceEvent (rank : Nat) : Event :=
  Fin.ofNat {plan.history_event_count} rank

abbrev actions : List (TraceAction Tx View Seqno Event) := [
{actions}
]

abbrev initial : State Tx View Seqno Event := initialState

set_option maxRecDepth 100000 in
theorem replaySucceeded : (replay actions initial).isSome := by
  decide +kernel

theorem implementationTraceReachable :
    Exists fun final =>
      replay actions initial = some final /\\ Reachable final :=
  replay_from_initial replaySucceeded

#print axioms implementationTraceReachable

run_cmd do
  let axioms <- Lean.collectAxioms ``implementationTraceReachable
  if axioms.contains ``sorryAx then
    throwError "generated trace reachability proof depends on sorryAx"
  if axioms.contains ``Lean.ofReduceBool then
    throwError "generated trace reachability proof depends on native compiler evaluation"
  Lean.logInfo m!"Audited generated pure Lean trace reachability proof axioms."

end CCFConsistency.GeneratedImplementationTrace
"""


def _run_command(command: list[str], cwd: pathlib.Path) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise LeanTraceValidationError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result.stdout


def validate_trace(
    plan,
    lean_project: pathlib.Path,
    generated_dir: pathlib.Path,
    *,
    lake: str = "lake",
) -> pathlib.Path:
    """Generate and compile a pure Lean trace proof."""

    lean_project = lean_project.resolve()
    generated_dir = generated_dir.resolve()
    try:
        generated_relative = generated_dir.relative_to(lean_project)
    except ValueError as exc:
        raise LeanTraceValidationError(
            "generated directory must be inside the Lean project"
        ) from exc
    if not generated_relative.parts or any(
        LEAN_IDENTIFIER.fullmatch(part) is None for part in generated_relative.parts
    ):
        raise LeanTraceValidationError(
            "generated directory components must be valid Lean identifiers"
        )

    generated_dir.mkdir(parents=True, exist_ok=True)
    source_path = generated_dir / f"{GENERATED_MODULE}.lean"
    source_path.write_text(
        render_trace_source(plan),
        encoding="utf-8",
        newline="\n",
    )
    _run_command(
        [lake, "env", "lean", source_path.relative_to(lean_project).as_posix()],
        lean_project,
    )
    return source_path


def _write_plan(plan, output: TextIO) -> None:
    trace_planner._write_plan(plan, output)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Schema-check and rank-normalise a CCF consistency NDJSON trace, "
            "then generate a kernel-checked replay against the pure Lean model"
        )
    )
    parser.add_argument("trace", type=pathlib.Path, help="input NDJSON trace")
    parser.add_argument(
        "-o", "--output", type=pathlib.Path, help="output JSON plan (default: stdout)"
    )
    parser.add_argument(
        "--lean-output",
        type=pathlib.Path,
        help="write the generated pure Lean replay proof without compiling it",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="compile the generated replay proof with Lean",
    )
    parser.add_argument(
        "--lean-project",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent,
        help="Lean project used by --validate (default: lean directory)",
    )
    parser.add_argument(
        "--generated-dir",
        type=pathlib.Path,
        help="generated module directory (default: LEAN_PROJECT/Generated)",
    )
    parser.add_argument(
        "--lake",
        default="lake",
        help="Lake executable used by --validate (default: lake)",
    )
    args = parser.parse_args()

    try:
        with args.trace.open(encoding="utf-8") as trace_file:
            plan = trace_planner.plan_trace(trace_planner.parse_trace(trace_file))
        if args.lean_output is not None:
            args.lean_output.parent.mkdir(parents=True, exist_ok=True)
            args.lean_output.write_text(
                render_trace_source(plan),
                encoding="utf-8",
                newline="\n",
            )
        if args.validate:
            generated_dir = args.generated_dir
            if generated_dir is None:
                generated_dir = args.lean_project / "Generated"
            validate_trace(
                plan,
                args.lean_project,
                generated_dir,
                lake=args.lake,
            )
            print(
                f"Pure Lean validated {len(plan.steps)} replay steps "
                f"across {len(plan.steps) + 1} states."
            )
        if args.output is None and args.lean_output is None and not args.validate:
            _write_plan(plan, sys.stdout)
        elif args.output is not None:
            with args.output.open("w", encoding="utf-8", newline="\n") as output:
                _write_plan(plan, output)
    except (OSError, TraceValidationError, LeanTraceValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
