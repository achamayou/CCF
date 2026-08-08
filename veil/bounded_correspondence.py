#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Compare a small TLC state graph with an action-aligned Veil graph."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HISTORY_LIMIT = 3
VIEW_LIMIT = 2
MAX_DEPTH = 8

APPEND_OTHER_BEGIN = "-- BEGIN CCF VEIL APPEND OTHER ACTION"
APPEND_OTHER_END = "-- END CCF VEIL APPEND OTHER ACTION"
MODEL_CHECK_BEGIN = "-- BEGIN CCF VEIL BOUNDED CHECK"
MODEL_CHECK_END = "-- END CCF VEIL BOUNDED CHECK"

DOT_EDGE = re.compile(r'^(-?\d+) -> (-?\d+) \[label="([^"]+)"')
DOT_NODE = re.compile(r'^(-?\d+) \[label="')
DOT_INITIAL = re.compile(r"^(-?\d+) \[.*style = filled")
LEAN_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
LEAN_MODULE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")

TLC_ACTION_NAMES = {
    "MCRoTxRequestAction": "RoTxRequestAction",
    "MCRoTxResponseAction": "RoTxResponseAction",
    "MCRwTxRequestAction": "RwTxRequestAction",
    "MCRwTxResponseAction": "RwTxResponseAction",
    "MCStatusCommittedResponseAction": "StatusCommittedResponseAction",
    "MCStatusInvalidResponseAction": "StatusInvalidResponseAction",
    "MCTruncateLedgerAction": "TruncateLedgerAction",
    "RwTxExecuteAction": "RwTxExecuteAction",
}


class CorrespondenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class GraphStats:
    generated_states: int
    distinct_states: int
    cumulative_by_depth: dict[int, int]
    actions: dict[str, int]


def _replace_marked_block(source: str, begin: str, end: str, replacement: str) -> str:
    if source.count(begin) != 1 or source.count(end) != 1:
        raise CorrespondenceError(f"expected exactly one {begin!r}/{end!r} marker pair")
    before, _, remainder = source.partition(begin)
    _, _, after = remainder.partition(end)
    return before + replacement + after


def render_veil_source(
    source: str,
    history_limit: int = HISTORY_LIMIT,
    view_limit: int = VIEW_LIMIT,
    max_depth: int = MAX_DEPTH,
) -> str:
    """Create the action-restricted Veil model used for correspondence."""

    if history_limit < 1 or view_limit < 1 or max_depth < 1:
        raise CorrespondenceError("all correspondence bounds must be positive")
    if source.count("import Veil\n") != 1:
        raise CorrespondenceError("expected exactly one Veil import")

    source = _replace_marked_block(
        source,
        APPEND_OTHER_BEGIN,
        APPEND_OTHER_END,
        "-- AppendOtherTxnAction is absent from the TLC MC wrapper.",
    )
    bounded_check = f"""-- Generated bounded correspondence check.
#model_check compiled {{
  tx := Fin {history_limit},
  view := Fin {view_limit},
  seqno := Fin {history_limit},
  histEvent := Fin {history_limit}
}} {{ }} (maxDepth := {max_depth})
"""
    source = _replace_marked_block(
        source, MODEL_CHECK_BEGIN, MODEL_CHECK_END, bounded_check
    )
    source = source.replace(
        "import Veil\n",
        "import Veil\n\nset_option veil.__modelCheckCompileMode true\n",
        1,
    )

    module_end = "\nend CCFConsistency\n"
    if not source.endswith(module_end):
        raise CorrespondenceError("expected CCFConsistency module end")
    # Internal model-check compilation emits the module end and exports its
    # runner itself.
    return source[: -len(module_end)] + "\n"


def render_runner_source(module_name: str, workers: int) -> str:
    if LEAN_MODULE.fullmatch(module_name) is None:
        raise CorrespondenceError(f"{module_name!r} is not a valid Lean module name")
    if workers < 1:
        raise CorrespondenceError("worker count must be positive")
    return f"""import {module_name}

def main : IO Unit := do
  let (instanceId, cancelToken) <-
    Veil.ModelChecker.Concrete.allocProgressInstance
  let parallelConfig : Veil.ModelChecker.ParallelConfig := {{
    numSubTasks := {workers},
    thresholdToParallel := 1,
    numSubSteps := 1
  }}
  let result <-
    modelCheckerResult (some parallelConfig) instanceId cancelToken
  let progress <-
    Veil.ModelChecker.Concrete.getProgress instanceId
  let output := Lean.Json.mkObj [
    ("result", Lean.toJson result),
    ("progress", Lean.toJson progress)
  ]
  IO.println output.compress
"""


def parse_tlc_dot(path: Path) -> GraphStats:
    adjacency: dict[str, list[str]] = defaultdict(list)
    nodes: set[str] = set()
    initial_states: set[str] = set()
    actions: Counter[str] = Counter()

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if match := DOT_EDGE.match(line):
            source, target, action = match.groups()
            nodes.update((source, target))
            adjacency[source].append(target)
            try:
                action = TLC_ACTION_NAMES[action]
            except KeyError as exc:
                raise CorrespondenceError(f"unexpected TLC action {action!r}") from exc
            actions[action] += 1
        elif match := DOT_NODE.match(line):
            nodes.add(match.group(1))
        if match := DOT_INITIAL.match(line):
            initial_states.add(match.group(1))

    if len(initial_states) != 1:
        raise CorrespondenceError(
            f"expected one TLC initial state, found {len(initial_states)}"
        )
    initial = next(iter(initial_states))
    distances = {initial: 0}
    queue = deque([initial])
    while queue:
        source = queue.popleft()
        for target in adjacency[source]:
            if target not in distances:
                distances[target] = distances[source] + 1
                queue.append(target)
    if distances.keys() != nodes:
        raise CorrespondenceError(
            f"TLC DOT contains {len(nodes - distances.keys())} unreachable states"
        )

    layers = Counter(distances.values())
    cumulative: dict[int, int] = {}
    total = 0
    for depth in sorted(layers):
        total += layers[depth]
        cumulative[depth] = total
    return GraphStats(
        generated_states=sum(actions.values()) + 1,
        distinct_states=len(nodes),
        cumulative_by_depth=cumulative,
        actions=dict(actions),
    )


def parse_veil_output(path: Path) -> GraphStats:
    payload = json.loads(path.read_text(encoding="utf-8"))
    result = payload["result"]
    if result.get("result") != "no_violation_found":
        raise CorrespondenceError(f"Veil reported {result!r}")
    termination = result.get("termination_reason", {})
    if termination.get("kind") != "explored_all_reachable_states":
        raise CorrespondenceError(f"Veil did not reach a fixed point: {termination!r}")

    progress = payload["progress"]
    cumulative = {0: 1}
    for point in progress["history"]:
        depth = int(point["diameter"])
        distinct = int(point["distinctStates"])
        cumulative[depth] = max(cumulative.get(depth, 0), distinct)

    actions: Counter[str] = Counter()
    for stat in progress["actionStats"]:
        _, marker, suffix = stat["name"].partition(".Label.")
        if not marker:
            raise CorrespondenceError(f"unexpected Veil action label {stat['name']!r}")
        action = suffix.partition(" ")[0]
        if action == "TruncateLedgerToEmptyAction":
            action = "TruncateLedgerAction"
        actions[action] += int(stat["statesGenerated"])

    return GraphStats(
        generated_states=int(progress["statesFound"]),
        distinct_states=int(progress["distinctStates"]),
        cumulative_by_depth=cumulative,
        actions=dict(actions),
    )


def compare_graphs(tlc: GraphStats, veil: GraphStats) -> None:
    differences = []
    if tlc.generated_states != veil.generated_states:
        differences.append(
            "generated states: "
            f"TLC={tlc.generated_states}, Veil={veil.generated_states}"
        )
    if tlc.distinct_states != veil.distinct_states:
        differences.append(
            "distinct states: "
            f"TLC={tlc.distinct_states}, Veil={veil.distinct_states}"
        )
    for depth, tlc_count in tlc.cumulative_by_depth.items():
        veil_count = veil.cumulative_by_depth.get(depth)
        if veil_count != tlc_count:
            differences.append(f"depth {depth}: TLC={tlc_count}, Veil={veil_count}")
    max_tlc_depth = max(tlc.cumulative_by_depth)
    for depth, count in veil.cumulative_by_depth.items():
        if depth > max_tlc_depth and count != tlc.distinct_states:
            differences.append(f"Veil found {count} states at extra depth {depth}")
    if tlc.actions != veil.actions:
        all_actions = sorted(tlc.actions.keys() | veil.actions.keys())
        for action in all_actions:
            if tlc.actions.get(action) != veil.actions.get(action):
                differences.append(
                    f"{action}: TLC={tlc.actions.get(action, 0)}, "
                    f"Veil={veil.actions.get(action, 0)}"
                )
    if differences:
        raise CorrespondenceError(
            "bounded graphs differ:\n  " + "\n  ".join(differences)
        )


def format_report(tlc: GraphStats) -> str:
    lines = [
        "Bounded TLC/Veil correspondence matched.",
        (
            f"Generated states: {tlc.generated_states}; "
            f"distinct states: {tlc.distinct_states}."
        ),
        "Cumulative states by depth: "
        + ", ".join(
            f"{depth}={count}" for depth, count in tlc.cumulative_by_depth.items()
        ),
        "Transitions by action: "
        + ", ".join(
            f"{action}={count}" for action, count in sorted(tlc.actions.items())
        ),
    ]
    return "\n".join(lines)


def _run_command(command: list[str], cwd: Path) -> str:
    result = subprocess.run(
        command, cwd=cwd, text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        output = result.stdout + result.stderr
        raise CorrespondenceError(
            f"command failed ({result.returncode}): " f"{' '.join(command)}\n{output}"
        )
    return result.stdout


def run_correspondence(
    workers: int, output_dir: Path, lake: str = "lake"
) -> GraphStats:
    veil_dir = Path(__file__).resolve().parent
    repo_root = veil_dir.parent
    tla_dir = repo_root / "tla"
    generated_dir = output_dir.resolve()
    try:
        generated_relative = generated_dir.relative_to(veil_dir)
    except ValueError as exc:
        raise CorrespondenceError(
            "output directory must be inside the veil directory"
        ) from exc
    if not generated_relative.parts or any(
        LEAN_IDENTIFIER.fullmatch(part) is None for part in generated_relative.parts
    ):
        raise CorrespondenceError(
            "output directory components must be valid Lean identifiers"
        )

    for jar in ("tla2tools.jar", "CommunityModules-deps.jar"):
        if not (tla_dir / jar).is_file():
            raise CorrespondenceError(
                f"{jar} is missing; run python3 tla/install_deps.py"
            )

    generated_dir.mkdir(parents=True, exist_ok=True)
    model_path = generated_dir / "CCFConsistencyCorrespondence.lean"
    runner_path = generated_dir / "RunCCFConsistencyCorrespondence.lean"
    module_prefix = ".".join(generated_relative.parts)
    module_name = f"{module_prefix}.CCFConsistencyCorrespondence"
    source = (veil_dir / "CCFConsistency.lean").read_text(encoding="utf-8")
    model_path.write_text(render_veil_source(source), encoding="utf-8", newline="\n")
    runner_path.write_text(
        render_runner_source(module_name, workers),
        encoding="utf-8",
        newline="\n",
    )

    dot_stem = generated_dir / "tlc-h3-v2"
    config = tla_dir / "consistency" / "MCMultiNodeReadsSmall.cfg"
    tlc_output = _run_command(
        [
            sys.executable,
            "tlc.py",
            "--workers",
            str(workers),
            "--dot",
            "--trace-name",
            str(dot_stem),
            "--config",
            str(config),
            "mc",
            "consistency/MCMultiNodeReads.tla",
        ],
        tla_dir,
    )
    (generated_dir / "tlc-h3-v2.log").write_text(
        tlc_output, encoding="utf-8", newline="\n"
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
    veil_output = _run_command(
        [lake, "env", "lean", "--run", runner_relative.as_posix()],
        veil_dir,
    )
    veil_output_path = generated_dir / "veil-h3-v2.json"
    veil_output_path.write_text(
        veil_output.strip() + "\n", encoding="utf-8", newline="\n"
    )

    tlc_stats = parse_tlc_dot(dot_stem.with_suffix(".dot"))
    veil_stats = parse_veil_output(veil_output_path)
    compare_graphs(tlc_stats, veil_stats)
    return tlc_stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workers",
        type=int,
        default=os.cpu_count() or 1,
        help="TLC workers and Veil subtasks (default: all logical CPUs)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).with_name("Generated"),
    )
    parser.add_argument("--lake", default="lake")
    args = parser.parse_args()

    try:
        stats = run_correspondence(
            workers=args.workers,
            output_dir=args.output_dir,
            lake=args.lake,
        )
    except (
        CorrespondenceError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(format_report(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
