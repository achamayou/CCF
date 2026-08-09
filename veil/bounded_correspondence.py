#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Compare the checked-in TLC bounds with an action-aligned Veil graph."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HISTORY_LIMIT = 4
VIEW_LIMIT = 3
MAX_DEPTH = 12

APPEND_OTHER_BEGIN = "-- BEGIN CCF VEIL APPEND OTHER ACTION"
APPEND_OTHER_END = "-- END CCF VEIL APPEND OTHER ACTION"
MODEL_CHECK_BEGIN = "-- BEGIN CCF VEIL BOUNDED CHECK"
MODEL_CHECK_END = "-- END CCF VEIL BOUNDED CHECK"

TLC_SUMMARY = re.compile(
    r"^([\d,]+) states generated, ([\d,]+) distinct states found,"
    r" \d+ states left on queue\.$"
)
TLC_DFID_SUMMARY = re.compile(
    r"^([\d,]+) states generated, ([\d,]+) distinct states found\.$"
)
TLC_GRAPH_DEPTH = re.compile(
    r"^The depth of the complete state graph search is ([\d,]+)\.$"
)
TLC_ACTION_COVERAGE = re.compile(r"^<([A-Za-z0-9_]+) line [^>]+>: [\d,]+:([\d,]+)$")
LEAN_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
LEAN_MODULE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
TLC_HISTORY_LIMIT = re.compile(r"^(\s*HistoryLimit\s*=\s*)\d+(\s*)$", re.MULTILINE)
TLC_VIEW_LIMIT = re.compile(r"^(\s*ViewLimit\s*=\s*)\d+(\s*)$", re.MULTILINE)

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


def render_tlc_config(
    source: str,
    history_limit: int = HISTORY_LIMIT,
    view_limit: int = VIEW_LIMIT,
) -> str:
    """Apply correspondence bounds to the canonical TLC configuration."""

    if history_limit < 1 or view_limit < 1:
        raise CorrespondenceError("all correspondence bounds must be positive")

    for name, pattern, value in (
        ("HistoryLimit", TLC_HISTORY_LIMIT, history_limit),
        ("ViewLimit", TLC_VIEW_LIMIT, view_limit),
    ):
        source, count = pattern.subn(
            lambda match: f"{match.group(1)}{value}{match.group(2)}", source
        )
        if count != 1:
            raise CorrespondenceError(f"expected exactly one {name} assignment")
    return source


def render_runner_source(
    module_name: str, workers: int, progress_interval_ms: int = 30_000
) -> str:
    if LEAN_MODULE.fullmatch(module_name) is None:
        raise CorrespondenceError(f"{module_name!r} is not a valid Lean module name")
    if workers < 1:
        raise CorrespondenceError("worker count must be positive")
    if progress_interval_ms < 1:
        raise CorrespondenceError("progress interval must be positive")
    return f"""import {module_name}

def main : IO Unit := do
  let (instanceId, cancelToken) <-
    Veil.ModelChecker.Concrete.allocProgressInstance
  let parallelConfig : Veil.ModelChecker.ParallelConfig := {{
    numSubTasks := {workers},
    thresholdToParallel := 1,
    numSubSteps := 1
  }}
  let checkerTask <- IO.asTask (prio := .dedicated) do
    modelCheckerResult (some parallelConfig) instanceId cancelToken
  let startTime <- IO.monoMsNow
  let mut nextReport := startTime + {progress_interval_ms}
  while true do
    let finished <- IO.hasFinished checkerTask
    if finished then break
    IO.sleep 1000
    let now <- IO.monoMsNow
    if nextReport <= now then
      let progress <-
        Veil.ModelChecker.Concrete.getProgress instanceId
      let elapsedMs := now - progress.startTimeMs
      let statesPerSecond :=
        if elapsedMs = 0 then 0
        else progress.statesFound * 1000 / elapsedMs
      IO.eprintln s!"Veil progress: elapsed={{elapsedMs / 1000}}s, depth={{progress.diameter}}, generated={{progress.statesFound}}, distinct={{progress.distinctStates}}, queue={{progress.queue}}, average={{statesPerSecond}} states/s"
      let stderr <- IO.getStderr
      stderr.flush
      nextReport := now + {progress_interval_ms}
  let resultExcept <- IO.wait checkerTask
  let result <- IO.ofExcept resultExcept
  let progress <-
    Veil.ModelChecker.Concrete.getProgress instanceId
  let output := Lean.Json.mkObj [
    ("result", Lean.toJson result),
    ("progress", Lean.toJson progress)
  ]
  IO.println output.compress
"""


def _count(value: str) -> int:
    return int(value.replace(",", ""))


def _parse_tlc_summary(output: str) -> tuple[int, int]:
    matches = []
    for line in output.splitlines():
        line = line.strip()
        matches.append(TLC_SUMMARY.match(line) or TLC_DFID_SUMMARY.match(line))
    summaries = [match for match in matches if match is not None]
    if len(summaries) != 1:
        raise CorrespondenceError(
            f"expected one TLC state summary, found {len(summaries)}"
        )
    return _count(summaries[0].group(1)), _count(summaries[0].group(2))


def _parse_tlc_graph_depth(output: str) -> int:
    matches = [
        match
        for line in output.splitlines()
        if (match := TLC_GRAPH_DEPTH.match(line.strip())) is not None
    ]
    if len(matches) != 1:
        raise CorrespondenceError(f"expected one TLC graph depth, found {len(matches)}")
    return _count(matches[0].group(1))


def parse_tlc_output(
    breadth_first_output: str, depth_outputs: dict[int, str]
) -> GraphStats:
    """Parse an exhaustive TLC run and one depth-limited run per BFS layer."""

    if "Model checking completed. No error has been found." not in breadth_first_output:
        raise CorrespondenceError("TLC breadth-first run did not complete successfully")

    generated_states, distinct_states = _parse_tlc_summary(breadth_first_output)
    graph_depth = _parse_tlc_graph_depth(breadth_first_output)
    expected_depths = set(range(1, graph_depth + 1))
    if depth_outputs.keys() != expected_depths:
        raise CorrespondenceError(
            "TLC depth runs do not cover the complete graph: "
            f"expected {sorted(expected_depths)}, got {sorted(depth_outputs)}"
        )

    cumulative: dict[int, int] = {}
    for depth, output in sorted(depth_outputs.items()):
        if any(line.startswith("Error:") for line in output.splitlines()):
            raise CorrespondenceError(
                f"TLC depth-limited run {depth} did not complete successfully"
            )
        _, depth_distinct = _parse_tlc_summary(output)
        cumulative[depth - 1] = depth_distinct
    if cumulative[graph_depth - 1] != distinct_states:
        raise CorrespondenceError(
            "TLC depth-limited and breadth-first runs disagree: "
            f"depth {graph_depth - 1} has {cumulative[graph_depth - 1]} states, "
            f"breadth-first run has {distinct_states}"
        )

    actions: Counter[str] = Counter()
    for raw_line in breadth_first_output.splitlines():
        match = TLC_ACTION_COVERAGE.match(raw_line.strip())
        if match is None or match.group(1) not in TLC_ACTION_NAMES:
            continue
        actions[TLC_ACTION_NAMES[match.group(1)]] += _count(match.group(2))
    if sum(actions.values()) + 1 != generated_states:
        raise CorrespondenceError(
            "TLC action coverage does not account for all generated states: "
            f"actions={sum(actions.values())}, generated={generated_states}"
        )
    return GraphStats(
        generated_states=generated_states,
        distinct_states=distinct_states,
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


def _run_command(
    command: list[str],
    cwd: Path,
    accepted_returncodes: frozenset[int] = frozenset({0}),
    stream_stderr: bool = False,
) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=None if stream_stderr else subprocess.PIPE,
        check=False,
    )
    if result.returncode not in accepted_returncodes:
        output = result.stdout + (result.stderr or "")
        raise CorrespondenceError(
            f"command failed ({result.returncode}): " f"{' '.join(command)}\n{output}"
        )
    return result.stdout


def _tlc_command(
    java: str,
    tla_dir: Path,
    workers: int,
    arguments: list[str],
    max_heap_mb: int | None = None,
) -> list[str]:
    classpath = os.pathsep.join(
        str(tla_dir / jar) for jar in ("tla2tools.jar", "CommunityModules-deps.jar")
    )
    command = [java]
    if max_heap_mb is not None:
        command.append(f"-Xmx{max_heap_mb}m")
    command.extend(
        [
            "-XX:+UseParallelGC",
            "-Dtlc2.tool.impl.Tool.cdot=true",
            "-cp",
            classpath,
            "tlc2.TLC",
            "-workers",
            str(workers),
            "-checkpoint",
            "0",
            "-lncheck",
            "final",
            *arguments,
        ]
    )
    return command


def _run_tlc_depth(
    java: str, tla_dir: Path, config: Path, depth: int
) -> tuple[int, str]:
    with tempfile.TemporaryDirectory(prefix=f"ccf-tlc-depth-{depth}-") as metadir:
        output = _run_command(
            _tlc_command(
                java,
                tla_dir,
                1,
                [
                    "-metadir",
                    metadir,
                    "-dfid",
                    str(depth),
                    "-config",
                    str(config),
                    "consistency/MCMultiNodeReads.tla",
                ],
                max_heap_mb=768,
            ),
            tla_dir,
            accepted_returncodes=frozenset({0, 255}),
        )
    return depth, output


def _run_tlc_depths(
    java: str, tla_dir: Path, config: Path, graph_depth: int, workers: int
) -> dict[int, str]:
    outputs: dict[int, str] = {}
    with ThreadPoolExecutor(max_workers=min(workers, graph_depth)) as executor:
        futures = [
            executor.submit(_run_tlc_depth, java, tla_dir, config, depth)
            for depth in range(1, graph_depth + 1)
        ]
        for future in as_completed(futures):
            depth, output = future.result()
            outputs[depth] = output
    return outputs


def run_correspondence(
    workers: int, output_dir: Path, lake: str = "lake", java: str = "java"
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

    scope_name = f"h{HISTORY_LIMIT}-v{VIEW_LIMIT}"
    canonical_config = tla_dir / "consistency" / "MCMultiNodeReads.cfg"
    config = generated_dir / "MCMultiNodeReadsCorrespondence.cfg"
    config.write_text(
        render_tlc_config(canonical_config.read_text(encoding="utf-8")),
        encoding="utf-8",
        newline="\n",
    )
    tlc_output = _run_command(
        _tlc_command(
            java,
            tla_dir,
            workers,
            [
                "-coverage",
                "9999",
                "-config",
                str(config),
                "consistency/MCMultiNodeReads.tla",
            ],
        ),
        tla_dir,
    )
    (generated_dir / f"tlc-{scope_name}.log").write_text(
        tlc_output, encoding="utf-8", newline="\n"
    )
    depth_outputs = _run_tlc_depths(
        java, tla_dir, config, _parse_tlc_graph_depth(tlc_output), workers
    )
    (generated_dir / f"tlc-{scope_name}-depths.log").write_text(
        "\n".join(
            f"===== depth {depth} =====\n{output.rstrip()}"
            for depth, output in sorted(depth_outputs.items())
        )
        + "\n",
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
    veil_output = _run_command(
        [lake, "env", "lean", "--run", runner_relative.as_posix()],
        veil_dir,
        stream_stderr=True,
    )
    veil_output_path = generated_dir / f"veil-{scope_name}.json"
    veil_output_path.write_text(
        veil_output.strip() + "\n", encoding="utf-8", newline="\n"
    )

    tlc_stats = parse_tlc_output(tlc_output, depth_outputs)
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
    parser.add_argument("--java", default="java")
    args = parser.parse_args()

    try:
        stats = run_correspondence(
            workers=args.workers,
            output_dir=args.output_dir,
            lake=args.lake,
            java=args.java,
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
