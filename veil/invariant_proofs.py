#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import pathlib
import re


MODEL_CHECK_BEGIN = "-- BEGIN CCF VEIL BOUNDED CHECK"
MODEL_CHECK_END = "-- END CCF VEIL BOUNDED CHECK"
IMPORT_MARKER = "import Veil\n"
DEFAULT_SMT_TIMEOUT = 120

ACTION_DECLARATION = re.compile(r"^action\s+([A-Za-z_][A-Za-z0-9_]*)\b", re.MULTILINE)

AXIOM_AUDIT = """run_cmd do
  let env <- Lean.getEnv
  let mut checked := 0
  for (name, info) in env.constants.toList do
    if `CCFConsistency |>.isPrefixOf name then
      match info with
      | .thmInfo _ =>
          checked := checked + 1
          let axioms <- Lean.collectAxioms name
          if axioms.contains ``sorryAx then
            throwError "theorem {name} depends on sorryAx"
      | _ => pure ()
  if checked = 0 then
    throwError "no CCFConsistency theorems were audited"
  Lean.logInfo m!"Audited {checked} CCFConsistency theorems for sorryAx."
"""


class InvariantProofError(ValueError):
    pass


def action_names(source: str) -> tuple[str, ...]:
    return tuple(ACTION_DECLARATION.findall(source))


def _replace_marked_block(source: str, replacement: str) -> str:
    before, begin, remainder = source.partition(MODEL_CHECK_BEGIN)
    if not begin:
        raise InvariantProofError("Veil source is missing the bounded-check start marker")
    _, end, after = remainder.partition(MODEL_CHECK_END)
    if not end:
        raise InvariantProofError("Veil source is missing the bounded-check end marker")
    return (
        before
        + "-- Generated deductive invariant check.\n"
        + replacement.rstrip()
        + "\n"
        + MODEL_CHECK_END
        + after
    )


def render_proof_source(
    source: str,
    action: str | None = None,
    smt_timeout: int = DEFAULT_SMT_TIMEOUT,
    diagnose: bool = False,
) -> str:
    """Render a proof or counterexample driver from the canonical model."""

    if source.count(IMPORT_MARKER) != 1:
        raise InvariantProofError("Veil source must contain exactly one Veil import")
    if source.count("#gen_spec") != 1:
        raise InvariantProofError("Veil source must contain exactly one #gen_spec")
    if smt_timeout <= 0:
        raise InvariantProofError("SMT timeout must be positive")

    available_actions = action_names(source)
    if action is not None and action not in available_actions:
        raise InvariantProofError(
            f"unknown action {action!r}; expected one of {', '.join(available_actions)}"
        )

    options = (
        "set_option veil.violationIsError true\n"
        f"set_option veil.smt.trust {str(diagnose).lower()}\n"
        f"set_option veil.printCounterexamples {str(diagnose).lower()}\n"
        f"set_option veil.smt.timeout {smt_timeout}\n"
    )
    source = source.replace(IMPORT_MARKER, IMPORT_MARKER + "\n" + options, 1)
    if action is None and not diagnose:
        commands = f"#check_invariants\n#gen_theorems\n\n{AXIOM_AUDIT}"
    elif action is None:
        commands = "#check_invariants"
    else:
        commands = f"#check_action {action}"
    return _replace_marked_block(source, commands)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a scratch Veil driver that reconstructs and kernel-checks "
            "Lean proofs for CCF consistency invariant obligations"
        )
    )
    parser.add_argument(
        "--spec",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("CCFConsistency.lean"),
        help="canonical Veil specification",
    )
    parser.add_argument(
        "--action",
        help="check one action; omit to check initialization and every action",
    )
    parser.add_argument(
        "--smt-timeout",
        type=int,
        default=DEFAULT_SMT_TIMEOUT,
        help="per-obligation SMT timeout in seconds",
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help=(
            "trust SMT answers and print counterexamples for diagnosis; "
            "do not use this mode as proof evidence"
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name(".generated")
        / "CCFConsistencyInvariantProofs.lean",
        help="generated Lean proof-driver path",
    )
    args = parser.parse_args()

    try:
        source = args.spec.read_text(encoding="utf-8")
        generated = render_proof_source(
            source, args.action, args.smt_timeout, diagnose=args.diagnose
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(generated, encoding="utf-8", newline="\n")
    except (OSError, InvariantProofError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
