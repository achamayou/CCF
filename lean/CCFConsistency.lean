-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFConsistency.Proofs
import CCFConsistency.Examples
import CCFConsistency.Trace

/-!
# CCF consistency in pure Lean

This library is a translation of the CCF consistency specification in
`tla/consistency` using ordinary Lean definitions and proofs.
-/

#print axioms CCFConsistency.reachableProved

run_cmd do
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
  Lean.logInfo m!"Audited {checked} pure Lean theorems for sorryAx."
