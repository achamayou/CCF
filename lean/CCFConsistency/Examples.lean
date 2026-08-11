-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFConsistency.Model

set_option autoImplicit false

/-!
# Non-vacuity examples

These examples instantiate every abstract domain with `Nat` and construct an
ordinary request, execution, and response path. They ensure that the translated
guards are jointly satisfiable rather than making safety vacuous.
-/

namespace CCFConsistency.Examples

abbrev NatState := State Nat Nat Nat Nat

noncomputable def requestedState : NatState :=
  rwTxRequestNext (initialState : NatState) 0 0

noncomputable def executedState : NatState :=
  rwTxExecuteNext requestedState 0 0 0

noncomputable def respondedState : NatState :=
  rwTxResponseNext executedState 0 0 0 1

theorem requestReachable : Reachable requestedState := by
  apply Reachable.step Reachable.initial
  apply Step.rwTxRequest
  · simp [
      State.nextTx,
      State.requested,
      State.rwRequested,
      State.roRequested,
      State.txLt,
      orderedLt,
      initialState
    ]
  · simp [
      State.nextHistoryEvent,
      State.eventLt,
      orderedLt,
      initialState
    ]

theorem executeReachable : Reachable executedState := by
  apply Reachable.step requestReachable
  apply Step.rwTxExecute
  · simp [requestedState, rwTxRequestNext, updateUnary]
  · simp [
      State.txInLedger,
      requestedState,
      rwTxRequestNext,
      initialState
    ]
  · simp [requestedState, rwTxRequestNext, initialState]
  · simp [
      State.nextLedgerSlot,
      State.seqLt,
      orderedLt,
      requestedState,
      rwTxRequestNext,
      initialState
    ]

theorem responseReachable : Reachable respondedState := by
  apply Reachable.step executeReachable
  apply Step.rwTxResponse
  · simp [
      executedState,
      rwTxExecuteNext,
      requestedState,
      rwTxRequestNext,
      updateUnary
    ]
  · simp [
      State.responded,
      State.responseEvent,
      executedState,
      rwTxExecuteNext,
      requestedState,
      rwTxRequestNext,
      initialState
    ]
  · simp [
      executedState,
      rwTxExecuteNext,
      requestedState,
      rwTxRequestNext,
      initialState
    ]
  · simp [
      executedState,
      rwTxExecuteNext,
      updateBinary,
      updateUnary
    ]
  · simp [
      executedState,
      rwTxExecuteNext,
      requestedState,
      rwTxRequestNext,
      updateBinary,
      updateUnary
    ]
  · simp [
      State.nextHistoryEvent,
      State.eventLt,
      orderedLt,
      executedState,
      rwTxExecuteNext,
      requestedState,
      rwTxRequestNext,
      initialState,
      updateBinary,
      updateUnary
    ]
    omega

end CCFConsistency.Examples
