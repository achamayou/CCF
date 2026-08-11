-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFConsistency.Model
import CCFConsistency.TraceInfra

set_option autoImplicit false

/-!
# CCF consistency trace replay

The generic half of trace replay lives in `CCFConsistency/TraceInfra.lean`:
finite domains, decidable quantifiers, and the replay engine with its
reachability theorems. This file is the CCF-specific half, and it is
deliberately short so it can be checked by eye.

It contains exactly three things:

1. `Decidable` instances for the derived predicates of `Model.lean`. Each is
   inferred from the predicate itself, so it cannot disagree with it; nothing
   here restates a guard.
2. `TraceAction`, one constructor per action, and `Enabled`, which lists the
   guards of each action.
3. `next`, which dispatches to the canonical transition functions, and
   `enabled_step`, which proves an enabled action is a canonical `Step`.

Auditing this file means checking one thing: that `Enabled` and `next` match
the corresponding `Step` constructor in `Model.lean`. `enabled_step` is exactly
that correspondence, and the compiler checks it.
-/

namespace CCFConsistency

open TraceReplay

universe uTx uView uSeqno uEvent

variable
  {Tx : Type uTx}
  {View : Type uView}
  {Seqno : Type uSeqno}
  {Event : Type uEvent}

variable
  [LinearOrder Tx] [OrderBot Tx] [TraceDomain Tx]
  [LinearOrder View] [OrderBot View] [TraceDomain View]
  [LinearOrder Seqno] [OrderBot Seqno] [TraceDomain Seqno]
  [LinearOrder Event] [OrderBot Event] [TraceDomain Event]

/-! ## Decidability of the derived predicates

A trace fixes each domain to a finite one, so every quantifier of the model can
be evaluated. Each instance below is obtained by unfolding the predicate's own
definition and letting instance resolution do the rest, so no instance can
disagree with the predicate it decides. They are ordered so each may use the
previous. -/

instance instDecidableOrderedLt
    {Alpha : Type uTx} [LinearOrder Alpha] (left right : Alpha) :
    Decidable (orderedLt left right) := by
  unfold orderedLt
  infer_instance

namespace State

instance instDecidableViewLt
    (state : State Tx View Seqno Event) (left right : View) :
    Decidable (state.viewLt left right) := by
  unfold viewLt
  infer_instance

instance instDecidableSeqLt
    (state : State Tx View Seqno Event) (left right : Seqno) :
    Decidable (state.seqLt left right) := by
  unfold seqLt
  infer_instance

instance instDecidableEventLt
    (state : State Tx View Seqno Event) (left right : Event) :
    Decidable (state.eventLt left right) := by
  unfold eventLt
  infer_instance

instance instDecidableTxLt
    (state : State Tx View Seqno Event) (left right : Tx) :
    Decidable (state.txLt left right) := by
  unfold txLt
  infer_instance

instance instDecidableResponseEvent
    (state : State Tx View Seqno Event) (event : Event) :
    Decidable (state.responseEvent event) := by
  unfold responseEvent
  infer_instance

instance instDecidableRwRequested
    (state : State Tx View Seqno Event) (tx : Tx) :
    Decidable (state.rwRequested tx) := by
  unfold rwRequested
  infer_instance

instance instDecidableRoRequested
    (state : State Tx View Seqno Event) (tx : Tx) :
    Decidable (state.roRequested tx) := by
  unfold roRequested
  infer_instance

instance instDecidableRequested
    (state : State Tx View Seqno Event) (tx : Tx) :
    Decidable (state.requested tx) := by
  unfold requested
  infer_instance

instance instDecidableResponded
    (state : State Tx View Seqno Event) (tx : Tx) :
    Decidable (state.responded tx) := by
  unfold responded
  infer_instance

instance instDecidableTxInLedger
    (state : State Tx View Seqno Event) (tx : Tx) :
    Decidable (state.txInLedger tx) := by
  unfold txInLedger
  infer_instance

instance instDecidableCommittedTxId
    (state : State Tx View Seqno Event) (view : View) (seqno : Seqno) :
    Decidable (state.committedTxId view seqno) := by
  unfold committedTxId
  infer_instance

instance instDecidableCurrentView
    (state : State Tx View Seqno Event) (view : View) :
    Decidable (state.currentView view) := by
  unfold currentView
  infer_instance

instance instDecidableNextView
    (state : State Tx View Seqno Event) (view : View) :
    Decidable (state.nextView view) := by
  unfold nextView
  infer_instance

instance instDecidableNextLedgerSlot
    (state : State Tx View Seqno Event) (branch : View) (slot : Seqno) :
    Decidable (state.nextLedgerSlot branch slot) := by
  unfold nextLedgerSlot
  infer_instance

instance instDecidableLastLedgerSlot
    (state : State Tx View Seqno Event) (branch : View) (slot : Seqno) :
    Decidable (state.lastLedgerSlot branch slot) := by
  unfold lastLedgerSlot
  infer_instance

instance instDecidableNextHistoryEvent
    (state : State Tx View Seqno Event) (event : Event) :
    Decidable (state.nextHistoryEvent event) := by
  unfold nextHistoryEvent
  infer_instance

instance instDecidableNextTx
    (state : State Tx View Seqno Event) (tx : Tx) :
    Decidable (state.nextTx tx) := by
  unfold nextTx
  infer_instance

instance instDecidableNoCommittedTxId
    (state : State Tx View Seqno Event) :
    Decidable state.noCommittedTxId := by
  unfold noCommittedTxId
  infer_instance

instance instDecidableMaxCommittedSeqno
    (state : State Tx View Seqno Event) (seqno : Seqno) :
    Decidable (state.maxCommittedSeqno seqno) := by
  unfold maxCommittedSeqno
  infer_instance

instance instDecidableValidTruncationSource
    (state : State Tx View Seqno Event) (source : View) (cut : Seqno) :
    Decidable (state.validTruncationSource source cut) := by
  unfold validTruncationSource
  infer_instance

instance instDecidableInvalidStatusAllowed
    (state : State Tx View Seqno Event) (response : Event) :
    Decidable (state.invalidStatusAllowed response) := by
  unfold invalidStatusAllowed
  infer_instance

end State

/-! ## Actions -/

inductive TraceAction
    (Tx : Type uTx)
    (View : Type uView)
    (Seqno : Type uSeqno)
    (Event : Type uEvent) where
  | rwTxRequest (tx : Tx) (event : Event)
  | roTxRequest (tx : Tx) (event : Event)
  | rwTxExecute (request : Event) (branch : View) (slot : Seqno)
  | appendOtherTxn (branch : View) (slot : Seqno)
  | rwTxResponse
      (request : Event)
      (branch : View)
      (slot : Seqno)
      (response : Event)
  | roTxResponse
      (request : Event)
      (branch : View)
      (last : Seqno)
      (response : Event)
  | statusCommittedResponse
      (response : Event)
      (status : Event)
      (current : View)
  | statusInvalidResponse (response : Event) (status : Event)
  | truncateLedger (source : View) (cut : Seqno) (newView : View)
  | truncateLedgerToEmpty (source : View) (newView : View)

namespace TraceAction

/-- The guard of each action. Each clause is the hypothesis list of the
corresponding `Step` constructor in `Model.lean`, in the same order. -/
def Enabled
    (action : TraceAction Tx View Seqno Event)
    (state : State Tx View Seqno Event) :
    Prop :=
  match action with
  | .rwTxRequest tx event =>
      state.nextTx tx /\ state.nextHistoryEvent event
  | .roTxRequest tx event =>
      state.nextTx tx /\ state.nextHistoryEvent event
  | .rwTxExecute request branch slot =>
      state.rwRequestEvent request /\
        Not (state.txInLedger (state.eventTx request)) /\
          state.activeView branch /\
            state.nextLedgerSlot branch slot
  | .appendOtherTxn branch slot =>
      state.activeView branch /\ state.nextLedgerSlot branch slot
  | .rwTxResponse request branch slot response =>
      state.rwRequestEvent request /\
        Not (state.responded (state.eventTx request)) /\
          state.activeView branch /\
            state.clientEntry branch slot /\
              state.entryTx branch slot = state.eventTx request /\
                state.nextHistoryEvent response
  | .roTxResponse request branch last response =>
      state.roRequestEvent request /\
        Not (state.responded (state.eventTx request)) /\
          state.activeView branch /\
            state.lastLedgerSlot branch last /\
              state.nextHistoryEvent response
  | .statusCommittedResponse response status current =>
      state.rwResponseEvent response /\
        state.currentView current /\
          state.ledgerEntry current (state.eventSeqno response) /\
            state.entryView current (state.eventSeqno response) =
              state.eventView response /\
              Not (Exists fun invalid =>
                state.invalidStatusEvent invalid /\
                  state.eventView invalid = state.eventView response /\
                    state.eventSeqno invalid <= state.eventSeqno response) /\
                state.nextHistoryEvent status
  | .statusInvalidResponse response status =>
      state.rwResponseEvent response /\
        state.invalidStatusAllowed response /\
          state.nextHistoryEvent status
  | .truncateLedger source cut newView =>
      state.activeView source /\
        state.ledgerEntry source cut /\
          state.validTruncationSource source cut /\
            state.nextView newView
  | .truncateLedgerToEmpty source newView =>
      state.activeView source /\ state.noCommittedTxId /\ state.nextView newView

instance instDecidableEnabled
    (action : TraceAction Tx View Seqno Event)
    (state : State Tx View Seqno Event) :
    Decidable (action.Enabled state) := by
  cases action <;> unfold Enabled <;> infer_instance

/-- The transition of each action, dispatched to the canonical transition
functions of `Model.lean`. There is no second state model. -/
def next
    (action : TraceAction Tx View Seqno Event)
    (state : State Tx View Seqno Event) :
    State Tx View Seqno Event :=
  match action with
  | .rwTxRequest tx event =>
      CCFConsistency.rwTxRequestNext state tx event
  | .roTxRequest tx event =>
      CCFConsistency.roTxRequestNext state tx event
  | .rwTxExecute request branch slot =>
      CCFConsistency.rwTxExecuteNext state request branch slot
  | .appendOtherTxn branch slot =>
      CCFConsistency.appendOtherTxnNext state branch slot
  | .rwTxResponse request branch slot response =>
      CCFConsistency.rwTxResponseNext state request branch slot response
  | .roTxResponse request branch last response =>
      CCFConsistency.roTxResponseNext state request branch last response
  | .statusCommittedResponse response status _ =>
      CCFConsistency.statusCommittedResponseNext state response status
  | .statusInvalidResponse response status =>
      CCFConsistency.statusInvalidResponseNext state response status
  | .truncateLedger source cut newView =>
      CCFConsistency.truncateLedgerNext state source cut newView
  | .truncateLedgerToEmpty _ newView =>
      CCFConsistency.truncateLedgerToEmptyNext state newView

omit [TraceDomain Tx] [TraceDomain View]
  [OrderBot Seqno] [TraceDomain Seqno]
  [OrderBot Event] [TraceDomain Event] in
/-- An enabled action is a canonical `Step`. This is the whole correspondence
between this file and `Model.lean`. -/
theorem enabled_step
    (action : TraceAction Tx View Seqno Event)
    (state : State Tx View Seqno Event)
    (enabled : action.Enabled state) :
    Step state (action.next state) := by
  cases action with
  | rwTxRequest tx event =>
      exact Step.rwTxRequest state tx event enabled.1 enabled.2
  | roTxRequest tx event =>
      exact Step.roTxRequest state tx event enabled.1 enabled.2
  | rwTxExecute request branch slot =>
      exact
        Step.rwTxExecute state request branch slot
          enabled.1 enabled.2.1 enabled.2.2.1 enabled.2.2.2
  | appendOtherTxn branch slot =>
      exact Step.appendOtherTxn state branch slot enabled.1 enabled.2
  | rwTxResponse request branch slot response =>
      exact
        Step.rwTxResponse state request branch slot response
          enabled.1 enabled.2.1 enabled.2.2.1 enabled.2.2.2.1
          enabled.2.2.2.2.1 enabled.2.2.2.2.2
  | roTxResponse request branch last response =>
      exact
        Step.roTxResponse state request branch last response
          enabled.1 enabled.2.1 enabled.2.2.1 enabled.2.2.2.1 enabled.2.2.2.2
  | statusCommittedResponse response status current =>
      exact
        Step.statusCommittedResponse state response status current
          enabled.1 enabled.2.1 enabled.2.2.1 enabled.2.2.2.1
          enabled.2.2.2.2.1 enabled.2.2.2.2.2
  | statusInvalidResponse response status =>
      exact
        Step.statusInvalidResponse state response status
          enabled.1 enabled.2.1 enabled.2.2
  | truncateLedger source cut newView =>
      exact
        Step.truncateLedger state source cut newView
          enabled.1 enabled.2.1 enabled.2.2.1 enabled.2.2.2
  | truncateLedgerToEmpty source newView =>
      exact
        Step.truncateLedgerToEmpty state source newView
          enabled.1 enabled.2.1 enabled.2.2

end TraceAction

/-! ## Replay -/

/-- The CCF consistency model as a replayable system. The guard is evaluated,
not restated: `decide` uses the instances above. -/
def traceSystem :
    TraceReplay.System
      (State Tx View Seqno Event)
      (TraceAction Tx View Seqno Event) where
  Reachable := Reachable
  enabled action state := decide (action.Enabled state)
  next action state := action.next state
  preserves action state reachable enabled :=
    Reachable.step reachable
      (action.enabled_step state (of_decide_eq_true enabled))

/-- Replay a trace from a state, failing at the first rejected guard. -/
abbrev replay
    (actions : List (TraceAction Tx View Seqno Event))
    (state : State Tx View Seqno Event) :
    Option (State Tx View Seqno Event) :=
  traceSystem.replay actions state

omit [OrderBot Event] in
/-- A successful replay from the initializer reaches a `Reachable` state. This
is the theorem every generated trace module applies. -/
theorem replay_from_initial
    {actions : List (TraceAction Tx View Seqno Event)}
    (success :
      (replay actions (initialState : State Tx View Seqno Event)).isSome) :
    Exists fun final =>
      replay actions (initialState : State Tx View Seqno Event) =
        some final /\
        Reachable final :=
  traceSystem.replay_sound Reachable.initial success

end CCFConsistency
