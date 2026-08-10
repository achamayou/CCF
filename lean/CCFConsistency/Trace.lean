-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFConsistency.Model

set_option autoImplicit false
set_option linter.unnecessarySeqFocus false
set_option linter.unusedSectionVars false

/-!
# Executable trace replay

The canonical `State` and its ten transition functions are executable. This
file only supplies finite Boolean guard checks and deterministic replay.
Every accepted action is proved to be a canonical `Step`, so a successful
replay produces an ordinary `Reachable` state without a second state model.
-/

namespace CCFConsistency

universe uTx uView uSeqno uEvent u

class TraceDomain (Alpha : Type u) where
  values : List Alpha
  complete : forall value, List.Mem value values

instance finTraceDomain (size : Nat) : TraceDomain (Fin size) where
  values := List.finRange size
  complete value := List.mem_finRange value

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

def finiteAll
    {Alpha : Type u}
    [TraceDomain Alpha]
    (predicate : Alpha -> Bool) :
    Bool :=
  TraceDomain.values.all predicate

def finiteAny
    {Alpha : Type u}
    [TraceDomain Alpha]
    (predicate : Alpha -> Bool) :
    Bool :=
  TraceDomain.values.any predicate

@[simp]
theorem finiteAll_eq_true
    {Alpha : Type u}
    [TraceDomain Alpha]
    (predicate : Alpha -> Bool) :
    finiteAll predicate = true <->
      forall item, predicate item = true := by
  constructor
  case mp =>
    intro all item
    exact List.all_eq_true.mp all item (TraceDomain.complete item)
  case mpr =>
    intro all
    exact List.all_eq_true.mpr fun item _ => all item

@[simp]
theorem finiteAny_eq_true
    {Alpha : Type u}
    [TraceDomain Alpha]
    (predicate : Alpha -> Bool) :
    finiteAny predicate = true <->
      Exists fun item => predicate item = true := by
  constructor
  case mp =>
    intro any
    cases List.any_eq_true.mp any with
    | intro item found =>
        exact Exists.intro item found.2
  case mpr =>
    intro existsItem
    cases existsItem with
    | intro item found =>
        exact
          List.any_eq_true.mpr
            (Exists.intro item (And.intro (TraceDomain.complete item) found))

def notBool (value : Bool) : Bool :=
  !value

def impliesBool (antecedent consequent : Bool) : Bool :=
  !antecedent || consequent

@[simp]
theorem notBool_eq_true (value : Bool) :
    notBool value = true <-> Not (value = true) := by
  cases value <;> simp [notBool]

@[simp]
theorem impliesBool_eq_true (antecedent consequent : Bool) :
    impliesBool antecedent consequent = true <->
      (antecedent = true -> consequent = true) := by
  cases antecedent <;> cases consequent <;> simp [impliesBool]

def orderedLtBool
    {Alpha : Type u}
    [LinearOrder Alpha]
    (left right : Alpha) :
    Bool :=
  decide (left <= right) && decide (Not (left = right))

@[simp]
theorem orderedLtBool_eq_true
    {Alpha : Type u}
    [LinearOrder Alpha]
    (left right : Alpha) :
    orderedLtBool left right = true <->
      orderedLt left right := by
  simp [orderedLtBool, orderedLt]

namespace State

def responseEventBool
    (state : State Tx View Seqno Event)
    (event : Event) :
    Bool :=
  state.rwResponseEvent event || state.roResponseEvent event

def rwRequestedBool
    (state : State Tx View Seqno Event)
    (tx : Tx) :
    Bool :=
  finiteAny fun event =>
    state.rwRequestEvent event && decide (state.eventTx event = tx)

def roRequestedBool
    (state : State Tx View Seqno Event)
    (tx : Tx) :
    Bool :=
  finiteAny fun event =>
    state.roRequestEvent event && decide (state.eventTx event = tx)

def requestedBool
    (state : State Tx View Seqno Event)
    (tx : Tx) :
    Bool :=
  state.rwRequestedBool tx || state.roRequestedBool tx

def respondedBool
    (state : State Tx View Seqno Event)
    (tx : Tx) :
    Bool :=
  finiteAny fun event =>
    state.responseEventBool event && decide (state.eventTx event = tx)

def txInLedgerBool
    (state : State Tx View Seqno Event)
    (tx : Tx) :
    Bool :=
  finiteAny fun branch =>
    finiteAny fun slot =>
      state.clientEntry branch slot &&
        decide (state.entryTx branch slot = tx)

def committedTxIdBool
    (state : State Tx View Seqno Event)
    (view : View)
    (seqno : Seqno) :
    Bool :=
  finiteAny fun event =>
    state.committedStatusEvent event &&
      decide (state.eventView event = view) &&
        decide (state.eventSeqno event = seqno)

def currentViewBool
    (state : State Tx View Seqno Event)
    (view : View) :
    Bool :=
  state.activeView view &&
    finiteAll fun later =>
      impliesBool
        (orderedLtBool view later)
        (notBool (state.activeView later))

def nextViewBool
    (state : State Tx View Seqno Event)
    (view : View) :
    Bool :=
  notBool (state.activeView view) &&
    finiteAll fun earlier =>
      impliesBool (orderedLtBool earlier view) (state.activeView earlier)

def nextLedgerSlotBool
    (state : State Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) :
    Bool :=
  notBool (state.ledgerEntry branch slot) &&
    finiteAll fun earlier =>
      impliesBool
        (orderedLtBool earlier slot)
        (state.ledgerEntry branch earlier)

def lastLedgerSlotBool
    (state : State Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) :
    Bool :=
  state.ledgerEntry branch slot &&
    finiteAll fun occupied =>
      impliesBool
        (state.ledgerEntry branch occupied)
        (decide (occupied <= slot))

def nextHistoryEventBool
    (state : State Tx View Seqno Event)
    (event : Event) :
    Bool :=
  notBool (state.eventUsed event) &&
    finiteAll fun earlier =>
      impliesBool (orderedLtBool earlier event) (state.eventUsed earlier)

def nextTxBool
    (state : State Tx View Seqno Event)
    (tx : Tx) :
    Bool :=
  notBool (state.requestedBool tx) &&
    finiteAll fun earlier =>
      impliesBool (orderedLtBool earlier tx) (state.requestedBool earlier)

def noCommittedTxIdBool
    (state : State Tx View Seqno Event) :
    Bool :=
  finiteAll fun view =>
    finiteAll fun seqno =>
      notBool (state.committedTxIdBool view seqno)

def maxCommittedSeqnoBool
    (state : State Tx View Seqno Event)
    (seqno : Seqno) :
    Bool :=
  (finiteAny fun view => state.committedTxIdBool view seqno) &&
    finiteAll fun view =>
      finiteAll fun other =>
        impliesBool
          (state.committedTxIdBool view other)
          (decide (other <= seqno))

def validTruncationSourceBool
    (state : State Tx View Seqno Event)
    (source : View)
    (cut : Seqno) :
    Bool :=
  state.noCommittedTxIdBool ||
    finiteAny fun commitSeq =>
      state.maxCommittedSeqnoBool commitSeq &&
        state.ledgerEntry source commitSeq &&
          state.committedTxIdBool
              (state.entryView source commitSeq)
              commitSeq &&
            decide (commitSeq <= cut)

def invalidCommitPassedBool
    (state : State Tx View Seqno Event)
    (response : Event)
    (current : View)
    (commitSeq : Seqno) :
    Bool :=
  state.maxCommittedSeqnoBool commitSeq &&
    decide (state.eventSeqno response <= commitSeq) &&
      state.ledgerEntry current (state.eventSeqno response) &&
        decide (
          Not (
            state.entryView current (state.eventSeqno response) =
              state.eventView response))

def invalidCommitInNewerViewBool
    (state : State Tx View Seqno Event)
    (response : Event)
    (current : View)
    (commitSeq : Seqno) :
    Bool :=
  state.maxCommittedSeqnoBool commitSeq &&
    orderedLtBool commitSeq (state.eventSeqno response) &&
      state.ledgerEntry current commitSeq &&
        orderedLtBool
          (state.eventView response)
          (state.entryView current commitSeq)

def invalidCurrentSuffixBool
    (state : State Tx View Seqno Event)
    (response : Event)
    (current : View) :
    Bool :=
  decide (state.eventView response = current) &&
    finiteAll fun committedView =>
      finiteAll fun committedSeq =>
        impliesBool
          (state.committedTxIdBool committedView committedSeq)
          (orderedLtBool committedSeq (state.eventSeqno response))

def invalidStatusAllowedBool
    (state : State Tx View Seqno Event)
    (response : Event) :
    Bool :=
  finiteAny fun current =>
    state.currentViewBool current &&
      ((finiteAny fun commitSeq =>
          state.invalidCommitPassedBool response current commitSeq) ||
        (finiteAny fun commitSeq =>
          state.invalidCommitInNewerViewBool response current commitSeq) ||
        state.invalidCurrentSuffixBool response current)

@[simp]
theorem responseEventBool_eq_true
    (state : State Tx View Seqno Event)
    (event : Event) :
    state.responseEventBool event = true <->
      state.responseEvent event := by
  simp [responseEventBool, responseEvent]

@[simp]
theorem rwRequestedBool_eq_true
    (state : State Tx View Seqno Event)
    (tx : Tx) :
    state.rwRequestedBool tx = true <->
      state.rwRequested tx := by
  simp [rwRequestedBool, rwRequested]

@[simp]
theorem roRequestedBool_eq_true
    (state : State Tx View Seqno Event)
    (tx : Tx) :
    state.roRequestedBool tx = true <->
      state.roRequested tx := by
  simp [roRequestedBool, roRequested]

@[simp]
theorem requestedBool_eq_true
    (state : State Tx View Seqno Event)
    (tx : Tx) :
    state.requestedBool tx = true <->
      state.requested tx := by
  simp [requestedBool, requested]

@[simp]
theorem respondedBool_eq_true
    (state : State Tx View Seqno Event)
    (tx : Tx) :
    state.respondedBool tx = true <->
      state.responded tx := by
  simp [respondedBool, responded]

@[simp]
theorem txInLedgerBool_eq_true
    (state : State Tx View Seqno Event)
    (tx : Tx) :
    state.txInLedgerBool tx = true <->
      state.txInLedger tx := by
  simp [txInLedgerBool, txInLedger]

@[simp]
theorem committedTxIdBool_eq_true
    (state : State Tx View Seqno Event)
    (view : View)
    (seqno : Seqno) :
    state.committedTxIdBool view seqno = true <->
      state.committedTxId view seqno := by
  simp [committedTxIdBool, committedTxId]
  aesop

@[simp]
theorem currentViewBool_eq_true
    (state : State Tx View Seqno Event)
    (view : View) :
    state.currentViewBool view = true <->
      state.currentView view := by
  simp [
    currentViewBool,
    currentView,
    viewLt
  ]

@[simp]
theorem nextViewBool_eq_true
    (state : State Tx View Seqno Event)
    (view : View) :
    state.nextViewBool view = true <->
      state.nextView view := by
  simp [
    nextViewBool,
    nextView,
    viewLt
  ]

@[simp]
theorem nextLedgerSlotBool_eq_true
    (state : State Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) :
    state.nextLedgerSlotBool branch slot = true <->
      state.nextLedgerSlot branch slot := by
  simp [
    nextLedgerSlotBool,
    nextLedgerSlot,
    seqLt
  ]

@[simp]
theorem lastLedgerSlotBool_eq_true
    (state : State Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) :
    state.lastLedgerSlotBool branch slot = true <->
      state.lastLedgerSlot branch slot := by
  simp [lastLedgerSlotBool, lastLedgerSlot]

@[simp]
theorem nextHistoryEventBool_eq_true
    (state : State Tx View Seqno Event)
    (event : Event) :
    state.nextHistoryEventBool event = true <->
      state.nextHistoryEvent event := by
  simp [
    nextHistoryEventBool,
    nextHistoryEvent,
    eventLt
  ]

@[simp]
theorem nextTxBool_eq_true
    (state : State Tx View Seqno Event)
    (tx : Tx) :
    state.nextTxBool tx = true <->
      state.nextTx tx := by
  simp [
    nextTxBool,
    nextTx,
    txLt
  ]

@[simp]
theorem noCommittedTxIdBool_eq_true
    (state : State Tx View Seqno Event) :
    state.noCommittedTxIdBool = true <->
      state.noCommittedTxId := by
  simp [noCommittedTxIdBool, noCommittedTxId]

@[simp]
theorem maxCommittedSeqnoBool_eq_true
    (state : State Tx View Seqno Event)
    (seqno : Seqno) :
    state.maxCommittedSeqnoBool seqno = true <->
      state.maxCommittedSeqno seqno := by
  simp [maxCommittedSeqnoBool, maxCommittedSeqno]

@[simp]
theorem validTruncationSourceBool_eq_true
    (state : State Tx View Seqno Event)
    (source : View)
    (cut : Seqno) :
    state.validTruncationSourceBool source cut = true <->
      state.validTruncationSource source cut := by
  simp [validTruncationSourceBool, validTruncationSource]
  aesop

@[simp]
theorem invalidCommitPassedBool_eq_true
    (state : State Tx View Seqno Event)
    (response : Event)
    (current : View)
    (commitSeq : Seqno) :
    state.invalidCommitPassedBool response current commitSeq = true <->
      state.maxCommittedSeqno commitSeq /\
        state.eventSeqno response <= commitSeq /\
          state.ledgerEntry current (state.eventSeqno response) /\
            Not (
              state.entryView current (state.eventSeqno response) =
                state.eventView response) := by
  simp [invalidCommitPassedBool]
  aesop

@[simp]
theorem invalidCommitInNewerViewBool_eq_true
    (state : State Tx View Seqno Event)
    (response : Event)
    (current : View)
    (commitSeq : Seqno) :
    state.invalidCommitInNewerViewBool response current commitSeq = true <->
      state.maxCommittedSeqno commitSeq /\
        state.seqLt commitSeq (state.eventSeqno response) /\
          state.ledgerEntry current commitSeq /\
            state.viewLt
              (state.eventView response)
              (state.entryView current commitSeq) := by
  simp [
    invalidCommitInNewerViewBool,
    seqLt,
    viewLt
  ]
  aesop

@[simp]
theorem invalidCurrentSuffixBool_eq_true
    (state : State Tx View Seqno Event)
    (response : Event)
    (current : View) :
    state.invalidCurrentSuffixBool response current = true <->
      state.eventView response = current /\
        forall committedView committedSeq,
          state.committedTxId committedView committedSeq ->
            state.seqLt committedSeq (state.eventSeqno response) := by
  simp [invalidCurrentSuffixBool, seqLt]

@[simp]
theorem invalidStatusAllowedBool_eq_true
    (state : State Tx View Seqno Event)
    (response : Event) :
    state.invalidStatusAllowedBool response = true <->
      state.invalidStatusAllowed response := by
  simp [
    invalidStatusAllowedBool,
    invalidStatusAllowed
  ]
  aesop (config := { maxRuleApplications := 1000 })

end State

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

def enabledBool
    (action : TraceAction Tx View Seqno Event)
    (state : State Tx View Seqno Event) :
    Bool :=
  match action with
  | .rwTxRequest tx event =>
      state.nextTxBool tx && state.nextHistoryEventBool event
  | .roTxRequest tx event =>
      state.nextTxBool tx && state.nextHistoryEventBool event
  | .rwTxExecute request branch slot =>
      state.rwRequestEvent request &&
        notBool (state.txInLedgerBool (state.eventTx request)) &&
          state.activeView branch &&
            state.nextLedgerSlotBool branch slot
  | .appendOtherTxn branch slot =>
      state.activeView branch && state.nextLedgerSlotBool branch slot
  | .rwTxResponse request branch slot response =>
      state.rwRequestEvent request &&
        notBool (state.respondedBool (state.eventTx request)) &&
          state.activeView branch &&
            state.clientEntry branch slot &&
              decide (state.entryTx branch slot = state.eventTx request) &&
                state.nextHistoryEventBool response
  | .roTxResponse request branch last response =>
      state.roRequestEvent request &&
        notBool (state.respondedBool (state.eventTx request)) &&
          state.activeView branch &&
            state.lastLedgerSlotBool branch last &&
              state.nextHistoryEventBool response
  | .statusCommittedResponse response status current =>
      state.rwResponseEvent response &&
        state.currentViewBool current &&
          state.ledgerEntry current (state.eventSeqno response) &&
            decide (
              state.entryView current (state.eventSeqno response) =
                state.eventView response) &&
              notBool
                  (finiteAny fun invalid =>
                    state.invalidStatusEvent invalid &&
                      decide (
                        state.eventView invalid = state.eventView response) &&
                        decide (
                          state.eventSeqno invalid <=
                            state.eventSeqno response)) &&
                state.nextHistoryEventBool status
  | .statusInvalidResponse response status =>
      state.rwResponseEvent response &&
        state.invalidStatusAllowedBool response &&
          state.nextHistoryEventBool status
  | .truncateLedger source cut newView =>
      state.activeView source &&
        state.ledgerEntry source cut &&
          state.validTruncationSourceBool source cut &&
            state.nextViewBool newView
  | .truncateLedgerToEmpty source newView =>
      state.activeView source &&
        state.noCommittedTxIdBool &&
          state.nextViewBool newView

theorem enabledBool_sound
    (action : TraceAction Tx View Seqno Event)
    (state : State Tx View Seqno Event)
    (enabled : action.enabledBool state = true) :
    action.Enabled state := by
  cases action <;>
    simp [enabledBool] at enabled <;>
    simp only [Enabled] <;>
    aesop

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
        Step.rwTxExecute
          state
          request
          branch
          slot
          enabled.1
          enabled.2.1
          enabled.2.2.1
          enabled.2.2.2
  | appendOtherTxn branch slot =>
      exact
        Step.appendOtherTxn
          state
          branch
          slot
          enabled.1
          enabled.2
  | rwTxResponse request branch slot response =>
      exact
        Step.rwTxResponse
          state
          request
          branch
          slot
          response
          enabled.1
          enabled.2.1
          enabled.2.2.1
          enabled.2.2.2.1
          enabled.2.2.2.2.1
          enabled.2.2.2.2.2
  | roTxResponse request branch last response =>
      exact
        Step.roTxResponse
          state
          request
          branch
          last
          response
          enabled.1
          enabled.2.1
          enabled.2.2.1
          enabled.2.2.2.1
          enabled.2.2.2.2
  | statusCommittedResponse response status current =>
      exact
        Step.statusCommittedResponse
          state
          response
          status
          current
          enabled.1
          enabled.2.1
          enabled.2.2.1
          enabled.2.2.2.1
          enabled.2.2.2.2.1
          enabled.2.2.2.2.2
  | statusInvalidResponse response status =>
      exact
        Step.statusInvalidResponse
          state
          response
          status
          enabled.1
          enabled.2.1
          enabled.2.2
  | truncateLedger source cut newView =>
      exact
        Step.truncateLedger
          state
          source
          cut
          newView
          enabled.1
          enabled.2.1
          enabled.2.2.1
          enabled.2.2.2
  | truncateLedgerToEmpty source newView =>
      exact
        Step.truncateLedgerToEmpty
          state
          source
          newView
          enabled.1
          enabled.2.1
          enabled.2.2

end TraceAction

def replay
    (actions : List (TraceAction Tx View Seqno Event))
    (state : State Tx View Seqno Event) :
    Option (State Tx View Seqno Event) :=
  match actions with
  | [] => some state
  | action :: remaining =>
      match action.enabledBool state with
      | true => replay remaining (action.next state)
      | false => none
termination_by actions.length

theorem replay_reachable
    {actions : List (TraceAction Tx View Seqno Event)}
    {state final : State Tx View Seqno Event}
    (stateReachable : Reachable state)
    (replayed : replay actions state = some final) :
    Reachable final := by
  induction actions generalizing state with
  | nil =>
      simp [replay] at replayed
      subst final
      exact stateReachable
  | cons action remaining induction =>
      cases enabled : action.enabledBool state with
      | false =>
          simp [replay, enabled] at replayed
      | true =>
        have semanticEnabled := action.enabledBool_sound state enabled
        simp [replay, enabled] at replayed
        exact
          induction
            (Reachable.step stateReachable
              (action.enabled_step state semanticEnabled))
            replayed

theorem replay_from_initial
    {actions : List (TraceAction Tx View Seqno Event)}
    (success :
      (replay actions
        (initialState : State Tx View Seqno Event)).isSome) :
    Exists fun final =>
      replay actions (initialState : State Tx View Seqno Event) =
        some final /\
        Reachable final := by
  let existsResult := Option.isSome_iff_exists.mp success
  cases existsResult with
  | intro final replayed =>
      exact
        Exists.intro final
          (And.intro replayed
            (replay_reachable Reachable.initial replayed))

end CCFConsistency
