-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFConsistency.Proofs

set_option autoImplicit false
set_option linter.unnecessarySeqFocus false
set_option linter.unusedSectionVars false

/-!
# Executable trace replay

`ConcreteState` stores decidable relations as `Bool` functions. Its transition
functions are executable counterparts of the canonical `State` transitions.
The soundness lemmas below connect every successful concrete replay step to a
canonical `Step`, so a computed replay yields an ordinary `Reachable` proof.
-/

namespace CCFConsistency

universe uTx uView uSeqno uEvent u v

class TraceDomain (Alpha : Type u) where
  values : List Alpha
  complete : forall value, List.Mem value values

instance finTraceDomain (size : Nat) : TraceDomain (Fin size) where
  values := List.finRange size
  complete value := List.mem_finRange value

structure ConcreteState
    (Tx : Type uTx)
    (View : Type uView)
    (Seqno : Type uSeqno)
    (Event : Type uEvent) where
  activeView : View -> Bool
  ledgerEntry : View -> Seqno -> Bool
  clientEntry : View -> Seqno -> Bool
  entryView : View -> Seqno -> View
  entryTx : View -> Seqno -> Tx
  eventUsed : Event -> Bool
  rwRequestEvent : Event -> Bool
  rwResponseEvent : Event -> Bool
  roRequestEvent : Event -> Bool
  roResponseEvent : Event -> Bool
  committedStatusEvent : Event -> Bool
  invalidStatusEvent : Event -> Bool
  eventTx : Event -> Tx
  eventView : Event -> View
  eventSeqno : Event -> Seqno
  eventBranch : Event -> View

variable
  {Tx : Type uTx}
  {View : Type uView}
  {Seqno : Type uSeqno}
  {Event : Type uEvent}

variable
  [LinearOrder Tx] [OrderBot Tx] [DecidableEq Tx] [TraceDomain Tx]
  [LinearOrder View] [OrderBot View] [DecidableEq View]
  [TraceDomain View]
  [LinearOrder Seqno] [OrderBot Seqno] [DecidableEq Seqno]
  [TraceDomain Seqno]
  [LinearOrder Event] [OrderBot Event] [DecidableEq Event]
  [TraceDomain Event]

def concreteUpdateUnary
    {Alpha : Type u}
    {Beta : Sort v}
    [DecidableEq Alpha]
    (old : Alpha -> Beta)
    (key : Alpha)
    (value : Beta) :
    Alpha -> Beta :=
  fun candidate => if candidate = key then value else old candidate

def concreteUpdateBinary
    {Alpha : Type u}
    {Beta : Type v}
    {Gamma : Sort uTx}
    [DecidableEq Alpha]
    [DecidableEq Beta]
    (old : Alpha -> Beta -> Gamma)
    (first : Alpha)
    (second : Beta)
    (value : Gamma) :
    Alpha -> Beta -> Gamma :=
  concreteUpdateUnary old first
    (concreteUpdateUnary (old first) second value)

@[simp]
theorem concreteUpdateUnary_same
    {Alpha : Type u}
    {Beta : Sort v}
    [DecidableEq Alpha]
    (old : Alpha -> Beta)
    (key : Alpha)
    (value : Beta) :
    concreteUpdateUnary old key value key = value := by
  simp [concreteUpdateUnary]

@[simp]
theorem concreteUpdateUnary_of_ne
    {Alpha : Type u}
    {Beta : Sort v}
    [DecidableEq Alpha]
    (old : Alpha -> Beta)
    (key candidate : Alpha)
    (value : Beta)
    (candidateNe : Not (candidate = key)) :
    concreteUpdateUnary old key value candidate = old candidate := by
  simp [concreteUpdateUnary, candidateNe]

namespace ConcreteState

def toState
    (state : ConcreteState Tx View Seqno Event) :
    State Tx View Seqno Event where
  activeView view := state.activeView view = true
  ledgerEntry view seqno := state.ledgerEntry view seqno = true
  clientEntry view seqno := state.clientEntry view seqno = true
  entryView := state.entryView
  entryTx := state.entryTx
  eventUsed event := state.eventUsed event = true
  rwRequestEvent event := state.rwRequestEvent event = true
  rwResponseEvent event := state.rwResponseEvent event = true
  roRequestEvent event := state.roRequestEvent event = true
  roResponseEvent event := state.roResponseEvent event = true
  committedStatusEvent event := state.committedStatusEvent event = true
  invalidStatusEvent event := state.invalidStatusEvent event = true
  eventTx := state.eventTx
  eventView := state.eventView
  eventSeqno := state.eventSeqno
  eventBranch := state.eventBranch

def initial : ConcreteState Tx View Seqno Event where
  activeView view := decide (view = Bot.bot)
  ledgerEntry _ _ := false
  clientEntry _ _ := false
  entryView _ _ := Bot.bot
  entryTx _ _ := Bot.bot
  eventUsed _ := false
  rwRequestEvent _ := false
  rwResponseEvent _ := false
  roRequestEvent _ := false
  roResponseEvent _ := false
  committedStatusEvent _ := false
  invalidStatusEvent _ := false
  eventTx _ := Bot.bot
  eventView _ := Bot.bot
  eventSeqno _ := Bot.bot
  eventBranch _ := Bot.bot

theorem initial_toState :
    (initial : ConcreteState Tx View Seqno Event).toState =
      (initialState : State Tx View Seqno Event) := by
  ext <;> simp [initial, toState, initialState]

def txLt
    (_state : ConcreteState Tx View Seqno Event)
    (left right : Tx) :
    Prop :=
  orderedLt left right

def viewLt
    (_state : ConcreteState Tx View Seqno Event)
    (left right : View) :
    Prop :=
  orderedLt left right

def seqLt
    (_state : ConcreteState Tx View Seqno Event)
    (left right : Seqno) :
    Prop :=
  orderedLt left right

def eventLt
    (_state : ConcreteState Tx View Seqno Event)
    (left right : Event) :
    Prop :=
  orderedLt left right

def responseEvent
    (state : ConcreteState Tx View Seqno Event)
    (event : Event) :
    Prop :=
  state.rwResponseEvent event = true \/
    state.roResponseEvent event = true

def rwRequested
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    Prop :=
  Exists fun event =>
    state.rwRequestEvent event = true /\ state.eventTx event = tx

def roRequested
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    Prop :=
  Exists fun event =>
    state.roRequestEvent event = true /\ state.eventTx event = tx

def requested
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    Prop :=
  state.rwRequested tx \/ state.roRequested tx

def responded
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    Prop :=
  Exists fun event =>
    state.responseEvent event /\ state.eventTx event = tx

def txInLedger
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    Prop :=
  Exists fun branch =>
    Exists fun slot =>
      state.clientEntry branch slot = true /\ state.entryTx branch slot = tx

def committedTxId
    (state : ConcreteState Tx View Seqno Event)
    (view : View)
    (seqno : Seqno) :
    Prop :=
  Exists fun event =>
    state.committedStatusEvent event = true /\
      state.eventView event = view /\
        state.eventSeqno event = seqno

def currentView
    (state : ConcreteState Tx View Seqno Event)
    (view : View) :
    Prop :=
  state.activeView view = true /\
    forall later, state.viewLt view later ->
      Not (state.activeView later = true)

def nextView
    (state : ConcreteState Tx View Seqno Event)
    (view : View) :
    Prop :=
  Not (state.activeView view = true) /\
    forall earlier, state.viewLt earlier view ->
      state.activeView earlier = true

def nextLedgerSlot
    (state : ConcreteState Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) :
    Prop :=
  Not (state.ledgerEntry branch slot = true) /\
    forall earlier, state.seqLt earlier slot ->
      state.ledgerEntry branch earlier = true

def lastLedgerSlot
    (state : ConcreteState Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) :
    Prop :=
  state.ledgerEntry branch slot = true /\
    forall occupied,
      state.ledgerEntry branch occupied = true -> occupied <= slot

def nextHistoryEvent
    (state : ConcreteState Tx View Seqno Event)
    (event : Event) :
    Prop :=
  Not (state.eventUsed event = true) /\
    forall earlier, state.eventLt earlier event ->
      state.eventUsed earlier = true

def nextTx
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    Prop :=
  Not (state.requested tx) /\
    forall earlier, state.txLt earlier tx -> state.requested earlier

def noCommittedTxId
    (state : ConcreteState Tx View Seqno Event) :
    Prop :=
  forall view seqno, Not (state.committedTxId view seqno)

def maxCommittedSeqno
    (state : ConcreteState Tx View Seqno Event)
    (seqno : Seqno) :
    Prop :=
  (Exists fun view => state.committedTxId view seqno) /\
    forall view other,
      state.committedTxId view other -> other <= seqno

def validTruncationSource
    (state : ConcreteState Tx View Seqno Event)
    (source : View)
    (cut : Seqno) :
    Prop :=
  state.noCommittedTxId \/
    Exists fun commitSeq =>
      state.maxCommittedSeqno commitSeq /\
        state.ledgerEntry source commitSeq = true /\
          state.committedTxId (state.entryView source commitSeq) commitSeq /\
            commitSeq <= cut

def invalidStatusAllowed
    (state : ConcreteState Tx View Seqno Event)
    (response : Event) :
    Prop :=
  Exists fun current =>
    state.currentView current /\
      ((Exists fun commitSeq =>
          state.maxCommittedSeqno commitSeq /\
            state.eventSeqno response <= commitSeq /\
              state.ledgerEntry current (state.eventSeqno response) = true /\
                Not (
                  state.entryView current (state.eventSeqno response) =
                    state.eventView response)) \/
        (Exists fun commitSeq =>
          state.maxCommittedSeqno commitSeq /\
            state.seqLt commitSeq (state.eventSeqno response) /\
              state.ledgerEntry current commitSeq = true /\
                state.viewLt
                  (state.eventView response)
                  (state.entryView current commitSeq)) \/
        (state.eventView response = current /\
          forall committedView committedSeq,
            state.committedTxId committedView committedSeq ->
              state.seqLt committedSeq (state.eventSeqno response)))

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

def responseEventBool
    (state : ConcreteState Tx View Seqno Event)
    (event : Event) :
    Bool :=
  state.rwResponseEvent event || state.roResponseEvent event

def rwRequestedBool
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    Bool :=
  finiteAny fun event =>
    state.rwRequestEvent event && decide (state.eventTx event = tx)

def roRequestedBool
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    Bool :=
  finiteAny fun event =>
    state.roRequestEvent event && decide (state.eventTx event = tx)

def requestedBool
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    Bool :=
  state.rwRequestedBool tx || state.roRequestedBool tx

def respondedBool
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    Bool :=
  finiteAny fun event =>
    state.responseEventBool event && decide (state.eventTx event = tx)

def txInLedgerBool
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    Bool :=
  finiteAny fun branch =>
    finiteAny fun slot =>
      state.clientEntry branch slot &&
        decide (state.entryTx branch slot = tx)

def committedTxIdBool
    (state : ConcreteState Tx View Seqno Event)
    (view : View)
    (seqno : Seqno) :
    Bool :=
  finiteAny fun event =>
    state.committedStatusEvent event &&
      decide (state.eventView event = view) &&
        decide (state.eventSeqno event = seqno)

def currentViewBool
    (state : ConcreteState Tx View Seqno Event)
    (view : View) :
    Bool :=
  state.activeView view &&
    finiteAll fun later =>
      impliesBool
        (orderedLtBool view later)
        (notBool (state.activeView later))

def nextViewBool
    (state : ConcreteState Tx View Seqno Event)
    (view : View) :
    Bool :=
  notBool (state.activeView view) &&
    finiteAll fun earlier =>
      impliesBool (orderedLtBool earlier view) (state.activeView earlier)

def nextLedgerSlotBool
    (state : ConcreteState Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) :
    Bool :=
  notBool (state.ledgerEntry branch slot) &&
    finiteAll fun earlier =>
      impliesBool
        (orderedLtBool earlier slot)
        (state.ledgerEntry branch earlier)

def lastLedgerSlotBool
    (state : ConcreteState Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) :
    Bool :=
  state.ledgerEntry branch slot &&
    finiteAll fun occupied =>
      impliesBool
        (state.ledgerEntry branch occupied)
        (decide (occupied <= slot))

def nextHistoryEventBool
    (state : ConcreteState Tx View Seqno Event)
    (event : Event) :
    Bool :=
  notBool (state.eventUsed event) &&
    finiteAll fun earlier =>
      impliesBool (orderedLtBool earlier event) (state.eventUsed earlier)

def nextTxBool
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    Bool :=
  notBool (state.requestedBool tx) &&
    finiteAll fun earlier =>
      impliesBool (orderedLtBool earlier tx) (state.requestedBool earlier)

def noCommittedTxIdBool
    (state : ConcreteState Tx View Seqno Event) :
    Bool :=
  finiteAll fun view =>
    finiteAll fun seqno =>
      notBool (state.committedTxIdBool view seqno)

def maxCommittedSeqnoBool
    (state : ConcreteState Tx View Seqno Event)
    (seqno : Seqno) :
    Bool :=
  (finiteAny fun view => state.committedTxIdBool view seqno) &&
    finiteAll fun view =>
      finiteAll fun other =>
        impliesBool
          (state.committedTxIdBool view other)
          (decide (other <= seqno))

def validTruncationSourceBool
    (state : ConcreteState Tx View Seqno Event)
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
    (state : ConcreteState Tx View Seqno Event)
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
    (state : ConcreteState Tx View Seqno Event)
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
    (state : ConcreteState Tx View Seqno Event)
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
    (state : ConcreteState Tx View Seqno Event)
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
theorem orderedLtBool_eq_true
    {Alpha : Type u}
    [LinearOrder Alpha]
    (left right : Alpha) :
    orderedLtBool left right = true <->
      orderedLt left right := by
  simp [orderedLtBool, orderedLt]

@[simp]
theorem responseEventBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
    (event : Event) :
    state.responseEventBool event = true <->
      state.responseEvent event := by
  simp [responseEventBool, responseEvent]

@[simp]
theorem rwRequestedBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    state.rwRequestedBool tx = true <->
      state.rwRequested tx := by
  simp [rwRequestedBool, rwRequested]

@[simp]
theorem roRequestedBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    state.roRequestedBool tx = true <->
      state.roRequested tx := by
  simp [roRequestedBool, roRequested]

@[simp]
theorem requestedBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    state.requestedBool tx = true <->
      state.requested tx := by
  simp [requestedBool, requested]

@[simp]
theorem respondedBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    state.respondedBool tx = true <->
      state.responded tx := by
  simp [respondedBool, responded]

@[simp]
theorem txInLedgerBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx) :
    state.txInLedgerBool tx = true <->
      state.txInLedger tx := by
  simp [txInLedgerBool, txInLedger]

@[simp]
theorem committedTxIdBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
    (view : View)
    (seqno : Seqno) :
    state.committedTxIdBool view seqno = true <->
      state.committedTxId view seqno := by
  simp [committedTxIdBool, committedTxId]
  aesop

@[simp]
theorem currentViewBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
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
    (state : ConcreteState Tx View Seqno Event)
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
    (state : ConcreteState Tx View Seqno Event)
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
    (state : ConcreteState Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) :
    state.lastLedgerSlotBool branch slot = true <->
      state.lastLedgerSlot branch slot := by
  simp [lastLedgerSlotBool, lastLedgerSlot]

@[simp]
theorem nextHistoryEventBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
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
    (state : ConcreteState Tx View Seqno Event)
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
    (state : ConcreteState Tx View Seqno Event) :
    state.noCommittedTxIdBool = true <->
      state.noCommittedTxId := by
  simp [noCommittedTxIdBool, noCommittedTxId]

@[simp]
theorem maxCommittedSeqnoBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
    (seqno : Seqno) :
    state.maxCommittedSeqnoBool seqno = true <->
      state.maxCommittedSeqno seqno := by
  simp [maxCommittedSeqnoBool, maxCommittedSeqno]

@[simp]
theorem validTruncationSourceBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
    (source : View)
    (cut : Seqno) :
    state.validTruncationSourceBool source cut = true <->
      state.validTruncationSource source cut := by
  simp [validTruncationSourceBool, validTruncationSource]
  aesop

@[simp]
theorem invalidCommitPassedBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
    (response : Event)
    (current : View)
    (commitSeq : Seqno) :
    state.invalidCommitPassedBool response current commitSeq = true <->
      state.maxCommittedSeqno commitSeq /\
        state.eventSeqno response <= commitSeq /\
          state.ledgerEntry current (state.eventSeqno response) = true /\
            Not (
              state.entryView current (state.eventSeqno response) =
                state.eventView response) := by
  simp [invalidCommitPassedBool]
  aesop

@[simp]
theorem invalidCommitInNewerViewBool_eq_true
    (state : ConcreteState Tx View Seqno Event)
    (response : Event)
    (current : View)
    (commitSeq : Seqno) :
    state.invalidCommitInNewerViewBool response current commitSeq = true <->
      state.maxCommittedSeqno commitSeq /\
        state.seqLt commitSeq (state.eventSeqno response) /\
          state.ledgerEntry current commitSeq = true /\
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
    (state : ConcreteState Tx View Seqno Event)
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
    (state : ConcreteState Tx View Seqno Event)
    (response : Event) :
    state.invalidStatusAllowedBool response = true <->
      state.invalidStatusAllowed response := by
  simp [
    invalidStatusAllowedBool,
    invalidStatusAllowed
  ]
  aesop (config := { maxRuleApplications := 1000 })

def rwTxRequestNext
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx)
    (event : Event) :
    ConcreteState Tx View Seqno Event :=
  { state with
    eventUsed := concreteUpdateUnary state.eventUsed event true
    rwRequestEvent :=
      concreteUpdateUnary state.rwRequestEvent event true
    eventTx := concreteUpdateUnary state.eventTx event tx }

def roTxRequestNext
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx)
    (event : Event) :
    ConcreteState Tx View Seqno Event :=
  { state with
    eventUsed := concreteUpdateUnary state.eventUsed event true
    roRequestEvent :=
      concreteUpdateUnary state.roRequestEvent event true
    eventTx := concreteUpdateUnary state.eventTx event tx }

def rwTxExecuteNext
    (state : ConcreteState Tx View Seqno Event)
    (request : Event)
    (branch : View)
    (slot : Seqno) :
    ConcreteState Tx View Seqno Event :=
  { state with
    ledgerEntry :=
      concreteUpdateBinary state.ledgerEntry branch slot true
    clientEntry :=
      concreteUpdateBinary state.clientEntry branch slot true
    entryView :=
      concreteUpdateBinary state.entryView branch slot branch
    entryTx :=
      concreteUpdateBinary
        state.entryTx
        branch
        slot
        (state.eventTx request) }

def appendOtherTxnNext
    (state : ConcreteState Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) :
    ConcreteState Tx View Seqno Event :=
  { state with
    ledgerEntry :=
      concreteUpdateBinary state.ledgerEntry branch slot true
    clientEntry :=
      concreteUpdateBinary state.clientEntry branch slot false
    entryView :=
      concreteUpdateBinary state.entryView branch slot branch }

def rwTxResponseNext
    (state : ConcreteState Tx View Seqno Event)
    (request : Event)
    (branch : View)
    (slot : Seqno)
    (response : Event) :
    ConcreteState Tx View Seqno Event :=
  { state with
    eventUsed := concreteUpdateUnary state.eventUsed response true
    rwResponseEvent :=
      concreteUpdateUnary state.rwResponseEvent response true
    eventTx :=
      concreteUpdateUnary state.eventTx response (state.eventTx request)
    eventView :=
      concreteUpdateUnary state.eventView response (state.entryView branch slot)
    eventSeqno :=
      concreteUpdateUnary state.eventSeqno response slot
    eventBranch :=
      concreteUpdateUnary
        state.eventBranch
        response
        (state.entryView branch slot) }

def roTxResponseNext
    (state : ConcreteState Tx View Seqno Event)
    (request : Event)
    (branch : View)
    (last : Seqno)
    (response : Event) :
    ConcreteState Tx View Seqno Event :=
  { state with
    eventUsed := concreteUpdateUnary state.eventUsed response true
    roResponseEvent :=
      concreteUpdateUnary state.roResponseEvent response true
    eventTx :=
      concreteUpdateUnary state.eventTx response (state.eventTx request)
    eventView :=
      concreteUpdateUnary state.eventView response (state.entryView branch last)
    eventSeqno :=
      concreteUpdateUnary state.eventSeqno response last
    eventBranch :=
      concreteUpdateUnary
        state.eventBranch
        response
        (state.entryView branch last) }

def statusCommittedResponseNext
    (state : ConcreteState Tx View Seqno Event)
    (response : Event)
    (status : Event) :
    ConcreteState Tx View Seqno Event :=
  { state with
    eventUsed := concreteUpdateUnary state.eventUsed status true
    committedStatusEvent :=
      concreteUpdateUnary state.committedStatusEvent status true
    eventView :=
      concreteUpdateUnary state.eventView status (state.eventView response)
    eventSeqno :=
      concreteUpdateUnary state.eventSeqno status (state.eventSeqno response) }

def statusInvalidResponseNext
    (state : ConcreteState Tx View Seqno Event)
    (response : Event)
    (status : Event) :
    ConcreteState Tx View Seqno Event :=
  { state with
    eventUsed := concreteUpdateUnary state.eventUsed status true
    invalidStatusEvent :=
      concreteUpdateUnary state.invalidStatusEvent status true
    eventView :=
      concreteUpdateUnary state.eventView status (state.eventView response)
    eventSeqno :=
      concreteUpdateUnary state.eventSeqno status (state.eventSeqno response) }

def truncateLedgerNext
    (state : ConcreteState Tx View Seqno Event)
    (source : View)
    (cut : Seqno)
    (newView : View) :
    ConcreteState Tx View Seqno Event :=
  { state with
    activeView := concreteUpdateUnary state.activeView newView true
    ledgerEntry :=
      concreteUpdateUnary state.ledgerEntry newView
        (fun slot => decide (slot <= cut) && state.ledgerEntry source slot)
    clientEntry :=
      concreteUpdateUnary state.clientEntry newView
        (fun slot => decide (slot <= cut) && state.clientEntry source slot)
    entryView :=
      concreteUpdateUnary state.entryView newView
        (fun slot =>
          if slot <= cut then
            state.entryView source slot
          else
            Bot.bot)
    entryTx :=
      concreteUpdateUnary state.entryTx newView
        (fun slot =>
          if slot <= cut && state.clientEntry source slot then
            state.entryTx source slot
          else
            Bot.bot) }

def truncateLedgerToEmptyNext
    (state : ConcreteState Tx View Seqno Event)
    (newView : View) :
    ConcreteState Tx View Seqno Event :=
  { state with
    activeView := concreteUpdateUnary state.activeView newView true }

private theorem unaryBoolUpdate_toState
    {Alpha : Type u}
    [DecidableEq Alpha]
    (old : Alpha -> Bool)
    (key candidate : Alpha)
    (value : Bool) :
    (concreteUpdateUnary old key value candidate = true) <->
      updateUnary
        (fun item => old item = true)
        key
        (value = true)
        candidate := by
  by_cases candidateEq : candidate = key
  <;> simp [
    concreteUpdateUnary,
    updateUnary,
    candidateEq
  ]

private theorem unaryBinaryBoolUpdate_toState
    {Alpha : Type u}
    {Beta : Type v}
    [DecidableEq Alpha]
    (old : Alpha -> Beta -> Bool)
    (key candidateFirst : Alpha)
    (value : Beta -> Bool)
    (candidateSecond : Beta) :
    (concreteUpdateUnary old key value
        candidateFirst candidateSecond = true) <->
      updateUnary
        (fun first second => old first second = true)
        key
        (fun second => value second = true)
        candidateFirst
        candidateSecond := by
  by_cases candidateEq : candidateFirst = key
  <;> simp [
    concreteUpdateUnary,
    updateUnary,
    candidateEq
  ]

private theorem unaryUpdate_toState
    {Alpha : Type u}
    {Beta : Sort v}
    [DecidableEq Alpha]
    (old : Alpha -> Beta)
    (key candidate : Alpha)
    (value : Beta) :
    concreteUpdateUnary old key value candidate =
      updateUnary old key value candidate := by
  by_cases candidateEq : candidate = key
  <;> simp [
    concreteUpdateUnary,
    updateUnary,
    candidateEq
  ]

private theorem binaryBoolUpdate_toState
    {Alpha : Type u}
    {Beta : Type v}
    [DecidableEq Alpha]
    [DecidableEq Beta]
    (old : Alpha -> Beta -> Bool)
    (first candidateFirst : Alpha)
    (second candidateSecond : Beta)
    (value : Bool) :
    (concreteUpdateBinary old first second value
        candidateFirst candidateSecond = true) =
      updateBinary
        (fun left right => old left right = true)
        first
        second
        (value = true)
        candidateFirst
        candidateSecond := by
  by_cases firstEq : candidateFirst = first
  case pos =>
    subst candidateFirst
    by_cases secondEq : candidateSecond = second
    <;> simp [
      concreteUpdateBinary,
      concreteUpdateUnary,
      updateBinary,
      updateUnary,
      secondEq
    ]
  case neg =>
    simp [
      concreteUpdateBinary,
      concreteUpdateUnary,
      updateBinary,
      updateUnary,
      firstEq
    ]

private theorem binaryUpdate_toState
    {Alpha : Type u}
    {Beta : Type v}
    {Gamma : Sort uTx}
    [DecidableEq Alpha]
    [DecidableEq Beta]
    (old : Alpha -> Beta -> Gamma)
    (first candidateFirst : Alpha)
    (second candidateSecond : Beta)
    (value : Gamma) :
    concreteUpdateBinary old first second value
        candidateFirst candidateSecond =
      updateBinary old first second value
        candidateFirst candidateSecond := by
  by_cases firstEq : candidateFirst = first
  case pos =>
    subst candidateFirst
    by_cases secondEq : candidateSecond = second
    <;> simp [
      concreteUpdateBinary,
      concreteUpdateUnary,
      updateBinary,
      updateUnary,
      secondEq
    ]
  case neg =>
    simp [
      concreteUpdateBinary,
      concreteUpdateUnary,
      updateBinary,
      updateUnary,
      firstEq
    ]

theorem rwTxRequestNext_toState
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx)
    (event : Event) :
    (rwTxRequestNext state tx event).toState =
      CCFConsistency.rwTxRequestNext state.toState tx event := by
  ext candidate <;>
    simp [
      rwTxRequestNext,
      toState,
      CCFConsistency.rwTxRequestNext,
      unaryBoolUpdate_toState
    ] <;>
    simp [unaryUpdate_toState]

theorem roTxRequestNext_toState
    (state : ConcreteState Tx View Seqno Event)
    (tx : Tx)
    (event : Event) :
    (roTxRequestNext state tx event).toState =
      CCFConsistency.roTxRequestNext state.toState tx event := by
  ext candidate <;>
    simp [
      roTxRequestNext,
      toState,
      CCFConsistency.roTxRequestNext,
      unaryBoolUpdate_toState
    ] <;>
    simp [unaryUpdate_toState]

theorem rwTxExecuteNext_toState
    (state : ConcreteState Tx View Seqno Event)
    (request : Event)
    (branch : View)
    (slot : Seqno) :
    (rwTxExecuteNext state request branch slot).toState =
      CCFConsistency.rwTxExecuteNext state.toState request branch slot := by
  ext candidateFirst candidateSecond <;>
    simp [
      rwTxExecuteNext,
      toState,
      CCFConsistency.rwTxExecuteNext,
      binaryBoolUpdate_toState
    ] <;>
    simp [binaryUpdate_toState]

theorem appendOtherTxnNext_toState
    (state : ConcreteState Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) :
    (appendOtherTxnNext state branch slot).toState =
      CCFConsistency.appendOtherTxnNext state.toState branch slot := by
  ext candidateFirst candidateSecond <;>
    simp [
      appendOtherTxnNext,
      toState,
      CCFConsistency.appendOtherTxnNext,
      binaryBoolUpdate_toState
    ] <;>
    simp [binaryUpdate_toState]

theorem rwTxResponseNext_toState
    (state : ConcreteState Tx View Seqno Event)
    (request : Event)
    (branch : View)
    (slot : Seqno)
    (response : Event) :
    (rwTxResponseNext state request branch slot response).toState =
      CCFConsistency.rwTxResponseNext
        state.toState request branch slot response := by
  ext candidate <;>
    simp [
      rwTxResponseNext,
      toState,
      CCFConsistency.rwTxResponseNext,
      unaryBoolUpdate_toState
    ] <;>
    simp [unaryUpdate_toState]

theorem roTxResponseNext_toState
    (state : ConcreteState Tx View Seqno Event)
    (request : Event)
    (branch : View)
    (last : Seqno)
    (response : Event) :
    (roTxResponseNext state request branch last response).toState =
      CCFConsistency.roTxResponseNext
        state.toState request branch last response := by
  ext candidate <;>
    simp [
      roTxResponseNext,
      toState,
      CCFConsistency.roTxResponseNext,
      unaryBoolUpdate_toState
    ] <;>
    simp [unaryUpdate_toState]

theorem statusCommittedResponseNext_toState
    (state : ConcreteState Tx View Seqno Event)
    (response : Event)
    (status : Event) :
    (statusCommittedResponseNext state response status).toState =
      CCFConsistency.statusCommittedResponseNext
        state.toState response status := by
  ext candidate <;>
    simp [
      statusCommittedResponseNext,
      toState,
      CCFConsistency.statusCommittedResponseNext,
      unaryBoolUpdate_toState
    ] <;>
    simp [unaryUpdate_toState]

theorem statusInvalidResponseNext_toState
    (state : ConcreteState Tx View Seqno Event)
    (response : Event)
    (status : Event) :
    (statusInvalidResponseNext state response status).toState =
      CCFConsistency.statusInvalidResponseNext state.toState response status := by
  ext candidate <;>
    simp [
      statusInvalidResponseNext,
      toState,
      CCFConsistency.statusInvalidResponseNext,
      unaryBoolUpdate_toState
    ] <;>
    simp [unaryUpdate_toState]

theorem truncateLedgerNext_toState
    (state : ConcreteState Tx View Seqno Event)
    (source : View)
    (cut : Seqno)
    (newView : View) :
    (truncateLedgerNext state source cut newView).toState =
      CCFConsistency.truncateLedgerNext state.toState source cut newView := by
  ext candidateFirst candidateSecond <;>
    simp [
      truncateLedgerNext,
      toState,
      CCFConsistency.truncateLedgerNext,
      unaryBoolUpdate_toState,
      unaryBinaryBoolUpdate_toState,
      Bool.and_eq_true
    ] <;>
    simp [unaryUpdate_toState]

theorem truncateLedgerToEmptyNext_toState
    (state : ConcreteState Tx View Seqno Event)
    (newView : View) :
    (truncateLedgerToEmptyNext state newView).toState =
      CCFConsistency.truncateLedgerToEmptyNext state.toState newView := by
  ext candidate <;>
    simp [
      truncateLedgerToEmptyNext,
      toState,
      CCFConsistency.truncateLedgerToEmptyNext,
      unaryBoolUpdate_toState
    ]

end ConcreteState

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

def StateEnabled
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

def Enabled
    (action : TraceAction Tx View Seqno Event)
    (state : ConcreteState Tx View Seqno Event) :
    Prop :=
  match action with
  | .rwTxRequest tx event =>
      state.nextTx tx /\ state.nextHistoryEvent event
  | .roTxRequest tx event =>
      state.nextTx tx /\ state.nextHistoryEvent event
  | .rwTxExecute request branch slot =>
      state.rwRequestEvent request = true /\
        Not (state.txInLedger (state.eventTx request)) /\
          state.activeView branch = true /\
            state.nextLedgerSlot branch slot
  | .appendOtherTxn branch slot =>
      state.activeView branch = true /\ state.nextLedgerSlot branch slot
  | .rwTxResponse request branch slot response =>
      state.rwRequestEvent request = true /\
        Not (state.responded (state.eventTx request)) /\
          state.activeView branch = true /\
            state.clientEntry branch slot = true /\
              state.entryTx branch slot = state.eventTx request /\
                state.nextHistoryEvent response
  | .roTxResponse request branch last response =>
      state.roRequestEvent request = true /\
        Not (state.responded (state.eventTx request)) /\
          state.activeView branch = true /\
            state.lastLedgerSlot branch last /\
              state.nextHistoryEvent response
  | .statusCommittedResponse response status current =>
      state.rwResponseEvent response = true /\
        state.currentView current /\
          state.ledgerEntry current (state.eventSeqno response) = true /\
            state.entryView current (state.eventSeqno response) =
              state.eventView response /\
              Not (Exists fun invalid =>
                state.invalidStatusEvent invalid = true /\
                  state.eventView invalid = state.eventView response /\
                    state.eventSeqno invalid <= state.eventSeqno response) /\
                state.nextHistoryEvent status
  | .statusInvalidResponse response status =>
      state.rwResponseEvent response = true /\
        state.invalidStatusAllowed response /\
          state.nextHistoryEvent status
  | .truncateLedger source cut newView =>
      state.activeView source = true /\
        state.ledgerEntry source cut = true /\
          state.validTruncationSource source cut /\
            state.nextView newView
  | .truncateLedgerToEmpty source newView =>
      state.activeView source = true /\
        state.noCommittedTxId /\
          state.nextView newView

def enabledBool
    (action : TraceAction Tx View Seqno Event)
    (state : ConcreteState Tx View Seqno Event) :
    Bool :=
  match action with
  | .rwTxRequest tx event =>
      state.nextTxBool tx && state.nextHistoryEventBool event
  | .roTxRequest tx event =>
      state.nextTxBool tx && state.nextHistoryEventBool event
  | .rwTxExecute request branch slot =>
      state.rwRequestEvent request &&
        ConcreteState.notBool
            (state.txInLedgerBool (state.eventTx request)) &&
          state.activeView branch &&
            state.nextLedgerSlotBool branch slot
  | .appendOtherTxn branch slot =>
      state.activeView branch && state.nextLedgerSlotBool branch slot
  | .rwTxResponse request branch slot response =>
      state.rwRequestEvent request &&
        ConcreteState.notBool
            (state.respondedBool (state.eventTx request)) &&
          state.activeView branch &&
            state.clientEntry branch slot &&
              decide (state.entryTx branch slot = state.eventTx request) &&
                state.nextHistoryEventBool response
  | .roTxResponse request branch last response =>
      state.roRequestEvent request &&
        ConcreteState.notBool
            (state.respondedBool (state.eventTx request)) &&
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
              ConcreteState.notBool
                  (ConcreteState.finiteAny fun invalid =>
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
    (state : ConcreteState Tx View Seqno Event)
    (enabled : action.enabledBool state = true) :
    action.Enabled state := by
  cases action <;>
    simp [enabledBool] at enabled <;>
    simp only [Enabled] <;>
    aesop

theorem enabled_toState
    (action : TraceAction Tx View Seqno Event)
    (state : ConcreteState Tx View Seqno Event)
    (enabled : action.Enabled state) :
    action.StateEnabled state.toState := by
  cases action <;>
    simpa [
      Enabled,
      StateEnabled,
      ConcreteState.toState,
      ConcreteState.nextTx,
      ConcreteState.nextHistoryEvent,
      ConcreteState.txInLedger,
      ConcreteState.nextLedgerSlot,
      ConcreteState.responded,
      ConcreteState.lastLedgerSlot,
      ConcreteState.invalidStatusAllowed,
      ConcreteState.validTruncationSource,
      ConcreteState.noCommittedTxId,
      ConcreteState.nextView,
      ConcreteState.requested,
      ConcreteState.rwRequested,
      ConcreteState.roRequested,
      ConcreteState.responseEvent,
      ConcreteState.currentView,
      ConcreteState.maxCommittedSeqno,
      ConcreteState.committedTxId,
      ConcreteState.txLt,
      ConcreteState.eventLt,
      ConcreteState.seqLt,
      ConcreteState.viewLt,
      State.nextTx,
      State.nextHistoryEvent,
      State.txInLedger,
      State.nextLedgerSlot,
      State.responded,
      State.lastLedgerSlot,
      State.invalidStatusAllowed,
      State.validTruncationSource,
      State.noCommittedTxId,
      State.nextView,
      State.requested,
      State.rwRequested,
      State.roRequested,
      State.responseEvent,
      State.currentView,
      State.maxCommittedSeqno,
      State.committedTxId,
      State.txLt,
      State.eventLt,
      State.seqLt,
      State.viewLt
    ] using enabled

def next
    (action : TraceAction Tx View Seqno Event)
    (state : ConcreteState Tx View Seqno Event) :
    ConcreteState Tx View Seqno Event :=
  match action with
  | .rwTxRequest tx event =>
      state.rwTxRequestNext tx event
  | .roTxRequest tx event =>
      state.roTxRequestNext tx event
  | .rwTxExecute request branch slot =>
      state.rwTxExecuteNext request branch slot
  | .appendOtherTxn branch slot =>
      state.appendOtherTxnNext branch slot
  | .rwTxResponse request branch slot response =>
      state.rwTxResponseNext request branch slot response
  | .roTxResponse request branch last response =>
      state.roTxResponseNext request branch last response
  | .statusCommittedResponse response status _ =>
      state.statusCommittedResponseNext response status
  | .statusInvalidResponse response status =>
      state.statusInvalidResponseNext response status
  | .truncateLedger source cut newView =>
      state.truncateLedgerNext source cut newView
  | .truncateLedgerToEmpty _ newView =>
      state.truncateLedgerToEmptyNext newView

theorem enabled_step
    (action : TraceAction Tx View Seqno Event)
    (state : ConcreteState Tx View Seqno Event)
    (enabled : action.Enabled state) :
    Step state.toState (action.next state).toState := by
  replace enabled := enabled_toState action state enabled
  cases action with
  | rwTxRequest tx event =>
      rw [next, ConcreteState.rwTxRequestNext_toState]
      exact Step.rwTxRequest state.toState tx event enabled.1 enabled.2
  | roTxRequest tx event =>
      rw [next, ConcreteState.roTxRequestNext_toState]
      exact Step.roTxRequest state.toState tx event enabled.1 enabled.2
  | rwTxExecute request branch slot =>
      rw [next, ConcreteState.rwTxExecuteNext_toState]
      exact
        Step.rwTxExecute
          state.toState
          request
          branch
          slot
          enabled.1
          enabled.2.1
          enabled.2.2.1
          enabled.2.2.2
  | appendOtherTxn branch slot =>
      rw [next, ConcreteState.appendOtherTxnNext_toState]
      exact
        Step.appendOtherTxn
          state.toState
          branch
          slot
          enabled.1
          enabled.2
  | rwTxResponse request branch slot response =>
      rw [next, ConcreteState.rwTxResponseNext_toState]
      exact
        Step.rwTxResponse
          state.toState
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
      rw [next, ConcreteState.roTxResponseNext_toState]
      exact
        Step.roTxResponse
          state.toState
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
      rw [next, ConcreteState.statusCommittedResponseNext_toState]
      exact
        Step.statusCommittedResponse
          state.toState
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
      rw [next, ConcreteState.statusInvalidResponseNext_toState]
      exact
        Step.statusInvalidResponse
          state.toState
          response
          status
          enabled.1
          enabled.2.1
          enabled.2.2
  | truncateLedger source cut newView =>
      rw [next, ConcreteState.truncateLedgerNext_toState]
      exact
        Step.truncateLedger
          state.toState
          source
          cut
          newView
          enabled.1
          enabled.2.1
          enabled.2.2.1
          enabled.2.2.2
  | truncateLedgerToEmpty source newView =>
      rw [next, ConcreteState.truncateLedgerToEmptyNext_toState]
      exact
        Step.truncateLedgerToEmpty
          state.toState
          source
          newView
          enabled.1
          enabled.2.1
          enabled.2.2

end TraceAction

def replay
    (actions : List (TraceAction Tx View Seqno Event))
    (state : ConcreteState Tx View Seqno Event) :
    Option (ConcreteState Tx View Seqno Event) :=
  match actions with
  | [] => some state
  | action :: remaining =>
      match action.enabledBool state with
      | true => replay remaining (action.next state)
      | false => none
termination_by actions.length

theorem replay_reachable
    {actions : List (TraceAction Tx View Seqno Event)}
    {state final : ConcreteState Tx View Seqno Event}
    (stateReachable : Reachable state.toState)
    (replayed : replay actions state = some final) :
    Reachable final.toState := by
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
        (ConcreteState.initial :
          ConcreteState Tx View Seqno Event)).isSome) :
    Exists fun final =>
      replay actions
          (ConcreteState.initial :
            ConcreteState Tx View Seqno Event) =
        some final /\
        Reachable final.toState := by
  let existsResult := Option.isSome_iff_exists.mp success
  cases existsResult with
  | intro final replayed =>
      refine Exists.intro final (And.intro replayed ?_)
      have initialReachable :
          Reachable
            (ConcreteState.initial :
              ConcreteState Tx View Seqno Event).toState := by
        rw [ConcreteState.initial_toState]
        exact Reachable.initial
      exact replay_reachable initialReachable replayed

end CCFConsistency
