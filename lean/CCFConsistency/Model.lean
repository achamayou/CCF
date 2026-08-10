-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib

set_option autoImplicit false

/-!
# Pure Lean CCF consistency model

This file directly represents the mutable relations and functions from the
Veil consistency model. Relations are Boolean so the canonical state and all
ten canonical transitions are executable, while Lean coerces their values to
propositions in guards and proofs. The domain parameters remain abstract and
ordered.
-/

namespace CCFConsistency

universe u v uTx uView uSeqno uEvent

@[ext]
structure State
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
  [LinearOrder Tx] [OrderBot Tx]
  [LinearOrder View] [OrderBot View]
  [LinearOrder Seqno] [OrderBot Seqno]
  [LinearOrder Event] [OrderBot Event]

def initialState : State Tx View Seqno Event where
  activeView v := decide (v = Bot.bot)
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

def orderedLt
    {Alpha : Type u}
    [LinearOrder Alpha]
    (left right : Alpha) : Prop :=
  left <= right /\ Not (left = right)

def updateUnary
    {Alpha : Type u}
    {Beta : Sort v}
    [DecidableEq Alpha]
    (old : Alpha -> Beta)
    (key : Alpha)
    (value : Beta) : Alpha -> Beta :=
  fun candidate =>
    if candidate = key then value else old candidate

def updateBinary
    {Alpha : Type u}
    {Beta : Type v}
    {Gamma : Sort uTx}
    [DecidableEq Alpha]
    [DecidableEq Beta]
    (old : Alpha -> Beta -> Gamma)
    (first : Alpha)
    (second : Beta)
    (value : Gamma) : Alpha -> Beta -> Gamma :=
  updateUnary old first (updateUnary (old first) second value)

@[simp]
theorem updateUnary_same
    {Alpha : Type u}
    {Beta : Sort v}
    [DecidableEq Alpha]
    (old : Alpha -> Beta)
    (key : Alpha)
    (value : Beta) :
    updateUnary old key value key = value := by
  simp [updateUnary]

@[simp]
theorem updateUnary_of_ne
    {Alpha : Type u}
    {Beta : Sort v}
    [DecidableEq Alpha]
    (old : Alpha -> Beta)
    (key candidate : Alpha)
    (value : Beta)
    (candidateNe : Not (candidate = key)) :
    updateUnary old key value candidate = old candidate := by
  simp [updateUnary, candidateNe]

@[simp]
theorem updateBinary_same
    {Alpha : Type u}
    {Beta : Type v}
    {Gamma : Sort uTx}
    [DecidableEq Alpha]
    [DecidableEq Beta]
    (old : Alpha -> Beta -> Gamma)
    (first : Alpha)
    (second : Beta)
    (value : Gamma) :
    updateBinary old first second value first second = value := by
  simp [updateBinary]

@[simp]
theorem updateBinary_of_first_ne
    {Alpha : Type u}
    {Beta : Type v}
    {Gamma : Sort uTx}
    [DecidableEq Alpha]
    [DecidableEq Beta]
    (old : Alpha -> Beta -> Gamma)
    (first candidateFirst : Alpha)
    (second candidateSecond : Beta)
    (value : Gamma)
    (firstNe : Not (candidateFirst = first)) :
    updateBinary old first second value candidateFirst candidateSecond =
      old candidateFirst candidateSecond := by
  simp [updateBinary, firstNe]

@[simp]
theorem updateBinary_of_second_ne
    {Alpha : Type u}
    {Beta : Type v}
    {Gamma : Sort uTx}
    [DecidableEq Alpha]
    [DecidableEq Beta]
    (old : Alpha -> Beta -> Gamma)
    (first candidateFirst : Alpha)
    (second candidateSecond : Beta)
    (value : Gamma)
    (secondNe : Not (candidateSecond = second)) :
    updateBinary old first second value candidateFirst candidateSecond =
      old candidateFirst candidateSecond := by
  by_cases firstEq : candidateFirst = first
  · subst candidateFirst
    simp [updateBinary, secondNe]
  · simp [updateBinary, firstEq]

namespace State

def txLt (_state : State Tx View Seqno Event) (left right : Tx) : Prop :=
  orderedLt left right

def viewLt (_state : State Tx View Seqno Event) (left right : View) : Prop :=
  orderedLt left right

def seqLt (_state : State Tx View Seqno Event) (left right : Seqno) : Prop :=
  orderedLt left right

def eventLt (_state : State Tx View Seqno Event) (left right : Event) : Prop :=
  orderedLt left right

def historyEvent (state : State Tx View Seqno Event) (event : Event) : Prop :=
  state.rwRequestEvent event \/
    state.rwResponseEvent event \/
      state.roRequestEvent event \/
        state.roResponseEvent event \/
          state.committedStatusEvent event \/
            state.invalidStatusEvent event

def requestEvent (state : State Tx View Seqno Event) (event : Event) : Prop :=
  state.rwRequestEvent event \/ state.roRequestEvent event

def responseEvent (state : State Tx View Seqno Event) (event : Event) : Prop :=
  state.rwResponseEvent event \/ state.roResponseEvent event

def observedAt
    (state : State Tx View Seqno Event)
    (response : Event)
    (slot : Seqno)
    (observed : Tx) : Prop :=
  state.responseEvent response /\
    slot <= state.eventSeqno response /\
      state.clientEntry (state.eventBranch response) slot /\
        state.entryTx (state.eventBranch response) slot = observed

def statusEvent (state : State Tx View Seqno Event) (event : Event) : Prop :=
  state.committedStatusEvent event \/ state.invalidStatusEvent event

def rwRequested (state : State Tx View Seqno Event) (tx : Tx) : Prop :=
  Exists fun event =>
    state.rwRequestEvent event /\ state.eventTx event = tx

def roRequested (state : State Tx View Seqno Event) (tx : Tx) : Prop :=
  Exists fun event =>
    state.roRequestEvent event /\ state.eventTx event = tx

def requested (state : State Tx View Seqno Event) (tx : Tx) : Prop :=
  state.rwRequested tx \/ state.roRequested tx

def responded (state : State Tx View Seqno Event) (tx : Tx) : Prop :=
  Exists fun event =>
    state.responseEvent event /\ state.eventTx event = tx

def txInLedger (state : State Tx View Seqno Event) (tx : Tx) : Prop :=
  Exists fun branch =>
    Exists fun slot =>
      state.clientEntry branch slot /\ state.entryTx branch slot = tx

def committedTxId
    (state : State Tx View Seqno Event)
    (view : View)
    (seqno : Seqno) : Prop :=
  Exists fun event =>
    state.committedStatusEvent event /\
      state.eventView event = view /\
        state.eventSeqno event = seqno

def invalidTxId
    (state : State Tx View Seqno Event)
    (view : View)
    (seqno : Seqno) : Prop :=
  Exists fun event =>
    state.invalidStatusEvent event /\
      state.eventView event = view /\
        state.eventSeqno event = seqno

def rwResponseCommitted
    (state : State Tx View Seqno Event)
    (event : Event) : Prop :=
  state.rwResponseEvent event /\
    state.committedTxId (state.eventView event) (state.eventSeqno event)

def roResponseCommitted
    (state : State Tx View Seqno Event)
    (event : Event) : Prop :=
  state.roResponseEvent event /\
    state.committedTxId (state.eventView event) (state.eventSeqno event)

def observes
    (state : State Tx View Seqno Event)
    (response : Event)
    (observed : Tx) : Prop :=
  Exists fun slot => state.observedAt response slot observed

def sameObservations
    (state : State Tx View Seqno Event)
    (left right : Event) : Prop :=
  forall slot observed,
    state.observedAt left slot observed <->
      state.observedAt right slot observed

def observationsSubset
    (state : State Tx View Seqno Event)
    (left right : Event) : Prop :=
  forall slot observed,
    state.observedAt left slot observed ->
      state.observedAt right slot observed

def txIdLt
    (state : State Tx View Seqno Event)
    (left right : Event) : Prop :=
  state.viewLt (state.eventView left) (state.eventView right) \/
    (state.eventView left = state.eventView right /\
      state.seqLt (state.eventSeqno left) (state.eventSeqno right))

def currentView (state : State Tx View Seqno Event) (view : View) : Prop :=
  state.activeView view /\
    forall later, state.viewLt view later -> Not (state.activeView later)

def nextView (state : State Tx View Seqno Event) (view : View) : Prop :=
  Not (state.activeView view) /\
    forall earlier, state.viewLt earlier view -> state.activeView earlier

def nextLedgerSlot
    (state : State Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) : Prop :=
  Not (state.ledgerEntry branch slot) /\
    forall earlier,
      state.seqLt earlier slot -> state.ledgerEntry branch earlier

def lastLedgerSlot
    (state : State Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) : Prop :=
  state.ledgerEntry branch slot /\
    forall occupied,
      state.ledgerEntry branch occupied -> occupied <= slot

def nextHistoryEvent
    (state : State Tx View Seqno Event)
    (event : Event) : Prop :=
  Not (state.eventUsed event) /\
    forall earlier,
      state.eventLt earlier event -> state.eventUsed earlier

def nextTx (state : State Tx View Seqno Event) (tx : Tx) : Prop :=
  Not (state.requested tx) /\
    forall earlier, state.txLt earlier tx -> state.requested earlier

def noCommittedTxId (state : State Tx View Seqno Event) : Prop :=
  forall view seqno, Not (state.committedTxId view seqno)

def maxCommittedSeqno
    (state : State Tx View Seqno Event)
    (seqno : Seqno) : Prop :=
  (Exists fun view => state.committedTxId view seqno) /\
    forall view other,
      state.committedTxId view other -> other <= seqno

def validTruncationSource
    (state : State Tx View Seqno Event)
    (source : View)
    (cut : Seqno) : Prop :=
  state.noCommittedTxId \/
    Exists fun commitSeq =>
      state.maxCommittedSeqno commitSeq /\
        state.ledgerEntry source commitSeq /\
          state.committedTxId (state.entryView source commitSeq) commitSeq /\
            commitSeq <= cut

def invalidStatusAllowed
    (state : State Tx View Seqno Event)
    (response : Event) : Prop :=
  Exists fun current =>
    state.currentView current /\
      ((Exists fun commitSeq =>
          state.maxCommittedSeqno commitSeq /\
            state.eventSeqno response <= commitSeq /\
              state.ledgerEntry current (state.eventSeqno response) /\
                Not (
                  state.entryView current (state.eventSeqno response) =
                    state.eventView response)) \/
        (Exists fun commitSeq =>
          state.maxCommittedSeqno commitSeq /\
            state.seqLt commitSeq (state.eventSeqno response) /\
              state.ledgerEntry current commitSeq /\
                state.viewLt
                  (state.eventView response)
                  (state.entryView current commitSeq)) \/
        (state.eventView response = current /\
          forall committedView committedSeq,
            state.committedTxId committedView committedSeq ->
              state.seqLt committedSeq (state.eventSeqno response)))

end State

def rwTxRequestNext
    (state : State Tx View Seqno Event)
    (tx : Tx)
    (event : Event) : State Tx View Seqno Event :=
  { state with
    eventUsed := updateUnary state.eventUsed event true
    rwRequestEvent := updateUnary state.rwRequestEvent event true
    eventTx := updateUnary state.eventTx event tx }

def roTxRequestNext
    (state : State Tx View Seqno Event)
    (tx : Tx)
    (event : Event) : State Tx View Seqno Event :=
  { state with
    eventUsed := updateUnary state.eventUsed event true
    roRequestEvent := updateUnary state.roRequestEvent event true
    eventTx := updateUnary state.eventTx event tx }

def rwTxExecuteNext
    (state : State Tx View Seqno Event)
    (request : Event)
    (branch : View)
    (slot : Seqno) : State Tx View Seqno Event :=
  { state with
    ledgerEntry :=
      updateBinary state.ledgerEntry branch slot true
    clientEntry :=
      updateBinary state.clientEntry branch slot true
    entryView :=
      updateBinary state.entryView branch slot branch
    entryTx :=
      updateBinary
        state.entryTx
        branch
        slot
        (state.eventTx request) }

def appendOtherTxnNext
    (state : State Tx View Seqno Event)
    (branch : View)
    (slot : Seqno) : State Tx View Seqno Event :=
  { state with
    ledgerEntry :=
      updateBinary state.ledgerEntry branch slot true
    clientEntry :=
      updateBinary state.clientEntry branch slot false
    entryView :=
      updateBinary state.entryView branch slot branch }

def rwTxResponseNext
    (state : State Tx View Seqno Event)
    (request : Event)
    (branch : View)
    (slot : Seqno)
    (response : Event) : State Tx View Seqno Event :=
  { state with
    eventUsed := updateUnary state.eventUsed response true
    rwResponseEvent := updateUnary state.rwResponseEvent response true
    eventTx :=
      updateUnary state.eventTx response (state.eventTx request)
    eventView :=
      updateUnary state.eventView response (state.entryView branch slot)
    eventSeqno := updateUnary state.eventSeqno response slot
    eventBranch :=
      updateUnary state.eventBranch response (state.entryView branch slot) }

def roTxResponseNext
    (state : State Tx View Seqno Event)
    (request : Event)
    (branch : View)
    (last : Seqno)
    (response : Event) : State Tx View Seqno Event :=
  { state with
    eventUsed := updateUnary state.eventUsed response true
    roResponseEvent := updateUnary state.roResponseEvent response true
    eventTx :=
      updateUnary state.eventTx response (state.eventTx request)
    eventView :=
      updateUnary state.eventView response (state.entryView branch last)
    eventSeqno := updateUnary state.eventSeqno response last
    eventBranch :=
      updateUnary state.eventBranch response (state.entryView branch last) }

def statusCommittedResponseNext
    (state : State Tx View Seqno Event)
    (response : Event)
    (status : Event) : State Tx View Seqno Event :=
  { state with
    eventUsed := updateUnary state.eventUsed status true
    committedStatusEvent :=
      updateUnary state.committedStatusEvent status true
    eventView :=
      updateUnary state.eventView status (state.eventView response)
    eventSeqno :=
      updateUnary state.eventSeqno status (state.eventSeqno response) }

def statusInvalidResponseNext
    (state : State Tx View Seqno Event)
    (response : Event)
    (status : Event) : State Tx View Seqno Event :=
  { state with
    eventUsed := updateUnary state.eventUsed status true
    invalidStatusEvent :=
      updateUnary state.invalidStatusEvent status true
    eventView :=
      updateUnary state.eventView status (state.eventView response)
    eventSeqno :=
      updateUnary state.eventSeqno status (state.eventSeqno response) }

def truncateLedgerNext
    (state : State Tx View Seqno Event)
    (source : View)
    (cut : Seqno)
    (newView : View) : State Tx View Seqno Event :=
  { state with
    activeView := updateUnary state.activeView newView true
    ledgerEntry :=
      updateUnary state.ledgerEntry newView
        (fun slot => decide (slot <= cut) && state.ledgerEntry source slot)
    clientEntry :=
      updateUnary state.clientEntry newView
        (fun slot => decide (slot <= cut) && state.clientEntry source slot)
    entryView :=
      updateUnary state.entryView newView
        (fun slot =>
          if slot <= cut then
            state.entryView source slot
          else
            Bot.bot)
    entryTx :=
      updateUnary state.entryTx newView
        (fun slot =>
          if decide (slot <= cut) && state.clientEntry source slot then
            state.entryTx source slot
          else
            Bot.bot) }

def truncateLedgerToEmptyNext
    (state : State Tx View Seqno Event)
    (newView : View) : State Tx View Seqno Event :=
  { state with
    activeView := updateUnary state.activeView newView true }

inductive Step :
    State Tx View Seqno Event ->
    State Tx View Seqno Event ->
    Prop where
  | rwTxRequest
      (state : State Tx View Seqno Event)
      (tx : Tx)
      (event : Event)
      (nextTx : state.nextTx tx)
      (nextEvent : state.nextHistoryEvent event) :
      Step state (rwTxRequestNext state tx event)
  | roTxRequest
      (state : State Tx View Seqno Event)
      (tx : Tx)
      (event : Event)
      (nextTx : state.nextTx tx)
      (nextEvent : state.nextHistoryEvent event) :
      Step state (roTxRequestNext state tx event)
  | rwTxExecute
      (state : State Tx View Seqno Event)
      (request : Event)
      (branch : View)
      (slot : Seqno)
      (requestIsRw : state.rwRequestEvent request)
      (txNotInLedger : Not (state.txInLedger (state.eventTx request)))
      (branchIsActive : state.activeView branch)
      (nextSlot : state.nextLedgerSlot branch slot) :
      Step state (rwTxExecuteNext state request branch slot)
  | appendOtherTxn
      (state : State Tx View Seqno Event)
      (branch : View)
      (slot : Seqno)
      (branchIsActive : state.activeView branch)
      (nextSlot : state.nextLedgerSlot branch slot) :
      Step state (appendOtherTxnNext state branch slot)
  | rwTxResponse
      (state : State Tx View Seqno Event)
      (request : Event)
      (branch : View)
      (slot : Seqno)
      (response : Event)
      (requestIsRw : state.rwRequestEvent request)
      (notResponded : Not (state.responded (state.eventTx request)))
      (branchIsActive : state.activeView branch)
      (entryIsClient : state.clientEntry branch slot)
      (entryMatches : state.entryTx branch slot = state.eventTx request)
      (nextEvent : state.nextHistoryEvent response) :
      Step state (rwTxResponseNext state request branch slot response)
  | roTxResponse
      (state : State Tx View Seqno Event)
      (request : Event)
      (branch : View)
      (last : Seqno)
      (response : Event)
      (requestIsRo : state.roRequestEvent request)
      (notResponded : Not (state.responded (state.eventTx request)))
      (branchIsActive : state.activeView branch)
      (lastSlot : state.lastLedgerSlot branch last)
      (nextEvent : state.nextHistoryEvent response) :
      Step state (roTxResponseNext state request branch last response)
  | statusCommittedResponse
      (state : State Tx View Seqno Event)
      (response : Event)
      (status : Event)
      (current : View)
      (responseIsRw : state.rwResponseEvent response)
      (viewIsCurrent : state.currentView current)
      (responseSlotExists :
        state.ledgerEntry current (state.eventSeqno response))
      (responseEntryMatches :
        state.entryView current (state.eventSeqno response) =
          state.eventView response)
      (notInvalid :
        Not (Exists fun invalid =>
          state.invalidStatusEvent invalid /\
            state.eventView invalid = state.eventView response /\
              state.eventSeqno invalid <= state.eventSeqno response))
      (nextEvent : state.nextHistoryEvent status) :
      Step state (statusCommittedResponseNext state response status)
  | statusInvalidResponse
      (state : State Tx View Seqno Event)
      (response : Event)
      (status : Event)
      (responseIsRw : state.rwResponseEvent response)
      (statusAllowed : state.invalidStatusAllowed response)
      (nextEvent : state.nextHistoryEvent status) :
      Step state (statusInvalidResponseNext state response status)
  | truncateLedger
      (state : State Tx View Seqno Event)
      (source : View)
      (cut : Seqno)
      (newView : View)
      (sourceIsActive : state.activeView source)
      (cutExists : state.ledgerEntry source cut)
      (sourceIsValid : state.validTruncationSource source cut)
      (viewIsNext : state.nextView newView) :
      Step state (truncateLedgerNext state source cut newView)
  | truncateLedgerToEmpty
      (state : State Tx View Seqno Event)
      (source : View)
      (newView : View)
      (sourceIsActive : state.activeView source)
      (noCommitted : state.noCommittedTxId)
      (viewIsNext : state.nextView newView) :
      Step state (truncateLedgerToEmptyNext state newView)

inductive Reachable : State Tx View Seqno Event -> Prop where
  | initial : Reachable initialState
  | step
      {state next : State Tx View Seqno Event}
      (reachable : Reachable state)
      (transition : Step state next) :
      Reachable next

end CCFConsistency
