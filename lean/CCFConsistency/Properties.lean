-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFConsistency.Model

set_option autoImplicit false

/-!
# Pure Lean CCF consistency properties

Each proposition in this file is a direct translation of the property with the
same name in `veil/CCFConsistency.lean`.
-/

namespace CCFConsistency

universe uTx uView uSeqno uEvent

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

def HistoryTypeOk (state : State Tx View Seqno Event) : Prop :=
  forall event, state.eventUsed event <-> state.historyEvent event

def HistoryEventKindUnique (state : State Tx View Seqno Event) : Prop :=
  forall event,
    (state.rwRequestEvent event ->
      Not (
        state.rwResponseEvent event \/
          state.roRequestEvent event \/
            state.roResponseEvent event \/
              state.committedStatusEvent event \/
                state.invalidStatusEvent event)) /\
    (state.rwResponseEvent event ->
      Not (
        state.roRequestEvent event \/
          state.roResponseEvent event \/
            state.committedStatusEvent event \/
              state.invalidStatusEvent event)) /\
    (state.roRequestEvent event ->
      Not (
        state.roResponseEvent event \/
          state.committedStatusEvent event \/
            state.invalidStatusEvent event)) /\
    (state.roResponseEvent event ->
      Not (
        state.committedStatusEvent event \/
          state.invalidStatusEvent event)) /\
    (state.committedStatusEvent event ->
      Not (state.invalidStatusEvent event))

def HistoryIsPrefix (state : State Tx View Seqno Event) : Prop :=
  forall later earlier,
    state.eventUsed later /\ state.eventLt earlier later ->
      state.eventUsed earlier

def ActiveViewsArePrefix (state : State Tx View Seqno Event) : Prop :=
  forall later earlier,
    state.activeView later /\ state.viewLt earlier later ->
      state.activeView earlier

def LedgerTypeOk (state : State Tx View Seqno Event) : Prop :=
  forall branch slot,
    state.ledgerEntry branch slot ->
      state.activeView branch /\
        state.entryView branch slot <= branch

def ClientEntriesAreLedgerEntries
    (state : State Tx View Seqno Event) : Prop :=
  forall branch slot,
    state.clientEntry branch slot -> state.ledgerEntry branch slot

def LedgerIsPrefix (state : State Tx View Seqno Event) : Prop :=
  forall branch later earlier,
    state.ledgerEntry branch later /\ state.seqLt earlier later ->
      state.ledgerEntry branch earlier

def LedgerTxIdsAreStableAcrossCopies
    (state : State Tx View Seqno Event) : Prop :=
  forall leftBranch leftSlot rightBranch rightSlot,
    state.clientEntry leftBranch leftSlot /\
      state.clientEntry rightBranch rightSlot /\
        state.entryTx leftBranch leftSlot =
          state.entryTx rightBranch rightSlot ->
      leftSlot = rightSlot /\
        state.entryView leftBranch leftSlot =
          state.entryView rightBranch rightSlot

def LedgerEntryExistsInOriginView
    (state : State Tx View Seqno Event) : Prop :=
  forall branch slot,
    state.ledgerEntry branch slot ->
      state.ledgerEntry (state.entryView branch slot) slot

def ResponseFrontierIsLedgerEntry
    (state : State Tx View Seqno Event) : Prop :=
  forall response,
    state.responseEvent response ->
      state.ledgerEntry
        (state.eventBranch response)
        (state.eventSeqno response)

def ClientEntryHasRequest (state : State Tx View Seqno Event) : Prop :=
  forall branch slot,
    state.clientEntry branch slot ->
      Exists fun request =>
        state.rwRequestEvent request /\
          state.eventTx request = state.entryTx branch slot

def ClientEntryMatchesOrigin (state : State Tx View Seqno Event) : Prop :=
  forall branch slot,
    state.clientEntry branch slot ->
      state.clientEntry (state.entryView branch slot) slot /\
        state.entryView (state.entryView branch slot) slot =
          state.entryView branch slot /\
        state.entryTx (state.entryView branch slot) slot =
          state.entryTx branch slot

def LedgerEntryViewsAreMonotonic
    (state : State Tx View Seqno Event) : Prop :=
  forall branch earlier later,
    state.ledgerEntry branch later /\ earlier <= later ->
      state.entryView branch earlier <= state.entryView branch later

def LedgerPrefixMatchesFrontierOrigin
    (state : State Tx View Seqno Event) : Prop :=
  forall branch frontier slot,
    state.ledgerEntry branch frontier /\ slot <= frontier ->
      state.ledgerEntry (state.entryView branch frontier) slot /\
        (state.clientEntry branch slot <->
          state.clientEntry (state.entryView branch frontier) slot) /\
        state.entryView branch slot =
          state.entryView (state.entryView branch frontier) slot /\
        (state.clientEntry branch slot ->
          state.entryTx branch slot =
            state.entryTx (state.entryView branch frontier) slot)

def ResponseBranchIsView (state : State Tx View Seqno Event) : Prop :=
  forall response,
    state.responseEvent response ->
      state.eventBranch response = state.eventView response

def ResponseFrontierMatchesOrigin
    (state : State Tx View Seqno Event) : Prop :=
  forall response,
    state.responseEvent response ->
      state.entryView
        (state.eventBranch response)
        (state.eventSeqno response) =
          state.eventView response

def RwResponseMatchesLedgerEntry
    (state : State Tx View Seqno Event) : Prop :=
  forall response,
    state.rwResponseEvent response ->
      state.clientEntry
        (state.eventBranch response)
        (state.eventSeqno response) /\
      state.entryTx
        (state.eventBranch response)
        (state.eventSeqno response) =
          state.eventTx response

def StatusHasRwResponse (state : State Tx View Seqno Event) : Prop :=
  forall status,
    state.statusEvent status ->
      Exists fun response =>
        state.rwResponseEvent response /\
          state.eventLt response status /\
            state.eventView response = state.eventView status /\
              state.eventSeqno response = state.eventSeqno status

def CommittedIdIsInCurrentLedger
    (state : State Tx View Seqno Event) : Prop :=
  forall committedView committedSeq current,
    state.committedTxId committedView committedSeq /\
      state.currentView current ->
        state.ledgerEntry current committedSeq /\
          state.entryView current committedSeq = committedView

def CommittedResponseMatchesCurrentLedger
    (state : State Tx View Seqno Event) : Prop :=
  forall response current,
    state.rwResponseCommitted response /\ state.currentView current ->
      state.clientEntry current (state.eventSeqno response) /\
        state.entryView current (state.eventSeqno response) =
          state.eventView response /\
        state.entryTx current (state.eventSeqno response) =
          state.eventTx response

def AllReceivedAfterSent (state : State Tx View Seqno Event) : Prop :=
  forall response,
    state.responseEvent response ->
      Exists fun request =>
        state.eventLt request response /\
          state.eventTx request = state.eventTx response /\
            ((state.rwRequestEvent request /\
                state.rwResponseEvent response) \/
              (state.roRequestEvent request /\
                state.roResponseEvent response))

def UniqueTxRequests (state : State Tx View Seqno Event) : Prop :=
  forall left right,
    state.requestEvent left /\
      state.requestEvent right /\
        Not (left = right) ->
      Not (state.eventTx left = state.eventTx right)

def OnlyObserveSentRequests (state : State Tx View Seqno Event) : Prop :=
  forall response slot observed,
    state.responseEvent response /\ state.observedAt response slot observed ->
      Exists fun request =>
        state.rwRequestEvent request /\
          state.eventTx request = observed /\
            state.eventLt request response

def ObservationsAreWithinResponsePrefix
    (state : State Tx View Seqno Event) : Prop :=
  forall response slot observed,
    state.observedAt response slot observed ->
      state.responseEvent response /\
        slot <= state.eventSeqno response

def UniqueRwTxs (state : State Tx View Seqno Event) : Prop :=
  forall left right,
    state.rwResponseEvent left /\
      state.rwResponseEvent right /\
        state.eventView left = state.eventView right /\
          state.eventSeqno left = state.eventSeqno right ->
      state.eventTx left = state.eventTx right

def SameObservations (state : State Tx View Seqno Event) : Prop :=
  forall left right,
    state.responseEvent left /\
      state.responseEvent right /\
        state.eventView left = state.eventView right /\
          state.eventSeqno left = state.eventSeqno right ->
      state.sameObservations left right

def UniqueTxIds (state : State Tx View Seqno Event) : Prop :=
  forall left right,
    state.responseEvent left /\
      state.responseEvent right /\
        state.eventTx left = state.eventTx right ->
      state.eventView left = state.eventView right /\
        state.eventSeqno left = state.eventSeqno right

/-- Auxiliary strengthening of `UniqueTxIds`: a transaction receives at most
one response. This is what the `notResponded` guard of the two response
actions actually maintains. -/
def UniqueResponseTxs (state : State Tx View Seqno Event) : Prop :=
  forall left right,
    state.responseEvent left /\
      state.responseEvent right /\
        state.eventTx left = state.eventTx right ->
      left = right

def UniqueCommittedSeqnos (state : State Tx View Seqno Event) : Prop :=
  forall left right,
    state.rwResponseCommitted left /\
      state.rwResponseCommitted right /\
        state.eventSeqno left = state.eventSeqno right ->
      state.eventTx left = state.eventTx right

def CommittedOrInvalid (state : State Tx View Seqno Event) : Prop :=
  forall view seqno,
    state.committedTxId view seqno ->
      Not (state.invalidTxId view seqno)

def OnceCommittedPreviousIsCommitted
    (state : State Tx View Seqno Event) : Prop :=
  forall committedView committedSeq status,
    state.committedTxId committedView committedSeq /\
      state.statusEvent status /\
        state.eventView status = committedView /\
          state.eventSeqno status <= committedSeq ->
      state.committedStatusEvent status

def OnceCommittedOlderViewSuffixIsInvalid
    (state : State Tx View Seqno Event) : Prop :=
  forall committedView committedSeq status,
    state.committedTxId committedView committedSeq /\
      state.statusEvent status /\
        state.viewLt (state.eventView status) committedView /\
          committedSeq <= state.eventSeqno status ->
      state.invalidStatusEvent status

def OnceInvalidSameViewSuffixIsInvalid
    (state : State Tx View Seqno Event) : Prop :=
  forall invalidView invalidSeq status,
    state.invalidTxId invalidView invalidSeq /\
      state.statusEvent status /\
        state.eventView status = invalidView /\
          invalidSeq <= state.eventSeqno status ->
      state.invalidStatusEvent status

def AllCommittedObserved (state : State Tx View Seqno Event) : Prop :=
  forall earlier request response,
    state.rwResponseCommitted earlier /\
      state.rwRequestEvent request /\
        state.rwResponseCommitted response /\
          state.eventTx request = state.eventTx response /\
            state.eventLt earlier request ->
      state.observes response (state.eventTx earlier)

def CommittedRwSerializable (state : State Tx View Seqno Event) : Prop :=
  forall left right,
    state.rwResponseCommitted left /\ state.rwResponseCommitted right ->
      state.observationsSubset left right \/
        state.observationsSubset right left

def AtMostOnceObserved (state : State Tx View Seqno Event) : Prop :=
  forall response leftSlot rightSlot observed,
    state.observedAt response leftSlot observed /\
      state.observedAt response rightSlot observed ->
      leftSlot = rightSlot

def CommittedRwOrderedRealTime
    (state : State Tx View Seqno Event) : Prop :=
  forall earlier request later,
    state.rwResponseCommitted earlier /\
      state.rwRequestEvent request /\
        state.rwResponseCommitted later /\
          state.eventTx request = state.eventTx later /\
            state.eventLt earlier request ->
      state.txIdLt earlier later

structure StructuralBundle (state : State Tx View Seqno Event) : Prop where
  historyTypeOk : HistoryTypeOk state
  historyEventKindUnique : HistoryEventKindUnique state
  historyIsPrefix : HistoryIsPrefix state
  activeViewsArePrefix : ActiveViewsArePrefix state
  ledgerTypeOk : LedgerTypeOk state
  clientEntriesAreLedgerEntries : ClientEntriesAreLedgerEntries state
  ledgerIsPrefix : LedgerIsPrefix state
  ledgerEntryExistsInOriginView : LedgerEntryExistsInOriginView state
  responseFrontierIsLedgerEntry : ResponseFrontierIsLedgerEntry state
  responseBranchIsView : ResponseBranchIsView state
  responseFrontierMatchesOrigin : ResponseFrontierMatchesOrigin state
  rwResponseMatchesLedgerEntry : RwResponseMatchesLedgerEntry state
  allReceivedAfterSent : AllReceivedAfterSent state
  observationsAreWithinResponsePrefix :
    ObservationsAreWithinResponsePrefix state

structure CoreBundle (state : State Tx View Seqno Event) : Prop
    extends StructuralBundle state where
  clientEntryMatchesOrigin : ClientEntryMatchesOrigin state
  ledgerEntryViewsAreMonotonic : LedgerEntryViewsAreMonotonic state
  ledgerPrefixMatchesFrontierOrigin : LedgerPrefixMatchesFrontierOrigin state

structure ProvenanceBundle (state : State Tx View Seqno Event) : Prop
    extends CoreBundle state where
  ledgerTxIdsAreStableAcrossCopies : LedgerTxIdsAreStableAcrossCopies state
  clientEntryHasRequest : ClientEntryHasRequest state
  uniqueTxRequests : UniqueTxRequests state

/-- Auxiliary: the active views always have a greatest element, so a current
view exists. Every commit clause is stated relative to `currentView`, so this
is a prerequisite for the commit layer. -/
def HasCurrentView (state : State Tx View Seqno Event) : Prop :=
  Exists fun current => state.currentView current

structure ResponseBundle (state : State Tx View Seqno Event) : Prop
    extends ProvenanceBundle state where
  onlyObserveSentRequests : OnlyObserveSentRequests state
  uniqueResponseTxs : UniqueResponseTxs state

structure StatusBundle (state : State Tx View Seqno Event) : Prop
    extends ResponseBundle state where
  statusHasRwResponse : StatusHasRwResponse state
  hasCurrentView : HasCurrentView state

structure CommitBundle (state : State Tx View Seqno Event) : Prop
    extends StatusBundle state where
  committedIdIsInCurrentLedger : CommittedIdIsInCurrentLedger state

structure ClosureBundle (state : State Tx View Seqno Event) : Prop
    extends CommitBundle state where
  committedOrInvalid : CommittedOrInvalid state

structure ProvedBundle (state : State Tx View Seqno Event) : Prop where
  closure : ClosureBundle state
  uniqueRwTxs : UniqueRwTxs state
  sameObservations : SameObservations state
  atMostOnceObserved : AtMostOnceObserved state
  uniqueTxIds : UniqueTxIds state
  committedResponseMatchesCurrentLedger :
    CommittedResponseMatchesCurrentLedger state
  uniqueCommittedSeqnos : UniqueCommittedSeqnos state

structure PropertyBundle (state : State Tx View Seqno Event) : Prop where
  historyTypeOk : HistoryTypeOk state
  historyEventKindUnique : HistoryEventKindUnique state
  historyIsPrefix : HistoryIsPrefix state
  activeViewsArePrefix : ActiveViewsArePrefix state
  ledgerTypeOk : LedgerTypeOk state
  clientEntriesAreLedgerEntries : ClientEntriesAreLedgerEntries state
  ledgerIsPrefix : LedgerIsPrefix state
  ledgerTxIdsAreStableAcrossCopies : LedgerTxIdsAreStableAcrossCopies state
  ledgerEntryExistsInOriginView : LedgerEntryExistsInOriginView state
  responseFrontierIsLedgerEntry : ResponseFrontierIsLedgerEntry state
  clientEntryHasRequest : ClientEntryHasRequest state
  clientEntryMatchesOrigin : ClientEntryMatchesOrigin state
  ledgerEntryViewsAreMonotonic : LedgerEntryViewsAreMonotonic state
  ledgerPrefixMatchesFrontierOrigin : LedgerPrefixMatchesFrontierOrigin state
  responseBranchIsView : ResponseBranchIsView state
  responseFrontierMatchesOrigin : ResponseFrontierMatchesOrigin state
  rwResponseMatchesLedgerEntry : RwResponseMatchesLedgerEntry state
  statusHasRwResponse : StatusHasRwResponse state
  committedIdIsInCurrentLedger : CommittedIdIsInCurrentLedger state
  committedResponseMatchesCurrentLedger :
    CommittedResponseMatchesCurrentLedger state
  allReceivedAfterSent : AllReceivedAfterSent state
  uniqueTxRequests : UniqueTxRequests state
  onlyObserveSentRequests : OnlyObserveSentRequests state
  observationsAreWithinResponsePrefix :
    ObservationsAreWithinResponsePrefix state
  uniqueRwTxs : UniqueRwTxs state
  sameObservations : SameObservations state
  uniqueTxIds : UniqueTxIds state
  uniqueCommittedSeqnos : UniqueCommittedSeqnos state
  committedOrInvalid : CommittedOrInvalid state
  onceCommittedPreviousIsCommitted : OnceCommittedPreviousIsCommitted state
  onceCommittedOlderViewSuffixIsInvalid :
    OnceCommittedOlderViewSuffixIsInvalid state
  onceInvalidSameViewSuffixIsInvalid :
    OnceInvalidSameViewSuffixIsInvalid state
  allCommittedObserved : AllCommittedObserved state
  committedRwSerializable : CommittedRwSerializable state
  atMostOnceObserved : AtMostOnceObserved state
  committedRwOrderedRealTime : CommittedRwOrderedRealTime state

def PropertyBundle.structural
    {state : State Tx View Seqno Event}
    (properties : PropertyBundle state) : StructuralBundle state where
  historyTypeOk := properties.historyTypeOk
  historyEventKindUnique := properties.historyEventKindUnique
  historyIsPrefix := properties.historyIsPrefix
  activeViewsArePrefix := properties.activeViewsArePrefix
  ledgerTypeOk := properties.ledgerTypeOk
  clientEntriesAreLedgerEntries := properties.clientEntriesAreLedgerEntries
  ledgerIsPrefix := properties.ledgerIsPrefix
  ledgerEntryExistsInOriginView := properties.ledgerEntryExistsInOriginView
  responseFrontierIsLedgerEntry := properties.responseFrontierIsLedgerEntry
  responseBranchIsView := properties.responseBranchIsView
  responseFrontierMatchesOrigin := properties.responseFrontierMatchesOrigin
  rwResponseMatchesLedgerEntry := properties.rwResponseMatchesLedgerEntry
  allReceivedAfterSent := properties.allReceivedAfterSent
  observationsAreWithinResponsePrefix :=
    properties.observationsAreWithinResponsePrefix

def PropertyBundle.core
    {state : State Tx View Seqno Event}
    (properties : PropertyBundle state) : CoreBundle state where
  toStructuralBundle := properties.structural
  clientEntryMatchesOrigin := properties.clientEntryMatchesOrigin
  ledgerEntryViewsAreMonotonic := properties.ledgerEntryViewsAreMonotonic
  ledgerPrefixMatchesFrontierOrigin :=
    properties.ledgerPrefixMatchesFrontierOrigin

def PropertyBundle.provenance
    {state : State Tx View Seqno Event}
    (properties : PropertyBundle state) : ProvenanceBundle state where
  toCoreBundle := properties.core
  ledgerTxIdsAreStableAcrossCopies :=
    properties.ledgerTxIdsAreStableAcrossCopies
  clientEntryHasRequest := properties.clientEntryHasRequest
  uniqueTxRequests := properties.uniqueTxRequests

end CCFConsistency
