-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFConsistency.Properties

set_option autoImplicit false

/-!
# Pure Lean proofs for CCF consistency

The proof starts with the complete property bundle for the canonical
initializer. Preservation proofs are added action by action.
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

theorem eqZeroOfLeZero
    {Alpha : Type uTx}
    [LinearOrder Alpha]
    [OrderBot Alpha]
    {value : Alpha}
    (valueLeZero : value <= Bot.bot) :
    value = Bot.bot :=
  le_antisymm valueLeZero bot_le

omit
  [LinearOrder Tx] [OrderBot Tx]
  [LinearOrder View] [OrderBot View]
  [LinearOrder Seqno] [OrderBot Seqno]
  [OrderBot Event] in
theorem historyEventNotNext
    {state : State Tx View Seqno Event}
    {event : Event}
    (historyTypeOk : HistoryTypeOk state)
    (nextEvent : state.nextHistoryEvent event) :
    Not (state.historyEvent event) := by
  intro eventHasKind
  exact nextEvent.1 ((historyTypeOk event).2 eventHasKind)

omit
  [LinearOrder Tx] [OrderBot Tx]
  [LinearOrder View] [OrderBot View]
  [LinearOrder Seqno] [OrderBot Seqno]
  [OrderBot Event] in
theorem usedEventLtNext
    {state : State Tx View Seqno Event}
    {used next : Event}
    (historyIsPrefix : HistoryIsPrefix state)
    (usedEvent : state.eventUsed used)
    (nextEvent : state.nextHistoryEvent next) :
    state.eventLt used next := by
  constructor
  · rcases le_total used next with usedLeNext | nextLeUsed
    · exact usedLeNext
    · by_cases usedEqNext : used = next
      · subst used
        exact False.elim (nextEvent.1 usedEvent)
      · have nextLtUsed : state.eventLt next used :=
          ⟨nextLeUsed, Ne.symm usedEqNext⟩
        have nextUsed :=
          historyIsPrefix used next ⟨usedEvent, nextLtUsed⟩
        exact False.elim (nextEvent.1 nextUsed)
  · intro usedEqNext
    subst used
    exact nextEvent.1 usedEvent

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View]
  [LinearOrder Seqno] [OrderBot Seqno]
  [LinearOrder Event] [OrderBot Event] in
theorem activeViewLtNext
    {state : State Tx View Seqno Event}
    {active next : View}
    (activeViewsArePrefix : ActiveViewsArePrefix state)
    (activeView : state.activeView active)
    (nextView : state.nextView next) :
    state.viewLt active next := by
  have activeNeNext : Not (active = next) := by
    intro activeEqNext
    subst active
    exact nextView.1 activeView
  constructor
  · rcases le_total active next with activeLeNext | nextLeActive
    · exact activeLeNext
    · have nextLtActive : state.viewLt next active :=
        ⟨nextLeActive, Ne.symm activeNeNext⟩
      exact False.elim
        (nextView.1
          (activeViewsArePrefix active next
            ⟨activeView, nextLtActive⟩))
  · exact activeNeNext

theorem initialProperties :
    PropertyBundle (initialState : State Tx View Seqno Event) := by
  constructor <;>
    simp [
      HistoryTypeOk,
      HistoryEventKindUnique,
      HistoryIsPrefix,
      ActiveViewsArePrefix,
      LedgerTypeOk,
      ClientEntriesAreLedgerEntries,
      LedgerIsPrefix,
      LedgerTxIdsAreStableAcrossCopies,
      LedgerEntryExistsInOriginView,
      ResponseFrontierIsLedgerEntry,
      ClientEntryHasRequest,
      ClientEntryMatchesOrigin,
      LedgerEntryViewsAreMonotonic,
      LedgerPrefixMatchesFrontierOrigin,
      ResponseBranchIsView,
      ResponseFrontierMatchesOrigin,
      RwResponseMatchesLedgerEntry,
      StatusHasRwResponse,
      CommittedIdIsInCurrentLedger,
      CommittedResponseMatchesCurrentLedger,
      AllReceivedAfterSent,
      UniqueTxRequests,
      OnlyObserveSentRequests,
      ObservationsAreWithinResponsePrefix,
      UniqueRwTxs,
      SameObservations,
      UniqueTxIds,
      UniqueCommittedSeqnos,
      CommittedOrInvalid,
      OnceCommittedPreviousIsCommitted,
      OnceCommittedOlderViewSuffixIsInvalid,
      OnceInvalidSameViewSuffixIsInvalid,
      AllCommittedObserved,
      CommittedRwSerializable,
      AtMostOnceObserved,
      CommittedRwOrderedRealTime,
      State.historyEvent,
      State.requestEvent,
      State.responseEvent,
      State.observedAt,
      State.statusEvent,
      State.committedTxId,
      State.invalidTxId,
      State.rwResponseCommitted,
      State.observes,
      State.sameObservations,
      State.observationsSubset,
      State.currentView,
      State.eventLt,
      State.viewLt,
      State.txIdLt,
      initialState,
      orderedLt
    ];
    grind [eqZeroOfLeZero]

theorem initialStructural :
    StructuralBundle (initialState : State Tx View Seqno Event) :=
  initialProperties.structural

theorem initialCore :
    CoreBundle (initialState : State Tx View Seqno Event) :=
  initialProperties.core

omit
  [OrderBot Tx] [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxRequestPreservesStructural
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : StructuralBundle state)
    (_nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    StructuralBundle (rwTxRequestNext state tx event) := by
  have eventUnused : Not (state.eventUsed event) :=
    nextEvent.1
  have eventHasNoKind : Not (state.historyEvent event) := by
    intro eventHasKind
    exact eventUnused ((properties.historyTypeOk event).2 eventHasKind)
  have responseNeEvent :
      forall response,
        state.responseEvent response -> Not (response = event) := by
    intro response responseIsResponse responseEq
    subst response
    apply eventHasNoKind
    rcases responseIsResponse with responseIsRw | responseIsRo
    · exact Or.inr (Or.inl responseIsRw)
    · exact Or.inr (Or.inr (Or.inr (Or.inl responseIsRo)))
  have requestNeEvent :
      forall request,
        state.requestEvent request -> Not (request = event) := by
    intro request requestIsRequest requestEq
    subst request
    apply eventHasNoKind
    rcases requestIsRequest with requestIsRw | requestIsRo
    · exact Or.inl requestIsRw
    · exact Or.inr (Or.inr (Or.inl requestIsRo))
  refine
    { historyTypeOk := ?_
      historyEventKindUnique := ?_
      historyIsPrefix := ?_
      activeViewsArePrefix := ?_
      ledgerTypeOk := ?_
      clientEntriesAreLedgerEntries := ?_
      ledgerIsPrefix := ?_
      ledgerEntryExistsInOriginView := ?_
      responseFrontierIsLedgerEntry := ?_
      responseBranchIsView := ?_
      responseFrontierMatchesOrigin := ?_
      rwResponseMatchesLedgerEntry := ?_
      allReceivedAfterSent := ?_
      observationsAreWithinResponsePrefix := ?_ }
  · intro candidate
    by_cases candidateEq : candidate = event
    · subst candidate
      simp [rwTxRequestNext, updateUnary, State.historyEvent]
    · simpa [
        rwTxRequestNext,
        updateUnary,
        State.historyEvent,
        candidateEq
      ] using properties.historyTypeOk candidate
  · rw [HistoryEventKindUnique]
    intro candidate
    by_cases candidateEq : candidate = event
    · subst candidate
      simp only [State.historyEvent, not_or] at eventHasNoKind
      simp [rwTxRequestNext, updateUnary, eventHasNoKind]
    · simpa [
        HistoryEventKindUnique,
        rwTxRequestNext,
        updateUnary,
        candidateEq
      ] using properties.historyEventKindUnique candidate
  · rw [HistoryIsPrefix]
    intro later earlier usedAndEarlier
    rcases usedAndEarlier with ⟨laterUsed, earlierLt⟩
    by_cases earlierEq : earlier = event
    · subst earlier
      simp [rwTxRequestNext, updateUnary]
    · by_cases laterEq : later = event
      · subst later
        simpa [rwTxRequestNext, updateUnary, earlierEq] using
          nextEvent.2 earlier earlierLt
      · have oldLaterUsed : state.eventUsed later := by
          simpa [rwTxRequestNext, updateUnary, laterEq] using laterUsed
        have oldEarlierUsed :=
          properties.historyIsPrefix later earlier
            ⟨oldLaterUsed, earlierLt⟩
        simpa [rwTxRequestNext, updateUnary, earlierEq] using oldEarlierUsed
  · simpa [ActiveViewsArePrefix, rwTxRequestNext] using
      properties.activeViewsArePrefix
  · simpa [LedgerTypeOk, rwTxRequestNext] using properties.ledgerTypeOk
  · simpa [ClientEntriesAreLedgerEntries, rwTxRequestNext] using
      properties.clientEntriesAreLedgerEntries
  · simpa [LedgerIsPrefix, rwTxRequestNext] using properties.ledgerIsPrefix
  · simpa [LedgerEntryExistsInOriginView, rwTxRequestNext] using
      properties.ledgerEntryExistsInOriginView
  · simpa [ResponseFrontierIsLedgerEntry, rwTxRequestNext] using
      properties.responseFrontierIsLedgerEntry
  · simpa [ResponseBranchIsView, rwTxRequestNext] using
      properties.responseBranchIsView
  · simpa [ResponseFrontierMatchesOrigin, rwTxRequestNext] using
      properties.responseFrontierMatchesOrigin
  · rw [RwResponseMatchesLedgerEntry]
    intro response responseIsRw
    have responseIsRwOld : state.rwResponseEvent response := by
      simpa [rwTxRequestNext] using responseIsRw
    have responseNe := responseNeEvent response (Or.inl responseIsRwOld)
    simpa [rwTxRequestNext, updateUnary, responseNe] using
      properties.rwResponseMatchesLedgerEntry response responseIsRwOld
  · rw [AllReceivedAfterSent]
    intro response responseIsResponse
    have responseIsResponseOld : state.responseEvent response := by
      simpa [State.responseEvent, rwTxRequestNext] using responseIsResponse
    have responseNe := responseNeEvent response responseIsResponseOld
    rcases
        properties.allReceivedAfterSent response responseIsResponseOld with
      ⟨request, requestLt, txMatches, requestAndResponseKinds⟩
    have requestIsRequest : state.requestEvent request := by
      rcases requestAndResponseKinds with rwKinds | roKinds
      · exact Or.inl rwKinds.1
      · exact Or.inr roKinds.1
    have requestNe := requestNeEvent request requestIsRequest
    refine ⟨request, ?_⟩
    simpa [
      rwTxRequestNext,
      updateUnary,
      responseNe,
      requestNe
    ] using
      And.intro requestLt
        (And.intro txMatches requestAndResponseKinds)
  · simpa [
      ObservationsAreWithinResponsePrefix,
      State.observedAt,
      State.responseEvent,
      rwTxRequestNext
    ] using properties.observationsAreWithinResponsePrefix

omit
  [OrderBot Tx] [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem roTxRequestPreservesStructural
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : StructuralBundle state)
    (_nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    StructuralBundle (roTxRequestNext state tx event) := by
  have eventUnused : Not (state.eventUsed event) :=
    nextEvent.1
  have eventHasNoKind : Not (state.historyEvent event) := by
    intro eventHasKind
    exact eventUnused ((properties.historyTypeOk event).2 eventHasKind)
  have responseNeEvent :
      forall response,
        state.responseEvent response -> Not (response = event) := by
    intro response responseIsResponse responseEq
    subst response
    apply eventHasNoKind
    rcases responseIsResponse with responseIsRw | responseIsRo
    · exact Or.inr (Or.inl responseIsRw)
    · exact Or.inr (Or.inr (Or.inr (Or.inl responseIsRo)))
  have requestNeEvent :
      forall request,
        state.requestEvent request -> Not (request = event) := by
    intro request requestIsRequest requestEq
    subst request
    apply eventHasNoKind
    rcases requestIsRequest with requestIsRw | requestIsRo
    · exact Or.inl requestIsRw
    · exact Or.inr (Or.inr (Or.inl requestIsRo))
  refine
    { historyTypeOk := ?_
      historyEventKindUnique := ?_
      historyIsPrefix := ?_
      activeViewsArePrefix := ?_
      ledgerTypeOk := ?_
      clientEntriesAreLedgerEntries := ?_
      ledgerIsPrefix := ?_
      ledgerEntryExistsInOriginView := ?_
      responseFrontierIsLedgerEntry := ?_
      responseBranchIsView := ?_
      responseFrontierMatchesOrigin := ?_
      rwResponseMatchesLedgerEntry := ?_
      allReceivedAfterSent := ?_
      observationsAreWithinResponsePrefix := ?_ }
  · intro candidate
    by_cases candidateEq : candidate = event
    · subst candidate
      simp [roTxRequestNext, updateUnary, State.historyEvent]
    · simpa [
        roTxRequestNext,
        updateUnary,
        State.historyEvent,
        candidateEq
      ] using properties.historyTypeOk candidate
  · rw [HistoryEventKindUnique]
    intro candidate
    by_cases candidateEq : candidate = event
    · subst candidate
      simp only [State.historyEvent, not_or] at eventHasNoKind
      simp [roTxRequestNext, updateUnary, eventHasNoKind]
    · simpa [
        HistoryEventKindUnique,
        roTxRequestNext,
        updateUnary,
        candidateEq
      ] using properties.historyEventKindUnique candidate
  · rw [HistoryIsPrefix]
    intro later earlier usedAndEarlier
    rcases usedAndEarlier with ⟨laterUsed, earlierLt⟩
    by_cases earlierEq : earlier = event
    · subst earlier
      simp [roTxRequestNext, updateUnary]
    · by_cases laterEq : later = event
      · subst later
        simpa [roTxRequestNext, updateUnary, earlierEq] using
          nextEvent.2 earlier earlierLt
      · have oldLaterUsed : state.eventUsed later := by
          simpa [roTxRequestNext, updateUnary, laterEq] using laterUsed
        have oldEarlierUsed :=
          properties.historyIsPrefix later earlier
            ⟨oldLaterUsed, earlierLt⟩
        simpa [roTxRequestNext, updateUnary, earlierEq] using oldEarlierUsed
  · simpa [ActiveViewsArePrefix, roTxRequestNext] using
      properties.activeViewsArePrefix
  · simpa [LedgerTypeOk, roTxRequestNext] using properties.ledgerTypeOk
  · simpa [ClientEntriesAreLedgerEntries, roTxRequestNext] using
      properties.clientEntriesAreLedgerEntries
  · simpa [LedgerIsPrefix, roTxRequestNext] using properties.ledgerIsPrefix
  · simpa [LedgerEntryExistsInOriginView, roTxRequestNext] using
      properties.ledgerEntryExistsInOriginView
  · simpa [ResponseFrontierIsLedgerEntry, roTxRequestNext] using
      properties.responseFrontierIsLedgerEntry
  · simpa [ResponseBranchIsView, roTxRequestNext] using
      properties.responseBranchIsView
  · simpa [ResponseFrontierMatchesOrigin, roTxRequestNext] using
      properties.responseFrontierMatchesOrigin
  · rw [RwResponseMatchesLedgerEntry]
    intro response responseIsRw
    have responseIsRwOld : state.rwResponseEvent response := by
      simpa [roTxRequestNext] using responseIsRw
    have responseNe := responseNeEvent response (Or.inl responseIsRwOld)
    simpa [roTxRequestNext, updateUnary, responseNe] using
      properties.rwResponseMatchesLedgerEntry response responseIsRwOld
  · rw [AllReceivedAfterSent]
    intro response responseIsResponse
    have responseIsResponseOld : state.responseEvent response := by
      simpa [State.responseEvent, roTxRequestNext] using responseIsResponse
    have responseNe := responseNeEvent response responseIsResponseOld
    rcases
        properties.allReceivedAfterSent response responseIsResponseOld with
      ⟨request, requestLt, txMatches, requestAndResponseKinds⟩
    have requestIsRequest : state.requestEvent request := by
      rcases requestAndResponseKinds with rwKinds | roKinds
      · exact Or.inl rwKinds.1
      · exact Or.inr roKinds.1
    have requestNe := requestNeEvent request requestIsRequest
    refine ⟨request, ?_⟩
    simpa [
      roTxRequestNext,
      updateUnary,
      responseNe,
      requestNe
    ] using
      And.intro requestLt
        (And.intro txMatches requestAndResponseKinds)
  · simpa [
      ObservationsAreWithinResponsePrefix,
      State.observedAt,
      State.responseEvent,
      roTxRequestNext
    ] using properties.observationsAreWithinResponsePrefix

omit
  [OrderBot Tx] [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxRequestPreservesCore
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : CoreBundle state)
    (nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    CoreBundle (rwTxRequestNext state tx event) where
  toStructuralBundle :=
    rwTxRequestPreservesStructural
      properties.toStructuralBundle
      nextTx
      nextEvent
  clientEntryMatchesOrigin := by
    simpa [ClientEntryMatchesOrigin, rwTxRequestNext] using
      properties.clientEntryMatchesOrigin
  ledgerEntryViewsAreMonotonic := by
    simpa [LedgerEntryViewsAreMonotonic, rwTxRequestNext] using
      properties.ledgerEntryViewsAreMonotonic
  ledgerPrefixMatchesFrontierOrigin := by
    simpa [LedgerPrefixMatchesFrontierOrigin, rwTxRequestNext] using
      properties.ledgerPrefixMatchesFrontierOrigin

omit
  [OrderBot Tx] [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem roTxRequestPreservesCore
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : CoreBundle state)
    (nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    CoreBundle (roTxRequestNext state tx event) where
  toStructuralBundle :=
    roTxRequestPreservesStructural
      properties.toStructuralBundle
      nextTx
      nextEvent
  clientEntryMatchesOrigin := by
    simpa [ClientEntryMatchesOrigin, roTxRequestNext] using
      properties.clientEntryMatchesOrigin
  ledgerEntryViewsAreMonotonic := by
    simpa [LedgerEntryViewsAreMonotonic, roTxRequestNext] using
      properties.ledgerEntryViewsAreMonotonic
  ledgerPrefixMatchesFrontierOrigin := by
    simpa [LedgerPrefixMatchesFrontierOrigin, roTxRequestNext] using
      properties.ledgerPrefixMatchesFrontierOrigin

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxExecutePreservesStructural
    {state : State Tx View Seqno Event}
    {request : Event}
    {branch : View}
    {slot : Seqno}
    (properties : StructuralBundle state)
    (_requestIsRw : state.rwRequestEvent request)
    (_txNotInLedger : Not (state.txInLedger (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    StructuralBundle (rwTxExecuteNext state request branch slot) := by
  have ledgerEntryPreserved :
      forall candidateBranch candidateSlot,
        state.ledgerEntry candidateBranch candidateSlot ->
          (rwTxExecuteNext state request branch slot).ledgerEntry
            candidateBranch
            candidateSlot := by
    intro candidateBranch candidateSlot oldEntry
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases slotEq : candidateSlot = slot
      · subst candidateSlot
        simp [rwTxExecuteNext, updateBinary, updateUnary]
      · simpa [
          rwTxExecuteNext,
          updateBinary,
          updateUnary,
          slotEq
        ] using oldEntry
    · simpa [
        rwTxExecuteNext,
        updateBinary,
        updateUnary,
        branchEq
      ] using oldEntry
  refine
    { historyTypeOk := ?_
      historyEventKindUnique := ?_
      historyIsPrefix := ?_
      activeViewsArePrefix := ?_
      ledgerTypeOk := ?_
      clientEntriesAreLedgerEntries := ?_
      ledgerIsPrefix := ?_
      ledgerEntryExistsInOriginView := ?_
      responseFrontierIsLedgerEntry := ?_
      responseBranchIsView := ?_
      responseFrontierMatchesOrigin := ?_
      rwResponseMatchesLedgerEntry := ?_
      allReceivedAfterSent := ?_
      observationsAreWithinResponsePrefix := ?_ }
  · simpa [HistoryTypeOk, State.historyEvent, rwTxExecuteNext] using
      properties.historyTypeOk
  · simpa [HistoryEventKindUnique, rwTxExecuteNext] using
      properties.historyEventKindUnique
  · simpa [HistoryIsPrefix, rwTxExecuteNext] using properties.historyIsPrefix
  · simpa [ActiveViewsArePrefix, rwTxExecuteNext] using
      properties.activeViewsArePrefix
  · rw [LedgerTypeOk]
    intro candidateBranch candidateSlot candidateEntry
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases slotEq : candidateSlot = slot
      · subst candidateSlot
        constructor
        · exact branchIsActive
        · simp [rwTxExecuteNext, updateBinary, updateUnary]
      · have oldEntry : state.ledgerEntry branch candidateSlot := by
          simpa [
            rwTxExecuteNext,
            updateBinary,
            updateUnary,
            slotEq
          ] using candidateEntry
        simpa [
          rwTxExecuteNext,
          updateBinary,
          updateUnary,
          slotEq
        ] using properties.ledgerTypeOk branch candidateSlot oldEntry
    · have oldEntry :
          state.ledgerEntry candidateBranch candidateSlot := by
        simpa [
          rwTxExecuteNext,
          updateBinary,
          updateUnary,
          branchEq
        ] using candidateEntry
      simpa [
        rwTxExecuteNext,
        updateBinary,
        updateUnary,
        branchEq
      ] using
        properties.ledgerTypeOk candidateBranch candidateSlot oldEntry
  · rw [ClientEntriesAreLedgerEntries]
    intro candidateBranch candidateSlot candidateIsClient
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases slotEq : candidateSlot = slot
      · subst candidateSlot
        simp [rwTxExecuteNext, updateBinary, updateUnary]
      · have oldClient : state.clientEntry branch candidateSlot := by
          simpa [
            rwTxExecuteNext,
            updateBinary,
            updateUnary,
            slotEq
          ] using candidateIsClient
        exact ledgerEntryPreserved branch candidateSlot
          (properties.clientEntriesAreLedgerEntries
            branch
            candidateSlot
            oldClient)
    · have oldClient :
          state.clientEntry candidateBranch candidateSlot := by
        simpa [
          rwTxExecuteNext,
          branchEq
        ] using candidateIsClient
      exact ledgerEntryPreserved candidateBranch candidateSlot
        (properties.clientEntriesAreLedgerEntries
          candidateBranch
          candidateSlot
          oldClient)
  · rw [LedgerIsPrefix]
    intro candidateBranch later earlier laterEntryAndEarlier
    rcases laterEntryAndEarlier with ⟨laterEntry, earlierLt⟩
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases laterEq : later = slot
      · subst later
        exact nextSlot.2 earlier earlierLt
          |> ledgerEntryPreserved branch earlier
      · have oldLaterEntry : state.ledgerEntry branch later := by
          simpa [
            rwTxExecuteNext,
            updateBinary,
            updateUnary,
            laterEq
          ] using laterEntry
        by_cases earlierEq : earlier = slot
        · subst earlier
          simp [rwTxExecuteNext, updateBinary, updateUnary]
        · exact ledgerEntryPreserved branch earlier
            (properties.ledgerIsPrefix branch later earlier
              ⟨oldLaterEntry, earlierLt⟩)
    · have oldLaterEntry :
          state.ledgerEntry candidateBranch later := by
        simpa [
          rwTxExecuteNext,
          updateBinary,
          updateUnary,
          branchEq
        ] using laterEntry
      exact ledgerEntryPreserved candidateBranch earlier
        (properties.ledgerIsPrefix candidateBranch later earlier
          ⟨oldLaterEntry, earlierLt⟩)
  · rw [LedgerEntryExistsInOriginView]
    intro candidateBranch candidateSlot candidateEntry
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases slotEq : candidateSlot = slot
      · subst candidateSlot
        simp [rwTxExecuteNext, updateBinary, updateUnary]
      · have oldEntry : state.ledgerEntry branch candidateSlot := by
          simpa [
            rwTxExecuteNext,
            updateBinary,
            updateUnary,
            slotEq
          ] using candidateEntry
        have oldOriginEntry :=
          properties.ledgerEntryExistsInOriginView
            branch
            candidateSlot
            oldEntry
        simpa [
          rwTxExecuteNext,
          updateBinary,
          updateUnary,
          slotEq
        ] using
          ledgerEntryPreserved
            (state.entryView branch candidateSlot)
            candidateSlot
            oldOriginEntry
    · have oldEntry :
          state.ledgerEntry candidateBranch candidateSlot := by
        simpa [
          rwTxExecuteNext,
          updateBinary,
          updateUnary,
          branchEq
        ] using candidateEntry
      have oldOriginEntry :=
        properties.ledgerEntryExistsInOriginView
          candidateBranch
          candidateSlot
          oldEntry
      simpa [
        rwTxExecuteNext,
        updateBinary,
        updateUnary,
        branchEq
      ] using
        ledgerEntryPreserved
          (state.entryView candidateBranch candidateSlot)
          candidateSlot
          oldOriginEntry
  · rw [ResponseFrontierIsLedgerEntry]
    intro response responseIsResponse
    have oldResponse : state.responseEvent response := by
      simpa [State.responseEvent, rwTxExecuteNext] using responseIsResponse
    exact ledgerEntryPreserved
      (state.eventBranch response)
      (state.eventSeqno response)
      (properties.responseFrontierIsLedgerEntry response oldResponse)
  · simpa [ResponseBranchIsView, rwTxExecuteNext] using
      properties.responseBranchIsView
  · rw [ResponseFrontierMatchesOrigin]
    intro response responseIsResponse
    have oldResponse : state.responseEvent response := by
      simpa [State.responseEvent, rwTxExecuteNext] using responseIsResponse
    have oldFrontier :=
      properties.responseFrontierIsLedgerEntry response oldResponse
    have oldMatch :=
      properties.responseFrontierMatchesOrigin response oldResponse
    by_cases branchEq : state.eventBranch response = branch
    · by_cases slotEq : state.eventSeqno response = slot
      · exact False.elim (nextSlot.1 (by simpa [branchEq, slotEq] using oldFrontier))
      · simpa [
          rwTxExecuteNext,
          updateBinary,
          updateUnary,
          branchEq,
          slotEq
        ] using oldMatch
    · simpa [
        rwTxExecuteNext,
        updateBinary,
        updateUnary,
        branchEq
      ] using oldMatch
  · rw [RwResponseMatchesLedgerEntry]
    intro response responseIsRw
    have oldResponseIsRw : state.rwResponseEvent response := by
      simpa [rwTxExecuteNext] using responseIsRw
    have oldFrontier :=
      properties.responseFrontierIsLedgerEntry
        response
        (Or.inl oldResponseIsRw)
    have oldMatch :=
      properties.rwResponseMatchesLedgerEntry response oldResponseIsRw
    by_cases branchEq : state.eventBranch response = branch
    · by_cases slotEq : state.eventSeqno response = slot
      · exact False.elim (nextSlot.1 (by simpa [branchEq, slotEq] using oldFrontier))
      · simpa [
          rwTxExecuteNext,
          updateBinary,
          updateUnary,
          branchEq,
          slotEq
        ] using oldMatch
    · simpa [
        rwTxExecuteNext,
        updateBinary,
        updateUnary,
        branchEq
      ] using oldMatch
  · simpa [AllReceivedAfterSent, rwTxExecuteNext] using
      properties.allReceivedAfterSent
  · rw [ObservationsAreWithinResponsePrefix]
    intro response observedSlot observed observedAt
    exact ⟨observedAt.1, observedAt.2.1⟩

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxExecutePreservesCore
    {state : State Tx View Seqno Event}
    {request : Event}
    {branch : View}
    {slot : Seqno}
    (properties : CoreBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (txNotInLedger : Not (state.txInLedger (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    CoreBundle (rwTxExecuteNext state request branch slot) := by
  refine
    { toStructuralBundle :=
        rwTxExecutePreservesStructural
          properties.toStructuralBundle
          requestIsRw
          txNotInLedger
          branchIsActive
          nextSlot
      clientEntryMatchesOrigin := ?_
      ledgerEntryViewsAreMonotonic := ?_
      ledgerPrefixMatchesFrontierOrigin := ?_ }
  · rw [ClientEntryMatchesOrigin]
    intro candidateBranch candidateSlot candidateIsClient
    by_cases slotEq : candidateSlot = slot
    · subst candidateSlot
      by_cases branchEq : candidateBranch = branch
      · subst candidateBranch
        simp [rwTxExecuteNext, updateBinary, updateUnary]
      · have oldClient : state.clientEntry candidateBranch slot := by
          simpa [
            rwTxExecuteNext,
            updateBinary,
            updateUnary,
            branchEq
          ] using candidateIsClient
        have oldMatch :=
          properties.clientEntryMatchesOrigin
            candidateBranch
            slot
            oldClient
        by_cases originEq : state.entryView candidateBranch slot = branch
        · have oldOriginClient : state.clientEntry branch slot := by
            simpa [originEq] using oldMatch.1
          have oldOriginEntry :=
            properties.clientEntriesAreLedgerEntries
              branch
              slot
              oldOriginClient
          exact False.elim (nextSlot.1 oldOriginEntry)
        · simpa [
            rwTxExecuteNext,
            branchEq,
            originEq
          ] using oldMatch
    · have oldClient :
          state.clientEntry candidateBranch candidateSlot := by
        simpa [
          rwTxExecuteNext,
          slotEq
        ] using candidateIsClient
      simpa [
        rwTxExecuteNext,
        slotEq
      ] using
        properties.clientEntryMatchesOrigin
          candidateBranch
          candidateSlot
          oldClient
  · rw [LedgerEntryViewsAreMonotonic]
    intro candidateBranch earlier later laterEntryAndOrder
    rcases laterEntryAndOrder with ⟨laterEntry, earlierLeLater⟩
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases laterEq : later = slot
      · subst later
        by_cases earlierEq : earlier = slot
        · subst earlier
          exact le_rfl
        · have earlierLt : state.seqLt earlier slot :=
            ⟨earlierLeLater, earlierEq⟩
          have oldEarlierEntry := nextSlot.2 earlier earlierLt
          have oldEarlierType :=
            properties.ledgerTypeOk branch earlier oldEarlierEntry
          simpa [
            rwTxExecuteNext,
            earlierEq
          ] using oldEarlierType.2
      · have oldLaterEntry : state.ledgerEntry branch later := by
          simpa [
            rwTxExecuteNext,
            laterEq
          ] using laterEntry
        by_cases earlierEq : earlier = slot
        · subst earlier
          have slotLtLater : state.seqLt slot later :=
            ⟨earlierLeLater, Ne.symm laterEq⟩
          have oldSlotEntry :=
            properties.ledgerIsPrefix
              branch
              later
              slot
              ⟨oldLaterEntry, slotLtLater⟩
          exact False.elim (nextSlot.1 oldSlotEntry)
        · simpa [
            rwTxExecuteNext,
            earlierEq,
            laterEq
          ] using
            properties.ledgerEntryViewsAreMonotonic
              branch
              earlier
              later
              ⟨oldLaterEntry, earlierLeLater⟩
    · have oldLaterEntry :
          state.ledgerEntry candidateBranch later := by
        simpa [
          rwTxExecuteNext,
          branchEq
        ] using laterEntry
      simpa [
        rwTxExecuteNext,
        branchEq
      ] using
        properties.ledgerEntryViewsAreMonotonic
          candidateBranch
          earlier
          later
          ⟨oldLaterEntry, earlierLeLater⟩
  · rw [LedgerPrefixMatchesFrontierOrigin]
    intro candidateBranch frontier candidateSlot frontierAndOrder
    rcases frontierAndOrder with ⟨frontierEntry, candidateLeFrontier⟩
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases frontierEq : frontier = slot
      · subst frontier
        by_cases candidateEq : candidateSlot = slot
        · subst candidateSlot
          simp [rwTxExecuteNext]
        · have candidateLt : state.seqLt candidateSlot slot :=
            ⟨candidateLeFrontier, candidateEq⟩
          have oldCandidateEntry := nextSlot.2 candidateSlot candidateLt
          simp [
            rwTxExecuteNext,
            candidateEq,
            oldCandidateEntry
          ]
      · have oldFrontierEntry : state.ledgerEntry branch frontier := by
          simpa [
            rwTxExecuteNext,
            frontierEq
          ] using frontierEntry
        by_cases candidateEq : candidateSlot = slot
        · subst candidateSlot
          have slotLtFrontier : state.seqLt slot frontier :=
            ⟨candidateLeFrontier, Ne.symm frontierEq⟩
          have oldSlotEntry :=
            properties.ledgerIsPrefix
              branch
              frontier
              slot
              ⟨oldFrontierEntry, slotLtFrontier⟩
          exact False.elim (nextSlot.1 oldSlotEntry)
        · simpa [
            rwTxExecuteNext,
            frontierEq,
            candidateEq
          ] using
            properties.ledgerPrefixMatchesFrontierOrigin
              branch
              frontier
              candidateSlot
              ⟨oldFrontierEntry, candidateLeFrontier⟩
    · have oldFrontierEntry :
          state.ledgerEntry candidateBranch frontier := by
        simpa [
          rwTxExecuteNext,
          branchEq
        ] using frontierEntry
      have oldMatch :=
        properties.ledgerPrefixMatchesFrontierOrigin
          candidateBranch
          frontier
          candidateSlot
          ⟨oldFrontierEntry, candidateLeFrontier⟩
      by_cases candidateEq : candidateSlot = slot
      · subst candidateSlot
        by_cases originEq :
            state.entryView candidateBranch frontier = branch
        · have oldOriginEntry : state.ledgerEntry branch slot := by
            simpa [originEq] using oldMatch.1
          exact False.elim (nextSlot.1 oldOriginEntry)
        · simpa [
            rwTxExecuteNext,
            branchEq,
            originEq
          ] using oldMatch
      · simpa [
          rwTxExecuteNext,
          branchEq,
          candidateEq
        ] using oldMatch

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxExecutePreservesStableCopies
    {state : State Tx View Seqno Event}
    {request : Event}
    {branch : View}
    {slot : Seqno}
    (properties : PropertyBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (txNotInLedger : Not (state.txInLedger (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    LedgerTxIdsAreStableAcrossCopies (rwTxExecuteNext state request branch slot) := by
  intro leftBranch leftSlot rightBranch rightSlot leftClient rightClient eqTx
  -- Case: left entry is the newly written slot
  by_cases leftNew : leftBranch = branch ∧ leftSlot = slot
  · rcases leftNew with ⟨leftBranchEq, leftSlotEq⟩
    subst leftBranchEq; subst leftSlotEq
    have leftTx : (rwTxExecuteNext state request branch slot).entryTx branch slot =
      state.eventTx request := by simp [rwTxExecuteNext, updateBinary_same]
    -- If right is also the newly written slot, done
    by_cases rightNew : rightBranch = branch ∧ rightSlot = slot
    · rcases rightNew with ⟨rbEq, rsEq⟩
      subst rbEq; subst rsEq
      simp [rwTxExecuteNext] at eqTx
      exact ⟨rfl, rfl⟩
    · -- right is an old entry; derive contradiction with txNotInLedger
      by_cases rightBranchEq : rightBranch = branch
      · -- same branch but different slot
        have rightSlotNe : Not (rightSlot = slot) := by
          intro h; apply rightNew; exact And.intro rightBranchEq h
        have rightClientOld : state.clientEntry rightBranch rightSlot := by
          simpa [rwTxExecuteNext, updateBinary_of_second_ne] using rightClient
        have rightEntryOld : state.entryTx rightBranch rightSlot =
          (rwTxExecuteNext state request branch slot).entryTx rightBranch rightSlot := by
          simpa [rwTxExecuteNext, updateBinary_of_second_ne] using rfl
        have oldTxEq := rightEntryOld.trans (eqTx.symm.trans leftTx)
        exact False.elim (txNotInLedger (Exists.intro rightBranch (Exists.intro rightSlot (And.intro rightClientOld oldTxEq))))
      · -- different branch
        have rightClientOld : state.clientEntry rightBranch rightSlot := by
          simpa [rwTxExecuteNext, updateBinary_of_first_ne] using rightClient
        have rightEntryOld : state.entryTx rightBranch rightSlot =
          (rwTxExecuteNext state request branch slot).entryTx rightBranch rightSlot := by
          simpa [rwTxExecuteNext, updateBinary_of_first_ne] using rfl
        have oldTxEq := rightEntryOld.trans (eqTx.symm.trans leftTx)
        exact False.elim (txNotInLedger (Exists.intro rightBranch (Exists.intro rightSlot (And.intro rightClientOld oldTxEq))))
  · -- left is an old entry
    by_cases rightNew : rightBranch = branch ∧ rightSlot = slot
    · -- right is new (symmetric to above)
      rcases rightNew with ⟨rbEq, rsEq⟩
      subst rbEq; subst rsEq
      have rightTx : (rwTxExecuteNext state request branch slot).entryTx branch slot =
        state.eventTx request := by simp [rwTxExecuteNext, updateBinary_same]
      by_cases leftBranchEq : leftBranch = branch
      · have leftSlotNe : Not (leftSlot = slot) := by
          intro h; apply leftNew; exact And.intro leftBranchEq h
        have leftClientOld : state.clientEntry leftBranch leftSlot := by
          simpa [rwTxExecuteNext, updateBinary_of_second_ne] using leftClient
        have leftEntryOld : state.entryTx leftBranch leftSlot =
          (rwTxExecuteNext state request branch slot).entryTx leftBranch leftSlot := by
          simpa [rwTxExecuteNext, updateBinary_of_second_ne] using rfl
        have oldTxEq := leftEntryOld.trans (eqTx.trans rightTx)
        exact False.elim (txNotInLedger (Exists.intro leftBranch (Exists.intro leftSlot (And.intro leftClientOld oldTxEq))))
      · have leftClientOld : state.clientEntry leftBranch leftSlot := by
          simpa [rwTxExecuteNext, updateBinary_of_first_ne] using leftClient
        have leftEntryOld : state.entryTx leftBranch leftSlot =
          (rwTxExecuteNext state request branch slot).entryTx leftBranch leftSlot := by
          simpa [rwTxExecuteNext, updateBinary_of_first_ne] using rfl
        have oldTxEq := leftEntryOld.trans (eqTx.trans rightTx)
        exact False.elim (txNotInLedger (Exists.intro leftBranch (Exists.intro leftSlot (And.intro leftClientOld oldTxEq))))
    · -- both entries are old: fall back to the old-state lemma
      have leftClientOld : state.clientEntry leftBranch leftSlot := by
        by_cases leftBranchEq : leftBranch = branch
        · by_cases leftSlotEq : leftSlot = slot
          · subst leftSlotEq; subst leftBranchEq; simp [rwTxExecuteNext] at leftClient; contradiction
          · simpa [rwTxExecuteNext, updateBinary_of_second_ne] using leftClient
        · simpa [rwTxExecuteNext, updateBinary_of_first_ne] using leftClient
      have rightClientOld : state.clientEntry rightBranch rightSlot := by
        by_cases rightBranchEq : rightBranch = branch
        · by_cases rightSlotEq : rightSlot = slot
          · subst rightSlotEq; subst rightBranchEq; simp [rwTxExecuteNext] at rightClient; contradiction
          · simpa [rwTxExecuteNext, updateBinary_of_second_ne] using rightClient
        · simpa [rwTxExecuteNext, updateBinary_of_first_ne] using rightClient
      have leftOldTx : state.entryTx leftBranch leftSlot =
        (rwTxExecuteNext state request branch slot).entryTx leftBranch leftSlot := by
        by_cases leftBranchEq : leftBranch = branch
        · by_cases leftSlotEq : leftSlot = slot
          · subst leftSlotEq; subst leftBranchEq; simp [rwTxExecuteNext] at leftClient; contradiction
          · simpa [rwTxExecuteNext, updateBinary_of_second_ne] using rfl
        · simpa [rwTxExecuteNext, updateBinary_of_first_ne] using rfl
      have rightOldTx : state.entryTx rightBranch rightSlot =
        (rwTxExecuteNext state request branch slot).entryTx rightBranch rightSlot := by
        by_cases rightBranchEq : rightBranch = branch
        · by_cases rightSlotEq : rightSlot = slot
          · subst rightSlotEq; subst rightBranchEq; simp [rwTxExecuteNext] at rightClient; contradiction
          · simpa [rwTxExecuteNext, updateBinary_of_second_ne] using rfl
        · simpa [rwTxExecuteNext, updateBinary_of_first_ne] using rfl
      have oldEq := leftOldTx.trans (eqTx.trans rightOldTx.symm)
      exact properties.ledgerTxIdsAreStableAcrossCopies leftBranch leftSlot rightBranch rightSlot leftClientOld rightClientOld oldEq

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem appendOtherTxnPreservesStructural
    {state : State Tx View Seqno Event}
    {branch : View}
    {slot : Seqno}
    (properties : StructuralBundle state)
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    StructuralBundle (appendOtherTxnNext state branch slot) := by
  have ledgerEntryPreserved :
      forall candidateBranch candidateSlot,
        state.ledgerEntry candidateBranch candidateSlot ->
          (appendOtherTxnNext state branch slot).ledgerEntry
            candidateBranch
            candidateSlot := by
    intro candidateBranch candidateSlot oldEntry
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases slotEq : candidateSlot = slot
      · subst candidateSlot
        simp [appendOtherTxnNext, updateBinary, updateUnary]
      · simpa [
          appendOtherTxnNext,
          updateBinary,
          updateUnary,
          slotEq
        ] using oldEntry
    · simpa [
        appendOtherTxnNext,
        updateBinary,
        updateUnary,
        branchEq
      ] using oldEntry
  refine
    { historyTypeOk := ?_
      historyEventKindUnique := ?_
      historyIsPrefix := ?_
      activeViewsArePrefix := ?_
      ledgerTypeOk := ?_
      clientEntriesAreLedgerEntries := ?_
      ledgerIsPrefix := ?_
      ledgerEntryExistsInOriginView := ?_
      responseFrontierIsLedgerEntry := ?_
      responseBranchIsView := ?_
      responseFrontierMatchesOrigin := ?_
      rwResponseMatchesLedgerEntry := ?_
      allReceivedAfterSent := ?_
      observationsAreWithinResponsePrefix := ?_ }
  · simpa [HistoryTypeOk, State.historyEvent, appendOtherTxnNext] using
      properties.historyTypeOk
  · simpa [HistoryEventKindUnique, appendOtherTxnNext] using
      properties.historyEventKindUnique
  · simpa [HistoryIsPrefix, appendOtherTxnNext] using properties.historyIsPrefix
  · simpa [ActiveViewsArePrefix, appendOtherTxnNext] using
      properties.activeViewsArePrefix
  · rw [LedgerTypeOk]
    intro candidateBranch candidateSlot candidateEntry
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases slotEq : candidateSlot = slot
      · subst candidateSlot
        constructor
        · exact branchIsActive
        · simp [appendOtherTxnNext, updateBinary, updateUnary]
      · have oldEntry : state.ledgerEntry branch candidateSlot := by
          simpa [
            appendOtherTxnNext,
            updateBinary,
            updateUnary,
            slotEq
          ] using candidateEntry
        simpa [
          appendOtherTxnNext,
          updateBinary,
          updateUnary,
          slotEq
        ] using properties.ledgerTypeOk branch candidateSlot oldEntry
    · have oldEntry :
          state.ledgerEntry candidateBranch candidateSlot := by
        simpa [
          appendOtherTxnNext,
          updateBinary,
          updateUnary,
          branchEq
        ] using candidateEntry
      simpa [
        appendOtherTxnNext,
        updateBinary,
        updateUnary,
        branchEq
      ] using
        properties.ledgerTypeOk candidateBranch candidateSlot oldEntry
  · rw [ClientEntriesAreLedgerEntries]
    intro candidateBranch candidateSlot candidateIsClient
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases slotEq : candidateSlot = slot
      · subst candidateSlot
        simp [appendOtherTxnNext, updateBinary, updateUnary] at candidateIsClient
      · have oldClient : state.clientEntry branch candidateSlot := by
          simpa [
            appendOtherTxnNext,
            updateBinary,
            updateUnary,
            slotEq
          ] using candidateIsClient
        exact ledgerEntryPreserved branch candidateSlot
          (properties.clientEntriesAreLedgerEntries
            branch
            candidateSlot
            oldClient)
    · have oldClient :
          state.clientEntry candidateBranch candidateSlot := by
        simpa [
          appendOtherTxnNext,
          updateBinary,
          updateUnary,
          branchEq
        ] using candidateIsClient
      exact ledgerEntryPreserved candidateBranch candidateSlot
        (properties.clientEntriesAreLedgerEntries
          candidateBranch
          candidateSlot
          oldClient)
  · rw [LedgerIsPrefix]
    intro candidateBranch later earlier laterEntryAndEarlier
    rcases laterEntryAndEarlier with ⟨laterEntry, earlierLt⟩
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases laterEq : later = slot
      · subst later
        exact nextSlot.2 earlier earlierLt
          |> ledgerEntryPreserved branch earlier
      · have oldLaterEntry : state.ledgerEntry branch later := by
          simpa [
            appendOtherTxnNext,
            updateBinary,
            updateUnary,
            laterEq
          ] using laterEntry
        by_cases earlierEq : earlier = slot
        · subst earlier
          simp [appendOtherTxnNext, updateBinary, updateUnary]
        · exact ledgerEntryPreserved branch earlier
            (properties.ledgerIsPrefix branch later earlier
              ⟨oldLaterEntry, earlierLt⟩)
    · have oldLaterEntry :
          state.ledgerEntry candidateBranch later := by
        simpa [
          appendOtherTxnNext,
          updateBinary,
          updateUnary,
          branchEq
        ] using laterEntry
      exact ledgerEntryPreserved candidateBranch earlier
        (properties.ledgerIsPrefix candidateBranch later earlier
          ⟨oldLaterEntry, earlierLt⟩)
  · rw [LedgerEntryExistsInOriginView]
    intro candidateBranch candidateSlot candidateEntry
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases slotEq : candidateSlot = slot
      · subst candidateSlot
        simp [appendOtherTxnNext, updateBinary, updateUnary]
      · have oldEntry : state.ledgerEntry branch candidateSlot := by
          simpa [
            appendOtherTxnNext,
            updateBinary,
            updateUnary,
            slotEq
          ] using candidateEntry
        have oldOriginEntry :=
          properties.ledgerEntryExistsInOriginView
            branch
            candidateSlot
            oldEntry
        simpa [
          appendOtherTxnNext,
          updateBinary,
          updateUnary,
          slotEq
        ] using
          ledgerEntryPreserved
            (state.entryView branch candidateSlot)
            candidateSlot
            oldOriginEntry
    · have oldEntry :
          state.ledgerEntry candidateBranch candidateSlot := by
        simpa [
          appendOtherTxnNext,
          updateBinary,
          updateUnary,
          branchEq
        ] using candidateEntry
      have oldOriginEntry :=
        properties.ledgerEntryExistsInOriginView
          candidateBranch
          candidateSlot
          oldEntry
      simpa [
        appendOtherTxnNext,
        updateBinary,
        updateUnary,
        branchEq
      ] using
        ledgerEntryPreserved
          (state.entryView candidateBranch candidateSlot)
          candidateSlot
          oldOriginEntry
  · rw [ResponseFrontierIsLedgerEntry]
    intro response responseIsResponse
    have oldResponse : state.responseEvent response := by
      simpa [State.responseEvent, appendOtherTxnNext] using responseIsResponse
    exact ledgerEntryPreserved
      (state.eventBranch response)
      (state.eventSeqno response)
      (properties.responseFrontierIsLedgerEntry response oldResponse)
  · simpa [ResponseBranchIsView, appendOtherTxnNext] using
      properties.responseBranchIsView
  · rw [ResponseFrontierMatchesOrigin]
    intro response responseIsResponse
    have oldResponse : state.responseEvent response := by
      simpa [State.responseEvent, appendOtherTxnNext] using responseIsResponse
    have oldFrontier :=
      properties.responseFrontierIsLedgerEntry response oldResponse
    have oldMatch :=
      properties.responseFrontierMatchesOrigin response oldResponse
    by_cases branchEq : state.eventBranch response = branch
    · by_cases slotEq : state.eventSeqno response = slot
      · exact False.elim (nextSlot.1 (by simpa [branchEq, slotEq] using oldFrontier))
      · simpa [
          appendOtherTxnNext,
          updateBinary,
          updateUnary,
          branchEq,
          slotEq
        ] using oldMatch
    · simpa [
        appendOtherTxnNext,
        updateBinary,
        updateUnary,
        branchEq
      ] using oldMatch
  · rw [RwResponseMatchesLedgerEntry]
    intro response responseIsRw
    have oldResponseIsRw : state.rwResponseEvent response := by
      simpa [appendOtherTxnNext] using responseIsRw
    have oldFrontier :=
      properties.responseFrontierIsLedgerEntry
        response
        (Or.inl oldResponseIsRw)
    have oldMatch :=
      properties.rwResponseMatchesLedgerEntry response oldResponseIsRw
    by_cases branchEq : state.eventBranch response = branch
    · by_cases slotEq : state.eventSeqno response = slot
      · exact False.elim (nextSlot.1 (by simpa [branchEq, slotEq] using oldFrontier))
      · simpa [
          appendOtherTxnNext,
          updateBinary,
          updateUnary,
          branchEq,
          slotEq
        ] using oldMatch
    · simpa [
        appendOtherTxnNext,
        updateBinary,
        updateUnary,
        branchEq
      ] using oldMatch
  · simpa [AllReceivedAfterSent, appendOtherTxnNext] using
      properties.allReceivedAfterSent
  · rw [ObservationsAreWithinResponsePrefix]
    intro response observedSlot observed observedAt
    exact ⟨observedAt.1, observedAt.2.1⟩

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem appendOtherTxnPreservesCore
    {state : State Tx View Seqno Event}
    {branch : View}
    {slot : Seqno}
    (properties : CoreBundle state)
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    CoreBundle (appendOtherTxnNext state branch slot) := by
  refine
    { toStructuralBundle :=
        appendOtherTxnPreservesStructural
          properties.toStructuralBundle
          branchIsActive
          nextSlot
      clientEntryMatchesOrigin := ?_
      ledgerEntryViewsAreMonotonic := ?_
      ledgerPrefixMatchesFrontierOrigin := ?_ }
  · rw [ClientEntryMatchesOrigin]
    intro candidateBranch candidateSlot candidateIsClient
    by_cases slotEq : candidateSlot = slot
    · subst candidateSlot
      by_cases branchEq : candidateBranch = branch
      · subst candidateBranch
        simp [appendOtherTxnNext] at candidateIsClient
      · have oldClient : state.clientEntry candidateBranch slot := by
          simpa [appendOtherTxnNext, branchEq] using candidateIsClient
        have oldMatch :=
          properties.clientEntryMatchesOrigin
            candidateBranch
            slot
            oldClient
        by_cases originEq : state.entryView candidateBranch slot = branch
        · have oldOriginClient : state.clientEntry branch slot := by
            simpa [originEq] using oldMatch.1
          have oldOriginEntry :=
            properties.clientEntriesAreLedgerEntries
              branch
              slot
              oldOriginClient
          exact False.elim (nextSlot.1 oldOriginEntry)
        · simpa [
            appendOtherTxnNext,
            branchEq,
            originEq
          ] using oldMatch
    · have oldClient :
          state.clientEntry candidateBranch candidateSlot := by
        simpa [appendOtherTxnNext, slotEq] using candidateIsClient
      simpa [appendOtherTxnNext, slotEq] using
        properties.clientEntryMatchesOrigin
          candidateBranch
          candidateSlot
          oldClient
  · rw [LedgerEntryViewsAreMonotonic]
    intro candidateBranch earlier later laterEntryAndOrder
    rcases laterEntryAndOrder with ⟨laterEntry, earlierLeLater⟩
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases laterEq : later = slot
      · subst later
        by_cases earlierEq : earlier = slot
        · subst earlier
          exact le_rfl
        · have earlierLt : state.seqLt earlier slot :=
            ⟨earlierLeLater, earlierEq⟩
          have oldEarlierEntry := nextSlot.2 earlier earlierLt
          have oldEarlierType :=
            properties.ledgerTypeOk branch earlier oldEarlierEntry
          simpa [appendOtherTxnNext, earlierEq] using oldEarlierType.2
      · have oldLaterEntry : state.ledgerEntry branch later := by
          simpa [appendOtherTxnNext, laterEq] using laterEntry
        by_cases earlierEq : earlier = slot
        · subst earlier
          have slotLtLater : state.seqLt slot later :=
            ⟨earlierLeLater, Ne.symm laterEq⟩
          have oldSlotEntry :=
            properties.ledgerIsPrefix
              branch
              later
              slot
              ⟨oldLaterEntry, slotLtLater⟩
          exact False.elim (nextSlot.1 oldSlotEntry)
        · simpa [
            appendOtherTxnNext,
            earlierEq,
            laterEq
          ] using
            properties.ledgerEntryViewsAreMonotonic
              branch
              earlier
              later
              ⟨oldLaterEntry, earlierLeLater⟩
    · have oldLaterEntry :
          state.ledgerEntry candidateBranch later := by
        simpa [appendOtherTxnNext, branchEq] using laterEntry
      simpa [appendOtherTxnNext, branchEq] using
        properties.ledgerEntryViewsAreMonotonic
          candidateBranch
          earlier
          later
          ⟨oldLaterEntry, earlierLeLater⟩
  · rw [LedgerPrefixMatchesFrontierOrigin]
    intro candidateBranch frontier candidateSlot frontierAndOrder
    rcases frontierAndOrder with ⟨frontierEntry, candidateLeFrontier⟩
    by_cases branchEq : candidateBranch = branch
    · subst candidateBranch
      by_cases frontierEq : frontier = slot
      · subst frontier
        by_cases candidateEq : candidateSlot = slot
        · subst candidateSlot
          simp [appendOtherTxnNext]
        · have candidateLt : state.seqLt candidateSlot slot :=
            ⟨candidateLeFrontier, candidateEq⟩
          have oldCandidateEntry := nextSlot.2 candidateSlot candidateLt
          simp [
            appendOtherTxnNext,
            candidateEq,
            oldCandidateEntry
          ]
      · have oldFrontierEntry : state.ledgerEntry branch frontier := by
          simpa [appendOtherTxnNext, frontierEq] using frontierEntry
        by_cases candidateEq : candidateSlot = slot
        · subst candidateSlot
          have slotLtFrontier : state.seqLt slot frontier :=
            ⟨candidateLeFrontier, Ne.symm frontierEq⟩
          have oldSlotEntry :=
            properties.ledgerIsPrefix
              branch
              frontier
              slot
              ⟨oldFrontierEntry, slotLtFrontier⟩
          exact False.elim (nextSlot.1 oldSlotEntry)
        · simpa [
            appendOtherTxnNext,
            frontierEq,
            candidateEq
          ] using
            properties.ledgerPrefixMatchesFrontierOrigin
              branch
              frontier
              candidateSlot
              ⟨oldFrontierEntry, candidateLeFrontier⟩
    · have oldFrontierEntry :
          state.ledgerEntry candidateBranch frontier := by
        simpa [appendOtherTxnNext, branchEq] using frontierEntry
      have oldMatch :=
        properties.ledgerPrefixMatchesFrontierOrigin
          candidateBranch
          frontier
          candidateSlot
          ⟨oldFrontierEntry, candidateLeFrontier⟩
      by_cases candidateEq : candidateSlot = slot
      · subst candidateSlot
        by_cases originEq :
            state.entryView candidateBranch frontier = branch
        · have oldOriginEntry : state.ledgerEntry branch slot := by
            simpa [originEq] using oldMatch.1
          exact False.elim (nextSlot.1 oldOriginEntry)
        · simpa [
            appendOtherTxnNext,
            branchEq,
            originEq
          ] using oldMatch
      · simpa [
          appendOtherTxnNext,
          branchEq,
          candidateEq
        ] using oldMatch

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxResponsePreservesCore
    {state : State Tx View Seqno Event}
    {request response : Event}
    {branch : View}
    {slot : Seqno}
    (properties : CoreBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (_notResponded : Not (state.responded (state.eventTx request)))
    (_branchIsActive : state.activeView branch)
    (entryIsClient : state.clientEntry branch slot)
    (entryMatches : state.entryTx branch slot = state.eventTx request)
    (nextEvent : state.nextHistoryEvent response) :
    CoreBundle (rwTxResponseNext state request branch slot response) := by
  have responseHasNoKind :=
    historyEventNotNext properties.historyTypeOk nextEvent
  have requestUsed : state.eventUsed request :=
    (properties.historyTypeOk request).2 (Or.inl requestIsRw)
  have requestLtResponse :=
    usedEventLtNext
      properties.historyIsPrefix
      requestUsed
      nextEvent
  have oldResponseNe :
      forall candidate,
        state.responseEvent candidate -> Not (candidate = response) := by
    intro candidate candidateIsResponse candidateEq
    subst candidate
    apply responseHasNoKind
    rcases candidateIsResponse with candidateIsRw | candidateIsRo
    · exact Or.inr (Or.inl candidateIsRw)
    · exact Or.inr (Or.inr (Or.inr (Or.inl candidateIsRo)))
  have oldRequestNe :
      forall candidate,
        state.requestEvent candidate -> Not (candidate = response) := by
    intro candidate candidateIsRequest candidateEq
    subst candidate
    apply responseHasNoKind
    rcases candidateIsRequest with candidateIsRw | candidateIsRo
    · exact Or.inl candidateIsRw
    · exact Or.inr (Or.inr (Or.inl candidateIsRo))
  have originMatch :=
    properties.clientEntryMatchesOrigin branch slot entryIsClient
  refine
    { toStructuralBundle :=
        { historyTypeOk := ?_
          historyEventKindUnique := ?_
          historyIsPrefix := ?_
          activeViewsArePrefix := ?_
          ledgerTypeOk := ?_
          clientEntriesAreLedgerEntries := ?_
          ledgerIsPrefix := ?_
          ledgerEntryExistsInOriginView := ?_
          responseFrontierIsLedgerEntry := ?_
          responseBranchIsView := ?_
          responseFrontierMatchesOrigin := ?_
          rwResponseMatchesLedgerEntry := ?_
          allReceivedAfterSent := ?_
          observationsAreWithinResponsePrefix := ?_ }
      clientEntryMatchesOrigin := ?_
      ledgerEntryViewsAreMonotonic := ?_
      ledgerPrefixMatchesFrontierOrigin := ?_ }
  · intro candidate
    by_cases candidateEq : candidate = response
    · subst candidate
      simp [rwTxResponseNext, updateUnary, State.historyEvent]
    · simpa [
        rwTxResponseNext,
        updateUnary,
        State.historyEvent,
        candidateEq
      ] using properties.historyTypeOk candidate
  · rw [HistoryEventKindUnique]
    intro candidate
    by_cases candidateEq : candidate = response
    · subst candidate
      simp only [State.historyEvent, not_or] at responseHasNoKind
      simp [rwTxResponseNext, updateUnary, responseHasNoKind]
    · simpa [
        HistoryEventKindUnique,
        rwTxResponseNext,
        updateUnary,
        candidateEq
      ] using properties.historyEventKindUnique candidate
  · rw [HistoryIsPrefix]
    intro later earlier usedAndEarlier
    rcases usedAndEarlier with ⟨laterUsed, earlierLt⟩
    by_cases earlierEq : earlier = response
    · subst earlier
      simp [rwTxResponseNext, updateUnary]
    · by_cases laterEq : later = response
      · subst later
        simpa [rwTxResponseNext, updateUnary, earlierEq] using
          nextEvent.2 earlier earlierLt
      · have oldLaterUsed : state.eventUsed later := by
          simpa [rwTxResponseNext, updateUnary, laterEq] using laterUsed
        have oldEarlierUsed :=
          properties.historyIsPrefix later earlier
            ⟨oldLaterUsed, earlierLt⟩
        simpa [rwTxResponseNext, updateUnary, earlierEq] using oldEarlierUsed
  · simpa [ActiveViewsArePrefix, rwTxResponseNext] using
      properties.activeViewsArePrefix
  · simpa [LedgerTypeOk, rwTxResponseNext] using properties.ledgerTypeOk
  · simpa [ClientEntriesAreLedgerEntries, rwTxResponseNext] using
      properties.clientEntriesAreLedgerEntries
  · simpa [LedgerIsPrefix, rwTxResponseNext] using properties.ledgerIsPrefix
  · simpa [LedgerEntryExistsInOriginView, rwTxResponseNext] using
      properties.ledgerEntryExistsInOriginView
  · rw [ResponseFrontierIsLedgerEntry]
    intro candidate candidateIsResponse
    by_cases candidateEq : candidate = response
    · subst candidate
      have branchEntry :=
        properties.clientEntriesAreLedgerEntries branch slot entryIsClient
      have originEntry :=
        properties.ledgerEntryExistsInOriginView branch slot branchEntry
      simpa [rwTxResponseNext, updateUnary] using originEntry
    · have oldCandidate : state.responseEvent candidate := by
        simpa [
          State.responseEvent,
          rwTxResponseNext,
          updateUnary,
          candidateEq
        ] using candidateIsResponse
      simpa [rwTxResponseNext, updateUnary, candidateEq] using
        properties.responseFrontierIsLedgerEntry candidate oldCandidate
  · rw [ResponseBranchIsView]
    intro candidate candidateIsResponse
    by_cases candidateEq : candidate = response
    · subst candidate
      simp [rwTxResponseNext, updateUnary]
    · have oldCandidate : state.responseEvent candidate := by
        simpa [
          State.responseEvent,
          rwTxResponseNext,
          updateUnary,
          candidateEq
        ] using candidateIsResponse
      simpa [rwTxResponseNext, updateUnary, candidateEq] using
        properties.responseBranchIsView candidate oldCandidate
  · rw [ResponseFrontierMatchesOrigin]
    intro candidate candidateIsResponse
    by_cases candidateEq : candidate = response
    · subst candidate
      simpa [rwTxResponseNext, updateUnary] using originMatch.2.1
    · have oldCandidate : state.responseEvent candidate := by
        simpa [
          State.responseEvent,
          rwTxResponseNext,
          updateUnary,
          candidateEq
        ] using candidateIsResponse
      simpa [rwTxResponseNext, updateUnary, candidateEq] using
        properties.responseFrontierMatchesOrigin candidate oldCandidate
  · rw [RwResponseMatchesLedgerEntry]
    intro candidate candidateIsRw
    by_cases candidateEq : candidate = response
    · subst candidate
      have originTx :
          state.entryTx (state.entryView branch slot) slot =
            state.eventTx request :=
        originMatch.2.2.trans entryMatches
      simpa [rwTxResponseNext, updateUnary] using
        And.intro originMatch.1 originTx
    · have oldCandidate : state.rwResponseEvent candidate := by
        simpa [rwTxResponseNext, updateUnary, candidateEq] using candidateIsRw
      simpa [rwTxResponseNext, updateUnary, candidateEq] using
        properties.rwResponseMatchesLedgerEntry candidate oldCandidate
  · rw [AllReceivedAfterSent]
    intro candidate candidateIsResponse
    by_cases candidateEq : candidate = response
    · subst candidate
      refine ⟨request, ?_⟩
      constructor
      · exact requestLtResponse
      · constructor
        · simp [
            rwTxResponseNext,
            updateUnary,
            requestLtResponse.2
          ]
        · left
          constructor
          · simpa [
              rwTxResponseNext,
              updateUnary,
              requestLtResponse.2
            ] using requestIsRw
          · simp [rwTxResponseNext, updateUnary]
    · have oldCandidate : state.responseEvent candidate := by
        simpa [
          State.responseEvent,
          rwTxResponseNext,
          updateUnary,
          candidateEq
        ] using candidateIsResponse
      rcases properties.allReceivedAfterSent candidate oldCandidate with
        ⟨oldRequest, oldRequestLt, oldTxMatches, oldKinds⟩
      have oldRequestIsRequest : state.requestEvent oldRequest := by
        rcases oldKinds with rwKinds | roKinds
        · exact Or.inl rwKinds.1
        · exact Or.inr roKinds.1
      have oldRequestNe := oldRequestNe oldRequest oldRequestIsRequest
      refine ⟨oldRequest, ?_⟩
      simpa [
        rwTxResponseNext,
        updateUnary,
        candidateEq,
        oldRequestNe
      ] using
        And.intro oldRequestLt (And.intro oldTxMatches oldKinds)
  · rw [ObservationsAreWithinResponsePrefix]
    intro candidate candidateSlot observed observation
    exact ⟨observation.1, observation.2.1⟩
  · simpa [ClientEntryMatchesOrigin, rwTxResponseNext] using
      properties.clientEntryMatchesOrigin
  · simpa [LedgerEntryViewsAreMonotonic, rwTxResponseNext] using
      properties.ledgerEntryViewsAreMonotonic
  · simpa [LedgerPrefixMatchesFrontierOrigin, rwTxResponseNext] using
      properties.ledgerPrefixMatchesFrontierOrigin

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem roTxResponsePreservesCore
    {state : State Tx View Seqno Event}
    {request response : Event}
    {branch : View}
    {last : Seqno}
    (properties : CoreBundle state)
    (requestIsRo : state.roRequestEvent request)
    (_notResponded : Not (state.responded (state.eventTx request)))
    (_branchIsActive : state.activeView branch)
    (lastSlot : state.lastLedgerSlot branch last)
    (nextEvent : state.nextHistoryEvent response) :
    CoreBundle (roTxResponseNext state request branch last response) := by
  have responseHasNoKind :=
    historyEventNotNext properties.historyTypeOk nextEvent
  have requestUsed : state.eventUsed request :=
    (properties.historyTypeOk request).2
      (Or.inr (Or.inr (Or.inl requestIsRo)))
  have requestLtResponse :=
    usedEventLtNext
      properties.historyIsPrefix
      requestUsed
      nextEvent
  have oldResponseNe :
      forall candidate,
        state.responseEvent candidate -> Not (candidate = response) := by
    intro candidate candidateIsResponse candidateEq
    subst candidate
    apply responseHasNoKind
    rcases candidateIsResponse with candidateIsRw | candidateIsRo
    · exact Or.inr (Or.inl candidateIsRw)
    · exact Or.inr (Or.inr (Or.inr (Or.inl candidateIsRo)))
  have oldRequestNe :
      forall candidate,
        state.requestEvent candidate -> Not (candidate = response) := by
    intro candidate candidateIsRequest candidateEq
    subst candidate
    apply responseHasNoKind
    rcases candidateIsRequest with candidateIsRw | candidateIsRo
    · exact Or.inl candidateIsRw
    · exact Or.inr (Or.inr (Or.inl candidateIsRo))
  have prefixAtLast :=
    properties.ledgerPrefixMatchesFrontierOrigin
      branch
      last
      last
      ⟨lastSlot.1, le_rfl⟩
  refine
    { toStructuralBundle :=
        { historyTypeOk := ?_
          historyEventKindUnique := ?_
          historyIsPrefix := ?_
          activeViewsArePrefix := ?_
          ledgerTypeOk := ?_
          clientEntriesAreLedgerEntries := ?_
          ledgerIsPrefix := ?_
          ledgerEntryExistsInOriginView := ?_
          responseFrontierIsLedgerEntry := ?_
          responseBranchIsView := ?_
          responseFrontierMatchesOrigin := ?_
          rwResponseMatchesLedgerEntry := ?_
          allReceivedAfterSent := ?_
          observationsAreWithinResponsePrefix := ?_ }
      clientEntryMatchesOrigin := ?_
      ledgerEntryViewsAreMonotonic := ?_
      ledgerPrefixMatchesFrontierOrigin := ?_ }
  · intro candidate
    by_cases candidateEq : candidate = response
    · subst candidate
      simp [roTxResponseNext, updateUnary, State.historyEvent]
    · simpa [
        roTxResponseNext,
        updateUnary,
        State.historyEvent,
        candidateEq
      ] using properties.historyTypeOk candidate
  · rw [HistoryEventKindUnique]
    intro candidate
    by_cases candidateEq : candidate = response
    · subst candidate
      simp only [State.historyEvent, not_or] at responseHasNoKind
      simp [roTxResponseNext, updateUnary, responseHasNoKind]
    · simpa [
        HistoryEventKindUnique,
        roTxResponseNext,
        updateUnary,
        candidateEq
      ] using properties.historyEventKindUnique candidate
  · rw [HistoryIsPrefix]
    intro later earlier usedAndEarlier
    rcases usedAndEarlier with ⟨laterUsed, earlierLt⟩
    by_cases earlierEq : earlier = response
    · subst earlier
      simp [roTxResponseNext, updateUnary]
    · by_cases laterEq : later = response
      · subst later
        simpa [roTxResponseNext, updateUnary, earlierEq] using
          nextEvent.2 earlier earlierLt
      · have oldLaterUsed : state.eventUsed later := by
          simpa [roTxResponseNext, updateUnary, laterEq] using laterUsed
        have oldEarlierUsed :=
          properties.historyIsPrefix later earlier
            ⟨oldLaterUsed, earlierLt⟩
        simpa [roTxResponseNext, updateUnary, earlierEq] using oldEarlierUsed
  · simpa [ActiveViewsArePrefix, roTxResponseNext] using
      properties.activeViewsArePrefix
  · simpa [LedgerTypeOk, roTxResponseNext] using properties.ledgerTypeOk
  · simpa [ClientEntriesAreLedgerEntries, roTxResponseNext] using
      properties.clientEntriesAreLedgerEntries
  · simpa [LedgerIsPrefix, roTxResponseNext] using properties.ledgerIsPrefix
  · simpa [LedgerEntryExistsInOriginView, roTxResponseNext] using
      properties.ledgerEntryExistsInOriginView
  · rw [ResponseFrontierIsLedgerEntry]
    intro candidate candidateIsResponse
    by_cases candidateEq : candidate = response
    · subst candidate
      simpa [roTxResponseNext, updateUnary] using prefixAtLast.1
    · have oldCandidate : state.responseEvent candidate := by
        simpa [
          State.responseEvent,
          roTxResponseNext,
          updateUnary,
          candidateEq
        ] using candidateIsResponse
      simpa [roTxResponseNext, updateUnary, candidateEq] using
        properties.responseFrontierIsLedgerEntry candidate oldCandidate
  · rw [ResponseBranchIsView]
    intro candidate candidateIsResponse
    by_cases candidateEq : candidate = response
    · subst candidate
      simp [roTxResponseNext, updateUnary]
    · have oldCandidate : state.responseEvent candidate := by
        simpa [
          State.responseEvent,
          roTxResponseNext,
          updateUnary,
          candidateEq
        ] using candidateIsResponse
      simpa [roTxResponseNext, updateUnary, candidateEq] using
        properties.responseBranchIsView candidate oldCandidate
  · rw [ResponseFrontierMatchesOrigin]
    intro candidate candidateIsResponse
    by_cases candidateEq : candidate = response
    · subst candidate
      simpa [roTxResponseNext, updateUnary] using prefixAtLast.2.2.1.symm
    · have oldCandidate : state.responseEvent candidate := by
        simpa [
          State.responseEvent,
          roTxResponseNext,
          updateUnary,
          candidateEq
        ] using candidateIsResponse
      simpa [roTxResponseNext, updateUnary, candidateEq] using
        properties.responseFrontierMatchesOrigin candidate oldCandidate
  · rw [RwResponseMatchesLedgerEntry]
    intro candidate candidateIsRw
    by_cases candidateEq : candidate = response
    · subst candidate
      have oldResponseIsRw : state.rwResponseEvent response := by
        simpa [roTxResponseNext] using candidateIsRw
      exact False.elim
        (responseHasNoKind (Or.inr (Or.inl oldResponseIsRw)))
    · have oldCandidate : state.rwResponseEvent candidate := by
        simpa [roTxResponseNext, updateUnary, candidateEq] using candidateIsRw
      simpa [roTxResponseNext, updateUnary, candidateEq] using
        properties.rwResponseMatchesLedgerEntry candidate oldCandidate
  · rw [AllReceivedAfterSent]
    intro candidate candidateIsResponse
    by_cases candidateEq : candidate = response
    · subst candidate
      refine ⟨request, ?_⟩
      constructor
      · exact requestLtResponse
      · constructor
        · simp [
            roTxResponseNext,
            updateUnary,
            requestLtResponse.2
          ]
        · right
          constructor
          · simpa [
              roTxResponseNext,
              updateUnary,
              requestLtResponse.2
            ] using requestIsRo
          · simp [roTxResponseNext, updateUnary]
    · have oldCandidate : state.responseEvent candidate := by
        simpa [
          State.responseEvent,
          roTxResponseNext,
          updateUnary,
          candidateEq
        ] using candidateIsResponse
      rcases properties.allReceivedAfterSent candidate oldCandidate with
        ⟨oldRequest, oldRequestLt, oldTxMatches, oldKinds⟩
      have oldRequestIsRequest : state.requestEvent oldRequest := by
        rcases oldKinds with rwKinds | roKinds
        · exact Or.inl rwKinds.1
        · exact Or.inr roKinds.1
      have oldRequestNe := oldRequestNe oldRequest oldRequestIsRequest
      refine ⟨oldRequest, ?_⟩
      simpa [
        roTxResponseNext,
        updateUnary,
        candidateEq,
        oldRequestNe
      ] using
        And.intro oldRequestLt (And.intro oldTxMatches oldKinds)
  · rw [ObservationsAreWithinResponsePrefix]
    intro candidate candidateSlot observed observation
    exact ⟨observation.1, observation.2.1⟩
  · simpa [ClientEntryMatchesOrigin, roTxResponseNext] using
      properties.clientEntryMatchesOrigin
  · simpa [LedgerEntryViewsAreMonotonic, roTxResponseNext] using
      properties.ledgerEntryViewsAreMonotonic
  · simpa [LedgerPrefixMatchesFrontierOrigin, roTxResponseNext] using
      properties.ledgerPrefixMatchesFrontierOrigin

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem statusCommittedResponsePreservesCore
    {state : State Tx View Seqno Event}
    {response status : Event}
    {current : View}
    (properties : CoreBundle state)
    (_responseIsRw : state.rwResponseEvent response)
    (_viewIsCurrent : state.currentView current)
    (_responseSlotExists :
      state.ledgerEntry current (state.eventSeqno response))
    (_responseEntryMatches :
      state.entryView current (state.eventSeqno response) =
        state.eventView response)
    (_notInvalid :
      Not (Exists fun invalid =>
        state.invalidStatusEvent invalid /\
          state.eventView invalid = state.eventView response /\
            state.eventSeqno invalid <= state.eventSeqno response))
    (nextEvent : state.nextHistoryEvent status) :
    CoreBundle (statusCommittedResponseNext state response status) := by
  have statusHasNoKind :=
    historyEventNotNext properties.historyTypeOk nextEvent
  have oldResponseNe :
      forall candidate,
        state.responseEvent candidate -> Not (candidate = status) := by
    intro candidate candidateIsResponse candidateEq
    subst candidate
    apply statusHasNoKind
    rcases candidateIsResponse with candidateIsRw | candidateIsRo
    · exact Or.inr (Or.inl candidateIsRw)
    · exact Or.inr (Or.inr (Or.inr (Or.inl candidateIsRo)))
  refine
    { toStructuralBundle :=
        { historyTypeOk := ?_
          historyEventKindUnique := ?_
          historyIsPrefix := ?_
          activeViewsArePrefix := ?_
          ledgerTypeOk := ?_
          clientEntriesAreLedgerEntries := ?_
          ledgerIsPrefix := ?_
          ledgerEntryExistsInOriginView := ?_
          responseFrontierIsLedgerEntry := ?_
          responseBranchIsView := ?_
          responseFrontierMatchesOrigin := ?_
          rwResponseMatchesLedgerEntry := ?_
          allReceivedAfterSent := ?_
          observationsAreWithinResponsePrefix := ?_ }
      clientEntryMatchesOrigin := ?_
      ledgerEntryViewsAreMonotonic := ?_
      ledgerPrefixMatchesFrontierOrigin := ?_ }
  · intro candidate
    by_cases candidateEq : candidate = status
    · subst candidate
      simp [statusCommittedResponseNext, updateUnary, State.historyEvent]
    · simpa [
        statusCommittedResponseNext,
        updateUnary,
        State.historyEvent,
        candidateEq
      ] using properties.historyTypeOk candidate
  · rw [HistoryEventKindUnique]
    intro candidate
    by_cases candidateEq : candidate = status
    · subst candidate
      simp only [State.historyEvent, not_or] at statusHasNoKind
      simp [
        statusCommittedResponseNext,
        updateUnary,
        statusHasNoKind
      ]
    · simpa [
        HistoryEventKindUnique,
        statusCommittedResponseNext,
        updateUnary,
        candidateEq
      ] using properties.historyEventKindUnique candidate
  · rw [HistoryIsPrefix]
    intro later earlier usedAndEarlier
    rcases usedAndEarlier with ⟨laterUsed, earlierLt⟩
    by_cases earlierEq : earlier = status
    · subst earlier
      simp [statusCommittedResponseNext, updateUnary]
    · by_cases laterEq : later = status
      · subst later
        simpa [
          statusCommittedResponseNext,
          updateUnary,
          earlierEq
        ] using nextEvent.2 earlier earlierLt
      · have oldLaterUsed : state.eventUsed later := by
          simpa [
            statusCommittedResponseNext,
            updateUnary,
            laterEq
          ] using laterUsed
        have oldEarlierUsed :=
          properties.historyIsPrefix later earlier
            ⟨oldLaterUsed, earlierLt⟩
        simpa [
          statusCommittedResponseNext,
          updateUnary,
          earlierEq
        ] using oldEarlierUsed
  · simpa [ActiveViewsArePrefix, statusCommittedResponseNext] using
      properties.activeViewsArePrefix
  · simpa [LedgerTypeOk, statusCommittedResponseNext] using
      properties.ledgerTypeOk
  · simpa [ClientEntriesAreLedgerEntries, statusCommittedResponseNext] using
      properties.clientEntriesAreLedgerEntries
  · simpa [LedgerIsPrefix, statusCommittedResponseNext] using
      properties.ledgerIsPrefix
  · simpa [LedgerEntryExistsInOriginView, statusCommittedResponseNext] using
      properties.ledgerEntryExistsInOriginView
  · rw [ResponseFrontierIsLedgerEntry]
    intro candidate candidateIsResponse
    have oldCandidate : state.responseEvent candidate := by
      simpa [
        State.responseEvent,
        statusCommittedResponseNext
      ] using candidateIsResponse
    have candidateNe := oldResponseNe candidate oldCandidate
    simpa [
      statusCommittedResponseNext,
      updateUnary,
      candidateNe
    ] using properties.responseFrontierIsLedgerEntry candidate oldCandidate
  · rw [ResponseBranchIsView]
    intro candidate candidateIsResponse
    have oldCandidate : state.responseEvent candidate := by
      simpa [
        State.responseEvent,
        statusCommittedResponseNext
      ] using candidateIsResponse
    have candidateNe := oldResponseNe candidate oldCandidate
    simpa [
      statusCommittedResponseNext,
      updateUnary,
      candidateNe
    ] using properties.responseBranchIsView candidate oldCandidate
  · rw [ResponseFrontierMatchesOrigin]
    intro candidate candidateIsResponse
    have oldCandidate : state.responseEvent candidate := by
      simpa [
        State.responseEvent,
        statusCommittedResponseNext
      ] using candidateIsResponse
    have candidateNe := oldResponseNe candidate oldCandidate
    simpa [
      statusCommittedResponseNext,
      updateUnary,
      candidateNe
    ] using properties.responseFrontierMatchesOrigin candidate oldCandidate
  · rw [RwResponseMatchesLedgerEntry]
    intro candidate candidateIsRw
    have candidateNe : Not (candidate = status) := by
      intro candidateEq
      subst candidate
      exact statusHasNoKind (Or.inr (Or.inl candidateIsRw))
    simpa [
      statusCommittedResponseNext,
      updateUnary,
      candidateNe
    ] using properties.rwResponseMatchesLedgerEntry candidate candidateIsRw
  · simpa [AllReceivedAfterSent, statusCommittedResponseNext] using
      properties.allReceivedAfterSent
  · rw [ObservationsAreWithinResponsePrefix]
    intro candidate slot observed observation
    exact ⟨observation.1, observation.2.1⟩
  · simpa [ClientEntryMatchesOrigin, statusCommittedResponseNext] using
      properties.clientEntryMatchesOrigin
  · simpa [LedgerEntryViewsAreMonotonic, statusCommittedResponseNext] using
      properties.ledgerEntryViewsAreMonotonic
  · simpa [LedgerPrefixMatchesFrontierOrigin, statusCommittedResponseNext] using
      properties.ledgerPrefixMatchesFrontierOrigin

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem statusInvalidResponsePreservesCore
    {state : State Tx View Seqno Event}
    {response status : Event}
    (properties : CoreBundle state)
    (_responseIsRw : state.rwResponseEvent response)
    (_statusAllowed : state.invalidStatusAllowed response)
    (nextEvent : state.nextHistoryEvent status) :
    CoreBundle (statusInvalidResponseNext state response status) := by
  have statusHasNoKind :=
    historyEventNotNext properties.historyTypeOk nextEvent
  have oldResponseNe :
      forall candidate,
        state.responseEvent candidate -> Not (candidate = status) := by
    intro candidate candidateIsResponse candidateEq
    subst candidate
    apply statusHasNoKind
    rcases candidateIsResponse with candidateIsRw | candidateIsRo
    · exact Or.inr (Or.inl candidateIsRw)
    · exact Or.inr (Or.inr (Or.inr (Or.inl candidateIsRo)))
  refine
    { toStructuralBundle :=
        { historyTypeOk := ?_
          historyEventKindUnique := ?_
          historyIsPrefix := ?_
          activeViewsArePrefix := ?_
          ledgerTypeOk := ?_
          clientEntriesAreLedgerEntries := ?_
          ledgerIsPrefix := ?_
          ledgerEntryExistsInOriginView := ?_
          responseFrontierIsLedgerEntry := ?_
          responseBranchIsView := ?_
          responseFrontierMatchesOrigin := ?_
          rwResponseMatchesLedgerEntry := ?_
          allReceivedAfterSent := ?_
          observationsAreWithinResponsePrefix := ?_ }
      clientEntryMatchesOrigin := ?_
      ledgerEntryViewsAreMonotonic := ?_
      ledgerPrefixMatchesFrontierOrigin := ?_ }
  · intro candidate
    by_cases candidateEq : candidate = status
    · subst candidate
      simp [statusInvalidResponseNext, updateUnary, State.historyEvent]
    · simpa [
        statusInvalidResponseNext,
        updateUnary,
        State.historyEvent,
        candidateEq
      ] using properties.historyTypeOk candidate
  · rw [HistoryEventKindUnique]
    intro candidate
    by_cases candidateEq : candidate = status
    · subst candidate
      simp only [State.historyEvent, not_or] at statusHasNoKind
      simp [
        statusInvalidResponseNext,
        updateUnary,
        statusHasNoKind
      ]
    · simpa [
        HistoryEventKindUnique,
        statusInvalidResponseNext,
        updateUnary,
        candidateEq
      ] using properties.historyEventKindUnique candidate
  · rw [HistoryIsPrefix]
    intro later earlier usedAndEarlier
    rcases usedAndEarlier with ⟨laterUsed, earlierLt⟩
    by_cases earlierEq : earlier = status
    · subst earlier
      simp [statusInvalidResponseNext, updateUnary]
    · by_cases laterEq : later = status
      · subst later
        simpa [
          statusInvalidResponseNext,
          updateUnary,
          earlierEq
        ] using nextEvent.2 earlier earlierLt
      · have oldLaterUsed : state.eventUsed later := by
          simpa [
            statusInvalidResponseNext,
            updateUnary,
            laterEq
          ] using laterUsed
        have oldEarlierUsed :=
          properties.historyIsPrefix later earlier
            ⟨oldLaterUsed, earlierLt⟩
        simpa [
          statusInvalidResponseNext,
          updateUnary,
          earlierEq
        ] using oldEarlierUsed
  · simpa [ActiveViewsArePrefix, statusInvalidResponseNext] using
      properties.activeViewsArePrefix
  · simpa [LedgerTypeOk, statusInvalidResponseNext] using
      properties.ledgerTypeOk
  · simpa [ClientEntriesAreLedgerEntries, statusInvalidResponseNext] using
      properties.clientEntriesAreLedgerEntries
  · simpa [LedgerIsPrefix, statusInvalidResponseNext] using
      properties.ledgerIsPrefix
  · simpa [LedgerEntryExistsInOriginView, statusInvalidResponseNext] using
      properties.ledgerEntryExistsInOriginView
  · rw [ResponseFrontierIsLedgerEntry]
    intro candidate candidateIsResponse
    have oldCandidate : state.responseEvent candidate := by
      simpa [
        State.responseEvent,
        statusInvalidResponseNext
      ] using candidateIsResponse
    have candidateNe := oldResponseNe candidate oldCandidate
    simpa [
      statusInvalidResponseNext,
      updateUnary,
      candidateNe
    ] using properties.responseFrontierIsLedgerEntry candidate oldCandidate
  · rw [ResponseBranchIsView]
    intro candidate candidateIsResponse
    have oldCandidate : state.responseEvent candidate := by
      simpa [
        State.responseEvent,
        statusInvalidResponseNext
      ] using candidateIsResponse
    have candidateNe := oldResponseNe candidate oldCandidate
    simpa [
      statusInvalidResponseNext,
      updateUnary,
      candidateNe
    ] using properties.responseBranchIsView candidate oldCandidate
  · rw [ResponseFrontierMatchesOrigin]
    intro candidate candidateIsResponse
    have oldCandidate : state.responseEvent candidate := by
      simpa [
        State.responseEvent,
        statusInvalidResponseNext
      ] using candidateIsResponse
    have candidateNe := oldResponseNe candidate oldCandidate
    simpa [
      statusInvalidResponseNext,
      updateUnary,
      candidateNe
    ] using properties.responseFrontierMatchesOrigin candidate oldCandidate
  · rw [RwResponseMatchesLedgerEntry]
    intro candidate candidateIsRw
    have candidateNe : Not (candidate = status) := by
      intro candidateEq
      subst candidate
      exact statusHasNoKind (Or.inr (Or.inl candidateIsRw))
    simpa [
      statusInvalidResponseNext,
      updateUnary,
      candidateNe
    ] using properties.rwResponseMatchesLedgerEntry candidate candidateIsRw
  · simpa [AllReceivedAfterSent, statusInvalidResponseNext] using
      properties.allReceivedAfterSent
  · rw [ObservationsAreWithinResponsePrefix]
    intro candidate slot observed observation
    exact ⟨observation.1, observation.2.1⟩
  · simpa [ClientEntryMatchesOrigin, statusInvalidResponseNext] using
      properties.clientEntryMatchesOrigin
  · simpa [LedgerEntryViewsAreMonotonic, statusInvalidResponseNext] using
      properties.ledgerEntryViewsAreMonotonic
  · simpa [LedgerPrefixMatchesFrontierOrigin, statusInvalidResponseNext] using
      properties.ledgerPrefixMatchesFrontierOrigin

omit [OrderBot Seqno] [OrderBot Event] in
theorem truncateLedgerPreservesCore
    {state : State Tx View Seqno Event}
    {source newView : View}
    {cut : Seqno}
    (properties : CoreBundle state)
    (sourceIsActive : state.activeView source)
    (_cutExists : state.ledgerEntry source cut)
    (_sourceIsValid : state.validTruncationSource source cut)
    (viewIsNext : state.nextView newView) :
    CoreBundle (truncateLedgerNext state source cut newView) := by
  have sourceLtNew :=
    activeViewLtNext
      properties.activeViewsArePrefix
      sourceIsActive
      viewIsNext
  have oldLedgerBranchNeNew :
      forall branch slot,
        state.ledgerEntry branch slot -> Not (branch = newView) := by
    intro branch slot entry branchEq
    subst branch
    exact viewIsNext.1 (properties.ledgerTypeOk newView slot entry).1
  refine
    { toStructuralBundle :=
        { historyTypeOk := ?_
          historyEventKindUnique := ?_
          historyIsPrefix := ?_
          activeViewsArePrefix := ?_
          ledgerTypeOk := ?_
          clientEntriesAreLedgerEntries := ?_
          ledgerIsPrefix := ?_
          ledgerEntryExistsInOriginView := ?_
          responseFrontierIsLedgerEntry := ?_
          responseBranchIsView := ?_
          responseFrontierMatchesOrigin := ?_
          rwResponseMatchesLedgerEntry := ?_
          allReceivedAfterSent := ?_
          observationsAreWithinResponsePrefix := ?_ }
      clientEntryMatchesOrigin := ?_
      ledgerEntryViewsAreMonotonic := ?_
      ledgerPrefixMatchesFrontierOrigin := ?_ }
  · simpa [HistoryTypeOk, truncateLedgerNext] using
      properties.historyTypeOk
  · simpa [HistoryEventKindUnique, truncateLedgerNext] using
      properties.historyEventKindUnique
  · simpa [HistoryIsPrefix, truncateLedgerNext] using
      properties.historyIsPrefix
  · rw [ActiveViewsArePrefix]
    intro later earlier activeAndEarlier
    rcases activeAndEarlier with ⟨laterActive, earlierLt⟩
    by_cases earlierEq : earlier = newView
    · subst earlier
      simp [truncateLedgerNext, updateUnary]
    · by_cases laterEq : later = newView
      · subst later
        have oldEarlier := viewIsNext.2 earlier earlierLt
        simpa [
          truncateLedgerNext,
          updateUnary,
          earlierEq
        ] using oldEarlier
      · have oldLater : state.activeView later := by
          simpa [
            truncateLedgerNext,
            updateUnary,
            laterEq
          ] using laterActive
        have oldEarlier :=
          properties.activeViewsArePrefix later earlier
            ⟨oldLater, earlierLt⟩
        simpa [
          truncateLedgerNext,
          updateUnary,
          earlierEq
        ] using oldEarlier
  · rw [LedgerTypeOk]
    intro branch slot entry
    by_cases branchEq : branch = newView
    · subst branch
      have copiedEntry :
          slot <= cut /\ state.ledgerEntry source slot := by
        simpa [truncateLedgerNext, updateUnary] using entry
      have oldType :=
        properties.ledgerTypeOk source slot copiedEntry.2
      constructor
      · simp [truncateLedgerNext, updateUnary]
      · simpa [
          truncateLedgerNext,
          updateUnary,
          copiedEntry.1
        ] using le_trans oldType.2 sourceLtNew.1
    · have oldEntry : state.ledgerEntry branch slot := by
        simpa [
          truncateLedgerNext,
          updateUnary,
          branchEq
        ] using entry
      have oldType := properties.ledgerTypeOk branch slot oldEntry
      constructor
      · simpa [
          truncateLedgerNext,
          updateUnary,
          branchEq
        ] using oldType.1
      · simpa [
          truncateLedgerNext,
          updateUnary,
          branchEq
        ] using oldType.2
  · rw [ClientEntriesAreLedgerEntries]
    intro branch slot client
    by_cases branchEq : branch = newView
    · subst branch
      have copiedClient :
          slot <= cut /\ state.clientEntry source slot := by
        simpa [truncateLedgerNext, updateUnary] using client
      have oldEntry :=
        properties.clientEntriesAreLedgerEntries
          source
          slot
          copiedClient.2
      simpa [
        truncateLedgerNext,
        updateUnary,
        copiedClient.1
      ] using oldEntry
    · have oldClient : state.clientEntry branch slot := by
        simpa [
          truncateLedgerNext,
          updateUnary,
          branchEq
        ] using client
      have oldEntry :=
        properties.clientEntriesAreLedgerEntries branch slot oldClient
      simpa [
        truncateLedgerNext,
        updateUnary,
        branchEq
      ] using oldEntry
  · rw [LedgerIsPrefix]
    intro branch later earlier laterEntryAndEarlier
    rcases laterEntryAndEarlier with ⟨laterEntry, earlierLt⟩
    by_cases branchEq : branch = newView
    · subst branch
      have copiedLater :
          later <= cut /\ state.ledgerEntry source later := by
        simpa [truncateLedgerNext, updateUnary] using laterEntry
      have earlierLeCut := le_trans earlierLt.1 copiedLater.1
      have oldEarlier :=
        properties.ledgerIsPrefix
          source
          later
          earlier
          ⟨copiedLater.2, earlierLt⟩
      simpa [
        truncateLedgerNext,
        updateUnary,
        earlierLeCut
      ] using oldEarlier
    · have oldLater : state.ledgerEntry branch later := by
        simpa [
          truncateLedgerNext,
          updateUnary,
          branchEq
        ] using laterEntry
      have oldEarlier :=
        properties.ledgerIsPrefix
          branch
          later
          earlier
          ⟨oldLater, earlierLt⟩
      simpa [
        truncateLedgerNext,
        updateUnary,
        branchEq
      ] using oldEarlier
  · rw [LedgerEntryExistsInOriginView]
    intro branch slot entry
    by_cases branchEq : branch = newView
    · subst branch
      have copiedEntry :
          slot <= cut /\ state.ledgerEntry source slot := by
        simpa [truncateLedgerNext, updateUnary] using entry
      have oldOrigin :=
        properties.ledgerEntryExistsInOriginView
          source
          slot
          copiedEntry.2
      have originNe :=
        oldLedgerBranchNeNew
          (state.entryView source slot)
          slot
          oldOrigin
      simpa [
        truncateLedgerNext,
        updateUnary,
        copiedEntry.1,
        originNe
      ] using oldOrigin
    · have oldEntry : state.ledgerEntry branch slot := by
        simpa [
          truncateLedgerNext,
          updateUnary,
          branchEq
        ] using entry
      have oldOrigin :=
        properties.ledgerEntryExistsInOriginView branch slot oldEntry
      have originNe :=
        oldLedgerBranchNeNew
          (state.entryView branch slot)
          slot
          oldOrigin
      simpa [
        truncateLedgerNext,
        updateUnary,
        branchEq,
        originNe
      ] using oldOrigin
  · rw [ResponseFrontierIsLedgerEntry]
    intro response responseIsResponse
    have oldResponse : state.responseEvent response := by
      simpa [State.responseEvent, truncateLedgerNext] using responseIsResponse
    have oldFrontier :=
      properties.responseFrontierIsLedgerEntry response oldResponse
    have branchNe :=
      oldLedgerBranchNeNew
        (state.eventBranch response)
        (state.eventSeqno response)
        oldFrontier
    simpa [
      truncateLedgerNext,
      updateUnary,
      branchNe
    ] using oldFrontier
  · simpa [ResponseBranchIsView, truncateLedgerNext] using
      properties.responseBranchIsView
  · rw [ResponseFrontierMatchesOrigin]
    intro response responseIsResponse
    have oldResponse : state.responseEvent response := by
      simpa [State.responseEvent, truncateLedgerNext] using responseIsResponse
    have oldFrontier :=
      properties.responseFrontierIsLedgerEntry response oldResponse
    have branchNe :=
      oldLedgerBranchNeNew
        (state.eventBranch response)
        (state.eventSeqno response)
        oldFrontier
    simpa [
      truncateLedgerNext,
      updateUnary,
      branchNe
    ] using properties.responseFrontierMatchesOrigin response oldResponse
  · rw [RwResponseMatchesLedgerEntry]
    intro response responseIsRw
    have oldFrontier :=
      properties.responseFrontierIsLedgerEntry response (Or.inl responseIsRw)
    have branchNe :=
      oldLedgerBranchNeNew
        (state.eventBranch response)
        (state.eventSeqno response)
        oldFrontier
    simpa [
      truncateLedgerNext,
      updateUnary,
      branchNe
    ] using properties.rwResponseMatchesLedgerEntry response responseIsRw
  · simpa [AllReceivedAfterSent, truncateLedgerNext] using
      properties.allReceivedAfterSent
  · rw [ObservationsAreWithinResponsePrefix]
    intro response slot observed observation
    exact ⟨observation.1, observation.2.1⟩
  · rw [ClientEntryMatchesOrigin]
    intro branch slot client
    by_cases branchEq : branch = newView
    · subst branch
      have copiedClient :
          slot <= cut /\ state.clientEntry source slot := by
        simpa [truncateLedgerNext, updateUnary] using client
      have oldMatch :=
        properties.clientEntryMatchesOrigin
          source
          slot
          copiedClient.2
      have oldOriginEntry :=
        properties.clientEntriesAreLedgerEntries
          (state.entryView source slot)
          slot
          oldMatch.1
      have originNe :=
        oldLedgerBranchNeNew
          (state.entryView source slot)
          slot
          oldOriginEntry
      simpa [
        truncateLedgerNext,
        updateUnary,
        copiedClient.1,
        copiedClient.2,
        originNe
      ] using oldMatch
    · have oldClient : state.clientEntry branch slot := by
        simpa [
          truncateLedgerNext,
          updateUnary,
          branchEq
        ] using client
      have oldMatch :=
        properties.clientEntryMatchesOrigin branch slot oldClient
      have oldOriginEntry :=
        properties.clientEntriesAreLedgerEntries
          (state.entryView branch slot)
          slot
          oldMatch.1
      have originNe :=
        oldLedgerBranchNeNew
          (state.entryView branch slot)
          slot
          oldOriginEntry
      simpa [
        truncateLedgerNext,
        updateUnary,
        branchEq,
        originNe
      ] using oldMatch
  · rw [LedgerEntryViewsAreMonotonic]
    intro branch earlier later laterEntryAndOrder
    rcases laterEntryAndOrder with ⟨laterEntry, earlierLeLater⟩
    by_cases branchEq : branch = newView
    · subst branch
      have copiedLater :
          later <= cut /\ state.ledgerEntry source later := by
        simpa [truncateLedgerNext, updateUnary] using laterEntry
      have earlierLeCut := le_trans earlierLeLater copiedLater.1
      have oldOrder :=
        properties.ledgerEntryViewsAreMonotonic
          source
          earlier
          later
          ⟨copiedLater.2, earlierLeLater⟩
      simpa [
        truncateLedgerNext,
        updateUnary,
        earlierLeCut,
        copiedLater.1
      ] using oldOrder
    · have oldLater : state.ledgerEntry branch later := by
        simpa [
          truncateLedgerNext,
          updateUnary,
          branchEq
        ] using laterEntry
      simpa [
        truncateLedgerNext,
        updateUnary,
        branchEq
      ] using
        properties.ledgerEntryViewsAreMonotonic
          branch
          earlier
          later
          ⟨oldLater, earlierLeLater⟩
  · rw [LedgerPrefixMatchesFrontierOrigin]
    intro branch frontier slot frontierAndOrder
    rcases frontierAndOrder with ⟨frontierEntry, slotLeFrontier⟩
    by_cases branchEq : branch = newView
    · subst branch
      have copiedFrontier :
          frontier <= cut /\ state.ledgerEntry source frontier := by
        simpa [truncateLedgerNext, updateUnary] using frontierEntry
      have slotLeCut := le_trans slotLeFrontier copiedFrontier.1
      have oldMatch :=
        properties.ledgerPrefixMatchesFrontierOrigin
          source
          frontier
          slot
          ⟨copiedFrontier.2, slotLeFrontier⟩
      have originNe :=
        oldLedgerBranchNeNew
          (state.entryView source frontier)
          slot
          oldMatch.1
      refine ⟨?_, ?_, ?_, ?_⟩
      · simpa [
          truncateLedgerNext,
          updateUnary,
          copiedFrontier.1,
          originNe
        ] using oldMatch.1
      · simpa [
          truncateLedgerNext,
          updateUnary,
          slotLeCut,
          copiedFrontier.1,
          originNe
        ] using oldMatch.2.1
      · simpa [
          truncateLedgerNext,
          updateUnary,
          slotLeCut,
          copiedFrontier.1,
          originNe
        ] using oldMatch.2.2.1
      · intro client
        have oldClient : state.clientEntry source slot := by
          simpa [
            truncateLedgerNext,
            updateUnary,
            slotLeCut
          ] using client
        simpa [
          truncateLedgerNext,
          updateUnary,
          slotLeCut,
          oldClient,
          copiedFrontier.1,
          originNe
        ] using oldMatch.2.2.2 oldClient
    · have oldFrontier : state.ledgerEntry branch frontier := by
        simpa [
          truncateLedgerNext,
          updateUnary,
          branchEq
        ] using frontierEntry
      have oldMatch :=
        properties.ledgerPrefixMatchesFrontierOrigin
          branch
          frontier
          slot
          ⟨oldFrontier, slotLeFrontier⟩
      have originNe :=
        oldLedgerBranchNeNew
          (state.entryView branch frontier)
          slot
          oldMatch.1
      simpa [
        truncateLedgerNext,
        updateUnary,
        branchEq,
        originNe
      ] using oldMatch

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem truncateLedgerToEmptyPreservesCore
    {state : State Tx View Seqno Event}
    {source newView : View}
    (properties : CoreBundle state)
    (_sourceIsActive : state.activeView source)
    (_noCommitted : state.noCommittedTxId)
    (viewIsNext : state.nextView newView) :
    CoreBundle (truncateLedgerToEmptyNext state newView) := by
  refine
    { toStructuralBundle :=
        { historyTypeOk := ?_
          historyEventKindUnique := ?_
          historyIsPrefix := ?_
          activeViewsArePrefix := ?_
          ledgerTypeOk := ?_
          clientEntriesAreLedgerEntries := ?_
          ledgerIsPrefix := ?_
          ledgerEntryExistsInOriginView := ?_
          responseFrontierIsLedgerEntry := ?_
          responseBranchIsView := ?_
          responseFrontierMatchesOrigin := ?_
          rwResponseMatchesLedgerEntry := ?_
          allReceivedAfterSent := ?_
          observationsAreWithinResponsePrefix := ?_ }
      clientEntryMatchesOrigin := ?_
      ledgerEntryViewsAreMonotonic := ?_
      ledgerPrefixMatchesFrontierOrigin := ?_ }
  · simpa [HistoryTypeOk, truncateLedgerToEmptyNext] using
      properties.historyTypeOk
  · simpa [HistoryEventKindUnique, truncateLedgerToEmptyNext] using
      properties.historyEventKindUnique
  · simpa [HistoryIsPrefix, truncateLedgerToEmptyNext] using
      properties.historyIsPrefix
  · rw [ActiveViewsArePrefix]
    intro later earlier activeAndEarlier
    rcases activeAndEarlier with ⟨laterActive, earlierLt⟩
    by_cases earlierEq : earlier = newView
    · subst earlier
      simp [truncateLedgerToEmptyNext, updateUnary]
    · by_cases laterEq : later = newView
      · subst later
        have oldEarlier := viewIsNext.2 earlier earlierLt
        simpa [
          truncateLedgerToEmptyNext,
          updateUnary,
          earlierEq
        ] using oldEarlier
      · have oldLater : state.activeView later := by
          simpa [
            truncateLedgerToEmptyNext,
            updateUnary,
            laterEq
          ] using laterActive
        have oldEarlier :=
          properties.activeViewsArePrefix later earlier
            ⟨oldLater, earlierLt⟩
        simpa [
          truncateLedgerToEmptyNext,
          updateUnary,
          earlierEq
        ] using oldEarlier
  · rw [LedgerTypeOk]
    intro branch slot entry
    have oldType := properties.ledgerTypeOk branch slot entry
    constructor
    · by_cases branchEq : branch = newView
      · subst branch
        simp [truncateLedgerToEmptyNext, updateUnary]
      · simpa [
          truncateLedgerToEmptyNext,
          updateUnary,
          branchEq
        ] using oldType.1
    · exact oldType.2
  · simpa [ClientEntriesAreLedgerEntries, truncateLedgerToEmptyNext] using
      properties.clientEntriesAreLedgerEntries
  · simpa [LedgerIsPrefix, truncateLedgerToEmptyNext] using
      properties.ledgerIsPrefix
  · simpa [LedgerEntryExistsInOriginView, truncateLedgerToEmptyNext] using
      properties.ledgerEntryExistsInOriginView
  · simpa [ResponseFrontierIsLedgerEntry, truncateLedgerToEmptyNext] using
      properties.responseFrontierIsLedgerEntry
  · simpa [ResponseBranchIsView, truncateLedgerToEmptyNext] using
      properties.responseBranchIsView
  · simpa [ResponseFrontierMatchesOrigin, truncateLedgerToEmptyNext] using
      properties.responseFrontierMatchesOrigin
  · simpa [RwResponseMatchesLedgerEntry, truncateLedgerToEmptyNext] using
      properties.rwResponseMatchesLedgerEntry
  · simpa [AllReceivedAfterSent, truncateLedgerToEmptyNext] using
      properties.allReceivedAfterSent
  · rw [ObservationsAreWithinResponsePrefix]
    intro response slot observed observation
    exact ⟨observation.1, observation.2.1⟩
  · simpa [ClientEntryMatchesOrigin, truncateLedgerToEmptyNext] using
      properties.clientEntryMatchesOrigin
  · simpa [LedgerEntryViewsAreMonotonic, truncateLedgerToEmptyNext] using
      properties.ledgerEntryViewsAreMonotonic
  · simpa [LedgerPrefixMatchesFrontierOrigin, truncateLedgerToEmptyNext] using
      properties.ledgerPrefixMatchesFrontierOrigin

omit [OrderBot Seqno] [OrderBot Event] in
theorem stepPreservesCore
    {state next : State Tx View Seqno Event}
    (properties : CoreBundle state)
    (transition : Step state next) :
    CoreBundle next := by
  cases transition with
  | rwTxRequest tx event nextTx nextEvent =>
      exact rwTxRequestPreservesCore properties nextTx nextEvent
  | roTxRequest tx event nextTx nextEvent =>
      exact roTxRequestPreservesCore properties nextTx nextEvent
  | rwTxExecute
      request
      branch
      slot
      requestIsRw
      txNotInLedger
      branchIsActive
      nextSlot =>
      exact
        rwTxExecutePreservesCore
          properties
          requestIsRw
          txNotInLedger
          branchIsActive
          nextSlot
  | appendOtherTxn branch slot branchIsActive nextSlot =>
      exact
        appendOtherTxnPreservesCore
          properties
          branchIsActive
          nextSlot
  | rwTxResponse
      request
      branch
      slot
      response
      requestIsRw
      notResponded
      branchIsActive
      entryIsClient
      entryMatches
      nextEvent =>
      exact
        rwTxResponsePreservesCore
          properties
          requestIsRw
          notResponded
          branchIsActive
          entryIsClient
          entryMatches
          nextEvent
  | roTxResponse
      request
      branch
      last
      response
      requestIsRo
      notResponded
      branchIsActive
      lastSlot
      nextEvent =>
      exact
        roTxResponsePreservesCore
          properties
          requestIsRo
          notResponded
          branchIsActive
          lastSlot
          nextEvent
  | statusCommittedResponse
      response
      status
      current
      responseIsRw
      viewIsCurrent
      responseSlotExists
      responseEntryMatches
      notInvalid
      nextEvent =>
      exact
        statusCommittedResponsePreservesCore
          properties
          responseIsRw
          viewIsCurrent
          responseSlotExists
          responseEntryMatches
          notInvalid
          nextEvent
  | statusInvalidResponse
      response
      status
      responseIsRw
      statusAllowed
      nextEvent =>
      exact
        statusInvalidResponsePreservesCore
          properties
          responseIsRw
          statusAllowed
          nextEvent
  | truncateLedger
      source
      cut
      newView
      sourceIsActive
      cutExists
      sourceIsValid
      viewIsNext =>
      exact
        truncateLedgerPreservesCore
          properties
          sourceIsActive
          cutExists
          sourceIsValid
          viewIsNext
  | truncateLedgerToEmpty
      source
      newView
      sourceIsActive
      noCommitted
      viewIsNext =>
      exact
        truncateLedgerToEmptyPreservesCore
          properties
          sourceIsActive
          noCommitted
          viewIsNext

theorem reachableCore
    {state : State Tx View Seqno Event}
    (reachable : Reachable state) :
    CoreBundle state := by
  induction reachable with
  | initial => exact initialCore
  | step _ transition properties =>
      exact stepPreservesCore properties transition

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem coreUniqueRwTxs
    {state : State Tx View Seqno Event}
    (properties : CoreBundle state) :
    UniqueRwTxs state := by
  rw [UniqueRwTxs]
  intro left right responses
  rcases responses with
    ⟨leftIsRw, rightIsRw, sameView, sameSeqno⟩
  have leftMatch :=
    properties.rwResponseMatchesLedgerEntry left leftIsRw
  have rightMatch :=
    properties.rwResponseMatchesLedgerEntry right rightIsRw
  have leftBranch :=
    properties.responseBranchIsView left (Or.inl leftIsRw)
  have rightBranch :=
    properties.responseBranchIsView right (Or.inl rightIsRw)
  calc
    state.eventTx left =
        state.entryTx
          (state.eventBranch left)
          (state.eventSeqno left) := leftMatch.2.symm
    _ =
        state.entryTx
          (state.eventBranch right)
          (state.eventSeqno right) := by
      rw [leftBranch, rightBranch, sameView, sameSeqno]
    _ = state.eventTx right := rightMatch.2

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem coreSameObservations
    {state : State Tx View Seqno Event}
    (properties : CoreBundle state) :
    SameObservations state := by
  rw [SameObservations]
  intro left right responses
  rcases responses with
    ⟨leftIsResponse, rightIsResponse, sameView, sameSeqno⟩
  have leftBranch :=
    properties.responseBranchIsView left leftIsResponse
  have rightBranch :=
    properties.responseBranchIsView right rightIsResponse
  rw [State.sameObservations]
  intro slot observed
  simp only [State.observedAt]
  rw [leftBranch, rightBranch, sameView, sameSeqno]
  constructor
  · rintro ⟨_, observation⟩
    exact ⟨rightIsResponse, observation⟩
  · rintro ⟨_, observation⟩
    exact ⟨leftIsResponse, observation⟩

theorem reachableProved
    {state : State Tx View Seqno Event}
    (reachable : Reachable state) :
    ProvedBundle state := by
  have core := reachableCore reachable
  exact
    { core
      uniqueRwTxs := coreUniqueRwTxs core
      sameObservations := coreSameObservations core }

end CCFConsistency
