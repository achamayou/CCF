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

theorem initialProvenance :
    ProvenanceBundle (initialState : State Tx View Seqno Event) :=
  initialProperties.provenance

omit
  [LinearOrder Tx] [OrderBot Tx]
  [LinearOrder View] [OrderBot View]
  [LinearOrder Seqno] [OrderBot Seqno]
  [OrderBot Event] in
/-- A fresh history event is distinct from every event that already has a
kind, so the old event functions are unchanged at every classified event. -/
theorem classifiedEventNeNext
    {state : State Tx View Seqno Event}
    {candidate event : Event}
    (historyTypeOk : HistoryTypeOk state)
    (nextEvent : state.nextHistoryEvent event)
    (candidateHasKind : state.historyEvent candidate) :
    Not (candidate = event) := by
  intro candidateEq
  subst candidate
  exact nextEvent.1 ((historyTypeOk event).2 candidateHasKind)

omit
  [OrderBot Tx] [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxRequestPreservesProvenance
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : ProvenanceBundle state)
    (nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    ProvenanceBundle (rwTxRequestNext state tx event) := by
  have requestNeEvent :
      forall candidate,
        state.requestEvent candidate -> Not (candidate = event) := by
    intro candidate candidateIsRequest
    refine classifiedEventNeNext properties.historyTypeOk nextEvent ?_
    rcases candidateIsRequest with candidateIsRw | candidateIsRo
    · exact Or.inl candidateIsRw
    · exact Or.inr (Or.inr (Or.inl candidateIsRo))
  refine
    { toCoreBundle :=
        rwTxRequestPreservesCore properties.toCoreBundle nextTx nextEvent
      ledgerTxIdsAreStableAcrossCopies := ?_
      clientEntryHasRequest := ?_
      uniqueTxRequests := ?_ }
  · simpa [LedgerTxIdsAreStableAcrossCopies, rwTxRequestNext] using
      properties.ledgerTxIdsAreStableAcrossCopies
  · rw [ClientEntryHasRequest]
    intro branch slot isClient
    have oldClient : state.clientEntry branch slot := by
      simpa [rwTxRequestNext] using isClient
    rcases properties.clientEntryHasRequest branch slot oldClient with
      ⟨request, requestIsRw, requestTx⟩
    have requestNe := requestNeEvent request (Or.inl requestIsRw)
    exact
      ⟨request, by simpa [rwTxRequestNext, requestNe] using requestIsRw,
        by simpa [rwTxRequestNext, requestNe] using requestTx⟩
  · rw [UniqueTxRequests]
    intro left right requests
    rcases requests with ⟨leftIsRequest, rightIsRequest, leftNeRight⟩
    by_cases leftEq : left = event
    · subst left
      have rightIsOld : state.requestEvent right := by
        simpa [
          State.requestEvent,
          rwTxRequestNext,
          Ne.symm leftNeRight
        ] using rightIsRequest
      have rightNe := requestNeEvent right rightIsOld
      simp only [rwTxRequestNext, updateUnary_same, updateUnary_of_ne _ _ _ _ rightNe]
      intro txEq
      exact nextTx.1 (rightIsOld.imp
        (fun rightIsRw => ⟨right, rightIsRw, txEq.symm⟩)
        (fun rightIsRo => ⟨right, rightIsRo, txEq.symm⟩))
    · by_cases rightEq : right = event
      · subst right
        have leftIsOld : state.requestEvent left := by
          simpa [State.requestEvent, rwTxRequestNext, leftEq] using leftIsRequest
        have leftNe := requestNeEvent left leftIsOld
        simp only [rwTxRequestNext, updateUnary_same, updateUnary_of_ne _ _ _ _ leftNe]
        intro txEq
        exact nextTx.1 (leftIsOld.imp
          (fun leftIsRw => ⟨left, leftIsRw, txEq⟩)
          (fun leftIsRo => ⟨left, leftIsRo, txEq⟩))
      · have leftIsOld : state.requestEvent left := by
          simpa [State.requestEvent, rwTxRequestNext, leftEq] using leftIsRequest
        have rightIsOld : state.requestEvent right := by
          simpa [State.requestEvent, rwTxRequestNext, rightEq] using rightIsRequest
        simpa [rwTxRequestNext, leftEq, rightEq] using
          properties.uniqueTxRequests left right
            ⟨leftIsOld, rightIsOld, leftNeRight⟩

omit
  [OrderBot Tx] [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem roTxRequestPreservesProvenance
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : ProvenanceBundle state)
    (nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    ProvenanceBundle (roTxRequestNext state tx event) := by
  have requestNeEvent :
      forall candidate,
        state.requestEvent candidate -> Not (candidate = event) := by
    intro candidate candidateIsRequest
    refine classifiedEventNeNext properties.historyTypeOk nextEvent ?_
    rcases candidateIsRequest with candidateIsRw | candidateIsRo
    · exact Or.inl candidateIsRw
    · exact Or.inr (Or.inr (Or.inl candidateIsRo))
  refine
    { toCoreBundle :=
        roTxRequestPreservesCore properties.toCoreBundle nextTx nextEvent
      ledgerTxIdsAreStableAcrossCopies := ?_
      clientEntryHasRequest := ?_
      uniqueTxRequests := ?_ }
  · simpa [LedgerTxIdsAreStableAcrossCopies, roTxRequestNext] using
      properties.ledgerTxIdsAreStableAcrossCopies
  · rw [ClientEntryHasRequest]
    intro branch slot isClient
    have oldClient : state.clientEntry branch slot := by
      simpa [roTxRequestNext] using isClient
    rcases properties.clientEntryHasRequest branch slot oldClient with
      ⟨request, requestIsRw, requestTx⟩
    have requestNe := requestNeEvent request (Or.inl requestIsRw)
    exact
      ⟨request, by simpa [roTxRequestNext, requestNe] using requestIsRw,
        by simpa [roTxRequestNext, requestNe] using requestTx⟩
  · rw [UniqueTxRequests]
    intro left right requests
    rcases requests with ⟨leftIsRequest, rightIsRequest, leftNeRight⟩
    by_cases leftEq : left = event
    · subst left
      have rightIsOld : state.requestEvent right := by
        simpa [
          State.requestEvent,
          roTxRequestNext,
          Ne.symm leftNeRight
        ] using rightIsRequest
      have rightNe := requestNeEvent right rightIsOld
      simp only [roTxRequestNext, updateUnary_same, updateUnary_of_ne _ _ _ _ rightNe]
      intro txEq
      exact nextTx.1 (rightIsOld.imp
        (fun rightIsRw => ⟨right, rightIsRw, txEq.symm⟩)
        (fun rightIsRo => ⟨right, rightIsRo, txEq.symm⟩))
    · by_cases rightEq : right = event
      · subst right
        have leftIsOld : state.requestEvent left := by
          simpa [State.requestEvent, roTxRequestNext, leftEq] using leftIsRequest
        have leftNe := requestNeEvent left leftIsOld
        simp only [roTxRequestNext, updateUnary_same, updateUnary_of_ne _ _ _ _ leftNe]
        intro txEq
        exact nextTx.1 (leftIsOld.imp
          (fun leftIsRw => ⟨left, leftIsRw, txEq⟩)
          (fun leftIsRo => ⟨left, leftIsRo, txEq⟩))
      · have leftIsOld : state.requestEvent left := by
          simpa [State.requestEvent, roTxRequestNext, leftEq] using leftIsRequest
        have rightIsOld : state.requestEvent right := by
          simpa [State.requestEvent, roTxRequestNext, rightEq] using rightIsRequest
        simpa [roTxRequestNext, leftEq, rightEq] using
          properties.uniqueTxRequests left right
            ⟨leftIsOld, rightIsOld, leftNeRight⟩

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxExecutePreservesProvenance
    {state : State Tx View Seqno Event}
    {request : Event}
    {branch : View}
    {slot : Seqno}
    (properties : ProvenanceBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (txNotInLedger : Not (state.txInLedger (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    ProvenanceBundle (rwTxExecuteNext state request branch slot) := by
  have offPointClient :
      forall candidateBranch candidateSlot,
        Not (candidateBranch = branch) \/ Not (candidateSlot = slot) ->
          ((rwTxExecuteNext state request branch slot).clientEntry
              candidateBranch candidateSlot =
            state.clientEntry candidateBranch candidateSlot) := by
    intro candidateBranch candidateSlot offPoint
    rcases offPoint with branchNe | slotNe
    · simp [rwTxExecuteNext, branchNe]
    · simp [rwTxExecuteNext, slotNe]
  have offPointTx :
      forall candidateBranch candidateSlot,
        Not (candidateBranch = branch) \/ Not (candidateSlot = slot) ->
          ((rwTxExecuteNext state request branch slot).entryTx
              candidateBranch candidateSlot =
            state.entryTx candidateBranch candidateSlot) := by
    intro candidateBranch candidateSlot offPoint
    rcases offPoint with branchNe | slotNe
    · simp [rwTxExecuteNext, branchNe]
    · simp [rwTxExecuteNext, slotNe]
  have offPointView :
      forall candidateBranch candidateSlot,
        Not (candidateBranch = branch) \/ Not (candidateSlot = slot) ->
          ((rwTxExecuteNext state request branch slot).entryView
              candidateBranch candidateSlot =
            state.entryView candidateBranch candidateSlot) := by
    intro candidateBranch candidateSlot offPoint
    rcases offPoint with branchNe | slotNe
    · simp [rwTxExecuteNext, branchNe]
    · simp [rwTxExecuteNext, slotNe]
  have newPointTx :
      (rwTxExecuteNext state request branch slot).entryTx branch slot =
        state.eventTx request := by
    simp [rwTxExecuteNext]
  refine
    { toCoreBundle :=
        rwTxExecutePreservesCore
          properties.toCoreBundle
          requestIsRw
          txNotInLedger
          branchIsActive
          nextSlot
      ledgerTxIdsAreStableAcrossCopies := ?_
      clientEntryHasRequest := ?_
      uniqueTxRequests := ?_ }
  · rw [LedgerTxIdsAreStableAcrossCopies]
    intro leftBranch leftSlot rightBranch rightSlot entries
    rcases entries with ⟨leftIsClient, rightIsClient, sameTx⟩
    by_cases leftIsNew : leftBranch = branch /\ leftSlot = slot
    · rcases leftIsNew with ⟨leftBranchEq, leftSlotEq⟩
      subst leftBranch
      subst leftSlot
      by_cases rightIsNew : rightBranch = branch /\ rightSlot = slot
      · rcases rightIsNew with ⟨rightBranchEq, rightSlotEq⟩
        subst rightBranch
        subst rightSlot
        exact ⟨rfl, rfl⟩
      · have rightOff :
            Not (rightBranch = branch) \/ Not (rightSlot = slot) := by
          by_cases rightBranchEq : rightBranch = branch
          · exact Or.inr (fun rightSlotEq =>
              rightIsNew ⟨rightBranchEq, rightSlotEq⟩)
          · exact Or.inl rightBranchEq
        have rightOldClient : state.clientEntry rightBranch rightSlot := by
          rw [offPointClient rightBranch rightSlot rightOff] at rightIsClient
          exact rightIsClient
        have rightOldTx :
            state.entryTx rightBranch rightSlot = state.eventTx request := by
          rw [<- offPointTx rightBranch rightSlot rightOff, <- sameTx,
            newPointTx]
        exact False.elim
          (txNotInLedger
            ⟨rightBranch, rightSlot, rightOldClient, rightOldTx⟩)
    · have leftOff :
          Not (leftBranch = branch) \/ Not (leftSlot = slot) := by
        by_cases leftBranchEq : leftBranch = branch
        · exact Or.inr (fun leftSlotEq =>
            leftIsNew ⟨leftBranchEq, leftSlotEq⟩)
        · exact Or.inl leftBranchEq
      have leftOldClient : state.clientEntry leftBranch leftSlot := by
        rw [offPointClient leftBranch leftSlot leftOff] at leftIsClient
        exact leftIsClient
      by_cases rightIsNew : rightBranch = branch /\ rightSlot = slot
      · rcases rightIsNew with ⟨rightBranchEq, rightSlotEq⟩
        subst rightBranch
        subst rightSlot
        have leftOldTx :
            state.entryTx leftBranch leftSlot = state.eventTx request := by
          rw [<- offPointTx leftBranch leftSlot leftOff, sameTx, newPointTx]
        exact False.elim
          (txNotInLedger ⟨leftBranch, leftSlot, leftOldClient, leftOldTx⟩)
      · have rightOff :
            Not (rightBranch = branch) \/ Not (rightSlot = slot) := by
          by_cases rightBranchEq : rightBranch = branch
          · exact Or.inr (fun rightSlotEq =>
              rightIsNew ⟨rightBranchEq, rightSlotEq⟩)
          · exact Or.inl rightBranchEq
        have rightOldClient : state.clientEntry rightBranch rightSlot := by
          rw [offPointClient rightBranch rightSlot rightOff] at rightIsClient
          exact rightIsClient
        have oldSameTx :
            state.entryTx leftBranch leftSlot =
              state.entryTx rightBranch rightSlot := by
          rw [<- offPointTx leftBranch leftSlot leftOff,
            <- offPointTx rightBranch rightSlot rightOff]
          exact sameTx
        have oldResult :=
          properties.ledgerTxIdsAreStableAcrossCopies
            leftBranch leftSlot rightBranch rightSlot
            ⟨leftOldClient, rightOldClient, oldSameTx⟩
        refine ⟨oldResult.1, ?_⟩
        rw [offPointView leftBranch leftSlot leftOff,
          offPointView rightBranch rightSlot rightOff]
        exact oldResult.2
  · rw [ClientEntryHasRequest]
    intro candidateBranch candidateSlot isClient
    by_cases isNew : candidateBranch = branch /\ candidateSlot = slot
    · rcases isNew with ⟨branchEq, slotEq⟩
      subst candidateBranch
      subst candidateSlot
      exact
        ⟨request, by simpa [rwTxExecuteNext] using requestIsRw,
          by simp [rwTxExecuteNext]⟩
    · have offPoint :
          Not (candidateBranch = branch) \/ Not (candidateSlot = slot) := by
        by_cases branchEq : candidateBranch = branch
        · exact Or.inr (fun slotEq => isNew ⟨branchEq, slotEq⟩)
        · exact Or.inl branchEq
      have oldClient :
          state.clientEntry candidateBranch candidateSlot := by
        rw [offPointClient candidateBranch candidateSlot offPoint] at isClient
        exact isClient
      rcases
          properties.clientEntryHasRequest
            candidateBranch candidateSlot oldClient with
        ⟨oldRequest, oldRequestIsRw, oldRequestTx⟩
      refine ⟨oldRequest, by simpa [rwTxExecuteNext] using oldRequestIsRw, ?_⟩
      rw [offPointTx candidateBranch candidateSlot offPoint]
      simpa [rwTxExecuteNext] using oldRequestTx
  · simpa [UniqueTxRequests, rwTxExecuteNext] using properties.uniqueTxRequests

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem appendOtherTxnPreservesProvenance
    {state : State Tx View Seqno Event}
    {branch : View}
    {slot : Seqno}
    (properties : ProvenanceBundle state)
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    ProvenanceBundle (appendOtherTxnNext state branch slot) := by
  have newPointNotClient :
      Not ((appendOtherTxnNext state branch slot).clientEntry branch slot) := by
    simp [appendOtherTxnNext]
  have offPointClient :
      forall candidateBranch candidateSlot,
        Not (candidateBranch = branch) \/ Not (candidateSlot = slot) ->
          ((appendOtherTxnNext state branch slot).clientEntry
              candidateBranch candidateSlot =
            state.clientEntry candidateBranch candidateSlot) := by
    intro candidateBranch candidateSlot offPoint
    rcases offPoint with branchNe | slotNe
    · simp [appendOtherTxnNext, branchNe]
    · simp [appendOtherTxnNext, slotNe]
  have offPointView :
      forall candidateBranch candidateSlot,
        Not (candidateBranch = branch) \/ Not (candidateSlot = slot) ->
          ((appendOtherTxnNext state branch slot).entryView
              candidateBranch candidateSlot =
            state.entryView candidateBranch candidateSlot) := by
    intro candidateBranch candidateSlot offPoint
    rcases offPoint with branchNe | slotNe
    · simp [appendOtherTxnNext, branchNe]
    · simp [appendOtherTxnNext, slotNe]
  have offPointOfClient :
      forall candidateBranch candidateSlot,
        (appendOtherTxnNext state branch slot).clientEntry
            candidateBranch candidateSlot ->
          Not (candidateBranch = branch) \/ Not (candidateSlot = slot) := by
    intro candidateBranch candidateSlot isClient
    by_cases branchEq : candidateBranch = branch
    · refine Or.inr ?_
      intro slotEq
      subst candidateBranch
      subst candidateSlot
      exact newPointNotClient isClient
    · exact Or.inl branchEq
  refine
    { toCoreBundle :=
        appendOtherTxnPreservesCore
          properties.toCoreBundle
          branchIsActive
          nextSlot
      ledgerTxIdsAreStableAcrossCopies := ?_
      clientEntryHasRequest := ?_
      uniqueTxRequests := ?_ }
  · rw [LedgerTxIdsAreStableAcrossCopies]
    intro leftBranch leftSlot rightBranch rightSlot entries
    rcases entries with ⟨leftIsClient, rightIsClient, sameTx⟩
    have leftOff := offPointOfClient leftBranch leftSlot leftIsClient
    have rightOff := offPointOfClient rightBranch rightSlot rightIsClient
    have leftOldClient : state.clientEntry leftBranch leftSlot := by
      rw [offPointClient leftBranch leftSlot leftOff] at leftIsClient
      exact leftIsClient
    have rightOldClient : state.clientEntry rightBranch rightSlot := by
      rw [offPointClient rightBranch rightSlot rightOff] at rightIsClient
      exact rightIsClient
    have oldSameTx :
        state.entryTx leftBranch leftSlot =
          state.entryTx rightBranch rightSlot := by
      simpa [appendOtherTxnNext] using sameTx
    have oldResult :=
      properties.ledgerTxIdsAreStableAcrossCopies
        leftBranch leftSlot rightBranch rightSlot
        ⟨leftOldClient, rightOldClient, oldSameTx⟩
    refine ⟨oldResult.1, ?_⟩
    rw [offPointView leftBranch leftSlot leftOff,
      offPointView rightBranch rightSlot rightOff]
    exact oldResult.2
  · rw [ClientEntryHasRequest]
    intro candidateBranch candidateSlot isClient
    have offPoint := offPointOfClient candidateBranch candidateSlot isClient
    have oldClient : state.clientEntry candidateBranch candidateSlot := by
      rw [offPointClient candidateBranch candidateSlot offPoint] at isClient
      exact isClient
    rcases
        properties.clientEntryHasRequest
          candidateBranch candidateSlot oldClient with
      ⟨oldRequest, oldRequestIsRw, oldRequestTx⟩
    exact
      ⟨oldRequest, by simpa [appendOtherTxnNext] using oldRequestIsRw,
        by simpa [appendOtherTxnNext] using oldRequestTx⟩
  · simpa [UniqueTxRequests, appendOtherTxnNext] using
      properties.uniqueTxRequests

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxResponsePreservesProvenance
    {state : State Tx View Seqno Event}
    {request response : Event}
    {branch : View}
    {slot : Seqno}
    (properties : ProvenanceBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (notResponded : Not (state.responded (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (entryIsClient : state.clientEntry branch slot)
    (entryMatches : state.entryTx branch slot = state.eventTx request)
    (nextEvent : state.nextHistoryEvent response) :
    ProvenanceBundle (rwTxResponseNext state request branch slot response) := by
  have requestNeResponse :
      forall candidate,
        state.requestEvent candidate -> Not (candidate = response) := by
    intro candidate candidateIsRequest
    refine classifiedEventNeNext properties.historyTypeOk nextEvent ?_
    rcases candidateIsRequest with candidateIsRw | candidateIsRo
    · exact Or.inl candidateIsRw
    · exact Or.inr (Or.inr (Or.inl candidateIsRo))
  refine
    { toCoreBundle :=
        rwTxResponsePreservesCore
          properties.toCoreBundle
          requestIsRw
          notResponded
          branchIsActive
          entryIsClient
          entryMatches
          nextEvent
      ledgerTxIdsAreStableAcrossCopies := ?_
      clientEntryHasRequest := ?_
      uniqueTxRequests := ?_ }
  · simpa [LedgerTxIdsAreStableAcrossCopies, rwTxResponseNext] using
      properties.ledgerTxIdsAreStableAcrossCopies
  · rw [ClientEntryHasRequest]
    intro candidateBranch candidateSlot isClient
    have oldClient : state.clientEntry candidateBranch candidateSlot := by
      simpa [rwTxResponseNext] using isClient
    rcases
        properties.clientEntryHasRequest
          candidateBranch candidateSlot oldClient with
      ⟨oldRequest, oldRequestIsRw, oldRequestTx⟩
    have oldRequestNe := requestNeResponse oldRequest (Or.inl oldRequestIsRw)
    exact
      ⟨oldRequest, by simpa [rwTxResponseNext] using oldRequestIsRw,
        by simpa [rwTxResponseNext, oldRequestNe] using oldRequestTx⟩
  · rw [UniqueTxRequests]
    intro left right requests
    rcases requests with ⟨leftIsRequest, rightIsRequest, leftNeRight⟩
    have leftIsOld : state.requestEvent left := by
      simpa [State.requestEvent, rwTxResponseNext] using leftIsRequest
    have rightIsOld : state.requestEvent right := by
      simpa [State.requestEvent, rwTxResponseNext] using rightIsRequest
    have leftNe := requestNeResponse left leftIsOld
    have rightNe := requestNeResponse right rightIsOld
    simpa [rwTxResponseNext, leftNe, rightNe] using
      properties.uniqueTxRequests left right
        ⟨leftIsOld, rightIsOld, leftNeRight⟩

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem roTxResponsePreservesProvenance
    {state : State Tx View Seqno Event}
    {request response : Event}
    {branch : View}
    {last : Seqno}
    (properties : ProvenanceBundle state)
    (requestIsRo : state.roRequestEvent request)
    (notResponded : Not (state.responded (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (lastSlot : state.lastLedgerSlot branch last)
    (nextEvent : state.nextHistoryEvent response) :
    ProvenanceBundle (roTxResponseNext state request branch last response) := by
  have requestNeResponse :
      forall candidate,
        state.requestEvent candidate -> Not (candidate = response) := by
    intro candidate candidateIsRequest
    refine classifiedEventNeNext properties.historyTypeOk nextEvent ?_
    rcases candidateIsRequest with candidateIsRw | candidateIsRo
    · exact Or.inl candidateIsRw
    · exact Or.inr (Or.inr (Or.inl candidateIsRo))
  refine
    { toCoreBundle :=
        roTxResponsePreservesCore
          properties.toCoreBundle
          requestIsRo
          notResponded
          branchIsActive
          lastSlot
          nextEvent
      ledgerTxIdsAreStableAcrossCopies := ?_
      clientEntryHasRequest := ?_
      uniqueTxRequests := ?_ }
  · simpa [LedgerTxIdsAreStableAcrossCopies, roTxResponseNext] using
      properties.ledgerTxIdsAreStableAcrossCopies
  · rw [ClientEntryHasRequest]
    intro candidateBranch candidateSlot isClient
    have oldClient : state.clientEntry candidateBranch candidateSlot := by
      simpa [roTxResponseNext] using isClient
    rcases
        properties.clientEntryHasRequest
          candidateBranch candidateSlot oldClient with
      ⟨oldRequest, oldRequestIsRw, oldRequestTx⟩
    have oldRequestNe := requestNeResponse oldRequest (Or.inl oldRequestIsRw)
    exact
      ⟨oldRequest, by simpa [roTxResponseNext] using oldRequestIsRw,
        by simpa [roTxResponseNext, oldRequestNe] using oldRequestTx⟩
  · rw [UniqueTxRequests]
    intro left right requests
    rcases requests with ⟨leftIsRequest, rightIsRequest, leftNeRight⟩
    have leftIsOld : state.requestEvent left := by
      simpa [State.requestEvent, roTxResponseNext] using leftIsRequest
    have rightIsOld : state.requestEvent right := by
      simpa [State.requestEvent, roTxResponseNext] using rightIsRequest
    have leftNe := requestNeResponse left leftIsOld
    have rightNe := requestNeResponse right rightIsOld
    simpa [roTxResponseNext, leftNe, rightNe] using
      properties.uniqueTxRequests left right
        ⟨leftIsOld, rightIsOld, leftNeRight⟩

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem statusCommittedResponsePreservesProvenance
    {state : State Tx View Seqno Event}
    {response status : Event}
    {current : View}
    (properties : ProvenanceBundle state)
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
    ProvenanceBundle (statusCommittedResponseNext state response status) := by
  refine
    { toCoreBundle :=
        statusCommittedResponsePreservesCore
          properties.toCoreBundle
          responseIsRw
          viewIsCurrent
          responseSlotExists
          responseEntryMatches
          notInvalid
          nextEvent
      ledgerTxIdsAreStableAcrossCopies := ?_
      clientEntryHasRequest := ?_
      uniqueTxRequests := ?_ }
  · simpa [
      LedgerTxIdsAreStableAcrossCopies,
      statusCommittedResponseNext
    ] using properties.ledgerTxIdsAreStableAcrossCopies
  · simpa [ClientEntryHasRequest, statusCommittedResponseNext] using
      properties.clientEntryHasRequest
  · simpa [
      UniqueTxRequests,
      State.requestEvent,
      statusCommittedResponseNext
    ] using properties.uniqueTxRequests

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem statusInvalidResponsePreservesProvenance
    {state : State Tx View Seqno Event}
    {response status : Event}
    (properties : ProvenanceBundle state)
    (responseIsRw : state.rwResponseEvent response)
    (statusAllowed : state.invalidStatusAllowed response)
    (nextEvent : state.nextHistoryEvent status) :
    ProvenanceBundle (statusInvalidResponseNext state response status) := by
  refine
    { toCoreBundle :=
        statusInvalidResponsePreservesCore
          properties.toCoreBundle
          responseIsRw
          statusAllowed
          nextEvent
      ledgerTxIdsAreStableAcrossCopies := ?_
      clientEntryHasRequest := ?_
      uniqueTxRequests := ?_ }
  · simpa [
      LedgerTxIdsAreStableAcrossCopies,
      statusInvalidResponseNext
    ] using properties.ledgerTxIdsAreStableAcrossCopies
  · simpa [ClientEntryHasRequest, statusInvalidResponseNext] using
      properties.clientEntryHasRequest
  · simpa [
      UniqueTxRequests,
      State.requestEvent,
      statusInvalidResponseNext
    ] using properties.uniqueTxRequests

omit [OrderBot Seqno] [OrderBot Event] in
theorem truncateLedgerPreservesProvenance
    {state : State Tx View Seqno Event}
    {source newView : View}
    {cut : Seqno}
    (properties : ProvenanceBundle state)
    (sourceIsActive : state.activeView source)
    (cutExists : state.ledgerEntry source cut)
    (sourceIsValid : state.validTruncationSource source cut)
    (viewIsNext : state.nextView newView) :
    ProvenanceBundle (truncateLedgerNext state source cut newView) := by
  -- Every client entry of the truncated state is a slot-preserving copy of a
  -- client entry of the old state, with the same transaction and origin view.
  have resolveCopy :
      forall candidateBranch candidateSlot,
        (truncateLedgerNext state source cut newView).clientEntry
            candidateBranch candidateSlot ->
          Exists fun originalBranch =>
            state.clientEntry originalBranch candidateSlot /\
              state.entryTx originalBranch candidateSlot =
                (truncateLedgerNext state source cut newView).entryTx
                  candidateBranch candidateSlot /\
              state.entryView originalBranch candidateSlot =
                (truncateLedgerNext state source cut newView).entryView
                  candidateBranch candidateSlot := by
    intro candidateBranch candidateSlot isClient
    by_cases branchEq : candidateBranch = newView
    · subst candidateBranch
      have copiedClient :
          candidateSlot <= cut /\ state.clientEntry source candidateSlot := by
        simpa [truncateLedgerNext, updateUnary] using isClient
      refine ⟨source, copiedClient.2, ?_, ?_⟩
      · simp [
          truncateLedgerNext,
          updateUnary,
          copiedClient.1,
          copiedClient.2
        ]
      · simp [truncateLedgerNext, updateUnary, copiedClient.1]
    · refine ⟨candidateBranch, ?_, ?_, ?_⟩
      · simpa [truncateLedgerNext, updateUnary, branchEq] using isClient
      · simp [truncateLedgerNext, updateUnary, branchEq]
      · simp [truncateLedgerNext, updateUnary, branchEq]
  refine
    { toCoreBundle :=
        truncateLedgerPreservesCore
          properties.toCoreBundle
          sourceIsActive
          cutExists
          sourceIsValid
          viewIsNext
      ledgerTxIdsAreStableAcrossCopies := ?_
      clientEntryHasRequest := ?_
      uniqueTxRequests := ?_ }
  · rw [LedgerTxIdsAreStableAcrossCopies]
    intro leftBranch leftSlot rightBranch rightSlot entries
    rcases entries with ⟨leftIsClient, rightIsClient, sameTx⟩
    rcases resolveCopy leftBranch leftSlot leftIsClient with
      ⟨leftOriginal, leftOldClient, leftOldTx, leftOldView⟩
    rcases resolveCopy rightBranch rightSlot rightIsClient with
      ⟨rightOriginal, rightOldClient, rightOldTx, rightOldView⟩
    have oldSameTx :
        state.entryTx leftOriginal leftSlot =
          state.entryTx rightOriginal rightSlot := by
      rw [leftOldTx, rightOldTx]
      exact sameTx
    have oldResult :=
      properties.ledgerTxIdsAreStableAcrossCopies
        leftOriginal leftSlot rightOriginal rightSlot
        ⟨leftOldClient, rightOldClient, oldSameTx⟩
    refine ⟨oldResult.1, ?_⟩
    rw [<- leftOldView, <- rightOldView]
    exact oldResult.2
  · rw [ClientEntryHasRequest]
    intro candidateBranch candidateSlot isClient
    rcases resolveCopy candidateBranch candidateSlot isClient with
      ⟨originalBranch, oldClient, oldTx, _⟩
    rcases
        properties.clientEntryHasRequest
          originalBranch candidateSlot oldClient with
      ⟨oldRequest, oldRequestIsRw, oldRequestTx⟩
    refine ⟨oldRequest, by simpa [truncateLedgerNext] using oldRequestIsRw, ?_⟩
    rw [<- oldTx]
    simpa [truncateLedgerNext] using oldRequestTx
  · simpa [UniqueTxRequests, State.requestEvent, truncateLedgerNext] using
      properties.uniqueTxRequests

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem truncateLedgerToEmptyPreservesProvenance
    {state : State Tx View Seqno Event}
    {source newView : View}
    (properties : ProvenanceBundle state)
    (sourceIsActive : state.activeView source)
    (noCommitted : state.noCommittedTxId)
    (viewIsNext : state.nextView newView) :
    ProvenanceBundle (truncateLedgerToEmptyNext state newView) := by
  refine
    { toCoreBundle :=
        truncateLedgerToEmptyPreservesCore
          properties.toCoreBundle
          sourceIsActive
          noCommitted
          viewIsNext
      ledgerTxIdsAreStableAcrossCopies := ?_
      clientEntryHasRequest := ?_
      uniqueTxRequests := ?_ }
  · simpa [
      LedgerTxIdsAreStableAcrossCopies,
      truncateLedgerToEmptyNext
    ] using properties.ledgerTxIdsAreStableAcrossCopies
  · simpa [ClientEntryHasRequest, truncateLedgerToEmptyNext] using
      properties.clientEntryHasRequest
  · simpa [
      UniqueTxRequests,
      State.requestEvent,
      truncateLedgerToEmptyNext
    ] using properties.uniqueTxRequests

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

omit [OrderBot Seqno] [OrderBot Event] in
theorem stepPreservesProvenance
    {state next : State Tx View Seqno Event}
    (properties : ProvenanceBundle state)
    (transition : Step state next) :
    ProvenanceBundle next := by
  cases transition with
  | rwTxRequest tx event nextTx nextEvent =>
      exact rwTxRequestPreservesProvenance properties nextTx nextEvent
  | roTxRequest tx event nextTx nextEvent =>
      exact roTxRequestPreservesProvenance properties nextTx nextEvent
  | rwTxExecute
      request
      branch
      slot
      requestIsRw
      txNotInLedger
      branchIsActive
      nextSlot =>
      exact
        rwTxExecutePreservesProvenance
          properties
          requestIsRw
          txNotInLedger
          branchIsActive
          nextSlot
  | appendOtherTxn branch slot branchIsActive nextSlot =>
      exact
        appendOtherTxnPreservesProvenance
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
        rwTxResponsePreservesProvenance
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
        roTxResponsePreservesProvenance
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
        statusCommittedResponsePreservesProvenance
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
        statusInvalidResponsePreservesProvenance
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
        truncateLedgerPreservesProvenance
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
        truncateLedgerToEmptyPreservesProvenance
          properties
          sourceIsActive
          noCommitted
          viewIsNext

theorem reachableProvenance
    {state : State Tx View Seqno Event}
    (reachable : Reachable state) :
    ProvenanceBundle state := by
  induction reachable with
  | initial => exact initialProvenance
  | step _ transition properties =>
      exact stepPreservesProvenance properties transition

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
/-- An existing response cannot reach the slot that `nextLedgerSlot` is about
to fill: its own frontier is a ledger entry, and the ledger is a prefix. -/
theorem responseCannotReachNextSlot
    {state : State Tx View Seqno Event}
    {branch : View}
    {slot : Seqno}
    {response : Event}
    (properties : StructuralBundle state)
    (nextSlot : state.nextLedgerSlot branch slot)
    (responseIsResponse : state.responseEvent response)
    (branchEq : state.eventBranch response = branch)
    (slotLe : slot <= state.eventSeqno response) :
    False := by
  have frontier :=
    properties.responseFrontierIsLedgerEntry response responseIsResponse
  rw [branchEq] at frontier
  by_cases slotEq : slot = state.eventSeqno response
  · refine nextSlot.1 ?_
    rw [slotEq]
    exact frontier
  · exact nextSlot.1
      (properties.ledgerIsPrefix
        branch
        (state.eventSeqno response)
        slot
        ⟨frontier, ⟨slotLe, slotEq⟩⟩)

theorem initialResponses :
    ResponseBundle (initialState : State Tx View Seqno Event) where
  toProvenanceBundle := initialProvenance
  onlyObserveSentRequests := initialProperties.onlyObserveSentRequests
  uniqueResponseTxs := by
    simp [UniqueResponseTxs, State.responseEvent, initialState]

omit
  [OrderBot Tx] [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxRequestPreservesResponses
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : ResponseBundle state)
    (nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    ResponseBundle (rwTxRequestNext state tx event) := by
  have classifiedNe :
      forall candidate,
        state.historyEvent candidate -> Not (candidate = event) :=
    fun candidate candidateHasKind =>
      classifiedEventNeNext properties.historyTypeOk nextEvent candidateHasKind
  have responseNeEvent :
      forall candidate,
        state.responseEvent candidate -> Not (candidate = event) := by
    intro candidate candidateIsResponse
    refine classifiedNe candidate ?_
    rcases candidateIsResponse with candidateIsRw | candidateIsRo
    · exact Or.inr (Or.inl candidateIsRw)
    · exact Or.inr (Or.inr (Or.inr (Or.inl candidateIsRo)))
  refine
    { toProvenanceBundle :=
        rwTxRequestPreservesProvenance
          properties.toProvenanceBundle nextTx nextEvent
      onlyObserveSentRequests := ?_
      uniqueResponseTxs := ?_ }
  · rw [OnlyObserveSentRequests]
    intro response slot observed observations
    rcases observations with ⟨responseIsResponse, observation⟩
    have oldResponse : state.responseEvent response := by
      simpa [State.responseEvent, rwTxRequestNext] using responseIsResponse
    have oldObservation : state.observedAt response slot observed := by
      simpa [
        State.observedAt,
        State.responseEvent,
        rwTxRequestNext
      ] using observation
    rcases
        properties.onlyObserveSentRequests response slot observed
          ⟨oldResponse, oldObservation⟩ with
      ⟨oldRequest, oldRequestIsRw, oldRequestTx, oldRequestLt⟩
    have oldRequestNe := classifiedNe oldRequest (Or.inl oldRequestIsRw)
    exact
      ⟨oldRequest, by simpa [rwTxRequestNext, oldRequestNe] using oldRequestIsRw,
        by simpa [rwTxRequestNext, oldRequestNe] using oldRequestTx,
        oldRequestLt⟩
  · rw [UniqueResponseTxs]
    intro left right responses
    rcases responses with ⟨leftIsResponse, rightIsResponse, sameTx⟩
    have leftOld : state.responseEvent left := by
      simpa [State.responseEvent, rwTxRequestNext] using leftIsResponse
    have rightOld : state.responseEvent right := by
      simpa [State.responseEvent, rwTxRequestNext] using rightIsResponse
    have leftNe := responseNeEvent left leftOld
    have rightNe := responseNeEvent right rightOld
    have oldSameTx : state.eventTx left = state.eventTx right := by
      simpa [rwTxRequestNext, leftNe, rightNe] using sameTx
    exact properties.uniqueResponseTxs left right
      ⟨leftOld, rightOld, oldSameTx⟩

omit
  [OrderBot Tx] [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem roTxRequestPreservesResponses
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : ResponseBundle state)
    (nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    ResponseBundle (roTxRequestNext state tx event) := by
  have classifiedNe :
      forall candidate,
        state.historyEvent candidate -> Not (candidate = event) :=
    fun candidate candidateHasKind =>
      classifiedEventNeNext properties.historyTypeOk nextEvent candidateHasKind
  have responseNeEvent :
      forall candidate,
        state.responseEvent candidate -> Not (candidate = event) := by
    intro candidate candidateIsResponse
    refine classifiedNe candidate ?_
    rcases candidateIsResponse with candidateIsRw | candidateIsRo
    · exact Or.inr (Or.inl candidateIsRw)
    · exact Or.inr (Or.inr (Or.inr (Or.inl candidateIsRo)))
  refine
    { toProvenanceBundle :=
        roTxRequestPreservesProvenance
          properties.toProvenanceBundle nextTx nextEvent
      onlyObserveSentRequests := ?_
      uniqueResponseTxs := ?_ }
  · rw [OnlyObserveSentRequests]
    intro response slot observed observations
    rcases observations with ⟨responseIsResponse, observation⟩
    have oldResponse : state.responseEvent response := by
      simpa [State.responseEvent, roTxRequestNext] using responseIsResponse
    have oldObservation : state.observedAt response slot observed := by
      simpa [
        State.observedAt,
        State.responseEvent,
        roTxRequestNext
      ] using observation
    rcases
        properties.onlyObserveSentRequests response slot observed
          ⟨oldResponse, oldObservation⟩ with
      ⟨oldRequest, oldRequestIsRw, oldRequestTx, oldRequestLt⟩
    have oldRequestNe := classifiedNe oldRequest (Or.inl oldRequestIsRw)
    exact
      ⟨oldRequest, by simpa [roTxRequestNext, oldRequestNe] using oldRequestIsRw,
        by simpa [roTxRequestNext, oldRequestNe] using oldRequestTx,
        oldRequestLt⟩
  · rw [UniqueResponseTxs]
    intro left right responses
    rcases responses with ⟨leftIsResponse, rightIsResponse, sameTx⟩
    have leftOld : state.responseEvent left := by
      simpa [State.responseEvent, roTxRequestNext] using leftIsResponse
    have rightOld : state.responseEvent right := by
      simpa [State.responseEvent, roTxRequestNext] using rightIsResponse
    have leftNe := responseNeEvent left leftOld
    have rightNe := responseNeEvent right rightOld
    have oldSameTx : state.eventTx left = state.eventTx right := by
      simpa [roTxRequestNext, leftNe, rightNe] using sameTx
    exact properties.uniqueResponseTxs left right
      ⟨leftOld, rightOld, oldSameTx⟩

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxExecutePreservesResponses
    {state : State Tx View Seqno Event}
    {request : Event}
    {branch : View}
    {slot : Seqno}
    (properties : ResponseBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (txNotInLedger : Not (state.txInLedger (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    ResponseBundle (rwTxExecuteNext state request branch slot) := by
  refine
    { toProvenanceBundle :=
        rwTxExecutePreservesProvenance
          properties.toProvenanceBundle
          requestIsRw
          txNotInLedger
          branchIsActive
          nextSlot
      onlyObserveSentRequests := ?_
      uniqueResponseTxs := ?_ }
  · rw [OnlyObserveSentRequests]
    intro response candidateSlot observed observations
    rcases observations with ⟨responseIsResponse, observation⟩
    have oldResponse : state.responseEvent response := by
      simpa [State.responseEvent, rwTxExecuteNext] using responseIsResponse
    have slotLe : candidateSlot <= state.eventSeqno response := by
      simpa [rwTxExecuteNext] using observation.2.1
    -- The freshly written point cannot be inside an existing response prefix.
    have offPoint :
        Not (state.eventBranch response = branch) \/
          Not (candidateSlot = slot) := by
      by_cases branchEq : state.eventBranch response = branch
      · refine Or.inr ?_
        intro slotEq
        subst candidateSlot
        exact
          responseCannotReachNextSlot
            properties.toStructuralBundle
            nextSlot
            oldResponse
            branchEq
            slotLe
      · exact Or.inl branchEq
    have oldObservation :
        state.observedAt response candidateSlot observed := by
      refine ⟨oldResponse, slotLe, ?_, ?_⟩
      · rcases offPoint with branchNe | slotNe
        · simpa [rwTxExecuteNext, branchNe] using observation.2.2.1
        · simpa [rwTxExecuteNext, slotNe] using observation.2.2.1
      · rcases offPoint with branchNe | slotNe
        · simpa [rwTxExecuteNext, branchNe] using observation.2.2.2
        · simpa [rwTxExecuteNext, slotNe] using observation.2.2.2
    rcases
        properties.onlyObserveSentRequests response candidateSlot observed
          ⟨oldResponse, oldObservation⟩ with
      ⟨oldRequest, oldRequestIsRw, oldRequestTx, oldRequestLt⟩
    exact
      ⟨oldRequest, by simpa [rwTxExecuteNext] using oldRequestIsRw,
        by simpa [rwTxExecuteNext] using oldRequestTx,
        oldRequestLt⟩
  · simpa [
      UniqueResponseTxs,
      State.responseEvent,
      rwTxExecuteNext
    ] using properties.uniqueResponseTxs

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem appendOtherTxnPreservesResponses
    {state : State Tx View Seqno Event}
    {branch : View}
    {slot : Seqno}
    (properties : ResponseBundle state)
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    ResponseBundle (appendOtherTxnNext state branch slot) := by
  refine
    { toProvenanceBundle :=
        appendOtherTxnPreservesProvenance
          properties.toProvenanceBundle
          branchIsActive
          nextSlot
      onlyObserveSentRequests := ?_
      uniqueResponseTxs := ?_ }
  · rw [OnlyObserveSentRequests]
    intro response candidateSlot observed observations
    rcases observations with ⟨responseIsResponse, observation⟩
    have oldResponse : state.responseEvent response := by
      simpa [State.responseEvent, appendOtherTxnNext] using responseIsResponse
    have slotLe : candidateSlot <= state.eventSeqno response := by
      simpa [appendOtherTxnNext] using observation.2.1
    have offPoint :
        Not (state.eventBranch response = branch) \/
          Not (candidateSlot = slot) := by
      by_cases branchEq : state.eventBranch response = branch
      · refine Or.inr ?_
        intro slotEq
        subst candidateSlot
        exact
          responseCannotReachNextSlot
            properties.toStructuralBundle
            nextSlot
            oldResponse
            branchEq
            slotLe
      · exact Or.inl branchEq
    have oldObservation :
        state.observedAt response candidateSlot observed := by
      refine ⟨oldResponse, slotLe, ?_, ?_⟩
      · rcases offPoint with branchNe | slotNe
        · simpa [appendOtherTxnNext, branchNe] using observation.2.2.1
        · simpa [appendOtherTxnNext, slotNe] using observation.2.2.1
      · simpa [appendOtherTxnNext] using observation.2.2.2
    rcases
        properties.onlyObserveSentRequests response candidateSlot observed
          ⟨oldResponse, oldObservation⟩ with
      ⟨oldRequest, oldRequestIsRw, oldRequestTx, oldRequestLt⟩
    exact
      ⟨oldRequest, by simpa [appendOtherTxnNext] using oldRequestIsRw,
        by simpa [appendOtherTxnNext] using oldRequestTx,
        oldRequestLt⟩
  · simpa [
      UniqueResponseTxs,
      State.responseEvent,
      appendOtherTxnNext
    ] using properties.uniqueResponseTxs

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem rwTxResponsePreservesResponses
    {state : State Tx View Seqno Event}
    {request response : Event}
    {branch : View}
    {slot : Seqno}
    (properties : ResponseBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (notResponded : Not (state.responded (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (entryIsClient : state.clientEntry branch slot)
    (entryMatches : state.entryTx branch slot = state.eventTx request)
    (nextEvent : state.nextHistoryEvent response) :
    ResponseBundle (rwTxResponseNext state request branch slot response) := by
  have classifiedNe :
      forall candidate,
        state.historyEvent candidate -> Not (candidate = response) :=
    fun candidate candidateHasKind =>
      classifiedEventNeNext properties.historyTypeOk nextEvent candidateHasKind
  have responseNeNew :
      forall candidate,
        state.responseEvent candidate -> Not (candidate = response) := by
    intro candidate candidateIsResponse
    refine classifiedNe candidate ?_
    rcases candidateIsResponse with candidateIsRw | candidateIsRo
    · exact Or.inr (Or.inl candidateIsRw)
    · exact Or.inr (Or.inr (Or.inr (Or.inl candidateIsRo)))
  refine
    { toProvenanceBundle :=
        rwTxResponsePreservesProvenance
          properties.toProvenanceBundle
          requestIsRw
          notResponded
          branchIsActive
          entryIsClient
          entryMatches
          nextEvent
      onlyObserveSentRequests := ?_
      uniqueResponseTxs := ?_ }
  · rw [OnlyObserveSentRequests]
    intro candidate candidateSlot observed observations
    rcases observations with ⟨candidateIsResponse, observation⟩
    by_cases candidateEq : candidate = response
    · subst candidate
      -- The new response reads the origin view of its own frontier entry.
      have newClient :
          state.clientEntry (state.entryView branch slot) candidateSlot := by
        simpa [rwTxResponseNext] using observation.2.2.1
      have newTx :
          state.entryTx (state.entryView branch slot) candidateSlot =
            observed := by
        simpa [rwTxResponseNext] using observation.2.2.2
      rcases
          properties.clientEntryHasRequest
            (state.entryView branch slot) candidateSlot newClient with
        ⟨oldRequest, oldRequestIsRw, oldRequestTx⟩
      have oldRequestUsed : state.eventUsed oldRequest :=
        (properties.historyTypeOk oldRequest).2 (Or.inl oldRequestIsRw)
      have oldRequestLt :=
        usedEventLtNext properties.historyIsPrefix oldRequestUsed nextEvent
      exact
        ⟨oldRequest, by simpa [rwTxResponseNext] using oldRequestIsRw,
          by
            simpa [rwTxResponseNext, oldRequestLt.2] using
              oldRequestTx.trans newTx,
          oldRequestLt⟩
    · have oldResponse : state.responseEvent candidate := by
        simpa [
          State.responseEvent,
          rwTxResponseNext,
          candidateEq
        ] using candidateIsResponse
      have oldObservation :
          state.observedAt candidate candidateSlot observed := by
        simpa [
          State.observedAt,
          State.responseEvent,
          rwTxResponseNext,
          candidateEq
        ] using observation
      rcases
          properties.onlyObserveSentRequests candidate candidateSlot observed
            ⟨oldResponse, oldObservation⟩ with
        ⟨oldRequest, oldRequestIsRw, oldRequestTx, oldRequestLt⟩
      have oldRequestNe := classifiedNe oldRequest (Or.inl oldRequestIsRw)
      exact
        ⟨oldRequest, by simpa [rwTxResponseNext] using oldRequestIsRw,
          by simpa [rwTxResponseNext, oldRequestNe] using oldRequestTx,
          oldRequestLt⟩
  · rw [UniqueResponseTxs]
    intro left right responses
    rcases responses with ⟨leftIsResponse, rightIsResponse, sameTx⟩
    by_cases leftEq : left = response
    · subst left
      by_cases rightEq : right = response
      · exact rightEq.symm
      · have rightOld : state.responseEvent right := by
          simpa [
            State.responseEvent,
            rwTxResponseNext,
            rightEq
          ] using rightIsResponse
        have rightNe := responseNeNew right rightOld
        have rightTx :
            state.eventTx right = state.eventTx request := by
          simpa [rwTxResponseNext, rightNe] using sameTx.symm
        exact False.elim (notResponded ⟨right, rightOld, rightTx⟩)
    · have leftOld : state.responseEvent left := by
        simpa [
          State.responseEvent,
          rwTxResponseNext,
          leftEq
        ] using leftIsResponse
      have leftNe := responseNeNew left leftOld
      by_cases rightEq : right = response
      · subst right
        have leftTx :
            state.eventTx left = state.eventTx request := by
          simpa [rwTxResponseNext, leftNe] using sameTx
        exact False.elim (notResponded ⟨left, leftOld, leftTx⟩)
      · have rightOld : state.responseEvent right := by
          simpa [
            State.responseEvent,
            rwTxResponseNext,
            rightEq
          ] using rightIsResponse
        have rightNe := responseNeNew right rightOld
        have oldSameTx : state.eventTx left = state.eventTx right := by
          simpa [rwTxResponseNext, leftNe, rightNe] using sameTx
        exact properties.uniqueResponseTxs left right
          ⟨leftOld, rightOld, oldSameTx⟩

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem roTxResponsePreservesResponses
    {state : State Tx View Seqno Event}
    {request response : Event}
    {branch : View}
    {last : Seqno}
    (properties : ResponseBundle state)
    (requestIsRo : state.roRequestEvent request)
    (notResponded : Not (state.responded (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (lastSlot : state.lastLedgerSlot branch last)
    (nextEvent : state.nextHistoryEvent response) :
    ResponseBundle (roTxResponseNext state request branch last response) := by
  have classifiedNe :
      forall candidate,
        state.historyEvent candidate -> Not (candidate = response) :=
    fun candidate candidateHasKind =>
      classifiedEventNeNext properties.historyTypeOk nextEvent candidateHasKind
  have responseNeNew :
      forall candidate,
        state.responseEvent candidate -> Not (candidate = response) := by
    intro candidate candidateIsResponse
    refine classifiedNe candidate ?_
    rcases candidateIsResponse with candidateIsRw | candidateIsRo
    · exact Or.inr (Or.inl candidateIsRw)
    · exact Or.inr (Or.inr (Or.inr (Or.inl candidateIsRo)))
  refine
    { toProvenanceBundle :=
        roTxResponsePreservesProvenance
          properties.toProvenanceBundle
          requestIsRo
          notResponded
          branchIsActive
          lastSlot
          nextEvent
      onlyObserveSentRequests := ?_
      uniqueResponseTxs := ?_ }
  · rw [OnlyObserveSentRequests]
    intro candidate candidateSlot observed observations
    rcases observations with ⟨candidateIsResponse, observation⟩
    by_cases candidateEq : candidate = response
    · subst candidate
      have newClient :
          state.clientEntry (state.entryView branch last) candidateSlot := by
        simpa [roTxResponseNext] using observation.2.2.1
      have newTx :
          state.entryTx (state.entryView branch last) candidateSlot =
            observed := by
        simpa [roTxResponseNext] using observation.2.2.2
      rcases
          properties.clientEntryHasRequest
            (state.entryView branch last) candidateSlot newClient with
        ⟨oldRequest, oldRequestIsRw, oldRequestTx⟩
      have oldRequestUsed : state.eventUsed oldRequest :=
        (properties.historyTypeOk oldRequest).2 (Or.inl oldRequestIsRw)
      have oldRequestLt :=
        usedEventLtNext properties.historyIsPrefix oldRequestUsed nextEvent
      exact
        ⟨oldRequest, by simpa [roTxResponseNext] using oldRequestIsRw,
          by
            simpa [roTxResponseNext, oldRequestLt.2] using
              oldRequestTx.trans newTx,
          oldRequestLt⟩
    · have oldResponse : state.responseEvent candidate := by
        simpa [
          State.responseEvent,
          roTxResponseNext,
          candidateEq
        ] using candidateIsResponse
      have oldObservation :
          state.observedAt candidate candidateSlot observed := by
        simpa [
          State.observedAt,
          State.responseEvent,
          roTxResponseNext,
          candidateEq
        ] using observation
      rcases
          properties.onlyObserveSentRequests candidate candidateSlot observed
            ⟨oldResponse, oldObservation⟩ with
        ⟨oldRequest, oldRequestIsRw, oldRequestTx, oldRequestLt⟩
      have oldRequestNe := classifiedNe oldRequest (Or.inl oldRequestIsRw)
      exact
        ⟨oldRequest, by simpa [roTxResponseNext] using oldRequestIsRw,
          by simpa [roTxResponseNext, oldRequestNe] using oldRequestTx,
          oldRequestLt⟩
  · rw [UniqueResponseTxs]
    intro left right responses
    rcases responses with ⟨leftIsResponse, rightIsResponse, sameTx⟩
    by_cases leftEq : left = response
    · subst left
      by_cases rightEq : right = response
      · exact rightEq.symm
      · have rightOld : state.responseEvent right := by
          simpa [
            State.responseEvent,
            roTxResponseNext,
            rightEq
          ] using rightIsResponse
        have rightNe := responseNeNew right rightOld
        have rightTx :
            state.eventTx right = state.eventTx request := by
          simpa [roTxResponseNext, rightNe] using sameTx.symm
        exact False.elim (notResponded ⟨right, rightOld, rightTx⟩)
    · have leftOld : state.responseEvent left := by
        simpa [
          State.responseEvent,
          roTxResponseNext,
          leftEq
        ] using leftIsResponse
      have leftNe := responseNeNew left leftOld
      by_cases rightEq : right = response
      · subst right
        have leftTx :
            state.eventTx left = state.eventTx request := by
          simpa [roTxResponseNext, leftNe] using sameTx
        exact False.elim (notResponded ⟨left, leftOld, leftTx⟩)
      · have rightOld : state.responseEvent right := by
          simpa [
            State.responseEvent,
            roTxResponseNext,
            rightEq
          ] using rightIsResponse
        have rightNe := responseNeNew right rightOld
        have oldSameTx : state.eventTx left = state.eventTx right := by
          simpa [roTxResponseNext, leftNe, rightNe] using sameTx
        exact properties.uniqueResponseTxs left right
          ⟨leftOld, rightOld, oldSameTx⟩

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem statusCommittedResponsePreservesResponses
    {state : State Tx View Seqno Event}
    {response status : Event}
    {current : View}
    (properties : ResponseBundle state)
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
    ResponseBundle (statusCommittedResponseNext state response status) := by
  have responseNeStatus :
      forall candidate,
        state.responseEvent candidate -> Not (candidate = status) := by
    intro candidate candidateIsResponse
    refine classifiedEventNeNext properties.historyTypeOk nextEvent ?_
    rcases candidateIsResponse with candidateIsRw | candidateIsRo
    · exact Or.inr (Or.inl candidateIsRw)
    · exact Or.inr (Or.inr (Or.inr (Or.inl candidateIsRo)))
  refine
    { toProvenanceBundle :=
        statusCommittedResponsePreservesProvenance
          properties.toProvenanceBundle
          responseIsRw
          viewIsCurrent
          responseSlotExists
          responseEntryMatches
          notInvalid
          nextEvent
      onlyObserveSentRequests := ?_
      uniqueResponseTxs := ?_ }
  · rw [OnlyObserveSentRequests]
    intro candidate candidateSlot observed observations
    rcases observations with ⟨candidateIsResponse, observation⟩
    have oldResponse : state.responseEvent candidate := by
      simpa [
        State.responseEvent,
        statusCommittedResponseNext
      ] using candidateIsResponse
    have candidateNe := responseNeStatus candidate oldResponse
    have oldObservation :
        state.observedAt candidate candidateSlot observed := by
      simpa [
        State.observedAt,
        State.responseEvent,
        statusCommittedResponseNext,
        candidateNe
      ] using observation
    rcases
        properties.onlyObserveSentRequests candidate candidateSlot observed
          ⟨oldResponse, oldObservation⟩ with
      ⟨oldRequest, oldRequestIsRw, oldRequestTx, oldRequestLt⟩
    exact
      ⟨oldRequest,
        by simpa [statusCommittedResponseNext] using oldRequestIsRw,
        by simpa [statusCommittedResponseNext] using oldRequestTx,
        oldRequestLt⟩
  · simpa [
      UniqueResponseTxs,
      State.responseEvent,
      statusCommittedResponseNext
    ] using properties.uniqueResponseTxs

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem statusInvalidResponsePreservesResponses
    {state : State Tx View Seqno Event}
    {response status : Event}
    (properties : ResponseBundle state)
    (responseIsRw : state.rwResponseEvent response)
    (statusAllowed : state.invalidStatusAllowed response)
    (nextEvent : state.nextHistoryEvent status) :
    ResponseBundle (statusInvalidResponseNext state response status) := by
  have responseNeStatus :
      forall candidate,
        state.responseEvent candidate -> Not (candidate = status) := by
    intro candidate candidateIsResponse
    refine classifiedEventNeNext properties.historyTypeOk nextEvent ?_
    rcases candidateIsResponse with candidateIsRw | candidateIsRo
    · exact Or.inr (Or.inl candidateIsRw)
    · exact Or.inr (Or.inr (Or.inr (Or.inl candidateIsRo)))
  refine
    { toProvenanceBundle :=
        statusInvalidResponsePreservesProvenance
          properties.toProvenanceBundle
          responseIsRw
          statusAllowed
          nextEvent
      onlyObserveSentRequests := ?_
      uniqueResponseTxs := ?_ }
  · rw [OnlyObserveSentRequests]
    intro candidate candidateSlot observed observations
    rcases observations with ⟨candidateIsResponse, observation⟩
    have oldResponse : state.responseEvent candidate := by
      simpa [
        State.responseEvent,
        statusInvalidResponseNext
      ] using candidateIsResponse
    have candidateNe := responseNeStatus candidate oldResponse
    have oldObservation :
        state.observedAt candidate candidateSlot observed := by
      simpa [
        State.observedAt,
        State.responseEvent,
        statusInvalidResponseNext,
        candidateNe
      ] using observation
    rcases
        properties.onlyObserveSentRequests candidate candidateSlot observed
          ⟨oldResponse, oldObservation⟩ with
      ⟨oldRequest, oldRequestIsRw, oldRequestTx, oldRequestLt⟩
    exact
      ⟨oldRequest,
        by simpa [statusInvalidResponseNext] using oldRequestIsRw,
        by simpa [statusInvalidResponseNext] using oldRequestTx,
        oldRequestLt⟩
  · simpa [
      UniqueResponseTxs,
      State.responseEvent,
      statusInvalidResponseNext
    ] using properties.uniqueResponseTxs

omit [OrderBot Seqno] [OrderBot Event] in
theorem truncateLedgerPreservesResponses
    {state : State Tx View Seqno Event}
    {source newView : View}
    {cut : Seqno}
    (properties : ResponseBundle state)
    (sourceIsActive : state.activeView source)
    (cutExists : state.ledgerEntry source cut)
    (sourceIsValid : state.validTruncationSource source cut)
    (viewIsNext : state.nextView newView) :
    ResponseBundle (truncateLedgerNext state source cut newView) := by
  -- Existing responses read an active branch, and the fresh view is not active.
  have responseBranchNeNew :
      forall candidate,
        state.responseEvent candidate ->
          Not (state.eventBranch candidate = newView) := by
    intro candidate candidateIsResponse branchEq
    have frontier :=
      properties.responseFrontierIsLedgerEntry candidate candidateIsResponse
    rw [branchEq] at frontier
    exact viewIsNext.1
      (properties.ledgerTypeOk newView (state.eventSeqno candidate) frontier).1
  refine
    { toProvenanceBundle :=
        truncateLedgerPreservesProvenance
          properties.toProvenanceBundle
          sourceIsActive
          cutExists
          sourceIsValid
          viewIsNext
      onlyObserveSentRequests := ?_
      uniqueResponseTxs := ?_ }
  · rw [OnlyObserveSentRequests]
    intro candidate candidateSlot observed observations
    rcases observations with ⟨candidateIsResponse, observation⟩
    have oldResponse : state.responseEvent candidate := by
      simpa [State.responseEvent, truncateLedgerNext] using candidateIsResponse
    have branchNe := responseBranchNeNew candidate oldResponse
    have oldObservation :
        state.observedAt candidate candidateSlot observed := by
      simpa [
        State.observedAt,
        State.responseEvent,
        truncateLedgerNext,
        updateUnary,
        branchNe
      ] using observation
    rcases
        properties.onlyObserveSentRequests candidate candidateSlot observed
          ⟨oldResponse, oldObservation⟩ with
      ⟨oldRequest, oldRequestIsRw, oldRequestTx, oldRequestLt⟩
    exact
      ⟨oldRequest, by simpa [truncateLedgerNext] using oldRequestIsRw,
        by simpa [truncateLedgerNext] using oldRequestTx,
        oldRequestLt⟩
  · simpa [
      UniqueResponseTxs,
      State.responseEvent,
      truncateLedgerNext
    ] using properties.uniqueResponseTxs

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem truncateLedgerToEmptyPreservesResponses
    {state : State Tx View Seqno Event}
    {source newView : View}
    (properties : ResponseBundle state)
    (sourceIsActive : state.activeView source)
    (noCommitted : state.noCommittedTxId)
    (viewIsNext : state.nextView newView) :
    ResponseBundle (truncateLedgerToEmptyNext state newView) := by
  refine
    { toProvenanceBundle :=
        truncateLedgerToEmptyPreservesProvenance
          properties.toProvenanceBundle
          sourceIsActive
          noCommitted
          viewIsNext
      onlyObserveSentRequests := ?_
      uniqueResponseTxs := ?_ }
  · simpa [
      OnlyObserveSentRequests,
      State.observedAt,
      State.responseEvent,
      truncateLedgerToEmptyNext
    ] using properties.onlyObserveSentRequests
  · simpa [
      UniqueResponseTxs,
      State.responseEvent,
      truncateLedgerToEmptyNext
    ] using properties.uniqueResponseTxs

omit [OrderBot Seqno] [OrderBot Event] in
theorem stepPreservesResponses
    {state next : State Tx View Seqno Event}
    (properties : ResponseBundle state)
    (transition : Step state next) :
    ResponseBundle next := by
  cases transition with
  | rwTxRequest tx event nextTx nextEvent =>
      exact rwTxRequestPreservesResponses properties nextTx nextEvent
  | roTxRequest tx event nextTx nextEvent =>
      exact roTxRequestPreservesResponses properties nextTx nextEvent
  | rwTxExecute
      request
      branch
      slot
      requestIsRw
      txNotInLedger
      branchIsActive
      nextSlot =>
      exact
        rwTxExecutePreservesResponses
          properties
          requestIsRw
          txNotInLedger
          branchIsActive
          nextSlot
  | appendOtherTxn branch slot branchIsActive nextSlot =>
      exact
        appendOtherTxnPreservesResponses
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
        rwTxResponsePreservesResponses
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
        roTxResponsePreservesResponses
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
        statusCommittedResponsePreservesResponses
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
        statusInvalidResponsePreservesResponses
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
        truncateLedgerPreservesResponses
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
        truncateLedgerToEmptyPreservesResponses
          properties
          sourceIsActive
          noCommitted
          viewIsNext

theorem reachableResponses
    {state : State Tx View Seqno Event}
    (reachable : Reachable state) :
    ResponseBundle state := by
  induction reachable with
  | initial => exact initialResponses
  | step _ transition properties =>
      exact stepPreservesResponses properties transition

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
/-- At most one response per transaction, so two responses carrying the same
transaction are the same event and trivially share a transaction id. -/
theorem responsesUniqueTxIds
    {state : State Tx View Seqno Event}
    (properties : ResponseBundle state) :
    UniqueTxIds state := by
  rw [UniqueTxIds]
  intro left right responses
  have sameEvent := properties.uniqueResponseTxs left right responses
  subst sameEvent
  exact ⟨rfl, rfl⟩

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View]
  [LinearOrder Seqno] [OrderBot Seqno]
  [LinearOrder Event] [OrderBot Event] in
/-- Transfer of `HasCurrentView` along any action that leaves `activeView`
alone. Only the two truncation actions need a genuine argument. -/
theorem hasCurrentViewOfActiveEq
    {state next : State Tx View Seqno Event}
    (activeEq : forall view, next.activeView view = state.activeView view)
    (hasCurrent : HasCurrentView state) :
    HasCurrentView next := by
  rcases hasCurrent with ⟨current, currentActive, currentMax⟩
  refine ⟨current, ?_, ?_⟩
  · rw [activeEq]
    exact currentActive
  · intro later laterGt
    rw [activeEq]
    exact currentMax later laterGt

omit [LinearOrder Event] [OrderBot Event] in
theorem initialHasCurrentView :
    HasCurrentView (initialState : State Tx View Seqno Event) := by
  refine ⟨Bot.bot, ?_, ?_⟩
  · simp [initialState]
  · intro later laterGt activeLater
    have laterEq : later = Bot.bot := by simpa [initialState] using activeLater
    exact laterGt.2 laterEq.symm

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- After a view change the fresh view is the greatest active one, because the
active views form a prefix and the fresh view was not active before. -/
theorem nextViewIsCurrent
    {state : State Tx View Seqno Event}
    {newView : View}
    {next : State Tx View Seqno Event}
    (properties : StructuralBundle state)
    (viewIsNext : state.nextView newView)
    (activeNew : next.activeView newView)
    (activeOther :
      forall view,
        Not (view = newView) -> next.activeView view = state.activeView view) :
    next.currentView newView := by
  refine ⟨activeNew, ?_⟩
  intro later laterGt activeLater
  have laterNe : Not (later = newView) := fun laterEq => laterGt.2 laterEq.symm
  rw [activeOther later laterNe] at activeLater
  exact viewIsNext.1
    (properties.activeViewsArePrefix later newView ⟨activeLater, laterGt⟩)

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View]
  [LinearOrder Seqno] [OrderBot Seqno]
  [LinearOrder Event] [OrderBot Event] in
/-- The current view is unique: two greatest active views coincide. -/
theorem currentViewUnique
    {state : State Tx View Seqno Event}
    {left right : View}
    (leftIsCurrent : state.currentView left)
    (rightIsCurrent : state.currentView right) :
    left = right := by
  by_contra leftNe
  rcases lt_or_gt_of_ne leftNe with leftLt | rightLt
  · exact leftIsCurrent.2 right ⟨le_of_lt leftLt, leftNe⟩ rightIsCurrent.1
  · exact rightIsCurrent.2 left
      ⟨le_of_lt rightLt, fun rightEq => leftNe rightEq.symm⟩
      leftIsCurrent.1

omit [LinearOrder Tx] [OrderBot Tx]
  [LinearOrder View] [OrderBot View] [OrderBot Seqno]
  [LinearOrder Event] [OrderBot Event] in
/-- The ledger is a prefix, stated with a non-strict bound. -/
theorem ledgerEntryOfLe
    {state : State Tx View Seqno Event}
    {branch : View}
    {earlier later : Seqno}
    (ledgerIsPrefix : LedgerIsPrefix state)
    (frontier : state.ledgerEntry branch later)
    (earlierLe : earlier <= later) :
    state.ledgerEntry branch earlier := by
  by_cases earlierEq : earlier = later
  · rw [earlierEq]
    exact frontier
  · exact ledgerIsPrefix branch later earlier ⟨frontier, ⟨earlierLe, earlierEq⟩⟩

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- Transfer a committed transaction identifier back across any action that
only classifies a fresh history event. -/
theorem committedTxIdOfFreshEvent
    {state next : State Tx View Seqno Event}
    {fresh : Event}
    {view : View}
    {seqno : Seqno}
    (properties : StructuralBundle state)
    (nextEvent : state.nextHistoryEvent fresh)
    (committed : next.committedTxId view seqno)
    (committedEq :
      forall candidate,
        next.committedStatusEvent candidate =
          state.committedStatusEvent candidate)
    (viewEq :
      forall candidate,
        Not (candidate = fresh) ->
          next.eventView candidate = state.eventView candidate)
    (seqnoEq :
      forall candidate,
        Not (candidate = fresh) ->
          next.eventSeqno candidate = state.eventSeqno candidate) :
    state.committedTxId view seqno := by
  rcases committed with ⟨candidate, candidateCommitted, candidateView, candidateSeqno⟩
  rw [committedEq] at candidateCommitted
  have candidateNe : Not (candidate = fresh) :=
    classifiedEventNeNext properties.historyTypeOk nextEvent
      (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl candidateCommitted)))))
  rw [viewEq candidate candidateNe] at candidateView
  rw [seqnoEq candidate candidateNe] at candidateSeqno
  exact ⟨candidate, candidateCommitted, candidateView, candidateSeqno⟩

theorem initialStatuses :
    StatusBundle (initialState : State Tx View Seqno Event) where
  toResponseBundle := initialResponses
  statusHasRwResponse := initialProperties.statusHasRwResponse
  hasCurrentView := initialHasCurrentView

omit
  [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxRequestPreservesStatuses
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : StatusBundle state)
    (nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    StatusBundle (rwTxRequestNext state tx event) := by
  refine
    { toResponseBundle :=
        rwTxRequestPreservesResponses
          properties.toResponseBundle nextTx nextEvent
      statusHasRwResponse := ?_
      hasCurrentView := ?_ }
  · simpa [
      StatusHasRwResponse,
      State.statusEvent,
      rwTxRequestNext
    ] using properties.statusHasRwResponse
  · exact hasCurrentViewOfActiveEq (fun _ => rfl) properties.hasCurrentView

omit
  [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem roTxRequestPreservesStatuses
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : StatusBundle state)
    (nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    StatusBundle (roTxRequestNext state tx event) := by
  refine
    { toResponseBundle :=
        roTxRequestPreservesResponses
          properties.toResponseBundle nextTx nextEvent
      statusHasRwResponse := ?_
      hasCurrentView := ?_ }
  · simpa [
      StatusHasRwResponse,
      State.statusEvent,
      roTxRequestNext
    ] using properties.statusHasRwResponse
  · exact hasCurrentViewOfActiveEq (fun _ => rfl) properties.hasCurrentView

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxExecutePreservesStatuses
    {state : State Tx View Seqno Event}
    {request : Event}
    {branch : View}
    {slot : Seqno}
    (properties : StatusBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (txNotInLedger : Not (state.txInLedger (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    StatusBundle (rwTxExecuteNext state request branch slot) := by
  refine
    { toResponseBundle :=
        rwTxExecutePreservesResponses
          properties.toResponseBundle
          requestIsRw
          txNotInLedger
          branchIsActive
          nextSlot
      statusHasRwResponse := ?_
      hasCurrentView := ?_ }
  · simpa [
      StatusHasRwResponse,
      State.statusEvent,
      rwTxExecuteNext
    ] using properties.statusHasRwResponse
  · exact hasCurrentViewOfActiveEq (fun _ => rfl) properties.hasCurrentView

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem appendOtherTxnPreservesStatuses
    {state : State Tx View Seqno Event}
    {branch : View}
    {slot : Seqno}
    (properties : StatusBundle state)
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    StatusBundle (appendOtherTxnNext state branch slot) := by
  refine
    { toResponseBundle :=
        appendOtherTxnPreservesResponses
          properties.toResponseBundle
          branchIsActive
          nextSlot
      statusHasRwResponse := ?_
      hasCurrentView := ?_ }
  · simpa [
      StatusHasRwResponse,
      State.statusEvent,
      appendOtherTxnNext
    ] using properties.statusHasRwResponse
  · exact hasCurrentViewOfActiveEq (fun _ => rfl) properties.hasCurrentView

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem rwTxResponsePreservesStatuses
    {state : State Tx View Seqno Event}
    {request response : Event}
    {branch : View}
    {slot : Seqno}
    (properties : StatusBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (notResponded : Not (state.responded (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (entryIsClient : state.clientEntry branch slot)
    (entryMatches : state.entryTx branch slot = state.eventTx request)
    (nextEvent : state.nextHistoryEvent response) :
    StatusBundle (rwTxResponseNext state request branch slot response) := by
  refine
    { toResponseBundle :=
        rwTxResponsePreservesResponses
          properties.toResponseBundle
          requestIsRw
          notResponded
          branchIsActive
          entryIsClient
          entryMatches
          nextEvent
      statusHasRwResponse := ?_
      hasCurrentView := ?_ }
  · rw [StatusHasRwResponse]
    intro status statusIsStatus
    have oldStatus : state.statusEvent status := by
      simpa [State.statusEvent, rwTxResponseNext] using statusIsStatus
    have statusNe : Not (status = response) := by
      refine classifiedEventNeNext properties.historyTypeOk nextEvent ?_
      rcases oldStatus with statusIsCommitted | statusIsInvalid
      · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl statusIsCommitted))))
      · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr statusIsInvalid))))
    rcases properties.statusHasRwResponse status oldStatus with
      ⟨oldResponse, oldResponseIsRw, oldResponseLt, oldView, oldSeqno⟩
    have oldResponseNe : Not (oldResponse = response) :=
      classifiedEventNeNext properties.historyTypeOk nextEvent
        (Or.inr (Or.inl oldResponseIsRw))
    exact
      ⟨oldResponse,
        by simpa [rwTxResponseNext, oldResponseNe] using oldResponseIsRw,
        oldResponseLt,
        by simpa [rwTxResponseNext, oldResponseNe, statusNe] using oldView,
        by simpa [rwTxResponseNext, oldResponseNe, statusNe] using oldSeqno⟩
  · exact hasCurrentViewOfActiveEq (fun _ => rfl) properties.hasCurrentView

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem roTxResponsePreservesStatuses
    {state : State Tx View Seqno Event}
    {request response : Event}
    {branch : View}
    {last : Seqno}
    (properties : StatusBundle state)
    (requestIsRo : state.roRequestEvent request)
    (notResponded : Not (state.responded (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (lastSlot : state.lastLedgerSlot branch last)
    (nextEvent : state.nextHistoryEvent response) :
    StatusBundle (roTxResponseNext state request branch last response) := by
  refine
    { toResponseBundle :=
        roTxResponsePreservesResponses
          properties.toResponseBundle
          requestIsRo
          notResponded
          branchIsActive
          lastSlot
          nextEvent
      statusHasRwResponse := ?_
      hasCurrentView := ?_ }
  · rw [StatusHasRwResponse]
    intro status statusIsStatus
    have oldStatus : state.statusEvent status := by
      simpa [State.statusEvent, roTxResponseNext] using statusIsStatus
    have statusNe : Not (status = response) := by
      refine classifiedEventNeNext properties.historyTypeOk nextEvent ?_
      rcases oldStatus with statusIsCommitted | statusIsInvalid
      · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl statusIsCommitted))))
      · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr statusIsInvalid))))
    rcases properties.statusHasRwResponse status oldStatus with
      ⟨oldResponse, oldResponseIsRw, oldResponseLt, oldView, oldSeqno⟩
    have oldResponseNe : Not (oldResponse = response) :=
      classifiedEventNeNext properties.historyTypeOk nextEvent
        (Or.inr (Or.inl oldResponseIsRw))
    exact
      ⟨oldResponse,
        by simpa [roTxResponseNext, oldResponseNe] using oldResponseIsRw,
        oldResponseLt,
        by simpa [roTxResponseNext, oldResponseNe, statusNe] using oldView,
        by simpa [roTxResponseNext, oldResponseNe, statusNe] using oldSeqno⟩
  · exact hasCurrentViewOfActiveEq (fun _ => rfl) properties.hasCurrentView

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem statusCommittedResponsePreservesStatuses
    {state : State Tx View Seqno Event}
    {response status : Event}
    {current : View}
    (properties : StatusBundle state)
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
    StatusBundle (statusCommittedResponseNext state response status) := by
  have responseUsed : state.eventUsed response :=
    (properties.historyTypeOk response).2 (Or.inr (Or.inl responseIsRw))
  have responseLtStatus :=
    usedEventLtNext properties.historyIsPrefix responseUsed nextEvent
  refine
    { toResponseBundle :=
        statusCommittedResponsePreservesResponses
          properties.toResponseBundle
          responseIsRw
          viewIsCurrent
          responseSlotExists
          responseEntryMatches
          notInvalid
          nextEvent
      statusHasRwResponse := ?_
      hasCurrentView := ?_ }
  · rw [StatusHasRwResponse]
    intro candidate candidateIsStatus
    by_cases candidateEq : candidate = status
    · subst candidate
      exact
        ⟨response,
          by simpa [statusCommittedResponseNext] using responseIsRw,
          responseLtStatus,
          by simp [statusCommittedResponseNext, responseLtStatus.2],
          by simp [statusCommittedResponseNext, responseLtStatus.2]⟩
    · have oldStatus : state.statusEvent candidate := by
        simpa [
          State.statusEvent,
          statusCommittedResponseNext,
          candidateEq
        ] using candidateIsStatus
      rcases properties.statusHasRwResponse candidate oldStatus with
        ⟨oldResponse, oldResponseIsRw, oldResponseLt, oldView, oldSeqno⟩
      have oldResponseNe : Not (oldResponse = status) :=
        classifiedEventNeNext properties.historyTypeOk nextEvent
          (Or.inr (Or.inl oldResponseIsRw))
      exact
        ⟨oldResponse,
          by simpa [statusCommittedResponseNext] using oldResponseIsRw,
          oldResponseLt,
          by
            simpa [
              statusCommittedResponseNext,
              oldResponseNe,
              candidateEq
            ] using oldView,
          by
            simpa [
              statusCommittedResponseNext,
              oldResponseNe,
              candidateEq
            ] using oldSeqno⟩
  · exact hasCurrentViewOfActiveEq (fun _ => rfl) properties.hasCurrentView

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem statusInvalidResponsePreservesStatuses
    {state : State Tx View Seqno Event}
    {response status : Event}
    (properties : StatusBundle state)
    (responseIsRw : state.rwResponseEvent response)
    (statusAllowed : state.invalidStatusAllowed response)
    (nextEvent : state.nextHistoryEvent status) :
    StatusBundle (statusInvalidResponseNext state response status) := by
  have responseUsed : state.eventUsed response :=
    (properties.historyTypeOk response).2 (Or.inr (Or.inl responseIsRw))
  have responseLtStatus :=
    usedEventLtNext properties.historyIsPrefix responseUsed nextEvent
  refine
    { toResponseBundle :=
        statusInvalidResponsePreservesResponses
          properties.toResponseBundle
          responseIsRw
          statusAllowed
          nextEvent
      statusHasRwResponse := ?_
      hasCurrentView := ?_ }
  · rw [StatusHasRwResponse]
    intro candidate candidateIsStatus
    by_cases candidateEq : candidate = status
    · subst candidate
      exact
        ⟨response,
          by simpa [statusInvalidResponseNext] using responseIsRw,
          responseLtStatus,
          by simp [statusInvalidResponseNext, responseLtStatus.2],
          by simp [statusInvalidResponseNext, responseLtStatus.2]⟩
    · have oldStatus : state.statusEvent candidate := by
        simpa [
          State.statusEvent,
          statusInvalidResponseNext,
          candidateEq
        ] using candidateIsStatus
      rcases properties.statusHasRwResponse candidate oldStatus with
        ⟨oldResponse, oldResponseIsRw, oldResponseLt, oldView, oldSeqno⟩
      have oldResponseNe : Not (oldResponse = status) :=
        classifiedEventNeNext properties.historyTypeOk nextEvent
          (Or.inr (Or.inl oldResponseIsRw))
      exact
        ⟨oldResponse,
          by simpa [statusInvalidResponseNext] using oldResponseIsRw,
          oldResponseLt,
          by
            simpa [
              statusInvalidResponseNext,
              oldResponseNe,
              candidateEq
            ] using oldView,
          by
            simpa [
              statusInvalidResponseNext,
              oldResponseNe,
              candidateEq
            ] using oldSeqno⟩
  · exact hasCurrentViewOfActiveEq (fun _ => rfl) properties.hasCurrentView

omit [OrderBot Seqno] [OrderBot Event] in
theorem truncateLedgerPreservesStatuses
    {state : State Tx View Seqno Event}
    {source newView : View}
    {cut : Seqno}
    (properties : StatusBundle state)
    (sourceIsActive : state.activeView source)
    (cutExists : state.ledgerEntry source cut)
    (sourceIsValid : state.validTruncationSource source cut)
    (viewIsNext : state.nextView newView) :
    StatusBundle (truncateLedgerNext state source cut newView) := by
  refine
    { toResponseBundle :=
        truncateLedgerPreservesResponses
          properties.toResponseBundle
          sourceIsActive
          cutExists
          sourceIsValid
          viewIsNext
      statusHasRwResponse := ?_
      hasCurrentView := ?_ }
  · simpa [
      StatusHasRwResponse,
      State.statusEvent,
      truncateLedgerNext
    ] using properties.statusHasRwResponse
  · refine
      ⟨newView,
        nextViewIsCurrent
          properties.toStructuralBundle
          viewIsNext
          (by simp [truncateLedgerNext, updateUnary])
          ?_⟩
    intro view viewNe
    simp [truncateLedgerNext, updateUnary, viewNe]

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem truncateLedgerToEmptyPreservesStatuses
    {state : State Tx View Seqno Event}
    {source newView : View}
    (properties : StatusBundle state)
    (sourceIsActive : state.activeView source)
    (noCommitted : state.noCommittedTxId)
    (viewIsNext : state.nextView newView) :
    StatusBundle (truncateLedgerToEmptyNext state newView) := by
  refine
    { toResponseBundle :=
        truncateLedgerToEmptyPreservesResponses
          properties.toResponseBundle
          sourceIsActive
          noCommitted
          viewIsNext
      statusHasRwResponse := ?_
      hasCurrentView := ?_ }
  · simpa [
      StatusHasRwResponse,
      State.statusEvent,
      truncateLedgerToEmptyNext
    ] using properties.statusHasRwResponse
  · refine
      ⟨newView,
        nextViewIsCurrent
          properties.toStructuralBundle
          viewIsNext
          (by simp [truncateLedgerToEmptyNext, updateUnary])
          ?_⟩
    intro view viewNe
    simp [truncateLedgerToEmptyNext, updateUnary, viewNe]

omit [OrderBot Seqno] [OrderBot Event] in
theorem stepPreservesStatuses
    {state next : State Tx View Seqno Event}
    (properties : StatusBundle state)
    (transition : Step state next) :
    StatusBundle next := by
  cases transition with
  | rwTxRequest tx event nextTx nextEvent =>
      exact rwTxRequestPreservesStatuses properties nextTx nextEvent
  | roTxRequest tx event nextTx nextEvent =>
      exact roTxRequestPreservesStatuses properties nextTx nextEvent
  | rwTxExecute
      request
      branch
      slot
      requestIsRw
      txNotInLedger
      branchIsActive
      nextSlot =>
      exact
        rwTxExecutePreservesStatuses
          properties
          requestIsRw
          txNotInLedger
          branchIsActive
          nextSlot
  | appendOtherTxn branch slot branchIsActive nextSlot =>
      exact appendOtherTxnPreservesStatuses properties branchIsActive nextSlot
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
        rwTxResponsePreservesStatuses
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
        roTxResponsePreservesStatuses
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
        statusCommittedResponsePreservesStatuses
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
        statusInvalidResponsePreservesStatuses
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
        truncateLedgerPreservesStatuses
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
        truncateLedgerToEmptyPreservesStatuses
          properties
          sourceIsActive
          noCommitted
          viewIsNext

theorem reachableStatuses
    {state : State Tx View Seqno Event}
    (reachable : Reachable state) :
    StatusBundle state := by
  induction reachable with
  | initial => exact initialStatuses
  | step _ transition properties =>
      exact stepPreservesStatuses properties transition

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

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
/-- Two observations of the same transaction by one response sit in the same
branch, so stable copied transaction identifiers force the same slot. -/
theorem provenanceAtMostOnceObserved
    {state : State Tx View Seqno Event}
    (properties : ProvenanceBundle state) :
    AtMostOnceObserved state := by
  rw [AtMostOnceObserved]
  intro response leftSlot rightSlot observed observations
  rcases observations with ⟨leftObservation, rightObservation⟩
  have leftClient :
      state.clientEntry (state.eventBranch response) leftSlot :=
    leftObservation.2.2.1
  have rightClient :
      state.clientEntry (state.eventBranch response) rightSlot :=
    rightObservation.2.2.1
  have sameTx :
      state.entryTx (state.eventBranch response) leftSlot =
        state.entryTx (state.eventBranch response) rightSlot :=
    leftObservation.2.2.2.trans rightObservation.2.2.2.symm
  exact
    (properties.ledgerTxIdsAreStableAcrossCopies
      (state.eventBranch response) leftSlot
      (state.eventBranch response) rightSlot
      ⟨leftClient, rightClient, sameTx⟩).1

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- Transfer an invalid transaction identifier back across any action that only
classifies a fresh history event. -/
theorem invalidTxIdOfFreshEvent
    {state next : State Tx View Seqno Event}
    {fresh : Event}
    {view : View}
    {seqno : Seqno}
    (properties : StructuralBundle state)
    (nextEvent : state.nextHistoryEvent fresh)
    (invalid : next.invalidTxId view seqno)
    (invalidEq :
      forall candidate,
        next.invalidStatusEvent candidate =
          state.invalidStatusEvent candidate)
    (viewEq :
      forall candidate,
        Not (candidate = fresh) ->
          next.eventView candidate = state.eventView candidate)
    (seqnoEq :
      forall candidate,
        Not (candidate = fresh) ->
          next.eventSeqno candidate = state.eventSeqno candidate) :
    state.invalidTxId view seqno := by
  rcases invalid with ⟨candidate, candidateInvalid, candidateView, candidateSeqno⟩
  rw [invalidEq] at candidateInvalid
  have candidateNe : Not (candidate = fresh) :=
    classifiedEventNeNext properties.historyTypeOk nextEvent
      (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr candidateInvalid)))))
  rw [viewEq candidate candidateNe] at candidateView
  rw [seqnoEq candidate candidateNe] at candidateSeqno
  exact ⟨candidate, candidateInvalid, candidateView, candidateSeqno⟩

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- A status event is already classified, so it differs from a fresh event. -/
theorem statusEventNeFresh
    {state : State Tx View Seqno Event}
    {candidate fresh : Event}
    (properties : StructuralBundle state)
    (nextEvent : state.nextHistoryEvent fresh)
    (candidateIsStatus : state.statusEvent candidate) :
    Not (candidate = fresh) := by
  refine classifiedEventNeNext properties.historyTypeOk nextEvent ?_
  rcases candidateIsStatus with candidateCommitted | candidateInvalid
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl candidateCommitted))))
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr candidateInvalid))))

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- A response's own frontier entry carries the response's view as its origin
view. -/
theorem responseOriginViewEq
    {state : State Tx View Seqno Event}
    {response : Event}
    (properties : StructuralBundle state)
    (responseIsResponse : state.responseEvent response) :
    state.entryView (state.eventView response) (state.eventSeqno response) =
      state.eventView response := by
  have branchEq := properties.responseBranchIsView response responseIsResponse
  have originEq :=
    properties.responseFrontierMatchesOrigin response responseIsResponse
  rw [branchEq] at originEq
  exact originEq

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- Origin views increase along a branch, stated through two known entry
views. -/
theorem entryViewMonotoneAt
    {state : State Tx View Seqno Event}
    {current : View}
    {leftSeq rightSeq : Seqno}
    {leftValue rightValue : View}
    (properties : CoreBundle state)
    (leftEntryView : state.entryView current leftSeq = leftValue)
    (rightEntry : state.ledgerEntry current rightSeq)
    (rightEntryView : state.entryView current rightSeq = rightValue)
    (seqLe : leftSeq <= rightSeq) :
    leftValue <= rightValue := by
  have monotone :=
    properties.ledgerEntryViewsAreMonotonic
      current leftSeq rightSeq ⟨rightEntry, seqLe⟩
  rw [leftEntryView, rightEntryView] at monotone
  exact monotone

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- The guard of `statusInvalidResponse` rules out a commit at the response's
view for its own sequence number and every later one. This is the single fact
behind the commit and invalid closure clauses. -/
theorem noCommitAtOrAboveInvalidResponse
    {state : State Tx View Seqno Event}
    {response : Event}
    {seqno : Seqno}
    (properties : CommitBundle state)
    (responseIsRw : state.rwResponseEvent response)
    (statusAllowed : state.invalidStatusAllowed response)
    (seqnoGe : state.eventSeqno response <= seqno) :
    Not (state.committedTxId (state.eventView response) seqno) := by
  intro committed
  rcases statusAllowed with ⟨current, currentIsCurrent, disjuncts⟩
  rcases disjuncts with divergentEntry | staleView | belowCommit
  · -- The current ledger disagrees with the response at its own slot.
    rcases divergentEntry with
      ⟨_commitSeq, _maxCommitted, _seqLe, _currentEntry, viewNe⟩
    have inCurrent :=
      properties.committedIdIsInCurrentLedger
        (state.eventView response) seqno current ⟨committed, currentIsCurrent⟩
    have prefixDown :=
      properties.ledgerPrefixMatchesFrontierOrigin
        current seqno (state.eventSeqno response) ⟨inCurrent.1, seqnoGe⟩
    rw [inCurrent.2] at prefixDown
    refine viewNe ?_
    rw [prefixDown.2.2.1]
    exact
      responseOriginViewEq
        properties.toStructuralBundle (Or.inl responseIsRw)
  · -- Everything committed is at or below a slot strictly below the response.
    rcases staleView with
      ⟨commitSeq, maxCommitted, commitLtResponse, _currentEntry, _viewLt⟩
    have seqnoLeCommit : seqno <= commitSeq :=
      maxCommitted.2 (state.eventView response) seqno committed
    have commitLtSeqno : commitSeq < seqno :=
      lt_of_lt_of_le
        (lt_of_le_of_ne commitLtResponse.1 commitLtResponse.2)
        seqnoGe
    exact absurd seqnoLeCommit (not_le_of_gt commitLtSeqno)
  · -- Everything committed is strictly below the response.
    rcases belowCommit with ⟨_viewEq, allBelow⟩
    have seqnoLtResponse :=
      allBelow (state.eventView response) seqno committed
    exact seqnoLtResponse.2 (le_antisymm seqnoLtResponse.1 seqnoGe)

theorem initialCommits :
    CommitBundle (initialState : State Tx View Seqno Event) where
  toStatusBundle := initialStatuses
  committedIdIsInCurrentLedger := initialProperties.committedIdIsInCurrentLedger

omit
  [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxRequestPreservesCommits
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : CommitBundle state)
    (nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    CommitBundle (rwTxRequestNext state tx event) := by
  refine
    { toStatusBundle :=
        rwTxRequestPreservesStatuses
          properties.toStatusBundle nextTx nextEvent
      committedIdIsInCurrentLedger := ?_ }
  simpa [
    CommittedIdIsInCurrentLedger,
    State.committedTxId,
    State.currentView,
    rwTxRequestNext
  ] using properties.committedIdIsInCurrentLedger

omit
  [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem roTxRequestPreservesCommits
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : CommitBundle state)
    (nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    CommitBundle (roTxRequestNext state tx event) := by
  refine
    { toStatusBundle :=
        roTxRequestPreservesStatuses
          properties.toStatusBundle nextTx nextEvent
      committedIdIsInCurrentLedger := ?_ }
  simpa [
    CommittedIdIsInCurrentLedger,
    State.committedTxId,
    State.currentView,
    roTxRequestNext
  ] using properties.committedIdIsInCurrentLedger

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxExecutePreservesCommits
    {state : State Tx View Seqno Event}
    {request : Event}
    {branch : View}
    {slot : Seqno}
    (properties : CommitBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (txNotInLedger : Not (state.txInLedger (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    CommitBundle (rwTxExecuteNext state request branch slot) := by
  refine
    { toStatusBundle :=
        rwTxExecutePreservesStatuses
          properties.toStatusBundle
          requestIsRw
          txNotInLedger
          branchIsActive
          nextSlot
      committedIdIsInCurrentLedger := ?_ }
  rw [CommittedIdIsInCurrentLedger]
  intro committedView committedSeq current committedAndCurrent
  rcases committedAndCurrent with ⟨committed, currentIsCurrent⟩
  have oldCommitted : state.committedTxId committedView committedSeq := by
    simpa [State.committedTxId, rwTxExecuteNext] using committed
  have oldCurrent : state.currentView current := by
    simpa [State.currentView, rwTxExecuteNext] using currentIsCurrent
  have oldResult :=
    properties.committedIdIsInCurrentLedger
      committedView committedSeq current ⟨oldCommitted, oldCurrent⟩
  -- The committed entry already exists, so it is not the slot being written.
  have offPoint :
      Not (current = branch) \/ Not (committedSeq = slot) := by
    by_cases branchEq : current = branch
    · refine Or.inr ?_
      intro slotEq
      subst current
      subst committedSeq
      exact nextSlot.1 oldResult.1
    · exact Or.inl branchEq
  refine ⟨?_, ?_⟩
  · rcases offPoint with branchNe | slotNe
    · simpa [rwTxExecuteNext, branchNe] using oldResult.1
    · simpa [rwTxExecuteNext, slotNe] using oldResult.1
  · rcases offPoint with branchNe | slotNe
    · simpa [rwTxExecuteNext, branchNe] using oldResult.2
    · simpa [rwTxExecuteNext, slotNe] using oldResult.2

omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem appendOtherTxnPreservesCommits
    {state : State Tx View Seqno Event}
    {branch : View}
    {slot : Seqno}
    (properties : CommitBundle state)
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    CommitBundle (appendOtherTxnNext state branch slot) := by
  refine
    { toStatusBundle :=
        appendOtherTxnPreservesStatuses
          properties.toStatusBundle
          branchIsActive
          nextSlot
      committedIdIsInCurrentLedger := ?_ }
  rw [CommittedIdIsInCurrentLedger]
  intro committedView committedSeq current committedAndCurrent
  rcases committedAndCurrent with ⟨committed, currentIsCurrent⟩
  have oldCommitted : state.committedTxId committedView committedSeq := by
    simpa [State.committedTxId, appendOtherTxnNext] using committed
  have oldCurrent : state.currentView current := by
    simpa [State.currentView, appendOtherTxnNext] using currentIsCurrent
  have oldResult :=
    properties.committedIdIsInCurrentLedger
      committedView committedSeq current ⟨oldCommitted, oldCurrent⟩
  have offPoint :
      Not (current = branch) \/ Not (committedSeq = slot) := by
    by_cases branchEq : current = branch
    · refine Or.inr ?_
      intro slotEq
      subst current
      subst committedSeq
      exact nextSlot.1 oldResult.1
    · exact Or.inl branchEq
  refine ⟨?_, ?_⟩
  · rcases offPoint with branchNe | slotNe
    · simpa [appendOtherTxnNext, branchNe] using oldResult.1
    · simpa [appendOtherTxnNext, slotNe] using oldResult.1
  · rcases offPoint with branchNe | slotNe
    · simpa [appendOtherTxnNext, branchNe] using oldResult.2
    · simpa [appendOtherTxnNext, slotNe] using oldResult.2

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem rwTxResponsePreservesCommits
    {state : State Tx View Seqno Event}
    {request response : Event}
    {branch : View}
    {slot : Seqno}
    (properties : CommitBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (notResponded : Not (state.responded (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (entryIsClient : state.clientEntry branch slot)
    (entryMatches : state.entryTx branch slot = state.eventTx request)
    (nextEvent : state.nextHistoryEvent response) :
    CommitBundle (rwTxResponseNext state request branch slot response) := by
  refine
    { toStatusBundle :=
        rwTxResponsePreservesStatuses
          properties.toStatusBundle
          requestIsRw
          notResponded
          branchIsActive
          entryIsClient
          entryMatches
          nextEvent
      committedIdIsInCurrentLedger := ?_ }
  rw [CommittedIdIsInCurrentLedger]
  intro committedView committedSeq current committedAndCurrent
  rcases committedAndCurrent with ⟨committed, currentIsCurrent⟩
  have oldCommitted :=
    committedTxIdOfFreshEvent
      properties.toStructuralBundle
      nextEvent
      committed
      (fun _ => rfl)
      (fun candidate candidateNe => by
        simp [rwTxResponseNext, candidateNe])
      (fun candidate candidateNe => by
        simp [rwTxResponseNext, candidateNe])
  have oldCurrent : state.currentView current := by
    simpa [State.currentView, rwTxResponseNext] using currentIsCurrent
  simpa [rwTxResponseNext] using
    properties.committedIdIsInCurrentLedger
      committedView committedSeq current ⟨oldCommitted, oldCurrent⟩

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem roTxResponsePreservesCommits
    {state : State Tx View Seqno Event}
    {request response : Event}
    {branch : View}
    {last : Seqno}
    (properties : CommitBundle state)
    (requestIsRo : state.roRequestEvent request)
    (notResponded : Not (state.responded (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (lastSlot : state.lastLedgerSlot branch last)
    (nextEvent : state.nextHistoryEvent response) :
    CommitBundle (roTxResponseNext state request branch last response) := by
  refine
    { toStatusBundle :=
        roTxResponsePreservesStatuses
          properties.toStatusBundle
          requestIsRo
          notResponded
          branchIsActive
          lastSlot
          nextEvent
      committedIdIsInCurrentLedger := ?_ }
  rw [CommittedIdIsInCurrentLedger]
  intro committedView committedSeq current committedAndCurrent
  rcases committedAndCurrent with ⟨committed, currentIsCurrent⟩
  have oldCommitted :=
    committedTxIdOfFreshEvent
      properties.toStructuralBundle
      nextEvent
      committed
      (fun _ => rfl)
      (fun candidate candidateNe => by
        simp [roTxResponseNext, candidateNe])
      (fun candidate candidateNe => by
        simp [roTxResponseNext, candidateNe])
  have oldCurrent : state.currentView current := by
    simpa [State.currentView, roTxResponseNext] using currentIsCurrent
  simpa [roTxResponseNext] using
    properties.committedIdIsInCurrentLedger
      committedView committedSeq current ⟨oldCommitted, oldCurrent⟩

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem statusCommittedResponsePreservesCommits
    {state : State Tx View Seqno Event}
    {response status : Event}
    {current : View}
    (properties : CommitBundle state)
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
    CommitBundle (statusCommittedResponseNext state response status) := by
  refine
    { toStatusBundle :=
        statusCommittedResponsePreservesStatuses
          properties.toStatusBundle
          responseIsRw
          viewIsCurrent
          responseSlotExists
          responseEntryMatches
          notInvalid
          nextEvent
      committedIdIsInCurrentLedger := ?_ }
  rw [CommittedIdIsInCurrentLedger]
  intro committedView committedSeq candidateCurrent committedAndCurrent
  rcases committedAndCurrent with ⟨committed, currentIsCurrent⟩
  have oldCurrent : state.currentView candidateCurrent := by
    simpa [State.currentView, statusCommittedResponseNext] using currentIsCurrent
  have currentEq : candidateCurrent = current :=
    currentViewUnique oldCurrent viewIsCurrent
  subst candidateCurrent
  rcases committed with ⟨witness, witnessCommitted, witnessView, witnessSeqno⟩
  by_cases witnessEq : witness = status
  · -- The new status is the committed identifier, and its guards are exactly
    -- the two facts required.
    subst witness
    have viewEq : state.eventView response = committedView := by
      simpa [statusCommittedResponseNext] using witnessView
    have seqnoEq : state.eventSeqno response = committedSeq := by
      simpa [statusCommittedResponseNext] using witnessSeqno
    subst committedView
    subst committedSeq
    exact
      ⟨by simpa [statusCommittedResponseNext] using responseSlotExists,
        by simpa [statusCommittedResponseNext] using responseEntryMatches⟩
  · have oldCommittedEvent : state.committedStatusEvent witness := by
      simpa [statusCommittedResponseNext, witnessEq] using witnessCommitted
    have oldCommitted : state.committedTxId committedView committedSeq :=
      ⟨witness, oldCommittedEvent,
        by simpa [statusCommittedResponseNext, witnessEq] using witnessView,
        by simpa [statusCommittedResponseNext, witnessEq] using witnessSeqno⟩
    simpa [statusCommittedResponseNext] using
      properties.committedIdIsInCurrentLedger
        committedView committedSeq current ⟨oldCommitted, viewIsCurrent⟩

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem statusInvalidResponsePreservesCommits
    {state : State Tx View Seqno Event}
    {response status : Event}
    (properties : CommitBundle state)
    (responseIsRw : state.rwResponseEvent response)
    (statusAllowed : state.invalidStatusAllowed response)
    (nextEvent : state.nextHistoryEvent status) :
    CommitBundle (statusInvalidResponseNext state response status) := by
  refine
    { toStatusBundle :=
        statusInvalidResponsePreservesStatuses
          properties.toStatusBundle
          responseIsRw
          statusAllowed
          nextEvent
      committedIdIsInCurrentLedger := ?_ }
  rw [CommittedIdIsInCurrentLedger]
  intro committedView committedSeq current committedAndCurrent
  rcases committedAndCurrent with ⟨committed, currentIsCurrent⟩
  have oldCommitted :=
    committedTxIdOfFreshEvent
      properties.toStructuralBundle
      nextEvent
      committed
      (fun _ => rfl)
      (fun candidate candidateNe => by
        simp [statusInvalidResponseNext, candidateNe])
      (fun candidate candidateNe => by
        simp [statusInvalidResponseNext, candidateNe])
  have oldCurrent : state.currentView current := by
    simpa [State.currentView, statusInvalidResponseNext] using currentIsCurrent
  simpa [statusInvalidResponseNext] using
    properties.committedIdIsInCurrentLedger
      committedView committedSeq current ⟨oldCommitted, oldCurrent⟩

omit [OrderBot Seqno] [OrderBot Event] in
theorem truncateLedgerPreservesCommits
    {state : State Tx View Seqno Event}
    {source newView : View}
    {cut : Seqno}
    (properties : CommitBundle state)
    (sourceIsActive : state.activeView source)
    (cutExists : state.ledgerEntry source cut)
    (sourceIsValid : state.validTruncationSource source cut)
    (viewIsNext : state.nextView newView) :
    CommitBundle (truncateLedgerNext state source cut newView) := by
  refine
    { toStatusBundle :=
        truncateLedgerPreservesStatuses
          properties.toStatusBundle
          sourceIsActive
          cutExists
          sourceIsValid
          viewIsNext
      committedIdIsInCurrentLedger := ?_ }
  rw [CommittedIdIsInCurrentLedger]
  intro committedView committedSeq candidateCurrent committedAndCurrent
  rcases committedAndCurrent with ⟨committed, currentIsCurrent⟩
  -- The fresh view is the current view of the truncated state.
  have newIsCurrent :
      (truncateLedgerNext state source cut newView).currentView newView := by
    refine
      nextViewIsCurrent
        properties.toStructuralBundle
        viewIsNext
        (by simp [truncateLedgerNext, updateUnary])
        ?_
    intro view viewNe
    simp [truncateLedgerNext, updateUnary, viewNe]
  have currentEq : candidateCurrent = newView :=
    currentViewUnique currentIsCurrent newIsCurrent
  subst candidateCurrent
  have oldCommitted : state.committedTxId committedView committedSeq := by
    simpa [State.committedTxId, truncateLedgerNext] using committed
  rcases sourceIsValid with noCommitted | validSource
  · exact False.elim (noCommitted committedView committedSeq oldCommitted)
  rcases validSource with
    ⟨commitSeq, maxCommitted, sourceHasCommit, commitInSource, commitLeCut⟩
  rcases properties.hasCurrentView with ⟨oldCurrent, oldCurrentIsCurrent⟩
  have committedSeqLeCommit : committedSeq <= commitSeq :=
    maxCommitted.2 committedView committedSeq oldCommitted
  have committedSeqLeCut : committedSeq <= cut :=
    le_trans committedSeqLeCommit commitLeCut
  have sourceHasCommittedSeq : state.ledgerEntry source committedSeq :=
    ledgerEntryOfLe
      properties.ledgerIsPrefix sourceHasCommit committedSeqLeCommit
  -- The outgoing current view and the truncation source agree on the origin
  -- view of every committed slot, because both agree at the maximum committed
  -- slot and the ledger prefix carries origin views down from there.
  have currentAtCommit :=
    properties.committedIdIsInCurrentLedger
      (state.entryView source commitSeq) commitSeq oldCurrent
      ⟨commitInSource, oldCurrentIsCurrent⟩
  have currentAtCommitted :=
    properties.committedIdIsInCurrentLedger
      committedView committedSeq oldCurrent
      ⟨oldCommitted, oldCurrentIsCurrent⟩
  have sourcePrefix :=
    properties.ledgerPrefixMatchesFrontierOrigin
      source commitSeq committedSeq ⟨sourceHasCommit, committedSeqLeCommit⟩
  have currentPrefix :=
    properties.ledgerPrefixMatchesFrontierOrigin
      oldCurrent commitSeq committedSeq
      ⟨currentAtCommit.1, committedSeqLeCommit⟩
  have sourceViewEq :
      state.entryView source committedSeq = committedView := by
    rw [sourcePrefix.2.2.1, <- currentAtCommit.2, <- currentPrefix.2.2.1]
    exact currentAtCommitted.2
  refine ⟨?_, ?_⟩
  · simp [
      truncateLedgerNext,
      updateUnary,
      committedSeqLeCut,
      sourceHasCommittedSeq
    ]
  · simp [
      truncateLedgerNext,
      updateUnary,
      committedSeqLeCut,
      sourceViewEq
    ]

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem truncateLedgerToEmptyPreservesCommits
    {state : State Tx View Seqno Event}
    {source newView : View}
    (properties : CommitBundle state)
    (sourceIsActive : state.activeView source)
    (noCommitted : state.noCommittedTxId)
    (viewIsNext : state.nextView newView) :
    CommitBundle (truncateLedgerToEmptyNext state newView) := by
  refine
    { toStatusBundle :=
        truncateLedgerToEmptyPreservesStatuses
          properties.toStatusBundle
          sourceIsActive
          noCommitted
          viewIsNext
      committedIdIsInCurrentLedger := ?_ }
  rw [CommittedIdIsInCurrentLedger]
  intro committedView committedSeq current committedAndCurrent
  rcases committedAndCurrent with ⟨committed, _⟩
  have oldCommitted : state.committedTxId committedView committedSeq := by
    simpa [State.committedTxId, truncateLedgerToEmptyNext] using committed
  exact False.elim (noCommitted committedView committedSeq oldCommitted)

omit [OrderBot Seqno] [OrderBot Event] in
theorem stepPreservesCommits
    {state next : State Tx View Seqno Event}
    (properties : CommitBundle state)
    (transition : Step state next) :
    CommitBundle next := by
  cases transition with
  | rwTxRequest tx event nextTx nextEvent =>
      exact rwTxRequestPreservesCommits properties nextTx nextEvent
  | roTxRequest tx event nextTx nextEvent =>
      exact roTxRequestPreservesCommits properties nextTx nextEvent
  | rwTxExecute
      request
      branch
      slot
      requestIsRw
      txNotInLedger
      branchIsActive
      nextSlot =>
      exact
        rwTxExecutePreservesCommits
          properties
          requestIsRw
          txNotInLedger
          branchIsActive
          nextSlot
  | appendOtherTxn branch slot branchIsActive nextSlot =>
      exact appendOtherTxnPreservesCommits properties branchIsActive nextSlot
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
        rwTxResponsePreservesCommits
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
        roTxResponsePreservesCommits
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
        statusCommittedResponsePreservesCommits
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
        statusInvalidResponsePreservesCommits
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
        truncateLedgerPreservesCommits
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
        truncateLedgerToEmptyPreservesCommits
          properties
          sourceIsActive
          noCommitted
          viewIsNext

theorem reachableCommits
    {state : State Tx View Seqno Event}
    (reachable : Reachable state) :
    CommitBundle state := by
  induction reachable with
  | initial => exact initialCommits
  | step _ transition properties =>
      exact stepPreservesCommits properties transition

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- A committed read-write response is present, as a client entry with the same
transaction, in the current view. -/
theorem commitsCommittedResponseMatchesCurrentLedger
    {state : State Tx View Seqno Event}
    (properties : CommitBundle state) :
    CommittedResponseMatchesCurrentLedger state := by
  rw [CommittedResponseMatchesCurrentLedger]
  intro response current committedAndCurrent
  rcases committedAndCurrent with ⟨responseCommitted, currentIsCurrent⟩
  have inCurrent :=
    properties.committedIdIsInCurrentLedger
      (state.eventView response) (state.eventSeqno response) current
      ⟨responseCommitted.2, currentIsCurrent⟩
  have branchIsView :=
    properties.responseBranchIsView response (Or.inl responseCommitted.1)
  have entryMatch :=
    properties.rwResponseMatchesLedgerEntry response responseCommitted.1
  rw [branchIsView] at entryMatch
  have prefixAtResponse :=
    properties.ledgerPrefixMatchesFrontierOrigin
      current (state.eventSeqno response) (state.eventSeqno response)
      ⟨inCurrent.1, le_rfl⟩
  rw [inCurrent.2] at prefixAtResponse
  have currentIsClient :
      state.clientEntry current (state.eventSeqno response) :=
    prefixAtResponse.2.1.2 entryMatch.1
  refine ⟨currentIsClient, inCurrent.2, ?_⟩
  rw [prefixAtResponse.2.2.2 currentIsClient]
  exact entryMatch.2

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- Two committed responses at the same sequence number sit at the same slot of
the current view, hence carry the same transaction. -/
theorem commitsUniqueCommittedSeqnos
    {state : State Tx View Seqno Event}
    (properties : CommitBundle state) :
    UniqueCommittedSeqnos state := by
  rw [UniqueCommittedSeqnos]
  intro left right committedAndSeqno
  rcases committedAndSeqno with ⟨leftCommitted, rightCommitted, sameSeqno⟩
  rcases properties.hasCurrentView with ⟨current, currentIsCurrent⟩
  have leftInCurrent :=
    properties.committedIdIsInCurrentLedger
      (state.eventView left) (state.eventSeqno left) current
      ⟨leftCommitted.2, currentIsCurrent⟩
  have rightInCurrent :=
    properties.committedIdIsInCurrentLedger
      (state.eventView right) (state.eventSeqno right) current
      ⟨rightCommitted.2, currentIsCurrent⟩
  have sameView : state.eventView left = state.eventView right := by
    rw [<- leftInCurrent.2, <- rightInCurrent.2, sameSeqno]
  exact
    coreUniqueRwTxs properties.toCoreBundle left right
      ⟨leftCommitted.1, rightCommitted.1, sameView, sameSeqno⟩

omit [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
/-- All four closure clauses only inspect the status events and their
transaction identifiers, so they transfer across any action that leaves the
status relations alone and rewrites `eventView` and `eventSeqno` only at
unclassified events. -/
theorem closureOfStatusPreserving
    {state next : State Tx View Seqno Event}
    (properties : ClosureBundle state)
    (nextCommits : CommitBundle next)
    (committedEq :
      forall candidate,
        next.committedStatusEvent candidate =
          state.committedStatusEvent candidate)
    (invalidEq :
      forall candidate,
        next.invalidStatusEvent candidate =
          state.invalidStatusEvent candidate)
    (viewEq :
      forall candidate,
        state.statusEvent candidate ->
          next.eventView candidate = state.eventView candidate)
    (seqnoEq :
      forall candidate,
        state.statusEvent candidate ->
          next.eventSeqno candidate = state.eventSeqno candidate) :
    ClosureBundle next := by
  have statusBack :
      forall candidate,
        next.statusEvent candidate -> state.statusEvent candidate := by
    intro candidate candidateIsStatus
    rcases candidateIsStatus with candidateCommitted | candidateInvalid
    · refine Or.inl ?_
      rw [<- committedEq]
      exact candidateCommitted
    · refine Or.inr ?_
      rw [<- invalidEq]
      exact candidateInvalid
  have committedBack :
      forall view seqno,
        next.committedTxId view seqno -> state.committedTxId view seqno := by
    intro view seqno committed
    rcases committed with ⟨witness, witnessCommitted, witnessView, witnessSeqno⟩
    rw [committedEq] at witnessCommitted
    have witnessIsStatus : state.statusEvent witness := Or.inl witnessCommitted
    rw [viewEq witness witnessIsStatus] at witnessView
    rw [seqnoEq witness witnessIsStatus] at witnessSeqno
    exact ⟨witness, witnessCommitted, witnessView, witnessSeqno⟩
  have invalidBack :
      forall view seqno,
        next.invalidTxId view seqno -> state.invalidTxId view seqno := by
    intro view seqno invalid
    rcases invalid with ⟨witness, witnessInvalid, witnessView, witnessSeqno⟩
    rw [invalidEq] at witnessInvalid
    have witnessIsStatus : state.statusEvent witness := Or.inr witnessInvalid
    rw [viewEq witness witnessIsStatus] at witnessView
    rw [seqnoEq witness witnessIsStatus] at witnessSeqno
    exact ⟨witness, witnessInvalid, witnessView, witnessSeqno⟩
  refine
    { toCommitBundle := nextCommits
      committedOrInvalid := ?_
      onceCommittedPreviousIsCommitted := ?_
      onceCommittedOlderViewSuffixIsInvalid := ?_
      onceInvalidSameViewSuffixIsInvalid := ?_ }
  · intro view seqno committed invalid
    exact
      properties.committedOrInvalid view seqno
        (committedBack view seqno committed)
        (invalidBack view seqno invalid)
  · intro committedView committedSeq status hypotheses
    rcases hypotheses with ⟨committed, statusIsStatus, statusView, statusSeqno⟩
    have statusIsStatusOld := statusBack status statusIsStatus
    rw [viewEq status statusIsStatusOld] at statusView
    rw [seqnoEq status statusIsStatusOld] at statusSeqno
    rw [committedEq status]
    exact
      properties.onceCommittedPreviousIsCommitted committedView committedSeq
        status
        ⟨committedBack committedView committedSeq committed,
          statusIsStatusOld, statusView, statusSeqno⟩
  · intro committedView committedSeq status hypotheses
    rcases hypotheses with ⟨committed, statusIsStatus, statusViewLt, seqLe⟩
    have statusIsStatusOld := statusBack status statusIsStatus
    rw [viewEq status statusIsStatusOld] at statusViewLt
    rw [seqnoEq status statusIsStatusOld] at seqLe
    rw [invalidEq status]
    exact
      properties.onceCommittedOlderViewSuffixIsInvalid committedView
        committedSeq status
        ⟨committedBack committedView committedSeq committed,
          statusIsStatusOld, statusViewLt, seqLe⟩
  · intro invalidView invalidSeq status hypotheses
    rcases hypotheses with ⟨invalid, statusIsStatus, statusView, seqLe⟩
    have statusIsStatusOld := statusBack status statusIsStatus
    rw [viewEq status statusIsStatusOld] at statusView
    rw [seqnoEq status statusIsStatusOld] at seqLe
    rw [invalidEq status]
    exact
      properties.onceInvalidSameViewSuffixIsInvalid invalidView invalidSeq
        status
        ⟨invalidBack invalidView invalidSeq invalid, statusIsStatusOld,
          statusView, seqLe⟩

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- The specialisation of `closureOfStatusPreserving` used by every action
whose only event change classifies a fresh history event. -/
theorem closureOfFreshEvent
    {state next : State Tx View Seqno Event}
    {fresh : Event}
    (properties : ClosureBundle state)
    (nextCommits : CommitBundle next)
    (nextEvent : state.nextHistoryEvent fresh)
    (committedEq :
      forall candidate,
        next.committedStatusEvent candidate =
          state.committedStatusEvent candidate)
    (invalidEq :
      forall candidate,
        next.invalidStatusEvent candidate =
          state.invalidStatusEvent candidate)
    (viewEq :
      forall candidate,
        Not (candidate = fresh) ->
          next.eventView candidate = state.eventView candidate)
    (seqnoEq :
      forall candidate,
        Not (candidate = fresh) ->
          next.eventSeqno candidate = state.eventSeqno candidate) :
    ClosureBundle next :=
  closureOfStatusPreserving
    properties
    nextCommits
    committedEq
    invalidEq
    (fun candidate candidateIsStatus =>
      viewEq candidate
        (statusEventNeFresh properties.toStructuralBundle nextEvent
          candidateIsStatus))
    (fun candidate candidateIsStatus =>
      seqnoEq candidate
        (statusEventNeFresh properties.toStructuralBundle nextEvent
          candidateIsStatus))

theorem initialClosure :
    ClosureBundle (initialState : State Tx View Seqno Event) where
  toCommitBundle := initialCommits
  committedOrInvalid := initialProperties.committedOrInvalid
  onceCommittedPreviousIsCommitted :=
    initialProperties.onceCommittedPreviousIsCommitted
  onceCommittedOlderViewSuffixIsInvalid :=
    initialProperties.onceCommittedOlderViewSuffixIsInvalid
  onceInvalidSameViewSuffixIsInvalid :=
    initialProperties.onceInvalidSameViewSuffixIsInvalid

omit
  [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxRequestPreservesClosure
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : ClosureBundle state)
    (nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    ClosureBundle (rwTxRequestNext state tx event) :=
  closureOfStatusPreserving
    properties
    (rwTxRequestPreservesCommits properties.toCommitBundle nextTx nextEvent)
    (fun _ => rfl) (fun _ => rfl) (fun _ _ => rfl) (fun _ _ => rfl)


omit
  [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem roTxRequestPreservesClosure
    {state : State Tx View Seqno Event}
    {tx : Tx}
    {event : Event}
    (properties : ClosureBundle state)
    (nextTx : state.nextTx tx)
    (nextEvent : state.nextHistoryEvent event) :
    ClosureBundle (roTxRequestNext state tx event) :=
  closureOfStatusPreserving
    properties
    (roTxRequestPreservesCommits properties.toCommitBundle nextTx nextEvent)
    (fun _ => rfl) (fun _ => rfl) (fun _ _ => rfl) (fun _ _ => rfl)


omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem rwTxExecutePreservesClosure
    {state : State Tx View Seqno Event}
    {request : Event}
    {branch : View}
    {slot : Seqno}
    (properties : ClosureBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (txNotInLedger : Not (state.txInLedger (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    ClosureBundle (rwTxExecuteNext state request branch slot) :=
  closureOfStatusPreserving
    properties
    (rwTxExecutePreservesCommits
      properties.toCommitBundle
      requestIsRw
      txNotInLedger
      branchIsActive
      nextSlot)
    (fun _ => rfl) (fun _ => rfl) (fun _ _ => rfl) (fun _ _ => rfl)


omit
  [LinearOrder Tx] [OrderBot Tx]
  [OrderBot View] [OrderBot Seqno] [OrderBot Event] in
theorem appendOtherTxnPreservesClosure
    {state : State Tx View Seqno Event}
    {branch : View}
    {slot : Seqno}
    (properties : ClosureBundle state)
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    ClosureBundle (appendOtherTxnNext state branch slot) :=
  closureOfStatusPreserving
    properties
    (appendOtherTxnPreservesCommits
      properties.toCommitBundle branchIsActive nextSlot)
    (fun _ => rfl) (fun _ => rfl) (fun _ _ => rfl) (fun _ _ => rfl)


omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem rwTxResponsePreservesClosure
    {state : State Tx View Seqno Event}
    {request response : Event}
    {branch : View}
    {slot : Seqno}
    (properties : ClosureBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (notResponded : Not (state.responded (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (entryIsClient : state.clientEntry branch slot)
    (entryMatches : state.entryTx branch slot = state.eventTx request)
    (nextEvent : state.nextHistoryEvent response) :
    ClosureBundle (rwTxResponseNext state request branch slot response) :=
  closureOfFreshEvent
    properties
    (rwTxResponsePreservesCommits
      properties.toCommitBundle
      requestIsRw
      notResponded
      branchIsActive
      entryIsClient
      entryMatches
      nextEvent)
    nextEvent
    (fun _ => rfl)
    (fun _ => rfl)
    (fun candidate candidateNe => by simp [rwTxResponseNext, candidateNe])
    (fun candidate candidateNe => by simp [rwTxResponseNext, candidateNe])

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem roTxResponsePreservesClosure
    {state : State Tx View Seqno Event}
    {request response : Event}
    {branch : View}
    {last : Seqno}
    (properties : ClosureBundle state)
    (requestIsRo : state.roRequestEvent request)
    (notResponded : Not (state.responded (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (lastSlot : state.lastLedgerSlot branch last)
    (nextEvent : state.nextHistoryEvent response) :
    ClosureBundle (roTxResponseNext state request branch last response) :=
  closureOfFreshEvent
    properties
    (roTxResponsePreservesCommits
      properties.toCommitBundle
      requestIsRo
      notResponded
      branchIsActive
      lastSlot
      nextEvent)
    nextEvent
    (fun _ => rfl)
    (fun _ => rfl)
    (fun candidate candidateNe => by simp [roTxResponseNext, candidateNe])
    (fun candidate candidateNe => by simp [roTxResponseNext, candidateNe])

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem statusCommittedResponsePreservesClosure
    {state : State Tx View Seqno Event}
    {response status : Event}
    {current : View}
    (properties : ClosureBundle state)
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
    ClosureBundle (statusCommittedResponseNext state response status) := by
  -- Split each new-state fact into an old fact or the freshly created one.
  have statusSplit :
      forall candidate,
        (statusCommittedResponseNext state response status).statusEvent
            candidate ->
          state.statusEvent candidate \/ candidate = status := by
    intro candidate candidateIsStatus
    by_cases candidateEq : candidate = status
    · exact Or.inr candidateEq
    · refine Or.inl ?_
      rcases candidateIsStatus with candidateCommitted | candidateInvalid
      · exact Or.inl
          (by
            simpa [statusCommittedResponseNext, candidateEq] using
              candidateCommitted)
      · exact Or.inr
          (by simpa [statusCommittedResponseNext] using candidateInvalid)
  have committedSplit :
      forall view seqno,
        (statusCommittedResponseNext state response status).committedTxId
            view seqno ->
          state.committedTxId view seqno \/
            (state.eventView response = view /\
              state.eventSeqno response = seqno) := by
    intro view seqno committed
    rcases committed with ⟨witness, witnessCommitted, witnessView, witnessSeqno⟩
    by_cases witnessEq : witness = status
    · subst witness
      exact Or.inr
        ⟨by simpa [statusCommittedResponseNext] using witnessView,
          by simpa [statusCommittedResponseNext] using witnessSeqno⟩
    · exact Or.inl
        ⟨witness,
          by
            simpa [statusCommittedResponseNext, witnessEq] using
              witnessCommitted,
          by simpa [statusCommittedResponseNext, witnessEq] using witnessView,
          by
            simpa [statusCommittedResponseNext, witnessEq] using
              witnessSeqno⟩
  have invalidBack :
      forall view seqno,
        (statusCommittedResponseNext state response status).invalidTxId
            view seqno ->
          state.invalidTxId view seqno := by
    intro view seqno invalid
    exact
      invalidTxIdOfFreshEvent
        properties.toStructuralBundle
        nextEvent
        invalid
        (fun _ => rfl)
        (fun candidate candidateNe => by
          simp [statusCommittedResponseNext, candidateNe])
        (fun candidate candidateNe => by
          simp [statusCommittedResponseNext, candidateNe])
  refine
    { toCommitBundle :=
        statusCommittedResponsePreservesCommits
          properties.toCommitBundle
          responseIsRw
          viewIsCurrent
          responseSlotExists
          responseEntryMatches
          notInvalid
          nextEvent
      committedOrInvalid := ?_
      onceCommittedPreviousIsCommitted := ?_
      onceCommittedOlderViewSuffixIsInvalid := ?_
      onceInvalidSameViewSuffixIsInvalid := ?_ }
  · intro view seqno committed invalid
    have invalidOld := invalidBack view seqno invalid
    rcases committedSplit view seqno committed with oldCommitted | newCommitted
    · exact properties.committedOrInvalid view seqno oldCommitted invalidOld
    · rcases invalidOld with
        ⟨invalidEvent, eventIsInvalid, invalidView, invalidSeqno⟩
      exact
        notInvalid
          ⟨invalidEvent, eventIsInvalid,
            invalidView.trans newCommitted.1.symm,
            le_of_eq (invalidSeqno.trans newCommitted.2.symm)⟩
  · intro committedView committedSeq candidate hypotheses
    rcases hypotheses with
      ⟨committed, candidateIsStatus, candidateView, candidateSeqno⟩
    by_cases candidateEq : candidate = status
    · subst candidate
      simp [statusCommittedResponseNext]
    · have candidateIsStatusOld : state.statusEvent candidate := by
        rcases statusSplit candidate candidateIsStatus with oldStatus | isNew
        · exact oldStatus
        · exact absurd isNew candidateEq
      have candidateViewOld : state.eventView candidate = committedView := by
        simpa [statusCommittedResponseNext, candidateEq] using candidateView
      have candidateSeqnoOld :
          state.eventSeqno candidate <= committedSeq := by
        simpa [statusCommittedResponseNext, candidateEq] using candidateSeqno
      have goalEq :
          (statusCommittedResponseNext state response status).committedStatusEvent
              candidate =
            state.committedStatusEvent candidate := by
        simp [statusCommittedResponseNext, candidateEq]
      rw [goalEq]
      rcases committedSplit committedView committedSeq committed with
        oldCommitted | newCommitted
      · exact
          properties.onceCommittedPreviousIsCommitted
            committedView committedSeq candidate
            ⟨oldCommitted, candidateIsStatusOld, candidateViewOld,
              candidateSeqnoOld⟩
      · -- The new commit protects the candidate through the `notInvalid` guard.
        rcases candidateIsStatusOld with candidateCommitted | candidateInvalid
        · exact candidateCommitted
        · exact absurd
            ⟨candidate, candidateInvalid,
              candidateViewOld.trans newCommitted.1.symm,
              candidateSeqnoOld.trans_eq newCommitted.2.symm⟩
            notInvalid
  · intro committedView committedSeq candidate hypotheses
    rcases hypotheses with
      ⟨committed, candidateIsStatus, candidateViewLt, seqLe⟩
    by_cases candidateEq : candidate = status
    · subst candidate
      exfalso
      have viewEq :
          (statusCommittedResponseNext state response status).eventView status =
            state.eventView response := by
        simp [statusCommittedResponseNext]
      have seqnoEq :
          (statusCommittedResponseNext state response status).eventSeqno status =
            state.eventSeqno response := by
        simp [statusCommittedResponseNext]
      rw [viewEq] at candidateViewLt
      rw [seqnoEq] at seqLe
      rcases committedSplit committedView committedSeq committed with
        oldCommitted | newCommitted
      · have inCurrent :=
          properties.committedIdIsInCurrentLedger
            committedView committedSeq current ⟨oldCommitted, viewIsCurrent⟩
        have monotone :=
          entryViewMonotoneAt
            properties.toCoreBundle
            inCurrent.2
            responseSlotExists
            responseEntryMatches
            seqLe
        exact candidateViewLt.2 (le_antisymm candidateViewLt.1 monotone)
      · exact candidateViewLt.2 newCommitted.1
    · have candidateIsStatusOld : state.statusEvent candidate := by
        rcases statusSplit candidate candidateIsStatus with oldStatus | isNew
        · exact oldStatus
        · exact absurd isNew candidateEq
      have candidateViewLtOld :
          state.viewLt (state.eventView candidate) committedView := by
        simpa [statusCommittedResponseNext, candidateEq] using candidateViewLt
      have seqLeOld : committedSeq <= state.eventSeqno candidate := by
        simpa [statusCommittedResponseNext, candidateEq] using seqLe
      have goalEq :
          (statusCommittedResponseNext state response status).invalidStatusEvent
              candidate =
            state.invalidStatusEvent candidate := by
        simp [statusCommittedResponseNext]
      rw [goalEq]
      rcases committedSplit committedView committedSeq committed with
        oldCommitted | newCommitted
      · exact
          properties.onceCommittedOlderViewSuffixIsInvalid
            committedView committedSeq candidate
            ⟨oldCommitted, candidateIsStatusOld, candidateViewLtOld, seqLeOld⟩
      · rcases candidateIsStatusOld with candidateCommitted | candidateInvalid
        · exfalso
          -- A committed candidate above the new commit would need a later view.
          have candidateCommittedId :
              state.committedTxId
                (state.eventView candidate) (state.eventSeqno candidate) :=
            ⟨candidate, candidateCommitted, rfl, rfl⟩
          have inCurrent :=
            properties.committedIdIsInCurrentLedger
              (state.eventView candidate) (state.eventSeqno candidate) current
              ⟨candidateCommittedId, viewIsCurrent⟩
          have responseLeCandidate :
              state.eventSeqno response <= state.eventSeqno candidate :=
            newCommitted.2.trans_le seqLeOld
          have monotone :=
            entryViewMonotoneAt
              properties.toCoreBundle
              responseEntryMatches
              inCurrent.1
              inCurrent.2
              responseLeCandidate
          rw [<- newCommitted.1] at candidateViewLtOld
          exact
            candidateViewLtOld.2
              (le_antisymm candidateViewLtOld.1 monotone)
        · exact candidateInvalid
  · intro invalidView invalidSeq candidate hypotheses
    rcases hypotheses with ⟨invalid, candidateIsStatus, candidateView, seqLe⟩
    have invalidOld := invalidBack invalidView invalidSeq invalid
    by_cases candidateEq : candidate = status
    · subst candidate
      exfalso
      have viewEq :
          (statusCommittedResponseNext state response status).eventView status =
            state.eventView response := by
        simp [statusCommittedResponseNext]
      have seqnoEq :
          (statusCommittedResponseNext state response status).eventSeqno status =
            state.eventSeqno response := by
        simp [statusCommittedResponseNext]
      rw [viewEq] at candidateView
      rw [seqnoEq] at seqLe
      rcases invalidOld with
        ⟨invalidEvent, eventIsInvalid, witnessView, witnessSeqno⟩
      exact
        notInvalid
          ⟨invalidEvent, eventIsInvalid,
            witnessView.trans candidateView.symm,
            witnessSeqno.trans_le seqLe⟩
    · have candidateIsStatusOld : state.statusEvent candidate := by
        rcases statusSplit candidate candidateIsStatus with oldStatus | isNew
        · exact oldStatus
        · exact absurd isNew candidateEq
      have candidateViewOld : state.eventView candidate = invalidView := by
        simpa [statusCommittedResponseNext, candidateEq] using candidateView
      have seqLeOld : invalidSeq <= state.eventSeqno candidate := by
        simpa [statusCommittedResponseNext, candidateEq] using seqLe
      have goalEq :
          (statusCommittedResponseNext state response status).invalidStatusEvent
              candidate =
            state.invalidStatusEvent candidate := by
        simp [statusCommittedResponseNext]
      rw [goalEq]
      exact
        properties.onceInvalidSameViewSuffixIsInvalid
          invalidView invalidSeq candidate
          ⟨invalidOld, candidateIsStatusOld, candidateViewOld, seqLeOld⟩

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem statusInvalidResponsePreservesClosure
    {state : State Tx View Seqno Event}
    {response status : Event}
    (properties : ClosureBundle state)
    (responseIsRw : state.rwResponseEvent response)
    (statusAllowed : state.invalidStatusAllowed response)
    (nextEvent : state.nextHistoryEvent status) :
    ClosureBundle (statusInvalidResponseNext state response status) := by
  have statusSplit :
      forall candidate,
        (statusInvalidResponseNext state response status).statusEvent
            candidate ->
          state.statusEvent candidate \/ candidate = status := by
    intro candidate candidateIsStatus
    by_cases candidateEq : candidate = status
    · exact Or.inr candidateEq
    · refine Or.inl ?_
      rcases candidateIsStatus with candidateCommitted | candidateInvalid
      · exact Or.inl
          (by simpa [statusInvalidResponseNext] using candidateCommitted)
      · exact Or.inr
          (by
            simpa [statusInvalidResponseNext, candidateEq] using
              candidateInvalid)
  have committedBack :
      forall view seqno,
        (statusInvalidResponseNext state response status).committedTxId
            view seqno ->
          state.committedTxId view seqno := by
    intro view seqno committed
    exact
      committedTxIdOfFreshEvent
        properties.toStructuralBundle
        nextEvent
        committed
        (fun _ => rfl)
        (fun candidate candidateNe => by
          simp [statusInvalidResponseNext, candidateNe])
        (fun candidate candidateNe => by
          simp [statusInvalidResponseNext, candidateNe])
  have invalidSplit :
      forall view seqno,
        (statusInvalidResponseNext state response status).invalidTxId
            view seqno ->
          state.invalidTxId view seqno \/
            (state.eventView response = view /\
              state.eventSeqno response = seqno) := by
    intro view seqno invalid
    rcases invalid with ⟨witness, witnessInvalid, witnessView, witnessSeqno⟩
    by_cases witnessEq : witness = status
    · subst witness
      exact Or.inr
        ⟨by simpa [statusInvalidResponseNext] using witnessView,
          by simpa [statusInvalidResponseNext] using witnessSeqno⟩
    · exact Or.inl
        ⟨witness,
          by
            simpa [statusInvalidResponseNext, witnessEq] using witnessInvalid,
          by simpa [statusInvalidResponseNext, witnessEq] using witnessView,
          by simpa [statusInvalidResponseNext, witnessEq] using witnessSeqno⟩
  refine
    { toCommitBundle :=
        statusInvalidResponsePreservesCommits
          properties.toCommitBundle
          responseIsRw
          statusAllowed
          nextEvent
      committedOrInvalid := ?_
      onceCommittedPreviousIsCommitted := ?_
      onceCommittedOlderViewSuffixIsInvalid := ?_
      onceInvalidSameViewSuffixIsInvalid := ?_ }
  · intro view seqno committed invalid
    have committedOld := committedBack view seqno committed
    rcases invalidSplit view seqno invalid with oldInvalid | newInvalid
    · exact properties.committedOrInvalid view seqno committedOld oldInvalid
    · have committedAtResponse :
          state.committedTxId (state.eventView response) seqno := by
        rw [newInvalid.1]
        exact committedOld
      exact
        noCommitAtOrAboveInvalidResponse
          properties.toCommitBundle
          responseIsRw
          statusAllowed
          (le_of_eq newInvalid.2)
          committedAtResponse
  · intro committedView committedSeq candidate hypotheses
    rcases hypotheses with
      ⟨committed, candidateIsStatus, candidateView, candidateSeqno⟩
    have committedOld := committedBack committedView committedSeq committed
    by_cases candidateEq : candidate = status
    · subst candidate
      exfalso
      have viewEq :
          (statusInvalidResponseNext state response status).eventView status =
            state.eventView response := by
        simp [statusInvalidResponseNext]
      have seqnoEq :
          (statusInvalidResponseNext state response status).eventSeqno status =
            state.eventSeqno response := by
        simp [statusInvalidResponseNext]
      rw [viewEq] at candidateView
      rw [seqnoEq] at candidateSeqno
      have committedAtResponse :
          state.committedTxId (state.eventView response) committedSeq := by
        rw [candidateView]
        exact committedOld
      exact
        noCommitAtOrAboveInvalidResponse
          properties.toCommitBundle
          responseIsRw
          statusAllowed
          candidateSeqno
          committedAtResponse
    · have candidateIsStatusOld : state.statusEvent candidate := by
        rcases statusSplit candidate candidateIsStatus with oldStatus | isNew
        · exact oldStatus
        · exact absurd isNew candidateEq
      have candidateViewOld : state.eventView candidate = committedView := by
        simpa [statusInvalidResponseNext, candidateEq] using candidateView
      have candidateSeqnoOld :
          state.eventSeqno candidate <= committedSeq := by
        simpa [statusInvalidResponseNext, candidateEq] using candidateSeqno
      have goalEq :
          (statusInvalidResponseNext state response status).committedStatusEvent
              candidate =
            state.committedStatusEvent candidate := by
        simp [statusInvalidResponseNext]
      rw [goalEq]
      exact
        properties.onceCommittedPreviousIsCommitted
          committedView committedSeq candidate
          ⟨committedOld, candidateIsStatusOld, candidateViewOld,
            candidateSeqnoOld⟩
  · intro committedView committedSeq candidate hypotheses
    rcases hypotheses with
      ⟨committed, candidateIsStatus, candidateViewLt, seqLe⟩
    have committedOld := committedBack committedView committedSeq committed
    by_cases candidateEq : candidate = status
    · subst candidate
      simp [statusInvalidResponseNext]
    · have candidateIsStatusOld : state.statusEvent candidate := by
        rcases statusSplit candidate candidateIsStatus with oldStatus | isNew
        · exact oldStatus
        · exact absurd isNew candidateEq
      have candidateViewLtOld :
          state.viewLt (state.eventView candidate) committedView := by
        simpa [statusInvalidResponseNext, candidateEq] using candidateViewLt
      have seqLeOld : committedSeq <= state.eventSeqno candidate := by
        simpa [statusInvalidResponseNext, candidateEq] using seqLe
      have goalEq :
          (statusInvalidResponseNext state response status).invalidStatusEvent
              candidate =
            state.invalidStatusEvent candidate := by
        simp [statusInvalidResponseNext, candidateEq]
      rw [goalEq]
      exact
        properties.onceCommittedOlderViewSuffixIsInvalid
          committedView committedSeq candidate
          ⟨committedOld, candidateIsStatusOld, candidateViewLtOld, seqLeOld⟩
  · intro invalidView invalidSeq candidate hypotheses
    rcases hypotheses with ⟨invalid, candidateIsStatus, candidateView, seqLe⟩
    by_cases candidateEq : candidate = status
    · subst candidate
      simp [statusInvalidResponseNext]
    · have candidateIsStatusOld : state.statusEvent candidate := by
        rcases statusSplit candidate candidateIsStatus with oldStatus | isNew
        · exact oldStatus
        · exact absurd isNew candidateEq
      have candidateViewOld : state.eventView candidate = invalidView := by
        simpa [statusInvalidResponseNext, candidateEq] using candidateView
      have seqLeOld : invalidSeq <= state.eventSeqno candidate := by
        simpa [statusInvalidResponseNext, candidateEq] using seqLe
      have goalEq :
          (statusInvalidResponseNext state response status).invalidStatusEvent
              candidate =
            state.invalidStatusEvent candidate := by
        simp [statusInvalidResponseNext, candidateEq]
      rw [goalEq]
      rcases invalidSplit invalidView invalidSeq invalid with
        oldInvalid | newInvalid
      · exact
          properties.onceInvalidSameViewSuffixIsInvalid
            invalidView invalidSeq candidate
            ⟨oldInvalid, candidateIsStatusOld, candidateViewOld, seqLeOld⟩
      · -- A committed candidate at or above the new invalid slot is impossible.
        rcases candidateIsStatusOld with candidateCommitted | candidateInvalid
        · exfalso
          have candidateCommittedId :
              state.committedTxId
                (state.eventView candidate) (state.eventSeqno candidate) :=
            ⟨candidate, candidateCommitted, rfl, rfl⟩
          have viewEqResponse :
              state.eventView candidate = state.eventView response :=
            candidateViewOld.trans newInvalid.1.symm
          have committedAtResponse :
              state.committedTxId
                (state.eventView response) (state.eventSeqno candidate) := by
            rw [<- viewEqResponse]
            exact candidateCommittedId
          exact
            noCommitAtOrAboveInvalidResponse
              properties.toCommitBundle
              responseIsRw
              statusAllowed
              (newInvalid.2.trans_le seqLeOld)
              committedAtResponse
        · exact candidateInvalid

omit [OrderBot Seqno] [OrderBot Event] in
theorem truncateLedgerPreservesClosure
    {state : State Tx View Seqno Event}
    {source newView : View}
    {cut : Seqno}
    (properties : ClosureBundle state)
    (sourceIsActive : state.activeView source)
    (cutExists : state.ledgerEntry source cut)
    (sourceIsValid : state.validTruncationSource source cut)
    (viewIsNext : state.nextView newView) :
    ClosureBundle (truncateLedgerNext state source cut newView) :=
  closureOfStatusPreserving
    properties
    (truncateLedgerPreservesCommits
      properties.toCommitBundle
      sourceIsActive
      cutExists
      sourceIsValid
      viewIsNext)
    (fun _ => rfl) (fun _ => rfl) (fun _ _ => rfl) (fun _ _ => rfl)


omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
theorem truncateLedgerToEmptyPreservesClosure
    {state : State Tx View Seqno Event}
    {source newView : View}
    (properties : ClosureBundle state)
    (sourceIsActive : state.activeView source)
    (noCommitted : state.noCommittedTxId)
    (viewIsNext : state.nextView newView) :
    ClosureBundle (truncateLedgerToEmptyNext state newView) :=
  closureOfStatusPreserving
    properties
    (truncateLedgerToEmptyPreservesCommits
      properties.toCommitBundle
      sourceIsActive
      noCommitted
      viewIsNext)
    (fun _ => rfl) (fun _ => rfl) (fun _ _ => rfl) (fun _ _ => rfl)


omit [OrderBot Seqno] [OrderBot Event] in
theorem stepPreservesClosure
    {state next : State Tx View Seqno Event}
    (properties : ClosureBundle state)
    (transition : Step state next) :
    ClosureBundle next := by
  cases transition with
  | rwTxRequest tx event nextTx nextEvent =>
      exact rwTxRequestPreservesClosure properties nextTx nextEvent
  | roTxRequest tx event nextTx nextEvent =>
      exact roTxRequestPreservesClosure properties nextTx nextEvent
  | rwTxExecute
      request
      branch
      slot
      requestIsRw
      txNotInLedger
      branchIsActive
      nextSlot =>
      exact
        rwTxExecutePreservesClosure
          properties
          requestIsRw
          txNotInLedger
          branchIsActive
          nextSlot
  | appendOtherTxn branch slot branchIsActive nextSlot =>
      exact appendOtherTxnPreservesClosure properties branchIsActive nextSlot
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
        rwTxResponsePreservesClosure
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
        roTxResponsePreservesClosure
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
        statusCommittedResponsePreservesClosure
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
        statusInvalidResponsePreservesClosure
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
        truncateLedgerPreservesClosure
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
        truncateLedgerToEmptyPreservesClosure
          properties
          sourceIsActive
          noCommitted
          viewIsNext

theorem reachableClosure
    {state : State Tx View Seqno Event}
    (reachable : Reachable state) :
    ClosureBundle state := by
  induction reachable with
  | initial => exact initialClosure
  | step _ transition properties =>
      exact stepPreservesClosure properties transition

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- Two committed responses read nested prefixes of the current view, so the
one with the smaller frontier observes a subset. -/
theorem observationsSubsetOfSeqnoLe
    {state : State Tx View Seqno Event}
    {left right : Event}
    {current : View}
    (properties : CommitBundle state)
    (currentIsCurrent : state.currentView current)
    (leftCommitted : state.rwResponseCommitted left)
    (rightCommitted : state.rwResponseCommitted right)
    (seqLe : state.eventSeqno left <= state.eventSeqno right) :
    state.observationsSubset left right := by
  have leftInCurrent :=
    properties.committedIdIsInCurrentLedger
      (state.eventView left) (state.eventSeqno left) current
      ⟨leftCommitted.2, currentIsCurrent⟩
  have rightInCurrent :=
    properties.committedIdIsInCurrentLedger
      (state.eventView right) (state.eventSeqno right) current
      ⟨rightCommitted.2, currentIsCurrent⟩
  have leftBranch :=
    properties.responseBranchIsView left (Or.inl leftCommitted.1)
  have rightBranch :=
    properties.responseBranchIsView right (Or.inl rightCommitted.1)
  intro slot observed observation
  have slotLeLeft : slot <= state.eventSeqno left := observation.2.1
  have leftClient : state.clientEntry (state.eventBranch left) slot :=
    observation.2.2.1
  have leftTx : state.entryTx (state.eventBranch left) slot = observed :=
    observation.2.2.2
  rw [leftBranch] at leftClient
  rw [leftBranch] at leftTx
  -- Lift the observation from the response's own view into the current view.
  have leftPrefix :=
    properties.ledgerPrefixMatchesFrontierOrigin
      current (state.eventSeqno left) slot ⟨leftInCurrent.1, slotLeLeft⟩
  rw [leftInCurrent.2] at leftPrefix
  have currentClient : state.clientEntry current slot :=
    leftPrefix.2.1.2 leftClient
  have currentTx : state.entryTx current slot = observed :=
    (leftPrefix.2.2.2 currentClient).trans leftTx
  -- Push it back down into the other response's view.
  have slotLeRight : slot <= state.eventSeqno right := le_trans slotLeLeft seqLe
  have rightPrefix :=
    properties.ledgerPrefixMatchesFrontierOrigin
      current (state.eventSeqno right) slot ⟨rightInCurrent.1, slotLeRight⟩
  rw [rightInCurrent.2] at rightPrefix
  have rightClient : state.clientEntry (state.eventView right) slot :=
    rightPrefix.2.1.1 currentClient
  have rightTx : state.entryTx (state.eventView right) slot = observed :=
    (rightPrefix.2.2.2 currentClient).symm.trans currentTx
  refine ⟨Or.inl rightCommitted.1, slotLeRight, ?_, ?_⟩
  · rw [rightBranch]
    exact rightClient
  · rw [rightBranch]
    exact rightTx

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- Committed read-write responses are serializable: their observation sets are
totally ordered by inclusion. -/
theorem commitsCommittedRwSerializable
    {state : State Tx View Seqno Event}
    (properties : CommitBundle state) :
    CommittedRwSerializable state := by
  rw [CommittedRwSerializable]
  intro left right committedPair
  rcases committedPair with ⟨leftCommitted, rightCommitted⟩
  rcases properties.hasCurrentView with ⟨current, currentIsCurrent⟩
  rcases le_total (state.eventSeqno left) (state.eventSeqno right) with
    leftLe | rightLe
  · exact Or.inl
      (observationsSubsetOfSeqnoLe
        properties currentIsCurrent leftCommitted rightCommitted leftLe)
  · exact Or.inr
      (observationsSubsetOfSeqnoLe
        properties currentIsCurrent rightCommitted leftCommitted rightLe)

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- The real-time core: a committed response that completes before a request is
sent occupies a strictly earlier ledger slot than the committed response to that
request.

If it did not, then the earlier response's own prefix would already contain the
later response's transaction, so `OnlyObserveSentRequests` would place the
request before the earlier response, contradicting the real-time hypothesis. -/
theorem committedResponseSeqnoLt
    {state : State Tx View Seqno Event}
    {earlier request later : Event}
    (properties : CommitBundle state)
    (earlierCommitted : state.rwResponseCommitted earlier)
    (requestIsRw : state.rwRequestEvent request)
    (laterCommitted : state.rwResponseCommitted later)
    (requestTx : state.eventTx request = state.eventTx later)
    (earlierLtRequest : state.eventLt earlier request) :
    state.seqLt (state.eventSeqno earlier) (state.eventSeqno later) := by
  rcases properties.hasCurrentView with ⟨current, currentIsCurrent⟩
  have earlierMatch :=
    commitsCommittedResponseMatchesCurrentLedger properties earlier current
      ⟨earlierCommitted, currentIsCurrent⟩
  have laterMatch :=
    commitsCommittedResponseMatchesCurrentLedger properties later current
      ⟨laterCommitted, currentIsCurrent⟩
  have earlierEntry :=
    properties.clientEntriesAreLedgerEntries
      current (state.eventSeqno earlier) earlierMatch.1
  have earlierBranch :=
    properties.responseBranchIsView earlier (Or.inl earlierCommitted.1)
  have notLe :
      Not (state.eventSeqno later <= state.eventSeqno earlier) := by
    intro laterLe
    have prefixDown :=
      properties.ledgerPrefixMatchesFrontierOrigin
        current (state.eventSeqno earlier) (state.eventSeqno later)
        ⟨earlierEntry, laterLe⟩
    rw [earlierMatch.2.1] at prefixDown
    have clientAtLater :
        state.clientEntry
          (state.eventView earlier) (state.eventSeqno later) :=
      prefixDown.2.1.1 laterMatch.1
    have txAtLater :
        state.entryTx (state.eventView earlier) (state.eventSeqno later) =
          state.eventTx later :=
      (prefixDown.2.2.2 laterMatch.1).symm.trans laterMatch.2.2
    have observation :
        state.observedAt
          earlier (state.eventSeqno later) (state.eventTx later) := by
      refine ⟨Or.inl earlierCommitted.1, laterLe, ?_, ?_⟩
      · rw [earlierBranch]
        exact clientAtLater
      · rw [earlierBranch]
        exact txAtLater
    rcases
        properties.onlyObserveSentRequests
          earlier (state.eventSeqno later) (state.eventTx later)
          ⟨Or.inl earlierCommitted.1, observation⟩ with
      ⟨witness, witnessIsRw, witnessTx, witnessLt⟩
    have witnessEq : witness = request := by
      by_contra witnessNe
      exact
        properties.uniqueTxRequests witness request
          ⟨Or.inl witnessIsRw, Or.inl requestIsRw, witnessNe⟩
          (witnessTx.trans requestTx.symm)
    subst witness
    exact
      earlierLtRequest.2 (le_antisymm earlierLtRequest.1 witnessLt.1)
  have seqLt : state.eventSeqno earlier < state.eventSeqno later :=
    not_le.mp notLe
  exact ⟨le_of_lt seqLt, ne_of_lt seqLt⟩

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- Committed read-write transaction identifiers respect the real-time order of
the requests that produced them. -/
theorem commitsCommittedRwOrderedRealTime
    {state : State Tx View Seqno Event}
    (properties : CommitBundle state) :
    CommittedRwOrderedRealTime state := by
  rw [CommittedRwOrderedRealTime]
  intro earlier request later hypotheses
  rcases hypotheses with
    ⟨earlierCommitted, requestIsRw, laterCommitted, requestTx, earlierLt⟩
  have seqLt :=
    committedResponseSeqnoLt
      properties earlierCommitted requestIsRw laterCommitted requestTx
      earlierLt
  rcases properties.hasCurrentView with ⟨current, currentIsCurrent⟩
  have earlierInCurrent :=
    properties.committedIdIsInCurrentLedger
      (state.eventView earlier) (state.eventSeqno earlier) current
      ⟨earlierCommitted.2, currentIsCurrent⟩
  have laterInCurrent :=
    properties.committedIdIsInCurrentLedger
      (state.eventView later) (state.eventSeqno later) current
      ⟨laterCommitted.2, currentIsCurrent⟩
  have viewLe : state.eventView earlier <= state.eventView later :=
    entryViewMonotoneAt
      properties.toCoreBundle
      earlierInCurrent.2
      laterInCurrent.1
      laterInCurrent.2
      seqLt.1
  by_cases viewEq : state.eventView earlier = state.eventView later
  · exact Or.inr ⟨viewEq, seqLt⟩
  · exact Or.inl ⟨viewLe, viewEq⟩

omit [LinearOrder Tx] [OrderBot Tx] [OrderBot View] [OrderBot Seqno]
  [OrderBot Event] in
/-- A committed response observes every transaction that was already committed
before its own request was sent. -/
theorem commitsAllCommittedObserved
    {state : State Tx View Seqno Event}
    (properties : CommitBundle state) :
    AllCommittedObserved state := by
  rw [AllCommittedObserved]
  intro earlier request response hypotheses
  rcases hypotheses with
    ⟨earlierCommitted, requestIsRw, responseCommitted, requestTx, earlierLt⟩
  have seqLt :=
    committedResponseSeqnoLt
      properties earlierCommitted requestIsRw responseCommitted requestTx
      earlierLt
  rcases properties.hasCurrentView with ⟨current, currentIsCurrent⟩
  have earlierMatch :=
    commitsCommittedResponseMatchesCurrentLedger properties earlier current
      ⟨earlierCommitted, currentIsCurrent⟩
  have responseInCurrent :=
    properties.committedIdIsInCurrentLedger
      (state.eventView response) (state.eventSeqno response) current
      ⟨responseCommitted.2, currentIsCurrent⟩
  have responseBranch :=
    properties.responseBranchIsView response (Or.inl responseCommitted.1)
  have prefixDown :=
    properties.ledgerPrefixMatchesFrontierOrigin
      current (state.eventSeqno response) (state.eventSeqno earlier)
      ⟨responseInCurrent.1, seqLt.1⟩
  rw [responseInCurrent.2] at prefixDown
  refine
    ⟨state.eventSeqno earlier, Or.inl responseCommitted.1, seqLt.1, ?_, ?_⟩
  · rw [responseBranch]
    exact prefixDown.2.1.1 earlierMatch.1
  · rw [responseBranch]
    exact (prefixDown.2.2.2 earlierMatch.1).symm.trans earlierMatch.2.2

theorem reachableProved
    {state : State Tx View Seqno Event}
    (reachable : Reachable state) :
    PropertyBundle state := by
  have closure := reachableClosure reachable
  exact
    { historyTypeOk := closure.historyTypeOk
      historyEventKindUnique := closure.historyEventKindUnique
      historyIsPrefix := closure.historyIsPrefix
      activeViewsArePrefix := closure.activeViewsArePrefix
      ledgerTypeOk := closure.ledgerTypeOk
      clientEntriesAreLedgerEntries := closure.clientEntriesAreLedgerEntries
      ledgerIsPrefix := closure.ledgerIsPrefix
      ledgerTxIdsAreStableAcrossCopies :=
        closure.ledgerTxIdsAreStableAcrossCopies
      ledgerEntryExistsInOriginView := closure.ledgerEntryExistsInOriginView
      responseFrontierIsLedgerEntry := closure.responseFrontierIsLedgerEntry
      clientEntryHasRequest := closure.clientEntryHasRequest
      clientEntryMatchesOrigin := closure.clientEntryMatchesOrigin
      ledgerEntryViewsAreMonotonic := closure.ledgerEntryViewsAreMonotonic
      ledgerPrefixMatchesFrontierOrigin :=
        closure.ledgerPrefixMatchesFrontierOrigin
      responseBranchIsView := closure.responseBranchIsView
      responseFrontierMatchesOrigin := closure.responseFrontierMatchesOrigin
      rwResponseMatchesLedgerEntry := closure.rwResponseMatchesLedgerEntry
      statusHasRwResponse := closure.statusHasRwResponse
      committedIdIsInCurrentLedger := closure.committedIdIsInCurrentLedger
      committedResponseMatchesCurrentLedger :=
        commitsCommittedResponseMatchesCurrentLedger closure.toCommitBundle
      allReceivedAfterSent := closure.allReceivedAfterSent
      uniqueTxRequests := closure.uniqueTxRequests
      onlyObserveSentRequests := closure.onlyObserveSentRequests
      observationsAreWithinResponsePrefix :=
        closure.observationsAreWithinResponsePrefix
      uniqueRwTxs := coreUniqueRwTxs closure.toCoreBundle
      sameObservations := coreSameObservations closure.toCoreBundle
      uniqueTxIds := responsesUniqueTxIds closure.toResponseBundle
      uniqueCommittedSeqnos :=
        commitsUniqueCommittedSeqnos closure.toCommitBundle
      committedOrInvalid := closure.committedOrInvalid
      onceCommittedPreviousIsCommitted :=
        closure.onceCommittedPreviousIsCommitted
      onceCommittedOlderViewSuffixIsInvalid :=
        closure.onceCommittedOlderViewSuffixIsInvalid
      onceInvalidSameViewSuffixIsInvalid :=
        closure.onceInvalidSameViewSuffixIsInvalid
      allCommittedObserved :=
        commitsAllCommittedObserved closure.toCommitBundle
      committedRwSerializable :=
        commitsCommittedRwSerializable closure.toCommitBundle
      atMostOnceObserved :=
        provenanceAtMostOnceObserved closure.toProvenanceBundle
      committedRwOrderedRealTime :=
        commitsCommittedRwOrderedRealTime closure.toCommitBundle }

end CCFConsistency
