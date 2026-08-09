-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Veil

set_option synthInstance.maxHeartbeats 200000
set_option veil.violationIsError true
set_option veil.smt.trust false
set_option veil.printCounterexamples false
set_option veil.smt.timeout 120

/-!
# CCF client consistency

This is a single-level Veil model of the final `MultiNodeReads` transition
system under `tla/consistency`. It deliberately does not model CCF's consensus
protocol.

The TLA+ sequences are represented relationally:

* `histEvent` is totally ordered, and used history events form a prefix.
* `view` is totally ordered, and active ledger branches form a prefix.
* `seqno` is totally ordered, and occupied positions in each branch form a
  prefix.
* `tx` is totally ordered, and requested transactions form a prefix.

The first element of each finite Veil order has rank zero. Concrete CCF view
and sequence numbers are therefore rank-normalised when checking a trace.
-/

veil module CCFConsistency

type tx
type view
type seqno
type histEvent

instantiate txOrder : TotalOrderWithZero tx
instantiate viewOrder : TotalOrderWithZero view
instantiate seqOrder : TotalOrderWithZero seqno
instantiate eventOrder : TotalOrderWithZero histEvent

-- Abstract ledger branches. Entry metadata is meaningful only when
-- `ledgerEntry branch slot` holds.
relation activeView : view -> Bool
relation ledgerEntry : view -> seqno -> Bool
relation clientEntry : view -> seqno -> Bool
function entryView : view -> seqno -> view
function entryTx : view -> seqno -> tx

-- Externally visible history.
relation eventUsed : histEvent -> Bool
relation rwRequestEvent : histEvent -> Bool
relation rwResponseEvent : histEvent -> Bool
relation roRequestEvent : histEvent -> Bool
relation roResponseEvent : histEvent -> Bool
relation committedStatusEvent : histEvent -> Bool
relation invalidStatusEvent : histEvent -> Bool
function eventTx : histEvent -> tx
function eventView : histEvent -> view
function eventSeqno : histEvent -> seqno

-- Ledger branches are immutable after entries are appended. Remembering the
-- branch where the response's final entry originated is therefore enough to
-- derive its observations, without retaining which identical copy replied.
function eventBranch : histEvent -> view

#gen_state

theory ghost relation txLt (left right : tx) :=
  And (txOrder.le left right) (Not (left = right))

theory ghost relation viewLt (left right : view) :=
  And (viewOrder.le left right) (Not (left = right))

theory ghost relation seqLt (left right : seqno) :=
  And (seqOrder.le left right) (Not (left = right))

theory ghost relation eventLt (left right : histEvent) :=
  And (eventOrder.le left right) (Not (left = right))

ghost relation historyEvent (e : histEvent) :=
  Or (rwRequestEvent e)
    (Or (rwResponseEvent e)
      (Or (roRequestEvent e)
        (Or (roResponseEvent e)
          (Or (committedStatusEvent e) (invalidStatusEvent e)))))

ghost relation requestEvent (e : histEvent) :=
  Or (rwRequestEvent e) (roRequestEvent e)

ghost relation responseEvent (e : histEvent) :=
  Or (rwResponseEvent e) (roResponseEvent e)

ghost relation observedAt
    (response : histEvent) (slot : seqno) (observed : tx) :=
  And (responseEvent response)
    (And (seqOrder.le slot (eventSeqno response))
      (And (clientEntry (eventBranch response) slot)
        (entryTx (eventBranch response) slot = observed)))

ghost relation statusEvent (e : histEvent) :=
  Or (committedStatusEvent e) (invalidStatusEvent e)

ghost relation rwRequested (t : tx) :=
  ∃ e, And (rwRequestEvent e) (eventTx e = t)

ghost relation roRequested (t : tx) :=
  ∃ e, And (roRequestEvent e) (eventTx e = t)

ghost relation requested (t : tx) :=
  Or (rwRequested t) (roRequested t)

ghost relation responded (t : tx) :=
  ∃ e, And (responseEvent e) (eventTx e = t)

ghost relation txInLedger (t : tx) :=
  ∃ branch slot,
    And (clientEntry branch slot) (entryTx branch slot = t)

ghost relation committedTxId (v : view) (s : seqno) :=
  ∃ e,
    And (committedStatusEvent e)
      (And (eventView e = v) (eventSeqno e = s))

ghost relation invalidTxId (v : view) (s : seqno) :=
  ∃ e,
    And (invalidStatusEvent e)
      (And (eventView e = v) (eventSeqno e = s))

ghost relation rwResponseCommitted (e : histEvent) :=
  And (rwResponseEvent e) (committedTxId (eventView e) (eventSeqno e))

ghost relation roResponseCommitted (e : histEvent) :=
  And (roResponseEvent e) (committedTxId (eventView e) (eventSeqno e))

ghost relation observes (response : histEvent) (observed : tx) :=
  ∃ slot, observedAt response slot observed

ghost relation sameObservations (left right : histEvent) :=
  ∀ slot observed,
    observedAt left slot observed = observedAt right slot observed

ghost relation observationsSubset (left right : histEvent) :=
  ∀ slot observed,
    observedAt left slot observed -> observedAt right slot observed

ghost relation txIdLt (left right : histEvent) :=
  Or (viewLt (eventView left) (eventView right))
    (And (eventView left = eventView right)
      (seqLt (eventSeqno left) (eventSeqno right)))

ghost relation currentView (v : view) :=
  And (activeView v)
    (∀ later, viewLt v later -> Not (activeView later))

ghost relation nextView (v : view) :=
  And (Not (activeView v))
    (∀ earlier, viewLt earlier v -> activeView earlier)

ghost relation nextLedgerSlot (branch : view) (slot : seqno) :=
  And (Not (ledgerEntry branch slot))
    (∀ earlier, seqLt earlier slot -> ledgerEntry branch earlier)

ghost relation lastLedgerSlot (branch : view) (slot : seqno) :=
  And (ledgerEntry branch slot)
    (∀ occupied,
      ledgerEntry branch occupied -> seqOrder.le occupied slot)

ghost relation nextHistoryEvent (e : histEvent) :=
  And (Not (eventUsed e))
    (∀ earlier, eventLt earlier e -> eventUsed earlier)

ghost relation nextTx (t : tx) :=
  And (Not (requested t))
    (∀ earlier, txLt earlier t -> requested earlier)

ghost relation noCommittedTxId :=
  ∀ v s, Not (committedTxId v s)

ghost relation maxCommittedSeqno (s : seqno) :=
  And (∃ v, committedTxId v s)
    (∀ v other, committedTxId v other -> seqOrder.le other s)

ghost relation validTruncationSource
    (source : view) (cut : seqno) :=
  Or noCommittedTxId
    (∃ commitSeq,
      And (maxCommittedSeqno commitSeq)
        (And (ledgerEntry source commitSeq)
          (And (committedTxId (entryView source commitSeq) commitSeq)
            (seqOrder.le commitSeq cut))))

ghost relation invalidStatusAllowed (response : histEvent) :=
  ∃ current,
    And (currentView current)
      (Or
        -- Commit passed this slot with a transaction from another view.
        (∃ commitSeq,
          And (maxCommittedSeqno commitSeq)
            (And (seqOrder.le (eventSeqno response) commitSeq)
              (And (ledgerEntry current (eventSeqno response))
                (Not
                  (entryView current (eventSeqno response) =
                    eventView response)))))
        (Or
          -- Commit is behind this slot but is already in a newer view.
          (∃ commitSeq,
            And (maxCommittedSeqno commitSeq)
              (And (seqLt commitSeq (eventSeqno response))
                (And (ledgerEntry current commitSeq)
                  (viewLt (eventView response)
                    (entryView current commitSeq)))))
          -- The current view may declare its uncommitted suffix invalid.
          (And (eventView response = current)
            (∀ committedView committedSeq,
              committedTxId committedView committedSeq ->
                seqLt committedSeq (eventSeqno response)))))

after_init {
  activeView V := decide $ V = viewOrder.zero
  ledgerEntry V S := false
  clientEntry V S := false
  entryView V S := viewOrder.zero
  entryTx V S := txOrder.zero

  eventUsed E := false
  rwRequestEvent E := false
  rwResponseEvent E := false
  roRequestEvent E := false
  roResponseEvent E := false
  committedStatusEvent E := false
  invalidStatusEvent E := false
  eventTx E := txOrder.zero
  eventView E := viewOrder.zero
  eventSeqno E := seqOrder.zero
  eventBranch E := viewOrder.zero
}

action RwTxRequestAction (t : tx) (e : histEvent) {
  require nextTx t
  require nextHistoryEvent e
  eventUsed e := true
  rwRequestEvent e := true
  eventTx e := t
}

action RoTxRequestAction (t : tx) (e : histEvent) {
  require nextTx t
  require nextHistoryEvent e
  eventUsed e := true
  roRequestEvent e := true
  eventTx e := t
}

action RwTxExecuteAction (request : histEvent) (branch : view)
    (slot : seqno) {
  require rwRequestEvent request
  require Not (txInLedger (eventTx request))
  require activeView branch
  require nextLedgerSlot branch slot
  ledgerEntry branch slot := true
  clientEntry branch slot := true
  entryView branch slot := branch
  entryTx branch slot := eventTx request
}

-- BEGIN CCF VEIL APPEND OTHER ACTION
action AppendOtherTxnAction (branch : view) (slot : seqno) {
  require activeView branch
  require nextLedgerSlot branch slot
  ledgerEntry branch slot := true
  clientEntry branch slot := false
  entryView branch slot := branch
}
-- END CCF VEIL APPEND OTHER ACTION

action RwTxResponseAction (request : histEvent) (branch : view)
    (slot : seqno) (response : histEvent) {
  require rwRequestEvent request
  require Not (responded (eventTx request))
  require activeView branch
  require clientEntry branch slot
  require entryTx branch slot = eventTx request
  require nextHistoryEvent response

  eventUsed response := true
  rwResponseEvent response := true
  eventTx response := eventTx request
  eventView response := entryView branch slot
  eventSeqno response := slot
  eventBranch response := entryView branch slot
}

action RoTxResponseAction (request : histEvent) (branch : view)
    (last : seqno) (response : histEvent) {
  require roRequestEvent request
  require Not (responded (eventTx request))
  require activeView branch
  require lastLedgerSlot branch last
  require nextHistoryEvent response

  eventUsed response := true
  roResponseEvent response := true
  eventTx response := eventTx request
  eventView response := entryView branch last
  eventSeqno response := last
  eventBranch response := entryView branch last
}

action StatusCommittedResponseAction
    (response : histEvent) (status : histEvent) (current : view) {
  require rwResponseEvent response
  require currentView current
  require ledgerEntry current (eventSeqno response)
  require entryView current (eventSeqno response) = eventView response
  require Not (∃ invalid,
    And (invalidStatusEvent invalid)
      (And (eventView invalid = eventView response)
        (seqOrder.le (eventSeqno invalid) (eventSeqno response))))
  require nextHistoryEvent status

  eventUsed status := true
  committedStatusEvent status := true
  eventView status := eventView response
  eventSeqno status := eventSeqno response
}

action StatusInvalidResponseAction
    (response : histEvent) (status : histEvent) {
  require rwResponseEvent response
  require invalidStatusAllowed response
  require nextHistoryEvent status

  eventUsed status := true
  invalidStatusEvent status := true
  eventView status := eventView response
  eventSeqno status := eventSeqno response
}

-- The non-empty case of TLA+'s TruncateLedgerAction. Veil actions are split
-- rather than using a disjunctive next-state relation.
action TruncateLedgerAction
    (source : view) (cut : seqno) (newView : view) {
  require activeView source
  require ledgerEntry source cut
  require validTruncationSource source cut
  require nextView newView

  activeView newView := true
  ledgerEntry newView S :=
    decide $ And (seqOrder.le S cut) (ledgerEntry source S)
  clientEntry newView S :=
    decide $ And (seqOrder.le S cut) (clientEntry source S)
  entryView newView S :=
    if seqOrder.le S cut then entryView source S else viewOrder.zero
  entryTx newView S :=
    if And (seqOrder.le S cut) (clientEntry source S) then
      entryTx source S
    else
      txOrder.zero
}

-- TLA+ also permits truncating to the empty prefix when nothing is committed.
action TruncateLedgerToEmptyAction (source : view) (newView : view) {
  require activeView source
  require noCommittedTxId
  require nextView newView
  activeView newView := true
}

-- BEGIN CCF VEIL PROPERTIES
-- Structural counterparts of HistoryTypeOK, LedgerTypeOK, and the prefix
-- properties.
invariant [history_type_ok]
  ∀ e, Iff (eventUsed e) (historyEvent e)

invariant [history_event_kind_unique]
  ∀ e,
    And (rwRequestEvent e ->
      Not (Or (rwResponseEvent e)
        (Or (roRequestEvent e)
          (Or (roResponseEvent e)
            (Or (committedStatusEvent e) (invalidStatusEvent e))))))
      (And (rwResponseEvent e ->
        Not (Or (roRequestEvent e)
          (Or (roResponseEvent e)
            (Or (committedStatusEvent e) (invalidStatusEvent e)))))
        (And (roRequestEvent e ->
          Not (Or (roResponseEvent e)
            (Or (committedStatusEvent e) (invalidStatusEvent e))))
          (And (roResponseEvent e ->
            Not (Or (committedStatusEvent e) (invalidStatusEvent e)))
            (committedStatusEvent e -> Not (invalidStatusEvent e)))))

invariant [history_is_prefix]
  ∀ later earlier,
    And (eventUsed later) (eventLt earlier later) -> eventUsed earlier

invariant [active_views_are_prefix]
  ∀ later earlier,
    And (activeView later) (viewLt earlier later) -> activeView earlier

invariant [ledger_type_ok]
  ∀ branch slot,
    ledgerEntry branch slot ->
      And (activeView branch)
        (viewOrder.le (entryView branch slot) branch)

invariant [client_entries_are_ledger_entries]
  ∀ branch slot,
    clientEntry branch slot -> ledgerEntry branch slot

invariant [ledger_is_prefix]
  ∀ branch later earlier,
    And (ledgerEntry branch later) (seqLt earlier later) ->
      ledgerEntry branch earlier

invariant [ledger_tx_ids_are_stable_across_copies]
  ∀ leftBranch leftSlot rightBranch rightSlot,
    And (clientEntry leftBranch leftSlot)
      (And (clientEntry rightBranch rightSlot)
        (entryTx leftBranch leftSlot = entryTx rightBranch rightSlot)) ->
      And (leftSlot = rightSlot)
        (entryView leftBranch leftSlot = entryView rightBranch rightSlot)

invariant [ledger_entry_exists_in_origin_view]
  ∀ branch slot,
    ledgerEntry branch slot ->
      ledgerEntry (entryView branch slot) slot

invariant [response_frontier_is_ledger_entry]
  ∀ response,
    responseEvent response ->
      ledgerEntry (eventBranch response) (eventSeqno response)

-- Auxiliary reachability facts used to make the external-history properties
-- inductive. Each follows directly from execution, response, and status actions.
invariant [client_entry_has_request]
  ∀ branch slot,
    clientEntry branch slot ->
      ∃ request,
        And (rwRequestEvent request)
          (eventTx request = entryTx branch slot)

invariant [client_entry_matches_origin]
  ∀ branch slot,
    clientEntry branch slot ->
      And (clientEntry (entryView branch slot) slot)
        (And
          (entryView (entryView branch slot) slot = entryView branch slot)
          (entryTx (entryView branch slot) slot = entryTx branch slot))

invariant [ledger_entry_views_are_monotonic]
  ∀ branch earlier later,
    And (ledgerEntry branch later) (seqOrder.le earlier later) ->
      viewOrder.le (entryView branch earlier) (entryView branch later)

invariant [ledger_prefix_matches_frontier_origin]
  ∀ branch frontier slot,
    And (ledgerEntry branch frontier) (seqOrder.le slot frontier) ->
      And (ledgerEntry (entryView branch frontier) slot)
        (And
          (clientEntry branch slot =
            clientEntry (entryView branch frontier) slot)
          (And
            (entryView branch slot =
              entryView (entryView branch frontier) slot)
            (clientEntry branch slot ->
              entryTx branch slot =
                entryTx (entryView branch frontier) slot)))

invariant [response_branch_is_view]
  ∀ response,
    responseEvent response ->
      eventBranch response = eventView response

invariant [response_frontier_matches_origin]
  ∀ response,
    responseEvent response ->
      entryView (eventBranch response) (eventSeqno response) =
        eventView response

invariant [rw_response_matches_ledger_entry]
  ∀ response,
    rwResponseEvent response ->
      And (clientEntry (eventBranch response) (eventSeqno response))
        (entryTx (eventBranch response) (eventSeqno response) =
          eventTx response)

invariant [status_has_rw_response]
  ∀ status,
    statusEvent status ->
      ∃ response,
        And (rwResponseEvent response)
          (And (eventLt response status)
            (And (eventView response = eventView status)
              (eventSeqno response = eventSeqno status)))

invariant [committed_id_is_in_current_ledger]
  ∀ committedView committedSeq current,
    And (committedTxId committedView committedSeq) (currentView current) ->
      And (ledgerEntry current committedSeq)
        (entryView current committedSeq = committedView)

invariant [committed_response_matches_current_ledger]
  ∀ response current,
    And (rwResponseCommitted response) (currentView current) ->
      And (clientEntry current (eventSeqno response))
        (And
          (entryView current (eventSeqno response) = eventView response)
          (entryTx current (eventSeqno response) = eventTx response))

-- ExternalHistoryInvars.tla properties checked for MultiNodeReads.
invariant [all_received_after_sent]
  ∀ response,
    responseEvent response ->
      ∃ request,
        And (eventLt request response)
          (And (eventTx request = eventTx response)
            (Or
              (And (rwRequestEvent request) (rwResponseEvent response))
              (And (roRequestEvent request) (roResponseEvent response))))

invariant [unique_tx_requests]
  ∀ left right,
    And (requestEvent left)
      (And (requestEvent right) (Not (left = right))) ->
      Not (eventTx left = eventTx right)

invariant [only_observe_sent_requests]
  ∀ response slot observed,
    And (responseEvent response) (observedAt response slot observed) ->
      ∃ request,
        And (rwRequestEvent request)
          (And (eventTx request = observed) (eventLt request response))

invariant [observations_are_within_response_prefix]
  ∀ response slot observed,
    observedAt response slot observed ->
      And (responseEvent response)
        (seqOrder.le slot (eventSeqno response))

invariant [unique_rw_txs]
  ∀ left right,
    And (rwResponseEvent left)
      (And (rwResponseEvent right)
        (And (eventView left = eventView right)
          (eventSeqno left = eventSeqno right))) ->
      eventTx left = eventTx right

invariant [same_observations]
  ∀ left right,
    And (responseEvent left)
      (And (responseEvent right)
        (And (eventView left = eventView right)
          (eventSeqno left = eventSeqno right))) ->
      sameObservations left right

invariant [unique_tx_ids]
  ∀ left right,
    And (responseEvent left)
      (And (responseEvent right) (eventTx left = eventTx right)) ->
      And (eventView left = eventView right)
        (eventSeqno left = eventSeqno right)

invariant [unique_committed_seqnos]
  ∀ left right,
    And (rwResponseCommitted left)
      (And (rwResponseCommitted right)
        (eventSeqno left = eventSeqno right)) ->
      eventTx left = eventTx right

invariant [committed_or_invalid]
  ∀ v s,
    committedTxId v s -> Not (invalidTxId v s)

invariant [once_committed_previous_is_committed]
  ∀ committedView committedSeq status,
    And (committedTxId committedView committedSeq)
      (And (statusEvent status)
        (And (eventView status = committedView)
          (seqOrder.le (eventSeqno status) committedSeq))) ->
      committedStatusEvent status

invariant [once_committed_older_view_suffix_is_invalid]
  ∀ committedView committedSeq status,
    And (committedTxId committedView committedSeq)
      (And (statusEvent status)
        (And (viewLt (eventView status) committedView)
          (seqOrder.le committedSeq (eventSeqno status)))) ->
      invalidStatusEvent status

invariant [once_invalid_same_view_suffix_is_invalid]
  ∀ invalidView invalidSeq status,
    And (invalidTxId invalidView invalidSeq)
      (And (statusEvent status)
        (And (eventView status = invalidView)
          (seqOrder.le invalidSeq (eventSeqno status)))) ->
      invalidStatusEvent status

invariant [all_committed_observed]
  ∀ earlier request response,
    And (rwResponseCommitted earlier)
      (And (rwRequestEvent request)
        (And (rwResponseCommitted response)
          (And (eventTx request = eventTx response)
            (eventLt earlier request)))) ->
      observes response (eventTx earlier)

invariant [committed_rw_serializable]
  ∀ left right,
    And (rwResponseCommitted left) (rwResponseCommitted right) ->
      Or (observationsSubset left right) (observationsSubset right left)

invariant [at_most_once_observed]
  ∀ response leftSlot rightSlot observed,
    And (observedAt response leftSlot observed)
      (observedAt response rightSlot observed) ->
      leftSlot = rightSlot

-- This real-time clause follows the prose definition in the TLA+ source:
-- both endpoints are committed read-write responses.
safety [committed_rw_ordered_real_time]
  ∀ earlier request later,
    And (rwResponseCommitted earlier)
      (And (rwRequestEvent request)
        (And (rwResponseCommitted later)
          (And (eventTx request = eventTx later)
            (eventLt earlier request)))) ->
      txIdLt earlier later

-- CommittedRwOrderedSerializableInv is intentionally excluded. Its exact
-- append-by-one condition has a reachable counterexample when an intervening
-- write executes without a response or status; see README.md.

-- END CCF VEIL PROPERTIES
#gen_spec

-- This checked-in block is the deductive proof of every declared invariant and
-- safety property. Correspondence and trace tooling replace the marked block
-- with their own finite checks in ignored scratch copies of this source.
-- BEGIN CCF VEIL BOUNDED CHECK
#check_invariants
#gen_theorems

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
  Lean.logInfo m!"Audited {checked} CCFConsistency theorems for sorryAx."
-- END CCF VEIL BOUNDED CHECK

end CCFConsistency
