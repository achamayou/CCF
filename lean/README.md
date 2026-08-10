# CCF consistency in pure Lean

This directory is a standalone Lean 4 and Mathlib translation of
`veil/CCFConsistency.lean`. It does not import Veil, invoke an SMT solver, or
model CCF consensus.

The model is unbounded: transactions, views, sequence numbers, and history
events are abstract ordered types, and the final theorem quantifies over every
state reachable through the ordinary Lean `Step` relation.

## Contents

- `CCFConsistency/Model.lean` defines the state, derived predicates,
  initializer, all ten actions, `Step`, and `Reachable`.
- `CCFConsistency/Properties.lean` translates all 35 Veil invariants and the
  one Veil safety property.
- `CCFConsistency/Proofs.lean` proves initialization, action preservation, and
  the reachable-state result described below.
- `CCFConsistency/Trace.lean` evaluates finite action guards, calls the
  canonical transitions from `Model.lean`, and proves that each successful
  replay step is a canonical `Step`.
- `CCFConsistency/Examples.lean` constructs a concrete request, execute, and
  response path over `Nat` to rule out vacuous guards.
- `trace_validation.py` reuses the Veil trace planner to generate and check a
  proof for a fresh implementation trace.
- `PLAN.md` records the translation strategy and the proof-engineering fixed
  point.

## Build

Run Lean and Lake only from a WSL-native filesystem. Do not build this project
from `/mnt/c`, where Mathlib's file workload is prohibitively slow.

From a WSL-native clone or copy:

```bash
cd lean
lake build
```

`lean-toolchain`, `lakefile.toml`, and `lake-manifest.json` pin Lean 4.28.0,
Mathlib, and its transitive dependencies.

The library prints the axioms of `CCFConsistency.reachableProved` and audits
every theorem under the `CCFConsistency` namespace. The build fails if any
theorem transitively depends on `sorryAx`.

## Implementation trace validation

From the repository root, validate a generated consistency trace with:

```bash
python3 lean/trace_validation.py \
  build/consistency/trace.ndjson --validate
```

The validator imports `parse_trace` and `plan_trace` from
`veil/trace_validation.py`. Consequently, Veil and pure Lean use the same
strict NDJSON schema checks, rank normalization, unlogged ledger backfill, and
view-change reconstruction. The resulting plan is rendered as one typed list
of the ten pure Lean `TraceAction` constructors over finite `Fin` domains.

`Model.State` itself stores relations as `Bool` functions. The ten transition
functions used by the unbounded proofs are therefore executable, and
`TraceAction.next` calls those exact functions directly. There is no second
trace state, mirrored transition implementation, projection, or transition
equivalence layer. `Trace.lean` adds only finite Boolean evaluations of the
canonical guards and proves that an accepted guard constructs the corresponding
canonical `Step`. The generated module then:

1. reduces the complete deterministic replay with `decide +kernel`;
2. uses `replay_from_initial` to prove that the final canonical state is
   `Reachable`.

Trace validation deliberately stops at reachability. It does not import
`Proofs.lean` or reevaluate properties for the concrete path. The separate
library build checks the generic `reachableProved` theorem once; that theorem
then applies to every state produced by any successful replay.

The generated proof does not use `native_decide`; Lean's kernel checks the
reduction. It also audits the final reachability theorem for transitive
`sorryAx` dependencies. Generated modules are written below `lean/Generated/`
and are not checked in.

Continuous verification downloads the same fresh implementation trace artifact
used by TLC and Veil, builds the pure Lean library, tests the generator, and
compiles this generated replay proof.

## What is proved

`initialProperties` proves all 36 translated clauses for `initialState`.

`stepPreservesCore` proves that every one of the ten actions preserves the
17-clause `CoreBundle`. `stepPreservesProvenance` extends that to the 20-clause
`ProvenanceBundle`, which adds stable copied transaction identifiers,
client-entry request provenance, and unique request transactions.
`stepPreservesResponses` extends it again to the 22-clause `ResponseBundle`,
which adds request-before-observation ordering and an auxiliary
"one response per transaction" clause. `stepPreservesStatuses` extends it once
more to the 24-clause `StatusBundle`, which adds status provenance and an
auxiliary "a current view exists" clause. `stepPreservesCommits` extends it to
the 25-clause `CommitBundle`, which adds the keystone commit clause, and
`stepPreservesClosure` extends it to the 26-clause `ClosureBundle`, which adds
commit and invalid exclusivity. `reachableCore`, `reachableProvenance`,
`reachableResponses`, `reachableStatuses`, `reachableCommits`, and
`reachableClosure` lift those results to every reachable state. Six further
full-spec properties are logical consequences of that inductive core:

- `coreUniqueRwTxs`
- `coreSameObservations`
- `provenanceAtMostOnceObserved`
- `responsesUniqueTxIds`
- `commitsCommittedResponseMatchesCurrentLedger`
- `commitsUniqueCommittedSeqnos`

The exported fixed-point theorem is:

```lean
theorem reachableProved
    (reachable : Reachable state) :
    ProvedBundle state
```

It establishes 30 of the 36 translated properties for all reachable states,
over abstract and potentially infinite domains. `ClosureBundle` also carries two
auxiliary strengthenings that are not themselves among the 36 translated
clauses: `UniqueResponseTxs` and `HasCurrentView`.

| Action                    | Preserves all 26 closure clauses |
| ------------------------- | -------------------------------- |
| `rwTxRequest`             | Proved                          |
| `roTxRequest`             | Proved                          |
| `rwTxExecute`             | Proved                          |
| `appendOtherTxn`          | Proved                          |
| `rwTxResponse`            | Proved                          |
| `roTxResponse`            | Proved                          |
| `statusCommittedResponse` | Proved                          |
| `statusInvalidResponse`   | Proved                          |
| `truncateLedger`          | Proved                          |
| `truncateLedgerToEmpty`   | Proved                          |

## Exact property coverage

All rows have a proved initializer. "Proved" means preservation by all ten
actions and an exported reachable-state theorem, either directly through
`ClosureBundle` or as a consequence of it. "Open" means all ten preservation
cases remain outside the exported theorem; no assumption is used in their
place.

| Lean property                           | Reachable-state status     |
| --------------------------------------- | -------------------------- |
| `HistoryTypeOk`                         | Proved                     |
| `HistoryEventKindUnique`                | Proved                     |
| `HistoryIsPrefix`                       | Proved                     |
| `ActiveViewsArePrefix`                  | Proved                     |
| `LedgerTypeOk`                          | Proved                     |
| `ClientEntriesAreLedgerEntries`         | Proved                     |
| `LedgerIsPrefix`                        | Proved                     |
| `LedgerTxIdsAreStableAcrossCopies`      | Proved                     |
| `LedgerEntryExistsInOriginView`         | Proved                     |
| `ResponseFrontierIsLedgerEntry`         | Proved                     |
| `ClientEntryHasRequest`                 | Proved                     |
| `ClientEntryMatchesOrigin`              | Proved                     |
| `LedgerEntryViewsAreMonotonic`          | Proved                     |
| `LedgerPrefixMatchesFrontierOrigin`     | Proved                     |
| `ResponseBranchIsView`                  | Proved                     |
| `ResponseFrontierMatchesOrigin`         | Proved                     |
| `RwResponseMatchesLedgerEntry`          | Proved                     |
| `StatusHasRwResponse`                   | Proved                     |
| `CommittedIdIsInCurrentLedger`          | Proved                     |
| `CommittedResponseMatchesCurrentLedger` | Proved from the commits    |
| `AllReceivedAfterSent`                  | Proved                     |
| `UniqueTxRequests`                      | Proved                     |
| `OnlyObserveSentRequests`               | Proved                     |
| `ObservationsAreWithinResponsePrefix`   | Proved                     |
| `UniqueRwTxs`                           | Proved from the core       |
| `SameObservations`                      | Proved from the core       |
| `UniqueTxIds`                           | Proved from the responses  |
| `UniqueCommittedSeqnos`                 | Proved from the commits    |
| `CommittedOrInvalid`                    | Proved                     |
| `OnceCommittedPreviousIsCommitted`      | Open                       |
| `OnceCommittedOlderViewSuffixIsInvalid` | Open                       |
| `OnceInvalidSameViewSuffixIsInvalid`    | Open                       |
| `AllCommittedObserved`                  | Open                       |
| `CommittedRwSerializable`               | Open                       |
| `AtMostOnceObserved`                    | Proved from the provenance |
| `CommittedRwOrderedRealTime`            | Open                       |

## How the provenance layer closes

The provenance clauses are inductive together, and each rests on an action
guard rather than on an assumption:

- `rwTxExecute` carries `txNotInLedger`, so the transaction it writes cannot
  already sit in a client entry. Comparing the new entry with any older entry
  is therefore impossible, and `LedgerTxIdsAreStableAcrossCopies` reduces to
  the induction hypothesis.
- `truncateLedger` copies a prefix of one branch into a fresh view. Every
  client entry of the truncated state is resolved back to the entry it was
  copied from, at the same slot and with the same origin view, so both
  provenance clauses transfer along the copy.
- `rwTxRequest` and `roTxRequest` carry `nextTx`, whose `Not (requested tx)`
  component gives `UniqueTxRequests` directly.
- Response and status actions only classify a fresh, unused history event, so
  every already-classified event keeps its transaction.

`AtMostOnceObserved` then needs no induction of its own: both observations of
one response sit in the branch `eventBranch response`, so stable copied
transaction identifiers force the two slots to coincide.

## How the response layer closes

`OnlyObserveSentRequests` states that everything a response observes was
requested strictly earlier. Two facts make it inductive:

- A ledger append never lands inside an existing response's prefix.
  `responseCannotReachNextSlot` derives this from `ResponseFrontierIsLedgerEntry`
  and `LedgerIsPrefix`: if an existing response could reach the slot that
  `nextLedgerSlot` is about to fill, that slot would already be a ledger entry,
  contradicting the guard. So `rwTxExecute` and `appendOtherTxn` never add an
  observation to an existing response.
- A new response observes only entries that already exist, and every used
  event precedes a fresh history event (`usedEventLtNext`). `ClientEntryHasRequest`
  from the provenance layer supplies the request, and it is used, so it
  precedes the new response.

`truncateLedger` is neutral here because an existing response reads an active
branch while the fresh view is not yet active, so no existing observation set
changes.

`UniqueResponseTxs` is maintained by the `notResponded` guard of both response
actions, and `UniqueTxIds` follows immediately: two responses carrying the same
transaction are the same event.

## How the status layer closes

`StatusHasRwResponse` needs only that a status event is created next to the
response it refers to. `statusCommittedResponse` and `statusInvalidResponse`
copy `eventView` and `eventSeqno` from their response and classify a fresh
event, so the response itself is the witness and `usedEventLtNext` orders it
first. No other action creates a status event or touches `eventView` and
`eventSeqno` at an already-classified event, so existing witnesses survive.

The layer also carries `HasCurrentView`, the auxiliary fact that a greatest
active view always exists. Every remaining commit clause is stated relative to
`currentView`, so without it those clauses are vacuous rather than meaningful.
It is preserved because a view change makes the fresh view active while
`ActiveViewsArePrefix` and `nextView` rule out any active view above it
(`nextViewIsCurrent`); all other actions leave `activeView` untouched
(`hasCurrentViewOfActiveEq`).

## How the commit layer closes

`CommittedIdIsInCurrentLedger` is the keystone: the current view contains every
committed entry, with a matching origin view. Its hard case is `truncateLedger`,
where the current view moves to a freshly copied one. The argument is:

1. The fresh view is the new current view (`nextViewIsCurrent`), and the current
   view is unique (`currentViewUnique`), so the goal is about the fresh view.
2. The `validTruncationSource` guard supplies a maximum committed sequence
   number `commitSeq` that lies at or below the cut and is present in `source`,
   together with `committedTxId (entryView source commitSeq) commitSeq`. So
   every committed slot is at or below the cut and survives the copy.
3. The remaining question is whether `source` and the outgoing current view
   agree on the origin view of a committed slot. They do, but not because
   active branches agree in general - they do not. Both agree at `commitSeq`
   itself: the source by the guard above, the outgoing current view by the
   induction hypothesis applied at `commitSeq`. `LedgerPrefixMatchesFrontierOrigin`
   then carries that agreement down from `commitSeq` to every committed slot on
   both sides, so the two origin views coincide.

Two more clauses then follow without any induction of their own:

- `CommittedResponseMatchesCurrentLedger` combines the keystone with
  `RwResponseMatchesLedgerEntry`, `ResponseBranchIsView`, and
  `LedgerPrefixMatchesFrontierOrigin` at the response's own frontier.
- `UniqueCommittedSeqnos` combines the keystone with the already proved
  `UniqueRwTxs`: two committed responses at the same sequence number read the
  same slot of the current view, so they have the same view, so they carry the
  same transaction. This is where `HasCurrentView` earns its place.

## Fixed-point boundary

The 6 remaining clauses are the two remaining commit-side `Once...` clauses,
the same-view invalid suffix clause, and the three client-facing consequences.

`CommittedOrInvalid` is proved by the single lemma
`noCommitAtOrAboveInvalidResponse`: each of the three disjuncts of
`invalidStatusAllowed` rules out a commit at the invalidated response's view,
for its own sequence number and every later one. The first disjunct is the
interesting one, and it needs the keystone commit clause together with
`LedgerPrefixMatchesFrontierOrigin` and `responseOriginViewEq` to contradict its
`entryView current` disequality.

That same lemma, applied at a later sequence number rather than at the
response's own, is what `OnceCommittedPreviousIsCommitted` and
`OnceInvalidSameViewSuffixIsInvalid` need for their `statusInvalidResponse`
cases. `OnceCommittedOlderViewSuffixIsInvalid` instead needs
`entryViewMonotoneAt` against the `statusCommittedResponse` guard. Both helper
lemmas are already proved here, so those three clauses are mechanical rather
than open-ended; they were left out only to keep this change reviewable.

`AllCommittedObserved`, `CommittedRwSerializable`, and
`CommittedRwOrderedRealTime` are the client-facing statements. They need the
closure clauses first, and then a further fact that the model does not yet
record inductively: that the ledger position of a committed response is
monotonic in the real-time order of the requests that produced them.

No theorem in this project claims those 6 open properties.

## Trust and correspondence

- Proof terms are checked by Lean's kernel. Mathlib tactics are proof
  producers, not trusted solvers.
- No `sorry`, custom axiom, trusted invariant, heartbeat override, or external
  solver answer is present.
- Proofs may expose Lean's standard `Classical.choice`, `propext`, or quotient
  axioms in `#print axioms`; the build separately rejects `sorryAx`.
- Trace replay success is reduced by the Lean kernel. The generated proof does
  not rely on the native compiler evaluation axiom.
- The definitions were translated directly from the Veil model, including
  action guards and simultaneous old-state reads.
- There is not yet a machine-checked equivalence theorem between the Veil DSL
  elaboration and this hand-written Lean transition system. The Veil model
  remains the canonical checked-in specification and CI gate.

## Next proof layers

1. Prove `OnceCommittedPreviousIsCommitted` and
   `OnceInvalidSameViewSuffixIsInvalid` from
   `noCommitAtOrAboveInvalidResponse`, applied at a later sequence number.
2. Prove `OnceCommittedOlderViewSuffixIsInvalid` from `entryViewMonotoneAt`
   against the `statusCommittedResponse` guard.
3. Record ledger-position monotonicity for committed responses relative to the
   real-time order of their requests.
4. Derive `AllCommittedObserved`, `CommittedRwSerializable`, and
   `CommittedRwOrderedRealTime`, then replace `ProvedBundle` with the complete
   `PropertyBundle` in the reachable theorem.
