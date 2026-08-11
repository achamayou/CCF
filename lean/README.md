# CCF consistency in pure Lean

This directory is a standalone Lean 4 and Mathlib translation of the CCF
consistency specification in `tla/consistency`, covering `ExternalHistory.tla`,
`ExternalHistoryInvars.tla`, `SingleNode.tla`, `SingleNodeReads.tla`,
`MultiNode.tla` and `MultiNodeReads.tla`. It does not invoke an SMT solver and
does not model the consensus protocol in `tla/consensus`. The TLA+ refinement
tower is flattened into a single transition system.

The model is unbounded: transactions, views, sequence numbers, and history
events are abstract ordered types, and the final theorem quantifies over every
state reachable through the ordinary Lean `Step` relation.

All 35 invariants and the one safety property of the TLA+ specification are proved for every
reachable state, with no remaining assumptions or open cases.

## Contents

- `CCFConsistency/Model.lean` defines the state, derived predicates,
  initializer, all ten actions, `Step`, and `Reachable`.
- `CCFConsistency/Properties.lean` translates all 35 invariants and the
  one safety property of the TLA+ specification.
- `CCFConsistency/Proofs.lean` proves initialization, action preservation, and
  the complete reachable-state result described below.
- `CCFConsistency/TraceInfra.lean` is the model-independent half of trace
  replay: finite domains, decidable quantifiers over them, and the replay
  engine with its reachability theorems. It could be reused by any other
  specification.
- `CCFConsistency/Trace.lean` is the CCF-specific half: decidability instances
  for the model's derived predicates, the action guards, and the proof that an
  enabled action is a canonical `Step`.
- `CCFConsistency/Examples.lean` constructs a concrete request, execute, and
  response path over `Nat` to rule out vacuous guards.
- `trace_planner.py` parses an implementation trace and plans the unlogged
  internal actions it implies.
- `trace_validation.py` renders that plan as a kernel-checked Lean replay proof
  and compiles it.
- `COMPARISON.md` compares this development with the original TLA+ specification
  in `tla/consistency`: line counts by category, what each approach establishes,
  and a readability assessment.

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

`trace_planner.py` performs strict NDJSON schema checking, rank normalisation,
unlogged ledger backfill, and view-change reconstruction, and produces an exact
list of steps. `trace_validation.py` renders that plan as one typed list of the
ten `TraceAction` constructors over finite `Fin` domains, then compiles it.

The implementation logs only client-visible events, so the planner exists to
supply what a model checker would otherwise search for. See "Why a planner is
needed" below.

### Why there is nothing to audit in the guard evaluation

`Model.State` stores relations as `Bool` functions, so the ten transition
functions used by the unbounded proofs are executable and `TraceAction.next`
calls those exact functions. There is no second trace state, mirrored
transition implementation, projection, or transition equivalence layer.

The guards are handled the same way. The model's derived predicates quantify
over abstract domains, so they cannot be evaluated as they stand. Rather than
restate each one as a hand-written Boolean twin, which a reader would then have
to check against the original, `TraceInfra.lean` supplies `Decidable` instances
for quantifiers over an enumerable domain and `Trace.lean` derives decidability
for each predicate from its own definition:

```lean
instance ... : Decidable (state.nextTx tx) := by
  unfold nextTx
  infer_instance
```

Replay then evaluates `decide (action.Enabled state)`. Since every instance is
inferred from the predicate it decides, no instance can disagree with the
model, and no soundness lemma is needed to check that it does not.

What remains to audit in `Trace.lean` is one correspondence: that `Enabled` and
`next` match the hypotheses and conclusion of the matching `Step` constructor
in `Model.lean`. `TraceAction.enabled_step` states exactly that, and the
compiler checks it.

The generated module then:

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

Deciding a guard reduces through instance terms rather than through a direct
chain of Boolean operators, which costs replay time: the current 73-event
trace takes roughly 35 seconds instead of roughly 15. That is comfortably below
the cost of the library build itself, and it buys the removal of roughly 400
lines of hand-written Boolean mirrors and soundness lemmas that previously had
to be trusted by inspection.

### Why a planner is needed

TLC can validate the same trace with `tla/consistency/TraceMultiNodeReads.tla`
in far fewer lines, because it reads the NDJSON itself and *searches* for the
internal actions the implementation never logs: ledger appends for transactions
it did not report, and the view changes implied by a jump in transaction
identifiers.

Replay in Lean is a deterministic fold over a list of actions, so there is no
search. Something must decide in advance which unlogged actions occurred and
where, which is exactly what `trace_planner.py` does. The cost is a planner
outside the proof; the benefit is that a successful replay is a theorem rather
than a tool's report.

Continuous verification downloads the same fresh implementation trace artifact
used by TLC, builds the pure Lean library, tests the generator, and
compiles this generated replay proof.

## What is proved

Every one of the 36 translated clauses holds in every reachable state. The
exported theorem is:

```lean
theorem reachableProved
    (reachable : Reachable state) :
    PropertyBundle state
```

`PropertyBundle` is the complete translation of all 35 invariants and the
one safety property of the TLA+ specification, so nothing is left assumed or omitted. The result
holds over abstract and potentially infinite domains.

`initialProperties` proves all 36 clauses for `initialState`. The preservation
argument is built as a tower of inductive bundles, each one preserved by all
ten actions and lifted to every reachable state:

| Bundle              | Clauses | Adds                                                                       | Lifted by             |
| ------------------- | ------- | -------------------------------------------------------------------------- | --------------------- |
| `StructuralBundle`  | 14      | history, ledger and response shape                                          | (inside `CoreBundle`) |
| `CoreBundle`        | 17      | client-entry origin, monotone origin views, ledger prefix origin            | `reachableCore`       |
| `ProvenanceBundle`  | 20      | stable copied transaction ids, entry request provenance, unique requests    | `reachableProvenance` |
| `ResponseBundle`    | 22      | request-before-observation ordering, one response per transaction           | `reachableResponses`  |
| `StatusBundle`      | 24      | status provenance, existence of a current view                              | `reachableStatuses`   |
| `CommitBundle`      | 25      | the keystone: the current view holds every committed entry                  | `reachableCommits`    |
| `ClosureBundle`     | 29      | commit and invalid exclusivity, the three commit-status closure clauses     | `reachableClosure`    |

Two of those clauses, `UniqueResponseTxs` and `HasCurrentView`, are auxiliary
strengthenings rather than translated invariants, which is why the bundle
sizes run ahead of the count of translated clauses.

The remaining nine translated properties are logical consequences of that
inductive core rather than separate inductions:

- `coreUniqueRwTxs`
- `coreSameObservations`
- `provenanceAtMostOnceObserved`
- `responsesUniqueTxIds`
- `commitsCommittedResponseMatchesCurrentLedger`
- `commitsUniqueCommittedSeqnos`
- `commitsCommittedRwSerializable`
- `commitsAllCommittedObserved`
- `commitsCommittedRwOrderedRealTime`

| Action                    | Preserves all 29 closure clauses |
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

Every row is proved for every reachable state. "Proved" means preservation by
all ten actions inside one of the inductive bundles; "Proved from ..." means the
clause is a logical consequence of a bundle rather than a separate induction.
No assumption, admitted case or open obligation is used anywhere.

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
| `OnceCommittedPreviousIsCommitted`      | Proved                     |
| `OnceCommittedOlderViewSuffixIsInvalid` | Proved                     |
| `OnceInvalidSameViewSuffixIsInvalid`    | Proved                     |
| `AllCommittedObserved`                  | Proved from the commits    |
| `CommittedRwSerializable`               | Proved from the commits    |
| `AtMostOnceObserved`                    | Proved from the provenance |
| `CommittedRwOrderedRealTime`            | Proved from the commits    |

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

## How the closure layer closes

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
cases. Their `statusCommittedResponse` cases instead use the `notInvalid`
guard: a status event in the same view at or below the newly committed slot
cannot be invalid, so it must be committed.

`OnceCommittedOlderViewSuffixIsInvalid` uses `entryViewMonotoneAt` against the
`statusCommittedResponse` guard in both directions. If a status event in a
strictly older view sat at or above the newly committed slot and were itself
committed, the keystone clause would place both in the current view, and origin
views increase along a branch, so the older view would have to be at least the
newer one. That contradiction leaves only the invalid classification.

All eight non-status actions go through `closureOfStatusPreserving`, which
observes that the four clauses only inspect status events and their transaction
identifiers, so they survive any action that leaves the status relations alone
and rewrites `eventView` and `eventSeqno` only at unclassified events.

## How the client-facing properties close

The last three clauses are the ones a CCF user actually cares about, and all
three reduce to a single real-time fact, `committedResponseSeqnoLt`: a committed
response that completes before a request is sent occupies a strictly earlier
ledger slot than the committed response to that request.

That lemma is proved by contradiction, and the contradiction is supplied by the
response layer rather than by any new induction. Suppose the later response sat
at or below the earlier response's slot. Both committed responses live in the
current view, so `LedgerPrefixMatchesFrontierOrigin` moves the later response's
client entry down into the earlier response's own view. The earlier response
would therefore have *observed* the later transaction, and
`OnlyObserveSentRequests` puts the request for an observed transaction strictly
before the observing response. `UniqueTxRequests` identifies that request with
the given one, so the request would precede the earlier response, contradicting
the real-time hypothesis.

From there:

- `commitsCommittedRwOrderedRealTime` combines the slot ordering with
  `entryViewMonotoneAt`: a strictly earlier slot in the current view forces a
  no-later origin view, which is exactly `txIdLt`.
- `commitsAllCommittedObserved` reads the earlier response's own slot back out
  of the later response's prefix, again through
  `LedgerPrefixMatchesFrontierOrigin`.
- `commitsCommittedRwSerializable` needs no real-time reasoning at all. Both
  committed responses read prefixes of the same current view, so whichever has
  the smaller frontier observes a subset (`observationsSubsetOfSeqnoLe`).

## Possible next steps

The translated specification is fully proved, so the remaining work is about
reducing the trusted surface rather than closing obligations:

1. Establish a machine-checked correspondence between the TLA+ modules and this
   hand-written transition system, replacing the manual translation argument
   recorded below.
2. Generalise the trace validator to check partial or streaming traces without
   regenerating the whole replay module.
3. Explore whether the same bundle tower can be reused for a refinement proof
   against a lower-level model.

## Trust and correspondence

- Proof terms are checked by Lean's kernel. Mathlib tactics are proof
  producers, not trusted solvers.
- No `sorry`, custom axiom, trusted invariant, heartbeat override, or external
  solver answer is present.
- Proofs may expose Lean's standard `Classical.choice`, `propext`, or quotient
  axioms in `#print axioms`; the build separately rejects `sorryAx`.
- Trace replay success is reduced by the Lean kernel. The generated proof does
  not rely on the native compiler evaluation axiom.
- The definitions were translated by hand from the TLA+ modules listed at the
  top of this file, including action guards and simultaneous old-state reads.
- There is not yet a machine-checked equivalence theorem between the TLA+
  specification and this Lean transition system. The TLA+ modules in
  `tla/consistency` remain the canonical specification, and this development is
  a cross-check on them rather than a replacement.

## Corrections applied to the TLA+ source

Three definitions in `ExternalHistoryInvars.tla` could not be translated as
written. They are recorded here because they are findings about the TLA+
specification, not about this translation.

- `CommittedRwOrderedRealTimeInv` describes two committed read-write
  transactions, but its innermost quantifier ranges over read-only responses.
  `CommittedRwOrderedRealTime` here ranges over read-write responses.
- `InvalidNotObservedByCommittedInv` compares a transaction identifier with an
  entire history record and does not associate its invalid status with the
  candidate invalid response. The apparent intended correction is not an
  invariant of the transition system: an uncommitted transaction may be
  declared invalid, copied into a new view, observed by a later transaction,
  and that later transaction may commit. This development therefore does not
  assert the clause. Resolving it requires either weakening the intended
  property or strengthening the commit rule.
- `CommittedRwOrderedSerializableInv` assumes consecutive known-committed
  responses differ by exactly one observed write. A third write may execute
  between them without receiving a response or status, so the later response
  also observes that write. The counterexample needs three transactions, three
  ledger positions, seven history events and ten transitions; existing TLC
  configurations check this property with a history limit of six and so do not
  reach it. `CommittedRwSerializable` here states the subset-ordering form that
  does hold.

The first and third are the clearest evidence that a typed translation is
worth doing independently of the unbounded proof: both survived model checking.
