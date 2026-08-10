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
"one response per transaction" clause. `reachableCore`,
`reachableProvenance`, and `reachableResponses` lift those results to every
reachable state. Four further full-spec properties are logical consequences of
that inductive core:

- `coreUniqueRwTxs`
- `coreSameObservations`
- `provenanceAtMostOnceObserved`
- `responsesUniqueTxIds`

The exported fixed-point theorem is:

```lean
theorem reachableProved
    (reachable : Reachable state) :
    ProvedBundle state
```

It establishes 25 of the 36 translated properties for all reachable states,
over abstract and potentially infinite domains. `ResponseBundle` also carries
`UniqueResponseTxs`, an auxiliary strengthening that is not itself one of the
36 translated clauses.

| Action                    | Preserves all 22 response clauses |
| ------------------------- | --------------------------------- |
| `rwTxRequest`             | Proved                            |
| `roTxRequest`             | Proved                            |
| `rwTxExecute`             | Proved                            |
| `appendOtherTxn`          | Proved                            |
| `rwTxResponse`            | Proved                            |
| `roTxResponse`            | Proved                            |
| `statusCommittedResponse` | Proved                            |
| `statusInvalidResponse`   | Proved                            |
| `truncateLedger`          | Proved                            |
| `truncateLedgerToEmpty`   | Proved                            |

## Exact property coverage

All rows have a proved initializer. "Proved" means preservation by all ten
actions and an exported reachable-state theorem, either directly through
`ResponseBundle` or as a consequence of it. "Open" means all ten preservation
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
| `StatusHasRwResponse`                   | Open                       |
| `CommittedIdIsInCurrentLedger`          | Open                       |
| `CommittedResponseMatchesCurrentLedger` | Open                       |
| `AllReceivedAfterSent`                  | Proved                     |
| `UniqueTxRequests`                      | Proved                     |
| `OnlyObserveSentRequests`               | Proved                     |
| `ObservationsAreWithinResponsePrefix`   | Proved                     |
| `UniqueRwTxs`                           | Proved from the core       |
| `SameObservations`                      | Proved from the core       |
| `UniqueTxIds`                           | Proved from the responses  |
| `UniqueCommittedSeqnos`                 | Open                       |
| `CommittedOrInvalid`                    | Open                       |
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

## Fixed-point boundary

The 11 remaining clauses form a single mutually dependent cluster around commit
status rather than a set of independent obligations. `StatusHasRwResponse`
needs status provenance across truncation; `CommittedIdIsInCurrentLedger` and
`CommittedResponseMatchesCurrentLedger` need the committed identifier to be
tracked through every view change; `CommittedOrInvalid` and the three
`Once...` clauses need commit and invalid closure to be maintained together;
and `AllCommittedObserved`, `CommittedRwSerializable`,
`CommittedRwOrderedRealTime`, and `UniqueCommittedSeqnos` all rest on those
commit facts.

No theorem in this project claims those 11 open properties.

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

1. Add status provenance (`StatusHasRwResponse`), which needs the response a
   status refers to to survive every view change.
2. Track the committed identifier through `truncateLedger`, giving
   `CommittedIdIsInCurrentLedger` and
   `CommittedResponseMatchesCurrentLedger`. The `validTruncationSource` guard
   is the fact to exploit: it keeps the maximum committed sequence number
   inside the retained prefix.
3. Prove commit/invalid closure (`CommittedOrInvalid` and the three `Once...`
   clauses) as one bundle, using the `notInvalid` guard on
   `statusCommittedResponse` and `invalidStatusAllowed` on
   `statusInvalidResponse`.
4. Derive `UniqueCommittedSeqnos`, `AllCommittedObserved`,
   `CommittedRwSerializable`, and `CommittedRwOrderedRealTime`, then replace
   `ProvedBundle` with the complete `PropertyBundle` in the reachable theorem.
