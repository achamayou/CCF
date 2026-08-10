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
`reachableCore` and `reachableProvenance` lift those results to every reachable
state. Three further full-spec properties are logical consequences of that
inductive core:

- `coreUniqueRwTxs`
- `coreSameObservations`
- `provenanceAtMostOnceObserved`

The exported fixed-point theorem is:

```lean
theorem reachableProved
    (reachable : Reachable state) :
    ProvedBundle state
```

It establishes 23 of the 36 translated properties for all reachable states,
over abstract and potentially infinite domains.

| Action                    | Preserves all 20 provenance clauses |
| ------------------------- | ----------------------------------- |
| `rwTxRequest`             | Proved                              |
| `roTxRequest`             | Proved                              |
| `rwTxExecute`             | Proved                              |
| `appendOtherTxn`          | Proved                              |
| `rwTxResponse`            | Proved                              |
| `roTxResponse`            | Proved                              |
| `statusCommittedResponse` | Proved                              |
| `statusInvalidResponse`   | Proved                              |
| `truncateLedger`          | Proved                              |
| `truncateLedgerToEmpty`   | Proved                              |

## Exact property coverage

All rows have a proved initializer. "Proved" means preservation by all ten
actions and an exported reachable-state theorem, either directly through
`ProvenanceBundle` or as a consequence of it. "Open" means all ten preservation
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
| `OnlyObserveSentRequests`               | Open                       |
| `ObservationsAreWithinResponsePrefix`   | Proved                     |
| `UniqueRwTxs`                           | Proved from the core       |
| `SameObservations`                      | Proved from the core       |
| `UniqueTxIds`                           | Open                       |
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

## Fixed-point boundary

The 13 remaining clauses form a single mutually dependent cluster around commit
status rather than a set of independent obligations. `StatusHasRwResponse`
needs status provenance across truncation; `CommittedIdIsInCurrentLedger` and
`CommittedResponseMatchesCurrentLedger` need the committed identifier to be
tracked through every view change; `CommittedOrInvalid` and the three
`Once...` clauses need commit and invalid closure to be maintained together;
and `AllCommittedObserved`, `CommittedRwSerializable`,
`CommittedRwOrderedRealTime`, `UniqueTxIds`, `UniqueCommittedSeqnos`, and
`OnlyObserveSentRequests` all rest on a real-time ordering fact that the
current state does not yet record: that a client entry is written only after
its request event.

No theorem in this project claims those 13 open properties.

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

1. Record request/entry real-time ordering as an inductive clause: a client
   entry is written only after its request event. This is the missing fact
   behind `OnlyObserveSentRequests` and the ordering clauses.
2. Add a response-transaction uniqueness clause, carried by the `notResponded`
   guard, and derive `UniqueTxIds` from it.
3. Add status provenance and current-ledger commit facts
   (`StatusHasRwResponse`, `CommittedIdIsInCurrentLedger`,
   `CommittedResponseMatchesCurrentLedger`), which need the committed
   identifier tracked through `truncateLedger`.
4. Prove commit/invalid closure (`CommittedOrInvalid` and the three `Once...`
   clauses) as one bundle.
5. Derive serializability and `CommittedRwOrderedRealTime`, then replace
   `ProvedBundle` with the complete `PropertyBundle` in the reachable theorem.
