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
- `CCFConsistency/Examples.lean` constructs a concrete request, execute, and
  response path over `Nat` to rule out vacuous guards.
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

## What is proved

`initialProperties` proves all 36 translated clauses for `initialState`.

`stepPreservesCore` proves that every one of the ten actions preserves the
17-clause `CoreBundle`. `reachableCore` lifts that result to every reachable
state. Two additional full-spec properties are logical consequences of that
core:

- `coreUniqueRwTxs`
- `coreSameObservations`

The exported fixed-point theorem is:

```lean
theorem reachableProved
    (reachable : Reachable state) :
    ProvedBundle state
```

It establishes 19 of the 36 translated properties for all reachable states,
over abstract and potentially infinite domains.

| Action                    | Preserves all 17 core clauses |
| ------------------------- | ----------------------------- |
| `rwTxRequest`             | Proved                        |
| `roTxRequest`             | Proved                        |
| `rwTxExecute`             | Proved                        |
| `appendOtherTxn`          | Proved                        |
| `rwTxResponse`            | Proved                        |
| `roTxResponse`            | Proved                        |
| `statusCommittedResponse` | Proved                        |
| `statusInvalidResponse`   | Proved                        |
| `truncateLedger`          | Proved                        |
| `truncateLedgerToEmpty`   | Proved                        |

## Exact property coverage

All rows have a proved initializer. "Proved" means preservation by all ten
actions and an exported reachable-state theorem, either directly through
`CoreBundle` or as a consequence of it. "Open" means all ten preservation
cases remain outside the exported theorem; no assumption is used in their
place.

| Lean property                           | Reachable-state status |
| --------------------------------------- | ---------------------- |
| `HistoryTypeOk`                         | Proved                 |
| `HistoryEventKindUnique`                | Proved                 |
| `HistoryIsPrefix`                       | Proved                 |
| `ActiveViewsArePrefix`                  | Proved                 |
| `LedgerTypeOk`                          | Proved                 |
| `ClientEntriesAreLedgerEntries`         | Proved                 |
| `LedgerIsPrefix`                        | Proved                 |
| `LedgerTxIdsAreStableAcrossCopies`      | Open                   |
| `LedgerEntryExistsInOriginView`         | Proved                 |
| `ResponseFrontierIsLedgerEntry`         | Proved                 |
| `ClientEntryHasRequest`                 | Open                   |
| `ClientEntryMatchesOrigin`              | Proved                 |
| `LedgerEntryViewsAreMonotonic`          | Proved                 |
| `LedgerPrefixMatchesFrontierOrigin`     | Proved                 |
| `ResponseBranchIsView`                  | Proved                 |
| `ResponseFrontierMatchesOrigin`         | Proved                 |
| `RwResponseMatchesLedgerEntry`          | Proved                 |
| `StatusHasRwResponse`                   | Open                   |
| `CommittedIdIsInCurrentLedger`          | Open                   |
| `CommittedResponseMatchesCurrentLedger` | Open                   |
| `AllReceivedAfterSent`                  | Proved                 |
| `UniqueTxRequests`                      | Open                   |
| `OnlyObserveSentRequests`               | Open                   |
| `ObservationsAreWithinResponsePrefix`   | Proved                 |
| `UniqueRwTxs`                           | Proved from the core   |
| `SameObservations`                      | Proved from the core   |
| `UniqueTxIds`                           | Open                   |
| `UniqueCommittedSeqnos`                 | Open                   |
| `CommittedOrInvalid`                    | Open                   |
| `OnceCommittedPreviousIsCommitted`      | Open                   |
| `OnceCommittedOlderViewSuffixIsInvalid` | Open                   |
| `OnceInvalidSameViewSuffixIsInvalid`    | Open                   |
| `AllCommittedObserved`                  | Open                   |
| `CommittedRwSerializable`               | Open                   |
| `AtMostOnceObserved`                    | Open                   |
| `CommittedRwOrderedRealTime`            | Open                   |

## Fixed-point boundary

The smallest representative open preservation obligation is the new-ledger
entry case of:

```lean
theorem rwTxExecutePreservesStableCopies
    (properties : PropertyBundle state)
    (requestIsRw : state.rwRequestEvent request)
    (txNotInLedger : Not (state.txInLedger (state.eventTx request)))
    (branchIsActive : state.activeView branch)
    (nextSlot : state.nextLedgerSlot branch slot) :
    LedgerTxIdsAreStableAcrossCopies
      (rwTxExecuteNext state request branch slot)
```

Its proof must split both compared entries around the newly written point and
use `txNotInLedger` to exclude an old equal transaction. Completing it is only
the start of a second, mutually supporting layer: request provenance, request
uniqueness, status closure, commit/invalid monotonicity, observation
uniqueness, serializability, and the real-time safety clause depend on one
another across response, status, and truncation actions.

No theorem in this project claims those 17 open properties.

## Trust and correspondence

- Proof terms are checked by Lean's kernel. Mathlib tactics are proof
  producers, not trusted solvers.
- No `sorry`, custom axiom, trusted invariant, heartbeat override, or external
  solver answer is present.
- Classical reasoning used by functional updates may expose Lean's standard
  `Classical.choice`, `propext`, or quotient axioms in `#print axioms`; the
  build separately rejects `sorryAx`.
- The definitions were translated directly from the Veil model, including
  action guards and simultaneous old-state reads.
- There is not yet a machine-checked equivalence theorem between the Veil DSL
  elaboration and this hand-written Lean transition system. The Veil model
  remains the canonical checked-in specification and CI gate.

## Next proof layers

1. Prove stable copied transaction IDs, client-entry request provenance, and
   unique requests as one preservation bundle.
2. Add status provenance and current-ledger commit facts.
3. Prove commit/invalid closure and observation uniqueness.
4. Derive serializability and `CommittedRwOrderedRealTime`, then replace
   `ProvedBundle` with the complete `PropertyBundle` in the reachable theorem.
