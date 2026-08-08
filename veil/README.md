# CCF consistency in Veil

`CCFConsistency.lean` is a single-level Veil model of the client-visible CCF
consistency specification. It consolidates the state and transitions from
`ExternalHistory.tla`, `SingleNode.tla`, `SingleNodeReads.tla`,
`MultiNode.tla`, and `MultiNodeReads.tla`. It does not model the consensus
protocol in `tla/consensus`.

Veil is embedded in Lean, so the specification has a `.lean` extension rather
than a `.veil` extension. This project pins the Veil 2.0 preview revision
`2ccca695fe62d2e488da8725a747972c2f115a61` and its Lean toolchain because the
preview language is still changing.

## Model correspondence

| TLA+ concept                                                 | Veil representation                                                                                                                                  |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `history` sequence                                           | Ordered `histEvent` domain whose used elements form a prefix                                                                                         |
| `ledgerBranches` sequence of sequences                       | Ordered active `view` prefix and an occupied `seqno` prefix per view                                                                                 |
| Optional client transaction in a ledger entry                | `clientEntry` plus `entryTx`                                                                                                                         |
| Response `observed` sequence                                 | `eventBranch` records the immutable branch where the final entry originated; `observedAt response ledger_position tx` derives the client-only prefix |
| `RwTxRequestAction`, execution, response, and status actions | Actions with the same names                                                                                                                          |
| `AppendOtherTxnAction`                                       | `AppendOtherTxnAction`                                                                                                                               |
| Empty/non-empty choices in `TruncateLedgerAction`            | Two Veil actions, as Veil models disjuncts as separate actions                                                                                       |
| `ExternalHistoryInvars`                                      | Named Veil invariants and the ordered real-time `safety` clause, excluding the unresolved and false clauses below                                   |
| TLC finite bounds                                            | Concrete `Fin` instantiations in `#model_check`                                                                                                      |

The order domains are abstract in the specification and finite only in the
embedded model-check command. Their first elements have rank zero. A concrete
trace validator should rank-normalise transaction IDs, views, sequence
numbers, and external events rather than assume that CCF's numeric IDs begin
at the same value.

Three definitions in `ExternalHistoryInvars.tla` need resolution:

- `CommittedRwOrderedRealTimeInv` describes two committed read-write
  transactions, but its innermost quantifier ranges over read-only responses.
  `committed_rw_ordered_real_time` ranges over read-write responses.
- `InvalidNotObservedByCommittedInv` compares a transaction ID with an entire
  history record and does not associate its invalid status with the candidate
  invalid response. The apparent intended correction is not an invariant of
  the existing transition system: an uncommitted transaction may be declared
  invalid, copied into a new view, observed by a later transaction, and that
  later transaction may commit. The Veil model therefore does not assert this
  malformed/vacuous TLA+ clause. Resolving it requires either weakening the
  intended property or strengthening the commit rule.
- `CommittedRwOrderedSerializableInv` assumes consecutive known-committed
  responses differ by exactly one observed write. A third write may execute
  between them without receiving a response or status, so the later response
  also observes that write. The property is excluded from the normal TLA+ and
  Veil safety sets. A dedicated expected-counterexample TLC configuration
  checks the ten-action witness in continuous verification. See
  [`CommittedRwOrderedSerializableCounterexample.md`](../tla/consistency/CommittedRwOrderedSerializableCounterexample.md)
  for the complete trace, explanation, history, and TLC reproduction.

## Run the bounded check

Veil currently supports Linux and macOS; use WSL2 on Windows. Install Node.js
24 and `elan`, then run:

```bash
cd veil
lake exe cache get
lake build
```

The checked-in `#model_check` is deliberately a small smoke configuration:
two transactions, views, and ledger positions, six external events, and depth
fourteen. Internal ledger and view actions consume depth without consuming a
history event, so useful configurations generally need
`maxDepth >= 2 * |histEvent| + |view|`. Veil's explicit-state checker is useful
for testing finite instances but is not a proof for arbitrary scopes.

## Bounded TLC correspondence

`bounded_correspondence.py` checks an action-aligned finite instance against
TLC. Run it from the repository root after installing the pinned TLC
dependencies:

```bash
python3 tla/install_deps.py
python3 veil/bounded_correspondence.py
```

The comparison uses `HistoryLimit = 3` and `ViewLimit = 2` in TLC, and
`tx := Fin 3`, `view := Fin 2`, `seqno := Fin 3`, and
`histEvent := Fin 3` in Veil. The TLC model-checking wrappers omit
`AppendOtherTxnAction`, so the script generates an ignored scratch copy of the
single Veil specification with only that action removed. Empty and non-empty
Veil truncation actions are combined under TLC's single truncation label.

Veil canonicalises fields that are not represented in TLA+: copied ledger
positions beyond the truncation point are reset, non-client entries have no
transaction value, and a response remembers the origin branch rather than
which identical copied branch replied. This makes each bounded Veil state
correspond to one TLC `history`/`ledgerBranches` state.

The complete fixed-point comparison is:

| Measure                                 |                               TLC |                              Veil |
| --------------------------------------- | --------------------------------: | --------------------------------: |
| Generated states                        |                               580 |                               580 |
| Distinct states                         |                               341 |                               341 |
| Cumulative states at depths 0 through 7 | `1, 4, 11, 31, 78, 172, 281, 341` | `1, 4, 11, 31, 78, 172, 281, 341` |

| Action              | Transitions in each model |
| ------------------- | ------------------------: |
| Read-only request   |                        52 |
| Read-only response  |                        10 |
| Read-write request  |                        52 |
| Read-write execute  |                       248 |
| Read-write response |                        61 |
| Committed status    |                         3 |
| Invalid status      |                         2 |
| Ledger truncation   |                       151 |

This is exact bounded graph-statistics correspondence at this scope, including
every BFS layer and action total. It is strong evidence for the translation,
but it is not an unbounded equivalence proof or a direct comparison of every
source/target state pair.

## Proposed model-checking progression

1. Extend the bounded comparison to history four, then to three views. Export
   canonical state and labelled-edge digests from both checkers so later runs
   compare the actual projected graph rather than its layer and action totals.
   Add a bounded TLC counterpart of `AppendOtherTxnAction` to compare the full
   Veil action set without making the TLC ledger unbounded.
2. Fix and re-run the TLA+ real-time invariant. Keep the checked
   three-transaction ordered-serialization counterexample as a regression
   while defining any replacement property.
3. Expand the Linux CI matrix. Increase `Fin` scopes and `maxDepth` independently
   so failures identify whether transactions, views, sequence numbers, or
   history length exposed the counterexample. Pin both the Veil revision and
   Lean toolchain in CI. Add satisfiable reachability queries for a commit, an
   invalidation, multiple commits, and a view change, plus an expected
   counterexample for multi-node read-only linearizability. These prevent an
   over-constrained model from passing vacuously.
4. Move from bounded testing to proof. Run `#check_invariants`, inspect each
   counterexample to induction, and add only justified auxiliary invariants
   until the complete declared set is jointly inductive. Do not replace failed
   obligations with `trusted invariant`.
5. Mutate one guard at a time, such as permitting truncation below the commit
   point or committing an entry from another view, and require Veil to find
   the expected violation. This checks that the properties and finite scopes
   are not vacuous.
6. Exercise the stronger restricted models from the same source file. Disable
   view-change/invalidation actions to check the single-node-only invariants,
   and add a second initial-state mode corresponding to
   `MCMultiNodeReadsAlt.tla`. The checked-in smoke run represents the final
   `MultiNodeReads` transition system, not these restricted configurations.

## Implementation trace validation

`trace_validation.py` accepts the existing `tests/tvc.py` NDJSON format. It
schema-checks each line, rank-normalises sparse transaction IDs, views, and
sequence numbers, and plans the unlogged ledger and view backfill performed by
`TraceMultiNodeReads.tla`.

The generator creates an ignored scratch copy of `CCFConsistency.lean` and
injects a constrained `sat trace` query inside the defining Veil module. A
separate module cannot import and extend a specification after `#gen_spec`.
Each logged action is followed by assertions fixing its event and transaction
ID. The final assertion requires every finite history event to be used, which
prevents a shorter prefix from satisfying the query.

Missing ledger entries use `AppendOtherTxnAction`. View changes use a generated
finite-domain `TraceTruncateLedgerAction` that copies every ranked sequence
position explicitly. This is equivalent to the base truncation action over the
trace's exhausted finite sequence domain, while avoiding a current Veil
symbolic-simplification failure on bulk relation updates. It also resets
metadata outside the copied prefix, matching the canonical base state. The
scratch module raises the trace discharger's simplification and heartbeat
budgets; these changes do not affect the checked-in protocol model.

Run the unit tests and the two end-to-end fixtures with:

```bash
cd veil
python3 -m unittest
python3 trace_validation.py testdata/one_write_trace.ndjson \
  --lean-output .generated/CCFConsistencyOneWriteTrace.lean \
  --trace-name one_write_trace
python3 trace_validation.py testdata/valid_trace.ndjson \
  --lean-output .generated/CCFConsistencyTrace.lean \
  --trace-name representative_trace
lake lean .generated/CCFConsistencyOneWriteTrace.lean
lake lean .generated/CCFConsistencyTrace.lean
```

The fixtures cover a committed write and a longer trace with a read,
non-client ledger backfill, a view change, and another commit. Continuous
verification runs both. TLC should remain the production trace-validation
oracle until the Veil adapter also accepts the historical implementation
corpus and rejects deliberately corrupted traces.
