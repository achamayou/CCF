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
| `ExternalHistoryInvars`                                      | Named Veil invariants and safety properties, except the documented false or malformed clauses below                                                  |
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
  also observes that write. This produces a counterexample with three
  transactions, three ledger positions, seven history events, and ten
  transitions. Existing TLC configurations check this property with a history
  limit of six and therefore do not reach the counterexample. The Veil model
  documents but does not assert this false clause. It remains excluded from
  bounded checks and deductive verification until the property or model is
  reconciled.

## Build and prove the specification

Veil currently supports Linux and macOS; use WSL2 on Windows. Install Node.js
24 and `elan`, then run:

```bash
cd veil
lake exe cache get
lake build
```

`lake build` runs the checked-in deductive proof described below. Finite model
checking is performed separately by the bounded correspondence harness.

## Bounded TLC correspondence

`bounded_correspondence.py` checks an action-aligned finite instance against
TLC. Run it from the repository root after installing the pinned TLC
dependencies:

```bash
python3 tla/install_deps.py
python3 veil/bounded_correspondence.py
```

The generated Veil runner reports its completed depth, generated and distinct
state counts, frontier size, elapsed time, and average throughput every 30
seconds while the check is running.

The comparison derives `HistoryLimit = 4` and `ViewLimit = 3` from the canonical
TLC configuration, and uses `tx := Fin 4`, `view := Fin 3`,
`seqno := Fin 4`, and `histEvent := Fin 4` in Veil. The TLC model-checking
wrappers omit `AppendOtherTxnAction`, so the script generates an ignored scratch
copy of the single Veil specification with only that action removed. Empty and
non-empty Veil truncation actions are combined under TLC's single truncation
label.

Veil canonicalises fields that are not represented in TLA+: copied ledger
positions beyond the truncation point are reset, non-client entries have no
transaction value, and a response remembers the origin branch rather than
which identical copied branch replied. This makes each bounded Veil state
correspond to one TLC `history`/`ledgerBranches` state.

The complete fixed-point comparison is:

| Measure                                  |                                                      TLC |                                                     Veil |
| ---------------------------------------- | -------------------------------------------------------: | -------------------------------------------------------: |
| Generated states                         |                                                   36,569 |                                                   36,569 |
| Distinct states                          |                                                   15,789 |                                                   15,789 |
| Cumulative states at depths 0 through 10 | `1, 4, 12, 34, 108, 356, 1077, 2996, 7145, 12429, 15789` | `1, 4, 12, 34, 108, 356, 1077, 2996, 7145, 12429, 15789` |

| Action              | Transitions in each model |
| ------------------- | ------------------------: |
| Read-only request   |                     1,419 |
| Read-only response  |                       697 |
| Read-write request  |                     1,419 |
| Read-write execute  |                    14,954 |
| Read-write response |                     4,206 |
| Committed status    |                       156 |
| Invalid status      |                        58 |
| Ledger truncation   |                    13,659 |

This is exact bounded graph-statistics correspondence at this scope, including
every BFS layer and action total. It is strong evidence for the translation,
but it is not an unbounded equivalence proof or a direct comparison of every
source/target state pair.

See [BOUNDED_CORRESPONDENCE.md](BOUNDED_CORRESPONDENCE.md) for the complete
scope, runtimes, prior and attempted larger runs, methodology, and precise
limits of this result.

## Proposed model-checking progression

1. Export canonical state and labelled-edge digests from both checkers so later
   runs compare the actual projected graph rather than its layer and action
   totals. Then extend the bounded comparison to a third view or fifth history
   event. Add a bounded TLC counterpart of `AppendOtherTxnAction` to compare the
   full Veil action set without making the TLC ledger unbounded.
2. Correct the excluded TLA+ ordered-serialization clause so it permits
   intervening ledger writes, then model-check the correction before adding it
   back to the Veil proof set.
3. Expand the Linux CI matrix. Increase `Fin` scopes and `maxDepth` independently
   so failures identify whether transactions, views, sequence numbers, or
   history length exposed the counterexample. Pin both the Veil revision and
   Lean toolchain in CI. Add satisfiable reachability queries for a commit, an
   invalidation, multiple commits, and a view change, plus an expected
   counterexample for multi-node read-only linearizability. These prevent an
   over-constrained model from passing vacuously.
4. Keep the complete deductive proof below in CI. When the model or a declared
   property changes, inspect any counterexample to induction and add only
   justified reachability invariants; never replace a failed obligation with
   `trusted invariant`.
5. Mutate one guard at a time, such as permitting truncation below the commit
   point or committing an entry from another view, and require Veil to find
   the expected violation. This checks that the properties and finite scopes
   are not vacuous.
6. Exercise the stronger restricted models from the same source file. Disable
   view-change/invalidation actions to check the single-node-only invariants,
   and add a second initial-state mode corresponding to
   `MCMultiNodeReadsAlt.tla`. The current bounded correspondence run represents
   the final `MultiNodeReads` transition system, not these restricted
   configurations.

## Deductive invariant proofs

The proof is checked in directly at the end of `CCFConsistency.lean`; it is not
generated by a script. The file sets `veil.smt.trust false`, so cvc5 results are
reconstructed as Lean proofs rather than accepted as trusted solver answers.
It then runs `#gen_theorems`, adding every successful verification condition to
the environment so Lean's kernel checks each reconstructed proof term. Finally,
it audits every theorem in the `CCFConsistency` namespace and fails if any
transitively depends on `sorryAx`. The file explicitly keeps
`veil.violationIsError` enabled, so an incomplete matrix cannot succeed by
materializing only its proven subset.

The complete proof covers 36 jointly inductive clauses. Initialization and all
ten actions establish or preserve every clause, and every action is also proved
to terminate successfully. This is 396 reconstructed invariant goals plus 11
successful-termination checks. The proof is independent of the finite `Fin`
scopes used by the executable model checker.

On 2026-08-09, `lake build CCFConsistency` completed the direct self-auditing
proof with exit code 0. Lean built the proof module in 1,130 seconds; the
complete command took 1,131.31 seconds and peaked at 9,841,332 KB of resident
memory. The final audit checked 864 theorems in the `CCFConsistency` namespace
without finding a transitive `sorryAx` dependency. The proof source contains no
trusted invariants, trusted SMT answers, custom axiom declarations, or `sorry`
declarations.

Check the complete initialization/action matrix directly with:

```bash
cd veil
lake build CCFConsistency
```

The twelve auxiliary invariants between
`ledger_entry_exists_in_origin_view` and
`committed_response_matches_current_ledger` make explicit the reachable
provenance and prefix relationships between ledger entries, requests,
responses, and statuses. They strengthen the joint induction hypothesis and
are proved across initialization and every action rather than assumed.

This proves the declared properties of the Veil transition system. It does not
prove unbounded equivalence with the TLA+ specification or validate the
implementation. The known-false `CommittedRwOrderedSerializableInv` and
malformed/false `InvalidNotObservedByCommittedInv` clauses are documented above
but intentionally not part of the proof matrix.

The proved external-history set establishes the three components of
`CommittedRwLinearizableInv`: committed read-write serializability, observation
of earlier committed writes, and at-most-once observation. It also proves the
corrected read-write real-time ordering clause. It does not establish the
stronger `CommittedRwOrderedSpecLinearizableInv` conjunction because its
ordered-serialization component is the known-false clause excluded above.

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

CI does not use checked-in NDJSON fixtures. It builds the real `js_generic`
application, runs `tests/consistency_trace_validation.py`, and forces a primary
election while `tests/tvc.py` issues a mix of reads and writes. TLC validates
the resulting `build/consistency/trace.ndjson` in that same job.

Generate the same trace locally with:

```bash
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug -DLONG_TESTS=ON
cmake --build build --target js_generic
(cd build && ./tests.sh -VV --timeout 180 \
  -R '^consistency_trace_validation$')
```

Validate it with TLC and generate the corresponding Veil query with:

```bash
(cd tla && JSON=../build/consistency/trace.ndjson \
  ./tlc.py --workers 1 tv --disable-dfs \
  consistency/TraceMultiNodeReads.tla)
python3 veil/trace_validation.py build/consistency/trace.ndjson \
  --lean-output veil/.generated/CCFConsistencyImplementationTrace.lean \
  --trace-name implementation_trace
```

Synthetic adapter behavior remains covered by Python unit tests, but every
continuous-verification run validates a fresh implementation trace rather than
a committed sample. Veil's current `sat trace` implementation encodes the
complete replay as one symbolic query, which is not yet practical for the full
implementation-generated trace. The generated Veil query is therefore
development tooling rather than a CI gate.
