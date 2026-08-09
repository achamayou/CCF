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
| TLC finite bounds                                            | Concrete `Fin` instantiations in a generated scratch `#model_check`                                                                                  |

The order domains remain abstract in the checked-in specification and are made
finite only in generated bounded-check or trace-replay copies. Their first
elements have rank zero. A concrete trace validator should rank-normalise
transaction IDs, views, sequence numbers, and external events rather than
assume that CCF's numeric IDs begin at the same value.

Three definitions in `ExternalHistoryInvars.tla` require correction or
exclusion in Veil:

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

The checked-in CI job uses Ubuntu 24.04, Node.js 24, Clang/LLD/libc++ 15, and
the Lean version pinned by `lean-toolchain`. Use the same Linux environment or
WSL2 on Windows. After installing the native dependencies, Node.js 24, and
`elan`, run:

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

The comparison derives a temporary TLC configuration from the canonical one,
setting `HistoryLimit = 4` and `ViewLimit = 3`, and uses `tx := Fin 4`,
`view := Fin 3`, `seqno := Fin 4`, and `histEvent := Fin 4` in Veil. The TLC
model-checking wrappers omit `AppendOtherTxnAction`, so the script generates an
ignored scratch copy of the single Veil specification with only that action
removed. Empty and non-empty Veil truncation actions are combined under TLC's
single truncation label.

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

## Remaining validation work

1. Export canonical state and labelled-edge digests from both checkers so later
   runs compare the actual projected graph rather than its layer and action
   totals. Then extend the bounded comparison to a fourth view or fifth history
   event. Add a bounded TLC counterpart of `AppendOtherTxnAction` to compare the
   full Veil action set without making the TLC ledger unbounded.
2. Correct the excluded TLA+ ordered-serialization clause so it permits
   intervening ledger writes, then model-check the correction before adding it
   back to the Veil proof set.
3. Expand the bounded Veil CI matrix. Increase `Fin` scopes and `maxDepth`
   independently so failures identify whether transactions, views, sequence
   numbers, or history length exposed the counterexample. Add Veil reachability
   queries corresponding to the existing TLC commit, invalidation,
   multiple-commit, and non-linearizable read checks, plus an explicit
   view-change query. These guard against an over-constrained model passing
   vacuously.
4. Mutate one guard at a time, such as permitting truncation below the commit
   point or committing an entry from another view, and require Veil to find
   the expected violation. This checks that the properties and finite scopes
   are not vacuous.
5. Exercise the stronger restricted models from the same source file. Disable
   view-change/invalidation actions to check the single-node-only invariants,
   and add a second initial-state mode corresponding to
   `MCMultiNodeReadsAlt.tla`. The current bounded correspondence run represents
   the final `MultiNodeReads` transition system, not these restricted
   configurations.

## Deductive invariant proofs

The proof is checked in directly at the end of `CCFConsistency.lean`; it is not
generated by a script. It is an unbounded, joint inductive proof over the
abstract ordered domains, independent of the finite `Fin` scopes used by the
bounded correspondence and trace tools.

### How the proof works

1. `#gen_spec` finalises the state, initializer, actions, and declared
   properties as one transition system.
2. `#check_invariants` constructs the complete joint-induction matrix. Each
   step may use all 36 clauses as its induction hypothesis, including the
   auxiliary reachability facts, but must re-establish every clause.
3. `veil.violationIsError true` makes any open or failed condition fail the
   build rather than allowing a proven subset to be materialized.
4. `veil.smt.trust false` makes Veil reconstruct each cvc5 result as a Lean
   proof term rather than accepting a trusted solver answer.
5. `#gen_theorems` adds the reconstructed verification conditions to the Lean
   environment, where the kernel checks their proof terms.
6. A final `Lean.collectAxioms` pass audits every theorem in the
   `CCFConsistency` namespace and fails if any theorem transitively depends on
   `sorryAx`. It also fails if no theorem was found, preventing an empty audit
   from succeeding.

The file declares 35 invariants and one safety property. The initializer and
all ten actions must establish or preserve every clause:

- `RwTxRequestAction` and `RoTxRequestAction` add ordered client requests.
- `RwTxExecuteAction` and `AppendOtherTxnAction` append client and non-client
  ledger entries.
- `RwTxResponseAction` and `RoTxResponseAction` return observations.
- `StatusCommittedResponseAction` and `StatusInvalidResponseAction` classify
  read-write responses.
- `TruncateLedgerAction` and `TruncateLedgerToEmptyAction` create a new view
  from a retained or empty ledger prefix.

This produces `36 * (1 initializer + 10 actions) = 396` reconstructed
preservation goals. Veil also checks successful termination for the initializer
and each action, adding 11 conditions, for 407 conditions in total. No declared
property or action is omitted from this matrix, including
`AppendOtherTxnAction` and both truncation actions.

### What is proved

The jointly proved clauses cover:

- History event typing, exclusive event kinds, request/response ordering, and
  history-prefix structure.
- Active-view and ledger-prefix structure, ledger-entry typing, stable
  transaction identities across branch copies, and client-entry provenance.
- Response frontier/origin consistency and the provenance of commit and
  invalid status events.
- Unique requests and transaction-ID assignments, consistent transactions and
  observations for responses sharing an ID, and a unique transaction at each
  committed sequence number.
- Mutual exclusion and monotonicity of committed and invalid statuses.
- The three components of `CommittedRwLinearizableInv`: committed read-write
  serializability, observation of earlier committed writes, and at-most-once
  observation.
- The corrected read-write real-time ordering property
  `committed_rw_ordered_real_time`.

The twelve auxiliary invariants from `ledger_entry_exists_in_origin_view`
through `committed_response_matches_current_ledger` make the reachable
provenance and prefix relationships between ledger entries, requests,
responses, and statuses explicit. They strengthen the joint induction
hypothesis, but are proved across initialization and every action rather than
assumed.

Types, state fields, ghost relations, and action bodies define the transition
system rather than separate claims. They are expanded and exercised by the
verification conditions, but the deductive proof does not independently prove
that these definitions are a faithful translation of TLA+ or the CCF
implementation.

### What is not proved

- `CommittedRwOrderedSerializableInv` is intentionally not declared. Its exact
  append-by-one condition has a reachable counterexample when an intervening
  write executes without receiving a response or status.
- `InvalidNotObservedByCommittedInv` is malformed as written in TLA+, and its
  apparent intended correction is also false for the current transition
  system.
- Consequently, the stronger
  `CommittedRwOrderedSpecLinearizableInv` conjunction is not established,
  although its corrected real-time component is proved.
- The proof establishes safety, not liveness or fairness. It does not prove
  that every action guard is satisfiable or that every modeled scenario is
  reachable; bounded checks and implementation traces provide separate
  non-vacuity evidence.
- It does not prove unbounded equivalence with the TLA+ specification, a
  refinement from the CCF implementation, or implementation trace conformance.
  The bounded correspondence and TLC trace validator provide separate evidence
  for those relationships.
- It does not cover CCF consensus, which is deliberately outside this
  consistency-only model.

The precise theorem-level claim is therefore: every declared invariant and
safety property holds in every reachable state for every instantiation of the
abstract ordered domains used by the `CCFConsistency` Veil transition system.

On 2026-08-09, `lake build CCFConsistency` completed the direct self-auditing
proof with exit code 0. Lean built the proof module in 1,130 seconds; the
complete command took 1,131.31 seconds and peaked at 9,841,332 KB of resident
memory. The final audit checked 864 theorems in the `CCFConsistency` namespace
without finding a transitive `sorryAx` dependency. The proof source contains no
trusted invariants, trusted SMT answers, custom axiom declarations, or `sorry`
declarations.

The 864 audited declarations include generated helper and verification
theorems; they are not 864 user-facing properties. The audit specifically rules
out transitive `sorryAx` dependencies rather than claiming that Lean's
foundational axioms or imported libraries are outside the trusted computing
base. A replayed warning about an imported SMT bit-blasting declaration using
`sorry` does not affect these results: no `CCFConsistency` theorem depends on
that declaration.

Reproduce the complete initialization/action matrix directly with:

```bash
cd veil
lake build CCFConsistency
```

The `Build and prove Veil consistency spec` CI step runs the same Lake build.
`test_invariant_proofs.py` is a fast structural guard rather than a second proof
driver: it checks that the direct invariant check, untrusted SMT setting,
theorem generation, cvc5 loading, and `sorryAx` audit cannot be removed while
leaving a superficially successful build.

## Implementation trace validation

`trace_validation.py` accepts the existing `tests/tvc.py` NDJSON format. It
schema-checks each line, rank-normalises sparse transaction IDs, views, and
sequence numbers, and plans the unlogged ledger and view backfill performed by
`TraceMultiNodeReads.tla`.

Validation replays that one concrete plan; it does not explore the protocol's
state space looking for a matching trace. The generated, ignored scratch copy
of `CCFConsistency.lean` turns the ten environment actions into internal
procedures and installs one zero-argument action for each concrete replay step.
A `traceReplayStep` program counter enables only the next recorded or
backfilled operation, and four immutable theory functions supply its concrete
finite-domain arguments by rank. Consequently, Veil has exactly one enabled
transition at each non-final replay state. The scratch module raises Lean's
elaboration heartbeat budget for the generated finite model; it does not raise
a search bound or permit additional transitions.

Missing ledger entries use `AppendOtherTxnAction`. View changes use a generated
finite-domain `TraceTruncateLedgerAction` procedure that copies every ranked sequence
position explicitly. This is equivalent to the base truncation action over the
trace's exhausted finite sequence domain, while avoiding a current Veil
concrete-execution limitation on bulk relation updates. It also leaves metadata
outside the copied prefix at the canonical initial values.

The scratch replay omits the declared invariants and safety property. It checks
transition conformance only: each expected canonical procedure must be enabled
and execute from the state produced by the preceding step. The finite
truncation helper uses the canonical guards and performs the canonical copy
assignment at every rank in the trace's exhausted sequence-number domain. If a
precondition is false, replay deadlocks before the designated final step and
fails.

Safety is supplied by the separate checked-in deductive proof. That proof
establishes every declared property for the canonical initial state and after
every canonical action. A successful conformance replay therefore describes a
reachable path whose states satisfy all 35 invariants and the safety property,
without reevaluating their quantified formulas after every concrete step. The
canonical specification and proof retain all properties; only the ignored
generated replay copy removes them.

The validator accepts only `no_violation_found` after complete exploration and
requires exactly `number of planned steps + 1` explored, generated, and
distinct states. This rejects premature deadlock, partial replay, and accidental
branching. On the current 73-event implementation trace, planning inserts seven
internal ledger/view operations, so the 80-step replay must visit exactly 81
states. With the pinned dependencies already built, an end-to-end Linux
compile-and-replay run took 233.57 seconds and peaked at 4,321,988 KB RSS. The
same trace took 1,251.69 seconds when every property was evaluated after every
state, so transition-only replay is 5.4 times faster.

CI does not use checked-in NDJSON fixtures. It builds the real `js_generic`
application, runs `tests/consistency_trace_validation.py`, and forces a primary
election while `tests/tvc.py` issues a mix of reads and writes. The trace job
uploads the resulting `build/consistency/trace.ndjson`; the Veil job downloads
and deterministically replays that same fresh trace. The existing TLC replay
remains in the trace-generation job.

Generate the same trace locally with:

```bash
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug -DLONG_TESTS=ON
cmake --build build --target js_generic
(cd build && ./tests.sh -VV --timeout 180 \
  -R '^consistency_trace_validation$')
```

Validate it with TLC and Veil with:

```bash
(cd tla && JSON=../build/consistency/trace.ndjson \
  ./tlc.py --workers 1 tv --disable-dfs \
  consistency/TraceMultiNodeReads.tla)
python3 veil/trace_validation.py build/consistency/trace.ndjson \
  --validate
```

Synthetic adapter behavior remains covered by Python unit tests, but every
continuous-verification run validates a fresh implementation trace rather than
a committed sample.
