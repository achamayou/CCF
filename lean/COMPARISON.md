# CCF consistency: TLA+ and pure Lean compared

This document compares the original TLA+ consistency specification in
`tla/consistency` with the pure Lean translation in `lean`. It reports what
each artifact costs in lines, what each one actually establishes, and how
readable each is, so that the cost of the Lean experiment can be judged against
what it buys.

## Method

Line counts are split into code, comment and blank.

- TLA+ modules and configurations are counted with the repository's own
  `tla/loc.py`, which treats `\*` lines, `(* ... *)` blocks, separator rules and
  everything after the `====` module footer as comment.
- Lean files are counted by stripping `--` line comments and nestable
  `/- ... -/` blocks, including `/-! -/` and `/-- -/` documentation.
- Python files are counted by stripping comments and docstrings with the
  standard tokenizer.

Blank lines are excluded from "code" in every case.

Two artifacts are deliberately excluded from the core totals:

- `tla/consistency/Consistency.tla` and its configuration (225 code lines).
  The file states "DO NOT MODIFY THIS FILE" and is a flattened copy of the
  other modules, stitched together for the tla-web visualiser, with community
  module operators inlined. Counting it would double count the core spec.
- `tla/tla2tools.jar` and `tla/CommunityModules-deps.jar`, which are vendored
  binaries, not source.

## Provenance

The Lean development translates the refinement tower named in `veil/README.md`:
`ExternalHistory.tla`, `ExternalHistoryInvars.tla`, `SingleNode.tla`,
`SingleNodeReads.tla`, `MultiNode.tla` and `MultiNodeReads.tla`. It does not
model the consensus protocol in `tla/consensus`. The Lean model is a single
level: the refinement structure of the TLA+ tower is flattened into one
transition system.

## Headline comparison

| Concern | TLA+ | Pure Lean | Ratio |
| ------------------------- | -----: | --------: | ----: |
| Core specification        |    396 |       959 |  2.4x |
| Verification artifact     |    293 |     7,378 | 25.2x |
| Trace validation          |    156 |       857 |  5.5x |
| **Total**                 |**845** | **9,194** |**10.9x** |

All figures are code lines. The three rows measure different things and the
rest of this document explains why comparing them directly is misleading.

## 1. The core specification

The transition system and the properties.

| TLA+ module                 | Code | Comment | Blank | Total |
| --------------------------- | ---: | ------: | ----: | ----: |
| `ExternalHistory.tla`       |   74 |      36 |    28 |   138 |
| `ExternalHistoryInvars.tla` |  161 |      76 |    41 |   278 |
| `SingleNode.tla`            |   90 |      31 |    20 |   141 |
| `SingleNodeReads.tla`       |   29 |       7 |     6 |    42 |
| `MultiNode.tla`             |   35 |      14 |     7 |    56 |
| `MultiNodeReads.tla`        |    7 |       2 |     4 |    13 |
| **Total**                   |**396**|  **166**| **106**|**668**|

| Lean file          | Code | Comment | Total |
| ------------------ | ---: | ------: | ----: |
| `Model.lean`       |  557 |      75 |   632 |
| `Properties.lean`  |  402 |      71 |   473 |
| **Total**          |**959**|  **146**|**1,105**|

The Lean core spec is 2.4 times the size of the TLA+ one. The difference is
almost entirely in the model rather than the properties:

- **Properties**: 161 TLA+ lines against 402 Lean lines. Both express the same
  35 invariants and one safety property. The ratio here is mostly notation:
  Lean repeats a `state.` prefix on every relation, spends a line per
  definition signature, and uses ASCII `forall` and `/\` where TLA+ uses `\A`
  and a leading-`/\` conjunction list.
- **Model**: 235 TLA+ lines across four modules against 557 Lean lines. This is
  where the real gap is, and it has three causes.

**Why the model is larger in Lean.** First, TLA+ actions are relations over
primed variables, and `UNCHANGED <<vars>>` says nothing changes in one token.
Lean transitions are total functions returning a new state, so every action
must name every field it writes and inherit the rest through `{ state with ... }`.
Second, TLA+ has sets, sequences and records as primitives with a large standard
library; Lean's state is a 16-field structure over four abstract ordered types,
and helpers such as `updateUnary` and `updateBinary` have to be defined and
given simp lemmas. Third, the TLA+ tower shares definitions across five
refinement levels, so `MultiNodeReads.tla` costs 7 lines by inheriting almost
everything; the flattened Lean model cannot amortise in the same way.

It is worth being explicit that **the TLA+ tower specifies more, not less**: it
defines five abstraction levels and the refinement mappings between them. The
Lean model deliberately collapses that to one level, and still costs 2.4 times
as much.

## 2. What verification costs, and what it buys

This is the row where the two approaches are not comparable at all.

### TLA+: bounded model checking, no proof

| Artifact                                   | Code |
| ------------------------------------------ | ---: |
| Model-checking modules (5 `MC*.tla`)       |   68 |
| Model-checking configurations (10 `.cfg`)  |  225 |
| **Total**                                  |**293**|

There is no proof. TLC exhaustively explores a finite instance. The baseline
`MCMultiNodeReads` run measured for this comparison:

- 6,962,866 states generated, 2,793,475 distinct
- complete state graph depth 15
- finished in **1 min 09 s**
- fingerprint collision probability about 1.4e-6

For 293 lines of harness, that is a very strong result about a small
configuration, obtained with no proof engineering whatsoever.

### Lean: unbounded proof

| Artifact                                | Code |
| --------------------------------------- | ---: |
| `Proofs.lean`                            | 7,258 |
| `Examples.lean` (non-vacuity witnesses)  |   101 |
| `CCFConsistency.lean` (axiom audit)      |    19 |
| **Total**                                |**7,378**|

`reachableProved` establishes all 36 translated clauses for every reachable
state, over abstract and potentially infinite domains, with no bound on the
number of transactions, views, sequence numbers or events. The proof is checked
by Lean's kernel, depends only on `propext`, `Classical.choice` and
`Quot.sound`, and the build rejects any theorem reaching `sorryAx`.

A clean rebuild takes **1 min 48 s** wall (Mathlib already built), of which
`Proofs.lean` is 44 s.

### Reading the 25x

The 25x ratio is the price of moving from "no counterexample in a small finite
instance" to "true in all instances". It is not overhead or inefficiency, and it
is not something a better proof style would remove; it is the proof itself. The
structure is a tower of six inductive bundles, each proved preserved by all ten
actions, which is roughly 60 preservation cases plus nine derived consequences.

The honest summary is that TLA+ buys a great deal of confidence very cheaply,
and Lean buys certainty at roughly thirty times the cost.

## 3. Trace validation

Both systems check the same NDJSON trace emitted by the implementation.

| Artifact                                | Code |
| --------------------------------------- | ---: |
| **TLA+**                                 |      |
| `TraceMultiNodeReads.tla`                |  131 |
| `TraceMultiNodeReads.cfg`                |   25 |
| **Total**                                |**156**|
| **Lean**                                 |      |
| `Trace.lean` (CCF-specific)              |  299 |
| `TraceInfra.lean` (generic, reusable)    |  103 |
| `trace_validation.py` (renderer)         |  300 |
| `test_trace_validation.py`               |  155 |
| **Total**                                |**857**|

TLA+ is 5.5 times smaller here, and the reason is architectural rather than
incidental.

**TLC searches; Lean replays.** `TraceMultiNodeReads.tla` reads the log itself
with `ndJsonDeserialize` and constrains TLC's ordinary state exploration so that
each step must agree with the next logged event. Internal actions that the
implementation never logs, such as ledger truncations and view changes, are
simply found by TLC's search. Nothing outside TLA+ is required.

Lean has no search. Replay is a deterministic fold over a list of actions, so
something must decide in advance which unlogged internal actions occurred and
where. That is what the Python planner does: it parses the NDJSON, normalises
ranks, backfills unlogged ledger entries, and reconstructs view changes, then
emits a typed list of `TraceAction` constructors. The planner is shared with the
Veil development (`veil/trace_validation.py`, 905 code lines, imported by
`lean/trace_validation.py` for its parser and planner); its cost is not counted
in the 857 above, and counting it would roughly double the Lean figure.

So the comparison is really:

- TLA+: 156 lines, no external tooling, because the model checker can search.
- Lean: 857 lines plus a shared 905-line planner, because a proof assistant
  replaying a fixed sequence cannot.

What Lean gets in exchange is that a successful replay is a *theorem*
(`Reachable final`), kernel-checked, rather than a report from a tool. And
because the properties are already proved for all reachable states, the trace
run does not re-check any property; it only has to establish reachability.

Runtime: the Lean replay of the 73-event trace takes about 35 to 40 seconds.

## 4. Readability

Line counts do not measure how hard something is to read, so this section is
qualitative and deliberately even-handed.

### Where the two are genuinely close

The properties read almost identically. TLA+:

```tla
AllCommittedObservedInv ==
    \A i \in RwTxResponseCommittedEventIndexes :
        \A j \in RwTxRequestCommittedEventIndexes :
            \A k \in RwTxResponseCommittedEventIndexes :
                /\ history[k].tx = history[j].tx
                /\ i < j
                => Contains(history[k].observed, history[i].tx)
```

Lean:

```lean
def AllCommittedObserved (state : State Tx View Seqno Event) : Prop :=
  forall earlier request response,
    state.rwResponseCommitted earlier /\
      state.rwRequestEvent request /\
        state.rwResponseCommitted response /\
          state.eventTx request = state.eventTx response /\
            state.eventLt earlier request ->
      state.observes response (state.eventTx earlier)
```

Seven lines against nine, the same quantifier structure, the same reading. A
reviewer who understands one will understand the other. This is the strongest
evidence that the translation is faithful in shape and not just in outcome.

### Where TLA+ is clearly easier

- **Density.** The entire transition system and property set is 396 lines. A
  reader can hold it in their head. The Lean equivalent is 959 lines and needs
  more scrolling for the same understanding.
- **Indexed history.** TLA+ models the history as a sequence and indexes into
  it, which matches how one talks about traces informally. Lean models it as
  abstract events with an order and per-event functions, which is better for
  proving and worse for reading.
- **Refinement is expressible.** The tower states abstraction levels and their
  relationships directly. Lean has no equivalent structure here.
- **Trace validation is tiny** for the reasons above.

### Where Lean is clearly easier

- **Nothing is implicit.** Every definition has a type; every use is checked.
  In TLA+, a misspelled record field or a wrong arity silently produces a
  different, possibly vacuous, formula. `ExternalHistoryInvars.tla` is a
  concrete instance: `veil/README.md` documents three definitions there that
  are false or malformed as written, one of them vacuous. Those survived model
  checking. A vacuous clause in Lean is still possible, which is exactly why
  `Examples.lean` constructs a concrete request/execute/response path, but the
  type system rules out the whole class of arity and field errors.
- **The proof does not need to be read.** 7,258 lines sounds unreadable, and it
  is, but nobody has to read it. It is checked by the kernel, and the exported
  statement `reachableProved : Reachable state -> PropertyBundle state` is one
  line. The thing a human must audit is the model and the properties, which is
  959 lines, against 396 for TLA+.
- **The trust boundary is small and stated.** The build prints the axioms of the
  final theorem and fails if any theorem reaches `sorryAx`.

### The part that must be audited by hand

For trace validation specifically, the Lean side was deliberately reduced to a
single human obligation: that each action's guard and transition in `Trace.lean`
match the corresponding `Step` constructor in `Model.lean`. That correspondence
is `TraceAction.enabled_step` and the compiler checks it. Everything else in the
trace layer is either inferred from the model (the decidability instances) or
model-independent (`TraceInfra.lean`).

Earlier revisions of that file carried about 400 lines of hand-written Boolean
mirrors of the model's predicates plus soundness lemmas relating them. Those
were removed in favour of derived decidability, at a cost of roughly 2.5x in
replay time. That trade is the single clearest example in this project of
choosing auditability over performance.

## 5. What each approach actually establishes

| | TLA+ with TLC | Pure Lean |
| --- | --- | --- |
| Scope | One finite configuration | All reachable states, unbounded domains |
| Result | No counterexample found | Theorem, kernel-checked |
| Depth reached | 15 | Not applicable |
| States examined | 2,793,475 distinct | Not applicable |
| Trusted base | TLC and its Java implementation | Lean kernel; Mathlib is proof-producing, not trusted |
| Failure mode | Missed bug outside the finite instance | Mis-stated model or property |
| Counterexamples | Produced automatically | Not produced |
| Effort to add a property | Write it, rerun TLC | Write it, then prove preservation for ten actions |

The last row matters most in practice. In TLA+, adding an invariant costs a few
lines and a rerun. In Lean it costs a preservation proof for every action, which
in this development ranged from a one-line `simpa` to several hundred lines for
the commit keystone.

## 6. Verification cost in wall-clock time

| Task | Time |
| --- | ---: |
| TLC baseline (`MCMultiNodeReads`, 2.79M distinct states) | 1 min 09 s |
| TLC with coverage statistics | 2 min 56 s |
| TLC depth exploration | 5 min 17 s |
| Lean full rebuild including the whole proof | 1 min 48 s |
| Lean no-op rebuild | 5.7 s |
| Lean kernel-checked trace replay (73 events, 80 actions) | about 35 to 40 s |

The Lean proof checks in about the same wall-clock time as TLC explores its
finite model, which is worth noting given that the Lean result is unbounded.
The cost of the Lean approach is entirely in human proof-engineering effort, not
in machine time. Lean's figure assumes Mathlib is already built; CI uses a
prebuilt Mathlib cache, since compiling Mathlib from source would take hours.

## 7. Supporting tooling

Not attributed to either column above, for fairness.

| Artifact | Code | Note |
| --- | ---: | --- |
| `tla/tlc.py` | 239 | TLC runner, shared with `tla/consensus` |
| `tla/install_deps.py` | 106 | Dependency fetcher, shared |
| `tla/trace2scen.py` | 76 | Trace to scenario, shared |
| `tla/loc.py` | 123 | The counter used by this document |
| `tla/actions.py` | 36 | Shared |
| `tla` shell helpers | 44 | Shared |
| `veil/trace_validation.py` | 905 | Trace planner, shared by Veil and Lean |

For reference, the intermediate Veil specification is 513 code lines, sitting
between the 396 of TLA+ and the 959 of the Lean model plus properties. Veil's
own trace validation reuses the same 905-line planner.

## 8. Conclusions

1. **As specifications, the two are comparable, with TLA+ ahead on density.**
   396 against 959 code lines, and the TLA+ version additionally expresses a
   five-level refinement tower. If the goal is a specification for humans to
   read and argue about, TLA+ remains the better medium.

2. **The properties translate essentially one to one.** This is the most
   reassuring result in the comparison: the invariants read the same in both,
   which is direct evidence that the Lean development says what the TLA+ one
   says.

3. **Proof costs about thirty times what model checking costs, and delivers a
   different kind of answer.** 7,378 lines against 293. Nobody should pay that
   to reproduce what TLC already provides. It is worth paying when a bounded
   result is genuinely not enough.

4. **They are complementary, not competing.** TLC finds counterexamples, which
   Lean does not; the model-checking configurations here include deliberate
   reachability and non-linearizability checks that a proof assistant cannot
   replace. The Lean proof rules out bugs beyond any bound TLC can reach. A
   defect found by TLC in seconds might take days to discover as a failed proof
   obligation.

5. **Trace validation strongly favours TLA+ on cost**, 156 lines against 857
   plus a shared planner, because TLC can search for unlogged internal actions
   while a replay-based checker must be told what they were. The Lean version's
   compensation is that its output is a kernel-checked theorem.

6. **Type checking caught a class of defect that model checking did not.** Three
   definitions in `ExternalHistoryInvars.tla` are recorded as false or malformed,
   one vacuous, and they survived model checking. That is the clearest practical
   argument for the Lean translation as a cross-check on the TLA+ original,
   independent of whether the unbounded proof is needed.
