# Pure Lean consistency experiment

## Goal

Translate `veil/CCFConsistency.lean` into ordinary Lean 4 without importing
Veil, invoking its DSL, generating verification conditions, or calling an SMT
solver. The experiment should state the same consistency transition system,
the same 35 invariants, and the same safety property, then prove as much of the
reachable-state theorem as possible with kernel-checked Lean terms.

This directory is intentionally separate from `veil/`. It is an experiment,
not a replacement for the Veil specification or its CI gate.

## Constraints

- Use Lean 4.28.0 and Mathlib, with no Veil or SMT dependency.
- Keep the four domains abstract, with a total order and least element.
- Represent every Veil state relation and function directly.
- Preserve all ten action guards and simultaneous state updates.
- Give every Veil invariant and safety property a named Lean proposition.
- Admit no `sorry`, custom axioms, trusted invariants, or external solver
  answers.
- End with a theorem about all states reachable through the ordinary Lean
  transition relation, rather than a theorem over a bounded finite instance.

## Semantic mapping

| Veil construct                   | Pure Lean construct                                      |
| -------------------------------- | -------------------------------------------------------- |
| `type` plus `TotalOrderWithZero` | Type parameter with Mathlib `LinearOrder` and `OrderBot` |
| Mutable relation                 | Predicate-valued field of `State`                        |
| Mutable function                 | Function-valued field of `State`                         |
| Ghost relation                   | Ordinary `def` over `State`                              |
| `after_init`                     | `initialState` value                                     |
| Action guard                     | Premise of a `Step` constructor                          |
| Action assignment                | Pure function returning an updated `State`               |
| Simultaneous assignment          | Structure update whose fields all read the old state     |
| Invariant or safety declaration  | Named proposition over `State`                           |
| Joint inductive check            | Preservation theorem for a selected property bundle      |
| Reachable-state safety           | Induction over `Reachable`                               |

Mathlib supplies reflexivity, transitivity, antisymmetry, totality, and the
least-element laws. Strict order is still defined exactly as Veil defines it:
`le` plus disequality. Relations use `Prop`; equality between Veil Boolean
observations is translated as logical equivalence.

## Execution plan

| Step | Deliverable                                                                   | Status                                                   |
| ---- | ----------------------------------------------------------------------------- | -------------------------------------------------------- |
| 1    | Standalone Lake project pinned to Lean 4.28.0                                 | Complete                                                 |
| 2    | Direct state, ghost definitions, initializer, and all ten actions             | Complete                                                 |
| 3    | Named translations of all 35 invariants and one safety property               | Complete                                                 |
| 4    | Complete property bundle and proof for the initializer                        | Complete                                                 |
| 5    | Preservation lemmas for each action using only Lean tactics and helper lemmas | Fixed point: all ten actions preserve the 17-clause core |
| 6    | `Reachable` induction and top-level safety theorem                            | Complete for `ProvedBundle` (19 of 36 properties)        |
| 7    | No-`sorry`/axiom audit, documentation, and semantic coverage review           | Complete                                                 |

## Proof strategy

1. Keep action updates transparent and prove reusable simplification lemmas for
   unary and binary function updates.
2. Construct an explicit request/execute/response path over `Nat` to show that
   the translated guards admit nontrivial executions.
3. Bundle the properties so every preservation proof may use all auxiliary
   invariants, matching Veil's joint induction.
4. Split preservation by action. Within each action, split by property rather
   than asking one tactic invocation to solve the full matrix.
5. Use `simp`, `grind`, `omega`, propositional reasoning, and explicit witnesses.
   These tactics construct proof terms checked by Lean's kernel.
6. Prove the initializer and inexpensive structural properties first. Use the
   resulting lemmas to attack provenance, status monotonicity, serializability,
   and real-time ordering.
7. Audit the transitive axioms of the final reachable-state theorem. A theorem
   depending on `sorryAx` is a build failure.

## Fixed-point rule

The target is the complete reachable-state safety theorem. If ordinary Lean
automation reaches a genuine proof-engineering fixed point before that target,
the experiment may stop only with:

- a compiling, no-`sorry` model containing all actions and properties;
- every completed proof exposed as a named theorem;
- an exact matrix of proved and open preservation cases;
- the smallest reproducible open verification condition;
- no claim that untranslated or unproved properties are established.

That fallback still measures the work needed to replace Veil; it must not hide
gaps behind assumptions.

The experiment reached this fallback after completing a 17-property
action-preservation matrix and deriving two more properties from that core.
`reachableProved` therefore establishes 19 of the 36 translated clauses. The
remaining 17 clauses and their preservation cases are listed explicitly in
`README.md`; none is assumed.

## Validation

From this directory:

```bash
lake build
```

The final build compiles the model and proofs, prints the axioms of
`reachableProved`, and rejects any transitive dependency on `sorryAx`.
