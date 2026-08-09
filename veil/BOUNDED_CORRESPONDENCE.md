# Bounded TLA+ and Veil correspondence

This document records the finite-state comparison between CCF's consistency
models in TLA+ and Veil. It covers consistency only; it does not cover the
consensus specifications under `tla/consensus`.

## Compared models

- TLA+: `tla/consistency/MCMultiNodeReads.tla`
- Veil: `veil/CCFConsistency.lean`
- Harness: `veil/bounded_correspondence.py`

The harness derives its bounded TLC configuration from the canonical
`tla/consistency/MCMultiNodeReads.cfg`. It does not maintain a second checked-in
configuration.

The TLC model-checking wrapper omits `AppendOtherTxnAction`. For this comparison,
the harness generates an ignored scratch copy of the Veil model with only that
action removed. It also combines Veil's empty and non-empty ledger truncation
actions under TLC's single `TruncateLedgerAction` label.

## Confirmed scope

The following scope reached a fixed point in both checkers on 2026-08-08:

| Bound                     | TLC                          | Veil                 |
| ------------------------- | ---------------------------- | -------------------- |
| External history          | `HistoryLimit = 4`           | `histEvent := Fin 4` |
| Transactions              | Bounded by the history scope | `tx := Fin 4`        |
| Ledger sequence positions | Bounded by the history scope | `seqno := Fin 4`     |
| Ledger views              | `ViewLimit = 3`              | `view := Fin 3`      |
| Search depth              | Complete graph depth 11      | `maxDepth := 12`     |

`ViewLimit = 3` permits the initial ledger view and two subsequent views, so
this scope includes repeated view change, ledger truncation, and invalidation
behavior.

TLC used 12 workers. Veil used 12 parallel subtasks. TLC completed its
breadth-first search in 12 seconds. Veil recorded 378.319 seconds of
explicit-state exploration; this excludes Lean compilation.

## Fixed-point results

| Measure          |    TLC |   Veil |
| ---------------- | -----: | -----: |
| Generated states | 36,569 | 36,569 |
| Distinct states  | 15,789 | 15,789 |

The cumulative distinct-state counts match at every breadth-first level:

| Depth |    TLC |   Veil |
| ----: | -----: | -----: |
|     0 |      1 |      1 |
|     1 |      4 |      4 |
|     2 |     12 |     12 |
|     3 |     34 |     34 |
|     4 |    108 |    108 |
|     5 |    356 |    356 |
|     6 |  1,077 |  1,077 |
|     7 |  2,996 |  2,996 |
|     8 |  7,145 |  7,145 |
|     9 | 12,429 | 12,429 |
|    10 | 15,789 | 15,789 |

Veil's final depth-11 fixed-point step remained at 15,789 distinct states.

The generated transition counts also match for every aligned action:

| Action                          |    TLC |   Veil |
| ------------------------------- | -----: | -----: |
| `RoTxRequestAction`             |  1,419 |  1,419 |
| `RoTxResponseAction`            |    697 |    697 |
| `RwTxRequestAction`             |  1,419 |  1,419 |
| `RwTxExecuteAction`             | 14,954 | 14,954 |
| `RwTxResponseAction`            |  4,206 |  4,206 |
| `StatusCommittedResponseAction` |    156 |    156 |
| `StatusInvalidResponseAction`   |     58 |     58 |
| `TruncateLedgerAction`          | 13,659 | 13,659 |

## Progression of checked scopes

| Scope                                         | TLC generated | TLC distinct | Veil result                  |
| --------------------------------------------- | ------------: | -----------: | ---------------------------- |
| `HistoryLimit = 3`, `ViewLimit = 2`, depth 8  |           580 |          341 | Exact match; 2.799 seconds   |
| `HistoryLimit = 4`, `ViewLimit = 2`, depth 10 |         5,026 |        2,792 | Exact match; 36.436 seconds  |
| `HistoryLimit = 4`, `ViewLimit = 3`, depth 12 |        36,569 |       15,789 | Exact match; 378.319 seconds |
| `HistoryLimit = 5`, `ViewLimit = 2`, depth 12 |        50,639 |       27,144 | TLC only                     |
| `HistoryLimit = 6`, `ViewLimit = 3`, depth 15 |     6,962,866 |    2,793,475 | Not completed                |

The confirmed scope increases the original `HistoryLimit = 3`,
`ViewLimit = 2` comparison by 63.1 times in generated states and 46.3 times in
distinct states. The largest scope reached a TLC fixed point in 69 seconds, but
its Veil exploration was stopped after approximately 90 minutes without
completing. No TLA+/Veil correspondence claim is made for either TLC-only row.

## What this establishes

At the confirmed scope, TLC and Veil agree on:

1. Total generated states.
2. Total distinct states.
3. Cumulative distinct states at every breadth-first level.
4. Generated transitions for every aligned action.
5. Fixed-point termination without an invariant violation.

This is exact bounded graph-statistics correspondence. It is stronger than
comparing only the final state count, but it is not:

- A direct state-by-state or labelled-edge comparison.
- A bisimulation proof.
- An unbounded proof of equivalence.
- A comparison of `AppendOtherTxnAction`, which the TLC wrapper does not include.

The next stronger bounded check would export canonical state and labelled-edge
digests from both checkers and compare those directly.

## Reproduction

From the repository root on Linux or WSL:

```bash
python3 tla/install_deps.py
python3 veil/bounded_correspondence.py --workers "$(nproc)"
```

The harness writes ignored generated sources, checker output, and the derived
TLC configuration under `veil/Generated/`.
