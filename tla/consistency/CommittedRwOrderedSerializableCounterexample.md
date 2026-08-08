# `CommittedRwOrderedSerializableInv` counterexample

## Result

`CommittedRwOrderedSerializableInv` is not an invariant of the consistency
transition system. A ten-action, seven-history-event execution violates it
without a view change, read-only transaction, invalid status, or non-client
ledger entry. The counterexample is therefore present in the single-node
subset as well as the multi-node models.

This is a specification-property failure, not a CCF consistency failure. The
property is stronger than serialisability: it assumes that two responses which
are consecutive after filtering for explicitly known committed transaction IDs
are also consecutive in the ledger. The model does not make that assumption.

The false property remains defined in `ExternalHistoryInvars.tla` so that the
counterexample can be checked, but it is excluded from the normal invariant
configurations. The Veil translation similarly excludes it from the declared
safety properties.

## The property

`CommittedRwResponses` contains read-write responses whose transaction IDs
have an explicit committed-status event in `history`, sorted by transaction
ID. The property requires each adjacent pair in that filtered sequence to
differ by exactly the later transaction:

```tla
CommittedRwOrderedSerializableInv ==
    \A i \in 1..Len(CommittedRwResponses)-1:
        CommittedRwResponses[i+1].observed =
            Append(
                CommittedRwResponses[i].observed,
                CommittedRwResponses[i+1].tx)
```

The equality is too strong. An intervening client write can be present in the
ledger and in the later response's observations without having its own
response or committed-status event in the external history.

## Minimal counterexample

TLC finds the following breadth-first trace. Transaction IDs are
`<<view, sequence number>>`.

| Step | Action | Relevant result | History length |
| ---: | --- | --- | ---: |
| 1 | Request transaction `0` | Request `0` is visible | 1 |
| 2 | Request transaction `1` | Request `1` is visible | 2 |
| 3 | Request transaction `2` | Request `2` is visible | 3 |
| 4 | Execute transaction `0` | Ledger slot 1 is `(view 1, tx 0)` | 3 |
| 5 | Execute transaction `1` | Ledger slot 2 is `(view 1, tx 1)` | 3 |
| 6 | Execute transaction `2` | Ledger slot 3 is `(view 1, tx 2)` | 3 |
| 7 | Respond to transaction `0` | ID `<<1, 1>>`, observes `<<0>>` | 4 |
| 8 | Respond to transaction `2` | ID `<<1, 3>>`, observes `<<0, 1, 2>>` | 5 |
| 9 | Report transaction `0` committed | `<<1, 1>>` enters `CommittedTxIDs` | 6 |
| 10 | Report transaction `2` committed | `<<1, 3>>` enters `CommittedTxIDs` | 7 |

There is deliberately no response or status event for transaction `1`.

In the final state:

```tla
CommittedTxIDs = {<<1, 1>>, <<1, 3>>}

CommittedRwResponses =
    <<
        [tx |-> 0, tx_id |-> <<1, 1>>, observed |-> <<0>>],
        [tx |-> 2, tx_id |-> <<1, 3>>, observed |-> <<0, 1, 2>>]
    >>
```

The property checks the only adjacent pair and compares:

```text
actual   = <<0, 1, 2>>
expected = Append(<<0>>, 2) = <<0, 2>>
```

The extra `1` makes the equality false. The weaker
`CommittedRwSerializableInv` still holds because `<<0>>` is a prefix of
`<<0, 1, 2>>`.

In a real ledger, committing sequence number 3 commits the preceding ledger
prefix as well. The abstraction's `CommittedTxIDs`, however, represents
committed statuses explicitly observed by clients, not every transaction
implicitly covered by the commit watermark. Filtering responses with that set
can therefore hide transaction `1` even though later execution observes it.

## Reproduce with TLC

Install the pinned TLC dependencies once:

```bash
cd tla
python3 install_deps.py
```

Run the expected-counterexample wrapper:

```bash
./tlc_debug.sh --workers 1 --difftrace \
  --config consistency/MCSingleNodeOrderedSerializableCounterexample.cfg \
  mc consistency/MCSingleNode.tla
```

The dedicated configuration checks only
`CommittedRwOrderedSerializableInv`, as required by `tlc_debug.sh`. TLC reports:

```text
Error: Invariant CommittedRwOrderedSerializableInv is violated.
...
Counterexample found as expected.
```

`MCSingleNode.tla` is used because the violating execution needs none of the
multi-node or read-only actions. It is a smaller state space while remaining a
valid execution of `MCMultiNode.tla` and `MCMultiNodeReads.tla`.

## Veil handling

The Veil translation no longer declares the false formula as a safety
property. Its source links to this counterexample, while the dedicated TLC
configuration remains the executable regression because it produces a compact,
human-readable witness for the original TLA+ formula.

## Why existing model checking missed it

### TLA+ bound

The normal `MCMultiNode.cfg` and `MCMultiNodeReads.cfg` configurations both set:

```tla
HistoryLimit = 6
```

Seven external events are necessary:

1. Three request events are needed to place a client transaction between the
   two compared ledger entries.
2. Two response events are needed for the outer transactions.
3. Two committed-status events are needed for both outer transaction IDs to
   enter `CommittedTxIDs`.

The three execution actions do not consume history slots, but they bring the
total trace to ten transitions. With `HistoryLimit = 6`, TLC exhaustively
checks the bounded state graph and correctly reports no violation. Raising
only this bound to 7 exposes the counterexample.

The bound predates the property. It was introduced with the original
consistency specification in commit `724c827247`
([PR #5699](https://github.com/microsoft/CCF/pull/5699)). Commit
`bf4fcff670`
([PR #6185](https://github.com/microsoft/CCF/pull/6185)) later added
`CommittedRwOrderedSpecLinearizableInv` to the two multi-node model-checking
configurations without changing `HistoryLimit`.

Other configurations did not close the gap:

- The single-node configurations had a history limit of 7 but did not check
  the new property.
- `MCMultiNodeReadsAlt.cfg` had a larger history limit but did not check the
  new property.
- The configurations which did check it remained capped at 6.

This was a scope-boundary blind spot, not a TLC search failure.

### Veil bound

The Veil port in commit `1fa804b4b` translated the TLA+ equality directly. Its
checked-in explicit-state smoke scope used:

```lean
tx := Fin 2
seqno := Fin 2
histEvent := Fin 6
```

The counterexample needs at least three transactions, three ledger positions,
and seven history events, so each of these bounds independently excludes it.
`maxDepth := 14` was already sufficient for the ten transitions and was not
the limiting factor.

The Veil source documented the suspected counterexample, but retained the
formula as a safety clause to match the TLA+ source. This branch removes that
false safety claim; the dedicated TLC target provides the executable witness.

## How the property admitted the bug

PR #6185 intended to state that committed read-write transactions are
serialisable in transaction-ID order. The implementation selected only
responses with explicitly observed committed statuses, sorted that filtered
set, and then treated adjacent elements as adjacent ledger writes.

Those notions of adjacency differ:

- Adjacent in `CommittedRwResponses` means no other response with an explicit
  committed-status event is between the pair.
- Adjacent in the ledger means no client write is between their sequence
  numbers.

The transition system permits a write to execute without a response or status
event. Such a write is absent from `CommittedRwResponses` but remains present
in every later observation of that ledger prefix. The `Append` equality
therefore cannot hold in general.

Possible repairs require a separate design decision. For example, the
property could allow an observed suffix between the two compared writes, or
the abstraction could distinguish actual ledger commitment from client receipt
of a committed status. This counterexample branch does not choose or assert a
replacement guarantee.
