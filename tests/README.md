# End-to-End Tests

## Test hierarchy

```
CTest entry          ctest -R e2e_logging
└── Entry-point      tests/e2e_logging.py
    └── Runner       cr.add("cpp", run_cpp, ...)
        └── Group    run_cpp(args) — creates and owns a network
            └── Case test_historical_query(network, args) — single test
```

## Naming conventions

### CTest entries

Registered in CMakeLists.txt via `add_e2e_test(NAME ...)`. Names should be
unique and not be substrings of each other, so that `ctest -R <name>` matches
exactly one test. For example, `recovery_test` and `recovery_test_suite` are
problematic because `-R recovery_test` matches both.

### Entry-points

Python scripts (e.g. `schema.py`, `e2e_logging.py`) that use `ConcurrentRunner`
to run one or more groups in parallel. A single entry-point may bin-pack
unrelated groups for efficient CI run-time.

### Runners (ConcurrentRunner threads)

The first argument to `cr.add("name", ...)`. This name appears in every log
line from that thread, so it should be short and descriptive (e.g. `"cpp"`,
`"operations"`, `"recovery"`).

### Groups — `run_` prefix

Top-level functions that create and own a network, then call test cases on it.

- Should take `(args)` or `(const_args)`.
- Should create their own network via `with infra.network.network(...)`.
- Should not return `network`.
- `const_args` signals the function will `copy.deepcopy` before mutating.

### Test cases — `test_` prefix

Individual test functions that operate on an existing network.

- Should take `(network, args)` and return `network` (enables chaining).
- Should have a `@reqs.description("...")` decorator.
- Should not create their own network.

### Other helpers

Functions that don't fit either pattern (e.g. shared test groups that operate
on an existing network but aren't individual tests) should avoid the `test_`
and `run_` prefixes.

## Divergent suffix commit repro

Two reproductions of the same defect: a follower commits a divergent suffix on
the strength of an `AppendEntries` that only verified a matching _prefix_.

`execute_append_entries_finish` calls `commit_if_possible(r.leader_commit_idx)`.
The skip path in the entry loop (`i <= last_idx` and matching term, so
`continue`) never applies or term-checks past `r.idx`, so a local committable
signature _after_ `r.idx` is still in `committable_indices` and gets committed.
`leaderCommit` is the leader's commit index, not evidence that this request
matched the follower that far.

Both reproductions are expected to FAIL on unpatched `main`. That is the point:
they pass once `raft.h` caps the commit at the verified prefix.

```cpp
// src/consensus/aft/raft.h, execute_append_entries_finish
commit_if_possible(std::min(r.leader_commit_idx, r.idx));
```

### 1. Deterministic driver scenario

`raft_scenarios/divergent_suffix_commit` drives five in-process nodes with
hand-ordered message delivery. Runs in under a second, fails every time.

```sh
cd build
./raft_driver ../tests/raft_scenarios/divergent_suffix_commit
```

Expected on unpatched `main` (exit code 1):

```
unsafe commit idx (8)
```

It is picked up automatically by `ctest -R raft_scenario_test`, which runs the
whole `tests/raft_scenarios/` directory and fails if any scenario does.

### 2. End-to-end partition test

`test_divergent_suffix_not_committed_from_prefix_ae` in `partitions_test.py`
produces the same shape on a real five-node network over TCP. Linux only: it
needs `iptables` and therefore root.

```sh
cd build
sudo env \
  CCF_DIVERGENT_SUFFIX_ONLY=1 \
  CCF_DIVERGENT_SUFFIX_LOOPS=5 \
  XTABLES_LIBDIR=/usr/lib/x86_64-linux-gnu/xtables \
  PATH="$PATH" VIRTUAL_ENV="$VIRTUAL_ENV" \
  python ../tests/partitions_test.py \
    -b . \
    --package ./samples/apps/logging/logging \
    --workspace ./workspace \
    --label divergent_suffix \
    --constitution ../samples/constitutions/default/actions.js \
    --constitution ../samples/constitutions/default/validate.js \
    --constitution ../samples/constitutions/default/resolve.js \
    --constitution ../samples/constitutions/default/apply.js \
    --election-timeout-ms 2000 \
    --log-level info
```

`CCF_DIVERGENT_SUFFIX_ONLY` skips the rest of the partitions suite;
`CCF_DIVERGENT_SUFFIX_LOOPS` sets the number of attempts. Budget about three
minutes per attempt, most of it waiting for TCP retransmission backoff.

Expected on unpatched `main`, once per attempt:

```
AssertionError: n2 committed divergent 3.51 while 4.69 is committed on the
term-C branch
```

With the commit cap applied, the same choreography runs to completion and n2
discards the branch instead:

```
n2 has 3.58 as Invalid, commit 4.74; n0 committed 4.72
[rollback] Dropping conflicting branch. Rolling back 5 entries, beginning with 3.54.
```

Observed 5/5 reproductions unpatched and 5/5 passes patched.

#### How it works

n0 leads term A, n1 leads term B, n0 leads term C. n2 is left holding a signed
term-B suffix that no one else has, and n0 must send it a term-C
`AppendEntries` whose `prev_idx`/`idx` cover only the shared prefix while
`leader_commit_idx` sits past n2's divergent signature.

Four preconditions have to hold at once:

1. `sent_idx[n2]` must land inside the shared range. Only a NACK lowers it, so
   one term-B NACK is held back and delivered late.
2. n2's commit index must not be past the index that NACK reports, or
   `recv_append_entries` early-returns at `r.prev_idx < state->commit_idx`.
3. n0 must still be leader in term C when it consumes the NACK, so n0 -> n2 is
   muted across the whole term-C election. Any term-B response reaching n0
   after it steps up calls `become_aware_of_new_term` and demotes it.
4. The leader commit index must be high enough to select n2's signature.

The awkward part is that `iptables -j DROP` only delays traffic: n0 accumulates
around 20 KB of term-C `AppendEntries` behind the block, which are delivered in
order on release and roll n2 back harmlessly before the interesting message
arrives. That queue has to be destroyed, not flushed.

`ss -K` is the obvious tool but needs `CONFIG_INET_DIAG_DESTROY`, which WSL2
kernels do not set. Instead the test installs a `REJECT --reject-with
tcp-reset` rule matched to bare acks only (`-m length --length 0:79`). n0's
retransmissions are far larger so never match; the only packet that trips the
rule is n0's delayed ack for the incoming NACK, which the host has already read
off the socket by then. The RST tears down the connection and its
`pending_writes`, n0 reconnects on a fresh socket, and the split
prefix/conflict pair is the first thing on the wire.

Because the trigger is n0's own ack, the rule can be armed before the NACK is
released, which removes the timing race. It must be dropped again before n0
reconnects, since a SYN with options is 60 bytes and would also match.

The follow-up conflicting message needs no special handling: by the time it
arrives n2 has already committed, and it is discarded at
`r.prev_idx < state->commit_idx`.

#### Supporting changes

- `config.jinja` and `infra/network.py` make `client_connection_timeout`
  configurable. The 2s default is a `TCP_USER_TIMEOUT`, which destroys the
  socket holding the retained NACK long before it is wanted.
- `infra/partitions.py` gains `length` and `target` on `isolate_node`, for the
  ack-only REJECT rule described above.
