// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use super::*;

#[test]
fn set_prepends_new_and_existing_keys_without_reordering_other_entries() {
    let mut rows = Assoc::<u64, u64>::new();
    rows.set(1, 10);
    rows.set(2, 20);
    rows.set(3, 30);
    assert_eq!(rows.0, [(3, 30), (2, 20), (1, 10)]);
    rows.set(2, 21);
    assert_eq!(rows.0, [(2, 21), (3, 30), (1, 10)]);

    let mut duplicate = Assoc(vec![(3_u64, 30_u64), (1, 10), (3, 31), (2, 20)]);
    duplicate.set(3, 32);
    assert_eq!(duplicate.0, [(3, 32), (1, 10), (2, 20)]);
}

fn run(s: &mut Store, action: Action) -> Output {
    s.execute(action).unwrap()
}

fn begin(s: &mut Store, id: Attempt) {
    run(s, Action::Begin(id));
    run(s, Action::Snapshot(id));
}

fn acquire(s: &mut Store, id: Attempt, map: &[u8]) -> Output {
    run(s, Action::Acquire(id, Bytes::copy_from(map)))
}

fn op(s: &mut Store, id: Attempt, map: &[u8], op: Operation) -> Output {
    run(s, Action::Operate(id, Bytes::copy_from(map), op))
}

fn write(s: &mut Store, id: Attempt, map: &[u8], k: &[u8], v: Option<&[u8]>) {
    op(
        s,
        id,
        map,
        Operation::Write(Bytes::copy_from(k), v.map(Bytes::copy_from)),
    );
}

fn assert_read(
    s: &mut Store,
    id: Attempt,
    map: &[u8],
    k: &[u8],
    global: bool,
    want: Option<&[u8]>,
) {
    let Output::Value(got) = op(s, id, map, Operation::Get(Bytes::copy_from(k), global)) else {
        panic!("get must return a value observation");
    };
    assert_eq!(got.as_ref().map(Bytes::as_slice), want);
}

fn applied(s: &mut Store, id: Attempt, outcome: Outcome, version: Version) {
    run(s, Action::CommitBegin(id));
    assert!(matches!(run(s, Action::Apply(id)), Output::Applied(v, _, _) if v == version));
    assert!(matches!(
        run(s, Action::CommitResult(id, outcome)),
        Output::Committed(result, v) if v == version && result == outcome
    ));
    run(s, Action::End(id));
}

fn put(s: &mut Store, id: Attempt, map: &[u8], key: &[u8], value: &[u8], version: Version) {
    begin(s, id);
    acquire(s, id, map);
    write(s, id, map, key, Some(value));
    applied(s, id, Outcome::Success, version);
}

fn expect_conflict(s: &mut Store, id: Attempt) {
    run(s, Action::CommitBegin(id));
    assert!(matches!(s.execute(Action::Apply(id)), Err(Error::Disabled)));
    assert!(matches!(
        s.execute(Action::CommitResult(id, Outcome::Success)),
        Err(Error::Disabled)
    ));
    assert!(matches!(
        run(s, Action::CommitResult(id, Outcome::Conflict)),
        Output::Committed(Outcome::Conflict, 0)
    ));
}

#[test]
fn distinct_global_cuts_are_pinned_per_map() {
    let mut s = Store::new(4);
    begin(&mut s, 1);
    for map in [b"a", b"b"] {
        acquire(&mut s, 1, map);
        write(&mut s, 1, map, b"old", Some(b"v1"));
    }
    applied(&mut s, 1, Outcome::Success, 1);
    begin(&mut s, 1);
    for map in [b"a", b"b"] {
        acquire(&mut s, 1, map);
        write(&mut s, 1, map, b"new", Some(b"v2"));
    }
    applied(&mut s, 1, Outcome::NoReplicate, 2);
    assert!(matches!(
        run(&mut s, Action::Compact(1)),
        Output::Compacted(1)
    ));

    begin(&mut s, 2);
    assert!(matches!(acquire(&mut s, 2, b"a"), Output::Acquired(2, 1)));
    assert!(matches!(
        run(&mut s, Action::Compact(2)),
        Output::Compacted(2)
    ));
    assert!(matches!(acquire(&mut s, 2, b"b"), Output::Acquired(2, 2)));
    assert_read(&mut s, 2, b"a", b"old", true, Some(b"v1"));
    assert_read(&mut s, 2, b"a", b"new", true, None);
    assert_read(&mut s, 2, b"a", b"new", false, Some(b"v2"));
    assert_read(&mut s, 2, b"b", b"new", true, Some(b"v2"));
    assert!(matches!(
        s.execute(Action::Acquire(2, Bytes::copy_from(b"a"))),
        Err(Error::Disabled)
    ));
}

#[test]
fn late_acquisition_uses_the_surviving_cut_without_refreshing_existing_views() {
    let mut s = Store::new(0);
    put(&mut s, 0, b"late", b"k", b"base", 1);
    put(&mut s, 0, b"pinned", b"k", b"discarded", 2);
    put(&mut s, 0, b"late", b"k", b"discarded", 3);

    begin(&mut s, 1);
    assert!(matches!(
        acquire(&mut s, 1, b"pinned"),
        Output::Acquired(2, 0)
    ));
    assert!(matches!(
        run(&mut s, Action::Rollback(1, 1)),
        Output::RolledBack(1)
    ));
    put(&mut s, 0, b"late", b"k", b"replacement", 2);
    run(&mut s, Action::Compact(2));
    put(&mut s, 0, b"late", b"beyond", b"newer", 3);
    put(&mut s, 0, b"late", b"beyond", b"too new", 4);
    assert!(matches!(
        acquire(&mut s, 1, b"late"),
        Output::Acquired(3, 2)
    ));
    assert_read(&mut s, 1, b"late", b"k", false, Some(b"replacement"));
    assert_read(&mut s, 1, b"late", b"beyond", false, Some(b"newer"));
    assert_read(&mut s, 1, b"late", b"beyond", true, None);
    assert_read(&mut s, 1, b"pinned", b"k", false, Some(b"discarded"));
    assert_read(&mut s, 1, b"pinned", b"k", true, None);
}

#[test]
fn rollback_reuses_sequence_number_but_not_empty_map_birth() {
    let mut s = Store::new(2);
    begin(&mut s, 0);
    acquire(&mut s, 0, b"empty");
    write(&mut s, 0, b"empty", b"k", None);
    applied(&mut s, 0, Outcome::Success, 1);
    begin(&mut s, 1);
    assert!(matches!(
        acquire(&mut s, 1, b"empty"),
        Output::Acquired(0, 0)
    ));
    write(&mut s, 1, b"empty", b"never", Some(b"stale"));

    // Same term isolates the lineage check from stale-term rejection.
    assert!(matches!(
        run(&mut s, Action::Rollback(0, 2)),
        Output::RolledBack(0)
    ));
    begin(&mut s, 0);
    acquire(&mut s, 0, b"empty");
    write(&mut s, 0, b"empty", b"k", None);
    applied(&mut s, 0, Outcome::Success, 1);
    assert_read(&mut s, 1, b"empty", b"k", false, None);
    expect_conflict(&mut s, 1);
    begin(&mut s, 3);
    acquire(&mut s, 3, b"empty");
    assert_read(&mut s, 3, b"empty", b"never", false, None);
}

#[test]
fn compacted_existing_map_is_unavailable_but_absent_map_is_still_empty() {
    let mut s = Store::new(0);
    put(&mut s, 0, b"existing", b"k", b"v1", 1);
    begin(&mut s, 1);
    put(&mut s, 0, b"existing", b"k", b"v2", 2);
    put(&mut s, 0, b"absent", b"k", b"v3", 3);
    run(&mut s, Action::Compact(3));
    assert!(matches!(
        acquire(&mut s, 1, b"existing"),
        Output::Unavailable
    ));
    assert!(matches!(
        acquire(&mut s, 1, b"absent"),
        Output::Acquired(0, 0)
    ));
    assert_read(&mut s, 1, b"absent", b"k", true, None);
    write(&mut s, 1, b"absent", b"k", Some(b"stale"));
    expect_conflict(&mut s, 1);
    for cut in [0, 4] {
        assert!(matches!(
            run(&mut s, Action::Compact(cut)),
            Output::Compacted(3)
        ));
    }
    assert!(matches!(
        run(&mut s, Action::Rollback(2, 1)),
        Output::RollbackRejected
    ));
    run(&mut s, Action::Begin(2));
    assert!(matches!(
        run(&mut s, Action::Snapshot(2)),
        Output::Snapshot(3, 3, 0)
    ));
}

#[test]
fn two_map_application_and_conflicts_preserve_versioned_read_dependencies() {
    let mut s = Store::new(0);
    begin(&mut s, 1);
    acquire(&mut s, 1, b"a");
    acquire(&mut s, 1, b"b");
    assert_read(&mut s, 1, b"a", b"k", false, None);
    write(&mut s, 1, b"b", b"k", Some(b"stale"));
    begin(&mut s, 2);
    acquire(&mut s, 2, b"a");
    acquire(&mut s, 2, b"b");
    write(&mut s, 2, b"a", b"k", Some(b""));
    write(&mut s, 2, b"b", b"k", Some(b"other"));
    assert_read(&mut s, 2, b"a", b"k", false, Some(b""));
    applied(&mut s, 2, Outcome::Success, 1);
    expect_conflict(&mut s, 1);
    begin(&mut s, 3);
    acquire(&mut s, 3, b"a");
    acquire(&mut s, 3, b"b");
    assert_read(&mut s, 3, b"b", b"k", false, Some(b"other"));
    write(&mut s, 3, b"a", b"k", Some(b"pending"));
    assert!(matches!(
        op(&mut s, 3, b"a", Operation::Previous(Bytes::copy_from(b"k"))),
        Output::Previous(Some(1))
    ));
    put(&mut s, 2, b"a", b"k", b"", 2);
    expect_conflict(&mut s, 3);
}

#[test]
fn reads_of_staged_deletions_and_global_values_do_not_add_dependencies() {
    let mut s = Store::new(0);
    put(&mut s, 0, b"a", b"k", b"", 1);
    run(&mut s, Action::Compact(1));

    begin(&mut s, 1);
    acquire(&mut s, 1, b"a");
    write(&mut s, 1, b"a", b"k", None);
    assert_read(&mut s, 1, b"a", b"k", false, None);
    assert_read(&mut s, 1, b"a", b"k", true, Some(b""));
    let key = Bytes::copy_from(b"k");
    assert!(matches!(
        op(&mut s, 1, b"a", Operation::Has(key.clone(), false)),
        Output::Presence(false)
    ));
    assert!(matches!(
        op(&mut s, 1, b"a", Operation::Has(key, true)),
        Output::Presence(true)
    ));

    put(&mut s, 0, b"a", b"k", b"replacement", 2);
    applied(&mut s, 1, Outcome::Success, 3);
    begin(&mut s, 2);
    acquire(&mut s, 2, b"a");
    assert_read(&mut s, 2, b"a", b"k", false, None);
}

#[test]
fn byte_ranges_are_ordered_and_take_whole_map_dependencies_except_when_empty() {
    let mut s = Store::new(0);
    begin(&mut s, 1);
    acquire(&mut s, 1, b"a");
    for key in [b"\xff".as_slice(), b"\x00\x00", b"\x00", b""] {
        write(&mut s, 1, b"a", key, Some(b"value"));
    }
    let lower = Some(Bytes::copy_from(b"\x00"));
    let upper = Some(Bytes::copy_from(b"\xff"));
    let Output::Entries(got) = op(
        &mut s,
        1,
        b"a",
        Operation::Range(lower.clone(), upper.clone()),
    ) else {
        panic!("range must return entries");
    };
    assert_eq!(
        got.iter().map(|(k, _)| k.as_slice()).collect::<Vec<_>>(),
        [b"\x00".as_slice(), b"\x00\x00"]
    );
    assert!(matches!(
        op(&mut s, 1, b"a", Operation::Size),
        Output::Size(4)
    ));
    applied(&mut s, 1, Outcome::Success, 1);
    begin(&mut s, 1);
    acquire(&mut s, 1, b"a");
    op(
        &mut s,
        1,
        b"a",
        Operation::Range(lower.clone(), upper.clone()),
    );
    write(&mut s, 1, b"a", b"\x00", None);
    begin(&mut s, 2);
    acquire(&mut s, 2, b"a");
    assert!(
        matches!(op(&mut s, 2, b"a", Operation::Range(upper, lower)), Output::Entries(entries) if entries.is_empty())
    );
    write(&mut s, 2, b"a", b"\x00", None);
    put(&mut s, 0, b"a", b"outside", b"phantom", 2);
    expect_conflict(&mut s, 1);
    applied(&mut s, 2, Outcome::Success, 3);
    begin(&mut s, 2);
    acquire(&mut s, 2, b"a");
    op(&mut s, 2, b"a", Operation::Clear);
    assert!(matches!(
        op(
            &mut s,
            2,
            b"a",
            Operation::Has(Bytes::copy_from(b"\xff"), false)
        ),
        Output::Presence(false)
    ));
    assert!(
        matches!(op(&mut s, 2, b"a", Operation::Scan), Output::Entries(entries) if entries.is_empty())
    );
    applied(&mut s, 2, Outcome::Success, 4);
}

#[test]
fn rollback_restores_prefix_and_stale_term_cannot_publish() {
    let mut s = Store::new(0);
    begin(&mut s, 0);
    assert!(matches!(
        run(&mut s, Action::Rollback(99, 1)),
        Output::RolledBack(0)
    ));
    acquire(&mut s, 0, b"a");
    write(&mut s, 0, b"a", b"k", Some(b"stale"));
    expect_conflict(&mut s, 0);
    run(&mut s, Action::End(0));
    put(&mut s, 0, b"a", b"k", b"durable", 1);
    run(&mut s, Action::Compact(1));
    put(&mut s, 0, b"a", b"k", b"discarded", 2);
    assert!(matches!(
        run(&mut s, Action::Rollback(1, 2)),
        Output::RolledBack(1)
    ));
    assert!(matches!(
        s.execute(Action::Rollback(1, 1)),
        Err(Error::Disabled)
    ));
    assert!(matches!(
        s.execute(Action::SetTerm(1)),
        Err(Error::Disabled)
    ));
    begin(&mut s, 0);
    acquire(&mut s, 0, b"a");
    assert_read(&mut s, 0, b"a", b"k", true, Some(b"durable"));
    assert_read(&mut s, 0, b"a", b"k", false, Some(b"durable"));
    run(&mut s, Action::CommitBegin(0));
    assert!(matches!(
        run(&mut s, Action::CommitResult(0, Outcome::Success)),
        Output::Committed(Outcome::Success, 0)
    ));
}

#[test]
fn identity_exhaustion_never_looks_like_conflict_or_partially_applies() {
    let mut s = Store::new(0);
    s.history.next_identity = u64::MAX;
    begin(&mut s, 0);
    acquire(&mut s, 0, b"a");
    write(&mut s, 0, b"a", b"k", Some(b"value"));
    run(&mut s, Action::CommitBegin(0));
    assert!(matches!(s.execute(Action::Apply(0)), Err(Error::Exhausted)));
    assert_eq!(s.history.next_identity, u64::MAX);
    assert_eq!(s.history.frames.len(), 1);
    begin(&mut s, 1);
    acquire(&mut s, 1, b"a");
    assert_read(&mut s, 1, b"a", b"k", false, None);
}
