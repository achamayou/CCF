// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use super::*;

#[test]
fn address_comparison_checks_full_key_and_map_after_matching_last_byte() {
    let address = |map, key| Address {
        map: Bytes::copy_from(map),
        key: Bytes::copy_from(key),
    };
    let a = address(b"map", b"xa");
    assert!(a.same(&address(b"map", b"xa")));
    assert!(!a.same(&address(b"map", b"ya")));
    assert!(!a.same(&address(b"map", b"xb")));
    assert!(!a.same(&address(b"map", b"a")));
    assert!(!a.same(&address(b"other", b"xa")));
    assert!(address(b"map", b"").same(&address(b"map", b"")));
    assert!(!address(b"map", b"").same(&address(b"other", b"")));
}

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

#[test]
fn map_validation_compares_only_the_selected_ordered_key_cell_pairs() {
    let m = Bytes::copy_from(b"m");
    let other = Bytes::copy_from(b"other");
    let row = |map: &Bytes, key, version| {
        (
            Address {
                map: map.clone(),
                key: Bytes::copy_from(key),
            },
            Cell {
                value: Bytes::copy_from(b""),
                version,
            },
        )
    };
    let db = Assoc(vec![
        row(&m, b"b", 2),
        row(&other, b"a", 1),
        row(&m, b"a", 1),
    ]);
    let expected = image(&db, &m);
    assert!(same_image(&db, &m, &expected));
    assert!(same_image(
        &db,
        &Bytes::copy_from(b"missing"),
        &Assoc::new()
    ));
    assert!(!same_image(&db, &m, &Assoc::new()));

    let mut changed = db.clone();
    changed.0[1].1.version += 1;
    assert!(same_image(&changed, &m, &expected));
    changed.0[2].1.version += 1;
    assert!(!same_image(&changed, &m, &expected));
    let mut changed = db.clone();
    changed.0.pop();
    assert!(!same_image(&changed, &m, &expected));
    let mut changed = db;
    changed.0.swap(0, 2);
    assert!(!same_image(&changed, &m, &expected));
}

#[test]
fn bulk_publication_matches_the_general_fold_in_order() {
    fn address(i: u8) -> Address {
        let key = [i / 2, i % 5];
        Address {
            map: Bytes::copy_from(&[i % 2]),
            key: Bytes::copy_from(if i < 2 { &[] } else { &key }),
        }
    }

    fn assert_same(actual: Data, expected: &Data) {
        assert_eq!(actual.0.len(), expected.0.len());
        for ((a, c), (want_a, want_c)) in actual.0.iter().zip(&expected.0) {
            assert_eq!(a.map.as_slice(), want_a.map.as_slice());
            assert_eq!(a.key.as_slice(), want_a.key.as_slice());
            assert_eq!(c.value.as_slice(), want_c.value.as_slice());
            assert_eq!(c.version, want_c.version);
        }
    }

    let cell = |i| Cell {
        value: Bytes::copy_from(&[i]),
        version: u64::from(i) + 3,
    };
    let base = Assoc(
        (0..90)
            .rev()
            .map(|i| (address(i), cell(i)))
            .chain([(address(1), cell(97)), (address(80), cell(98))])
            .collect(),
    );
    let mut writes = Assoc(
        (0..64)
            .map(|i| {
                let write = match i % 3 {
                    0 => Write::Remove,
                    1 => Write::Put(Bytes::copy_from(&[])),
                    _ => Write::Put(Bytes::copy_from(&[i])),
                };
                (address(i), write)
            })
            .collect(),
    );
    for len in [63, 64] {
        let prefix = Assoc(writes.0[..len].to_vec());
        let expected = publish_sequential(base.clone(), &prefix, 100);
        assert_same(publish(&base, &prefix, 100), &expected);
        assert_same(publish_batch(&base, &prefix, 100).unwrap(), &expected);
    }
    writes
        .0
        .push((address(0), Write::Put(Bytes::copy_from(b"repeat"))));
    assert!(publish_batch(&base, &writes, 100).is_none());
    assert_same(
        publish(&base, &writes, 100),
        &publish_sequential(base.clone(), &writes, 100),
    );

    let collisions = Assoc(
        (0..65)
            .map(|i| {
                (
                    Address {
                        map: Bytes::copy_from(&[i]),
                        key: Bytes::copy_from(&[]),
                    },
                    Write::Put(Bytes::copy_from(&[i])),
                )
            })
            .collect(),
    );
    assert!(publish_batch(&base, &collisions, 100).is_none());
    assert_same(
        publish(&base, &collisions, 100),
        &publish_sequential(base.clone(), &collisions, 100),
    );
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
fn ending_another_attempt_keeps_the_pinned_reader_and_its_dependency() {
    let mut store = Store::new(0);
    let map = b"public:map";
    put(&mut store, 0, map, b"key", b"before", 1);
    begin(&mut store, 1);
    acquire(&mut store, 1, map);
    assert_read(&mut store, 1, map, b"key", false, Some(b"before"));
    put(&mut store, 2, map, b"key", b"after", 2);

    assert_read(&mut store, 1, map, b"key", false, Some(b"before"));
    write(&mut store, 1, map, b"other", Some(b"new"));
    expect_conflict(&mut store, 1);
}

#[test]
fn a_shared_image_stays_pinned_when_later_acquisitions_pin_different_cuts() {
    let mut s = Store::new(7);
    let m = b"public:map";
    let k = b"key";
    put(&mut s, 1, m, k, b"first", 1);
    run(&mut s, Action::Compact(1));
    begin(&mut s, 2);
    acquire(&mut s, 2, m);

    put(&mut s, 3, m, k, b"second", 2);
    begin(&mut s, 4);
    acquire(&mut s, 4, m);
    run(&mut s, Action::Compact(2));
    begin(&mut s, 5);
    acquire(&mut s, 5, m);

    assert_read(&mut s, 2, m, k, false, Some(b"first"));
    assert_read(&mut s, 2, m, k, true, Some(b"first"));
    assert_read(&mut s, 4, m, k, false, Some(b"second"));
    assert_read(&mut s, 4, m, k, true, Some(b"first"));
    assert_read(&mut s, 5, m, k, false, Some(b"second"));
    assert_read(&mut s, 5, m, k, true, Some(b"second"));
}

#[test]
fn replay_rejects_gaps_and_duplicates_without_publishing() {
    let mut s = Store::new(7);
    let addr = Address {
        map: Bytes::copy_from(b"public:map"),
        key: Bytes::copy_from(b"key"),
    };
    let value = Bytes::copy_from(b"value");
    assert_eq!(
        s.replay_next(2, vec![(addr.clone(), Some(value.clone()))]),
        Err(Error::Disabled)
    );
    assert_eq!(
        s.replay_next(
            1,
            vec![(addr.clone(), Some(value.clone())), (addr.clone(), None)],
        ),
        Err(Error::Disabled)
    );
    assert_eq!(s.history.head().version, 0);
    assert_eq!(s.history.next_identity, 1);

    s.replay_next(1, vec![(addr, Some(value))]).unwrap();
    assert_eq!(s.history.head().version, 1);
    assert_eq!(s.history.term, 7);
    begin(&mut s, 1);
    acquire(&mut s, 1, b"public:map");
    assert_read(&mut s, 1, b"public:map", b"key", false, Some(b"value"));
    assert!(matches!(
        op(
            &mut s,
            1,
            b"public:map",
            Operation::Previous(Bytes::copy_from(b"key"))
        ),
        Output::Previous(Some(1))
    ));
}

#[test]
fn lineage_search_finds_older_active_revisions_but_not_rolled_back_ones() {
    let mut store = Store::new(0);
    let name = b"public:map";
    let map = Bytes::copy_from(name);
    put(&mut store, 0, name, b"key", b"one", 1);
    let first = store.history.head().revision(&map);
    let birth = store.history.head().births.get(&map);
    put(&mut store, 0, name, b"key", b"two", 2);
    let discarded = store.history.head().revision(&map);
    assert!(store.history.map_lineage(&map, birth, first));
    assert!(store.history.map_lineage(&map, birth, discarded));

    assert!(matches!(
        store.execute(Action::Rollback(1, 1)),
        Ok(Output::RolledBack(1))
    ));
    put(&mut store, 0, name, b"key", b"replacement", 2);
    assert!(store.history.map_lineage(&map, birth, first));
    assert!(!store.history.map_lineage(&map, birth, discarded));
}

#[test]
fn invalid_provisional_replay_does_not_cut_back_the_indexed_branch() {
    let mut store = Store::new(0);
    let map = b"public:map";
    let key = b"key";
    let address = Address {
        map: Bytes::copy_from(map),
        key: Bytes::copy_from(key),
    };
    put(&mut store, 0, map, key, b"one", 1);
    put(&mut store, 0, map, key, b"two", 2);
    begin(&mut store, 1);
    acquire(&mut store, 1, map);

    let identity = store.history.next_identity;
    assert_eq!(
        store.replay_ccf(
            2,
            vec![(address.clone(), None), (address.clone(), None)],
            false
        ),
        Err(Error::Disabled)
    );
    assert_eq!(store.history.head().version, 2);
    assert_eq!(store.history.next_identity, identity);
    begin(&mut store, 2);
    acquire(&mut store, 2, map);
    assert_read(&mut store, 2, map, key, false, Some(b"two"));

    store
        .replay_ccf(
            2,
            vec![(address, Some(Bytes::copy_from(b"replacement")))],
            false,
        )
        .unwrap();
    assert_read(&mut store, 1, map, key, false, Some(b"two"));
    begin(&mut store, 3);
    acquire(&mut store, 3, map);
    assert_read(&mut store, 3, map, key, false, Some(b"replacement"));
}

#[test]
fn restored_snapshot_retains_versions_and_only_rolls_back_its_suffix() {
    let mut s = Store::new(7);
    let name = b"public:restored";
    let version = 1_000_000;
    s.install_snapshot(
        version,
        vec![SnapshotMap {
            name: Bytes::copy_from(name),
            revision: version - 1,
            cells: vec![(
                Bytes::copy_from(b"k"),
                version - 3,
                Bytes::copy_from(b"old"),
            )],
        }],
    )
    .unwrap();
    assert_eq!(s.history.log.active_len(), 1);
    assert_eq!(s.history.global, version);
    let maps = s.snapshot_maps(version).unwrap();
    assert_eq!(maps.len(), 1);
    assert_eq!(maps[0].revision, version - 1);
    assert_eq!(maps[0].cells[0].1, version - 3);

    begin(&mut s, 1);
    assert!(matches!(
        acquire(&mut s, 1, name),
        Output::Acquired(local, global) if local == version - 1 && global == local
    ));
    assert_read(&mut s, 1, name, b"k", true, Some(b"old"));
    write(&mut s, 1, name, b"k", Some(b"new"));
    applied(&mut s, 1, Outcome::Success, version + 1);
    assert_eq!(s.history.log.active_len(), 2);
    assert!(matches!(
        run(&mut s, Action::Rollback(version - 1, 8)),
        Output::RollbackRejected
    ));
    assert!(matches!(
        run(&mut s, Action::Rollback(version, 8)),
        Output::RolledBack(v) if v == version
    ));
    assert_eq!(s.history.log.active_len(), 1);
    assert_eq!(s.history.head().version, version);
    begin(&mut s, 2);
    acquire(&mut s, 2, name);
    assert_read(&mut s, 2, name, b"k", false, Some(b"old"));
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
fn history_retains_frame_ids_across_version_reuse_and_snapshot_install() {
    let mut store = Store::new(0);
    put(&mut store, 0, b"a", b"k", b"first", 1);
    put(&mut store, 0, b"a", b"k", b"discarded", 2);
    let pinned = store.history.log.at_cut(2);
    assert!(matches!(
        run(&mut store, Action::Rollback(1, 1)),
        Output::RolledBack(1)
    ));
    put(&mut store, 0, b"a", b"k", b"replacement", 2);
    let key = Address {
        map: Bytes::copy_from(b"a"),
        key: Bytes::copy_from(b"k"),
    };
    let saved = store.history.log.read(pinned);
    assert_eq!(saved.version, 2);
    assert_eq!(
        store
            .history
            .index
            .get(saved.data, &key)
            .unwrap()
            .value
            .as_slice(),
        b"discarded"
    );
    let head = store.history.head();
    assert_eq!(head.version, 2);
    assert_eq!(
        store
            .history
            .index
            .get(head.data, &key)
            .unwrap()
            .value
            .as_slice(),
        b"replacement"
    );
    store.install_snapshot(3, Vec::new()).unwrap();
    assert_eq!(store.history.log.active_len(), 1);
    assert_eq!(store.history.head().version, 3);
    let saved = store.history.log.read(pinned);
    assert_eq!(
        store
            .history
            .index
            .get(saved.data, &key)
            .unwrap()
            .value
            .as_slice(),
        b"discarded"
    );
}

#[test]
fn acquired_views_keep_both_cuts_across_version_reuse_and_snapshot_install() {
    let mut store = Store::new(0);
    put(&mut store, 0, b"a", b"k", b"global", 1);
    run(&mut store, Action::Compact(1));
    put(&mut store, 0, b"a", b"k", b"old-local", 2);
    begin(&mut store, 1);
    acquire(&mut store, 1, b"a");

    assert!(matches!(
        run(&mut store, Action::Rollback(1, 1)),
        Output::RolledBack(1)
    ));
    put(&mut store, 0, b"a", b"k", b"new-local", 2);
    assert_read(&mut store, 1, b"a", b"k", false, Some(b"old-local"));
    assert_read(&mut store, 1, b"a", b"k", true, Some(b"global"));
    store.install_snapshot(3, Vec::new()).unwrap();
    assert_read(&mut store, 1, b"a", b"k", false, Some(b"old-local"));
    assert_read(&mut store, 1, b"a", b"k", true, Some(b"global"));
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
    assert_eq!(s.history.log.active_len(), 1);
    begin(&mut s, 1);
    acquire(&mut s, 1, b"a");
    assert_read(&mut s, 1, b"a", b"k", false, None);
}
