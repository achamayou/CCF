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
fn ccf_pending_writes_replace_and_clear_without_recency_order() {
    let mut store = Store::new(0);
    begin(&mut store, 0);
    for map in [b"m", b"n"] {
        acquire(&mut store, 0, map);
    }
    let mut operation = |map: &[u8], operation| op(&mut store, 0, map, operation);
    let write = |key: &[u8], value: Option<&[u8]>| {
        Operation::Write(Bytes::copy_from(key), value.map(Bytes::copy_from))
    };
    operation(b"m", write(b"z", Some(b"old")));
    operation(b"m", write(b"a", Some(b"first")));
    operation(b"n", write(b"a", Some(b"other map")));
    operation(b"m", write(b"m", Some(b"remove")));
    operation(b"m", write(b"m", None));
    operation(b"m", write(b"z", Some(b"latest")));
    let Output::Entries(rows) = operation(b"m", Operation::Range(None, None)) else {
        panic!("range must return the pending image");
    };
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0.as_slice(), b"a");
    assert_eq!(rows[1].0.as_slice(), b"z");
    assert_eq!(rows[1].1.as_slice(), b"latest");
    operation(b"m", Operation::Clear);
    operation(b"m", write(b"a", Some(b"")));

    let pending = store.pending_writes(0).unwrap();
    assert_eq!(pending.len(), 4);
    assert_eq!(pending[0].0.key.as_slice(), b"z");
    assert!(pending[0].1.is_none());
    assert_eq!(pending[1].0.key.as_slice(), b"m");
    assert!(pending[1].1.is_none());
    assert_eq!(pending[2].0.map.as_slice(), b"n");
    assert_eq!(pending[2].1.as_ref().unwrap().as_slice(), b"other map");
    assert_eq!(pending[3].0.map.as_slice(), b"m");
    assert!(pending[3].1.as_ref().unwrap().as_slice().is_empty());

    applied(&mut store, 0, Outcome::Success, 1);
    begin(&mut store, 1);
    acquire(&mut store, 1, b"m");
    acquire(&mut store, 1, b"n");
    assert_read(&mut store, 1, b"m", b"a", false, Some(b""));
    assert_read(&mut store, 1, b"m", b"z", false, None);
    assert_read(&mut store, 1, b"n", b"a", false, Some(b"other map"));
}

#[test]
fn sorted_publication_keeps_scan_order_and_pinned_values() {
    let mut store = Store::new(0);
    let map = b"public:sorted";
    for (id, value) in [(0, b"old"), (2, b"new")] {
        begin(&mut store, id);
        acquire(&mut store, id, map);
        for key in 0..256_u16 {
            write(&mut store, id, map, &key.to_be_bytes(), Some(value));
        }
        let pending = &store.txs.0[store.tx_index(id).unwrap()].1.pending;
        assert!(prepare_sorted_batch(pending, id + 1).is_some());
        let mut reordered = pending.clone();
        reordered.0.swap(0, 1);
        assert!(prepare_sorted_batch(&reordered, id + 1).is_none());
        let mut crossed_map = pending.clone();
        crossed_map.0[0].0.map = Bytes::copy_from(b"public:other");
        assert!(prepare_sorted_batch(&crossed_map, id + 1).is_none());
        let mut long_key = pending.clone();
        long_key.0[0].0.key = Bytes::copy_from(&[0xff; 57]);
        assert!(prepare_sorted_batch(&long_key, id + 1).is_none());
        let version = if id == 0 { 1 } else { 2 };
        assert!(
            publication_base(&store.history.index, store.history.head().data, pending).is_empty()
        );
        applied(&mut store, id, Outcome::Success, version);
        if id == 0 {
            begin(&mut store, 1);
            acquire(&mut store, 1, map);
        }
    }
    for (id, expected) in [(1, b"old"), (3, b"new")] {
        if id == 3 {
            begin(&mut store, id);
            acquire(&mut store, id, map);
        }
        let Output::Entries(rows) = op(&mut store, id, map, Operation::Scan) else {
            panic!("scan must return the published rows");
        };
        assert_eq!(rows.len(), 256);
        for ((key, value), index) in rows.iter().zip(0..256_u16) {
            assert_eq!(key.as_slice(), index.to_be_bytes());
            assert_eq!(value.as_slice(), expected);
        }
    }
}

#[test]
fn bulk_replacement_requires_full_coverage_and_preserves_a_pinned_cut() {
    let mut store = Store::new(0);
    let map = b"public:batch";
    begin(&mut store, 0);
    acquire(&mut store, 0, map);
    for key in 0..257_u16 {
        write(&mut store, 0, map, &key.to_be_bytes(), Some(b"old"));
    }
    applied(&mut store, 0, Outcome::Success, 1);
    begin(&mut store, 1);
    acquire(&mut store, 1, map);
    begin(&mut store, 2);
    acquire(&mut store, 2, map);
    for key in 0..257_u16 {
        let value = if key == 1 {
            None
        } else {
            Some(b"new".as_slice())
        };
        write(&mut store, 2, map, &key.to_be_bytes(), value);
    }
    let index = &store.history.index;
    let root = store.history.head().data;
    let pending = &store.txs.0[store.tx_index(2).unwrap()].1.pending;
    assert!(prepare_sorted_batch(pending, 2).is_none());
    assert!(
        index
            .scan_links(publication_base(index, root, pending))
            .is_empty()
    );

    let mut partial = pending.clone();
    partial.0.pop();
    assert_eq!(
        index
            .scan_links(publication_base(index, root, &partial))
            .len(),
        257
    );
    let mut reordered = pending.clone();
    reordered.0.swap(0, 1);
    assert_eq!(
        index
            .scan_links(publication_base(index, root, &reordered))
            .len(),
        257
    );

    applied(&mut store, 2, Outcome::Success, 2);
    assert_read(
        &mut store,
        1,
        map,
        &1_u16.to_be_bytes(),
        false,
        Some(b"old"),
    );
    begin(&mut store, 3);
    acquire(&mut store, 3, map);
    let Output::Entries(rows) = op(&mut store, 3, map, Operation::Scan) else {
        panic!("scan must return the replaced rows");
    };
    let keys = (0..257_u16).filter(|&key| key != 1);
    assert_eq!(rows.len(), 256);
    for ((key, value), expected) in rows.iter().zip(keys) {
        assert_eq!(key.as_slice(), expected.to_be_bytes());
        assert_eq!(value.as_slice(), b"new");
    }
}

#[test]
fn older_acquisition_reuses_compacted_images_only_on_ordinary_history() {
    let mut store = Store::new(0);
    let map = b"public:stable";
    let name = Bytes::copy_from(map);
    put(&mut store, 0, map, b"k", b"stable", 1);
    begin(&mut store, 1);
    put(&mut store, 0, b"public:other", b"k", b"advanced", 2);
    run(&mut store, Action::Compact(2));
    assert!(matches!(
        acquire(&mut store, 1, map),
        Output::Acquired(1, 1)
    ));
    let tx = &store.txs.0[store.tx_index(1).unwrap()].1;
    let view = tx.views.get_ref(&name).unwrap();
    let PinnedImage::Root(root) = view.local else {
        panic!("live map must pin a root");
    };
    assert_eq!(root.0, store.history.at_cut(2).data.0);
    assert!(view.global.is_none());
    assert_read(&mut store, 1, map, b"k", false, Some(b"stable"));

    store.install_snapshot(3, Vec::new()).unwrap();
    begin(&mut store, 2);
    put(&mut store, 0, b"public:other", b"k", b"advanced again", 4);
    run(&mut store, Action::Compact(4));
    assert!(matches!(
        acquire(&mut store, 2, map),
        Output::Acquired(1, 1)
    ));
    let tx = &store.txs.0[store.tx_index(2).unwrap()].1;
    let view = tx.views.get_ref(&name).unwrap();
    let PinnedImage::Root(root) = view.local else {
        panic!("live imported map must pin a root");
    };
    assert_eq!(root.0, store.history.at_cut(3).data.0);
    assert!(view.global.is_some());
    assert_read(&mut store, 2, map, b"k", false, Some(b"stable"));
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
    let Output::Entries(committed) = op(
        &mut s,
        1,
        b"a",
        Operation::Range(lower.clone(), upper.clone()),
    ) else {
        panic!("range over committed rows must return entries");
    };
    assert_eq!(
        committed
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice()))
            .collect::<Vec<_>>(),
        [
            (b"\x00".as_slice(), b"value".as_slice()),
            (b"\x00\x00", b"value")
        ]
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
fn ring_branch_and_retained_stay_bounded_across_pinned_churn() {
    let mut store = Store::new(0);
    put(&mut store, 0, b"a", b"k", b"v1", 1);
    begin(&mut store, 1);
    acquire(&mut store, 1, b"a");
    for v in 2..=200u64 {
        put(&mut store, 0, b"a", b"k", format!("v{v}").as_bytes(), v);
        run(&mut store, Action::Compact(v));
    }
    assert_eq!(store.history.log.active_len(), 1);
    assert!(store.history.log.slot_capacity() <= 3);
    assert_eq!(store.history.retained.len(), 1);
    assert_eq!(store.history.retained[0].version, 1);
    assert_read(&mut store, 1, b"a", b"k", false, Some(b"v1"));
    run(&mut store, Action::End(1));
    assert!(store.history.retained.is_empty());
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

#[test]
fn compacted_metadata_elides_when_unneeded_and_preserves_rollback_lineage() {
    let mut s = Store::new(0);
    // v1 writes map "m"; v2 writes "other" so v2 still carries v1's lineage for "m".
    put(&mut s, 0, b"m", b"k1", b"v1", 1);
    put(&mut s, 0, b"other", b"o2", b"v2", 2);
    // Compact to v2 with no live transactions: v0 and v1 are trimmed completely.
    run(&mut s, Action::Compact(2));
    assert_eq!(s.history.log.active_len(), 1);
    assert_eq!(s.history.log.active_at(0).version, 2);
    assert!(s.history.retained.is_empty());

    // Hold a snapshot at v2 so compaction past v2 must retain v2 until End.
    begin(&mut s, 10);

    // Advance to v3 and v4 touching only "other", and have tx 11 acquire "m" at v4.
    put(&mut s, 0, b"other", b"o3", b"v3", 3);
    put(&mut s, 0, b"other", b"o4", b"v4", 4);
    begin(&mut s, 11);
    acquire(&mut s, 11, b"m");

    // Same-term rollback to v3, then overwrite "m" on a different key at v4' and v5'.
    assert!(matches!(
        run(&mut s, Action::Rollback(3, 0)),
        Output::RolledBack(3)
    ));
    put(&mut s, 0, b"m", b"k2", b"v4b", 4);
    put(&mut s, 0, b"m", b"k3", b"v5b", 5);

    // Compact to v5: active ring trims to [v5]; v2, v3, v4' move to retained
    // (v2/v3 for tx 11's lineage & tx 10's snapshot; v4' for tx 11's snapshot version 4).
    run(&mut s, Action::Compact(5));
    assert_eq!(s.history.log.active_len(), 1);
    assert_eq!(s.history.log.active_at(0).version, 5);
    assert!(s.history.resolve_cut(2).is_some());
    assert!(s.history.resolve_cut(3).is_some());
    assert!(s.history.resolve_cut(4).is_some());

    // tx 11 writes a disjoint key on "m" and must still apply cleanly because v2/v3 survive;
    // ending tx 11 inside applied() prunes both v3 (lineage-only) and v4' (snapshot).
    write(&mut s, 11, b"m", b"k4", Some(b"ok"));
    applied(&mut s, 11, Outcome::Success, 6);
    assert!(s.history.resolve_cut(3).is_none());
    assert!(s.history.resolve_cut(4).is_none());
    assert!(s.history.resolve_cut(2).is_some());

    // Ending tx 10 prunes v2 immediately, leaving retained empty.
    run(&mut s, Action::End(10));
    assert!(s.history.retained.is_empty());
}

#[test]
fn detached_tx_preserves_compacted_metadata_and_concurrent_reads() {
    let mut s = Store::new(1);
    let mut writer = DetachedTx::new(1);
    assert!(!writer.is_registered());
    let (v0, t0, out) = s
        .snapshot_and_acquire_detached(&mut writer, Bytes::copy_from(b"m"), None)
        .unwrap();
    assert_eq!((v0, t0), (0, 1));
    assert!(matches!(out, Output::Acquired(0, 0)));
    assert!(writer.is_registered());
    writer
        .stage_write(
            Bytes::copy_from(b"m"),
            Bytes::copy_from(b"k1"),
            Some(Bytes::copy_from(b"v1")),
        )
        .unwrap();
    assert_eq!(writer.pending_writes().unwrap().len(), 1);
    assert!(matches!(
        s.prepare_ccf_commit_detached(&mut writer).unwrap(),
        CommitPreparation::Applied(1, 1)
    ));
    assert!(matches!(
        writer.finish(Outcome::Success).unwrap(),
        Output::Committed(Outcome::Success, 1)
    ));
    assert!(matches!(
        writer
            .inspect_finished(
                &s,
                Bytes::copy_from(b"m"),
                Operation::Get(Bytes::copy_from(b"k1"), false),
            )
            .unwrap(),
        Output::Value(Some(v)) if v.as_slice() == b"v1"
    ));
    s.end_detached(&mut writer);
    assert!(!writer.is_registered());

    // Two detached transactions share `&Store` concurrently across compaction.
    let mut r1 = DetachedTx::new(2);
    let mut r2 = DetachedTx::new(3);
    s.snapshot_and_acquire_detached(&mut r1, Bytes::copy_from(b"m"), None)
        .unwrap();
    s.snapshot_and_acquire_detached(&mut r2, Bytes::copy_from(b"m"), None)
        .unwrap();

    // Advance and compact past v1 while r1 and r2 stay open.
    let mut w2 = DetachedTx::new(4);
    s.snapshot_and_acquire_detached(&mut w2, Bytes::copy_from(b"other"), None)
        .unwrap();
    w2.stage_write(
        Bytes::copy_from(b"other"),
        Bytes::copy_from(b"o"),
        Some(Bytes::copy_from(b"x")),
    )
    .unwrap();
    assert!(matches!(
        s.prepare_ccf_commit_detached(&mut w2).unwrap(),
        CommitPreparation::Applied(2, 1)
    ));
    w2.finish(Outcome::Success).unwrap();
    s.end_detached(&mut w2);

    assert!(matches!(s.compact_ccf(2), Output::Compacted(2)));
    assert!(s.history.resolve_cut(1).is_some());

    // Both detached readers observe via immutable `&Store` while staging writes locally.
    assert!(matches!(
        r1.operate(
            &s,
            Bytes::copy_from(b"m"),
            Operation::Get(Bytes::copy_from(b"k1"), false),
        )
        .unwrap(),
        Output::Value(Some(v)) if v.as_slice() == b"v1"
    ));
    r2.stage_write(
        Bytes::copy_from(b"m"),
        Bytes::copy_from(b"k2"),
        Some(Bytes::copy_from(b"v2")),
    )
    .unwrap();
    assert!(matches!(
        r2.operate(
            &s,
            Bytes::copy_from(b"m"),
            Operation::Get(Bytes::copy_from(b"k2"), false),
        )
        .unwrap(),
        Output::Value(Some(v)) if v.as_slice() == b"v2"
    ));

    // Late acquisition on r1 against compacted v1 succeeds via retained metadata.
    assert!(matches!(
        s.snapshot_and_acquire_detached(&mut r1, Bytes::copy_from(b"late"), None)
            .unwrap()
            .2,
        Output::Acquired(0, 0)
    ));

    // Ending both detached transactions prunes retained metadata completely.
    s.end_detached(&mut r1);
    assert!(s.history.resolve_cut(1).is_some());
    s.end_detached(&mut r2);
    assert!(s.history.retained.is_empty());
}

#[test]
fn reserved_placeholder_backfills_across_concurrent_writes_and_preserves_overwrites() {
    let mut s = Store::new(1);

    // Seed v1 with shared/k1 = "v1".
    let mut seed = DetachedTx::new(1);
    s.snapshot_and_acquire_detached(&mut seed, Bytes::copy_from(b"shared"), None)
        .unwrap();
    seed.stage_write(
        Bytes::copy_from(b"shared"),
        Bytes::copy_from(b"k1"),
        Some(Bytes::copy_from(b"v1")),
    )
    .unwrap();
    assert!(matches!(
        s.prepare_ccf_commit_detached(&mut seed).unwrap(),
        CommitPreparation::Applied(1, 1)
    ));
    s.end_detached(&mut seed);

    // Reserve v2 as a placeholder, then commit a normal transaction at v3
    // touching a disjoint map "app" and overwriting shared/k1.
    assert_eq!(s.reserve_placeholder_ccf().unwrap(), 2);

    let mut normal = DetachedTx::new(2);
    s.snapshot_and_acquire_detached(&mut normal, Bytes::copy_from(b"app"), None)
        .unwrap();
    s.snapshot_and_acquire_detached(&mut normal, Bytes::copy_from(b"shared"), None)
        .unwrap();
    normal
        .stage_write(
            Bytes::copy_from(b"app"),
            Bytes::copy_from(b"a"),
            Some(Bytes::copy_from(b"app_v3")),
        )
        .unwrap();
    normal
        .stage_write(
            Bytes::copy_from(b"shared"),
            Bytes::copy_from(b"k1"),
            Some(Bytes::copy_from(b"v3")),
        )
        .unwrap();
    assert!(matches!(
        s.prepare_ccf_commit_detached(&mut normal).unwrap(),
        CommitPreparation::Applied(3, 1)
    ));
    s.end_detached(&mut normal);

    // Backfill reserved v2 writing a new signature map "sig", plus shared/k1
    // (overwritten at v3) and shared/k2 (untouched at v3).
    let mut reserved = DetachedTx::new(3);
    s.snapshot_and_acquire_detached(&mut reserved, Bytes::copy_from(b"sig"), Some(1))
        .unwrap();
    s.snapshot_and_acquire_detached(&mut reserved, Bytes::copy_from(b"shared"), Some(1))
        .unwrap();
    reserved
        .stage_write(
            Bytes::copy_from(b"sig"),
            Bytes::copy_from(b"s"),
            Some(Bytes::copy_from(b"sig_v2")),
        )
        .unwrap();
    reserved
        .stage_write(
            Bytes::copy_from(b"shared"),
            Bytes::copy_from(b"k1"),
            Some(Bytes::copy_from(b"v2")),
        )
        .unwrap();
    reserved
        .stage_write(
            Bytes::copy_from(b"shared"),
            Bytes::copy_from(b"k2"),
            Some(Bytes::copy_from(b"v2_k2")),
        )
        .unwrap();
    assert!(matches!(
        s.backfill_reserved_ccf(&mut reserved, 2).unwrap(),
        CommitPreparation::Applied(2, 1)
    ));
    s.end_detached(&mut reserved);

    // Verify historical cut at v2 sees v2's writes and NOT v3's writes.
    let mut read_v2 = DetachedTx::new(4);
    s.snapshot_and_acquire_detached(&mut read_v2, Bytes::copy_from(b"sig"), Some(2))
        .unwrap();
    s.snapshot_and_acquire_detached(&mut read_v2, Bytes::copy_from(b"shared"), Some(2))
        .unwrap();
    s.snapshot_and_acquire_detached(&mut read_v2, Bytes::copy_from(b"app"), Some(2))
        .unwrap();
    assert!(matches!(
        read_v2
            .operate(
                &s,
                Bytes::copy_from(b"sig"),
                Operation::Get(Bytes::copy_from(b"s"), false)
            )
            .unwrap(),
        Output::Value(Some(v)) if v.as_slice() == b"sig_v2"
    ));
    assert!(matches!(
        read_v2
            .operate(
                &s,
                Bytes::copy_from(b"shared"),
                Operation::Get(Bytes::copy_from(b"k1"), false)
            )
            .unwrap(),
        Output::Value(Some(v)) if v.as_slice() == b"v2"
    ));
    assert!(matches!(
        read_v2
            .operate(
                &s,
                Bytes::copy_from(b"app"),
                Operation::Get(Bytes::copy_from(b"a"), false)
            )
            .unwrap(),
        Output::Value(None)
    ));
    s.end_detached(&mut read_v2);

    // Verify head at v3 sees backfilled sig & shared/k2 AND preserves v3's
    // overwrite of shared/k1 and app/a.
    let mut read_v3 = DetachedTx::new(5);
    s.snapshot_and_acquire_detached(&mut read_v3, Bytes::copy_from(b"sig"), None)
        .unwrap();
    s.snapshot_and_acquire_detached(&mut read_v3, Bytes::copy_from(b"shared"), None)
        .unwrap();
    s.snapshot_and_acquire_detached(&mut read_v3, Bytes::copy_from(b"app"), None)
        .unwrap();
    assert!(matches!(
        read_v3
            .operate(
                &s,
                Bytes::copy_from(b"sig"),
                Operation::Get(Bytes::copy_from(b"s"), false)
            )
            .unwrap(),
        Output::Value(Some(v)) if v.as_slice() == b"sig_v2"
    ));
    assert!(matches!(
        read_v3
            .operate(
                &s,
                Bytes::copy_from(b"shared"),
                Operation::Get(Bytes::copy_from(b"k1"), false)
            )
            .unwrap(),
        Output::Value(Some(v)) if v.as_slice() == b"v3"
    ));
    assert!(matches!(
        read_v3
            .operate(
                &s,
                Bytes::copy_from(b"shared"),
                Operation::Get(Bytes::copy_from(b"k2"), false)
            )
            .unwrap(),
        Output::Value(Some(v)) if v.as_slice() == b"v2_k2"
    ));
    assert!(matches!(
        read_v3
            .operate(
                &s,
                Bytes::copy_from(b"app"),
                Operation::Get(Bytes::copy_from(b"a"), false)
            )
            .unwrap(),
        Output::Value(Some(v)) if v.as_slice() == b"app_v3"
    ));
    s.end_detached(&mut read_v3);

    assert!(matches!(s.compact_ccf(3), Output::Compacted(3)));
    assert_eq!(s.map_revision_at(3, &Bytes::copy_from(b"sig")), Some(2));
    assert_eq!(s.map_revision_at(3, &Bytes::copy_from(b"shared")), Some(3));
}

#[test]
fn install_snapshot_sorts_unsorted_maps_preserves_omitted_and_rejects_duplicates() {
    let mut s = Store::new(1);
    put(&mut s, 0, b"keep", b"old", b"v1", 1);
    put(&mut s, 0, b"replaced", b"stale", b"drop", 2);

    // Reject duplicate keys within a map without mutating the store.
    let dup = vec![SnapshotMap {
        name: Bytes::copy_from(b"replaced"),
        revision: 2,
        cells: vec![
            (Bytes::copy_from(b"b"), 2, Bytes::copy_from(b"1")),
            (Bytes::copy_from(b"a"), 1, Bytes::copy_from(b"2")),
            (Bytes::copy_from(b"b"), 2, Bytes::copy_from(b"3")),
        ],
    }];
    assert_eq!(s.install_snapshot(5, dup), Err(Error::Disabled));
    assert_eq!(s.history.global, 0);

    // Install unsorted multi-map snapshot with prefix keys and varying map lengths.
    let snap = vec![
        SnapshotMap {
            name: Bytes::copy_from(b"longer_map"),
            revision: 4,
            cells: vec![
                (Bytes::copy_from(b"ab"), 4, Bytes::copy_from(b"v_ab")),
                (Bytes::copy_from(b""), 1, Bytes::copy_from(b"v_empty")),
                (Bytes::copy_from(b"a"), 3, Bytes::copy_from(b"v_a")),
            ],
        },
        SnapshotMap {
            name: Bytes::copy_from(b"replaced"),
            revision: 5,
            cells: vec![
                (Bytes::copy_from(b"z"), 5, Bytes::copy_from(b"vz")),
                (Bytes::copy_from(b"k"), 2, Bytes::copy_from(b"vk")),
            ],
        },
        SnapshotMap {
            name: Bytes::copy_from(b"m"),
            revision: 3,
            cells: vec![(Bytes::copy_from(b"x"), 3, Bytes::copy_from(b"vx"))],
        },
    ];
    s.install_snapshot(5, snap).unwrap();
    assert_eq!(s.history.global, 5);

    begin(&mut s, 10);
    acquire(&mut s, 10, b"keep");
    acquire(&mut s, 10, b"replaced");
    acquire(&mut s, 10, b"longer_map");
    acquire(&mut s, 10, b"m");
    assert_read(&mut s, 10, b"keep", b"old", false, Some(b"v1"));
    assert_read(&mut s, 10, b"replaced", b"stale", false, None);
    assert_read(&mut s, 10, b"replaced", b"k", false, Some(b"vk"));
    assert_read(&mut s, 10, b"replaced", b"z", false, Some(b"vz"));
    assert_read(&mut s, 10, b"longer_map", b"", false, Some(b"v_empty"));
    assert_read(&mut s, 10, b"longer_map", b"a", false, Some(b"v_a"));
    assert_read(&mut s, 10, b"longer_map", b"ab", false, Some(b"v_ab"));
    assert_read(&mut s, 10, b"m", b"x", false, Some(b"vx"));
    run(&mut s, Action::End(10));
}
