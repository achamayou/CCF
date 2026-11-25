// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use std::hint::black_box;
use std::time::Instant;

use ccf_kv::engine::{Action, Bytes, Operation, Outcome, Output, Store};

const SAMPLES: usize = 9;
const ATTEMPT: u64 = 1;

fn measure(
    workload: &str,
    entries: usize,
    operations: usize,
    mut setup: impl FnMut() -> Store,
    mut run: impl FnMut(&mut Store),
) {
    let mut samples = [0.0; SAMPLES];
    run(&mut setup());
    for sample in &mut samples {
        let mut store = setup();
        let start = Instant::now();
        run(&mut store);
        *sample = start.elapsed().as_secs_f64() * 1e9 / operations as f64;
        black_box(&store);
    }
    samples.sort_unstable_by(f64::total_cmp);
    println!(
        "{workload},{entries},{operations},{:.1},{:.1},{:.1}",
        samples[SAMPLES / 2],
        samples[0],
        samples[SAMPLES - 1],
    );
}

fn attempt(store: &mut Store, id: u64, map: &Bytes) {
    store.execute(Action::Begin(id)).unwrap();
    store.execute(Action::Snapshot(id)).unwrap();
    assert!(matches!(
        store.execute(Action::Acquire(id, map.clone())).unwrap(),
        Output::Acquired(..)
    ));
}

fn write(store: &mut Store, id: u64, map: &Bytes, keys: &[Bytes], value: &Bytes) {
    for key in keys {
        black_box(
            store
                .execute(Action::Operate(
                    id,
                    map.clone(),
                    Operation::Write(key.clone(), Some(value.clone())),
                ))
                .unwrap(),
        );
    }
}

fn staged(map: &Bytes, keys: &[Bytes], value: &Bytes) -> Store {
    let mut store = Store::new(0);
    attempt(&mut store, ATTEMPT, map);
    write(&mut store, ATTEMPT, map, keys, value);
    store
}

fn main() {
    let map = Bytes::copy_from(b"benchmark");
    let value = Bytes::copy_from(&[0xab; 64]);
    println!("workload,entries,operations,median_ns_per_operation,min_ns,max_ns");
    for entries in [64, 512, 2048] {
        let keys: Vec<Bytes> = (0..entries as u64)
            .map(|i| Bytes::copy_from(&i.to_be_bytes()))
            .collect();
        measure(
            "stage_distinct",
            entries,
            entries,
            || staged(&map, &[], &value),
            |store| write(store, ATTEMPT, &map, &keys, &value),
        );
        measure(
            "stage_replace",
            entries,
            entries,
            || staged(&map, &keys, &value),
            |store| write(store, ATTEMPT, &map, &keys, &value),
        );
        measure(
            "apply",
            entries,
            1,
            || {
                let mut store = staged(&map, &keys, &value);
                store.execute(Action::CommitBegin(ATTEMPT)).unwrap();
                store
            },
            |store| {
                let out = store.execute(Action::Apply(ATTEMPT)).unwrap();
                assert!(matches!(&out, Output::Applied(1, 0, writes) if writes.len() == entries));
                black_box(out);
            },
        );
    }

    let keys: Vec<Bytes> = (0_u64..512)
        .map(|i| Bytes::copy_from(&i.to_be_bytes()))
        .collect();
    measure(
        "point_read",
        keys.len(),
        keys.len(),
        || {
            let mut store = staged(&map, &keys, &value);
            store.execute(Action::CommitBegin(ATTEMPT)).unwrap();
            store.execute(Action::Apply(ATTEMPT)).unwrap();
            store
                .execute(Action::CommitResult(ATTEMPT, Outcome::Success))
                .unwrap();
            store.execute(Action::End(ATTEMPT)).unwrap();
            attempt(&mut store, ATTEMPT, &map);
            store
        },
        |store| {
            for key in &keys {
                let out = store
                    .execute(Action::Operate(
                        ATTEMPT,
                        map.clone(),
                        Operation::Get(key.clone(), false),
                    ))
                    .unwrap();
                assert!(matches!(&out, Output::Value(Some(v)) if v.as_slice() == value.as_slice()));
                black_box(out);
            }
        },
    );
}
