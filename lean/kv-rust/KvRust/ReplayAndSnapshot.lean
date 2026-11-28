-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Apply
public import KvRust.SnapshotInstall

import all Aeneas.Data.List.List

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

local instance replayInstDecidableEqBytes : DecidableEq CcfKv.engine.Bytes :=
  fun a b =>
    decidable_of_iff (alloc.vec.Vec.val a = alloc.vec.Vec.val b)
      ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

local instance replayInstDecidableEqAddress : DecidableEq CcfKv.engine.Address :=
  fun a b =>
    decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

/-! ### Part 1: Ordered CCF replay and empty-base sorted-batch replay -/

private theorem byteOrder_self (xs : List U8) : byteOrder xs xs = 0#i8 := by
  induction xs with
  | nil => rfl
  | cons x rest ih =>
      simp only [byteOrder, lt_irrefl, ite_false]
      exact ih

/-- `compare_address_order a b` returns `-1` only when `a` strictly precedes `b`
in `(map.len, map, key)` order, so in particular `a ≠ b`. -/
theorem compare_address_order_lt_ne (a b : CcfKv.engine.Address)
    : WP.spec (CcfKv.engine.compare_address_order a b)
        (fun ord => ord = (-1)#i8 → a ≠ b) := by
  unfold CcfKv.engine.compare_address_order
  simp only [CcfKv.engine.Bytes.as_slice, bind_ok]
  have hma : (Slice.len (alloc.vec.Vec.deref a.map)).val = a.map.val.length := by
    simp [alloc.vec.Vec.deref]
  have hmb : (Slice.len (alloc.vec.Vec.deref b.map)).val = b.map.val.length := by
    simp [alloc.vec.Vec.deref]
  by_cases hlt :
    Slice.len (alloc.vec.Vec.deref a.map) < Slice.len (alloc.vec.Vec.deref b.map)
  · rw [ite_eq_left hlt, WP.spec_ok]
    intro _ heq
    subst heq
    have : a.map.val.length < a.map.val.length := by rwa [← hma]
    omega
  · rw [ite_eq_right hlt]
    by_cases hgt : Slice.len (alloc.vec.Vec.deref a.map) > Slice.len (alloc.vec.Vec.deref b.map)
    · rw [ite_eq_left hgt, WP.spec_ok]
      intro h; cases h
    · rw [ite_eq_right hgt]
      apply WP.spec_bind
        (compare_slices_spec (alloc.vec.Vec.deref a.map) (alloc.vec.Vec.deref b.map))
      intro mord hmord
      by_cases hne : mord != 0#i8
      · rw [ite_eq_left hne, WP.spec_ok]
        intro hneg heq
        subst heq
        have hzero : mord = 0#i8 := by rw [hmord, byteOrder_self]
        rw [hzero] at hneg
        cases hneg
      · rw [ite_eq_right hne]
        apply WP.spec_mono
          (compare_slices_spec (alloc.vec.Vec.deref a.key) (alloc.vec.Vec.deref b.key))
        intro kord hkord hneg heq
        subst heq
        have hzero : kord = 0#i8 := by rw [hkord, byteOrder_self]
        rw [hzero] at hneg
        cases hneg

/-- `writes_strictly_increasing` always terminates cleanly. -/
theorem writes_strictly_increasing_terminates
    (writes : alloc.vec.Vec (CcfKv.engine.Address × Option CcfKv.engine.Bytes))
    : WP.spec (CcfKv.engine.writes_strictly_increasing writes) (fun _ => True) := by
  unfold CcfKv.engine.writes_strictly_increasing CcfKv.engine.writes_strictly_increasing_loop
  have hlen : (alloc.vec.Vec.len writes).val = writes.val.length := alloc.vec.Vec.len_val writes
  have hcap := alloc.vec.Vec.len_ineq writes
  apply loop.spec_decr_nat
    (fun i : Usize => writes.val.length + 1 - i.val)
    (fun i => 1 ≤ i.val) _ _ _
  · intro i hi
    unfold CcfKv.engine.writes_strictly_increasing_loop.body
    by_cases hlt : i < alloc.vec.Vec.len writes
    · have hiLt : i.val < writes.val.length := by rwa [← hlen]
      rw [ite_eq_left hlt]
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.sub_spec (x := i) (y := 1#usize) (by omega))
      intro i2 hi2
      have hi2Lt : i2.val < writes.val.length := by omega
      rw [alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec writes i2 hi2Lt)
      rintro ⟨a, _⟩ _
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec writes i hiLt)
      rintro ⟨a1, _⟩ _
      apply WP.spec_bind (compare_address_order_lt_ne a a1)
      intro ord _
      by_cases hne : ord != (-1)#i8
      · rw [ite_eq_left hne, WP.spec_ok]; trivial
      · rw [ite_eq_right hne]
        apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
        intro i4 hi4
        rw [WP.spec_ok]
        exact ⟨by omega, by omega⟩
    · rw [ite_eq_right hlt, WP.spec_ok]; trivial
  · change 1 ≤ (1#usize : Usize).val; decide

/-- `prepare_replay_ordered` copies every write into `Assoc` preserving exact order. -/
theorem prepare_replay_ordered_spec
    (writes : alloc.vec.Vec (CcfKv.engine.Address × Option CcfKv.engine.Bytes))
    : WP.spec (CcfKv.engine.prepare_replay_ordered writes)
        (fun pending => pending.val = writes.val.map replayRow) := by
  have hlen : (alloc.vec.Vec.len writes).val = writes.val.length := alloc.vec.Vec.len_val writes
  have hcap := alloc.vec.Vec.len_ineq writes
  have hloop : WP.spec
      (CcfKv.engine.prepare_replay_ordered_loop writes
        (alloc.vec.Vec.with_capacity (CcfKv.engine.Address × CcfKv.engine.Write)
          (alloc.vec.Vec.len writes)) 0#usize)
      (fun rows => rows.val = writes.val.map replayRow) := by
    unfold CcfKv.engine.prepare_replay_ordered_loop
    apply loop.spec_decr_nat
      (fun p : alloc.vec.Vec (CcfKv.engine.Address × CcfKv.engine.Write) × Usize =>
        writes.val.length - p.2.val)
      (fun (rows, j) =>
        rows.val.length = j.val
        ∧ rows.val ++ (writes.val.drop j.val).map replayRow = writes.val.map replayRow)
      _ _ _
    · rintro ⟨rows, j⟩ ⟨hj, hrows⟩
      dsimp only at hj hrows ⊢
      unfold CcfKv.engine.prepare_replay_ordered_loop.body
      have hone : (1#usize : Usize).val = 1 := rfl
      by_cases hlt : j < alloc.vec.Vec.len writes
      · have hjLt : j.val < writes.val.length := by rwa [← hlen]
        rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec writes j hjLt)
        rintro ⟨addr, value⟩ hrow
        have hwrite :
            (match value with
            | none => Result.ok CcfKv.engine.Write.Remove
            | some bytes => do
                let b ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone bytes
                Result.ok (CcfKv.engine.Write.Put b))
            = .ok (replayRow (addr, value)).2 := by
          cases value <;> simp [replayRow, clone_bytes]
        change WP.spec (do
          let write ←
            match value with
            | none => Result.ok CcfKv.engine.Write.Remove
            | some bytes => do
                let b ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone bytes
                Result.ok (CcfKv.engine.Write.Put b)
          let a ← CcfKv.engine.Address.Insts.CoreCloneClone.clone addr
          let rows1 ← alloc.vec.Vec.push rows (a, write)
          let j1 ← j + 1#usize
          Result.ok (ControlFlow.cont (rows1, j1))) _
        rw [hwrite, bind_ok, clone_address, bind_ok]
        apply WP.spec_bind (alloc.vec.Vec.push_spec rows _ (by omega))
        intro rows1 hrows1
        apply WP.spec_bind (Usize.add_spec (x := j) (y := 1#usize) (by omega))
        intro j1 hj1
        have hj1Val : j1.val = j.val + 1 := by omega
        have hsplit : writes.val.drop j.val = (addr, value) :: writes.val.drop j1.val := by
          rw [hj1Val, List.drop_eq_getElem_cons hjLt, ← hrow]
        rw [WP.spec_ok]
        dsimp only
        refine ⟨⟨by simp [hrows1, hj, hj1Val], ?_⟩, by omega⟩
        simpa [replayRow, hrows1, hsplit, List.append_assoc] using hrows
      · have hge : writes.val.length ≤ j.val := by
          rw [← hlen]; exact Nat.le_of_not_gt hlt
        rw [ite_eq_right hlt, WP.spec_ok]
        simpa [List.drop_eq_nil_of_le hge] using hrows
    · simp [alloc.vec.Vec.with_capacity]
  unfold CcfKv.engine.prepare_replay_ordered
  apply WP.spec_bind hloop
  intro rows hrows
  rw [WP.spec_ok]
  exact hrows

/-- `Store.prepare_replay_ccf` matches `Store.prepare_replay`: rejects duplicates or
version mismatches with `Err .Disabled`, or returns the exact mapped write list. -/
theorem prepare_replay_ccf_matches (previous identity version : U64)
    (hVersion : version.val = previous.val + 1) (hI : identity.val < U64.max)
    (writes : alloc.vec.Vec (CcfKv.engine.Address × Option CcfKv.engine.Bytes))
    : WP.spec (CcfKv.engine.Store.prepare_replay_ccf previous identity version writes)
        (fun result =>
          result = .Err .Disabled
          ∨ ∃ pending,
              result = .Ok pending ∧ pending.val = writes.val.map replayRow) := by
  have hmax : core.num.U64.MAX.val = U64.max := by rw [U64.max_eq]; rfl
  have hle : version.val ≤ U64.max := by scalar_tac
  have hv : previous ≠ core.num.U64.MAX := fun he => by
    have he' := congrArg (fun v : U64 => v.val) he; omega
  have hi : identity ≠ core.num.U64.MAX := fun he => by
    have he' := congrArg (fun v : U64 => v.val) he; omega
  have hone : (1#u64 : U64).val = 1 := rfl
  unfold CcfKv.engine.Store.prepare_replay_ccf
  simp only [hv, hi, ite_false]
  apply WP.spec_bind (U64.add_spec (x := previous) (y := 1#u64) (by omega))
  intro v hv'
  have hEq : v = version := UScalar.eq_of_val_eq (by omega)
  subst v
  simp only [bne_self_eq_false, Bool.false_eq_true, ite_false]
  apply WP.spec_bind (writes_strictly_increasing_terminates writes)
  intro ordered _
  cases ordered with
  | true =>
      simp only [ite_true]
      apply WP.spec_bind (prepare_replay_ordered_spec writes)
      intro pending hp
      rw [WP.spec_ok]
      exact Or.inr ⟨pending, rfl, hp⟩
  | false =>
      simp only [Bool.false_eq_true, ite_false]
      exact prepare_replay_matches previous identity version hVersion hI writes

/-- `collect_replay_put_batch` succeeds only when all writes are `Put`s, producing an
all-`some` vector of `SnapshotBatchRow`s matching `pending` entry-for-entry. -/
theorem collect_replay_put_batch_spec
    (pending : CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write)
    (version : U64)
    (hKeys : ∀ row ∈ pending.val, IndexKeyRoom row)
    : WP.spec (CcfKv.engine.collect_replay_put_batch pending version)
        (fun res =>
          match res with
          | none => True
          | some batch =>
              ∃ rows : List SnapshotBatchRow,
                batch.val = rows.map some
                ∧ rows.length = pending.val.length
                ∧ (∀ i,
                    i < pending.val.length
                    → ∃ a val r,
                        pending.val[i]? = some (a, .Put val)
                        ∧ rows[i]? = some r
                        ∧ r.key.val = packedAddress a
                        ∧ r.value = { address := a, value := { value := val, version } }
                        ∧ r.key.val.length
                          = 8 + a.map.val.length + a.key.val.length)) := by
  unfold CcfKv.engine.collect_replay_put_batch
  have hlen : (alloc.vec.Vec.len pending).val = pending.val.length :=
    alloc.vec.Vec.len_val pending
  have hcap := alloc.vec.Vec.len_ineq pending
  by_cases hsmall : alloc.vec.Vec.len pending < 64#usize
  · simp only [hsmall, ite_true, WP.spec_ok]
  · simp only [hsmall, ite_false]
    unfold CcfKv.engine.collect_replay_put_batch_loop
    apply loop.spec_decr_nat
      (fun p : alloc.vec.Vec (Option SnapshotBatchRow) × Usize =>
        pending.val.length - p.2.val)
      (fun (batch, j) =>
        j.val ≤ pending.val.length
        ∧ ∃ rows : List SnapshotBatchRow,
            batch.val = rows.map some
            ∧ rows.length = j.val
            ∧ ∀ k, k < j.val →
                ∃ a val r,
                  pending.val[k]? = some (a, .Put val)
                  ∧ rows[k]? = some r
                  ∧ r.key.val = packedAddress a
                  ∧ r.value = { address := a, value := { value := val, version } }
                  ∧ r.key.val.length = 8 + a.map.val.length + a.key.val.length)
      _ _ _
    · rintro ⟨batch, j⟩ ⟨hjLe, rows, hbatch, hrowsLen, hmatch⟩
      dsimp only at hjLe hbatch hrowsLen hmatch ⊢
      unfold CcfKv.engine.collect_replay_put_batch_loop.body
      by_cases hlt : j < alloc.vec.Vec.len pending
      · have hjLt : j.val < pending.val.length := by rwa [← hlen]
        rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending j hjLt)
        rintro ⟨addr, write⟩ hrow
        cases write with
        | Remove => simp [WP.spec_ok]
        | Put val =>
            simp only [clone_address, clone_bytes, bind_ok]
            have hmem : (addr, CcfKv.engine.Write.Put val) ∈ pending.val := by
              rw [hrow]; exact List.getElem_mem hjLt
            have hkroom : 2 * (8 + addr.map.val.length + addr.key.val.length) + 1 ≤ Usize.max :=
              hKeys (addr, CcfKv.engine.Write.Put val) hmem
            have hpackRoom : 8 + addr.map.val.length + addr.key.val.length ≤ Usize.max := by
              omega
            apply WP.spec_bind
              (index_batch_row_refines addr
                ({ value := val, version } : CcfKv.engine.Cell) hpackRoom)
            intro rr ⟨hrKey, hrVal, hrLen⟩
            have hbatchLen : batch.val.length < Usize.max := by
              rw [hbatch, List.length_map, hrowsLen]; omega
            apply WP.spec_bind (alloc.vec.Vec.push_spec batch (some rr) hbatchLen)
            intro batch1 hbatch1
            have hone : (1#usize : Usize).val = 1 := rfl
            apply WP.spec_bind (Usize.add_spec (x := j) (y := 1#usize) (by omega))
            intro j1 hj1
            rw [WP.spec_ok]
            dsimp only
            refine ⟨⟨by omega, rows ++ [rr], ?_, ?_, ?_⟩, by omega⟩
            · rw [hbatch1, hbatch, List.map_append]; rfl
            · rw [List.length_append, List.length_singleton, hrowsLen]; omega
            · intro k hk
              by_cases hkj : k < j.val
              · obtain ⟨a0, v0, r0, hp0, hr0, hk0, hv0, hl0⟩ := hmatch k hkj
                refine ⟨a0, v0, r0, hp0, ?_, hk0, hv0, hl0⟩
                rw [List.getElem?_append_left (by omega)]
                exact hr0
              · have hkEq : k = j.val := by omega
                subst hkEq
                refine ⟨addr, val, rr, ?_, ?_, hrKey, hrVal, hrLen⟩
                · rw [List.getElem?_eq_getElem hjLt, ← hrow]
                · rw [List.getElem?_append_right (by omega), hrowsLen, Nat.sub_self]
                  rfl
      · have hge : pending.val.length ≤ j.val := by
          rw [← hlen]; exact Nat.le_of_not_gt hlt
        have hjEq : j.val = pending.val.length := by omega
        rw [ite_eq_right hlt, WP.spec_ok]
        exact ⟨rows, hbatch, hjEq ▸ hrowsLen, fun k hk => hmatch k (by omega)⟩
    · refine ⟨Nat.zero_le _, [], by simp [alloc.vec.Vec.with_capacity], rfl, fun k hk => by
        change k < (0#usize : Usize).val at hk; have : (0#usize : Usize).val = 0 := rfl; omega⟩

/-- On put-only writes, `advance_replay_stamps_put_only` produces the exact same
`revisions` and `births` maps (up to `find` on every map name) as `Kv.Model.advance`. -/
theorem advance_replay_stamps_put_only_spec (encode : List U8 → String)
    (inj : Function.Injective encode)
    (revisions births : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.Stamp)
    (pending : CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write)
    (stamp : CcfKv.engine.Stamp)
    (hPutOnly : ∀ row ∈ pending.val, ∃ val, row.2 = .Put val)
    (hR : revisions.val.length + pending.val.length ≤ Usize.max)
    (hB : births.val.length + pending.val.length ≤ Usize.max)
    : WP.spec (CcfKv.engine.advance_replay_stamps_put_only revisions births pending stamp)
        (fun (revOut, birthOut) =>
          (∀ m,
            find (revOut.val.map fun (k, s) => (encode k.val, modelStamp s)) m
            = find
                ((encodeWrites encode (byteWrites pending.val)).foldl
                  (fun rs (a, value) =>
                    if value.isSome || (find ([] : Data) a).isSome then
                      set rs a.1 (modelStamp stamp)
                    else
                      rs)
                  (revisions.val.map fun (k, s) => (encode k.val, modelStamp s)))
                m)
          ∧ (∀ m,
              find (birthOut.val.map fun (k, s) => (encode k.val, modelStamp s)) m
              = find
                  ((encodeWrites encode (byteWrites pending.val)).foldl
                    (fun bs (a, _) =>
                      if (find bs a.1).isSome then
                        bs
                      else
                        set bs a.1 (modelStamp stamp))
                    (births.val.map fun (k, s) => (encode k.val, modelStamp s)))
                  m)) := by
  let enc : CcfKv.engine.Bytes → String := fun b => encode b.val
  have hencInj : Function.Injective enc := inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  let revStep (rs : Assoc String Stamp) (w : Addr String String × Option String) : Assoc String Stamp :=
    if w.2.isSome || (find ([] : Data) w.1).isSome then set rs w.1.1 (modelStamp stamp) else rs
  let birthStep (bs : Assoc String Stamp) (w : Addr String String × Option String) : Assoc String Stamp :=
    if (find bs w.1.1).isSome then bs else set bs w.1.1 (modelStamp stamp)
  let proj (rows : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.Stamp) : Assoc String Stamp :=
    rows.val.map fun (k, s) => (enc k, modelStamp s)
  let encW (row : CcfKv.engine.Address × CcfKv.engine.Write) : Addr String String × Option String :=
    (encodeAddr encode (byteAddr row.1),
      match row.2 with
      | .Put v => some (encode v.val)
      | .Remove => none)
  have hEW : encodeWrites encode (byteWrites pending.val) = pending.val.map encW := by
    simp only [encodeWrites, byteWrites, List.map_map, Function.comp_def]
    apply List.map_congr_left
    rintro ⟨a, w⟩ _
    cases w <;> rfl
  have hbyteSame : ∀ a b : CcfKv.engine.Bytes,
      CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey.same a b = .ok (decide (a = b)) := fun a b => by
    rw [bytes_same]; congr 1
  have hfindSet : ∀ (xs : Assoc String Stamp) (k : String) (v : Stamp) (q : String),
      find (Kv.Model.set xs k v) q = if q = k then some v else find xs q := by
    intro xs k v q
    unfold Kv.Model.set
    by_cases hqk : q = k
    · subst hqk; simp [find]
    · have hkq : k ≠ q := Ne.symm hqk
      simp only [find, hkq, ite_false, hqk]
      unfold Kv.Model.erase
      induction xs with
      | nil => rfl
      | cons head tail ih =>
          by_cases hhk : head.1 = k
          · have hneq : (head.1 != k) = false := by simp [hhk]
            have hnq : head.1 ≠ q := by rw [hhk]; exact hkq
            simp [hneq, find, hnq, ih]
          · have hneq : (head.1 != k) = true := by simp [hhk]
            by_cases hhq : head.1 = q
            · rw [List.filter_cons, hneq, ite_eq_left rfl, find, ite_eq_left hhq, find,
                ite_eq_left hhq]
            · rw [List.filter_cons, hneq, ite_eq_left rfl, find, ite_eq_right hhq, find,
                ite_eq_right hhq]
              exact ih
  have hlen : (alloc.vec.Vec.len pending).val = pending.val.length := alloc.vec.Vec.len_val pending
  have hcap := alloc.vec.Vec.len_ineq pending
  rw [hEW]
  unfold CcfKv.engine.advance_replay_stamps_put_only CcfKv.engine.advance_replay_stamps_put_only_loop
  apply loop.spec_decr_nat
    (fun p : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.Stamp ×
        CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.Stamp ×
        CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write × Usize =>
      pending.val.length - p.2.2.2.val)
    (fun (curRev, curBirth, curPend, i) =>
      curPend = pending
      ∧ i.val ≤ pending.val.length
      ∧ curRev.val.length ≤ revisions.val.length + i.val
      ∧ curBirth.val.length ≤ births.val.length + i.val
      ∧ (∀ m, find (proj curRev) m
            = find (((pending.val.take i.val).map encW).foldl revStep (proj revisions)) m)
      ∧ (∀ m, find (proj curBirth) m
            = find (((pending.val.take i.val).map encW).foldl birthStep (proj births)) m)
      ∧ (∀ prev, 0 < i.val → pending.val[i.val - 1]? = some prev →
            find (proj curRev) (enc prev.1.map) = some (modelStamp stamp)
            ∧ (find (proj curBirth) (enc prev.1.map)).isSome = true))
    _ _ _
  · rintro ⟨curRev, curBirth, curPend, i⟩
      ⟨hpendEq, hiLe, hrevLen, hbirthLen, hrevEq, hbirthEq, hprevSet⟩
    dsimp only at hpendEq hiLe hrevLen hbirthLen hrevEq hbirthEq hprevSet ⊢
    subst curPend
    unfold CcfKv.engine.advance_replay_stamps_put_only_loop.body
    by_cases hlt : i < alloc.vec.Vec.len pending
    · have hiLt : i.val < pending.val.length := by rwa [← hlen]
      rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending i hiLt)
      rintro ⟨a, w⟩ hrow
      have hmem : (a, w) ∈ pending.val := by rw [hrow]; exact List.getElem_mem hiLt
      obtain ⟨val, hwPut⟩ := hPutOnly (a, w) hmem
      dsimp only at hwPut
      subst hwPut
      have htakeSucc : pending.val.take (i.val + 1) = pending.val.take i.val ++ [(a, .Put val)] := by
        rw [List.take_add_one, List.getElem?_eq_getElem hiLt, ← hrow]; simp
      have hrevStepEq : ∀ rs, revStep rs (encW (a, .Put val)) = Kv.Model.set rs (enc a.map) (modelStamp stamp) := by
        intro rs
        simp [revStep, encW, encodeAddr, byteAddr, enc]
      have hbirthStepEq : ∀ bs,
          birthStep bs (encW (a, .Put val)) =
            if (find bs (enc a.map)).isSome then bs
            else Kv.Model.set bs (enc a.map) (modelStamp stamp) := by
        intro bs; simp [birthStep, encW, encodeAddr, byteAddr, enc]
      have hupdateSpec : WP.spec
          (do
            let b ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a.map
            let rev1 ←
              CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                curRev b stamp
            let birth1 ← CcfKv.engine.update_birth curBirth a.map stamp
            Result.ok (rev1, birth1))
          (fun (rev1, birth1) =>
            rev1.val.length ≤ curRev.val.length + 1
            ∧ birth1.val.length ≤ curBirth.val.length + 1
            ∧ (∀ m, find (proj rev1) m =
                find (revStep (((pending.val.take i.val).map encW).foldl revStep (proj revisions))
                  (encW (a, .Put val))) m)
            ∧ (∀ m, find (proj birth1) m =
                find (birthStep (((pending.val.take i.val).map encW).foldl birthStep (proj births))
                  (encW (a, .Put val))) m)) := by
        simp only [clone_bytes, bind_ok]
        apply WP.spec_bind
          (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
            CcfKv.engine.Bytes.Insts.CoreCloneClone
            CcfKv.engine.Stamp.Insts.CoreCloneClone curRev a.map stamp
            (fun k => hbyteSame k a.map) clone_bytes (fun _ => rfl) (by omega))
        intro rev1 hrev1
        have hrev1Len : rev1.val.length ≤ curRev.val.length + 1 := by
          rw [hrev1, Kv.Model.set, List.length_cons]
          exact Nat.succ_le_succ (List.length_filter_le _ _)
        have hrev1Proj : proj rev1 = Kv.Model.set (proj curRev) (enc a.map) (modelStamp stamp) := by
          simp only [proj, hrev1, set_projected curRev.val a.map stamp enc modelStamp hencInj]
        unfold CcfKv.engine.update_birth
        rw [Aeneas.Std.bind_assoc]
        apply WP.spec_bind
          (assoc_index CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey curBirth a.map
            (fun k => hbyteSame k a.map))
        intro idx hidx
        have hfindBirth : find (proj curBirth) (enc a.map) = (find curBirth.val a.map).map modelStamp :=
          find_projected curBirth.val a.map enc modelStamp hencInj
        cases idx with
        | some k =>
            have hnoneFalse : core.option.Option.is_none (some k) = false := rfl
            rw [hnoneFalse]
            simp only [Bool.false_eq_true, ite_false, bind_ok, WP.spec_ok]
            obtain ⟨v0, _, hv0⟩ := hidx
            refine ⟨hrev1Len, Nat.le_succ _, ?_, ?_⟩
            · intro m
              rw [hrev1Proj, hrevStepEq, hfindSet, hfindSet, hrevEq m]
            · intro m
              rw [hbirthStepEq, ← hbirthEq (enc a.map), hfindBirth, hv0]
              simp only [Option.map_some, Option.isSome_some, ite_true]
              exact hbirthEq m
        | none =>
            have hnoneTrue : core.option.Option.is_none (none : Option Usize) = true := rfl
            rw [hnoneTrue]
            simp only [ite_true, clone_bytes, bind_ok]
            apply WP.spec_bind
              (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                CcfKv.engine.Bytes.Insts.CoreCloneClone
                CcfKv.engine.Stamp.Insts.CoreCloneClone curBirth a.map stamp
                (fun k => hbyteSame k a.map) clone_bytes (fun _ => rfl) (by omega))
            intro birth1 hbirth1
            rw [WP.spec_ok]
            have hbirth1Len : birth1.val.length ≤ curBirth.val.length + 1 := by
              rw [hbirth1, Kv.Model.set, List.length_cons]
              exact Nat.succ_le_succ (List.length_filter_le _ _)
            have hbirth1Proj : proj birth1 = Kv.Model.set (proj curBirth) (enc a.map) (modelStamp stamp) := by
              simp only [proj, hbirth1, set_projected curBirth.val a.map stamp enc modelStamp hencInj]
            have hnone : find curBirth.val a.map = none := hidx
            refine ⟨hrev1Len, hbirth1Len, ?_, ?_⟩
            · intro m
              rw [hrev1Proj, hrevStepEq, hfindSet, hfindSet, hrevEq m]
            · intro m
              rw [hbirthStepEq, ← hbirthEq (enc a.map), hfindBirth, hnone]
              simp only [Option.map_none, Option.isSome_none, Bool.false_eq_true, ite_false]
              rw [hbirth1Proj, hfindSet, hfindSet, hbirthEq m]
      have hbranch : WP.spec
          (if i = 0#usize then
            do
              let b ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a.map
              let rev1 ←
                CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                  CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                  curRev b stamp
              let birth1 ← CcfKv.engine.update_birth curBirth a.map stamp
              Result.ok (rev1, birth1)
          else
            do
              let i2 ← i - 1#usize
              let (a1, _) ←
                alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice
                  (CcfKv.engine.Address × CcfKv.engine.Write)) pending i2
              let b ← CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey.same a1.map a.map
              if b then Result.ok (curRev, curBirth)
              else
                let b1 ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a.map
                let rev1 ←
                  CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                    CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                    curRev b1 stamp
                let birth1 ← CcfKv.engine.update_birth curBirth a.map stamp
                Result.ok (rev1, birth1))
          (fun (rev1, birth1) =>
            rev1.val.length ≤ curRev.val.length + 1
            ∧ birth1.val.length ≤ curBirth.val.length + 1
            ∧ (∀ m, find (proj rev1) m =
                find (revStep (((pending.val.take i.val).map encW).foldl revStep (proj revisions))
                  (encW (a, .Put val))) m)
            ∧ (∀ m, find (proj birth1) m =
                find (birthStep (((pending.val.take i.val).map encW).foldl birthStep (proj births))
                  (encW (a, .Put val))) m)) := by
        by_cases hz : i = 0#usize
        · rw [ite_eq_left hz]; exact hupdateSpec
        · rw [ite_eq_right hz]
          have hiPos : 0 < i.val := by
            by_contra h0
            have : i.val = 0 := by omega
            exact hz (UScalar.eq_of_val_eq this)
          have hone : (1#usize : Usize).val = 1 := rfl
          apply WP.spec_bind (Usize.sub_spec (x := i) (y := 1#usize) (by omega))
          intro i2 hi2
          have hi2Val : i2.val = i.val - 1 := by omega
          have hi2Lt : i2.val < pending.val.length := by omega
          rw [alloc.vec.Vec.index_slice_index]
          apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending i2 hi2Lt)
          rintro ⟨a1, w1⟩ hprevRow
          change WP.spec (do
            let b ← CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey.same a1.map a.map
            if b then Result.ok (curRev, curBirth)
            else
              let b1 ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a.map
              let rev1 ←
                CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                  CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                  curRev b1 stamp
              let birth1 ← CcfKv.engine.update_birth curBirth a.map stamp
              Result.ok (rev1, birth1)) _
          rw [hbyteSame a1.map a.map, bind_ok]
          by_cases hsame : a1.map = a.map
          · simp only [hsame, decide_true, ite_true, WP.spec_ok]
            have hprevAt : pending.val[i.val - 1]? = some (a1, w1) := by
              rw [← hi2Val, List.getElem?_eq_getElem hi2Lt, ← hprevRow]
            obtain ⟨hprevR, hprevB⟩ := hprevSet (a1, w1) hiPos hprevAt
            rw [hsame] at hprevR hprevB
            refine ⟨Nat.le_succ _, Nat.le_succ _, ?_, ?_⟩
            · intro m
              rw [hrevStepEq, hfindSet]
              by_cases hm : m = enc a.map
              · subst hm; rw [ite_eq_left rfl]; exact hprevR
              · rw [ite_eq_right hm]; exact hrevEq m
            · intro m
              rw [hbirthStepEq, ← hbirthEq (enc a.map)]
              simp only [hprevB, ite_true]
              exact hbirthEq m
          · simp only [hsame, decide_false, Bool.false_eq_true, ite_false]
            exact hupdateSpec
      apply WP.spec_bind hbranch
      rintro ⟨rev1, birth1⟩ ⟨hr1Len, hb1Len, hr1Eq, hb1Eq⟩
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro i2 hi2
      have hi2Val : i2.val = i.val + 1 := by omega
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨rfl, by omega, by omega, by omega, ?_, ?_, ?_⟩, by omega⟩
      · intro m
        rw [hi2Val, htakeSucc, List.map_append, List.map_singleton, List.foldl_append, List.foldl_cons,
          List.foldl_nil]
        exact hr1Eq m
      · intro m
        rw [hi2Val, htakeSucc, List.map_append, List.map_singleton, List.foldl_append, List.foldl_cons,
          List.foldl_nil]
        exact hb1Eq m
      · intro prev _ hprevAt
        have hprevEq : prev = (a, .Put val) := by
          rw [hi2Val, Nat.add_sub_cancel, List.getElem?_eq_getElem hiLt, ← hrow] at hprevAt
          exact Option.some.inj hprevAt.symm
        subst hprevEq
        constructor
        · rw [hr1Eq (enc a.map), hrevStepEq, hfindSet, ite_eq_left rfl]
        · rw [hb1Eq (enc a.map), hbirthStepEq]
          cases hf
                : find (((pending.val.take i.val).map encW).foldl birthStep (proj births))
                    (enc a.map) with
          | some _ => simp only [Option.isSome_some, ite_true, hf]
          | none => simp [hfindSet]
    · have hge : pending.val.length ≤ i.val := by
        rw [← hlen]; exact Nat.le_of_not_gt hlt
      have hiEq : i.val = pending.val.length := by omega
      rw [ite_eq_right hlt, WP.spec_ok]
      rw [hiEq, List.take_length] at hrevEq hbirthEq
      exact ⟨hrevEq, hbirthEq⟩
  · refine ⟨rfl, Nat.zero_le _, by simp, by simp, fun m => by simp, fun m => by simp,
      fun _ hpos => by change 0 < (0#usize : Usize).val at hpos; exact absurd hpos (by decide)⟩

/-- `Store.replay_ccf` rejects provisional replay at or below the compacted frontier
without modifying the store. -/
theorem replay_ccf_rejects_below_global (s : CcfKv.engine.Store)
    (prior : List CcfKv.engine.Frame) (head : CcfKv.engine.Frame)
    (hHead : s.history.activeFrames = prior ++ [head])
    (valid : BranchValid s.history.log)
    (version : U64) (hpos : version ≠ 0#u64) (hleHead : version ≤ head.version)
    (hbelow : version.val - 1 < s.history.global.val)
    (writes : alloc.vec.Vec (CcfKv.engine.Address × Option CcfKv.engine.Bytes))
    (trackDeletes : Bool)
    : WP.spec (CcfKv.engine.Store.replay_ccf s version writes trackDeletes)
        (fun r => r = (.Err .Disabled, s)) := by
  unfold CcfKv.engine.Store.replay_ccf
  have hbne : (version != 0#u64) = true := by
    simp [bne_iff_ne, hpos]
  rw [ite_eq_left hbne, history_head s.history prior head hHead valid, bind_ok,
    ite_eq_left hleHead]
  have hvpos : 1 ≤ version.val := by
    by_contra h0
    have : version.val = 0 := by omega
    exact hpos (UScalar.eq_of_val_eq this)
  have hone : (1#u64 : U64).val = 1 := rfl
  apply WP.spec_bind (U64.sub_spec (x := version) (y := 1#u64) (by omega))
  intro prev hprev
  have hlt : prev < s.history.global := by
    change prev.val < s.history.global.val; omega
  rw [ite_eq_left hlt, WP.spec_ok]

/-! ### Part 2: Full `Store.install_snapshot` verification -/

/-- `Store.install_snapshot` rejects versions below the global frontier without mutating `s`. -/
theorem install_snapshot_rejects_below_global (s : CcfKv.engine.Store)
    (version : U64) (maps : alloc.vec.Vec CcfKv.engine.SnapshotMap)
    (hbelow : version < s.history.global)
    : WP.spec (CcfKv.engine.Store.install_snapshot s version maps)
        (fun r => r = (.Err .Disabled, s)) := by
  unfold CcfKv.engine.Store.install_snapshot
  simp [hbelow]

/-- `Store.install_snapshot` rejects when `next_identity = u64::MAX` without mutating `s`. -/
theorem install_snapshot_rejects_exhausted (s : CcfKv.engine.Store)
    (version : U64) (maps : alloc.vec.Vec CcfKv.engine.SnapshotMap)
    (hge : ¬ version < s.history.global)
    (hmax : s.history.next_identity = core.num.U64.MAX)
    : WP.spec (CcfKv.engine.Store.install_snapshot s version maps)
        (fun r => r = (.Err .Exhausted, s)) := by
  unfold CcfKv.engine.Store.install_snapshot
  simp [hge, hmax]

private theorem validate_snapshot_map_loop0_terminates (rev : U64)
    (cells : alloc.vec.Vec (CcfKv.engine.Bytes × U64 × CcfKv.engine.Bytes))
    : WP.spec (CcfKv.engine.validate_snapshot_map_loop0 rev cells 0#usize)
        (fun _ => True) := by
  unfold CcfKv.engine.validate_snapshot_map_loop0
  have hlen : (alloc.vec.Vec.len cells).val = cells.val.length := alloc.vec.Vec.len_val cells
  have hcap := alloc.vec.Vec.len_ineq cells
  apply loop.spec_decr_nat
    (fun j : Usize => cells.val.length - j.val)
    (fun _ => True) _ _ _
  · intro j _
    unfold CcfKv.engine.validate_snapshot_map_loop0.body
    by_cases hlt : j < alloc.vec.Vec.len cells
    · have hjLt : j.val < cells.val.length := by rwa [← hlen]
      rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec cells j hjLt)
      rintro ⟨_, written, _⟩ _
      change WP.spec (if written = 0#u64 then Result.ok (ControlFlow.done false)
        else if written > rev then Result.ok (ControlFlow.done false)
        else do let j1 ← j + 1#usize; Result.ok (ControlFlow.cont j1)) _
      by_cases hz : written = 0#u64
      · rw [ite_eq_left hz, WP.spec_ok]; trivial
      · rw [ite_eq_right hz]
        by_cases hbad : written > rev
        · rw [ite_eq_left hbad, WP.spec_ok]; trivial
        · rw [ite_eq_right hbad]
          have hone : (1#usize : Usize).val = 1 := rfl
          apply WP.spec_bind (Usize.add_spec (x := j) (y := 1#usize) (by omega))
          intro j1 hj1
          rw [WP.spec_ok]; exact ⟨trivial, by omega⟩
    · rw [ite_eq_right hlt, WP.spec_ok]; trivial
  · trivial

private theorem validate_snapshot_map_loop1_terminates (rev : U64)
    (cells : alloc.vec.Vec (CcfKv.engine.Bytes × U64 × CcfKv.engine.Bytes))
    : WP.spec (CcfKv.engine.validate_snapshot_map_loop1 rev cells 0#usize)
        (fun _ => True) := by
  unfold CcfKv.engine.validate_snapshot_map_loop1
  have hlen : (alloc.vec.Vec.len cells).val = cells.val.length := alloc.vec.Vec.len_val cells
  have hcap := alloc.vec.Vec.len_ineq cells
  apply loop.spec_decr_nat
    (fun j : Usize => cells.val.length - j.val)
    (fun _ => True) _ _ _
  · intro j _
    unfold CcfKv.engine.validate_snapshot_map_loop1.body
    by_cases hlt : j < alloc.vec.Vec.len cells
    · have hjLt : j.val < cells.val.length := by rwa [← hlen]
      rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec cells j hjLt)
      rintro ⟨_, written, _⟩ _
      change WP.spec (if written = 0#u64 then Result.ok (ControlFlow.done false)
        else if written > rev then Result.ok (ControlFlow.done false)
        else do let j1 ← j + 1#usize; Result.ok (ControlFlow.cont j1)) _
      by_cases hz : written = 0#u64
      · rw [ite_eq_left hz, WP.spec_ok]; trivial
      · rw [ite_eq_right hz]
        by_cases hbad : written > rev
        · rw [ite_eq_left hbad, WP.spec_ok]; trivial
        · rw [ite_eq_right hbad]
          have hone : (1#usize : Usize).val = 1 := rfl
          apply WP.spec_bind (Usize.add_spec (x := j) (y := 1#usize) (by omega))
          intro j1 hj1
          rw [WP.spec_ok]; exact ⟨trivial, by omega⟩
    · rw [ite_eq_right hlt, WP.spec_ok]; trivial
  · trivial

private theorem validate_snapshot_map_spec (frame : CcfKv.engine.Frame)
    (sm : CcfKv.engine.SnapshotMap) (identity : U64)
    (hB : frame.births.val.length < Usize.max)
    (hR : frame.revisions.val.length < Usize.max)
    : WP.spec (CcfKv.engine.validate_snapshot_map frame sm identity)
        (fun (_, frame1) =>
          frame1.version = frame.version
          ∧ frame1.data = frame.data
          ∧ frame1.births.val.length ≤ frame.births.val.length + 1
          ∧ frame1.revisions.val.length ≤ frame.revisions.val.length + 1) := by
  have hbyteSame : ∀ a b : CcfKv.engine.Bytes,
      CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey.same a b = .ok (decide (a = b)) := fun a b => by
    rw [bytes_same]; congr 1
  unfold CcfKv.engine.validate_snapshot_map
  by_cases hrevGt : sm.revision > frame.version
  · rw [ite_eq_left hrevGt, WP.spec_ok]
    exact ⟨rfl, rfl, Nat.le_succ _, Nat.le_succ _⟩
  · rw [ite_eq_right hrevGt]
    apply WP.spec_bind
      (assoc_get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
        CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
        frame.births sm.name (fun k => hbyteSame k sm.name) (fun _ => rfl))
    intro found _
    have hUpdateBoth :
        WP.spec
          (do
            let b ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone sm.name
            let a ←
              CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                frame.births b { version := sm.revision, identity }
            let a1 ←
              if sm.revision = 0#u64 then
                CcfKv.engine.Assoc.erase CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                  CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                  frame.revisions sm.name
              else
                CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                  CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                  frame.revisions b { version := sm.revision, identity }
            Result.ok (a, a1))
          (fun (a, a1) =>
            a.val.length ≤ frame.births.val.length + 1
            ∧ a1.val.length ≤ frame.revisions.val.length + 1) := by
      simp only [clone_bytes, bind_ok]
      apply WP.spec_bind
        (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
          CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
          frame.births sm.name { version := sm.revision, identity }
          (fun k => hbyteSame k sm.name) clone_bytes (fun _ => rfl) hB)
      intro a ha
      have haLen : a.val.length ≤ frame.births.val.length + 1 := by
        rw [ha, Kv.Model.set, List.length_cons]
        exact Nat.succ_le_succ (List.length_filter_le _ _)
      by_cases hz : sm.revision = 0#u64
      · rw [ite_eq_left hz]
        apply WP.spec_bind
          (assoc_erase CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
            CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
            frame.revisions sm.name (fun k => hbyteSame k sm.name) clone_bytes (fun _ => rfl))
        intro a1 ha1
        rw [WP.spec_ok]
        refine ⟨haLen, ?_⟩
        rw [ha1, Kv.Model.erase]
        exact (List.length_filter_le _ _).trans (Nat.le_succ _)
      · rw [ite_eq_right hz]
        apply WP.spec_bind
          (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
            CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
            frame.revisions sm.name { version := sm.revision, identity }
            (fun k => hbyteSame k sm.name) clone_bytes (fun _ => rfl) hR)
        intro a1 ha1
        rw [WP.spec_ok]
        refine ⟨haLen, ?_⟩
        rw [ha1, Kv.Model.set, List.length_cons]
        exact Nat.succ_le_succ (List.length_filter_le _ _)
    cases found with
    | none =>
        simp only [clone_bytes, bind_ok]
        apply WP.spec_bind
          (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
            CcfKv.engine.Bytes.Insts.CoreCloneClone
            CcfKv.engine.Stamp.Insts.CoreCloneClone frame.births sm.name
            { version := sm.revision, identity } (fun k => hbyteSame k sm.name)
            clone_bytes (fun _ => rfl) hB)
        intro a ha
        have haLen : a.val.length ≤ frame.births.val.length + 1 := by
          rw [ha, Kv.Model.set, List.length_cons]
          exact Nat.succ_le_succ (List.length_filter_le _ _)
        have ha1Spec : WP.spec
            (if sm.revision = 0#u64 then
              CcfKv.engine.Assoc.erase CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                frame.revisions sm.name
            else
              CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                frame.revisions sm.name { version := sm.revision, identity })
            (fun a1 => a1.val.length ≤ frame.revisions.val.length + 1) := by
          by_cases hz : sm.revision = 0#u64
          · rw [ite_eq_left hz]
            apply WP.spec_mono
              (assoc_erase CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                frame.revisions sm.name (fun k => hbyteSame k sm.name) clone_bytes (fun _ => rfl))
            intro a1 ha1; rw [ha1, Kv.Model.erase]
            exact (List.length_filter_le _ _).trans (Nat.le_succ _)
          · rw [ite_eq_right hz]
            apply WP.spec_mono
              (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                frame.revisions sm.name { version := sm.revision, identity }
                (fun k => hbyteSame k sm.name) clone_bytes (fun _ => rfl) hR)
            intro a1 ha1; rw [ha1, Kv.Model.set, List.length_cons]
            exact Nat.succ_le_succ (List.length_filter_le _ _)
        apply WP.spec_bind ha1Spec
        intro a1 ha1Len
        apply WP.spec_bind (validate_snapshot_map_loop0_terminates sm.revision sm.cells)
        intro _ _
        rw [WP.spec_ok]
        exact ⟨rfl, rfl, haLen, ha1Len⟩
    | some prev =>
        dsimp only
        by_cases hdup : prev.identity = identity
        · rw [ite_eq_left hdup, WP.spec_ok]
          exact ⟨rfl, rfl, Nat.le_succ _, Nat.le_succ _⟩
        · rw [ite_eq_right hdup]
          simp only [clone_bytes, bind_ok]
          apply WP.spec_bind
            (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
              CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
              frame.births sm.name { version := sm.revision, identity }
              (fun k => hbyteSame k sm.name) clone_bytes (fun _ => rfl) hB)
          intro a ha
          have haLen : a.val.length ≤ frame.births.val.length + 1 := by
            rw [ha, Kv.Model.set, List.length_cons]
            exact Nat.succ_le_succ (List.length_filter_le _ _)
          have ha1Spec : WP.spec
              (if sm.revision = 0#u64 then
                CcfKv.engine.Assoc.erase CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                  CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                  frame.revisions sm.name
              else
                CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                  CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                  frame.revisions sm.name { version := sm.revision, identity })
              (fun a1 => a1.val.length ≤ frame.revisions.val.length + 1) := by
            by_cases hz : sm.revision = 0#u64
            · rw [ite_eq_left hz]
              apply WP.spec_mono
                (assoc_erase CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                  CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                  frame.revisions sm.name (fun k => hbyteSame k sm.name) clone_bytes (fun _ => rfl))
              intro a1 ha1; rw [ha1, Kv.Model.erase]
              exact (List.length_filter_le _ _).trans (Nat.le_succ _)
            · rw [ite_eq_right hz]
              apply WP.spec_mono
                (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                  CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                  frame.revisions sm.name { version := sm.revision, identity }
                  (fun k => hbyteSame k sm.name) clone_bytes (fun _ => rfl) hR)
              intro a1 ha1; rw [ha1, Kv.Model.set, List.length_cons]
              exact Nat.succ_le_succ (List.length_filter_le _ _)
          apply WP.spec_bind ha1Spec
          intro a1 ha1Len
          apply WP.spec_bind (validate_snapshot_map_loop1_terminates sm.revision sm.cells)
          intro _ _
          rw [WP.spec_ok]
          exact ⟨rfl, rfl, haLen, ha1Len⟩

/-- Total cell count across a list of `SnapshotMap`s. -/
def snapshotCellCount (maps : List CcfKv.engine.SnapshotMap) : Nat :=
  maps.foldl (fun acc m => acc + m.cells.val.length) 0

private theorem snapshotCellCount_append (xs : List CcfKv.engine.SnapshotMap)
    (m : CcfKv.engine.SnapshotMap)
    : snapshotCellCount (xs ++ [m]) = snapshotCellCount xs + m.cells.val.length := by
  simp [snapshotCellCount]

private theorem snapshotCellCount_take_le (maps : List CcfKv.engine.SnapshotMap) (k : Nat)
    : snapshotCellCount (maps.take k) ≤ snapshotCellCount maps := by
  have hsplit : maps = maps.take k ++ maps.drop k := (List.take_append_drop k maps).symm
  have hshift : ∀ (xs : List CcfKv.engine.SnapshotMap) (init : Nat),
      xs.foldl (fun acc m => acc + m.cells.val.length) init
        = init + xs.foldl (fun acc m => acc + m.cells.val.length) 0 := by
    intro xs
    induction xs with
    | nil => intro init; simp
    | cons h t ih =>
        intro init
        simp only [List.foldl_cons, Nat.zero_add]
        rw [ih (init + h.cells.val.length), ih h.cells.val.length]
        omega
  have hadd : ∀ (a b : List CcfKv.engine.SnapshotMap),
      snapshotCellCount (a ++ b) = snapshotCellCount a + snapshotCellCount b := by
    intro a b
    unfold snapshotCellCount
    rw [List.foldl_append, hshift]
  conv_rhs => rw [hsplit, hadd]
  omega

private theorem validate_snapshot_maps_spec (frame : CcfKv.engine.Frame)
    (maps : Slice CcfKv.engine.SnapshotMap) (identity : U64)
    (hB : frame.births.val.length + maps.val.length ≤ Usize.max)
    (hR : frame.revisions.val.length + maps.val.length ≤ Usize.max)
    (hCells : snapshotCellCount maps.val ≤ Usize.max)
    : WP.spec (CcfKv.engine.validate_snapshot_maps frame maps identity)
        (fun (res, frame1) =>
          frame1.version = frame.version
          ∧ frame1.data = frame.data
          ∧ match res with
            | none => True
            | some total => total.val = snapshotCellCount maps.val) := by
  unfold CcfKv.engine.validate_snapshot_maps CcfKv.engine.validate_snapshot_maps_loop
  have hlen : (Slice.len maps).val = maps.val.length := Slice.len_val maps
  have hcap : maps.val.length ≤ Usize.max := maps.property
  apply loop.spec_decr_nat
    (fun p : CcfKv.engine.Frame × Usize × Usize => maps.val.length - p.2.2.val)
    (fun (cur, total, i) =>
      i.val ≤ maps.val.length
      ∧ cur.version = frame.version
      ∧ cur.data = frame.data
      ∧ cur.births.val.length ≤ frame.births.val.length + i.val
      ∧ cur.revisions.val.length ≤ frame.revisions.val.length + i.val
      ∧ total.val = snapshotCellCount (maps.val.take i.val))
    _ _ _
  · rintro ⟨cur, total, i⟩ ⟨hiLe, hver, hdat, hcurB, hcurR, htot⟩
    dsimp only at hiLe hver hdat hcurB hcurR htot ⊢
    unfold CcfKv.engine.validate_snapshot_maps_loop.body
    by_cases hlt : i < Slice.len maps
    · have hiLt : i.val < maps.val.length := by rwa [← hlen]
      rw [ite_eq_left hlt]
      apply WP.spec_bind (Slice.index_usize_spec maps i hiLt)
      intro sm hsm
      apply WP.spec_bind
        (validate_snapshot_map_spec cur sm identity (by omega) (by omega))
      rintro ⟨ok, cur1⟩ ⟨hver1, hdat1, hB1, hR1⟩
      change WP.spec (if ok = true then do
        let total1 ← total + alloc.vec.Vec.len sm.cells
        let i1 ← i + 1#usize
        Result.ok (ControlFlow.cont (cur1, total1, i1))
        else Result.ok (ControlFlow.done (none, cur1))) _
      cases ok with
      | true =>
          simp only [ite_true]
          have htakeSucc : maps.val.take (i.val + 1) = maps.val.take i.val ++ [sm] := by
            rw [List.take_add_one, List.getElem?_eq_getElem hiLt, ← hsm]; simp
          have hsumLe : snapshotCellCount (maps.val.take (i.val + 1)) ≤ snapshotCellCount maps.val :=
            snapshotCellCount_take_le maps.val (i.val + 1)
          have hsmLen : (alloc.vec.Vec.len sm.cells).val = sm.cells.val.length :=
            alloc.vec.Vec.len_val sm.cells
          rw [htakeSucc, snapshotCellCount_append] at hsumLe
          apply WP.spec_bind
            (Usize.add_spec (x := total) (y := alloc.vec.Vec.len sm.cells) (by omega))
          intro total1 htotal1
          have hone : (1#usize : Usize).val = 1 := rfl
          apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
          intro i1 hi1
          rw [WP.spec_ok]
          dsimp only
          refine ⟨
            ⟨by omega, hver1.trans hver, hdat1.trans hdat, by omega, by omega, ?_⟩,
            by omega
          ⟩
          rw [show i1.val = i.val + 1 by omega, htakeSucc, snapshotCellCount_append]
          omega
      | false =>
          simp only [Bool.false_eq_true, ite_false, WP.spec_ok]
          exact ⟨hver1.trans hver, hdat1.trans hdat, trivial⟩
    · have hge : maps.val.length ≤ i.val := by
        rw [← hlen]; exact Nat.le_of_not_gt hlt
      have hiEq : i.val = maps.val.length := by omega
      rw [ite_eq_right hlt, WP.spec_ok]
      rw [hiEq, List.take_length] at htot
      exact ⟨hver, hdat, htot⟩
  · refine ⟨Nat.zero_le _, rfl, rfl, by simp, by simp, by simp [snapshotCellCount]⟩

private theorem collect_preserved_snapshot_rows_spec
    (batch : alloc.vec.Vec (Option SnapshotBatchRow))
    (index : CellIndex) (frame : CcfKv.engine.Frame) (identity : U64)
    (initRows : List SnapshotBatchRow) (frameRows : CellRows)
    (hOwned : batch.val = initRows.map some)
    (hView : IndexView index frame.data frameRows) (hValid : IndexValid index)
    (hScanRoom : 18 * frameRows.length ≤ Usize.max)
    (hBatchRoom : initRows.length + frameRows.length ≤ Usize.max)
    (hKeys
      : ∀ row ∈ frameRows, 8 + row.1.map.val.length + row.1.key.val.length ≤ Usize.max)
    (hRowDepth : ∀ row ∈ frameRows, 8 + row.1.map.val.length + row.1.key.val.length ≤ 56)
    (hInitDepth : ∀ r ∈ initRows, r.key.val.length ≤ 56)
    (hInitPacked : ∀ r ∈ initRows, r.key.val = packedAddress r.value.address)
    : WP.spec (CcfKv.engine.collect_preserved_snapshot_rows batch index frame identity)
        (fun out =>
          ∃ outRows : List SnapshotBatchRow,
            out.val = outRows.map some
            ∧ outRows.length ≤ initRows.length + frameRows.length
            ∧ (∀ r ∈ outRows, r.key.val.length ≤ 56)
            ∧ (∀ r ∈ outRows, r.key.val = packedAddress r.value.address)) := by
  have hbyteSame : ∀ a b : CcfKv.engine.Bytes,
      CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey.same a b = .ok (decide (a = b)) := fun a b => by
    rw [bytes_same]; congr 1
  unfold CcfKv.engine.collect_preserved_snapshot_rows
  simp only [CcfKv.radix.RadixRoot.is_empty, bind_ok]
  by_cases hz : frame.data = 0#u32
  · rw [ite_eq_left (by simp [hz]), WP.spec_ok]
    exact ⟨initRows, hOwned, Nat.le_add_right _ _, hInitDepth, hInitPacked⟩
  · rw [ite_eq_right (by simp [hz])]
    apply WP.spec_bind
      (index_scan_refines index frame.data frameRows hView hValid hScanRoom)
    intro links ⟨hlinksLen, hlinksAt⟩
    unfold CcfKv.engine.collect_preserved_snapshot_rows_loop
    have hllen : (alloc.vec.Vec.len links).val = links.val.length := alloc.vec.Vec.len_val links
    have hlcap := alloc.vec.Vec.len_ineq links
    apply loop.spec_decr_nat
      (fun p : alloc.vec.Vec (Option SnapshotBatchRow) × Usize =>
        links.val.length - p.2.val)
      (fun (cur, i) =>
        i.val ≤ links.val.length
        ∧ ∃ curRows : List SnapshotBatchRow,
            cur.val = curRows.map some
            ∧ curRows.length ≤ initRows.length + i.val
            ∧ (∀ r ∈ curRows, r.key.val.length ≤ 56)
            ∧ (∀ r ∈ curRows, r.key.val = packedAddress r.value.address))
      _ _ _
    · rintro ⟨cur, i⟩ ⟨hiLe, curRows, hcur, hcurLen, hcurDepth, hcurPacked⟩
      dsimp only at hiLe hcur hcurLen hcurDepth hcurPacked ⊢
      unfold CcfKv.engine.collect_preserved_snapshot_rows_loop.body
      by_cases hlt : i < alloc.vec.Vec.len links
      · have hiLt : i.val < links.val.length := by rwa [← hllen]
        rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec links i hiLt)
        intro link hlink
        have hlinkAt : links.val[i.val]? = some link := by
          rw [List.getElem?_eq_getElem hiLt, ← hlink]
        obtain ⟨entry, hentryAt, hscan⟩ := hlinksAt i.val link hlinkAt
        apply WP.spec_bind hscan
        rintro ⟨addr, cell⟩ hpair
        have hentryMem : (addr, cell) ∈ frameRows := by
          rw [hpair]; exact List.mem_iff_getElem?.mpr ⟨i.val, hentryAt⟩
        have hpushSpec : WP.spec
            (CcfKv.engine.push_preserved_snapshot_row cur addr cell frame.births identity)
            (fun cur1 =>
              ∃ rows1 : List SnapshotBatchRow,
                cur1.val = rows1.map some
                ∧ rows1.length ≤ curRows.length + 1
                ∧ (∀ r ∈ rows1, r.key.val.length ≤ 56)
                ∧ (∀ r ∈ rows1, r.key.val = packedAddress r.value.address)) := by
          unfold CcfKv.engine.push_preserved_snapshot_row
          apply WP.spec_bind
            (assoc_get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
              CcfKv.engine.Bytes.Insts.CoreCloneClone
              CcfKv.engine.Stamp.Insts.CoreCloneClone frame.births addr.map
              (fun k => hbyteSame k addr.map) (fun _ => rfl))
          intro found _
          have hbranch : ∀ (replaced : Bool), WP.spec
              (if replaced then Result.ok cur
              else
                do
                  let a ← CcfKv.engine.Address.Insts.CoreCloneClone.clone addr
                  let c ← CcfKv.engine.Cell.Insts.CoreCloneClone.clone cell
                  let rr ← CcfKv.kv_index.AddressIndex.batch_row a c
                  alloc.vec.Vec.push cur (some rr))
              (fun cur1 =>
                ∃ rows1 : List SnapshotBatchRow,
                  cur1.val = rows1.map some
                  ∧ rows1.length ≤ curRows.length + 1
                  ∧ (∀ r ∈ rows1, r.key.val.length ≤ 56)
                  ∧ (∀ r ∈ rows1, r.key.val = packedAddress r.value.address)) := by
            intro replaced
            cases replaced with
            | true =>
                simp only [ite_true, WP.spec_ok]
                exact ⟨curRows, hcur, Nat.le_succ _, hcurDepth, hcurPacked⟩
            | false =>
                simp only [Bool.false_eq_true, ite_false, clone_address, clone_cell, bind_ok]
                apply WP.spec_bind (index_batch_row_refines addr cell (hKeys _ hentryMem))
                intro rr ⟨hrKey, hrVal, hrLen⟩
                have hcurRoom : cur.val.length < Usize.max := by
                  rw [hcur, List.length_map]; omega
                apply WP.spec_mono (alloc.vec.Vec.push_spec cur (some rr) hcurRoom)
                intro cur1 hcur1
                refine ⟨
                  curRows ++ [rr],
                  by rw [hcur1, hcur, List.map_append]; rfl,
                  by rw [List.length_append, List.length_singleton],
                  ?_,
                  ?_
                ⟩
                · intro r hr
                  rcases List.mem_append.mp hr with h1 | h2
                  · exact hcurDepth r h1
                  · simp only [List.mem_singleton] at h2; subst h2
                    rw [hrLen]; exact hRowDepth _ hentryMem
                · intro r hr
                  rcases List.mem_append.mp hr with h1 | h2
                  · exact hcurPacked r h1
                  · simp only [List.mem_singleton] at h2; subst h2
                    rw [hrKey, hrVal]
          cases found with
          | none => simp only [bind_ok]; exact hbranch false
          | some st =>
              simp only [bind_ok]; exact hbranch (decide (st.identity = identity))
        apply WP.spec_bind hpushSpec
        rintro cur1 ⟨rows1, hcur1, hrows1Len, hrows1Depth, hrows1Packed⟩
        have hone : (1#usize : Usize).val = 1 := rfl
        apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
        intro i1 hi1
        rw [WP.spec_ok]
        dsimp only
        exact ⟨⟨by omega, rows1, hcur1, by omega, hrows1Depth, hrows1Packed⟩, by omega⟩
      · have hge : links.val.length ≤ i.val := by
          rw [← hllen]; exact Nat.le_of_not_gt hlt
        rw [ite_eq_right hlt, WP.spec_ok]
        exact ⟨curRows, hcur, by omega, hcurDepth, hcurPacked⟩
    · exact ⟨Nat.zero_le _, initRows, hOwned, by simp, hInitDepth, hInitPacked⟩

private theorem collect_snapshot_map_rows_spec
    (batch : alloc.vec.Vec (Option SnapshotBatchRow)) (sm : CcfKv.engine.SnapshotMap)
    (initRows : List SnapshotBatchRow) (hOwned : batch.val = initRows.map some)
    (hRoom : initRows.length + sm.cells.val.length ≤ Usize.max)
    (hDepth : ∀ cell ∈ sm.cells.val, 8 + sm.name.val.length + cell.1.val.length ≤ 56)
    (hInitDepth : ∀ r ∈ initRows, r.key.val.length ≤ 56)
    (hInitPacked : ∀ r ∈ initRows, r.key.val = packedAddress r.value.address)
    : WP.spec (CcfKv.engine.collect_snapshot_map_rows batch sm)
        (fun out =>
          ∃ outRows : List SnapshotBatchRow,
            out.val = outRows.map some
            ∧ outRows.length = initRows.length + sm.cells.val.length
            ∧ (∀ r ∈ outRows, r.key.val.length ≤ 56)
            ∧ (∀ r ∈ outRows, r.key.val = packedAddress r.value.address)) := by
  unfold CcfKv.engine.collect_snapshot_map_rows CcfKv.engine.collect_snapshot_map_rows_loop
  have hclen : (alloc.vec.Vec.len sm.cells).val = sm.cells.val.length := alloc.vec.Vec.len_val sm.cells
  have hccap := alloc.vec.Vec.len_ineq sm.cells
  apply loop.spec_decr_nat
    (fun p : alloc.vec.Vec (Option SnapshotBatchRow) × Usize =>
      sm.cells.val.length - p.2.val)
    (fun (cur, j) =>
      j.val ≤ sm.cells.val.length
      ∧ ∃ curRows : List SnapshotBatchRow,
          cur.val = curRows.map some
          ∧ curRows.length = initRows.length + j.val
          ∧ (∀ r ∈ curRows, r.key.val.length ≤ 56)
          ∧ (∀ r ∈ curRows, r.key.val = packedAddress r.value.address))
    _ _ _
  · rintro ⟨cur, j⟩ ⟨hjLe, curRows, hcur, hcurLen, hcurDepth, hcurPacked⟩
    dsimp only at hjLe hcur hcurLen hcurDepth hcurPacked ⊢
    unfold CcfKv.engine.collect_snapshot_map_rows_loop.body
    by_cases hlt : j < alloc.vec.Vec.len sm.cells
    · have hjLt : j.val < sm.cells.val.length := by rwa [← hclen]
      rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec sm.cells j hjLt)
      rintro ⟨key, written, value⟩ hcell
      have hcellMem : (key, written, value) ∈ sm.cells.val := by
        rw [hcell]; exact List.getElem_mem hjLt
      simp only [clone_bytes, bind_ok]
      have h56 : 8 + sm.name.val.length + key.val.length ≤ 56 := hDepth _ hcellMem
      have hpackRoom : 8 + sm.name.val.length + key.val.length ≤ Usize.max := by
        have hwidth := Usize.max_succ_eq_pow
        rcases System.Platform.numBits_eq with h | h <;> simp [h] at hwidth <;> omega
      apply WP.spec_bind
        (index_batch_row_refines { map := sm.name, key }
          ({ value, version := written } : CcfKv.engine.Cell) hpackRoom)
      intro rr ⟨hrKey, hrVal, hrLen⟩
      have hcurRoom : cur.val.length < Usize.max := by
        rw [hcur, List.length_map]; omega
      apply WP.spec_bind (alloc.vec.Vec.push_spec cur (some rr) hcurRoom)
      intro cur1 hcur1
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.add_spec (x := j) (y := 1#usize) (by omega))
      intro j1 hj1
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨by omega, curRows ++ [rr], by rw [hcur1, hcur, List.map_append]; rfl,
        by rw [List.length_append, List.length_singleton, hcurLen]; omega, ?_, ?_⟩, by omega⟩
      · intro r hr
        rcases List.mem_append.mp hr with h1 | h2
        · exact hcurDepth r h1
        · simp only [List.mem_singleton] at h2; subst h2; rw [hrLen]; exact h56
      · intro r hr
        rcases List.mem_append.mp hr with h1 | h2
        · exact hcurPacked r h1
        · simp only [List.mem_singleton] at h2; subst h2; rw [hrKey, hrVal]
    · have hge : sm.cells.val.length ≤ j.val := by
        rw [← hclen]; exact Nat.le_of_not_gt hlt
      have hjEq : j.val = sm.cells.val.length := by omega
      rw [ite_eq_right hlt, WP.spec_ok]
      exact ⟨curRows, hcur, hjEq ▸ hcurLen, hcurDepth, hcurPacked⟩
  · exact ⟨Nat.zero_le _, initRows, hOwned, by simp, hInitDepth, hInitPacked⟩

private theorem install_snapshot_loop0_spec
    (maps : alloc.vec.Vec CcfKv.engine.SnapshotMap)
    (batch : alloc.vec.Vec (Option SnapshotBatchRow))
    (initRows : List SnapshotBatchRow) (hOwned : batch.val = initRows.map some)
    (hRoom : initRows.length + snapshotCellCount maps.val ≤ Usize.max)
    (hDepth
      : ∀ sm ∈ maps.val,
        ∀ cell ∈ sm.cells.val, 8 + sm.name.val.length + cell.1.val.length ≤ 56)
    (hInitDepth : ∀ r ∈ initRows, r.key.val.length ≤ 56)
    (hInitPacked : ∀ r ∈ initRows, r.key.val = packedAddress r.value.address)
    : WP.spec (CcfKv.engine.Store.install_snapshot_loop0 maps batch 0#usize)
        (fun out =>
          ∃ outRows : List SnapshotBatchRow,
            out.val = outRows.map some
            ∧ outRows.length = initRows.length + snapshotCellCount maps.val
            ∧ (∀ r ∈ outRows, r.key.val.length ≤ 56)
            ∧ (∀ r ∈ outRows, r.key.val = packedAddress r.value.address)) := by
  unfold CcfKv.engine.Store.install_snapshot_loop0
  have hmlen : (alloc.vec.Vec.len maps).val = maps.val.length := alloc.vec.Vec.len_val maps
  have hmcap := alloc.vec.Vec.len_ineq maps
  apply loop.spec_decr_nat
    (fun p : alloc.vec.Vec (Option SnapshotBatchRow) × Usize => maps.val.length - p.2.val)
    (fun (cur, i) =>
      i.val ≤ maps.val.length
      ∧ ∃ curRows : List SnapshotBatchRow,
          cur.val = curRows.map some
          ∧ curRows.length = initRows.length + snapshotCellCount (maps.val.take i.val)
          ∧ (∀ r ∈ curRows, r.key.val.length ≤ 56)
          ∧ (∀ r ∈ curRows, r.key.val = packedAddress r.value.address))
    _ _ _
  · rintro ⟨cur, i⟩ ⟨hiLe, curRows, hcur, hcurLen, hcurDepth, hcurPacked⟩
    dsimp only at hiLe hcur hcurLen hcurDepth hcurPacked ⊢
    unfold CcfKv.engine.Store.install_snapshot_loop0.body
    by_cases hlt : i < alloc.vec.Vec.len maps
    · have hiLt : i.val < maps.val.length := by rwa [← hmlen]
      rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec maps i hiLt)
      intro sm hsm
      have hsmMem : sm ∈ maps.val := by rw [hsm]; exact List.getElem_mem hiLt
      have htakeSucc : maps.val.take (i.val + 1) = maps.val.take i.val ++ [sm] := by
        rw [List.take_add_one, List.getElem?_eq_getElem hiLt, ← hsm]; simp
      have hsumLe : snapshotCellCount (maps.val.take (i.val + 1)) ≤ snapshotCellCount maps.val :=
        snapshotCellCount_take_le maps.val (i.val + 1)
      rw [htakeSucc, snapshotCellCount_append] at hsumLe
      apply WP.spec_bind
        (collect_snapshot_map_rows_spec cur sm curRows hcur (by omega)
          (hDepth sm hsmMem) hcurDepth hcurPacked)
      intro cur1 ⟨rows1, hcur1, hrows1Len, hrows1Depth, hrows1Packed⟩
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro i1 hi1
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨by omega, rows1, hcur1, ?_, hrows1Depth, hrows1Packed⟩, by omega⟩
      rw [show i1.val = i.val + 1 by omega, htakeSucc, snapshotCellCount_append]
      omega
    · have hge : maps.val.length ≤ i.val := by
        rw [← hmlen]; exact Nat.le_of_not_gt hlt
      have hiEq : i.val = maps.val.length := by omega
      rw [ite_eq_right hlt, WP.spec_ok]
      rw [hiEq, List.take_length] at hcurLen
      exact ⟨curRows, hcur, hcurLen, hcurDepth, hcurPacked⟩
  · exact ⟨Nat.zero_le _, initRows, hOwned, by simp [snapshotCellCount], hInitDepth, hInitPacked⟩

private theorem install_snapshot_loop1_terminates
    (views : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.RecoveryView)
    (maps : alloc.vec.Vec CcfKv.engine.SnapshotMap)
    : WP.spec (CcfKv.engine.Store.install_snapshot_loop1 views maps 0#usize)
        (fun _ => True) := by
  have hbyteSame : ∀ a b : CcfKv.engine.Bytes,
      CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey.same a b = .ok (decide (a = b)) := fun a b => by
    rw [bytes_same]; congr 1
  unfold CcfKv.engine.Store.install_snapshot_loop1
  have hmlen : (alloc.vec.Vec.len maps).val = maps.val.length := alloc.vec.Vec.len_val maps
  have hmcap := alloc.vec.Vec.len_ineq maps
  apply loop.spec_decr_nat
    (fun p : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.RecoveryView × Usize =>
      maps.val.length - p.2.val)
    (fun _ => True) _ _ _
  · rintro ⟨cur, i⟩ _
    dsimp only
    unfold CcfKv.engine.Store.install_snapshot_loop1.body
    by_cases hlt : i < alloc.vec.Vec.len maps
    · have hiLt : i.val < maps.val.length := by rwa [← hmlen]
      rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec maps i hiLt)
      intro sm _
      apply WP.spec_bind
        (assoc_erase CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
          CcfKv.engine.Bytes.Insts.CoreCloneClone
          CcfKv.engine.RecoveryView.Insts.CoreCloneClone
          cur sm.name (fun k => hbyteSame k sm.name) clone_bytes
          (fun rv => by
            simp [CcfKv.engine.RecoveryView.Insts.CoreCloneClone.clone, clone_assoc, lift]))
      intro cur1 _
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro i1 hi1
      rw [WP.spec_ok]; dsimp only; exact ⟨trivial, by omega⟩
    · rw [ite_eq_right hlt, WP.spec_ok]; trivial
  · trivial

private theorem clone_frame_ok (f : CcfKv.engine.Frame)
    : CcfKv.engine.Frame.Insts.CoreCloneClone.clone f = .ok f := by
  unfold CcfKv.engine.Frame.Insts.CoreCloneClone.clone
  simp [CcfKv.radix.RadixRoot.Insts.CoreCloneClone.clone, clone_assoc, lift]

/-- Full `Store.install_snapshot` theorem: either rejects invalid snapshots without
mutating `s`, or replaces the active branch with a single irrevocable base frame at
`version`, releasing all prior active frame roots, preserving `extraPins` (e.g. live
transaction pins), `BranchValid`, `HistoryIndexValid`, and `IndexLiveness`. -/
theorem install_snapshot_refines (s : CcfKv.engine.Store) (version : U64)
    (maps : alloc.vec.Vec CcfKv.engine.SnapshotMap)
    (extraPins : List U32)
    (cutFrame : CcfKv.engine.Frame) (cutRows : CellRows)
    (valid : BranchValid s.history.log)
    (live : IndexLiveness s.history.index (framePins s.history.activeFrames ++ extraPins))
    (hAtCut : CcfKv.engine.History.at_cut s.history version = .ok cutFrame)
    (hCutView : IndexView s.history.index cutFrame.data cutRows)
    (hB : cutFrame.births.val.length + maps.val.length ≤ Usize.max)
    (hR : cutFrame.revisions.val.length + maps.val.length ≤ Usize.max)
    (hScanRoom : 18 * cutRows.length ≤ Usize.max)
    (hTotalRoom : cutRows.length + snapshotCellCount maps.val ≤ Usize.max)
    (hCutDepth : ∀ row ∈ cutRows, 8 + row.1.map.val.length + row.1.key.val.length ≤ 56)
    (hMapDepth
      : ∀ sm ∈ maps.val,
        ∀ cell ∈ sm.cells.val, 8 + sm.name.val.length + cell.1.val.length ≤ 56)
    (hDirRoom
      : s.history.index.values.dirs.val.length
          + 2 * ((cutRows.length + snapshotCellCount maps.val) * (112 + 1))
        < 2147483647)
    (hRowRoom
      : s.history.index.values.rows.val.length
          + (cutRows.length + snapshotCellCount maps.val)
        ≤ 2147483647)
    (hRefRoom
      : (framePins s.history.activeFrames ++ extraPins).length
          + 17
            * (s.history.index.values.dirs.val.length
                + 2 * ((cutRows.length + snapshotCellCount maps.val) * (112 + 1))
                + 2)
          + 1
        ≤ U32.max)
    (hQueueRoom
      : 2
            * ((s.history.index.values.dirs.val.length
                  + 2 * ((cutRows.length + snapshotCellCount maps.val) * (112 + 1))
                  + 1)
                + (s.history.index.values.rows.val.length
                    + (cutRows.length + snapshotCellCount maps.val)))
          + 1
        ≤ Usize.max)
    : WP.spec (CcfKv.engine.Store.install_snapshot s version maps)
        (fun (result, after) =>
          (result = .Err .Disabled ∧ after = s)
          ∨ (result = .Err .Exhausted ∧ after = s)
          ∨ (result = .Ok ()
              ∧ ∃ baseFrame : CcfKv.engine.Frame,
                  after.history.activeFrames = [baseFrame]
                  ∧ baseFrame.version = version
                  ∧ after.history.global = version
                  ∧ after.history.retained.val = []
                  ∧ after.history.reuse_compacted_images = false
                  ∧ after.history.next_identity.val = s.history.next_identity.val + 1
                  ∧ after.txs = s.txs
                  ∧ BranchValid after.history.log
                  ∧ HistoryIndexValid after.history
                  ∧ IndexLiveness after.history.index
                      (framePins after.history.activeFrames ++ extraPins))) := by
  unfold CcfKv.engine.Store.install_snapshot
  by_cases hbelow : version < s.history.global
  · simp [hbelow]
  · rw [ite_eq_right hbelow]
    by_cases hmax : s.history.next_identity = core.num.U64.MAX
    · simp [hmax]
    · rw [ite_eq_right hmax, hAtCut, bind_ok, clone_frame_ok, bind_ok]
      have hB' : cutFrame.births.val.length + (alloc.vec.Vec.deref maps).val.length ≤ Usize.max := by
        simpa [alloc.vec.Vec.deref] using hB
      have hR' : cutFrame.revisions.val.length + (alloc.vec.Vec.deref maps).val.length ≤ Usize.max := by
        simpa [alloc.vec.Vec.deref] using hR
      have hC' : snapshotCellCount (alloc.vec.Vec.deref maps).val ≤ Usize.max := by
        simpa [alloc.vec.Vec.deref] using Nat.le_trans (Nat.le_add_left _ _) hTotalRoom
      apply WP.spec_bind
        (validate_snapshot_maps_spec { cutFrame with version } (alloc.vec.Vec.deref maps)
          s.history.next_identity hB' hR' hC')
      rintro ⟨optTotal, frame1⟩ ⟨hf1Ver, hf1Data, hopt⟩
      cases optTotal with
      | none =>
          change WP.spec (Result.ok (core.result.Result.Err CcfKv.engine.Error.Disabled, s)) _
          rw [WP.spec_ok]; exact Or.inl ⟨rfl, rfl⟩
      | some totalCells =>
          change WP.spec (do
            let batch1 ← CcfKv.engine.collect_preserved_snapshot_rows
              (alloc.vec.Vec.with_capacity (Option SnapshotBatchRow) totalCells)
              s.history.index frame1 s.history.next_identity
            let batch2 ← CcfKv.engine.Store.install_snapshot_loop0 maps batch1 0#usize
            let o1 ← CcfKv.engine.sort_and_check_unique_batch batch2
            match o1 with
            | none => Result.ok (core.result.Result.Err CcfKv.engine.Error.Disabled, s)
            | some sorted => do
              let (rr, ai) ← CcfKv.kv_index.AddressIndex.build_sorted_batch s.history.index sorted
              let h ← CcfKv.engine.History.pop_active_to { s.history with index := ai } 0#usize
              let bl ← CcfKv.branch_log.BranchLog.reset_branch h.log { frame1 with data := rr }
              let (_, ai1) ← CcfKv.kv_index.AddressIndex.retire_budget h.index CcfKv.engine.RETIRE_BUDGET
              let i ← s.history.next_identity + 1#u64
              let a ← CcfKv.engine.Store.install_snapshot_loop1 s.recovery_views maps 0#usize
              Result.ok (core.result.Result.Ok (),
                { s with
                  history :=
                    { h with
                      log := bl
                      retained := alloc.vec.Vec.new CcfKv.engine.Frame
                      index := ai1
                      global := version
                      next_identity := i
                      reuse_compacted_images := false }
                  recovery_views := a })) _
          have hcutKeys : ∀ row ∈ cutRows,
              8 + row.1.map.val.length + row.1.key.val.length ≤ Usize.max := by
            intro row hr
            have h56 := hCutDepth row hr
            have hwidth := Usize.max_succ_eq_pow
            rcases System.Platform.numBits_eq with h | h <;> simp [h] at hwidth <;> omega
          have hCutView1 : IndexView s.history.index frame1.data cutRows := by
            rw [hf1Data]; exact hCutView
          apply WP.spec_bind
            (collect_preserved_snapshot_rows_spec
              (alloc.vec.Vec.with_capacity (Option SnapshotBatchRow) totalCells)
              s.history.index frame1 s.history.next_identity [] cutRows
              (by simp [alloc.vec.Vec.with_capacity])
              hCutView1 live.valid hScanRoom
              (by simp; omega)
              hcutKeys hCutDepth
              (by simp)
              (by simp))
          intro batch1 ⟨rows1, hbatch1, hrows1Len, hrows1Depth, hrows1Packed⟩
          apply WP.spec_bind
            (install_snapshot_loop0_spec maps batch1 rows1 hbatch1
              (by simp at hrows1Len; omega) hMapDepth hrows1Depth hrows1Packed)
          intro batch2 ⟨rows2, hbatch2, hrows2Len, hrows2Depth, hrows2Packed⟩
          apply WP.spec_bind (sort_and_check_unique_batch_spec batch2 rows2 hbatch2)
          intro optSorted hsorted
          cases optSorted with
          | none =>
              rw [WP.spec_ok]; exact Or.inl ⟨rfl, rfl⟩
          | some sorted =>
              obtain ⟨outRows, houtOwned, houtPerm, houtOrdered⟩ := hsorted
              have houtLen : outRows.length ≤ cutRows.length + snapshotCellCount maps.val := by
                rw [houtPerm.length_eq, hrows2Len]; simp at hrows1Len; omega
              have hDepth112 : ∀ r ∈ outRows, 2 * r.key.val.length ≤ 112 := by
                intro r hr
                have h56 := hrows2Depth r (houtPerm.subset hr)
                omega
              have hKeysRoom : ∀ r ∈ outRows, 2 * r.key.val.length + 1 ≤ Usize.max := by
                intro r hr
                have h112 := hDepth112 r hr
                have hwidth := Usize.max_succ_eq_pow
                rcases System.Platform.numBits_eq with h | h <;> simp [h] at hwidth <;> omega
              have hDirRoom' :
                  s.history.index.values.dirs.val.length + 2 * (outRows.length * (112 + 1))
                    < 2147483647 := by
                have hmul := Nat.mul_le_mul_right (112 + 1) houtLen
                omega
              have hRowRoom' :
                  s.history.index.values.rows.val.length + outRows.length ≤ 2147483647 := by
                omega
              have hRefRoom' :
                  (framePins s.history.activeFrames ++ extraPins).length
                    + 17 * (s.history.index.values.dirs.val.length
                        + 2 * (outRows.length * (112 + 1)) + 2)
                    + 1 ≤ U32.max := by
                have hmul := Nat.mul_le_mul_right (112 + 1) houtLen
                omega
              simp only []
              unfold CcfKv.kv_index.AddressIndex.build_sorted_batch
              rw [Aeneas.Std.bind_assoc]
              apply WP.spec_bind
                (single_build_sorted_batch_refines s.history.index sorted outRows
                  (framePins s.history.activeFrames ++ extraPins) live houtOwned
                  houtOrdered 112 hDepth112 hKeysRoom hDirRoom' hRowRoom' hRefRoom')
              rintro ⟨root, ai⟩ ⟨haiLive, _, haiGrowth, bindings, hrootView, hrootBindings⟩
              let newExtra : List U32 := if root = 0#u32 then extraPins else root :: extraPins
              have haiLive' : IndexLiveness ai (framePins s.history.activeFrames ++ newExtra) := by
                have hperm :
                    (if root = 0#u32 then framePins s.history.activeFrames ++ extraPins
                      else root :: (framePins s.history.activeFrames ++ extraPins)).Perm
                    (framePins s.history.activeFrames ++ newExtra) := by
                  by_cases hz : root = 0#u32
                  · simp [hz, newExtra]
                  · simp only [hz, ite_false, newExtra]
                    exact List.perm_middle.symm
                exact haiLive.perm hperm
              have haiQueue : 2 * (ai.values.dirs.val.length + ai.values.rows.val.length) + 1
                  ≤ Usize.max := by
                have hd := haiGrowth.1
                have hr := haiGrowth.2
                have hmul := Nat.mul_le_mul_right (112 + 1) houtLen
                omega
              change WP.spec (Aeneas.Std.bind (Result.ok (root, ai)) _) _
              rw [bind_ok]
              apply WP.spec_bind
                (history_pop_active_to_zero_refines { s.history with index := ai }
                  newExtra valid haiLive' haiQueue)
              intro h1 ⟨_, _, _, _, _, _, hh1Vals, hh1Live⟩
              let baseFrame : CcfKv.engine.Frame := { frame1 with data := root }
              apply WP.spec_bind (branch_reset_branch_refines h1.log baseFrame)
              intro bl2 ⟨hbl2Valid, hbl2Vals⟩
              have hh1Queue : 2 * (h1.index.values.dirs.val.length + h1.index.values.rows.val.length) + 1
                  ≤ Usize.max := by rw [hh1Vals]; exact haiQueue
              apply WP.spec_bind
                (index_retire_budget_refines h1.index newExtra CcfKv.engine.RETIRE_BUDGET
                  hh1Live hh1Queue)
              rintro ⟨_, ai2⟩ ⟨hai2Live, hai2Pres, _, _⟩
              have hmaxVal : core.num.U64.MAX.val = U64.max := by rw [U64.max_eq]; rfl
              have hltMax : s.history.next_identity.val < U64.max := by
                have hle : s.history.next_identity.val ≤ U64.max := by scalar_tac
                have hne : s.history.next_identity.val ≠ U64.max := fun h =>
                  hmax (UScalar.eq_of_val_eq (by omega))
                omega
              have hone : (1#u64 : U64).val = 1 := rfl
              apply WP.spec_bind
                (U64.add_spec (x := s.history.next_identity) (y := 1#u64) (by omega))
              intro nextId hnextId
              apply WP.spec_bind (install_snapshot_loop1_terminates s.recovery_views maps)
              intro views1 _
              rw [WP.spec_ok]
              have hrootViewH1 : SingleView h1.index root bindings := by
                refine ⟨by rw [hh1Vals]; exact hrootView.lookup,
                  by rw [hh1Vals]; exact hrootView.values, hrootView.sorted⟩
              have hrootPres : SingleView ai2 root bindings
                  ∧ singleBindings ai2 bindings = singleBindings h1.index bindings := by
                by_cases hz : root = 0#u32
                · subst hz
                  have hnil : bindings = [] := by
                    obtain ⟨_, ht⟩ := hrootViewH1.lookup
                    cases ht with
                    | empty => rfl
                    | leaf _ _ _ tagged => exact absurd tagged (by decide)
                    | branch _ _ _ _ pos => exact absurd pos (by decide)
                  subst hnil
                  exact ⟨⟨⟨0, .empty 0⟩, (fun _ h => by cases h), List.Pairwise.nil⟩, rfl⟩
                · exact hai2Pres root (by simp [newExtra, hz]) bindings hrootViewH1
              have hIndexView : IndexView ai2 root
                  (outRows.map fun r => (r.value.address, r.value.value)) := by
                refine ⟨bindings, hrootPres.1, ?_⟩
                rw [hrootPres.2]
                have hsb : singleBindings h1.index bindings = singleBindings ai bindings := by
                  simp [singleBindings, hh1Vals]
                rw [hsb, hrootBindings, packedBindings, List.map_map]
                apply List.map_congr_left
                intro r hr
                simp only [Function.comp_def]
                exact Prod.ext (hrows2Packed r (houtPerm.subset hr)) rfl
              have hhistValid : HistoryIndexValid
                  { h1 with
                    log := bl2
                    retained := alloc.vec.Vec.new CcfKv.engine.Frame
                    index := ai2
                    global := version
                    next_identity := nextId
                    reuse_compacted_images := false } := by
                refine ⟨hai2Live.valid, ?_, ?_⟩
                · intro f hf
                  change f ∈ branchValues bl2 at hf
                  rw [hbl2Vals, List.mem_singleton] at hf
                  subst hf
                  exact index_rows_view ⟨_, hIndexView⟩
                · intro f hf
                  simp [alloc.vec.Vec.new] at hf
              have hliveFinal : IndexLiveness ai2
                  (framePins (branchValues bl2) ++ extraPins) := by
                rw [hbl2Vals]
                have hp : newExtra.Perm (framePins [baseFrame] ++ extraPins) := by
                  by_cases hz : root = 0#u32 <;> simp [newExtra, framePins, baseFrame, hz]
                exact hai2Live.perm hp
              exact Or.inr
                (Or.inr
                  ⟨
                    rfl,
                    baseFrame,
                    hbl2Vals,
                    hf1Ver,
                    rfl,
                    by simp [alloc.vec.Vec.new],
                    rfl,
                    by dsimp only; omega,
                    rfl,
                    hbl2Valid,
                    hhistValid,
                    hliveFinal
                  ⟩)

/-! ## Part 3: End-to-End `Store::replay_indexed_ccf` Refinement -/

private theorem publish_nil_nodup_puts
    (v : Nat) (ws : List (Addr String String × Option String))
    (hPuts : ∀ w ∈ ws, ∃ val, w.2 = some val)
    (hNodup : (ws.map Prod.fst).Nodup)
    : publish [] v ws
      = ws.filterMap
          (fun w => w.2.map fun val => (w.1, { value := val, version := v })) := by
  induction ws with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨a, wv⟩ := hd
      obtain ⟨val, rfl⟩ := hPuts (a, wv) List.mem_cons_self
      rw [List.map_cons, List.nodup_cons] at hNodup
      obtain ⟨haNotMem, htlNodup⟩ := hNodup
      have htlPuts : ∀ w ∈ tl, ∃ val, w.2 = some val :=
        fun w hw => hPuts w (List.mem_cons_of_mem _ hw)
      have hih := ih htlPuts htlNodup
      simp only [publish, List.foldr_cons, Option.map_some, List.filterMap_cons]
      change Kv.Model.set (publish [] v tl) a { value := val, version := v } = _
      rw [hih]
      have herase :
          Kv.Model.erase
            (tl.filterMap (fun w => w.2.map fun val => (w.1, ({ value := val, version := v } : Kv.Model.Cell String))))
            a
          = tl.filterMap (fun w => w.2.map fun val => (w.1, ({ value := val, version := v } : Kv.Model.Cell String))) := by
        unfold Kv.Model.erase
        apply List.filter_eq_self.mpr
        intro p hp
        obtain ⟨w, hw, hsome⟩ := List.mem_filterMap.mp hp
        obtain ⟨val', hval'⟩ := htlPuts w hw
        rw [hval'] at hsome
        simp only [Option.map_some, Option.some.injEq] at hsome
        have hpa : p.1 ≠ a := by
          rw [← hsome]
          intro heq
          exact haNotMem (List.mem_map.mpr ⟨w, hw, heq⟩)
        simp [hpa]
      unfold Kv.Model.set
      rw [herase]

private theorem append_replay_ccf_ok_matches_advance (encode : List U8 → String)
    (inj : Function.Injective encode) (s : CcfKv.engine.Store) (model : Store)
    (prior : List CcfKv.engine.Frame) (head : CcfKv.engine.Frame)
    (hHead : s.history.activeFrames = prior ++ [head])
    (hModelHead : model.head = modelFrame encode s.history.index head)
    (hIdentity : model.nextIdentity = s.history.next_identity.val)
    (version : U64) (hVersion : version.val = head.version.val + 1)
    (writes : alloc.vec.Vec (CcfKv.engine.Address × Option CcfKv.engine.Bytes))
    (pending : CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write)
    (hp : pending.val = writes.val.map replayRow)
    (hI : s.history.next_identity.val < U64.max)
    (hD
      : IndexBatchRoom s.history.index (storePins s).length
          ((indexRows s.history.index head.data).length + writes.val.length)
          writes.val.length)
    (hKeys : ∀ row ∈ writes.val, IndexKeyRoom (replayRow row))
    (hDepth : ∀ row ∈ writes.val, 8 + row.1.map.val.length + row.1.key.val.length ≤ 56)
    (hDirFast
      : s.history.index.values.dirs.val.length + 2 * (writes.val.length * (112 + 1))
        < 2147483647)
    (hRowFast : s.history.index.values.rows.val.length + writes.val.length ≤ 2147483647)
    (hRefFast
      : (storePins s).length
          + 17
            * (s.history.index.values.dirs.val.length
                + 2 * (writes.val.length * (112 + 1))
                + 2)
          + 1
        ≤ U32.max)
    (hR : head.revisions.val.length + writes.val.length ≤ Usize.max)
    (hB : head.births.val.length + writes.val.length ≤ Usize.max)
    (valid : BranchValid s.history.log) (indexed : HistoryIndexValid s.history)
    (live : IndexLiveness s.history.index (storePins s))
    (ringRoom
      : s.history.log.len.val = s.history.log.slots.val.length
        → 2 * s.history.log.slots.val.length + 1 ≤ Usize.max)
    : WP.spec
        (do
          let self1 ← CcfKv.engine.Store.append_replay_ccf s version pending false
          Result.ok (core.result.Result.Ok (), self1))
        (fun ((result : core.result.Result Unit CcfKv.engine.Error), after) =>
          result = core.result.Result.Ok ()
          ∧ ∃ next,
              FrameOrderEq (modelFrame encode after.history.index next)
                (advance model (encodeReport encode writes)).head
              ∧ after.history.activeFrames = s.history.activeFrames ++ [next]
              ∧ after.history.next_identity.val = s.history.next_identity.val + 1
              ∧ after.history.term = s.history.term
              ∧ after.history.global = s.history.global
              ∧ after.txs = s.txs
              ∧ BranchValid after.history.log
              ∧ HistoryIndexValid after.history
              ∧ IndexLiveness after.history.index (storePins after)
              ∧ IndexKeeps s.history.index after.history.index) := by
  have hheadRes := history_head s.history prior head hHead valid
  · have hlength : pending.val.length = writes.val.length := by simp [hp]
    have hWrite : encodeWrites encode (byteWrites pending.val) = encodeReport encode writes := by
      simp only [hp, byteWrites, encodeWrites, encodeReport, List.map_map, Function.comp_def]
      apply List.map_congr_left
      rintro ⟨addr, value⟩ _
      cases value <;> rfl
    have versionEq : version.val = model.head.version + 1 := by
      simpa only [hModelHead, modelFrame, modelMetadata] using hVersion
    have keyRoom : ∀ row ∈ pending.val, IndexKeyRoom row := by
      intro row hm
      rw [hp] at hm
      obtain ⟨entry, present, rfl⟩ := List.mem_map.mp hm
      exact hKeys entry present
    -- Helper proving the fallback `append_replay` branch.
    have hFallback : WP.spec
        (do
          let self1 ← CcfKv.engine.Store.append_replay s version pending false
          Result.ok (core.result.Result.Ok (), self1))
        (fun ((result : core.result.Result Unit CcfKv.engine.Error), after) =>
          result = core.result.Result.Ok ()
          ∧ ∃ next,
              FrameOrderEq (modelFrame encode after.history.index next)
                (advance model (encodeReport encode writes)).head
              ∧ after.history.activeFrames = s.history.activeFrames ++ [next]
              ∧ after.history.next_identity.val = s.history.next_identity.val + 1
              ∧ after.history.term = s.history.term
              ∧ after.history.global = s.history.global
              ∧ after.txs = s.txs
              ∧ BranchValid after.history.log
              ∧ HistoryIndexValid after.history
              ∧ IndexLiveness after.history.index (storePins after)
              ∧ IndexKeeps s.history.index after.history.index) := by
      simp only [CcfKv.engine.Store.append_replay, Bool.false_eq_true, ite_false,
        Aeneas.Std.bind_assoc]
      apply WP.spec_bind
        (prepare_frame_matches_model encode inj s.history prior head (txsPins s.txs.val)
          valid hHead indexed live model pending version s.history.next_identity
          hModelHead versionEq hIdentity.symm (hlength.symm ▸ hD) keyRoom
          (hlength.symm ▸ hR) (hlength.symm ▸ hB))
      rintro ⟨next, prepared⟩ ⟨arena, same, modelFrameEq, view, arenaLive, preserved, _⟩
      change prepared = { s.history with index := arena } at same
      subst prepared
      let publishStore (log : CcfKv.branch_log.BranchLog CcfKv.engine.Frame) (identity : U64)
          : CcfKv.engine.Store :=
        { s with
          history := { s.history with
            log
            index := arena
            next_identity := identity
            reuse_compacted_images := false } }
      change WP.spec (Aeneas.Std.bind
        (do
          let log ← CcfKv.branch_log.BranchLog.append s.history.log next
          let identity ← s.history.next_identity + 1#u64
          Result.ok (publishStore log identity))
        (fun updated => Result.ok (core.result.Result.Ok (), updated))) _
      rw [Aeneas.Std.bind_assoc]
      apply WP.spec_bind (branch_append_refines s.history.log next valid ringRoom)
      rintro log ⟨logValid, hf⟩
      rw [Aeneas.Std.bind_assoc]
      have one : (1#u64 : U64).val = 1 := rfl
      apply WP.spec_bind
        (U64.add_spec (x := s.history.next_identity) (y := 1#u64) (by omega))
      intro ident hident
      simp only [bind_ok, WP.spec_ok, publishStore]
      have hpinsPerm :
          (if next.data = 0#u32 then framePins s.history.activeFrames ++ txsPins s.txs.val
            else next.data :: (framePins s.history.activeFrames ++ txsPins s.txs.val)).Perm
          (framePins (branchValues log) ++ txsPins s.txs.val) := by
        rw [hf]
        have hp' := (framePins_append s.history.activeFrames next).symm.append_right (txsPins s.txs.val)
        by_cases hz : next.data = 0#u32 <;> simpa [hz] using hp'
      exact ⟨
        True.intro,
        next,
        hWrite ▸ modelFrameEq,
        hf,
        by omega,
        True.intro,
        True.intro,
        True.intro,
        logValid,
        indexed.append preserved arenaLive.valid next view hf rfl,
        arenaLive.perm hpinsPerm,
        preserved
      ⟩
    unfold CcfKv.engine.Store.append_replay_ccf
    rw [Aeneas.Std.bind_assoc, hheadRes, bind_ok]
    unfold CcfKv.radix.RadixRoot.is_empty
    rw [Aeneas.Std.bind_assoc, bind_ok]
    by_cases hEmpty : head.data = 0#u32
    · simp only [hEmpty, decide_true, ite_true]
      have hPenKeys : ∀ row ∈ pending.val, 8 + row.1.map.val.length + row.1.key.val.length ≤ 56 := by
        intro row hr
        rw [hp] at hr
        obtain ⟨w, hw, rfl⟩ := List.mem_map.mp hr
        exact hDepth w hw
      rw [Aeneas.Std.bind_assoc]
      apply WP.spec_bind (collect_replay_put_batch_spec pending version keyRoom)
      intro obatch hobatch
      cases obatch with
      | none => exact hFallback
      | some batch =>
          obtain ⟨batchRows, hbatchOwned, hbatchLenEq, hbatchAt⟩ := hobatch
          have hbatchLen : batchRows.length = writes.val.length := by omega
          have hPutOnly : ∀ row ∈ pending.val, ∃ val, row.2 = CcfKv.engine.Write.Put val := by
            intro row hrow
            obtain ⟨i, hi, hget⟩ := List.mem_iff_getElem.mp hrow
            obtain ⟨a, val, _, hpAt, _, _, _, _⟩ := hbatchAt i hi
            rw [List.getElem?_eq_getElem hi, Option.some.injEq] at hpAt
            exact ⟨val, by rw [← hget, hpAt]⟩
          have hbatchMap :
              batchRows.map (fun r => (r.key.val, r.value)) =
              pending.val.map (fun row =>
                (packedAddress row.1,
                  { address := row.1
                    value :=
                      { value := match row.2 with
                          | .Put v => v
                          | .Remove => alloc.vec.Vec.new U8
                        version := version } })) := by
            apply List.ext_getElem (by simp [hbatchLenEq])
            intro i hi1 hi2
            have hi : i < pending.val.length := by simpa using hi2
            obtain ⟨a, val, r, hpAt, hbAt, hkey, hval, _⟩ := hbatchAt i hi
            have hpEq : pending.val[i]'hi = (a, CcfKv.engine.Write.Put val) := by
              rw [List.getElem?_eq_getElem hi, Option.some.injEq] at hpAt; exact hpAt
            have hbEq : batchRows[i]'(by omega) = r := by
              rw [List.getElem?_eq_getElem (by omega), Option.some.injEq] at hbAt; exact hbAt
            simp only [List.getElem_map, hpEq, hbEq]
            exact Prod.ext hkey hval
          have hbatchDepth : ∀ r ∈ batchRows, r.key.val.length ≤ 56 := by
            intro r hr
            obtain ⟨i, hi, hget⟩ := List.mem_iff_getElem.mp hr
            obtain ⟨a, val, r', hpAt, hbAt, _, _, hlenEq⟩ := hbatchAt i (by omega)
            rw [List.getElem?_eq_getElem hi, Option.some.injEq] at hbAt
            have hrEq : r = r' := by rw [← hget, hbAt]
            rw [hrEq, hlenEq]
            have haMem : (a, CcfKv.engine.Write.Put val) ∈ pending.val := by
              rw [List.getElem?_eq_getElem (by omega), Option.some.injEq] at hpAt
              rw [← hpAt]; exact List.getElem_mem (by omega)
            exact hPenKeys _ haMem
          have hbatchPacked : ∀ r ∈ batchRows, r.key.val = packedAddress r.value.address := by
            intro r hr
            obtain ⟨i, hi, hget⟩ := List.mem_iff_getElem.mp hr
            obtain ⟨a, val, r', _, hbAt, hkey, hval, _⟩ := hbatchAt i (by omega)
            rw [List.getElem?_eq_getElem hi, Option.some.injEq] at hbAt
            have hrEq : r = r' := by rw [← hget, hbAt]
            rw [hrEq, hkey, hval]
          rw [Aeneas.Std.bind_assoc]
          apply WP.spec_bind
            (sort_and_check_unique_batch_spec batch batchRows hbatchOwned)
          intro osorted hosorted
          cases osorted with
          | none => exact hFallback
          | some sorted =>
              obtain ⟨outRows, houtOwned, houtPerm, houtOrdered⟩ := hosorted
              have houtLen : outRows.length = writes.val.length := by
                rw [houtPerm.length_eq, hbatchLen]
              rw [Aeneas.Std.bind_assoc, bind_ok]
              simp only [clone_assoc, bind_ok]
              rw [Aeneas.Std.bind_assoc]
              apply WP.spec_bind
                (advance_replay_stamps_put_only_spec encode inj head.revisions head.births
                  pending { version := version, identity := s.history.next_identity }
                  hPutOnly (by omega) (by omega))
              rintro ⟨revisions1, births1⟩ ⟨hrev1, hbirth1⟩
              change WP.spec (Aeneas.Std.bind
                (do
                  let (data, ai) ← s.history.index.build_sorted_batch sorted
                  let bl ← s.history.log.append
                    { version := version, data := data, revisions := revisions1, births := births1 }
                  let i ← s.history.next_identity + 1#u64
                  Result.ok
                    { s with
                      history :=
                        { s.history with
                          log := bl
                          index := ai
                          next_identity := i
                          reuse_compacted_images := false } })
                (fun self1 => Result.ok (core.result.Result.Ok (), self1))) _
              rw [Aeneas.Std.bind_assoc]
              unfold CcfKv.kv_index.AddressIndex.build_sorted_batch
              rw [Aeneas.Std.bind_assoc]
              have hDepth112 : ∀ r ∈ outRows, 2 * r.key.val.length ≤ 112 := by
                intro r hr
                have := hbatchDepth r (houtPerm.subset hr)
                omega
              have hKeysRoom' : ∀ r ∈ outRows, 2 * r.key.val.length + 1 ≤ Usize.max := by
                intro r hr
                have hrB := houtPerm.subset hr
                obtain ⟨i, hi, hget⟩ := List.mem_iff_getElem.mp hrB
                obtain ⟨a, val, r', hpAt, hbAt, _, _, hlenEq⟩ := hbatchAt i (by omega)
                rw [List.getElem?_eq_getElem hi, Option.some.injEq] at hbAt
                have hrEq : r = r' := by rw [← hget, hbAt]
                have haMem : (a, CcfKv.engine.Write.Put val) ∈ pending.val := by
                  rw [List.getElem?_eq_getElem (by omega), Option.some.injEq] at hpAt
                  rw [← hpAt]; exact List.getElem_mem (by omega)
                have hkr := keyRoom _ haMem
                unfold IndexKeyRoom at hkr
                rw [hrEq, hlenEq]
                exact hkr
              apply WP.spec_bind
                (single_build_sorted_batch_refines s.history.index sorted outRows
                  (storePins s) live houtOwned houtOrdered 112 hDepth112 hKeysRoom'
                  (houtLen.symm ▸ hDirFast) (houtLen.symm ▸ hRowFast)
                  (houtLen.symm ▸ hRefFast))
              rintro ⟨dataRoot, ai⟩ ⟨haiLive, haiKeeps, _, bindings, hrootView, hrootBindings⟩
              let next : CcfKv.engine.Frame :=
                { version := version
                  data := dataRoot
                  revisions := revisions1
                  births := births1 }
              change WP.spec (Aeneas.Std.bind (Result.ok (dataRoot, ai)) _) _
              rw [bind_ok]
              change WP.spec (Aeneas.Std.bind
                (do
                  let bl ← s.history.log.append next
                  let i ← s.history.next_identity + 1#u64
                  Result.ok
                    { s with
                      history :=
                        { s.history with
                          log := bl
                          index := ai
                          next_identity := i
                          reuse_compacted_images := false } })
                (fun self1 => Result.ok (core.result.Result.Ok (), self1))) _
              rw [Aeneas.Std.bind_assoc]
              apply WP.spec_bind (branch_append_refines s.history.log next valid ringRoom)
              rintro log ⟨logValid, hf⟩
              rw [Aeneas.Std.bind_assoc]
              have hone : (1#u64 : U64).val = 1 := rfl
              apply WP.spec_bind
                (U64.add_spec (x := s.history.next_identity) (y := 1#u64) (by omega))
              intro ident hident
              simp only [bind_ok, WP.spec_ok]
              -- Build `IndexView ai dataRoot (outRows.map ...)`
              have hIndexView : IndexView ai dataRoot
                  (outRows.map fun r => (r.value.address, r.value.value)) := by
                refine ⟨bindings, hrootView, ?_⟩
                rw [hrootBindings, packedBindings, List.map_map]
                apply List.map_congr_left
                intro r hr
                simp only [Function.comp_def]
                exact Prod.ext (hbatchPacked r (houtPerm.subset hr)) rfl
              have hIndexRows : indexRows ai dataRoot =
                  outRows.map (fun r => (r.value.address, r.value.value)) :=
                index_rows_eq hIndexView
              have hHeadRowsNil : indexRows s.history.index head.data = [] := by
                rw [hEmpty]
                exact index_rows_eq ⟨[], ⟨⟨0, .empty 0⟩, (fun _ h => by cases h), List.Pairwise.nil⟩, rfl⟩
              have hModelDataNil : model.head.data = [] := by
                rw [hModelHead, modelFrame, hHeadRowsNil]
                rfl
              -- Distinct addresses in `outRows` -> distinct encoded addresses in `encodeReport`.
              have houtKeyNodup : (outRows.map fun r => r.key.val).Nodup := by
                rw [List.nodup_iff_pairwise_ne, List.pairwise_map]
                exact houtOrdered.imp (fun {a b} hlt heq => by
                  rw [heq] at hlt; exact lt_irrefl _ hlt)
              have hbatchKeyNodup : (batchRows.map fun r => r.key.val).Nodup :=
                (houtPerm.map _).nodup_iff.mp houtKeyNodup
              have hpenAddrNodup : (pending.val.map Prod.fst).Nodup := by
                have hpackMap : batchRows.map (fun r => r.key.val) =
                    (pending.val.map Prod.fst).map packedAddress := by
                  have h1 := congrArg (List.map Prod.fst) hbatchMap
                  simpa [List.map_map, Function.comp_def] using h1
                rw [hpackMap] at hbatchKeyNodup
                exact List.Nodup.of_map packedAddress hbatchKeyNodup
              have hEncAddrInj : Function.Injective (fun a : CcfKv.engine.Address =>
                  encodeAddr encode (byteAddr a)) := by
                intro a1 a2 heq
                cases a1 with
                | mk m1 k1 =>
                    cases a2 with
                    | mk m2 k2 =>
                        have hm : encode m1.val = encode m2.val := (Prod.mk.inj heq).1
                        have hk : encode k1.val = encode k2.val := (Prod.mk.inj heq).2
                        have hm' : m1 = m2 := alloc.vec.Vec.ext _ _ (inj hm)
                        have hk' : k1 = k2 := alloc.vec.Vec.ext _ _ (inj hk)
                        subst hm'; subst hk'; rfl
              have hwsNodup :
                  ((encodeWrites encode (byteWrites pending.val)).map Prod.fst).Nodup := by
                have hmap : (encodeWrites encode (byteWrites pending.val)).map Prod.fst =
                    (pending.val.map Prod.fst).map (fun a => encodeAddr encode (byteAddr a)) := by
                  simp [encodeWrites, byteWrites, List.map_map, Function.comp_def]
                rw [hmap]
                exact hpenAddrNodup.map hEncAddrInj
              have hwsPuts : ∀ w ∈ encodeWrites encode (byteWrites pending.val),
                  ∃ val, w.2 = some val := by
                intro w hw
                simp only [encodeWrites, byteWrites, List.map_map, List.mem_map,
                  Function.comp_def] at hw
                obtain ⟨row, hrow, rfl⟩ := hw
                obtain ⟨val, hval⟩ := hPutOnly row hrow
                exact ⟨encode val.val, by simp [hval]⟩
              have hPubEq := publish_nil_nodup_puts version.val
                (encodeWrites encode (byteWrites pending.val)) hwsPuts hwsNodup
              have hModelFrameEq :
                  FrameOrderEq (modelFrame encode ai next)
                    (advance model (encodeReport encode writes)).head := by
                refine ⟨?_, ?_, ?_, ?_⟩
                · change version.val = model.head.version + 1
                  exact versionEq
                · change (encodeData encode (indexedCellData (indexRows ai dataRoot))).Perm
                    (publish model.head.data (model.head.version + 1) (encodeReport encode writes))
                  rw [hIndexRows, hModelDataNil, ← versionEq, ← hWrite, hPubEq]
                  have hpermData :
                      (encodeData encode (indexedCellData (outRows.map fun r => (r.value.address, r.value.value)))).Perm
                      (encodeData encode (indexedCellData (batchRows.map fun r => (r.value.address, r.value.value)))) :=
                    ((houtPerm.map _).map _).map _
                  refine hpermData.trans ?_
                  have hEqList :
                      encodeData encode (indexedCellData (batchRows.map fun r => (r.value.address, r.value.value))) =
                      (encodeWrites encode (byteWrites pending.val)).filterMap
                        (fun w => w.2.map fun val => (w.1, ({ value := val, version := version.val } : Kv.Model.Cell String))) := by
                    have hvalMap : batchRows.map (fun r => r.value) =
                        pending.val.map (fun row =>
                          { address := row.1
                            value :=
                              { value := match row.2 with
                                  | .Put v => v
                                  | .Remove => alloc.vec.Vec.new U8
                                version := version } }) := by
                      have h1 := congrArg (List.map Prod.snd) hbatchMap
                      simpa [List.map_map, Function.comp_def] using h1
                    have h1 :
                        encodeData encode (indexedCellData (batchRows.map fun r => (r.value.address, r.value.value))) =
                        (batchRows.map fun r => r.value).map (fun b =>
                          (encodeAddr encode (byteAddr b.address),
                            ({ value := encode b.value.value.val, version := b.value.version.val } : Kv.Model.Cell String))) := by
                      simp [encodeData, indexedCellData, encodeCell, byteCell, List.map_map,
                        Function.comp_def]
                    rw [h1, hvalMap, List.map_map]
                    have h2 :
                        (encodeWrites encode (byteWrites pending.val)).filterMap
                          (fun w => w.2.map fun val => (w.1, ({ value := val, version := version.val } : Kv.Model.Cell String))) =
                        pending.val.filterMap (fun row =>
                          match row.2 with
                          | .Put v => some (encodeAddr encode (byteAddr row.1),
                              ({ value := encode v.val, version := version.val } : Kv.Model.Cell String))
                          | .Remove => none) := by
                      simp only [encodeWrites, byteWrites, List.filterMap_map, Function.comp_def]
                      apply List.filterMap_congr
                      intro row _
                      cases row.2 <;> rfl
                    rw [h2]
                    have h3 :
                        pending.val.filterMap (fun row =>
                          match row.2 with
                          | .Put v => some (encodeAddr encode (byteAddr row.1),
                              ({ value := encode v.val, version := version.val } : Kv.Model.Cell String))
                          | .Remove => none) =
                        pending.val.map (fun row =>
                          (encodeAddr encode (byteAddr row.1),
                            ({ value := encode (match row.2 with | .Put v => v | .Remove => alloc.vec.Vec.new U8).val,
                               version := version.val } : Kv.Model.Cell String))) := by
                      clear h2 h1 hvalMap hpermData hPubEq hwsPuts hwsNodup hbatchMap hbatchAt
                      generalize pending.val = rows at hPutOnly ⊢
                      induction rows with
                      | nil => rfl
                      | cons hd tl ih =>
                          obtain ⟨val, hval⟩ := hPutOnly hd List.mem_cons_self
                          simp only [List.filterMap_cons, List.map_cons, hval]
                          congr 1
                          exact ih (fun r hr => hPutOnly r (List.mem_cons_of_mem _ hr))
                    rw [h3]
                    rfl
                  rw [hEqList]
                · intro m
                  have hmodRev : model.head.revisions =
                      head.revisions.val.map (fun (k, st) => (encode k.val, modelStamp st)) := by
                    rw [hModelHead]; rfl
                  have hstEq : modelStamp { version := version, identity := s.history.next_identity } =
                      { version := model.head.version + 1, identity := model.nextIdentity } := by
                    simp [modelStamp, versionEq, hIdentity]
                  change find (revisions1.val.map fun (k, st) => (encode k.val, modelStamp st)) m = _
                  rw [hrev1 m]
                  simp only [advance, hModelDataNil, hmodRev, hWrite, hstEq]
                · intro m
                  have hmodBirth : model.head.births =
                      head.births.val.map (fun (k, st) => (encode k.val, modelStamp st)) := by
                    rw [hModelHead]; rfl
                  have hstEq : modelStamp { version := version, identity := s.history.next_identity } =
                      { version := model.head.version + 1, identity := model.nextIdentity } := by
                    simp [modelStamp, versionEq, hIdentity]
                  change find (births1.val.map fun (k, st) => (encode k.val, modelStamp st)) m = _
                  rw [hbirth1 m]
                  simp only [advance, hmodBirth, hWrite, hstEq]
              have hpinsPerm :
                  (if dataRoot = 0#u32 then storePins s else dataRoot :: storePins s).Perm
                  (framePins (branchValues log) ++ txsPins s.txs.val) := by
                rw [hf]
                have hp' :=
                  (framePins_append s.history.activeFrames next).symm.append_right (txsPins s.txs.val)
                by_cases hz : dataRoot = 0#u32 <;> simpa [next, storePins, hz] using hp'
              exact ⟨
                True.intro,
                next,
                hModelFrameEq,
                hf,
                by omega,
                True.intro,
                True.intro,
                True.intro,
                logValid,
                indexed.append haiKeeps haiLive.valid next
                  (index_rows_view ⟨_, hIndexView⟩) hf rfl,
                haiLive.perm hpinsPerm,
                haiKeeps
              ⟩
    · simp only [hEmpty, decide_false, Bool.false_eq_true, ite_false]
      exact hFallback

/-- `Store::replay_indexed_ccf` (with `track_deletes = false`) either rejects and leaves the
store unchanged, or appends a frame order-equivalent to `Kv.Model.advance` while preserving
`BranchValid`, `HistoryIndexValid`, `IndexLiveness`, and `IndexKeeps` across both the
sorted-batch fast path (when the head frame is empty and all writes are unique `Put`s) and
the fallback `append_replay` path. -/
theorem replay_indexed_ccf_matches_advance (encode : List U8 → String)
    (inj : Function.Injective encode) (s : CcfKv.engine.Store) (model : Store)
    (prior : List CcfKv.engine.Frame) (head : CcfKv.engine.Frame)
    (hHead : s.history.activeFrames = prior ++ [head])
    (hModelHead : model.head = modelFrame encode s.history.index head)
    (hIdentity : model.nextIdentity = s.history.next_identity.val)
    (version : U64) (hVersion : version.val = head.version.val + 1)
    (writes : alloc.vec.Vec (CcfKv.engine.Address × Option CcfKv.engine.Bytes))
    (hI : s.history.next_identity.val < U64.max)
    (hD
      : IndexBatchRoom s.history.index (storePins s).length
          ((indexRows s.history.index head.data).length + writes.val.length)
          writes.val.length)
    (hKeys : ∀ row ∈ writes.val, IndexKeyRoom (replayRow row))
    (hDepth : ∀ row ∈ writes.val, 8 + row.1.map.val.length + row.1.key.val.length ≤ 56)
    (hDirFast
      : s.history.index.values.dirs.val.length + 2 * (writes.val.length * (112 + 1))
        < 2147483647)
    (hRowFast : s.history.index.values.rows.val.length + writes.val.length ≤ 2147483647)
    (hRefFast
      : (storePins s).length
          + 17
            * (s.history.index.values.dirs.val.length
                + 2 * (writes.val.length * (112 + 1))
                + 2)
          + 1
        ≤ U32.max)
    (hR : head.revisions.val.length + writes.val.length ≤ Usize.max)
    (hB : head.births.val.length + writes.val.length ≤ Usize.max)
    (valid : BranchValid s.history.log) (indexed : HistoryIndexValid s.history)
    (live : IndexLiveness s.history.index (storePins s))
    (ringRoom
      : s.history.log.len.val = s.history.log.slots.val.length
        → 2 * s.history.log.slots.val.length + 1 ≤ Usize.max)
    : WP.spec (CcfKv.engine.Store.replay_indexed_ccf s version writes false)
        (fun (result, after) =>
          (result = .Err .Disabled ∧ after = s)
          ∨ (result = .Ok ()
              ∧ ∃ next,
                  FrameOrderEq (modelFrame encode after.history.index next)
                    (advance model (encodeReport encode writes)).head
                  ∧ after.history.activeFrames = s.history.activeFrames ++ [next]
                  ∧ after.history.next_identity.val = s.history.next_identity.val + 1
                  ∧ after.history.term = s.history.term
                  ∧ after.history.global = s.history.global
                  ∧ after.txs = s.txs
                  ∧ BranchValid after.history.log
                  ∧ HistoryIndexValid after.history
                  ∧ IndexLiveness after.history.index (storePins after)
                  ∧ IndexKeeps s.history.index after.history.index)) := by
  unfold CcfKv.engine.Store.replay_indexed_ccf
  have hheadRes := history_head s.history prior head hHead valid
  rw [hheadRes, bind_ok]
  apply WP.spec_bind
    (prepare_replay_ccf_matches head.version s.history.next_identity version hVersion hI
      writes)
  rintro r (rfl | ⟨pending, rfl, hp⟩)
  · simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  · simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
    exact WP.spec_mono
      (append_replay_ccf_ok_matches_advance encode inj s model prior head hHead hModelHead
        hIdentity version hVersion writes pending hp hI hD hKeys hDepth hDirFast hRowFast
        hRefFast hR hB valid indexed live ringRoom)
      (fun _ h => Or.inr h)

/-! ## Part 4: Provisional Replacement Replay (`Store::replay_ccf` when `version ≤ head`) -/

private theorem indexView_of_preserves_replay {V : Type}
    {before after : CcfKv.kv_index.AddressIndex V} {pins : List U32}
    (hpres : IndexPreservesPins before after pins)
    {r : U32} (hr : r ∈ pins) {rows : List (CcfKv.engine.Address × V)}
    (hview : IndexView before r rows)
    : IndexView after r rows := by
  obtain ⟨bindings, hsv, hsb⟩ := hview
  obtain ⟨hsv', hsb'⟩ := hpres r hr bindings hsv
  exact ⟨bindings, hsv', by rw [hsb', hsb]⟩

/-- Provisional replacement replay: when `0 < version ≤ head.version` and `version - 1 ≥ global`,
`Store::replay_ccf` validates the writes against the cut at `version - 1`, rolls back any
provisional suffix above `version - 1`, and appends the replacement frame order-equivalent to
`Kv.Model.advance` from the cut model while preserving `BranchValid`, `HistoryIndexValid`,
and `IndexLiveness`. -/
theorem replay_ccf_replace_matches_advance (encode : List U8 → String)
    (inj : Function.Injective encode) (s : CcfKv.engine.Store) (prevModel : Store)
    (prior : List CcfKv.engine.Frame) (head baseFrame prevFrame : CcfKv.engine.Frame)
    (hHead : s.history.activeFrames = prior ++ [head])
    (hBaseAt : s.history.activeFrames[0]? = some baseFrame)
    (hBaseLeGlobal : baseFrame.version.val ≤ s.history.global.val)
    (hHeadVer : head.version.val = baseFrame.version.val + prior.length)
    (version : U64) (hPos : 0 < version.val) (hLeHead : version.val ≤ head.version.val)
    (hGeGlobal : s.history.global.val ≤ version.val - 1)
    (hPrevAt
      : s.history.activeFrames[version.val - 1 - baseFrame.version.val]? = some prevFrame)
    (hPrevVer : prevFrame.version.val = version.val - 1)
    (hAtCut
      : ∀ previous : U64,
          previous.val = version.val - 1 → s.history.at_cut previous = .ok prevFrame)
    (hModelPrev : prevModel.head = modelFrame encode s.history.index prevFrame)
    (hIdentity : prevModel.nextIdentity = s.history.next_identity.val)
    (writes : alloc.vec.Vec (CcfKv.engine.Address × Option CcfKv.engine.Bytes))
    (hI : s.history.next_identity.val < U64.max)
    (hD
      : IndexBatchRoom s.history.index (storePins s).length
          ((indexRows s.history.index prevFrame.data).length + writes.val.length)
          writes.val.length)
    (hKeys : ∀ row ∈ writes.val, IndexKeyRoom (replayRow row))
    (hDepth : ∀ row ∈ writes.val, 8 + row.1.map.val.length + row.1.key.val.length ≤ 56)
    (hDirFast
      : s.history.index.values.dirs.val.length + 2 * (writes.val.length * (112 + 1))
        < 2147483647)
    (hRowFast : s.history.index.values.rows.val.length + writes.val.length ≤ 2147483647)
    (hRefFast
      : (storePins s).length
          + 17
            * (s.history.index.values.dirs.val.length
                + 2 * (writes.val.length * (112 + 1))
                + 2)
          + 1
        ≤ U32.max)
    (hQueueRoom
      : 2
            * (s.history.index.values.dirs.val.length
                + s.history.index.values.rows.val.length)
          + 1
        ≤ Usize.max)
    (hR : prevFrame.revisions.val.length + writes.val.length ≤ Usize.max)
    (hB : prevFrame.births.val.length + writes.val.length ≤ Usize.max)
    (valid : BranchValid s.history.log) (indexed : HistoryIndexValid s.history)
    (live : IndexLiveness s.history.index (storePins s))
    (hRingRoom : 2 * s.history.activeFrames.length + 1 ≤ Usize.max)
    : WP.spec (CcfKv.engine.Store.replay_ccf s version writes false)
        (fun (result, after) =>
          (result = .Err .Disabled ∧ after = s)
          ∨ (result = .Ok ()
              ∧ ∃ next,
                  FrameOrderEq (modelFrame encode after.history.index next)
                    (advance prevModel (encodeReport encode writes)).head
                  ∧ after.history.activeFrames
                    = s.history.activeFrames.take
                        (version.val - 1 - baseFrame.version.val + 1)
                      ++ [next]
                  ∧ after.history.next_identity.val = s.history.next_identity.val + 1
                  ∧ after.history.term = s.history.term
                  ∧ after.history.global = s.history.global
                  ∧ after.txs = s.txs
                  ∧ BranchValid after.history.log
                  ∧ HistoryIndexValid after.history
                  ∧ IndexLiveness after.history.index (storePins after))) := by
  unfold CcfKv.engine.Store.replay_ccf
  have hne0 : (version != 0#u64) = true := by
    have : version ≠ 0#u64 := fun h => by
      have : version.val = 0 := congrArg UScalar.val h; omega
    simp [this]
  rw [hne0, ite_eq_left rfl]
  rw [history_head s.history prior head hHead valid, bind_ok]
  have hle : version ≤ head.version := hLeHead
  rw [ite_eq_left hle]
  have hone : (1#u64 : U64).val = 1 := rfl
  apply WP.spec_bind (U64.sub_spec (x := version) (y := 1#u64) (by omega))
  intro previous hprevSub
  have hprevVal : previous.val = version.val - 1 := by omega
  have hnotLt : ¬ previous < s.history.global := by
    change ¬ previous.val < s.history.global.val; omega
  rw [ite_eq_right hnotLt, hAtCut previous hprevVal, bind_ok]
  have hVersionEq : version.val = prevFrame.version.val + 1 := by omega
  apply WP.spec_bind
    (prepare_replay_ccf_matches prevFrame.version s.history.next_identity version
      hVersionEq hI writes)
  rintro r (rfl | ⟨pending, rfl, hp⟩)
  · simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  · simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
    apply WP.spec_bind
      (history_rollback s.history previous s.history.term prior head baseFrame (txsPins s.txs.val)
        hHead hBaseAt hBaseLeGlobal hHeadVer (by omega) (le_refl _) valid live hQueueRoom)
    rintro ⟨rbOut, h1⟩ ⟨cut, hrbOut, hcutVal, h1Valid, h1Frames, h1Ret, h1Gl, h1Nid, h1Term,
      _, h1Live, h1Pres, h1DirsLen, h1RowsLen⟩
    subst hrbOut
    change WP.spec
      (Aeneas.Std.bind (Result.ok (core.ops.control_flow.ControlFlow.Continue (CcfKv.engine.Output.RolledBack cut)))
        (fun cf1 =>
          match cf1 with
          | core.ops.control_flow.ControlFlow.Continue val1 => do
              let b ←
                match val1 with
                | CcfKv.engine.Output.Unit => Result.ok false
                | CcfKv.engine.Output.Snapshot _ _ _ => Result.ok false
                | CcfKv.engine.Output.Acquired _ _ => Result.ok false
                | CcfKv.engine.Output.Unavailable => Result.ok false
                | CcfKv.engine.Output.Value _ => Result.ok false
                | CcfKv.engine.Output.Presence _ => Result.ok false
                | CcfKv.engine.Output.Previous _ => Result.ok false
                | CcfKv.engine.Output.Entries _ => Result.ok false
                | CcfKv.engine.Output.Size _ => Result.ok false
                | CcfKv.engine.Output.Applied _ _ _ => Result.ok false
                | CcfKv.engine.Output.Committed _ _ => Result.ok false
                | CcfKv.engine.Output.Compacted _ => Result.ok false
                | CcfKv.engine.Output.RolledBack _ => Result.ok true
                | CcfKv.engine.Output.RollbackRejected => Result.ok false
              if b then do
                let self1 ←
                  CcfKv.engine.Store.append_replay_ccf { s with history := h1 } version pending false
                Result.ok (core.result.Result.Ok (), self1)
              else
                Result.ok (core.result.Result.Err CcfKv.engine.Error.Disabled, { s with history := h1 })
          | core.ops.control_flow.ControlFlow.Break residual => do
              let r2 ←
                core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual Unit
                  (core.convert.FromSame CcfKv.engine.Error) residual
              Result.ok (r2, { s with history := h1 }))) _
    rw [bind_ok]
    change WP.spec (Aeneas.Std.bind (Result.ok true) _) _
    rw [bind_ok, ite_eq_left rfl]
    have hcutEq : cut.val = version.val - 1 := by omega
    have hidxLt : version.val - 1 - baseFrame.version.val < s.history.activeFrames.length := by
      rw [hHead, List.length_append, List.length_singleton]; omega
    have htakeSplit :
        s.history.activeFrames.take (version.val - 1 - baseFrame.version.val + 1)
        = s.history.activeFrames.take (version.val - 1 - baseFrame.version.val) ++ [prevFrame] := by
      rw [List.take_succ_eq_append_getElem hidxLt]
      congr 2
      rw [List.getElem?_eq_getElem hidxLt, Option.some.injEq] at hPrevAt
      exact hPrevAt
    have h1FramesSplit :
        h1.activeFrames
        = s.history.activeFrames.take (version.val - 1 - baseFrame.version.val) ++ [prevFrame] := by
      rw [h1Frames, hcutEq, htakeSplit]
    have h1HistValid : HistoryIndexValid h1 := by
      refine ⟨h1Live.valid, ?_, ?_⟩
      · intro frame hframe
        have hfOld : frame ∈ s.history.activeFrames := by
          rw [h1Frames] at hframe
          exact List.mem_of_mem_take hframe
        by_cases hz : frame.data = 0#u32
        · have hEmpty : IndexView h1.index frame.data [] := by
            rw [hz]
            exact ⟨[], ⟨⟨0, .empty 0⟩, (fun _ h => by cases h), List.Pairwise.nil⟩, rfl⟩
          exact index_rows_view ⟨[], hEmpty⟩
        · have hfPin : frame.data ∈ framePins h1.activeFrames ++ txsPins s.txs.val :=
            List.mem_append_left _ (List.mem_filterMap.mpr ⟨frame, hframe, by simp [hz]⟩)
          have hv := indexView_of_preserves_replay h1Pres hfPin (indexed.active frame hfOld)
          exact index_rows_view ⟨_, hv⟩
      · intro frame hframe
        rw [h1Ret] at hframe
        exact indexed.retainedEmpty frame hframe
    have hprevMemH1 : prevFrame ∈ h1.activeFrames := by
      rw [h1FramesSplit]; exact List.mem_append_right _ List.mem_cons_self
    have hprevMemS : prevFrame ∈ s.history.activeFrames := by
      rw [h1Frames] at hprevMemH1; exact List.mem_of_mem_take hprevMemH1
    have hprevRowsEq : indexRows h1.index prevFrame.data = indexRows s.history.index prevFrame.data := by
      by_cases hz : prevFrame.data = 0#u32
      · rw [hz]
        have he1 : IndexView h1.index 0#u32 [] :=
          ⟨[], ⟨⟨0, .empty 0⟩, (fun _ h => by cases h), List.Pairwise.nil⟩, rfl⟩
        have he2 : IndexView s.history.index 0#u32 [] :=
          ⟨[], ⟨⟨0, .empty 0⟩, (fun _ h => by cases h), List.Pairwise.nil⟩, rfl⟩
        rw [index_rows_eq he1, index_rows_eq he2]
      · have hpPin : prevFrame.data ∈ framePins h1.activeFrames ++ txsPins s.txs.val :=
          List.mem_append_left _ (List.mem_filterMap.mpr ⟨prevFrame, hprevMemH1, by simp [hz]⟩)
        have hv := indexView_of_preserves_replay h1Pres hpPin (indexed.active prevFrame hprevMemS)
        exact index_rows_eq hv
    have hModelPrevH1 : prevModel.head = modelFrame encode h1.index prevFrame := by
      rw [hModelPrev]; simp [modelFrame, hprevRowsEq]
    have h1PinsLe : (storePins { s with history := h1 }).length ≤ (storePins s).length := by
      simp only [storePins, List.length_append]
      have hfp : (framePins h1.activeFrames).length ≤ (framePins s.history.activeFrames).length := by
        rw [h1Frames]
        have hdrop : s.history.activeFrames =
            s.history.activeFrames.take (cut.val - baseFrame.version.val + 1)
            ++ s.history.activeFrames.drop (cut.val - baseFrame.version.val + 1) :=
          (List.take_append_drop _ _).symm
        conv_rhs => rw [hdrop]
        simp only [framePins, List.filterMap_append, List.length_append]
        exact Nat.le_add_right _ _
      omega
    have h1D : IndexBatchRoom h1.index (storePins { s with history := h1 }).length
        ((indexRows h1.index prevFrame.data).length + writes.val.length) writes.val.length := by
      rw [hprevRowsEq]
      refine ⟨?_, ?_, ?_, ?_⟩
      · rw [h1DirsLen]; exact hD.lookup
      · rw [h1RowsLen]; exact hD.values
      · have h := hD.refs; rw [h1DirsLen]; omega
      · have h := hD.queue; rw [h1DirsLen, h1RowsLen]; exact h
    have h1DirFast :
        h1.index.values.dirs.val.length + 2 * (writes.val.length * (112 + 1)) < 2147483647 := by
      rw [h1DirsLen]; exact hDirFast
    have h1RowFast :
        h1.index.values.rows.val.length + writes.val.length ≤ 2147483647 := by
      rw [h1RowsLen]; exact hRowFast
    have h1RefFast :
        (storePins { s with history := h1 }).length
          + 17 * (h1.index.values.dirs.val.length + 2 * (writes.val.length * (112 + 1)) + 2)
          + 1 ≤ U32.max := by
      rw [h1DirsLen]; omega
    have h1RingRoom :
        h1.log.len.val = h1.log.slots.val.length
        → 2 * h1.log.slots.val.length + 1 ≤ Usize.max := by
      intro hfull
      have hlenEq : h1.log.len.val = h1.activeFrames.length := by
        change h1.log.len.val = (branchValues h1.log).length
        exact (branch_values_length h1.log h1Valid).symm
      have hleLen : h1.activeFrames.length ≤ s.history.activeFrames.length := by
        rw [h1Frames, List.length_take]; exact Nat.min_le_right _ _
      omega
    have hApp := append_replay_ccf_ok_matches_advance encode inj { s with history := h1 } prevModel
      (s.history.activeFrames.take (version.val - 1 - baseFrame.version.val)) prevFrame
      h1FramesSplit hModelPrevH1 (by rw [h1Nid]; exact hIdentity) version hVersionEq writes
      pending hp (by rw [h1Nid]; exact hI) h1D hKeys hDepth h1DirFast h1RowFast h1RefFast
      hR hB h1Valid h1HistValid h1Live h1RingRoom
    refine WP.spec_mono hApp ?_
    rintro ⟨res, after⟩ ⟨hOk, next, hFrameEq, hAFrames, hANid, hATerm, hAGl, hATxs,
      hAValid, hAHist, hALive, _⟩
    refine Or.inr ⟨hOk, next, hFrameEq, ?_, ?_, ?_, ?_, hATxs, hAValid, hAHist, hALive⟩
    · rw [hAFrames, h1Frames, hcutEq]
    · rw [hANid, h1Nid]
    · rw [hATerm, h1Term]
    · rw [hAGl, h1Gl]

/-! ## Part 5: `Store::swap_recovery_maps` Guard Proofs -/

/-- `Store::swap_recovery_maps` rejects with `Error::Disabled` and leaves both stores unchanged
when the destination store has active transactions. -/
theorem swap_recovery_maps_rejects_self_txs (s source : CcfKv.engine.Store)
    (names : alloc.vec.Vec CcfKv.engine.Bytes) (hne : s.txs.val ≠ [])
    : CcfKv.engine.Store.swap_recovery_maps s source names
      = .ok (.Err .Disabled, s, source) := by
  unfold CcfKv.engine.Store.swap_recovery_maps
  have hemp : alloc.vec.Vec.is_empty s.txs = .ok false := by
    unfold alloc.vec.Vec.is_empty
    simp [List.length_eq_zero_iff, hne]
  dsimp only
  rw [hemp, bind_ok]
  rfl

/-- `Store::swap_recovery_maps` rejects with `Error::Disabled` and leaves both stores unchanged
when the source store has active transactions. -/
theorem swap_recovery_maps_rejects_source_txs (s source : CcfKv.engine.Store)
    (names : alloc.vec.Vec CcfKv.engine.Bytes)
    (hself : s.txs.val = []) (hsrc : source.txs.val ≠ [])
    : CcfKv.engine.Store.swap_recovery_maps s source names
      = .ok (.Err .Disabled, s, source) := by
  unfold CcfKv.engine.Store.swap_recovery_maps
  have h1 : alloc.vec.Vec.is_empty s.txs = .ok true := by
    unfold alloc.vec.Vec.is_empty
    simp [hself]
  have h2 : alloc.vec.Vec.is_empty source.txs = .ok false := by
    unfold alloc.vec.Vec.is_empty
    simp [List.length_eq_zero_iff, hsrc]
  dsimp only
  rw [h1, bind_ok, ite_eq_left rfl, h2, bind_ok]
  rfl

/-- `Store::swap_recovery_maps` rejects with `Error::Disabled` and leaves both stores unchanged
when `source`'s head version is ahead of the destination store's head version. -/
theorem swap_recovery_maps_rejects_source_ahead (s source : CcfKv.engine.Store)
    (names : alloc.vec.Vec CcfKv.engine.Bytes)
    (sprior dprior : List CcfKv.engine.Frame) (shead dhead : CcfKv.engine.Frame)
    (hself : s.txs.val = []) (hsrc : source.txs.val = [])
    (hsHead : source.history.activeFrames = sprior ++ [shead])
    (hdHead : s.history.activeFrames = dprior ++ [dhead])
    (hsValid : BranchValid source.history.log) (hdValid : BranchValid s.history.log)
    (hahead : dhead.version.val < shead.version.val)
    : CcfKv.engine.Store.swap_recovery_maps s source names
      = .ok (.Err .Disabled, s, source) := by
  unfold CcfKv.engine.Store.swap_recovery_maps
  have h1 : alloc.vec.Vec.is_empty s.txs = .ok true := by
    unfold alloc.vec.Vec.is_empty; simp [hself]
  have h2 : alloc.vec.Vec.is_empty source.txs = .ok true := by
    unfold alloc.vec.Vec.is_empty; simp [hsrc]
  dsimp only
  rw [h1, bind_ok, ite_eq_left rfl, h2, bind_ok, ite_eq_left rfl,
    history_head source.history sprior shead hsHead hsValid, bind_ok,
    history_head s.history dprior dhead hdHead hdValid, bind_ok]
  have hgt : shead.version > dhead.version := hahead
  rw [ite_eq_left hgt]

/-- `Store::swap_recovery_maps` rejects with `Error::Exhausted` and leaves both stores unchanged
when either store's identity counter is at `U64::MAX`. -/
theorem swap_recovery_maps_rejects_exhausted (s source : CcfKv.engine.Store)
    (names : alloc.vec.Vec CcfKv.engine.Bytes)
    (sprior dprior : List CcfKv.engine.Frame) (shead dhead : CcfKv.engine.Frame)
    (hself : s.txs.val = []) (hsrc : source.txs.val = [])
    (hsHead : source.history.activeFrames = sprior ++ [shead])
    (hdHead : s.history.activeFrames = dprior ++ [dhead])
    (hsValid : BranchValid source.history.log) (hdValid : BranchValid s.history.log)
    (hle : shead.version.val ≤ dhead.version.val)
    (hexh
      : s.history.next_identity = core.num.U64.MAX
        ∨ source.history.next_identity = core.num.U64.MAX)
    : CcfKv.engine.Store.swap_recovery_maps s source names
      = .ok (.Err .Exhausted, s, source) := by
  unfold CcfKv.engine.Store.swap_recovery_maps
  have h1 : alloc.vec.Vec.is_empty s.txs = .ok true := by
    unfold alloc.vec.Vec.is_empty; simp [hself]
  have h2 : alloc.vec.Vec.is_empty source.txs = .ok true := by
    unfold alloc.vec.Vec.is_empty; simp [hsrc]
  dsimp only
  rw [h1, bind_ok, ite_eq_left rfl, h2, bind_ok, ite_eq_left rfl,
    history_head source.history sprior shead hsHead hsValid, bind_ok,
    history_head s.history dprior dhead hdHead hdValid, bind_ok]
  have hngt : ¬ shead.version > dhead.version := by
    change ¬ shead.version.val > dhead.version.val; omega
  rw [ite_eq_right hngt]
  rcases hexh with hmax1 | hmax2
  · rw [ite_eq_left hmax1]
  · by_cases hmax1 : s.history.next_identity = core.num.U64.MAX
    · rw [ite_eq_left hmax1]
    · rw [ite_eq_right hmax1, ite_eq_left hmax2]

end KvRust
