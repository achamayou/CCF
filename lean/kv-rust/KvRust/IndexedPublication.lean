-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.IndexedImage

@[expose] public section

namespace KvRust

open Aeneas.Std

local instance : DecidableEq Spike.engine.Address :=
  fun a b => decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

abbrev IndexWrite := Spike.engine.Address × Spike.engine.Write

def applyIndexedWrite (version : U64) (row : IndexWrite) (data : CellRows) : CellRows :=
  match row.2 with
  | .Put value => Kv.Model.set data row.1 {value, version}
  | .Remove => Kv.Model.erase data row.1

def indexedCellData (rows : CellRows) : Kv.Model.DB (List U8) (List U8) (List U8) :=
  rows.map fun (a, c) => (byteAddr a, byteCell c)

theorem indexed_fold_projects (rows : CellRows) (writes : List IndexWrite) (version : U64)
    : indexedCellData (writes.foldr (applyIndexedWrite version) rows)
      = Kv.Model.publish (indexedCellData rows) version.val (byteWrites writes) := by
  induction writes with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨a, w⟩ := row
      cases w with
      | Put value =>
          change _ = Kv.Model.set (Kv.Model.publish (indexedCellData rows) version.val
            (byteWrites rest)) (byteAddr a) (byteCell {value, version})
          rw [← ih]
          exact (set_projected _ a {value, version} byteAddr byteCell
            (fun _ _ h => byteAddr_inj h)).symm
      | Remove =>
          change _ = Kv.Model.erase (Kv.Model.publish (indexedCellData rows) version.val
            (byteWrites rest)) (byteAddr a)
          rw [← ih]
          exact (erase_projected _ a byteAddr byteCell (fun _ _ h => byteAddr_inj h)).symm

abbrev CellIndex := Spike.kv_index.AddressIndex Spike.engine.Cell

def IndexKeyRoom (row : IndexWrite) : Prop :=
  2 * (8 + row.1.map.val.length + row.1.key.val.length) + 1 ≤ Usize.max

/-- Conservative headroom for every edit in the batch, including removal and reinsertion
of a stamp on replacement. The bound is computed from the input sizes alone. -/
structure IndexBatchRoom (index : CellIndex) (peak writes : Nat) : Prop where
  lookup : index.values.dirs.val.length + writes * (peak + 1) ≤ 2147483647
  order : index.order.dirs.val.length + writes * (2 * peak + 1) ≤ 2147483647
  values : index.values.rows.val.length + writes ≤ 2147483647
  stamps : index.order.rows.val.length + writes ≤ 2147483647
  clock : index.last.val + writes ≤ U64.max

private theorem indexed_row_refines (index : CellIndex) (root : Spike.radix.DualRoot)
    (rows : CellRows) (write : IndexWrite) (version : U64)
    (view : IndexView index root rows) (valid : IndexValid index)
    (keyRoom : IndexKeyRoom write) (space : IndexBatchRoom index rows.length 1)
    : WP.spec (Spike.engine.publish_indexed_row index root write version)
        (fun (next, after) =>
          IndexView after next (applyIndexedWrite version write rows)
          ∧ IndexValid after
          ∧ IndexKeeps index after
          ∧ IndexGrowth index after (rows.length + 1) (2 * rows.length + 1) 1) := by
  obtain ⟨address, action⟩ := write
  have lookup := space.lookup
  have order := space.order
  have values := space.values
  have stamps := space.stamps
  have clock := space.clock
  have key : 2 * (8 + address.map.val.length + address.key.val.length) + 1 ≤ Usize.max :=
    keyRoom
  simp only [Nat.one_mul] at lookup order
  cases action with
  | Put value =>
      simp only [Spike.engine.publish_indexed_row, clone_address, clone_bytes, bind_ok,
        applyIndexedWrite]
      exact index_put_refines index root rows view address {value, version} valid
        (by omega) order (by omega) (by omega) key (by omega)
  | Remove =>
      simp only [Spike.engine.publish_indexed_row, applyIndexedWrite]
      apply WP.spec_mono
        (index_remove_refines index root rows view address valid
          (by omega) (by omega) (by omega))
      rintro ⟨next, after⟩ ⟨updated, good, kept, ⟨⟨ld, lv⟩, ⟨od, ov⟩, stamp⟩⟩
      dsimp only
      exact ⟨updated, good, kept, ⟨by omega, by omega⟩, ⟨by omega, by omega⟩, by omega⟩

private theorem indexed_write_length (version : U64) (row : IndexWrite) (data : CellRows)
    : (applyIndexedWrite version row data).length ≤ data.length + 1 := by
  obtain ⟨a, w⟩ := row
  have erased : (Kv.Model.erase data a).length ≤ data.length := List.length_filter_le _ _
  cases w <;> simp only [applyIndexedWrite, Kv.Model.set, List.length_cons] <;> omega

/-- Extracted publication implements the exact fold order and retains every prior live root. -/
theorem indexed_publication_refines (index : CellIndex) (root : Spike.radix.DualRoot)
    (rows : CellRows)
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write) (version : U64)
    (view : IndexView index root rows) (valid : IndexValid index)
    (space : IndexBatchRoom index (rows.length + pending.val.length) pending.val.length)
    (addresses : ∀ row ∈ pending.val, IndexKeyRoom row)
    : WP.spec (Spike.engine.publish_indexed index root pending version)
        (fun (next, after) =>
          IndexView after next (pending.val.foldr (applyIndexedWrite version) rows)
          ∧ IndexValid after
          ∧ IndexKeeps index after
          ∧ IndexGrowth index after
              (pending.val.length * (rows.length + pending.val.length + 1))
              (pending.val.length * (2 * (rows.length + pending.val.length) + 1))
              pending.val.length) := by
  let total := pending.val.length
  let peak := rows.length + total
  let lookupCost := peak + 1
  let orderCost := 2 * peak + 1
  let expected := pending.val.foldr (applyIndexedWrite version) rows
  change WP.spec _ (fun (next, after) => IndexView after next expected ∧ IndexValid after
    ∧ IndexKeeps index after ∧ IndexGrowth index after (total * lookupCost) (total * orderCost) total)
  unfold Spike.engine.publish_indexed Spike.engine.publish_indexed_loop
  apply loop.spec_decr_nat (fun (_, _, i) => (i : Usize).val)
    (fun (arena, cut, i) =>
      i.val ≤ total
      ∧ IndexValid arena
      ∧ IndexKeeps index arena
      ∧ IndexGrowth index arena ((total - i.val) * lookupCost)
          ((total - i.val) * orderCost) (total - i.val)
      ∧ ∃ current : CellRows,
          IndexView arena cut current
          ∧ current.length + i.val ≤ peak
          ∧ (pending.val.take i.val).foldr (applyIndexedWrite version) current = expected)
    _ _ _
  · rintro ⟨arena, cut, i⟩ ⟨hi, good, kept, growth, current, related, size, remaining⟩
    dsimp only at hi good kept growth related size remaining ⊢
    unfold Spike.engine.publish_indexed_loop.body
    have one : (1#usize : Usize).val = 1 := rfl
    by_cases run : (0#usize : Usize) < i
    · have positive : 0 < i.val := run
      rw [ite_eq_left run]
      apply WP.spec_bind (Usize.sub_spec (x := i) (y := 1#usize) (by omega))
      intro j hj
      have step : i.val = j.val + 1 := by omega
      have bound : j.val < pending.val.length := by change j.val < total; omega
      rw [alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending j bound)
      intro row read
      have keys : IndexKeyRoom row := addresses row (read ▸ List.getElem_mem _)
      have used : total - j.val = (total - i.val).succ := by omega
      have split (cost : Nat) :
          (total - i.val) * cost + cost ≤ total * cost := by
        rw [← Nat.succ_mul, ← used]
        exact Nat.mul_le_mul_right _ (Nat.sub_le _ _)
      obtain ⟨⟨ld, lv⟩, ⟨od, ov⟩, tick⟩ := growth
      have lookupStep := split lookupCost
      have orderStep := split orderCost
      have ⟨pl, po, pv, ps, pc⟩ :
          IndexBatchRoom index peak total := space
      have smaller : current.length ≤ peak := by omega
      have lstep : current.length + 1 ≤ lookupCost := by dsimp [lookupCost]; omega
      have ostep : 2 * current.length + 1 ≤ orderCost := by dsimp [orderCost]; omega
      change index.values.dirs.val.length + total * lookupCost ≤ 2147483647 at pl
      change index.order.dirs.val.length + total * orderCost ≤ 2147483647 at po
      have nextRoom : IndexBatchRoom arena current.length 1 :=
        ⟨by simp only [Nat.one_mul]; omega, by simp only [Nat.one_mul]; omega,
          by omega, by omega, by omega⟩
      apply WP.spec_bind (indexed_row_refines arena cut current row version related good keys nextRoom)
      rintro ⟨next, after⟩ ⟨nextView, nextValid, nextKeeps, ⟨⟨dl, vl⟩, ⟨do', vo⟩, stamp⟩⟩
      change WP.spec (Result.ok (ControlFlow.cont (after, next, j))) _
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨by omega, nextValid, kept.trans nextKeeps, ?_,
        applyIndexedWrite version row current, nextView, ?_, ?_⟩, by omega⟩
      · rw [used, Nat.succ_mul, Nat.succ_mul]
        exact ⟨⟨by omega, by omega⟩, ⟨by omega, by omega⟩, by omega⟩
      · have len := indexed_write_length version row current
        omega
      · rw [step, List.take_succ_eq_append_getElem bound, ← read, List.foldr_append] at remaining
        exact remaining
    · have zero : i.val = 0 := by
        have notPositive : ¬ 0 < i.val := run
        omega
      rw [ite_eq_right run, WP.spec_ok]
      rw [zero, Nat.sub_zero] at growth
      simp only [zero, List.take_zero, List.foldr_nil] at remaining
      exact ⟨remaining ▸ related, good, kept, growth⟩
  · have length : (alloc.vec.Vec.len pending).val = total := alloc.vec.Vec.len_val pending
    simp only [length, Nat.sub_self, Nat.zero_mul, Nat.le_refl, true_and]
    exact ⟨valid, .refl _, ⟨⟨Nat.le_refl _, Nat.le_refl _⟩,
      ⟨Nat.le_refl _, Nat.le_refl _⟩, Nat.le_refl _⟩, rows, view, Nat.le_refl _,
      by simp [total, expected]⟩

end KvRust
