-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Range

@[expose] public section

namespace KvRust

open Aeneas.Std

abbrev PendingWrite := CcfKv.engine.Address × CcfKv.engine.Write

def pendingAddressLt (a b : CcfKv.engine.Address) : Prop :=
  a.key.val < b.key.val ∨ (a.key.val = b.key.val ∧ a.map.val < b.map.val)

def PendingSorted (rows : List PendingWrite) : Prop :=
  rows.Pairwise (fun a b => pendingAddressLt b.1 a.1)

private theorem pending_lt_irrefl (a : CcfKv.engine.Address)
    : ¬ pendingAddressLt a a := by
  simp [pendingAddressLt]

theorem PendingSorted.unique {rows : List PendingWrite} (sorted : PendingSorted rows)
    : (rows.map Prod.fst).Nodup := by
  change (rows.map Prod.fst).Pairwise (· ≠ ·)
  rw [List.pairwise_map]
  apply sorted.imp
  intro left right lt eq
  exact pending_lt_irrefl _ (eq ▸ lt)

private theorem pending_lt_trans {a b c : CcfKv.engine.Address}
    (ab : pendingAddressLt a b) (bc : pendingAddressLt b c)
    : pendingAddressLt a c := by
  rcases ab with ab | ⟨eqAB, ab⟩ <;> rcases bc with bc | ⟨eqBC, bc⟩
  · exact Or.inl (lt_trans ab bc)
  · exact Or.inl (eqBC ▸ ab)
  · exact Or.inl (eqAB.symm ▸ bc)
  · exact Or.inr ⟨eqAB.trans eqBC, lt_trans ab bc⟩

private theorem byte_order_zero (a b : List U8) : byteOrder a b = 0#i8 ↔ a = b := by
  have rev : 0#i8 ≤ byteOrder a b ↔ b ≤ a :=
    (not_lt (a := byteOrder a b) (b := 0#i8)).symm.trans
      ((not_congr (byteOrder_lt a b)).trans not_lt)
  rw [le_antisymm_iff, byteOrder_le, rev, ← le_antisymm_iff]

private theorem byte_order_pos (a b : List U8) : 0#i8 < byteOrder a b ↔ b < a := by
  rw [← not_le, byteOrder_le, not_le]

private theorem pending_order_refines (a b : CcfKv.engine.Address)
    : WP.spec (CcfKv.engine.pending_key_order a b)
        (fun order =>
          (order = 0#i8 ↔ a = b)
          ∧ (0#i8 < order ↔ pendingAddressLt b a)
          ∧ (order < 0#i8 ↔ pendingAddressLt a b)) := by
  unfold CcfKv.engine.pending_key_order
  apply WP.spec_bind (bytes_compare a.key b.key)
  intro order keyCompare
  subst order
  by_cases same : a.key.val = b.key.val
  · have zero := (byte_order_zero _ _).mpr same
    rw [zero]
    simp only [bne_self_eq_false, Bool.false_eq_true, ite_false]
    apply WP.spec_mono (bytes_compare a.map b.map)
    intro order mapCompare
    rw [mapCompare, byte_order_zero, byte_order_pos, byteOrder_lt]
    refine ⟨?_, ?_, ?_⟩
    · constructor
      · intro sameMap
        exact byteAddr_inj (Prod.ext sameMap same)
      · rintro rfl
        rfl
    · simp [pendingAddressLt, same]
    · simp [pendingAddressLt, same]
  · have nonzero : byteOrder a.key.val b.key.val ≠ 0#i8 :=
      fun z => same ((byte_order_zero _ _).mp z)
    have reverse : b.key.val ≠ a.key.val := Ne.symm same
    have diff : a ≠ b := fun eq => same (congrArg (fun x => x.key.val) eq)
    have unequal : (byteOrder a.key.val b.key.val != 0#i8) = true := bne_iff_ne.mpr nonzero
    rw [ite_eq_left unequal, WP.spec_ok]
    simp only [pendingAddressLt, reverse, same, false_and, or_false]
    exact ⟨iff_of_false nonzero diff, byte_order_pos _ _, byteOrder_lt _ _⟩

local instance pendingAddressEquality : DecidableEq CcfKv.engine.Address :=
  fun a b => decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

private theorem sorted_edit (rows left right : List PendingWrite)
    (address : CcfKv.engine.Address) (write : CcfKv.engine.Write)
    (rest : PendingSorted (left ++ right))
    (older : ∀ row ∈ left, pendingAddressLt address row.1)
    (newer : ∀ row ∈ right, pendingAddressLt row.1 address)
    (contents : Kv.Model.erase rows address = left ++ right)
    : PendingSorted (left ++ (address, write) :: right)
      ∧ (left ++ (address, write) :: right).Perm (Kv.Model.set rows address write) := by
  constructor
  · obtain ⟨hl, hr, cross⟩ := List.pairwise_append.mp rest
    apply List.pairwise_append.mpr
    refine ⟨hl, List.pairwise_cons.mpr ⟨newer, hr⟩, ?_⟩
    intro a ha b hb
    rcases List.mem_cons.mp hb with rfl | inRight
    · exact older a ha
    · exact cross a ha b inRight
  · rw [Kv.Model.set, contents]
    exact List.perm_middle

private theorem erase_ordered (address : CcfKv.engine.Address) (rows : List PendingWrite)
    (diff : ∀ row ∈ rows, row.1 ≠ address)
    : Kv.Model.erase rows address = rows := by
  exact List.filter_eq_self.mpr fun row present => bne_iff_ne.mpr (diff row present)

private theorem split_pending_insert (xs : List PendingWrite) (i : Nat) (x : PendingWrite)
    (within : i ≤ xs.length)
    : xs.insertIdx i x = xs.take i ++ x :: xs.drop i := by
  induction xs generalizing i with
  | nil => cases i <;> simp_all
  | cons a xs ih =>
      cases i with
      | zero => rfl
      | succ i => simp [List.insertIdx_succ_cons, ih _ (by simpa using within)]

private theorem prefix_before {rows : List PendingWrite} {address : CcfKv.engine.Address}
    (cut : Nat)
    (before
      : ∀ i (inRows : i < rows.length), i < cut → pendingAddressLt address rows[i].1)
    : ∀ row ∈ rows.take cut, pendingAddressLt address row.1 := by
  intro row present
  obtain ⟨i, hi, read⟩ := List.mem_iff_getElem.mp present
  rw [List.length_take] at hi
  rw [← read, List.getElem_take]
  exact before i (by omega) (by omega)

private theorem suffix_after {rows : List PendingWrite} {address : CcfKv.engine.Address}
    (cut : Nat)
    (after : ∀ i (inRows : i < rows.length), cut ≤ i → pendingAddressLt rows[i].1 address)
    : ∀ row ∈ rows.drop cut, pendingAddressLt row.1 address := by
  intro row present
  obtain ⟨i, hi, read⟩ := List.mem_iff_getElem.mp present
  rw [List.length_drop] at hi
  rw [← read, List.getElem_drop]
  exact after (cut + i) (by omega) (by omega)

private theorem sorted_replacement (rows : List PendingWrite)
    (sorted : PendingSorted rows) (address : CcfKv.engine.Address)
    (write : CcfKv.engine.Write) (i : Nat) (inside : i < rows.length)
    (found : rows[i].1 = address)
    : PendingSorted (rows.set i (address, write))
      ∧ (rows.set i (address, write)).Perm (Kv.Model.set rows address write) := by
  have compare := List.pairwise_iff_getElem.mp sorted
  have front := prefix_before i (fun j hj lt => found ▸ compare j i hj inside lt)
  have back := suffix_after (i + 1) (fun j hj le =>
    found ▸ compare i j inside hj (by omega))
  have split : rows = rows.take i ++ rows[i] :: rows.drop (i + 1) := by
    conv_lhs => rw [← List.take_append_drop i rows, List.drop_eq_getElem_cons inside]
  have ordered := List.pairwise_append.mp (split ▸ sorted)
  have tailOrder := List.pairwise_cons.mp ordered.2.1
  have rest : PendingSorted (rows.take i ++ rows.drop (i + 1)) :=
    List.pairwise_append.mpr ⟨ordered.1, tailOrder.2,
      fun a ha b hb => ordered.2.2 a ha b (List.mem_cons_of_mem _ hb)⟩
  have eraseEq : Kv.Model.erase rows address = rows.take i ++ rows.drop (i + 1) := by
    conv_lhs => rw [split]
    unfold Kv.Model.erase
    have eraseFront := erase_ordered address (rows.take i) (fun row hm eq =>
      pending_lt_irrefl address (eq ▸ front row hm))
    have eraseBack := erase_ordered address (rows.drop (i + 1)) (fun row hm eq =>
      pending_lt_irrefl address (eq ▸ back row hm))
    simp only [List.filter_append, List.filter_cons, found, bne_self_eq_false,
      Bool.false_eq_true, ite_false]
    exact congrArg₂ List.append eraseFront eraseBack
  rw [List.set_eq_take_append_cons_drop, ite_eq_left inside]
  exact sorted_edit rows _ _ address write rest front back eraseEq

private theorem sorted_insertion (rows : List PendingWrite) (sorted : PendingSorted rows)
    (address : CcfKv.engine.Address) (write : CcfKv.engine.Write) (i : Nat)
    (older : ∀ row ∈ rows.take i, pendingAddressLt address row.1)
    (newer : ∀ row ∈ rows.drop i, pendingAddressLt row.1 address)
    : PendingSorted (rows.take i ++ (address, write) :: rows.drop i)
      ∧ (rows.take i ++ (address, write) :: rows.drop i).Perm
          (Kv.Model.set rows address write) := by
  have rest : PendingSorted (rows.take i ++ rows.drop i) := by
    simpa only [List.take_append_drop] using sorted
  have eraseEq : Kv.Model.erase rows address = rows := erase_ordered address _ (fun row hm eq => by
    rw [← List.take_append_drop i rows] at hm
    rcases List.mem_append.mp hm with hm | hm
    · exact pending_lt_irrefl address (eq ▸ older row hm)
    · exact pending_lt_irrefl address (eq ▸ newer row hm))
  exact sorted_edit rows _ _ address write rest older newer
    (eraseEq.trans (List.take_append_drop _ _).symm)

/-- Key-ordered staging keeps one final value or tombstone per address and
changes only the order of the write set compared with the list model. -/
theorem stage_write_by_key_refines (rows : alloc.vec.Vec PendingWrite)
    (address : CcfKv.engine.Address) (write : CcfKv.engine.Write)
    (sorted : PendingSorted rows.val) (room : rows.val.length < Usize.max)
    : WP.spec (CcfKv.engine.stage_write rows address write)
        (fun next =>
          PendingSorted next.val
          ∧ next.val.Perm (Kv.Model.set rows.val address write)) := by
  unfold CcfKv.engine.stage_write
  apply WP.spec_bind (Pₘ := fun next : alloc.vec.Vec PendingWrite =>
    PendingSorted next.val ∧ next.val.Perm (Kv.Model.set rows.val address write))
  swap
  · intro next done
    rw [WP.spec_ok]
    exact done
  let length := rows.val.length
  let before := fun cut => ∀ i (hi : i < length), i < cut → pendingAddressLt address rows.val[i].1
  let after := fun cut => ∀ i (hi : i < length), cut ≤ i → pendingAddressLt rows.val[i].1 address
  have compare := List.pairwise_iff_getElem.mp sorted
  unfold CcfKv.engine.stage_write_loop
  apply loop.spec_decr_nat (fun (lo, hi) => (hi : Usize).val - (lo : Usize).val)
    (fun (lo, hi) => lo.val ≤ hi.val ∧ hi.val ≤ length ∧ before lo.val ∧ after hi.val) _ _
    _
  · rintro ⟨lo, hi⟩ ⟨ordered, bounded, frontInv, backInv⟩
    dsimp only at ordered bounded frontInv backInv ⊢
    unfold CcfKv.engine.stage_write_loop.body
    by_cases run : lo < hi
    · rw [ite_eq_left run]
      have hrun : lo.val < hi.val := run
      have two : (2#usize : Usize).val = 2 := rfl
      have one : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.sub_spec (x := hi) (y := lo) ordered)
      intro width hw
      apply WP.spec_bind (Usize.div_spec width (y := 2#usize) (by decide))
      intro half hh
      rw [two] at hh
      have offset : half.val < hi.val - lo.val := by omega
      apply WP.spec_bind (Usize.add_spec (x := lo) (y := half) (by omega))
      intro mid hm
      have inside : mid.val < rows.val.length := by dsimp [length] at bounded; omega
      rw [alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec rows mid inside)
      rintro ⟨key, value⟩ read
      change WP.spec (do
        let order ← CcfKv.engine.pending_key_order key address
        if order = 0#i8 then _ else _) _
      apply WP.spec_bind (pending_order_refines key address)
      intro order ⟨zero, pos, neg⟩
      have keyAt : rows.val[mid.val].1 = key := (congrArg Prod.fst read).symm
      by_cases equal : order = 0#i8
      · rw [ite_eq_left equal, alloc.vec.Vec.index_mut_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec rows mid inside)
        rintro ⟨⟨found, old⟩, back⟩ ⟨actual, update⟩
        change WP.spec (Result.ok (ControlFlow.done (back (found, write)))) _
        rw [WP.spec_ok]
        have same : found = address :=
          (congrArg Prod.fst actual).trans (keyAt.trans (zero.mp equal))
        rw [same, update]
        change PendingSorted (rows.set mid (address, write)).val ∧
          (rows.set mid (address, write)).val.Perm (Kv.Model.set rows.val address write)
        rw [alloc.vec.Vec.set_val_eq]
        exact sorted_replacement _ sorted address write mid.val inside (keyAt.trans (zero.mp equal))
      · rw [ite_eq_right equal]
        by_cases greater : 0#i8 < order
        · rw [ite_eq_left greater]
          have positive := pos.mp greater
          apply WP.spec_bind (Usize.add_spec (x := mid) (y := 1#usize) (by omega))
          intro next step
          rw [WP.spec_ok]
          change (next.val ≤ hi.val ∧ hi.val ≤ length ∧ before next.val ∧ after hi.val) ∧
            hi.val - next.val < hi.val - lo.val
          refine ⟨⟨by omega, bounded, ?_, backInv⟩, by omega⟩
          intro j hj bound
          by_cases same : j = mid.val
          · simpa only [same, keyAt] using positive
          · have earlier : j < mid.val := by omega
            exact pending_lt_trans (keyAt.symm ▸ positive) (compare j mid.val hj inside earlier)
        · rw [ite_eq_right greater, WP.spec_ok]
          have smaller : order < 0#i8 := lt_of_le_of_ne (le_of_not_gt greater) equal
          have negative := neg.mp smaller
          change (lo.val ≤ mid.val ∧ mid.val ≤ length ∧ before lo.val ∧ after mid.val) ∧
            mid.val - lo.val < hi.val - lo.val
          refine ⟨⟨by omega, by omega, frontInv, ?_⟩, by omega⟩
          intro j hj bound
          by_cases same : j = mid.val
          · simpa only [same, keyAt] using negative
          · have later : mid.val < j := by omega
            exact pending_lt_trans (compare mid.val j inside hj later) (keyAt.symm ▸ negative)
    · rw [ite_eq_right run]
      have stop : lo.val = hi.val := by
        have hstop : ¬ lo.val < hi.val := run
        omega
      have take := prefix_before lo.val frontInv
      have drop := suffix_after lo.val (stop.symm ▸ backInv)
      have result := sorted_insertion rows.val sorted address write lo.val take drop
      have size : (alloc.vec.Vec.len rows).val = rows.val.length := alloc.vec.Vec.len_val _
      by_cases endOfRows : lo = alloc.vec.Vec.len rows
      · rw [ite_eq_left endOfRows]
        apply WP.spec_bind (alloc.vec.Vec.push_spec rows (address, write) room)
        intro next added
        rw [WP.spec_ok]
        have past : rows.val.length ≤ lo.val := by rw [endOfRows, size]
        simpa [added, List.take_of_length_le past, List.drop_eq_nil_of_le past] using result
      · rw [ite_eq_right endOfRows]
        have inside : lo.val < rows.val.length := by
          have no : lo.val ≠ (alloc.vec.Vec.len rows).val := fun e => endOfRows (UScalar.eq_of_val_eq e)
          dsimp [length] at bounded
          omega
        apply WP.spec_bind (alloc.vec.Vec.insert_spec rows lo (address, write) inside room)
        intro next added
        rw [WP.spec_ok]
        change PendingSorted next.val ∧ next.val.Perm (Kv.Model.set rows.val address write)
        rw [added, split_pending_insert _ _ _ (by omega)]
        exact result
  · have size : (alloc.vec.Vec.len rows).val = length := alloc.vec.Vec.len_val _
    change (0#usize : Usize).val ≤ (alloc.vec.Vec.len rows).val ∧
      (alloc.vec.Vec.len rows).val ≤ length ∧ before (0#usize : Usize).val ∧
      after (alloc.vec.Vec.len rows).val
    have zero : (0#usize : Usize).val = 0 := rfl
    exact ⟨by omega, by omega, fun _ _ h => by omega, fun _ _ h => by omega⟩

end KvRust
