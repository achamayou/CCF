-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs

import all Aeneas.Data.List.List

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- Ring-buffer physical index for logical offset `offset` starting at `head`. -/
def branchSlot (capacity head offset : Nat) : Nat :=
  if offset < capacity - head then head + offset else offset - (capacity - head)

private theorem branch_slot_bound {capacity head offset : Nat}
    (hHead : head < capacity) (hOff : offset ≤ capacity)
    : branchSlot capacity head offset < capacity := by
  unfold branchSlot
  split <;> omega

private theorem branch_slot_lt {capacity head offset : Nat}
    (hHead : head < capacity) (hOff : offset < capacity)
    : branchSlot capacity head offset < capacity :=
  branch_slot_bound hHead (Nat.le_of_lt hOff)

private theorem branch_slot_inj {capacity head i j : Nat}
    (hHead : head < capacity) (hi : i < capacity) (hj : j < capacity)
    (heq : branchSlot capacity head i = branchSlot capacity head j)
    : i = j := by
  unfold branchSlot at heq
  split at heq <;> split at heq <;> omega

private theorem branch_slot_shift {capacity head offset : Nat}
    (hHead : head < capacity) (hOff : offset + 1 < capacity)
    : branchSlot capacity (branchSlot capacity head 1) offset
      = branchSlot capacity head (offset + 1) := by
  unfold branchSlot
  split <;> split <;> split <;> omega

/-- Valid ring-buffered active branch: non-empty (`1 ≤ len ≤ cap`), `head < cap`,
and every logical offset `0 ≤ i < len` holds `some v`. -/
structure BranchValid {T : Type} (log : CcfKv.branch_log.BranchLog T) : Prop where
  nonempty : 0 < log.len.val
  lenLeCap : log.len.val ≤ log.slots.val.length
  headLt : log.head.val < log.slots.val.length
  live
    : ∀ i,
        i < log.len.val
        → ∃ v,
            log.slots.val[branchSlot log.slots.val.length log.head.val i]? = some (some v)

/-- Logical sequence of active elements `0..log.len` oldest-first. -/
def branchValues {T : Type} (log : CcfKv.branch_log.BranchLog T) : List T :=
  (List.range log.len.val).filterMap
    fun i =>
      (log.slots.val[branchSlot log.slots.val.length log.head.val i]?).join

private theorem branch_values_of_range {T : Type} (slots : List (Option T))
    (head n : Nat)
    (hlive : ∀ i, i < n → ∃ v, slots[branchSlot slots.length head i]? = some (some v))
    : ((List.range n).filterMap
          fun i => (slots[branchSlot slots.length head i]?).join).length
        = n
      ∧ ∀ k,
          k < n
          → ((List.range n).filterMap
              fun i => (slots[branchSlot slots.length head i]?).join)[k]?
            = (slots[branchSlot slots.length head k]?).join := by
  induction n with
  | zero => simp
  | succ m ih =>
      have hprev := ih (fun i hi => hlive i (Nat.lt_succ_of_lt hi))
      obtain ⟨v, hv⟩ := hlive m (Nat.lt_succ_self m)
      have hjoin : (slots[branchSlot slots.length head m]?).join = some v := by
        simp [hv]
      have hstep :
          ((List.range (m + 1)).filterMap fun i => (slots[branchSlot slots.length head i]?).join) =
          ((List.range m).filterMap fun i => (slots[branchSlot slots.length head i]?).join) ++ [v] := by
        rw [List.range_succ, List.filterMap_append, List.filterMap_cons, List.filterMap_nil, hjoin]
      rw [hstep]
      refine ⟨by rw [List.length_append, hprev.1]; rfl, ?_⟩
      intro k hk
      by_cases hlt : k < m
      · rw [List.getElem?_append_left (hprev.1.symm ▸ hlt)]
        exact hprev.2 k hlt
      · have hkm : k = m := by omega
        subst hkm
        rw [List.getElem?_append_right (by rw [hprev.1]), hprev.1, Nat.sub_self, hjoin]
        rfl

theorem branch_values_length {T : Type} (log : CcfKv.branch_log.BranchLog T)
    (valid : BranchValid log)
    : (branchValues log).length = log.len.val :=
  (branch_values_of_range log.slots.val log.head.val log.len.val valid.live).1

theorem branch_values_getElem? {T : Type} (log : CcfKv.branch_log.BranchLog T)
    (valid : BranchValid log) {k : Nat} (hk : k < log.len.val)
    : (branchValues log)[k]?
      = (log.slots.val[branchSlot log.slots.val.length log.head.val k]?).join :=
  (branch_values_of_range log.slots.val log.head.val log.len.val valid.live).2 k hk

private theorem usize_le_max (x : Usize) : x.val ≤ Usize.max := by
  scalar_tac

theorem branch_values_capacity {T : Type} (log : CcfKv.branch_log.BranchLog T)
    : (branchValues log).length ≤ Usize.max :=
  (List.length_filterMap_le _ _).trans
    (by rw [List.length_range]; exact usize_le_max log.len)

theorem branch_active_len {T : Type} (log : CcfKv.branch_log.BranchLog T)
    (valid : BranchValid log)
    : WP.spec (CcfKv.branch_log.BranchLog.active_len log)
        (fun n => n.val = (branchValues log).length) := by
  simp [CcfKv.branch_log.BranchLog.active_len, branch_values_length log valid]

private theorem branch_slot_matches {T : Type} (log : CcfKv.branch_log.BranchLog T)
    (offset : Usize) (hHead : log.head.val ≤ log.slots.val.length)
    : WP.spec (CcfKv.branch_log.BranchLog.slot log offset)
        (fun i => i.val = branchSlot log.slots.val.length log.head.val offset.val) := by
  unfold CcfKv.branch_log.BranchLog.slot
  have length : (alloc.vec.Vec.len log.slots).val = log.slots.val.length :=
    alloc.vec.Vec.len_val log.slots
  have space := alloc.vec.Vec.len_ineq log.slots
  apply WP.spec_bind
    (Usize.sub_spec (x := alloc.vec.Vec.len log.slots) (y := log.head) (by omega))
  intro suffix sub
  by_cases run : offset < suffix
  · have below : offset.val < suffix.val := run
    rw [ite_eq_left run]
    apply WP.spec_mono (Usize.add_spec (x := log.head) (y := offset) (by omega))
    intro i hi
    have right : offset.val < log.slots.val.length - log.head.val := by omega
    simpa [branchSlot, right] using hi
  · have beyond : suffix.val ≤ offset.val := Nat.le_of_not_gt run
    rw [ite_eq_right run]
    apply WP.spec_mono (Usize.sub_spec (x := offset) (y := suffix) beyond)
    intro i hi
    have right : ¬ offset.val < log.slots.val.length - log.head.val := by omega
    have eq : suffix.val = log.slots.val.length - log.head.val := by omega
    simpa [branchSlot, right, eq] using hi.1

theorem branch_new_refines {T : Type} (base : T)
    : WP.spec (CcfKv.branch_log.BranchLog.new base)
        (fun log =>
          BranchValid log ∧ branchValues log = [base] ∧ log.slots.val.length = 1) := by
  have room : 0 < Usize.max := by scalar_tac
  unfold CcfKv.branch_log.BranchLog.new
  apply WP.spec_bind
    (alloc.vec.Vec.push_spec (alloc.vec.Vec.new (Option T)) (some base) room)
  intro slots hs
  rw [WP.spec_ok]
  have hlen : slots.val.length = 1 := by simp [hs]
  have h0 : slots.val = [some base] := by simpa using hs
  refine ⟨
    ⟨
      by change 0 < (1#usize : Usize).val; decide,
      by change (1#usize : Usize).val ≤ slots.val.length; rw [hlen]; decide,
      by change (0#usize : Usize).val < slots.val.length; rw [hlen]; decide,
      ?_
    ⟩,
    ?_,
    hlen
  ⟩
  · intro i hi
    have hi0 : i = 0 := by
      change i < (1#usize : Usize).val at hi
      have h1 : (1#usize : Usize).val = 1 := rfl
      omega
    subst hi0
    refine ⟨base, ?_⟩
    rw [h0]
    rfl
  · unfold branchValues
    rw [h0]
    rfl

theorem branch_active_at {T : Type} (log : CcfKv.branch_log.BranchLog T)
    (valid : BranchValid log) (i : Usize) (frame : T)
    (saved : (branchValues log)[i.val]? = some frame)
    : WP.spec (CcfKv.branch_log.BranchLog.active_at log i) (· = frame) := by
  have hi : i.val < log.len.val := by
    have := (List.getElem?_eq_some_iff.mp saved).1
    rwa [branch_values_length log valid] at this
  have hslotLt : branchSlot log.slots.val.length log.head.val i.val < log.slots.val.length :=
    branch_slot_lt valid.headLt (lt_of_lt_of_le hi valid.lenLeCap)
  have hget := branch_values_getElem? log valid hi
  rw [saved] at hget
  unfold CcfKv.branch_log.BranchLog.active_at
  apply WP.spec_bind (branch_slot_matches log i (Nat.le_of_lt valid.headLt))
  intro idx hidx
  have hidxLt : idx.val < log.slots.val.length := by rw [hidx]; exact hslotLt
  rw [alloc.vec.Vec.index_slice_index]
  apply WP.spec_bind (alloc.vec.Vec.index_usize_spec log.slots idx hidxLt)
  intro opt hopt
  have hoptAt : log.slots.val[branchSlot log.slots.val.length log.head.val i.val]? = some opt := by
    rw [← hidx, List.getElem?_eq_getElem hidxLt, hopt]
  rw [hoptAt] at hget
  cases opt with
  | none => simp at hget
  | some got =>
      simp only [Option.join_some, Option.some.injEq] at hget
      rw [WP.spec_ok, hget]

theorem branch_cut_refines {T : Type} (log : CcfKv.branch_log.BranchLog T)
    (valid : BranchValid log) (offset : U64)
    : WP.spec (CcfKv.branch_log.BranchLog.at_cut log offset)
        (fun idx =>
          idx.val = min offset.val (log.len.val - 1)) := by
  let last := log.len.val - 1
  have pos : 0 < log.len.val := valid.nonempty
  have cap : log.len.val ≤ Usize.max := usize_le_max log.len
  have one : (1#usize : Usize).val = 1 := rfl
  unfold CcfKv.branch_log.BranchLog.at_cut
  apply WP.spec_bind (Usize.sub_spec (x := log.len) (y := 1#usize) (by omega))
  intro head hp
  have headVal : head.val = last := by dsimp [last]; omega
  let head64 := UScalar.cast .U64 head
  have castHead : head64.val = last := by
    rw [show head64.val = head.val from UScalar.cast_val_mod_pow_greater_numBits_eq .U64 head
      (by
        simp only [UScalarTy.Usize_numBits_eq, UScalarTy.U64_numBits_eq]
        rcases System.Platform.numBits_eq with h | h <;> simp [h]), headVal]
  simp only [lift, bind_ok]
  by_cases earlier : offset < head64
  · have hlt : offset.val < last := by change offset.val < head64.val at earlier; omega
    rw [ite_eq_left earlier, WP.spec_ok, Nat.min_eq_left hlt.le]
    apply UScalar.cast_val_mod_pow_of_inBounds_eq
    have hbd : offset.val ≤ Usize.max := by dsimp [last] at hlt; omega
    rw [← UScalar.max_USize_eq, UScalar.max] at hbd
    have := Nat.two_pow_pos UScalarTy.Usize.numBits
    omega
  · have hle : last ≤ offset.val := by change ¬ offset.val < head64.val at earlier; omega
    rw [ite_eq_right earlier, WP.spec_ok, Nat.min_eq_right hle, headVal]

private theorem branch_reallocate_loop0 {T : Type}
    (log : CcfKv.branch_log.BranchLog T) (valid : BranchValid log)
    (capacity : Usize)
    : WP.spec
        (CcfKv.branch_log.BranchLog.reallocate_loop0 log
          (alloc.vec.Vec.with_capacity (Option T) capacity) 0#usize)
        (fun (lenOut, next) =>
          lenOut = log.len
          ∧ next.val.length = log.len.val
          ∧ ∀ k,
              k < log.len.val
              → next.val[k]?
                = log.slots.val[branchSlot log.slots.val.length log.head.val k]?) := by
  unfold CcfKv.branch_log.BranchLog.reallocate_loop0
  apply loop.spec_decr_nat
    (fun s : CcfKv.branch_log.BranchLog T × alloc.vec.Vec (Option T) × Usize =>
      log.len.val - s.2.2.val)
    (fun s =>
      s.1.head = log.head
      ∧ s.1.len = log.len
      ∧ s.2.2.val ≤ log.len.val
      ∧ s.1.slots.val.length = log.slots.val.length
      ∧ s.2.1.val.length = s.2.2.val
      ∧ (∀ k,
          s.2.2.val ≤ k
          → k < log.len.val
          → s.1.slots.val[branchSlot log.slots.val.length log.head.val k]?
            = log.slots.val[branchSlot log.slots.val.length log.head.val k]?)
      ∧ (∀ k,
          k < s.2.2.val
          → s.2.1.val[k]?
            = log.slots.val[branchSlot log.slots.val.length log.head.val k]?)) _ _ _
  · rintro ⟨cur, next, i⟩ ⟨hheadEq, hlenEq, hiLe, hvLen, hnextLen, hrem, hcopied⟩
    dsimp only at hheadEq hlenEq hiLe hvLen hnextLen hrem hcopied
    unfold CcfKv.branch_log.BranchLog.reallocate_loop0.body
    dsimp only
    rw [hlenEq]
    by_cases hlt : i < log.len
    · have hi : i.val < log.len.val := hlt
      rw [ite_eq_left hlt]
      have hcapLog : log.len.val ≤ Usize.max := usize_le_max log.len
      have hiCap : i.val < log.slots.val.length := lt_of_lt_of_le hi valid.lenLeCap
      apply WP.spec_bind
        (branch_slot_matches cur i (by rw [hheadEq, hvLen]; exact Nat.le_of_lt valid.headLt))
      intro idx hidx
      rw [hheadEq, hvLen] at hidx
      have hidxLt : idx.val < cur.slots.val.length := by
        rw [hvLen, hidx]; exact branch_slot_lt valid.headLt hiCap
      rw [alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec cur.slots idx hidxLt)
      rintro ⟨o, back⟩ ⟨ho, hback⟩
      have hoEq : o = cur.slots.val[idx.val] := ho
      have hpushRoom : next.val.length < Usize.max := by
        have := usize_le_max capacity; omega
      simp only [core.option.Option.take]
      apply WP.spec_bind (alloc.vec.Vec.push_spec next o hpushRoom)
      intro next1 hnext1
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro i1 hi1
      have hi1Val : i1.val = i.val + 1 := by rw [hi1, hone]
      rw [WP.spec_ok]
      dsimp only
      have hv1Val : (back none).val = cur.slots.val.set idx.val none := by
        rw [hback]; exact alloc.vec.Vec.set_val_eq _ _ _
      refine ⟨⟨hheadEq, rfl, by omega, by rw [hv1Val, List.length_set, hvLen],
        by rw [hnext1, List.length_append, List.length_singleton, hnextLen]; omega, ?_, ?_⟩,
        by omega⟩
      · intro k hkGe hkLt
        have hne : branchSlot log.slots.val.length log.head.val k ≠ idx.val := by
          rw [hidx]
          intro heq
          have := branch_slot_inj valid.headLt (lt_of_lt_of_le hkLt valid.lenLeCap) hiCap heq
          omega
        rw [hv1Val, List.getElem?_set_ne (Ne.symm hne)]
        exact hrem k (by omega) hkLt
      · intro k hkLt
        rw [hnext1]
        by_cases hkOld : k < i.val
        · rw [List.getElem?_append_left (by omega)]
          exact hcopied k hkOld
        · have hki : k = i.val := by omega
          subst hki
          rw [List.getElem?_append_right (by omega), hnextLen, Nat.sub_self]
          simp only [List.getElem?_cons_zero]
          have hvi : cur.slots.val[idx.val]? = some o := by
            rw [List.getElem?_eq_getElem hidxLt, ← hoEq]
          have := hrem i.val (Nat.le_refl _) hi
          rw [← hidx, hvi] at this
          rwa [hidx] at this
    · have hiEq : i.val = log.len.val := by
        have := Nat.le_of_not_gt hlt; omega
      rw [ite_eq_right hlt, WP.spec_ok]
      dsimp only
      exact ⟨rfl, by omega, fun k hk => hcopied k (by omega)⟩
  · refine ⟨rfl, rfl, Nat.zero_le _, rfl, by simp [alloc.vec.Vec.with_capacity], fun _ _ _ => rfl,
      fun k hk => by
        change k < (0#usize : Usize).val at hk
        have h0 : (0#usize : Usize).val = 0 := rfl
        omega⟩

private theorem branch_reallocate_loop1 {T : Type} (capacity : Usize)
    (init : alloc.vec.Vec (Option T)) (hle : init.val.length ≤ capacity.val)
    : WP.spec (CcfKv.branch_log.BranchLog.reallocate_loop1 capacity init)
        (fun out =>
          out.val.length = capacity.val
          ∧ ∀ k, k < init.val.length → out.val[k]? = init.val[k]?) := by
  unfold CcfKv.branch_log.BranchLog.reallocate_loop1
  apply loop.spec_decr_nat
    (fun v : alloc.vec.Vec (Option T) => capacity.val - v.val.length)
    (fun v =>
      init.val.length ≤ v.val.length
      ∧ v.val.length ≤ capacity.val
      ∧ ∀ k, k < init.val.length → v.val[k]? = init.val[k]?) _ _ _
  · intro v ⟨hge, hleV, hkeep⟩
    unfold CcfKv.branch_log.BranchLog.reallocate_loop1.body
    dsimp only
    have hvLen : (alloc.vec.Vec.len v).val = v.val.length := alloc.vec.Vec.len_val _
    by_cases hlt : alloc.vec.Vec.len v < capacity
    · have hlt' : v.val.length < capacity.val := by rwa [← hvLen]
      rw [ite_eq_left hlt]
      have hcapBound : capacity.val ≤ Usize.max := usize_le_max capacity
      apply WP.spec_bind (alloc.vec.Vec.push_spec v none (by omega))
      intro v1 hv1
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨by rw [hv1, List.length_append, List.length_singleton]; omega,
        by rw [hv1, List.length_append, List.length_singleton]; omega, ?_⟩,
        by rw [hv1, List.length_append, List.length_singleton]; omega⟩
      intro k hk
      rw [hv1, List.getElem?_append_left (by omega)]
      exact hkeep k hk
    · have heq : v.val.length = capacity.val := by
        have : ¬ v.val.length < capacity.val := by rwa [← hvLen]
        omega
      rw [ite_eq_right hlt, WP.spec_ok]
      exact ⟨heq, hkeep⟩
  · exact ⟨Nat.le_refl _, hle, fun _ _ => rfl⟩

private theorem branch_reallocate_refines {T : Type} (log : CcfKv.branch_log.BranchLog T)
    (valid : BranchValid log) (capacity : Usize) (hcap : log.len.val ≤ capacity.val)
    : WP.spec (CcfKv.branch_log.BranchLog.reallocate log capacity)
        (fun after =>
          BranchValid after
          ∧ branchValues after = branchValues log
          ∧ after.slots.val.length = capacity.val
          ∧ after.len = log.len) := by
  unfold CcfKv.branch_log.BranchLog.reallocate
  apply WP.spec_bind (branch_reallocate_loop0 log valid capacity)
  rintro ⟨lenOut, next1⟩ ⟨hlenOut, h1Len, h1At⟩
  subst hlenOut
  apply WP.spec_bind (branch_reallocate_loop1 capacity next1 (by omega))
  intro next2 ⟨h2Len, h2At⟩
  rw [WP.spec_ok]
  have hslotEq : ∀ k, k < log.len.val →
      next2.val[branchSlot next2.val.length (0#usize).val k]?
        = log.slots.val[branchSlot log.slots.val.length log.head.val k]? := by
    intro k hk
    have h0 : (0#usize).val = 0 := rfl
    have hslot0 : branchSlot next2.val.length 0 k = k := by
      unfold branchSlot; rw [Nat.sub_zero, ite_eq_left (by omega), Nat.zero_add]
    rw [h0, hslot0, h2At k (by omega), h1At k hk]
  have hvalidAfter : BranchValid { slots := next2, head := 0#usize, len := log.len } := by
    refine ⟨valid.nonempty, by rw [h2Len]; exact hcap, by change 0 < next2.val.length; have := valid.nonempty; omega, ?_⟩
    intro i hi
    change ∃ v, next2.val[branchSlot next2.val.length (0#usize).val i]? = some (some v)
    rw [hslotEq i hi]
    exact valid.live i hi
  refine ⟨hvalidAfter, ?_, h2Len, rfl⟩
  unfold branchValues
  dsimp only
  apply List.filterMap_congr
  intro k hk
  have hkLt : k < log.len.val := List.mem_range.mp hk
  rw [hslotEq k hkLt]

theorem branch_grow_refines {T : Type} (log : CcfKv.branch_log.BranchLog T)
    (valid : BranchValid log) (room : 2 * log.slots.val.length + 1 ≤ Usize.max)
    : WP.spec (CcfKv.branch_log.BranchLog.grow log)
        (fun after =>
          BranchValid after
          ∧ branchValues after = branchValues log
          ∧ after.len.val < after.slots.val.length
          ∧ after.len = log.len) := by
  unfold CcfKv.branch_log.BranchLog.grow
  have hlen : (alloc.vec.Vec.len log.slots).val = log.slots.val.length := alloc.vec.Vec.len_val _
  have htwo : (2#usize : Usize).val = 2 := rfl
  have hone : (1#usize : Usize).val = 1 := rfl
  apply WP.spec_bind
    (Usize.mul_spec (x := 2#usize) (y := alloc.vec.Vec.len log.slots)
      (by rw [htwo, hlen]; omega))
  intro i1 hi1
  have hi1Val : i1.val = 2 * log.slots.val.length := by rw [hi1, htwo, hlen]
  apply WP.spec_bind (Usize.add_spec (x := i1) (y := 1#usize) (by omega))
  intro cap hcap
  have hcapVal : cap.val = 2 * log.slots.val.length + 1 := by rw [hcap, hi1Val, hone]
  apply WP.spec_mono
    (branch_reallocate_refines log valid cap (by have := valid.lenLeCap; omega))
  intro after ⟨hv, hvals, hslots, hlenEq⟩
  exact ⟨
    hv,
    hvals,
    by rw [hlenEq, hslots, hcapVal]; have := valid.lenLeCap; omega,
    hlenEq
  ⟩

theorem branch_shrink_refines {T : Type} (log : CcfKv.branch_log.BranchLog T)
    (valid : BranchValid log)
    : WP.spec (CcfKv.branch_log.BranchLog.shrink_if_sparse log)
        (fun after =>
          BranchValid after
          ∧ branchValues after = branchValues log
          ∧ after.len = log.len) := by
  unfold CcfKv.branch_log.BranchLog.shrink_if_sparse
  have hlen : (alloc.vec.Vec.len log.slots).val = log.slots.val.length := alloc.vec.Vec.len_val _
  have hcapBound := alloc.vec.Vec.len_ineq log.slots
  by_cases hsmall : alloc.vec.Vec.len log.slots ≤ 64#usize
  · rw [ite_eq_left hsmall, WP.spec_ok]
    exact ⟨valid, rfl, rfl⟩
  · rw [ite_eq_right hsmall]
    have hgt64 : 64 < log.slots.val.length := by
      have : ¬ log.slots.val.length ≤ 64 := by
        change ¬ (alloc.vec.Vec.len log.slots).val ≤ (64#usize : Usize).val at hsmall
        have h64 : (64#usize : Usize).val = 64 := rfl
        omega
      omega
    apply WP.spec_bind (Usize.div_spec (x := alloc.vec.Vec.len log.slots) (y := 4#usize) (by decide))
    intro quarter hq
    have hqVal : quarter.val = log.slots.val.length / 4 := by
      rw [hq, hlen]; rfl
    by_cases hdense : log.len ≥ quarter
    · rw [ite_eq_left hdense, WP.spec_ok]
      exact ⟨valid, rfl, rfl⟩
    · rw [ite_eq_right hdense]
      have hsparse : log.len.val < log.slots.val.length / 4 := by
        have : ¬ log.len.val ≥ quarter.val := hdense
        omega
      have htwo : (2#usize : Usize).val = 2 := rfl
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.mul_spec (x := 2#usize) (y := log.len) (by rw [htwo]; omega))
      intro i3 hi3
      have hi3Val : i3.val = 2 * log.len.val := by rw [hi3, htwo]
      apply WP.spec_bind (Usize.add_spec (x := i3) (y := 1#usize) (by omega))
      intro cap hcap
      have hcapVal : cap.val = 2 * log.len.val + 1 := by rw [hcap, hi3Val, hone]
      apply WP.spec_mono (branch_reallocate_refines log valid cap (by omega))
      intro after ⟨hv, hvals, _, hlenEq⟩
      exact ⟨hv, hvals, hlenEq⟩

theorem branch_append_refines {T : Type} (log : CcfKv.branch_log.BranchLog T) (frame : T)
    (valid : BranchValid log)
    (room : log.len.val = log.slots.val.length → 2 * log.slots.val.length + 1 ≤ Usize.max)
    : WP.spec (CcfKv.branch_log.BranchLog.append log frame)
        (fun after =>
          BranchValid after ∧ branchValues after = branchValues log ++ [frame]) := by
  unfold CcfKv.branch_log.BranchLog.append
  have hlen : (alloc.vec.Vec.len log.slots).val = log.slots.val.length := alloc.vec.Vec.len_val _
  have hprep : WP.spec
      (if log.len = alloc.vec.Vec.len log.slots then CcfKv.branch_log.BranchLog.grow log else Result.ok log)
      (fun s1 =>
        BranchValid s1
        ∧ branchValues s1 = branchValues log
        ∧ s1.len.val < s1.slots.val.length) := by
    by_cases hfull : log.len = alloc.vec.Vec.len log.slots
    · rw [ite_eq_left hfull]
      have hEq : log.len.val = log.slots.val.length := by
        rw [← hlen]; exact congrArg UScalar.val hfull
      apply WP.spec_mono (branch_grow_refines log valid (room hEq))
      intro s1 ⟨hv, hvals, hlt, _⟩
      exact ⟨hv, hvals, hlt⟩
    · rw [ite_eq_right hfull, WP.spec_ok]
      have hne : log.len.val ≠ log.slots.val.length := by
        intro heq
        exact hfull (UScalar.eq_of_val_eq (by omega))
      exact ⟨valid, rfl, Nat.lt_of_le_of_ne valid.lenLeCap hne⟩
  apply WP.spec_bind hprep
  intro s1 ⟨hv1, hvals1, hlt1⟩
  have hcap1 := alloc.vec.Vec.len_ineq s1.slots
  apply WP.spec_bind (branch_slot_matches s1 s1.len (Nat.le_of_lt hv1.headLt))
  intro idx hidx
  have hidxLt : idx.val < s1.slots.val.length := by
    rw [hidx]; exact branch_slot_lt hv1.headLt hlt1
  rw [alloc.vec.Vec.index_mut_slice_index]
  apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec s1.slots idx hidxLt)
  rintro ⟨_, back⟩ ⟨_, hback⟩
  have hone : (1#usize : Usize).val = 1 := rfl
  apply WP.spec_bind (Usize.add_spec (x := s1.len) (y := 1#usize) (by omega))
  intro i1 hi1
  rw [WP.spec_ok]
  have hvVal : (back (some frame)).val = s1.slots.val.set idx.val (some frame) := by
    rw [hback]; exact alloc.vec.Vec.set_val_eq _ _ _
  have hvLen : (back (some frame)).val.length = s1.slots.val.length := by
    rw [hvVal, List.length_set]
  have hi1Val : i1.val = s1.len.val + 1 := by rw [hi1, hone]
  have hvalidAfter : BranchValid { s1 with slots := back (some frame), len := i1 } := by
    refine ⟨by change 0 < i1.val; omega, by change i1.val ≤ (back (some frame)).val.length; rw [hvLen]; omega,
      by change s1.head.val < (back (some frame)).val.length; rw [hvLen]; exact hv1.headLt, ?_⟩
    intro k hk
    change k < i1.val at hk
    change ∃ v, (back (some frame)).val[branchSlot (back (some frame)).val.length s1.head.val k]?
      = some (some v)
    rw [hvLen]
    by_cases hlt : k < s1.len.val
    · have hne : branchSlot s1.slots.val.length s1.head.val k ≠ idx.val := by
        rw [hidx]
        intro heq
        have := branch_slot_inj hv1.headLt (lt_trans hlt hlt1) hlt1 heq
        omega
      rw [hvVal, List.getElem?_set_ne (Ne.symm hne)]
      exact hv1.live k hlt
    · have hkeq : k = s1.len.val := by omega
      subst hkeq
      rw [← hidx, hvVal, List.getElem?_set_self hidxLt]
      exact ⟨frame, rfl⟩
  refine ⟨hvalidAfter, ?_⟩
  rw [← hvals1]
  unfold branchValues
  dsimp only
  rw [hi1Val, List.range_succ, List.filterMap_append, List.filterMap_cons, List.filterMap_nil, hvLen]
  congr 1
  · apply List.filterMap_congr
    intro k hk
    have hkLt : k < s1.len.val := List.mem_range.mp hk
    have hne : branchSlot s1.slots.val.length s1.head.val k ≠ idx.val := by
      rw [hidx]
      intro heq
      have := branch_slot_inj hv1.headLt (lt_trans hkLt hlt1) hlt1 heq
      omega
    rw [hvVal, List.getElem?_set_ne (Ne.symm hne)]
  · rw [← hidx, hvVal, List.getElem?_set_self hidxLt]
    rfl

theorem branch_pop_front_refines {T : Type} (log : CcfKv.branch_log.BranchLog T)
    (valid : BranchValid log) (hge : 2 ≤ log.len.val)
    : WP.spec (CcfKv.branch_log.BranchLog.pop_front log)
        (fun (frame, after) =>
          BranchValid after
          ∧ branchValues log = frame :: branchValues after
          ∧ after.len.val + 1 = log.len.val) := by
  have hheadLt : log.head.val < log.slots.val.length := valid.headLt
  have hslot0 : branchSlot log.slots.val.length log.head.val 0 = log.head.val := by
    unfold branchSlot; rw [ite_eq_left (by omega), Nat.add_zero]
  obtain ⟨hd, hhd⟩ := valid.live 0 (by omega)
  rw [hslot0] at hhd
  unfold CcfKv.branch_log.BranchLog.pop_front
  rw [alloc.vec.Vec.index_mut_slice_index]
  apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec log.slots log.head hheadLt)
  rintro ⟨o, back⟩ ⟨ho, hback⟩
  have hoEq : o = some hd := by
    have h1 : log.slots.val[log.head.val]? = some o := by
      rw [List.getElem?_eq_getElem hheadLt, ← ho]
    exact Option.some.inj (h1.symm.trans hhd)
  simp only [hoEq, core.option.Option.take]
  have hvVal : (back none).val = log.slots.val.set log.head.val none := by
    rw [hback]; exact alloc.vec.Vec.set_val_eq _ _ _
  have hvLen : (back none).val.length = log.slots.val.length := by
    rw [hvVal, List.length_set]
  apply WP.spec_bind
    (branch_slot_matches { log with slots := back none } 1#usize
      (by rw [hvLen]; exact Nat.le_of_lt hheadLt))
  intro newHead hnewHead
  rw [hvLen] at hnewHead
  have hone : (1#usize : Usize).val = 1 := rfl
  apply WP.spec_bind (Usize.sub_spec (x := log.len) (y := 1#usize) (by omega))
  intro newLen hnewLen
  have hnewLenVal : newLen.val = log.len.val - 1 := by rw [hnewLen.1, hone]
  rw [WP.spec_ok]
  have hnewHeadLt : newHead.val < log.slots.val.length := by
    rw [hnewHead]; exact branch_slot_bound hheadLt (by have := valid.lenLeCap; omega)
  have hshiftSlot : ∀ k, k < newLen.val →
      (back none).val[branchSlot (back none).val.length newHead.val k]?
        = log.slots.val[branchSlot log.slots.val.length log.head.val (k + 1)]? := by
    intro k hk
    rw [hvLen, hnewHead, hone]
    have hkp1 : k + 1 < log.slots.val.length := by have := valid.lenLeCap; omega
    change (back none).val[branchSlot log.slots.val.length (branchSlot log.slots.val.length log.head.val 1) k]? = _
    rw [branch_slot_shift hheadLt hkp1]
    have hne : branchSlot log.slots.val.length log.head.val (k + 1) ≠ log.head.val := by
      intro heq
      have h0 : branchSlot log.slots.val.length log.head.val (k + 1)
          = branchSlot log.slots.val.length log.head.val 0 := heq.trans hslot0.symm
      have := branch_slot_inj hheadLt hkp1 (by omega) h0
      omega
    rw [hvVal, List.getElem?_set_ne (Ne.symm hne)]
  have hvalidAfter : BranchValid { slots := back none, head := newHead, len := newLen } := by
    refine ⟨by change 0 < newLen.val; omega,
      by change newLen.val ≤ (back none).val.length; rw [hvLen]; have := valid.lenLeCap; omega,
      by change newHead.val < (back none).val.length; rw [hvLen]; exact hnewHeadLt, ?_⟩
    intro k hk
    change k < newLen.val at hk
    change ∃ v, (back none).val[branchSlot (back none).val.length newHead.val k]? = some (some v)
    rw [hshiftSlot k hk]
    exact valid.live (k + 1) (by omega)
  refine ⟨hvalidAfter, ?_, by change newLen.val + 1 = log.len.val; omega⟩
  unfold branchValues
  dsimp only
  have hlenEq : log.len.val = newLen.val + 1 := by omega
  rw [hlenEq, List.range_succ_eq_map, List.filterMap_cons, hslot0, hhd, Option.join_some,
    List.filterMap_map]
  refine congrArg (hd :: ·) ?_
  apply List.filterMap_congr
  intro k hk
  have hkLt : k < newLen.val := List.mem_range.mp hk
  change (log.slots.val[branchSlot log.slots.val.length log.head.val (k + 1)]?).join =
    ((back none).val[branchSlot (back none).val.length newHead.val k]?).join
  rw [hshiftSlot k hkLt]

theorem branch_pop_back_refines {T : Type} (log : CcfKv.branch_log.BranchLog T)
    (valid : BranchValid log) (hge : 2 ≤ log.len.val)
    : WP.spec (CcfKv.branch_log.BranchLog.pop_back log)
        (fun (frame, after) =>
          BranchValid after
          ∧ branchValues log = branchValues after ++ [frame]
          ∧ after.len.val + 1 = log.len.val) := by
  have hone : (1#usize : Usize).val = 1 := rfl
  unfold CcfKv.branch_log.BranchLog.pop_back
  apply WP.spec_bind (Usize.sub_spec (x := log.len) (y := 1#usize) (by omega))
  intro lastIdx hlastIdx
  have hlastValEq : lastIdx.val = log.len.val - 1 := by rw [hlastIdx.1, hone]
  have hlastLt : lastIdx.val < log.len.val := by omega
  have hlastCap : lastIdx.val < log.slots.val.length := lt_of_lt_of_le hlastLt valid.lenLeCap
  apply WP.spec_bind (branch_slot_matches log lastIdx (Nat.le_of_lt valid.headLt))
  intro idx hidx
  have hidxLt : idx.val < log.slots.val.length := by
    rw [hidx]; exact branch_slot_lt valid.headLt hlastCap
  obtain ⟨lastVal, hlastVal⟩ := valid.live lastIdx.val hlastLt
  rw [alloc.vec.Vec.index_mut_slice_index]
  apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec log.slots idx hidxLt)
  rintro ⟨o, back⟩ ⟨ho, hback⟩
  have hoEq : o = some lastVal := by
    have h1 : log.slots.val[idx.val]? = some o := by
      rw [List.getElem?_eq_getElem hidxLt, ← ho]
    rw [hidx] at h1
    exact Option.some.inj (h1.symm.trans hlastVal)
  simp only [hoEq, core.option.Option.take]
  change WP.spec (Result.ok (lastVal, { log with slots := back none, len := lastIdx })) _
  rw [WP.spec_ok]
  have hvVal : (back none).val = log.slots.val.set idx.val none := by
    rw [hback]; exact alloc.vec.Vec.set_val_eq _ _ _
  have hvLen : (back none).val.length = log.slots.val.length := by
    rw [hvVal, List.length_set]
  have hkeepSlot : ∀ k, k < lastIdx.val →
      (back none).val[branchSlot (back none).val.length log.head.val k]?
        = log.slots.val[branchSlot log.slots.val.length log.head.val k]? := by
    intro k hk
    rw [hvLen]
    have hne : branchSlot log.slots.val.length log.head.val k ≠ idx.val := by
      rw [hidx]
      intro heq
      have := branch_slot_inj valid.headLt (lt_trans hk hlastCap) hlastCap heq
      omega
    rw [hvVal, List.getElem?_set_ne (Ne.symm hne)]
  have hvalidAfter : BranchValid { log with slots := back none, len := lastIdx } := by
    refine ⟨by change 0 < lastIdx.val; omega,
      by change lastIdx.val ≤ (back none).val.length; rw [hvLen]; have := valid.lenLeCap; omega,
      by change log.head.val < (back none).val.length; rw [hvLen]; exact valid.headLt, ?_⟩
    intro k hk
    change k < lastIdx.val at hk
    change ∃ v, (back none).val[branchSlot (back none).val.length log.head.val k]? = some (some v)
    rw [hkeepSlot k hk]
    exact valid.live k (by omega)
  refine ⟨hvalidAfter, ?_, by change lastIdx.val + 1 = log.len.val; omega⟩
  unfold branchValues
  dsimp only
  have hlenEq : log.len.val = lastIdx.val + 1 := by omega
  rw [hlenEq, List.range_succ, List.filterMap_append, List.filterMap_cons, List.filterMap_nil,
    hlastVal, Option.join_some]
  congr 1
  apply List.filterMap_congr
  intro k hk
  have hkLt : k < lastIdx.val := List.mem_range.mp hk
  change (log.slots.val[branchSlot log.slots.val.length log.head.val k]?).join =
    ((back none).val[branchSlot (back none).val.length log.head.val k]?).join
  rw [hkeepSlot k hkLt]

end KvRust
