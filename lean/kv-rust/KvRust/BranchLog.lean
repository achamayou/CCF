-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs

import all Aeneas.Data.List.List

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- Every active offset resolves to a live, immutable frame. -/
def BranchValid {T : Type} (log : Spike.branch_log.BranchLog T) : Prop :=
  log.branch.val ≠ [] ∧ ∀ id ∈ log.branch.val, id.val < log.frames.val.length

/-- No frame ID appears twice on the active branch. -/
def BranchUnique {T : Type} (log : Spike.branch_log.BranchLog T) : Prop :=
  log.branch.val.Nodup

theorem branch_new_unique {T : Type} (log : Spike.branch_log.BranchLog T)
    (h : log.branch.val = [0#usize])
    : BranchUnique log := by
  simp [BranchUnique, h]

theorem branch_append_unique {T : Type} {log after : Spike.branch_log.BranchLog T}
    (valid : BranchValid log) (unique : BranchUnique log)
    {id : Usize} (hid : id.val = log.frames.val.length)
    (hbranch : after.branch.val = log.branch.val ++ [id])
    : BranchUnique after := by
  unfold BranchUnique
  rw [hbranch, List.nodup_append]
  refine ⟨unique, List.nodup_singleton id, ?_⟩
  intro a ha b hb heq
  rw [List.mem_singleton.mp hb] at heq
  have hlt := valid.2 a ha
  rw [heq, hid] at hlt
  exact Nat.lt_irrefl _ hlt

theorem branch_rewind_unique {T : Type} {log after : Spike.branch_log.BranchLog T}
    (unique : BranchUnique log) {n : Nat}
    (hbranch : after.branch.val = log.branch.val.take n)
    : BranchUnique after := by
  unfold BranchUnique
  rw [hbranch]
  exact unique.sublist (List.take_sublist _ _)

def branchValues {T : Type} (log : Spike.branch_log.BranchLog T) : List T :=
  log.branch.val.filterMap fun id => log.frames.val[id.val]?

theorem branch_values_length {T : Type} (log : Spike.branch_log.BranchLog T)
    (valid : BranchValid log)
    : (branchValues log).length = log.branch.val.length := by
  have hl (ids : List Usize) (live : ∀ id ∈ ids, id.val < log.frames.val.length) :
      (ids.filterMap fun id => log.frames.val[id.val]?).length = ids.length := by
    induction ids with
    | nil => rfl
    | cons h t ih =>
        simp [List.getElem?_eq_getElem (live h List.mem_cons_self),
          ih (fun i hm => live i (List.mem_cons_of_mem _ hm))]
  exact hl _ valid.2

theorem branch_values_capacity {T : Type} (log : Spike.branch_log.BranchLog T)
    : (branchValues log).length ≤ Usize.max :=
  (List.length_filterMap_le _ _).trans (alloc.vec.Vec.len_ineq _)

theorem branch_active_len {T : Type} (log : Spike.branch_log.BranchLog T)
    (valid : BranchValid log)
    : WP.spec (Spike.branch_log.BranchLog.active_len log)
        (fun n => n.val = (branchValues log).length) := by
  simp [Spike.branch_log.BranchLog.active_len, branch_values_length log valid]

theorem branch_new_refines {T : Type} (base : T)
    : WP.spec (Spike.branch_log.BranchLog.new base)
        (fun log =>
          BranchValid log
          ∧ branchValues log = [base]
          ∧ log.frames.val = [base]
          ∧ log.branch.val = [0#usize]) := by
  have room : 0 < Usize.max := by scalar_tac
  unfold Spike.branch_log.BranchLog.new
  apply WP.spec_bind (alloc.vec.Vec.push_spec (alloc.vec.Vec.new T) base room)
  intro frames hf
  apply WP.spec_bind (alloc.vec.Vec.push_spec (alloc.vec.Vec.new Usize) 0#usize room)
  intro branch hb
  rw [WP.spec_ok]
  simp [BranchValid, branchValues, hf, hb]

theorem branch_resolve_refines {T : Type} (log : Spike.branch_log.BranchLog T)
    (offset : Usize)
    : WP.spec (Spike.branch_log.BranchLog.resolve log offset)
        (· = log.branch.val[offset.val]?) := by
  unfold Spike.branch_log.BranchLog.resolve
  have len : (alloc.vec.Vec.len log.branch).val = log.branch.val.length := alloc.vec.Vec.len_val _
  by_cases inside : offset < alloc.vec.Vec.len log.branch
  · rw [ite_eq_left inside, alloc.vec.Vec.index_slice_index]
    have bound : offset.val < log.branch.val.length := by rwa [← len]
    apply WP.spec_bind (alloc.vec.Vec.index_usize_spec log.branch offset bound)
    intro id h
    rw [WP.spec_ok, List.getElem?_eq_getElem bound, h]
  · rw [ite_eq_right inside, WP.spec_ok]
    have past : log.branch.val.length ≤ offset.val := by rw [← len]; exact Nat.le_of_not_gt inside
    rw [List.getElem?_eq_none past]

theorem branch_read_refines {T : Type} (log : Spike.branch_log.BranchLog T)
    (id : Spike.branch_log.FrameId) (frame : T)
    (saved : log.frames.val[id.val]? = some frame)
    : WP.spec (Spike.branch_log.BranchLog.read log id) (· = frame) := by
  unfold Spike.branch_log.BranchLog.read
  rw [alloc.vec.Vec.index_slice_index]
  have inside : id.val < log.frames.val.length := by
    by_contra absent
    simp [List.getElem?_eq_none (Nat.le_of_not_gt absent)] at saved
  apply WP.spec_mono (alloc.vec.Vec.index_usize_spec log.frames id inside)
  intro got h
  rw [List.getElem?_eq_getElem inside, ← h, Option.some.injEq] at saved
  exact saved

private theorem indexed_branch_values {T : Type} (frames : List T) (ids : List Usize)
    (live : ∀ id ∈ ids, id.val < frames.length) (offset : Nat)
    : ((ids.filterMap fun id => frames[id.val]?))[offset]?
      = ids[offset]?.bind (fun id => frames[id.val]?) := by
  induction ids generalizing offset with
  | nil => cases offset <;> rfl
  | cons id ids ih =>
      have bound := live id List.mem_cons_self
      cases offset with
      | zero => simp [List.getElem?_eq_getElem bound]
      | succ offset =>
          simp only [List.filterMap_cons, List.getElem?_eq_getElem bound,
            List.getElem?_cons_succ]
          exact ih (fun i hm => live i (List.mem_cons_of_mem _ hm)) offset

theorem branch_active_at {T : Type} (log : Spike.branch_log.BranchLog T)
    (valid : BranchValid log) (i : Usize) (frame : T)
    (saved : (branchValues log)[i.val]? = some frame)
    : WP.spec (Spike.branch_log.BranchLog.active_at log i) (· = frame) := by
  have inside : i.val < log.branch.val.length := by
    by_contra outside
    have hn : (branchValues log).length ≤ i.val := by
      rw [branch_values_length log valid]
      exact Nat.le_of_not_gt outside
    rw [List.getElem?_eq_none hn] at saved
    cases saved
  unfold Spike.branch_log.BranchLog.active_at
  rw [alloc.vec.Vec.index_slice_index]
  apply WP.spec_bind (alloc.vec.Vec.index_usize_spec log.branch i inside)
  intro id he
  have pick := indexed_branch_values log.frames.val log.branch.val valid.2 i.val
  change (branchValues log)[i.val]? = _ at pick
  rw [pick, List.getElem?_eq_getElem inside, ← he, Option.bind_some] at saved
  exact branch_read_refines log id frame saved

/-- A requested offset past the last surviving frame selects the current head.
The handle still identifies the immutable value, not just its branch offset. -/
theorem branch_cut_refines {T : Type} (log : Spike.branch_log.BranchLog T)
    (valid : BranchValid log) (offset : U64)
    : WP.spec (Spike.branch_log.BranchLog.at_cut log offset)
        (fun id =>
          ∃ frame,
            log.frames.val[id.val]? = some frame
            ∧ (branchValues log)[min offset.val (log.branch.val.length - 1)]?
              = some frame) := by
  let last := log.branch.val.length - 1
  have len : (alloc.vec.Vec.len log.branch).val = log.branch.val.length := alloc.vec.Vec.len_val _
  have pos : 0 < log.branch.val.length := List.length_pos_iff.mpr valid.1
  have cap := alloc.vec.Vec.len_ineq log.branch
  have one : (1#usize : Usize).val = 1 := rfl
  unfold Spike.branch_log.BranchLog.at_cut
  apply WP.spec_bind
    (Usize.sub_spec (x := alloc.vec.Vec.len log.branch) (y := 1#usize) (by omega))
  intro head hp
  have headVal : head.val = last := by dsimp [last]; omega
  let head64 := UScalar.cast .U64 head
  have castHead : head64.val = last := by
    rw [show head64.val = head.val from UScalar.cast_val_mod_pow_greater_numBits_eq .U64 head
      (by
        simp only [UScalarTy.Usize_numBits_eq, UScalarTy.U64_numBits_eq]
        rcases System.Platform.numBits_eq with h | h <;> simp [h]), headVal]
  simp only [lift, bind_ok, alloc.vec.Vec.index_slice_index]
  change WP.spec (do
    let index ← if offset < head64 then Result.ok (UScalar.cast .Usize offset)
      else Result.ok head
    let id ← alloc.vec.Vec.index_usize log.branch index
    Result.ok id) _
  have selected : WP.spec
      (if offset < head64 then Result.ok (UScalar.cast .Usize offset) else Result.ok head)
      (fun i => i.val = min offset.val last) := by
    by_cases earlier : offset < head64
    · have hlt : offset.val < last := by change offset.val < head64.val at earlier; omega
      rw [ite_eq_left earlier, WP.spec_ok, Nat.min_eq_left hlt.le]
      apply UScalar.cast_val_mod_pow_of_inBounds_eq
      rw [← UScalar.max_USize_eq, UScalar.max] at cap
      have := Nat.two_pow_pos UScalarTy.Usize.numBits
      dsimp [last] at hlt
      omega
    · have hle : last ≤ offset.val := by change ¬offset.val < head64.val at earlier; omega
      rw [ite_eq_right earlier, WP.spec_ok, Nat.min_eq_right hle, headVal]
  apply WP.spec_bind selected
  intro index hi
  have bound : index.val < log.branch.val.length := by
    rw [hi]
    exact (Nat.min_le_right _ _).trans_lt (by dsimp [last]; omega)
  apply WP.spec_bind (alloc.vec.Vec.index_usize_spec log.branch index bound)
  intro id he
  have hm : id ∈ log.branch.val := he ▸ List.getElem_mem bound
  have slot := valid.2 id hm
  rw [WP.spec_ok]
  refine ⟨_, List.getElem?_eq_getElem slot, ?_⟩
  have pick := indexed_branch_values log.frames.val log.branch.val valid.2 index.val
  change (branchValues log)[index.val]? = _ at pick
  rw [← hi, pick, List.getElem?_eq_getElem bound, ← he, Option.bind_some,
    List.getElem?_eq_getElem slot]

/-- `at_cut` returns the exact frame ID stored at `min offset (branch.len - 1)`. -/
theorem branch_cut_id_refines {T : Type} (log : Spike.branch_log.BranchLog T)
    (valid : BranchValid log) (offset : U64)
    : WP.spec (Spike.branch_log.BranchLog.at_cut log offset)
        (fun id =>
          log.branch.val[min offset.val (log.branch.val.length - 1)]? = some id) := by
  let last := log.branch.val.length - 1
  have len : (alloc.vec.Vec.len log.branch).val = log.branch.val.length := alloc.vec.Vec.len_val _
  have pos : 0 < log.branch.val.length := List.length_pos_iff.mpr valid.1
  have cap := alloc.vec.Vec.len_ineq log.branch
  have one : (1#usize : Usize).val = 1 := rfl
  unfold Spike.branch_log.BranchLog.at_cut
  apply WP.spec_bind
    (Usize.sub_spec (x := alloc.vec.Vec.len log.branch) (y := 1#usize) (by omega))
  intro head hp
  have headVal : head.val = last := by dsimp [last]; omega
  let head64 := UScalar.cast .U64 head
  have castHead : head64.val = last := by
    rw [show head64.val = head.val from UScalar.cast_val_mod_pow_greater_numBits_eq .U64 head
      (by
        simp only [UScalarTy.Usize_numBits_eq, UScalarTy.U64_numBits_eq]
        rcases System.Platform.numBits_eq with h | h <;> simp [h]), headVal]
  simp only [lift, bind_ok, alloc.vec.Vec.index_slice_index]
  have selected : WP.spec
      (if offset < head64 then Result.ok (UScalar.cast .Usize offset) else Result.ok head)
      (fun i => i.val = min offset.val last) := by
    by_cases earlier : offset < head64
    · have hlt : offset.val < last := by change offset.val < head64.val at earlier; omega
      rw [ite_eq_left earlier, WP.spec_ok, Nat.min_eq_left hlt.le]
      apply UScalar.cast_val_mod_pow_of_inBounds_eq
      have hbd : offset.val ≤ Usize.max := by omega
      rw [← UScalar.max_USize_eq, UScalar.max] at hbd
      have := Nat.two_pow_pos UScalarTy.Usize.numBits
      omega
    · have hge : last ≤ offset.val := by
        change ¬ offset.val < head64.val at earlier; omega
      rw [ite_eq_right earlier, WP.spec_ok, headVal, Nat.min_eq_right hge]
  apply WP.spec_bind selected
  intro index hindex
  have hi : index.val < log.branch.val.length := by rw [hindex]; omega
  apply WP.spec_bind (alloc.vec.Vec.index_usize_spec log.branch index hi)
  intro id hid
  rw [WP.spec_ok, ← hindex, List.getElem?_eq_getElem hi, hid]

/-- Resolving and borrowing gives the same frame as indexing the active projection. -/
theorem branch_observe_refines {T : Type} (log : Spike.branch_log.BranchLog T)
    (valid : BranchValid log) (offset : Usize)
    : WP.spec
        (do
          let id ← Spike.branch_log.BranchLog.resolve log offset
          match id with
          | none => Result.ok none
          | some id =>
              let frame ← Spike.branch_log.BranchLog.read log id
              Result.ok (some frame))
        (· = (branchValues log)[offset.val]?) := by
  have agrees := indexed_branch_values log.frames.val log.branch.val valid.2 offset.val
  change (branchValues log)[offset.val]? = _ at agrees
  apply WP.spec_bind (branch_resolve_refines log offset)
  intro found hf
  rw [hf, agrees]
  cases atOffset : log.branch.val[offset.val]? with
  | none => simp
  | some id =>
      have mem : id ∈ log.branch.val := List.mem_iff_getElem?.mpr ⟨_, atOffset⟩
      have bound := valid.2 id mem
      have live := List.getElem?_eq_getElem bound
      apply WP.spec_bind (branch_read_refines log id _ live)
      intro frame hframe
      rw [WP.spec_ok, hframe, Option.bind_some, live]

/-- Append extends the logical branch and retains the value of every previously issued ID. -/
theorem branch_append_refines {T : Type} (log : Spike.branch_log.BranchLog T) (frame : T)
    (valid : BranchValid log) (room : log.frames.val.length < Usize.max)
    (branchRoom : log.branch.val.length < Usize.max)
    : WP.spec (Spike.branch_log.BranchLog.append log frame)
        (fun (id, after) =>
          BranchValid after
          ∧ branchValues after = branchValues log ++ [frame]
          ∧ id.val = log.frames.val.length
          ∧ after.frames.val[id.val]? = some frame
          ∧ (∀ previous,
              previous < id.val → after.frames.val[previous]? = log.frames.val[previous]?)
          ∧ after.frames.val = log.frames.val ++ [frame]
          ∧ after.branch.val = log.branch.val ++ [id]) := by
  unfold Spike.branch_log.BranchLog.append
  apply WP.spec_bind (alloc.vec.Vec.push_spec log.frames frame room)
  intro frames hf
  apply WP.spec_bind
    (alloc.vec.Vec.push_spec log.branch (alloc.vec.Vec.len log.frames) branchRoom)
  intro branch hb
  rw [WP.spec_ok]
  let id := alloc.vec.Vec.len log.frames
  have index : id.val = log.frames.val.length := alloc.vec.Vec.len_val _
  have newest : frames.val[id.val]? = some frame := by
    rw [hf, index, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]
    rfl
  have keep : ∀ i, i < id.val → frames.val[i]? = log.frames.val[i]? := by
    intro i hi
    rw [hf, List.getElem?_append_left (index ▸ hi)]
  refine ⟨?_, ?_, index, newest, keep, hf, hb⟩
  · change branch.val ≠ [] ∧ ∀ j ∈ branch.val, j.val < frames.val.length
    rw [hb]
    refine ⟨by simp, ?_⟩
    intro j hj
    rcases List.mem_append.mp hj with old | new
    · have h := valid.2 j old
      simp [hf]
      omega
    · have same := List.mem_singleton.mp new
      rw [same, hf, List.length_append, List.length_singleton]
      change id.val < log.frames.val.length + 1
      omega
  · change branch.val.filterMap (fun j => frames.val[j.val]?) = branchValues log ++ [frame]
    rw [hb, List.filterMap_append]
    have same : log.branch.val.filterMap (fun j => frames.val[j.val]?) = branchValues log := by
      apply List.filterMap_congr
      intro j hj
      exact keep j.val (index.symm ▸ valid.2 j hj)
    rw [same]
    change branchValues log ++ [id].filterMap (fun j => frames.val[j.val]?) =
      branchValues log ++ [frame]
    rw [List.filterMap_cons, newest]
    rfl

private theorem branch_take_values {T : Type} (frames : List T) (ids : List Usize)
    (live : ∀ id ∈ ids, id.val < frames.length) (count : Nat)
    : (ids.take count).filterMap (fun id => frames[id.val]?)
      = (ids.filterMap (fun id => frames[id.val]?)).take count := by
  induction ids generalizing count with
  | nil => simp
  | cons id ids ih =>
      have bound := live id List.mem_cons_self
      have rest := ih (fun i hm => live i (List.mem_cons_of_mem _ hm))
      cases count <;> simp [List.getElem?_eq_getElem bound, rest]

/-- Rewind changes only the active branch. A failed rewind does not change anything. -/
theorem branch_rewind_refines {T : Type} (log : Spike.branch_log.BranchLog T)
    (offset : Usize) (valid : BranchValid log)
    : WP.spec (Spike.branch_log.BranchLog.rewind log offset)
        (fun (ok, after) =>
          ok = decide (offset.val < log.branch.val.length)
          ∧ BranchValid after
          ∧ after.frames = log.frames
          ∧ if ok then
              branchValues after = (branchValues log).take (offset.val + 1)
              ∧ after.branch.val = log.branch.val.take (offset.val + 1)
            else
              after = log) := by
  unfold Spike.branch_log.BranchLog.rewind
  have len : (alloc.vec.Vec.len log.branch).val = log.branch.val.length := alloc.vec.Vec.len_val _
  have cap := alloc.vec.Vec.len_ineq log.branch
  by_cases past : offset ≥ alloc.vec.Vec.len log.branch
  · have off : ¬offset.val < log.branch.val.length := by rw [← len]; exact Nat.not_lt_of_ge past
    simp [past, off, valid]
  · have inside : offset.val < log.branch.val.length := by
      rw [← len]
      exact Nat.lt_of_not_ge past
    rw [ite_eq_right past]
    have one : (1#usize : Usize).val = 1 := rfl
    apply WP.spec_bind (Usize.add_spec (x := offset) (y := 1#usize) (by omega))
    intro n hn
    have count : n.val = offset.val + 1 := by omega
    apply WP.spec_bind
      (alloc.vec.Vec.resize_spec core.clone.CloneUsize log.branch n 0#usize rfl)
    intro branch resized
    rw [WP.spec_ok]
    have take : branch.val = log.branch.val.take (offset.val + 1) := by
      rw [resized, List.resize, Nat.sub_eq_zero_of_le (by omega : n.val ≤ log.branch.val.length),
        List.replicate_zero, List.append_nil, count]
      simp
    refine ⟨by simp [inside], ?_, rfl, ?_⟩
    · change branch.val ≠ [] ∧ _
      rw [take]
      refine ⟨?_, fun id hm => valid.2 id (List.mem_of_mem_take hm)⟩
      cases h : log.branch.val with
      | nil => exact (valid.1 h).elim
      | cons hd tail => simp
    · refine ⟨?_, take⟩
      change branch.val.filterMap (fun id => log.frames.val[id.val]?) = _
      rw [take, branch_take_values _ _ valid.2]
      rfl

theorem branch_read_mut_refines {T : Type} (log : Spike.branch_log.BranchLog T)
    (id : Spike.branch_log.FrameId) (frame : T)
    (saved : log.frames.val[id.val]? = some frame)
    : WP.spec (Spike.branch_log.BranchLog.read_mut log id)
        (fun (got, back) =>
          got = frame
          ∧ ∀ next,
              (back next).branch = log.branch
              ∧ (back next).frames.val = log.frames.val.set id.val next) := by
  unfold Spike.branch_log.BranchLog.read_mut
  rw [alloc.vec.Vec.index_mut_slice_index]
  have inside : id.val < log.frames.val.length := by
    by_contra absent
    simp [List.getElem?_eq_none (Nat.le_of_not_gt absent)] at saved
  apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec log.frames id inside)
  rintro ⟨got, indexBack⟩ ⟨hgot, hback⟩
  change WP.spec (Result.ok _) _
  rw [WP.spec_ok]
  refine ⟨?_, ?_⟩
  · rw [List.getElem?_eq_getElem inside, ← hgot, Option.some.injEq] at saved
    exact saved
  · intro next
    refine ⟨rfl, ?_⟩
    simp [hback, alloc.vec.Vec.set]

end KvRust
