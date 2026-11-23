-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- Unsigned byte-list lexicographic order, encoded as Rust's three comparison results. -/
def byteOrder : List U8 → List U8 → I8
  | [], [] => 0#i8
  | [], _ :: _ => (-1)#i8
  | _ :: _, [] => 1#i8
  | a :: xs, b :: ys =>
      if a < b then (-1)#i8 else if b < a then 1#i8 else byteOrder xs ys

private theorem order_zero (a b : List U8) : byteOrder a b = 0#i8 ↔ a = b := by
  have hneg : (-1)#i8 ≠ 0#i8 := by decide
  have hpos : 1#i8 ≠ 0#i8 := by decide
  induction a generalizing b with
  | nil => cases b <;> simp [byteOrder, hneg]
  | cons a xs ih =>
      cases b with
      | nil => simp [byteOrder, hpos]
      | cons b bs =>
          by_cases hab : a < b
          · have hne : a ≠ b := fun eq => (lt_irrefl b) (eq ▸ hab)
            simp [byteOrder, hab, hneg, hne]
          · by_cases hba : b < a
            · have hne : a ≠ b := fun eq => (lt_irrefl b) (eq ▸ hba)
              simp [byteOrder, hab, hba, hpos, hne]
            · have heq : a = b := le_antisymm (le_of_not_gt hba) (le_of_not_gt hab)
              simp [byteOrder, heq, ih]

private theorem order_at_end (a b : List U8) (i : Nat)
    (ha : i ≤ a.length) (hb : i ≤ b.length) (h : a.length ≤ i ∨ b.length ≤ i)
    : byteOrder (a.drop i) (b.drop i)
      = if a.length < b.length then
          (-1)#i8
        else if b.length < a.length then
          1#i8
        else
          0#i8 := by
  by_cases hab : a.length < b.length
  · have ha' : a.length ≤ i := by omega
    have hb' : b.drop i ≠ [] := fun he => by
      have := List.drop_eq_nil_iff.mp he
      omega
    cases he : b.drop i with
    | nil => exact (hb' he).elim
    | cons => simp [List.drop_eq_nil_of_le ha', byteOrder, hab]
  · by_cases hba : b.length < a.length
    · have hb' : b.length ≤ i := by omega
      have ha' : a.drop i ≠ [] := fun he => by
        have := List.drop_eq_nil_iff.mp he
        omega
      cases he : a.drop i with
      | nil => exact (ha' he).elim
      | cons => simp [List.drop_eq_nil_of_le hb', byteOrder, hab, hba]
    · have ha' : a.length ≤ i := by omega
      have hb' : b.length ≤ i := by omega
      simp [List.drop_eq_nil_of_le ha', List.drop_eq_nil_of_le hb', byteOrder, hab, hba]

/-- The extracted comparator terminates with the unsigned lexicographic order of the byte lists. -/
theorem bytes_compare (a b : Spike.engine.Bytes)
    : WP.spec (Spike.engine.Bytes.compare a b)
        (fun r => r = byteOrder (alloc.vec.Vec.val a) (alloc.vec.Vec.val b)) := by
  let xs := alloc.vec.Vec.val a
  let ys := alloc.vec.Vec.val b
  unfold Spike.engine.Bytes.compare Spike.engine.Bytes.compare_loop
  apply loop.spec_decr_nat
    (fun (p : Spike.engine.Bytes × Spike.engine.Bytes × Usize) => xs.length - p.2.2.val)
    (fun p => p.1 = a ∧ p.2.1 = b ∧ p.2.2.val ≤ xs.length ∧ p.2.2.val ≤ ys.length
      ∧ byteOrder (xs.drop p.2.2.val) (ys.drop p.2.2.val) = byteOrder xs ys)
    _ _ _
  · rintro ⟨aa, bb, i⟩ ⟨aha, bhb, ha, hb, hinv⟩
    dsimp only at aha bhb ha hb hinv ⊢
    subst aa bb
    have hla : (alloc.vec.Vec.len a).val = xs.length := alloc.vec.Vec.len_val a
    have hlb : (alloc.vec.Vec.len b).val = ys.length := alloc.vec.Vec.len_val b
    have hlen := alloc.vec.Vec.len_ineq a
    have hone : (1#usize : Usize).val = 1 := rfl
    unfold Spike.engine.Bytes.compare_loop.body
    by_cases hai : i < alloc.vec.Vec.len a <;> by_cases hbi : i < alloc.vec.Vec.len b
    · have ha' : i.val < xs.length := by
        rw [← hla]
        exact hai
      have hb' : i.val < ys.length := by
        rw [← hlb]
        exact hbi
      simp only [hai, hbi, ite_true, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec a i ha')
      intro x hx
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec b i hb')
      intro y hy
      rw [List.drop_eq_getElem_cons ha', List.drop_eq_getElem_cons hb', ← hx, ← hy] at hinv
      by_cases hxy : x < y <;> by_cases hyx : y < x
      · exact (lt_asymm hxy hyx).elim
      · simpa only [hxy, ite_true, WP.spec_ok]
          using (show (-1)#i8 = byteOrder xs ys by simpa [byteOrder, hxy] using hinv)
      · simpa only [hxy, hyx, ite_false, ite_true, WP.spec_ok]
          using (show 1#i8 = byteOrder xs ys by simpa [byteOrder, hxy, hyx] using hinv)
      · have hnext : i.val + (1#usize : Usize).val ≤ Usize.max := by
          change xs.length ≤ Usize.max at hlen
          omega
        simp only [hxy, hyx, ite_false]
        apply WP.spec_bind (Usize.add_spec hnext)
        intro next hnextval
        simp only [WP.spec_ok]
        have heq : next.val = i.val + 1 := by omega
        refine ⟨⟨True.intro, True.intro, by omega, by omega, ?_⟩, by omega⟩
        simpa [heq, byteOrder, hxy, hyx] using hinv
    all_goals
      have he : xs.length ≤ i.val ∨ ys.length ≤ i.val := by
        first
        | right
          rw [← hlb]
          exact Nat.le_of_not_gt hbi
        | left
          rw [← hla]
          exact Nat.le_of_not_gt hai
      have hend := (order_at_end xs ys i.val ha hb he).symm.trans hinv
      simp only [hai, hbi, ite_true, ite_false]
      by_cases hlt : alloc.vec.Vec.len a < alloc.vec.Vec.len b
      · have hl : xs.length < ys.length := by rwa [← hla, ← hlb]
        simp [hlt, show (-1)#i8 = byteOrder xs ys by simpa [hl] using hend]; rfl
      · by_cases hgt : alloc.vec.Vec.len b < alloc.vec.Vec.len a
        · have hl : ¬xs.length < ys.length := by rwa [← hla, ← hlb]
          have hg : ys.length < xs.length := by rwa [← hla, ← hlb]
          simp [hlt, hgt, show 1#i8 = byteOrder xs ys by simpa [hl, hg] using hend]; rfl
        · have hl : ¬xs.length < ys.length := by rwa [← hla, ← hlb]
          have hg : ¬ys.length < xs.length := by rwa [← hla, ← hlb]
          simp [hlt, hgt, show 0#i8 = byteOrder xs ys by simpa [hl, hg] using hend]; rfl
  · simp

/-- Equality used by extracted lookups is equality of byte contents. -/
theorem bytes_same (a b : Spike.engine.Bytes)
    : Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey.same a b
      = .ok (decide (alloc.vec.Vec.val a = alloc.vec.Vec.val b)) := by
  have h := bytes_compare a b
  unfold Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey.same
  cases hr : Spike.engine.Bytes.compare a b using Result.cases with
  | ret r =>
      simp only [hr, WP.spec_ok] at h
      simp [h, order_zero]
  | vis _ _ => simp [hr] at h
  | div => simp [hr] at h

private theorem bytes_same_slice (a b : Spike.engine.Bytes)
    : Spike.engine.Bytes.same_slice a b
      = .ok (decide (alloc.vec.Vec.val a = alloc.vec.Vec.val b)) := by
  simp only [Spike.engine.Bytes.same_slice,
    Spike.engine.Bytes.as_slice, bind_ok]
  let result := core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8
    (alloc.vec.Vec.deref a) (alloc.vec.Vec.deref b)
  have h := core.slice.cmp.PartialEqSlice.eq_homo_spec core.cmp.PartialEqU8
    (alloc.vec.Vec.deref a) (alloc.vec.Vec.deref b) (by
      intro x y
      simp)
  change WP.spec result _ at h
  change result = _
  cases hr : result using Result.cases with
  | ret eq =>
      simp only [hr, WP.spec_ok, Slice.eq_iff] at h
      cases eq <;> simp_all [alloc.vec.Vec.deref]
  | vis _ _ => simp [hr] at h
  | div => simp [hr] at h

/-- Both components of an address use byte-content equality. -/
theorem address_same (a b : Spike.engine.Address)
    : Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey.same a b
      = .ok
          (decide
            (alloc.vec.Vec.val a.map = alloc.vec.Vec.val b.map
              ∧ alloc.vec.Vec.val a.key = alloc.vec.Vec.val b.key)) := by
  unfold Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey.same
  by_cases h : alloc.vec.Vec.val a.key = alloc.vec.Vec.val b.key
  · simp [bytes_same_slice, h]
  · simp [bytes_same_slice, h]

end KvRust
