-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- Copying bytes at the native API boundary preserves their full contents. -/
theorem bytes_copy_from (bytes : Slice U8)
    : WP.spec (CcfKv.engine.Bytes.copy_from bytes)
        (fun copy => copy.val = bytes.val) := by
  unfold CcfKv.engine.Bytes.copy_from
  apply WP.spec_bind (alloc.slice.Slice.to_vec_spec core.clone.CloneU8 bytes (fun _ _ => rfl))
  intro copy hc
  rw [WP.spec_ok]
  change copy.slice.val = bytes.val
  exact congrArg Slice.val hc.symm

/-- Unsigned byte-list lexicographic order, encoded as Rust's three comparison results. -/
def byteOrder : List U8 → List U8 → I8
  | [], [] => 0#i8
  | [], _ :: _ => (-1)#i8
  | _ :: _, [] => 1#i8
  | a :: xs, b :: ys =>
      if a < b then (-1)#i8 else if b < a then 1#i8 else byteOrder xs ys

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
theorem bytes_compare (a b : CcfKv.engine.Bytes)
    : WP.spec (CcfKv.engine.Bytes.compare a b)
        (fun r => r = byteOrder (alloc.vec.Vec.val a) (alloc.vec.Vec.val b)) := by
  let xs := alloc.vec.Vec.val a
  let ys := alloc.vec.Vec.val b
  unfold CcfKv.engine.Bytes.compare CcfKv.engine.Bytes.compare_loop
  apply loop.spec_decr_nat
    (fun (p : CcfKv.engine.Bytes × CcfKv.engine.Bytes × Usize) => xs.length - p.2.2.val)
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
    unfold CcfKv.engine.Bytes.compare_loop.body
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

private theorem bytes_same_slice (a b : CcfKv.engine.Bytes)
    : CcfKv.engine.Bytes.same_slice a b
      = .ok (decide (alloc.vec.Vec.val a = alloc.vec.Vec.val b)) := by
  simp only [CcfKv.engine.Bytes.same_slice,
    CcfKv.engine.Bytes.as_slice, bind_ok]
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

/-- Equality used by extracted lookups is equality of byte contents. -/
theorem bytes_same (a b : CcfKv.engine.Bytes)
    : CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey.same a b
      = .ok (decide (alloc.vec.Vec.val a = alloc.vec.Vec.val b)) := by
  simpa only [CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey.same] using bytes_same_slice a b

private theorem bytes_same_key (a b : CcfKv.engine.Bytes)
    : CcfKv.engine.Bytes.same_key a b = .ok (decide (a.val = b.val)) := by
  have proved : WP.spec (CcfKv.engine.Bytes.same_key a b)
      (· = decide (a.val = b.val)) := by
    unfold CcfKv.engine.Bytes.same_key
    let lenA := alloc.vec.Vec.len a
    let lenB := alloc.vec.Vec.len b
    have hlenA : lenA.val = a.val.length := alloc.vec.Vec.len_val a
    have hlenB : lenB.val = b.val.length := alloc.vec.Vec.len_val b
    have lengths : lenA = lenB ↔ a.val.length = b.val.length := by
      constructor
      · intro same
        rw [← hlenA, ← hlenB, same]
      · intro same
        apply UScalar.eq_of_val_eq
        rw [hlenA, hlenB, same]
    have zero : (0#usize : Usize).val = 0 := rfl
    have one : (1#usize : Usize).val = 1 := rfl
    by_cases sameSize : lenA = lenB
    · have lengthEq := lengths.mp sameSize
      simp only [show alloc.vec.Vec.len a = alloc.vec.Vec.len b from sameSize,
        bne_self_eq_false, Bool.false_eq_true, ite_false]
      by_cases empty : lenB = 0#usize
      · have bl : b.val.length = 0 := by rw [← hlenB, empty, zero]
        have al : a.val.length = 0 := lengthEq.trans bl
        rw [ite_eq_left empty, WP.spec_ok]
        simp [List.length_eq_zero_iff.mp al, List.length_eq_zero_iff.mp bl]
      · have pos : 0 < lenB.val := by
          by_contra no
          apply empty
          exact UScalar.eq_of_val_eq (by omega)
        rw [ite_eq_right empty]
        apply WP.spec_bind (Usize.sub_spec (x := lenB) (y := 1#usize) (by omega))
        intro i hi
        have insideB : i.val < b.val.length := by omega
        have insideA : i.val < a.val.length := by omega
        simp only [alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec a i insideA)
        intro x hx
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec b i insideB)
        intro y hy
        by_cases same : x = y
        · simp [same, bytes_same_slice]
        · have distinct : a.val ≠ b.val := by
            intro eq
            apply same
            have he := congrArg (fun (l : List U8) => l[i.val]?) eq
            rw [List.getElem?_eq_getElem insideA, List.getElem?_eq_getElem insideB, ← hx, ← hy]
              at he
            exact Option.some.inj he
          simp [same, distinct]
    · have different : a.val ≠ b.val := fun h =>
        sameSize (lengths.mpr (congrArg List.length h))
      simp [show alloc.vec.Vec.len a ≠ alloc.vec.Vec.len b from sameSize, different]
  cases hr : CcfKv.engine.Bytes.same_key a b using Result.cases with
  | ret result => simpa [hr, Result.ok.injEq] using proved
  | vis _ _ => simp [hr] at proved
  | div => simp [hr] at proved

/-- Both components of an address use byte-content equality. -/
theorem address_same (a b : CcfKv.engine.Address)
    : CcfKv.engine.Address.Insts.Ccf_kvEngineKey.same a b
      = .ok
          (decide
            (alloc.vec.Vec.val a.map = alloc.vec.Vec.val b.map
              ∧ alloc.vec.Vec.val a.key = alloc.vec.Vec.val b.key)) := by
  unfold CcfKv.engine.Address.Insts.Ccf_kvEngineKey.same
  by_cases h : alloc.vec.Vec.val a.key = alloc.vec.Vec.val b.key
  · simp [bytes_same_key, bytes_same_slice, h]
  · simp [bytes_same_key, h]

end KvRust
