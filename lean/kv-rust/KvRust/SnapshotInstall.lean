-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Range
public import KvRust.RadixSingleReclaim

@[expose] public section

namespace KvRust

open Aeneas.Std

abbrev SnapshotBatchRow := CcfKv.radix.RadixRow (CcfKv.kv_index.Binding CcfKv.engine.Cell)

private theorem order_at_end_slice (a b : List U8) (i : Nat)
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

/-- `engine.compare_slices` terminates with the unsigned lexicographic byte order. -/
theorem compare_slices_spec (a b : Slice U8)
    : WP.spec (CcfKv.engine.compare_slices a b)
        (fun r => r = byteOrder a.val b.val) := by
  let xs := a.val
  let ys := b.val
  unfold CcfKv.engine.compare_slices CcfKv.engine.compare_slices_loop
  apply loop.spec_decr_nat
    (fun (i : Usize) => xs.length - i.val)
    (fun i => i.val ≤ xs.length ∧ i.val ≤ ys.length
      ∧ byteOrder (xs.drop i.val) (ys.drop i.val) = byteOrder xs ys)
    _ _ _
  · intro i ⟨ha, hb, hinv⟩
    have hla : (Slice.len a).val = xs.length := Slice.len_val a
    have hlb : (Slice.len b).val = ys.length := Slice.len_val b
    have hlen : xs.length ≤ Usize.max := a.property
    have hone : (1#usize : Usize).val = 1 := rfl
    unfold CcfKv.engine.compare_slices_loop.body
    by_cases hai : i < Slice.len a <;> by_cases hbi : i < Slice.len b
    · have ha' : i.val < xs.length := by rw [← hla]; exact hai
      have hb' : i.val < ys.length := by rw [← hlb]; exact hbi
      simp only [hai, hbi, ite_true]
      apply WP.spec_bind (Slice.index_usize_spec a i ha')
      intro x hx
      apply WP.spec_bind (Slice.index_usize_spec b i hb')
      intro y hy
      rw [List.drop_eq_getElem_cons ha', List.drop_eq_getElem_cons hb', ← hx, ← hy] at hinv
      by_cases hxy : x < y <;> by_cases hyx : y < x
      · exact (lt_asymm hxy hyx).elim
      · simpa only [hxy, ite_true, WP.spec_ok]
          using (show (-1)#i8 = byteOrder xs ys by simpa [byteOrder, hxy] using hinv)
      · have hgt : x > y := hyx
        simpa only [hxy, hgt, ite_false, ite_true, WP.spec_ok]
          using (show 1#i8 = byteOrder xs ys by simpa [byteOrder, hxy, hyx] using hinv)
      · have hngt : ¬ x > y := hyx
        have hnext : i.val + (1#usize : Usize).val ≤ Usize.max := by
          change xs.length ≤ Usize.max at hlen
          omega
        simp only [hxy, hngt, ite_false]
        apply WP.spec_bind (Usize.add_spec hnext)
        intro next hnextval
        simp only [WP.spec_ok]
        have heq : next.val = i.val + 1 := by omega
        refine ⟨⟨by omega, by omega, ?_⟩, by omega⟩
        simpa [heq, byteOrder, hxy, hyx] using hinv
    all_goals
      have he : xs.length ≤ i.val ∨ ys.length ≤ i.val := by
        first
        | right; rw [← hlb]; exact Nat.le_of_not_gt hbi
        | left; rw [← hla]; exact Nat.le_of_not_gt hai
      have hend := (order_at_end_slice xs ys i.val ha hb he).symm.trans hinv
      simp only [hai, hbi, ite_true, ite_false]
      by_cases hlt : Slice.len a < Slice.len b
      · have hl : xs.length < ys.length := by rwa [← hla, ← hlb]
        simp [hlt, show (-1)#i8 = byteOrder xs ys by simpa [hl] using hend]; rfl
      · by_cases hgt : Slice.len a > Slice.len b
        · have hl : ¬ xs.length < ys.length := by rwa [← hla, ← hlb]
          have hg : ys.length < xs.length := by rwa [← hla, ← hlb]
          simp [hlt, hgt, show 1#i8 = byteOrder xs ys by simpa [hl, hg] using hend]; rfl
        · have hl : ¬ xs.length < ys.length := by rwa [← hla, ← hlb]
          have hg : ¬ ys.length < xs.length := by rwa [← hla, ← hlb]
          simp [hlt, hgt, show 0#i8 = byteOrder xs ys by simpa [hl, hg] using hend]; rfl
  · simp

/-- `engine.compare_batch_rows` on two present rows compares their packed byte keys. -/
theorem compare_batch_rows_spec (a b : SnapshotBatchRow)
    : WP.spec (CcfKv.engine.compare_batch_rows (some a) (some b))
        (fun r => r = byteOrder a.key.val b.key.val) := by
  unfold CcfKv.engine.compare_batch_rows CcfKv.engine.batch_row_key
  simp only [bind_ok]
  simpa [alloc.vec.Vec.deref] using compare_slices_spec (alloc.vec.Vec.deref a.key)
    (alloc.vec.Vec.deref b.key)

private theorem pairwise_of_adjacent_lt {α : Type} {lt : α → α → Prop}
    (trans : ∀ {a b c}, lt a b → lt b c → lt a c)
    (l : List α)
    (hadj : ∀ i (h : i + 1 < l.length), lt l[i] l[i + 1])
    : l.Pairwise lt := by
  induction l with
  | nil => exact List.Pairwise.nil
  | cons x xs ih =>
      have hxs : xs.Pairwise lt := ih (fun i hi => by
        have h := hadj (i + 1) (by simp; omega)
        simpa [List.getElem_cons_succ] using h)
      refine List.Pairwise.cons ?_ hxs
      intro y hy
      rcases List.getElem_of_mem hy with ⟨k, hk, rfl⟩
      clear hy
      induction k with
      | zero =>
          simpa using hadj 0 (by simp; omega)
      | succ k ihk =>
          have hstep : lt xs[k] xs[k + 1] := by
            have h := hadj (k + 1) (by simp; omega)
            simpa [List.getElem_cons_succ] using h
          exact trans (ihk (by omega)) hstep

private theorem list_u8_lt_trans {a b c : List U8} (hab : a < b) (hbc : b < c) : a < c := by
  induction a generalizing b c with
  | nil =>
      cases b with
      | nil => exact (lt_irrefl [] hab).elim
      | cons _ _ =>
          cases c with
          | nil => simp at hbc
          | cons _ _ => exact List.nil_lt_cons _ _
  | cons x xs ih =>
      cases b with
      | nil => simp at hab
      | cons y ys =>
          cases c with
          | nil => simp at hbc
          | cons z zs =>
              rw [List.cons_lt_cons_iff] at hab hbc ⊢
              rcases hab with hxy | ⟨rfl, hxs⟩
              · rcases hbc with hyz | ⟨rfl, _⟩
                · exact Or.inl (lt_trans hxy hyz)
                · exact Or.inl hxy
              · rcases hbc with hyz | ⟨rfl, hys⟩
                · exact Or.inl hyz
                · exact Or.inr ⟨rfl, ih hxs hys⟩

/-- `engine.batch_order_state` terminates on all-present batches; returning `-1` certifies
    strict ascending byte-key order across the entire batch. -/
theorem batch_order_state_spec (batch : Slice (Option SnapshotBatchRow))
    (rows : List SnapshotBatchRow) (owned : batch.val = rows.map some)
    : WP.spec (CcfKv.engine.batch_order_state batch)
        (fun ord => ord = (-1)#i8 → rows.Pairwise (fun a b => a.key.val < b.key.val)) := by
  unfold CcfKv.engine.batch_order_state CcfKv.engine.batch_order_state_loop
  have hlen : (Slice.len batch).val = rows.length := by
    simp [owned]
  have hmax : batch.val.length ≤ Usize.max := batch.property
  have hone : (1#usize : Usize).val = 1 := rfl
  apply loop.spec_decr_nat
    (fun (i : Usize) => rows.length + 1 - i.val)
    (fun i => 1 ≤ i.val ∧ i.val ≤ rows.length + 1
      ∧ ∀ k (hk : k + 1 < i.val) (hk' : k + 1 < rows.length),
          rows[k].key.val < rows[k + 1].key.val)
    _ _ _
  · intro i ⟨hi1, hile, hprev⟩
    unfold CcfKv.engine.batch_order_state_loop.body
    by_cases hlt : i < Slice.len batch
    · have hi : i.val < rows.length := by rw [← hlen]; exact hlt
      have him1 : i.val - 1 < rows.length := by omega
      have hbi : i.val < batch.val.length := by rw [owned, List.length_map]; exact hi
      have hbm1 : i.val - 1 < batch.val.length := by rw [owned, List.length_map]; exact him1
      simp only [hlt, ite_true]
      apply WP.spec_bind (Usize.sub_spec (x := i) (y := 1#usize) (by omega))
      intro i2 hi2
      have hi2val : i2.val = i.val - 1 := by omega
      have hbm1' : i2.val < batch.val.length := by rw [hi2val]; exact hbm1
      apply WP.spec_bind (Slice.index_usize_spec batch i2 hbm1')
      intro o ho
      apply WP.spec_bind (Slice.index_usize_spec batch i hbi)
      intro o1 ho1
      have ho_eq : o = some rows[i.val - 1] := by
        rw [ho]
        simp [owned, hi2val]
      have ho1_eq : o1 = some rows[i.val] := by
        rw [ho1]
        simp [owned]
      rw [ho_eq, ho1_eq]
      apply WP.spec_bind (compare_batch_rows_spec rows[i.val - 1] rows[i.val])
      intro ord hord
      by_cases hge : ord ≥ 0#i8
      · simp only [hge, ite_true, WP.spec_ok]
        intro hneg
        rw [hneg] at hge
        have hbad : ¬ ((-1)#i8 ≥ 0#i8) := by decide
        exact (hbad hge).elim
      · simp only [hge, ite_false]
        have hstep : rows[i.val - 1].key.val < rows[i.val].key.val := by
          have hneg : byteOrder rows[i.val - 1].key.val rows[i.val].key.val < 0#i8 := by
            rw [← hord]
            exact lt_of_not_ge hge
          exact (byteOrder_lt _ _).mp hneg
        have hnext : i.val + (1#usize : Usize).val ≤ Usize.max := by
          rw [owned, List.length_map] at hmax
          omega
        apply WP.spec_bind (Usize.add_spec hnext)
        intro i3 hi3
        simp only [WP.spec_ok]
        refine ⟨⟨by omega, by omega, ?_⟩, by omega⟩
        intro k hk hk'
        by_cases hlast : k + 1 = i.val
        · have hk_eq : k = i.val - 1 := by omega
          simpa [hk_eq, Nat.sub_add_cancel hi1] using hstep
        · exact hprev k (by omega) hk'
    · simp only [hlt, ite_false, WP.spec_ok]
      intro _
      have hi_ge : rows.length ≤ i.val := by
        rw [← hlen]
        exact Nat.le_of_not_gt hlt
      exact pairwise_of_adjacent_lt (lt := fun a b => a.key.val < b.key.val) list_u8_lt_trans rows
        (fun k hk => hprev k (by omega) hk)
  · refine ⟨by omega, by omega, ?_⟩
    intro k hk
    omega

private def subslice {α : Type} (l : List α) (lo hi : Nat) : List α :=
  (l.drop lo).take (hi - lo)

private theorem subslice_nil {α : Type} (l : List α) (lo : Nat) : subslice l lo lo = [] := by
  simp [subslice]

private theorem subslice_length {α : Type} (l : List α) {lo hi : Nat}
    (_h1 : lo ≤ hi) (h2 : hi ≤ l.length) : (subslice l lo hi).length = hi - lo := by
  simp [subslice]
  omega

private theorem subslice_full {α : Type} (l : List α) : subslice l 0 l.length = l := by
  simp [subslice]

private theorem subslice_append_elem {α : Type} (l : List α) {lo hi : Nat}
    (h1 : lo ≤ hi) (h2 : hi < l.length)
    : subslice l lo hi ++ [l[hi]] = subslice l lo (hi + 1) := by
  simp only [subslice]
  have htake : (l.drop lo).take (hi - lo) ++ [(l.drop lo)[hi - lo]'(by simp; omega)]
      = (l.drop lo).take (hi - lo + 1) := by
    rw [List.take_succ_eq_append_getElem (by simp; omega)]
  have hget : (l.drop lo)[hi - lo]'(by simp; omega) = l[hi] := by
    simp [List.getElem_drop, Nat.add_sub_cancel' h1]
  rw [hget] at htake
  simpa [show hi + 1 - lo = hi - lo + 1 by omega] using htake

private theorem subslice_split {α : Type} (l : List α) {a b c : Nat}
    (hab : a ≤ b) (hbc : b ≤ c)
    : subslice l a b ++ subslice l b c = subslice l a c := by
  simp only [subslice]
  have hdrop : l.drop b = (l.drop a).drop (b - a) := by
    rw [List.drop_drop, Nat.add_sub_cancel' hab]
  rw [hdrop, ← List.take_add, show (b - a) + (c - b) = c - a by omega]

private def SlicePreserved (src : List (Option SnapshotBatchRow))
    (orig : List SnapshotBatchRow) (lo hi : Nat) : Prop :=
  src.length = orig.length
  ∧ ∀ k (hk : k < orig.length), lo ≤ k → k < hi → src[k]? = some (some orig[k])

private theorem slice_preserved_set_none {src : List (Option SnapshotBatchRow)}
    {orig : List SnapshotBatchRow} {idx lo hi : Nat}
    (hp : SlicePreserved src orig lo hi) (hlo : idx < lo ∨ hi ≤ idx)
    : SlicePreserved (src.set idx none) orig lo hi := by
  refine ⟨by simp [hp.1], fun k hk h1 h2 => ?_⟩
  have hne : idx ≠ k := by omega
  rw [List.getElem?_set_ne hne]
  exact hp.2 k hk h1 h2

private theorem merge_runs_loop0_spec
    (src dst : alloc.vec.Vec (Option SnapshotBatchRow))
    (orig : List SnapshotBatchRow) (dst0 : List SnapshotBatchRow)
    (left mid right : Usize)
    (hord : left.val ≤ mid.val ∧ mid.val ≤ right.val ∧ right.val ≤ orig.length)
    (hcap : orig.length ≤ Usize.max)
    (hsrc_l : SlicePreserved src.val orig left.val mid.val)
    (hsrc_r : SlicePreserved src.val orig mid.val right.val)
    (hsrc_tail : SlicePreserved src.val orig right.val orig.length)
    (hdst : dst.val = dst0.map some)
    (hdst_len : dst0.length + (right.val - left.val) ≤ orig.length)
    : WP.spec (CcfKv.engine.merge_runs_loop0 src dst mid right left mid)
        (fun (src', dst', i', j') =>
          left.val ≤ i'.val ∧ i'.val ≤ mid.val
          ∧ mid.val ≤ j'.val ∧ j'.val ≤ right.val
          ∧ SlicePreserved src'.val orig i'.val mid.val
          ∧ SlicePreserved src'.val orig j'.val right.val
          ∧ SlicePreserved src'.val orig right.val orig.length
          ∧ ∃ taken, dst'.val = (dst0 ++ taken).map some
              ∧ taken.Perm (subslice orig left.val i'.val ++ subslice orig mid.val j'.val)) := by
  unfold CcfKv.engine.merge_runs_loop0
  apply loop.spec_decr_nat
    (fun (p : alloc.vec.Vec (Option SnapshotBatchRow) × alloc.vec.Vec (Option SnapshotBatchRow)
          × Usize × Usize) => (mid.val - p.2.2.1.val) + (right.val - p.2.2.2.val))
    (fun p =>
      left.val ≤ p.2.2.1.val ∧ p.2.2.1.val ≤ mid.val
      ∧ mid.val ≤ p.2.2.2.val ∧ p.2.2.2.val ≤ right.val
      ∧ SlicePreserved p.1.val orig p.2.2.1.val mid.val
      ∧ SlicePreserved p.1.val orig p.2.2.2.val right.val
      ∧ SlicePreserved p.1.val orig right.val orig.length
      ∧ ∃ taken, p.2.1.val = (dst0 ++ taken).map some
          ∧ taken.Perm (subslice orig left.val p.2.2.1.val ++ subslice orig mid.val p.2.2.2.val))
    _ _ _
  · rintro ⟨s, d, i, j⟩ ⟨hli, him, hmj, hjr, hsl, hsr, hst, taken, hd, hperm⟩
    dsimp only at hli him hmj hjr hsl hsr hst hd hperm ⊢
    unfold CcfKv.engine.merge_runs_loop0.body
    by_cases him_lt : i < mid
    · by_cases hjr_lt : j < right
      · simp only [him_lt, hjr_lt, ite_true, alloc.vec.Vec.index_slice_index,
          alloc.vec.Vec.index_mut_slice_index]
        have hi_lt : i.val < mid.val := him_lt
        have hj_lt : j.val < right.val := hjr_lt
        have hi_orig : i.val < orig.length := by omega
        have hj_orig : j.val < orig.length := by omega
        have hi_s : i.val < s.val.length := by rw [hsl.1]; exact hi_orig
        have hj_s : j.val < s.val.length := by rw [hsr.1]; exact hj_orig
        have hget_i : s.val[i.val] = some orig[i.val] := by
          have h := hsl.2 i.val hi_orig (Nat.le_refl _) hi_lt
          rw [List.getElem?_eq_getElem hi_s] at h
          exact Option.some.inj h
        have hget_j : s.val[j.val] = some orig[j.val] := by
          have h := hsr.2 j.val hj_orig (Nat.le_refl _) hj_lt
          rw [List.getElem?_eq_getElem hj_s] at h
          exact Option.some.inj h
        have htaken_len : taken.length = (i.val - left.val) + (j.val - mid.val) := by
          rw [hperm.length_eq, List.length_append,
            subslice_length orig hli (by omega), subslice_length orig hmj (by omega)]
        have hd_cap : d.val.length < Usize.max := by
          rw [hd, List.length_map, List.length_append, htaken_len]
          omega
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec s i hi_s)
        intro o ho
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec s j hj_s)
        intro o1 ho1
        rw [ho, hget_i, ho1, hget_j]
        apply WP.spec_bind (compare_batch_rows_spec orig[i.val] orig[j.val])
        intro cmp _
        by_cases hle : cmp ≤ 0#i8
        · simp only [hle, ite_true]
          apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec s i hi_s)
          rintro ⟨o2, back⟩ ⟨ho2, hback⟩
          have ho2_eq : o2 = some orig[i.val] := by rw [ho2]; exact hget_i
          rw [ho2_eq]
          simp only [core.option.Option.take]
          apply WP.spec_bind (alloc.vec.Vec.push_spec d (some orig[i.val]) hd_cap)
          intro d1 hd1
          have hi_add : i.val + (1#usize : Usize).val ≤ Usize.max := by
            change i.val + 1 ≤ Usize.max; omega
          apply WP.spec_bind (Usize.add_spec hi_add)
          intro i2 hi2
          simp only [WP.spec_ok]
          have hi2_val : i2.val = i.val + 1 := hi2
          have hs1_val : (back none).val = s.val.set i.val none := by
            simp [hback]
          refine ⟨⟨by omega, by omega, hmj, hjr, ?_, ?_, ?_, taken ++ [orig[i.val]], ?_, ?_⟩,
            by omega⟩
          · rw [hs1_val, hi2_val]
            refine ⟨by simp [hsl.1], fun k hk h1 h2 => ?_⟩
            rw [List.getElem?_set_ne (by omega)]
            exact hsl.2 k hk (by omega) h2
          · rw [hs1_val]
            exact slice_preserved_set_none hsr (Or.inl (by omega))
          · rw [hs1_val]
            exact slice_preserved_set_none hst (Or.inl (by omega))
          · simp [hd1, hd, List.append_assoc]
          · rw [hi2_val, ← subslice_append_elem orig hli hi_orig]
            refine (hperm.append_right [orig[i.val]]).trans ?_
            rw [List.append_assoc, List.append_assoc]
            exact List.Perm.append_left _ List.perm_append_comm
        · simp only [hle, ite_false]
          apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec s j hj_s)
          rintro ⟨o2, back⟩ ⟨ho2, hback⟩
          have ho2_eq : o2 = some orig[j.val] := by rw [ho2]; exact hget_j
          rw [ho2_eq]
          simp only [core.option.Option.take]
          apply WP.spec_bind (alloc.vec.Vec.push_spec d (some orig[j.val]) hd_cap)
          intro d1 hd1
          have hj_add : j.val + (1#usize : Usize).val ≤ Usize.max := by
            change j.val + 1 ≤ Usize.max; omega
          apply WP.spec_bind (Usize.add_spec hj_add)
          intro j1 hj1
          simp only [WP.spec_ok]
          have hj1_val : j1.val = j.val + 1 := hj1
          have hs1_val : (back none).val = s.val.set j.val none := by
            simp [hback]
          refine ⟨⟨hli, him, by omega, by omega, ?_, ?_, ?_, taken ++ [orig[j.val]], ?_, ?_⟩,
            by omega⟩
          · rw [hs1_val]
            exact slice_preserved_set_none hsl (Or.inr (by omega))
          · rw [hs1_val, hj1_val]
            refine ⟨by simp [hsr.1], fun k hk h1 h2 => ?_⟩
            rw [List.getElem?_set_ne (by omega)]
            exact hsr.2 k hk (by omega) h2
          · rw [hs1_val]
            exact slice_preserved_set_none hst (Or.inl (by omega))
          · simp [hd1, hd, List.append_assoc]
          · rw [hj1_val, ← subslice_append_elem orig hmj hj_orig]
            simpa [List.append_assoc] using hperm.append_right [orig[j.val]]
      · simp only [him_lt, hjr_lt, ite_true, ite_false, WP.spec_ok]
        exact ⟨hli, him, hmj, hjr, hsl, hsr, hst, taken, hd, hperm⟩
    · simp only [him_lt, ite_false, WP.spec_ok]
      exact ⟨hli, him, hmj, hjr, hsl, hsr, hst, taken, hd, hperm⟩
  · refine ⟨Nat.le_refl _, hord.1, Nat.le_refl _, hord.2.1, hsrc_l, hsrc_r, hsrc_tail, [], ?_, ?_⟩
    · simpa using hdst
    · simp [subslice_nil]

private theorem merge_runs_drain_spec
    (src dst : alloc.vec.Vec (Option SnapshotBatchRow))
    (orig : List SnapshotBatchRow) (dst0 : List SnapshotBatchRow)
    (i0 hi : Usize)
    (other_lo other_hi tail_lo : Nat)
    (hord : i0.val ≤ hi.val ∧ hi.val ≤ orig.length)
    (hcap : orig.length ≤ Usize.max)
    (hdisj_other : hi.val ≤ other_lo ∨ other_hi ≤ i0.val)
    (hdisj_tail : hi.val ≤ tail_lo)
    (hsrc_i : SlicePreserved src.val orig i0.val hi.val)
    (hsrc_other : SlicePreserved src.val orig other_lo other_hi)
    (hsrc_tail : SlicePreserved src.val orig tail_lo orig.length)
    (hdst : dst.val = dst0.map some)
    (hdst_len : dst0.length + (hi.val - i0.val) ≤ orig.length)
    : WP.spec (CcfKv.engine.merge_runs_loop1 src dst hi i0)
        (fun (src', dst') =>
          SlicePreserved src'.val orig other_lo other_hi
          ∧ SlicePreserved src'.val orig tail_lo orig.length
          ∧ dst'.val = (dst0 ++ subslice orig i0.val hi.val).map some) := by
  unfold CcfKv.engine.merge_runs_loop1
  apply loop.spec_decr_nat
    (fun (p : alloc.vec.Vec (Option SnapshotBatchRow) × alloc.vec.Vec (Option SnapshotBatchRow)
          × Usize) => hi.val - p.2.2.val)
    (fun p =>
      i0.val ≤ p.2.2.val ∧ p.2.2.val ≤ hi.val
      ∧ SlicePreserved p.1.val orig p.2.2.val hi.val
      ∧ SlicePreserved p.1.val orig other_lo other_hi
      ∧ SlicePreserved p.1.val orig tail_lo orig.length
      ∧ p.2.1.val = (dst0 ++ subslice orig i0.val p.2.2.val).map some)
    _ _ _
  · rintro ⟨s, d, i⟩ ⟨hi0, hih, hsi, hso, hst, hd⟩
    dsimp only at hi0 hih hsi hso hst hd ⊢
    unfold CcfKv.engine.merge_runs_loop1.body
    by_cases hlt : i < hi
    · simp only [hlt, ite_true, alloc.vec.Vec.index_mut_slice_index]
      have hi_lt : i.val < hi.val := hlt
      have hi_orig : i.val < orig.length := by omega
      have hi_s : i.val < s.val.length := by rw [hsi.1]; exact hi_orig
      have hget_i : s.val[i.val] = some orig[i.val] := by
        have h := hsi.2 i.val hi_orig (Nat.le_refl _) hi_lt
        rw [List.getElem?_eq_getElem hi_s] at h
        exact Option.some.inj h
      have hd_cap : d.val.length < Usize.max := by
        rw [hd, List.length_map, List.length_append, subslice_length orig hi0 (by omega)]
        omega
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec s i hi_s)
      rintro ⟨o, back⟩ ⟨ho, hback⟩
      rw [ho, hget_i]
      simp only [core.option.Option.take]
      apply WP.spec_bind (alloc.vec.Vec.push_spec d (some orig[i.val]) hd_cap)
      intro d1 hd1
      have hi_add : i.val + (1#usize : Usize).val ≤ Usize.max := by
        change i.val + 1 ≤ Usize.max; omega
      apply WP.spec_bind (Usize.add_spec hi_add)
      intro i1 hi1
      simp only [WP.spec_ok]
      have hi1_val : i1.val = i.val + 1 := hi1
      have hs1_val : (back none).val = s.val.set i.val none := by
        simp [hback]
      refine ⟨⟨by omega, by omega, ?_, ?_, ?_, ?_⟩, by omega⟩
      · rw [hs1_val, hi1_val]
        refine ⟨by simp [hsi.1], fun k hk h1 h2 => ?_⟩
        rw [List.getElem?_set_ne (by omega)]
        exact hsi.2 k hk (by omega) h2
      · rw [hs1_val]
        exact slice_preserved_set_none hso (by omega)
      · rw [hs1_val]
        exact slice_preserved_set_none hst (Or.inl (by omega))
      · rw [hd1, hd, hi1_val, ← subslice_append_elem orig hi0 hi_orig]
        simp [List.append_assoc]
    · simp only [hlt, ite_false, WP.spec_ok]
      have heq : i.val = hi.val := by
        have : hi.val ≤ i.val := Nat.le_of_not_gt hlt
        omega
      rw [heq] at hd
      exact ⟨hso, hst, hd⟩
  · refine ⟨Nat.le_refl _, hord.1, hsrc_i, hsrc_other, hsrc_tail, ?_⟩
    simpa [subslice_nil] using hdst

private theorem merge_runs_loop2_eq_loop1
    (src dst : alloc.vec.Vec (Option SnapshotBatchRow)) (right j : Usize)
    : CcfKv.engine.merge_runs_loop2 src dst right j
      = CcfKv.engine.merge_runs_loop1 src dst right j := rfl

private theorem merge_runs_spec
    (src dst : alloc.vec.Vec (Option SnapshotBatchRow))
    (orig : List SnapshotBatchRow) (dst0 : List SnapshotBatchRow)
    (left mid right : Usize)
    (hord : left.val ≤ mid.val ∧ mid.val ≤ right.val ∧ right.val ≤ orig.length)
    (hcap : orig.length ≤ Usize.max)
    (hsrc : SlicePreserved src.val orig left.val orig.length)
    (hdst : dst.val = dst0.map some)
    (hdst_len : dst0.length + (right.val - left.val) ≤ orig.length)
    : WP.spec (CcfKv.engine.merge_runs src dst left mid right)
        (fun (src', dst') =>
          SlicePreserved src'.val orig right.val orig.length
          ∧ ∃ merged, dst'.val = (dst0 ++ merged).map some
              ∧ merged.Perm (subslice orig left.val right.val)) := by
  unfold CcfKv.engine.merge_runs
  have hsrc_l : SlicePreserved src.val orig left.val mid.val :=
    ⟨hsrc.1, fun k hk h1 h2 => hsrc.2 k hk h1 (by omega)⟩
  have hsrc_r : SlicePreserved src.val orig mid.val right.val :=
    ⟨hsrc.1, fun k hk h1 h2 => hsrc.2 k hk (by omega) (by omega)⟩
  have hsrc_t : SlicePreserved src.val orig right.val orig.length :=
    ⟨hsrc.1, fun k hk h1 h2 => hsrc.2 k hk (by omega) h2⟩
  apply WP.spec_bind
    (merge_runs_loop0_spec src dst orig dst0 left mid right hord hcap hsrc_l hsrc_r hsrc_t hdst
      hdst_len)
  rintro ⟨s1, d1, i1, j1⟩ ⟨hli, him, hmj, hjr, hsl1, hsr1, hst1, taken, hd1, hperm1⟩
  have htaken_len : taken.length = (i1.val - left.val) + (j1.val - mid.val) := by
    rw [hperm1.length_eq, List.length_append,
      subslice_length orig hli (by omega), subslice_length orig hmj (by omega)]
  apply WP.spec_bind
    (merge_runs_drain_spec s1 d1 orig (dst0 ++ taken) i1 mid j1.val right.val right.val
      ⟨him, by omega⟩ hcap (Or.inl (by omega)) (by omega) hsl1 hsr1 hst1 hd1
      (by rw [List.length_append, htaken_len]; omega))
  rintro ⟨s2, d2⟩ ⟨hsr2, hst2, hd2⟩
  change WP.spec (CcfKv.engine.merge_runs_loop1 s2 d2 right j1) _
  apply WP.spec_mono
    (merge_runs_drain_spec s2 d2 orig ((dst0 ++ taken) ++ subslice orig i1.val mid.val) j1 right
      right.val right.val right.val
      ⟨hjr, by omega⟩ hcap (Or.inl (Nat.le_refl _)) (Nat.le_refl _) hsr2
      ⟨hsr2.1, fun _ _ h1 h2 => by omega⟩ hst2 hd2
      (by
        rw [List.length_append, List.length_append, htaken_len,
          subslice_length orig him (by omega)]
        omega))
  rintro ⟨s3, d3⟩ ⟨_, hst3, hd3⟩
  refine ⟨hst3, taken ++ subslice orig i1.val mid.val ++ subslice orig j1.val right.val, ?_, ?_⟩
  · simpa [List.append_assoc] using hd3
  · have hleft := subslice_split orig hli him
    have hright := subslice_split orig hmj hjr
    have hfull := subslice_split orig hord.1 hord.2.1
    refine ((hperm1.append_right _).append_right _).trans ?_
    rw [← hfull, ← hleft, ← hright]
    simp only [List.append_assoc]
    apply List.Perm.append_left
    rw [← List.append_assoc, ← List.append_assoc]
    exact List.Perm.append_right _ List.perm_append_comm

/-- `engine.merge_pass` outputs an all-present permutation of its input batch. -/
theorem merge_pass_spec (src : alloc.vec.Vec (Option SnapshotBatchRow))
    (rows : List SnapshotBatchRow) (width : Usize)
    (owned : src.val = rows.map some) (hpos : 0 < width.val)
    : WP.spec (CcfKv.engine.merge_pass src width)
        (fun dst => ∃ (outRows : List SnapshotBatchRow),
          dst.val = outRows.map some ∧ outRows.Perm rows) := by
  unfold CcfKv.engine.merge_pass CcfKv.engine.merge_pass_loop
  have hlen : (alloc.vec.Vec.len src).val = rows.length := by
    simp [owned]
  have hcap : rows.length ≤ Usize.max := by
    have h := alloc.vec.Vec.len_ineq src
    rw [owned, List.length_map] at h
    exact h
  let n := alloc.vec.Vec.len src
  have hn_val : n.val = rows.length := hlen
  let dst0 := alloc.vec.Vec.with_capacity (Option SnapshotBatchRow) n
  have hdst0 : dst0.val = ([] : List SnapshotBatchRow).map some := by
    simp [dst0, alloc.vec.Vec.with_capacity]
  apply loop.spec_decr_nat
    (fun (p : alloc.vec.Vec (Option SnapshotBatchRow) × alloc.vec.Vec (Option SnapshotBatchRow)
          × Usize) => rows.length - p.2.2.val)
    (fun p =>
      p.2.2.val ≤ rows.length
      ∧ SlicePreserved p.1.val rows p.2.2.val rows.length
      ∧ ∃ (out : List SnapshotBatchRow),
          p.2.1.val = out.map some ∧ out.Perm (subslice rows 0 p.2.2.val))
    _ _ _
  · rintro ⟨s, d, left⟩ ⟨hle, hs, out, hd, hperm⟩
    dsimp only at hle hs hd hperm ⊢
    unfold CcfKv.engine.merge_pass_loop.body
    by_cases hlt : left < n
    · have hl_lt : left.val < rows.length := by rw [← hn_val]; exact hlt
      have hlt' : left < alloc.vec.Vec.len src := hlt
      simp only [hlt', ite_true]
      apply WP.spec_bind (Usize.sub_spec (x := n) (y := left) (by omega))
      intro rem hrem
      have hrem_val : rem.val = rows.length - left.val := by omega
      have hmid_spec : WP.spec
          (if width < rem then left + width else Result.ok n)
          (fun mid => left.val < mid.val ∧ mid.val ≤ rows.length) := by
        by_cases hw : width < rem
        · have hw_val : width.val < rem.val := hw
          simp only [hw, ite_true]
          apply WP.spec_mono (Usize.add_spec (x := left) (y := width) (by omega))
          intro mid hmid
          omega
        · simp only [hw, ite_false, WP.spec_ok]
          omega
      apply WP.spec_bind hmid_spec
      intro mid ⟨hlm, hmn⟩
      apply WP.spec_bind (Usize.sub_spec (x := n) (y := mid) (by omega))
      intro rem2 hrem2
      have hrem2_val : rem2.val = rows.length - mid.val := by omega
      have hright_spec : WP.spec
          (if width < rem2 then mid + width else Result.ok n)
          (fun right => mid.val ≤ right.val ∧ right.val ≤ rows.length) := by
        by_cases hw2 : width < rem2
        · have hw2_val : width.val < rem2.val := hw2
          simp only [hw2, ite_true]
          apply WP.spec_mono (Usize.add_spec (x := mid) (y := width) (by omega))
          intro right hright
          omega
        · simp only [hw2, ite_false, WP.spec_ok]
          omega
      apply WP.spec_bind hright_spec
      intro right ⟨hmr, hrn⟩
      have hout_len : out.length = left.val := by
        rw [hperm.length_eq, subslice_length rows (Nat.zero_le _) hle]
        omega
      apply WP.spec_bind
        (merge_runs_spec s d rows out left mid right ⟨by omega, hmr, hrn⟩ hcap hs hd
          (by omega))
      rintro ⟨s1, d1⟩ ⟨hs1, merged, hd1, hmerged⟩
      change WP.spec (Result.ok _) _
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨hrn, hs1, out ++ merged, hd1, ?_⟩, by omega⟩
      rw [← subslice_split rows (Nat.zero_le left.val) (by omega)]
      exact hperm.append hmerged
    · have hlt' : ¬ left < alloc.vec.Vec.len src := hlt
      rw [ite_eq_right hlt', WP.spec_ok]
      have hl_eq : left.val = rows.length := by
        have : rows.length ≤ left.val := by rw [← hlen]; exact Nat.le_of_not_gt hlt
        omega
      rw [hl_eq, subslice_full] at hperm
      exact ⟨out, hd, hperm⟩
  · refine ⟨Nat.zero_le _, ?_, [], hdst0, by simp [subslice_nil]⟩
    refine ⟨by rw [owned, List.length_map], fun k hk _ _ => ?_⟩
    rw [owned, List.getElem?_map, List.getElem?_eq_getElem hk]
    rfl

/-- `engine.sort_and_check_unique_batch` always terminates on all-present rows, and whenever
    it succeeds with `some sorted`, `sorted` is an all-present permutation of `rows` in strictly
    ascending packed byte-key order. -/
theorem sort_and_check_unique_batch_spec
    (batch : alloc.vec.Vec (Option SnapshotBatchRow))
    (rows : List SnapshotBatchRow) (owned : batch.val = rows.map some)
    : WP.spec (CcfKv.engine.sort_and_check_unique_batch batch)
        (fun res =>
          match res with
          | none => True
          | some out =>
              ∃ (outRows : List SnapshotBatchRow),
                out.val = outRows.map some
                ∧ outRows.Perm rows
                ∧ outRows.Pairwise (fun a b => a.key.val < b.key.val)) := by
  unfold CcfKv.engine.sort_and_check_unique_batch
  have hlen : (alloc.vec.Vec.len batch).val = rows.length := by
    simp [owned]
  have hcap : rows.length ≤ Usize.max := by
    have h := alloc.vec.Vec.len_ineq batch
    rw [owned, List.length_map] at h
    exact h
  by_cases hsmall : alloc.vec.Vec.len batch ≤ 1#usize
  · simp only [hsmall, ite_true, WP.spec_ok]
    refine ⟨rows, owned, List.Perm.refl _, ?_⟩
    have hle1 : rows.length ≤ 1 := by
      rw [← hlen]
      exact hsmall
    cases rows with
    | nil => exact List.Pairwise.nil
    | cons x xs =>
        cases xs with
        | nil => exact List.Pairwise.cons (by simp) List.Pairwise.nil
        | cons _ _ => simp at hle1
  · simp only [hsmall, ite_false]
    apply WP.spec_bind
      (batch_order_state_spec (alloc.vec.Vec.deref batch) rows
        (by simpa [alloc.vec.Vec.deref] using owned))
    intro initial hinit
    by_cases hsorted : initial = (-1)#i8
    · simp only [hsorted, ite_true, WP.spec_ok]
      exact ⟨rows, owned, List.Perm.refl _, hinit hsorted⟩
    · simp only [hsorted, ite_false]
      by_cases hdup : initial = 0#i8
      · simp only [hdup, ite_true, WP.spec_ok]
      · simp only [hdup, ite_false]
        let n := alloc.vec.Vec.len batch
        have hn_val : n.val = rows.length := hlen
        have hloop_spec : WP.spec
            (CcfKv.engine.sort_and_check_unique_batch_loop n batch 1#usize)
            (fun sorted => ∃ (outRows : List SnapshotBatchRow),
              sorted.val = outRows.map some ∧ outRows.Perm rows) := by
          unfold CcfKv.engine.sort_and_check_unique_batch_loop
          apply loop.spec_decr_nat
            (fun (p : alloc.vec.Vec (Option SnapshotBatchRow) × Usize) => rows.length - p.2.val)
            (fun p => 0 < p.2.val ∧ p.2.val ≤ rows.length
              ∧ ∃ (curRows : List SnapshotBatchRow),
                  p.1.val = curRows.map some ∧ curRows.Perm rows)
            _ _ _
          · rintro ⟨cur, width⟩ ⟨hwpos, hwle, curRows, hcur, hcurPerm⟩
            dsimp only at hwpos hwle hcur hcurPerm ⊢
            unfold CcfKv.engine.sort_and_check_unique_batch_loop.body
            by_cases hwlt : width < n
            · simp only [hwlt, ite_true]
              apply WP.spec_bind (merge_pass_spec cur curRows width hcur hwpos)
              intro next ⟨nextRows, hnext, hnextPerm⟩
              have hw_lt : width.val < rows.length := by rw [← hn_val]; exact hwlt
              apply WP.spec_bind (Usize.sub_spec (x := n) (y := width) (by omega))
              intro rem hrem
              have hrem_val : rem.val = rows.length - width.val := by omega
              by_cases hover : width > rem
              · simp only [hover, ite_true, WP.spec_ok]
                refine ⟨⟨by omega, by omega, nextRows, hnext, hnextPerm.trans hcurPerm⟩,
                  by omega⟩
              · simp only [hover, ite_false]
                have hle_rem : width.val ≤ rem.val := Nat.le_of_not_gt hover
                apply WP.spec_bind (Usize.add_spec (x := width) (y := width) (by omega))
                intro w2 hw2
                simp only [WP.spec_ok]
                refine ⟨⟨by omega, by omega, nextRows, hnext, hnextPerm.trans hcurPerm⟩,
                  by omega⟩
            · simp only [hwlt, ite_false, WP.spec_ok]
              exact ⟨curRows, hcur, hcurPerm⟩
          · dsimp only
            have hone : (1#usize : Usize).val = 1 := rfl
            have hgt1 : 1 < rows.length := by
              rw [← hlen]
              exact Nat.lt_of_not_ge hsmall
            refine ⟨by omega, by omega, rows, owned, List.Perm.refl _⟩
        apply WP.spec_bind hloop_spec
        intro sorted ⟨outRows, hout, hperm⟩
        apply WP.spec_bind
          (batch_order_state_spec (alloc.vec.Vec.deref sorted) outRows
            (by simpa [alloc.vec.Vec.deref] using hout))
        intro ord hord
        by_cases hok : ord = (-1)#i8
        · simp only [hok, ite_true, WP.spec_ok]
          exact ⟨outRows, hout, hperm, hord hok⟩
        · simp only [hok, ite_false, WP.spec_ok]

end KvRust
