-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs
public import Kv.Model

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

private theorem index_loop {K V : Type} [DecidableEq K] (eq : Spike.engine.Key K)
    (rows : Spike.engine.Assoc K V) (key : K)
    (heq : ∀ k, eq.same k key = .ok (decide (k = key)))
    : WP.spec (Spike.engine.Assoc.index eq rows key)
        (fun
          | none => find rows.val key = none
          | some i =>
              ∃ v, rows.val[i.val]? = some (key, v) ∧ find rows.val key = some v) := by
  unfold Spike.engine.Assoc.index Spike.engine.Assoc.index_loop
  apply loop.spec_decr_nat
    (fun (p : Spike.engine.Assoc K V × Usize) => rows.val.length - p.2.val)
    (fun p => p.1 = rows ∧ find (rows.val.drop p.2.val) key = find rows.val key)
    _ _ _
  · rintro ⟨xs, i⟩ ⟨hrows, hinv⟩
    dsimp only at hrows hinv ⊢
    subst xs
    have hlen := alloc.vec.Vec.len_ineq rows
    have hone : (1#usize : Usize).val = 1 := rfl
    unfold Spike.engine.Assoc.index_loop.body
    have hlenval : (alloc.vec.Vec.len rows).val = rows.val.length :=
      alloc.vec.Vec.len_val rows
    by_cases h : i.val < rows.val.length
    · have hb : i < alloc.vec.Vec.len rows := by
        change i.val < (alloc.vec.Vec.len rows).val
        rwa [hlenval]
      rw [ite_eq_left hb, alloc.vec.Vec.index_slice_index]
      have hdrop := List.drop_eq_getElem_cons (l := rows.val) h
      have hnext : i.val + (1#usize : Usize).val ≤ Usize.max := by omega
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec rows i h)
      intro row hrow
      obtain ⟨k, v⟩ := row
      change WP.spec (do
        let b ← eq.same k key
        if b then Result.ok (ControlFlow.done (some i))
        else
          let next ← i + 1#usize
          Result.ok (ControlFlow.cont (rows, next))) _
      simp only [heq k, bind_ok]
      by_cases hk : k = key
      · subst k
        simp only [decide_true, ite_true, WP.spec_ok]
        refine ⟨v, ?_, ?_⟩
        · rw [List.getElem?_eq_getElem h, ← hrow]
        · rw [← hinv, hdrop, ← hrow]
          simp [find]
      · simp only [decide_eq_false hk, Bool.false_eq_true, ite_false]
        apply WP.spec_bind (Usize.add_spec hnext)
        intro next hnextval
        simp only [WP.spec_ok]
        refine ⟨⟨True.intro, ?_⟩, ?_⟩
        · have hidx : next.val = i.val + 1 := by omega
          rw [hidx, ← hinv, hdrop, ← hrow]
          simp [find, hk]
        · omega
    · have hb : ¬i < alloc.vec.Vec.len rows := by
        change ¬i.val < (alloc.vec.Vec.len rows).val
        rwa [hlenval]
      rw [ite_eq_right hb, WP.spec_ok]
      rw [← hinv, List.drop_eq_nil_of_le (Nat.le_of_not_gt h)]
      rfl
  · simp

/-- An extracted lookup returns the first model binding for any finite association list. -/
theorem assoc_get {K V : Type} [DecidableEq K] (eq : Spike.engine.Key K)
    (ck : core.clone.Clone K) (cv : core.clone.Clone V)
    (rows : Spike.engine.Assoc K V) (key : K)
    (heq : ∀ k, eq.same k key = .ok (decide (k = key)))
    (hclone : ∀ v, cv.clone v = .ok v)
    : WP.spec (Spike.engine.Assoc.get eq ck cv rows key)
        (fun r => r = find rows.val key) := by
  unfold Spike.engine.Assoc.get
  apply WP.spec_bind (index_loop eq rows key heq)
  rintro (_ | i) h
  · simpa using h.symm
  · obtain ⟨v, hget, hfind⟩ := h
    simp [alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_usize, hget, hfind, hclone]

end KvRust
