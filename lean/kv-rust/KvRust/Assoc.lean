-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs
public import Kv.Model

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- The extracted index search locates the same first binding as model lookup. -/
theorem assoc_index {K V : Type} [DecidableEq K] (eq : Spike.engine.Key K)
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
  apply WP.spec_bind (assoc_index eq rows key heq)
  rintro (_ | i) h
  · simpa using h.symm
  · obtain ⟨v, hget, hfind⟩ := h
    simp [alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_usize, hget, hfind, hclone]

private theorem copy_row {K V : Type} [DecidableEq K] (eq : Spike.engine.Key K)
    (ck : core.clone.Clone K) (cv : core.clone.Clone V)
    (out : alloc.vec.Vec (K × V)) (row : K × V) (key : K)
    (heq : ∀ k, eq.same k key = .ok (decide (k = key)))
    (hck : ∀ k, ck.clone k = .ok k) (hcv : ∀ v, cv.clone v = .ok v)
    (hcap : out.val.length < Usize.max)
    : WP.spec (Spike.engine.copy_if_different eq ck cv out row key)
        (fun r => r.val = out.val ++ erase [row] key) := by
  obtain ⟨k, v⟩ := row
  unfold Spike.engine.copy_if_different
  change WP.spec (do
    let same ← eq.same k key
    if same then Result.ok out
    else
      let x ← ck.clone k
      let y ← cv.clone v
      alloc.vec.Vec.push out (x, y)) _
  by_cases hk : k = key
  · simp [heq, hk, erase]
  · simpa [heq, hk, hck, hcv, erase] using alloc.vec.Vec.push_spec out (k, v) hcap

private theorem copy_other {K V : Type} [DecidableEq K] (eq : Spike.engine.Key K)
    (ck : core.clone.Clone K) (cv : core.clone.Clone V)
    (rows : Spike.engine.Assoc K V) (key : K) (initial : alloc.vec.Vec (K × V))
    (heq : ∀ k, eq.same k key = .ok (decide (k = key)))
    (hck : ∀ k, ck.clone k = .ok k) (hcv : ∀ v, cv.clone v = .ok v)
    (hcap : initial.val.length + rows.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.Assoc.copy_other_rows eq ck cv rows key initial)
        (fun r => r.val = initial.val ++ erase rows.val key) := by
  unfold Spike.engine.Assoc.copy_other_rows Spike.engine.Assoc.copy_other_rows_loop
  apply loop.spec_decr_nat
    (fun (p : Spike.engine.Assoc K V × alloc.vec.Vec (K × V) × Usize) =>
      rows.val.length - p.2.2.val)
    (fun p =>
      p.1 = rows
      ∧ p.2.2.val ≤ rows.val.length
      ∧ p.2.1.val ++ erase (rows.val.drop p.2.2.val) key
        = initial.val ++ erase rows.val key
      ∧ p.2.1.val.length + (rows.val.length - p.2.2.val) ≤ Usize.max)
    _ _ _
  · rintro ⟨xs, out, i⟩ ⟨hrows, hi, hacc, hsize⟩
    dsimp only at hrows hi hacc hsize ⊢
    subst xs
    unfold Spike.engine.Assoc.copy_other_rows_loop.body
    have hlen := alloc.vec.Vec.len_val rows
    have hbound := alloc.vec.Vec.len_ineq rows
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i.val < rows.val.length
    · have hb : i < alloc.vec.Vec.len rows := by
        change i.val < (alloc.vec.Vec.len rows).val
        rwa [hlen]
      rw [ite_eq_left hb, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec rows i h)
      intro row hrow
      apply WP.spec_bind (copy_row eq ck cv out row key heq hck hcv (by omega))
      intro next hnext
      have hidx : i.val + (1#usize : Usize).val ≤ Usize.max := by omega
      apply WP.spec_bind (Usize.add_spec hidx)
      intro j hj
      have hj' : j.val = i.val + 1 := by omega
      simp only [WP.spec_ok]
      refine ⟨⟨True.intro, by omega, ?_, ?_⟩, by omega⟩
      ·
        rw [hj', hnext, List.append_assoc, ← hacc, List.drop_eq_getElem_cons h, ← hrow]
        apply congrArg (out.val ++ ·)
        symm
        exact List.filter_append [row] (rows.val.drop (i.val + 1))
      · have hfiltered := List.length_filter_le (p := fun (r : K × V) => r.1 != key) [row]
        have hh : (erase [row] key).length ≤ 1 := by simpa [erase] using hfiltered
        rw [hnext, List.length_append]
        omega
    · have hb : ¬ i < alloc.vec.Vec.len rows := by
        change ¬i.val < (alloc.vec.Vec.len rows).val
        rwa [hlen]
      rw [ite_eq_right hb, WP.spec_ok]
      simpa [List.drop_eq_nil_of_le (Nat.le_of_not_gt h), erase] using hacc
  · simpa using hcap

/-- Extracted erasure removes all matches and preserves the order of the remaining rows. -/
theorem assoc_erase {K V : Type} [DecidableEq K] (eq : Spike.engine.Key K)
    (ck : core.clone.Clone K) (cv : core.clone.Clone V)
    (rows : Spike.engine.Assoc K V) (key : K)
    (heq : ∀ k, eq.same k key = .ok (decide (k = key)))
    (hck : ∀ k, ck.clone k = .ok k) (hcv : ∀ v, cv.clone v = .ok v)
    : WP.spec (Spike.engine.Assoc.erase eq ck cv rows key)
        (fun r => r.val = erase rows.val key) := by
  unfold Spike.engine.Assoc.erase
  apply WP.spec_bind
    (copy_other eq ck cv rows key (alloc.vec.Vec.new _) heq hck hcv (by simp))
  intro out hout
  simpa using hout

/-- Extracted replacement prepends the new binding and removes all older bindings for that key. -/
theorem assoc_set {K V : Type} [DecidableEq K] (eq : Spike.engine.Key K)
    (ck : core.clone.Clone K) (cv : core.clone.Clone V)
    (rows : Spike.engine.Assoc K V) (key : K) (value : V)
    (heq : ∀ k, eq.same k key = .ok (decide (k = key)))
    (hck : ∀ k, ck.clone k = .ok k) (hcv : ∀ v, cv.clone v = .ok v)
    (hcap : rows.val.length < Usize.max)
    : WP.spec (Spike.engine.Assoc.set eq ck cv rows key value)
        (fun r => r.val = set rows.val key value) := by
  unfold Spike.engine.Assoc.set
  simp only [hck, bind_ok]
  have hstart : (alloc.vec.Vec.new (K × V)).val.length < Usize.max := by
    simpa using Nat.zero_lt_of_lt hcap
  apply WP.spec_bind (alloc.vec.Vec.push_spec (alloc.vec.Vec.new _) (key, value) hstart)
  intro next hnext
  have hrows : next.val.length + rows.val.length ≤ Usize.max := by
    simpa [hnext, Nat.add_comm] using Nat.succ_le_of_lt hcap
  apply WP.spec_bind (copy_other eq ck cv rows key next heq hck hcv hrows)
  intro out hout
  simpa [hnext, Kv.Model.set] using hout

/-- A key-preserving projection commutes with association-list lookup. -/
theorem find_projected {K V K' V' : Type} [DecidableEq K] [DecidableEq K']
    (rows : Kv.Model.Assoc K V) (key : K) (keyOf : K → K') (valueOf : V → V')
    (injective : Function.Injective keyOf)
    : find (rows.map fun (k, v) => (keyOf k, valueOf v)) (keyOf key)
      = (find rows key).map valueOf := by
  induction rows with
  | nil => rfl
  | cons row rows ih =>
      obtain ⟨k, v⟩ := row
      by_cases h : k = key
      · subst k
        simp [find]
      · have hn : keyOf k ≠ keyOf key := fun h' => h (injective h')
        simp [find, h, hn, ih]

/-- Injective key projection commutes with erasure. -/
theorem erase_projected {K V K' V' : Type} [DecidableEq K] [DecidableEq K']
    (rows : Kv.Model.Assoc K V) (key : K) (keyOf : K → K') (valueOf : V → V')
    (injective : Function.Injective keyOf)
    : erase (rows.map fun (k, v) => (keyOf k, valueOf v)) (keyOf key)
      = (erase rows key).map (fun (k, v) => (keyOf k, valueOf v)) := by
  induction rows with
  | nil => rfl
  | cons row rows ih =>
      obtain ⟨k, v⟩ := row
      by_cases h : k = key
      · subst k
        simpa [erase] using ih
      · have hn : keyOf k ≠ keyOf key := fun h' => h (injective h')
        simp only [erase, List.map_cons, List.filter_cons] at ih ⊢
        simp [h, hn, ih]

/-- Injective key projection commutes with replacement. -/
theorem set_projected {K V K' V' : Type} [DecidableEq K] [DecidableEq K']
    (rows : Kv.Model.Assoc K V) (key : K) (value : V)
    (keyOf : K → K') (valueOf : V → V') (injective : Function.Injective keyOf)
    : Kv.Model.set (rows.map fun (k, v) => (keyOf k, valueOf v)) (keyOf key)
        (valueOf value)
      = (Kv.Model.set rows key value).map (fun (k, v) => (keyOf k, valueOf v)) := by
  simp only [Kv.Model.set, List.map_cons, erase_projected rows key keyOf valueOf injective]

/-- Erase removes precisely the selected lookup binding. -/
theorem find_erase_key {K V : Type} [DecidableEq K] (rows : Kv.Model.Assoc K V) (k q : K)
    : find (erase rows k) q = if q = k then none else find rows q := by
  by_cases he : q = k
  · subst q
    induction rows with
    | nil => simp [erase, find]
    | cons row rest ih =>
        obtain ⟨a, v⟩ := row
        by_cases h : a = k <;> simp_all [erase, find]
  · induction rows with
    | nil => simp [he, erase, find]
    | cons row rest ih =>
        obtain ⟨a, v⟩ := row
        by_cases h : a = k <;> by_cases hq : a = q <;> simp_all [erase, find]

/-- Set replaces the selected lookup binding without affecting other keys. -/
theorem find_set_key {K V : Type} [DecidableEq K] (rows : Kv.Model.Assoc K V) (k q : K)
    (v : V)
    : find (Kv.Model.set rows k v) q = if q = k then some v else find rows q := by
  by_cases he : q = k
  · subst q
    simp [Kv.Model.set, find]
  · simp [Kv.Model.set, find, he, Ne.symm he, find_erase_key]

private theorem lookup_missing_of_not_mem {K V : Type} [DecidableEq K]
    (rows : Kv.Model.Assoc K V) (k : K) (h : k ∉ rows.map Prod.fst)
    : find rows k = none := by
  induction rows with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨a, v⟩ := row
      have hk : k ≠ a := fun he => h (by simp [he])
      have ht : k ∉ rest.map Prod.fst := fun hm => h (by simp [hm])
      simp [find, Ne.symm hk, ih ht]

/-- A native in-place update agrees with the model's association-list replacement on lookups. -/
theorem find_index_update {K V : Type} [DecidableEq K] (rows : Kv.Model.Assoc K V)
    (i : Nat) (k q : K) (old next : V)
    (h : rows[i]? = some (k, old)) (unique : (rows.map Prod.fst).Nodup)
    : find (rows.set i (k, next)) q = find (Kv.Model.set rows k next) q := by
  rw [find_set_key]
  induction rows generalizing i with
  | nil => simp at h
  | cons row rest ih =>
      obtain ⟨a, v⟩ := row
      cases i with
      | zero =>
          have he : (a, v) = (k, old) := by simpa using h
          have hak := congrArg Prod.fst he
          change a = k at hak
          subst a
          by_cases hk : q = k
          · subst q
            simp [find]
          · simp [find, hk, Ne.symm hk]
      | succ i =>
          have hn : a ∉ rest.map Prod.fst ∧ (rest.map Prod.fst).Nodup :=
            List.nodup_cons.mp unique
          have hr : rest[i]? = some (k, old) := h
          have hak : a ≠ k := by
            intro he
            have mem : (k, old) ∈ rest := List.mem_of_getElem? hr
            apply hn.1
            rw [he]
            exact List.mem_map.mpr ⟨_, mem, rfl⟩
          by_cases ha : a = q
          · have hq : q ≠ k := ha ▸ hak
            simp [find, ha, hq]
          · simp [find, ha, ih i hr hn.2]

/-- A native in-place update preserves the sequence of keys. -/
theorem index_update_keys {K V : Type} (rows : Kv.Model.Assoc K V) (i : Nat)
    (k : K) (old next : V) (h : rows[i]? = some (k, old))
    : (rows.set i (k, next)).map Prod.fst = rows.map Prod.fst := by
  obtain ⟨hidx, he⟩ := List.getElem?_eq_some_iff.mp h
  rw [List.map_set]
  have hm : i < (rows.map Prod.fst).length := by simpa using hidx
  have hk : (rows.map Prod.fst)[i] = k := by
    rw [List.getElem_map, he]
  rw [← hk]
  exact List.set_getElem_self hm

end KvRust
