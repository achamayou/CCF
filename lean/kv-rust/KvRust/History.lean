-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs
public import Kv.Model

import all Aeneas.Data.List.List

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

private theorem returning {α : Type} {r : Result α} {p : α → Prop} (h : WP.spec r p)
    : ∃ v, r = .ok v ∧ p v := by
  cases r using Result.cases with
  | ret v => exact ⟨v, rfl, by simpa using h⟩
  | vis _ _ => simp at h
  | div => simp at h

/-- The history vector is the model's history in reverse chronological order. -/
def modelFrames (s : Spike.engine.History) (project : Spike.engine.Frame → Frame)
    : List Frame :=
  s.frames.val.reverse.map project

private theorem filter_is_take {α : Type} (xs : List α) (p : α → Bool) (n : Nat)
    (h : ∀ i (hi : i < xs.length), p xs[i] = decide (i < n))
    : xs.filter p = xs.take n := by
  induction xs generalizing n with
  | nil => simp
  | cons x xs ih =>
      have hhead := h 0 (by simp)
      change p x = decide (0 < n) at hhead
      cases n with
      | zero =>
          have htail : ∀ i (hi : i < xs.length), p xs[i] = decide (i < 0) := by
            intro i hi
            have he := h (i + 1) (by simp; omega)
            change p xs[i] = decide (i + 1 < 0) at he
            simpa using he
          simp [hhead, ih 0 htail]
      | succ n =>
          have htail : ∀ i (hi : i < xs.length), p xs[i] = decide (i < n) := by
            intro i hi
            have he := h (i + 1) (by simp; omega)
            change p xs[i] = decide (i + 1 < n + 1) at he
            simpa using he
          simp [hhead, ih n htail]

/-- Both implementations compute the same compaction cut, including backward and above-head requests. -/
theorem compact_cut_model (global head requested : U64) (s : Store)
    (hg : s.global = global.val) (hh : s.head.version = head.val)
    : (do
        let result ← Spike.engine.compact_cut global head requested
        Result.ok result.val)
      = .ok (compactStore s requested.val).global := by
  simp only [Spike.engine.compact_cut, compactStore, hg, hh]
  by_cases hhead : requested.val ≤ head.val
  · by_cases hglobal : global.val < requested.val
    · simp [hhead, hglobal, Nat.max_eq_right (Nat.le_of_lt hglobal)]
    · simp [hhead, hglobal, Nat.max_eq_left (Nat.le_of_not_gt hglobal)]
  · simp [hhead, hg]

/-- Both implementations compute the same rollback cut for every representable request. -/
theorem rollback_cut_model (global head requested : U64) (s : Store)
    (hg : s.global = global.val) (hh : s.head.version = head.val)
    : (do
        let result ← Spike.engine.rollback_cut global head requested
        Result.ok result.val)
      = .ok (rollbackCut s requested.val) := by
  simp only [Spike.engine.rollback_cut, rollbackCut, hg, hh]
  by_cases hhead : requested.val < head.val
  · by_cases hglobal : global.val < requested.val
    · simp [hhead, hglobal, Nat.min_eq_right (Nat.le_of_lt hhead),
        Nat.max_eq_right (Nat.le_of_lt hglobal)]
    · simp [hhead, hglobal, Nat.min_eq_right (Nat.le_of_lt hhead),
        Nat.max_eq_left (Nat.le_of_not_gt hglobal)]
  · by_cases hglobal : global.val < head.val
    · simp [hhead, hglobal, Nat.min_eq_left (Nat.le_of_not_gt hhead),
        Nat.max_eq_right (Nat.le_of_lt hglobal)]
    · simp [hhead, hglobal, Nat.min_eq_left (Nat.le_of_not_gt hhead),
        Nat.max_eq_left (Nat.le_of_not_gt hglobal)]

/-- The extracted head lookup returns the last frame of the oldest-first vector. -/
theorem history_head (history : Spike.engine.History) (prior : List Spike.engine.Frame)
    (head : Spike.engine.Frame) (h : history.frames.val = prior ++ [head])
    : Spike.engine.History.head history = .ok head := by
  have hlen : (alloc.vec.Vec.len history.frames).val = prior.length + 1 := by
    simp [h]
  obtain ⟨i, hi, hidx⟩ := returning
    (Usize.sub_spec (x := alloc.vec.Vec.len history.frames) (y := 1#usize) (by simp [hlen]))
  have hone : (1#usize : Usize).val = 1 := rfl
  have hi' : i.val = prior.length := by omega
  simp only [Spike.engine.History.head, hi, bind_ok, alloc.vec.Vec.index_slice_index,
    alloc.vec.Vec.index_usize]
  rw [alloc.vec.Vec.getElem?_Nat_eq, h, hi']
  simp

/-- For histories generated from the model's initial state, cut offsets are absolute. -/
theorem history_relative_cut_zero (s : Spike.engine.History) (cut : U64)
    (hNonempty : s.frames.val ≠ [])
    (hIndexed : ∀ i (hi : i < s.frames.val.length), s.frames.val[i].version.val = i)
    : Spike.engine.History.relative_cut s cut = .ok cut := by
  have hb : 0 < s.frames.val.length := List.length_pos_iff.mpr hNonempty
  have hBase := hIndexed 0 hb
  have hRead : s.frames.val[0]? = some s.frames.val[0] := List.getElem?_eq_getElem hb
  have hZero : s.frames.val[0].version = 0#u64 := UScalar.eq_of_val_eq hBase
  simp [Spike.engine.History.relative_cut, alloc.vec.Vec.index_slice_index,
    alloc.vec.Vec.index_usize, alloc.vec.Vec.getElem?_Nat_eq, hRead, hZero]
  obtain ⟨offset, hr, hv⟩ := returning
    (U64.sub_spec (x := cut) (y := 0#u64) (by scalar_tac))
  have he : offset = cut := UScalar.eq_of_val_eq (by simpa using hv)
  simpa [he] using hr

/-- With a zero base, the extracted cut lookup clamps to the last retained vector index. -/
theorem history_at_cut_index (s : Spike.engine.History) (cut : U64)
    (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hframes : s.frames.val = prior ++ [head])
    (hzero : Spike.engine.History.relative_cut s cut = .ok cut)
    : WP.spec (Spike.engine.History.at_cut s cut)
        (fun f => s.frames.val[min cut.val prior.length]? = some f) := by
  have hlen : (alloc.vec.Vec.len s.frames).val = prior.length + 1 := by simp [hframes]
  have hone : (1#usize : Usize).val = 1 := rfl
  have hsize : s.frames.val.length = prior.length + 1 := by simp [hframes]
  have hbounded := alloc.vec.Vec.len_ineq s.frames
  unfold Spike.engine.History.at_cut
  simp only [hzero, bind_ok]
  apply WP.spec_bind
    (Usize.sub_spec (x := alloc.vec.Vec.len s.frames) (y := 1#usize) (by omega))
  intro i hi
  have hi' : i.val = prior.length := by omega
  let head64 := UScalar.cast .U64 i
  have hcast : head64.val = prior.length := by
    rw [show head64.val = i.val from UScalar.cast_val_mod_pow_greater_numBits_eq .U64 i
      (by
        simp only [UScalarTy.Usize_numBits_eq, UScalarTy.U64_numBits_eq]
        rcases System.Platform.numBits_eq with h | h <;> simp [h]), hi']
  simp only [lift, bind_ok, alloc.vec.Vec.index_slice_index]
  by_cases hcut : cut < head64
  · have hn : cut.val < prior.length := by
      change cut.val < head64.val at hcut
      omega
    have hc : (UScalar.cast .Usize cut).val = cut.val := by
      apply UScalar.cast_val_mod_pow_of_inBounds_eq
      rw [← UScalar.max_USize_eq, UScalar.max] at hbounded
      have := Nat.two_pow_pos UScalarTy.Usize.numBits
      omega
    rw [ite_eq_left hcut]
    apply WP.spec_mono (alloc.vec.Vec.index_usize_spec s.frames (UScalar.cast .Usize cut)
      (by change (UScalar.cast .Usize cut).val < s.frames.val.length; omega))
    intro f hf
    rw [Nat.min_eq_left (Nat.le_of_lt hn), ← hc, List.getElem?_eq_getElem (by omega)]
    exact congrArg some hf.symm
  · have hn : prior.length ≤ cut.val := by
      change ¬cut.val < head64.val at hcut
      omega
    rw [ite_eq_right hcut]
    apply WP.spec_mono (alloc.vec.Vec.index_usize_spec s.frames i
      (by change i.val < s.frames.val.length; omega))
    intro f hf
    rw [Nat.min_eq_right hn, ← hi', List.getElem?_eq_getElem (by omega)]
    exact congrArg some hf.symm

private theorem find_reverse_indexed {α : Type} (xs : List α) (project : α → Frame)
    (cut : Nat) (hversions : ∀ i (hi : i < xs.length), (project xs[i]).version = i)
    : ((xs.reverse.map project).find? fun f => decide (f.version ≤ cut))
      = xs[min cut (xs.length - 1)]?.map project := by
  induction xs using List.reverseRecOn with
  | nil => simp
  | append_singleton prior last ih =>
      have hlast : (project last).version = prior.length := by
        have ht := hversions prior.length (by simp)
        rw [List.getElem_append_right (Nat.le_refl _)] at ht
        simpa using ht
      have hprior : ∀ i (hi : i < prior.length), (project prior[i]).version = i := by
        intro i hi
        have ht := hversions i (by simp; omega)
        rwa [List.getElem_append_left hi] at ht
      simp only [List.reverse_append, List.reverse_singleton, List.singleton_append,
        List.map_cons, List.find?_cons, hlast, List.length_append, List.length_singleton,
        Nat.add_sub_cancel]
      by_cases hc : prior.length ≤ cut
      · simp [hc]
      · have hi' : cut < prior.length := Nat.lt_of_not_ge hc
        have hmin : cut ≤ prior.length - 1 := by omega
        simp only [hc, decide_false, Nat.min_eq_left (Nat.le_of_lt hi'),
          List.getElem?_append_left hi']
        simpa only [Nat.min_eq_left hmin] using ih hprior

/-- Indexed Rust lookup and the model's search of the current branch select the same frame. -/
theorem history_at_cut_matches_model (s : Spike.engine.History) (cut : U64)
    (model : Store) (project : Spike.engine.Frame → Frame)
    (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hframes : s.frames.val = prior ++ [head])
    (hmodel : model.history = modelFrames s project)
    (hzero : Spike.engine.History.relative_cut s cut = .ok cut)
    (hversions
      : ∀ i (hi : i < s.frames.val.length), (project s.frames.val[i]).version = i)
    : WP.spec (Spike.engine.History.at_cut s cut)
        (fun f => project f = atCut model cut.val ∧ project f ∈ model.history) := by
  apply WP.spec_mono (history_at_cut_index s cut prior head hframes hzero)
  intro f hf
  have hlen : s.frames.val.length - 1 = prior.length := by simp [hframes]
  have he : model.history.find? (fun fr => decide (fr.version ≤ cut.val)) = some (project f) := by
    rw [hmodel, modelFrames, find_reverse_indexed _ project _ hversions, hlen, hf]
    rfl
  exact ⟨by simp [atCut, he], List.mem_of_find?_eq_some he⟩

/-- The version of the selected reference frame is the cut clamped to the surviving branch. -/
theorem model_cut_version (s : Spike.engine.History) (model : Store)
    (project : Spike.engine.Frame → Frame)
    (nonempty : s.frames.val ≠ [])
    (hmodel : model.history = modelFrames s project)
    (indexed : ∀ i (hi : i < s.frames.val.length), (project s.frames.val[i]).version = i)
    (cut : Nat)
    : (atCut model cut).version = min cut (s.frames.val.length - 1) := by
  have hlen : 0 < s.frames.val.length := List.length_pos_iff.mpr nonempty
  have hi : min cut (s.frames.val.length - 1) < s.frames.val.length := by omega
  rw [atCut, hmodel, modelFrames, find_reverse_indexed _ _ _ indexed,
    List.getElem?_eq_getElem hi]
  exact indexed _ hi

/-- Compaction preserves the frames, term and identity counter, and matches the model's frontier. -/
theorem history_compact (s : Spike.engine.History) (requested : U64)
    (model : Store) (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hframes : s.frames.val = prior ++ [head]) (hg : model.global = s.global.val)
    (hh : model.head.version = head.version.val)
    : ∃ cut,
        Spike.engine.History.compact s requested = .ok (cut, {s with global := cut})
        ∧ cut.val = (compactStore model requested.val).global := by
  have hcut := compact_cut_model s.global head.version requested model hg hh
  rw [Spike.engine.History.compact, history_head s prior head hframes]
  cases h : Spike.engine.compact_cut s.global head.version requested
    using Result.cases with
  | ret cut =>
      exact ⟨cut, by simp [h], by simpa [h] using hcut⟩
  | vis _ _ => simp [h] at hcut
  | div => simp [h] at hcut

/-- A request below the irrevocable cut reports rejection and leaves the entire Rust store unchanged. -/
theorem rollback_rejected (s : Spike.engine.Store) (requested term : U64)
    (h : requested.val < s.history.global.val)
    : Spike.engine.Store.execute s (.Rollback requested term)
      = .ok (.Ok .RollbackRejected, s) := by
  simp [Spike.engine.Store.execute, Spike.engine.History.rollback, h]

/-- A request at or above the cut with a stale term is disabled without changing the store. -/
theorem rollback_stale_term (s : Spike.engine.Store) (requested term : U64)
    (hcut : s.history.global.val ≤ requested.val) (hterm : term.val < s.history.term.val)
    : Spike.engine.Store.execute s (.Rollback requested term)
      = .ok (.Err .Disabled, s) := by
  simp [Spike.engine.Store.execute, Spike.engine.History.rollback, Nat.not_lt.mpr hcut, hterm]

/-- A legal rollback keeps exactly the prefix through the cut and does not reuse identities. -/
theorem history_rollback (s : Spike.engine.History) (requested term : U64)
    (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hframes : s.frames.val = prior ++ [head]) (hindex : head.version.val = prior.length)
    (hzero : ∀ cut, Spike.engine.History.relative_cut s cut = .ok cut)
    (hcut : s.global.val ≤ requested.val) (hterm : s.term.val ≤ term.val)
    : ∃ cut after,
        Spike.engine.History.rollback s requested term
          = .ok (.Ok (.RolledBack cut), after)
        ∧ cut.val = max s.global.val (min head.version.val requested.val)
        ∧ after.frames.val = s.frames.val.take (cut.val + 1)
        ∧ after.global = s.global
        ∧ after.next_identity = s.next_identity
        ∧ after.term = term := by
  let model : Store := { global := s.global.val, head := {version := head.version.val} }
  have hspec := rollback_cut_model s.global head.version requested model rfl rfl
  have hsuccess : ∃ cut, Spike.engine.rollback_cut s.global head.version requested = .ok cut
      ∧ cut.val = max s.global.val (min head.version.val requested.val) := by
    cases h : Spike.engine.rollback_cut s.global head.version requested
      using Result.cases with
    | ret cut => exact ⟨cut, rfl, by simpa [h, model, rollbackCut] using hspec⟩
    | vis _ _ => simp [h] at hspec
    | div => simp [h] at hspec
  obtain ⟨cut, hcalc, hvalue⟩ := hsuccess
  have hlen : s.frames.val.length = prior.length + 1 := by simp [hframes]
  by_cases hsmall : cut.val < head.version.val
  · let i := UScalar.cast .Usize cut
    have hsize := alloc.vec.Vec.len_ineq s.frames
    have hbound : cut.val ≤ Usize.max := by omega
    have hi : i.val = cut.val := by
      apply UScalar.cast_val_mod_pow_of_inBounds_eq
      have := hbound
      rw [← UScalar.max_USize_eq, UScalar.max] at this
      have := Nat.two_pow_pos UScalarTy.Usize.numBits
      omega
    have hplus : i.val + (1#usize : Usize).val ≤ Usize.max := by
      have hone : (1#usize : Usize).val = 1 := rfl
      omega
    obtain ⟨len, hadd, hlenval⟩ := returning (Usize.add_spec hplus)
    have hn : len.val = cut.val + 1 := by
      have hone : (1#usize : Usize).val = 1 := rfl
      omega
    have hnlt : len.val < s.frames.length := by
      change len.val < s.frames.val.length
      omega
    let empty : Spike.engine.Frame := {
      version := 0#u64
      data := alloc.vec.Vec.new _
      revisions := alloc.vec.Vec.new _
      births := alloc.vec.Vec.new _
    }
    have hempty : Spike.engine.Frame.empty = .ok empty := by
      simp [Spike.engine.Frame.empty, Spike.engine.Assoc.new, empty]
    have hresize : ∃ v,
        alloc.vec.Vec.resize Spike.engine.Frame.Insts.CoreCloneClone s.frames len empty = .ok v
        ∧ v.val = s.frames.val.take (cut.val + 1) := by
      rw [alloc.vec.Vec.resize, ite_eq_left hnlt]
      refine ⟨_, rfl, ?_⟩
      simp [List.resize, hn, Nat.sub_eq_zero_of_le (by omega :
        cut.val + 1 ≤ s.frames.val.length)]
    obtain ⟨frames, hv, htake⟩ := hresize
    refine ⟨cut, {s with frames, term}, ?_, hvalue, htake, rfl, rfl, rfl⟩
    simp [Spike.engine.History.rollback, Nat.not_lt.mpr hcut, Nat.not_lt.mpr hterm,
      history_head s prior head hframes, hcalc, hsmall, ← show i = UScalar.cast .Usize cut from rfl,
      hzero, lift, hadd, hempty, hv]
  · refine ⟨cut, {s with term}, ?_, hvalue, ?_, rfl, rfl, rfl⟩
    · simp [Spike.engine.History.rollback, Nat.not_lt.mpr hcut, Nat.not_lt.mpr hterm,
        history_head s prior head hframes, hcalc, hsmall]
    · symm
      apply List.take_of_length_le
      omega

/-- Successful extracted rollback retains exactly the frames kept by `rollbackStore`. -/
theorem rollback_retains_model_frames (s : Spike.engine.Store) (requested term : U64)
    (model : Store) (project : Spike.engine.Frame → Frame)
    (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hframes : s.history.frames.val = prior ++ [head])
    (hindex : head.version.val = prior.length)
    (hzero : ∀ cut, Spike.engine.History.relative_cut s.history cut = .ok cut)
    (hversions
      : ∀ i (hi : i < s.history.frames.val.length),
          (project s.history.frames.val[i]).version = i)
    (hmodel : model.history = modelFrames s.history project)
    (hglobal : model.global = s.history.global.val)
    (hhead : model.head.version = head.version.val)
    (hcut : s.history.global.val ≤ requested.val) (hterm : s.history.term.val ≤ term.val)
    : ∃ cut after,
        Spike.engine.Store.execute s (.Rollback requested term)
          = .ok (.Ok (.RolledBack cut), after)
        ∧ cut.val = rollbackCut model requested.val
        ∧ after.history.frames.val = s.history.frames.val.take (cut.val + 1)
        ∧ modelFrames after.history project
          = (rollbackStore model requested.val term.val).history
        ∧ after.txs = s.txs
        ∧ after.history.global = s.history.global
        ∧ after.history.next_identity = s.history.next_identity
        ∧ after.history.term = term := by
  obtain ⟨cut, retained, hrun, hvalue, htake, hg, hi, ht⟩ :=
    history_rollback s.history requested term prior head hframes hindex hzero hcut hterm
  have hmodelcut : cut.val = rollbackCut model requested.val := by
    simpa [rollbackCut, hglobal, hhead] using hvalue
  refine ⟨cut, {s with history := retained}, ?_, hmodelcut, htake, ?_, rfl, hg, hi, ht⟩
  · simp [Spike.engine.Store.execute, hrun]
  · have hfilter : s.history.frames.val.filter
        (fun f => decide ((project f).version ≤ cut.val))
      = s.history.frames.val.take (cut.val + 1) := by
      apply filter_is_take
      intro i hi'
      simp [hversions i hi']
    simp only [rollbackStore, modelFrames, hmodel, List.filter_map, List.filter_reverse,
      ← hmodelcut, Function.comp_def, hfilter, htake]

end KvRust
