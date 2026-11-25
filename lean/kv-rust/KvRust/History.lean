-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.BranchLog
public import KvRust.Keys
public import KvRust.KvIndex
public import Kv.Model

import all Aeneas.Data.List.List

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

abbrev _root_.CcfKv.engine.History.activeFrames (history : CcfKv.engine.History)
    : List CcfKv.engine.Frame :=
  branchValues history.log

private theorem returning {α : Type} {r : Result α} {p : α → Prop} (h : WP.spec r p)
    : ∃ v, r = .ok v ∧ p v := by
  cases r using Result.cases with
  | ret v => exact ⟨v, rfl, by simpa using h⟩
  | vis _ _ => simp at h
  | div => simp at h

/-- Both implementations compute the same compaction cut, including backward and above-head requests. -/
theorem compact_cut_model (global head requested : U64) (s : Store)
    (hg : s.global = global.val) (hh : s.head.version = head.val)
    : (do
        let result ← CcfKv.engine.compact_cut global head requested
        Result.ok result.val)
      = .ok (compactStore s requested.val).global := by
  simp only [CcfKv.engine.compact_cut, compactStore, hg, hh]
  by_cases hhead : requested.val ≤ head.val
  · by_cases hglobal : global.val < requested.val
    · simp [hhead, hglobal, Nat.max_eq_right (Nat.le_of_lt hglobal)]
    · simp [hhead, hglobal, Nat.max_eq_left (Nat.le_of_not_gt hglobal)]
  · simp [hhead, hg]

/-- Both implementations compute the same rollback cut for every representable request. -/
theorem rollback_cut_model (global head requested : U64) (s : Store)
    (hg : s.global = global.val) (hh : s.head.version = head.val)
    : (do
        let result ← CcfKv.engine.rollback_cut global head requested
        Result.ok result.val)
      = .ok (rollbackCut s requested.val) := by
  simp only [CcfKv.engine.rollback_cut, rollbackCut, hg, hh]
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

/-- The extracted head lookup returns the last frame of the oldest-first active suffix. -/
theorem history_head (history : CcfKv.engine.History) (prior : List CcfKv.engine.Frame)
    (head : CcfKv.engine.Frame) (h : history.activeFrames = prior ++ [head])
    (valid : BranchValid history.log)
    : CcfKv.engine.History.head history = .ok head := by
  have hit : WP.spec (CcfKv.engine.History.head history) (· = head) := by
    unfold CcfKv.engine.History.head
    apply WP.spec_bind (branch_active_len history.log valid)
    intro count hcount
    have hc : count.val = prior.length + 1 := by
      change count.val = history.activeFrames.length at hcount
      simp [h] at hcount
      exact hcount
    have one : (1#usize : Usize).val = 1 := rfl
    apply WP.spec_bind (Usize.sub_spec (x := count) (y := 1#usize) (by omega))
    intro index hi
    have pick : index.val = prior.length := by omega
    apply branch_active_at history.log valid index head
    change history.activeFrames[index.val]? = some head
    rw [h, pick, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]
    rfl
  obtain ⟨found, result, eq⟩ := returning hit
  rw [result, eq]

/-- Relative cut subtracts the active ring's base version, clamping below it to zero. -/
theorem history_relative_cut (s : CcfKv.engine.History) (cut : U64)
    (baseFrame : CcfKv.engine.Frame)
    (hbase : s.activeFrames[0]? = some baseFrame)
    (valid : BranchValid s.log)
    : WP.spec (CcfKv.engine.History.relative_cut s cut)
        (fun off =>
          off.val
          = if cut.val < baseFrame.version.val then
              0
            else
              cut.val - baseFrame.version.val) := by
  unfold CcfKv.engine.History.relative_cut
  apply WP.spec_bind (branch_active_at s.log valid 0#usize baseFrame hbase)
  intro got hgot
  subst got
  by_cases hlt : cut < baseFrame.version
  · have hlt' : cut.val < baseFrame.version.val := hlt
    rw [ite_eq_left hlt, WP.spec_ok]
    simp [hlt']
  · have hge : baseFrame.version.val ≤ cut.val := Nat.le_of_not_gt hlt
    rw [ite_eq_right hlt]
    apply WP.spec_mono (U64.sub_spec (x := cut) (y := baseFrame.version) hge)
    intro off hoff
    simp [Nat.not_lt.mpr hge, hoff.1]

/-- Resolving a cut selects an active ring offset when `cut ≥ base`, or searches
the compacted metadata-only `retained` list when `cut < base`. -/
theorem history_resolve_cut (s : CcfKv.engine.History) (cut : U64)
    (baseFrame : CcfKv.engine.Frame)
    (hbase : s.activeFrames[0]? = some baseFrame)
    (valid : BranchValid s.log)
    : WP.spec (CcfKv.engine.History.resolve_cut s cut)
        (fun res =>
          if cut.val < baseFrame.version.val then
            match res with
            | none => ∀ f ∈ s.retained.val, f.version ≠ cut
            | some (.Retained idx) =>
                ∃ f, s.retained.val[idx.val]? = some f ∧ f.version = cut
            | some (.Active _) => False
          else
            ∃ idx,
              res = some (.Active idx)
              ∧ idx.val
                = min (cut.val - baseFrame.version.val) (s.activeFrames.length - 1)) := by
  unfold CcfKv.engine.History.resolve_cut
  apply WP.spec_bind (branch_active_at s.log valid 0#usize baseFrame hbase)
  intro got hgot
  subst got
  by_cases hlt : cut < baseFrame.version
  · have hlt' : cut.val < baseFrame.version.val := hlt
    rw [ite_eq_left hlt]
    unfold CcfKv.engine.History.resolve_cut_loop
    apply loop.spec_decr_nat (fun i : Usize => s.retained.val.length - i.val)
      (fun i =>
        i.val ≤ s.retained.val.length
        ∧ ∀ k, k < i.val → ∀ f, s.retained.val[k]? = some f → f.version ≠ cut) _ _ _
    · intro i ⟨hiLe, hprev⟩
      unfold CcfKv.engine.History.resolve_cut_loop.body
      dsimp only
      have hlen : (alloc.vec.Vec.len s.retained).val = s.retained.val.length := alloc.vec.Vec.len_val _
      have hcap := alloc.vec.Vec.len_ineq s.retained
      by_cases hrun : i < alloc.vec.Vec.len s.retained
      · have hiLt : i.val < s.retained.val.length := by rwa [← hlen]
        rw [ite_eq_left hrun, alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec s.retained i hiLt)
        intro f hf
        have hfAt : s.retained.val[i.val]? = some f := by
          rw [List.getElem?_eq_getElem hiLt, ← hf]
        by_cases heq : f.version = cut
        · rw [ite_eq_left heq, WP.spec_ok]
          dsimp only
          rw [ite_eq_left hlt']
          exact ⟨f, hfAt, heq⟩
        · rw [ite_eq_right heq]
          have hone : (1#usize : Usize).val = 1 := rfl
          apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
          intro i1 hi1
          rw [WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          intro k hk g hg
          by_cases hkOld : k < i.val
          · exact hprev k hkOld g hg
          · have hki : k = i.val := by omega
            subst hki
            have hgf : g = f := Option.some.inj (hg.symm.trans hfAt)
            subst hgf
            exact heq
      · have hiEq : i.val = s.retained.val.length := by
          have : s.retained.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt hrun
          omega
        rw [ite_eq_right hrun, WP.spec_ok]
        dsimp only
        rw [ite_eq_left hlt']
        intro f hf
        obtain ⟨k, hk⟩ := List.mem_iff_getElem?.mp hf
        have hkLt : k < s.retained.val.length := (List.getElem?_eq_some_iff.mp hk).1
        exact hprev k (by omega) f hk
    · exact ⟨Nat.zero_le _, fun k hk => by
        change k < (0#usize : Usize).val at hk
        have h0 : (0#usize : Usize).val = 0 := rfl
        omega⟩
  · have hge : baseFrame.version.val ≤ cut.val := Nat.le_of_not_gt hlt
    rw [ite_eq_right hlt]
    apply WP.spec_bind (U64.sub_spec (x := cut) (y := baseFrame.version) hge)
    intro rel hrel
    apply WP.spec_bind (branch_cut_refines s.log valid rel)
    intro idx hidx
    rw [WP.spec_ok, ite_eq_right (Nat.not_lt.mpr hge)]
    refine ⟨idx, rfl, ?_⟩
    rw [hidx, hrel.1, branch_values_length s.log valid]

/-- Reading a resolved cut returns the frame from the active ring or `retained`. -/
theorem history_read_cut_active (s : CcfKv.engine.History) (offset : Usize)
    (frame : CcfKv.engine.Frame) (valid : BranchValid s.log)
    (saved : s.activeFrames[offset.val]? = some frame)
    : WP.spec (CcfKv.engine.History.read_cut s (.Active offset)) (· = frame) :=
  branch_active_at s.log valid offset frame saved

theorem history_read_cut_retained (s : CcfKv.engine.History) (idx : Usize)
    (frame : CcfKv.engine.Frame)
    (saved : s.retained.val[idx.val]? = some frame)
    : WP.spec (CcfKv.engine.History.read_cut s (.Retained idx)) (· = frame) := by
  unfold CcfKv.engine.History.read_cut
  dsimp only
  have hi : idx.val < s.retained.val.length := (List.getElem?_eq_some_iff.mp saved).1
  rw [alloc.vec.Vec.index_slice_index]
  apply WP.spec_mono (alloc.vec.Vec.index_usize_spec s.retained idx hi)
  intro got hgot
  rw [List.getElem?_eq_getElem hi, ← hgot, Option.some.injEq] at saved
  exact saved

/-- All non-empty radix roots currently retained by active frames. -/
def framePins (frames : List CcfKv.engine.Frame) : List U32 :=
  frames.filterMap fun f => if f.data = 0#u32 then none else some f.data

theorem framePins_cons (f : CcfKv.engine.Frame) (frames : List CcfKv.engine.Frame)
    : framePins (f :: frames)
      = if f.data = 0#u32 then framePins frames else f.data :: framePins frames := by
  unfold framePins
  by_cases hz : f.data = 0#u32 <;> simp [hz]

theorem framePins_append (frames : List CcfKv.engine.Frame) (f : CcfKv.engine.Frame)
    : (framePins (frames ++ [f])).Perm
        (if f.data = 0#u32 then framePins frames else f.data :: framePins frames) := by
  unfold framePins
  rw [List.filterMap_append, List.filterMap_cons, List.filterMap_nil]
  by_cases hz : f.data = 0#u32
  · simp [hz]
  · simp only [hz, ite_false]
    exact List.perm_append_singleton f.data _

private theorem bytes_same_terminates (a b : CcfKv.engine.Bytes)
    : WP.spec (CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey.same a b) (fun _ => True) := by
  rw [bytes_same, WP.spec_ok]
  trivial

private theorem assoc_stamp_get_terminates
    (rows : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.Stamp)
    (k : CcfKv.engine.Bytes)
    : WP.spec
        (CcfKv.engine.Assoc.get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
          CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
          rows k)
        (fun _ => True) := by
  unfold CcfKv.engine.Assoc.get CcfKv.engine.Assoc.index CcfKv.engine.Assoc.index_from
    CcfKv.engine.Assoc.index_from_loop
  have hloop : WP.spec
      (loop (fun (self1, i1) => CcfKv.engine.Assoc.index_from_loop.body
        CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey k self1 i1) (rows, 0#usize))
      (fun r => match r with | none => True | some idx => idx.val < rows.val.length) := by
    apply loop.spec_decr_nat
      (fun s : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.Stamp × Usize =>
        rows.val.length - s.2.val)
      (fun s => s.1 = rows ∧ s.2.val ≤ rows.val.length) _ _ _
    · rintro ⟨cur, i⟩ ⟨hcur, hi⟩
      dsimp only at hcur hi
      subst cur
      unfold CcfKv.engine.Assoc.index_from_loop.body
      dsimp only
      have hlen : (alloc.vec.Vec.len rows).val = rows.val.length := alloc.vec.Vec.len_val _
      have hcap := alloc.vec.Vec.len_ineq rows
      by_cases hlt : i < alloc.vec.Vec.len rows
      · have hilt : i.val < rows.val.length := by rwa [← hlen]
        rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec rows i hilt)
        rintro ⟨rk, _⟩ _
        apply WP.spec_bind (bytes_same_terminates rk k)
        intro b _
        cases b with
        | true => rw [ite_eq_left rfl, WP.spec_ok]; exact hilt
        | false =>
            rw [ite_eq_right (by decide)]
            have hone : (1#usize : Usize).val = 1 := rfl
            apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
            intro j hj
            rw [WP.spec_ok]
            dsimp only
            exact ⟨⟨rfl, by omega⟩, by omega⟩
      · rw [ite_eq_right hlt, WP.spec_ok]; trivial
    · exact ⟨rfl, Nat.zero_le _⟩
  apply WP.spec_bind hloop
  intro found hfound
  cases found with
  | none => rw [WP.spec_ok]; trivial
  | some idx =>
      dsimp only
      rw [alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec rows idx hfound)
      rintro ⟨_, st⟩ _
      simp [CcfKv.engine.Stamp.Insts.CoreCloneClone.clone]

private theorem stamp_same_terminates (a b : CcfKv.engine.Stamp)
    : WP.spec (CcfKv.engine.Stamp.same a b) (fun _ => True) := by
  unfold CcfKv.engine.Stamp.same
  split <;> simp

private theorem frame_matches_lineage_terminates (f : CcfKv.engine.Frame)
    (m : CcfKv.engine.Bytes) (birth : Option CcfKv.engine.Stamp)
    (rev : CcfKv.engine.Stamp)
    : WP.spec (CcfKv.engine.Frame.matches_lineage f m birth rev) (fun _ => True) := by
  unfold CcfKv.engine.Frame.matches_lineage
  apply WP.spec_bind (assoc_stamp_get_terminates f.births m)
  intro ob _
  have hsame : WP.spec (match ob with
      | none => match birth with | none => Result.ok true | some _ => Result.ok false
      | some a => match birth with | none => Result.ok false | some b => CcfKv.engine.Stamp.same a b)
      (fun _ => True) := by
    cases ob <;> cases birth
    · simp
    · simp
    · simp
    · exact stamp_same_terminates _ _
  apply WP.spec_bind hsame
  intro sb _
  cases sb with
  | false => rw [ite_eq_right (by decide), WP.spec_ok]; trivial
  | true =>
      rw [ite_eq_left rfl]
      have hrev : WP.spec (CcfKv.engine.Frame.revision f m) (fun _ => True) := by
        unfold CcfKv.engine.Frame.revision
        apply WP.spec_bind (assoc_stamp_get_terminates f.revisions m)
        intro orv _
        cases orv <;> simp [CcfKv.engine.Stamp.zero]
      apply WP.spec_bind hrev
      intro st _
      exact stamp_same_terminates st rev

private theorem view_needs_frame_terminates (row : CcfKv.engine.Bytes × CcfKv.engine.View)
    (f g : CcfKv.engine.Frame)
    : WP.spec (CcfKv.engine.view_needs_frame row f g) (fun _ => True) := by
  unfold CcfKv.engine.view_needs_frame
  rcases row with ⟨m, v⟩
  apply WP.spec_bind (frame_matches_lineage_terminates f m v.birth v.revision)
  intro b _
  cases b with
  | false => rw [ite_eq_right (by decide), WP.spec_ok]; trivial
  | true =>
      rw [ite_eq_left rfl]
      apply WP.spec_bind (frame_matches_lineage_terminates g m v.birth v.revision)
      intro _ _; rw [WP.spec_ok]; trivial

private theorem tx_needs_frame_terminates (tx : CcfKv.engine.Tx)
    (f g : CcfKv.engine.Frame)
    : WP.spec (CcfKv.engine.tx_needs_frame tx f g) (fun _ => True) := by
  unfold CcfKv.engine.tx_needs_frame
  cases tx.snapshot with
  | none =>
      unfold CcfKv.engine.tx_needs_frame_loop0
      apply loop.spec_decr_nat
        (fun s : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View × Usize =>
          tx.views.val.length - s.2.val)
        (fun s => s.1 = tx.views ∧ s.2.val ≤ tx.views.val.length) _ _ _
      · rintro ⟨a, i⟩ ⟨ha, hiLe⟩
        dsimp only at ha hiLe
        subst ha
        unfold CcfKv.engine.tx_needs_frame_loop0.body
        dsimp only
        have hlen : (alloc.vec.Vec.len tx.views).val = tx.views.val.length := alloc.vec.Vec.len_val _
        have hcap := alloc.vec.Vec.len_ineq tx.views
        by_cases hlt : i < alloc.vec.Vec.len tx.views
        · have hilt : i.val < tx.views.val.length := by rwa [← hlen]
          rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
          apply WP.spec_bind (alloc.vec.Vec.index_usize_spec tx.views i hilt)
          intro row _
          apply WP.spec_bind (view_needs_frame_terminates row f g)
          intro b _
          cases b with
          | true => rw [ite_eq_left rfl, WP.spec_ok]; trivial
          | false =>
              rw [ite_eq_right (by decide)]
              have hone : (1#usize : Usize).val = 1 := rfl
              apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
              intro j hj
              rw [WP.spec_ok]
              dsimp only
              exact ⟨⟨rfl, by omega⟩, by omega⟩
        · rw [ite_eq_right hlt, WP.spec_ok]; trivial
      · exact ⟨rfl, Nat.zero_le _⟩
  | some snap =>
      dsimp only
      by_cases hv : snap.version = f.version
      · rw [ite_eq_left hv, WP.spec_ok]; trivial
      · rw [ite_eq_right hv]
        unfold CcfKv.engine.tx_needs_frame_loop1
        apply loop.spec_decr_nat
          (fun s : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View × Usize =>
            tx.views.val.length - s.2.val)
          (fun s => s.1 = tx.views ∧ s.2.val ≤ tx.views.val.length) _ _ _
        · rintro ⟨a, i⟩ ⟨ha, hiLe⟩
          dsimp only at ha hiLe
          subst ha
          unfold CcfKv.engine.tx_needs_frame_loop1.body
          dsimp only
          have hlen : (alloc.vec.Vec.len tx.views).val = tx.views.val.length := alloc.vec.Vec.len_val _
          have hcap := alloc.vec.Vec.len_ineq tx.views
          by_cases hlt : i < alloc.vec.Vec.len tx.views
          · have hilt : i.val < tx.views.val.length := by rwa [← hlen]
            rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
            apply WP.spec_bind (alloc.vec.Vec.index_usize_spec tx.views i hilt)
            intro row _
            apply WP.spec_bind (view_needs_frame_terminates row _ g)
            intro b _
            cases b with
            | true => rw [ite_eq_left rfl, WP.spec_ok]; trivial
            | false =>
                rw [ite_eq_right (by decide)]
                have hone : (1#usize : Usize).val = 1 := rfl
                apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
                intro j hj
                rw [WP.spec_ok]
                dsimp only
                exact ⟨⟨rfl, by omega⟩, by omega⟩
          · rw [ite_eq_right hlt, WP.spec_ok]; trivial
        · exact ⟨rfl, Nat.zero_le _⟩

/-- `txs_need_frame` always terminates with a deterministic boolean result. -/
theorem txs_need_frame_terminates (txs : CcfKv.engine.Assoc U64 CcfKv.engine.Tx)
    (f g : CcfKv.engine.Frame)
    : WP.spec (CcfKv.engine.txs_need_frame txs f g)
        (fun b => CcfKv.engine.txs_need_frame txs f g = .ok b) := by
  have hterm : WP.spec (CcfKv.engine.txs_need_frame txs f g) (fun _ => True) := by
    unfold CcfKv.engine.txs_need_frame CcfKv.engine.txs_need_frame_loop
    apply loop.spec_decr_nat
      (fun s : CcfKv.engine.Assoc U64 CcfKv.engine.Tx × Usize => txs.val.length - s.2.val)
      (fun s => s.1 = txs ∧ s.2.val ≤ txs.val.length) _ _ _
    · rintro ⟨a, i⟩ ⟨ha, hiLe⟩
      dsimp only at ha hiLe
      subst a
      unfold CcfKv.engine.txs_need_frame_loop.body
      dsimp only
      have hlen : (alloc.vec.Vec.len txs).val = txs.val.length := alloc.vec.Vec.len_val _
      have hcap := alloc.vec.Vec.len_ineq txs
      by_cases hlt : i < alloc.vec.Vec.len txs
      · have hilt : i.val < txs.val.length := by rwa [← hlen]
        rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec txs i hilt)
        rintro ⟨_, tx⟩ _
        apply WP.spec_bind (tx_needs_frame_terminates tx f g)
        intro b _
        cases b with
        | true => rw [ite_eq_left rfl, WP.spec_ok]; trivial
        | false =>
            rw [ite_eq_right (by decide)]
            have hone : (1#usize : Usize).val = 1 := rfl
            apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
            intro j hj
            rw [WP.spec_ok]
            dsimp only
            exact ⟨⟨rfl, by omega⟩, by omega⟩
      · rw [ite_eq_right hlt, WP.spec_ok]; trivial
    · exact ⟨rfl, Nat.zero_le _⟩
  obtain ⟨b, hok, _⟩ := returning hterm
  rw [hok, WP.spec_ok]

/-- Popping active tail frames down to `keepLen` releases their radix roots
and leaves the prefix `s.activeFrames.take keepLen.val` and `s.retained` intact. -/
theorem history_pop_active_to_refines (s : CcfKv.engine.History)
    (keepLen : Usize) (extraPins : List U32)
    (valid : BranchValid s.log)
    (hpos : 1 ≤ keepLen.val) (hle : keepLen.val ≤ s.activeFrames.length)
    (live : IndexLiveness s.index (framePins s.activeFrames ++ extraPins))
    (queueRoom
      : 2 * (s.index.values.dirs.val.length + s.index.values.rows.val.length) + 1
        ≤ Usize.max)
    : WP.spec (CcfKv.engine.History.pop_active_to s keepLen)
        (fun after =>
          BranchValid after.log
          ∧ after.activeFrames = s.activeFrames.take keepLen.val
          ∧ after.retained = s.retained
          ∧ after.global = s.global
          ∧ after.term = s.term
          ∧ after.next_identity = s.next_identity
          ∧ after.reuse_compacted_images = s.reuse_compacted_images
          ∧ after.index.values = s.index.values
          ∧ IndexLiveness after.index (framePins after.activeFrames ++ extraPins)) := by
  unfold CcfKv.engine.History.pop_active_to CcfKv.engine.History.pop_active_to_loop
  have hloop : WP.spec
      (loop (fun cur => CcfKv.engine.History.pop_active_to_loop.body keepLen cur) s)
      (fun (bl, v, ai, gl, tm, nid, re) =>
        BranchValid bl
        ∧ branchValues bl = s.activeFrames.take keepLen.val
        ∧ v = s.retained
        ∧ gl = s.global
        ∧ tm = s.term
        ∧ nid = s.next_identity
        ∧ re = s.reuse_compacted_images
        ∧ ai.values = s.index.values
        ∧ IndexLiveness ai (framePins (branchValues bl) ++ extraPins)) := by
    apply loop.spec_decr_nat
      (fun cur : CcfKv.engine.History => cur.activeFrames.length - keepLen.val)
      (fun cur =>
        BranchValid cur.log
        ∧ keepLen.val ≤ cur.activeFrames.length
        ∧ cur.activeFrames = s.activeFrames.take cur.activeFrames.length
        ∧ cur.retained = s.retained
        ∧ cur.global = s.global
        ∧ cur.term = s.term
        ∧ cur.next_identity = s.next_identity
        ∧ cur.reuse_compacted_images = s.reuse_compacted_images
        ∧ cur.index.values = s.index.values
        ∧ IndexLiveness cur.index (framePins cur.activeFrames ++ extraPins)) _ _ _
    · intro cur ⟨hval, hge, htake, hret, hgl, htm, hid, hre, hvals, hlive⟩
      unfold CcfKv.engine.History.pop_active_to_loop.body
      dsimp only
      apply WP.spec_bind (branch_active_len cur.log hval)
      intro alen halen
      change alen.val = cur.activeFrames.length at halen
      by_cases hgt : alen > keepLen
      · have hgt' : keepLen.val < cur.activeFrames.length := by
          have : keepLen.val < alen.val := hgt
          omega
        rw [ite_eq_left hgt]
        have hlenGe2 : 2 ≤ cur.log.len.val := by
          have := branch_values_length cur.log hval
          change cur.activeFrames.length = cur.log.len.val at this
          omega
        apply WP.spec_bind (branch_pop_back_refines cur.log hval hlenGe2)
        rintro ⟨frame, bl1⟩ ⟨hval1, hsplit, hlenDec⟩
        have htake1 : branchValues bl1 = s.activeFrames.take (branchValues bl1).length := by
          have h1 : (branchValues cur.log).take (branchValues bl1).length = branchValues bl1 := by
            rw [hsplit, List.take_left]
          have h2 : (branchValues bl1).length ≤ cur.activeFrames.length := by
            change (branchValues bl1).length ≤ (branchValues cur.log).length
            rw [hsplit, List.length_append, List.length_singleton]; omega
          calc
            branchValues bl1 = cur.activeFrames.take (branchValues bl1).length := h1.symm
            _ = (s.activeFrames.take cur.activeFrames.length).take
                  (branchValues bl1).length := by
              rw [← htake]
            _ = s.activeFrames.take (branchValues bl1).length := by
              rw [List.take_take, Nat.min_eq_left h2]
        have hpinsSplit : (framePins cur.activeFrames ++ extraPins).Perm
            (if frame.data = 0#u32 then framePins (branchValues bl1) ++ extraPins
              else frame.data :: (framePins (branchValues bl1) ++ extraPins)) := by
          change (framePins (branchValues cur.log) ++ extraPins).Perm _
          rw [hsplit]
          have hp := (framePins_append (branchValues bl1) frame).append_right extraPins
          by_cases hz : frame.data = 0#u32 <;> simpa [hz] using hp
        change WP.spec (do
          let b ← CcfKv.radix.RadixRoot.is_empty frame.data
          if b then Result.ok (ControlFlow.cont { cur with log := bl1 })
          else do
            let ai ← CcfKv.kv_index.AddressIndex.release_root cur.index frame.data
            Result.ok (ControlFlow.cont { cur with log := bl1, index := ai })) _
        simp only [CcfKv.radix.RadixRoot.is_empty, bind_ok]
        by_cases hz : frame.data = 0#u32
        · rw [ite_eq_left (by simp [hz]), WP.spec_ok]
          rw [ite_eq_left hz] at hpinsSplit
          refine ⟨⟨hval1, ?_, htake1, hret, hgl, htm, hid, hre, hvals, hlive.perm hpinsSplit⟩, ?_⟩
          · change keepLen.val ≤ (branchValues bl1).length
            rw [branch_values_length bl1 hval1, branch_values_length cur.log hval] at *
            omega
          · change (branchValues bl1).length - keepLen.val < cur.activeFrames.length - keepLen.val
            rw [branch_values_length bl1 hval1, branch_values_length cur.log hval] at *
            omega
        · rw [ite_eq_right (by simp [hz])]
          have hqCur : 2 * (cur.index.values.dirs.val.length + cur.index.values.rows.val.length) + 1
              ≤ Usize.max := by rw [hvals]; exact queueRoom
          apply WP.spec_bind
            (index_release_root_refines cur.index (framePins (branchValues bl1) ++ extraPins)
              frame.data (hlive.perm hpinsSplit) hqCur)
          intro ai1 ⟨hvals1, hlive1⟩
          rw [WP.spec_ok]
          refine ⟨⟨hval1, ?_, htake1, hret, hgl, htm, hid, hre, hvals1.trans hvals, hlive1⟩, ?_⟩
          · change keepLen.val ≤ (branchValues bl1).length
            rw [branch_values_length bl1 hval1, branch_values_length cur.log hval] at *
            omega
          · change (branchValues bl1).length - keepLen.val < cur.activeFrames.length - keepLen.val
            rw [branch_values_length bl1 hval1, branch_values_length cur.log hval] at *
            omega
      · have heq : cur.activeFrames.length = keepLen.val := by
          have : alen.val ≤ keepLen.val := Nat.le_of_not_gt hgt
          omega
        rw [ite_eq_right hgt, WP.spec_ok]
        exact ⟨hval, heq ▸ htake, hret, hgl, htm, hid, hre, hvals, hlive⟩
    · exact ⟨valid, hle, by simp, rfl, rfl, rfl, rfl, rfl, rfl, live⟩
  apply WP.spec_bind hloop
  rintro ⟨bl, v, ai, gl, tm, nid, re⟩ hpost
  change WP.spec (Result.ok _) _
  rw [WP.spec_ok]
  exact hpost

/-- Compacting `count` leading active frames pops them from the ring, releases
their radix roots, and moves needed metadata-only frames into `retained`. -/
theorem history_compact_prefix_refines (s : CcfKv.engine.History)
    (count : Usize) (txs : CcfKv.engine.Assoc U64 CcfKv.engine.Tx)
    (extraPins : List U32) (globalFrame : CcfKv.engine.Frame)
    (valid : BranchValid s.log)
    (hcountLt : count.val < s.activeFrames.length)
    (hglAt : s.activeFrames[count.val]? = some globalFrame)
    (hretRoom : s.retained.val.length + count.val ≤ Usize.max)
    (live : IndexLiveness s.index (framePins s.activeFrames ++ extraPins))
    (queueRoom
      : 2 * (s.index.values.dirs.val.length + s.index.values.rows.val.length) + 1
        ≤ Usize.max)
    : WP.spec (CcfKv.engine.History.compact_prefix s count txs)
        (fun after =>
          BranchValid after.log
          ∧ after.activeFrames = s.activeFrames.drop count.val
          ∧ after.global = s.global
          ∧ after.term = s.term
          ∧ after.next_identity = s.next_identity
          ∧ after.reuse_compacted_images = s.reuse_compacted_images
          ∧ after.index.values = s.index.values
          ∧ IndexLiveness after.index (framePins after.activeFrames ++ extraPins)
          ∧ (∀ f ∈ s.retained.val, f ∈ after.retained.val)
          ∧ (∀ f ∈ after.retained.val,
              f ∈ s.retained.val
              ∨ ∃ orig ∈ s.activeFrames.take count.val, f = { orig with data := 0#u32 })
          ∧ (∀ orig ∈ s.activeFrames.take count.val,
              { orig with data := 0#u32 } ∈ after.retained.val
              ∨ CcfKv.engine.txs_need_frame txs orig globalFrame = .ok false)) := by
  unfold CcfKv.engine.History.compact_prefix CcfKv.engine.History.compact_prefix_loop
  apply loop.spec_decr_nat (fun st : CcfKv.engine.History × Usize => st.2.val)
    (fun st =>
      let cur := st.1
      let rem := st.2
      let done := count.val - rem.val
      rem.val ≤ count.val
      ∧ BranchValid cur.log
      ∧ cur.activeFrames = s.activeFrames.drop done
      ∧ cur.retained.val.length ≤ s.retained.val.length + done
      ∧ cur.global = s.global
      ∧ cur.term = s.term
      ∧ cur.next_identity = s.next_identity
      ∧ cur.reuse_compacted_images = s.reuse_compacted_images
      ∧ cur.index.values = s.index.values
      ∧ IndexLiveness cur.index (framePins cur.activeFrames ++ extraPins)
      ∧ (∀ f ∈ s.retained.val, f ∈ cur.retained.val)
      ∧ (∀ f ∈ cur.retained.val,
          f ∈ s.retained.val
          ∨ ∃ orig ∈ s.activeFrames.take done, f = { orig with data := 0#u32 })
      ∧ (∀ orig ∈ s.activeFrames.take done,
          { orig with data := 0#u32 } ∈ cur.retained.val
          ∨ CcfKv.engine.txs_need_frame txs orig globalFrame = .ok false)) _ _ _
  · rintro ⟨cur, rem⟩ ⟨hremLe, hval, hdrop, hretLen, hgl, htm, hid, hre, hvals, hlive,
      hretSub, hretFrom, hneeded⟩
    dsimp only at hremLe hval hdrop hretLen hgl htm hid hre hvals hlive hretSub hretFrom hneeded
    unfold CcfKv.engine.History.compact_prefix_loop.body
    dsimp only
    by_cases hpos : rem > 0#usize
    · have hremPos : 0 < rem.val := hpos
      rw [ite_eq_left hpos]
      have hdoneLt : count.val - rem.val < s.activeFrames.length := by omega
      have hcur0 : cur.activeFrames[0]? = some (s.activeFrames[count.val - rem.val]'hdoneLt) := by
        rw [hdrop, List.getElem?_drop, Nat.add_zero, List.getElem?_eq_getElem hdoneLt]
      have hcurRem : cur.activeFrames[rem.val]? = some globalFrame := by
        rw [hdrop, List.getElem?_drop]
        have hsum : count.val - rem.val + rem.val = count.val := by omega
        rw [hsum, hglAt]
      let hdFrame := s.activeFrames[count.val - rem.val]'hdoneLt
      apply WP.spec_bind (branch_active_at cur.log hval 0#usize hdFrame hcur0)
      intro fRead hfRead
      subst fRead
      apply WP.spec_bind (branch_active_at cur.log hval rem globalFrame hcurRem)
      intro gRead hgRead
      subst gRead
      apply WP.spec_bind (txs_need_frame_terminates txs hdFrame globalFrame)
      intro needed hNeededEq
      have hlenGe2 : 2 ≤ cur.log.len.val := by
        have := branch_values_length cur.log hval
        change cur.activeFrames.length = cur.log.len.val at this
        rw [hdrop, List.length_drop] at this
        omega
      apply WP.spec_bind (branch_pop_front_refines cur.log hval hlenGe2)
      rintro ⟨popped, bl1⟩ ⟨hval1, hcons, _⟩
      have hpopEq : popped = hdFrame := by
        have h1 : cur.activeFrames[0]? = some popped := by
          change (branchValues cur.log)[0]? = some popped
          rw [hcons]; rfl
        exact Option.some.inj (h1.symm.trans hcur0)
      subst popped
      have hdrop1 : branchValues bl1 = s.activeFrames.drop (count.val - rem.val + 1) := by
        have hstep : s.activeFrames.drop (count.val - rem.val)
            = hdFrame :: s.activeFrames.drop (count.val - rem.val + 1) :=
          List.drop_eq_getElem_cons hdoneLt
        have hEq : hdFrame :: branchValues bl1 = hdFrame :: s.activeFrames.drop (count.val - rem.val + 1) := by
          rw [← hcons]
          exact hdrop.trans hstep
        exact (List.cons.inj hEq).2
      have hreleaseSpec : WP.spec
          (if decide (hdFrame.data = 0#u32) then Result.ok (cur.index, hdFrame.data)
          else do
            let rr1 ← CcfKv.kv_index.AddressIndex.empty_root cur.index
            let ai1 ← CcfKv.kv_index.AddressIndex.release_root cur.index hdFrame.data
            Result.ok (ai1, rr1))
          (fun (ai1, rr) =>
            rr = 0#u32
            ∧ ai1.values = cur.index.values
            ∧ IndexLiveness ai1 (framePins (branchValues bl1) ++ extraPins)) := by
        have hpins : framePins cur.activeFrames =
            if hdFrame.data = 0#u32 then framePins (branchValues bl1)
            else hdFrame.data :: framePins (branchValues bl1) := by
          change framePins (branchValues cur.log) = _
          rw [hcons, framePins_cons]
        by_cases hz : hdFrame.data = 0#u32
        · rw [ite_eq_left (by simp [hz]), WP.spec_ok]
          rw [hpins, ite_eq_left hz] at hlive
          exact ⟨hz, rfl, hlive⟩
        · rw [ite_eq_right (by simp [hz])]
          have hliveIf : IndexLiveness cur.index
              (if hdFrame.data = 0#u32 then framePins (branchValues bl1) ++ extraPins
                else hdFrame.data :: (framePins (branchValues bl1) ++ extraPins)) := by
            rw [ite_eq_right hz]
            rw [hpins, ite_eq_right hz] at hlive
            exact hlive
          apply WP.spec_bind (index_empty_root_refines cur.index)
          intro rr1 ⟨hrr0, _⟩
          have hqCur : 2 * (cur.index.values.dirs.val.length + cur.index.values.rows.val.length) + 1
              ≤ Usize.max := by rw [hvals]; exact queueRoom
          apply WP.spec_bind
            (index_release_root_refines cur.index (framePins (branchValues bl1) ++ extraPins)
              hdFrame.data hliveIf hqCur)
          intro ai1 ⟨hvals1, hlive1⟩
          rw [WP.spec_ok]
          exact ⟨hrr0, hvals1, hlive1⟩
      change WP.spec (do
        let b ← CcfKv.radix.RadixRoot.is_empty hdFrame.data
        let (ai, rr) ← if b then Result.ok (cur.index, hdFrame.data)
          else do
            let rr1 ← CcfKv.kv_index.AddressIndex.empty_root cur.index
            let ai1 ← CcfKv.kv_index.AddressIndex.release_root cur.index hdFrame.data
            Result.ok (ai1, rr1)
        let v ← if needed then alloc.vec.Vec.push cur.retained { hdFrame with data := rr }
          else Result.ok cur.retained
        let count1 ← rem - 1#usize
        Result.ok (ControlFlow.cont ({ cur with log := bl1, retained := v, index := ai }, count1))) _
      simp only [CcfKv.radix.RadixRoot.is_empty, bind_ok]
      apply WP.spec_bind hreleaseSpec
      rintro ⟨ai1, rr⟩ ⟨hrr0, hvals1, hlive1⟩
      subst rr
      have hpushSpec : WP.spec
          (if needed then alloc.vec.Vec.push cur.retained { hdFrame with data := 0#u32 }
            else Result.ok cur.retained)
          (fun v1 =>
            v1.val.length ≤ cur.retained.val.length + 1
            ∧ (∀ f ∈ cur.retained.val, f ∈ v1.val)
            ∧ (∀ f ∈ v1.val, f ∈ cur.retained.val ∨ f = { hdFrame with data := 0#u32 })
            ∧ (needed = true → { hdFrame with data := 0#u32 } ∈ v1.val)) := by
        cases needed with
        | false =>
            rw [ite_eq_right (by decide), WP.spec_ok]
            exact ⟨
              Nat.le_succ _,
              fun _ hm => hm,
              fun _ hm => Or.inl hm,
              fun h => by cases h
            ⟩
        | true =>
            rw [ite_eq_left rfl]
            apply WP.spec_mono
              (alloc.vec.Vec.push_spec cur.retained { hdFrame with data := 0#u32 }
                (by omega))
            intro v1 hv1
            refine ⟨
              by rw [hv1, List.length_append, List.length_singleton],
              fun f hf => by rw [hv1]; exact List.mem_append_left _ hf,
              fun f hf => by
                rw [hv1] at hf
                rcases List.mem_append.mp hf with hold | hnew
                · exact Or.inl hold
                · exact Or.inr (List.mem_singleton.mp hnew),
              fun _ => by rw [hv1]; exact List.mem_append_right _ List.mem_cons_self
            ⟩
      apply WP.spec_bind hpushSpec
      intro v1 ⟨hv1Len, hv1Keep, hv1From, hv1Has⟩
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.sub_spec (x := rem) (y := 1#usize) (by omega))
      intro rem1 hrem1
      have hrem1Val : rem1.val = rem.val - 1 := by rw [hrem1.1, hone]
      have hdone1 : count.val - rem1.val = count.val - rem.val + 1 := by omega
      have htakeStep : s.activeFrames.take (count.val - rem1.val)
          = s.activeFrames.take (count.val - rem.val) ++ [hdFrame] := by
        rw [hdone1, List.take_succ_eq_append_getElem hdoneLt]
      rw [WP.spec_ok]
      dsimp only
      refine ⟨
        ⟨
          by omega,
          hval1,
          by rw [hdone1]; exact hdrop1,
          by omega,
          hgl,
          htm,
          hid,
          hre,
          hvals1.trans hvals,
          hlive1,
          fun f hf => hv1Keep f (hretSub f hf),
          ?_,
          ?_
        ⟩,
        by omega
      ⟩
      · intro f hf
        rcases hv1From f hf with hold | rfl
        · rcases hretFrom f hold with hinit | ⟨orig, horig, heq⟩
          · exact Or.inl hinit
          · exact Or.inr ⟨orig, by rw [htakeStep]; exact List.mem_append_left _ horig, heq⟩
        · exact Or.inr ⟨hdFrame, by rw [htakeStep]; exact List.mem_append_right _ List.mem_cons_self, rfl⟩
      · intro orig horig
        rw [htakeStep] at horig
        rcases List.mem_append.mp horig with hold | hnew
        · rcases hneeded orig hold with hmem | hfalse
          · exact Or.inl (hv1Keep _ hmem)
          · exact Or.inr hfalse
        · have heq := List.mem_singleton.mp hnew
          subst heq
          cases needed with
          | true => exact Or.inl (hv1Has rfl)
          | false => exact Or.inr hNeededEq
    · have hrem0 : rem.val = 0 := by
        have : ¬ (0#usize : Usize).val < rem.val := hpos
        have h0 : (0#usize : Usize).val = 0 := rfl
        omega
      rw [ite_eq_right hpos, WP.spec_ok]
      have hdoneEq : count.val - rem.val = count.val := by omega
      rw [hdoneEq] at hdrop hretFrom hneeded
      exact ⟨hval, hdrop, hgl, htm, hid, hre, hvals, hlive, hretSub, hretFrom, hneeded⟩
  · exact ⟨Nat.le_refl _, valid, by simp, by simp, rfl, rfl, rfl, rfl, rfl, live,
      fun _ hm => hm, fun _ hm => Or.inl hm, fun _ hm => by simp at hm⟩

private theorem any_retained_prunable_terminates
    (retained : alloc.vec.Vec CcfKv.engine.Frame) (globalFrame : CcfKv.engine.Frame)
    (txs : CcfKv.engine.Assoc U64 CcfKv.engine.Tx)
    : WP.spec (CcfKv.engine.any_retained_prunable retained globalFrame txs)
        (fun _ => True) := by
  unfold CcfKv.engine.any_retained_prunable CcfKv.engine.any_retained_prunable_loop
  apply loop.spec_decr_nat (fun i : Usize => retained.val.length - i.val)
    (fun i => i.val ≤ retained.val.length) _ _ _
  · intro i hiLe
    unfold CcfKv.engine.any_retained_prunable_loop.body
    dsimp only
    have hlen : (alloc.vec.Vec.len retained).val = retained.val.length := alloc.vec.Vec.len_val _
    have hcap := alloc.vec.Vec.len_ineq retained
    by_cases hlt : i < alloc.vec.Vec.len retained
    · have hiLt : i.val < retained.val.length := by rwa [← hlen]
      rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec retained i hiLt)
      intro f _
      apply WP.spec_bind (txs_need_frame_terminates txs f globalFrame)
      intro b _
      cases b with
      | true =>
          rw [ite_eq_left rfl]
          have hone : (1#usize : Usize).val = 1 := rfl
          apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
          intro j hj
          rw [WP.spec_ok]
          exact ⟨by omega, by omega⟩
      | false => rw [ite_eq_right (by decide), WP.spec_ok]; trivial
    · rw [ite_eq_right hlt, WP.spec_ok]; trivial
  · exact Nat.zero_le _

private theorem prune_retained_frames_refines
    (retained : alloc.vec.Vec CcfKv.engine.Frame) (globalFrame : CcfKv.engine.Frame)
    (txs : CcfKv.engine.Assoc U64 CcfKv.engine.Tx) (empty : CcfKv.radix.RadixRoot)
    : WP.spec (CcfKv.engine.prune_retained_frames retained globalFrame txs empty)
        (fun kept =>
          (∀ f ∈ kept.val, f ∈ retained.val)
          ∧ (∀ f ∈ retained.val,
              f ∈ kept.val
              ∨ CcfKv.engine.txs_need_frame txs f globalFrame = .ok false)) := by
  unfold CcfKv.engine.prune_retained_frames CcfKv.engine.prune_retained_frames_loop
  apply loop.spec_decr_nat
    (fun st : alloc.vec.Vec CcfKv.engine.Frame
              × alloc.vec.Vec CcfKv.engine.Frame
              × Usize =>
      retained.val.length - st.2.2.val)
    (fun st =>
      let cur := st.1
      let kept := st.2.1
      let i := st.2.2
      i.val ≤ retained.val.length
      ∧ cur.val.length = retained.val.length
      ∧ kept.val.length ≤ i.val
      ∧ (∀ k, i.val ≤ k → k < retained.val.length → cur.val[k]? = retained.val[k]?)
      ∧ (∀ f ∈ kept.val, f ∈ retained.val)
      ∧ (∀ k,
          k < i.val
          → ∀ f,
              retained.val[k]? = some f
              → f ∈ kept.val ∨ CcfKv.engine.txs_need_frame txs f globalFrame = .ok false))
    _ _ _
  · rintro ⟨cur, kept, i⟩ ⟨hiLe, hcurLen, hkeptLen, hrem, hsub, hdone⟩
    dsimp only at hiLe hcurLen hkeptLen hrem hsub hdone
    unfold CcfKv.engine.prune_retained_frames_loop.body
    dsimp only
    have hlen : (alloc.vec.Vec.len cur).val = cur.val.length := alloc.vec.Vec.len_val _
    have hcap := alloc.vec.Vec.len_ineq retained
    by_cases hlt : i < alloc.vec.Vec.len cur
    · have hiLt : i.val < retained.val.length := by rw [← hcurLen, ← hlen]; exact hlt
      have hiCur : i.val < cur.val.length := by rw [hcurLen]; exact hiLt
      rw [ite_eq_left hlt]
      unfold CcfKv.engine.Frame.empty
      simp only [CcfKv.engine.Assoc.new, bind_ok, alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec cur i hiCur)
      rintro ⟨f, back⟩ ⟨hf, hback⟩
      simp only [core.mem.swap]
      have hfOrig : retained.val[i.val]? = some f := by
        have h1 : cur.val[i.val]? = some f := by
          rw [List.getElem?_eq_getElem (by omega), ← hf]
        exact (hrem i.val (Nat.le_refl _) hiLt).symm.trans h1
      have hfMem : f ∈ retained.val := List.mem_of_getElem? hfOrig
      apply WP.spec_bind (txs_need_frame_terminates txs f globalFrame)
      intro b hbEq
      let dummy : CcfKv.engine.Frame := {
        version := 0#u64
        data := empty
        revisions := alloc.vec.Vec.new _
        births := alloc.vec.Vec.new _
      }
      have hcur1Val : (back dummy).val = cur.val.set i.val dummy := by
        rw [hback]; exact alloc.vec.Vec.set_val_eq _ _ _
      have hbranch : WP.spec
          (if b then do
              let kept2 ← alloc.vec.Vec.push kept f
              Result.ok (back dummy, kept2)
            else Result.ok (back dummy, kept))
          (fun (cur1, kept1) =>
            cur1 = back dummy
            ∧ kept1.val.length ≤ i.val + 1
            ∧ (∀ g ∈ kept.val, g ∈ kept1.val)
            ∧ (∀ g ∈ kept1.val, g ∈ retained.val)
            ∧ (f ∈ kept1.val ∨ CcfKv.engine.txs_need_frame txs f globalFrame = .ok false)) := by
        cases b with
        | false =>
            rw [ite_eq_right (by decide), WP.spec_ok]
            exact ⟨rfl, by omega, fun _ hm => hm, hsub, Or.inr hbEq⟩
        | true =>
            rw [ite_eq_left rfl]
            apply WP.spec_bind (alloc.vec.Vec.push_spec kept f (by omega))
            intro kept2 hkept2
            rw [WP.spec_ok]
            refine ⟨
              rfl,
              by rw [hkept2, List.length_append, List.length_singleton]; omega,
              fun g hg => by rw [hkept2]; exact List.mem_append_left _ hg,
              fun g hg => by
                rw [hkept2] at hg
                rcases List.mem_append.mp hg with hold | hnew
                · exact hsub g hold
                · rw [List.mem_singleton.mp hnew]; exact hfMem,
              Or.inl (by rw [hkept2]; exact List.mem_append_right _ List.mem_cons_self)
            ⟩
      apply WP.spec_bind hbranch
      rintro ⟨cur1, kept1⟩ ⟨hcur1Eq, hkept1Len, hkept1Keep, hkept1Sub, hfDone⟩
      subst hcur1Eq
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro i1 hi1
      rw [WP.spec_ok]
      dsimp only
      refine ⟨
        ⟨
          by omega,
          by rw [hcur1Val, List.length_set, hcurLen],
          by omega,
          ?_,
          hkept1Sub,
          ?_
        ⟩,
        by omega
      ⟩
      · intro k hkGe hkLt
        rw [hcur1Val, List.getElem?_set_ne (by omega)]
        exact hrem k (by omega) hkLt
      · intro k hkLt g hg
        by_cases hkOld : k < i.val
        · rcases hdone k hkOld g hg with hmem | hfalse
          · exact Or.inl (hkept1Keep g hmem)
          · exact Or.inr hfalse
        · have hki : k = i.val := by omega
          subst hki
          have hgf : g = f := Option.some.inj (hg.symm.trans hfOrig)
          subst hgf
          exact hfDone
    · have hiEq : i.val = retained.val.length := by
        have : cur.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt hlt
        omega
      rw [ite_eq_right hlt, WP.spec_ok]
      refine ⟨hsub, ?_⟩
      intro f hf
      obtain ⟨k, hk⟩ := List.mem_iff_getElem?.mp hf
      have hkLt : k < retained.val.length := (List.getElem?_eq_some_iff.mp hk).1
      exact hdone k (by omega) f hk
  · exact ⟨Nat.zero_le _, rfl, by simp [alloc.vec.Vec.with_capacity], fun _ _ _ => rfl,
      fun _ hm => by simp [alloc.vec.Vec.with_capacity] at hm,
      fun k hk => by
        change k < (0#usize : Usize).val at hk
        have h0 : (0#usize : Usize).val = 0 := rfl
        omega⟩

/-- Pruning `retained` on `Action::End` preserves the active ring and index while
dropping only compacted metadata frames no remaining live attempt needs. -/
theorem history_prune_retained_refines (s : CcfKv.engine.History)
    (txs : CcfKv.engine.Assoc U64 CcfKv.engine.Tx)
    (globalFrame : CcfKv.engine.Frame)
    (hglobal0 : s.activeFrames[0]? = some globalFrame)
    (valid : BranchValid s.log)
    : WP.spec (CcfKv.engine.History.prune_retained s txs)
        (fun after =>
          after.log = s.log
          ∧ after.index = s.index
          ∧ after.global = s.global
          ∧ after.term = s.term
          ∧ after.next_identity = s.next_identity
          ∧ after.reuse_compacted_images = s.reuse_compacted_images
          ∧ (∀ f ∈ after.retained.val, f ∈ s.retained.val)
          ∧ (∀ f ∈ s.retained.val,
              f ∈ after.retained.val
              ∨ CcfKv.engine.txs_need_frame txs f globalFrame = .ok false)) := by
  unfold CcfKv.engine.History.prune_retained
  by_cases hreuse : s.reuse_compacted_images = true
  · rw [ite_eq_left hreuse]
    simp only [alloc.vec.Vec.is_empty, bind_ok]
    by_cases hemp : s.retained.val.length = 0
    · rw [ite_eq_left (by simp [hemp]), WP.spec_ok]
      exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ hm => hm, fun _ hm => Or.inl hm⟩
    · rw [ite_eq_right (by simp [hemp])]
      apply WP.spec_bind (branch_active_at s.log valid 0#usize globalFrame hglobal0)
      intro gRead hgRead
      subst gRead
      apply WP.spec_bind (any_retained_prunable_terminates s.retained globalFrame txs)
      intro anyP _
      cases anyP with
      | false =>
          rw [ite_eq_right (by decide), WP.spec_ok]
          exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ hm => hm, fun _ hm => Or.inl hm⟩
      | true =>
          rw [ite_eq_left rfl]
          apply WP.spec_bind (index_empty_root_refines s.index)
          intro emp _
          apply WP.spec_bind (prune_retained_frames_refines s.retained globalFrame txs emp)
          intro kept ⟨hsub, hdone⟩
          rw [WP.spec_ok]
          exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, hsub, hdone⟩
  · rw [ite_eq_right hreuse, WP.spec_ok]
    exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ hm => hm, fun _ hm => Or.inl hm⟩

/-- Compaction advances the frontier, pops compacted active frames into `retained`
only when needed by a live transaction, shrinks the ring if sparse, and runs
bounded retirement while preserving all remaining pins. -/
theorem history_compact (s : CcfKv.engine.History) (requested : U64)
    (txs : CcfKv.engine.Assoc U64 CcfKv.engine.Tx)
    (model : Store) (prior : List CcfKv.engine.Frame) (head : CcfKv.engine.Frame)
    (extraPins : List U32)
    (hframes : s.activeFrames = prior ++ [head]) (hg : model.global = s.global.val)
    (hh : model.head.version = head.version.val)
    (hBase
      : s.reuse_compacted_images = true
        → ∀ f, s.activeFrames[0]? = some f → f.version = s.global)
    (hIndexed
      : ∀ f,
          s.activeFrames[0]? = some f
          → ∀ i (hi : i < s.activeFrames.length),
              s.activeFrames[i].version.val = f.version.val + i)
    (valid : BranchValid s.log)
    (hretRoom : s.retained.val.length + s.activeFrames.length ≤ Usize.max)
    (live : IndexLiveness s.index (framePins s.activeFrames ++ extraPins))
    (queueRoom
      : 2 * (s.index.values.dirs.val.length + s.index.values.rows.val.length) + 1
        ≤ Usize.max)
    : WP.spec (CcfKv.engine.History.compact s requested txs)
        (fun (cut, after) =>
          cut.val = (compactStore model requested.val).global
          ∧ after.global = cut
          ∧ after.term = s.term
          ∧ after.next_identity = s.next_identity
          ∧ after.reuse_compacted_images = s.reuse_compacted_images
          ∧ BranchValid after.log
          ∧ after.activeFrames
            = (if s.reuse_compacted_images then
                  s.activeFrames.drop (cut.val - s.global.val)
                else
                  s.activeFrames)
          ∧ IndexLiveness after.index (framePins after.activeFrames ++ extraPins)
          ∧ IndexPreservesPins s.index after.index
              (framePins after.activeFrames ++ extraPins)
          ∧ after.index.values.dirs.val.length = s.index.values.dirs.val.length
          ∧ after.index.values.rows.val.length = s.index.values.rows.val.length
          ∧ (∀ f ∈ s.retained.val, f ∈ after.retained.val)
          ∧ (∀ f ∈ after.retained.val,
              f ∈ s.retained.val
              ∨ (s.reuse_compacted_images = true
                  ∧ ∃ orig ∈ s.activeFrames.take (cut.val - s.global.val),
                      f = { orig with data := 0#u32 }))
          ∧ (∃ globalFrame,
              after.activeFrames[0]? = some globalFrame
              ∧ (s.reuse_compacted_images = true
                  → ∀ orig ∈ s.activeFrames.take (cut.val - s.global.val),
                      { orig with data := 0#u32 } ∈ after.retained.val
                      ∨ CcfKv.engine.txs_need_frame txs orig globalFrame
                        = .ok false))) := by
  have hcutModel := compact_cut_model s.global head.version requested model hg hh
  have hlenPos : 0 < s.activeFrames.length := by simp [hframes]
  let baseFrame := s.activeFrames[0]'hlenPos
  have hbaseAt : s.activeFrames[0]? = some baseFrame := List.getElem?_eq_getElem hlenPos
  have hcutSuccess : ∃ next, CcfKv.engine.compact_cut s.global head.version requested = .ok next
      ∧ next.val = (compactStore model requested.val).global := by
    cases h : CcfKv.engine.compact_cut s.global head.version requested
      using Result.cases with
    | ret next => exact ⟨next, rfl, by simpa [h] using hcutModel⟩
    | vis _ _ => rw [h] at hcutModel; simp at hcutModel
    | div => rw [h] at hcutModel; simp at hcutModel
  obtain ⟨next, hcutRes, hnextVal⟩ := hcutSuccess
  unfold CcfKv.engine.History.compact
  rw [history_head s prior head hframes valid, bind_ok, hcutRes, bind_ok]
  by_cases hreuse : s.reuse_compacted_images = true
  · rw [ite_eq_left hreuse]
    have hbaseEq : baseFrame.version = s.global := hBase hreuse baseFrame hbaseAt
    have hheadVer : head.version.val = s.global.val + prior.length := by
      have hidx : prior.length < s.activeFrames.length := by simp [hframes]
      have hheadEq : s.activeFrames[prior.length]'hidx = head := by
        apply Option.some.inj
        rw [← List.getElem?_eq_getElem hidx, hframes]
        simp
      have := hIndexed baseFrame hbaseAt prior.length hidx
      rw [hheadEq, hbaseEq] at this
      exact this
    by_cases hlt : s.global < next
    · have hlt' : s.global.val < next.val := hlt
      have hnextLeHead : next.val ≤ head.version.val := by
        unfold CcfKv.engine.compact_cut at hcutRes
        by_cases h1 : requested ≤ head.version <;> by_cases h2 : s.global < requested
        · simp only [h1, h2, ite_true, Result.ok.injEq] at hcutRes
          subst hcutRes
          exact h1
        · simp only [h1, h2, ite_true, ite_false, Result.ok.injEq] at hcutRes
          subst hcutRes
          omega
        · simp only [h1, ite_false, Result.ok.injEq] at hcutRes
          subst hcutRes
          omega
        · simp only [h1, ite_false, Result.ok.injEq] at hcutRes
          subst hcutRes
          omega
      rw [ite_eq_left hlt]
      apply WP.spec_bind (U64.sub_spec (x := next) (y := s.global) (Nat.le_of_lt hlt'))
      intro diff hdiff
      have hdiffLt : diff.val < s.activeFrames.length := by
        rw [hdiff.1, hframes, List.length_append, List.length_singleton]; omega
      have hcap : s.activeFrames.length ≤ Usize.max := branch_values_capacity s.log
      have hcastVal : (UScalar.cast .Usize diff).val = diff.val := by
        apply UScalar.cast_val_mod_pow_of_inBounds_eq
        have hbd : diff.val ≤ Usize.max := by omega
        rw [← UScalar.max_USize_eq, UScalar.max] at hbd
        have := Nat.two_pow_pos UScalarTy.Usize.numBits
        omega
      simp only [lift, bind_ok]
      let count := UScalar.cast .Usize diff
      have hcountEq : count.val = next.val - s.global.val := by
        rw [hcastVal, hdiff.1]
      have hcountLt : count.val < s.activeFrames.length := by
        rw [hcountEq, hframes, List.length_append, List.length_singleton]; omega
      let glFrame := s.activeFrames[count.val]'hcountLt
      have hglAt : s.activeFrames[count.val]? = some glFrame := List.getElem?_eq_getElem hcountLt
      have hretRoom1 : s.retained.val.length + count.val ≤ Usize.max := by
        have := hretRoom; omega
      apply WP.spec_bind
        (history_compact_prefix_refines { s with global := next } count txs extraPins
          glFrame valid hcountLt hglAt hretRoom1 live queueRoom)
      intro s1 ⟨hval1, hdrop1, hgl1, htm1, hid1, hre1, hvals1, hlive1, hsub1, hfrom1, hneed1⟩
      apply WP.spec_bind (branch_shrink_refines s1.log hval1)
      intro bl2 ⟨hval2, hvals2, _⟩
      have hq1 : 2 * (s1.index.values.dirs.val.length + s1.index.values.rows.val.length) + 1
          ≤ Usize.max := by rw [hvals1]; exact queueRoom
      have hlive2In : IndexLiveness s1.index (framePins (branchValues bl2) ++ extraPins) := by
        rw [hvals2]; exact hlive1
      apply WP.spec_bind
        (index_retire_budget_refines s1.index (framePins (branchValues bl2) ++ extraPins)
          CcfKv.engine.RETIRE_BUDGET hlive2In hq1)
      rintro ⟨_, ai2⟩ ⟨hlive2, hpres2, hdLen2, hrLen2⟩
      change WP.spec (Result.ok _) _
      rw [WP.spec_ok]
      have hpres1 : IndexPreservesPins s.index s1.index (framePins (branchValues bl2) ++ extraPins) := by
        intro root _ bindings hview
        exact ⟨⟨by rw [hvals1]; exact hview.lookup, by rw [hvals1]; exact hview.values,
          hview.sorted⟩, by simp [singleBindings, hvals1]⟩
      have hact2 : branchValues bl2 = s.activeFrames.drop (next.val - s.global.val) := by
        rw [hvals2]; change s1.activeFrames = _; rw [hdrop1, hcountEq]
      refine ⟨hgl1.symm ▸ hnextVal, rfl, htm1, hid1, hre1, hval2,
        by change branchValues bl2 = _; rw [ite_eq_left hreuse, hgl1]; exact hact2,
        hlive2, hpres1.trans hpres2, by rw [hdLen2, hvals1], by rw [hrLen2, hvals1],
        hsub1,
        by
          intro f hf
          rcases hfrom1 f hf with hold | hnew
          · exact Or.inl hold
          · exact Or.inr ⟨hreuse, by rwa [hgl1, ← hcountEq]⟩,
        glFrame, ?_, ?_⟩
      · change (branchValues bl2)[0]? = some glFrame
        rw [hact2, ← hcountEq, List.getElem?_drop, Nat.add_zero, hglAt]
      · intro _ orig horig
        rw [hgl1, ← hcountEq] at horig
        exact hneed1 orig horig
    · have hnextEq : next = s.global := by
        unfold CcfKv.engine.compact_cut at hcutRes
        by_cases h1 : requested ≤ head.version <;> by_cases h2 : s.global < requested
        · simp only [h1, h2, ite_true, Result.ok.injEq] at hcutRes
          subst hcutRes
          exact absurd h2 hlt
        · simp only [h1, h2, ite_true, ite_false, Result.ok.injEq] at hcutRes
          exact hcutRes.symm
        · simp only [h1, ite_false, Result.ok.injEq] at hcutRes
          exact hcutRes.symm
        · simp only [h1, ite_false, Result.ok.injEq] at hcutRes
          exact hcutRes.symm
      rw [ite_eq_right hlt, WP.spec_ok]
      have hsub0 : next.val - s.global.val = 0 := by rw [hnextEq]; exact Nat.sub_self _
      refine ⟨hnextVal, rfl, rfl, rfl, rfl, valid, by simp [hreuse, hsub0], live, .refl _ _,
        rfl, rfl, fun _ hm => hm, fun _ hm => Or.inl hm, baseFrame, hbaseAt, ?_⟩
      intro _ orig horig
      simp [hsub0] at horig
  · rw [ite_eq_right hreuse, WP.spec_ok]
    refine ⟨hnextVal, rfl, rfl, rfl, rfl, valid, by simp [hreuse], live, .refl _ _,
      rfl, rfl, fun _ hm => hm, fun _ hm => Or.inl hm, baseFrame, hbaseAt, ?_⟩
    intro htrue; exact absurd htrue hreuse

/-- A request below the irrevocable cut reports rejection and leaves the entire Rust store unchanged. -/
theorem rollback_rejected (s : CcfKv.engine.Store) (requested term : U64)
    (h : requested.val < s.history.global.val)
    : CcfKv.engine.Store.execute s (.Rollback requested term)
      = .ok (.Ok .RollbackRejected, s) := by
  simp [CcfKv.engine.Store.execute, CcfKv.engine.History.rollback, h]

/-- A request at or above the cut with a stale term is disabled without changing the store. -/
theorem rollback_stale_term (s : CcfKv.engine.Store) (requested term : U64)
    (hcut : s.history.global.val ≤ requested.val) (hterm : term.val < s.history.term.val)
    : CcfKv.engine.Store.execute s (.Rollback requested term)
      = .ok (.Err .Disabled, s) := by
  simp [CcfKv.engine.Store.execute, CcfKv.engine.History.rollback, Nat.not_lt.mpr hcut, hterm]

/-- A legal rollback pops discarded frames `> cut`, shrinks the ring if sparse,
runs bounded retirement, and preserves `retained` and all surviving pins. -/
theorem history_rollback (s : CcfKv.engine.History) (requested term : U64)
    (prior : List CcfKv.engine.Frame) (head baseFrame : CcfKv.engine.Frame)
    (extraPins : List U32)
    (hframes : s.activeFrames = prior ++ [head])
    (hbaseAt : s.activeFrames[0]? = some baseFrame)
    (hbaseLeGlobal : baseFrame.version.val ≤ s.global.val)
    (hheadVer : head.version.val = baseFrame.version.val + prior.length)
    (hcut : s.global.val ≤ requested.val) (hterm : s.term.val ≤ term.val)
    (valid : BranchValid s.log)
    (live : IndexLiveness s.index (framePins s.activeFrames ++ extraPins))
    (queueRoom
      : 2 * (s.index.values.dirs.val.length + s.index.values.rows.val.length) + 1
        ≤ Usize.max)
    : WP.spec (CcfKv.engine.History.rollback s requested term)
        (fun (out, after) =>
          ∃ cut,
            out = .Ok (.RolledBack cut)
            ∧ cut.val = max s.global.val (min head.version.val requested.val)
            ∧ BranchValid after.log
            ∧ after.activeFrames
              = s.activeFrames.take (cut.val - baseFrame.version.val + 1)
            ∧ after.retained = s.retained
            ∧ after.global = s.global
            ∧ after.next_identity = s.next_identity
            ∧ after.term = term
            ∧ after.reuse_compacted_images = s.reuse_compacted_images
            ∧ IndexLiveness after.index (framePins after.activeFrames ++ extraPins)
            ∧ IndexPreservesPins s.index after.index
                (framePins after.activeFrames ++ extraPins)
            ∧ after.index.values.dirs.val.length = s.index.values.dirs.val.length
            ∧ after.index.values.rows.val.length = s.index.values.rows.val.length) := by
  let model : Store := { global := s.global.val, head := {version := head.version.val} }
  have hspec := rollback_cut_model s.global head.version requested model rfl rfl
  have hsuccess : ∃ cut, CcfKv.engine.rollback_cut s.global head.version requested = .ok cut
      ∧ cut.val = max s.global.val (min head.version.val requested.val) := by
    cases h : CcfKv.engine.rollback_cut s.global head.version requested
      using Result.cases with
    | ret cut => exact ⟨cut, rfl, by simpa [h, model, rollbackCut] using hspec⟩
    | vis _ _ => rw [h] at hspec; simp at hspec
    | div => rw [h] at hspec; simp at hspec
  obtain ⟨cut, hcutRes, hcutVal⟩ := hsuccess
  unfold CcfKv.engine.History.rollback
  rw [ite_eq_right (by change ¬ requested.val < s.global.val; omega),
    ite_eq_right (by change ¬ term.val < s.term.val; omega),
    history_head s prior head hframes valid, bind_ok, hcutRes, bind_ok]
  by_cases hdrop : cut < head.version
  · have hlt : cut.val < head.version.val := hdrop
    rw [ite_eq_left hdrop]
    have hgeBase : baseFrame.version.val ≤ cut.val := by
      have : s.global.val ≤ cut.val := by rw [hcutVal]; exact Nat.le_max_left _ _
      omega
    apply WP.spec_bind (history_relative_cut s cut baseFrame hbaseAt valid)
    intro rel hrel
    have hrelVal : rel.val = cut.val - baseFrame.version.val := by
      rw [hrel, ite_eq_right (Nat.not_lt.mpr hgeBase)]
    have hcap : s.activeFrames.length ≤ Usize.max := branch_values_capacity s.log
    have hrelLt : rel.val < prior.length := by omega
    have hcastVal : (UScalar.cast .Usize rel).val = rel.val := by
      apply UScalar.cast_val_mod_pow_of_inBounds_eq
      have hbd : rel.val ≤ Usize.max := by
        rw [hframes, List.length_append, List.length_singleton] at hcap; omega
      rw [← UScalar.max_USize_eq, UScalar.max] at hbd
      have := Nat.two_pow_pos UScalarTy.Usize.numBits
      omega
    simp only [lift, bind_ok]
    have hone : (1#usize : Usize).val = 1 := rfl
    apply WP.spec_bind (Usize.add_spec (x := UScalar.cast .Usize rel) (y := 1#usize)
      (by rw [hframes, List.length_append, List.length_singleton] at hcap; omega))
    intro keepLen hkeepLen
    have hkeepVal : keepLen.val = cut.val - baseFrame.version.val + 1 := by
      rw [hkeepLen, hcastVal, hrelVal, hone]
    have hkeepLe : keepLen.val ≤ s.activeFrames.length := by
      rw [hframes, List.length_append, List.length_singleton]; omega
    apply WP.spec_bind
      (history_pop_active_to_refines s keepLen extraPins valid (by omega) hkeepLe live queueRoom)
    intro s1 ⟨hval1, htake1, hret1, hgl1, _, hid1, hre1, hvals1, hlive1⟩
    apply WP.spec_bind (branch_shrink_refines s1.log hval1)
    intro bl2 ⟨hval2, hvals2, _⟩
    have hq1 : 2 * (s1.index.values.dirs.val.length + s1.index.values.rows.val.length) + 1
        ≤ Usize.max := by rw [hvals1]; exact queueRoom
    have hlive2In : IndexLiveness s1.index (framePins (branchValues bl2) ++ extraPins) := by
      rw [hvals2]; exact hlive1
    apply WP.spec_bind
      (index_retire_budget_refines s1.index (framePins (branchValues bl2) ++ extraPins)
        CcfKv.engine.RETIRE_BUDGET hlive2In hq1)
    rintro ⟨_, ai2⟩ ⟨hlive2, hpres2, hdLen2, hrLen2⟩
    change WP.spec (Result.ok _) _
    rw [WP.spec_ok]
    have hpres1 : IndexPreservesPins s.index s1.index (framePins (branchValues bl2) ++ extraPins) := by
      intro root _ bindings hview
      exact ⟨⟨by rw [hvals1]; exact hview.lookup, by rw [hvals1]; exact hview.values,
        hview.sorted⟩, by simp [singleBindings, hvals1]⟩
    refine ⟨cut, rfl, hcutVal, hval2,
      by change branchValues bl2 = _; rw [hvals2]; change s1.activeFrames = _; rw [htake1, hkeepVal],
      hret1, hgl1, hid1, rfl, hre1, hlive2, hpres1.trans hpres2,
      by rw [hdLen2, hvals1], by rw [hrLen2, hvals1]⟩
  · have hge : head.version.val ≤ cut.val := Nat.le_of_not_gt hdrop
    rw [ite_eq_right hdrop, WP.spec_ok]
    have htakeAll : s.activeFrames.take (cut.val - baseFrame.version.val + 1) = s.activeFrames := by
      apply List.take_of_length_le
      rw [hframes, List.length_append, List.length_singleton]
      omega
    exact ⟨cut, rfl, hcutVal, valid, htakeAll.symm, rfl, rfl, rfl, rfl, rfl, live, .refl _ _,
      rfl, rfl⟩

end KvRust
