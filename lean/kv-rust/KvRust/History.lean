-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.BranchLog
public import KvRust.KvIndex
public import Kv.Model

import all Aeneas.Data.List.List

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

abbrev _root_.Spike.engine.History.activeFrames (history : Spike.engine.History)
    : List Spike.engine.Frame :=
  branchValues history.log

/-- Every previously issued frame slot retains its value across this history update. -/
def FrameSlotsPreserved (before after : Spike.engine.History) : Prop :=
  ∀ (i : Nat) frame,
    before.log.frames.val[i]? = some frame → after.log.frames.val[i]? = some frame

theorem FrameSlotsPreserved.of_same (before after : Spike.engine.History)
    (same : after.log.frames = before.log.frames)
    : FrameSlotsPreserved before after := by
  intro i frame saved
  simpa only [same] using saved

private theorem returning {α : Type} {r : Result α} {p : α → Prop} (h : WP.spec r p)
    : ∃ v, r = .ok v ∧ p v := by
  cases r using Result.cases with
  | ret v => exact ⟨v, rfl, by simpa using h⟩
  | vis _ _ => simp at h
  | div => simp at h

/-- The history vector is the model's history in reverse chronological order. -/
def modelFrames (s : Spike.engine.History) (project : Spike.engine.Frame → Frame)
    : List Frame :=
  s.activeFrames.reverse.map project

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
    (head : Spike.engine.Frame) (h : history.activeFrames = prior ++ [head])
    (valid : BranchValid history.log)
    : Spike.engine.History.head history = .ok head := by
  have hit : WP.spec (Spike.engine.History.head history) (· = head) := by
    unfold Spike.engine.History.head
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

/-- For histories generated from the model's initial state, cut offsets are absolute. -/
theorem history_relative_cut_zero (s : Spike.engine.History) (cut : U64)
    (hNonempty : s.activeFrames ≠ [])
    (hIndexed : ∀ i (hi : i < s.activeFrames.length), s.activeFrames[i].version.val = i)
    (valid : BranchValid s.log)
    : Spike.engine.History.relative_cut s cut = .ok cut := by
  have hb : 0 < s.activeFrames.length := List.length_pos_iff.mpr hNonempty
  have hBase := hIndexed 0 hb
  have hRead : s.activeFrames[0]? = some s.activeFrames[0] := List.getElem?_eq_getElem hb
  have hZero : s.activeFrames[0].version = 0#u64 := UScalar.eq_of_val_eq hBase
  obtain ⟨first, selected, hfirst⟩ := returning
    (branch_active_at s.log valid 0#usize s.activeFrames[0] hRead)
  simp [Spike.engine.History.relative_cut, selected, hfirst, hZero]
  obtain ⟨offset, hr, hv⟩ := returning
    (U64.sub_spec (x := cut) (y := 0#u64) (by scalar_tac))
  have he : offset = cut := UScalar.eq_of_val_eq (by simpa using hv)
  simpa [he] using hr

/-- With a zero base, the extracted cut lookup clamps to the last retained vector index. -/
theorem history_at_cut_index (s : Spike.engine.History) (cut : U64)
    (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hframes : s.activeFrames = prior ++ [head])
    (hzero : Spike.engine.History.relative_cut s cut = .ok cut)
    (valid : BranchValid s.log)
    : WP.spec (Spike.engine.History.at_cut s cut)
        (fun f => s.activeFrames[min cut.val prior.length]? = some f) := by
  unfold Spike.engine.History.at_cut Spike.engine.History.pin_cut
  simp only [hzero, bind_ok]
  apply WP.spec_bind (branch_cut_refines s.log valid cut)
  rintro id ⟨frame, saved, selected⟩
  apply WP.spec_mono (branch_read_refines s.log id frame saved)
  intro actual hread
  have last : s.log.branch.val.length - 1 = prior.length := by
    rw [← branch_values_length s.log valid]
    change s.activeFrames.length - 1 = _
    simp [hframes]
  simpa [last, hread] using selected

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
    (hframes : s.activeFrames = prior ++ [head])
    (hmodel : model.history = modelFrames s project)
    (hzero : Spike.engine.History.relative_cut s cut = .ok cut)
    (hversions
      : ∀ i (hi : i < s.activeFrames.length), (project s.activeFrames[i]).version = i)
    (valid : BranchValid s.log)
    : WP.spec (Spike.engine.History.at_cut s cut)
        (fun f => project f = atCut model cut.val ∧ project f ∈ model.history) := by
  apply WP.spec_mono (history_at_cut_index s cut prior head hframes hzero valid)
  intro f hf
  have hlen : s.activeFrames.length - 1 = prior.length := by simp [hframes]
  have he : model.history.find? (fun fr => decide (fr.version ≤ cut.val)) = some (project f) := by
    rw [hmodel, modelFrames, find_reverse_indexed _ project _ hversions, hlen, hf]
    rfl
  exact ⟨by simp [atCut, he], List.mem_of_find?_eq_some he⟩

/-- Pinning a cut returns a stable frame slot with the model's selected value. -/
theorem history_pin_cut_matches_model (s : Spike.engine.History) (cut : U64)
    (model : Store) (project : Spike.engine.Frame → Frame)
    (hmodel : model.history = modelFrames s project)
    (hzero : Spike.engine.History.relative_cut s cut = .ok cut)
    (hversions
      : ∀ i (hi : i < s.activeFrames.length), (project s.activeFrames[i]).version = i)
    (valid : BranchValid s.log)
    : WP.spec (Spike.engine.History.pin_cut s cut)
        (fun id =>
          ∃ frame,
            s.log.frames.val[id.val]? = some frame
            ∧ project frame = atCut model cut.val
            ∧ project frame ∈ model.history) := by
  unfold Spike.engine.History.pin_cut
  simp only [hzero, bind_ok]
  apply WP.spec_mono (branch_cut_refines s.log valid cut)
  rintro id ⟨frame, saved, selected⟩
  have len : s.log.branch.val.length = s.activeFrames.length :=
    (branch_values_length s.log valid).symm
  change s.activeFrames[min cut.val (s.log.branch.val.length - 1)]? = some frame at selected
  rw [len] at selected
  have found : model.history.find? (fun f => decide (f.version ≤ cut.val))
      = some (project frame) := by
    rw [hmodel, modelFrames, find_reverse_indexed _ project _ hversions, selected]
    rfl
  exact ⟨frame, saved, by simp [atCut, found], List.mem_of_find?_eq_some found⟩

/-- The version of the selected reference frame is the cut clamped to the surviving branch. -/
theorem model_cut_version (s : Spike.engine.History) (model : Store)
    (project : Spike.engine.Frame → Frame)
    (nonempty : s.activeFrames ≠ [])
    (hmodel : model.history = modelFrames s project)
    (indexed
      : ∀ i (hi : i < s.activeFrames.length), (project s.activeFrames[i]).version = i)
    (cut : Nat)
    : (atCut model cut).version = min cut (s.activeFrames.length - 1) := by
  have hlen : 0 < s.activeFrames.length := List.length_pos_iff.mpr nonempty
  have hi : min cut (s.activeFrames.length - 1) < s.activeFrames.length := by omega
  rw [atCut, hmodel, modelFrames, find_reverse_indexed _ _ _ indexed,
    List.getElem?_eq_getElem hi]
  exact indexed _ hi

/-- All non-empty radix roots currently retained by archived frames. -/
def framePins (frames : List Spike.engine.Frame) : List U32 :=
  frames.filterMap fun f => if f.data = 0#u32 then none else some f.data

theorem framePins_append (frames : List Spike.engine.Frame) (f : Spike.engine.Frame)
    : (framePins (frames ++ [f])).Perm
        (if f.data = 0#u32 then framePins frames else f.data :: framePins frames) := by
  unfold framePins
  rw [List.filterMap_append, List.filterMap_cons, List.filterMap_nil]
  by_cases hz : f.data = 0#u32
  · simp [hz]
  · simp only [hz, ite_false]
    exact List.perm_append_singleton f.data _

theorem framePins_set_clear (frames : List Spike.engine.Frame) (i : Nat)
    (f : Spike.engine.Frame) (hget : frames[i]? = some f)
    : (framePins frames).Perm
        (if f.data = 0#u32 then
            framePins (frames.set i { f with data := 0#u32 })
          else
            f.data :: framePins (frames.set i { f with data := 0#u32 })) := by
  induction frames generalizing i with
  | nil => simp at hget
  | cons hd tl ih =>
      cases i with
      | zero =>
          simp only [List.getElem?_cons_zero, Option.some.injEq] at hget
          subst hget
          unfold framePins
          simp only [List.set_cons_zero, List.filterMap_cons, ite_true]
          by_cases hz : hd.data = 0#u32 <;> simp [hz]
      | succ j =>
          simp only [List.getElem?_cons_succ] at hget
          have hsub := ih j hget
          unfold framePins at hsub ⊢
          simp only [List.set_cons_succ, List.filterMap_cons]
          by_cases hhd : hd.data = 0#u32
          · simp only [hhd, ite_true]
            exact hsub
          · simp only [hhd, ite_false]
            by_cases hf : f.data = 0#u32
            · simp only [hf, ite_true] at hsub ⊢
              exact hsub.cons hd.data
            · simp only [hf, ite_false] at hsub ⊢
              exact (hsub.cons hd.data).trans (List.Perm.swap f.data hd.data _)

/-- Releasing active frames in `[start, end)` clears only their `data` roots,
keeps all frame metadata and branch IDs intact, and preserves liveness against
the updated `framePins ++ extraPins`. -/
theorem history_release_active_range_refines (s : Spike.engine.History)
    (start «end» : Usize) (extraPins : List U32)
    (valid : BranchValid s.log) (unique : BranchUnique s.log)
    (hle : start.val ≤ «end».val) (hbound : «end».val ≤ s.log.branch.val.length)
    (live : IndexLiveness s.index (framePins s.log.frames.val ++ extraPins))
    (queueRoom
      : 2 * (s.index.values.dirs.val.length + s.index.values.rows.val.length) + 1
        ≤ Usize.max)
    : WP.spec (Spike.engine.History.release_active_range s start «end»)
        (fun after =>
          after.log.branch = s.log.branch
          ∧ after.global = s.global
          ∧ after.term = s.term
          ∧ after.next_identity = s.next_identity
          ∧ after.reuse_compacted_images = s.reuse_compacted_images
          ∧ after.index.values = s.index.values
          ∧ BranchValid after.log
          ∧ BranchUnique after.log
          ∧ IndexLiveness after.index (framePins after.log.frames.val ++ extraPins)
          ∧ after.log.frames.val.length = s.log.frames.val.length
          ∧ (∀ (k : Nat) (f : Spike.engine.Frame),
              s.log.frames.val[k]? = some f
              → ∃ f',
                  after.log.frames.val[k]? = some f'
                  ∧ f'.version = f.version
                  ∧ f'.revisions = f.revisions
                  ∧ f'.births = f.births
                  ∧ (f'.data = f.data ∨ f'.data = 0#u32)
                  ∧ ((∀ off (id : Usize),
                        start.val ≤ off
                        → off < «end».val
                        → s.log.branch.val[off]? = some id
                        → id.val ≠ k)
                      → f' = f))) := by
  unfold Spike.engine.History.release_active_range Spike.engine.History.release_active_range_loop
  let endVal := «end».val
  apply loop.spec_decr_nat
    (fun (_, i) => endVal - i.val)
    (fun (cur, i) =>
      start.val ≤ i.val ∧ i.val ≤ endVal
      ∧ cur.log.branch = s.log.branch
      ∧ cur.global = s.global
      ∧ cur.term = s.term
      ∧ cur.next_identity = s.next_identity
      ∧ cur.reuse_compacted_images = s.reuse_compacted_images
      ∧ cur.index.values = s.index.values
      ∧ BranchValid cur.log
      ∧ BranchUnique cur.log
      ∧ IndexLiveness cur.index (framePins cur.log.frames.val ++ extraPins)
      ∧ cur.log.frames.val.length = s.log.frames.val.length
      ∧ ∀ (k : Nat) (f : Spike.engine.Frame),
          s.log.frames.val[k]? = some f →
          ∃ f', cur.log.frames.val[k]? = some f'
            ∧ f'.version = f.version
            ∧ f'.revisions = f.revisions
            ∧ f'.births = f.births
            ∧ (f'.data = f.data ∨ f'.data = 0#u32)
            ∧ ((∀ off (id : Usize), start.val ≤ off → off < i.val →
                  s.log.branch.val[off]? = some id → id.val ≠ k)
                → f' = f))
    _ _ _
  · rintro ⟨cur, i⟩ ⟨hsi, hie, hbr, hgl, htm, hid, hreuse, hvals, hval, huniq, hlive, hflen, hslots⟩
    dsimp only at hsi hie hbr hgl htm hid hreuse hvals hval huniq hlive hflen hslots ⊢
    unfold Spike.engine.History.release_active_range_loop.body
    by_cases hlt : i < «end»
    · have hilt : i.val < «end».val := hlt
      have hcap : «end».val ≤ Usize.max := by scalar_tac
      have hone : (1#usize : Usize).val = 1 := rfl
      rw [ite_eq_left hlt]
      apply WP.spec_bind (branch_resolve_refines cur.log i)
      intro opt hopt
      have hiBr : i.val < cur.log.branch.val.length := by rw [hbr]; omega
      obtain ⟨id, hidAt⟩ : ∃ id, cur.log.branch.val[i.val]? = some id :=
        ⟨cur.log.branch.val[i.val], List.getElem?_eq_getElem hiBr⟩
      rw [hidAt] at hopt
      subst opt
      have hidBound : id.val < cur.log.frames.val.length :=
        hval.2 id (List.mem_iff_getElem?.mpr ⟨i.val, hidAt⟩)
      obtain ⟨fCur, hfCur⟩ : ∃ fCur, cur.log.frames.val[id.val]? = some fCur :=
        ⟨cur.log.frames.val[id.val], List.getElem?_eq_getElem hidBound⟩
      have hbody :
          WP.spec
            (do
              let f ← Spike.branch_log.BranchLog.read cur.log id
              let b ← Spike.radix.RadixRoot.is_empty f.data
              if b then Result.ok (cur.log, cur.index)
              else do
                let rr ← Spike.kv_index.AddressIndex.empty_root cur.index
                let (f1, read_mut_back) ← Spike.branch_log.BranchLog.read_mut cur.log id
                let ai1 ← Spike.kv_index.AddressIndex.release_root cur.index f.data
                let bl1 := read_mut_back { f1 with data := rr }
                Result.ok (bl1, ai1))
            (fun (bl1, ai1) =>
              bl1.branch = s.log.branch
              ∧ ai1.values = s.index.values
              ∧ BranchValid bl1
              ∧ BranchUnique bl1
              ∧ IndexLiveness ai1 (framePins bl1.frames.val ++ extraPins)
              ∧ bl1.frames.val.length = s.log.frames.val.length
              ∧ ∀ (k : Nat) (f : Spike.engine.Frame),
                  s.log.frames.val[k]? = some f →
                  ∃ f', bl1.frames.val[k]? = some f'
                    ∧ f'.version = f.version
                    ∧ f'.revisions = f.revisions
                    ∧ f'.births = f.births
                    ∧ (f'.data = f.data ∨ f'.data = 0#u32)
                    ∧ ((∀ off (id0 : Usize), start.val ≤ off → off < i.val + 1 →
                          s.log.branch.val[off]? = some id0 → id0.val ≠ k)
                        → f' = f)) := by
        apply WP.spec_bind (branch_read_refines cur.log id fCur hfCur)
        intro fRead hfRead
        subst fRead
        unfold Spike.radix.RadixRoot.is_empty
        by_cases hzero : fCur.data = 0#u32
        · simp only [hzero, decide_true, bind_ok, ite_true, WP.spec_ok]
          refine ⟨hbr, hvals, hval, huniq, hlive, hflen, fun k f hf => ?_⟩
          obtain ⟨f', hf', hv, hr, hb, hd, hunt⟩ := hslots k f hf
          refine ⟨f', hf', hv, hr, hb, hd, fun hno => ?_⟩
          exact hunt (fun off id0 h1 h2 h3 => hno off id0 h1 (by omega) h3)
        · simp only [hzero, decide_false, bind_ok, Bool.false_eq_true, ite_false]
          apply WP.spec_bind (index_empty_root_refines cur.index)
          intro rr ⟨hrr0, _⟩
          subst hrr0
          apply WP.spec_bind (branch_read_mut_refines cur.log id fCur hfCur)
          rintro ⟨f1, back⟩ ⟨hf1Eq, hback⟩
          subst f1
          let bl1 := back { fCur with data := 0#u32 }
          obtain ⟨hblBr, hblFr⟩ := hback { fCur with data := 0#u32 }
          have hperm := framePins_set_clear cur.log.frames.val id.val fCur hfCur
          simp only [hzero, ite_false] at hperm
          have hlivePerm : IndexLiveness cur.index
              (if fCur.data = 0#u32 then framePins bl1.frames.val ++ extraPins
               else fCur.data :: (framePins bl1.frames.val ++ extraPins)) := by
            simp only [hzero, ite_false]
            have hp2 : (framePins cur.log.frames.val ++ extraPins).Perm
                (fCur.data :: (framePins bl1.frames.val ++ extraPins)) := by
              rw [hblFr]
              exact (hperm.append_right extraPins).trans List.Perm.rfl
            exact hlive.perm hp2
          have hqCur : 2 * (cur.index.values.dirs.val.length + cur.index.values.rows.val.length) + 1 ≤ Usize.max := by
            rw [hvals]; exact queueRoom
          apply WP.spec_bind
            (index_release_root_refines cur.index (framePins bl1.frames.val ++ extraPins)
              fCur.data hlivePerm hqCur)
          intro ai1 ⟨haiVals, haiLive⟩
          change WP.spec (Result.ok (bl1, ai1)) _
          rw [WP.spec_ok]
          have hblLen : bl1.frames.val.length = s.log.frames.val.length := by
            rw [hblFr, List.length_set, hflen]
          have hblValid : BranchValid bl1 := by
            refine ⟨hblBr.symm ▸ hval.1, fun j hj => ?_⟩
            rw [hblLen, ← hflen]
            exact hval.2 j (hblBr ▸ hj)
          have hblUniq : BranchUnique bl1 := by
            unfold BranchUnique; rw [hblBr]; exact huniq
          refine ⟨hblBr.trans hbr, haiVals.trans hvals, hblValid, hblUniq, haiLive, hblLen, ?_⟩
          intro k f hf
          obtain ⟨f', hf', hv, hr, hb, hd, hunt⟩ := hslots k f hf
          by_cases hk : k = id.val
          · subst hk
            have hsame : f' = fCur := Option.some.inj (hf'.symm.trans hfCur)
            subst hsame
            refine ⟨{ f' with data := 0#u32 }, ?_, hv, hr, hb, Or.inr rfl, fun hno => ?_⟩
            · rw [hblFr, List.getElem?_set_self hidBound]
            · exfalso
              exact hno i.val id hsi (by omega) (hbr ▸ hidAt) rfl
          · refine ⟨f', ?_, hv, hr, hb, hd, fun hno => ?_⟩
            · rw [hblFr, List.getElem?_set_ne (Ne.symm hk)]
              exact hf'
            · exact hunt (fun off id0 h1 h2 h3 => hno off id0 h1 (by omega) h3)
      apply WP.spec_bind hbody
      rintro ⟨bl1, ai1⟩ ⟨hbr1, hvals1, hval1, huniq1, hlive1, hflen1, hslots1⟩
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro i1 hi1
      change WP.spec (Result.ok (ControlFlow.cont ({ cur with log := bl1, index := ai1 }, i1))) _
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨by omega, by omega, hbr1, hgl, htm, hid, hreuse, hvals1, hval1, huniq1,
        hlive1, hflen1, ?_⟩, by omega⟩
      intro k f hf
      obtain ⟨f', hf', hv, hr, hb, hd, hunt⟩ := hslots1 k f hf
      exact ⟨f', hf', hv, hr, hb, hd, fun hno => hunt (fun off id0 h1 h2 h3 =>
        hno off id0 h1 (by omega) h3)⟩
    · have hiEq : i.val = endVal := by
        have : ¬ i.val < «end».val := hlt
        omega
      rw [ite_eq_right hlt, WP.spec_ok]
      refine ⟨hbr, hgl, htm, hid, hreuse, hvals, hval, huniq, hlive, hflen, ?_⟩
      intro k f hf
      obtain ⟨f', hf', hv, hr, hb, hd, hunt⟩ := hslots k f hf
      refine ⟨f', hf', hv, hr, hb, hd, fun hno => hunt (fun off id0 h1 h2 h3 => ?_)⟩
      exact hno off id0 h1 (by omega) h3
  · exact ⟨Nat.le_refl _, hle, rfl, rfl, rfl, rfl, rfl, rfl, valid, unique, live, rfl,
      fun k f hf => ⟨f, hf, rfl, rfl, rfl, Or.inl rfl, fun _ => rfl⟩⟩

/-- Compaction advances the frontier, releases compacted roots `< next` when
`reuse_compacted_images` is enabled, runs bounded retirement, and preserves all
remaining pins. -/
theorem history_compact (s : Spike.engine.History) (requested : U64)
    (model : Store) (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (extraPins : List U32)
    (hframes : s.activeFrames = prior ++ [head]) (hg : model.global = s.global.val)
    (hh : model.head.version = head.version.val)
    (hIndexed : ∀ i (hi : i < s.activeFrames.length), s.activeFrames[i].version.val = i)
    (valid : BranchValid s.log) (unique : BranchUnique s.log)
    (live : IndexLiveness s.index (framePins s.log.frames.val ++ extraPins))
    (queueRoom
      : 2 * (s.index.values.dirs.val.length + s.index.values.rows.val.length) + 1
        ≤ Usize.max)
    : WP.spec (Spike.engine.History.compact s requested)
        (fun (cut, after) =>
          cut.val = (compactStore model requested.val).global
          ∧ after.global = cut
          ∧ after.term = s.term
          ∧ after.next_identity = s.next_identity
          ∧ after.reuse_compacted_images = s.reuse_compacted_images
          ∧ after.log.branch = s.log.branch
          ∧ BranchValid after.log
          ∧ BranchUnique after.log
          ∧ IndexLiveness after.index (framePins after.log.frames.val ++ extraPins)
          ∧ IndexPreservesPins s.index after.index
              (framePins after.log.frames.val ++ extraPins)
          ∧ after.index.values.dirs.val.length = s.index.values.dirs.val.length
          ∧ after.index.values.rows.val.length = s.index.values.rows.val.length
          ∧ after.log.frames.val.length = s.log.frames.val.length
          ∧ (∀ (k : Nat) (f : Spike.engine.Frame),
              s.log.frames.val[k]? = some f
              → ∃ f',
                  after.log.frames.val[k]? = some f'
                  ∧ f'.version = f.version
                  ∧ f'.revisions = f.revisions
                  ∧ f'.births = f.births
                  ∧ (f'.data = f.data ∨ f'.data = 0#u32)
                  ∧ ((s.reuse_compacted_images = false
                        ∨ ∀ off (id : Usize),
                            s.global.val ≤ off
                            → off < cut.val
                            → s.log.branch.val[off]? = some id
                            → id.val ≠ k)
                      → f' = f))) := by
  have hcutModel := compact_cut_model s.global head.version requested model hg hh
  have hnonempty : s.activeFrames ≠ [] := by simp [hframes]
  have hheadVer : head.version.val = prior.length := by
    have hidx : prior.length < s.activeFrames.length := by simp [hframes]
    have hi := hIndexed prior.length hidx
    have he : s.activeFrames[prior.length] = head := by
      apply Option.some.inj
      rw [← List.getElem?_eq_getElem hidx, hframes]
      simp
    rwa [he] at hi
  unfold Spike.engine.History.compact
  rw [history_head s prior head hframes valid, bind_ok]
  cases hcutRun : Spike.engine.compact_cut s.global head.version requested
    using Result.cases with
  | div => rw [hcutRun] at hcutModel; simp at hcutModel
  | vis _ _ => rw [hcutRun] at hcutModel; simp at hcutModel
  | ret next =>
      change Spike.engine.compact_cut s.global head.version requested = Result.ok next at hcutRun
      have hnextVal : next.val = (compactStore model requested.val).global := by
        simpa [hcutRun] using hcutModel
      rw [bind_ok]
      by_cases hreuse : s.reuse_compacted_images = true
      · rw [ite_eq_left hreuse]
        by_cases hlt : s.global < next
        · rw [ite_eq_left hlt]
          have hltVal : s.global.val < next.val := hlt
          have hnextLe : next.val ≤ head.version.val := by
            unfold Spike.engine.compact_cut at hcutRun
            split at hcutRun
            · split at hcutRun
              · rw [Result.ok.injEq] at hcutRun; subst hcutRun; assumption
              · rw [Result.ok.injEq] at hcutRun; subst hcutRun; exact absurd hltVal (Nat.lt_irrefl _)
            · rw [Result.ok.injEq] at hcutRun; subst hcutRun; exact absurd hltVal (Nat.lt_irrefl _)
          have hzero1 := history_relative_cut_zero { s with global := next } s.global hnonempty hIndexed valid
          have hzero2 := history_relative_cut_zero { s with global := next } next hnonempty hIndexed valid
          simp only [hzero1, hzero2, lift, bind_ok]
          have hsize : s.activeFrames.length ≤ Usize.max := branch_values_capacity s.log
          have hactLen : s.activeFrames.length = prior.length + 1 := by simp [hframes]
          have hbrLen : s.log.branch.val.length = prior.length + 1 := by
            rw [← branch_values_length s.log valid]
            exact hactLen
          have hstartVal : (UScalar.cast .Usize s.global).val = s.global.val := by
            apply UScalar.cast_val_mod_pow_of_inBounds_eq
            have hcap : s.global.val ≤ Usize.max := by omega
            rw [← UScalar.max_USize_eq, UScalar.max] at hcap
            have := Nat.two_pow_pos UScalarTy.Usize.numBits
            omega
          have hendVal : (UScalar.cast .Usize next).val = next.val := by
            apply UScalar.cast_val_mod_pow_of_inBounds_eq
            have hcap : next.val ≤ Usize.max := by omega
            rw [← UScalar.max_USize_eq, UScalar.max] at hcap
            have := Nat.two_pow_pos UScalarTy.Usize.numBits
            omega
          apply WP.spec_bind
            (history_release_active_range_refines { s with global := next }
              (UScalar.cast .Usize s.global) (UScalar.cast .Usize next) extraPins
              valid unique (by rw [hstartVal, hendVal]; omega)
              (by change (UScalar.cast .Usize next).val ≤ s.log.branch.val.length; rw [hendVal]; omega)
              live queueRoom)
          intro s1 ⟨hbr1, hgl1, htm1, hid1, hre1, hvals1, hval1, huniq1, hlive1, hflen1, hslots1⟩
          have hq1 : 2 * (s1.index.values.dirs.val.length + s1.index.values.rows.val.length) + 1 ≤ Usize.max := by
            rw [hvals1]; exact queueRoom
          apply WP.spec_bind
            (index_retire_budget_refines s1.index (framePins s1.log.frames.val ++ extraPins)
              Spike.engine.RETIRE_BUDGET hlive1 hq1)
          rintro ⟨_, ai⟩ ⟨hlive2, hpres2, hdLen2, hrLen2⟩
          change WP.spec (Result.ok (s1.global, { s1 with index := ai })) _
          rw [WP.spec_ok]
          have hpres1 : IndexPreservesPins s.index s1.index (framePins s1.log.frames.val ++ extraPins) :=
            index_preserves_pins_of_keeps (by unfold IndexKeeps; rw [hvals1]; exact .refl _)
          refine ⟨hgl1.symm ▸ hnextVal, rfl, htm1, hid1, hre1, hbr1, hval1, huniq1, hlive2,
            hpres1.trans hpres2, by rw [hdLen2, hvals1], by rw [hrLen2, hvals1], hflen1, ?_⟩
          intro k f hf
          obtain ⟨f', hf', hv, hr, hb, hd, hunt⟩ := hslots1 k f hf
          refine ⟨f', hf', hv, hr, hb, hd, ?_⟩
          rintro (hfalse | hno)
          · rw [hreuse] at hfalse; cases hfalse
          · apply hunt
            intro off id0 h1 h2 hEq
            rw [hstartVal] at h1
            rw [hendVal] at h2
            exact hno off id0 h1 (hgl1.symm ▸ h2) (by simpa using hEq)
        · rw [ite_eq_right hlt, WP.spec_ok]
          exact ⟨hnextVal, rfl, rfl, rfl, rfl, rfl, valid, unique, live, .refl _ _, rfl, rfl, rfl,
            fun k f hf => ⟨f, hf, rfl, rfl, rfl, Or.inl rfl, fun _ => rfl⟩⟩
      · rw [ite_eq_right hreuse, WP.spec_ok]
        exact ⟨hnextVal, rfl, rfl, rfl, rfl, rfl, valid, unique, live, .refl _ _, rfl, rfl, rfl,
          fun k f hf => ⟨f, hf, rfl, rfl, rfl, Or.inl rfl, fun _ => rfl⟩⟩

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

/-- A legal rollback releases discarded frames `> cut`, rewinds the active branch
to the prefix through `cut`, runs bounded retirement, and preserves all surviving pins. -/
theorem history_rollback (s : Spike.engine.History) (requested term : U64)
    (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (extraPins : List U32)
    (hframes : s.activeFrames = prior ++ [head])
    (hindex : head.version.val = prior.length)
    (hzero : ∀ cut, Spike.engine.History.relative_cut s cut = .ok cut)
    (hcut : s.global.val ≤ requested.val) (hterm : s.term.val ≤ term.val)
    (valid : BranchValid s.log) (unique : BranchUnique s.log)
    (live : IndexLiveness s.index (framePins s.log.frames.val ++ extraPins))
    (queueRoom
      : 2 * (s.index.values.dirs.val.length + s.index.values.rows.val.length) + 1
        ≤ Usize.max)
    : WP.spec (Spike.engine.History.rollback s requested term)
        (fun (out, after) =>
          ∃ cut,
            out = .Ok (.RolledBack cut)
            ∧ cut.val = max s.global.val (min head.version.val requested.val)
            ∧ after.log.branch.val = s.log.branch.val.take (cut.val + 1)
            ∧ after.global = s.global
            ∧ after.next_identity = s.next_identity
            ∧ after.term = term
            ∧ after.reuse_compacted_images = s.reuse_compacted_images
            ∧ BranchValid after.log
            ∧ BranchUnique after.log
            ∧ IndexLiveness after.index (framePins after.log.frames.val ++ extraPins)
            ∧ IndexPreservesPins s.index after.index
                (framePins after.log.frames.val ++ extraPins)
            ∧ after.index.values.dirs.val.length = s.index.values.dirs.val.length
            ∧ after.index.values.rows.val.length = s.index.values.rows.val.length
            ∧ after.log.frames.val.length = s.log.frames.val.length
            ∧ (∀ (k : Nat) (f : Spike.engine.Frame),
                s.log.frames.val[k]? = some f
                → ∃ f',
                    after.log.frames.val[k]? = some f'
                    ∧ f'.version = f.version
                    ∧ f'.revisions = f.revisions
                    ∧ f'.births = f.births
                    ∧ (f'.data = f.data ∨ f'.data = 0#u32)
                    ∧ ((∀ off (id : Usize),
                          cut.val + 1 ≤ off
                          → off < s.log.branch.val.length
                          → s.log.branch.val[off]? = some id
                          → id.val ≠ k)
                        → f' = f))) := by
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
  have hlen : s.activeFrames.length = prior.length + 1 := by simp [hframes]
  have hbrLen : s.log.branch.val.length = prior.length + 1 := by
    rw [← branch_values_length s.log valid]
    exact hlen
  unfold Spike.engine.History.rollback
  have hnotLow : ¬ (requested < s.global) := by change ¬ (requested.val < s.global.val); omega
  have hnotTerm : ¬ (term < s.term) := by change ¬ (term.val < s.term.val); omega
  rw [ite_eq_right hnotLow, ite_eq_right hnotTerm,
    history_head s prior head hframes valid, bind_ok, hcalc, bind_ok]
  by_cases hsmall : cut < head.version
  · rw [ite_eq_left hsmall]
    have hsmallVal : cut.val < head.version.val := hsmall
    rw [hzero cut, bind_ok, lift, bind_ok]
    let offset := UScalar.cast .Usize cut
    have hsize : s.activeFrames.length ≤ Usize.max := branch_values_capacity s.log
    have hbound : cut.val ≤ Usize.max := by omega
    have hoff : offset.val = cut.val := by
      apply UScalar.cast_val_mod_pow_of_inBounds_eq
      have := hbound
      rw [← UScalar.max_USize_eq, UScalar.max] at this
      have := Nat.two_pow_pos UScalarTy.Usize.numBits
      omega
    have hone : (1#usize : Usize).val = 1 := rfl
    apply WP.spec_bind (branch_active_len s.log valid)
    intro activeLen hal
    have halVal : activeLen.val = prior.length + 1 := by
      change activeLen.val = s.activeFrames.length at hal
      omega
    apply WP.spec_bind (Usize.add_spec (x := offset) (y := 1#usize) (by omega))
    intro start hstart
    have hstartVal : start.val = cut.val + 1 := by omega
    apply WP.spec_bind
      (history_release_active_range_refines s start activeLen extraPins valid unique
        (by omega) (by omega) live queueRoom)
    intro s1 ⟨hbr1, hgl1, htm1, hid1, hre1, hvals1, hval1, huniq1, hlive1, hflen1, hslots1⟩
    apply WP.spec_bind (branch_rewind_refines s1.log offset hval1)
    rintro ⟨ok, bl⟩ ⟨hok, hvalBl, hfrBl, hrew⟩
    have hoffLt : offset.val < s1.log.branch.val.length := by rw [hbr1, hbrLen]; omega
    have hokTrue : ok = true := by simpa [hoffLt] using hok
    subst hokTrue
    simp only [ite_true] at hrew
    obtain ⟨_, hbrBl⟩ := hrew
    change WP.spec (do
      massert true
      let (_, ai) ← Spike.kv_index.AddressIndex.retire_budget s1.index Spike.engine.RETIRE_BUDGET
      Result.ok (core.result.Result.Ok (Spike.engine.Output.RolledBack cut),
        { s1 with log := bl, index := ai, term })) _
    simp only [massert, ite_true, bind_ok]
    have hq1 : 2 * (s1.index.values.dirs.val.length + s1.index.values.rows.val.length) + 1 ≤ Usize.max := by
      rw [hvals1]; exact queueRoom
    apply WP.spec_bind
      (index_retire_budget_refines s1.index (framePins s1.log.frames.val ++ extraPins)
        Spike.engine.RETIRE_BUDGET hlive1 hq1)
    rintro ⟨_, ai⟩ ⟨hlive2, hpres2, hdLen2, hrLen2⟩
    change WP.spec (Result.ok (core.result.Result.Ok (Spike.engine.Output.RolledBack cut),
      { s1 with log := bl, index := ai, term })) _
    rw [WP.spec_ok]
    have hpres1 : IndexPreservesPins s.index s1.index (framePins s1.log.frames.val ++ extraPins) :=
      index_preserves_pins_of_keeps (by unfold IndexKeeps; rw [hvals1]; exact .refl _)
    have huniqBl : BranchUnique bl := branch_rewind_unique huniq1 hbrBl
    refine ⟨cut, rfl, hvalue, ?_, hgl1, hid1, rfl, hre1, hvalBl, huniqBl,
      by rw [hfrBl]; exact hlive2, by rw [hfrBl]; exact hpres1.trans hpres2,
      by rw [hdLen2, hvals1], by rw [hrLen2, hvals1], by rw [hfrBl, hflen1], ?_⟩
    · rw [hbrBl, hbr1, hoff]
    · intro k f hf
      rw [hfrBl]
      obtain ⟨f', hf', hv, hr, hb, hd, hunt⟩ := hslots1 k f hf
      refine ⟨f', hf', hv, hr, hb, hd, fun hno => hunt (fun off id0 h1 h2 hEq => ?_)⟩
      exact hno off id0 (by omega) (by omega) hEq
  · rw [ite_eq_right hsmall, WP.spec_ok]
    have hge : head.version.val ≤ cut.val := Nat.le_of_not_gt hsmall
    refine ⟨cut, rfl, hvalue, ?_, rfl, rfl, rfl, rfl, valid, unique, live, .refl _ _, rfl, rfl, rfl,
      fun k f hf => ⟨f, hf, rfl, rfl, rfl, Or.inl rfl, fun _ => rfl⟩⟩
    symm
    apply List.take_of_length_le
    omega

end KvRust
