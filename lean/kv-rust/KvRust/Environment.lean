-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Relation

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Compaction advances only the modeled frontier. -/
theorem compact_step_matches (encode : List U8 → String) (sid : Nat)
    (native : Spike.engine.Store) (w : State) (cut : U64)
    (related : StateMatches encode sid native w)
    : WP.spec (Spike.engine.Store.execute native (.Compact cut))
        (StepMatches encode sid (.compact sid cut.val) native
          (execute w (.compact sid cut.val))) := by
  obtain ⟨s, archive, hs, h, hattempts⟩ := related.history
  obtain ⟨prior, head, hframes, hhead⟩ := h.split
  obtain ⟨result, hrun, hcut⟩ := history_compact native.history cut s prior head
    hframes h.global hhead.version.symm h.valid
  let store := compactStore s cut.val
  let w' := {w with stores := Kv.Model.set w.stores sid store}
  let next := {native with history := {native.history with global := result}}
  have he : execute w (.compact sid cut.val) = some (w', .compacted store.global) := by
    simp [execute, hs, w', store]
  have hn : HistoryMatches encode next.history store archive := by
    have he' : store = {s with global := store.global} := by
      unfold store compactStore
      split <;> rfl
    refine ⟨h.nonempty, ?_, ?_, h.indexed, hcut.symm, ?_, ?_, h.valid,
      h.indexValid.congr rfl rfl, ?_, h.revisions, h.nativeArchive, ?_, ?_⟩
    · rw [he']; exact h.frames
    · rw [he']; exact h.head
    · rw [he']; exact h.term
    · rw [he']; exact h.identity
    · rw [he']; exact h.nativeShape
    · rw [he']; exact h.modelSub
    · rw [he']; exact h.modelArchive
  have rel := replace_history related.unique hattempts h hn (w' := w')
    (by simp [w', find_set_key]) rfl rfl (reachable_execute related.reachable he)
    (HistoryKeeps.of_same rfl rfl) (fun _ hm => hm)
  simp only [Spike.engine.Store.execute, hrun, bind_ok, he]
  change WP.spec (Result.ok (core.result.Result.Ok (Spike.engine.Output.Compacted result), next)) _
  rw [WP.spec_ok]
  exact ⟨
    .Compacted result,
    rfl,
    OutputMatches.of_eq (congrArg Output.compacted hcut),
    rel
  ⟩

/-- Rollback preserves the irrevocable prefix and does not rewrite the attempts' captured cuts. -/
theorem rollback_step_matches (encode : List U8 → String) (sid : Nat)
    (native : Spike.engine.Store) (w : State) (requested term : U64)
    (related : StateMatches encode sid native w)
    : WP.spec (Spike.engine.Store.execute native (.Rollback requested term))
        (StepMatches encode sid (.rollback sid requested.val term.val) native
          (execute w (.rollback sid requested.val term.val))) := by
  obtain ⟨s, archive, hs, h, hattempts⟩ := related.history
  obtain ⟨prior, head, hframes, hhead⟩ := h.split
  by_cases hLow : requested.val < native.history.global.val
  · have hn := rollback_rejected native requested term hLow
    simp [hn, StepMatches, OutputMatches, execute, hs, h.global, hLow, modelOutput, related]
  · by_cases hStale : term.val < native.history.term.val
    · have hn := rollback_stale_term native requested term (Nat.le_of_not_gt hLow) hStale
      simp [hn, StepMatches, execute, hs, h.global, hLow, h.term, hStale]
    · let store := rollbackStore s requested.val term.val
      let w' := {w with stores := Kv.Model.set w.stores sid store}
      let nativeStore : Store := {
        s with
          history := modelFrames native.history (modelFrame encode native.history.index)
          head := modelFrame encode native.history.index head
      }
      have hindex : head.version.val = prior.length := by
        have hidx : prior.length < native.history.activeFrames.length := by simp [hframes]
        have hh := h.indexed prior.length hidx
        have he : native.history.activeFrames[prior.length] = head := by
          apply Option.some.inj
          rw [← List.getElem?_eq_getElem hidx, hframes]
          simp
        rw [he] at hh
        exact hh
      obtain ⟨cut, after, hrun, hcut, htake, hmodel, htxs, hglobal, hidentity, hterm, hlog,
        hkept, hindexKept⟩ :=
        rollback_retains_model_frames native requested term nativeStore
          (modelFrame encode native.history.index) prior head
          hframes hindex (fun v => history_relative_cut_zero native.history v h.nonempty h.indexed h.valid)
          h.indexed rfl h.global rfl
          (Nat.le_of_not_gt hLow) (Nat.le_of_not_gt hStale) h.valid
      have hcutEq : rollbackCut s requested.val = rollbackCut nativeStore requested.val := by
        simp [rollbackCut, nativeStore, hhead.version]
      have hh : store.head.version = cut.val := by
        have hsize : native.history.activeFrames.length - 1 = prior.length := by simp [hframes]
        have hc : s.head.version = prior.length := hhead.version.symm.trans hindex
        have hreach := (Kv.Properties.reachable_store_invariants w sid s related.reachable hs).2.2.1
        have hbounded : cut.val ≤ prior.length := by
          rw [hcut, ← hcutEq, rollbackCut, max_le_iff, ← hc]
          exact ⟨hreach, min_le_left _ _⟩
        have hp := model_cut_version native.history nativeStore
          (modelFrame encode native.history.index) h.nonempty rfl h.indexed cut.val
        have hAtEq := (history_order_eq_atCut (s := nativeStore) (t := s) h.frames cut.val).version
        simpa [store, rollbackStore, hcutEq, ← hcut, ← hAtEq, hsize, Nat.min_eq_left hbounded] using hp
      have he : execute w (.rollback sid requested.val term.val) = some (w', .rolledBack cut.val) := by
        simpa [w', store, execute, hs, h.global, hLow, h.term, hStale] using hh
      have reach := reachable_execute related.reachable he
      have hstore : find w'.stores sid = some store := by simp [w', find_set_key]
      have hAfterFrames : modelFrames after.history (modelFrame encode after.history.index) =
          (modelFrames native.history (modelFrame encode native.history.index)).filter
            (fun f => decide (f.version ≤ cut.val)) := by
        rw [hindexKept, hmodel, hcut]
        rfl
      have hFilterShape {fs : List Frame} {v c : Nat} (shape : Kv.Properties.History fs v)
          (bound : c ≤ v) :
          Kv.Properties.History (fs.filter fun f => decide (f.version ≤ c)) c := by
        induction shape with
        | zero =>
            have hz : c = 0 := by omega
            subst hz
            exact .zero
        | succ f n tail fv eff rest ih =>
            by_cases hle : n + 1 ≤ c
            · have heq : c = n + 1 := by omega
              subst heq
              have hKeep : (f :: tail).filter (fun g => decide (g.version ≤ n + 1)) = f :: tail := by
                apply List.filter_eq_self.mpr
                intro g hg
                apply decide_eq_true
                rcases List.mem_cons.mp hg with rfl | old
                · omega
                · have bounded (rows : List Frame) (k : Nat) (hr : Kv.Properties.History rows k)
                      (x : Frame) (hx : x ∈ rows) : x.version ≤ k := by
                    induction hr with
                    | zero => rw [List.mem_singleton.mp hx]
                    | succ f' n' t' fv' _ _ ih' =>
                        rcases List.mem_cons.mp hx with rfl | o'
                        · omega
                        · exact Nat.le_trans (ih' o') (Nat.le_succ _)
                  exact Nat.le_trans (bounded tail n rest g old) (Nat.le_succ _)
              rw [hKeep]
              exact .succ f n tail fv eff rest
            · have hlt : c ≤ n := by omega
              simp only [List.filter_cons, fv, hle, decide_false, Bool.false_eq_true, ite_false]
              exact ih hlt
      have hCutBound : cut.val ≤ s.head.version := by
        have hreach := (Kv.Properties.reachable_store_invariants w sid s related.reachable hs).2.2.1
        rw [hcut, ← hcutEq, rollbackCut]
        exact max_le hreach (min_le_left _ _)
      have hvalid : HistoryMatches encode after.history store archive := by
        refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, hlog, h.indexValid.congr hindexKept hkept, ?_, ?_,
          ?_, ?_, ?_⟩
        · simp [htake, List.take_eq_nil_iff, h.nonempty]
        · rw [hAfterFrames]
          change List.Forall₂ FrameOrderEq _ (s.history.filter fun f => decide (f.version ≤ rollbackCut s requested.val))
          rw [hcutEq, ← hcut]
          exact history_order_eq_filter h.frames cut.val
        · exact (Kv.Properties.reachable_store_invariants w' sid store reach hstore).2.1
        · intro i hi
          have hi' : i < (native.history.activeFrames.take (cut.val + 1)).length := by
            rwa [← htake]
          have hElem : after.history.activeFrames[i] = native.history.activeFrames[i]'(by
              simp only [List.length_take] at hi'; omega) := by
            have he := List.getElem_take (h := hi') (xs := native.history.activeFrames)
            simpa only [htake] using he
          rw [hElem]
          exact h.indexed _ _
        · change s.global = after.history.global.val
          rw [hglobal]; exact h.global
        · change term.val = after.history.term.val
          rw [hterm]
        · change s.nextIdentity = after.history.next_identity.val
          rw [hidentity]; exact h.identity
        · rw [hAfterFrames, hh]
          exact hFilterShape h.nativeShape hCutBound
        · rw [hAfterFrames]
          exact h.revisions.filter _
        · rw [hkept, hindexKept, hidentity]
          exact h.nativeArchive
        · intro f hf
          exact h.modelSub f (List.mem_of_mem_filter hf)
        · exact h.modelArchive
      have rel := replace_history related.unique hattempts h hvalid hstore htxs rfl reach
        (HistoryKeeps.of_same hkept hindexKept) (fun _ hm => hm)
      simp only [he, StepMatches, OutputMatches, hrun, WP.spec_ok]
      exact ⟨.RolledBack cut, rfl, rfl, rel⟩

end KvRust
