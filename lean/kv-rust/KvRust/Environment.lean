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
        (StepMatches encode sid native (execute w (.compact sid cut.val))) := by
  obtain ⟨s, hs, h⟩ := related.history
  obtain ⟨prior, head, hframes, hhead⟩ := h.split
  obtain ⟨result, hrun, hcut⟩ := history_compact native.history cut s prior head
    hframes h.global (congrArg Frame.version hhead)
  let store := compactStore s cut.val
  let w' := {w with stores := Kv.Model.set w.stores sid store}
  let next := {native with history := {native.history with global := result}}
  have he : execute w (.compact sid cut.val) = some (w', .compacted store.global) := by
    simp [execute, hs, w', store]
  have hn : HistoryMatches encode next.history store := by
    have he' : store = {s with global := store.global} := by
      unfold store compactStore
      split <;> rfl
    refine ⟨h.nonempty, ?_, ?_, h.indexed, hcut.symm, ?_, ?_⟩
    · rw [he']; exact h.frames
    · rw [he']; exact h.head
    · rw [he']; exact h.term
    · rw [he']; exact h.identity
  have rel := replace_history related hn (w' := w')
    (by simp [w', find_set_key]) rfl rfl (reachable_execute related.reachable he)
  simp only [Spike.engine.Store.execute, hrun, bind_ok, he]
  change WP.spec (Result.ok (core.result.Result.Ok (Spike.engine.Output.Compacted result), next)) _
  rw [WP.spec_ok]
  exact ⟨.Compacted result, rfl, congrArg Output.compacted hcut, rel⟩

/-- Rollback preserves the irrevocable prefix and does not rewrite the attempts' captured cuts. -/
theorem rollback_step_matches (encode : List U8 → String) (sid : Nat)
    (native : Spike.engine.Store) (w : State) (requested term : U64)
    (related : StateMatches encode sid native w)
    : WP.spec (Spike.engine.Store.execute native (.Rollback requested term))
        (StepMatches encode sid native
          (execute w (.rollback sid requested.val term.val))) := by
  obtain ⟨s, hs, h⟩ := related.history
  obtain ⟨prior, head, hframes, hhead⟩ := h.split
  by_cases hLow : requested.val < native.history.global.val
  · have hn := rollback_rejected native requested term hLow
    simp [hn, StepMatches, execute, hs, h.global, hLow, modelOutput, related]
  · by_cases hStale : term.val < native.history.term.val
    · have hn := rollback_stale_term native requested term (Nat.le_of_not_gt hLow) hStale
      simp [hn, StepMatches, execute, hs, h.global, hLow, h.term, hStale]
    · let store := rollbackStore s requested.val term.val
      let w' := {w with stores := Kv.Model.set w.stores sid store}
      have hindex : head.version.val = prior.length := by
        have hidx : prior.length < native.history.frames.val.length := by simp [hframes]
        have hh := h.indexed prior.length hidx
        have he : native.history.frames.val[prior.length] = head := by
          apply Option.some.inj
          rw [← List.getElem?_eq_getElem hidx, hframes]
          simp
        rw [he] at hh
        exact hh
      obtain ⟨cut, after, hrun, hcut, htake, hmodel, htxs, hglobal, hidentity, hterm⟩ :=
        rollback_retains_model_frames native requested term s (modelFrame encode) prior head
          hframes hindex h.indexed h.frames h.global (congrArg Frame.version hhead)
          (Nat.le_of_not_gt hLow) (Nat.le_of_not_gt hStale)
      have hh : store.head.version = cut.val := by
        have hsize : native.history.frames.val.length - 1 = prior.length := by simp [hframes]
        have hc : s.head.version = prior.length := (congrArg Frame.version hhead).trans hindex
        have hreach := (Kv.Properties.reachable_store_invariants w sid s related.reachable hs).2.2.1
        have hbounded : cut.val ≤ prior.length := by
          rw [hcut, rollbackCut, max_le_iff, ← hc]
          exact ⟨hreach, min_le_left _ _⟩
        have hp := model_cut_version native.history s (modelFrame encode) h.nonempty h.frames
          h.indexed cut.val
        simpa [store, rollbackStore, ← hcut, hsize, Nat.min_eq_left hbounded] using hp
      have he : execute w (.rollback sid requested.val term.val) = some (w', .rolledBack cut.val) := by
        simpa [w', store, execute, hs, h.global, hLow, h.term, hStale] using hh
      have reach := reachable_execute related.reachable he
      have hstore : find w'.stores sid = some store := by simp [w', find_set_key]
      have hvalid : HistoryMatches encode after.history store := by
        refine ⟨?_, hmodel.symm, ?_, ?_, ?_, ?_, ?_⟩
        · simp [htake, List.take_eq_nil_iff, h.nonempty]
        · exact (Kv.Properties.reachable_store_invariants w' sid store reach hstore).2.1
        · intro i hi
          have hi' : i < (native.history.frames.val.take (cut.val + 1)).length := by
            rwa [← htake]
          have hElem : after.history.frames.val[i] = native.history.frames.val[i]'(by
              simp only [List.length_take] at hi'; omega) := by
            have he := List.getElem_take (h := hi') (xs := native.history.frames.val)
            simpa only [htake] using he
          rw [hElem]
          exact h.indexed _ _
        · change s.global = after.history.global.val
          rw [hglobal]; exact h.global
        · change term.val = after.history.term.val
          rw [hterm]
        · change s.nextIdentity = after.history.next_identity.val
          rw [hidentity]; exact h.identity
      have rel := replace_history related hvalid hstore htxs rfl reach
      simp only [he, StepMatches, hrun, WP.spec_ok]
      exact ⟨.RolledBack cut, rfl, rfl, rel⟩

end KvRust
