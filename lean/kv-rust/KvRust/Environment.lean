-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Relation

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

private theorem filter_ver_indexed_reverse (xs : List Frame) (cut : Nat)
    (hver : ∀ (v : Nat) gf, xs[v]? = some gf → gf.version = v)
    : (xs.reverse.filter (fun f => decide (f.version ≤ cut))).reverse
      = xs.take (cut + 1) := by
  induction xs using List.reverseRecOn with
  | nil => simp
  | append_singleton p last ih =>
      have hlast : last.version = p.length :=
        hver p.length last (by rw [List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]; rfl)
      have hpver : ∀ (v : Nat) gf, p[v]? = some gf → gf.version = v := fun v gf hgv =>
        hver v gf (by
          have hv : v < p.length := (List.getElem?_eq_some_iff.mp hgv).1
          rw [List.getElem?_append_left hv]; exact hgv)
      rw [List.reverse_append, List.reverse_singleton, List.singleton_append, List.filter_cons]
      by_cases hc : p.length ≤ cut
      · simp only [hlast, decide_eq_true hc, ↓reduceIte, List.reverse_cons, ih hpver,
          List.take_append, List.take_of_length_le (by omega : p.length ≤ cut + 1),
          List.take_of_length_le (by simp; omega : [last].length ≤ cut + 1 - p.length)]
      · have hlt : cut + 1 ≤ p.length := by omega
        simp only [hlast, decide_eq_false hc, Bool.false_eq_true, ↓reduceIte, ih hpver,
          List.take_append_of_le_length hlt]

/-- Compaction advances the modeled frontier, moves needed compacted active frames into
`retained` (dropping unneeded ones), shrinks the ring if sparse, and runs bounded retirement. -/
theorem compact_step_matches (encode : List U8 → String) (inj : Function.Injective encode)
    (sid : Nat) (native : CcfKv.engine.Store) (w : State) (cut : U64)
    (related : StateMatches encode sid native w)
    (queueRoom
      : 2
            * (native.history.index.values.dirs.val.length
                + native.history.index.values.rows.val.length)
          + 1
        ≤ Usize.max)
    (retRoom
      : native.history.retained.val.length + native.history.activeFrames.length
        ≤ Usize.max)
    : WP.spec (CcfKv.engine.Store.execute native (.Compact cut))
        (StepMatches encode sid (.compact sid cut.val) native
          (execute w (.compact sid cut.val))) := by
  obtain ⟨s, natHistory, natArchive, archive, hs, h, hMeta, hattempts⟩ := related.history
  obtain ⟨prior, head, hframes, hhead⟩ := h.split
  obtain ⟨bf0, hbf0, hbf0Le, hbf0Re, hsum0⟩ := h.aligned.base
  unfold CcfKv.engine.Store.execute
  apply WP.spec_bind
    (history_compact native.history cut native.txs s prior head (txsPins native.txs.val)
      hframes h.global hhead.version.symm
      (fun hrc f hf => by
        have hfEq : f = bf0 := Option.some.inj (hf.symm.trans hbf0)
        rw [hfEq]; exact hbf0Re hrc)
      (fun f hf i hi => active_frame_version h.aligned hf i hi)
      h.valid retRoom related.liveness queueRoom)
  rintro ⟨result, afterHist⟩
    ⟨hcut, hglobal, hterm, hident, hreuse, hvalid', hactAfter, hlive', hpres', _, _,
      hretKeep, hretFrom, globalFrame, hglAfter0, hneed⟩
  let store := compactStore s cut.val
  let w' := {w with stores := Kv.Model.set w.stores sid store}
  let next := {native with history := afterHist}
  have he : execute w (.compact sid cut.val) = some (w', .compacted store.global) := by
    simp [execute, hs, w', store]
  have hreach := reachable_execute related.reachable he
  have hstore : find w'.stores sid = some store := by simp [w', find_set_key]
  have hmono : native.history.global.val ≤ result.val := by
    rw [hcut, ← h.global]
    unfold compactStore
    split
    · exact Nat.le_max_left _ _
    · exact Nat.le_refl _
  have hheadVer : head.version.val = bf0.version.val + prior.length := by
    have hidx : prior.length < native.history.activeFrames.length := by simp [hframes]
    have heq : native.history.activeFrames[prior.length]'hidx = head := by simp [hframes]
    have hv := active_frame_version h.aligned hbf0 prior.length hidx
    rwa [heq] at hv
  have hresLeHead : result.val ≤ head.version.val := by
    have hinv := Kv.Properties.reachable_store_invariants w' sid store hreach hstore
    have hbound : store.global ≤ store.head.version := hinv.2.2.1
    have hsh : store.head = s.head := by unfold store compactStore; split <;> rfl
    have hhv : head.version.val = s.head.version := hhead.version
    rw [hcut, hhv, ← hsh]
    exact hbound
  have hactSub : ∀ f' ∈ afterHist.activeFrames, f' ∈ native.history.activeFrames := by
    intro f' hf'
    rw [hactAfter] at hf'
    cases hrc : native.history.reuse_compacted_images with
    | true =>
        simp only [hrc, ↓reduceIte] at hf'
        exact List.mem_of_mem_drop hf'
    | false =>
        simp only [hrc, Bool.false_eq_true, ↓reduceIte] at hf'
        exact hf'
  have hidxValid' : HistoryIndexValid afterHist := by
    refine h.indexValid.of_preserves_pins hlive'.valid hpres'
      (fun f' hf' => Or.inr ⟨f', hactSub f' hf', rfl⟩)
      (fun rf hrf => ?_)
    rcases hretFrom rf hrf with hold | ⟨_, _, _, rfl⟩
    · exact h.indexValid.retainedEmpty rf hold
    · rfl
  let shift := if native.history.reuse_compacted_images then result.val - native.history.global.val else 0
  have hshiftEq : afterHist.activeFrames = native.history.activeFrames.drop shift := by
    dsimp [shift]
    cases hrc : native.history.reuse_compacted_images with
    | true => simpa [hrc] using hactAfter
    | false => simpa [hrc] using hactAfter
  have hshiftLt : shift < native.history.activeFrames.length := by
    dsimp [shift]
    cases hrc : native.history.reuse_compacted_images with
    | true =>
        have hlenAct : native.history.activeFrames.length = prior.length + 1 := by simp [hframes]
        have hbfG := hbf0Re hrc
        simp only [↓reduceIte]
        have : bf0.version.val = native.history.global.val := congrArg UScalar.val hbfG
        omega
    | false =>
        simp [hframes]
  have hbaseAfterAt : afterHist.activeFrames[0]? = some (native.history.activeFrames[shift]'hshiftLt) := by
    rw [hshiftEq, List.getElem?_drop, Nat.add_zero, List.getElem?_eq_getElem hshiftLt]
  have hbaseAfterVer : (native.history.activeFrames[shift]'hshiftLt).version.val = bf0.version.val + shift :=
    active_frame_version h.aligned hbf0 shift hshiftLt
  have haligned' : ArchiveAligned encode afterHist natHistory := by
    refine ⟨h.aligned.nonempty, ?_, ?_, ?_, ?_, h.aligned.verIndexed⟩
    · refine ⟨native.history.activeFrames[shift]'hshiftLt, hbaseAfterAt, ?_, ?_, ?_⟩
      · rw [hbaseAfterVer, hglobal]
        dsimp [shift]
        cases hrc : native.history.reuse_compacted_images with
        | true =>
            have : bf0.version.val = native.history.global.val := congrArg UScalar.val (hbf0Re hrc)
            simp only [↓reduceIte]; omega
        | false =>
            simp only [Bool.false_eq_true, ↓reduceIte]; omega
      · intro hrc'
        have hrc : native.history.reuse_compacted_images = true := hreuse ▸ hrc'
        apply UScalar.eq_of_val_eq
        rw [hbaseAfterVer, hglobal]
        have : bf0.version.val = native.history.global.val := congrArg UScalar.val (hbf0Re hrc)
        dsimp [shift]
        simp only [hrc, ↓reduceIte]; omega
      · rw [hbaseAfterVer, hshiftEq, List.length_drop]
        omega
    · intro bf hbf i hi
      have hbfEq : bf = native.history.activeFrames[shift]'hshiftLt :=
        Option.some.inj (hbf.symm.trans hbaseAfterAt)
      subst hbfEq
      have hiDrop : shift + i < native.history.activeFrames.length := by
        rw [hshiftEq, List.length_drop] at hi; omega
      have hfEq : afterHist.activeFrames[i]'hi = native.history.activeFrames[shift + i]'hiDrop := by
        simp only [hshiftEq, List.getElem_drop]
      have hact0 := h.aligned.activeEq bf0 hbf0 (shift + i) hiDrop
      have hpin : (afterHist.activeFrames[i]'hi).data = 0#u32
          ∨ (afterHist.activeFrames[i]'hi).data ∈ framePins afterHist.activeFrames ++ txsPins native.txs.val := by
        by_cases hz : (afterHist.activeFrames[i]'hi).data = 0#u32
        · exact Or.inl hz
        · exact Or.inr (List.mem_append_left _
            (List.mem_filterMap.mpr ⟨afterHist.activeFrames[i]'hi, List.getElem_mem hi, by simp [hz]⟩))
      have hview := index_preserves_pins_view hpres' (afterHist.activeFrames[i]'hi).data _ hpin
        (h.indexValid.active _ (hfEq ▸ List.getElem_mem hiDrop))
      have hrows : indexRows afterHist.index (afterHist.activeFrames[i]'hi).data
          = indexRows native.history.index (afterHist.activeFrames[i]'hi).data :=
        index_rows_eq hview
      have hmfEq : modelFrame encode afterHist.index (afterHist.activeFrames[i]'hi)
          = modelFrame encode native.history.index (native.history.activeFrames[shift + i]'hiDrop) := by
        unfold modelFrame
        rw [hrows, hfEq]
      rw [hbaseAfterVer, Nat.add_assoc, hmfEq]
      exact hact0
    · intro rf hrf
      rcases hretFrom rf hrf with hold | ⟨hrc, orig, horigTake, rfl⟩
      · obtain ⟨hltG, hzero, gf, hgfAt, hmeta⟩ := h.aligned.retainedEq rf hold
        exact ⟨by rw [hglobal]; omega, hzero, gf, hgfAt, hmeta⟩
      · obtain ⟨j, hjLt, rfl⟩ := List.getElem_of_mem horigTake
        have hjTake : j < result.val - native.history.global.val ∧ j < native.history.activeFrames.length := by
          rw [List.length_take] at hjLt; omega
        have hjGet : (native.history.activeFrames.take (result.val - native.history.global.val))[j]'hjLt
            = native.history.activeFrames[j]'hjTake.2 := List.getElem_take
        rw [hjGet]
        have hbfG : bf0.version.val = native.history.global.val := congrArg UScalar.val (hbf0Re hrc)
        have hverJ : (native.history.activeFrames[j]'hjTake.2).version.val = native.history.global.val + j := by
          have hv := active_frame_version h.aligned hbf0 j hjTake.2
          rw [hbfG] at hv
          exact hv
        have hactJ := h.aligned.activeEq bf0 hbf0 j hjTake.2
        rw [hbfG] at hactJ
        refine ⟨by rw [hglobal]; change (native.history.activeFrames[j]'hjTake.2).version.val < result.val; omega,
          rfl, modelFrame encode native.history.index (native.history.activeFrames[j]'hjTake.2),
          by rw [show (({native.history.activeFrames[j]'hjTake.2 with data := 0#u32} : CcfKv.engine.Frame).version.val)
            = native.history.global.val + j from hverJ]; exact hactJ,
          ⟨rfl, rfl, rfl⟩⟩
    · intro hrc'
      have hrc : native.history.reuse_compacted_images = false := hreuse ▸ hrc'
      have hemp0 := h.aligned.retainedReuse hrc
      apply List.eq_nil_iff_forall_not_mem.mpr
      intro rf hrf
      rcases hretFrom rf hrf with hold | ⟨htrue, _⟩
      · rw [hemp0] at hold; cases hold
      · rw [hrc] at htrue; cases htrue
  have hmetaAfter : StoreMetaLive encode next natHistory :=
    store_meta_live_after_prune inj hMeta h.aligned haligned' (fun _ hm => hm)
      (List.mem_of_getElem? hglAfter0)
      (fun f hf => by
        rcases List.mem_append.mp hf with hact | hret
        · cases hrc : native.history.reuse_compacted_images with
          | false =>
              exact Or.inl
                (List.mem_append_left _ (by rw [hactAfter, hrc]; simpa using hact))
          | true =>
              have hsplit : native.history.activeFrames =
                  native.history.activeFrames.take (result.val - native.history.global.val) ++
                  native.history.activeFrames.drop (result.val - native.history.global.val) :=
                (List.take_append_drop _ _).symm
              rw [hsplit] at hact
              rcases List.mem_append.mp hact with htake | hdrop
              · rcases hneed hrc f htake with hkept | hfalse
                · exact Or.inr (Or.inl ⟨{f with data := 0#u32}, hkept, rfl, rfl, rfl⟩)
                · exact Or.inr (Or.inr hfalse)
              · exact Or.inl (List.mem_append_left _ (by rw [hactAfter, hrc]; simpa using hdrop))
        · exact Or.inl (List.mem_append_right _ (hretKeep f hret)))
  have he' : store = {s with global := store.global} := by
    unfold store compactStore
    split <;> rfl
  have hn : HistoryMatches encode afterHist store natHistory natArchive archive :=
    history_related hreach hstore (by rw [he']; exact h.frames)
      (by rw [hglobal, hcut])
      (by rw [hterm, he']; exact h.term)
      (by rw [hident, he']; exact h.identity)
      hvalid' hidxValid' haligned' h.revisions h.natSub
      (by rw [hident]; exact h.nativeArchive) h.natSorted
      (by rw [he']; exact h.modelSub) (by rw [he']; exact h.modelArchive)
  have rel := replace_history (n' := next) related.unique hattempts hn hmetaAfter hlive'
    hstore rfl rfl hreach hpres' (fun _ hm => hm) (fun _ hm => hm)
  change WP.spec (Result.ok (core.result.Result.Ok (CcfKv.engine.Output.Compacted result), next)) _
  rw [WP.spec_ok, he]
  exact ⟨
    .Compacted result,
    rfl,
    OutputMatches.of_eq (congrArg Output.compacted hcut),
    rel
  ⟩

/-- Rollback preserves the irrevocable prefix, releases and retires rolled-back active
frames, leaves `retained` intact, and does not rewrite the attempts' captured cuts. -/
theorem rollback_step_matches (encode : List U8 → String) (sid : Nat)
    (native : CcfKv.engine.Store) (w : State) (requested term : U64)
    (related : StateMatches encode sid native w)
    (queueRoom
      : 2
            * (native.history.index.values.dirs.val.length
                + native.history.index.values.rows.val.length)
          + 1
        ≤ Usize.max)
    : WP.spec (CcfKv.engine.Store.execute native (.Rollback requested term))
        (StepMatches encode sid (.rollback sid requested.val term.val) native
          (execute w (.rollback sid requested.val term.val))) := by
  obtain ⟨s, natHistory, natArchive, archive, hs, h, hMeta, hattempts⟩ := related.history
  obtain ⟨prior, head, hframes, hhead⟩ := h.split
  obtain ⟨bf0, hbf0, hbf0Le, hbf0Re, hsum0⟩ := h.aligned.base
  by_cases hLow : requested.val < native.history.global.val
  · have hn := rollback_rejected native requested term hLow
    simp [hn, StepMatches, OutputMatches, execute, hs, h.global, hLow, modelOutput, related]
  · by_cases hStale : term.val < native.history.term.val
    · have hn := rollback_stale_term native requested term (Nat.le_of_not_gt hLow) hStale
      simp [hn, StepMatches, execute, hs, h.global, hLow, h.term, hStale]
    · let store := rollbackStore s requested.val term.val
      let w' := {w with stores := Kv.Model.set w.stores sid store}
      have hheadVer : head.version.val = bf0.version.val + prior.length := by
        have hidx : prior.length < native.history.activeFrames.length := by simp [hframes]
        have heq : native.history.activeFrames[prior.length]'hidx = head := by simp [hframes]
        have hv := active_frame_version h.aligned hbf0 prior.length hidx
        rwa [heq] at hv
      unfold CcfKv.engine.Store.execute
      apply WP.spec_bind
        (history_rollback native.history requested term prior head bf0
          (txsPins native.txs.val) hframes hbf0 hbf0Le hheadVer
          (Nat.le_of_not_gt hLow) (Nat.le_of_not_gt hStale) h.valid
          related.liveness queueRoom)
      rintro ⟨out, afterHist⟩
        ⟨cut, hout, hcut, hvalid', hactAfter, hretAfter, hglobal, hident, hterm, hreuse,
          hlive', hpres', _, _⟩
      have hcutEq : cut.val = rollbackCut s requested.val := by
        have hhv : head.version.val = s.head.version := hhead.version
        rw [hcut, ← h.global, hhv, rollbackCut]
      have hcutGeGlobal : native.history.global.val ≤ cut.val := by
        rw [hcut]; exact Nat.le_max_left _ _
      have hcutLeHead : cut.val ≤ head.version.val := by
        have hlenAct : native.history.activeFrames.length = prior.length + 1 := by simp [hframes]
        rw [hcut]
        exact max_le (by have := h.globalBound; omega) (Nat.min_le_left _ _)
      have htakeLen : cut.val - bf0.version.val + 1 ≤ native.history.activeFrames.length := by
        have hlenAct : native.history.activeFrames.length = prior.length + 1 := by simp [hframes]
        omega
      let natHistory' := natHistory.filter (fun f => decide (f.version ≤ cut.val))
      have hrevFilter : natHistory'.reverse = natHistory.reverse.take (cut.val + 1) := by
        have h1 := filter_ver_indexed_reverse natHistory.reverse cut.val h.aligned.verIndexed
        simpa [natHistory', List.reverse_reverse] using h1
      have hlenNat' : natHistory'.length = cut.val + 1 := by
        have := congrArg List.length hrevFilter
        rw [List.length_reverse, List.length_take, List.length_reverse] at this
        have hlenAct : native.history.activeFrames.length = prior.length + 1 := by simp [hframes]
        omega
      have hFramesForall : List.Forall₂ FrameOrderEq natHistory' store.history := by
        change List.Forall₂ FrameOrderEq _ (s.history.filter fun f => decide (f.version ≤ rollbackCut s requested.val))
        rw [← hcutEq]
        exact history_order_eq_filter h.frames cut.val
      have hh : store.head.version = cut.val := by
        have hreachS := (Kv.Properties.reachable_store_invariants w sid s related.reachable hs)
        have hheadAt : store.history.head? = some store.head := by
          change (s.history.filter (fun f => decide (f.version ≤ rollbackCut s requested.val))).head? =
            some (atCut s (rollbackCut s requested.val))
          unfold atCut
          cases hfind
                : s.history.find?
                    (fun f => decide (f.version ≤ rollbackCut s requested.val)) with
          | none =>
              exfalso
              have hzeroMem : ∃ f ∈ s.history, f.version = 0 := by
                have hshape := hreachS.1
                clear hfind
                generalize s.head.version = v at hshape
                generalize s.history = hist at hshape
                induction hshape with
                | zero => exact ⟨_, List.mem_cons_self, rfl⟩
                | succ _ _ _ _ _ _ ih =>
                    obtain ⟨f, hf, hv⟩ := ih
                    exact ⟨f, List.mem_cons_of_mem _ hf, hv⟩
              obtain ⟨f0, hf0, hv0⟩ := hzeroMem
              have hnone := List.find?_eq_none.mp hfind f0 hf0
              simp [hv0] at hnone
          | some f =>
              rw [List.head?_filter]
              exact hfind
        cases hnf : natHistory' with
        | nil =>
            have := congrArg List.length hnf
            rw [hlenNat'] at this
            simp at this
        | cons first rest =>
            rw [hnf] at hFramesForall
            cases hsh : store.history with
            | nil => rw [hsh] at hheadAt; cases hheadAt
            | cons sh st =>
                rw [hsh] at hFramesForall hheadAt
                have hshEq : sh = store.head := Option.some.inj hheadAt
                subst hshEq
                cases hFramesForall with
                | cons hfo _ =>
                    rw [← hfo.version]
                    have hlastAt : natHistory'.reverse[cut.val]? = some first := by
                      have hrestLen : rest.length = cut.val := by
                        have := congrArg List.length hnf
                        rw [hlenNat'] at this
                        simp at this; omega
                      rw [hnf, List.reverse_cons, List.getElem?_append_right (by rw [List.length_reverse]; omega),
                        List.length_reverse, hrestLen, Nat.sub_self]
                      rfl
                    rw [hrevFilter, List.getElem?_take_of_lt (by omega)] at hlastAt
                    exact h.aligned.verIndexed cut.val first hlastAt
      have he : execute w (.rollback sid requested.val term.val) = some (w', .rolledBack cut.val) := by
        simpa [w', store, execute, hs, h.global, hLow, h.term, hStale] using hh
      have reach := reachable_execute related.reachable he
      have hstore : find w'.stores sid = some store := by simp [w', find_set_key]
      have hidxValid' : HistoryIndexValid afterHist :=
        h.indexValid.of_preserves_pins hlive'.valid hpres'
          (fun f' hf' => Or.inr ⟨f', by rw [hactAfter] at hf'; exact List.mem_of_mem_take hf', rfl⟩)
          (fun rf hrf => h.indexValid.retainedEmpty rf (hretAfter ▸ hrf))
      have hbaseAfterAt : afterHist.activeFrames[0]? = some bf0 := by
        rw [hactAfter, List.getElem?_take_of_lt (by omega)]
        exact hbf0
      have haligned' : ArchiveAligned encode afterHist natHistory' := by
        refine ⟨by omega, ?_, ?_, ?_, ?_, ?_⟩
        · refine ⟨bf0, hbaseAfterAt, hglobal.symm ▸ hbf0Le,
            fun hrc' => hglobal.symm ▸ hbf0Re (hreuse ▸ hrc'), ?_⟩
          rw [hactAfter, List.length_take, hlenNat']
          omega
        · intro bf hbf i hi
          have hbfEq : bf = bf0 := Option.some.inj (hbf.symm.trans hbaseAfterAt)
          subst bf
          have hiOrig : i < native.history.activeFrames.length := by
            rw [hactAfter, List.length_take] at hi; omega
          have hiCut : i < cut.val - bf0.version.val + 1 := by
            rw [hactAfter, List.length_take] at hi; omega
          have hfEq : afterHist.activeFrames[i]'hi = native.history.activeFrames[i]'hiOrig := by
            simp only [hactAfter, List.getElem_take]
          have hpin : (afterHist.activeFrames[i]'hi).data = 0#u32
              ∨ (afterHist.activeFrames[i]'hi).data ∈ framePins afterHist.activeFrames ++ txsPins native.txs.val := by
            by_cases hz : (afterHist.activeFrames[i]'hi).data = 0#u32
            · exact Or.inl hz
            · exact Or.inr (List.mem_append_left _
                (List.mem_filterMap.mpr ⟨afterHist.activeFrames[i]'hi, List.getElem_mem hi, by simp [hz]⟩))
          have hview := index_preserves_pins_view hpres' (afterHist.activeFrames[i]'hi).data _ hpin
            (h.indexValid.active _ (hfEq ▸ List.getElem_mem hiOrig))
          have hrows : indexRows afterHist.index (afterHist.activeFrames[i]'hi).data
              = indexRows native.history.index (afterHist.activeFrames[i]'hi).data :=
            index_rows_eq hview
          have hmfEq : modelFrame encode afterHist.index (afterHist.activeFrames[i]'hi)
              = modelFrame encode native.history.index (native.history.activeFrames[i]'hiOrig) := by
            unfold modelFrame
            rw [hrows, hfEq]
          rw [hrevFilter, List.getElem?_take_of_lt (by omega), hmfEq]
          exact h.aligned.activeEq bf0 hbf0 i hiOrig
        · intro rf hrf
          obtain ⟨hltG, hzero, gf, hgfAt, hmeta⟩ := h.aligned.retainedEq rf (hretAfter ▸ hrf)
          refine ⟨hglobal.symm ▸ hltG, hzero, gf, ?_, hmeta⟩
          rw [hrevFilter, List.getElem?_take_of_lt (by omega)]
          exact hgfAt
        · intro hrc'
          rw [hretAfter]
          exact h.aligned.retainedReuse (hreuse ▸ hrc')
        · intro v gf hgv
          rw [hrevFilter] at hgv
          have hvLt : v < cut.val + 1 := by
            have := (List.getElem?_eq_some_iff.mp hgv).1
            rw [List.length_take] at this; omega
          rw [List.getElem?_take_of_lt hvLt] at hgv
          exact h.aligned.verIndexed v gf hgv
      have hmetaAfter : StoreMetaLive encode {native with history := afterHist} natHistory' := by
        refine ⟨?_, ?_⟩
        · intro id' t' snap' bf hmem hsnap' hbf hlt
          have hbfEq : bf = bf0 := Option.some.inj (hbf.symm.trans hbaseAfterAt)
          subst bf
          rw [hretAfter]
          exact hMeta.snapLive id' t' snap' bf0 hmem hsnap' hbf0 hlt
        · intro id' t' bm bv gf hmem hvm hgf hb hr'
          have hgfOld : gf ∈ natHistory := (List.mem_filter.mp hgf).1
          have hgfLeCut : gf.version ≤ cut.val := by
            simpa using (List.mem_filter.mp hgf).2
          obtain ⟨nf, hnfMem, hfm⟩ := hMeta.viewLive id' t' bm bv gf hmem hvm hgfOld hb hr'
          rcases List.mem_append.mp hnfMem with hact | hret
          · obtain ⟨j, hjLt, rfl⟩ := List.getElem_of_mem hact
            by_cases hkeep : j < cut.val - bf0.version.val + 1
            · refine ⟨native.history.activeFrames[j]'hjLt, List.mem_append_left _ ?_, hfm⟩
              rw [hactAfter]
              have hjTake : j < (native.history.activeFrames.take (cut.val - bf0.version.val + 1)).length := by
                rw [List.length_take]; omega
              have hjEq : (native.history.activeFrames.take (cut.val - bf0.version.val + 1))[j]'hjTake
                  = native.history.activeFrames[j]'hjLt := List.getElem_take
              rw [← hjEq]
              exact List.getElem_mem hjTake
            · -- `gf.version ≤ cut.val < bf0.version + j`: use `RevisionFlow.stamps_between`
              -- to witness `(bv.birth, bv.revision)` at the surviving frame `cut.val`.
              have hcutOffLt : cut.val - bf0.version.val < native.history.activeFrames.length := by omega
              let nfCut := native.history.activeFrames[cut.val - bf0.version.val]'hcutOffLt
              let gfCut := modelFrame encode native.history.index nfCut
              let gfNew := modelFrame encode native.history.index (native.history.activeFrames[j]'hjLt)
              have hgfNewAt : natHistory.reverse[bf0.version.val + j]? = some gfNew :=
                h.aligned.activeEq bf0 hbf0 j hjLt
              have hgfCutAt : natHistory.reverse[cut.val]? = some gfCut := by
                have h1 := h.aligned.activeEq bf0 hbf0 (cut.val - bf0.version.val) hcutOffLt
                have hsumC : bf0.version.val + (cut.val - bf0.version.val) = cut.val := by omega
                rwa [hsumC] at h1
              obtain ⟨kOld, hkOldLt, hkOldEq⟩ := List.getElem_of_mem (List.mem_reverse.mpr hgfOld)
              have hgfOldVer : gf.version = kOld := by
                have h1 := h.aligned.verIndexed kOld gf (by rw [← hkOldEq]; exact List.getElem?_eq_getElem hkOldLt)
                exact h1
              have hstampEq : ∀ (a b : Stamp), (a == b) = true → a = b := by
                rintro ⟨av, ai⟩ ⟨bv, bi⟩ hab
                change ((av == bv) && (ai == bi)) = true at hab
                simp only [Bool.and_eq_true, beq_iff_eq] at hab
                rw [hab.1, hab.2]
              have hoptStampEq : ∀ (a b : Option Stamp), (a == b) = true → a = b := by
                intro a b hab
                cases a <;> cases b
                · rfl
                · cases hab
                · cases hab
                · exact congrArg some (hstampEq _ _ hab)
              unfold frameMatches at hfm
              simp only [Bool.and_eq_true] at hfm
              have hbNew : find gfNew.births (encode bm.val) = bv.birth.map modelStamp :=
                hoptStampEq _ _ hfm.1
              have hrNew : revision gfNew (encode bm.val) = modelStamp bv.revision :=
                hstampEq _ _ hfm.2
              have hbOld : find gf.births (encode bm.val) = bv.birth.map modelStamp :=
                hoptStampEq _ _ hb
              have hrOld : revision gf (encode bm.val) = modelStamp bv.revision :=
                hstampEq _ _ hr'
              have hpw := List.pairwise_iff_getElem.mp h.revisions.flow
              have hnatAt : ∀ (p : Nat) (gfP : Frame),
                  natHistory.reverse[p]? = some gfP →
                  ∃ (hLt : natHistory.length - 1 - p < natHistory.length),
                    natHistory[natHistory.length - 1 - p]'hLt = gfP := by
                intro p gfP hp
                have hpLt : p < natHistory.length := by
                  have := (List.getElem?_eq_some_iff.mp hp).1
                  rwa [List.length_reverse] at this
                have hLt : natHistory.length - 1 - p < natHistory.length := by omega
                refine ⟨hLt, ?_⟩
                apply Option.some.inj
                rw [← List.getElem?_eq_getElem hLt, ← List.getElem?_reverse hpLt, hp]
              obtain ⟨hidxNew, hgetNew⟩ := hnatAt (bf0.version.val + j) gfNew hgfNewAt
              obtain ⟨hidxCut, hgetCut⟩ := hnatAt cut.val gfCut hgfCutAt
              obtain ⟨hidxOld, hgetOld⟩ := hnatAt kOld gf (by rw [← hkOldEq]; exact List.getElem?_eq_getElem hkOldLt)
              have hflowNewCut : RevisionFlow gfNew gfCut := by
                have h1 := hpw _ _ hidxNew hidxCut (by omega)
                rwa [hgetNew, hgetCut] at h1
              have hflowCutOld : RevisionFlow gfCut gf := by
                by_cases heqCut : kOld = cut.val
                · subst heqCut
                  have hgfEq : gf = gfCut := Option.some.inj
                    ((by rw [← hkOldEq]; exact List.getElem?_eq_getElem hkOldLt : natHistory.reverse[cut.val]? = some gf).symm.trans hgfCutAt)
                  rw [hgfEq]
                  exact RevisionFlow.refl _
                · have h1 := hpw _ _ hidxCut hidxOld (by omega)
                  rwa [hgetCut, hgetOld] at h1
              have hbetween := RevisionFlow.stamps_between hflowNewCut hflowCutOld (encode bm.val)
                (hbOld.trans hbNew.symm) (hrOld.trans hrNew.symm)
              refine ⟨nfCut, List.mem_append_left _ ?_, ?_⟩
              · rw [hactAfter]
                have hcutTake : cut.val - bf0.version.val
                    < (native.history.activeFrames.take (cut.val - bf0.version.val + 1)).length := by
                  rw [List.length_take]; omega
                have hcutEqElem : (native.history.activeFrames.take (cut.val - bf0.version.val + 1))[
                    cut.val - bf0.version.val]'hcutTake = nfCut := List.getElem_take
                rw [← hcutEqElem]
                exact List.getElem_mem hcutTake
              · unfold frameMatches
                have hbCutM : find (modelMetadata (encode ∘ alloc.vec.Vec.val) nfCut).births (encode bm.val)
                    = bv.birth.map modelStamp := by
                  change find gfCut.births (encode bm.val) = _
                  rw [hbetween.1, hbOld]
                have hrCutM : revision (modelMetadata (encode ∘ alloc.vec.Vec.val) nfCut) (encode bm.val)
                    = modelStamp bv.revision := by
                  change revision gfCut (encode bm.val) = _
                  rw [hbetween.2, hrOld]
                change ((find (modelMetadata (encode ∘ alloc.vec.Vec.val) nfCut).births (encode bm.val)
                        == bv.birth.map modelStamp)
                    && (revision (modelMetadata (encode ∘ alloc.vec.Vec.val) nfCut) (encode bm.val)
                        == modelStamp bv.revision)) = true
                rw [hbCutM, hrCutM]
                cases bv.birth with
                | none =>
                    change (true
                      && ((bv.revision.version.val == bv.revision.version.val)
                        && (bv.revision.identity.val == bv.revision.identity.val))) = true
                    simp
                | some b =>
                    change (((b.version.val == b.version.val)
                      && (b.identity.val == b.identity.val))
                      && ((bv.revision.version.val == bv.revision.version.val)
                        && (bv.revision.identity.val == bv.revision.identity.val))) = true
                    simp
          · exact ⟨nf, List.mem_append_right _ (hretAfter.symm ▸ hret), hfm⟩
      have hNatRev' : RevisionHistory natHistory' := h.revisions.filter _
      have hNatSub' : ∀ f ∈ natHistory', f ∈ natArchive := fun f hf =>
        h.natSub f (List.mem_of_mem_filter hf)
      have hModSub' : ∀ f ∈ store.history, f ∈ archive := fun f hf =>
        h.modelSub f (List.mem_of_mem_filter hf)
      have hvalid : HistoryMatches encode afterHist store natHistory' natArchive archive :=
        history_related reach hstore hFramesForall
          (by change s.global = afterHist.global.val; rw [hglobal]; exact h.global)
          (by change term.val = afterHist.term.val; rw [hterm])
          (by change s.nextIdentity = afterHist.next_identity.val; rw [hident]; exact h.identity)
          hvalid' hidxValid' haligned' hNatRev' hNatSub'
          (by rw [hident]; exact h.nativeArchive) h.natSorted hModSub' h.modelArchive
      have rel := replace_history (n' := {native with history := afterHist})
        related.unique hattempts hvalid hmetaAfter hlive' hstore rfl rfl reach hpres'
        (fun _ hm => hm) (fun _ hm => hm)
      change WP.spec (Result.ok (out, ({native with history := afterHist} : CcfKv.engine.Store))) _
      rw [WP.spec_ok, he, hout]
      exact ⟨.RolledBack cut, rfl, rfl, rel⟩

end KvRust
