-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Relation

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

private theorem branch_nodup_ne {ids : List Usize} (huniq : ids.Nodup)
    {i j : Nat} {a b : Usize}
    (hi : ids[i]? = some a) (hj : ids[j]? = some b) (hne : i ≠ j)
    : a.val ≠ b.val := by
  intro heq
  have hEq : a = b := UScalar.eq_of_val_eq heq
  subst hEq
  obtain ⟨hiLt, hiGet⟩ := List.getElem?_eq_some_iff.mp hi
  obtain ⟨hjLt, hjGet⟩ := List.getElem?_eq_some_iff.mp hj
  have h := List.nodup_iff_injective_getElem.mp huniq
  have hfin : (⟨i, hiLt⟩ : Fin ids.length) = ⟨j, hjLt⟩ := h (hiGet.trans hjGet.symm)
  exact hne (congrArg Fin.val hfin)

private theorem branch_values_getElem? {T : Type} (log : Spike.branch_log.BranchLog T)
    (valid : BranchValid log) (i : Nat) (id : Usize) (f : T)
    (hbr : log.branch.val[i]? = some id) (hf : log.frames.val[id.val]? = some f)
    : (branchValues log)[i]? = some f := by
  unfold branchValues
  have hbd : ∀ x ∈ log.branch.val, x.val < log.frames.val.length := valid.2
  generalize log.branch.val = ids at hbd hbr
  induction ids generalizing i with
  | nil => simp at hbr
  | cons x xs ih =>
      have hxLt : x.val < log.frames.val.length := hbd x List.mem_cons_self
      rw [List.filterMap_cons, List.getElem?_eq_getElem hxLt]
      dsimp only
      cases i with
      | zero =>
          simp only [List.getElem?_cons_zero, Option.some.injEq] at hbr
          subst hbr
          rw [List.getElem?_cons_zero]
          exact (List.getElem?_eq_getElem hxLt).symm.trans hf
      | succ j =>
          simp only [List.getElem?_cons_succ] at hbr ⊢
          exact ih j (fun y hy => hbd y (List.mem_cons_of_mem _ hy)) hbr

/-- Compaction advances the modeled frontier and may release and retire compacted frame roots. -/
theorem compact_step_matches (encode : List U8 → String) (sid : Nat)
    (native : Spike.engine.Store) (w : State) (cut : U64)
    (related : StateMatches encode sid native w)
    (queueRoom
      : 2
            * (native.history.index.values.dirs.val.length
                + native.history.index.values.rows.val.length)
          + 1
        ≤ Usize.max)
    : WP.spec (Spike.engine.Store.execute native (.Compact cut))
        (StepMatches encode sid (.compact sid cut.val) native
          (execute w (.compact sid cut.val))) := by
  obtain ⟨s, natArchive, archive, hs, h, hattempts⟩ := related.history
  obtain ⟨prior, head, hframes, hhead⟩ := h.split
  unfold Spike.engine.Store.execute
  apply WP.spec_bind
    (history_compact native.history cut s prior head (txsPins native.txs.val) hframes
      h.global hhead.version.symm h.indexed h.valid h.unique related.liveness queueRoom)
  rintro ⟨result, afterHist⟩
    ⟨hcut, hglobal, hterm, hident, hreuse, hbr, hvalid', hunique', hlive', hpres', _, _, hlenEq, hslot⟩
  let store := compactStore s cut.val
  let w' := {w with stores := Kv.Model.set w.stores sid store}
  let next := {native with history := afterHist}
  have he : execute w (.compact sid cut.val) = some (w', .compacted store.global) := by
    simp [execute, hs, w', store]
  have hreach := reachable_execute related.reachable he
  have hstore : find w'.stores sid = some store := by simp [w', find_set_key]
  have hactLen : afterHist.activeFrames.length = native.history.activeFrames.length := by
    rw [branch_values_length afterHist.log hvalid', branch_values_length native.history.log h.valid, hbr]
  have hheadVer : head.version.val = prior.length := by
    have hidx : prior.length < native.history.activeFrames.length := by simp [hframes]
    have hh := h.indexed prior.length hidx
    have heq : native.history.activeFrames[prior.length] = head := by
      apply Option.some.inj
      rw [← List.getElem?_eq_getElem hidx, hframes]
      simp
    rwa [heq] at hh
  have hactVer : ∀ i (hi : i < afterHist.activeFrames.length), afterHist.activeFrames[i].version.val = i := by
    intro i hi
    have hi' : i < native.history.activeFrames.length := hactLen ▸ hi
    have hbrLen : i < native.history.log.branch.val.length := by
      rwa [← branch_values_length native.history.log h.valid]
    let id := native.history.log.branch.val[i]'hbrLen
    have hidMem : id ∈ native.history.log.branch.val := List.getElem_mem hbrLen
    have hidLt : id.val < native.history.log.frames.val.length := h.valid.2 id hidMem
    let f := native.history.log.frames.val[id.val]'hidLt
    have hf : native.history.log.frames.val[id.val]? = some f := List.getElem?_eq_getElem hidLt
    obtain ⟨f', hf', hfv, _, _, _, _⟩ := hslot id.val f hf
    have hget0 : native.history.activeFrames[i]? = some f := by
      have := branch_values_getElem? native.history.log h.valid i id f
        (List.getElem?_eq_getElem hbrLen) hf
      simpa [Spike.engine.History.activeFrames] using this
    have hget1 : afterHist.activeFrames[i]? = some f' := by
      have := branch_values_getElem? afterHist.log hvalid' i id f'
        (by rw [hbr]; exact List.getElem?_eq_getElem hbrLen) hf'
      simpa [Spike.engine.History.activeFrames] using this
    have hf0 : native.history.activeFrames[i]'hi' = f :=
      Option.some.inj ((List.getElem?_eq_getElem hi').symm.trans hget0)
    have hf1 : afterHist.activeFrames[i]'hi = f' :=
      Option.some.inj ((List.getElem?_eq_getElem hi).symm.trans hget1)
    rw [hf1, hfv, ← hf0]
    exact h.indexed i hi'
  have hidxValid' : HistoryIndexValid afterHist := by
    refine h.indexValid.of_preserves_pins hlive'.valid hpres' ?_
    intro i f' hf'
    have hiLt : i < native.history.log.frames.val.length := by
      have := (List.getElem?_eq_some_iff.mp hf').1
      omega
    let f := native.history.log.frames.val[i]'hiLt
    obtain ⟨f'', hf'', _, _, _, hdata, _⟩ := hslot i f (List.getElem?_eq_getElem hiLt)
    have heq : f' = f'' := Option.some.inj (hf'.symm.trans hf'')
    subst heq
    rcases hdata with hd | h0
    · exact Or.inr ⟨i, f, List.getElem?_eq_getElem hiLt, hd⟩
    · exact Or.inl h0
  have haligned' : ArchiveAligned encode afterHist natArchive := by
    refine ⟨by rw [hlenEq]; exact h.aligned.len, ?_, ?_⟩
    · intro i nf' gf hnf' hgf
      have hiLt : i < native.history.log.frames.val.length := by
        have := (List.getElem?_eq_some_iff.mp hnf').1
        omega
      let f := native.history.log.frames.val[i]'hiLt
      obtain ⟨f'', hf'', hfv, hfr, hfb, _, _⟩ := hslot i f (List.getElem?_eq_getElem hiLt)
      have heq : nf' = f'' := Option.some.inj (hnf'.symm.trans hf'')
      subst heq
      have hmeta := h.aligned.metaEq i f gf (List.getElem?_eq_getElem hiLt) hgf
      exact ⟨by rw [hfv]; exact hmeta.1, by simp only [modelMetadata, hfr]; exact hmeta.2.1,
        by simp only [modelMetadata, hfb]; exact hmeta.2.2⟩
    · intro pos id nf' gf hpos hnf' hgf hliveCond
      have hpos0 : native.history.log.branch.val[pos]? = some id := by rwa [← hbr]
      have hidLt : id.val < native.history.log.frames.val.length := by
        have := (List.getElem?_eq_some_iff.mp hnf').1
        omega
      let f := native.history.log.frames.val[id.val]'hidLt
      have hf0 : native.history.log.frames.val[id.val]? = some f := List.getElem?_eq_getElem hidLt
      have hposLt : pos < native.history.log.branch.val.length :=
        (List.getElem?_eq_some_iff.mp hpos0).1
      have hposActLt : pos < native.history.activeFrames.length := by
        rwa [branch_values_length native.history.log h.valid]
      have hfVer : f.version.val = pos := by
        have hget : native.history.activeFrames[pos]? = some f := by
          have := branch_values_getElem? native.history.log h.valid pos id f hpos0 hf0
          simpa [Spike.engine.History.activeFrames] using this
        have hfEq : native.history.activeFrames[pos]'hposActLt = f :=
          Option.some.inj ((List.getElem?_eq_getElem hposActLt).symm.trans hget)
        rw [← hfEq]
        exact h.indexed pos hposActLt
      obtain ⟨f'', hf'', hfv'', _, _, _, hkept⟩ := hslot id.val f hf0
      have heq : nf' = f'' := Option.some.inj (hnf'.symm.trans hf'')
      subst heq
      have hsame : nf' = f := by
        apply hkept
        cases hrc : afterHist.reuse_compacted_images with
        | false => exact Or.inl (by rw [← hreuse]; exact hrc)
        | true =>
            have hge : afterHist.global.val ≤ nf'.version.val := hliveCond hrc
            rw [hfv'', hfVer] at hge
            right
            intro off id' _ hoffLt hoff
            have hne : off ≠ pos := by rw [hglobal] at hge; omega
            exact branch_nodup_ne h.unique hoff hpos0 hne
      subst hsame
      have hlive0 : native.history.reuse_compacted_images = true → native.history.global.val ≤ f.version.val := by
        intro hrc0
        have hge : afterHist.global.val ≤ f.version.val := hliveCond (by rw [hreuse]; exact hrc0)
        have hmono : native.history.global.val ≤ result.val := by
          rw [hcut, ← h.global]
          unfold compactStore
          split
          · exact Nat.le_max_left _ _
          · exact Nat.le_refl _
        rw [hglobal] at hge
        omega
      have hmf0 := h.aligned.activeLive pos id f gf hpos0 hf0 hgf hlive0
      have hpin : f.data = 0#u32 ∨ f.data ∈ framePins afterHist.log.frames.val ++ txsPins native.txs.val := by
        by_cases hz : f.data = 0#u32
        · exact Or.inl hz
        · exact Or.inr (List.mem_append_left _
            (List.mem_filterMap.mpr ⟨f, List.mem_iff_getElem?.mpr ⟨id.val, hnf'⟩, by simp [hz]⟩))
      have hview := index_preserves_pins_view hpres' f.data _ hpin (h.indexValid.archived id.val f hf0)
      have hrows : indexRows afterHist.index f.data = indexRows native.history.index f.data :=
        index_rows_eq hview
      simpa only [modelFrame, hrows] using hmf0
  have hglobalBound' : afterHist.global.val < afterHist.activeFrames.length := by
    rw [hglobal, hcut, hactLen, hframes, List.length_append, List.length_singleton]
    have hbound := (Kv.Properties.reachable_store_invariants w' sid store hreach hstore).2.2.1
    have hheadEq : store.head.version = prior.length := by
      have : store.head = s.head := by unfold store compactStore; split <;> rfl
      rw [this, ← hhead.version]
      exact hheadVer
    change store.global < prior.length + 1
    omega
  have hnatFramesEq : natModelFrames afterHist.log natArchive = natModelFrames native.history.log natArchive := by
    unfold natModelFrames
    rw [hbr]
  have he' : store = {s with global := store.global} := by
    unfold store compactStore
    split <;> rfl
  have hn : HistoryMatches encode afterHist store natArchive archive := by
    refine ⟨?_, ?_, ?_, hactVer, ?_, hglobalBound', ?_, ?_, hvalid', hunique', hidxValid',
      haligned', ?_, ?_, h.natSorted, ?_, ?_⟩
    · intro hnil
      have := congrArg List.length hnil
      rw [hactLen] at this
      exact h.nonempty (List.eq_nil_of_length_eq_zero this)
    · rw [hnatFramesEq, he']; exact h.frames
    · rw [he']; exact h.head
    · rw [hglobal, hcut]
    · rw [hterm, he']; exact h.term
    · rw [hident, he']; exact h.identity
    · rw [hnatFramesEq]; exact h.revisions
    · rw [hident]; exact h.nativeArchive
    · rw [he']; exact h.modelSub
    · rw [he']; exact h.modelArchive
  have rel := replace_history (n' := next) related.unique hattempts hn hlive' hstore rfl rfl hreach hpres'
    (fun _ hm => hm) (fun _ hm => hm)
  change WP.spec (Result.ok (core.result.Result.Ok (Spike.engine.Output.Compacted result), next)) _
  rw [WP.spec_ok, he]
  exact ⟨
    .Compacted result,
    rfl,
    OutputMatches.of_eq (congrArg Output.compacted hcut),
    rel
  ⟩

/-- Rollback preserves the irrevocable prefix, releases and retires rolled-back frame roots,
and does not rewrite the attempts' captured cuts. -/
theorem rollback_step_matches (encode : List U8 → String) (sid : Nat)
    (native : Spike.engine.Store) (w : State) (requested term : U64)
    (related : StateMatches encode sid native w)
    (queueRoom
      : 2
            * (native.history.index.values.dirs.val.length
                + native.history.index.values.rows.val.length)
          + 1
        ≤ Usize.max)
    : WP.spec (Spike.engine.Store.execute native (.Rollback requested term))
        (StepMatches encode sid (.rollback sid requested.val term.val) native
          (execute w (.rollback sid requested.val term.val))) := by
  obtain ⟨s, natArchive, archive, hs, h, hattempts⟩ := related.history
  obtain ⟨prior, head, hframes, hhead⟩ := h.split
  by_cases hLow : requested.val < native.history.global.val
  · have hn := rollback_rejected native requested term hLow
    simp [hn, StepMatches, OutputMatches, execute, hs, h.global, hLow, modelOutput, related]
  · by_cases hStale : term.val < native.history.term.val
    · have hn := rollback_stale_term native requested term (Nat.le_of_not_gt hLow) hStale
      simp [hn, StepMatches, execute, hs, h.global, hLow, h.term, hStale]
    · let store := rollbackStore s requested.val term.val
      let w' := {w with stores := Kv.Model.set w.stores sid store}
      have hindex : head.version.val = prior.length := by
        have hidx : prior.length < native.history.activeFrames.length := by simp [hframes]
        have hh := h.indexed prior.length hidx
        have he : native.history.activeFrames[prior.length] = head := by
          apply Option.some.inj
          rw [← List.getElem?_eq_getElem hidx, hframes]
          simp
        rw [he] at hh
        exact hh
      unfold Spike.engine.Store.execute
      apply WP.spec_bind
        (history_rollback native.history requested term prior head
          (txsPins native.txs.val) hframes hindex
          (fun v =>
            history_relative_cut_zero native.history v h.nonempty h.indexed h.valid)
          (Nat.le_of_not_gt hLow) (Nat.le_of_not_gt hStale) h.valid h.unique
          related.liveness queueRoom)
      rintro ⟨out, afterHist⟩
        ⟨cut, hout, hcut, hbr, hglobal, hident, hterm, hreuse, hvalid', hunique', hlive',
          hpres', _, _, hlenEq, hslot⟩
      have hcutEq : cut.val = rollbackCut s requested.val := by
        have hhv : head.version.val = s.head.version := hhead.version
        rw [hcut, ← h.global, hhv, rollbackCut]
      have hreachS := (Kv.Properties.reachable_store_invariants w sid s related.reachable hs)
      have hbounded : cut.val ≤ prior.length := by
        rw [hcut]
        exact max_le (by have := h.globalBound; rw [hframes, List.length_append, List.length_singleton] at this; omega)
          (by rw [hindex]; exact Nat.min_le_left _ _)
      have hbrLen : native.history.log.branch.val.length = prior.length + 1 := by
        have hlen := branch_values_length native.history.log h.valid
        change native.history.activeFrames.length = native.history.log.branch.val.length at hlen
        rw [← hlen, hframes, List.length_append, List.length_singleton]
      have hactLen : afterHist.activeFrames.length = cut.val + 1 := by
        rw [branch_values_length afterHist.log hvalid', hbr, List.length_take, hbrLen]
        omega
      have hnatVer : ∀ (i : Nat) (hi : i < native.history.log.branch.val.length) (gf : Frame),
          natArchive[native.history.log.branch.val[i].val]? = some gf → gf.version = i := by
        intro i hi gf hgf
        let id := native.history.log.branch.val[i]'hi
        have hidLt : id.val < native.history.log.frames.val.length :=
          h.valid.2 id (List.getElem_mem hi)
        let f := native.history.log.frames.val[id.val]'hidLt
        have hmeta := h.aligned.metaEq id.val f gf (List.getElem?_eq_getElem hidLt) hgf
        have hi' : i < native.history.activeFrames.length := by
          rwa [branch_values_length native.history.log h.valid]
        have hget : native.history.activeFrames[i]? = some f := by
          have := branch_values_getElem? native.history.log h.valid i id f
            (List.getElem?_eq_getElem hi) (List.getElem?_eq_getElem hidLt)
          simpa [Spike.engine.History.activeFrames] using this
        have hfEq : native.history.activeFrames[i]'hi' = f :=
          Option.some.inj ((List.getElem?_eq_getElem hi').symm.trans hget)
        rw [hmeta.1, ← hfEq]
        exact h.indexed i hi'
      have hAfterFrames : natModelFrames afterHist.log natArchive =
          (natModelFrames native.history.log natArchive).filter
            (fun f => decide (f.version ≤ cut.val)) := by
        have := natModelFrames_take h.valid h.aligned.len hbr hnatVer (Nat.succ_pos cut.val)
        simpa only [Nat.add_sub_cancel] using this
      have hFramesForall : List.Forall₂ FrameOrderEq (natModelFrames afterHist.log natArchive)
          store.history := by
        rw [hAfterFrames]
        change List.Forall₂ FrameOrderEq _ (s.history.filter fun f => decide (f.version ≤ rollbackCut s requested.val))
        rw [← hcutEq]
        exact history_order_eq_filter h.frames cut.val
      have hh : store.head.version = cut.val := by
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
        have hnonemptyNat : natModelFrames afterHist.log natArchive ≠ [] := by
          intro hnil
          have hlenNil := congrArg List.length hnil
          have hlenPos : (natModelFrames afterHist.log natArchive).length = afterHist.log.branch.val.length :=
            natModelFrames_length hvalid' (by rw [hlenEq]; exact h.aligned.len)
          rw [hlenPos, hbr, List.length_take, hbrLen] at hlenNil
          simp only [List.length_nil] at hlenNil
          omega
        cases hnf : natModelFrames afterHist.log natArchive with
        | nil => exact (hnonemptyNat hnf).elim
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
                    have hbrTake : afterHist.log.branch.val =
                        (native.history.log.branch.val.take cut.val) ++
                        [native.history.log.branch.val[cut.val]'(by omega)] := by
                      rw [hbr, List.take_add_one, List.getElem?_eq_getElem (by omega)]
                      simp
                    unfold natModelFrames at hnf
                    rw [hbrTake, List.reverse_append, List.reverse_singleton,
                      List.singleton_append, List.filterMap_cons] at hnf
                    have hltCut : (native.history.log.branch.val[cut.val]'(by omega)).val < natArchive.length :=
                      h.aligned.len.symm ▸ h.valid.2 _ (List.getElem_mem (by omega))
                    rw [List.getElem?_eq_getElem hltCut] at hnf
                    have hfirstEq : natArchive[(native.history.log.branch.val[cut.val]'(by omega)).val]'hltCut = first :=
                      (List.cons.inj hnf).1
                    rw [← hfirstEq]
                    exact hnatVer cut.val (by omega) _ (List.getElem?_eq_getElem hltCut)
      have he : execute w (.rollback sid requested.val term.val) = some (w', .rolledBack cut.val) := by
        simpa [w', store, execute, hs, h.global, hLow, h.term, hStale] using hh
      have reach := reachable_execute related.reachable he
      have hstore : find w'.stores sid = some store := by simp [w', find_set_key]
      have hidxValid' : HistoryIndexValid afterHist := by
        refine h.indexValid.of_preserves_pins hlive'.valid hpres' ?_
        intro i f' hf'
        have hiLt : i < native.history.log.frames.val.length := by
          have := (List.getElem?_eq_some_iff.mp hf').1
          omega
        let f := native.history.log.frames.val[i]'hiLt
        obtain ⟨f'', hf'', _, _, _, hdata, _⟩ := hslot i f (List.getElem?_eq_getElem hiLt)
        have heq : f' = f'' := Option.some.inj (hf'.symm.trans hf'')
        subst heq
        rcases hdata with hd | h0
        · exact Or.inr ⟨i, f, List.getElem?_eq_getElem hiLt, hd⟩
        · exact Or.inl h0
      have haligned' : ArchiveAligned encode afterHist natArchive := by
        refine ⟨by rw [hlenEq]; exact h.aligned.len, ?_, ?_⟩
        · intro i nf' gf hnf' hgf
          have hiLt : i < native.history.log.frames.val.length := by
            have := (List.getElem?_eq_some_iff.mp hnf').1
            omega
          let f := native.history.log.frames.val[i]'hiLt
          obtain ⟨f'', hf'', hfv, hfr, hfb, _, _⟩ := hslot i f (List.getElem?_eq_getElem hiLt)
          have heq : nf' = f'' := Option.some.inj (hnf'.symm.trans hf'')
          subst heq
          have hmeta := h.aligned.metaEq i f gf (List.getElem?_eq_getElem hiLt) hgf
          exact ⟨by rw [hfv]; exact hmeta.1, by simp only [modelMetadata, hfr]; exact hmeta.2.1,
            by simp only [modelMetadata, hfb]; exact hmeta.2.2⟩
        · intro pos id nf' gf hpos hnf' hgf hliveCond
          have hposLt : pos < cut.val + 1 := by
            have := (List.getElem?_eq_some_iff.mp hpos).1
            rw [hbr, List.length_take] at this
            omega
          have hpos0 : native.history.log.branch.val[pos]? = some id := by
            rw [hbr, List.getElem?_take_of_lt hposLt] at hpos
            exact hpos
          have hidLt : id.val < native.history.log.frames.val.length := by
            have := (List.getElem?_eq_some_iff.mp hnf').1
            omega
          let f := native.history.log.frames.val[id.val]'hidLt
          have hf0 : native.history.log.frames.val[id.val]? = some f := List.getElem?_eq_getElem hidLt
          obtain ⟨f'', hf'', _, _, _, _, hkept⟩ := hslot id.val f hf0
          have heq : nf' = f'' := Option.some.inj (hnf'.symm.trans hf'')
          subst heq
          have hsame : nf' = f := by
            apply hkept
            intro off id' hoffGe _ hoff
            have hne : off ≠ pos := by omega
            exact branch_nodup_ne h.unique hoff hpos0 hne
          subst hsame
          have hlive0 : native.history.reuse_compacted_images = true → native.history.global.val ≤ f.version.val := by
            intro hrc0
            have hge : afterHist.global.val ≤ f.version.val := hliveCond (by rw [hreuse]; exact hrc0)
            rwa [hglobal] at hge
          have hmf0 := h.aligned.activeLive pos id f gf hpos0 hf0 hgf hlive0
          have hpin : f.data = 0#u32 ∨ f.data ∈ framePins afterHist.log.frames.val ++ txsPins native.txs.val := by
            by_cases hz : f.data = 0#u32
            · exact Or.inl hz
            · exact Or.inr (List.mem_append_left _
                (List.mem_filterMap.mpr ⟨f, List.mem_iff_getElem?.mpr ⟨id.val, hnf'⟩, by simp [hz]⟩))
          have hview := index_preserves_pins_view hpres' f.data _ hpin (h.indexValid.archived id.val f hf0)
          have hrows : indexRows afterHist.index f.data = indexRows native.history.index f.data :=
            index_rows_eq hview
          simpa only [modelFrame, hrows] using hmf0
      have hNatRev' : RevisionHistory (natModelFrames afterHist.log natArchive) := by
        rw [hAfterFrames]
        exact h.revisions.filter _
      have hModSub' : ∀ f ∈ store.history, f ∈ archive := by
        intro f hf
        exact h.modelSub f (List.mem_of_mem_filter hf)
      have hvalid : HistoryMatches encode afterHist store natArchive archive :=
        history_related reach hstore hFramesForall (by change s.global = afterHist.global.val; rw [hglobal]; exact h.global)
          (by change term.val = afterHist.term.val; rw [hterm])
          (by change s.nextIdentity = afterHist.next_identity.val; rw [hident]; exact h.identity)
          hvalid' hunique' hidxValid' haligned' hNatRev'
          (by rw [hident]; exact h.nativeArchive) h.natSorted hModSub' h.modelArchive
      have rel := replace_history (n' := {native with history := afterHist})
        related.unique hattempts hvalid hlive' hstore rfl rfl reach hpres'
        (fun _ hm => hm) (fun _ hm => hm)
      change WP.spec (Result.ok (out, ({native with history := afterHist} : Spike.engine.Store))) _
      rw [WP.spec_ok, he, hout]
      exact ⟨.RolledBack cut, rfl, rfl, rel⟩

end KvRust
