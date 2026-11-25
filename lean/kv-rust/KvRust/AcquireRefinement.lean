-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Relation

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Capacity for inserting one new map handle and retaining its radix root references. -/
def FitsAcquire (n : Spike.engine.Store) (id : U64) : Prop :=
  ∀ t,
    find n.txs.val id = some t
    → t.views.val.length < Usize.max
      ∧ (storePins n).length + 17 * n.history.index.values.dirs.val.length + 2 ≤ U32.max

private theorem selected_unique (w : State) (sid : Nat) (s : Store) (snap : Snapshot)
    (m : String) (h : transitionSystem.Reachable w) (hs : find w.stores sid = some s)
    : Kv.Properties.Unique (image (captureLocal s snap m).data m) := by
  by_cases hb : (find (atCut s snap.current.version).births m).isSome
  · have hh := (Kv.Properties.reachable_store_invariants w sid s h hs).1
    have he : Kv.Properties.Unique (atCut s snap.current.version).data := by
      unfold atCut
      cases hf : s.history.find? (fun f => decide (f.version ≤ snap.current.version)) with
      | none => exact List.Pairwise.nil
      | some f => exact history_data_unique hh f (List.mem_of_find?_eq_some hf)
    simp only [captureLocal, hb, ite_true]
    exact unique_image _ _ he
  · rw [captureLocal, ite_eq_right hb]
    exact List.Pairwise.nil

private theorem capture_current (s : Store) (snap : Snapshot) (m : String)
    : (captureGlobal s snap m).current = captureLocal s snap m := by
  by_cases h : (find (captureLocal s snap m).births m).isNone <;> simp [captureGlobal, h]

private theorem acquire_observation (encode : List U8 → String)
    (output : core.result.Result Spike.engine.Output Spike.engine.Error) (obs : Output)
    (h : modelAcquisition output = some obs)
    : ∃ out, output = .Ok out ∧ modelOutput encode out = obs := by
  cases output with
  | Err e => cases h
  | Ok out =>
      refine ⟨out, rfl, ?_⟩
      cases out <;> cases h <;> rfl

private theorem native_view_present (encode : List U8 → String) (sid : Nat)
    (index : CellIndex) (natArchive archive : List Frame) (t : Spike.engine.Tx)
    (tx : Tx) (view : GlobalView) (key : String)
    (rel : AttemptMatches encode sid index natArchive archive t tx)
    (hf : find tx.globalViews key = some view)
    : (find (rustPinnedViews encode index t.views) key).isSome := by
  have hrel := rel.views.find key
  rw [lookup_model_view _ _ _ hf] at hrel
  cases h : find (rustPinnedViews encode index t.views) key with
  | none => rw [h] at hrel; cases hrel
  | some _ => rfl

private theorem atCut_in_archive {s : Store} {archive : List Frame}
    (sub : ∀ f ∈ s.history, f ∈ archive) (emptyIn : ({} : Frame) ∈ archive) (cut : Nat)
    : atCut s cut ∈ archive := by
  unfold atCut
  cases hf : s.history.find? (fun f => decide (f.version ≤ cut)) with
  | none => exact emptyIn
  | some f => exact sub f (List.mem_of_find?_eq_some hf)

private theorem updated_relation (encode : List U8 → String) (sid : Nat)
    (oldIndex newIndex : CellIndex) (natArchive archive : List Frame) (s : Store)
    (snap : Snapshot) (rustSnap : Spike.engine.Snapshot) (key : String)
    (t t' : Spike.engine.Tx) (tx tx' : Tx)
    (rel : AttemptMatches encode sid oldIndex natArchive archive t tx)
    (hvals : newIndex.values = oldIndex.values) (hSnap : t.snapshot = some rustSnap)
    (hFreshModel : find tx.globalViews key = none)
    (hModelSub : ∀ f ∈ s.history, f ∈ archive) (hEmptyIn : ({} : Frame) ∈ archive)
    (unique : Kv.Properties.Unique (image (captureLocal s snap key).data key))
    (v
      : ViewsOrderEq (modelPinnedViews tx'.globalViews)
          (rustPinnedViews encode newIndex t'.views))
    (live : ViewsLive newIndex t'.views)
    (orig : ViewsOrigin encode newIndex natArchive t'.views)
    (otherViews
      : ∀ m,
          m ≠ key
          → find (rustPinnedViews encode newIndex t'.views) m
            = find (rustPinnedViews encode oldIndex t.views) m)
    (viewsKeep : ∀ row ∈ t.views.val, row ∈ t'.views.val)
    (hu : tx'.unavailable = t'.unavailable)
    (hn
      : if available s snap key then
          t' = {t with views := t'.views}
        else
          t' = {t with unavailable := true})
    (hm
      : if available s snap key then
          tx'
          = {
            tx with
              globalViews := Kv.Model.set tx.globalViews key (captureGlobal s snap key)
              data := pinData tx.data key (captureLocal s snap key).data
          }
        else
          tx' = {tx with unavailable := true})
    : AttemptMatches encode sid newIndex natArchive archive t' tx' := by
  have hpresAll : ∀ pins, IndexPreservesPins oldIndex newIndex pins := by
    intro pins r _ bindings hview
    exact ⟨⟨by rw [hvals]; exact hview.lookup, by rw [hvals]; exact hview.values, hview.sorted⟩,
      by simp [singleBindings, hvals]⟩
  by_cases ha : available s snap key
  · rw [ite_eq_left ha] at hn hm
    have hnone : t'.snapshot = some rustSnap := by
      simpa only [hSnap] using congrArg Spike.engine.Tx.snapshot hn
    have hFreshNative : find (rustPinnedViews encode oldIndex t.views) key = none := by
      have hr := rel.views.find key
      rw [projected_view_missing tx.globalViews key hFreshModel] at hr
      cases h : find (rustPinnedViews encode oldIndex t.views) key with
      | none => rfl
      | some _ => rw [h] at hr; cases hr
    have hdepsEq : pointDeps encode newIndex t' = pointDeps encode oldIndex t := by
      have hdt : t'.deps = t.deps := by simpa using congrArg Spike.engine.Tx.deps hn
      unfold pointDeps
      rw [hdt]
      congr 1
      apply List.map_congr_left
      intro d hd
      cases d with
      | Key _ _ => rfl
      | Map m pin =>
          obtain ⟨row, hrow, _, hpin⟩ := rel.depsPins m pin hd
          have hsub : ∀ r ∈ pinPins pin, r ∈ txPins t := fun r hr =>
            List.mem_flatMap.mpr ⟨row, hrow, List.mem_append_left _ (hpin ▸ hr)⟩
          have hEq := (pin_preserved_of_pins (hpresAll (txPins t)) m pin hsub
            (hpin ▸ (rel.live row hrow).1)).2
          simp only [Function.comp_def, byteDependency, encodeDependency, hEq]
    refine ⟨?_, ?_, ?_, v, live, orig, ?_, ?_, ?_, ?_, ?_, hu, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · rw [hm]; exact rel.store
    · rw [hm, hn]; exact rel.snapshot
    · rw [hm, hn]; exact rel.phase
    · intro row hrow
      rw [hm] at hrow
      rcases List.mem_cons.mp hrow with rfl | old
      · constructor
        · rw [capture_current]
          unfold captureLocal
          split
          · exact atCut_in_archive hModelSub hEmptyIn _
          · exact hEmptyIn
        · unfold captureGlobal
          dsimp only
          split
          · exact hEmptyIn
          · exact atCut_in_archive hModelSub hEmptyIn _
      · exact rel.modelViewsIn row (List.mem_filter.mp old).1
    · intro m
      rw [hm]
      change image (pinData tx.data key (captureLocal s snap key).data) m =
        ((find (Kv.Model.set tx.globalViews key (captureGlobal s snap key)) m).map
          (fun view => image view.current.data m)).getD []
      rw [pinned_data_image, find_set_key]
      by_cases he : m = key
      · subst m
        simp [capture_current]
      · simpa [he] using rel.data m
    · intro m
      rw [hm]
      change Kv.Properties.Unique (image (pinData tx.data key (captureLocal s snap key).data) m)
      rw [pinned_data_image]
      by_cases he : m = key
      · simpa [he] using unique
      · simpa [he] using rel.dataUnique m
    · intro op hop
      rw [hm] at hop ⊢
      change (find (Kv.Model.set tx.globalViews key (captureGlobal s snap key)) op.map).isSome = true
      rw [find_set_key]
      by_cases he : op.map = key
      · simp [he]
      · simpa [he] using rel.log op hop
    · intro hz
      rw [hnone] at hz
      cases hz
    · rw [hm, hn]; exact rel.writes
    · rw [hn]; exact rel.sorted
    · rw [hm, hdepsEq]; exact rel.deps
    · intro d hd
      rw [hdepsEq] at hd
      have hprev := rel.nativeDeps d hd
      cases d with
      | key _ _ => trivial
      | map m expected =>
          obtain ⟨pv, hpv, hexp⟩ := hprev
          have hne : m ≠ key := by
            rintro rfl
            rw [hFreshNative] at hpv
            cases hpv
          exact ⟨pv, (otherViews m hne).trans hpv, hexp⟩
    · intro mp pin hmem
      have hdt : t'.deps = t.deps := by simpa using congrArg Spike.engine.Tx.deps hn
      rw [hdt] at hmem
      obtain ⟨row, hrow, hmEq, hpEq⟩ := rel.depsPins mp pin hmem
      exact ⟨row, viewsKeep row hrow, hmEq, hpEq⟩
    · intro d hd
      rw [hm] at hd ⊢
      have hprev := rel.modelDeps d hd
      cases d with
      | key _ _ => trivial
      | map m expected =>
          obtain ⟨gv, hgv, hexp⟩ := hprev
          have hne : m ≠ key := by
            rintro rfl
            rw [hFreshModel] at hgv
            cases hgv
          refine ⟨gv, ?_, hexp⟩
          change find (Kv.Model.set tx.globalViews key _) m = some gv
          rw [find_set_key, ite_eq_right hne]
          exact hgv
  · rw [ite_eq_right ha] at hn hm
    rw [hn, hm]
    have hrelNew := rel.withPreservedPins (hpresAll (txPins t))
      (fun row hrow r hr => List.mem_flatMap.mpr ⟨row, hrow, hr⟩)
      (fun _ hm => hm) (fun _ hm => hm)
    exact {hrelNew with unavailable := rfl}

/-- Lazy acquisition preserves the relation, including stale and duplicate acquisition guards. -/
theorem acquire_step_matches (encode : List U8 → String) (inj : Function.Injective encode)
    (sid : Nat) (n : Spike.engine.Store) (w : State) (id : U64) (m : Spike.engine.Bytes)
    (rel : StateMatches encode sid n w) (room : FitsAcquire n id)
    : WP.spec (Spike.engine.Store.execute n (.Acquire id m))
        (StepMatches encode sid (.acquire sid id.val (encode (alloc.vec.Vec.val m))) n
          (execute w (.acquire sid id.val (encode (alloc.vec.Vec.val m))))) := by
  obtain ⟨s, natArchive, archive, hs, hh, hMeta, hattempts⟩ := rel.history
  let key := encode (alloc.vec.Vec.val m)
  have bind_some {α β : Type} (x : α) (f : α → Option β) : (some x >>= f) = f x := rfl
  have refuse (bad : ∀ t, find n.txs.val id = some t →
      t.snapshot = none ∨ t.phase ≠ .Active ∨ (find (rustPinnedViews encode n.history.index t.views) key).isSome)
      (hm : execute w (.acquire sid id.val key) = none) :
      WP.spec (Spike.engine.Store.execute n (.Acquire id m))
        (StepMatches encode sid (.acquire sid id.val key) n (execute w (.acquire sid id.val key))) := by
    rw [hm]
    exact execute_acquire_disabled encode inj n id m bad
  cases hn : find n.txs.val id with
  | none =>
      apply refuse (by simp [hn])
      have hm : lookupTx w sid id.val = none := by
        simp [lookupTx, hs, lookup_missing_of_attempts hattempts hn]
      simp [execute, hm]
  | some t =>
      obtain ⟨tx, hlookup, hr⟩ := lookup_of_attempts hs hattempts hn
      have bad (p : Prop) (hp : p) (why : p →
          t.snapshot = none ∨ t.phase ≠ .Active ∨ (find (rustPinnedViews encode n.history.index t.views) key).isSome)
          (hm : execute w (.acquire sid id.val key) = none) :
          WP.spec (Spike.engine.Store.execute n (.Acquire id m))
            (StepMatches encode sid (.acquire sid id.val key) n (execute w (.acquire sid id.val key))) :=
        refuse (fun other hOther => (Option.some.inj (hn.symm.trans hOther)) ▸ why hp) hm
      cases hns : t.snapshot with
      | none =>
          have hsnap : tx.snapshot = none := by
            have he := hr.snapshot
            rw [hns] at he
            cases h : tx.snapshot <;> simp_all
          exact bad _ hns Or.inl (by simp [execute, hlookup, hsnap])
      | some rustSnap =>
          cases hms : tx.snapshot with
          | none => have he := hr.snapshot; simp [hms, hns] at he
          | some snap =>
              by_cases hp : t.phase = .Active
              · have hphase : tx.phase = .active := by simp [hr.phase, hp, modelPhase]
                cases hm : find tx.globalViews key with
                | some view =>
                    exact bad _
                      (native_view_present encode sid n.history.index natArchive archive t
                        tx view key hr hm)
                      (Or.inr ∘ Or.inr) (by simp [execute, hlookup, hms, hm, hphase])
                | none =>
                    have hCut : snap.current.version = rustSnap.version.val := by
                      have he := hr.snapshot
                      rw [hms, hns] at he
                      exact congrArg Prod.fst (Option.some.inj he)
                    obtain ⟨prior, head, hf, _⟩ := hh.split
                    obtain ⟨hViewRoom, hRefRoom⟩ := room t hn
                    have hbrLen : n.history.log.branch.val.length = n.history.activeFrames.length :=
                      (branch_values_length n.history.log hh.valid).symm
                    have hSnapMetaLive : ∀ (fid : Usize) nf,
                        n.history.log.branch.val[min rustSnap.version.val
                            (n.history.log.branch.val.length - 1)]? = some fid
                        → n.history.log.frames.val[fid.val]? = some nf
                        → nf.meta_live = true := by
                      intro fid nf hfid hnf
                      by_cases hlt :
                        rustSnap.version.val < n.history.log.branch.val.length
                      · have hmin : min rustSnap.version.val (n.history.log.branch.val.length - 1)
                            = rustSnap.version.val := by omega
                        rw [hmin] at hfid
                        have hmemTx : (id, t) ∈ n.txs.val := by
                          have hfm : ∀ (xs : List (U64 × Spike.engine.Tx)),
                              find xs id = some t → (id, t) ∈ xs := by
                            intro xs
                            induction xs with
                            | nil => intro hf'; simp [find] at hf'
                            | cons p tl ih =>
                                intro hf'
                                rcases p with ⟨pk, pv⟩
                                by_cases heq : pk = id
                                · subst heq; simp [find] at hf'; subst hf'; exact List.mem_cons_self
                                · simp [find, heq] at hf'; exact List.mem_cons_of_mem _ (ih hf')
                          exact hfm n.txs.val hn
                        exact hMeta.snapLive id t rustSnap fid nf hmemTx hns hfid hnf
                      · have hmin : min rustSnap.version.val (n.history.log.branch.val.length - 1)
                            = n.history.log.branch.val.length - 1 := by omega
                        rw [hmin] at hfid
                        have hactLt : n.history.log.branch.val.length - 1 < n.history.activeFrames.length := by
                          have hpos : 0 < n.history.activeFrames.length := List.length_pos_iff.mpr hh.nonempty
                          omega
                        have hactAt : n.history.activeFrames[n.history.log.branch.val.length - 1]? = some nf := by
                          rw [branch_active_getElem? n.history.log hh.valid, hfid]
                          simpa using hnf
                        have hactEq : n.history.activeFrames[n.history.log.branch.val.length - 1] = nf :=
                          Option.some.inj ((List.getElem?_eq_getElem hactLt).symm.trans hactAt)
                        have hver : nf.version.val = n.history.log.branch.val.length - 1 := by
                          rw [← hactEq]; exact hh.indexed _ hactLt
                        exact hh.aligned.globalMetaLive _ fid nf hfid hnf (fun _ => by
                          have := hh.globalBound; omega)
                    apply WP.spec_mono
                      (execute_acquire_matches_model encode inj n id w sid s natArchive tx
                        t snap rustSnap m prior head hf hh.frames hh.indexed hh.global
                        hh.globalBound hh.revisions hn hlookup hns hms hCut hp hphase
                        hr.views hr.unavailable hm (hr.fresh_log hm) hViewRoom hh.valid
                        hh.indexValid hh.aligned hSnapMetaLive rel.liveness hRefRoom
                        hr.live hr.nativeOrig)
                    rintro ⟨output, after⟩ ⟨modelAfter, txAfter, tAfter, obs, index, hstep, ho, hw, hv, hu,
                      han, ham, _, hlog, hglobal, hterm, hident, hreuse, hvals, hliveAfter,
                      hidx, hrow, hLive, hOrig, hViewsKeep, hViewStep, hOther⟩
                    rw [hstep]
                    obtain ⟨out, hout, hc⟩ := acquire_observation encode output obs ho
                    have hpres : IndexPreservesPins n.history.index after.history.index (storePins after) := by
                      intro r _ bindings hview
                      exact ⟨⟨by rw [hvals]; exact hview.lookup, by rw [hvals]; exact hview.values,
                        hview.sorted⟩, by simp [singleBindings, hvals]⟩
                    have hidxValidAfter : HistoryIndexValid after.history :=
                      hh.indexValid.of_preserves_pins hliveAfter.valid hpres (fun i f' hf' =>
                        Or.inr ⟨i, f', hlog ▸ hf', rfl⟩)
                    have halignedAfter : ArchiveAligned encode after.history natArchive :=
                      hh.aligned.of_preserves_pins hh.indexValid hpres
                        (congrArg Spike.branch_log.BranchLog.branch hlog)
                        (congrArg Spike.branch_log.BranchLog.frames hlog)
                        hglobal hreuse
                    have hhistAfter : HistoryMatches encode after.history s natArchive archive :=
                      { hh with
                        nonempty := by unfold Spike.engine.History.activeFrames; rw [hlog]; exact hh.nonempty
                        frames := by rw [hlog]; exact hh.frames
                        indexed := by unfold Spike.engine.History.activeFrames; rw [hlog]; exact hh.indexed
                        global := by rw [hglobal]; exact hh.global
                        globalBound := by
                          unfold Spike.engine.History.activeFrames
                          rw [hglobal, hlog]
                          exact hh.globalBound
                        term := by rw [hterm]; exact hh.term
                        identity := by rw [hident]; exact hh.identity
                        valid := by rw [hlog]; exact hh.valid
                        unique := by rw [hlog]; exact hh.unique
                        indexValid := hidxValidAfter
                        aligned := halignedAfter
                        revisions := by rw [hlog]; exact hh.revisions
                        nativeArchive := by rw [hident]; exact hh.nativeArchive }
                    have hsnapEqT : tAfter.snapshot = t.snapshot := by
                      by_cases ha : available s snap key
                      · rw [ite_eq_left ha] at han
                        simpa using congrArg Spike.engine.Tx.snapshot han
                      · rw [ite_eq_right ha] at han
                        simpa using congrArg Spike.engine.Tx.snapshot han
                    have hmetaAfter : StoreMetaLive encode after natArchive := by
                      refine ⟨?_, ?_⟩
                      · intro id' t' snap' fid' nf' hmem hsnap' hfid' hnf'
                        have hmem' : (id', t') ∈ n.txs.val.set index (id, tAfter) := by
                          simpa only [hrow] using hmem
                        rcases List.mem_or_eq_of_mem_set hmem' with hold | heq
                        · exact hMeta.snapLive id' t' snap' fid' nf' hold hsnap'
                            (hlog ▸ hfid') (hlog ▸ hnf')
                        · obtain ⟨rfl, rfl⟩ := Prod.mk.inj heq
                          exact hMeta.snapLive id' t snap' fid' nf' (List.mem_of_getElem? hidx)
                            (hsnapEqT.symm.trans hsnap') (hlog ▸ hfid') (hlog ▸ hnf')
                      · intro id' t' bm bv off fid' gf hmem hvm hfid' hgf hb hr'
                        have hmem' : (id', t') ∈ n.txs.val.set index (id, tAfter) := by
                          simpa only [hrow] using hmem
                        rcases List.mem_or_eq_of_mem_set hmem' with hold | heq
                        · obtain ⟨off', fid', nf', hbr', hnf', hfm'⟩ :=
                            hMeta.viewLive id' t' bm bv off fid' gf hold hvm (hlog ▸ hfid') hgf hb hr'
                          exact ⟨off', fid', nf', hlog.symm ▸ hbr', hlog.symm ▸ hnf', hfm'⟩
                        · obtain ⟨rfl, rfl⟩ := Prod.mk.inj heq
                          by_cases ha : available s snap key
                          · rw [ite_eq_left ha] at hViewStep ham
                            obtain ⟨newView, hcons⟩ := hViewStep
                            rw [hcons] at hvm
                            rcases List.mem_cons.mp hvm with heqRow | holdV
                            · obtain ⟨hbmEq, hbvEq⟩ := Prod.mk.inj heqRow
                              subst hbmEq; subst hbvEq
                              -- New view `(bm, bv)` matches the active frame at `min rustSnap.version (branch.len - 1)`
                              let offC := min rustSnap.version.val (n.history.log.branch.val.length - 1)
                              have hposBr : 0 < n.history.log.branch.val.length :=
                                List.length_pos_iff.mpr hh.valid.1
                              have hoffCLt : offC < n.history.log.branch.val.length := by
                                dsimp [offC]; omega
                              let fidC := n.history.log.branch.val[offC]'hoffCLt
                              have hfidC : n.history.log.branch.val[offC]? = some fidC :=
                                List.getElem?_eq_getElem hoffCLt
                              have hfidCLt : fidC.val < n.history.log.frames.val.length :=
                                hh.valid.2 fidC (List.getElem_mem hoffCLt)
                              let nfC := n.history.log.frames.val[fidC.val]'hfidCLt
                              have hnfC : n.history.log.frames.val[fidC.val]? = some nfC :=
                                List.getElem?_eq_getElem hfidCLt
                              have hgfCLt : fidC.val < natArchive.length :=
                                hh.aligned.len.symm ▸ hfidCLt
                              let gfC := natArchive[fidC.val]'hgfCLt
                              have hgfC : natArchive[fidC.val]? = some gfC :=
                                List.getElem?_eq_getElem hgfCLt
                              have hnfCLive : nfC.meta_live = true := hSnapMetaLive fidC nfC hfidC hnfC
                              have hmetaC := hh.aligned.metaEq fidC.val nfC gfC hnfC hgfC hnfCLive
                              -- `gfC` is `atCut nativeModel snap.current.version` and `bv` matches `captureGlobal s snap key`
                              have hrelKey := hv.find key
                              have hmodFind : find (modelPinnedViews txAfter.globalViews) key
                                  = some (modelPinnedView key (captureGlobal s snap key)) := by
                                rw [ham]
                                change find (modelPinnedViews (Kv.Model.set tx.globalViews key
                                  (captureGlobal s snap key))) key = _
                                unfold modelPinnedViews Kv.Model.set
                                simp [find]
                              rw [hmodFind] at hrelKey
                              have hnatFind : find (rustPinnedViews encode after.history.index t'.views) key
                                  = some (rustPinnedView encode after.history.index bm bv) := by
                                unfold rustPinnedViews
                                rw [hcons, List.map_cons]
                                simp [find, key]
                              rw [hnatFind] at hrelKey
                              cases hrelKey with
                              | some hviewEq =>
                                  have hcurStamps :
                                      bv.birth.map modelStamp = find (captureLocal s snap key).births key
                                      ∧ modelStamp bv.revision = revision (captureLocal s snap key) key := by
                                    have hbEq := hviewEq.birth
                                    have hrEq := hviewEq.revision
                                    simp only [modelPinnedView, rustPinnedView, capture_current] at hbEq hrEq
                                    exact ⟨hbEq.symm, hrEq.symm⟩
                                  -- Show `atCut s snap.current.version` has the same stamps as `gfC`
                                  have hCutEq : FrameOrderEq gfC (atCut s snap.current.version) := by
                                    have hrevIdx : (natModelFrames n.history.log natArchive).length
                                        = n.history.log.branch.val.length :=
                                      natModelFrames_length hh.valid hh.aligned.len
                                    have hidxRev : n.history.log.branch.val.length - 1 - offC
                                        < (natModelFrames n.history.log natArchive).length := by
                                      rw [hrevIdx]; omega
                                    have hnatAt : (natModelFrames n.history.log natArchive)[
                                        n.history.log.branch.val.length - 1 - offC]? = some gfC := by
                                      unfold natModelFrames
                                      have hbd : ∀ x ∈ n.history.log.branch.val, x.val < natArchive.length :=
                                        fun x hx => hh.aligned.len.symm ▸ hh.valid.2 x hx
                                      have hrevFm : ∀ (ids : List Usize) (k : Nat),
                                          (∀ x ∈ ids, x.val < natArchive.length) →
                                          (ids.reverse.filterMap fun x => natArchive[x.val]?)[k]? =
                                            ids.reverse[k]?.bind fun x => natArchive[x.val]? := by
                                        intro ids
                                        have hfm : ∀ (l : List Usize) (k : Nat),
                                            (∀ x ∈ l, x.val < natArchive.length) →
                                            (l.filterMap fun x => natArchive[x.val]?)[k]? =
                                              l[k]?.bind fun x => natArchive[x.val]? := by
                                          intro l
                                          induction l with
                                          | nil => intro k _; simp
                                          | cons a tl ih =>
                                              intro k hbd'
                                              have ha' := hbd' a List.mem_cons_self
                                              cases k with
                                              | zero =>
                                                  simp [List.getElem?_eq_getElem ha']
                                              | succ j =>
                                                  simp only [List.filterMap_cons,
                                                    List.getElem?_eq_getElem ha', List.getElem?_cons_succ]
                                                  exact ih j (fun x hx => hbd' x (List.mem_cons_of_mem _ hx))
                                        intro k hbd'
                                        exact hfm ids.reverse k
                                          (fun x hx => hbd' x (List.mem_reverse.mp hx))
                                      rw [hrevFm _ _ hbd, List.getElem?_reverse (by omega)]
                                      have hsubEq : n.history.log.branch.val.length - 1
                                          - (n.history.log.branch.val.length - 1 - offC) = offC := by omega
                                      rw [hsubEq, hfidC]
                                      simpa using hgfC
                                    have hforall := List.forall₂_iff_get.mp hh.frames
                                    have hmLt : n.history.log.branch.val.length - 1 - offC < s.history.length := by
                                      rw [← hforall.1]; exact hidxRev
                                    have hfo := hforall.2 (n.history.log.branch.val.length - 1 - offC) hidxRev hmLt
                                    simp only [List.get_eq_getElem] at hfo
                                    have hgfEq : (natModelFrames n.history.log natArchive)[
                                        n.history.log.branch.val.length - 1 - offC]'hidxRev = gfC :=
                                      Option.some.inj ((List.getElem?_eq_getElem hidxRev).symm.trans hnatAt)
                                    rw [hgfEq] at hfo
                                    -- Show `s.history[...]` equals `atCut s snap.current.version`
                                    have hfindAt : s.history.find? (fun f => decide (f.version ≤ snap.current.version))
                                        = some (s.history[n.history.log.branch.val.length - 1 - offC]'hmLt) := by
                                      have hinv := (Kv.Properties.reachable_store_invariants w sid s rel.reachable hs).1
                                      have hverS : ∀ j (hj : j < s.history.length),
                                          s.history[j].version = s.history.length - 1 - j := by
                                        have hrec : ∀ (l : List Frame) (v : Nat), Kv.Properties.History l v →
                                            l.length = v + 1 ∧ ∀ j (hj : j < l.length), l[j].version = l.length - 1 - j := by
                                          intro l v hh'
                                          induction hh' with
                                          | zero =>
                                              refine ⟨rfl, ?_⟩
                                              intro j hj
                                              cases j with
                                              | zero => rfl
                                              | succ _ => simp at hj
                                          | succ f k rest hv _ _ ih =>
                                              refine ⟨by simp [ih.1], ?_⟩
                                              intro j hj
                                              cases j with
                                              | zero => simp [hv, ih.1]
                                              | succ j' =>
                                                  have hj' : j' < rest.length := by simpa using hj
                                                  simpa [ih.1] using ih.2 j' hj'
                                        exact (hrec _ _ hinv).2
                                      have hfindGen : ∀ (l : List Frame) (k : Nat) (hk : k < l.length),
                                          (∀ j (hj : j < k), ¬ (l[j].version ≤ snap.current.version)) →
                                          l[k].version ≤ snap.current.version →
                                          l.find? (fun f => decide (f.version ≤ snap.current.version)) = some l[k] := by
                                        intro l
                                        induction l with
                                        | nil => intro k hk; simp at hk
                                        | cons x xs ih =>
                                            intro k hk hbef hcur
                                            cases k with
                                            | zero =>
                                                simp only [List.getElem_cons_zero] at hcur ⊢
                                                rw [List.find?_cons_of_pos (by simp [hcur])]
                                            | succ k' =>
                                                have h0 : ¬ (x.version ≤ snap.current.version) := hbef 0 (by omega)
                                                rw [List.find?_cons_of_neg (by simp [h0])]
                                                exact ih k' (by simpa using hk)
                                                  (fun j hj => hbef (j + 1) (by omega))
                                                  hcur
                                      apply hfindGen s.history
                                        (n.history.log.branch.val.length - 1 - offC) hmLt
                                      · intro j hj
                                        have hlenS : s.history.length = n.history.log.branch.val.length := by
                                          rw [← hforall.1, hrevIdx]
                                        have hjv := hverS j (by omega)
                                        dsimp [offC] at *
                                        omega
                                      · have hlenS : s.history.length = n.history.log.branch.val.length := by
                                          rw [← hforall.1, hrevIdx]
                                        have hkv := hverS (n.history.log.branch.val.length - 1 - offC) hmLt
                                        dsimp [offC] at *
                                        omega
                                    have hatEq : atCut s snap.current.version =
                                        s.history[n.history.log.branch.val.length - 1 - offC]'hmLt := by
                                      simp [atCut, hfindAt]
                                    rwa [hatEq]
                                  have hStampsC :
                                      find gfC.births key = bv.birth.map modelStamp
                                      ∧ revision gfC key = modelStamp bv.revision := by
                                    rw [hcurStamps.1, hcurStamps.2]
                                    by_cases hborn :
                                      (find (atCut s snap.current.version).births
                                        key).isSome
                                      = true
                                    · simp only [captureLocal, hborn, ite_true]
                                      exact ⟨hCutEq.births key, hCutEq.revision_eq key⟩
                                    · have hnone
                                          : find (atCut s snap.current.version).births key
                                            = none := by
                                        cases h
                                              : find
                                                  (atCut s snap.current.version).births
                                                  key with
                                        | none => rfl
                                        | some _ => simp [h] at hborn
                                      have hnoneG : find gfC.births key = none :=
                                        (hCutEq.births key).trans hnone
                                      have hunborn := hh.nativeArchive.unborn gfC
                                        (List.mem_of_getElem? hgfC) key hnoneG
                                      rw [captureLocal, ite_eq_right hborn]
                                      exact ⟨
                                        by simp [hnoneG, find],
                                        by simp [revision, hunborn.2, find]
                                      ⟩
                                  refine ⟨
                                    offC,
                                    fidC,
                                    nfC,
                                    hlog.symm ▸ hfidC,
                                    hlog.symm ▸ hnfC,
                                    ?_
                                  ⟩
                                  unfold frameMatches
                                  have hbMeta : find (modelMetadata (encode ∘ alloc.vec.Vec.val) nfC).births key
                                      = find gfC.births key := by
                                    rw [hmetaC.2.2]
                                  have hrMeta : revision (modelMetadata (encode ∘ alloc.vec.Vec.val) nfC) key
                                      = revision gfC key := by
                                    unfold revision; rw [hmetaC.2.1]
                                  change (nfC.meta_live
                                      && (find (modelMetadata (encode ∘ alloc.vec.Vec.val) nfC).births key
                                          == bv.birth.map modelStamp)
                                      && (revision (modelMetadata (encode ∘ alloc.vec.Vec.val) nfC) key
                                          == modelStamp bv.revision)) = true
                                  rw [hnfCLive, hbMeta, hrMeta, hStampsC.1, hStampsC.2]
                                  cases bv.birth with
                                  | none =>
                                      change (true && true
                                        && ((bv.revision.version.val == bv.revision.version.val)
                                          && (bv.revision.identity.val == bv.revision.identity.val)))
                                        = true
                                      simp
                                  | some b =>
                                      change (true && ((b.version.val == b.version.val)
                                        && (b.identity.val == b.identity.val))
                                        && ((bv.revision.version.val == bv.revision.version.val)
                                          && (bv.revision.identity.val == bv.revision.identity.val)))
                                        = true
                                      simp
                            · obtain ⟨off', fid', nf', hbr', hnf', hfm'⟩ :=
                                hMeta.viewLive id' t bm bv off fid' gf (List.mem_of_getElem? hidx)
                                  holdV (hlog ▸ hfid') hgf hb hr'
                              exact ⟨off', fid', nf', hlog.symm ▸ hbr', hlog.symm ▸ hnf', hfm'⟩
                          · rw [ite_eq_right ha] at hViewStep
                            obtain ⟨off', fid', nf', hbr', hnf', hfm'⟩ :=
                              hMeta.viewLive id' t bm bv off fid' gf (List.mem_of_getElem? hidx)
                                (hViewStep ▸ hvm) (hlog ▸ hfid') hgf hb hr'
                            exact ⟨off', fid', nf', hlog.symm ▸ hbr', hlog.symm ▸ hnf', hfm'⟩
                    refine ⟨
                      out,
                      hout,
                      OutputMatches.of_eq hc,
                      replace_attempt rel.unique hattempts id index t tAfter txAfter
                        hidx hrow
                        (congrArg State.txs hw)
                        (by rw [hw]; exact hs)
                        hhistAfter
                        hliveAfter
                        hmetaAfter
                        ?_
                        (reachable_execute rel.reachable hstep)
                        hpres
                        (fun _ hm => hm)
                        (fun _ hm => hm)
                    ⟩
                    exact updated_relation encode sid n.history.index after.history.index
                      natArchive archive s snap rustSnap key t tAfter tx txAfter hr hvals
                      hns hm hh.modelSub hh.modelArchive.emptyPresent
                      (selected_unique w sid s snap key rel.reachable hs)
                      hv hLive hOrig hOther hViewsKeep hu han ham
              · have hm : (tx.phase != .active) = true := by
                  rw [hr.phase]
                  exact model_phase_inactive t.phase hp
                exact bad _ hp (Or.inr ∘ Or.inl)
                  (by simp only [execute, hlookup, bind_some, hms, hm, Bool.true_or,
                        ite_true])

end KvRust
