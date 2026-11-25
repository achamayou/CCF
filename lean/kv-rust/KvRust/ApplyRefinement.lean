-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Relation

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Capacity required for a live attempt to publish a new frame. -/
def FitsApply (n : Spike.engine.Store) (id : U64) : Prop :=
  ∀ t,
    find n.txs.val id = some t
    → ∀ prior head,
        n.history.activeFrames = prior ++ [head]
        → ApplyCapacity n.history head t (storePins n).length

private def nativeCommitting : Spike.engine.Phase → Bool
  | .Committing => true
  | _ => false

private theorem apply_empty {encode : List U8 → String} {sid : Nat} {t : Spike.engine.Tx}
    {index : CellIndex} {natArchive archive : List Frame} {tx : Tx}
    (h : AttemptMatches encode sid index natArchive archive t tx)
    : tx.normal.writes.isEmpty = t.pending.val.isEmpty := by
  have hlen : tx.normal.writes.length = t.pending.val.length := by
    have hp := h.writes.length_eq.symm
    simpa [pointWrites, encodeWrites, byteWrites] using hp
  cases hw : tx.normal.writes <;> cases hp : t.pending.val <;> simp [hw, hp] at hlen ⊢

private theorem history_version_bound {frames : List Frame} {latest : Nat}
    (shape : Kv.Properties.History frames latest) {f : Frame} (hf : f ∈ frames)
    : f.version ≤ latest := by
  induction shape with
  | zero => rw [List.mem_singleton.mp hf]
  | succ hd n tail hv _ _ ih =>
      rcases List.mem_cons.mp hf with rfl | old
      · exact Nat.le_of_eq hv
      · exact Nat.le_trans (ih old) (Nat.le_succ _)

private theorem find_in_mem {K V : Type} [DecidableEq K] {rows : Assoc K V} {k : K}
    {v : V} (h : find rows k = some v)
    : (k, v) ∈ rows := by
  induction rows with
  | nil => simp [find] at h
  | cons row rest ih =>
      obtain ⟨rk, rv⟩ := row
      by_cases he : rk = k
      · subst rk
        simp [find] at h
        subst rv
        exact List.mem_cons_self
      · simp [find, he] at h
        exact List.mem_cons_of_mem _ (ih h)

private theorem stamp_beq_eq {a b : Stamp} (h : (a == b) = true) : a = b := by
  cases a; cases b
  change (_ == _ && _ == _) = true at h
  simp only [Bool.and_eq_true, beq_iff_eq] at h
  simp [h]

private theorem opt_stamp_beq_eq {a b : Option Stamp} (h : (a == b) = true) : a = b := by
  cases a <;> cases b
  · rfl
  · cases h
  · cases h
  · exact congrArg some (stamp_beq_eq h)

private theorem nat_active_in_archive
    (log : Spike.branch_log.BranchLog Spike.engine.Frame) (natArchive : List Frame)
    {f : Frame} (hf : f ∈ natModelFrames log natArchive)
    : f ∈ natArchive := by
  unfold natModelFrames at hf
  obtain ⟨id, _, hsaved⟩ := List.mem_filterMap.mp hf
  exact List.mem_iff_getElem?.mpr ⟨id.val, hsaved⟩

private theorem nat_head_in_frames {encode : List U8 → String}
    {n : Spike.engine.History} {s : Store} {natArchive archive : List Frame}
    (hs : HistoryMatches encode n s natArchive archive)
    {prior : List Spike.engine.Frame} {head : Spike.engine.Frame}
    (hf : n.activeFrames = prior ++ [head])
    : (natModelFrames n.log natArchive).head?
      = some (modelFrame encode n.index head) := by
  have hbrNonempty : n.log.branch.val ≠ [] := by
    intro hnil
    have hlen := branch_values_length n.log hs.valid
    change n.activeFrames.length = n.log.branch.val.length at hlen
    rw [hf, hnil] at hlen
    simp at hlen
  let priorIds := n.log.branch.val.dropLast
  let headId := n.log.branch.val.getLast hbrNonempty
  have hbr' : n.log.branch.val = priorIds ++ [headId] :=
    (List.dropLast_append_getLast hbrNonempty).symm
  have hheadIdLt : headId.val < n.log.frames.val.length :=
    hs.valid.2 headId (by rw [hbr']; exact List.mem_append_right _ List.mem_cons_self)
  have hheadIdLtG : headId.val < natArchive.length := hs.aligned.len.symm ▸ hheadIdLt
  let nfHead := n.log.frames.val[headId.val]'hheadIdLt
  let gfHead := natArchive[headId.val]'hheadIdLtG
  have hheadSaved : n.log.frames.val[headId.val]? = some nfHead := List.getElem?_eq_getElem hheadIdLt
  have hgfSaved : natArchive[headId.val]? = some gfHead := List.getElem?_eq_getElem hheadIdLtG
  have hactSplit : n.activeFrames =
      (priorIds.filterMap fun id => n.log.frames.val[id.val]?) ++ [nfHead] := by
    unfold Spike.engine.History.activeFrames branchValues
    rw [hbr', List.filterMap_append, List.filterMap_cons, List.filterMap_nil, hheadSaved]
  have hheadEq : nfHead = head := by
    have hsame := hactSplit.symm.trans hf
    exact (List.append_inj_right' hsame rfl) |> List.cons.inj |>.1
  subst hheadEq
  have hactLen : n.activeFrames.length = priorIds.length + 1 := by
    rw [branch_values_length n.log hs.valid, hbr', List.length_append, List.length_singleton]
  have hlenPrior : prior.length = priorIds.length := by
    have := congrArg List.length hf
    rw [hactLen, List.length_append, List.length_singleton] at this
    omega
  have hheadVer : nfHead.version.val = priorIds.length := by
    have hidx : prior.length < n.activeFrames.length := by simp [hf]
    have hget : n.activeFrames[prior.length]'hidx = nfHead := by
      apply Option.some.inj
      rw [← List.getElem?_eq_getElem hidx, hf, List.getElem?_append_right (Nat.le_refl _),
        Nat.sub_self]
      rfl
    rw [← hlenPrior, ← hget]
    exact hs.indexed prior.length hidx
  have hliveHead : modelFrame encode n.index nfHead = gfHead :=
    hs.aligned.activeLive priorIds.length headId nfHead gfHead
      (by rw [hbr', List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]; rfl)
      hheadSaved hgfSaved (fun _ => by have := hs.globalBound; omega)
  unfold natModelFrames
  rw [hbr', List.reverse_append, List.reverse_singleton, List.singleton_append,
    List.filterMap_cons, hgfSaved, hliveHead]
  rfl

private theorem eligibility (encode : List U8 → String) (inj : Function.Injective encode)
    {sid : Nat} {w : State} {s : Store} {store : Spike.engine.Store}
    {natArchive archive : List Frame} {tx : Tx} {t : Spike.engine.Tx} {id : U64}
    {pinsCount : Nat}
    (reach : transitionSystem.Reachable w) (hsFound : find w.stores sid = some s)
    (hs : HistoryMatches encode store.history s natArchive archive)
    (hMeta : StoreMetaLive encode store natArchive)
    (hTxMem : (id, t) ∈ store.txs.val)
    (ht : AttemptMatches encode sid store.history.index natArchive archive t tx)
    (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hf : store.history.activeFrames = prior ++ [head])
    (hhead : FrameOrderEq (modelFrame encode store.history.index head) s.head)
    (space : ApplyCapacity store.history head t pinsCount)
    : WP.spec (Spike.engine.Tx.can_apply t store.history)
        (fun r => r = canApply s tx) := by
  let n := store.history
  let nativeHead := modelFrame encode n.index head
  let nativeFrames := natModelFrames n.log natArchive
  let nativeStore : Store := {
    s with
      history := nativeFrames
      head := nativeHead
  }
  have hinj : Function.Injective (encode ∘ alloc.vec.Vec.val (α := U8)) :=
    inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  have hViewLive : ∀ row ∈ t.views.val,
      n.activeFrames.any
          (fun f => frameMatches (encode ∘ alloc.vec.Vec.val) f row.1 row.2.birth row.2.revision)
      = stampsOnBranch nativeStore (viewStamps (encode ∘ alloc.vec.Vec.val) row) := by
    rintro ⟨bm, bv⟩ hvm
    apply Bool.eq_iff_iff.mpr
    simp only [stampsOnBranch, viewStamps, nativeStore, List.any_eq_true, Bool.and_eq_true]
    constructor
    · rintro ⟨nf, hnfMem, hfm⟩
      unfold Spike.engine.History.activeFrames branchValues at hnfMem
      obtain ⟨fid, hfidBr, hnfAt⟩ := List.mem_filterMap.mp hnfMem
      have hfidLt : fid.val < n.log.frames.val.length := hs.valid.2 fid hfidBr
      have hgfLt : fid.val < natArchive.length := hs.aligned.len.symm ▸ hfidLt
      let gf := natArchive[fid.val]'hgfLt
      have hgfAt : natArchive[fid.val]? = some gf := List.getElem?_eq_getElem hgfLt
      have hgfMem : gf ∈ nativeFrames :=
        List.mem_filterMap.mpr ⟨fid, List.mem_reverse.mpr hfidBr, hgfAt⟩
      unfold frameMatches at hfm
      simp only [Bool.and_eq_true] at hfm
      have hmeta := hs.aligned.metaEq fid.val nf gf hnfAt hgfAt hfm.1.1
      refine ⟨gf, hgfMem, ?_, ?_⟩
      · simpa only [modelMetadata, hmeta.2.2] using hfm.1.2
      · simpa only [modelMetadata, revision, hmeta.2.1] using hfm.2
    · rintro ⟨gf, hgfMem, hb, hr⟩
      unfold nativeFrames natModelFrames at hgfMem
      obtain ⟨fid, hfidRev, hgfAt⟩ := List.mem_filterMap.mp hgfMem
      have hfidMem : fid ∈ n.log.branch.val := List.mem_reverse.mp hfidRev
      obtain ⟨off, hfidBr⟩ := List.mem_iff_getElem?.mp hfidMem
      obtain ⟨off', fid', nf', hbr', hnf', hfm'⟩ :=
        hMeta.viewLive id t bm bv off fid gf hTxMem hvm hfidBr hgfAt hb hr
      have hnfMem : nf' ∈ n.activeFrames :=
        List.mem_filterMap.mpr ⟨fid', List.mem_of_getElem? hbr', hnf'⟩
      exact ⟨nf', hnfMem, hfm'⟩
  have hl := acquired_lineage_matches_model (encode ∘ alloc.vec.Vec.val) hinj
    n t nativeStore tx hViewLive ht.stamps hs.valid
  have hLineageEq : tx.globalViews.all (fun (m, view) => mapLineage nativeStore view.current m) =
      tx.globalViews.all (fun (m, view) => mapLineage s view.current m) := by
    apply List.all_congr rfl
    rintro ⟨m, view⟩
    exact history_order_eq_mapLineage (s := nativeStore) (t := s) hs.frames (.refl _) m
  have hHeadFirstNative : nativeFrames.head? = some nativeHead :=
    nat_head_in_frames hs hf
  have hHeadMemNative : nativeHead ∈ nativeFrames :=
    List.mem_of_head? hHeadFirstNative
  have hHeadMemNatArch : nativeHead ∈ natArchive :=
    nat_active_in_archive n.log natArchive hHeadMemNative
  have hHeadMemModel : s.head ∈ s.history := by
    have hh := hs.head
    cases h : s.history with
    | nil => simp [h] at hh
    | cons first rest =>
        rw [h] at hh
        rw [Option.some.inj hh]
        exact List.mem_cons_self
  have hModelShape : Kv.Properties.History s.history s.head.version :=
    (Kv.Properties.reachable_store_invariants w sid s reach hsFound).1
  have hNatUnique : Kv.Properties.Unique nativeHead.data :=
    hs.nativeArchive.unique nativeHead hHeadMemNatArch
  have hModUnique : Kv.Properties.Unique s.head.data :=
    hs.modelArchive.unique s.head (hs.modelSub s.head hHeadMemModel)
  have hCheckDeps (hLin : tx.globalViews.all (fun (m, view) => mapLineage s view.current m) = true) :
      WP.spec (Spike.engine.Tx.valid_dependencies t n) (fun r => r = validates s.head.data tx.normal.deps) := by
    have hNatCanon : ∀ d ∈ pointDeps encode n.index t,
        d.holds nativeHead.data = holdsByContents nativeHead.data d := by
      intro d hd
      have hfrom := ht.nativeDeps d hd
      cases d with
      | key _ _ => rfl
      | map m expected =>
          obtain ⟨pv, hpv, hexp⟩ := hfrom
          have hmem := find_in_mem hpv
          unfold rustPinnedViews at hmem
          obtain ⟨⟨bm, bv⟩, hbvMem, hpair⟩ := List.mem_map.mp hmem
          have hmEq : encode bm.val = m := congrArg Prod.fst hpair
          have hpvEq : rustPinnedView encode n.index bm bv = pv := congrArg Prod.snd hpair
          have hStampMem : viewStamps (encode ∘ alloc.vec.Vec.val) (bm, bv) ∈
              tx.globalViews.map capturedStamps := by
            rw [ht.stamps]
            exact List.mem_map_of_mem hbvMem
          obtain ⟨⟨m', gv⟩, hgvMem, hgvEq⟩ := List.mem_map.mp hStampMem
          have hm' : m' = m := (congrArg Prod.fst hgvEq).trans hmEq
          subst hm'
          have hMapLin := List.all_eq_true.mp (hLineageEq.trans hLin) (m', gv) hgvMem
          unfold mapLineage at hMapLin
          obtain ⟨old, holdMem, holdMatch⟩ := List.any_eq_true.mp hMapLin
          simp only [Bool.and_eq_true] at holdMatch
          have hbEq : find old.births m' = bv.birth.map modelStamp := by
            have := congrArg (fun x => x.2.1) hgvEq
            exact (opt_stamp_beq_eq holdMatch.1).trans this
          have hrEq : revision old m' = modelStamp bv.revision := by
            have := congrArg (fun x => x.2.2) hgvEq
            exact (stamp_beq_eq holdMatch.2).trans this
          have holdArch : old ∈ natArchive := nat_active_in_archive n.log natArchive holdMem
          have hOrig := ht.nativeOrig (bm, bv) hbvMem
          unfold ViewOrigin at hOrig
          dsimp only at hOrig
          rw [hmEq] at hOrig
          have hImgEq : expected = image old.data m' := by
            rw [hexp, ← hpvEq]
            change encodeImage encode (pinImage n.index bm bv.local) = image old.data m'
            cases hb : bv.birth with
            | none =>
                rw [hb] at hOrig hbEq
                exact hOrig.1.trans (hs.nativeArchive.unborn old holdArch m' hbEq).1.symm
            | some stamp =>
                rw [hb] at hOrig
                obtain ⟨f, hfMem, hfRev, hfImg⟩ := hOrig
                exact hfImg.trans (hs.nativeArchive.sameRevision f hfMem old holdArch m'
                  (hfRev.trans hrEq.symm))
          rw [hImgEq]
          simp only [Dependency.holds, holdsByContents]
          apply decide_eq_decide.mpr
          constructor
          · intro h; rw [h]
          · intro hperm
            exact encKeyLt_perm_eq inj
              (hs.natSorted nativeHead hHeadMemNatArch m')
              (hs.natSorted old holdArch m') hperm
    have hModOrigins : ∀ d ∈ tx.normal.deps, DependencyHasOrigin s.history s.head d := by
      intro d hd
      have hfrom := ht.modelDeps d hd
      cases d with
      | key _ _ => trivial
      | map m expected =>
          obtain ⟨gv, hgv, hexp⟩ := hfrom
          have hgvMem := find_in_mem hgv
          have hgvArch := (ht.modelViewsIn (m, gv) hgvMem).1
          have hMapLin := List.all_eq_true.mp hLin (m, gv) hgvMem
          unfold mapLineage at hMapLin
          obtain ⟨old, holdMem, holdMatch⟩ := List.any_eq_true.mp hMapLin
          simp only [Bool.and_eq_true] at holdMatch
          have holdArch := hs.modelSub old holdMem
          have hImgEq : expected = image old.data m :=
            hexp.trans (hs.modelArchive.sameRevision gv.current hgvArch old holdArch m
              (stamp_beq_eq holdMatch.2).symm)
          refine ⟨old, holdMem, history_version_bound hModelShape holdMem, hImgEq, ?_⟩
          rw [hImgEq]
          exact archive_image_cells_bounded hs.modelArchive holdArch m
    have hDepsRefl : List.Forall₂ DependencyOrderEq tx.normal.deps tx.normal.deps :=
      List.forall₂_iff_get.mpr
        ⟨
          rfl,
          fun i hi _ => by
            cases tx.normal.deps.get ⟨i, hi⟩ with
            | key _ _ => exact .key _ _
            | map _ _ => exact .map _ .rfl
        ⟩
    have hModelEq : validates s.head.data tx.normal.deps =
        tx.normal.deps.all (holdsByContents s.head.data) :=
      validates_by_contents hModelShape s.head s.head hHeadMemModel (.refl _) hModUnique
        hDepsRefl hModOrigins
    have hNatEq : validates nativeHead.data (pointDeps encode n.index t) =
        tx.normal.deps.all (holdsByContents s.head.data) := by
      have hRel := ht.deps
      clear hModOrigins hDepsRefl hModelEq
      generalize pointDeps encode n.index t = nds at hRel hNatCanon
      generalize tx.normal.deps = mds at hRel
      induction hRel with
      | nil => rfl
      | @cons x y xs ys hxy hrest ih =>
          simp only [validates, List.all_cons] at ih ⊢
          rw [hNatCanon x List.mem_cons_self, dependency_order_eq hhead.data hNatUnique hxy,
            ih (fun d hd => hNatCanon d (List.mem_cons_of_mem _ hd))]
    apply WP.spec_mono
      (validate_dependencies_matches_model t n head (indexRows n.index head.data)
        (hs.indexValid.head prior head hf) hs.indexValid.index
        (by simp [history_head n prior head hf hs.valid]) space.dependencies)
    intro r hr
    rw [hr, ← validates_encoding encode inj]
    have hRev : validates (encodeData encode (indexedCellData (indexRows n.index head.data)))
        ((t.deps.val.map (byteDependency n.index)).map (encodeDependency encode)) =
        validates nativeHead.data (pointDeps encode n.index t) := by
      simp [validates, pointDeps, nativeHead, modelFrame, List.all_reverse,
        List.map_map, Function.comp_def]
    rw [hRev, hNatEq, ← hModelEq]
  have hcheck : WP.spec (do
      let b ← Spike.engine.Tx.valid_lineage t n
      if b then Spike.engine.Tx.valid_dependencies t n else Result.ok false)
      (fun r => r = (tx.globalViews.all (fun (m, view) => mapLineage s view.current m)
        && validates s.head.data tx.normal.deps)) := by
    apply WP.spec_bind hl
    intro b hb
    rw [hLineageEq] at hb
    cases b with
    | false => simp [← hb]
    | true =>
        simp only [ite_true, ← hb, Bool.true_and]
        exact hCheckDeps hb.symm
  have hsnap : tx.snapshot.map Snapshot.term = t.snapshot.map (fun x => x.term.val) := by
    simpa only [snapshotCut, modelSnapshot, List.map_map, Option.map_map,
      Function.comp_def]
      using congrArg (Option.map Prod.snd) ht.snapshot
  unfold Spike.engine.Tx.can_apply
  by_cases hu : t.unavailable = true
  · simp [hu, canApply, ht.unavailable]
  · simp only [hu]
    have hu' : t.unavailable = false := Bool.eq_false_of_not_eq_true hu
    cases hts : t.snapshot with
    | none =>
        have htv : tx.globalViews = [] := by
          have hst := ht.stamps
          rw [ht.noSnapshot hts] at hst
          exact List.map_eq_nil_iff.mp hst
        cases hms : tx.snapshot with
        | some snap => simp [hms, hts] at hsnap
        | none =>
            simpa [hts, hu', canApply, ht.unavailable, validLineage, hms, htv] using hcheck
    | some snap =>
        cases hms : tx.snapshot with
        | none => simp [hms, hts] at hsnap
        | some msnap =>
            have hst : msnap.term = snap.term.val := by simpa [hms, hts] using hsnap
            have htermEq : store.history.term.val = snap.term.val ↔ snap.term = store.history.term :=
              ⟨fun h => UScalar.eq_of_val_eq h.symm, fun h => congrArg (fun v : U64 => v.val) h.symm⟩
            by_cases htm : snap.term = store.history.term
            · have ht' := htermEq.mpr htm
              simpa [n, hts, htm, ht', hu', canApply, ht.unavailable, validLineage, hms,
                hs.term, hst]
                using hcheck
            · have ht' : store.history.term.val ≠ snap.term.val := fun h => htm (htermEq.mp h)
              simp [htm, ht', hu', canApply, ht.unavailable, validLineage, hms, hs.term, hst]

/-- Local publication both takes the model's enabled transition and preserves the state relation.
Disabled publication leaves the store unchanged. -/
theorem apply_step_matches (encode : List U8 → String) (inj : Function.Injective encode)
    (sid : Nat) (n : Spike.engine.Store) (w : State) (id : U64)
    (h : StateMatches encode sid n w) (room : FitsApply n id)
    : WP.spec (Spike.engine.Store.execute n (.Apply id))
        (StepMatches encode sid (.apply sid id.val) n
          (execute w (.apply sid id.val))) := by
  obtain ⟨s, natArchive, archive, hs, hhist, hMeta, hattempts⟩ := h.history
  obtain ⟨prior, head, hframes, hhead⟩ := hhist.split
  have bind_some {α β : Type} (x : α) (f : α → Option β) : (some x >>= f) = f x := rfl
  cases hn : find n.txs.val id with
  | none =>
      have hr := apply_rejected_keeps_store n id (by simp [hn])
      have hl : lookupTx w sid id.val = none := by
        simp [lookupTx, hs, lookup_missing_of_attempts hattempts hn]
      simp [hr, StepMatches, execute, hl]
  | some t =>
      obtain ⟨tx, hl, ht⟩ := lookup_of_attempts hs hattempts hn
      have hempty := apply_empty ht
      have he : execute w (.apply sid id.val) =
          if tx.phase != .committing || tx.normal.writes.isEmpty then none
          else
            if canApply s tx then
              let next := advance s tx.normal.writes
              some ({ w with stores := Kv.Model.set w.stores sid next
                             txs := Kv.Model.set w.txs id.val { tx with phase := .applied next.head.version } },
                .applied next.head.version s.term tx.normal.writes)
            else none := by
        simp only [execute, hl, bind_some, tryApply]
        split
        · rfl
        · split <;> rfl
      have hp : (tx.phase != .committing) = !nativeCommitting t.phase := by
        rw [ht.phase]
        cases t.phase <;> rfl
      have hp_eq : nativeCommitting t.phase = true ↔ t.phase = .Committing := by
        cases t.phase <;> simp [nativeCommitting]
      have hp_ne (hn : t.phase ≠ .Committing) : nativeCommitting t.phase = false :=
        Bool.eq_false_of_not_eq_true (hn ∘ hp_eq.mp)
      by_cases hPhase : t.phase = .Committing
      · by_cases hWrites : t.pending.val = []
        · have hr := apply_rejected_keeps_store n id (by
            intro other ho
            have : other = t := Option.some.inj (ho.symm.trans hn)
            subst other
            simp [hWrites])
          simp [hr, he, hempty, hWrites, StepMatches]
        · have hw : t.pending.val.isEmpty = false := by simpa using hWrites
          have capacity := room t hn prior head hframes
          have hTxMem : (id, t) ∈ n.txs.val := find_in_mem hn
          have heligible := eligibility encode inj h.reachable hs hhist hMeta hTxMem ht
            prior head hframes hhead capacity
          by_cases ha : canApply s tx
          · let nativeHead := modelFrame encode n.history.index head
            let nativeFrames := natModelFrames n.history.log natArchive
            let nativeStore : Store := {
              s with
                history := nativeFrames
                head := nativeHead
            }
            let nativeWrites := encodeWrites encode (byteWrites t.pending.val)
            have hOk
                : WP.spec (Spike.engine.Tx.can_apply t n.history) (fun r => r = true) :=
              ha ▸ heligible
            change WP.spec (Spike.engine.Store.apply n id true) _
            apply WP.spec_mono
              (apply_accepted_matches_model encode inj n id true t nativeStore prior head
                natArchive hn hPhase hWrites hOk hframes rfl rfl hhist.term hhist.global
                hhist.identity capacity hhist.valid hhist.unique hhist.indexValid
                hhist.aligned h.liveness)
            rintro ⟨observed, after⟩
              ⟨version, writes, index, nextFrame, hout, hv, hterm, hreport, hnextOrder, hnextView,
                hhist', hg, hterm', hi, _, hidx, hr, hvalid, hunique, indexed, haligned',
                hlive', hpres', _, hframesApp, ⟨idNew, hidNew, hbrApp⟩, hmetaNext⟩
            let store := advance s tx.normal.writes
            let next := {tx with phase := .applied store.head.version}
            let w' : State := {w with stores := Kv.Model.set w.stores sid store
                                      txs := Kv.Model.set w.txs id.val next}
            let natArchive' := natArchive ++ [modelFrame encode after.history.index nextFrame]
            let archive' := archive ++ [store.head]
            have hstep
                : execute w (.apply sid id.val)
                  = some (w', .applied store.head.version s.term tx.normal.writes) := by
              simp [he, hp, hempty, hPhase, nativeCommitting, hw, ha, w', store, next]
            have reach := reachable_execute h.reachable hstep
            have hstore : find w'.stores sid = some store := by simp [w', find_set_key]
            have hNatHeadFirst : nativeStore.history.head? = some nativeStore.head :=
              nat_head_in_frames hhist hframes
            have hHeadMemNat : nativeHead ∈ natArchive :=
              nat_active_in_archive n.history.log natArchive (List.mem_of_head? hNatHeadFirst)
            have hHeadMemMod : s.head ∈ archive := by
              apply hhist.modelSub
              have hh := hhist.head
              cases h : s.history with
              | nil => simp [h] at hh
              | cons first rest =>
                  rw [h] at hh
                  rw [Option.some.inj hh]
                  exact List.mem_cons_self
            have hHeadOrder : FrameOrderEq (modelFrame encode after.history.index nextFrame) store.head :=
              hnextOrder.trans
                (advance_order_eq nativeStore s nativeWrites tx.normal.writes hhead rfl ht.writes
                  (hhist.nativeArchive.unique nativeHead hHeadMemNat)
                  (sorted_pending_unique encode inj t ht.sorted))
            have hFramesNext : List.Forall₂ FrameOrderEq
                (natModelFrames after.history.log natArchive') store.history := by
              rw [hhist']
              exact .cons hHeadOrder hhist.frames
            have hNextSorted : ∀ m,
                (image (modelFrame encode after.history.index nextFrame).data m).Pairwise
                  (encKeyLt encode) :=
              modelFrame_image_sorted inj after.history.index nextFrame hnextView
            have hArchCanon : ∀ f ∈ natArchive, ∀ m,
                (image (modelFrame encode after.history.index nextFrame).data m).Perm (image f.data m)
                → image (modelFrame encode after.history.index nextFrame).data m = image f.data m :=
              fun f hf m hperm =>
                encKeyLt_perm_eq inj (hNextSorted m) (hhist.natSorted f hf m) hperm
            have hNatRevNext : RevisionHistory (natModelFrames after.history.log natArchive') := by
              rw [hhist']
              exact hhist.revisions.advance_order hNatHeadFirst nativeWrites _ hnextOrder
                (fun f hf m hp => hArchCanon f (nat_active_in_archive n.history.log natArchive hf) m hp)
            have hNatArchNext : ArchiveConsistent natArchive' after.history.next_identity.val := by
              rw [hi]
              have hIdEq : nativeStore.nextIdentity = n.history.next_identity.val := hhist.identity
              exact (hIdEq.symm ▸ hhist.nativeArchive).append_order (s := nativeStore)
                hHeadMemNat nativeWrites _ hnextOrder hArchCanon
            have hNatSortedNext : ∀ f ∈ natArchive', ∀ m,
                (image f.data m).Pairwise (encKeyLt encode) := by
              intro f hf m
              rcases List.mem_append.mp hf with hold | hnew
              · exact hhist.natSorted f hold m
              · rw [List.mem_singleton.mp hnew]
                exact hNextSorted m
            have hModSubNext : ∀ f ∈ store.history, f ∈ archive' := by
              intro f hf
              rcases List.mem_cons.mp hf with rfl | old
              · exact List.mem_append_right _ List.mem_cons_self
              · exact List.mem_append_left _ (hhist.modelSub f old)
            have hModArchNext : ArchiveConsistent archive' store.nextIdentity :=
              hhist.modelArchive.append hHeadMemMod tx.normal.writes
            have hrel : HistoryMatches encode after.history store natArchive' archive' :=
              history_related reach hstore hFramesNext hg.symm hterm'.symm hi.symm
                hvalid hunique indexed haligned' hNatRevNext hNatArchNext hNatSortedNext
                hModSubNext hModArchNext
            have hv' : version.val = store.head.version := by
              exact hv.trans (advance_order_eq nativeStore s nativeWrites tx.normal.writes hhead rfl ht.writes
                (hhist.nativeArchive.unique nativeHead hHeadMemNat)
                (sorted_pending_unique encode inj t ht.sorted)).version
            have htxMemAfter : (id, {t with phase := .Applied version}) ∈ after.txs.val := by
              rw [hr]
              have hidxLt : index < n.txs.val.length := (List.getElem?_eq_some_iff.mp hidx).1
              have hget : (n.txs.val.set index (id, {t with phase := .Applied version}))[index]? =
                  some (id, {t with phase := .Applied version}) := by
                rw [List.getElem?_set_self hidxLt]
              exact List.mem_of_getElem? hget
            have htxSub : ∀ row ∈ t.views.val, ∀ r ∈ viewPins row.2, r ∈ storePins after :=
              fun row hrow r hrPin =>
                List.mem_append_right _ (List.mem_flatMap.mpr
                  ⟨(id, {t with phase := .Applied version}), htxMemAfter,
                    List.mem_flatMap.mpr ⟨row, hrow, hrPin⟩⟩)
            have htx
                : AttemptMatches encode sid after.history.index natArchive' archive'
                    {t with phase := .Applied version} next := by
              simpa only [next, modelPhase, hv']
                using (ht.withPhase (.Applied version)).withPreservedPins hpres' htxSub
                  (fun _ hm => List.mem_append_left _ hm)
                  (fun _ hm => List.mem_append_left _ hm)
            have hmetaAfter : StoreMetaLive encode after natArchive' := by
              refine ⟨?_, ?_⟩
              · intro id' t' snap' fid' nf' hmem hsnap' hfid' hnf'
                rw [hbrApp] at hfid'
                by_cases hlt : snap'.version.val < n.history.log.branch.val.length
                · rw [List.getElem?_append_left hlt] at hfid'
                  have hfidLt : fid'.val < n.history.log.frames.val.length :=
                    hhist.valid.2 fid' (List.mem_of_getElem? hfid')
                  rw [hframesApp, List.getElem?_append_left hfidLt] at hnf'
                  rw [hr] at hmem
                  rcases List.mem_or_eq_of_mem_set hmem with hold | heq
                  · exact hMeta.snapLive id' t' snap' fid' nf' hold hsnap' hfid' hnf'
                  · obtain ⟨rfl, rfl⟩ := Prod.mk.inj heq
                    exact hMeta.snapLive id' t snap' fid' nf' (List.mem_of_getElem? hidx)
                      hsnap' hfid' hnf'
                · rw [List.getElem?_append_right (Nat.le_of_not_gt hlt)] at hfid'
                  have hsub : snap'.version.val - n.history.log.branch.val.length = 0 := by
                    have := (List.getElem?_eq_some_iff.mp hfid').1
                    simp at this; omega
                  rw [hsub] at hfid'
                  have hfidEq : fid' = idNew := Option.some.inj (by simpa using hfid'.symm)
                  subst hfidEq
                  rw [hframesApp, hidNew, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self] at hnf'
                  have hnfEq : nf' = nextFrame := Option.some.inj (by simpa using hnf'.symm)
                  subst hnfEq
                  exact hmetaNext
              · intro id' t' bm bv off fid' gf hmem hvm hfid' hgf hb hr'
                rw [hbrApp] at hfid'
                by_cases hoff : off < n.history.log.branch.val.length
                · rw [List.getElem?_append_left hoff] at hfid'
                  have hfidLt : fid'.val < n.history.log.frames.val.length :=
                    hhist.valid.2 fid' (List.mem_of_getElem? hfid')
                  rw [List.getElem?_append_left (hhist.aligned.len.symm ▸ hfidLt)] at hgf
                  have hmemBefore : (id', t') ∈ n.txs.val ∨ (id' = id ∧ t'.views = t.views) := by
                    rw [hr] at hmem
                    rcases List.mem_or_eq_of_mem_set hmem with hold | heq
                    · exact Or.inl hold
                    · obtain ⟨hidEq, htEq⟩ := Prod.mk.inj heq
                      exact Or.inr ⟨hidEq, by rw [htEq]⟩
                  obtain ⟨off', fid'', nf'', hbr'', hnf'', hfm''⟩ :
                      ∃ (off' : Nat) (fid'' : Usize) (nf'' : Spike.engine.Frame),
                        n.history.log.branch.val[off']? = some fid''
                        ∧ n.history.log.frames.val[fid''.val]? = some nf''
                        ∧ frameMatches (encode ∘ alloc.vec.Vec.val) nf'' bm bv.birth bv.revision = true := by
                    rcases hmemBefore with hold | ⟨hidEq, hviewsEq⟩
                    · exact hMeta.viewLive id' t' bm bv off fid' gf hold hvm hfid' hgf hb hr'
                    · exact hMeta.viewLive id t bm bv off fid' gf (List.mem_of_getElem? hidx)
                        (hviewsEq ▸ hvm) hfid' hgf hb hr'
                  have hoff'Lt : off' < n.history.log.branch.val.length :=
                    (List.getElem?_eq_some_iff.mp hbr'').1
                  have hfid''Lt : fid''.val < n.history.log.frames.val.length :=
                    hhist.valid.2 fid'' (List.mem_of_getElem? hbr'')
                  exact ⟨off', fid'', nf'',
                    by rw [hbrApp, List.getElem?_append_left hoff'Lt]; exact hbr'',
                    by rw [hframesApp, List.getElem?_append_left hfid''Lt]; exact hnf'',
                    hfm''⟩
                · rw [List.getElem?_append_right (Nat.le_of_not_gt hoff)] at hfid'
                  have hsub : off - n.history.log.branch.val.length = 0 := by
                    have := (List.getElem?_eq_some_iff.mp hfid').1
                    simp at this; omega
                  rw [hsub] at hfid'
                  have hfidEq : fid' = idNew := Option.some.inj (by simpa using hfid'.symm)
                  rw [hfidEq, hidNew, ← hhist.aligned.len, List.getElem?_append_right (Nat.le_refl _),
                    Nat.sub_self] at hgf
                  have hgfEq : gf = modelFrame encode after.history.index nextFrame :=
                    Option.some.inj (by simpa using hgf.symm)
                  subst hgfEq
                  refine ⟨n.history.log.branch.val.length, idNew, nextFrame, ?_, ?_, ?_⟩
                  · rw [hbrApp, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]; rfl
                  · rw [hframesApp, hidNew, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]; rfl
                  · unfold frameMatches
                    simp only [hmetaNext, Bool.true_and, Bool.and_eq_true]
                    exact ⟨hb, hr'⟩
            have rel :=
              replace_attempt h.unique hattempts id index t
                {t with phase := .Applied version} next hidx hr rfl hstore hrel hlive'
                hmetaAfter htx reach hpres' (fun _ hm => List.mem_append_left _ hm)
                (fun _ hm => List.mem_append_left _ hm)
            rw [hstep]
            refine ⟨.Applied version n.history.term writes, hout, ?_, rel⟩
            simp only [modelOutput, OutputMatches, hv', hhist.term, hreport, ite_true]
            exact ⟨trivial, trivial, ht.writes⟩
          · have haf : canApply s tx = false := Bool.eq_false_of_not_eq_true ha
            have hr := apply_rejected_keeps_store n id (by
              intro other ho
              have : other = t := Option.some.inj (ho.symm.trans hn)
              subst other
              intro _ _
              exact haf ▸ heligible)
            simp [hr, he, hp, hempty, hPhase, nativeCommitting, hw, ha, StepMatches]
      · have hr := apply_rejected_keeps_store n id (by
          intro other ho
          have : other = t := Option.some.inj (ho.symm.trans hn)
          subst other
          intro contradiction
          exact (hPhase contradiction).elim)
        simp [hr, he, hp, hp_ne hPhase, StepMatches]

end KvRust
