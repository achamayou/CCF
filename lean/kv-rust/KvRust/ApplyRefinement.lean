-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Relation

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Capacity required for a live attempt to publish a new frame. -/
def FitsApply (n : CcfKv.engine.Store) (id : U64) : Prop :=
  ∀ t,
    find n.txs.val id = some t
    → ∀ prior head,
        n.history.activeFrames = prior ++ [head]
        → ApplyCapacity n.history head t (storePins n).length

private def nativeCommitting : CcfKv.engine.Phase → Bool
  | .Committing => true
  | _ => false

private theorem apply_empty {encode : List U8 → String} {sid : Nat} {t : CcfKv.engine.Tx}
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

private theorem nat_head_in_frames {encode : List U8 → String}
    {n : CcfKv.engine.History} {s : Store} {natHistory natArchive archive : List Frame}
    (hs : HistoryMatches encode n s natHistory natArchive archive)
    {prior : List CcfKv.engine.Frame} {head : CcfKv.engine.Frame}
    (hf : n.activeFrames = prior ++ [head])
    : natHistory.head? = some (modelFrame encode n.index head) := by
  obtain ⟨bf, hbf, _, _, hsum⟩ := hs.aligned.base
  have hlen : n.activeFrames.length = prior.length + 1 := by simp [hf]
  have hheadLt : prior.length < n.activeFrames.length := by omega
  have hheadEq : n.activeFrames[prior.length]'hheadLt = head := by simp [hf]
  have hactEq := hs.aligned.activeEq bf hbf prior.length hheadLt
  rw [hheadEq] at hactEq
  have hidxRev : bf.version.val + prior.length = natHistory.length - 1 := by omega
  rw [hidxRev] at hactEq
  have hpos := hs.aligned.nonempty
  cases hnh : natHistory with
  | nil => simp [hnh] at hpos
  | cons nh0 nhRest =>
      rw [hnh] at hactEq
      simp only [List.reverse_cons, List.length_cons, Nat.add_sub_cancel] at hactEq
      rw [List.getElem?_append_right (by rw [List.length_reverse]), List.length_reverse,
        Nat.sub_self, List.getElem?_cons_zero] at hactEq
      exact hactEq

private theorem eligibility (encode : List U8 → String) (inj : Function.Injective encode)
    {sid : Nat} {s : Store} {store : CcfKv.engine.Store}
    {natHistory natArchive archive : List Frame} {tx : Tx} {t : CcfKv.engine.Tx}
    {id : U64} {pinsCount : Nat}
    (hs : HistoryMatches encode store.history s natHistory natArchive archive)
    (hMeta : StoreMetaLive encode store natHistory) (hTxMem : (id, t) ∈ store.txs.val)
    (ht : AttemptMatches encode sid store.history.index natArchive archive t tx)
    (prior : List CcfKv.engine.Frame) (head : CcfKv.engine.Frame)
    (hf : store.history.activeFrames = prior ++ [head])
    (hhead : FrameOrderEq (modelFrame encode store.history.index head) s.head)
    (space : ApplyCapacity store.history head t pinsCount)
    : WP.spec (CcfKv.engine.Tx.can_apply t store.history)
        (fun r => r = canApply s tx) := by
  let n := store.history
  let nativeHead := modelFrame encode n.index head
  let nativeStore : Store := {
    s with
      history := natHistory
      head := nativeHead
  }
  have hinj : Function.Injective (encode ∘ alloc.vec.Vec.val (α := U8)) :=
    inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  have hViewLive : ∀ row ∈ t.views.val,
      (n.activeFrames ++ n.retained.val).any
          (fun f => frameMatches (encode ∘ alloc.vec.Vec.val) f row.1 row.2.birth row.2.revision)
      = stampsOnBranch nativeStore (viewStamps (encode ∘ alloc.vec.Vec.val) row) := by
    rintro ⟨bm, bv⟩ hvm
    apply Bool.eq_iff_iff.mpr
    simp only [stampsOnBranch, viewStamps, nativeStore, List.any_eq_true, Bool.and_eq_true]
    constructor
    · rintro ⟨nf, hnfMem, hfm⟩
      unfold frameMatches at hfm
      simp only [Bool.and_eq_true] at hfm
      rcases List.mem_append.mp hnfMem with hact | hret
      · obtain ⟨bf, hbf, _, _, _⟩ := hs.aligned.base
        obtain ⟨j, hjLt, rfl⟩ := List.getElem_of_mem hact
        have hactEq := hs.aligned.activeEq bf hbf j hjLt
        let gf := modelFrame encode n.index (n.activeFrames[j]'hjLt)
        have hgfMem : gf ∈ natHistory :=
          List.mem_reverse.mp (List.mem_of_getElem? hactEq)
        exact ⟨gf, hgfMem, hfm.1, hfm.2⟩
      · obtain ⟨_, _, gf, hgfAt, hmeta⟩ := hs.aligned.retainedEq nf hret
        have hgfMem : gf ∈ natHistory :=
          List.mem_reverse.mp (List.mem_of_getElem? hgfAt)
        refine ⟨gf, hgfMem, ?_, ?_⟩
        · simpa only [modelMetadata, hmeta.2.2] using hfm.1
        · simpa only [modelMetadata, revision, hmeta.2.1] using hfm.2
    · rintro ⟨gf, hgfMem, hb, hr⟩
      exact hMeta.viewLive id t bm bv gf hTxMem hvm hgfMem hb hr
  have hl := acquired_lineage_matches_model (encode ∘ alloc.vec.Vec.val) hinj
    n t nativeStore tx hViewLive ht.stamps hs.valid
  have hLineageEq : tx.globalViews.all (fun (m, view) => mapLineage nativeStore view.current m) =
      tx.globalViews.all (fun (m, view) => mapLineage s view.current m) := by
    apply List.all_congr rfl
    rintro ⟨m, view⟩
    exact history_order_eq_mapLineage (s := nativeStore) (t := s) hs.frames (.refl _) m
  have hHeadFirstNative : natHistory.head? = some nativeHead :=
    nat_head_in_frames hs hf
  have hHeadMemNative : nativeHead ∈ natHistory :=
    List.mem_of_head? hHeadFirstNative
  have hHeadMemNatArch : nativeHead ∈ natArchive :=
    hs.natSub nativeHead hHeadMemNative
  have hNatUnique : Kv.Properties.Unique nativeHead.data :=
    hs.nativeArchive.unique nativeHead hHeadMemNatArch
  have hCheckDeps (hLin : tx.globalViews.all (fun (m, view) => mapLineage s view.current m) = true) :
      WP.spec (CcfKv.engine.Tx.valid_dependencies t n) (fun r => r = validates s.head.data tx.normal.deps) := by
    have hNatCanon : ∀ d ∈ pointDeps encode n.index t,
        holdsExact nativeHead.data d = holdsByContents nativeHead.data d := by
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
          have holdArch : old ∈ natArchive := hs.natSub old holdMem
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
          simp only [holdsExact, holdsByContents]
          apply decide_eq_decide.mpr
          constructor
          · intro h; rw [h]
          · intro hperm
            exact encKeyLt_perm_eq inj
              (hs.natSorted nativeHead hHeadMemNatArch m')
              (hs.natSorted old holdArch m') hperm
    have hModelEq : validates s.head.data tx.normal.deps =
        tx.normal.deps.all (holdsByContents s.head.data) := by
      unfold validates
      apply List.all_congr rfl
      intro d
      cases d <;> rfl
    have hNatEq : validatesExact nativeHead.data (pointDeps encode n.index t) =
        tx.normal.deps.all (holdsByContents s.head.data) := by
      have hRel := ht.deps
      clear hModelEq
      generalize pointDeps encode n.index t = nds at hRel hNatCanon
      generalize tx.normal.deps = mds at hRel
      induction hRel with
      | nil => rfl
      | @cons x y xs ys hxy hrest ih =>
          simp only [validatesExact, List.all_cons] at ih ⊢
          rw [hNatCanon x List.mem_cons_self, dependency_order_eq hhead.data hNatUnique hxy,
            ih (fun d hd => hNatCanon d (List.mem_cons_of_mem _ hd))]
    apply WP.spec_mono
      (validate_dependencies_matches_model t n head (indexRows n.index head.data)
        (hs.indexValid.head prior head hf) hs.indexValid.index
        (by simp [history_head n prior head hf hs.valid]) space.dependencies)
    intro r hr
    rw [hr, ← validates_exact_encoding encode inj]
    have hRev : validatesExact (encodeData encode (indexedCellData (indexRows n.index head.data)))
        ((t.deps.val.map (byteDependency n.index)).map (encodeDependency encode)) =
        validatesExact nativeHead.data (pointDeps encode n.index t) := by
      simp [validatesExact, pointDeps, nativeHead, modelFrame, List.all_reverse,
        List.map_map, Function.comp_def]
    rw [hRev, hNatEq, ← hModelEq]
  have hcheck : WP.spec (do
      let b ← CcfKv.engine.Tx.valid_lineage t n
      if b then CcfKv.engine.Tx.valid_dependencies t n else Result.ok false)
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
  unfold CcfKv.engine.Tx.can_apply
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
    (sid : Nat) (n : CcfKv.engine.Store) (w : State) (id : U64)
    (h : StateMatches encode sid n w) (room : FitsApply n id)
    : WP.spec (CcfKv.engine.Store.execute n (.Apply id))
        (StepMatches encode sid (.apply sid id.val) n
          (execute w (.apply sid id.val))) := by
  obtain ⟨s, natHistory, natArchive, archive, hs, hhist, hMeta, hattempts⟩ := h.history
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
          have heligible := eligibility encode inj hhist hMeta hTxMem ht
            prior head hframes hhead capacity
          by_cases ha : canApply s tx
          · let nativeHead := modelFrame encode n.history.index head
            let nativeStore : Store := {
              s with
                history := natHistory
                head := nativeHead
            }
            let nativeWrites := encodeWrites encode (byteWrites t.pending.val)
            have hOk
                : WP.spec (CcfKv.engine.Tx.can_apply t n.history) (fun r => r = true) :=
              ha ▸ heligible
            change WP.spec (CcfKv.engine.Store.apply n id true) _
            apply WP.spec_mono
              (apply_accepted_matches_model encode inj n id true t nativeStore prior head
                natHistory hn hPhase hWrites hOk hframes rfl hhist.term hhist.global
                hhist.identity capacity hhist.valid hhist.indexValid
                hhist.aligned h.liveness)
            rintro ⟨observed, after⟩
              ⟨version, writes, index, nextFrame, hout, hv, hterm, hreport, hnextOrder, hnextView,
                hg, hterm', hi, _, hretEq, hidx, hr, hvalid, indexed, haligned',
                hlive', hpres', hactApp⟩
            let store := advance s tx.normal.writes
            let next := {tx with phase := .applied store.head.version}
            let w' : State := {w with stores := Kv.Model.set w.stores sid store
                                      txs := Kv.Model.set w.txs id.val next}
            let natHistory' := modelFrame encode after.history.index nextFrame :: natHistory
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
              hhist.natSub nativeHead (List.mem_of_head? hNatHeadFirst)
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
            have hFramesNext : List.Forall₂ FrameOrderEq natHistory' store.history :=
              .cons hHeadOrder hhist.frames
            have hNextSorted : ∀ m,
                (image (modelFrame encode after.history.index nextFrame).data m).Pairwise
                  (encKeyLt encode) :=
              modelFrame_image_sorted inj after.history.index nextFrame hnextView
            have hArchCanon : ∀ f ∈ natArchive, ∀ m,
                (image (modelFrame encode after.history.index nextFrame).data m).Perm (image f.data m)
                → image (modelFrame encode after.history.index nextFrame).data m = image f.data m :=
              fun f hf m hperm =>
                encKeyLt_perm_eq inj (hNextSorted m) (hhist.natSorted f hf m) hperm
            have hNatRevNext : RevisionHistory natHistory' :=
              hhist.revisions.advance_order hNatHeadFirst nativeWrites _ hnextOrder
                (fun f hf m hp => hArchCanon f (hhist.natSub f hf) m hp)
            have hNatSubNext : ∀ f ∈ natHistory', f ∈ natArchive' := by
              intro f hf
              rcases List.mem_cons.mp hf with rfl | hold
              · exact List.mem_append_right _ List.mem_cons_self
              · exact List.mem_append_left _ (hhist.natSub f hold)
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
            have hrel : HistoryMatches encode after.history store natHistory' natArchive' archive' :=
              history_related reach hstore hFramesNext hg.symm hterm'.symm hi.symm
                hvalid indexed haligned' hNatRevNext hNatSubNext hNatArchNext hNatSortedNext
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
            have hmetaAfter : StoreMetaLive encode after natHistory' := by
              refine ⟨?_, ?_⟩
              · intro id' t' snap' bf hmem hsnap' hbf hlt
                have hbf0 : n.history.activeFrames[0]? = some bf := by
                  have hpos : 0 < n.history.activeFrames.length := List.length_pos_iff.mpr hhist.nonempty
                  rwa [hactApp, List.getElem?_append_left hpos] at hbf
                rw [hretEq]
                rw [hr] at hmem
                rcases List.mem_or_eq_of_mem_set hmem with hold | heq
                · exact hMeta.snapLive id' t' snap' bf hold hsnap' hbf0 hlt
                · obtain ⟨rfl, rfl⟩ := Prod.mk.inj heq
                  exact hMeta.snapLive id' t snap' bf (List.mem_of_getElem? hidx) hsnap' hbf0 hlt
              · intro id' t' bm bv gf hmem hvm hgf hb hr'
                rcases List.mem_cons.mp hgf with rfl | hgfOld
                · refine ⟨nextFrame, List.mem_append_left _ (by rw [hactApp]; exact List.mem_append_right _ List.mem_cons_self), ?_⟩
                  unfold frameMatches
                  simp only [Bool.and_eq_true]
                  exact ⟨hb, hr'⟩
                · have hmemBefore : (id', t') ∈ n.txs.val ∨ (id' = id ∧ t'.views = t.views) := by
                    rw [hr] at hmem
                    rcases List.mem_or_eq_of_mem_set hmem with hold | heq
                    · exact Or.inl hold
                    · obtain ⟨hidEq, htEq⟩ := Prod.mk.inj heq
                      exact Or.inr ⟨hidEq, by rw [htEq]⟩
                  obtain ⟨nf', hnf'Mem, hfm'⟩ :
                      ∃ nf' ∈ n.history.activeFrames ++ n.history.retained.val,
                        frameMatches (encode ∘ alloc.vec.Vec.val) nf' bm bv.birth bv.revision = true := by
                    rcases hmemBefore with hold | ⟨_, hviewsEq⟩
                    · exact hMeta.viewLive id' t' bm bv gf hold hvm hgfOld hb hr'
                    · exact hMeta.viewLive id t bm bv gf (List.mem_of_getElem? hidx)
                        (hviewsEq ▸ hvm) hgfOld hb hr'
                  refine ⟨nf', ?_, hfm'⟩
                  rcases List.mem_append.mp hnf'Mem with hact | hret
                  · exact List.mem_append_left _ (by rw [hactApp]; exact List.mem_append_left _ hact)
                  · exact List.mem_append_right _ (hretEq.symm ▸ hret)
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
