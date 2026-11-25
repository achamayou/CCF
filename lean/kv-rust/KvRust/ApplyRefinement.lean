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
        n.history.activeFrames = prior ++ [head] → ApplyCapacity n.history head t

private def nativeCommitting : Spike.engine.Phase → Bool
  | .Committing => true
  | _ => false

private theorem apply_empty {encode : List U8 → String} {sid : Nat} {t : Spike.engine.Tx}
    {history : Spike.engine.History} {archive : List Frame} {tx : Tx}
    (h : AttemptMatches encode sid history archive t tx)
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

private theorem native_active_in_archive (encode : List U8 → String)
    (n : Spike.engine.History) {f : Frame}
    (hf : f ∈ modelFrames n (modelFrame encode n.index))
    : f ∈ n.log.frames.val.map (modelFrame encode n.index) := by
  unfold modelFrames at hf
  obtain ⟨nf, hmem, rfl⟩ := List.mem_map.mp hf
  have hact : nf ∈ n.activeFrames := List.mem_reverse.mp hmem
  obtain ⟨id, _, hsaved⟩ := List.mem_filterMap.mp hact
  exact List.mem_map_of_mem (List.mem_iff_getElem?.mpr ⟨id.val, hsaved⟩)

private theorem eligibility (encode : List U8 → String) (inj : Function.Injective encode)
    {sid : Nat} {w : State} {s : Store} {n : Spike.engine.History} {archive : List Frame}
    {tx : Tx} {t : Spike.engine.Tx}
    (reach : transitionSystem.Reachable w) (hsFound : find w.stores sid = some s)
    (hs : HistoryMatches encode n s archive)
    (ht : AttemptMatches encode sid n archive t tx) (prior : List Spike.engine.Frame)
    (head : Spike.engine.Frame) (hf : n.activeFrames = prior ++ [head])
    (hhead : FrameOrderEq (modelFrame encode n.index head) s.head)
    (space : ApplyCapacity n head t)
    : WP.spec (Spike.engine.Tx.can_apply t n) (fun r => r = canApply s tx) := by
  let nativeHead := modelFrame encode n.index head
  let nativeFrames := modelFrames n (modelFrame encode n.index)
  let nativeStore : Store := {
    s with
      history := nativeFrames
      head := nativeHead
  }
  have hinj : Function.Injective (encode ∘ alloc.vec.Vec.val (α := U8)) :=
    inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  have hmeta : nativeStore.history.map onlyMetadata =
      modelFrames n (modelMetadata (encode ∘ alloc.vec.Vec.val)) := by
    simp only [nativeStore, nativeFrames, modelFrames, List.map_map]
    apply List.map_congr_left
    intro f _
    rfl
  have hl := acquired_lineage_matches_model (encode ∘ alloc.vec.Vec.val) hinj
    n t nativeStore tx hmeta ht.stamps hs.valid
  have hLineageEq : tx.globalViews.all (fun (m, view) => mapLineage nativeStore view.current m) =
      tx.globalViews.all (fun (m, view) => mapLineage s view.current m) := by
    apply List.all_congr rfl
    rintro ⟨m, view⟩
    exact history_order_eq_mapLineage (s := nativeStore) (t := s) hs.frames (.refl _) m
  have hHeadMemNative : nativeHead ∈ nativeFrames := by
    unfold nativeFrames modelFrames
    rw [hf, List.reverse_append, List.reverse_singleton, List.singleton_append, List.map_cons]
    exact List.mem_cons_self
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
    hs.nativeArchive.unique nativeHead (native_active_in_archive encode n hHeadMemNative)
  have hModUnique : Kv.Properties.Unique s.head.data :=
    hs.modelArchive.unique s.head (hs.modelSub s.head hHeadMemModel)
  have hCheckDeps (hLin : tx.globalViews.all (fun (m, view) => mapLineage s view.current m) = true) :
      WP.spec (Spike.engine.Tx.valid_dependencies t n) (fun r => r = validates s.head.data tx.normal.deps) := by
    have hNatCanon : ∀ d ∈ pointDeps encode t,
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
          have hpvEq : rustPinnedView encode n bm bv = pv := congrArg Prod.snd hpair
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
          have holdArch := native_active_in_archive encode n holdMem
          obtain ⟨oldNative, holdNativeMem, holdEq⟩ := List.mem_map.mp holdArch
          obtain ⟨oldIdx, holdIdx⟩ := List.mem_iff_getElem?.mp holdNativeMem
          have hOrig := ht.nativeOrig (bm, bv) hbvMem
          unfold ViewOrigin at hOrig
          dsimp only at hOrig
          rw [hmEq] at hOrig
          have hImgEq : expected = image old.data m' := by
            rw [hexp, ← hpvEq]
            change encodeImage encode (pinImage n bm bv.local) = image old.data m'
            cases hb : bv.birth with
            | none =>
                rw [hb] at hOrig hbEq
                exact hOrig.1.trans (hs.nativeArchive.unborn old holdArch m' hbEq).1.symm
            | some stamp =>
                rw [hb] at hOrig
                obtain ⟨f, hfMem, hfRev, hfImg⟩ := hOrig
                have hfArch : modelFrame encode n.index f ∈
                    n.log.frames.val.map (modelFrame encode n.index) :=
                  List.mem_map_of_mem hfMem
                exact hfImg.trans (hs.nativeArchive.sameRevision _ hfArch old holdArch m'
                  (hfRev.trans hrEq.symm))
          rw [hImgEq, ← holdEq]
          simp only [Dependency.holds, holdsByContents]
          apply decide_eq_decide.mpr
          constructor
          · intro h; rw [h]
          · intro hperm
            exact modelFrame_image_eq_of_perm inj n.index head oldNative
              (hs.indexValid.head prior head hf) (hs.indexValid.archived oldIdx oldNative holdIdx)
              m' hperm
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
    have hNatEq : validates nativeHead.data (pointDeps encode t) =
        tx.normal.deps.all (holdsByContents s.head.data) := by
      have hRel := ht.deps
      clear hModOrigins hDepsRefl hModelEq
      generalize pointDeps encode t = nds at hRel hNatCanon
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
        ((t.deps.val.map byteDependency).map (encodeDependency encode)) =
        validates nativeHead.data (pointDeps encode t) := by
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
            have htermEq : n.term.val = snap.term.val ↔ snap.term = n.term :=
              ⟨fun h => UScalar.eq_of_val_eq h.symm, fun h => congrArg (fun v : U64 => v.val) h.symm⟩
            by_cases htm : snap.term = n.term
            · have ht' := htermEq.mpr htm
              simpa [hts, htm, ht', hu', canApply, ht.unavailable, validLineage, hms,
                hs.term, hst]
                using hcheck
            · have ht' : n.term.val ≠ snap.term.val := fun h => htm (htermEq.mp h)
              simp [htm, ht', hu', canApply, ht.unavailable, validLineage, hms, hs.term, hst]

/-- Local publication both takes the model's enabled transition and preserves the state relation.
Disabled publication leaves the store unchanged. -/
theorem apply_step_matches (encode : List U8 → String) (inj : Function.Injective encode)
    (sid : Nat) (n : Spike.engine.Store) (w : State) (id : U64)
    (h : StateMatches encode sid n w) (room : FitsApply n id)
    : WP.spec (Spike.engine.Store.execute n (.Apply id))
        (StepMatches encode sid (.apply sid id.val) n
          (execute w (.apply sid id.val))) := by
  obtain ⟨s, archive, hs, hhist, hattempts⟩ := h.history
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
          have heligible := eligibility encode inj h.reachable hs hhist ht prior head hframes
            hhead capacity
          by_cases ha : canApply s tx
          · let nativeHead := modelFrame encode n.history.index head
            let nativeFrames := modelFrames n.history (modelFrame encode n.history.index)
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
                hn hPhase hWrites hOk hframes rfl rfl hhist.term hhist.global
                hhist.identity capacity hhist.valid hhist.indexValid)
            rintro ⟨observed, after⟩
              ⟨version, writes, index, nextFrame, hout, hv, hterm, hreport, hnextOrder, hnextView,
                hhist', hg, hterm', hi, hidx, hr, hvalid, indexed, kept, hArchRaw, hNatArchEq⟩
            let store := advance s tx.normal.writes
            let next := {tx with phase := .applied store.head.version}
            let w' : State := {w with stores := Kv.Model.set w.stores sid store
                                      txs := Kv.Model.set w.txs id.val next}
            let archive' := archive ++ [store.head]
            have hstep
                : execute w (.apply sid id.val)
                  = some (w', .applied store.head.version s.term tx.normal.writes) := by
              simp [he, hp, hempty, hPhase, nativeCommitting, hw, ha, w', store, next]
            have reach := reachable_execute h.reachable hstep
            have hstore : find w'.stores sid = some store := by simp [w', find_set_key]
            have hHeadMemNat : nativeHead ∈ n.history.log.frames.val.map (modelFrame encode n.history.index) := by
              apply native_active_in_archive encode n.history
              unfold modelFrames
              rw [hframes, List.reverse_append, List.reverse_singleton, List.singleton_append, List.map_cons]
              exact List.mem_cons_self
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
                (modelFrames after.history (modelFrame encode after.history.index)) store.history := by
              rw [hhist']
              exact .cons hHeadOrder hhist.frames
            have hNatHeadFirst : nativeStore.history.head? = some nativeStore.head := by
              change nativeFrames.head? = some nativeHead
              unfold nativeFrames modelFrames
              rw [hframes, List.reverse_append, List.reverse_singleton, List.singleton_append, List.map_cons]
              rfl
            have hArchCanon : ∀ f ∈ n.history.log.frames.val.map (modelFrame encode n.history.index),
                ∀ m,
                  (image (modelFrame encode after.history.index nextFrame).data m).Perm (image f.data m)
                  → image (modelFrame encode after.history.index nextFrame).data m = image f.data m := by
              intro f hf m hperm
              obtain ⟨fnat, hfnatMem, rfl⟩ := List.mem_map.mp hf
              obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hfnatMem
              have hret := model_frame_retained encode kept.index fnat (hhist.indexValid.archived j fnat hj)
              have hjAfter : after.history.log.frames.val[j]? = some fnat := kept.slots j fnat hj
              rw [← hret] at hperm ⊢
              exact modelFrame_image_eq_of_perm inj after.history.index nextFrame fnat
                hnextView (indexed.archived j fnat hjAfter) m hperm
            have hNatRevNext : RevisionHistory
                (modelFrames after.history (modelFrame encode after.history.index)) := by
              rw [hhist']
              exact hhist.revisions.advance_order hNatHeadFirst nativeWrites _ hnextOrder
                (fun f hf m hp => hArchCanon f (native_active_in_archive encode n.history hf) m hp)
            have hNatArchNext : ArchiveConsistent
                (after.history.log.frames.val.map (modelFrame encode after.history.index))
                after.history.next_identity.val := by
              rw [hNatArchEq, hi]
              have hIdEq : nativeStore.nextIdentity = n.history.next_identity.val := hhist.identity
              exact (hIdEq.symm ▸ hhist.nativeArchive).append_order (s := nativeStore)
                hHeadMemNat nativeWrites _ hnextOrder hArchCanon
            have hModSubNext : ∀ f ∈ store.history, f ∈ archive' := by
              intro f hf
              rcases List.mem_cons.mp hf with rfl | old
              · exact List.mem_append_right _ List.mem_cons_self
              · exact List.mem_append_left _ (hhist.modelSub f old)
            have hModArchNext : ArchiveConsistent archive' store.nextIdentity :=
              hhist.modelArchive.append hHeadMemMod tx.normal.writes
            have hrel : HistoryMatches encode after.history store archive' :=
              history_related reach hstore hFramesNext hg.symm hterm'.symm hi.symm
                hvalid indexed hNatRevNext hNatArchNext hModSubNext hModArchNext
            have hv' : version.val = store.head.version := by
              exact hv.trans (advance_order_eq nativeStore s nativeWrites tx.normal.writes hhead rfl ht.writes
                (hhist.nativeArchive.unique nativeHead hHeadMemNat)
                (sorted_pending_unique encode inj t ht.sorted)).version
            have htx
                : AttemptMatches encode sid after.history archive'
                    {t with phase := .Applied version} next := by
              simpa only [next, modelPhase, hv']
                using (ht.withPhase (.Applied version)).withHistory kept hhist.indexValid
                  (fun _ hm => List.mem_append_left _ hm)
            have rel :=
              replace_attempt h.unique hattempts hhist id index t
                {t with phase := .Applied version} next hidx hr rfl hstore hrel htx reach kept
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
