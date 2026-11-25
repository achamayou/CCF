-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Lifecycle

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- The two constructors establish the relation from empty state. -/
theorem new_matches (encode : List U8 → String) (sid : Nat) (term : U64)
    : WP.spec (CcfKv.engine.Store.new term)
        (fun n =>
          ∃ w,
            execute {} (.storeCreate sid term.val) = some (w, .unit)
            ∧ StateMatches encode sid n w) := by
  apply WP.spec_mono (store_new_lifecycle encode term)
  intro n ⟨head, _, _, _, _, hnat, hg, ht, hi, htx, valid, unique, indexed, aligned, hlive⟩
  let s : Store := {term := term.val}
  let w : State := {stores := [(sid, s)]}
  have hs : find w.stores sid = some s := by simp [w, find]
  have he : execute {} (.storeCreate sid term.val) = some (w, .unit) := by
    simp [execute, find, Kv.Model.set, erase, s, w]
  have hReach := reachable_execute (CCF.TransitionSystem.Reachable.initial rfl) he
  have hFrames : List.Forall₂ FrameOrderEq
      (natModelFrames n.history.log [s.head]) s.history := by
    rw [hnat]
    exact .cons (.refl _) .nil
  have hRev : RevisionHistory (natModelFrames n.history.log [s.head]) := by
    rw [hnat]
    exact revision_history_new
  have hNatArch : ArchiveConsistent [s.head] n.history.next_identity.val := by
    rw [hi]
    simpa [s] using archive_consistent_new
  have hNatSorted : ∀ f ∈ [s.head], ∀ m, (image f.data m).Pairwise (encKeyLt encode) := by
    intro f hf m
    rw [List.mem_singleton.mp hf]
    exact List.Pairwise.nil
  have hr := history_related (encode := encode) (n := n.history) (natArchive := [s.head])
    (archive := [{}]) hReach hs hFrames hg.symm (by change term.val = n.history.term.val; rw [ht])
    hi.symm valid unique indexed aligned hRev hNatArch hNatSorted (fun f hm => hm)
    archive_consistent_new
  have hMetaInit : StoreMetaLive encode n [s.head] :=
    ⟨fun _ _ _ _ _ hmem => by simp [htx] at hmem,
      fun _ _ _ _ _ _ _ hmem => by simp [htx] at hmem⟩
  refine ⟨w, he, ⟨⟨s, [s.head], [{}], hs, hr, hMetaInit, ?_⟩, hlive, ?_, hReach⟩⟩
  · intro id
    simp [htx, find, w]
  · simp [htx]

private theorem lifecycle_observation (encode : List U8 → String)
    (r : core.result.Result CcfKv.engine.Output CcfKv.engine.Error) (out : Output)
    (h : lifecycleOutput r = some out)
    : ∃ v, r = .Ok v ∧ modelOutput encode v = out := by
  cases r with
  | Err e => cases h
  | Ok v =>
      refine ⟨v, rfl, ?_⟩
      cases v <;> cases h <;> rfl

private theorem refinement_of_lifecycle_post (encode : List U8 → String) (sid : Nat)
    (n : CcfKv.engine.Store) (w : State) (action : Action)
    (r : core.result.Result CcfKv.engine.Output CcfKv.engine.Error × CcfKv.engine.Store)
    (rel : StateMatches encode sid n w) (post : State → CcfKv.engine.Store → Prop)
    (hp : LifecycleModelPost n (execute w action) post r)
    (success
      : ∀ w' out,
          execute w action = some (w', out)
          → post w' r.2
          → transitionSystem.Reachable w'
          → StateMatches encode sid r.2 w')
    : StepMatches encode sid action n (execute w action) r := by
  cases he : execute w action with
  | none => simpa only [he, StepMatches, LifecycleModelPost] using hp
  | some pair =>
      obtain ⟨w', out⟩ := pair
      simp only [he, LifecycleModelPost] at hp
      obtain ⟨v, hv, hV⟩ := lifecycle_observation encode r.1 out hp.1
      exact ⟨v, hv, OutputMatches.of_eq hV, success w' out he hp.2 (reachable_execute rel.reachable he)⟩

private theorem assoc_find_mem {K V : Type} [DecidableEq K] {rows : Assoc K V} {k : K}
    {v : V} (h : find rows k = some v)
    : (k, v) ∈ rows := by
  induction rows with
  | nil => simp [find] at h
  | cons hd tl ih =>
      obtain ⟨rk, rv⟩ := hd
      by_cases he : rk = k
      · subst rk
        simp only [find, ite_true, Option.some.injEq] at h
        subst h
        exact List.mem_cons_self
      · simp only [find, he, ite_false] at h
        exact List.mem_cons_of_mem _ (ih h)

private theorem related_row (encode : List U8 → String) (sid : Nat)
    (n : CcfKv.engine.Store) (w : State) (id : U64) (action : Action)
    {s : Store} {natArchive archive : List Frame}
    (hs : find w.stores sid = some s)
    (hhist : HistoryMatches encode n.history s natArchive archive)
    (hMeta : StoreMetaLive encode n natArchive)
    (hattempts
      : ∀ q : U64,
          Option.Rel (AttemptMatches encode sid n.history.index natArchive archive)
            (find n.txs.val q) (find w.txs q.val))
    (h : StateMatches encode sid n w)
    (op
      : Result
          (core.result.Result CcfKv.engine.Output CcfKv.engine.Error
            × CcfKv.engine.Store))
    (before
      : WP.spec op
          (LifecycleModelPost n (execute w action)
            (LifecycleModelRow encode n w sid id natArchive archive)))
    (hSnapMeta
      : ∀ w' out old next modelTx snap fid nf,
          execute w action = some (w', out)
          → find n.txs.val id = some old
          → w' = {w with txs := Kv.Model.set w.txs id.val modelTx}
          → AttemptMatches encode sid n.history.index natArchive archive next modelTx
          → next.snapshot = some snap
          → n.history.log.branch.val[snap.version.val]? = some fid
          → n.history.log.frames.val[fid.val]? = some nf
          → nf.meta_live = true)
    : WP.spec op (StepMatches encode sid action n (execute w action)) := by
  apply WP.spec_mono before
  intro r hr
  apply refinement_of_lifecycle_post encode sid n w action r h _ hr
  intro w' out hstep ⟨old, next, modelTx, hfindOld, hw, ⟨hh, hviews, index, hi, hn⟩, ht⟩ reach
  have hpins : storePins r.2 = storePins n := by
    unfold storePins
    rw [hh, hn, txsPins_set_same_views n.txs.val index id old next hi hviews]
  have hlive' : IndexLiveness r.2.history.index (storePins r.2) := by
    rw [hh, hpins]
    exact h.liveness
  have hmeta' : StoreMetaLive encode r.2 natArchive := by
    refine ⟨?_, ?_⟩
    · intro id' t' snap' fid' nf' hmem hsnap' hfid' hnf'
      rw [hh] at hfid' hnf'
      rw [hn] at hmem
      rcases List.mem_or_eq_of_mem_set hmem with hold | heq
      · exact hMeta.snapLive id' t' snap' fid' nf' hold hsnap' hfid' hnf'
      · obtain ⟨hidEq, htEq⟩ := Prod.mk.inj heq
        exact hSnapMeta w' out old next modelTx snap' fid' nf' hstep hfindOld hw ht
          (htEq ▸ hsnap') hfid' hnf'
    · intro id' t' bm bv off fid' gf hmem hvm hfid' hgf hb hr'
      rw [hh] at hfid' ⊢
      rw [hn] at hmem
      rcases List.mem_or_eq_of_mem_set hmem with hold | heq
      · exact hMeta.viewLive id' t' bm bv off fid' gf hold hvm hfid' hgf hb hr'
      · obtain ⟨rfl, rfl⟩ := Prod.mk.inj heq
        exact hMeta.viewLive id' old bm bv off fid' gf (List.mem_of_getElem? hi)
          (hviews ▸ hvm) hfid' hgf hb hr'
  refine replace_attempt h.unique hattempts id index old next modelTx hi hn
    (congrArg State.txs hw)
    (by rw [hw]; exact hs)
    (by rw [hh]; exact hhist)
    hlive' hmeta'
    (by rw [hh]; exact ht)
    reach
    (by rw [hh]; exact SinglePreservesPins.refl _ _)
    (fun _ hm => hm)
    (fun _ hm => hm)

private theorem lookup_for_lifecycle (encode : List U8 → String) (sid : Nat)
    (n : CcfKv.engine.Store) (w : State) (id : U64)
    {s : Store} {natArchive archive : List Frame}
    (hs : find w.stores sid = some s)
    (hattempts
      : ∀ q : U64,
          Option.Rel (AttemptMatches encode sid n.history.index natArchive archive)
            (find n.txs.val q) (find w.txs q.val))
    : Option.Rel
        (fun t (_, tx) => LifecycleAttempt encode n.history.index natArchive archive t tx)
        (find n.txs.val id) (lookupTx w sid id.val) := by
  have he := lookupRelated_of_attempts hs hattempts id
  cases hn : find n.txs.val id <;> cases hm : lookupTx w sid id.val <;>
    rw [hn, hm] at he
  · exact .none
  · cases he
  · cases he
  · exact .some (LifecycleAttempt.ofMatched (Option.rel_some_some.mp he).2)

/-- Commit initiation preserves the shared state relation. -/
theorem commit_begin_step_matches (encode : List U8 → String) (sid : Nat)
    (n : CcfKv.engine.Store) (w : State) (id : U64) (h : StateMatches encode sid n w)
    : WP.spec (CcfKv.engine.Store.execute n (.CommitBegin id))
        (StepMatches encode sid (.commitBegin sid id.val) n
          (execute w (.commitBegin sid id.val))) := by
  obtain ⟨s, natArchive, archive, hs, hhist, hMeta, hattempts⟩ := h.history
  refine related_row encode sid n w id _ hs hhist hMeta hattempts h _
    (execute_commit_begin_matches_model encode n w sid id natArchive archive
      (lookup_for_lifecycle encode sid n w id hs hattempts)) ?_
  intro w' out old next modelTx snap fid nf hstep hfindOld hw ht hsnap hfid hnf
  obtain ⟨tx, hlookup, hrelOld⟩ := lookup_of_attempts hs hattempts hfindOld
  have htxEq : modelTx.snapshot = tx.snapshot := by
    have hbind : ∀ {α β : Type} (x : α) (f : α → Option β), (some x >>= f) = f x := fun _ _ => rfl
    simp only [execute, hlookup, hbind] at hstep
    split at hstep
    · cases hstep
    · have hwEq := congrArg Prod.fst (Option.some.inj hstep)
      have htxsEq := congrArg (fun st : State => find st.txs id.val) (hwEq.trans hw)
      simp only [find_set_key, ite_true] at htxsEq
      have hmEq := Option.some.inj htxsEq
      rw [← hmEq]
  have hsnapVer : old.snapshot.map (fun s => s.version.val) = some snap.version.val := by
    have h1 := ht.snapshot
    have h2 := hrelOld.snapshot
    rw [htxEq] at h1
    have h3 := h2.symm.trans h1
    rw [hsnap] at h3
    have h4 := congrArg (Option.map Prod.fst) h3
    simpa [modelSnapshot, Option.map_map] using h4
  cases holdSnap : old.snapshot with
  | none => simp [holdSnap] at hsnapVer
  | some os =>
      have hosVer : os.version.val = snap.version.val := by simpa [holdSnap] using hsnapVer
      exact hMeta.snapLive id old os fid nf (assoc_find_mem hfindOld) holdSnap
        (hosVer ▸ hfid) hnf

/-- Commit completion preserves the relation even when replication fails. -/
theorem commit_result_step_matches (encode : List U8 → String) (sid : Nat)
    (n : CcfKv.engine.Store) (w : State) (id : U64) (result : CcfKv.engine.Outcome)
    (h : StateMatches encode sid n w)
    : WP.spec (CcfKv.engine.Store.execute n (.CommitResult id result))
        (StepMatches encode sid (.commitResult sid id.val (modelOutcome result)) n
          (execute w (.commitResult sid id.val (modelOutcome result)))) := by
  obtain ⟨s, natArchive, archive, hs, hhist, hMeta, hattempts⟩ := h.history
  have hSnapPres : ∀ (outKind : Outcome) w' out old next modelTx snap fid nf,
      execute w (.commitResult sid id.val outKind) = some (w', out) →
      find n.txs.val id = some old →
      w' = {w with txs := Kv.Model.set w.txs id.val modelTx} →
      AttemptMatches encode sid n.history.index natArchive archive next modelTx →
      next.snapshot = some snap →
      n.history.log.branch.val[snap.version.val]? = some fid →
      n.history.log.frames.val[fid.val]? = some nf →
      nf.meta_live = true := by
    intro outKind w' out old next modelTx snap fid nf hstep hfindOld hw ht hsnap hfid hnf
    obtain ⟨tx, hlookup, hrelOld⟩ := lookup_of_attempts hs hattempts hfindOld
    have htxEq : modelTx.snapshot = tx.snapshot := by
      have hbind : ∀ {α β : Type} (x : α) (f : α → Option β), (some x >>= f) = f x := fun _ _ => rfl
      simp only [execute, hlookup, hbind] at hstep
      cases hph : tx.phase with
      | active => simp [hph] at hstep
      | finished => simp [hph] at hstep
      | committing =>
          simp only [hph] at hstep
          split at hstep
          · cases hstep
          · have hwEq := congrArg Prod.fst (Option.some.inj hstep)
            have htxsEq := congrArg (fun st : State => find st.txs id.val) (hwEq.trans hw)
            simp only [find_set_key, ite_true] at htxsEq
            rw [← Option.some.inj htxsEq]
      | applied v =>
          simp only [hph] at hstep
          split at hstep
          · cases hstep
          · have hwEq := congrArg Prod.fst (Option.some.inj hstep)
            have htxsEq := congrArg (fun st : State => find st.txs id.val) (hwEq.trans hw)
            simp only [find_set_key, ite_true] at htxsEq
            rw [← Option.some.inj htxsEq]
    have hsnapVer : old.snapshot.map (fun s => s.version.val) = some snap.version.val := by
      have h1 := ht.snapshot
      have h2 := hrelOld.snapshot
      rw [htxEq] at h1
      have h3 := h2.symm.trans h1
      rw [hsnap] at h3
      have h4 := congrArg (Option.map Prod.fst) h3
      simpa [modelSnapshot, Option.map_map] using h4
    cases holdSnap : old.snapshot with
    | none => simp [holdSnap] at hsnapVer
    | some os =>
        have hosVer : os.version.val = snap.version.val := by simpa [holdSnap] using hsnapVer
        exact hMeta.snapLive id old os fid nf (assoc_find_mem hfindOld) holdSnap
          (hosVer ▸ hfid) hnf
  cases result <;> exact related_row encode sid n w id _ hs hhist hMeta hattempts h _
    (execute_commit_result_matches_model encode n w sid id natArchive archive _
      (lookup_for_lifecycle encode sid n w id hs hattempts)) (hSnapPres _)

/-- Explicit snapshot capture agrees on both guards and frozen metadata. -/
theorem snapshot_step_matches (encode : List U8 → String) (sid : Nat)
    (n : CcfKv.engine.Store) (w : State) (id : U64) (h : StateMatches encode sid n w)
    : WP.spec (CcfKv.engine.Store.execute n (.Snapshot id))
        (StepMatches encode sid (.snapshot sid id.val) n
          (execute w (.snapshot sid id.val))) := by
  obtain ⟨s, natArchive, archive, hs, hh, hMeta, hattempts⟩ := h.history
  obtain ⟨prior, head, hf, hhead⟩ := hh.split
  refine related_row encode sid n w id _ hs hh hMeta hattempts h _ ?_ ?_
  · apply execute_snapshot_matches_model encode n w sid id natArchive archive prior head hf hh.valid
    have he := lookupRelated_of_attempts hs hattempts id
    cases hn : find n.txs.val id <;> cases hm : lookupTx w sid id.val <;>
      rw [hn, hm] at he
    · exact .none
    · cases he
    · cases he
    · obtain ⟨rfl, hr⟩ := Option.rel_some_some.mp he
      exact .some ⟨LifecycleAttempt.ofMatched hr, hhead.version.symm, hh.global, hh.term⟩
  · intro w' out old next modelTx snap fid nf hstep hfindOld hw ht hsnap hfid hnf
    obtain ⟨tx, hlookup, _⟩ := lookup_of_attempts hs hattempts hfindOld
    have hmodelSnap : modelTx.snapshot = some {current := s.head, term := s.term} := by
      have hbind : ∀ {α β : Type} (x : α) (f : α → Option β), (some x >>= f) = f x := fun _ _ => rfl
      simp only [execute, hlookup, hbind] at hstep
      split at hstep
      · cases hstep
      · have hwEq := congrArg Prod.fst (Option.some.inj hstep)
        have htxsEq := congrArg (fun st : State => find st.txs id.val) (hwEq.trans hw)
        simp only [find_set_key, ite_true] at htxsEq
        rw [← Option.some.inj htxsEq]
    have hsnapEq : snap.version.val = s.head.version := by
      have h1 := ht.snapshot
      rw [hmodelSnap, hsnap] at h1
      exact (congrArg Prod.fst (Option.some.inj h1)).symm
    have hbrLen : n.history.log.branch.val.length = n.history.activeFrames.length :=
      (branch_values_length n.history.log hh.valid).symm
    have hactLt : snap.version.val < n.history.activeFrames.length := by
      rw [← hbrLen]; exact (List.getElem?_eq_some_iff.mp hfid).1
    have hactAt : n.history.activeFrames[snap.version.val]? = some nf := by
      rw [branch_active_getElem? n.history.log hh.valid, hfid]
      simpa using hnf
    have hactEq : n.history.activeFrames[snap.version.val] = nf :=
      Option.some.inj ((List.getElem?_eq_getElem hactLt).symm.trans hactAt)
    have hnfVer : nf.version.val = snap.version.val := by
      rw [← hactEq]; exact hh.indexed snap.version.val hactLt
    have hge : n.history.global.val ≤ nf.version.val := by
      have hinv := Kv.Properties.reachable_store_invariants w sid s h.reachable hs
      have hglLe : s.global ≤ s.head.version := hinv.2.2.1
      rw [hnfVer, hsnapEq, ← hh.global]
      exact hglLe
    exact hh.aligned.globalMetaLive snap.version.val fid nf hfid hnf (fun _ => hge)

/-- A term update does not alter the history frames or any frozen attempts. -/
theorem set_term_step_matches (encode : List U8 → String) (sid : Nat)
    (n : CcfKv.engine.Store) (w : State) (term : U64) (h : StateMatches encode sid n w)
    : WP.spec (CcfKv.engine.Store.execute n (.SetTerm term))
        (StepMatches encode sid (.setTerm sid term.val) n
          (execute w (.setTerm sid term.val))) := by
  obtain ⟨s, natArchive, archive, hs, hh, hMeta, hattempts⟩ := h.history
  apply WP.spec_mono (execute_set_term_matches_model n w sid term s hs hh.term)
  intro r hr
  apply refinement_of_lifecycle_post encode sid n w _ r h _ hr
  intro w' _ _ ⟨he, hn⟩ reach
  have hh' : HistoryMatches encode {n.history with term} {s with term := term.val} natArchive archive :=
    {hh with
      term := rfl
      indexValid := hh.indexValid.congr rfl rfl
      aligned := ⟨hh.aligned.len, hh.aligned.versionEq, hh.aligned.metaEq,
        hh.aligned.globalMetaLive, hh.aligned.activeLive⟩}
  have hlive' : IndexLiveness r.2.history.index (storePins r.2) := by
    rw [hn]
    exact h.liveness
  have hmeta' : StoreMetaLive encode r.2 natArchive := by
    rw [hn]
    exact ⟨hMeta.snapLive, hMeta.viewLive⟩
  refine replace_history h.unique hattempts (s' := {s with term := term.val}) ?_ hmeta'
    hlive' ?_ ?_ ?_ reach ?_ (fun _ hm => hm) (fun _ hm => hm)
  · rw [hn]; exact hh'
  · rw [he]; simp [find_set_key]
  · rw [hn]
  · rw [he]
  · rw [hn]
    exact SinglePreservesPins.refl _ _

private theorem keys_erase {K V : Type} [DecidableEq K] (xs : Assoc K V) (k : K)
    (h : (xs.map Prod.fst).Nodup)
    : ((erase xs k).map Prod.fst).Nodup :=
  (List.filter_sublist.map Prod.fst).nodup h

private theorem keys_set {K V : Type} [DecidableEq K] (xs : Assoc K V) (k : K) (v : V)
    (h : (xs.map Prod.fst).Nodup)
    : ((Kv.Model.set xs k v).map Prod.fst).Nodup := by
  apply List.Nodup.cons _ (keys_erase xs k h)
  intro he
  obtain ⟨⟨a, b⟩, hm, he⟩ := List.mem_map.mp he
  change a = k at he
  subst a
  have hf := (List.mem_filter.mp hm).2
  simp at hf

private theorem erase_missing {K V : Type} [DecidableEq K] (rows : Assoc K V) (k : K)
    (h : find rows k = none)
    : erase rows k = rows := by
  induction rows with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨rk, rv⟩ := hd
      by_cases he : rk = k
      · subst rk; simp [find] at h
      · simp only [find, he, ite_false] at h
        have hne : (rk != k) = true := bne_iff_ne.mpr he
        simp only [erase, List.filter_cons, hne, ite_true]
        exact congrArg ((rk, rv) :: ·) (ih h)

/-- Begin agrees with the model's duplicate-ID check and creates a related empty attempt. -/
theorem begin_step_matches (encode : List U8 → String) (sid : Nat)
    (n : CcfKv.engine.Store) (w : State) (id : U64) (h : StateMatches encode sid n w)
    (room : find n.txs.val id = none → n.txs.val.length < Usize.max)
    : WP.spec (CcfKv.engine.Store.execute n (.Begin id))
        (StepMatches encode sid (.txCreate sid id.val) n
          (execute w (.txCreate sid id.val))) := by
  obtain ⟨s, natArchive, archive, hs, hhist, hMeta, hattempts⟩ := h.history
  have he : (find w.txs id.val).isSome = (find n.txs.val id).isSome := by
    have hr := hattempts id
    cases hn : find n.txs.val id <;> cases hw : find w.txs id.val <;>
      rw [hn, hw] at hr <;> cases hr <;> rfl
  apply WP.spec_mono
    (execute_begin_matches_model encode n w sid id s natArchive archive hs he room)
  intro r hr
  apply refinement_of_lifecycle_post encode sid n w _ r h _ hr
  intro w' _ hstep ⟨hw, hh, hn, ht⟩ reach
  have hmiss : find n.txs.val id = none := by
    cases hfind : find n.txs.val id with
    | none => rfl
    | some _ =>
        have hsome : (find w.txs id.val).isSome = true := by rw [he, hfind]; rfl
        simp [execute, hs, hsome] at hstep
  have hlive' : IndexLiveness r.2.history.index (storePins r.2) := by
    have hpins : storePins r.2 = storePins n := by
      unfold storePins
      rw [hh, hn, Kv.Model.set, erase_missing n.txs.val id hmiss]
      simp [txsPins, txPins, lifecycleNewTx, alloc.vec.Vec.new]
    rw [hh, hpins]
    exact h.liveness
  have hmeta' : StoreMetaLive encode r.2 natArchive := by
    refine ⟨?_, ?_⟩
    · intro id' t' snap' fid' nf' hmem hsnap' hfid' hnf'
      rw [hh] at hfid' hnf'
      rw [hn, Kv.Model.set, erase_missing n.txs.val id hmiss] at hmem
      rcases List.mem_cons.mp hmem with heq | hold
      · obtain ⟨rfl, rfl⟩ := Prod.mk.inj heq
        simp [lifecycleNewTx] at hsnap'
      · exact hMeta.snapLive id' t' snap' fid' nf' hold hsnap' hfid' hnf'
    · intro id' t' bm bv off fid' gf hmem hvm hfid' hgf hb hr'
      rw [hh] at hfid' ⊢
      rw [hn, Kv.Model.set, erase_missing n.txs.val id hmiss] at hmem
      rcases List.mem_cons.mp hmem with heq | hold
      · obtain ⟨rfl, rfl⟩ := Prod.mk.inj heq
        simp [lifecycleNewTx, alloc.vec.Vec.new] at hvm
      · exact hMeta.viewLive id' t' bm bv off fid' gf hold hvm hfid' hgf hb hr'
  refine ⟨⟨s, natArchive, archive, ?_, ?_, hmeta', ?_⟩, hlive', ?_, reach⟩
  · rw [hw]; exact hs
  · rw [hh]; exact hhist
  · intro q
    rw [hh, hn, hw, find_set_key, find_set_key]
    by_cases eq : q = id
    · subst q
      simpa using Option.Rel.some ht.related
    · have hv : q.val ≠ id.val := fun he => eq (UScalar.eq_of_val_eq he)
      simpa [eq, hv] using hattempts q
  · rw [hn]
    exact keys_set _ _ _ h.unique

/-- End releases the attempt's pins, erases its row, opportunistically elides compacted
snapshot metadata, and retires freed nodes, or rejects without mutation. -/
theorem end_step_matches (encode : List U8 → String) (inj : Function.Injective encode)
    (sid : Nat) (n : CcfKv.engine.Store) (w : State) (id : U64)
    (h : StateMatches encode sid n w)
    (queueRoom
      : 2
            * (n.history.index.values.dirs.val.length
                + n.history.index.values.rows.val.length)
          + 1
        ≤ Usize.max)
    : WP.spec (CcfKv.engine.Store.execute n (.End id))
        (StepMatches encode sid (.txEnd sid id.val) n
          (execute w (.txEnd sid id.val))) := by
  obtain ⟨s, natArchive, archive, hs, hhist, hMeta, hattempts⟩ := h.history
  have he : (lookupTx w sid id.val).isSome = (find n.txs.val id).isSome := by
    have hr := lookupRelated_of_attempts hs hattempts id
    cases hn : find n.txs.val id <;> cases hw : lookupTx w sid id.val <;>
      rw [hn, hw] at hr <;> cases hr <;> rfl
  apply WP.spec_mono
    (execute_end_matches_model n w sid id he h.unique hhist.nonempty hhist.indexed
      hhist.globalBound hhist.valid hhist.unique h.liveness queueRoom)
  intro r hr
  apply refinement_of_lifecycle_post encode sid n w _ r h _ hr
  intro w' _ _ ⟨hw, hbrEq, hglobalEq, htermEq, hidentEq, hreuseEq, hvalid', hunique',
    hframesLen, hn, hlive', hpres, globalId, globalFrame, hglBr, hglBefore, hglAfter, hslots⟩ reach
  have hpresFrames : IndexPreservesPins n.history.index r.2.history.index
      (framePins r.2.history.log.frames.val ++ txsPins r.2.txs.val) := hpres
  have hslotAt : ∀ (k : Nat) (f' : CcfKv.engine.Frame),
      r.2.history.log.frames.val[k]? = some f'
      → ∃ f, n.history.log.frames.val[k]? = some f
        ∧ f'.version = f.version
        ∧ f'.data = f.data
        ∧ (f' = f
            ∨ (f'.meta_live = false
                ∧ f.version.val < n.history.global.val
                ∧ n.history.reuse_compacted_images = true
                ∧ CcfKv.engine.txs_need_frame r.2.txs f globalFrame = .ok false)) := by
    intro k f' hf'
    have hkLt : k < n.history.log.frames.val.length := by
      rw [← hframesLen]; exact (List.getElem?_eq_some_iff.mp hf').1
    let f := n.history.log.frames.val[k]'hkLt
    have hf : n.history.log.frames.val[k]? = some f := List.getElem?_eq_getElem hkLt
    obtain ⟨f'', hf'', hv, hd, hcase⟩ := hslots k f hf
    have heq : f' = f'' := Option.some.inj (hf'.symm.trans hf'')
    subst heq
    exact ⟨f, hf, hv, hd, hcase⟩
  have hidxValid' : HistoryIndexValid r.2.history :=
    hhist.indexValid.of_preserves_pins hlive'.valid hpresFrames (fun i f' hf' => by
      obtain ⟨f, hf, _, hd, _⟩ := hslotAt i f' hf'
      exact Or.inr ⟨i, f, hf, hd⟩)
  have haligned' : ArchiveAligned encode r.2.history natArchive := by
    refine ⟨by rw [hframesLen]; exact hhist.aligned.len, ?_, ?_, ?_, ?_⟩
    · intro i nf gf hnf hgf
      obtain ⟨f, hf, hv, _, _⟩ := hslotAt i nf hnf
      rw [hv]
      exact hhist.aligned.versionEq i f gf hf hgf
    · intro i nf gf hnf hgf hml
      obtain ⟨f, hf, _, _, hcase⟩ := hslotAt i nf hnf
      rcases hcase with rfl | ⟨hfalse, _, _, _⟩
      · exact hhist.aligned.metaEq i nf gf hf hgf hml
      · simp [hfalse] at hml
    · intro off fid nf hfid hnf hlive
      obtain ⟨f, hf, hv, _, hcase⟩ := hslotAt fid.val nf hnf
      have hlive0 : n.history.reuse_compacted_images = true → n.history.global.val ≤ f.version.val := by
        rw [← hreuseEq, ← hglobalEq, ← hv]; exact hlive
      rcases hcase with rfl | ⟨_, hlt, hreuseT, _⟩
      · exact hhist.aligned.globalMetaLive off fid nf (hbrEq ▸ hfid) hf hlive0
      · have := hlive0 hreuseT; omega
    · intro off fid nf gf hfid hnf hgf hlive
      obtain ⟨f, hf, hv, hd, hcase⟩ := hslotAt fid.val nf hnf
      have hlive0 : n.history.reuse_compacted_images = true → n.history.global.val ≤ f.version.val := by
        rw [← hreuseEq, ← hglobalEq, ← hv]; exact hlive
      rcases hcase with rfl | ⟨_, hlt, hreuseT, _⟩
      · have hmf0 := hhist.aligned.activeLive off fid nf gf (hbrEq ▸ hfid) hf hgf hlive0
        have hpin : nf.data = 0#u32 ∨ nf.data ∈ framePins r.2.history.log.frames.val ++ txsPins r.2.txs.val := by
          by_cases hz : nf.data = 0#u32
          · exact Or.inl hz
          · exact Or.inr (List.mem_append_left _
              (List.mem_filterMap.mpr ⟨nf, List.mem_iff_getElem?.mpr ⟨fid.val, hnf⟩, by simp [hz]⟩))
        have hview := index_preserves_pins_view hpresFrames nf.data _ hpin
          (hhist.indexValid.archived fid.val nf hf)
        have hrows : indexRows r.2.history.index nf.data = indexRows n.history.index nf.data :=
          index_rows_eq hview
        simpa only [modelFrame, hrows] using hmf0
      · have := hlive0 hreuseT; omega
  have hmeta' : StoreMetaLive encode r.2 natArchive :=
    store_meta_live_after_elision inj hMeta hhist.indexed hhist.valid hbrEq
      (fun row hrow => by rw [hn] at hrow; exact (List.mem_filter.mp hrow).1)
      hglBr hglAfter (fun k f hf => by
        obtain ⟨f', hf', hv, _, hcase⟩ := hslots k f hf
        refine ⟨f', hf', hv, ?_⟩
        rcases hcase with rfl | ⟨hml, _, _, hfalse⟩
        · exact Or.inl ⟨rfl, rfl, rfl⟩
        · exact Or.inr ⟨hml, hfalse⟩)
  have hnatEq : natModelFrames r.2.history.log natArchive = natModelFrames n.history.log natArchive := by
    unfold natModelFrames
    rw [hbrEq]
  have hhist' : HistoryMatches encode r.2.history s natArchive archive :=
    history_related reach (by rw [hw]; exact hs) (hnatEq.symm ▸ hhist.frames)
      (by rw [hglobalEq]; exact hhist.global)
      (by rw [htermEq]; exact hhist.term)
      (by rw [hidentEq]; exact hhist.identity)
      hvalid' hunique' hidxValid' haligned'
      (hnatEq.symm ▸ hhist.revisions)
      (by rw [hidentEq]; exact hhist.nativeArchive)
      hhist.natSorted hhist.modelSub hhist.modelArchive
  refine ⟨⟨s, natArchive, archive, ?_, hhist', hmeta', ?_⟩, hlive', ?_, reach⟩
  · rw [hw]; exact hs
  · intro q
    rw [hn, hw, find_erase_key, find_erase_key]
    by_cases eq : q = id
    · subst q
      simp
    · have hv : q.val ≠ id.val := fun he => eq (UScalar.eq_of_val_eq he)
      simp only [eq, hv, ite_false]
      have hprev := hattempts q
      cases hfq : find n.txs.val q with
      | none =>
          rw [hfq] at hprev
          cases hfm : find w.txs q.val with
          | none => exact .none
          | some _ => rw [hfm] at hprev; cases hprev
      | some t =>
          rw [hfq] at hprev
          cases hfm : find w.txs q.val with
          | none => rw [hfm] at hprev; cases hprev
          | some tx =>
              rw [hfm] at hprev
              have hmemAfter : (q, t) ∈ r.2.txs.val := by
                have hfq' : find r.2.txs.val q = some t := by
                  rw [hn, find_erase_key, ite_eq_right eq, hfq]
                exact assoc_find_mem hfq'
              have hsub : ∀ row ∈ t.views.val, ∀ r_1 ∈ viewPins row.2, r_1 ∈ storePins r.2 :=
                fun row hrow r_1 hr1 =>
                  List.mem_append_right _ (List.mem_flatMap.mpr
                    ⟨(q, t), hmemAfter, List.mem_flatMap.mpr ⟨row, hrow, hr1⟩⟩)
              exact .some ((Option.rel_some_some.mp hprev).withPreservedPins hpres hsub
                (fun _ hm => hm) (fun _ hm => hm))
  · rw [hn]
    exact keys_erase _ _ h.unique

end KvRust
