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
  intro n ⟨head, _, _, _, hg, ht, hi, htx, valid, indexed, aligned, hlive⟩
  let s : Store := {term := term.val}
  let w : State := {stores := [(sid, s)]}
  have hs : find w.stores sid = some s := by simp [w, find]
  have he : execute {} (.storeCreate sid term.val) = some (w, .unit) := by
    simp [execute, find, Kv.Model.set, erase, s, w]
  have hReach := reachable_execute (CCF.TransitionSystem.Reachable.initial rfl) he
  have hFrames : List.Forall₂ FrameOrderEq [s.head] s.history :=
    .cons (.refl _) .nil
  have hRev : RevisionHistory [s.head] := revision_history_new
  have hNatArch : ArchiveConsistent [s.head] n.history.next_identity.val := by
    rw [hi]
    simpa [s] using archive_consistent_new
  have hNatSorted : ∀ f ∈ [s.head], ∀ m, (image f.data m).Pairwise (encKeyLt encode) := by
    intro f hf m
    rw [List.mem_singleton.mp hf]
    exact List.Pairwise.nil
  have hr := history_related (encode := encode) (n := n.history) (natHistory := [s.head])
    (natArchive := [s.head]) (archive := [{}]) hReach hs hFrames hg.symm
    (by change term.val = n.history.term.val; rw [ht])
    hi.symm valid indexed aligned hRev (fun _ hm => hm) hNatArch hNatSorted
    (fun f hm => hm) archive_consistent_new
  have hMetaInit : StoreMetaLive encode n [s.head] :=
    ⟨fun _ _ _ _ hmem => by simp [htx] at hmem,
      fun _ _ _ _ _ hmem => by simp [htx] at hmem⟩
  refine ⟨
    w,
    he,
    ⟨⟨s, [s.head], [s.head], [{}], hs, hr, hMetaInit, ?_⟩, hlive, ?_, hReach⟩
  ⟩
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
    {s : Store} {natHistory natArchive archive : List Frame}
    (hs : find w.stores sid = some s)
    (hhist : HistoryMatches encode n.history s natHistory natArchive archive)
    (hMeta : StoreMetaLive encode n natHistory)
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
      : ∀ w' out old next modelTx snap bf,
          execute w action = some (w', out)
          → find n.txs.val id = some old
          → w' = {w with txs := Kv.Model.set w.txs id.val modelTx}
          → AttemptMatches encode sid n.history.index natArchive archive next modelTx
          → next.snapshot = some snap
          → n.history.activeFrames[0]? = some bf
          → snap.version.val < bf.version.val
          → ∃ rf ∈ n.history.retained.val, rf.version = snap.version)
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
  have hmeta' : StoreMetaLive encode r.2 natHistory := by
    refine ⟨?_, ?_⟩
    · intro id' t' snap' bf hmem hsnap' hbf hlt
      rw [hh] at hbf ⊢
      rw [hn] at hmem
      rcases List.mem_or_eq_of_mem_set hmem with hold | heq
      · exact hMeta.snapLive id' t' snap' bf hold hsnap' hbf hlt
      · obtain ⟨hidEq, htEq⟩ := Prod.mk.inj heq
        exact hSnapMeta w' out old next modelTx snap' bf hstep hfindOld hw ht
          (htEq ▸ hsnap') hbf hlt
    · intro id' t' bm bv gf hmem hvm hgf hb hr'
      rw [hh]
      rw [hn] at hmem
      rcases List.mem_or_eq_of_mem_set hmem with hold | heq
      · exact hMeta.viewLive id' t' bm bv gf hold hvm hgf hb hr'
      · obtain ⟨rfl, rfl⟩ := Prod.mk.inj heq
        exact hMeta.viewLive id' old bm bv gf (List.mem_of_getElem? hi)
          (hviews ▸ hvm) hgf hb hr'
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
  obtain ⟨s, natHistory, natArchive, archive, hs, hhist, hMeta, hattempts⟩ := h.history
  refine related_row encode sid n w id _ hs hhist hMeta hattempts h _
    (execute_commit_begin_matches_model encode n w sid id natArchive archive
      (lookup_for_lifecycle encode sid n w id hs hattempts)) ?_
  intro w' out old next modelTx snap bf hstep hfindOld hw ht hsnap hbf hlt
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
      have hosEq : os.version = snap.version := UScalar.eq_of_val_eq hosVer
      rw [← hosEq]
      exact hMeta.snapLive id old os bf (assoc_find_mem hfindOld) holdSnap hbf
        (hosVer.symm ▸ hlt)

/-- Commit completion preserves the relation even when replication fails. -/
theorem commit_result_step_matches (encode : List U8 → String) (sid : Nat)
    (n : CcfKv.engine.Store) (w : State) (id : U64) (result : CcfKv.engine.Outcome)
    (h : StateMatches encode sid n w)
    : WP.spec (CcfKv.engine.Store.execute n (.CommitResult id result))
        (StepMatches encode sid (.commitResult sid id.val (modelOutcome result)) n
          (execute w (.commitResult sid id.val (modelOutcome result)))) := by
  obtain ⟨s, natHistory, natArchive, archive, hs, hhist, hMeta, hattempts⟩ := h.history
  have hSnapPres : ∀ (outKind : Outcome) w' out old next modelTx snap bf,
      execute w (.commitResult sid id.val outKind) = some (w', out) →
      find n.txs.val id = some old →
      w' = {w with txs := Kv.Model.set w.txs id.val modelTx} →
      AttemptMatches encode sid n.history.index natArchive archive next modelTx →
      next.snapshot = some snap →
      n.history.activeFrames[0]? = some bf →
      snap.version.val < bf.version.val →
      ∃ rf ∈ n.history.retained.val, rf.version = snap.version := by
    intro outKind w' out old next modelTx snap bf hstep hfindOld hw ht hsnap hbf hlt
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
        have hosEq : os.version = snap.version := UScalar.eq_of_val_eq hosVer
        rw [← hosEq]
        exact hMeta.snapLive id old os bf (assoc_find_mem hfindOld) holdSnap hbf
          (hosVer.symm ▸ hlt)
  cases result <;> exact related_row encode sid n w id _ hs hhist hMeta hattempts h _
    (execute_commit_result_matches_model encode n w sid id natArchive archive _
      (lookup_for_lifecycle encode sid n w id hs hattempts)) (hSnapPres _)

/-- Explicit snapshot capture agrees on both guards and frozen metadata. -/
theorem snapshot_step_matches (encode : List U8 → String) (sid : Nat)
    (n : CcfKv.engine.Store) (w : State) (id : U64) (h : StateMatches encode sid n w)
    : WP.spec (CcfKv.engine.Store.execute n (.Snapshot id))
        (StepMatches encode sid (.snapshot sid id.val) n
          (execute w (.snapshot sid id.val))) := by
  obtain ⟨s, natHistory, natArchive, archive, hs, hh, hMeta, hattempts⟩ := h.history
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
  · intro w' out old next modelTx snap bf hstep hfindOld hw ht hsnap hbf hlt
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
    obtain ⟨bf0, hbf0, hbf0Le, _, _⟩ := hh.aligned.base
    have hbfEq : bf = bf0 := Option.some.inj (hbf.symm.trans hbf0)
    subst hbfEq
    have hinv := Kv.Properties.reachable_store_invariants w sid s h.reachable hs
    have hglLe : s.global ≤ s.head.version := hinv.2.2.1
    rw [hh.global] at hglLe
    omega

/-- A term update does not alter the history frames or any frozen attempts. -/
theorem set_term_step_matches (encode : List U8 → String) (sid : Nat)
    (n : CcfKv.engine.Store) (w : State) (term : U64) (h : StateMatches encode sid n w)
    : WP.spec (CcfKv.engine.Store.execute n (.SetTerm term))
        (StepMatches encode sid (.setTerm sid term.val) n
          (execute w (.setTerm sid term.val))) := by
  obtain ⟨s, natHistory, natArchive, archive, hs, hh, hMeta, hattempts⟩ := h.history
  apply WP.spec_mono (execute_set_term_matches_model n w sid term s hs hh.term)
  intro r hr
  apply refinement_of_lifecycle_post encode sid n w _ r h _ hr
  intro w' _ _ ⟨he, hn⟩ reach
  have hh' : HistoryMatches encode {n.history with term} {s with term := term.val} natHistory natArchive archive :=
    {hh with
      term := rfl
      indexValid := hh.indexValid.congr rfl rfl rfl
      aligned := ⟨hh.aligned.nonempty, hh.aligned.base, hh.aligned.activeEq,
        hh.aligned.retainedEq, hh.aligned.retainedReuse, hh.aligned.verIndexed⟩}
  have hlive' : IndexLiveness r.2.history.index (storePins r.2) := by
    rw [hn]
    exact h.liveness
  have hmeta' : StoreMetaLive encode r.2 natHistory := by
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
  obtain ⟨s, natHistory, natArchive, archive, hs, hhist, hMeta, hattempts⟩ := h.history
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
  have hmeta' : StoreMetaLive encode r.2 natHistory := by
    refine ⟨?_, ?_⟩
    · intro id' t' snap' bf hmem hsnap' hbf hlt
      rw [hh] at hbf ⊢
      rw [hn, Kv.Model.set, erase_missing n.txs.val id hmiss] at hmem
      rcases List.mem_cons.mp hmem with heq | hold
      · obtain ⟨rfl, rfl⟩ := Prod.mk.inj heq
        simp [lifecycleNewTx] at hsnap'
      · exact hMeta.snapLive id' t' snap' bf hold hsnap' hbf hlt
    · intro id' t' bm bv gf hmem hvm hgf hb hr'
      rw [hh]
      rw [hn, Kv.Model.set, erase_missing n.txs.val id hmiss] at hmem
      rcases List.mem_cons.mp hmem with heq | hold
      · obtain ⟨rfl, rfl⟩ := Prod.mk.inj heq
        simp [lifecycleNewTx, alloc.vec.Vec.new] at hvm
      · exact hMeta.viewLive id' t' bm bv gf hold hvm hgf hb hr'
  refine ⟨⟨s, natHistory, natArchive, archive, ?_, ?_, hmeta', ?_⟩, hlive', ?_, reach⟩
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

/-- End releases the attempt's pins, erases its row, prunes unneeded compacted
retained metadata, and retires freed nodes, or rejects without mutation. -/
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
  obtain ⟨s, natHistory, natArchive, archive, hs, hhist, hMeta, hattempts⟩ := h.history
  have he : (lookupTx w sid id.val).isSome = (find n.txs.val id).isSome := by
    have hr := lookupRelated_of_attempts hs hattempts id
    cases hn : find n.txs.val id <;> cases hw : lookupTx w sid id.val <;>
      rw [hn, hw] at hr <;> cases hr <;> rfl
  obtain ⟨baseFrame, hbase0, _, _, _⟩ := hhist.aligned.base
  apply WP.spec_mono
    (execute_end_matches_model n w sid id he h.unique baseFrame hbase0 hhist.valid
      h.liveness queueRoom)
  intro r hr
  apply refinement_of_lifecycle_post encode sid n w _ r h _ hr
  intro w' _ _ ⟨hw, hlogEq, hglobalEq, htermEq, hidentEq, hreuseEq, hn, hlive',
    hpres, hretSub, hretDone⟩ reach
  have hactEq : r.2.history.activeFrames = n.history.activeFrames := by
    unfold CcfKv.engine.History.activeFrames; rw [hlogEq]
  have hpresFrames : IndexPreservesPins n.history.index r.2.history.index
      (framePins r.2.history.activeFrames ++ txsPins r.2.txs.val) := hpres
  have hidxValid' : HistoryIndexValid r.2.history :=
    hhist.indexValid.of_preserves_pins hlive'.valid hpresFrames
      (fun f' hf' => Or.inr ⟨f', hactEq ▸ hf', rfl⟩)
      (fun rf hrf => hhist.indexValid.retainedEmpty rf (hretSub rf hrf))
  have haligned' : ArchiveAligned encode r.2.history natHistory :=
    hhist.aligned.of_preserves_pins hhist.indexValid hpresFrames hactEq
      hretSub hglobalEq hreuseEq
  have hmeta' : StoreMetaLive encode r.2 natHistory :=
    store_meta_live_after_prune inj hMeta hhist.aligned haligned'
      (fun row hrow => by rw [hn] at hrow; exact (List.mem_filter.mp hrow).1)
      (by rw [hactEq]; exact List.mem_of_getElem? hbase0)
      (fun f hf => by
        rcases List.mem_append.mp hf with hact | hret
        · exact Or.inl (List.mem_append_left _ (hactEq.symm ▸ hact))
        · rcases hretDone f hret with hkept | hfalse
          · exact Or.inl (List.mem_append_right _ hkept)
          · exact Or.inr (Or.inr hfalse))
  have hhist' : HistoryMatches encode r.2.history s natHistory natArchive archive :=
    history_related reach (by rw [hw]; exact hs) hhist.frames
      (by rw [hglobalEq]; exact hhist.global)
      (by rw [htermEq]; exact hhist.term)
      (by rw [hidentEq]; exact hhist.identity)
      (by rw [hlogEq]; exact hhist.valid) hidxValid' haligned'
      hhist.revisions hhist.natSub
      (by rw [hidentEq]; exact hhist.nativeArchive)
      hhist.natSorted hhist.modelSub hhist.modelArchive
  refine ⟨⟨s, natHistory, natArchive, archive, ?_, hhist', hmeta', ?_⟩, hlive', ?_, reach⟩
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
