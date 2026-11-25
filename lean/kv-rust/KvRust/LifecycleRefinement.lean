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
    : WP.spec (Spike.engine.Store.new term)
        (fun n =>
          ∃ w,
            execute {} (.storeCreate sid term.val) = some (w, .unit)
            ∧ StateMatches encode sid n w) := by
  apply WP.spec_mono (store_new_lifecycle encode term)
  intro n ⟨head, _, hsaved, hzero, hf, hg, ht, hi, htx, valid, indexed⟩
  let s : Store := {term := term.val}
  let w : State := {stores := [(sid, s)]}
  have hs : find w.stores sid = some s := by simp [w, find]
  have he : execute {} (.storeCreate sid term.val) = some (w, .unit) := by
    simp [execute, find, Kv.Model.set, erase, s, w]
  have hReach := reachable_execute (CCF.TransitionSystem.Reachable.initial rfl) he
  have hFrames : List.Forall₂ FrameOrderEq
      (modelFrames n.history (modelFrame encode n.history.index)) s.history := by
    rw [hf]
    exact .cons (.refl _) .nil
  have hRev : RevisionHistory (modelFrames n.history (modelFrame encode n.history.index)) := by
    rw [hf]
    exact revision_history_new
  have hNatArch : ArchiveConsistent
      (n.history.log.frames.val.map (modelFrame encode n.history.index))
      n.history.next_identity.val := by
    rw [hsaved, hi]
    simpa [hzero, s] using archive_consistent_new
  have hr := history_related (encode := encode) (n := n.history) (archive := [{}]) hReach hs
    hFrames hg.symm (by change term.val = n.history.term.val; rw [ht]) hi.symm valid indexed
    hRev hNatArch (fun f hm => hm) archive_consistent_new
  refine ⟨w, he, ⟨⟨s, [{}], hs, hr, ?_⟩, ?_, hReach⟩⟩
  · intro id
    simp [htx, find, w]
  · simp [htx]

private theorem lifecycle_observation (encode : List U8 → String)
    (r : core.result.Result Spike.engine.Output Spike.engine.Error) (out : Output)
    (h : lifecycleOutput r = some out)
    : ∃ v, r = .Ok v ∧ modelOutput encode v = out := by
  cases r with
  | Err e => cases h
  | Ok v =>
      refine ⟨v, rfl, ?_⟩
      cases v <;> cases h <;> rfl

private theorem refinement_of_lifecycle_post (encode : List U8 → String) (sid : Nat)
    (n : Spike.engine.Store) (w : State) (action : Action)
    (r : core.result.Result Spike.engine.Output Spike.engine.Error × Spike.engine.Store)
    (rel : StateMatches encode sid n w) (post : State → Spike.engine.Store → Prop)
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

private theorem related_row (encode : List U8 → String) (sid : Nat)
    (n : Spike.engine.Store) (w : State) (id : U64) (action : Action)
    {s : Store} {archive : List Frame}
    (hs : find w.stores sid = some s)
    (hhist : HistoryMatches encode n.history s archive)
    (hattempts
      : ∀ q : U64,
          Option.Rel (AttemptMatches encode sid n.history archive)
            (find n.txs.val q) (find w.txs q.val))
    (h : StateMatches encode sid n w)
    (op
      : Result
          (core.result.Result Spike.engine.Output Spike.engine.Error
            × Spike.engine.Store))
    (before
      : WP.spec op
          (LifecycleModelPost n (execute w action)
            (LifecycleModelRow encode n w sid id archive)))
    : WP.spec op (StepMatches encode sid action n (execute w action)) := by
  apply WP.spec_mono before
  intro r hr
  apply refinement_of_lifecycle_post encode sid n w action r h _ hr
  intro w' _ _ ⟨old, next, modelTx, _, hw, ⟨hh, index, hi, hn⟩, ht⟩ reach
  refine replace_attempt h.unique hattempts hhist id index old next modelTx hi hn
    (congrArg State.txs hw)
    (by rw [hw]; exact hs)
    (by rw [hh]; exact hhist)
    (by rw [hh]; exact ht)
    reach
    (HistoryKeeps.of_same (congrArg (fun h => h.log.frames) hh)
      (congrArg (fun h => h.index) hh))
    (fun _ hm => hm)

private theorem lookup_for_lifecycle (encode : List U8 → String) (sid : Nat)
    (n : Spike.engine.Store) (w : State) (id : U64)
    {s : Store} {archive : List Frame}
    (hs : find w.stores sid = some s)
    (hattempts
      : ∀ q : U64,
          Option.Rel (AttemptMatches encode sid n.history archive)
            (find n.txs.val q) (find w.txs q.val))
    : Option.Rel (fun t (_, tx) => LifecycleAttempt encode n.history archive t tx)
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
    (n : Spike.engine.Store) (w : State) (id : U64) (h : StateMatches encode sid n w)
    : WP.spec (Spike.engine.Store.execute n (.CommitBegin id))
        (StepMatches encode sid (.commitBegin sid id.val) n
          (execute w (.commitBegin sid id.val))) := by
  obtain ⟨s, archive, hs, hhist, hattempts⟩ := h.history
  exact related_row encode sid n w id _ hs hhist hattempts h _
    (execute_commit_begin_matches_model encode n w sid id archive
      (lookup_for_lifecycle encode sid n w id hs hattempts))

/-- Commit completion preserves the relation even when replication fails. -/
theorem commit_result_step_matches (encode : List U8 → String) (sid : Nat)
    (n : Spike.engine.Store) (w : State) (id : U64) (result : Spike.engine.Outcome)
    (h : StateMatches encode sid n w)
    : WP.spec (Spike.engine.Store.execute n (.CommitResult id result))
        (StepMatches encode sid (.commitResult sid id.val (modelOutcome result)) n
          (execute w (.commitResult sid id.val (modelOutcome result)))) := by
  obtain ⟨s, archive, hs, hhist, hattempts⟩ := h.history
  cases result <;> exact related_row encode sid n w id _ hs hhist hattempts h _
    (execute_commit_result_matches_model encode n w sid id archive _
      (lookup_for_lifecycle encode sid n w id hs hattempts))

/-- Explicit snapshot capture agrees on both guards and frozen metadata. -/
theorem snapshot_step_matches (encode : List U8 → String) (sid : Nat)
    (n : Spike.engine.Store) (w : State) (id : U64) (h : StateMatches encode sid n w)
    : WP.spec (Spike.engine.Store.execute n (.Snapshot id))
        (StepMatches encode sid (.snapshot sid id.val) n
          (execute w (.snapshot sid id.val))) := by
  obtain ⟨s, archive, hs, hh, hattempts⟩ := h.history
  obtain ⟨prior, head, hf, hhead⟩ := hh.split
  apply related_row encode sid n w id _ hs hh hattempts h
  apply execute_snapshot_matches_model encode n w sid id archive prior head hf hh.valid
  have he := lookupRelated_of_attempts hs hattempts id
  cases hn : find n.txs.val id <;> cases hm : lookupTx w sid id.val <;>
    rw [hn, hm] at he
  · exact .none
  · cases he
  · cases he
  · obtain ⟨rfl, hr⟩ := Option.rel_some_some.mp he
    exact .some ⟨LifecycleAttempt.ofMatched hr, hhead.version.symm, hh.global, hh.term⟩

/-- A term update does not alter the history frames or any frozen attempts. -/
theorem set_term_step_matches (encode : List U8 → String) (sid : Nat)
    (n : Spike.engine.Store) (w : State) (term : U64) (h : StateMatches encode sid n w)
    : WP.spec (Spike.engine.Store.execute n (.SetTerm term))
        (StepMatches encode sid (.setTerm sid term.val) n
          (execute w (.setTerm sid term.val))) := by
  obtain ⟨s, archive, hs, hh, hattempts⟩ := h.history
  apply WP.spec_mono (execute_set_term_matches_model n w sid term s hs hh.term)
  intro r hr
  apply refinement_of_lifecycle_post encode sid n w _ r h _ hr
  intro w' _ _ ⟨he, hn⟩ reach
  have hh' : HistoryMatches encode {n.history with term} {s with term := term.val} archive :=
    {hh with term := rfl, indexValid := hh.indexValid.congr rfl rfl}
  refine replace_history h.unique hattempts hh (s' := {s with term := term.val}) ?_ ?_ ?_ ?_ reach ?_
    (fun _ hm => hm)
  · rw [hn]; exact hh'
  · rw [he]; simp [find_set_key]
  · rw [hn]
  · rw [he]
  · rw [hn]
    exact HistoryKeeps.of_same rfl rfl

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

/-- Begin agrees with the model's duplicate-ID check and creates a related empty attempt. -/
theorem begin_step_matches (encode : List U8 → String) (sid : Nat)
    (n : Spike.engine.Store) (w : State) (id : U64) (h : StateMatches encode sid n w)
    (room : find n.txs.val id = none → n.txs.val.length < Usize.max)
    : WP.spec (Spike.engine.Store.execute n (.Begin id))
        (StepMatches encode sid (.txCreate sid id.val) n
          (execute w (.txCreate sid id.val))) := by
  obtain ⟨s, archive, hs, hhist, hattempts⟩ := h.history
  have he : (find w.txs id.val).isSome = (find n.txs.val id).isSome := by
    have hr := hattempts id
    cases hn : find n.txs.val id <;> cases hw : find w.txs id.val <;>
      rw [hn, hw] at hr <;> cases hr <;> rfl
  apply WP.spec_mono (execute_begin_matches_model encode n w sid id s archive hs he room)
  intro r hr
  apply refinement_of_lifecycle_post encode sid n w _ r h _ hr
  intro w' _ _ ⟨hw, hh, hn, ht⟩ reach
  refine ⟨⟨s, archive, ?_, ?_, ?_⟩, ?_, reach⟩
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

/-- End erases the same live attempt or rejects without mutation. -/
theorem end_step_matches (encode : List U8 → String) (sid : Nat)
    (n : Spike.engine.Store) (w : State) (id : U64) (h : StateMatches encode sid n w)
    : WP.spec (Spike.engine.Store.execute n (.End id))
        (StepMatches encode sid (.txEnd sid id.val) n
          (execute w (.txEnd sid id.val))) := by
  obtain ⟨s, archive, hs, hhist, hattempts⟩ := h.history
  have he : (lookupTx w sid id.val).isSome = (find n.txs.val id).isSome := by
    have hr := lookupRelated_of_attempts hs hattempts id
    cases hn : find n.txs.val id <;> cases hw : lookupTx w sid id.val <;>
      rw [hn, hw] at hr <;> cases hr <;> rfl
  apply WP.spec_mono (execute_end_matches_model n w sid id he)
  intro r hr
  apply refinement_of_lifecycle_post encode sid n w _ r h _ hr
  intro w' _ _ ⟨hw, hh, hn⟩ reach
  refine ⟨⟨s, archive, ?_, ?_, ?_⟩, ?_, reach⟩
  · rw [hw]; exact hs
  · rw [hh]; exact hhist
  · intro q
    rw [hh, hn, hw, find_erase_key, find_erase_key]
    by_cases eq : q = id
    · subst q
      simp
    · have hv : q.val ≠ id.val := fun he => eq (UScalar.eq_of_val_eq he)
      simpa [eq, hv] using hattempts q
  · rw [hn]
    exact keys_erase _ _ h.unique

end KvRust
