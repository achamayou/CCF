-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Relation

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Capacity for inserting one new map handle. -/
def FitsAcquire (n : Spike.engine.Store) (id : U64) : Prop :=
  ∀ t, find n.txs.val id = some t → t.views.val.length < Usize.max

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
    (history : Spike.engine.History) (archive : List Frame) (t : Spike.engine.Tx)
    (tx : Tx) (view : GlobalView) (key : String)
    (rel : AttemptMatches encode sid history archive t tx)
    (hf : find tx.globalViews key = some view)
    : (find (rustPinnedViews encode history t.views) key).isSome := by
  have hrel := rel.views.find key
  rw [lookup_model_view _ _ _ hf] at hrel
  cases h : find (rustPinnedViews encode history t.views) key with
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
    (history : Spike.engine.History) (archive : List Frame) (s : Store) (snap : Snapshot)
    (rustSnap : Spike.engine.Snapshot) (key : String) (t t' : Spike.engine.Tx)
    (tx tx' : Tx) (rel : AttemptMatches encode sid history archive t tx)
    (hSnap : t.snapshot = some rustSnap) (hFreshModel : find tx.globalViews key = none)
    (hModelSub : ∀ f ∈ s.history, f ∈ archive) (hEmptyIn : ({} : Frame) ∈ archive)
    (unique : Kv.Properties.Unique (image (captureLocal s snap key).data key))
    (v
      : ViewsOrderEq (modelPinnedViews tx'.globalViews)
          (rustPinnedViews encode history t'.views))
    (live : ViewsLive history t'.views) (orig : ViewsOrigin encode history t'.views)
    (otherViews
      : ∀ m,
          m ≠ key
          → find (rustPinnedViews encode history t'.views) m
            = find (rustPinnedViews encode history t.views) m)
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
    : AttemptMatches encode sid history archive t' tx' := by
  by_cases ha : available s snap key
  · rw [ite_eq_left ha] at hn hm
    have hnone : t'.snapshot = some rustSnap := by
      simpa only [hSnap] using congrArg Spike.engine.Tx.snapshot hn
    have hFreshNative : find (rustPinnedViews encode history t.views) key = none := by
      have hr := rel.views.find key
      rw [projected_view_missing tx.globalViews key hFreshModel] at hr
      cases h : find (rustPinnedViews encode history t.views) key with
      | none => rfl
      | some _ => rw [h] at hr; cases hr
    refine ⟨?_, ?_, ?_, v, live, orig, ?_, ?_, ?_, ?_, ?_, hu, ?_, ?_, ?_, ?_, ?_⟩
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
    · rw [hm, hn]; exact rel.deps
    · intro d hd
      rw [hn] at hd
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
    exact {rel with unavailable := rfl}

/-- Lazy acquisition preserves the relation, including stale and duplicate acquisition guards. -/
theorem acquire_step_matches (encode : List U8 → String) (inj : Function.Injective encode)
    (sid : Nat) (n : Spike.engine.Store) (w : State) (id : U64) (m : Spike.engine.Bytes)
    (rel : StateMatches encode sid n w) (room : FitsAcquire n id)
    : WP.spec (Spike.engine.Store.execute n (.Acquire id m))
        (StepMatches encode sid (.acquire sid id.val (encode (alloc.vec.Vec.val m))) n
          (execute w (.acquire sid id.val (encode (alloc.vec.Vec.val m))))) := by
  obtain ⟨s, archive, hs, hh, hattempts⟩ := rel.history
  let key := encode (alloc.vec.Vec.val m)
  have bind_some {α β : Type} (x : α) (f : α → Option β) : (some x >>= f) = f x := rfl
  have refuse (bad : ∀ t, find n.txs.val id = some t →
      t.snapshot = none ∨ t.phase ≠ .Active ∨ (find (rustPinnedViews encode n.history t.views) key).isSome)
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
          t.snapshot = none ∨ t.phase ≠ .Active ∨ (find (rustPinnedViews encode n.history t.views) key).isSome)
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
                      (native_view_present encode sid n.history archive t tx view key hr
                        hm)
                      (Or.inr ∘ Or.inr) (by simp [execute, hlookup, hms, hm, hphase])
                | none =>
                    have hCut : snap.current.version = rustSnap.version.val := by
                      have he := hr.snapshot
                      rw [hms, hns] at he
                      exact congrArg Prod.fst (Option.some.inj he)
                    obtain ⟨prior, head, hf, _⟩ := hh.split
                    apply WP.spec_mono
                      (execute_acquire_matches_model encode inj n id w sid s tx t snap
                        rustSnap m prior head hf hh.frames hh.indexed hh.global
                        hh.revisions hn hlookup hns hms hCut hp hphase hr.views
                        hr.unavailable hm (hr.fresh_log hm) (room t hn) hh.valid hr.live
                        hr.nativeOrig)
                    rintro ⟨output, after⟩ ⟨modelAfter, txAfter, tAfter, obs, index, hstep, ho, hw, hv, hu,
                      han, ham, _, hhist, hidx, hrow, hLive, hOrig, hOther⟩
                    rw [hstep]
                    obtain ⟨out, hout, hc⟩ := acquire_observation encode output obs ho
                    refine ⟨
                      out,
                      hout,
                      OutputMatches.of_eq hc,
                      replace_attempt rel.unique hattempts hh id index t tAfter txAfter
                        hidx hrow
                        (congrArg State.txs hw)
                        (by rw [hw]; exact hs)
                        (by rw [hhist]; exact hh)
                        ?_
                        (reachable_execute rel.reachable hstep)
                        (HistoryKeeps.of_same (congrArg (fun h => h.log.frames) hhist)
                          (congrArg (fun h => h.index) hhist))
                        (fun _ hm => hm)
                    ⟩
                    · rw [hhist]
                      exact updated_relation encode sid n.history archive s snap rustSnap key t
                        tAfter tx txAfter hr hns hm hh.modelSub hh.modelArchive.emptyPresent
                        (selected_unique w sid s snap key rel.reachable hs)
                        hv hLive hOrig hOther hu han ham
              · have hm : (tx.phase != .active) = true := by
                  rw [hr.phase]
                  exact model_phase_inactive t.phase hp
                exact bad _ hp (Or.inr ∘ Or.inl)
                  (by simp only [execute, hlookup, bind_some, hms, hm, Bool.true_or,
                        ite_true])

end KvRust
