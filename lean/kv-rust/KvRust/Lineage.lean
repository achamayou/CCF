-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.History
public import KvRust.Validation

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Preserve both coordinates of a map's revision or birth identity. -/
def modelStamp (s : CcfKv.engine.Stamp) : Stamp :=
  {version := s.version.val, identity := s.identity.val}

/-- Project the map metadata. Data is supplied separately by the store relation. -/
def modelMetadata (encode : CcfKv.engine.Bytes → String) (f : CcfKv.engine.Frame)
    : Frame :=
  {
    version := f.version.val
    births := f.births.val.map fun (m, s) => (encode m, modelStamp s)
    revisions := f.revisions.val.map fun (m, s) => (encode m, modelStamp s)
  }

local instance : DecidableEq CcfKv.engine.Bytes :=
  fun a b =>
    decidable_of_iff (alloc.vec.Vec.val a = alloc.vec.Vec.val b)
      ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

/-- The extracted byte key comparison implements decidable equality. -/
theorem key_same [DecidableEq CcfKv.engine.Bytes] (a b : CcfKv.engine.Bytes)
    : CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey.same a b = .ok (decide (a = b)) := by
  rw [bytes_same, Result.ok.injEq]
  exact decide_eq_decide.mpr ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

private theorem stamp_same (a b : CcfKv.engine.Stamp)
    : CcfKv.engine.Stamp.same a b = .ok (modelStamp a == modelStamp b) := by
  have hv : a.version.val = b.version.val ↔ a.version = b.version :=
    ⟨UScalar.eq_of_val_eq, congrArg (fun v : U64 => v.val)⟩
  have hi : a.identity.val = b.identity.val ↔ a.identity = b.identity :=
    ⟨UScalar.eq_of_val_eq, congrArg (fun v : U64 => v.val)⟩
  change CcfKv.engine.Stamp.same a b =
    .ok ((a.version.val == b.version.val) && (a.identity.val == b.identity.val))
  by_cases h : a.version = b.version
  · simp [CcfKv.engine.Stamp.same, h, ← hi]
    by_cases he : a.identity.val = b.identity.val <;> simp [he]
  · simp [CcfKv.engine.Stamp.same, h, hv]

/-- Extracted stamp lookup commutes with the map-name and stamp projections. -/
theorem stamps_find (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode)
    (rows : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.Stamp)
    (m : CcfKv.engine.Bytes)
    : WP.spec
        (CcfKv.engine.Assoc.get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
          CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
          rows m)
        (fun r =>
          r.map modelStamp
          = find (rows.val.map fun (k, s) => (encode k, modelStamp s)) (encode m)) := by
  apply WP.spec_mono
    (assoc_get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
      CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone rows m
      (fun a => key_same a m) (fun _ => rfl))
  intro r hr
  rw [hr, find_projected rows.val m encode modelStamp inj]

/-- The extracted revision lookup uses the same zero stamp for absent revisions as the model. -/
theorem revision_matches_model (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode) (f : CcfKv.engine.Frame) (m : CcfKv.engine.Bytes)
    : WP.spec (CcfKv.engine.Frame.revision f m)
        (fun r => modelStamp r = revision (modelMetadata encode f) (encode m)) := by
  unfold CcfKv.engine.Frame.revision
  apply WP.spec_bind (stamps_find encode inj f.revisions m)
  intro r hr
  unfold revision
  change WP.spec _ (fun s => modelStamp s =
    (find (f.revisions.val.map fun (k, stamp) => (encode k, modelStamp stamp)) (encode m)).getD {})
  rw [← hr]
  cases r <;> simp [CcfKv.engine.Stamp.zero, modelStamp]

/-- Boolean match of a native frame's live metadata against a map's birth and revision stamps. -/
def frameMatches (encode : CcfKv.engine.Bytes → String) (f : CcfKv.engine.Frame)
    (m : CcfKv.engine.Bytes) (b : Option CcfKv.engine.Stamp) (r : CcfKv.engine.Stamp)
    : Bool :=
  f.meta_live
  && (find (modelMetadata encode f).births (encode m) == b.map modelStamp)
  && (revision (modelMetadata encode f) (encode m) == modelStamp r)

theorem frame_matches (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode) (f : CcfKv.engine.Frame) (m : CcfKv.engine.Bytes)
    (b : Option CcfKv.engine.Stamp) (r : CcfKv.engine.Stamp)
    : WP.spec (CcfKv.engine.Frame.matches_lineage f m b r)
        (fun result => result = frameMatches encode f m b r) := by
  unfold CcfKv.engine.Frame.matches_lineage frameMatches
  cases hm : f.meta_live with
  | false => simp
  | true =>
      simp only [ite_true, Bool.true_and]
      apply WP.spec_bind (stamps_find encode inj f.births m)
      intro a ha
      have hb : WP.spec (match a with
          | none => match b with
            | none => Result.ok true
            | some _ => Result.ok false
          | some x => match b with
            | none => Result.ok false
            | some y => CcfKv.engine.Stamp.same x y)
          (fun result => result = (a.map modelStamp == b.map modelStamp)) := by
        cases a <;> cases b <;> simp [stamp_same]
      apply WP.spec_bind hb
      intro result hresult
      have he : find (modelMetadata encode f).births (encode m) = a.map modelStamp := ha.symm
      cases result with
      | false => simp [he, ← hresult]
      | true =>
          simp only [ite_true, he, ← hresult, Bool.true_and]
          apply WP.spec_bind (revision_matches_model encode inj f m)
          intro actual hactual
          simp [stamp_same, hactual]

/-- Exact specification of `History.map_lineage` over live-metadata active frames. -/
theorem map_lineage_live_spec (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode) (s : CcfKv.engine.History) (m : CcfKv.engine.Bytes)
    (birth : Option CcfKv.engine.Stamp) (rev : CcfKv.engine.Stamp)
    (valid : BranchValid s.log)
    : WP.spec (CcfKv.engine.History.map_lineage s m birth rev)
        (fun result =>
          result = s.activeFrames.any (fun f => frameMatches encode f m birth rev)) := by
  let matchesFrame := fun f : CcfKv.engine.Frame => frameMatches encode f m birth rev
  unfold CcfKv.engine.History.map_lineage CcfKv.engine.History.map_lineage_loop
  apply WP.spec_bind (branch_active_len s.log valid)
  intro count hlen
  change count.val = s.activeFrames.length at hlen
  apply loop.spec_decr_nat (fun (i : Usize) => i.val)
    (fun i =>
      i.val ≤ s.activeFrames.length
      ∧ (s.activeFrames.take i.val).any matchesFrame = s.activeFrames.any matchesFrame)
    _ _ _
  · intro i ⟨bound, hinv⟩
    unfold CcfKv.engine.History.map_lineage_loop.body
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : (0#usize : Usize) < i
    · have pos : 0 < i.val := h
      rw [ite_eq_left h]
      apply WP.spec_bind (Usize.sub_spec (x := i) (y := 1#usize) (by omega))
      intro j hj
      have step : i.val = j.val + 1 := by omega
      have hi : j.val < s.activeFrames.length := by omega
      apply WP.spec_bind (branch_active_at s.log valid j s.activeFrames[j.val]
        (List.getElem?_eq_getElem hi))
      intro frame hf
      apply WP.spec_bind (frame_matches encode inj frame m birth rev)
      intro found hfound
      have htake : s.activeFrames.take i.val =
          s.activeFrames.take j.val ++ [s.activeFrames[j.val]] := by
        rw [step, List.take_succ_eq_append_getElem hi]
      rw [htake, List.any_append, List.any_cons, List.any_nil, Bool.or_false] at hinv
      have hmatch : found = matchesFrame s.activeFrames[j.val] := by
        simpa [matchesFrame, hf] using hfound
      cases found with
      | true =>
          simp only [ite_true, WP.spec_ok]
          simpa [← hmatch] using hinv.symm
      | false =>
          simp only [Bool.false_eq_true, ite_false, WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          simpa [← hmatch] using hinv
    · have zero : i.val = 0 := by
        have no : ¬ 0 < i.val := h
        omega
      rw [ite_eq_right h, WP.spec_ok]
      simpa [zero] using hinv.symm
  · exact ⟨Nat.le_of_eq hlen, by rw [hlen, List.take_length]⟩

/-- Search precisely the surviving branch for a frame with both of the captured map identities,
when all active frames retain live metadata. -/
theorem map_lineage_matches_model (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode) (s : CcfKv.engine.History) (m : CcfKv.engine.Bytes)
    (birth : Option CcfKv.engine.Stamp) (rev : CcfKv.engine.Stamp)
    (model : Store) (captured : Frame)
    (hBirth : find captured.births (encode m) = birth.map modelStamp)
    (hRev : revision captured (encode m) = modelStamp rev)
    (hHistory
      : model.history.map (fun f => (find f.births (encode m), revision f (encode m)))
        = (modelFrames s (modelMetadata encode)).map
            (fun f => (find f.births (encode m), revision f (encode m))))
    (hMetaLive : ∀ f ∈ s.activeFrames, f.meta_live = true)
    (valid : BranchValid s.log)
    : WP.spec (CcfKv.engine.History.map_lineage s m birth rev)
        (fun result => result = mapLineage model captured (encode m)) := by
  let matchesFrame := fun f : CcfKv.engine.Frame =>
    (find (modelMetadata encode f).births (encode m) == birth.map modelStamp) &&
      (revision (modelMetadata encode f) (encode m) == modelStamp rev)
  have hmodel : mapLineage model captured (encode m) = s.activeFrames.any matchesFrame := by
    let check := fun (p : Option Stamp × Stamp) =>
      (p.1 == birth.map modelStamp) && (p.2 == modelStamp rev)
    have h := congrArg (fun fs => List.any fs check) hHistory
    simpa [mapLineage, modelFrames, hBirth, hRev, Function.comp_def, check, matchesFrame]
      using h
  have hliveEq : s.activeFrames.any (fun f => frameMatches encode f m birth rev) =
      s.activeFrames.any matchesFrame := by
    apply Bool.eq_iff_iff.mpr
    simp only [List.any_eq_true]
    exact ⟨
      fun ⟨f, hf, h⟩ => ⟨f, hf, by simpa [frameMatches, matchesFrame, hMetaLive f hf] using h⟩,
      fun ⟨f, hf, h⟩ => ⟨f, hf, by simpa [frameMatches, matchesFrame, hMetaLive f hf] using h⟩
    ⟩
  apply WP.spec_mono (map_lineage_live_spec encode inj s m birth rev valid)
  intro result hr
  rw [hr, hliveEq, ← hmodel]

/-- Forget a frame's data for a comparison that only depends on its map stamps. -/
def onlyMetadata (f : Frame) : Frame := { f with data := [] }

/-- The model-independent projection of the captured map stamps. -/
def capturedStamps (view : String × GlobalView) : String × Option Stamp × Stamp :=
  (view.1, find view.2.current.births view.1, revision view.2.current view.1)

/-- Project the Rust map name, birth and revision from an acquired view. -/
def viewStamps (encode : CcfKv.engine.Bytes → String)
    (view : CcfKv.engine.Bytes × CcfKv.engine.View)
    : String × Option Stamp × Stamp :=
  (encode view.1, view.2.birth.map modelStamp, modelStamp view.2.revision)

def stampsOnBranch (model : Store) (stamps : String × Option Stamp × Stamp) : Bool :=
  model.history.any
    fun f =>
      (find f.births stamps.1 == stamps.2.1) && (revision f stamps.1 == stamps.2.2)

/-- The extracted lineage check covers every acquired map and distinguishes reused versions,
provided every acquired view still has a live-metadata match whenever the model branch matches. -/
theorem acquired_lineage_matches_model (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode) (s : CcfKv.engine.History) (t : CcfKv.engine.Tx)
    (model : Store) (tx : Tx)
    (hViewLive
      : ∀ row ∈ t.views.val,
          s.activeFrames.any
            (fun f => frameMatches encode f row.1 row.2.birth row.2.revision)
          = stampsOnBranch model (viewStamps encode row))
    (hViews : tx.globalViews.map capturedStamps = t.views.val.map (viewStamps encode))
    (valid : BranchValid s.log)
    : WP.spec (CcfKv.engine.Tx.valid_lineage t s)
        (fun r =>
          r = tx.globalViews.all (fun (m, view) => mapLineage model view.current m)) := by
  let check := stampsOnBranch model ∘ viewStamps encode
  have hall : t.views.val.all check =
      tx.globalViews.all (fun (m, view) => mapLineage model view.current m) := by
    have h := congrArg (fun xs => List.all xs (stampsOnBranch model)) hViews
    simpa [List.all_map, check, Function.comp_def, stampsOnBranch, capturedStamps,
      mapLineage]
      using h.symm
  rw [← hall]
  unfold CcfKv.engine.Tx.valid_lineage CcfKv.engine.Tx.valid_lineage_loop
  apply loop.spec_decr_nat (fun (i : Usize) => t.views.val.length - i.val)
    (fun i => (t.views.val.drop i.val).all check = t.views.val.all check) _ _ _
  · intro i hinv
    unfold CcfKv.engine.Tx.valid_lineage_loop.body
    have hlen : (alloc.vec.Vec.len t.views).val = t.views.val.length := alloc.vec.Vec.len_val _
    have hbound := alloc.vec.Vec.len_ineq t.views
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len t.views
    · have hi : i.val < t.views.val.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec t.views i hi)
      rintro ⟨m, view⟩ hv
      change WP.spec (do
        let b ← CcfKv.engine.History.map_lineage s m view.birth view.revision
        if b then
          let next ← i + 1#usize
          Result.ok (ControlFlow.cont next)
        else Result.ok (ControlFlow.done false)) _
      have hmem : (m, view) ∈ t.views.val := by
        rw [hv]; exact List.getElem_mem hi
      apply WP.spec_bind
        (map_lineage_live_spec encode inj s m view.birth view.revision valid)
      intro result hr
      have hr' : result = check (m, view) := by
        simpa [check, Function.comp_def] using hr.trans (hViewLive (m, view) hmem)
      have hstep := hinv
      rw [List.drop_eq_getElem_cons hi, ← hv, List.all_cons, ← hr'] at hstep
      cases result with
      | false => simpa using hstep
      | true =>
          simp only [ite_true]
          have hinc : i.val + (1#usize : Usize).val ≤ Usize.max := by omega
          apply WP.spec_bind (Usize.add_spec hinc)
          intro j hj
          have hj' : j.val = i.val + 1 := by omega
          simp only [WP.spec_ok]
          exact ⟨by simpa [hj'] using hstep, by omega⟩
    · have hi : t.views.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      rw [ite_eq_right h, WP.spec_ok]
      simpa [List.drop_eq_nil_of_le hi] using hinv
  · simp

/-- The extracted engine and the executable KV model agree on commit eligibility for related states. -/
theorem can_apply_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (s : CcfKv.engine.History) (t : CcfKv.engine.Tx)
    (model : Store) (tx : Tx) (prior : List CcfKv.engine.Frame)
    (head : CcfKv.engine.Frame) (hHead : s.activeFrames = prior ++ [head])
    (hViewLive
      : ∀ row ∈ t.views.val,
          s.activeFrames.any
            (fun f =>
              frameMatches (encode ∘ alloc.vec.Vec.val) f row.1 row.2.birth
                row.2.revision)
          = stampsOnBranch model (viewStamps (encode ∘ alloc.vec.Vec.val) row))
    (hViews
      : tx.globalViews.map capturedStamps
        = t.views.val.map (viewStamps (encode ∘ alloc.vec.Vec.val)))
    (rows : CellRows) (indexView : IndexView s.index head.data rows)
    (indexValid : IndexValid s.index)
    (room : ∀ d ∈ t.deps.val, DependencyRoom s.index rows d)
    (hData : model.head.data = encodeData encode (indexedCellData rows))
    (hDeps
      : tx.normal.deps.reverse
        = t.deps.val.map (encodeDependency encode ∘ byteDependency s.index))
    (hExact
      : validatesExact model.head.data tx.normal.deps
        = validates model.head.data tx.normal.deps)
    (hTerm : model.term = s.term.val)
    (hSnapshot
      : tx.snapshot.map Snapshot.term = t.snapshot.map (fun snap => snap.term.val))
    (hEmpty : t.snapshot = none → t.views.val = [])
    (hUnavailable : tx.unavailable = t.unavailable)
    (valid : BranchValid s.log)
    : WP.spec (CcfKv.engine.Tx.can_apply t s) (fun r => r = canApply model tx) := by
  have hinj : Function.Injective (encode ∘ alloc.vec.Vec.val (α := U8)) :=
    inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  have hl := acquired_lineage_matches_model (encode ∘ alloc.vec.Vec.val) hinj
    s t model tx hViewLive hViews valid
  have hd : WP.spec (CcfKv.engine.Tx.valid_dependencies t s)
      (fun r => r = validates model.head.data tx.normal.deps) := by
    have hv := validates_exact_encoding encode inj (indexedCellData rows)
      (t.deps.val.map (byteDependency s.index))
    have he : validates model.head.data tx.normal.deps =
        validatesExact (indexedCellData rows) (t.deps.val.map (byteDependency s.index)) := by
      rw [← hExact, ← hv, hData, List.map_map, ← hDeps]
      exact (List.all_reverse).symm
    rw [he]
    exact validate_dependencies_matches_model t s head rows indexView indexValid
      (by simp [history_head s prior head hHead valid]) room
  have hcheck : WP.spec (do
      let b ← CcfKv.engine.Tx.valid_lineage t s
      if b then CcfKv.engine.Tx.valid_dependencies t s else Result.ok false)
      (fun r => r = (tx.globalViews.all (fun (m, view) => mapLineage model view.current m)
        && validates model.head.data tx.normal.deps)) := by
    apply WP.spec_bind hl
    intro b hb
    cases b <;> simp [← hb, hd]
  unfold CcfKv.engine.Tx.can_apply
  by_cases hu : t.unavailable = true
  · simp [hu, canApply, hUnavailable]
  · simp only [hu]
    have hu' : t.unavailable = false := Bool.eq_false_of_not_eq_true hu
    cases hs : t.snapshot with
    | none =>
        have htv : tx.globalViews = [] := by simpa [hEmpty hs] using hViews
        cases hms : tx.snapshot with
        | some snap => simp [hms, hs] at hSnapshot
        | none =>
            simpa [hs, hu', canApply, hUnavailable, validLineage, hms, htv] using hcheck
    | some snap =>
        cases hms : tx.snapshot with
        | none => simp [hms, hs] at hSnapshot
        | some msnap =>
            have hst : msnap.term = snap.term.val := by simpa [hms, hs] using hSnapshot
            have htermEq : s.term.val = snap.term.val ↔ snap.term = s.term :=
              ⟨fun h => UScalar.eq_of_val_eq h.symm, fun h => congrArg (fun v : U64 => v.val) h.symm⟩
            by_cases ht : snap.term = s.term
            · have ht' := htermEq.mpr ht
              simpa [hs, ht, ht', hu', canApply, hUnavailable, validLineage, hms, hTerm,
                hst]
                using hcheck
            · have ht' : s.term.val ≠ snap.term.val := fun h => ht (htermEq.mp h)
              simp [ht, ht', hu', canApply, hUnavailable, validLineage, hms, hTerm, hst]

private theorem view_needs_frame_spec (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode) (row : CcfKv.engine.Bytes × CcfKv.engine.View)
    (frame globalFrame : CcfKv.engine.Frame)
    : WP.spec (CcfKv.engine.view_needs_frame row frame globalFrame)
        (fun r =>
          r
          = (frameMatches encode frame row.1 row.2.birth row.2.revision
              && !frameMatches encode globalFrame row.1 row.2.birth row.2.revision)) := by
  unfold CcfKv.engine.view_needs_frame
  rcases row with ⟨m, v⟩
  apply WP.spec_bind (frame_matches encode inj frame m v.birth v.revision)
  intro b hb
  cases b with
  | false => simp [← hb]
  | true =>
      simp only [ite_true]
      apply WP.spec_bind (frame_matches encode inj globalFrame m v.birth v.revision)
      intro b1 hb1
      simp [← hb, ← hb1]

private theorem tx_needs_frame_loop0_spec (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode)
    (views : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View)
    (frame globalFrame : CcfKv.engine.Frame)
    : WP.spec (CcfKv.engine.tx_needs_frame_loop0 views frame globalFrame 0#usize)
        (fun r =>
          r
          = views.val.any
              (fun row =>
                frameMatches encode frame row.1 row.2.birth row.2.revision
                && !frameMatches encode globalFrame row.1 row.2.birth
                      row.2.revision)) := by
  let pred := fun row : CcfKv.engine.Bytes × CcfKv.engine.View =>
    frameMatches encode frame row.1 row.2.birth row.2.revision
      && !frameMatches encode globalFrame row.1 row.2.birth row.2.revision
  unfold CcfKv.engine.tx_needs_frame_loop0
  apply loop.spec_decr_nat
    (fun s : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View × Usize =>
      views.val.length - s.2.val)
    (fun s => s.1 = views ∧ (views.val.drop s.2.val).any pred = views.val.any pred) _ _ _
  · rintro ⟨a, i⟩ ⟨ha, hinv⟩
    subst ha
    unfold CcfKv.engine.tx_needs_frame_loop0.body
    dsimp only
    have hlen : (alloc.vec.Vec.len a).val = a.val.length := alloc.vec.Vec.len_val _
    have hbound := alloc.vec.Vec.len_ineq a
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len a
    · have hi : i.val < a.val.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec a i hi)
      intro row hrow
      apply WP.spec_bind (view_needs_frame_spec encode inj row frame globalFrame)
      intro b hb
      have hstep := hinv
      rw [List.drop_eq_getElem_cons hi, ← hrow, List.any_cons] at hstep
      cases b with
      | true =>
          simp only [ite_true, WP.spec_ok]
          change true = pred row at hb
          rw [← hb, Bool.true_or] at hstep
          exact hstep
      | false =>
          simp only [Bool.false_eq_true, ite_false]
          apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
          intro j hj
          rw [WP.spec_ok]
          dsimp only
          change false = pred row at hb
          rw [← hb, Bool.false_or] at hstep
          have hj' : j.val = i.val + 1 := by omega
          exact ⟨⟨rfl, by simpa [hj'] using hstep⟩, by omega⟩
    · have hi : a.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      rw [ite_eq_right h, WP.spec_ok]
      simpa [pred, List.drop_eq_nil_of_le hi] using hinv
  · exact ⟨rfl, by simp⟩

private theorem tx_needs_frame_loop1_spec (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode)
    (views : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View)
    (frame globalFrame : CcfKv.engine.Frame)
    : WP.spec
        (CcfKv.engine.tx_needs_frame_loop1 views frame.version frame.data frame.revisions
          frame.births frame.meta_live globalFrame 0#usize)
        (fun r =>
          r
          = views.val.any
              (fun row =>
                frameMatches encode frame row.1 row.2.birth row.2.revision
                && !frameMatches encode globalFrame row.1 row.2.birth
                      row.2.revision)) := by
  let pred := fun row : CcfKv.engine.Bytes × CcfKv.engine.View =>
    frameMatches encode frame row.1 row.2.birth row.2.revision
      && !frameMatches encode globalFrame row.1 row.2.birth row.2.revision
  unfold CcfKv.engine.tx_needs_frame_loop1
  apply loop.spec_decr_nat
    (fun s : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View × Usize =>
      views.val.length - s.2.val)
    (fun s => s.1 = views ∧ (views.val.drop s.2.val).any pred = views.val.any pred) _ _ _
  · rintro ⟨a, i⟩ ⟨ha, hinv⟩
    subst ha
    unfold CcfKv.engine.tx_needs_frame_loop1.body
    dsimp only
    have hlen : (alloc.vec.Vec.len a).val = a.val.length := alloc.vec.Vec.len_val _
    have hbound := alloc.vec.Vec.len_ineq a
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len a
    · have hi : i.val < a.val.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec a i hi)
      intro row hrow
      have hframeEq :
          ({ version := frame.version, data := frame.data, revisions := frame.revisions,
             births := frame.births, meta_live := frame.meta_live } : CcfKv.engine.Frame) = frame := by
        cases frame; rfl
      rw [hframeEq]
      apply WP.spec_bind (view_needs_frame_spec encode inj row frame globalFrame)
      intro b hb
      have hstep := hinv
      rw [List.drop_eq_getElem_cons hi, ← hrow, List.any_cons] at hstep
      cases b with
      | true =>
          simp only [ite_true, WP.spec_ok]
          change true = pred row at hb
          rw [← hb, Bool.true_or] at hstep
          exact hstep
      | false =>
          simp only [Bool.false_eq_true, ite_false]
          apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
          intro j hj
          rw [WP.spec_ok]
          dsimp only
          change false = pred row at hb
          rw [← hb, Bool.false_or] at hstep
          have hj' : j.val = i.val + 1 := by omega
          exact ⟨⟨rfl, by simpa [hj'] using hstep⟩, by omega⟩
    · have hi : a.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      rw [ite_eq_right h, WP.spec_ok]
      simpa [pred, List.drop_eq_nil_of_le hi] using hinv
  · exact ⟨rfl, by simp⟩

theorem tx_needs_frame_spec (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode) (tx : CcfKv.engine.Tx)
    (frame globalFrame : CcfKv.engine.Frame)
    : WP.spec (CcfKv.engine.tx_needs_frame tx frame globalFrame)
        (fun r =>
          r
          = ((match tx.snapshot with
              | none => false
              | some snap => decide (snap.version = frame.version))
              || tx.views.val.any
                  (fun row =>
                    frameMatches encode frame row.1 row.2.birth row.2.revision
                    && !frameMatches encode globalFrame row.1 row.2.birth
                          row.2.revision))) := by
  unfold CcfKv.engine.tx_needs_frame
  cases hs : tx.snapshot with
  | none =>
      simpa using tx_needs_frame_loop0_spec encode inj tx.views frame globalFrame
  | some snap =>
      by_cases hv : snap.version = frame.version
      · simp [hv]
      · simp only [hv, ite_false, decide_false, Bool.false_or]
        exact tx_needs_frame_loop1_spec encode inj tx.views frame globalFrame

theorem txs_need_frame_spec (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode)
    (txs : CcfKv.engine.Assoc U64 CcfKv.engine.Tx)
    (frame globalFrame : CcfKv.engine.Frame)
    : WP.spec (CcfKv.engine.txs_need_frame txs frame globalFrame)
        (fun r =>
          r
          = txs.val.any
              (fun entry =>
                (match entry.2.snapshot with
                  | none => false
                  | some snap => decide (snap.version = frame.version))
                || entry.2.views.val.any
                    (fun row =>
                      frameMatches encode frame row.1 row.2.birth row.2.revision
                      && !frameMatches encode globalFrame row.1 row.2.birth
                            row.2.revision))) := by
  let pred := fun entry : U64 × CcfKv.engine.Tx =>
    (match entry.2.snapshot with
      | none => false
      | some snap => decide (snap.version = frame.version))
    || entry.2.views.val.any
        (fun row =>
          frameMatches encode frame row.1 row.2.birth row.2.revision
          && !frameMatches encode globalFrame row.1 row.2.birth row.2.revision)
  unfold CcfKv.engine.txs_need_frame CcfKv.engine.txs_need_frame_loop
  apply loop.spec_decr_nat
    (fun s : CcfKv.engine.Assoc U64 CcfKv.engine.Tx × Usize => txs.val.length - s.2.val)
    (fun s => s.1 = txs ∧ (txs.val.drop s.2.val).any pred = txs.val.any pred) _ _ _
  · rintro ⟨a, i⟩ ⟨ha, hinv⟩
    subst ha
    unfold CcfKv.engine.txs_need_frame_loop.body
    dsimp only
    have hlen : (alloc.vec.Vec.len a).val = a.val.length := alloc.vec.Vec.len_val _
    have hbound := alloc.vec.Vec.len_ineq a
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len a
    · have hi : i.val < a.val.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec a i hi)
      rintro ⟨tid, tx⟩ hrow
      apply WP.spec_bind (tx_needs_frame_spec encode inj tx frame globalFrame)
      intro b hb
      have hstep := hinv
      rw [List.drop_eq_getElem_cons hi, ← hrow, List.any_cons] at hstep
      cases b with
      | true =>
          simp only [ite_true, WP.spec_ok]
          change true = pred (tid, tx) at hb
          rw [← hb, Bool.true_or] at hstep
          exact hstep
      | false =>
          simp only [Bool.false_eq_true, ite_false]
          apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
          intro j hj
          rw [WP.spec_ok]
          dsimp only
          change false = pred (tid, tx) at hb
          rw [← hb, Bool.false_or] at hstep
          have hj' : j.val = i.val + 1 := by omega
          exact ⟨⟨rfl, by simpa [hj'] using hstep⟩, by omega⟩
    · have hi : a.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      rw [ite_eq_right h, WP.spec_ok]
      simpa [pred, List.drop_eq_nil_of_le hi] using hinv
  · exact ⟨rfl, by simp⟩

/-- When `txs_need_frame` returns `false`, no live transaction snapshots `frame.version`
or depends exclusively on `frame` (without `globalFrame` also matching) for lineage. -/
theorem txs_need_frame_false_spec (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode)
    (txs : CcfKv.engine.Assoc U64 CcfKv.engine.Tx)
    (frame globalFrame : CcfKv.engine.Frame)
    (hFalse : CcfKv.engine.txs_need_frame txs frame globalFrame = .ok false)
    : ∀ (id : U64) (t : CcfKv.engine.Tx),
        (id, t) ∈ txs.val
        → (∀ snap, t.snapshot = some snap → snap.version ≠ frame.version)
          ∧ (∀ bm bv,
              (bm, bv) ∈ t.views.val
              → frameMatches encode frame bm bv.birth bv.revision = true
              → frameMatches encode globalFrame bm bv.birth bv.revision = true) := by
  have hspec := txs_need_frame_spec encode inj txs frame globalFrame
  rw [hFalse, WP.spec_ok] at hspec
  have hnone : ∀ entry ∈ txs.val,
      ((match entry.2.snapshot with
        | none => false
        | some snap => decide (snap.version = frame.version))
      || entry.2.views.val.any
          (fun row =>
            frameMatches encode frame row.1 row.2.birth row.2.revision
            && !frameMatches encode globalFrame row.1 row.2.birth row.2.revision)) = false := by
    intro entry hmem
    have := List.any_eq_false.mp hspec.symm entry hmem
    simpa using this
  intro id t hmem
  have ht := hnone (id, t) hmem
  have hparts := Bool.or_eq_false_iff.mp ht
  refine ⟨?_, ?_⟩
  · intro snap hsnap heq
    have hs := hparts.1
    simp [hsnap, heq] at hs
  · intro bm bv hvm hmf
    have hv := List.any_eq_false.mp hparts.2 (bm, bv) hvm
    simp [hmf] at hv
    exact hv

end KvRust
