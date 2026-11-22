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
def modelStamp (s : Spike.engine.Stamp) : Stamp :=
  {version := s.version.val, identity := s.identity.val}

/-- Project the map metadata. Data is supplied separately by the store relation. -/
def modelMetadata (encode : Spike.engine.Bytes → String) (f : Spike.engine.Frame)
    : Frame :=
  {
    version := f.version.val
    births := f.births.val.map fun (m, s) => (encode m, modelStamp s)
    revisions := f.revisions.val.map fun (m, s) => (encode m, modelStamp s)
  }

local instance : DecidableEq Spike.engine.Bytes :=
  fun a b =>
    decidable_of_iff (alloc.vec.Vec.val a = alloc.vec.Vec.val b)
      ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

private theorem key_same (a b : Spike.engine.Bytes)
    : Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey.same a b = .ok (decide (a = b)) := by
  rw [bytes_same]
  congr 1

private theorem stamp_same (a b : Spike.engine.Stamp)
    : Spike.engine.Stamp.same a b = .ok (modelStamp a == modelStamp b) := by
  have hv : a.version.val = b.version.val ↔ a.version = b.version :=
    ⟨UScalar.eq_of_val_eq, congrArg (fun v : U64 => v.val)⟩
  have hi : a.identity.val = b.identity.val ↔ a.identity = b.identity :=
    ⟨UScalar.eq_of_val_eq, congrArg (fun v : U64 => v.val)⟩
  change Spike.engine.Stamp.same a b =
    .ok ((a.version.val == b.version.val) && (a.identity.val == b.identity.val))
  by_cases h : a.version = b.version
  · simp [Spike.engine.Stamp.same, h, ← hi]
    by_cases he : a.identity.val = b.identity.val <;> simp [he]
  · simp [Spike.engine.Stamp.same, h, hv]

private theorem stamps_find (encode : Spike.engine.Bytes → String)
    (inj : Function.Injective encode)
    (rows : Spike.engine.Assoc Spike.engine.Bytes Spike.engine.Stamp)
    (m : Spike.engine.Bytes)
    : WP.spec
        (Spike.engine.Assoc.get Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
          Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.Stamp.Insts.CoreCloneClone
          rows m)
        (fun r =>
          r.map modelStamp
          = find (rows.val.map fun (k, s) => (encode k, modelStamp s)) (encode m)) := by
  apply WP.spec_mono
    (assoc_get Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
      Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.Stamp.Insts.CoreCloneClone rows m
      (fun a => key_same a m) (fun _ => rfl))
  intro r hr
  rw [hr, find_projected rows.val m encode modelStamp inj]

/-- The extracted revision lookup uses the same zero stamp for absent revisions as the model. -/
theorem revision_matches_model (encode : Spike.engine.Bytes → String)
    (inj : Function.Injective encode) (f : Spike.engine.Frame) (m : Spike.engine.Bytes)
    : WP.spec (Spike.engine.Frame.revision f m)
        (fun r => modelStamp r = revision (modelMetadata encode f) (encode m)) := by
  unfold Spike.engine.Frame.revision
  apply WP.spec_bind (stamps_find encode inj f.revisions m)
  intro r hr
  unfold revision
  change WP.spec _ (fun s => modelStamp s =
    (find (f.revisions.val.map fun (k, stamp) => (encode k, modelStamp stamp)) (encode m)).getD {})
  rw [← hr]
  cases r <;> simp [Spike.engine.Stamp.zero, modelStamp]

private theorem frame_matches (encode : Spike.engine.Bytes → String)
    (inj : Function.Injective encode) (f : Spike.engine.Frame) (m : Spike.engine.Bytes)
    (b : Option Spike.engine.Stamp) (r : Spike.engine.Stamp)
    : WP.spec (Spike.engine.Frame.matches_lineage f m b r)
        (fun result =>
          result
          = ((find (modelMetadata encode f).births (encode m) == b.map modelStamp)
              && (revision (modelMetadata encode f) (encode m) == modelStamp r))) := by
  unfold Spike.engine.Frame.matches_lineage
  apply WP.spec_bind (stamps_find encode inj f.births m)
  intro a ha
  have hb : WP.spec (match a with
      | none => match b with
        | none => Result.ok true
        | some _ => Result.ok false
      | some x => match b with
        | none => Result.ok false
        | some y => Spike.engine.Stamp.same x y)
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

/-- Search precisely the surviving branch for a frame with both of the captured map identities. -/
theorem map_lineage_matches_model (encode : Spike.engine.Bytes → String)
    (inj : Function.Injective encode) (s : Spike.engine.History) (m : Spike.engine.Bytes)
    (birth : Option Spike.engine.Stamp) (rev : Spike.engine.Stamp)
    (model : Store) (captured : Frame)
    (hBirth : find captured.births (encode m) = birth.map modelStamp)
    (hRev : revision captured (encode m) = modelStamp rev)
    (hHistory
      : model.history.map (fun f => (find f.births (encode m), revision f (encode m)))
        = (modelFrames s (modelMetadata encode)).map
            (fun f => (find f.births (encode m), revision f (encode m))))
    : WP.spec (Spike.engine.History.map_lineage s m birth rev)
        (fun result => result = mapLineage model captured (encode m)) := by
  let matchesFrame := fun f : Spike.engine.Frame =>
    (find (modelMetadata encode f).births (encode m) == birth.map modelStamp) &&
      (revision (modelMetadata encode f) (encode m) == modelStamp rev)
  have hmodel : mapLineage model captured (encode m) = s.frames.val.any matchesFrame := by
    let check := fun (p : Option Stamp × Stamp) =>
      (p.1 == birth.map modelStamp) && (p.2 == modelStamp rev)
    have h := congrArg (fun fs => List.any fs check) hHistory
    simpa [mapLineage, modelFrames, hBirth, hRev, Function.comp_def, check, matchesFrame]
      using h
  rw [hmodel]
  unfold Spike.engine.History.map_lineage Spike.engine.History.map_lineage_loop
  apply loop.spec_decr_nat (fun (i : Usize) => s.frames.val.length - i.val)
    (fun i => (s.frames.val.drop i.val).any matchesFrame = s.frames.val.any matchesFrame)
    _ _ _
  · intro i hinv
    unfold Spike.engine.History.map_lineage_loop.body
    have hlen : (alloc.vec.Vec.len s.frames).val = s.frames.val.length := alloc.vec.Vec.len_val _
    have hbound := alloc.vec.Vec.len_ineq s.frames
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len s.frames
    · have hi : i.val < s.frames.val.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec s.frames i hi)
      intro frame hf
      apply WP.spec_bind (frame_matches encode inj frame m birth rev)
      intro result hr
      change result = matchesFrame frame at hr
      have hstep := hinv
      rw [List.drop_eq_getElem_cons hi, ← hf, List.any_cons, ← hr] at hstep
      cases result with
      | true => simpa using hstep
      | false =>
          simp only [Bool.false_eq_true, ite_false]
          have hinc : i.val + (1#usize : Usize).val ≤ Usize.max := by omega
          apply WP.spec_bind (Usize.add_spec hinc)
          intro j hj
          have hj' : j.val = i.val + 1 := by omega
          simp only [WP.spec_ok]
          exact ⟨by simpa [hj'] using hstep, by omega⟩
    · have hi : s.frames.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      rw [ite_eq_right h, WP.spec_ok]
      simpa [List.drop_eq_nil_of_le hi] using hinv
  · simp

/-- Forget a frame's data for a comparison that only depends on its map stamps. -/
def onlyMetadata (f : Frame) : Frame := { f with data := [] }

/-- The model-independent projection of the captured map stamps. -/
def capturedStamps (view : String × GlobalView) : String × Option Stamp × Stamp :=
  (view.1, find view.2.current.births view.1, revision view.2.current view.1)

/-- Project the Rust map name, birth and revision from an acquired view. -/
def viewStamps (encode : Spike.engine.Bytes → String)
    (view : Spike.engine.Bytes × Spike.engine.View)
    : String × Option Stamp × Stamp :=
  (encode view.1, view.2.birth.map modelStamp, modelStamp view.2.revision)

private def stampsOnBranch (model : Store) (stamps : String × Option Stamp × Stamp)
    : Bool :=
  model.history.any
    fun f =>
      (find f.births stamps.1 == stamps.2.1) && (revision f stamps.1 == stamps.2.2)

private theorem view_on_branch (encode : Spike.engine.Bytes → String)
    (inj : Function.Injective encode) (s : Spike.engine.History) (model : Store)
    (view : Spike.engine.Bytes × Spike.engine.View)
    (hHistory : model.history.map onlyMetadata = modelFrames s (modelMetadata encode))
    : WP.spec (Spike.engine.History.map_lineage s view.1 view.2.birth view.2.revision)
        (fun result => result = stampsOnBranch model (viewStamps encode view)) := by
  let frame : Frame := {
    births := match view.2.birth with
      | none => []
      | some stamp => [(encode view.1, modelStamp stamp)]
    revisions := [(encode view.1, modelStamp view.2.revision)]
  }
  have hb : find frame.births (encode view.1) = view.2.birth.map modelStamp := by
    cases h : view.2.birth <;> simp [frame, h, find]
  have hr : revision frame (encode view.1) = modelStamp view.2.revision := by
    simp [frame, revision, find]
  have hs := congrArg
    (List.map fun (f : Frame) => (find f.births (encode view.1), revision f (encode view.1))) hHistory
  simp only [List.map_map, Function.comp_def, onlyMetadata, revision] at hs
  have h := map_lineage_matches_model encode inj s view.1 view.2.birth view.2.revision model frame
    hb hr (by simpa only [revision] using hs)
  simpa [mapLineage, hb, hr, stampsOnBranch, viewStamps] using h

/-- The extracted lineage check covers every acquired map and distinguishes reused versions. -/
theorem acquired_lineage_matches_model (encode : Spike.engine.Bytes → String)
    (inj : Function.Injective encode) (s : Spike.engine.History) (t : Spike.engine.Tx)
    (model : Store) (tx : Tx)
    (hHistory : model.history.map onlyMetadata = modelFrames s (modelMetadata encode))
    (hViews : tx.globalViews.map capturedStamps = t.views.val.map (viewStamps encode))
    : WP.spec (Spike.engine.Tx.valid_lineage t s)
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
  unfold Spike.engine.Tx.valid_lineage Spike.engine.Tx.valid_lineage_loop
  apply loop.spec_decr_nat (fun (i : Usize) => t.views.val.length - i.val)
    (fun i => (t.views.val.drop i.val).all check = t.views.val.all check) _ _ _
  · intro i hinv
    unfold Spike.engine.Tx.valid_lineage_loop.body
    have hlen : (alloc.vec.Vec.len t.views).val = t.views.val.length := alloc.vec.Vec.len_val _
    have hbound := alloc.vec.Vec.len_ineq t.views
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len t.views
    · have hi : i.val < t.views.val.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec t.views i hi)
      rintro ⟨m, view⟩ hv
      change WP.spec (do
        let b ← Spike.engine.History.map_lineage s m view.birth view.revision
        if b then
          let next ← i + 1#usize
          Result.ok (ControlFlow.cont next)
        else Result.ok (ControlFlow.done false)) _
      apply WP.spec_bind (view_on_branch encode inj s model (m, view) hHistory)
      intro result hr
      change result = check (m, view) at hr
      have hstep := hinv
      rw [List.drop_eq_getElem_cons hi, ← hv, List.all_cons, ← hr] at hstep
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
    (inj : Function.Injective encode) (s : Spike.engine.History) (t : Spike.engine.Tx)
    (model : Store) (tx : Tx) (prior : List Spike.engine.Frame)
    (head : Spike.engine.Frame) (hHead : s.frames.val = prior ++ [head])
    (hHistory
      : model.history.map onlyMetadata
        = modelFrames s (modelMetadata (encode ∘ alloc.vec.Vec.val)))
    (hViews
      : tx.globalViews.map capturedStamps
        = t.views.val.map (viewStamps (encode ∘ alloc.vec.Vec.val)))
    (hData : model.head.data = encodeData encode (byteData head.data))
    (hDeps
      : tx.normal.deps.reverse
        = t.deps.val.map (encodeDependency encode ∘ byteDependency))
    (hTerm : model.term = s.term.val)
    (hSnapshot
      : tx.snapshot.map Snapshot.term = t.snapshot.map (fun snap => snap.term.val))
    (hEmpty : t.snapshot = none → t.views.val = [])
    (hUnavailable : tx.unavailable = t.unavailable)
    : WP.spec (Spike.engine.Tx.can_apply t s) (fun r => r = canApply model tx) := by
  have hinj : Function.Injective (encode ∘ alloc.vec.Vec.val (α := U8)) :=
    inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  have hl := acquired_lineage_matches_model (encode ∘ alloc.vec.Vec.val) hinj
    s t model tx hHistory hViews
  have hd : WP.spec (Spike.engine.Tx.valid_dependencies t head.data)
      (fun r => r = validates model.head.data tx.normal.deps) := by
    have hv := validates_encoding encode inj (byteData head.data) (t.deps.val.map byteDependency)
    have he : validates model.head.data tx.normal.deps =
        validates (byteData head.data) (t.deps.val.map byteDependency) := by
      rw [← hv, hData, List.map_map, ← hDeps]
      exact (List.all_reverse).symm
    rw [he]
    exact validate_dependencies_matches_model t head.data
  have hcheck : WP.spec (do
      let b ← Spike.engine.Tx.valid_lineage t s
      if b then
        let f ← Spike.engine.History.head s
        Spike.engine.Tx.valid_dependencies t f.data
      else Result.ok false)
      (fun r => r = (tx.globalViews.all (fun (m, view) => mapLineage model view.current m)
        && validates model.head.data tx.normal.deps)) := by
    apply WP.spec_bind hl
    intro b hb
    cases b <;> simp [← hb, history_head s prior head hHead, hd]
  unfold Spike.engine.Tx.can_apply
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

end KvRust
