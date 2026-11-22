-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Apply

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- The part of a map acquisition retained by Rust and observable in the model. -/
structure PinnedView where
  /-- The identity of the application that created this map, if it existed. -/
  birth : Option Stamp
  /-- The identity of the last application to change the local image. -/
  revision : Stamp
  /-- The ordered, versioned cells pinned for normal reads. -/
  localImage : Assoc String (Cell String)
  /-- The ordered, versioned cells pinned for global reads. -/
  globalImage : Assoc String (Cell String)

/-- Project a Rust handle without depending on the rest of either historical frame. -/
def rustPinnedView (encode : List U8 → String) (view : Spike.engine.View) : PinnedView :=
  {
    birth := view.birth.map modelStamp
    revision := modelStamp view.revision
    localImage := encodeImage encode (byteImage view.local)
    globalImage := encodeImage encode (byteImage view.global)
  }

/-- Project the same map and its birth/revision stamps from the model's two pinned frames. -/
def modelPinnedView (m : String) (view : GlobalView) : PinnedView :=
  {
    birth := find view.current.births m
    revision := revision view.current m
    localImage := image view.current.data m
    globalImage := image view.frame.data m
  }

/-- Relate the association lists of acquired views, including their order. -/
def rustPinnedViews (encode : List U8 → String)
    (rows : Spike.engine.Assoc Spike.engine.Bytes Spike.engine.View)
    : Assoc String PinnedView :=
  rows.val.map fun (m, v) => (encode (alloc.vec.Vec.val m), rustPinnedView encode v)

/-- Project the acquired model views in their original association-list order. -/
def modelPinnedViews (rows : Assoc String GlobalView) : Assoc String PinnedView :=
  rows.map fun (m, v) => (m, modelPinnedView m v)

/-- Projection cannot add a lookup binding for a map that was not acquired. -/
theorem projected_view_missing (rows : Assoc String GlobalView) (m : String)
    (h : find rows m = none)
    : find (modelPinnedViews rows) m = none := by
  induction rows with
  | nil => rfl
  | cons row rows ih =>
      obtain ⟨k, v⟩ := row
      by_cases he : k = m
      · simp [find, he] at h
      · simp [find, he, modelPinnedViews] at h ⊢
        exact ih h

private theorem model_pins_set (rows : Assoc String GlobalView) (m : String)
    (v : GlobalView)
    : modelPinnedViews (Kv.Model.set rows m v)
      = Kv.Model.set (modelPinnedViews rows) m (modelPinnedView m v) := by
  simp only [modelPinnedViews, Kv.Model.set, List.map_cons, erase, List.filter_map]
  rfl

private theorem image_filter_maps (db : Data) (map : String) (keep : String → Bool)
    : image (db.filter fun row => keep row.1.1) map
      = if keep map then image db map else [] := by
  unfold image
  rw [List.filterMap_filter]
  by_cases hk : keep map
  · rw [ite_eq_left hk]
    apply List.filterMap_congr
    rintro ⟨⟨m, key⟩, c⟩ _
    by_cases he : m = map
    · simp [he, hk]
    · simp [he]
  · rw [ite_eq_right hk]
    apply List.filterMap_eq_nil_iff.mpr
    rintro ⟨⟨m, key⟩, c⟩ _
    by_cases he : m = map
    · simp [he, hk]
    · simp [he]

/-- Pinning one map replaces its read image without changing any other map's image. -/
theorem pinned_data_image (db captured : Data) (m other : String)
    : image (pinData db m captured) other
      = if other = m then image captured other else image db other := by
  have happ : image ((db.filter fun row => row.1.1 != m) ++
      (captured.filter fun row => row.1.1 == m)) other =
      image (db.filter fun row => row.1.1 != m) other ++
      image (captured.filter fun row => row.1.1 == m) other := by
    simp only [image, List.filterMap_append]
  rw [pinData, happ, image_filter_maps db other (fun k => k != m),
    image_filter_maps captured other (fun k => k == m)]
  by_cases h : other = m <;> simp [h]

local instance : DecidableEq Spike.engine.Bytes :=
  fun a b =>
    decidable_of_iff (alloc.vec.Vec.val a = alloc.vec.Vec.val b)
      ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

private theorem map_encoding_injective (encode : List U8 → String)
    (inj : Function.Injective encode)
    : Function.Injective (encode ∘ alloc.vec.Vec.val (α := U8)) :=
  inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)

/-- Cloning a view preserves its pinned data and stamps. -/
theorem clone_view (v : Spike.engine.View)
    : Spike.engine.View.Insts.CoreCloneClone.clone v = .ok v := by
  cases v
  simp [Spike.engine.View.Insts.CoreCloneClone.clone, clone_assoc]

private theorem install_view (encode : List U8 → String) (inj : Function.Injective encode)
    (rows : Spike.engine.Assoc Spike.engine.Bytes Spike.engine.View)
    (m : Spike.engine.Bytes) (v : Spike.engine.View) (room : rows.val.length < Usize.max)
    : WP.spec
        (Spike.engine.Assoc.set Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
          Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.View.Insts.CoreCloneClone
          rows m v)
        (fun next =>
          rustPinnedViews encode next
          = Kv.Model.set (rustPinnedViews encode rows)
              (encode (alloc.vec.Vec.val m)) (rustPinnedView encode v)) := by
  apply WP.spec_mono (assoc_set Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
    Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.View.Insts.CoreCloneClone rows m v
    (fun a => key_same a m) clone_bytes clone_view room)
  intro next he
  unfold rustPinnedViews
  rw [he]
  exact (set_projected rows.val m v (encode ∘ alloc.vec.Vec.val)
    (rustPinnedView encode) (map_encoding_injective encode inj)).symm

private theorem revision_frame (encode : List U8 → String)
    (inj : Function.Injective encode) (f : Spike.engine.Frame) (m : Spike.engine.Bytes)
    : WP.spec (Spike.engine.Frame.revision f m)
        (fun r =>
          modelStamp r = revision (modelFrame encode f) (encode (alloc.vec.Vec.val m))) :=
  revision_matches_model (encode ∘ alloc.vec.Vec.val) (map_encoding_injective encode inj)
    f m

private theorem image_frame (encode : List U8 → String) (inj : Function.Injective encode)
    (f : Spike.engine.Frame) (m : Spike.engine.Bytes)
    : WP.spec (Spike.engine.image f.data m)
        (fun rows =>
          encodeImage encode (byteImage rows)
          = image (modelFrame encode f).data (encode (alloc.vec.Vec.val m))) := by
  apply WP.spec_mono (image_matches_model f.data m)
  intro rows h
  rw [h]
  exact (image_encoding encode inj (byteData f.data) (alloc.vec.Vec.val m)).symm

private theorem stamp_refl (stamp : Stamp) : (stamp == stamp) = true := by
  change (stamp.version == stamp.version && stamp.identity == stamp.identity) = true
  simp

private theorem lineage_of_mem (s : Store) (f : Frame) (m : String) (hf : f ∈ s.history)
    : mapLineage s f m = true := by
  unfold mapLineage
  apply List.any_eq_true.mpr
  refine ⟨f, hf, ?_⟩
  cases find f.births m <;> simp [stamp_refl]

/-- An enabled lazy acquisition pins the model's local and global views or flags unavailability. -/
theorem acquire_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (s : Spike.engine.History) (model : Store)
    (t : Spike.engine.Tx) (snap : Snapshot) (rustSnap : Spike.engine.Snapshot)
    (m : Spike.engine.Bytes) (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hframes : s.frames.val = prior ++ [head])
    (hmodel : model.history = modelFrames s (modelFrame encode))
    (hversions
      : ∀ i (hi : i < s.frames.val.length),
          (modelFrame encode s.frames.val[i]).version = i)
    (hglobal : model.global = s.global.val) (hSnapshot : t.snapshot = some rustSnap)
    (hCut : snap.current.version = rustSnap.version.val) (hPhase : t.phase = .Active)
    (hAbsent
      : find (rustPinnedViews encode t.views) (encode (alloc.vec.Vec.val m)) = none)
    (hRoom : t.views.val.length < Usize.max)
    : let k := encode (alloc.vec.Vec.val m)
      let v := captureGlobal model snap k
      WP.spec (Spike.engine.Tx.acquire t s m)
        (fun (output, after) =>
          if available model snap k then
            ∃ localVer globalVer views,
              output = .Ok (.Acquired localVer globalVer)
              ∧ localVer.val = (revision v.current k).version
              ∧ globalVer.val = (revision v.frame k).version
              ∧ after = {t with views}
              ∧ rustPinnedViews encode views
                = Kv.Model.set (rustPinnedViews encode t.views) k (modelPinnedView k v)
          else
            output = .Ok .Unavailable ∧ after = {t with unavailable := true}) := by
  let enc := encode ∘ alloc.vec.Vec.val (α := U8)
  let k := enc m
  let v := captureGlobal model snap k
  change WP.spec (Spike.engine.Tx.acquire t s m) (fun (output, after) =>
    if available model snap k then
      ∃ localVer globalVer views,
        output = .Ok (.Acquired localVer globalVer) ∧
        localVer.val = (revision v.current k).version ∧ globalVer.val = (revision v.frame k).version ∧
        after = {t with views} ∧ rustPinnedViews encode views =
          Kv.Model.set (rustPinnedViews encode t.views) k (modelPinnedView k v)
    else output = .Ok .Unavailable ∧ after = {t with unavailable := true})
  have hi := map_encoding_injective encode inj
  change find (rustPinnedViews encode t.views) k = none at hAbsent
  have hn : find t.views.val m = none := by
    have hm : find (rustPinnedViews encode t.views) k =
        (find t.views.val m).map (rustPinnedView encode) :=
      find_projected t.views.val m enc (rustPinnedView encode) hi
    rw [hAbsent] at hm
    cases e : find t.views.val m with
    | none => rfl
    | some view =>
        rw [e, Option.map_some] at hm
        cases hm
  simp only [Spike.engine.Tx.acquire, hSnapshot, hPhase, bind_ok]
  apply WP.spec_bind (assoc_index Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey t.views m
    (fun a => key_same a m))
  intro index hindex
  cases index with
  | some i => simp [hn] at hindex
  | none =>
      simp only [core.option.Option.is_some]
      apply WP.spec_bind
        (history_at_cut_matches_model s rustSnap.version model (modelFrame encode)
          prior head hframes hmodel hversions)
      intro current ⟨hCurrent, hMem⟩
      have hCutFrame : modelFrame encode current = atCut model snap.current.version := by
        rwa [hCut]
      apply WP.spec_bind (stamps_find enc hi current.births m)
      intro birth hbirth
      have hb
          : find (atCut model snap.current.version).births k = birth.map modelStamp := by
        rw [← hCutFrame]
        exact hbirth.symm
      cases birth with
      | none =>
          have hAv : available model snap k = true := by
            simp [available, captureLocal, hb, mapAvailable, image, find]
          have hView : v = {frame := {}} := by
            simp [v, captureGlobal, captureLocal, hb, find]
          let empty : Spike.engine.View :=
            { birth := none, revision := {version := 0#u64, identity := 0#u64}
              «local» := alloc.vec.Vec.new _, global := alloc.vec.Vec.new _ }
          have he : rustPinnedView encode empty = modelPinnedView k v := by
            simp [hView, empty, rustPinnedView, modelPinnedView, encodeImage, byteImage, modelStamp,
              revision, image, find]
          simp only [core.option.Option.is_none, Spike.engine.Stamp.zero,
            Spike.engine.Assoc.new, bind_ok]
          apply WP.spec_bind (install_view encode inj t.views m empty hRoom)
          intro views hvers
          rw [WP.spec_ok]
          have hViews : rustPinnedViews encode views =
              Kv.Model.set (rustPinnedViews encode t.views) k (modelPinnedView k v) :=
            hvers.trans (congrArg (Kv.Model.set (rustPinnedViews encode t.views) k) he)
          simp [hAv, hView, revision, find, hViews]
      | some birth =>
          have hLocal : captureLocal model snap k = modelFrame encode current := by
            simp [captureLocal, hb, hCutFrame]
          have hBorn
              : find (modelFrame encode current).births k = some (modelStamp birth) := by
            simpa [hCutFrame] using hb
          have hLineage : mapLineage model (modelFrame encode current) k = true :=
            lineage_of_mem _ _ _ hMem
          simp only [core.option.Option.is_none]
          apply WP.spec_bind
            (history_at_cut_matches_model s s.global model (modelFrame encode)
              prior head hframes hmodel hversions)
          intro global hg
          have hGlobal : modelFrame encode global = atCut model model.global := by
            rw [hglobal]; exact hg.1
          have hView
              : v
                = {
                  current := modelFrame encode current, frame := modelFrame encode global
                } := by
            simp [v, captureGlobal, hLocal, hBorn, hGlobal]
          apply WP.spec_bind (revision_frame encode inj current m)
          intro localRev hl
          apply WP.spec_bind (revision_frame encode inj global m)
          intro globalRev hgRev
          have hAv
              : available model snap k
                = decide (globalRev.version.val ≤ localRev.version.val) := by
            have hl' := congrArg Stamp.version hl
            have hg' := congrArg Stamp.version hgRev
            change localRev.version.val = (revision (modelFrame encode current) k).version at hl'
            change globalRev.version.val = (revision (modelFrame encode global) k).version at hg'
            simp [available, hLocal, mapAvailable, hBorn, hLineage, ← hGlobal, ← hl',
              ← hg']
          by_cases hOld : localRev.version < globalRev.version
          · have hlt : localRev.version.val < globalRev.version.val := hOld
            simp [hOld, hAv, Nat.not_le.mpr hlt]
          · rw [ite_eq_right hOld]
            apply WP.spec_bind (image_frame encode inj current m)
            intro localRows hLocalRows
            apply WP.spec_bind (image_frame encode inj global m)
            intro globalRows hGlobalRows
            apply WP.spec_bind
              (install_view encode inj t.views m
                {
                  birth := some birth,
                  revision := localRev,
                  «local» := localRows,
                  global := globalRows
                } hRoom)
            intro views hViews
            have hle : globalRev.version.val ≤ localRev.version.val :=
              Nat.le_of_not_gt hOld
            have hPin : rustPinnedView encode
                {birth := some birth, revision := localRev, «local» := localRows, global := globalRows} =
                  modelPinnedView k v := by
              change find (modelFrame encode current).births (encode (alloc.vec.Vec.val m)) =
                some (modelStamp birth) at hBorn
              simp [rustPinnedView, modelPinnedView, hView, hBorn, hl, hLocalRows, hGlobalRows, k, enc]
            rw [WP.spec_ok]
            refine (ite_eq_left (by simp [hAv, hle])).mpr ?_
            refine ⟨
              localRev.version,
              globalRev.version,
              views,
              rfl,
              ?_,
              ?_,
              rfl,
              hViews.trans ?_
            ⟩
            · simpa [modelStamp, hView, k, enc] using congrArg Stamp.version hl
            · simpa [modelStamp, hView, k, enc] using congrArg Stamp.version hgRev
            · exact congrArg (Kv.Model.set (rustPinnedViews encode t.views) k) hPin

/-- Compare the observable result of a completed acquisition, including both reported revisions. -/
def modelAcquisition (out : core.result.Result Spike.engine.Output Spike.engine.Error)
    : Option Output :=
  match out with
  | .Ok (.Acquired localVer globalVer) => some (.acquired localVer.val globalVer.val)
  | .Ok .Unavailable => some .unavailable
  | _ => none

private theorem option_bind_some {α β : Type} (x : α) (f : α → Option β)
    : (some x >>= f) = f x :=
  rfl

private theorem acquire_disabled (encode : List U8 → String)
    (inj : Function.Injective encode) (t : Spike.engine.Tx) (s : Spike.engine.History)
    (m : Spike.engine.Bytes)
    (disabled
      : t.snapshot = none
        ∨ t.phase ≠ .Active
        ∨ (find (rustPinnedViews encode t.views) (encode (alloc.vec.Vec.val m))).isSome)
    : WP.spec (Spike.engine.Tx.acquire t s m) (fun r => r = (.Err .Disabled, t)) := by
  cases hs : t.snapshot with
  | none => simp [Spike.engine.Tx.acquire, hs]
  | some snap =>
      have restore (phase : Spike.engine.Phase) (hp : t.phase = phase) :
          {t with snapshot := some snap, phase := phase} = t := by
        rw [← hs, ← hp]
      cases hp : t.phase with
      | Committing => simp [Spike.engine.Tx.acquire, hs, hp, restore _ hp]
      | Finished => simp [Spike.engine.Tx.acquire, hs, hp, restore _ hp]
      | Applied version => simp [Spike.engine.Tx.acquire, hs, hp, restore _ hp]
      | Active =>
          have hPresent
              : (find (rustPinnedViews encode t.views)
                  (encode (alloc.vec.Vec.val m))).isSome :=
            disabled.resolve_left (by simp [hs]) |>.resolve_left (by simp [hp])
          simp only [Spike.engine.Tx.acquire, hs, hp, bind_ok]
          apply WP.spec_bind
            (assoc_index Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey t.views m
              (fun a => key_same a m))
          intro i hi
          cases i with
          | none =>
              have hfind := find_projected t.views.val m (encode ∘ alloc.vec.Vec.val)
                (rustPinnedView encode) (map_encoding_injective encode inj)
              change find (rustPinnedViews encode t.views) (encode (alloc.vec.Vec.val m)) =
                (find t.views.val m).map (rustPinnedView encode) at hfind
              change find t.views.val m = none at hi
              rw [hfind, hi] at hPresent
              cases hPresent
          | some i => simp [restore _ hp]

/-- Acquiring without a live, active, uncaptured view leaves the store and all attempts unchanged. -/
theorem execute_acquire_disabled (encode : List U8 → String)
    (inj : Function.Injective encode) (s : Spike.engine.Store) (id : U64)
    (m : Spike.engine.Bytes)
    (disabled
      : ∀ t,
          find s.txs.val id = some t
          → t.snapshot = none
            ∨ t.phase ≠ .Active
            ∨ (find (rustPinnedViews encode t.views)
                (encode (alloc.vec.Vec.val m))).isSome)
    : WP.spec (Spike.engine.Store.execute s (.Acquire id m))
        (fun r => r = (.Err .Disabled, s)) := by
  unfold Spike.engine.Store.execute
  apply WP.spec_bind (tx_index s id)
  intro outcome hi
  cases outcome with
  | Err e =>
      obtain ⟨rfl, _⟩ := hi
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  | Ok i =>
      obtain ⟨t, hrow, hfound⟩ := hi
      obtain ⟨idx, hget⟩ := List.getElem?_eq_some_iff.mp hrow
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec s.txs i idx)
      rintro ⟨row, back⟩ hback
      have he : row = (id, t) := hback.1.trans hget
      subst row
      change WP.spec (do
        let (out, next) ← Spike.engine.Tx.acquire t s.history m
        Result.ok (out, {s with txs := back (id, next)})) _
      apply WP.spec_bind (acquire_disabled encode inj t s.history m (disabled t hfound))
      intro result hr
      subst result
      have hunchanged : back (id, t) = s.txs := by
        rw [hback.2]
        apply alloc.vec.Vec.ext
        rw [alloc.vec.Vec.set_val_eq, ← hget]
        exact List.set_getElem_self idx
      change WP.spec (Result.ok (core.result.Result.Err Spike.engine.Error.Disabled,
        ({s with txs := back (id, t)} : Spike.engine.Store))) _
      simp [hunchanged]

/-- The extracted dispatcher and `Kv.Model.execute` agree on an enabled acquisition and the updated attempt. -/
theorem execute_acquire_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (s : Spike.engine.Store) (id : U64) (w : State)
    (sid : Nat) (model : Store) (tx : Tx) (t : Spike.engine.Tx) (snap : Snapshot)
    (rustSnap : Spike.engine.Snapshot) (m : Spike.engine.Bytes)
    (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hframes : s.history.frames.val = prior ++ [head])
    (hmodel : model.history = modelFrames s.history (modelFrame encode))
    (hversions
      : ∀ i (hi : i < s.history.frames.val.length),
          (modelFrame encode s.history.frames.val[i]).version = i)
    (hglobal : model.global = s.history.global.val)
    (hNativeTx : find s.txs.val id = some t)
    (hLookup : lookupTx w sid id.val = some (model, tx))
    (hNativeSnap : t.snapshot = some rustSnap) (hModelSnap : tx.snapshot = some snap)
    (hCut : snap.current.version = rustSnap.version.val)
    (hNativePhase : t.phase = .Active) (hModelPhase : tx.phase = .active)
    (hPinned : modelPinnedViews tx.globalViews = rustPinnedViews encode t.views)
    (hUnavailable : tx.unavailable = t.unavailable)
    (hFresh : find tx.globalViews (encode (alloc.vec.Vec.val m)) = none)
    (hLog : tx.normal.log.all (fun op => op.map != encode (alloc.vec.Vec.val m)) = true)
    (hRoom : t.views.val.length < Usize.max)
    : WP.spec (Spike.engine.Store.execute s (.Acquire id m))
        (fun (output, after) =>
          ∃ modelAfter txAfter tAfter obs index,
            execute w (.acquire sid id.val (encode (alloc.vec.Vec.val m)))
              = some (modelAfter, obs)
            ∧ modelAcquisition output = some obs
            ∧ modelAfter = {w with txs := Kv.Model.set w.txs id.val txAfter}
            ∧ modelPinnedViews txAfter.globalViews = rustPinnedViews encode tAfter.views
            ∧ txAfter.unavailable = tAfter.unavailable
            ∧ (if available model snap (encode (alloc.vec.Vec.val m)) then
                  tAfter = {t with views := tAfter.views}
                else
                  tAfter = {t with unavailable := true})
            ∧ (if available model snap (encode (alloc.vec.Vec.val m)) then
                  txAfter
                  = {
                    tx with
                      globalViews :=
                        Kv.Model.set tx.globalViews (encode (alloc.vec.Vec.val m))
                          (captureGlobal model snap (encode (alloc.vec.Vec.val m)))
                      data :=
                        pinData tx.data (encode (alloc.vec.Vec.val m))
                          (captureLocal model snap (encode (alloc.vec.Vec.val m))).data
                  }
                else
                  txAfter = {tx with unavailable := true})
            ∧ (∀ other,
                image txAfter.data other
                = if available model snap (encode (alloc.vec.Vec.val m))
                      ∧ other = encode (alloc.vec.Vec.val m) then
                    image (captureLocal model snap (encode (alloc.vec.Vec.val m))).data
                      other
                  else
                    image tx.data other)
            ∧ after.history = s.history
            ∧ s.txs.val[index]? = some (id, t)
            ∧ after.txs.val = s.txs.val.set index (id, tAfter)) := by
  let k := encode (alloc.vec.Vec.val m)
  let v := captureGlobal model snap k
  have hMissing : find (rustPinnedViews encode t.views) k = none := by
    rw [← hPinned]
    exact projected_view_missing tx.globalViews k hFresh
  have hStep : execute w (.acquire sid id.val k) =
      if available model snap k then
        some ({w with txs := Kv.Model.set w.txs id.val {tx with
          globalViews := Kv.Model.set tx.globalViews k v
          data := pinData tx.data k v.current.data}},
          .acquired (revision v.current k).version (revision v.frame k).version)
      else some ({w with txs := Kv.Model.set w.txs id.val {tx with unavailable := true}},
        .unavailable) := by
    change find tx.globalViews k = none at hFresh
    change (tx.normal.log.all (fun op => op.map != k)) = true at hLog
    have hp : (Phase.active != Phase.active) = false := rfl
    simp only [execute, hLookup, option_bind_some, hModelSnap, hModelPhase, hp, hFresh,
      Option.isSome_none, Bool.false_or, hLog, Bool.not_true, Bool.false_eq_true, ite_false]
    rfl
  unfold Spike.engine.Store.execute
  apply WP.spec_bind (tx_index s id)
  intro outcome hi
  cases outcome with
  | Err _ => simp [hNativeTx] at hi
  | Ok i =>
      obtain ⟨old, hrow, ht⟩ := hi
      rw [hNativeTx] at ht
      cases ht
      obtain ⟨idx, hget⟩ := List.getElem?_eq_some_iff.mp hrow
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec s.txs i idx)
      rintro ⟨row, back⟩ hback
      have he : row = (id, t) := hback.1.trans hget
      subst row
      change WP.spec (do
        let (out, next) ← Spike.engine.Tx.acquire t s.history m
        Result.ok (out, {s with txs := back (id, next)})) _
      apply WP.spec_bind
        (acquire_matches_model encode inj s.history model t snap rustSnap m prior head
          hframes hmodel hversions hglobal hNativeSnap hCut hNativePhase hMissing hRoom)
      rintro ⟨out, next⟩ hn
      change (if available model snap k then
          ∃ localVer globalVer views,
            out = .Ok (.Acquired localVer globalVer) ∧
            localVer.val = (revision v.current k).version ∧
            globalVer.val = (revision v.frame k).version ∧
            next = {t with views} ∧
            rustPinnedViews encode views =
              Kv.Model.set (rustPinnedViews encode t.views) k (modelPinnedView k v)
        else out = .Ok .Unavailable ∧ next = {t with unavailable := true}) at hn
      have hupdate : (back (id, next)).val = s.txs.val.set i.val (id, next) := by
        rw [hback.2]
        exact alloc.vec.Vec.set_val_eq _ _ _
      change WP.spec (Result.ok (out, ({s with txs := back (id, next)} : Spike.engine.Store))) _
      rw [WP.spec_ok]
      by_cases ha : available model snap k
      · rw [ite_eq_left ha] at hn
        obtain ⟨lv, gv, views, hout, hl, hg, hNext, hViews⟩ := hn
        let modelNext : Tx := {
          tx with
            globalViews := Kv.Model.set tx.globalViews k v
            data := pinData tx.data k v.current.data
        }
        refine ⟨{w with txs := Kv.Model.set w.txs id.val modelNext}, modelNext, next,
          .acquired lv.val gv.val, i.val, ?_, ?_, rfl, ?_, ?_, ?_, ?_, ?_, rfl, hrow, hupdate⟩
        · change execute w (.acquire sid id.val k) = _
          rw [hStep, ite_eq_left ha, ← hl, ← hg]
        · rw [hout]
          rfl
        · change modelPinnedViews (Kv.Model.set tx.globalViews k v) = rustPinnedViews encode next.views
          rw [model_pins_set, hPinned, hNext]
          exact hViews.symm
        · rw [hNext]
          exact hUnavailable
        · change (if available model snap k then _ else _)
          rw [ite_eq_left ha, hNext]
        · change (if available model snap k then _ else _)
          rw [ite_eq_left ha]
          have hv : v.current = captureLocal model snap k := by
            change (captureGlobal model snap k).current = _
            by_cases hb : (find (captureLocal model snap k).births k).isNone <;>
              simp [captureGlobal, hb]
          simp only [modelNext, hv]
          rfl
        · intro other
          have he : v.current = captureLocal model snap k := by
            change (captureGlobal model snap k).current = _
            by_cases h : (find (captureLocal model snap k).births k).isNone <;>
              simp [captureGlobal, h]
          change image (pinData tx.data k v.current.data) other =
            (if available model snap k ∧ other = k
              then image (captureLocal model snap k).data other else image tx.data other)
          simp [pinned_data_image, he, ha]
      · rw [ite_eq_right ha] at hn
        obtain ⟨hout, hNext⟩ := hn
        let modelNext := {tx with unavailable := true}
        refine ⟨{w with txs := Kv.Model.set w.txs id.val modelNext}, modelNext, next,
          .unavailable, i.val, ?_, ?_, rfl, ?_, ?_, ?_, ?_, ?_, rfl, hrow, hupdate⟩
        · change execute w (.acquire sid id.val k) = _
          rw [hStep, ite_eq_right ha]
        · rw [hout]
          rfl
        · rw [hNext]
          exact hPinned
        · rw [hNext]
        · change (if available model snap k then _ else _)
          rw [ite_eq_right ha, hNext]
        · change (if available model snap k then _ else _)
          rw [ite_eq_right ha]
        · have ha' : ¬available model snap (encode (alloc.vec.Vec.val m)) = true := ha
          simp [modelNext, ha']

end KvRust
