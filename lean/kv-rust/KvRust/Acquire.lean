-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Apply
public import KvRust.PinnedImage
public import KvRust.RetainedCuts

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
noncomputable def rustPinnedView (encode : List U8 → String)
    (history : Spike.engine.History) (map : Spike.engine.Bytes) (view : Spike.engine.View)
    : PinnedView :=
  {
    birth := view.birth.map modelStamp
    revision := modelStamp view.revision
    localImage := encodeImage encode (pinImage history map view.local)
    globalImage := encodeImage encode (pinImage history map (view.global.getD view.local))
  }

/-- Project the same map and its birth/revision stamps from the model's two pinned frames. -/
def modelPinnedView (m : String) (view : GlobalView) : PinnedView :=
  {
    birth := find view.current.births m
    revision := revision view.current m
    localImage := image view.current.data m
    globalImage := image view.frame.data m
  }

/-- Two pinned map handles have identical lineage stamps and permuted cell images. -/
structure PinnedViewOrderEq (a b : PinnedView) : Prop where
  birth : a.birth = b.birth
  revision : a.revision = b.revision
  localImage : a.localImage.Perm b.localImage
  globalImage : a.globalImage.Perm b.globalImage

theorem PinnedViewOrderEq.refl (v : PinnedView) : PinnedViewOrderEq v v :=
  ⟨rfl, rfl, .rfl, .rfl⟩

theorem PinnedViewOrderEq.symm {a b : PinnedView} (h : PinnedViewOrderEq a b)
    : PinnedViewOrderEq b a :=
  ⟨h.birth.symm, h.revision.symm, h.localImage.symm, h.globalImage.symm⟩

theorem PinnedViewOrderEq.trans {a b c : PinnedView} (ab : PinnedViewOrderEq a b)
    (bc : PinnedViewOrderEq b c)
    : PinnedViewOrderEq a c :=
  ⟨
    ab.birth.trans bc.birth,
    ab.revision.trans bc.revision,
    ab.localImage.trans bc.localImage,
    ab.globalImage.trans bc.globalImage
  ⟩

/-- Relate acquired view lists with identical map order and stamps, and permuted images. -/
def ViewsOrderEq (a b : Assoc String PinnedView) : Prop :=
  List.Forall₂ (fun x y => x.1 = y.1 ∧ PinnedViewOrderEq x.2 y.2) a b

theorem ViewsOrderEq.refl (rows : Assoc String PinnedView) : ViewsOrderEq rows rows :=
  List.forall₂_iff_get.mpr ⟨rfl, fun _ _ _ => ⟨rfl, .refl _⟩⟩

theorem ViewsOrderEq.symm {a b : Assoc String PinnedView} (h : ViewsOrderEq a b)
    : ViewsOrderEq b a := by
  induction h with
  | nil => exact .nil
  | @cons x y xs ys head _ ih => exact .cons ⟨head.1.symm, head.2.symm⟩ ih

theorem ViewsOrderEq.trans {a b c : Assoc String PinnedView} (ab : ViewsOrderEq a b)
    (bc : ViewsOrderEq b c)
    : ViewsOrderEq a c := by
  induction ab generalizing c with
  | nil => cases bc; exact .nil
  | @cons x y xs ys h1 _ ih =>
      cases bc with
      | cons h2 rest => exact .cons ⟨h1.1.trans h2.1, h1.2.trans h2.2⟩ (ih rest)

theorem ViewsOrderEq.find {a b : Assoc String PinnedView} (h : ViewsOrderEq a b)
    (m : String)
    : Option.Rel PinnedViewOrderEq (find a m) (find b m) := by
  induction h with
  | nil => exact .none
  | @cons x y xs ys head _ ih =>
      obtain ⟨kx, vx⟩ := x
      obtain ⟨ky, vy⟩ := y
      obtain ⟨hk, hv⟩ := head
      dsimp only at hk hv
      subst ky
      by_cases he : kx = m
      · simp [Kv.Model.find, he, hv]
      · simpa [Kv.Model.find, he] using ih

theorem ViewsOrderEq.set {a b : Assoc String PinnedView} (h : ViewsOrderEq a b)
    (m : String) {va vb : PinnedView} (hv : PinnedViewOrderEq va vb)
    : ViewsOrderEq (Kv.Model.set a m va) (Kv.Model.set b m vb) := by
  refine List.Forall₂.cons ⟨rfl, hv⟩ ?_
  unfold Kv.Model.erase
  induction h with
  | nil => exact .nil
  | @cons x y xs ys head _ ih =>
      obtain ⟨hk, hv'⟩ := head
      simp only [List.filter_cons, hk]
      split
      · exact List.Forall₂.cons ⟨hk, hv'⟩ ih
      · exact ih

/-- Every acquired Rust view originates either from an unborn map or from an
archived frame slot whose revision and ordered image match the pinned handle. -/
def ViewOrigin (encode : List U8 → String) (history : Spike.engine.History)
    (map : Spike.engine.Bytes) (view : Spike.engine.View)
    : Prop :=
  let m := encode (alloc.vec.Vec.val map)
  let img := encodeImage encode (pinImage history map view.local)
  match view.birth with
  | none => img = [] ∧ modelStamp view.revision = {}
  | some _ =>
      ∃ f,
        f ∈ history.log.frames.val
        ∧ revision (modelFrame encode history.index f) m = modelStamp view.revision
        ∧ img = image (modelFrame encode history.index f).data m

def ViewsOrigin (encode : List U8 → String) (history : Spike.engine.History)
    (rows : Spike.engine.Assoc Spike.engine.Bytes Spike.engine.View)
    : Prop :=
  ∀ row ∈ rows.val, ViewOrigin encode history row.1 row.2

/-- Relate the association lists of acquired views, including their order. -/
noncomputable def rustPinnedViews (encode : List U8 → String)
    (history : Spike.engine.History)
    (rows : Spike.engine.Assoc Spike.engine.Bytes Spike.engine.View)
    : Assoc String PinnedView :=
  rows.val.map
    fun (m, v) => (encode (alloc.vec.Vec.val m), rustPinnedView encode history m v)

def ViewLive (history : Spike.engine.History) (view : Spike.engine.View) : Prop :=
  PinLive history view.local ∧ PinLive history (view.global.getD view.local)

def ViewsLive (history : Spike.engine.History)
    (rows : Spike.engine.Assoc Spike.engine.Bytes Spike.engine.View)
    : Prop :=
  ∀ row ∈ rows.val, ViewLive history row.2

theorem pinned_views_preserved (encode : List U8 → String)
    {before after : Spike.engine.History} (preserved : HistoryKeeps before after)
    (valid : HistoryIndexValid before)
    (rows : Spike.engine.Assoc Spike.engine.Bytes Spike.engine.View)
    (live : ViewsLive before rows)
    : ViewsLive after rows
      ∧ rustPinnedViews encode after rows = rustPinnedViews encode before rows := by
  have localKept (row) (present : row ∈ rows.val) :=
    pin_preserved preserved valid row.1 row.2.local (live row present).1
  have globalKept (row) (present : row ∈ rows.val) :=
    pin_preserved preserved valid row.1 (row.2.global.getD row.2.local) (live row present).2
  constructor
  · intro row present
    exact ⟨(localKept row present).1, (globalKept row present).1⟩
  · unfold rustPinnedViews
    apply List.map_congr_left
    rintro ⟨m, v⟩ present
    simp [rustPinnedView, (localKept (m, v) present).2, (globalKept (m, v) present).2]

/-- Project the acquired model views in their original association-list order. -/
def modelPinnedViews (rows : Assoc String GlobalView) : Assoc String PinnedView :=
  rows.map fun (m, v) => (m, modelPinnedView m v)

theorem ViewsOrderEq.stamps {encode : List U8 → String} {history : Spike.engine.History}
    {modelViews : Assoc String GlobalView}
    {nativeViews : Spike.engine.Assoc Spike.engine.Bytes Spike.engine.View}
    (h
      : ViewsOrderEq (modelPinnedViews modelViews)
          (rustPinnedViews encode history nativeViews))
    : modelViews.map capturedStamps
      = nativeViews.val.map (viewStamps (encode ∘ alloc.vec.Vec.val)) := by
  unfold modelPinnedViews rustPinnedViews ViewsOrderEq at h
  generalize modelViews = ms at h
  generalize nativeViews.val = ns at h
  induction ms generalizing ns with
  | nil =>
      cases ns with
      | nil => rfl
      | cons _ _ => cases h
  | cons mrow mrest ih =>
      cases ns with
      | nil => cases h
      | cons nrow nrest =>
          obtain ⟨⟨hk, hv⟩, tail⟩ := List.forall₂_cons.mp h
          dsimp only [modelPinnedView, rustPinnedView] at hk hv
          have headEq : capturedStamps mrow = viewStamps (encode ∘ alloc.vec.Vec.val) nrow := by
            have hb : Kv.Model.find mrow.2.current.births mrow.1 = Option.map modelStamp nrow.2.birth := hv.birth
            have hr : revision mrow.2.current mrow.1 = modelStamp nrow.2.revision := hv.revision
            unfold capturedStamps viewStamps
            rw [hb, hr, hk]
            rfl
          exact congrArg₂ List.cons headEq (ih nrest tail)

theorem views_origin_preserved (encode : List U8 → String)
    {before after : Spike.engine.History} (preserved : HistoryKeeps before after)
    (valid : HistoryIndexValid before)
    (rows : Spike.engine.Assoc Spike.engine.Bytes Spike.engine.View)
    (live : ViewsLive before rows) (orig : ViewsOrigin encode before rows)
    : ViewsOrigin encode after rows := by
  intro ⟨m, v⟩ present
  have hpin := (pin_preserved preserved valid m v.local (live (m, v) present).1).2
  have ho := orig (m, v) present
  unfold ViewOrigin at ho ⊢
  dsimp only at ho ⊢
  rw [hpin]
  cases hb : v.birth with
  | none => simpa only [hb] using ho
  | some stamp =>
      rw [hb] at ho
      obtain ⟨f, hf, hrev, himg⟩ := ho
      obtain ⟨idx, hidx⟩ := List.mem_iff_getElem?.mp hf
      have hkept := preserved.slots idx f hidx
      have hrows := preserved.rows valid idx f hidx
      have hframe : modelFrame encode after.index f = modelFrame encode before.index f := by
        simp only [modelFrame, hrows]
      refine ⟨f, List.mem_iff_getElem?.mpr ⟨idx, hkept⟩, ?_, ?_⟩
      · rwa [hframe]
      · rwa [hframe]

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
  obtain ⟨birth, rev, localRows, globalRows⟩ := v
  cases globalRows <;> simp [Spike.engine.View.Insts.CoreCloneClone.clone, clone_pin]

private theorem install_view (encode : List U8 → String) (inj : Function.Injective encode)
    (history : Spike.engine.History)
    (rows : Spike.engine.Assoc Spike.engine.Bytes Spike.engine.View)
    (m : Spike.engine.Bytes) (v : Spike.engine.View) (room : rows.val.length < Usize.max)
    (oldLive : ViewsLive history rows) (newLive : ViewLive history v)
    (oldOrig : ViewsOrigin encode history rows) (newOrig : ViewOrigin encode history m v)
    : WP.spec
        (Spike.engine.Assoc.set Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
          Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.View.Insts.CoreCloneClone
          rows m v)
        (fun next =>
          rustPinnedViews encode history next
            = Kv.Model.set (rustPinnedViews encode history rows)
                (encode (alloc.vec.Vec.val m)) (rustPinnedView encode history m v)
          ∧ ViewsLive history next
          ∧ ViewsOrigin encode history next) := by
  apply WP.spec_mono (assoc_set Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
    Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.View.Insts.CoreCloneClone rows m v
    (fun a => key_same a m) clone_bytes clone_view room)
  intro next he
  refine ⟨?_, ?_, ?_⟩
  · unfold rustPinnedViews
    rw [he]
    exact (set_projected_with_key rows.val m v (encode ∘ alloc.vec.Vec.val)
      (rustPinnedView encode history) (map_encoding_injective encode inj)).symm
  · intro row member
    rw [he] at member
    rcases List.mem_cons.mp member with same | old
    · subst row
      exact newLive
    · exact oldLive row (List.mem_filter.mp old).1
  · intro row member
    rw [he] at member
    rcases List.mem_cons.mp member with same | old
    · subst row
      exact newOrig
    · exact oldOrig row (List.mem_filter.mp old).1

private theorem revision_frame (encode : List U8 → String)
    (inj : Function.Injective encode) (index : CellIndex)
    (f : Spike.engine.Frame) (m : Spike.engine.Bytes)
    : WP.spec (Spike.engine.Frame.revision f m)
        (fun r =>
          modelStamp r
          = revision (modelFrame encode index f) (encode (alloc.vec.Vec.val m))) :=
  revision_matches_model (encode ∘ alloc.vec.Vec.val) (map_encoding_injective encode inj)
    f m

private theorem pin_global_spec (encode : List U8 → String)
    (history : Spike.engine.History) (f : Spike.engine.Frame) (m : Spike.engine.Bytes)
    (id : Spike.branch_log.FrameId) (saved : history.log.frames.val[id.val]? = some f)
    (localCut globalCut : U64) (localPin : Spike.engine.PinnedImage)
    (localLive : PinLive history localPin)
    (shared
      : localCut = globalCut
        → encodeImage encode (pinImage history m localPin)
          = image (modelFrame encode history.index f).data (encode m.val))
    (inj : Function.Injective encode)
    : WP.spec (Spike.engine.pin_global id localCut globalCut)
        (fun globalPin =>
          encodeImage encode (pinImage history m (globalPin.getD localPin))
            = image (modelFrame encode history.index f).data (encode m.val)
          ∧ PinLive history (globalPin.getD localPin)) := by
  unfold Spike.engine.pin_global
  by_cases same : localCut = globalCut
  · simpa [same] using And.intro (shared same) localLive
  · simp only [same, ite_false, WP.spec_ok, Option.getD_some]
    refine ⟨?_, ⟨f, saved⟩⟩
    simpa [pinImage, saved, modelFrame]
      using (image_encoding encode inj (indexedCellData (indexRows history.index f.data))
              m.val).symm

private theorem pin_maps_spec (encode : List U8 → String)
    (inj : Function.Injective encode) (history : Spike.engine.History)
    (current global : Spike.engine.Frame) (m : Spike.engine.Bytes)
    (currentId globalId : Spike.branch_log.FrameId)
    (currentSaved : history.log.frames.val[currentId.val]? = some current)
    (globalSaved : history.log.frames.val[globalId.val]? = some global) (cut : U64)
    (share
      : cut.val ≤ history.global.val
        → image (modelFrame encode history.index current).data (encode m.val)
          = image (modelFrame encode history.index global).data (encode m.val))
    : WP.spec (Spike.engine.pin_maps history currentId globalId cut)
        (fun (localPin, globalPin) =>
          encodeImage encode (pinImage history m localPin)
            = image (modelFrame encode history.index current).data (encode m.val)
          ∧ encodeImage encode (pinImage history m (globalPin.getD localPin))
            = image (modelFrame encode history.index global).data (encode m.val)
          ∧ PinLive history localPin
          ∧ PinLive history (globalPin.getD localPin)) := by
  let localPin : Spike.engine.PinnedImage := .Frame currentId
  let globalPin : Spike.engine.PinnedImage := .Frame globalId
  have localLive : PinLive history localPin := ⟨current, currentSaved⟩
  have globalLive : PinLive history globalPin := ⟨global, globalSaved⟩
  have localRows : encodeImage encode (pinImage history m localPin) =
      image (modelFrame encode history.index current).data (encode m.val) := by
    simpa [pinImage, localPin, currentSaved, modelFrame]
      using (image_encoding encode inj
              (indexedCellData (indexRows history.index current.data)) m.val).symm
  have globalRows : encodeImage encode (pinImage history m globalPin) =
      image (modelFrame encode history.index global).data (encode m.val) := by
    simpa [pinImage, globalPin, globalSaved, modelFrame]
      using (image_encoding encode inj
              (indexedCellData (indexRows history.index global.data)) m.val).symm
  let post : Spike.engine.PinnedImage × Option Spike.engine.PinnedImage → Prop :=
    fun (l, g) =>
      encodeImage encode (pinImage history m l)
        = image (modelFrame encode history.index current).data (encode m.val)
      ∧ encodeImage encode (pinImage history m (g.getD l))
        = image (modelFrame encode history.index global).data (encode m.val)
      ∧ PinLive history l ∧ PinLive history (g.getD l)
  have fallback : WP.spec (do
      let g ← Spike.engine.pin_global globalId cut history.global
      Result.ok (localPin, g)) post := by
    apply WP.spec_bind (pin_global_spec encode history global m globalId globalSaved cut
      history.global localPin localLive (fun eq => localRows.trans (share (by rw [eq]))) inj)
    intro g ⟨rows, live⟩
    rw [WP.spec_ok]
    exact ⟨localRows, rows, localLive, live⟩
  unfold Spike.engine.pin_maps
  by_cases reusable : history.reuse_compacted_images = true
  · rw [ite_eq_left reusable]
    by_cases older : cut < history.global
    · rw [ite_eq_left older, WP.spec_ok]
      have past : cut.val ≤ history.global.val := Nat.le_of_lt older
      exact ⟨globalRows.trans (share past).symm, globalRows, globalLive, globalLive⟩
    · rw [ite_eq_right older]
      exact fallback
  · rw [ite_eq_right reusable]
    exact fallback

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
    (hframes : s.activeFrames = prior ++ [head])
    (hmodel : model.history = modelFrames s (modelFrame encode s.index))
    (hversions
      : ∀ i (hi : i < s.activeFrames.length),
          (modelFrame encode s.index s.activeFrames[i]).version = i)
    (hglobal : model.global = s.global.val) (hSnapshot : t.snapshot = some rustSnap)
    (stable : RevisionHistory model.history)
    (hCut : snap.current.version = rustSnap.version.val) (hPhase : t.phase = .Active)
    (hAbsent
      : find (rustPinnedViews encode s t.views) (encode (alloc.vec.Vec.val m)) = none)
    (hRoom : t.views.val.length < Usize.max)
    (valid : BranchValid s.log)
    (oldLive : ViewsLive s t.views)
    (oldOrig : ViewsOrigin encode s t.views)
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
              ∧ rustPinnedViews encode s views
                = Kv.Model.set (rustPinnedViews encode s t.views) k (modelPinnedView k v)
              ∧ ViewsLive s views
              ∧ ViewsOrigin encode s views
          else
            output = .Ok .Unavailable ∧ after = {t with unavailable := true}) := by
  let enc := encode ∘ alloc.vec.Vec.val (α := U8)
  let k := enc m
  let v := captureGlobal model snap k
  have hzero (cut : U64) : Spike.engine.History.relative_cut s cut = .ok cut :=
    history_relative_cut_zero s cut (by simp [hframes]) hversions valid
  change WP.spec (Spike.engine.Tx.acquire t s m) (fun (output, after) =>
    if available model snap k then
      ∃ localVer globalVer views,
        output = .Ok (.Acquired localVer globalVer) ∧
        localVer.val = (revision v.current k).version ∧ globalVer.val = (revision v.frame k).version ∧
        after = {t with views} ∧ rustPinnedViews encode s views =
          Kv.Model.set (rustPinnedViews encode s t.views) k (modelPinnedView k v)
        ∧ ViewsLive s views ∧ ViewsOrigin encode s views
    else output = .Ok .Unavailable ∧ after = {t with unavailable := true})
  have hi := map_encoding_injective encode inj
  change find (rustPinnedViews encode s t.views) k = none at hAbsent
  have hn : find t.views.val m = none := by
    have hm : find (rustPinnedViews encode s t.views) k =
        (find t.views.val m).map (rustPinnedView encode s m) :=
      find_projected_with_key t.views.val m enc (rustPinnedView encode s) hi
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
        (history_pin_cut_matches_model s rustSnap.version model
          (modelFrame encode s.index) hmodel (hzero rustSnap.version) hversions valid)
      rintro currentId ⟨current, currentSaved, hCurrent, hMem⟩
      apply WP.spec_bind (branch_read_refines s.log currentId current currentSaved)
      intro frame hf
      subst frame
      have hCutFrame : modelFrame encode s.index current = atCut model snap.current.version := by
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
              «local» := .Empty, global := none }
          have he : rustPinnedView encode s m empty = modelPinnedView k v := by
            simp [hView, empty, rustPinnedView, modelPinnedView, encodeImage, pinImage, modelStamp,
              revision, image, find]
          simp only [core.option.Option.is_none, Spike.engine.Stamp.zero,
            bind_ok]
          apply WP.spec_bind
            (install_view encode inj s t.views m empty hRoom oldLive ⟨trivial, trivial⟩
              oldOrig (by simp [ViewOrigin, empty, encodeImage, pinImage, modelStamp]))
          intro views ⟨hvers, hLive, hOrig⟩
          rw [WP.spec_ok]
          have hViews : rustPinnedViews encode s views =
              Kv.Model.set (rustPinnedViews encode s t.views) k (modelPinnedView k v) :=
            hvers.trans (congrArg (Kv.Model.set (rustPinnedViews encode s t.views) k) he)
          simp [hAv, hView, revision, find, hViews, hLive, hOrig]
      | some birth =>
          have hLocal : captureLocal model snap k = modelFrame encode s.index current := by
            simp [captureLocal, hb, hCutFrame]
          have hBorn
              : find (modelFrame encode s.index current).births k = some (modelStamp birth) := by
            simpa [hCutFrame] using hb
          have hLineage : mapLineage model (modelFrame encode s.index current) k = true :=
            lineage_of_mem _ _ _ hMem
          simp only [core.option.Option.is_none]
          apply WP.spec_bind
            (history_pin_cut_matches_model s s.global model (modelFrame encode s.index)
              hmodel (hzero s.global) hversions valid)
          rintro globalId ⟨global, globalSaved, hGlobalCut, _⟩
          apply WP.spec_bind (branch_read_refines s.log globalId global globalSaved)
          intro frame hf
          subst frame
          have hGlobal : modelFrame encode s.index global = atCut model model.global := by
            rw [hglobal]; exact hGlobalCut
          have hView
              : v
                = {
                  current := modelFrame encode s.index current, frame := modelFrame encode s.index global
                } := by
            simp [v, captureGlobal, hLocal, hBorn, hGlobal]
          apply WP.spec_bind (revision_frame encode inj s.index current m)
          intro localRev hl
          apply WP.spec_bind (revision_frame encode inj s.index global m)
          intro globalRev hgRev
          have hAv
              : available model snap k
                = decide (globalRev.version.val ≤ localRev.version.val) := by
            have hl' := congrArg Stamp.version hl
            have hg' := congrArg Stamp.version hgRev
            change localRev.version.val = (revision (modelFrame encode s.index current) k).version at hl'
            change globalRev.version.val = (revision (modelFrame encode s.index global) k).version at hg'
            simp [available, hLocal, mapAvailable, hBorn, hLineage, ← hGlobal, ← hl',
              ← hg']
          by_cases hOld : localRev.version < globalRev.version
          · have hlt : localRev.version.val < globalRev.version.val := hOld
            simp [hOld, hAv, Nat.not_le.mpr hlt]
          · rw [ite_eq_right hOld]
            have hle : globalRev.version.val ≤ localRev.version.val :=
              Nat.le_of_not_gt hOld
            have hShared (past : rustSnap.version.val ≤ s.global.val) :
                image (modelFrame encode s.index current).data (encode m.val) =
                  image (modelFrame encode s.index global).data (encode m.val) := by
              have avail : available model snap k = true := hAv.trans (decide_eq_true hle)
              have older : snap.current.version ≤ model.global := by rwa [hCut, hglobal]
              rcases available_compacted_image model stable snap k older avail with absent | same
              · rw [hLocal, hBorn] at absent
                cases absent
              · rw [hLocal, ← hGlobal] at same
                exact same
            apply WP.spec_bind
              (pin_maps_spec encode inj s current global m currentId globalId currentSaved
                globalSaved rustSnap.version hShared)
            rintro ⟨localPin, globalPin⟩ ⟨hLocalRows, hGlobalRows, localLive, globalLive⟩
            have newOrig : ViewOrigin encode s m
                {birth := some birth, revision := localRev, «local» := localPin, global := globalPin} := by
              refine ⟨current, List.mem_iff_getElem?.mpr ⟨currentId.val, currentSaved⟩, ?_, ?_⟩
              · exact hl.symm
              · exact hLocalRows
            apply WP.spec_bind
              (install_view encode inj s t.views m
                {
                  birth := some birth,
                  revision := localRev,
                  «local» := localPin,
                  global := globalPin
                } hRoom oldLive ⟨localLive, globalLive⟩ oldOrig newOrig)
            intro views ⟨hViews, hLive, hOrig⟩
            have hPin : rustPinnedView encode s m
                {birth := some birth, revision := localRev, «local» := localPin, global := globalPin} =
                  modelPinnedView k v := by
              change find (modelFrame encode s.index current).births (encode (alloc.vec.Vec.val m)) =
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
              hViews.trans ?_,
              hLive,
              hOrig
            ⟩
            · simpa [modelStamp, hView, k, enc] using congrArg Stamp.version hl
            · simpa [modelStamp, hView, k, enc] using congrArg Stamp.version hgRev
            · exact congrArg (Kv.Model.set (rustPinnedViews encode s t.views) k) hPin

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
        ∨ (find (rustPinnedViews encode s t.views) (encode (alloc.vec.Vec.val m))).isSome)
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
              : (find (rustPinnedViews encode s t.views)
                  (encode (alloc.vec.Vec.val m))).isSome :=
            disabled.resolve_left (by simp [hs]) |>.resolve_left (by simp [hp])
          simp only [Spike.engine.Tx.acquire, hs, hp, bind_ok]
          apply WP.spec_bind
            (assoc_index Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey t.views m
              (fun a => key_same a m))
          intro i hi
          cases i with
          | none =>
              have hfind := find_projected_with_key t.views.val m (encode ∘ alloc.vec.Vec.val)
                (rustPinnedView encode s) (map_encoding_injective encode inj)
              change find (rustPinnedViews encode s t.views) (encode (alloc.vec.Vec.val m)) =
                (find t.views.val m).map (rustPinnedView encode s m) at hfind
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
            ∨ (find (rustPinnedViews encode s.history t.views)
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
    (hframes : s.history.activeFrames = prior ++ [head])
    (hmodel
      : List.Forall₂ FrameOrderEq
          (modelFrames s.history (modelFrame encode s.history.index)) model.history)
    (hversions
      : ∀ i (hi : i < s.history.activeFrames.length),
          (modelFrame encode s.history.index s.history.activeFrames[i]).version = i)
    (hglobal : model.global = s.history.global.val)
    (stable : RevisionHistory (modelFrames s.history (modelFrame encode s.history.index)))
    (hNativeTx : find s.txs.val id = some t)
    (hLookup : lookupTx w sid id.val = some (model, tx))
    (hNativeSnap : t.snapshot = some rustSnap) (hModelSnap : tx.snapshot = some snap)
    (hCut : snap.current.version = rustSnap.version.val)
    (hNativePhase : t.phase = .Active) (hModelPhase : tx.phase = .active)
    (hPinned
      : ViewsOrderEq (modelPinnedViews tx.globalViews)
          (rustPinnedViews encode s.history t.views))
    (hUnavailable : tx.unavailable = t.unavailable)
    (hFresh : find tx.globalViews (encode (alloc.vec.Vec.val m)) = none)
    (hLog : tx.normal.log.all (fun op => op.map != encode (alloc.vec.Vec.val m)) = true)
    (hRoom : t.views.val.length < Usize.max)
    (valid : BranchValid s.history.log)
    (oldLive : ViewsLive s.history t.views)
    (oldOrig : ViewsOrigin encode s.history t.views)
    : WP.spec (Spike.engine.Store.execute s (.Acquire id m))
        (fun (output, after) =>
          ∃ modelAfter txAfter tAfter obs index,
            execute w (.acquire sid id.val (encode (alloc.vec.Vec.val m)))
              = some (modelAfter, obs)
            ∧ modelAcquisition output = some obs
            ∧ modelAfter = {w with txs := Kv.Model.set w.txs id.val txAfter}
            ∧ ViewsOrderEq (modelPinnedViews txAfter.globalViews)
                (rustPinnedViews encode s.history tAfter.views)
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
            ∧ after.txs.val = s.txs.val.set index (id, tAfter)
            ∧ ViewsLive s.history tAfter.views
            ∧ ViewsOrigin encode s.history tAfter.views
            ∧ ∀ other,
                other ≠ encode (alloc.vec.Vec.val m)
                → find (rustPinnedViews encode s.history tAfter.views) other
                  = find (rustPinnedViews encode s.history t.views) other) := by
  let k := encode (alloc.vec.Vec.val m)
  let v := captureGlobal model snap k
  let nativeModel : Store := {
    model with
      history := modelFrames s.history (modelFrame encode s.history.index)
      head := modelFrame encode s.history.index head
  }
  let nv := captureGlobal nativeModel snap k
  have hMissing : find (rustPinnedViews encode s.history t.views) k = none := by
    have rel := hPinned.find k
    rw [projected_view_missing tx.globalViews k hFresh] at rel
    cases h : find (rustPinnedViews encode s.history t.views) k with
    | none => rfl
    | some _ => rw [h] at rel; cases rel
  have hAvailEq : available nativeModel snap k = available model snap k :=
    history_order_eq_available (s := nativeModel) (t := model) hmodel rfl snap k
  have hCurEq : FrameOrderEq nv.current v.current := by
    have h1 : nv.current = captureLocal nativeModel snap k := by
      unfold nv captureGlobal
      dsimp only
      split <;> rfl
    have h2 : v.current = captureLocal model snap k := by
      unfold v captureGlobal
      dsimp only
      split <;> rfl
    rw [h1, h2]
    exact history_order_eq_captureLocal (s := nativeModel) (t := model) hmodel snap k
  have hFrameEq : FrameOrderEq nv.frame v.frame :=
    history_order_eq_captureGlobal_frame (s := nativeModel) (t := model) hmodel rfl snap k
  have hViewEq : PinnedViewOrderEq (modelPinnedView k v) (modelPinnedView k nv) :=
    ⟨(hCurEq.births k).symm, (hCurEq.revision_eq k).symm,
      (hCurEq.image_perm k).symm, (hFrameEq.image_perm k).symm⟩
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
        (acquire_matches_model encode inj s.history nativeModel t snap rustSnap m prior
          head hframes rfl hversions hglobal hNativeSnap stable hCut hNativePhase hMissing
          hRoom valid oldLive oldOrig)
      rintro ⟨out, next⟩ hn
      change (if available nativeModel snap k then
          ∃ localVer globalVer views,
            out = .Ok (.Acquired localVer globalVer) ∧
            localVer.val = (revision nv.current k).version ∧
            globalVer.val = (revision nv.frame k).version ∧
            next = {t with views} ∧
            rustPinnedViews encode s.history views =
              Kv.Model.set (rustPinnedViews encode s.history t.views) k (modelPinnedView k nv) ∧
            ViewsLive s.history views ∧
            ViewsOrigin encode s.history views
        else out = .Ok .Unavailable ∧ next = {t with unavailable := true}) at hn
      rw [hAvailEq] at hn
      have hupdate : (back (id, next)).val = s.txs.val.set i.val (id, next) := by
        rw [hback.2]
        exact alloc.vec.Vec.set_val_eq _ _ _
      change WP.spec (Result.ok (out, ({s with txs := back (id, next)} : Spike.engine.Store))) _
      rw [WP.spec_ok]
      by_cases ha : available model snap k
      · rw [ite_eq_left ha] at hn
        obtain ⟨lv, gv, views, hout, hl, hg, hNext, hViews, hLive, hOrig⟩ := hn
        have hl' : lv.val = (revision v.current k).version :=
          hl.trans (congrArg Stamp.version (hCurEq.revision_eq k))
        have hg' : gv.val = (revision v.frame k).version :=
          hg.trans (congrArg Stamp.version (hFrameEq.revision_eq k))
        let modelNext : Tx := {
          tx with
            globalViews := Kv.Model.set tx.globalViews k v
            data := pinData tx.data k v.current.data
        }
        refine ⟨{w with txs := Kv.Model.set w.txs id.val modelNext}, modelNext, next,
          .acquired lv.val gv.val, i.val, ?_, ?_, rfl, ?_, ?_, ?_, ?_, ?_, rfl, hrow, hupdate,
          ?_, ?_, ?_⟩
        · change execute w (.acquire sid id.val k) = _
          rw [hStep, ite_eq_left ha, ← hl', ← hg']
        · rw [hout]
          rfl
        · change ViewsOrderEq (modelPinnedViews (Kv.Model.set tx.globalViews k v))
            (rustPinnedViews encode s.history next.views)
          rw [model_pins_set, hNext, hViews]
          exact hPinned.set k hViewEq
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
        · rw [hNext]; exact hLive
        · rw [hNext]; exact hOrig
        · intro other hne
          rw [hNext, hViews, find_set_key]
          exact ite_eq_right hne
      · rw [ite_eq_right ha] at hn
        obtain ⟨hout, hNext⟩ := hn
        let modelNext := {tx with unavailable := true}
        refine ⟨{w with txs := Kv.Model.set w.txs id.val modelNext}, modelNext, next,
          .unavailable, i.val, ?_, ?_, rfl, ?_, ?_, ?_, ?_, ?_, rfl, hrow, hupdate, ?_, ?_, ?_⟩
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
        · rw [hNext]; exact oldLive
        · rw [hNext]; exact oldOrig
        · intro other _; rw [hNext]

end KvRust
