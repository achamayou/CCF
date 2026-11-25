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
    (index : CellIndex) (map : CcfKv.engine.Bytes) (view : CcfKv.engine.View)
    : PinnedView :=
  {
    birth := view.birth.map modelStamp
    revision := modelStamp view.revision
    localImage := encodeImage encode (pinImage index map view.local)
    globalImage := encodeImage encode (pinImage index map (view.global.getD view.local))
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
archived ghost frame whose revision and ordered image match the pinned handle. -/
def ViewOrigin (encode : List U8 → String) (index : CellIndex) (natArchive : List Frame)
    (map : CcfKv.engine.Bytes) (view : CcfKv.engine.View)
    : Prop :=
  let m := encode (alloc.vec.Vec.val map)
  let img := encodeImage encode (pinImage index map view.local)
  match view.birth with
  | none => img = [] ∧ modelStamp view.revision = {}
  | some _ =>
      ∃ f ∈ natArchive, revision f m = modelStamp view.revision ∧ img = image f.data m

def ViewsOrigin (encode : List U8 → String) (index : CellIndex) (natArchive : List Frame)
    (rows : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View)
    : Prop :=
  ∀ row ∈ rows.val, ViewOrigin encode index natArchive row.1 row.2

/-- Relate the association lists of acquired views, including their order. -/
noncomputable def rustPinnedViews (encode : List U8 → String)
    (index : CellIndex)
    (rows : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View)
    : Assoc String PinnedView :=
  rows.val.map
    fun (m, v) => (encode (alloc.vec.Vec.val m), rustPinnedView encode index m v)

def ViewLive (index : CellIndex) (view : CcfKv.engine.View) : Prop :=
  PinLive index view.local ∧ PinLive index (view.global.getD view.local)

def ViewsLive (index : CellIndex)
    (rows : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View)
    : Prop :=
  ∀ row ∈ rows.val, ViewLive index row.2

def ViewScanRoom (index : CellIndex) (view : CcfKv.engine.View) : Prop :=
  PinScanRoom index view.local ∧ PinScanRoom index (view.global.getD view.local)

def ViewsScanRoom (index : CellIndex)
    (rows : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View)
    : Prop :=
  ∀ row ∈ rows.val, ViewScanRoom index row.2

theorem pinned_views_preserved_of_pins (encode : List U8 → String)
    {before after : CellIndex} {pins : List U32}
    (preserved : IndexPreservesPins before after pins)
    (rows : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View)
    (inPins : ∀ row ∈ rows.val, ∀ r ∈ viewPins row.2, r ∈ pins)
    (live : ViewsLive before rows)
    : ViewsLive after rows
      ∧ rustPinnedViews encode after rows = rustPinnedViews encode before rows := by
  have localKept (row) (present : row ∈ rows.val) :=
    pin_preserved_of_pins preserved row.1 row.2.local
      (fun r hr => inPins row present r (by unfold viewPins; exact List.mem_append_left _ hr))
      (live row present).1
  have globalKept (row) (present : row ∈ rows.val) :=
    pin_preserved_of_pins preserved row.1 (row.2.global.getD row.2.local)
      (fun r hr => by
        cases hg : row.2.global with
        | none =>
            rw [hg] at hr
            exact inPins row present r
              (by unfold viewPins; exact List.mem_append_left _ hr)
        | some g =>
            rw [hg] at hr
            exact inPins row present r
              (by unfold viewPins; rw [hg]; exact List.mem_append_right _ hr))
      (live row present).2
  constructor
  · intro row present
    exact ⟨(localKept row present).1, (globalKept row present).1⟩
  · unfold rustPinnedViews
    apply List.map_congr_left
    rintro ⟨m, v⟩ present
    simp [rustPinnedView, (localKept (m, v) present).2, (globalKept (m, v) present).2]

theorem pinned_views_preserved (encode : List U8 → String)
    {before after : CellIndex} (preserved : IndexKeeps before after)
    (rows : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View)
    (live : ViewsLive before rows)
    : ViewsLive after rows
      ∧ rustPinnedViews encode after rows = rustPinnedViews encode before rows := by
  have localKept (row) (present : row ∈ rows.val) :=
    pin_preserved preserved row.1 row.2.local (live row present).1
  have globalKept (row) (present : row ∈ rows.val) :=
    pin_preserved preserved row.1 (row.2.global.getD row.2.local) (live row present).2
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

theorem ViewsOrderEq.stamps {encode : List U8 → String} {index : CellIndex}
    {modelViews : Assoc String GlobalView}
    {nativeViews : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View}
    (h
      : ViewsOrderEq (modelPinnedViews modelViews)
          (rustPinnedViews encode index nativeViews))
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

theorem views_origin_preserved_of_pins (encode : List U8 → String)
    {before after : CellIndex} {pins : List U32} {archBefore archAfter : List Frame}
    (preserved : IndexPreservesPins before after pins)
    (sub : ∀ f ∈ archBefore, f ∈ archAfter)
    (rows : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View)
    (inPins : ∀ row ∈ rows.val, ∀ r ∈ viewPins row.2, r ∈ pins)
    (live : ViewsLive before rows) (orig : ViewsOrigin encode before archBefore rows)
    : ViewsOrigin encode after archAfter rows := by
  intro ⟨m, v⟩ present
  have hpin := (pin_preserved_of_pins preserved m v.local
    (fun r hr => inPins (m, v) present r (by unfold viewPins; exact List.mem_append_left _ hr))
    (live (m, v) present).1).2
  have ho := orig (m, v) present
  unfold ViewOrigin at ho ⊢
  dsimp only at ho ⊢
  rw [hpin]
  cases hb : v.birth with
  | none => simpa only [hb] using ho
  | some stamp =>
      rw [hb] at ho
      obtain ⟨f, hf, hrev, himg⟩ := ho
      exact ⟨f, sub f hf, hrev, himg⟩

theorem views_origin_preserved (encode : List U8 → String)
    {before after : CellIndex} {archBefore archAfter : List Frame}
    (preserved : IndexKeeps before after)
    (sub : ∀ f ∈ archBefore, f ∈ archAfter)
    (rows : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View)
    (live : ViewsLive before rows) (orig : ViewsOrigin encode before archBefore rows)
    : ViewsOrigin encode after archAfter rows := by
  intro ⟨m, v⟩ present
  have hpin := (pin_preserved preserved m v.local (live (m, v) present).1).2
  have ho := orig (m, v) present
  unfold ViewOrigin at ho ⊢
  dsimp only at ho ⊢
  rw [hpin]
  cases hb : v.birth with
  | none => simpa only [hb] using ho
  | some stamp =>
      rw [hb] at ho
      obtain ⟨f, hf, hrev, himg⟩ := ho
      exact ⟨f, sub f hf, hrev, himg⟩

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

local instance : DecidableEq CcfKv.engine.Bytes :=
  fun a b =>
    decidable_of_iff (alloc.vec.Vec.val a = alloc.vec.Vec.val b)
      ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

private theorem map_encoding_injective (encode : List U8 → String)
    (inj : Function.Injective encode)
    : Function.Injective (encode ∘ alloc.vec.Vec.val (α := U8)) :=
  inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)

/-- Cloning a view preserves its pinned data and stamps. -/
theorem clone_view (v : CcfKv.engine.View)
    : CcfKv.engine.View.Insts.CoreCloneClone.clone v = .ok v := by
  obtain ⟨birth, rev, localRows, globalRows⟩ := v
  cases globalRows <;> simp [CcfKv.engine.View.Insts.CoreCloneClone.clone, clone_pin]

private theorem install_view (encode : List U8 → String) (inj : Function.Injective encode)
    (index : CellIndex) (natArchive : List Frame)
    (rows : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.View)
    (m : CcfKv.engine.Bytes) (v : CcfKv.engine.View) (room : rows.val.length < Usize.max)
    (absent : find rows.val m = none)
    (oldLive : ViewsLive index rows) (newLive : ViewLive index v)
    (oldOrig : ViewsOrigin encode index natArchive rows)
    (newOrig : ViewOrigin encode index natArchive m v)
    : WP.spec
        (CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
          CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.View.Insts.CoreCloneClone
          rows m v)
        (fun next =>
          next.val = (m, v) :: rows.val
          ∧ rustPinnedViews encode index next
            = Kv.Model.set (rustPinnedViews encode index rows)
                (encode (alloc.vec.Vec.val m)) (rustPinnedView encode index m v)
          ∧ ViewsLive index next
          ∧ ViewsOrigin encode index natArchive next) := by
  apply WP.spec_mono
    (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
      CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.View.Insts.CoreCloneClone rows
      m v (fun a => key_same a m) clone_bytes clone_view room)
  intro next he
  have hcons : next.val = (m, v) :: rows.val := by
    have herase : Kv.Model.erase rows.val m = rows.val := by
      unfold Kv.Model.erase
      apply List.filter_eq_self.mpr
      intro r hr
      have hne : r.1 ≠ m := by
        intro hEq
        have hsome : (find rows.val m).isSome = true := by
          clear he absent
          generalize rows.val = rs at hr
          induction rs with
          | nil => cases hr
          | cons hd tl ih =>
              rcases List.mem_cons.mp hr with rfl | htl
              · simp [find, hEq]
              · by_cases h1 : hd.1 = m
                · simp [find, h1]
                · simpa [find, h1] using ih htl
        rw [absent] at hsome
        cases hsome
      show decide (r.1 ≠ m) = true
      exact decide_eq_true hne
    rw [he, Kv.Model.set, herase]
  refine ⟨hcons, ?_, ?_, ?_⟩
  · unfold rustPinnedViews
    rw [he]
    exact (set_projected_with_key rows.val m v (encode ∘ alloc.vec.Vec.val)
      (rustPinnedView encode index) (map_encoding_injective encode inj)).symm
  · intro row member
    rw [hcons] at member
    rcases List.mem_cons.mp member with rfl | old
    · exact newLive
    · exact oldLive row old
  · intro row member
    rw [hcons] at member
    rcases List.mem_cons.mp member with rfl | old
    · exact newOrig
    · exact oldOrig row old

private theorem revision_frame (encode : List U8 → String)
    (inj : Function.Injective encode) (index : CellIndex)
    (f : CcfKv.engine.Frame) (m : CcfKv.engine.Bytes)
    : WP.spec (CcfKv.engine.Frame.revision f m)
        (fun r =>
          modelStamp r
          = revision (modelFrame encode index f) (encode (alloc.vec.Vec.val m))) :=
  revision_matches_model (encode ∘ alloc.vec.Vec.val) (map_encoding_injective encode inj)
    f m

private theorem revision_meta_eq {encode : List U8 → String} {index : CellIndex}
    {nf : CcfKv.engine.Frame} {gf : Frame} (hm : FrameMetaEq encode nf gf) (k : String)
    : revision (modelFrame encode index nf) k = revision gf k := by
  unfold revision modelFrame
  rw [hm.2.1]

private theorem births_meta_eq {encode : List U8 → String} {index : CellIndex}
    {nf : CcfKv.engine.Frame} {gf : Frame} (hm : FrameMetaEq encode nf gf) (k : String)
    : find (modelFrame encode index nf).births k = find gf.births k := by
  unfold modelFrame
  rw [hm.2.2]

private theorem frame_root_ref {s : CcfKv.engine.History} {extraPins : List U32}
    {f : CcfKv.engine.Frame}
    (live : IndexLiveness s.index (framePins s.activeFrames ++ extraPins))
    (hmemAct : f ∈ s.activeFrames)
    : f.data ≠ 0#u32
      → SingleLinkLive s.index.values.dirs.val s.index.values.rows.val f.data
        ∧ radixReferences s.index.values.dirs.val
            (framePins s.activeFrames ++ extraPins) f.data
          > 0 := by
  intro hnz
  have hmem : f.data ∈ framePins s.activeFrames ++ extraPins :=
    List.mem_append_left extraPins
      (List.mem_filterMap.mpr ⟨f, hmemAct, by simp [hnz]⟩)
  refine ⟨live.pinsLive f.data hmem, ?_⟩
  rw [radixReferences_eq]
  exact List.count_pos_iff.mpr (List.mem_append_left _ hmem)

private theorem pin_maps_spec (encode : List U8 → String)
    (inj : Function.Injective encode) (history : CcfKv.engine.History)
    (current global : CcfKv.engine.Frame) (gfLocal gfGlobal : Frame)
    (m : CcfKv.engine.Bytes) (extraPins : List U32)
    (localRef : CcfKv.engine.CutRef) (globalOff : Usize) (cut : U64)
    (valid : BranchValid history.log) (idxValid : HistoryIndexValid history)
    (live : IndexLiveness history.index (framePins history.activeFrames ++ extraPins))
    (globalSaved : history.activeFrames[globalOff.val]? = some global)
    (localSpec
      : match localRef with
        | .Active off =>
            history.activeFrames[off.val]? = some current
            ∧ modelFrame encode history.index current = gfLocal
        | .Retained idx =>
            history.retained.val[idx.val]? = some current
            ∧ history.reuse_compacted_images = true
            ∧ cut < history.global)
    (hglobalLive : modelFrame encode history.index global = gfGlobal)
    (share
      : cut.val ≤ history.global.val
        → image gfLocal.data (encode m.val) = image gfGlobal.data (encode m.val))
    (refRoom
      : (framePins history.activeFrames ++ extraPins).length
          + 17 * history.index.values.dirs.val.length
          + 2
        ≤ U32.max)
    : WP.spec (CcfKv.engine.pin_maps history localRef globalOff cut)
        (fun ((localPin, globalPin), after) =>
          after.log = history.log
          ∧ after.retained = history.retained
          ∧ after.global = history.global
          ∧ after.term = history.term
          ∧ after.next_identity = history.next_identity
          ∧ after.reuse_compacted_images = history.reuse_compacted_images
          ∧ after.index.values = history.index.values
          ∧ IndexLiveness after.index
              (pinPins localPin
                ++ (match globalPin with
                    | none => []
                    | some g => pinPins g)
                ++ (framePins history.activeFrames ++ extraPins))
          ∧ encodeImage encode (pinImage after.index m localPin)
            = image gfLocal.data (encode m.val)
          ∧ encodeImage encode (pinImage after.index m (globalPin.getD localPin))
            = image gfGlobal.data (encode m.val)
          ∧ PinLive after.index localPin
          ∧ PinLive after.index (globalPin.getD localPin)) := by
  let pins0 := framePins history.activeFrames ++ extraPins
  have hglobalMem : global ∈ history.activeFrames := List.mem_of_getElem? globalSaved
  have hglobalView : IndexView history.index global.data (indexRows history.index global.data) :=
    idxValid.active global hglobalMem
  have hglobalRows : encodeImage encode (pinImage history.index m (.Root global.data)) =
      image gfGlobal.data (encode m.val) := by
    rw [← hglobalLive]
    simpa [pinImage, modelFrame]
      using (image_encoding encode inj
              (indexedCellData (indexRows history.index global.data)) m.val).symm
  have hrefGlobal : global.data ≠ 0#u32 → radixReferences history.index.values.dirs.val pins0 global.data < U32.max := by
    intro _
    have h1 := owners_count_le_bound history.index.values.dirs.val pins0 global.data
    have h2 : pins0.length + 17 * history.index.values.dirs.val.length + 2 ≤ U32.max := refRoom
    rw [radixReferences_eq]
    exact Nat.lt_of_le_of_lt h1 (by omega)
  have hfallback : ¬ (history.reuse_compacted_images = true ∧ cut < history.global) →
      WP.spec (do
        let f ← CcfKv.engine.History.read_cut history localRef
        let ai ← CcfKv.kv_index.AddressIndex.retain_root history.index f.data
        if cut = history.global then
          Result.ok ((CcfKv.engine.PinnedImage.Root f.data, none), { history with index := ai })
        else do
          let f1 ← CcfKv.branch_log.BranchLog.active_at history.log globalOff
          let ai1 ← CcfKv.kv_index.AddressIndex.retain_root ai f1.data
          Result.ok ((CcfKv.engine.PinnedImage.Root f.data, some (CcfKv.engine.PinnedImage.Root f1.data)),
            { history with index := ai1 }))
        (fun ((localPin, globalPin), after) =>
          after.log = history.log
          ∧ after.retained = history.retained
          ∧ after.global = history.global
          ∧ after.term = history.term
          ∧ after.next_identity = history.next_identity
          ∧ after.reuse_compacted_images = history.reuse_compacted_images
          ∧ after.index.values = history.index.values
          ∧ IndexLiveness after.index
              (pinPins localPin ++ (match globalPin with | none => [] | some g => pinPins g) ++ pins0)
          ∧ encodeImage encode (pinImage after.index m localPin) = image gfLocal.data (encode m.val)
          ∧ encodeImage encode (pinImage after.index m (globalPin.getD localPin))
              = image gfGlobal.data (encode m.val)
          ∧ PinLive after.index localPin
          ∧ PinLive after.index (globalPin.getD localPin)) := by
    intro hnotOld
    cases localRef with
    | Retained idx =>
        exact (hnotOld ⟨localSpec.2.1, localSpec.2.2⟩).elim
    | Active off =>
        obtain ⟨hcurSaved, hcurLive⟩ := localSpec
        have hcurMem : current ∈ history.activeFrames := List.mem_of_getElem? hcurSaved
        have hlocalView : IndexView history.index current.data (indexRows history.index current.data) :=
          idxValid.active current hcurMem
        have hlocalRows : encodeImage encode (pinImage history.index m (.Root current.data)) =
            image gfLocal.data (encode m.val) := by
          rw [← hcurLive]
          simpa [pinImage, modelFrame]
            using (image_encoding encode inj
                    (indexedCellData (indexRows history.index current.data)) m.val).symm
        have hrefLocal : current.data ≠ 0#u32 → radixReferences history.index.values.dirs.val pins0 current.data < U32.max := by
          intro _
          have h1 := owners_count_le_bound history.index.values.dirs.val pins0 current.data
          have h2 : pins0.length + 17 * history.index.values.dirs.val.length + 2 ≤ U32.max := refRoom
          rw [radixReferences_eq]
          exact Nat.lt_of_le_of_lt h1 (by omega)
        apply WP.spec_bind (history_read_cut_active history off current valid hcurSaved)
        intro fRead hfRead; subst fRead
        apply WP.spec_bind
          (index_retain_root_refines history.index pins0 current.data live
            (frame_root_ref live hcurMem) hrefLocal)
        intro ai1 ⟨hvals1, hlive1⟩
        have hk1 : IndexKeeps history.index ai1 := by unfold IndexKeeps; rw [hvals1]; exact .refl _
        have hlocalPres1 := pin_preserved hk1 m (.Root current.data) hlocalView
        by_cases hsame : cut = history.global
        · rw [ite_eq_left hsame, WP.spec_ok]
          have hlive1' : IndexLiveness ai1 (pinPins (.Root current.data) ++ [] ++ pins0) := by
            by_cases hz : current.data = 0#u32 <;> simpa [pinPins, hz] using hlive1
          refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, hvals1, hlive1', ?_, ?_, hlocalPres1.1, hlocalPres1.1⟩
          · rw [hlocalPres1.2]; exact hlocalRows
          · simp only [Option.getD_none]; rw [hlocalPres1.2, hlocalRows]; exact share (by rw [hsame])
        · rw [ite_eq_right hsame]
          apply WP.spec_bind (branch_active_at history.log valid globalOff global globalSaved)
          intro fRead2 hfRead2; subst fRead2
          let pins1 := if current.data = 0#u32 then pins0 else current.data :: pins0
          have hrefGlobal1 : global.data ≠ 0#u32 →
              SingleLinkLive ai1.values.dirs.val ai1.values.rows.val global.data
              ∧ radixReferences ai1.values.dirs.val pins1 global.data > 0 := by
            intro hnz
            have hmem0 : global.data ∈ pins0 :=
              List.mem_append_left extraPins (List.mem_filterMap.mpr ⟨global, hglobalMem, by simp [hnz]⟩)
            have hmem1 : global.data ∈ pins1 := by
              dsimp [pins1]; split
              · exact hmem0
              · exact List.mem_cons_of_mem _ hmem0
            refine ⟨hlive1.pinsLive global.data hmem1, ?_⟩
            rw [radixReferences_eq]
            exact List.count_pos_iff.mpr (List.mem_append_left _ hmem1)
          have hrefRoom1 : global.data ≠ 0#u32 → radixReferences ai1.values.dirs.val pins1 global.data < U32.max := by
            intro _
            have h1 := owners_count_le_bound ai1.values.dirs.val pins1 global.data
            have hlen1 : pins1.length ≤ pins0.length + 1 := by
              by_cases hcz : current.data = 0#u32 <;> simp [pins1, hcz]
            have h2 : pins0.length + 17 * history.index.values.dirs.val.length + 2 ≤ U32.max := refRoom
            rw [hvals1] at h1 ⊢
            rw [radixReferences_eq]
            exact Nat.lt_of_le_of_lt h1 (by omega)
          apply WP.spec_bind
            (index_retain_root_refines ai1 pins1 global.data hlive1 hrefGlobal1 hrefRoom1)
          intro ai2 ⟨hvals2, hlive2⟩
          change WP.spec (Result.ok _) _
          rw [WP.spec_ok]
          have hk2 : IndexKeeps history.index ai2 := by
            unfold IndexKeeps; rw [hvals2, hvals1]; exact .refl _
          have hlocalPres2 := pin_preserved hk2 m (.Root current.data) hlocalView
          have hglobalPres2 := pin_preserved hk2 m (.Root global.data) hglobalView
          have hlive2' : IndexLiveness ai2
              (pinPins (.Root current.data) ++ pinPins (.Root global.data) ++ pins0) := by
            by_cases hcz : current.data = 0#u32 <;> by_cases hgz : global.data = 0#u32
            · simpa [pinPins, pins1, hcz, hgz] using hlive2
            · simpa [pinPins, pins1, hcz, hgz] using hlive2
            · simpa [pinPins, pins1, hcz, hgz] using hlive2
            · simp only [pinPins, pins1, hcz, hgz, ite_false, List.cons_append, List.nil_append] at hlive2 ⊢
              exact hlive2.perm (List.Perm.swap current.data global.data pins0)
          refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, hvals2.trans hvals1, hlive2', ?_, ?_, hlocalPres2.1, hglobalPres2.1⟩
          · rw [hlocalPres2.2]; exact hlocalRows
          · simp only [Option.getD_some]; rw [hglobalPres2.2]; exact hglobalRows
  unfold CcfKv.engine.pin_maps
  by_cases reusable : history.reuse_compacted_images = true
  · rw [ite_eq_left reusable]
    by_cases older : cut < history.global
    · rw [ite_eq_left older]
      apply WP.spec_bind (branch_active_at history.log valid globalOff global globalSaved)
      intro fRead hfRead; subst fRead
      apply WP.spec_bind
        (index_retain_root_refines history.index pins0 global.data live
          (frame_root_ref live hglobalMem) hrefGlobal)
      intro ai1 ⟨hvals1, hlive1⟩
      change WP.spec (Result.ok _) _
      rw [WP.spec_ok]
      have hk1 : IndexKeeps history.index ai1 := by unfold IndexKeeps; rw [hvals1]; exact .refl _
      have hglobalPres1 := pin_preserved hk1 m (.Root global.data) hglobalView
      have hlive1' : IndexLiveness ai1 (pinPins (.Root global.data) ++ [] ++ pins0) := by
        by_cases hz : global.data = 0#u32 <;> simpa [pinPins, hz] using hlive1
      have past : cut.val ≤ history.global.val := Nat.le_of_lt older
      refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, hvals1, hlive1', ?_, ?_, hglobalPres1.1, hglobalPres1.1⟩
      · rw [hglobalPres1.2]; exact hglobalRows.trans (share past).symm
      · simp only [Option.getD_none]; rw [hglobalPres1.2]; exact hglobalRows
    · rw [ite_eq_right older]
      exact hfallback (fun h => older h.2)
  · rw [ite_eq_right reusable]
    exact hfallback (fun h => reusable h.1)

private theorem find_reverse_ver_indexed (xs : List Frame) (cut : Nat)
    (hpos : 0 < xs.length)
    (hver : ∀ (v : Nat) gf, xs[v]? = some gf → gf.version = v)
    : xs.reverse.find? (fun f => decide (f.version ≤ cut))
      = xs[min cut (xs.length - 1)]? := by
  induction xs using List.reverseRecOn with
  | nil => simp at hpos
  | append_singleton p last ih =>
      rw [List.reverse_append, List.reverse_singleton, List.singleton_append, List.find?_cons]
      have hlast : last.version = p.length :=
        hver p.length last (by rw [List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]; rfl)
      have hpver : ∀ (v : Nat) gf, p[v]? = some gf → gf.version = v := fun v gf hgv =>
        hver v gf (by
          have hv : v < p.length := (List.getElem?_eq_some_iff.mp hgv).1
          rw [List.getElem?_append_left hv]; exact hgv)
      by_cases hc : p.length ≤ cut
      · simp only [hlast, hc, decide_true, List.length_append, List.length_singleton,
          Nat.add_sub_cancel, Nat.min_eq_right hc, List.getElem?_append_right (Nat.le_refl _),
          Nat.sub_self]
        rfl
      · have hlt : cut < p.length := Nat.lt_of_not_ge hc
        have hp : 0 < p.length := by omega
        simp only [hlast, hc, decide_false, List.length_append, List.length_singleton,
          Nat.add_sub_cancel, Nat.min_eq_left hlt.le, List.getElem?_append_left hlt]
        have hle : cut ≤ p.length - 1 := by omega
        simpa only [Nat.min_eq_left hle] using ih hp hpver

private theorem atCut_natHistory {s : CcfKv.engine.History} {natHistory : List Frame}
    {model : Store} {encode : List U8 → String}
    (hmodel : model.history = natHistory)
    (aligned : ArchiveAligned encode s natHistory) (cut : Nat)
    : ∃ gf,
        natHistory.reverse[min cut (natHistory.length - 1)]? = some gf
        ∧ gf = atCut model cut
        ∧ gf ∈ model.history := by
  have hlt : min cut (natHistory.length - 1) < natHistory.reverse.length := by
    rw [List.length_reverse]; have := aligned.nonempty; omega
  let gf := natHistory.reverse[min cut (natHistory.length - 1)]'hlt
  have hgfAt : natHistory.reverse[min cut (natHistory.length - 1)]? = some gf :=
    List.getElem?_eq_getElem hlt
  have hfind := find_reverse_ver_indexed natHistory.reverse cut
    (by rw [List.length_reverse]; exact aligned.nonempty) aligned.verIndexed
  rw [List.reverse_reverse, List.length_reverse] at hfind
  refine ⟨gf, hgfAt, ?_, ?_⟩
  · rw [atCut, hmodel, hfind, hgfAt]; rfl
  · rw [hmodel]
    exact List.mem_reverse.mp (List.mem_of_getElem? hgfAt)

private theorem history_resolve_cut_matches_nat (s : CcfKv.engine.History) (cut : U64)
    (model : Store) (encode : List U8 → String) (natHistory : List Frame)
    (hmodel : model.history = natHistory)
    (valid : BranchValid s.log) (aligned : ArchiveAligned encode s natHistory)
    (hSnapRetained
      : ∀ bf,
          s.activeFrames[0]? = some bf
          → cut.val < bf.version.val
          → ∃ rf ∈ s.retained.val, rf.version = cut)
    : WP.spec (CcfKv.engine.History.resolve_cut s cut)
        (fun res =>
          ∃ cutRef nf gf,
            res = some cutRef
            ∧ FrameMetaEq encode nf gf
            ∧ gf = atCut model cut.val
            ∧ gf ∈ model.history
            ∧ match cutRef with
              | .Active off =>
                  s.activeFrames[off.val]? = some nf ∧ modelFrame encode s.index nf = gf
              | .Retained idx =>
                  s.retained.val[idx.val]? = some nf
                  ∧ s.reuse_compacted_images = true
                  ∧ cut < s.global) := by
  obtain ⟨baseFrame, hbaseAt, hbaseLe, hbaseRe, hsum⟩ := aligned.base
  obtain ⟨gf, hgfAt, hgfCut, hgfMem⟩ := atCut_natHistory hmodel aligned cut.val
  apply WP.spec_mono (history_resolve_cut s cut baseFrame hbaseAt valid)
  intro res hres
  by_cases hlt : cut.val < baseFrame.version.val
  · rw [ite_eq_left hlt] at hres
    cases res with
    | none =>
        obtain ⟨rf, hrfMem, hrfVer⟩ := hSnapRetained baseFrame hbaseAt hlt
        exact (hres rf hrfMem hrfVer).elim
    | some cr =>
        cases cr with
        | Active _ => cases hres
        | Retained idx =>
            obtain ⟨nf, hnfAt, hnfVer⟩ := hres
            obtain ⟨hltG, _, gf', hgf'At, hmeta⟩ :=
              aligned.retainedEq nf (List.mem_of_getElem? hnfAt)
            have hmin : min cut.val (natHistory.length - 1) = cut.val := by
              have hlenAct : 0 < s.activeFrames.length := (List.getElem?_eq_some_iff.mp hbaseAt).1
              omega
            rw [hmin] at hgfAt
            have hgfEq : gf' = gf := Option.some.inj (hgf'At.symm.trans (hnfVer.symm ▸ hgfAt))
            rw [hgfEq] at hmeta
            have hreTrue : s.reuse_compacted_images = true := by
              cases hrc : s.reuse_compacted_images with
              | true => rfl
              | false =>
                  have hemp := aligned.retainedReuse hrc
                  have hmem := List.mem_of_getElem? hnfAt
                  rw [hemp] at hmem
                  cases hmem
            refine ⟨.Retained idx, nf, gf, rfl, hmeta, hgfCut, hgfMem, hnfAt, hreTrue, ?_⟩
            change cut.val < s.global.val
            rw [← hnfVer]; exact hltG
  · have hge : baseFrame.version.val ≤ cut.val := Nat.le_of_not_gt hlt
    rw [ite_eq_right hlt] at hres
    obtain ⟨idx, rfl, hidxVal⟩ := hres
    have hactPos : 0 < s.activeFrames.length := (List.getElem?_eq_some_iff.mp hbaseAt).1
    have hidxLt : idx.val < s.activeFrames.length := by omega
    let nf := s.activeFrames[idx.val]'hidxLt
    have hnfAt : s.activeFrames[idx.val]? = some nf := List.getElem?_eq_getElem hidxLt
    have hsumIdx : baseFrame.version.val + idx.val = min cut.val (natHistory.length - 1) := by
      omega
    have hactEq := aligned.activeEq baseFrame hbaseAt idx.val hidxLt
    rw [hsumIdx] at hactEq
    have hmfEq : modelFrame encode s.index nf = gf := Option.some.inj (hactEq.symm.trans hgfAt)
    exact ⟨.Active idx, nf, gf, rfl, hmfEq ▸ frame_meta_eq_modelFrame encode s.index nf,
      hgfCut, hgfMem, hnfAt, hmfEq⟩

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
    (inj : Function.Injective encode) (s : CcfKv.engine.History) (model : Store)
    (natHistory natArchive : List Frame) (extraPins : List U32)
    (t : CcfKv.engine.Tx) (snap : Snapshot) (rustSnap : CcfKv.engine.Snapshot)
    (m : CcfKv.engine.Bytes)
    (hmodel : model.history = natHistory)
    (hNatSub : ∀ f ∈ natHistory, f ∈ natArchive)
    (hglobal : model.global = s.global.val)
    (hglobalBound : s.global.val < natHistory.length)
    (hSnapshot : t.snapshot = some rustSnap)
    (stable : RevisionHistory model.history)
    (hCut : snap.current.version = rustSnap.version.val) (hPhase : t.phase = .Active)
    (hAbsent
      : find (rustPinnedViews encode s.index t.views) (encode (alloc.vec.Vec.val m))
        = none)
    (hRoom : t.views.val.length < Usize.max)
    (valid : BranchValid s.log) (idxValid : HistoryIndexValid s)
    (aligned : ArchiveAligned encode s natHistory)
    (hSnapRetained
      : ∀ bf,
          s.activeFrames[0]? = some bf
          → rustSnap.version.val < bf.version.val
          → ∃ rf ∈ s.retained.val, rf.version = rustSnap.version)
    (live : IndexLiveness s.index (framePins s.activeFrames ++ extraPins))
    (refRoom
      : (framePins s.activeFrames ++ extraPins).length
          + 17 * s.index.values.dirs.val.length
          + 2
        ≤ U32.max)
    (oldLive : ViewsLive s.index t.views)
    (oldOrig : ViewsOrigin encode s.index natArchive t.views)
    : let k := encode (alloc.vec.Vec.val m)
      let v := captureGlobal model snap k
      WP.spec (CcfKv.engine.Tx.acquire t s m)
        (fun (output, afterTx, afterHist) =>
          afterHist.log = s.log
          ∧ afterHist.retained = s.retained
          ∧ afterHist.global = s.global
          ∧ afterHist.term = s.term
          ∧ afterHist.next_identity = s.next_identity
          ∧ afterHist.reuse_compacted_images = s.reuse_compacted_images
          ∧ afterHist.index.values = s.index.values
          ∧ if available model snap k then
              ∃ localVer globalVer views newView,
                output = .Ok (.Acquired localVer globalVer)
                ∧ localVer.val = (revision v.current k).version
                ∧ globalVer.val = (revision v.frame k).version
                ∧ afterTx = {t with views}
                ∧ views.val = (m, newView) :: t.views.val
                ∧ rustPinnedViews encode afterHist.index views
                  = Kv.Model.set (rustPinnedViews encode s.index t.views) k
                      (modelPinnedView k v)
                ∧ ViewsLive afterHist.index views
                ∧ ViewsOrigin encode afterHist.index natArchive views
                ∧ IndexLiveness afterHist.index
                    (viewPins newView ++ (framePins s.activeFrames ++ extraPins))
            else
              output = .Ok .Unavailable
              ∧ afterTx = {t with unavailable := true}
              ∧ afterHist = s) := by
  let enc := encode ∘ alloc.vec.Vec.val (α := U8)
  let k := enc m
  let v := captureGlobal model snap k
  have hi := map_encoding_injective encode inj
  change find (rustPinnedViews encode s.index t.views) k = none at hAbsent
  have hn : find t.views.val m = none := by
    have hm : find (rustPinnedViews encode s.index t.views) k =
        (find t.views.val m).map (rustPinnedView encode s.index m) :=
      find_projected_with_key t.views.val m enc (rustPinnedView encode s.index) hi
    rw [hAbsent] at hm
    cases e : find t.views.val m with
    | none => rfl
    | some view =>
        rw [e, Option.map_some] at hm
        cases hm
  simp only [CcfKv.engine.Tx.acquire, hSnapshot, hPhase, bind_ok]
  apply WP.spec_bind (assoc_index CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey t.views m
    (fun a => key_same a m))
  intro index hindex
  cases index with
  | some i => simp [hn] at hindex
  | none =>
      simp only [core.option.Option.is_some]
      apply WP.spec_bind
        (history_resolve_cut_matches_nat s rustSnap.version model encode natHistory
          hmodel valid aligned hSnapRetained)
      rintro res ⟨localRef, current, gfLocal, rfl, hcurMeta, hCurrent, hMem, hLocalSpec⟩
      have hreadSpec
          : WP.spec (CcfKv.engine.History.read_cut s localRef) (· = current) := by
        cases localRef with
        | Active off => exact history_read_cut_active s off current valid hLocalSpec.1
        | Retained idx => exact history_read_cut_retained s idx current hLocalSpec.1
      apply WP.spec_bind hreadSpec
      intro frame hf
      subst frame
      have hCutFrame : gfLocal = atCut model snap.current.version := by rwa [hCut]
      apply WP.spec_bind (stamps_find enc hi current.births m)
      intro birth hbirth
      have hb : find (atCut model snap.current.version).births k = birth.map modelStamp := by
        rw [← hCutFrame, ← births_meta_eq (index := s.index) hcurMeta k]
        exact hbirth.symm
      cases birth with
      | none =>
          have hAv : available model snap k = true := by
            simp [available, captureLocal, hb, mapAvailable, image, find]
          have hView : v = {frame := {}} := by
            simp [v, captureGlobal, captureLocal, hb, find]
          let empty : CcfKv.engine.View :=
            { birth := none, revision := {version := 0#u64, identity := 0#u64}
              «local» := .Empty, global := none }
          have he : rustPinnedView encode s.index m empty = modelPinnedView k v := by
            simp [hView, empty, rustPinnedView, modelPinnedView, encodeImage, pinImage, modelStamp,
              revision, image, find]
          simp only [core.option.Option.is_none, CcfKv.engine.Stamp.zero, bind_ok]
          apply WP.spec_bind
            (install_view encode inj s.index natArchive t.views m empty hRoom hn
              oldLive ⟨trivial, trivial⟩
              oldOrig (by simp [ViewOrigin, empty, encodeImage, pinImage, modelStamp]))
          intro views ⟨hcons, hvers, hLive, hOrig⟩
          rw [WP.spec_ok]
          have hViews : rustPinnedViews encode s.index views =
              Kv.Model.set (rustPinnedViews encode s.index t.views) k (modelPinnedView k v) :=
            hvers.trans (congrArg (Kv.Model.set (rustPinnedViews encode s.index t.views) k) he)
          refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, ?_⟩
          have hAv' : available model snap (encode (alloc.vec.Vec.val m)) = true := hAv
          rw [ite_eq_left hAv']
          refine ⟨
            0#u64,
            0#u64,
            views,
            empty,
            rfl,
            ?_,
            ?_,
            rfl,
            hcons,
            hViews,
            hLive,
            hOrig,
            by simpa [viewPins, pinPins, empty] using live
          ⟩
          · change (0#u64 : U64).val = (revision v.current k).version
            rw [hView]; rfl
          · change (0#u64 : U64).val = (revision v.frame k).version
            rw [hView]; rfl
      | some birth =>
          have hLocal : captureLocal model snap k = gfLocal := by
            simp [captureLocal, hb, hCutFrame]
          have hBorn : find gfLocal.births k = some (modelStamp birth) := by
            simpa [hCutFrame] using hb
          have hLineage : mapLineage model gfLocal k = true :=
            lineage_of_mem _ _ _ hMem
          simp only [core.option.Option.is_none]
          obtain ⟨baseFrame, hbaseAt, hbaseLe, _, hsum⟩ := aligned.base
          apply WP.spec_bind (history_relative_cut s s.global baseFrame hbaseAt valid)
          intro relG hrelG
          have hrelGVal : relG.val = s.global.val - baseFrame.version.val := by
            rw [hrelG, ite_eq_right (Nat.not_lt.mpr hbaseLe)]
          apply WP.spec_bind (branch_cut_refines s.log valid relG)
          intro globalOff hglobalOff
          have hactPos : 0 < s.activeFrames.length := (List.getElem?_eq_some_iff.mp hbaseAt).1
          have hglobalOffVal : globalOff.val = s.global.val - baseFrame.version.val := by
            have hlenAct : s.activeFrames.length = s.log.len.val := branch_values_length s.log valid
            rw [hglobalOff, hrelGVal]
            omega
          have hglobalOffLt : globalOff.val < s.activeFrames.length := by omega
          let global := s.activeFrames[globalOff.val]'hglobalOffLt
          have globalSaved : s.activeFrames[globalOff.val]? = some global :=
            List.getElem?_eq_getElem hglobalOffLt
          obtain ⟨gfGlobal, hgfGlobalAt, hGlobalCut, _⟩ :=
            atCut_natHistory hmodel aligned s.global.val
          have hglobalLive : modelFrame encode s.index global = gfGlobal := by
            have hactEq := aligned.activeEq baseFrame hbaseAt globalOff.val hglobalOffLt
            have hsumG : baseFrame.version.val + globalOff.val = min s.global.val (natHistory.length - 1) := by
              omega
            rw [hsumG] at hactEq
            exact Option.some.inj (hactEq.symm.trans hgfGlobalAt)
          have hglobMeta : FrameMetaEq encode global gfGlobal :=
            hglobalLive ▸ frame_meta_eq_modelFrame encode s.index global
          apply WP.spec_bind (branch_active_at s.log valid globalOff global globalSaved)
          intro frame hf
          subst frame
          have hGlobal : gfGlobal = atCut model model.global := by
            rw [hglobal]; exact hGlobalCut
          have hView : v = { current := gfLocal, frame := gfGlobal } := by
            simp [v, captureGlobal, hLocal, hBorn, hGlobal]
          apply WP.spec_bind (revision_frame encode inj s.index current m)
          intro localRev hl
          rw [revision_meta_eq hcurMeta] at hl
          apply WP.spec_bind (revision_frame encode inj s.index global m)
          intro globalRev hgRev
          rw [revision_meta_eq hglobMeta] at hgRev
          have hAv : available model snap k = decide (globalRev.version.val ≤ localRev.version.val) := by
            have hl' := congrArg Stamp.version hl
            have hg' := congrArg Stamp.version hgRev
            change localRev.version.val = (revision gfLocal k).version at hl'
            change globalRev.version.val = (revision gfGlobal k).version at hg'
            simp [available, hLocal, mapAvailable, hBorn, hLineage, ← hGlobal, ← hl', ← hg']
          by_cases hOld : localRev.version < globalRev.version
          · have hlt : localRev.version.val < globalRev.version.val := hOld
            rw [ite_eq_left hOld, WP.spec_ok]
            refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, ?_⟩
            have hAvF : ¬ available model snap (encode (alloc.vec.Vec.val m)) = true := by
              change ¬ available model snap k = true
              rw [hAv]
              simp [Nat.not_le.mpr hlt]
            rw [ite_eq_right hAvF]
            exact ⟨rfl, rfl, rfl⟩
          · rw [ite_eq_right hOld]
            have hle : globalRev.version.val ≤ localRev.version.val := Nat.le_of_not_gt hOld
            have hShared (past : rustSnap.version.val ≤ s.global.val) :
                image gfLocal.data (encode m.val) = image gfGlobal.data (encode m.val) := by
              have avail : available model snap k = true := hAv.trans (decide_eq_true hle)
              have older : snap.current.version ≤ model.global := by rwa [hCut, hglobal]
              rcases available_compacted_image model stable snap k older avail with absent | same
              · rw [hLocal, hBorn] at absent
                cases absent
              · rw [hLocal, ← hGlobal] at same
                exact same
            apply WP.spec_bind
              (pin_maps_spec encode inj s current global gfLocal gfGlobal m extraPins
                localRef globalOff rustSnap.version valid idxValid live globalSaved
                hLocalSpec hglobalLive hShared refRoom)
            rintro ⟨⟨localPin, globalPin⟩, afterHist⟩
              ⟨hlogEq, hretEq, hglEq, htmEq, hidEq, hreEq, hvalsEq, hliveAfter,
                hLocalRows, hGlobalRows, localLive, globalLive⟩
            have hkAfter : IndexKeeps s.index afterHist.index := by
              unfold IndexKeeps; rw [hvalsEq]; exact .refl _
            have hPresOld := pinned_views_preserved encode hkAfter t.views oldLive
            have hOrigOld := views_origin_preserved encode hkAfter (fun _ h => h) t.views oldLive oldOrig
            let newView : CcfKv.engine.View :=
              { birth := some birth, revision := localRev, «local» := localPin, global := globalPin }
            have newOrig : ViewOrigin encode afterHist.index natArchive m newView := by
              refine ⟨gfLocal, hNatSub gfLocal (hmodel ▸ hMem), ?_, ?_⟩
              · exact hl.symm
              · exact hLocalRows
            apply WP.spec_bind
              (install_view encode inj afterHist.index natArchive t.views m newView hRoom hn
                hPresOld.1 ⟨localLive, globalLive⟩ hOrigOld newOrig)
            intro views ⟨hcons, hViews, hLive, hOrig⟩
            have hPin : rustPinnedView encode afterHist.index m newView = modelPinnedView k v := by
              change find gfLocal.births (encode (alloc.vec.Vec.val m)) = some (modelStamp birth) at hBorn
              simp only [newView, rustPinnedView, modelPinnedView, hView, hBorn, hLocalRows, hGlobalRows, k, enc, Function.comp_def]
              congr 1
            change WP.spec (Result.ok _) _
            rw [WP.spec_ok]
            refine ⟨hlogEq, hretEq, hglEq, htmEq, hidEq, hreEq, hvalsEq, ?_⟩
            have hAvT : available model snap (encode (alloc.vec.Vec.val m)) = true := by
              change available model snap k = true
              rw [hAv]
              exact decide_eq_true hle
            rw [ite_eq_left hAvT]
            refine ⟨localRev.version, globalRev.version, views, newView, rfl, ?_, ?_, rfl, hcons,
              ?_, hLive, hOrig, ?_⟩
            · change localRev.version.val = (revision v.current k).version
              rw [hView]
              exact congrArg Stamp.version hl
            · change globalRev.version.val = (revision v.frame k).version
              rw [hView]
              exact congrArg Stamp.version hgRev
            · change rustPinnedViews encode afterHist.index views =
                Kv.Model.set (rustPinnedViews encode s.index t.views) k (modelPinnedView k v)
              rw [hViews, hPresOld.2, hPin]
              rfl
            · exact hliveAfter

/-- Compare the observable result of a completed acquisition, including both reported revisions. -/
def modelAcquisition (out : core.result.Result CcfKv.engine.Output CcfKv.engine.Error)
    : Option Output :=
  match out with
  | .Ok (.Acquired localVer globalVer) => some (.acquired localVer.val globalVer.val)
  | .Ok .Unavailable => some .unavailable
  | _ => none

private theorem option_bind_some {α β : Type} (x : α) (f : α → Option β)
    : (some x >>= f) = f x :=
  rfl

private theorem acquire_disabled (encode : List U8 → String)
    (inj : Function.Injective encode) (t : CcfKv.engine.Tx) (s : CcfKv.engine.History)
    (m : CcfKv.engine.Bytes)
    (disabled
      : t.snapshot = none
        ∨ t.phase ≠ .Active
        ∨ (find (rustPinnedViews encode s.index t.views)
            (encode (alloc.vec.Vec.val m))).isSome)
    : WP.spec (CcfKv.engine.Tx.acquire t s m) (fun r => r = (.Err .Disabled, t, s)) := by
  cases hs : t.snapshot with
  | none => simp [CcfKv.engine.Tx.acquire, hs]
  | some snap =>
      have restore (phase : CcfKv.engine.Phase) (hp : t.phase = phase) :
          {t with snapshot := some snap, phase := phase} = t := by
        rw [← hs, ← hp]
      cases hp : t.phase with
      | Committing => simp [CcfKv.engine.Tx.acquire, hs, hp, restore _ hp]
      | Finished => simp [CcfKv.engine.Tx.acquire, hs, hp, restore _ hp]
      | Applied version => simp [CcfKv.engine.Tx.acquire, hs, hp, restore _ hp]
      | Active =>
          have hPresent
              : (find (rustPinnedViews encode s.index t.views)
                  (encode (alloc.vec.Vec.val m))).isSome :=
            disabled.resolve_left (by simp [hs]) |>.resolve_left (by simp [hp])
          simp only [CcfKv.engine.Tx.acquire, hs, hp, bind_ok]
          apply WP.spec_bind
            (assoc_index CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey t.views m
              (fun a => key_same a m))
          intro i hi
          cases i with
          | none =>
              have hfind := find_projected_with_key t.views.val m (encode ∘ alloc.vec.Vec.val)
                (rustPinnedView encode s.index) (map_encoding_injective encode inj)
              change find (rustPinnedViews encode s.index t.views) (encode (alloc.vec.Vec.val m)) =
                (find t.views.val m).map (rustPinnedView encode s.index m) at hfind
              change find t.views.val m = none at hi
              rw [hfind, hi] at hPresent
              cases hPresent
          | some i => simp [restore _ hp]

/-- Acquiring without a live, active, uncaptured view leaves the store and all attempts unchanged. -/
theorem execute_acquire_disabled (encode : List U8 → String)
    (inj : Function.Injective encode) (s : CcfKv.engine.Store) (id : U64)
    (m : CcfKv.engine.Bytes)
    (disabled
      : ∀ t,
          find s.txs.val id = some t
          → t.snapshot = none
            ∨ t.phase ≠ .Active
            ∨ (find (rustPinnedViews encode s.history.index t.views)
                (encode (alloc.vec.Vec.val m))).isSome)
    : WP.spec (CcfKv.engine.Store.execute s (.Acquire id m))
        (fun r => r = (.Err .Disabled, s)) := by
  unfold CcfKv.engine.Store.execute
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
        let (out, next, hist) ← CcfKv.engine.Tx.acquire t s.history m
        Result.ok (out, {s with history := hist, txs := back (id, next)})) _
      apply WP.spec_bind (acquire_disabled encode inj t s.history m (disabled t hfound))
      intro result hr
      subst result
      have hunchanged : back (id, t) = s.txs := by
        rw [hback.2]
        apply alloc.vec.Vec.ext
        rw [alloc.vec.Vec.set_val_eq, ← hget]
        exact List.set_getElem_self idx
      change WP.spec (Result.ok (core.result.Result.Err CcfKv.engine.Error.Disabled,
        ({s with history := s.history, txs := back (id, t)} : CcfKv.engine.Store))) _
      simp [hunchanged]

/-- The extracted dispatcher and `Kv.Model.execute` agree on an enabled acquisition and the updated attempt. -/
theorem execute_acquire_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (s : CcfKv.engine.Store) (id : U64) (w : State)
    (sid : Nat) (model : Store) (natHistory natArchive : List Frame)
    (tx : Tx) (t : CcfKv.engine.Tx) (snap : Snapshot)
    (rustSnap : CcfKv.engine.Snapshot) (m : CcfKv.engine.Bytes)
    (head : CcfKv.engine.Frame)
    (hmodel : List.Forall₂ FrameOrderEq natHistory model.history)
    (hNatSub : ∀ f ∈ natHistory, f ∈ natArchive)
    (hglobal : model.global = s.history.global.val)
    (hglobalBound : s.history.global.val < natHistory.length)
    (stable : RevisionHistory natHistory)
    (hNativeTx : find s.txs.val id = some t)
    (hLookup : lookupTx w sid id.val = some (model, tx))
    (hNativeSnap : t.snapshot = some rustSnap) (hModelSnap : tx.snapshot = some snap)
    (hCut : snap.current.version = rustSnap.version.val)
    (hNativePhase : t.phase = .Active) (hModelPhase : tx.phase = .active)
    (hPinned
      : ViewsOrderEq (modelPinnedViews tx.globalViews)
          (rustPinnedViews encode s.history.index t.views))
    (hUnavailable : tx.unavailable = t.unavailable)
    (hFresh : find tx.globalViews (encode (alloc.vec.Vec.val m)) = none)
    (hLog : tx.normal.log.all (fun op => op.map != encode (alloc.vec.Vec.val m)) = true)
    (hRoom : t.views.val.length < Usize.max)
    (valid : BranchValid s.history.log) (idxValid : HistoryIndexValid s.history)
    (aligned : ArchiveAligned encode s.history natHistory)
    (hSnapRetained
      : ∀ bf,
          s.history.activeFrames[0]? = some bf
          → rustSnap.version.val < bf.version.val
          → ∃ rf ∈ s.history.retained.val, rf.version = rustSnap.version)
    (live : IndexLiveness s.history.index (storePins s))
    (refRoom
      : (storePins s).length + 17 * s.history.index.values.dirs.val.length + 2 ≤ U32.max)
    (oldLive : ViewsLive s.history.index t.views)
    (oldOrig : ViewsOrigin encode s.history.index natArchive t.views)
    : WP.spec (CcfKv.engine.Store.execute s (.Acquire id m))
        (fun (output, after) =>
          ∃ modelAfter txAfter tAfter obs index,
            execute w (.acquire sid id.val (encode (alloc.vec.Vec.val m)))
              = some (modelAfter, obs)
            ∧ modelAcquisition output = some obs
            ∧ modelAfter = {w with txs := Kv.Model.set w.txs id.val txAfter}
            ∧ ViewsOrderEq (modelPinnedViews txAfter.globalViews)
                (rustPinnedViews encode after.history.index tAfter.views)
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
            ∧ after.history.log = s.history.log
            ∧ after.history.retained = s.history.retained
            ∧ after.history.global = s.history.global
            ∧ after.history.term = s.history.term
            ∧ after.history.next_identity = s.history.next_identity
            ∧ after.history.reuse_compacted_images = s.history.reuse_compacted_images
            ∧ after.history.index.values = s.history.index.values
            ∧ IndexLiveness after.history.index (storePins after)
            ∧ s.txs.val[index]? = some (id, t)
            ∧ after.txs.val = s.txs.val.set index (id, tAfter)
            ∧ ViewsLive after.history.index tAfter.views
            ∧ ViewsOrigin encode after.history.index natArchive tAfter.views
            ∧ (∀ row ∈ t.views.val, row ∈ tAfter.views.val)
            ∧ (if available model snap (encode (alloc.vec.Vec.val m)) then
                  ∃ newView, tAfter.views.val = (m, newView) :: t.views.val
                else
                  tAfter.views = t.views)
            ∧ ∀ other,
                other ≠ encode (alloc.vec.Vec.val m)
                → find (rustPinnedViews encode after.history.index tAfter.views) other
                  = find (rustPinnedViews encode s.history.index t.views) other) := by
  let k := encode (alloc.vec.Vec.val m)
  let v := captureGlobal model snap k
  let nativeModel : Store := {
    model with
      history := natHistory
      head := modelFrame encode s.history.index head
  }
  let nv := captureGlobal nativeModel snap k
  have hMissing : find (rustPinnedViews encode s.history.index t.views) k = none := by
    have rel := hPinned.find k
    rw [projected_view_missing tx.globalViews k hFresh] at rel
    cases h : find (rustPinnedViews encode s.history.index t.views) k with
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
  unfold CcfKv.engine.Store.execute
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
        let (out, next, hist) ← CcfKv.engine.Tx.acquire t s.history m
        Result.ok (out, {s with history := hist, txs := back (id, next)})) _
      apply WP.spec_bind
        (acquire_matches_model encode inj s.history nativeModel natHistory natArchive
          (txsPins s.txs.val) t snap rustSnap m rfl hNatSub hglobal
          hglobalBound hNativeSnap stable hCut hNativePhase hMissing hRoom valid idxValid
          aligned hSnapRetained live refRoom oldLive oldOrig)
      rintro ⟨out, next, hist⟩ ⟨hlogEq, hretEq, hglEq, htmEq, hidEq, hreEq, hvalsEq, hn⟩
      rw [hAvailEq] at hn
      have hupdate : (back (id, next)).val = s.txs.val.set i.val (id, next) := by
        rw [hback.2]
        exact alloc.vec.Vec.set_val_eq _ _ _
      change WP.spec (Result.ok (out, ({s with history := hist, txs := back (id, next)} : CcfKv.engine.Store))) _
      rw [WP.spec_ok]
      by_cases ha : available model snap k
      · rw [ite_eq_left ha] at hn
        obtain ⟨lv, gv, views, newView, hout, hl, hg, hNext, hcons, hViews, hLive, hOrig, hLiveAfter⟩ := hn
        have hl' : lv.val = (revision v.current k).version :=
          hl.trans (congrArg Stamp.version (hCurEq.revision_eq k))
        have hg' : gv.val = (revision v.frame k).version :=
          hg.trans (congrArg Stamp.version (hFrameEq.revision_eq k))
        let modelNext : Tx := {
          tx with
            globalViews := Kv.Model.set tx.globalViews k v
            data := pinData tx.data k v.current.data
        }
        have htxsPinsPerm : (txsPins (back (id, next)).val).Perm (viewPins newView ++ txsPins s.txs.val) := by
          rw [hupdate]
          exact txsPins_set_add_view s.txs.val i.val id t next m newView hrow (by rw [hNext, hcons])
        have hstorePinsPerm : (viewPins newView ++ (framePins s.history.activeFrames ++ txsPins s.txs.val)).Perm
            (storePins { s with history := hist, txs := back (id, next) }) := by
          unfold storePins CcfKv.engine.History.activeFrames
          dsimp only
          rw [hlogEq]
          have h1 : (viewPins newView ++ (framePins (branchValues s.history.log) ++ txsPins s.txs.val)).Perm
              (framePins (branchValues s.history.log) ++ (viewPins newView ++ txsPins s.txs.val)) := by
            have ha1 : (viewPins newView ++ (framePins (branchValues s.history.log) ++ txsPins s.txs.val)).Perm
                ((viewPins newView ++ framePins (branchValues s.history.log)) ++ txsPins s.txs.val) := by
              rw [List.append_assoc]
            have ha2 : ((viewPins newView ++ framePins (branchValues s.history.log)) ++ txsPins s.txs.val).Perm
                ((framePins (branchValues s.history.log) ++ viewPins newView) ++ txsPins s.txs.val) :=
              List.perm_append_comm.append_right _
            have ha3 : ((framePins (branchValues s.history.log) ++ viewPins newView) ++ txsPins s.txs.val).Perm
                (framePins (branchValues s.history.log) ++ (viewPins newView ++ txsPins s.txs.val)) := by
              rw [List.append_assoc]
            exact ha1.trans (ha2.trans ha3)
          exact h1.trans (htxsPinsPerm.symm.append_left _)
        refine ⟨{w with txs := Kv.Model.set w.txs id.val modelNext}, modelNext, next,
          .acquired lv.val gv.val, i.val, ?_, ?_, rfl, ?_, ?_, ?_, ?_, ?_,
          hlogEq, hretEq, hglEq, htmEq, hidEq, hreEq, hvalsEq, hLiveAfter.perm hstorePinsPerm,
          hrow, hupdate, ?_, ?_, ?_, ?_, ?_⟩
        · change execute w (.acquire sid id.val k) = _
          rw [hStep, ite_eq_left ha, ← hl', ← hg']
        · rw [hout]
          rfl
        · change ViewsOrderEq (modelPinnedViews (Kv.Model.set tx.globalViews k v))
            (rustPinnedViews encode hist.index next.views)
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
        · intro row hrowMem
          rw [hNext, hcons]
          exact List.mem_cons_of_mem _ hrowMem
        · rw [ite_eq_left ha]
          exact ⟨newView, by rw [hNext, hcons]⟩
        · intro other hne
          rw [hNext, hViews, find_set_key]
          exact ite_eq_right hne
      · rw [ite_eq_right ha] at hn
        obtain ⟨hout, hNext, hHistEq⟩ := hn
        subst hHistEq
        let modelNext := {tx with unavailable := true}
        have htxsPinsEq : txsPins (back (id, next)).val = txsPins s.txs.val := by
          rw [hupdate]
          exact txsPins_set_same_views s.txs.val i.val id t next hrow (by rw [hNext])
        have hstorePinsEq : storePins { s with history := s.history, txs := back (id, next) } = storePins s := by
          simp [storePins, htxsPinsEq]
        refine ⟨{w with txs := Kv.Model.set w.txs id.val modelNext}, modelNext, next,
          .unavailable, i.val, ?_, ?_, rfl, ?_, ?_, ?_, ?_, ?_,
          rfl, rfl, rfl, rfl, rfl, rfl, rfl, hstorePinsEq.symm ▸ live,
          hrow, hupdate, ?_, ?_, ?_, ?_, ?_⟩
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
        · intro row hrowMem; rw [hNext]; exact hrowMem
        · rw [ite_eq_right ha, hNext]
        · intro other _; rw [hNext]

end KvRust
