-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Lineage

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

def PinLive (history : Spike.engine.History) : Spike.engine.PinnedImage → Prop
  | .Frame id => ∃ frame, history.log.frames.val[id.val]? = some frame
  | _ => True

def pinImage (history : Spike.engine.History) (map : Spike.engine.Bytes)
    : Spike.engine.PinnedImage → Assoc (List U8) (Cell (List U8))
  | .Empty => []
  | .Frame id =>
      (history.log.frames.val[id.val]?.map
        fun frame => image (byteData frame.data) map.val).getD
        []
  | .Recovered rows => byteImage rows

theorem pin_preserved {before after : Spike.engine.History}
    (preserved : FrameSlotsPreserved before after) (map : Spike.engine.Bytes)
    (pin : Spike.engine.PinnedImage) (live : PinLive before pin)
    : PinLive after pin ∧ pinImage after map pin = pinImage before map pin := by
  cases pin with
  | Empty => exact ⟨trivial, rfl⟩
  | Recovered rows => exact ⟨trivial, rfl⟩
  | Frame id =>
      obtain ⟨frame, old⟩ := live
      have kept := preserved id.val frame old
      exact ⟨⟨frame, kept⟩, by simp [pinImage, old, kept]⟩

theorem clone_pin (pin : Spike.engine.PinnedImage)
    : Spike.engine.PinnedImage.Insts.CoreCloneClone.clone pin = .ok pin := by
  cases pin <;> simp [Spike.engine.PinnedImage.Insts.CoreCloneClone.clone,
    Spike.branch_log.FrameId.Insts.CoreCloneClone.clone, clone_assoc]

/-- Materializing a frame handle copies precisely its selected ordered map. -/
theorem pin_materialize_refines (history : Spike.engine.History)
    (map : Spike.engine.Bytes) (pin : Spike.engine.PinnedImage)
    (live : PinLive history pin)
    : WP.spec (Spike.engine.PinnedImage.materialize pin history map)
        (fun rows => byteImage rows = pinImage history map pin) := by
  unfold Spike.engine.PinnedImage.materialize
  cases pin with
  | Empty => simp [Spike.engine.Assoc.new, byteImage, pinImage]
  | Recovered rows => simp [clone_assoc, pinImage]
  | Frame id =>
      obtain ⟨frame, saved⟩ := live
      apply WP.spec_bind (branch_read_refines history.log id frame saved)
      intro current he
      subst current
      simpa [pinImage, saved] using image_matches_model frame.data map

private theorem find_in_image {M K V : Type} [DecidableEq M] [DecidableEq K]
    (db : DB M K V) (map : M) (key : K)
    : find (image db map) key = find db (map, key) := by
  induction db with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨⟨m, k⟩, v⟩ := row
      by_cases onMap : m = map
      · subst m
        simp [image, find] at ih ⊢
        by_cases onKey : k = key <;> simp [onKey, ih]
      · have diff : (m, k) ≠ (map, key) := fun h => onMap (congrArg Prod.fst h)
        simpa [image, find, onMap, diff] using ih

local instance pinDecidableEqBytes : DecidableEq Spike.engine.Bytes :=
  fun a b =>
    decidable_of_iff (a.val = b.val) ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

/-- A borrowed point read agrees with a lookup after exact map materialization. -/
theorem pin_point_refines (history : Spike.engine.History)
    (address : Spike.engine.Address) (pin : Spike.engine.PinnedImage)
    (live : PinLive history pin)
    : WP.spec (Spike.engine.PinnedImage.point pin history address)
        (fun cell =>
          cell.map byteCell
          = find (pinImage history address.map pin) address.key.val) := by
  unfold Spike.engine.PinnedImage.point
  cases pin with
  | Empty => simp [pinImage, find]
  | Recovered rows =>
      apply WP.spec_mono (assoc_get Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
        Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.Cell.Insts.CoreCloneClone
        rows address.key (fun k => key_same k address.key) clone_cell)
      intro found he
      rw [pinImage, byteImage, find_projected _ _ _ _ (fun _ _ => alloc.vec.Vec.ext _ _), he]
  | Frame id =>
      obtain ⟨frame, saved⟩ := live
      apply WP.spec_bind (branch_read_refines history.log id frame saved)
      intro current he
      subst current
      simpa [pinImage, saved, find_in_image, byteAddr] using data_lookup frame.data address

end KvRust
