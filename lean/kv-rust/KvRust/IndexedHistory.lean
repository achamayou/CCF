-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Lineage

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- Every archived slot has a valid view, not just the slots on the current branch. -/
structure HistoryIndexValid (history : Spike.engine.History) : Prop where
  index : IndexValid history.index
  archived
    : ∀ (i : Nat) (frame : Spike.engine.Frame),
        history.log.frames.val[i]? = some frame
        → IndexView history.index frame.data (indexRows history.index frame.data)

theorem HistoryIndexValid.active {history : Spike.engine.History}
    (valid : HistoryIndexValid history) (frame : Spike.engine.Frame)
    (active : frame ∈ history.activeFrames)
    : IndexView history.index frame.data (indexRows history.index frame.data) := by
  obtain ⟨id, _, saved⟩ := List.mem_filterMap.mp active
  exact valid.archived id.val frame saved

theorem HistoryIndexValid.head {history : Spike.engine.History}
    (valid : HistoryIndexValid history) (prior : List Spike.engine.Frame)
    (frame : Spike.engine.Frame) (split : history.activeFrames = prior ++ [frame])
    : IndexView history.index frame.data (indexRows history.index frame.data) :=
  valid.active frame (by simp [split])

theorem HistoryIndexValid.congr {before after : Spike.engine.History}
    (valid : HistoryIndexValid before) (sameIndex : after.index = before.index)
    (sameArchive : after.log.frames = before.log.frames)
    : HistoryIndexValid after := by
  refine ⟨sameIndex.symm ▸ valid.index, ?_⟩
  intro i frame saved
  rw [sameIndex]
  exact valid.archived i frame (by simpa only [sameArchive] using saved)

/-- A persistent history update preserves both the frame slots and their storage roots. -/
structure HistoryKeeps (before after : Spike.engine.History) : Prop where
  slots : FrameSlotsPreserved before after
  index : IndexKeeps before.index after.index

theorem HistoryKeeps.of_same {before after : Spike.engine.History}
    (sameSlots : after.log.frames = before.log.frames)
    (sameIndex : after.index = before.index)
    : HistoryKeeps before after :=
  ⟨FrameSlotsPreserved.of_same before after sameSlots, sameIndex.symm ▸ .refl _⟩

theorem HistoryKeeps.rows {before after : Spike.engine.History}
    (kept : HistoryKeeps before after) (valid : HistoryIndexValid before) (i : Nat)
    (frame : Spike.engine.Frame) (saved : before.log.frames.val[i]? = some frame)
    : indexRows after.index frame.data = indexRows before.index frame.data :=
  index_rows_eq (index_keeps_view kept.index _ _ (valid.archived i frame saved))

/-- Project the entire extracted frame into the executable model. -/
noncomputable def modelFrame (encode : List U8 → String) (index : CellIndex)
    (frame : Spike.engine.Frame)
    : Kv.Model.Frame :=
  {
    modelMetadata (encode ∘ alloc.vec.Vec.val) frame with
      data := encodeData encode (indexedCellData (indexRows index frame.data))
  }

theorem model_frame_retained (encode : List U8 → String) {before after : CellIndex}
    (kept : IndexKeeps before after) (frame : Spike.engine.Frame)
    (view : IndexView before frame.data (indexRows before frame.data))
    : modelFrame encode after frame = modelFrame encode before frame := by
  have same := index_rows_eq (index_keeps_view kept _ _ view)
  simp only [modelFrame, same]

theorem model_frame_retained_active (encode : List U8 → String)
    {history : Spike.engine.History} {arena : CellIndex}
    (valid : HistoryIndexValid history) (kept : IndexKeeps history.index arena)
    : history.activeFrames.map (modelFrame encode arena)
      = history.activeFrames.map (modelFrame encode history.index) := by
  apply List.map_congr_left
  intro frame mem
  exact model_frame_retained encode kept frame (valid.active frame mem)

theorem HistoryIndexValid.append {before after : Spike.engine.History}
    (valid : HistoryIndexValid before) (kept : IndexKeeps before.index after.index)
    (live : IndexValid after.index) (frame : Spike.engine.Frame)
    (view : IndexView after.index frame.data (indexRows after.index frame.data))
    (archive : after.log.frames.val = before.log.frames.val ++ [frame])
    : HistoryIndexValid after := by
  refine ⟨live, ?_⟩
  intro i f entry
  rw [archive] at entry
  by_cases old : i < before.log.frames.val.length
  · rw [List.getElem?_append_left old] at entry
    have preserved := index_keeps_view kept _ _ (valid.archived i f entry)
    rwa [index_rows_eq preserved]
  · rw [List.getElem?_append_right (Nat.le_of_not_gt old)] at entry
    have member := List.mem_iff_getElem?.mpr ⟨_, entry⟩
    simpa using List.mem_singleton.mp member ▸ view

end KvRust
