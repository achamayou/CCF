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

/-- Encoded raw-byte order on projected map images, independent of any ordering
on `String` itself. -/
def encKeyLt (encode : List U8 → String) (a b : String × Kv.Model.Cell String) : Prop :=
  ∃ ka kb : List U8, encode ka = a.1 ∧ encode kb = b.1 ∧ ka < kb

private theorem encKeyLt_irrefl {encode : List U8 → String}
    (inj : Function.Injective encode) (a : String × Kv.Model.Cell String)
    : ¬ encKeyLt encode a a := by
  rintro ⟨ka, kb, ha, hb, hlt⟩
  have heq : ka = kb := inj (ha.trans hb.symm)
  exact lt_irrefl kb (heq ▸ hlt)

private theorem encKeyLt_trans {encode : List U8 → String}
    (inj : Function.Injective encode) {a b c : String × Kv.Model.Cell String}
    (ab : encKeyLt encode a b) (bc : encKeyLt encode b c)
    : encKeyLt encode a c := by
  obtain ⟨ka, kb, ha, hb, hlt1⟩ := ab
  obtain ⟨kb', kc, hb', hc, hlt2⟩ := bc
  have hkb : kb = kb' := inj (hb.trans hb'.symm)
  exact ⟨ka, kc, ha, hc, lt_trans hlt1 (hkb ▸ hlt2)⟩

private theorem encKeyLt_perm_eq {encode : List U8 → String}
    (inj : Function.Injective encode) {a b : List (String × Kv.Model.Cell String)}
    (ha : a.Pairwise (encKeyLt encode)) (hb : b.Pairwise (encKeyLt encode))
    (perm : a.Perm b)
    : a = b := by
  induction a generalizing b with
  | nil => exact perm.nil_eq
  | cons x xs ih =>
      cases b with
      | nil => exact (List.Perm.nil_eq perm.symm).symm
      | cons y ys =>
          obtain ⟨hx, hxs⟩ := List.pairwise_cons.mp ha
          obtain ⟨hy, hys⟩ := List.pairwise_cons.mp hb
          have hxy : x = y := by
            have hyIn : y ∈ x :: xs := perm.symm.subset List.mem_cons_self
            have hxIn : x ∈ y :: ys := perm.subset List.mem_cons_self
            rcases List.mem_cons.mp hyIn with rfl | hyXs
            · rfl
            · rcases List.mem_cons.mp hxIn with rfl | hxYs
              · rfl
              · exact (encKeyLt_irrefl inj x (encKeyLt_trans inj (hx y hyXs) (hy x hxYs))).elim
          subst hxy
          exact congrArg (List.cons x) (ih hxs hys (List.Perm.cons_inv perm))

private theorem packed_same_map_lt {a b : Spike.engine.Address}
    (hmap : a.map.val = b.map.val) (hlt : packedAddress a < packedAddress b)
    : a.key.val < b.key.val := by
  have hbo : byteOrder (packedAddress a) (packedAddress b) < 0#i8 := (byteOrder_lt _ _).mpr hlt
  have hpre : ∀ (p xs ys : List U8), byteOrder (p ++ xs) (p ++ ys) = byteOrder xs ys := by
    intro p xs ys
    induction p with
    | nil => rfl
    | cons h t ih => simp [byteOrder, ih]
  unfold packedAddress addressBytes at hbo
  rw [hmap, List.append_assoc, List.append_assoc, hpre, hpre] at hbo
  exact (byteOrder_lt _ _).mp hbo

theorem modelFrame_image_sorted {encode : List U8 → String}
    (inj : Function.Injective encode) (index : CellIndex) (frame : Spike.engine.Frame)
    (view : IndexView index frame.data (indexRows index frame.data)) (m : String)
    : (Kv.Model.image (modelFrame encode index frame).data m).Pairwise
        (encKeyLt encode) := by
  have hsort := index_view_sorted view
  change (Kv.Model.image (encodeData encode (indexedCellData (indexRows index frame.data))) m).Pairwise
    (encKeyLt encode)
  generalize indexRows index frame.data = rows at hsort
  induction rows with
  | nil => simp [indexedCellData, encodeData, Kv.Model.image]
  | cons row rest ih =>
      obtain ⟨a, c⟩ := row
      obtain ⟨hhead, hrest⟩ := List.pairwise_cons.mp hsort
      by_cases hm : encode a.map.val = m
      · simp only [indexedCellData, encodeData, encodeAddr, byteAddr, List.map_cons,
          Kv.Model.image, List.filterMap_cons, hm, ite_true]
        refine List.pairwise_cons.mpr ⟨?_, ih hrest⟩
        intro y hy
        obtain ⟨⟨⟨mt, kt⟩, ct⟩, hmem, hfilt⟩ := List.mem_filterMap.mp hy
        have hmt : mt = m := by
          by_cases h : mt = m
          · exact h
          · simp [h] at hfilt
        have hpair : (kt, ct) = y := by simpa [hmt] using hfilt
        obtain ⟨⟨⟨mb, kb⟩, cb⟩, hmem1, hpair1⟩ := List.mem_map.mp hmem
        obtain ⟨⟨ab, cb'⟩, hmem2, hpair2⟩ := List.mem_map.mp hmem1
        have habMap : encode ab.map.val = m := by
          have h1 : encode mb = mt := congrArg (fun x => x.1.1) hpair1
          have h2 : ab.map.val = mb := congrArg (fun x => x.1.1) hpair2
          exact (congrArg encode h2).trans (h1.trans hmt)
        have habKey : encode ab.key.val = y.1 := by
          have h1 : encode kb = kt := congrArg (fun x => x.1.2) hpair1
          have h2 : ab.key.val = kb := congrArg (fun x => x.1.2) hpair2
          have h3 : kt = y.1 := congrArg Prod.fst hpair
          exact (congrArg encode h2).trans (h1.trans h3)
        have hsameMap : a.map.val = ab.map.val := inj (hm.trans habMap.symm)
        exact ⟨a.key.val, ab.key.val, rfl, habKey, packed_same_map_lt hsameMap (hhead (ab, cb') hmem2)⟩
      · simp only [indexedCellData, encodeData, encodeAddr, byteAddr, List.map_cons,
          Kv.Model.image, List.filterMap_cons, hm, ite_false]
        exact ih hrest

/-- Under single-radix storage, any two valid frames whose projected map images
are permutations of each other have identical map images. -/
theorem modelFrame_image_eq_of_perm {encode : List U8 → String}
    (inj : Function.Injective encode) (index : CellIndex) (f1 f2 : Spike.engine.Frame)
    (v1 : IndexView index f1.data (indexRows index f1.data))
    (v2 : IndexView index f2.data (indexRows index f2.data)) (m : String)
    (perm
      : (Kv.Model.image (modelFrame encode index f1).data m).Perm
          (Kv.Model.image (modelFrame encode index f2).data m))
    : Kv.Model.image (modelFrame encode index f1).data m
      = Kv.Model.image (modelFrame encode index f2).data m :=
  encKeyLt_perm_eq inj
    (modelFrame_image_sorted inj index f1 v1 m)
    (modelFrame_image_sorted inj index f2 v2 m)
    perm

end KvRust
