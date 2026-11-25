-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.KvIndex

@[expose] public section

namespace KvRust

open Aeneas.Std

abbrev CellRows := List (CcfKv.engine.Address × CcfKv.engine.Cell)

abbrev MapRows := alloc.vec.Vec (CcfKv.engine.Bytes × CcfKv.engine.Cell)

def indexedImageRows (rows : CellRows) (map : CcfKv.engine.Bytes)
    : List (CcfKv.engine.Bytes × CcfKv.engine.Cell) :=
  rows.filterMap fun (a, c) => if a.map.val = map.val then some (a.key, c) else none

theorem indexed_image_append (rows more : CellRows) (map : CcfKv.engine.Bytes)
    : indexedImageRows (rows ++ more) map
      = indexedImageRows rows map ++ indexedImageRows more map := by
  simp [indexedImageRows, List.filterMap_append]

theorem indexed_image_projects (rows : CellRows) (map : CcfKv.engine.Bytes)
    : (indexedImageRows rows map).map (fun (k, c) => (k.val, byteCell c))
      = Kv.Model.image (rows.map fun (a, c) => (byteAddr a, byteCell c)) map.val := by
  induction rows with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨a, c⟩ := row
      by_cases same : a.map.val = map.val <;>
        simp [indexedImageRows, Kv.Model.image, byteAddr, same] at ih ⊢ <;> rw [ih]

private theorem append_image_row_refines (out : MapRows)
    (row : CcfKv.engine.Address × CcfKv.engine.Cell) (map : CcfKv.engine.Bytes)
    (room : out.val.length < Usize.max)
    : WP.spec (CcfKv.engine.append_image_row out row.1 row.2 map)
        (fun next =>
          next.val = out.val ++ indexedImageRows [row] map
          ∧ next.val.length ≤ out.val.length + 1) := by
  obtain ⟨a, c⟩ := row
  unfold CcfKv.engine.append_image_row
  by_cases same : a.map.val = map.val
  · simp only [bytes_same, same, decide_true, bind_ok, ite_true, clone_bytes, clone_cell]
    apply WP.spec_mono (alloc.vec.Vec.push_spec out (a.key, c) room)
    intro next hn
    simp [hn, indexedImageRows, same]
  · simp [bytes_same, same, indexedImageRows]

/-- The extracted map materialization preserves the ordered, versioned rows. -/
theorem indexed_image_refines (index : CcfKv.kv_index.AddressIndex CcfKv.engine.Cell)
    (root : CcfKv.radix.RadixRoot) (rows : CellRows) (map : CcfKv.engine.Bytes)
    (view : IndexView index root rows) (valid : IndexValid index)
    (mapRoom : 2 * (8 + map.val.length) ≤ Usize.max)
    (room : 18 * rows.length ≤ Usize.max)
    : WP.spec (CcfKv.engine.indexed_image index root map)
        (fun out => out.val = indexedImageRows rows map) := by
  let selected := rows.filter fun r => decide (r.1.map.val = map.val)
  have hSelImg : indexedImageRows selected map = indexedImageRows rows map := by
    unfold selected indexedImageRows
    clear view valid room
    induction rows with
    | nil => rfl
    | cons r rest ih =>
        by_cases hm : r.1.map.val = map.val <;> simp [hm, ih]
  unfold CcfKv.engine.indexed_image
  apply WP.spec_bind (index_scan_map_refines index root rows map view valid mapRoom room)
  intro links ⟨length, load⟩
  change links.val.length = selected.length at length
  change ∀ (i : Nat) link, links.val[i]? = some link →
    ∃ entry, selected[i]? = some entry ∧ WP.spec (CcfKv.kv_index.AddressIndex.scan_row index link) (· = entry) at load
  apply WP.spec_bind
    (Pₘ := fun out => out.val = indexedImageRows selected map)
  · unfold CcfKv.engine.indexed_image_loop
    apply loop.spec_decr_nat (fun (_, i) => selected.length - (i : Usize).val)
      (fun (out, i) =>
        i.val ≤ selected.length
        ∧ out.val.length + (selected.length - i.val) ≤ Usize.max
        ∧ out.val ++ indexedImageRows (selected.drop i.val) map
          = indexedImageRows selected map)
      _ _ _
    · rintro ⟨out, i⟩ ⟨hi, space, ordered⟩
      dsimp only at hi space ordered ⊢
      unfold CcfKv.engine.indexed_image_loop.body
      have size := alloc.vec.Vec.len_ineq links
      have len : (alloc.vec.Vec.len links).val = links.val.length :=
        alloc.vec.Vec.len_val links
      have one : (1#usize : Usize).val = 1 := rfl
      by_cases h : i < alloc.vec.Vec.len links
      · have hb : i.val < links.val.length := by rwa [← len]
        rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec links i hb)
        intro leaf saved
        obtain ⟨row, modelRow, read⟩ := load i.val leaf
          ((List.getElem?_eq_getElem hb).trans (congrArg some saved.symm))
        apply WP.spec_bind read
        intro current same
        subst current
        cases row with
        | mk address cell =>
            apply WP.spec_bind
              (append_image_row_refines out (address, cell) map (by omega))
            intro next hn
            apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
            intro j hj
            rw [WP.spec_ok]
            dsimp only
            refine ⟨⟨by omega, by omega, ?_⟩, by omega⟩
            have within : i.val < selected.length := by omega
            have rowEq : selected[i.val] = (address, cell) := by
              rw [List.getElem?_eq_getElem within, Option.some.injEq] at modelRow
              exact modelRow
            have drop : selected.drop i.val = [(address, cell)] ++ selected.drop j.val := by
              rw [List.drop_eq_getElem_cons within, rowEq, show j.val = i.val + 1 by omega]
              rfl
            rw [hn.1, List.append_assoc, ← indexed_image_append, ← drop]
            exact ordered
      · have hb : selected.length ≤ i.val := by
          have no : ¬ i.val < (alloc.vec.Vec.len links).val := h
          omega
        rw [ite_eq_right h, WP.spec_ok]
        simpa [List.drop_eq_nil_of_le hb, indexedImageRows] using ordered
    · have hcap := alloc.vec.Vec.len_ineq links
      have h0 : (0#usize : Usize).val = 0 := rfl
      simp only [h0, Nat.zero_le, Nat.sub_zero, List.drop_zero, true_and]
      have hwc : (alloc.vec.Vec.with_capacity (CcfKv.engine.Bytes × CcfKv.engine.Cell) (alloc.vec.Vec.len links)).val = [] := by
        simp [alloc.vec.Vec.with_capacity]
      simp [hwc, ← length, hcap]
  · intro out eq
    simpa [hSelImg] using eq

end KvRust
