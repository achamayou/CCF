-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.KvIndex

@[expose] public section

namespace KvRust

open Aeneas.Std

abbrev CellRows := List (Spike.engine.Address × Spike.engine.Cell)

abbrev MapRows := alloc.vec.Vec (Spike.engine.Bytes × Spike.engine.Cell)

def indexedImageRows (rows : CellRows) (map : Spike.engine.Bytes)
    : List (Spike.engine.Bytes × Spike.engine.Cell) :=
  rows.filterMap fun (a, c) => if a.map.val = map.val then some (a.key, c) else none

theorem indexed_image_append (rows more : CellRows) (map : Spike.engine.Bytes)
    : indexedImageRows (rows ++ more) map
      = indexedImageRows rows map ++ indexedImageRows more map := by
  simp [indexedImageRows, List.filterMap_append]

theorem indexed_image_projects (rows : CellRows) (map : Spike.engine.Bytes)
    : (indexedImageRows rows map).map (fun (k, c) => (k.val, byteCell c))
      = Kv.Model.image (rows.map fun (a, c) => (byteAddr a, byteCell c)) map.val := by
  induction rows with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨a, c⟩ := row
      by_cases same : a.map.val = map.val <;>
        simp [indexedImageRows, Kv.Model.image, byteAddr, same] at ih ⊢ <;> rw [ih]

private theorem append_image_row_refines (out : MapRows)
    (row : Spike.engine.Address × Spike.engine.Cell) (map : Spike.engine.Bytes)
    (room : out.val.length < Usize.max)
    : WP.spec (Spike.engine.append_image_row out row.1 row.2 map)
        (fun next =>
          next.val = out.val ++ indexedImageRows [row] map
          ∧ next.val.length ≤ out.val.length + 1) := by
  obtain ⟨a, c⟩ := row
  unfold Spike.engine.append_image_row
  by_cases same : a.map.val = map.val
  · simp only [bytes_same, same, decide_true, bind_ok, ite_true, clone_bytes, clone_cell]
    apply WP.spec_mono (alloc.vec.Vec.push_spec out (a.key, c) room)
    intro next hn
    simp [hn, indexedImageRows, same]
  · simp [bytes_same, same, indexedImageRows]

/-- The extracted map materialization preserves the ordered, versioned rows. -/
theorem indexed_image_refines (index : Spike.kv_index.AddressIndex Spike.engine.Cell)
    (root : Spike.radix.DualRoot) (rows : CellRows) (map : Spike.engine.Bytes)
    (view : IndexView index root rows) (valid : IndexValid index)
    (room : 18 * rows.length ≤ Usize.max)
    : WP.spec (Spike.engine.indexed_image index root map)
        (fun out => out.val = indexedImageRows rows map) := by
  unfold Spike.engine.indexed_image
  apply WP.spec_bind (index_scan_refines index root rows view valid room)
  intro links ⟨length, load⟩
  apply WP.spec_bind
    (Pₘ := fun out => out.val = indexedImageRows rows map)
  · unfold Spike.engine.indexed_image_loop
    apply loop.spec_decr_nat (fun (_, i) => rows.length - (i : Usize).val)
      (fun (out, i) =>
        i.val ≤ rows.length
        ∧ out.val.length + (rows.length - i.val) ≤ Usize.max
        ∧ out.val ++ indexedImageRows (rows.drop i.val) map = indexedImageRows rows map)
      _ _ _
    · rintro ⟨out, i⟩ ⟨hi, space, ordered⟩
      dsimp only at hi space ordered ⊢
      unfold Spike.engine.indexed_image_loop.body
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
            have within : i.val < rows.length := by omega
            have rowEq : rows[i.val] = (address, cell) := by
              rw [List.getElem?_eq_getElem within, Option.some.injEq] at modelRow
              exact modelRow
            have drop : rows.drop i.val = [(address, cell)] ++ rows.drop j.val := by
              rw [List.drop_eq_getElem_cons within, rowEq, show j.val = i.val + 1 by omega]
              rfl
            rw [hn.1, List.append_assoc, ← indexed_image_append, ← drop]
            exact ordered
      · have hb : rows.length ≤ i.val := by
          have no : ¬ i.val < (alloc.vec.Vec.len links).val := h
          omega
        rw [ite_eq_right h, WP.spec_ok]
        simpa [List.drop_eq_nil_of_le hb, indexedImageRows] using ordered
    · simp [← length, alloc.vec.Vec.len_ineq links]
  · intro out eq
    simpa using eq

end KvRust
