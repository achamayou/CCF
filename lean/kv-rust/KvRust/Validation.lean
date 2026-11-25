-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.History
public import KvRust.IndexedPublication
public import KvRust.OrderEquivalence

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

local instance : DecidableEq Spike.engine.Address :=
  fun a b =>
    decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

/-- Extracted cell lookup computes the model's point observation on the committed data. -/
theorem data_lookup (db : Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell)
    (addr : Spike.engine.Address)
    : WP.spec
        (Spike.engine.Assoc.get Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
          Spike.engine.Address.Insts.CoreCloneClone Spike.engine.Cell.Insts.CoreCloneClone
          db addr)
        (fun result => result.map byteCell = find (byteData db) (byteAddr addr)) := by
  apply WP.spec_mono
    (assoc_get Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
      Spike.engine.Address.Insts.CoreCloneClone Spike.engine.Cell.Insts.CoreCloneClone db addr
      (fun a => compare_address a addr) clone_cell)
  intro result hr
  rw [hr, byteData, find_projected db.val addr byteAddr byteCell (fun _ _ => byteAddr_inj)]

theorem index_data_lookup (index : CellIndex) (root : Spike.radix.RadixRoot)
    (rows : CellRows) (view : IndexView index root rows) (addr : Spike.engine.Address)
    (space : 8 + addr.map.val.length + addr.key.val.length ≤ Usize.max)
    : WP.spec (Spike.kv_index.AddressIndex.get index root addr)
        (fun out => out.map byteCell = find (indexedCellData rows) (byteAddr addr)) := by
  apply WP.spec_mono (index_get_refines index root rows view addr space)
  intro out same
  rw [same, indexedCellData, find_projected rows addr byteAddr byteCell (fun _ _ => byteAddr_inj)]

/-- Cell comparison includes the version, so the same value written twice is not the same cell. -/
theorem cell_same (a b : Spike.engine.Cell)
    : Spike.engine.Cell.same a b = .ok (decide (byteCell a = byteCell b)) := by
  have hversion : a.version.val = b.version.val ↔ a.version = b.version :=
    ⟨UScalar.eq_of_val_eq, congrArg (fun v : U64 => v.val)⟩
  by_cases hv : a.version = b.version
  · simp [Spike.engine.Cell.same, hv, bytes_same, byteCell]
  · simp [Spike.engine.Cell.same, hv, byteCell, hversion]

/-- Point dependencies accept exactly the unchanged cell or unchanged absence. -/
theorem point_dependency_matches_model
    (index : CellIndex) (root : Spike.radix.RadixRoot)
    (rows : CellRows) (view : IndexView index root rows)
    (addr : Spike.engine.Address) (expected : Option Spike.engine.Cell)
    (space : 8 + addr.map.val.length + addr.key.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.Dependency.holds (.Key addr expected) index root)
        (fun r =>
          r
          = (Dependency.key (byteAddr addr) (expected.map byteCell)).holds
              (indexedCellData rows)) := by
  unfold Spike.engine.Dependency.holds
  apply WP.spec_bind (index_data_lookup index root rows view addr space)
  intro lookup h
  cases lookup <;> cases expected <;> simp [Dependency.holds, ← h, cell_same]

private abbrev Rows := alloc.vec.Vec (Spike.engine.Bytes × Spike.engine.Cell)

/-- Project the ordered map image used to record a scan dependency. -/
def byteImage (rows : alloc.vec.Vec (Spike.engine.Bytes × Spike.engine.Cell))
    : Assoc (List U8) (Cell (List U8)) :=
  rows.val.map fun (k, c) => (alloc.vec.Vec.val k, byteCell c)

private def imageRows (rows : List (Spike.engine.Address × Spike.engine.Cell))
    (m : Spike.engine.Bytes)
    : Assoc (List U8) (Cell (List U8)) :=
  image (rows.map fun (a, c) => (byteAddr a, byteCell c)) (alloc.vec.Vec.val m)

private theorem image_append (rows next : List (Spike.engine.Address × Spike.engine.Cell))
    (m : Spike.engine.Bytes)
    : imageRows (rows ++ next) m = imageRows rows m ++ imageRows next m := by
  simp [imageRows, image, List.filterMap_append]

private theorem image_copy (out : Rows) (row : Spike.engine.Address × Spike.engine.Cell)
    (m : Spike.engine.Bytes) (hcap : out.val.length < Usize.max)
    : WP.spec (Spike.engine.copy_if_on_map out row m)
        (fun r =>
          byteImage r = byteImage out ++ imageRows [row] m
          ∧ r.val.length ≤ out.val.length + 1) := by
  obtain ⟨a, c⟩ := row
  unfold Spike.engine.copy_if_on_map
  change WP.spec (do
    let same ← Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey.same a.map m
    if same then
      let k ← Spike.engine.Bytes.Insts.CoreCloneClone.clone a.key
      let v ← Spike.engine.Cell.Insts.CoreCloneClone.clone c
      alloc.vec.Vec.push out (k, v)
    else Result.ok out) _
  by_cases h : alloc.vec.Vec.val a.map = alloc.vec.Vec.val m
  · simp only [bytes_same, h, decide_true, bind_ok, ite_true, clone_bytes, clone_cell]
    apply WP.spec_mono (alloc.vec.Vec.push_spec out (a.key, c) hcap)
    intro next hn
    simp [byteImage, hn, imageRows, image, byteAddr, h]
  · simp [bytes_same, h, imageRows, image, byteAddr]

/-- Extracted image construction has the same ordered cells as the model. -/
theorem image_matches_model
    (db : Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell)
    (m : Spike.engine.Bytes)
    : WP.spec (Spike.engine.image db m)
        (fun r => byteImage r = image (byteData db) (alloc.vec.Vec.val m)) := by
  unfold Spike.engine.image
  apply WP.spec_bind
    (Pₘ := fun r => byteImage r = imageRows db.val m)
  · unfold Spike.engine.image_loop
    apply loop.spec_decr_nat (fun (_, _, i) => db.val.length - (i : Usize).val)
      (fun (rows, out, i) => rows = db ∧ i.val ≤ db.val.length
        ∧ out.val.length + (db.val.length - i.val) ≤ Usize.max
        ∧ byteImage out ++ imageRows (db.val.drop i.val) m = imageRows db.val m)
      _ _ _
    · rintro ⟨rows, out, i⟩ ⟨hr, hi, hs, he⟩
      dsimp only at hr hi hs he ⊢
      subst rows
      unfold Spike.engine.image_loop.body
      have hlen : (alloc.vec.Vec.len db).val = db.val.length := alloc.vec.Vec.len_val db
      have hcap := alloc.vec.Vec.len_ineq db
      have hone : (1#usize : Usize).val = 1 := rfl
      by_cases h : i < alloc.vec.Vec.len db
      · have hb : i.val < db.val.length := by rw [← hlen]; exact h
        rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec db i hb)
        intro row hrow
        apply WP.spec_bind (image_copy out row m (by omega))
        intro next hn
        have hinc : i.val + (1#usize : Usize).val ≤ Usize.max := by omega
        apply WP.spec_bind (Usize.add_spec hinc)
        intro j hj
        have hj' : j.val = i.val + 1 := by omega
        simp only [WP.spec_ok]
        refine ⟨⟨True.intro, by omega, by omega, ?_⟩, by omega⟩
        have hdrop : db.val.drop i.val = [row] ++ db.val.drop j.val := by
          rw [hj', List.drop_eq_getElem_cons hb, ← hrow]
          rfl
        rw [hn.1, List.append_assoc, ← image_append, ← hdrop]
        exact he
      · have hb : db.val.length ≤ i.val := by
          rw [← hlen]
          exact Nat.le_of_not_gt h
        rw [ite_eq_right h, WP.spec_ok]
        simpa [List.drop_eq_nil_of_le hb, imageRows, image] using he
    · simp [byteImage]
  · intro r hr
    simpa [imageRows, byteData] using hr

/-- Whether a pinned image handle's radix root has a valid view in `index`. -/
def PinLive (index : CellIndex) : Spike.engine.PinnedImage → Prop
  | .Root root => IndexView index root (indexRows index root)
  | _ => True

/-- The byte-level map image represented by a pinned image handle. -/
noncomputable def pinImage (index : CellIndex) (map : Spike.engine.Bytes)
    : Spike.engine.PinnedImage → Assoc (List U8) (Cell (List U8))
  | .Empty => []
  | .Root root => image (indexedCellData (indexRows index root)) map.val
  | .Recovered rows => byteImage rows

/-- Capacity required to scan a pinned image handle in `index`. -/
def PinScanRoom (index : CellIndex) : Spike.engine.PinnedImage → Prop
  | .Root root => 18 * (indexRows index root).length ≤ Usize.max
  | _ => True

/-- The streaming check compares the ordered map image without constructing it. -/
private theorem indexed_same_image_matches
    (index : CellIndex) (root : Spike.radix.RadixRoot) (db : CellRows)
    (view : IndexView index root db) (valid : IndexValid index)
    (space : 18 * db.length ≤ Usize.max) (m : Spike.engine.Bytes)
    (mapRoom : 2 * (8 + m.val.length) ≤ Usize.max) (expected : Rows)
    : WP.spec (Spike.engine.indexed_same_image index root m expected)
        (fun r => r = decide (imageRows db m = byteImage expected)) := by
  let selected := db.filter fun r => decide (r.1.map.val = m.val)
  have hSelImg : imageRows selected m = imageRows db m := by
    unfold selected imageRows image
    clear view valid space mapRoom
    induction db with
    | nil => rfl
    | cons r rest ih =>
        obtain ⟨a, c⟩ := r
        by_cases hm : a.map.val = m.val <;> simpa [hm, byteAddr] using ih
  have hSelImgLen : (imageRows selected m).length = selected.length := by
    unfold selected imageRows image
    clear view valid space mapRoom hSelImg
    induction db with
    | nil => rfl
    | cons r rest ih =>
        obtain ⟨a, c⟩ := r
        by_cases hm : a.map.val = m.val <;> simp [hm, byteAddr]
  unfold Spike.engine.indexed_same_image
  apply WP.spec_bind (index_scan_map_refines index root db m view valid mapRoom space)
  intro links ⟨len, load⟩
  change links.val.length = selected.length at len
  change ∀ (i : Nat) link, links.val[i]? = some link →
    ∃ entry, selected[i]? = some entry ∧ WP.spec (Spike.kv_index.AddressIndex.scan_row index link) (· = entry) at load
  have hlen : (alloc.vec.Vec.len links).val = links.val.length := alloc.vec.Vec.len_val links
  have elen : (alloc.vec.Vec.len expected).val = expected.val.length := alloc.vec.Vec.len_val expected
  by_cases hneLen : alloc.vec.Vec.len links != alloc.vec.Vec.len expected
  · rw [ite_eq_left hneLen, WP.spec_ok]
    have hdiff : selected.length ≠ expected.val.length := by
      have hne : alloc.vec.Vec.len links ≠ alloc.vec.Vec.len expected := bne_iff_ne.mp hneLen
      intro heq
      apply hne
      apply UScalar.eq_of_val_eq
      omega
    have hnot : imageRows db m ≠ byteImage expected := by
      intro heq
      have := congrArg List.length heq
      rw [← hSelImg, hSelImgLen, byteImage, List.length_map] at this
      exact hdiff this
    simp [hnot]
  · rw [ite_eq_right hneLen]
    unfold Spike.engine.indexed_same_image_loop
    let agrees : Prop := imageRows selected m = byteImage expected
    have hAgreesEq : agrees ↔ imageRows db m = byteImage expected := by rw [← hSelImg]
    apply WP.spec_mono (P₀ := fun r => r = decide agrees)
    · apply loop.spec_decr_nat
        (fun (i, _) => selected.length - (i : Usize).val)
        (fun (i, j) => j.val ≤ expected.val.length
          ∧ (agrees ↔ imageRows (selected.drop i.val) m = (byteImage expected).drop j.val))
        _ _ _
      · rintro ⟨i, j⟩ ⟨hj, inv⟩
        dsimp only at hj inv ⊢
        unfold Spike.engine.indexed_same_image_loop.body
        have hcap := alloc.vec.Vec.len_ineq links
        have ecap := alloc.vec.Vec.len_ineq expected
        have one : (1#usize : Usize).val = 1 := rfl
        by_cases run : i < alloc.vec.Vec.len links
        · have linkBound : i.val < links.val.length := by rwa [← hlen]
          have inside : i.val < selected.length := by omega
          have inc : i.val + (1#usize : Usize).val ≤ Usize.max := by omega
          rw [ite_eq_left run, alloc.vec.Vec.index_slice_index]
          apply WP.spec_bind (alloc.vec.Vec.index_usize_spec links i linkBound)
          intro leaf saved
          obtain ⟨entry, atEntry, read⟩ := load i.val leaf
            ((List.getElem?_eq_getElem linkBound).trans (congrArg some saved.symm))
          apply WP.spec_bind read
          rintro ⟨a, v⟩ eq
          subst entry
          change WP.spec (do
            let next ← Spike.engine.match_indexed_row a v m expected j
            match next with
            | none => Result.ok (ControlFlow.done false)
            | some j' =>
                let i' ← i + 1#usize
                Result.ok (ControlFlow.cont (i', j'))) _
          unfold Spike.engine.match_indexed_row
          rw [List.getElem?_eq_getElem inside, Option.some.injEq] at atEntry
          have step : selected.drop i.val = [(a, v)] ++ selected.drop (i.val + 1) := by
            rw [List.drop_eq_getElem_cons inside, atEntry]
            rfl
          by_cases onMap : alloc.vec.Vec.val a.map = alloc.vec.Vec.val m
          · have suffix : imageRows (selected.drop i.val) m =
                (alloc.vec.Vec.val a.key, byteCell v) :: imageRows (selected.drop (i.val + 1)) m := by
              rw [step, image_append]
              simp [imageRows, image, byteAddr, onMap]
            simp only [bytes_same, bind_ok, decide_eq_true_eq]
            rw [ite_eq_left onMap]
            by_cases exhausted : j ≥ alloc.vec.Vec.len expected
            · have empty : (byteImage expected).drop j.val = [] := by
                apply List.drop_eq_nil_of_le
                simp only [byteImage, List.length_map]
                rw [← elen]
                exact exhausted
              have different : ¬agrees := by
                intro h
                have eq := inv.mp h
                rw [suffix, empty] at eq
                contradiction
              rw [ite_eq_left exhausted, bind_ok, WP.spec_ok]
              simp [agrees, different]
            · have bound : j.val < expected.val.length := by
                rw [← elen]
                exact Nat.lt_of_not_ge exhausted
              rw [ite_eq_right exhausted, alloc.vec.Vec.index_slice_index, Aeneas.Std.bind_assoc]
              apply WP.spec_bind (alloc.vec.Vec.index_usize_spec expected j bound)
              rintro ⟨k, c⟩ got
              change WP.spec (do
                let next ←
                  if a.key.val = k.val then do
                    let b ← Spike.engine.Cell.same v c
                    if b then
                      let j' ← j + 1#usize
                      Result.ok (some j')
                    else Result.ok none
                  else Result.ok none
                match next with
                | none => Result.ok (ControlFlow.done false)
                | some j' =>
                    let i' ← i + 1#usize
                    Result.ok (ControlFlow.cont (i', j'))) _
              have rest : (byteImage expected).drop j.val =
                  (alloc.vec.Vec.val k, byteCell c) :: (byteImage expected).drop (j.val + 1) := by
                unfold byteImage
                rw [← List.map_drop, List.drop_eq_getElem_cons bound, ← got, List.map_cons, List.map_drop]
              have eq : agrees ↔ alloc.vec.Vec.val a.key = alloc.vec.Vec.val k
                  ∧ byteCell v = byteCell c
                  ∧ imageRows (selected.drop (i.val + 1)) m = (byteImage expected).drop (j.val + 1) := by
                rw [inv, suffix, rest]
                simp [and_assoc]
              by_cases key : alloc.vec.Vec.val a.key = alloc.vec.Vec.val k
              · by_cases value : byteCell v = byteCell c
                · simp only [cell_same, bind_ok, decide_eq_true_eq, key, value, ite_true]
                  rw [Aeneas.Std.bind_assoc]
                  apply WP.spec_bind (Usize.add_spec (x := j) (y := 1#usize) (by omega))
                  intro j' nextJ
                  simp only [bind_ok]
                  apply WP.spec_bind (Usize.add_spec inc)
                  intro i' nextI
                  have jEq : j'.val = j.val + 1 := by omega
                  have iEq : i'.val = i.val + 1 := by omega
                  rw [WP.spec_ok]
                  dsimp only
                  refine ⟨⟨by omega, ?_⟩, by omega⟩
                  simpa [iEq, jEq, key, value] using eq
                · have different : ¬agrees := fun h => value (eq.mp h).2.1
                  simp [cell_same, key, value, agrees, different]
              · have different : ¬agrees := fun h => key (eq.mp h).1
                simp [key, agrees, different]
          · have suffix : imageRows (selected.drop i.val) m = imageRows (selected.drop (i.val + 1)) m := by
              rw [step, image_append]
              simp [imageRows, image, byteAddr, onMap]
            simp only [bytes_same, bind_ok, decide_eq_true_eq]
            rw [ite_eq_right onMap, bind_ok]
            apply WP.spec_bind (Usize.add_spec inc)
            intro i' nextI
            have iEq : i'.val = i.val + 1 := by omega
            rw [WP.spec_ok]
            dsimp only
            refine ⟨⟨hj, ?_⟩, by omega⟩
            simpa [iEq, suffix] using inv
        · have off : selected.length ≤ i.val := by rw [← len, ← hlen]; exact Nat.le_of_not_gt run
          rw [ite_eq_right run, WP.spec_ok]
          have remaining : agrees ↔ expected.val.length ≤ j.val := by
            rw [inv, List.drop_eq_nil_of_le off]
            simp only [imageRows, image, List.map_nil, List.filterMap_nil]
            rw [Eq.comm, List.drop_eq_nil_iff]
            simp only [byteImage, List.length_map]
          have cmp : j = alloc.vec.Vec.len expected ↔ agrees := by
            constructor
            · intro h
              exact remaining.mpr (by simp [h, elen])
            · intro h
              have le := remaining.mp h
              apply UScalar.eq_of_val_eq
              omega
          change decide (j = alloc.vec.Vec.len expected) = decide agrees
          exact decide_eq_decide.mpr cmp
      · simp [agrees]
    · intro r hr
      rw [hr]
      exact decide_eq_decide.mpr hAgreesEq

private theorem imageRows_filter_eq (db : CellRows) (m : Spike.engine.Bytes)
    : imageRows (db.filter fun r => decide (r.1.map.val = m.val)) m = imageRows db m := by
  unfold imageRows image
  induction db with
  | nil => rfl
  | cons r rest ih =>
      obtain ⟨a, c⟩ := r
      by_cases hm : a.map.val = m.val <;> simpa [hm, byteAddr] using ih

private theorem imageRows_filter_length (db : CellRows) (m : Spike.engine.Bytes)
    : (imageRows (db.filter fun r => decide (r.1.map.val = m.val)) m).length
      = (db.filter fun r => decide (r.1.map.val = m.val)).length := by
  unfold imageRows image
  induction db with
  | nil => rfl
  | cons r rest ih =>
      obtain ⟨a, c⟩ := r
      by_cases hm : a.map.val = m.val
      · simp only [List.filter_cons, hm, decide_true, List.map_cons, List.filterMap_cons,
          byteAddr, ite_true, List.length_cons]
        exact congrArg Nat.succ ih
      · simp only [List.filter_cons, hm, decide_false, Bool.false_eq_true, ite_false]
        exact ih

private theorem indexed_same_map_roots_matches
    (index : CellIndex) (leftRoot rightRoot : Spike.radix.RadixRoot)
    (dbL dbR : CellRows)
    (viewL : IndexView index leftRoot dbL) (viewR : IndexView index rightRoot dbR)
    (valid : IndexValid index)
    (spaceL : 18 * dbL.length ≤ Usize.max) (spaceR : 18 * dbR.length ≤ Usize.max)
    (m : Spike.engine.Bytes) (mapRoom : 2 * (8 + m.val.length) ≤ Usize.max)
    : WP.spec (Spike.engine.indexed_same_map_roots index leftRoot rightRoot m)
        (fun r => r = decide (imageRows dbL m = imageRows dbR m)) := by
  unfold Spike.engine.indexed_same_map_roots
  by_cases hSameRoot : leftRoot = rightRoot
  · subst hSameRoot
    have hdb : dbL = dbR := index_view_unique viewL viewR
    subst hdb
    simp
  · rw [ite_eq_right hSameRoot]
    let selL := dbL.filter fun r => decide (r.1.map.val = m.val)
    let selR := dbR.filter fun r => decide (r.1.map.val = m.val)
    have hImgL : imageRows selL m = imageRows dbL m := imageRows_filter_eq dbL m
    have hImgR : imageRows selR m = imageRows dbR m := imageRows_filter_eq dbR m
    have hLenImgL : (imageRows selL m).length = selL.length := imageRows_filter_length dbL m
    have hLenImgR : (imageRows selR m).length = selR.length := imageRows_filter_length dbR m
    apply WP.spec_bind
      (index_scan_map_refines index leftRoot dbL m viewL valid mapRoom spaceL)
    intro linksL ⟨lenL, loadL⟩
    apply WP.spec_bind
      (index_scan_map_refines index rightRoot dbR m viewR valid mapRoom spaceR)
    intro linksR ⟨lenR, loadR⟩
    change linksL.val.length = selL.length at lenL
    change linksR.val.length = selR.length at lenR
    change ∀ (i : Nat) link, linksL.val[i]? = some link →
      ∃ entry, selL[i]? = some entry ∧ WP.spec (Spike.kv_index.AddressIndex.scan_row index link) (· = entry) at loadL
    change ∀ (i : Nat) link, linksR.val[i]? = some link →
      ∃ entry, selR[i]? = some entry ∧ WP.spec (Spike.kv_index.AddressIndex.scan_row index link) (· = entry) at loadR
    have hlenL : (alloc.vec.Vec.len linksL).val = linksL.val.length := alloc.vec.Vec.len_val linksL
    have hlenR : (alloc.vec.Vec.len linksR).val = linksR.val.length := alloc.vec.Vec.len_val linksR
    by_cases hneLen : alloc.vec.Vec.len linksL != alloc.vec.Vec.len linksR
    · rw [ite_eq_left hneLen, WP.spec_ok]
      have hdiff : selL.length ≠ selR.length := by
        have hne : alloc.vec.Vec.len linksL ≠ alloc.vec.Vec.len linksR := bne_iff_ne.mp hneLen
        intro heq
        apply hne
        apply UScalar.eq_of_val_eq
        omega
      have hnot : imageRows dbL m ≠ imageRows dbR m := by
        intro heq
        have := congrArg List.length heq
        rw [← hImgL, ← hImgR, hLenImgL, hLenImgR] at this
        exact hdiff this
      simp [hnot]
    · rw [ite_eq_right hneLen]
      have hEqLen : selL.length = selR.length := by
        have heq : alloc.vec.Vec.len linksL = alloc.vec.Vec.len linksR := by
          by_contra hne
          exact hneLen (bne_iff_ne.mpr hne)
        have hval := congrArg (fun x : Usize => x.val) heq
        omega
      unfold Spike.engine.indexed_same_map_roots_loop
      let agrees : Prop := imageRows selL m = imageRows selR m
      have hAgreesEq : agrees ↔ imageRows dbL m = imageRows dbR m := by rw [← hImgL, ← hImgR]
      apply WP.spec_mono (P₀ := fun r => r = decide agrees)
      · apply loop.spec_decr_nat
          (fun (i : Usize) => selL.length - i.val)
          (fun i =>
            agrees ↔ imageRows (selL.drop i.val) m = imageRows (selR.drop i.val) m)
          _ _ _
        · intro i inv
          unfold Spike.engine.indexed_same_map_roots_loop.body
          have hcap := alloc.vec.Vec.len_ineq linksL
          have one : (1#usize : Usize).val = 1 := rfl
          by_cases run : i < alloc.vec.Vec.len linksL
          · have linkBoundL : i.val < linksL.val.length := by rwa [← hlenL]
            have linkBoundR : i.val < linksR.val.length := by omega
            have insideL : i.val < selL.length := by omega
            have insideR : i.val < selR.length := by omega
            have inc : i.val + (1#usize : Usize).val ≤ Usize.max := by omega
            rw [ite_eq_left run, alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_slice_index]
            apply WP.spec_bind (alloc.vec.Vec.index_usize_spec linksL i linkBoundL)
            intro leafL savedL
            apply WP.spec_bind (alloc.vec.Vec.index_usize_spec linksR i linkBoundR)
            intro leafR savedR
            obtain ⟨entryL, atL, readL⟩ := loadL i.val leafL
              ((List.getElem?_eq_getElem linkBoundL).trans (congrArg some savedL.symm))
            obtain ⟨entryR, atR, readR⟩ := loadR i.val leafR
              ((List.getElem?_eq_getElem linkBoundR).trans (congrArg some savedR.symm))
            have hMapL : entryL.1.map.val = m.val := by
              have hmem : entryL ∈ selL := List.mem_of_getElem? atL
              exact of_decide_eq_true (List.mem_filter.mp hmem).2
            have hMapR : entryR.1.map.val = m.val := by
              have hmem : entryR ∈ selR := List.mem_of_getElem? atR
              exact of_decide_eq_true (List.mem_filter.mp hmem).2
            rw [List.getElem?_eq_getElem insideL, Option.some.injEq] at atL
            rw [List.getElem?_eq_getElem insideR, Option.some.injEq] at atR
            have stepL : imageRows (selL.drop i.val) m =
                (entryL.1.key.val, byteCell entryL.2) :: imageRows (selL.drop (i.val + 1)) m := by
              have hdrop : selL.drop i.val = [entryL] ++ selL.drop (i.val + 1) := by
                rw [List.drop_eq_getElem_cons insideL, atL]; rfl
              rw [hdrop, image_append]
              simp [imageRows, image, byteAddr, hMapL]
            have stepR : imageRows (selR.drop i.val) m =
                (entryR.1.key.val, byteCell entryR.2) :: imageRows (selR.drop (i.val + 1)) m := by
              have hdrop : selR.drop i.val = [entryR] ++ selR.drop (i.val + 1) := by
                rw [List.drop_eq_getElem_cons insideR, atR]; rfl
              rw [hdrop, image_append]
              simp [imageRows, image, byteAddr, hMapR]
            have eqStep : agrees ↔ entryL.1.key.val = entryR.1.key.val
                ∧ byteCell entryL.2 = byteCell entryR.2
                ∧ imageRows (selL.drop (i.val + 1)) m = imageRows (selR.drop (i.val + 1)) m := by
              rw [inv, stepL, stepR]
              simp [and_assoc]
            have hSameLink : WP.spec (Spike.engine.same_map_link index leafL leafR)
                (fun b => b = decide (entryL.1.key.val = entryR.1.key.val
                  ∧ byteCell entryL.2 = byteCell entryR.2)) := by
              unfold Spike.engine.same_map_link
              by_cases hlr : leafL = leafR
              · subst hlr
                rw [ite_eq_left rfl, WP.spec_ok]
                have hEntEq : entryL = entryR := by
                  cases hsr : Spike.kv_index.AddressIndex.scan_row index leafL
                    using Result.cases with
                  | ret v =>
                      rw [hsr, WP.spec_ok] at readL readR
                      exact readL.symm.trans readR
                  | vis _ _ => simp [hsr] at readL
                  | div => simp [hsr] at readL
                simp [hEntEq]
              · rw [ite_eq_right hlr]
                apply WP.spec_bind readL
                rintro ⟨la, lc⟩ heL
                apply WP.spec_bind readR
                rintro ⟨ra, rc⟩ heR
                simp only [bytes_same, bind_ok]
                by_cases hk : la.key.val = ra.key.val
                · simp [hk, cell_same, ← heL, ← heR]
                · simp [hk, ← heL, ← heR]
            apply WP.spec_bind hSameLink
            intro b hb
            cases b with
            | false =>
                have hdiff : ¬agrees := by
                  intro h
                  have ⟨hk, hc, _⟩ := eqStep.mp h
                  simp [hk, hc] at hb
                simp [agrees, hdiff]
            | true =>
                have ⟨hk, hc⟩ : entryL.1.key.val = entryR.1.key.val
                    ∧ byteCell entryL.2 = byteCell entryR.2 := by
                  simpa using hb.symm
                simp only [ite_true]
                apply WP.spec_bind (Usize.add_spec inc)
                intro i' nextI
                have iEq : i'.val = i.val + 1 := by omega
                rw [WP.spec_ok]
                refine ⟨?_, by omega⟩
                simpa [iEq, hk, hc] using eqStep
          · have offL : selL.length ≤ i.val := by rw [← lenL, ← hlenL]; exact Nat.le_of_not_gt run
            have offR : selR.length ≤ i.val := by omega
            rw [ite_eq_right run, WP.spec_ok]
            have htrue : agrees := by
              rw [inv, List.drop_eq_nil_of_le offL, List.drop_eq_nil_of_le offR]
            simp [agrees, htrue]
        · simp [agrees]
      · intro r hr
        rw [hr]
        exact decide_eq_decide.mpr hAgreesEq

/-- Extracted whole-map dependencies detect inserts, deletions and version changes. -/
theorem map_dependency_matches_model
    (index : CellIndex) (root : Spike.radix.RadixRoot) (db : CellRows)
    (view : IndexView index root db) (valid : IndexValid index)
    (space : 18 * db.length ≤ Usize.max)
    (m : Spike.engine.Bytes) (mapRoom : 2 * (8 + m.val.length) ≤ Usize.max)
    (expected : Spike.engine.PinnedImage)
    (pinLive : PinLive index expected) (pinRoom : PinScanRoom index expected)
    : WP.spec (Spike.engine.Dependency.holds (.Map m expected) index root)
        (fun r =>
          r
          = (Dependency.map (alloc.vec.Vec.val m) (pinImage index m expected)).holds
              (indexedCellData db)) := by
  unfold Spike.engine.Dependency.holds
  cases expected with
  | Empty =>
      apply WP.spec_bind (index_scan_map_refines index root db m view valid mapRoom space)
      intro links ⟨len, _⟩
      simp only [alloc.vec.Vec.is_empty, WP.spec_ok, Dependency.holds, pinImage]
      have hsel := imageRows_filter_eq db m
      have hslen := imageRows_filter_length db m
      have hiff : links.val.length = 0 ↔ image (indexedCellData db) m.val = [] := by
        change links.val.length = 0 ↔ imageRows db m = []
        rw [len, ← hslen, List.length_eq_zero_iff, hsel]
      exact decide_eq_decide.mpr hiff
  | Root pinned =>
      apply WP.spec_mono
        (indexed_same_map_roots_matches index root pinned db (indexRows index pinned)
          view pinLive valid space pinRoom m mapRoom)
      intro result h
      rw [h, Dependency.holds, pinImage]
      exact decide_eq_decide.mpr (by rfl)
  | Recovered rows =>
      apply WP.spec_mono
        (indexed_same_image_matches index root db view valid space m mapRoom rows)
      intro result h
      rw [h, Dependency.holds, pinImage]
      exact decide_eq_decide.mpr (by rfl)

/-- Project an extracted dependency into the existing KV model. -/
noncomputable def byteDependency (index : CellIndex)
    : Spike.engine.Dependency → Dependency (List U8) (List U8) (List U8)
  | .Key addr expected => .key (byteAddr addr) (expected.map byteCell)
  | .Map m expected => .map (alloc.vec.Vec.val m) (pinImage index m expected)

def DependencyRoom (index : CellIndex) (db : CellRows) : Spike.engine.Dependency → Prop
  | .Key a _ => 8 + a.map.val.length + a.key.val.length ≤ Usize.max
  | .Map m expected =>
      18 * db.length ≤ Usize.max
      ∧ 2 * (8 + m.val.length) ≤ Usize.max
      ∧ PinLive index expected
      ∧ PinScanRoom index expected

private theorem dependency_matches_model (index : CellIndex)
    (root : Spike.radix.RadixRoot) (db : CellRows) (view : IndexView index root db)
    (valid : IndexValid index) (d : Spike.engine.Dependency)
    (room : DependencyRoom index db d)
    : WP.spec (Spike.engine.Dependency.holds d index root)
        (fun r =>
          r = (byteDependency index d).holds (indexedCellData db)) := by
  cases d with
  | Key a e => exact point_dependency_matches_model index root db view a e room
  | Map m e =>
      exact map_dependency_matches_model index root db view valid room.1 m room.2.1 e
        room.2.2.1 room.2.2.2

/-- The extracted OCC read-set check accepts exactly the dependencies accepted by the model. -/
theorem validate_dependencies_matches_model
    (t : Spike.engine.Tx) (history : Spike.engine.History) (head : Spike.engine.Frame)
    (db : CellRows) (view : IndexView history.index head.data db)
    (valid : IndexValid history.index)
    (read : WP.spec (Spike.engine.History.head history) (· = head))
    (room : ∀ d ∈ t.deps.val, DependencyRoom history.index db d)
    : WP.spec (Spike.engine.Tx.valid_dependencies t history)
        (fun r =>
          r
          = validates (indexedCellData db)
              (t.deps.val.map (byteDependency history.index))) := by
  let checks := fun (deps : List Spike.engine.Dependency) =>
    validates (indexedCellData db) (deps.map (byteDependency history.index))
  unfold Spike.engine.Tx.valid_dependencies Spike.engine.Tx.valid_dependencies_loop
  apply loop.spec_decr_nat (fun (i : Usize) => t.deps.val.length - i.val)
    (fun i => checks (t.deps.val.drop i.val) = checks t.deps.val) _ _ _
  · intro i hinv
    unfold Spike.engine.Tx.valid_dependencies_loop.body
    have hlen : (alloc.vec.Vec.len t.deps).val = t.deps.val.length := alloc.vec.Vec.len_val t.deps
    have hcap := alloc.vec.Vec.len_ineq t.deps
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len t.deps
    · have hb : i.val < t.deps.val.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec t.deps i hb)
      intro d hd
      apply WP.spec_bind read
      intro actual ha
      subst actual
      apply WP.spec_bind (dependency_matches_model history.index head.data db view valid d
        (room d (hd ▸ List.getElem_mem _)))
      intro result hresult
      have hp := hinv
      rw [List.drop_eq_getElem_cons hb, ← hd] at hp
      cases result with
      | false =>
          simp only [Bool.false_eq_true, ite_false, WP.spec_ok]
          simpa [checks, validates, ← hresult] using hp
      | true =>
          simp only [ite_true]
          have hinc : i.val + (1#usize : Usize).val ≤ Usize.max := by omega
          apply WP.spec_bind (Usize.add_spec hinc)
          intro j hj
          have hj' : j.val = i.val + 1 := by omega
          simp only [WP.spec_ok]
          refine ⟨?_, by omega⟩
          simpa [hj', checks, validates, ← hresult] using hp
    · have hb : t.deps.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      rw [ite_eq_right h, WP.spec_ok]
      simpa [List.drop_eq_nil_of_le hb, checks, validates] using hinv
  · simp

/-- Encode both coordinates of a byte address as strings. -/
def encodeAddr (encode : List U8 → String) (a : Addr (List U8) (List U8))
    : Addr String String :=
  (encode a.1, encode a.2)

/-- Encode a value while preserving the version that wrote it. -/
def encodeCell (encode : List U8 → String) (c : Cell (List U8)) : Cell String :=
  {value := encode c.value, version := c.version}

/-- Encode an ordered cell image without changing its order. -/
def encodeImage (encode : List U8 → String) (rows : Assoc (List U8) (Cell (List U8)))
    : Assoc String (Cell String) :=
  rows.map fun (k, c) => (encode k, encodeCell encode c)

/-- Encode committed data for the string instance used by the executable KV model. -/
def encodeData (encode : List U8 → String) (db : DB (List U8) (List U8) (List U8))
    : Data :=
  db.map fun (a, c) => (encodeAddr encode a, encodeCell encode c)

/-- Encode the observation that is tested by a dependency. -/
def encodeDependency (encode : List U8 → String)
    : Dependency (List U8) (List U8) (List U8) → Dependency String String String
  | .key a c => .key (encodeAddr encode a) (c.map (encodeCell encode))
  | .map m cells => .map (encode m) (encodeImage encode cells)

/-- An injective encoding preserves address identity. -/
theorem encode_addr_inj {encode : List U8 → String} (inj : Function.Injective encode)
    : Function.Injective (encodeAddr encode) := by
  intro a b h
  exact Prod.ext (inj (congrArg Prod.fst h)) (inj (congrArg Prod.snd h))

private theorem encode_cell_inj {encode : List U8 → String}
    (inj : Function.Injective encode)
    : Function.Injective (encodeCell encode) := by
  intro a b h
  cases a
  cases b
  simp only [encodeCell, Cell.mk.injEq] at h ⊢
  exact ⟨inj h.1, h.2⟩

private theorem encode_image_inj {encode : List U8 → String}
    (inj : Function.Injective encode)
    : Function.Injective (encodeImage encode) := by
  intro a b hab
  induction a generalizing b with
  | nil => cases b <;> simp_all [encodeImage]
  | cons row rows ih =>
      cases b with
      | nil => simp [encodeImage] at hab
      | cons row' rows' =>
          have hr : Prod.map encode (encodeCell encode) row =
              Prod.map encode (encodeCell encode) row' ∧
                encodeImage encode rows = encodeImage encode rows' := by
            obtain ⟨k, c⟩ := row
            obtain ⟨k', c'⟩ := row'
            simpa only [encodeImage, List.map_cons, List.cons.injEq, Prod.map] using hab
          rw [(inj.prodMap (encode_cell_inj inj)) hr.1, ih hr.2]

/-- An injective encoding preserves the contents and order of a map image. -/
theorem image_encoding (encode : List U8 → String)
    (inj : Function.Injective encode) (db : DB (List U8) (List U8) (List U8))
    (m : List U8)
    : image (encodeData encode db) (encode m) = encodeImage encode (image db m) := by
  induction db with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨⟨map, key⟩, cell⟩ := row
      by_cases h : map = m
      · subst map
        simp [image, encodeData, encodeImage, encodeAddr] at ih ⊢
        exact ih
      · have hn : encode map ≠ encode m := fun he => h (inj he)
        simp [image, encodeData, encodeImage, encodeAddr, h, hn] at ih ⊢
        exact ih

private theorem dependency_encoding (encode : List U8 → String)
    (inj : Function.Injective encode) (db : DB (List U8) (List U8) (List U8))
    (d : Dependency (List U8) (List U8) (List U8))
    : (encodeDependency encode d).holds (encodeData encode db) = d.holds db := by
  cases d with
  | key a expected =>
      apply decide_eq_decide.mpr
      unfold encodeData
      rw [find_projected db a (encodeAddr encode) (encodeCell encode)
            (encode_addr_inj inj)]
      exact ⟨fun h => Option.map_injective (encode_cell_inj inj) h,
        congrArg (Option.map (encodeCell encode))⟩
  | map m expected =>
      apply decide_eq_decide.mpr
      rw [image_encoding encode inj]
      exact ⟨fun h => encode_image_inj inj h, congrArg (encodeImage encode)⟩

/-- Dependency validation is unchanged by an injective encoding into the executable model. -/
theorem validates_encoding (encode : List U8 → String) (inj : Function.Injective encode)
    (db : DB (List U8) (List U8) (List U8))
    (ds : List (Dependency (List U8) (List U8) (List U8)))
    : validates (encodeData encode db) (ds.map (encodeDependency encode))
      = validates db ds := by
  simp only [validates, List.all_map, Function.comp_def]
  exact List.all_congr rfl (dependency_encoding encode inj db)

/-- Rust appends dependencies while the model prepends them. -/
noncomputable def pointDeps (encode : List U8 → String) (index : CellIndex)
    (t : Spike.engine.Tx)
    : List (Dependency String String String) :=
  (t.deps.val.map (encodeDependency encode ∘ byteDependency index)).reverse

/-- On an ordinary branch, the extracted OCC check implements the relaxed
dependency contract for captured images that still have a surviving origin. -/
theorem validate_dependencies_by_contents (encode : List U8 → String)
    (inj : Function.Injective encode) (t : Spike.engine.Tx)
    (history : Spike.engine.History) (head : Spike.engine.Frame) (db : CellRows)
    (view : IndexView history.index head.data db) (valid : IndexValid history.index)
    (read : WP.spec (Spike.engine.History.head history) (· = head))
    (room : ∀ d ∈ t.deps.val, DependencyRoom history.index db d) (frames : List Frame)
    (current model : Frame) (shape : Kv.Properties.History frames current.version)
    (present : current ∈ frames)
    (nativeData : current.data = encodeData encode (indexedCellData db))
    (same : FrameOrderEq current model) (unique : Kv.Properties.Unique current.data)
    (reference : List (Dependency String String String))
    (related
      : List.Forall₂ DependencyOrderEq (pointDeps encode history.index t) reference)
    (origins
      : ∀ d ∈ pointDeps encode history.index t, DependencyHasOrigin frames current d)
    : WP.spec (Spike.engine.Tx.valid_dependencies t history)
        (fun r => r = reference.all (holdsByContents model.data)) := by
  apply WP.spec_mono
    (validate_dependencies_matches_model t history head db view valid read room)
  intro r checked
  rw [← validates_encoding encode inj, ← nativeData] at checked
  have reordered : validates current.data (pointDeps encode history.index t) =
      validates current.data
        ((t.deps.val.map (byteDependency history.index)).map (encodeDependency encode)) := by
    simp only [pointDeps, validates, List.all_reverse, List.map_map]
  exact checked.trans (reordered.symm.trans
    (validates_by_contents shape current model present same unique related origins))

/-- Encoding staged writes preserves deletions and the order of writes. -/
def encodeWrites (encode : List U8 → String)
    (writes : Writes (List U8) (List U8) (List U8))
    : Pending :=
  writes.map fun (addr, v) => (encodeAddr encode addr, v.map encode)

/-- Publication commutes with an injective encoding into the executable model. -/
theorem publish_encoding (encode : List U8 → String) (inj : Function.Injective encode)
    (db : DB (List U8) (List U8) (List U8)) (version : Nat)
    (writes : Writes (List U8) (List U8) (List U8))
    : encodeData encode (publish db version writes)
      = publish (encodeData encode db) version (encodeWrites encode writes) := by
  induction writes with
  | nil => rfl
  | cons w rest ih =>
      obtain ⟨addr, value⟩ := w
      cases value with
      | none =>
          simp only [encodeWrites, publish, List.map_cons, List.foldr_cons, Option.map_none] at ih ⊢
          rw [← ih]
          exact (erase_projected _ addr (encodeAddr encode) (encodeCell encode) (encode_addr_inj inj)).symm
      | some v =>
          simp only [encodeWrites, publish, List.map_cons, List.foldr_cons, Option.map_some] at ih ⊢
          rw [← ih]
          exact (set_projected _ addr {value := v, version} (encodeAddr encode) (encodeCell encode)
            (encode_addr_inj inj)).symm

end KvRust
