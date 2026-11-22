-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Publication

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
    (db : Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell)
    (addr : Spike.engine.Address) (expected : Option Spike.engine.Cell)
    : WP.spec (Spike.engine.Dependency.holds (.Key addr expected) db)
        (fun r =>
          r
          = (Dependency.key (byteAddr addr) (expected.map byteCell)).holds
              (byteData db)) := by
  unfold Spike.engine.Dependency.holds
  apply WP.spec_bind (data_lookup db addr)
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

private theorem same_image_suffix (a b : Rows) (hsize : a.val.length = b.val.length)
    : WP.spec (Spike.engine.same_image_loop a b 0#usize)
        (fun ok => ok = decide (byteImage a = byteImage b)) := by
  unfold Spike.engine.same_image_loop
  apply loop.spec_decr_nat (fun (i : Usize) => a.val.length - i.val)
    (fun i =>
      byteImage a = byteImage b ↔ (byteImage a).drop i.val = (byteImage b).drop i.val)
    _ _ _
  · intro i hinv
    unfold Spike.engine.same_image_loop.body
    have hlen : (alloc.vec.Vec.len a).val = a.val.length := alloc.vec.Vec.len_val a
    have hcap := alloc.vec.Vec.len_ineq a
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len a
    · have ha : i.val < a.val.length := by rw [← hlen]; exact h
      have hb : i.val < b.val.length := hsize ▸ ha
      simp only [h, ite_true, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec a i ha)
      rintro ⟨ak, av⟩ harow
      change WP.spec (do
        let row ← alloc.vec.Vec.index_usize b i
        let same ← Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey.same ak row.1
        if same then
          let equal ← Spike.engine.Cell.same av row.2
          if equal then
            let next ← i + 1#usize
            Result.ok (ControlFlow.cont next)
          else Result.ok (ControlFlow.done false)
        else Result.ok (ControlFlow.done false)) _
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec b i hb)
      rintro ⟨bk, bv⟩ hbrow
      have he :
          byteImage a = byteImage b ↔
            alloc.vec.Vec.val ak = alloc.vec.Vec.val bk ∧ byteCell av = byteCell bv ∧
              (byteImage a).drop (i.val + 1) = (byteImage b).drop (i.val + 1) := by
        rw [hinv]
        unfold byteImage
        rw [← List.map_drop, ← List.map_drop, List.drop_eq_getElem_cons ha,
          List.drop_eq_getElem_cons hb, ← harow, ← hbrow]
        simp [List.map_drop, and_assoc]
      by_cases hk : alloc.vec.Vec.val ak = alloc.vec.Vec.val bk
      · by_cases hv : byteCell av = byteCell bv
        · simp only [bytes_same, cell_same, hk, hv, decide_true, bind_ok, ite_true]
          have hinc : i.val + (1#usize : Usize).val ≤ Usize.max := by omega
          apply WP.spec_bind (Usize.add_spec hinc)
          intro next hn
          have hn' : next.val = i.val + 1 := by omega
          simp only [WP.spec_ok]
          refine ⟨?_, by omega⟩
          simpa [hn', hk, hv] using he
        · have hne : byteImage a ≠ byteImage b := fun eq => hv (he.mp eq).2.1
          simp [bytes_same, cell_same, hk, hv, hne]
      · have hne : byteImage a ≠ byteImage b := fun eq => hk (he.mp eq).1
        simp [bytes_same, hk, hne]
    · have ha : a.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      have hb : b.val.length ≤ i.val := hsize ▸ ha
      have he : byteImage a = byteImage b := hinv.mpr (by
        simp [byteImage, ← List.map_drop, List.drop_eq_nil_of_le ha, List.drop_eq_nil_of_le hb])
      simp [h, he]
  · simp

/-- Comparing extracted map images accepts exactly equal ordered key/cell lists. -/
theorem same_image_matches_model
    (a b : alloc.vec.Vec (Spike.engine.Bytes × Spike.engine.Cell))
    : WP.spec (Spike.engine.same_image a b)
        (fun r => r = decide (byteImage a = byteImage b)) := by
  unfold Spike.engine.same_image
  by_cases h : alloc.vec.Vec.len a = alloc.vec.Vec.len b
  · have hlen : a.val.length = b.val.length := by
      exact (alloc.vec.Vec.len_val a).symm.trans
        ((congrArg (fun i : Usize => i.val) h).trans (alloc.vec.Vec.len_val b))
    simpa [h] using same_image_suffix a b hlen
  · have hne : byteImage a ≠ byteImage b :=
      fun he =>
        h (UScalar.eq_of_val_eq (by simpa [byteImage] using congrArg List.length he))
    simp [h, hne]

/-- Extracted whole-map dependencies detect inserts, deletions and version changes. -/
theorem map_dependency_matches_model
    (db : Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell)
    (m : Spike.engine.Bytes)
    (expected : alloc.vec.Vec (Spike.engine.Bytes × Spike.engine.Cell))
    : WP.spec (Spike.engine.Dependency.holds (.Map m expected) db)
        (fun r =>
          r
          = (Dependency.map (alloc.vec.Vec.val m) (byteImage expected)).holds
              (byteData db)) := by
  unfold Spike.engine.Dependency.holds
  apply WP.spec_bind (image_matches_model db m)
  intro observed h
  simpa [h, Dependency.holds] using same_image_matches_model observed expected

/-- Project an extracted dependency into the existing KV model. -/
def byteDependency : Spike.engine.Dependency → Dependency (List U8) (List U8) (List U8)
  | .Key addr expected => .key (byteAddr addr) (expected.map byteCell)
  | .Map m expected => .map (alloc.vec.Vec.val m) (byteImage expected)

private theorem dependency_matches_model
    (db : Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell)
    (d : Spike.engine.Dependency)
    : WP.spec (Spike.engine.Dependency.holds d db)
        (fun r =>
          r = (byteDependency d).holds (byteData db)) := by
  cases d with
  | Key a e => exact point_dependency_matches_model db a e
  | Map m e => exact map_dependency_matches_model db m e

/-- The extracted OCC read-set check accepts exactly the dependencies accepted by the model. -/
theorem validate_dependencies_matches_model
    (t : Spike.engine.Tx) (db : Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell)
    : WP.spec (Spike.engine.Tx.valid_dependencies t db)
        (fun r => r = validates (byteData db) (t.deps.val.map byteDependency)) := by
  let checks := fun (deps : List Spike.engine.Dependency) =>
    validates (byteData db) (deps.map byteDependency)
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
      apply WP.spec_bind (dependency_matches_model db d)
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

private theorem encode_addr_inj {encode : List U8 → String}
    (inj : Function.Injective encode)
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

private theorem image_encoding (encode : List U8 → String)
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

end KvRust
