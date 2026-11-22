-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Assoc
public import KvRust.Keys
public import Kv.Properties

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

private theorem roundtrip {α : Type} {r : Result α} {x : α}
    (h : WP.spec r (fun y => y = x))
    : r = .ok x := by
  cases r using Result.cases with
  | ret y => simpa using h
  | vis _ _ => simp at h
  | div => simp at h

private theorem clone_vec {α : Type} (inst : core.clone.Clone α) (v : alloc.vec.Vec α)
    (h : ∀ a, inst.clone a = .ok a)
    : alloc.vec.CloneVec.clone inst v = .ok v := by
  apply roundtrip
  unfold alloc.vec.CloneVec.clone
  apply WP.spec_bind (Slice.clone_spec (s := v.slice) (fun a _ => h a))
  intro slice hs
  subst slice
  cases v
  simp

/-- Cloning extracted bytes preserves their contents. -/
theorem clone_bytes (v : Spike.engine.Bytes)
    : Spike.engine.Bytes.Insts.CoreCloneClone.clone v = .ok v := by
  simp [Spike.engine.Bytes.Insts.CoreCloneClone.clone, clone_vec core.clone.CloneU8 v (fun _ => rfl)]

private theorem clone_address (a : Spike.engine.Address)
    : Spike.engine.Address.Insts.CoreCloneClone.clone a = .ok a := by
  cases a
  simp [Spike.engine.Address.Insts.CoreCloneClone.clone, clone_bytes]

/-- Cloning a cell preserves both its value and version. -/
theorem clone_cell (c : Spike.engine.Cell)
    : Spike.engine.Cell.Insts.CoreCloneClone.clone c = .ok c := by
  cases c
  simp [Spike.engine.Cell.Insts.CoreCloneClone.clone, clone_bytes, lift]

/-- Both components of an extracted address project to the model's byte-list keys. -/
def byteAddr (a : Spike.engine.Address) : Addr (List U8) (List U8) :=
  (alloc.vec.Vec.val a.map, alloc.vec.Vec.val a.key)

/-- The byte-list projection preserves address identity. -/
theorem byteAddr_inj {a b : Spike.engine.Address} (h : byteAddr a = byteAddr b)
    : a = b := by
  obtain ⟨am, ak⟩ := a
  obtain ⟨bm, bk⟩ := b
  simp only [byteAddr, Prod.mk.injEq] at h
  have hm := alloc.vec.Vec.ext am bm h.1
  have hk := alloc.vec.Vec.ext ak bk h.2
  subst bm bk
  rfl

local instance : DecidableEq Spike.engine.Address :=
  fun a b =>
    decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

/-- The engine's address comparison implements decidable equality. -/
theorem compare_address [DecidableEq Spike.engine.Address] (a b : Spike.engine.Address)
    : Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey.same a b
      = .ok (decide (a = b)) := by
  have h : a = b ↔ byteAddr a = byteAddr b :=
    ⟨congrArg byteAddr, byteAddr_inj⟩
  simp [address_same, h, byteAddr]

/-- Project an extracted cell with its byte value and previous-write version. -/
def byteCell (c : Spike.engine.Cell) : Cell (List U8) :=
  {value := alloc.vec.Vec.val c.value, version := c.version.val}

/-- Project extracted committed data without collapsing absence and an empty byte list. -/
def byteData (data : Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell)
    : DB (List U8) (List U8) (List U8) :=
  data.val.map fun (a, c) => (byteAddr a, byteCell c)

/-- Project staged puts and removals to the model's representation. -/
def byteWrites (pending : List (Spike.engine.Address × Spike.engine.Write))
    : Writes (List U8) (List U8) (List U8) :=
  pending.map
    fun (a, w) =>
      (
        byteAddr a,
        match w with
        | .Put value => some (alloc.vec.Vec.val value)
        | .Remove => none
      )

private theorem project_erase (xs : List (Spike.engine.Address × Spike.engine.Cell))
    (addr : Spike.engine.Address)
    : (erase xs addr).map
        (fun (a, c) =>
          (
            byteAddr a,
            ({value := alloc.vec.Vec.val c.value, version := c.version.val}
              : Cell (List U8))
          ))
      = erase
          (xs.map
            fun (a, c) =>
              (
                byteAddr a,
                {value := alloc.vec.Vec.val c.value, version := c.version.val}
              ))
          (byteAddr addr) := by
  rw [erase, erase, List.filter_map]
  congr 1

/-- The publication loop returns the model's atomic data update for the whole staged write set. -/
theorem publish_matches_model
    (data : Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell)
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write) (version : U64)
    (capacity : data.val.length + pending.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.publish data pending version)
        (fun after =>
          byteData after
          = publish (byteData data) version.val (byteWrites pending.val)) := by
  let expected := publish (byteData data) version.val (byteWrites pending.val)
  unfold Spike.engine.publish Spike.engine.publish_loop
  apply loop.spec_decr_nat
    (fun (p : Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell × Usize) =>
      p.2.val)
    (fun p =>
      p.2.val ≤ pending.val.length
      ∧ p.1.val.length + p.2.val ≤ Usize.max
      ∧ publish (byteData p.1) version.val (byteWrites (pending.val.take p.2.val))
        = expected)
    _ _ _
  · rintro ⟨current, i⟩ ⟨hi, hspace, hremaining⟩
    dsimp only at hi hspace hremaining ⊢
    unfold Spike.engine.publish_loop.body
    have hzero : (0#usize : Usize).val = 0 := rfl
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : (0#usize : Usize) < i
    · rw [ite_eq_left h]
      have hpos : 0 < i.val := h
      have hsub : (1#usize : Usize).val ≤ i.val := by omega
      apply WP.spec_bind (Usize.sub_spec hsub)
      intro j hj
      have hstep : i.val = j.val + 1 := by omega
      have hidx : j.val < pending.val.length := by omega
      have hroom : current.val.length < Usize.max := by omega
      simp only [alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending j hidx)
      rintro ⟨addr, write⟩ hrow
      have hsplit : byteWrites (pending.val.take i.val) =
          byteWrites (pending.val.take j.val) ++ byteWrites [(addr, write)] := by
        rw [hstep, List.take_succ_eq_append_getElem hidx, ← hrow]
        simp [byteWrites]
      have hfold : publish
          (publish (byteData current) version.val (byteWrites [(addr, write)]))
          version.val (byteWrites (pending.val.take j.val)) = expected := by
        simpa only [hsplit, publish, List.foldr_append] using hremaining
      cases write with
      | Put value =>
          let cell : Spike.engine.Cell := {value, version}
          change WP.spec (do
            let a ← Spike.engine.Address.Insts.CoreCloneClone.clone addr
            let v ← Spike.engine.Bytes.Insts.CoreCloneClone.clone value
            let next ← Spike.engine.Assoc.set Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
              Spike.engine.Address.Insts.CoreCloneClone Spike.engine.Cell.Insts.CoreCloneClone
              current a {value := v, version}
            Result.ok (ControlFlow.cont (next, j))) _
          simp only [clone_address, clone_bytes, bind_ok]
          apply WP.spec_bind
            (assoc_set Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
              Spike.engine.Address.Insts.CoreCloneClone
              Spike.engine.Cell.Insts.CoreCloneClone current addr cell
              (fun a => compare_address a addr) clone_address clone_cell hroom)
          intro next hnext
          simp only [WP.spec_ok]
          have hlen : next.val.length ≤ current.val.length + 1 := by
            have hf :=
              List.length_filter_le
                (fun (p : Spike.engine.Address × Spike.engine.Cell) =>
                  p.1 != addr)
                current.val
            simp only [hnext, Kv.Model.set, List.length_cons, erase]
            omega
          have hdata : byteData next =
              publish (byteData current) version.val (byteWrites [(addr, .Put value)]) := by
            simp [byteData, byteCell, byteWrites, hnext, publish, Kv.Model.set, cell, project_erase]
          exact ⟨⟨by omega, by omega, hdata ▸ hfold⟩, by omega⟩
      | Remove =>
          change WP.spec (do
            let next ← Spike.engine.Assoc.erase Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
              Spike.engine.Address.Insts.CoreCloneClone Spike.engine.Cell.Insts.CoreCloneClone
              current addr
            Result.ok (ControlFlow.cont (next, j))) _
          apply WP.spec_bind
            (assoc_erase Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
              Spike.engine.Address.Insts.CoreCloneClone
              Spike.engine.Cell.Insts.CoreCloneClone current addr
              (fun a => compare_address a addr) clone_address clone_cell)
          intro next hnext
          simp only [WP.spec_ok]
          have hlen : next.val.length ≤ current.val.length := by
            rw [hnext, erase]
            exact List.length_filter_le _ _
          have hdata : byteData next =
              publish (byteData current) version.val (byteWrites [(addr, .Remove)]) := by
            simp [byteData, byteCell, byteWrites, hnext, publish, project_erase]
          exact ⟨⟨by omega, by omega, hdata ▸ hfold⟩, by omega⟩
    · rw [ite_eq_right h, WP.spec_ok]
      have hz : i.val = 0 := by
        have hn : ¬0 < i.val := h
        omega
      simpa [hz, byteWrites, publish, expected] using hremaining
  · simp [capacity, expected]

/-- The existing model's lookup and uniqueness theorems apply to the extracted publication. -/
theorem extracted_publish_properties
    (data : Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell)
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write) (version : U64)
    (capacity : data.val.length + pending.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.publish data pending version)
        (fun after =>
          (∀ addr,
            find (byteData after) addr
            = match find (byteWrites pending.val) addr with
              | none => find (byteData data) addr
              | some none => none
              | some (some value) => some {value, version := version.val})
          ∧ (Kv.Properties.Unique (byteData data)
              → Kv.Properties.Unique (byteData after))) := by
  apply WP.spec_mono (publish_matches_model data pending version capacity)
  intro after h
  rw [h]
  constructor
  · intro addr
    have lookup := Kv.Properties.publish_lookup (byteData data) version.val (byteWrites pending.val) addr
    cases he : find (byteWrites pending.val) addr with
    | none => simpa only [he] using lookup
    | some val => cases val <;> simpa only [he] using lookup
  · exact Kv.Properties.publish_unique (byteData data) version.val (byteWrites pending.val)

end KvRust
