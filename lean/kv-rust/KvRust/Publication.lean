-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Assoc
public import KvRust.Keys
public import Kv.Properties

import all Aeneas.Std.Core.Core

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

/-- Cloning an extracted association list preserves the ordered bindings. -/
theorem clone_assoc {K V : Type} (ck : core.clone.Clone K) (cv : core.clone.Clone V)
    (rows : CcfKv.engine.Assoc K V)
    : CcfKv.engine.Assoc.Insts.CoreCloneClone.clone ck cv rows = .ok rows := by
  simp [CcfKv.engine.Assoc.Insts.CoreCloneClone.clone, clone_vec (BuiltinClone (K × V)) rows
    (fun _ => rfl)]

/-- Cloning extracted bytes preserves their contents. -/
theorem clone_bytes (v : CcfKv.engine.Bytes)
    : CcfKv.engine.Bytes.Insts.CoreCloneClone.clone v = .ok v := by
  simp [CcfKv.engine.Bytes.Insts.CoreCloneClone.clone, clone_vec core.clone.CloneU8 v (fun _ => rfl)]

/-- Cloning an extracted address preserves both of its coordinates. -/
theorem clone_address (a : CcfKv.engine.Address)
    : CcfKv.engine.Address.Insts.CoreCloneClone.clone a = .ok a := by
  cases a
  simp [CcfKv.engine.Address.Insts.CoreCloneClone.clone, clone_bytes]

/-- Cloning a cell preserves both its value and version. -/
theorem clone_cell (c : CcfKv.engine.Cell)
    : CcfKv.engine.Cell.Insts.CoreCloneClone.clone c = .ok c := by
  cases c
  simp [CcfKv.engine.Cell.Insts.CoreCloneClone.clone, clone_bytes, lift]

/-- Both components of an extracted address project to the model's byte-list keys. -/
def byteAddr (a : CcfKv.engine.Address) : Addr (List U8) (List U8) :=
  (alloc.vec.Vec.val a.map, alloc.vec.Vec.val a.key)

/-- The byte-list projection preserves address identity. -/
theorem byteAddr_inj {a b : CcfKv.engine.Address} (h : byteAddr a = byteAddr b)
    : a = b := by
  obtain ⟨am, ak⟩ := a
  obtain ⟨bm, bk⟩ := b
  simp only [byteAddr, Prod.mk.injEq] at h
  have hm := alloc.vec.Vec.ext am bm h.1
  have hk := alloc.vec.Vec.ext ak bk h.2
  subst bm bk
  rfl

local instance : DecidableEq CcfKv.engine.Address :=
  fun a b =>
    decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

/-- The engine's address comparison implements decidable equality. -/
theorem compare_address [DecidableEq CcfKv.engine.Address] (a b : CcfKv.engine.Address)
    : CcfKv.engine.Address.Insts.Ccf_kvEngineKey.same a b
      = .ok (decide (a = b)) := by
  have h : a = b ↔ byteAddr a = byteAddr b :=
    ⟨congrArg byteAddr, byteAddr_inj⟩
  simp [address_same, h, byteAddr]

/-- Project an extracted cell with its byte value and previous-write version. -/
def byteCell (c : CcfKv.engine.Cell) : Cell (List U8) :=
  {value := alloc.vec.Vec.val c.value, version := c.version.val}

/-- Project extracted committed data without collapsing absence and an empty byte list. -/
def byteData (data : CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Cell)
    : DB (List U8) (List U8) (List U8) :=
  data.val.map fun (a, c) => (byteAddr a, byteCell c)

/-- Project staged puts and removals to the model's representation. -/
def byteWrites (pending : List (CcfKv.engine.Address × CcfKv.engine.Write))
    : Writes (List U8) (List U8) (List U8) :=
  pending.map
    fun (a, w) =>
      (
        byteAddr a,
        match w with
        | .Put value => some (alloc.vec.Vec.val value)
        | .Remove => none
      )

end KvRust
