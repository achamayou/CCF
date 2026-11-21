-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs
public import KvRust.Reference

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Encode the spike's empty or one-byte values as the model's lowercase hex. -/
def modelValue : Spike.Value → String
  | .Empty => ""
  | .Byte byte => String.ofList [(byte.val / 16).digitChar, (byte.val % 16).digitChar]

/-- Translate a committed cell without losing its previous-write version. -/
def modelCell (c : Spike.Cell) : Cell String :=
  { value := modelValue c.value, version := c.version.val }

/-- Embed a cell as a one-address model database. -/
def cellAt (addr : Addr String String) (cell : Option Spike.Cell) : Data :=
  match cell with
  | none => []
  | some c => [(addr, modelCell c)]

/-- Embed the three staging states without conflating removal with an unstaged address. -/
def writeAt (addr : Addr String String) (write : Spike.Write) : Pending :=
  match write with
  | .Keep => []
  | .Remove => [(addr, none)]
  | .Put v => [(addr, some (modelValue v))]

/-- For any slot, extracted reads match the model's overlay and dependency rule. -/
theorem slot_read (addr : Addr String String) (slot : Spike.Slot)
    : let db := cellAt addr slot.snapshot
      let writes := writeAt addr slot.write
      let value := valueAt db writes addr
      let needed := needs db writes (.read addr value)
      (do
        let (v, next) ← Spike.Slot.read slot
        Result.ok (v.map modelValue, next.read_snapshot))
      = Result.ok (value, slot.read_snapshot || !needed.isEmpty) := by
  obtain ⟨snapshot, readSnapshot, write⟩ := slot
  cases snapshot <;> cases readSnapshot <;> cases write <;>
    simp [Spike.Slot.read, cellAt, writeAt, valueAt, needs, find, modelCell]

/-- For any slot and version, extracted publication agrees with the model at that address. -/
theorem slot_publish (addr : Addr String String) (before : Option Spike.Cell)
    (write : Spike.Write) (version : U64)
    : (do
        let after ← Spike.Write.publish write before version
        Result.ok (after.map modelCell))
      = Result.ok
          (find (publish (cellAt addr before) version.val (writeAt addr write))
            addr) := by
  cases before <;> cases write <;> simp [Spike.Write.publish, cellAt, writeAt, publish, find,
    Kv.Model.set, erase, modelCell]

/-- Run the two-map schedule using the extracted Rust functions, not a Lean port. -/
def rustRun (first second competing : Spike.Value) : Result (Option Observation) := do
  let s ← Spike.Store.new
  let stale ← Spike.Store.snapshot s
  let (before, stale) ← Spike.Tx.get stale .A
  let stale ← Spike.Tx.put stale .B competing
  let writer ← Spike.Store.snapshot s
  let writer ← Spike.Tx.put writer .A first
  let writer ← Spike.Tx.put writer .B second
  let (own, writer) ← Spike.Tx.get writer .B
  let (applied, s) ← Spike.Store.apply s writer
  let (rejected, s) ← Spike.Store.apply s stale
  let a ← Spike.Store.head s .A
  let b ← Spike.Store.head s .B
  match applied, rejected with
  | .Applied version, .Conflict =>
      Result.ok
        (some
          {
            before := before.map modelValue
            own := own.map modelValue
            version := version.val
            a := a.map modelCell
            b := b.map modelCell
          })
  | _, _ => Result.ok none

/-- The same absent-read conflict schedule succeeds in both engines, for every spike value. -/
theorem two_map_schedule (first second competing : Spike.Value)
    : let expected : Observation :=
        {
          before := none
          own := some (modelValue second)
          version := 1
          a := some { value := modelValue first, version := 1 }
          b := some { value := modelValue second, version := 1 }
        }
      rustRun first second competing = .ok (some expected)
      ∧ modelRun (modelValue first) (modelValue second) (modelValue competing)
        = some expected := by
  constructor
  · have zero_ne_max : (0#u64 : U64) ≠ core.num.U64.MAX := by decide
    have zero_succ : (0#u64 + 1#u64 : Result U64) = Result.ok 1#u64 := by
      have bound : (0#u64 : U64).val + (1#u64 : U64).val ≤ U64.max := by
        simp [U64.max_eq]
      have h := U64.add_spec bound
      generalize (0#u64 + 1#u64 : Result U64) = result at h ⊢
      cases result using Result.cases with
      | ret value =>
          have eq : value.val = (1#u64 : U64).val := by simpa using h
          rw [UScalar.eq_of_val_eq eq]
      | vis _ _ => simp at h
      | div => simp at h
    simp [rustRun, Spike.Store.new, Spike.Store.snapshot, Spike.Slot.new, Spike.Tx.get,
      Spike.Slot.read, Spike.Tx.put, Spike.Tx.write, Spike.Store.apply, Spike.Write.pending,
      Spike.Slot.validates, Spike.Write.publish, Spike.Store.head, modelCell, zero_ne_max, zero_succ]
  · rfl

end KvRust
