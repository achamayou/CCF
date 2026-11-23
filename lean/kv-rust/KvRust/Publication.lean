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
    (rows : Spike.engine.Assoc K V)
    : Spike.engine.Assoc.Insts.CoreCloneClone.clone ck cv rows = .ok rows := by
  simp [Spike.engine.Assoc.Insts.CoreCloneClone.clone, clone_vec (BuiltinClone (K × V)) rows
    (fun _ => rfl)]

/-- Cloning extracted bytes preserves their contents. -/
theorem clone_bytes (v : Spike.engine.Bytes)
    : Spike.engine.Bytes.Insts.CoreCloneClone.clone v = .ok v := by
  simp [Spike.engine.Bytes.Insts.CoreCloneClone.clone, clone_vec core.clone.CloneU8 v (fun _ => rfl)]

/-- Cloning an extracted address preserves both of its coordinates. -/
theorem clone_address (a : Spike.engine.Address)
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
private theorem publish_sequential_matches_model
    (data : Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell)
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write) (version : U64)
    (capacity : data.val.length + pending.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.publish_sequential data pending version)
        (fun after =>
          byteData after
          = publish (byteData data) version.val (byteWrites pending.val)) := by
  let expected := publish (byteData data) version.val (byteWrites pending.val)
  unfold Spike.engine.publish_sequential Spike.engine.publish_sequential_loop
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
    unfold Spike.engine.publish_sequential_loop.body
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

private def stampedPut {A V : Type} (version : Nat) (row : A × Option V)
    : Option (A × Cell V) :=
  row.2.map fun value => (row.1, {value, version})

private def keep {A V : Type} [DecidableEq A] (keys : List A) (row : A × Cell V) : Bool :=
  decide (row.1 ∉ keys)

/-- When writes have distinct addresses, the model fold puts their new cells first,
then keeps untouched rows in their original order, including any repeated old rows. -/
private theorem publish_distinct {M K V : Type} [DecidableEq M] [DecidableEq K]
    (data : DB M K V) (version : Nat) (writes : Writes M K V)
    (distinct : (writes.map Prod.fst).Nodup)
    : publish data version writes
      = writes.filterMap (stampedPut version)
        ++ data.filter (keep (writes.map Prod.fst)) := by
  induction writes with
  | nil =>
      simp only [publish, List.foldr_nil, List.filterMap_nil, List.nil_append,
        List.map_nil]
      exact (List.filter_eq_self.mpr (by simp [keep])).symm
  | cons row tail ih =>
      obtain ⟨key, value⟩ := row
      simp only [List.map_cons, List.nodup_cons] at distinct
      have hkept :
          erase (tail.filterMap (stampedPut version)) key =
          tail.filterMap (stampedPut version) := by
        unfold erase
        apply List.filter_eq_self.mpr
        intro cell hc
        obtain ⟨⟨a, w⟩, hrow, hput⟩ := List.mem_filterMap.mp hc
        cases w with
        | none => simp [stampedPut] at hput
        | some v =>
            have hw : (a, ({value := v, version} : Cell V)) = cell := Option.some.inj hput
            subst cell
            have ha : a ≠ key := fun e => distinct.1 (e ▸ List.mem_map_of_mem hrow)
            simpa using ha
      have herase :
          erase (publish data version tail) key =
          tail.filterMap (stampedPut version) ++ data.filter (keep (key :: tail.map Prod.fst)) := by
        rw [ih distinct.2, erase, List.filter_append, ← erase, hkept, List.filter_filter]
        congr 1
        apply List.filter_congr
        intro row _
        by_cases he : row.1 = key
        · simp [keep, he]
        · have hbeq : (row.1 == key) = false := beq_eq_false_iff_ne.mpr he
          simp [keep, hbeq, bne]
      have hcons
          : publish data version ((key, value) :: tail)
            = match value with
              | none => erase (publish data version tail) key
              | some v =>
                  (key, {value := v, version})
                  :: erase (publish data version tail) key := by
        cases value <;> rfl
      rw [hcons, herase]
      cases value with
      | none => rw [List.filterMap_cons_none rfl]; rfl
      | some v =>
          rw [List.filterMap_cons_some (show stampedPut version (key, some v) = _ from rfl)]; rfl

private abbrev NativeData := Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell
private abbrev NativePending := Spike.engine.Assoc Spike.engine.Address Spike.engine.Write
private abbrev Buckets := alloc.vec.Vec (alloc.vec.Vec Usize)

private def bucketKey (a : Spike.engine.Address) : Nat :=
  (a.key.val[a.key.val.length - 1]?.getD 0#u8).val

private theorem bucket_for_spec (a : Spike.engine.Address)
    : WP.spec (Spike.engine.bucket_for a)
        (fun i => i.val = bucketKey a ∧ i.val < 256) := by
  unfold Spike.engine.bucket_for
  simp only [alloc.vec.Vec.is_empty, bind_ok]
  by_cases he : a.key.val.length = 0
  · have hempty : a.key.val = [] := List.length_eq_zero_iff.mp he
    simp [alloc.vec.Vec.length, hempty, bucketKey]
  · simp only [alloc.vec.Vec.length, he, decide_false, Bool.false_eq_true, ite_false]
    have hlen : (alloc.vec.Vec.len a.key).val = a.key.val.length := alloc.vec.Vec.len_val _
    have hone : (1#usize : Usize).val = 1 := rfl
    apply WP.spec_bind (Usize.sub_spec (by omega : (1#usize : Usize).val ≤ _))
    intro i hi
    have hb : i.val < a.key.val.length := by omega
    simp only [alloc.vec.Vec.index_slice_index]
    apply WP.spec_bind (alloc.vec.Vec.index_usize_spec a.key i hb)
    intro byte hbyte
    have hpow : UScalarTy.U8.numBits ≤ UScalarTy.Usize.numBits := by
      rcases System.Platform.numBits_eq with h | h <;> simp [h]
    have hcast := UScalar.cast_val_mod_pow_greater_numBits_eq .Usize byte hpow
    have hpos : a.key.val.length - 1 = i.val := by omega
    simp only [WP.spec_ok, hcast]
    refine ⟨?_, U8.lt_succ_max byte⟩
    simp [bucketKey, hpos, List.getElem?_eq_getElem hb, hbyte]

private def indexedAddresses (pending : NativePending) (items : List Usize)
    : List Spike.engine.Address :=
  items.filterMap fun i => pending.val[i.val]?.map Prod.fst

/-- A bucket contains only indices into the processed prefix, and represents exactly
the addresses in that prefix which select its slot. Collisions need not be absent. -/
private def bucketIndex (pending : NativePending) (buckets : Buckets) (n : Nat) : Prop :=
  buckets.val.length = 256
  ∧ ∀ slot items,
      buckets.val[slot]? = some items
      → (∀ i ∈ items.val, i.val < n)
        ∧ ∀ a,
            a ∈ indexedAddresses pending items.val
            ↔ a ∈ (pending.val.take n).map Prod.fst ∧ bucketKey a = slot

private theorem empty_buckets_spec
    : WP.spec Spike.engine.empty_buckets
        (fun buckets =>
          buckets.val.length = 256 ∧ ∀ bucket ∈ buckets.val, bucket.val = []) := by
  have hlimit : (256#usize : Usize).val = 256 := rfl
  have hone : (1#usize : Usize).val = 1 := rfl
  have hmax : 256 ≤ Usize.max := by scalar_tac
  unfold Spike.engine.empty_buckets Spike.engine.empty_buckets_loop
  apply loop.spec_decr_nat
    (fun (p : Buckets × Usize) => 256 - p.2.val)
    (fun p => p.2.val ≤ 256 ∧ p.1.val.length = p.2.val
      ∧ ∀ bucket ∈ p.1.val, bucket.val = [])
    _ _ _
  · rintro ⟨buckets, i⟩ ⟨hi, hlen, hall⟩
    dsimp only at hi hlen hall ⊢
    unfold Spike.engine.empty_buckets_loop.body
    split
    · rename_i go
      have hgo : i.val < (256#usize : Usize).val := go
      apply WP.spec_bind (alloc.vec.Vec.push_spec buckets (alloc.vec.Vec.new Usize) (by omega))
      intro next hnext
      apply WP.spec_bind (Usize.add_spec (by omega))
      intro j hj
      simp only [WP.spec_ok]
      refine ⟨⟨by omega, by simp only [hnext, List.length_append, List.length_singleton]; omega,
        ?_⟩, by omega⟩
      intro item hitem
      rw [hnext, List.mem_append, List.mem_singleton] at hitem
      rcases hitem with hm | rfl
      · exact hall _ hm
      · rfl
    · rename_i stop
      have hs : ¬i.val < (256#usize : Usize).val := stop
      simp only [WP.spec_ok]
      exact ⟨by omega, hall⟩
  · simp

private theorem bucket_contains_spec (pending : NativePending)
    (bucket : alloc.vec.Vec Usize) (a : Spike.engine.Address)
    (valid : ∀ i ∈ bucket.val, i.val < pending.val.length)
    : WP.spec (Spike.engine.bucket_contains bucket pending a)
        (fun found => found = decide (a ∈ indexedAddresses pending bucket.val)) := by
  let want := decide (a ∈ indexedAddresses pending bucket.val)
  have hone : (1#usize : Usize).val = 1 := rfl
  have hbound := alloc.vec.Vec.len_ineq bucket
  unfold Spike.engine.bucket_contains Spike.engine.bucket_contains_loop
  apply loop.spec_decr_nat
    (fun (p : NativePending × Usize) => bucket.val.length - p.2.val)
    (fun p => p.1 = pending ∧ p.2.val ≤ bucket.val.length
      ∧ decide (a ∈ indexedAddresses pending (bucket.val.drop p.2.val)) = want)
    _ _ _
  · rintro ⟨writes, i⟩ ⟨hpending, hi, hw⟩
    dsimp only at hpending hi hw ⊢
    subst writes
    unfold Spike.engine.bucket_contains_loop.body
    by_cases go : i < alloc.vec.Vec.len bucket
    · have hb : i.val < bucket.val.length := go
      simp only [go, ite_true, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec bucket i hb)
      intro idx hidx
      have hidx' : idx ∈ bucket.val := hidx ▸ List.getElem_mem hb
      have hp := valid idx hidx'
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending idx hp)
      rintro ⟨key, write⟩ hrow
      change WP.spec (do
        let b ← Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey.same key a
        if b then Result.ok (ControlFlow.done true)
        else
          let j ← i + 1#usize
          Result.ok (ControlFlow.cont (pending, j))) _
      rw [compare_address, bind_ok]
      have hsplit : indexedAddresses pending (bucket.val.drop i.val) =
          key :: indexedAddresses pending (bucket.val.drop (i.val + 1)) := by
        rw [List.drop_eq_getElem_cons hb, ← hidx]
        simp [indexedAddresses, List.getElem?_eq_getElem hp, ← hrow]
      rw [hsplit] at hw
      by_cases he : key = a
      · subst key
        have ht : want = true := by simpa using hw.symm
        simpa [want] using ht.symm
      · simp only [he, decide_false, Bool.false_eq_true, ite_false]
        apply WP.spec_bind (Usize.add_spec (by omega))
        intro j hj
        have hj' : j.val = i.val + 1 := by omega
        simp only [WP.spec_ok]
        refine ⟨⟨trivial, by omega, ?_⟩, by omega⟩
        simpa [hj', Ne.symm he] using hw
    · have hz : bucket.val.length ≤ i.val := by
        have hn : ¬i.val < (alloc.vec.Vec.len bucket).val := go
        change ¬i.val < bucket.val.length at hn
        omega
      simpa [go, List.drop_eq_nil_of_le hz, indexedAddresses, want] using hw
  · simp [want]

private theorem prefix_step (pending : NativePending) {i : Usize} {row}
    (hi : i.val < pending.val.length) (hr : row = pending.val[i.val])
    : pending.val.take (i.val + 1) = pending.val.take i.val ++ [row] := by
  rw [List.take_succ_eq_append_getElem hi, ← hr]

private theorem bucketIndex_push (pending : NativePending) (buckets : Buckets)
    (bucket next : alloc.vec.Vec Usize) (i slot : Usize)
    (row : Spike.engine.Address × Spike.engine.Write)
    (inv : bucketIndex pending buckets i.val) (hi : i.val < pending.val.length)
    (hrow : row = pending.val[i.val]) (hslot : slot.val = bucketKey row.1)
    (hb : slot.val < buckets.val.length) (hget : buckets.val[slot.val]? = some bucket)
    (hpush : next.val = bucket.val ++ [i])
    : bucketIndex pending (buckets.set slot next) (i.val + 1) := by
  have hprefix := prefix_step pending hi hrow
  have haddr : indexedAddresses pending next.val =
      indexedAddresses pending bucket.val ++ [row.1] := by
    rw [hpush, indexedAddresses, List.filterMap_append]
    simp [indexedAddresses, List.getElem?_eq_getElem hi, ← hrow]
  refine ⟨by simpa only [alloc.vec.Vec.set_val_eq, List.length_set] using inv.1, ?_⟩
  intro b xs hxs
  simp only [alloc.vec.Vec.set_val_eq] at hxs
  by_cases he : slot.val = b
  · subst b
    rw [List.getElem?_set_self hb] at hxs
    have h := inv.2 _ _ hget
    have hsame := Option.some.inj hxs
    subst xs
    refine ⟨?_, ?_⟩
    · intro j hj
      rw [hpush, List.mem_append, List.mem_singleton] at hj
      rcases hj with hj | rfl
      · have := h.1 j hj
        omega
      · omega
    · intro a
      rw [haddr, hprefix]
      by_cases ha : a = row.1
      · subst a
        simp [hslot]
      · simpa [ha] using h.2 a
  · rw [List.getElem?_set_ne he] at hxs
    have h := inv.2 _ _ hxs
    refine ⟨fun j hj => Nat.lt_succ_of_lt (h.1 j hj), ?_⟩
    intro a
    rw [hprefix, h.2 a]
    by_cases ha : a = row.1
    · subst a
      simp [← hslot, he]
    · simp [ha]

private theorem byteWrites_keys
    (pending : List (Spike.engine.Address × Spike.engine.Write))
    : (byteWrites pending).map Prod.fst = (pending.map Prod.fst).map byteAddr := by
  simp [byteWrites, List.map_map, Function.comp_def]

private theorem byteWrites_append (a b : List (Spike.engine.Address × Spike.engine.Write))
    : byteWrites (a ++ b) = byteWrites a ++ byteWrites b := by simp [byteWrites]

private theorem append_batch_put_spec (data : NativeData)
    (row : Spike.engine.Address × Spike.engine.Write) (version : U64)
    (room : data.val.length < Usize.max)
    : WP.spec (Spike.engine.append_batch_put data row version)
        (fun next =>
          byteData next
          = byteData data ++ (byteWrites [row]).filterMap (stampedPut version.val)) := by
  obtain ⟨addr, write⟩ := row
  cases write with
  | Remove => simp [Spike.engine.append_batch_put, byteWrites, stampedPut]
  | Put value =>
      simp only [Spike.engine.append_batch_put, clone_address, clone_bytes, bind_ok]
      apply WP.spec_bind (alloc.vec.Vec.push_spec data (addr, {value, version}) room)
      intro next hnext
      simp [byteData, byteWrites, byteCell, hnext, stampedPut]

private def batchPrefix (pending : NativePending) (version : U64) (data : NativeData)
    (buckets : Buckets) (n : Nat)
    : Prop :=
  ((byteWrites (pending.val.take n)).map Prod.fst).Nodup
  ∧ bucketIndex pending buckets n
  ∧ byteData data = (byteWrites (pending.val.take n)).filterMap (stampedPut version.val)

private theorem stage_batch_spec (pending : NativePending) (version : U64)
    : WP.spec (Spike.engine.stage_batch pending version)
        (fun result =>
          match result with
          | none => True
          | some (data, buckets) =>
              batchPrefix pending version data buckets pending.val.length) := by
  have hone : (1#usize : Usize).val = 1 := rfl
  have hmax := alloc.vec.Vec.len_ineq pending
  unfold Spike.engine.stage_batch Spike.engine.Assoc.new
  apply WP.spec_bind empty_buckets_spec
  intro buckets hbuckets
  simp only [bind_ok]
  unfold Spike.engine.stage_batch_loop
  apply loop.spec_decr_nat
    (fun (p : NativePending × Buckets × NativeData × Usize) =>
      pending.val.length - p.2.2.2.val)
    (fun p => p.1 = pending ∧ p.2.2.2.val ≤ pending.val.length
      ∧ batchPrefix pending version p.2.2.1 p.2.1 p.2.2.2.val)
    _ _ _
  · rintro ⟨writes, bs, data, i⟩ ⟨heq, hi, hn, hindex, hdata⟩
    dsimp only at heq hi hn hindex hdata ⊢
    subst writes
    unfold Spike.engine.stage_batch_loop.body
    by_cases go : i < alloc.vec.Vec.len pending
    · have hp : i.val < pending.val.length := go
      simp only [go, ite_true, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending i hp)
      rintro ⟨a, w⟩ hrow
      apply WP.spec_bind (bucket_for_spec a)
      intro slot ⟨hslot, hlt⟩
      have hb : slot.val < bs.val.length := hindex.1 ▸ hlt
      rw [alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec bs slot hb)
      rintro ⟨bucket, back⟩ ⟨hget, hback⟩
      have h :=
        hindex.2 _ _
          (by simpa only [List.getElem?_eq_getElem hb, Option.some.injEq] using hget.symm
            : bs.val[slot.val]? = some bucket)
      change WP.spec (if 64 ≤ bucket.val.length then Result.ok (ControlFlow.done none) else do
        let duplicate ← Spike.engine.bucket_contains bucket pending a
        if duplicate then Result.ok (ControlFlow.done none)
        else
          let next ← alloc.vec.Vec.push bucket i
          let updated ← Spike.engine.append_batch_put data (a, w) version
          let j ← i + 1#usize
          Result.ok (ControlFlow.cont (pending, back next, updated, j))) _
      by_cases hcap : 64 ≤ bucket.val.length
      · simp [hcap]
      · simp only [hcap, ite_false]
        apply WP.spec_bind (bucket_contains_spec pending bucket a (fun j hj => by
          have := h.1 j hj
          omega))
        intro duplicate hd
        by_cases hnew : duplicate = true
        · simp [hnew]
        · simp only [hnew]
          have hf : a ∉ (pending.val.take i.val).map Prod.fst := by
            intro hm
            have ha := (h.2 a).2 ⟨hm, hslot.symm⟩
            exact hnew (hd.trans (decide_eq_true ha))
          have hroom : data.val.length < Usize.max := by
            have hlen := congrArg List.length hdata
            have hle := List.length_filterMap_le (stampedPut version.val)
              (byteWrites (pending.val.take i.val))
            simp only [byteData, List.length_map] at hlen
            have hwlen : (byteWrites (pending.val.take i.val)).length =
                (pending.val.take i.val).length := List.length_map _
            rw [hwlen] at hle
            have := List.length_take_le i.val pending.val
            omega
          have hbucket : bucket.val.length < Usize.max := by
            have hmax' : 64 ≤ Usize.max := by scalar_tac
            omega
          apply WP.spec_bind (alloc.vec.Vec.push_spec bucket i hbucket)
          intro next hnext
          apply WP.spec_bind (append_batch_put_spec data (a, w) version hroom)
          intro updated hupdated
          apply WP.spec_bind (Usize.add_spec (by omega))
          intro j hj
          have hj' : j.val = i.val + 1 := by omega
          simp only [WP.spec_ok]
          refine ⟨⟨trivial, by omega, ?_, ?_, ?_⟩, by omega⟩
          · rw [hj', prefix_step pending hp hrow, byteWrites_append, List.map_append]
            apply List.nodup_append.mpr
            refine ⟨hn, by simp [byteWrites], ?_⟩
            intro key hk new hnewkey
            have hnewkey' : new = byteAddr a := by simpa [byteWrites] using hnewkey
            subst new
            intro hkey
            subst key
            rw [byteWrites_keys, List.mem_map] at hk
            obtain ⟨old, hold, he⟩ := hk
            exact hf (byteAddr_inj he ▸ hold)
          · rw [hj', hback]
            exact bucketIndex_push pending bs bucket next i slot (a, w) hindex hp hrow
              hslot hb (by simp [List.getElem?_eq_getElem hb, hget]) hnext
          · rw [hj', prefix_step pending hp hrow, byteWrites_append, List.filterMap_append,
              hupdated, hdata]
    · have hz : i.val = pending.val.length := by
        have hstop : ¬i.val < pending.val.length := go
        omega
      simp only [go, ite_false, WP.spec_ok]
      exact hz ▸ (show batchPrefix pending version data bs i.val from ⟨hn, hindex, hdata⟩)
  · refine ⟨rfl, by simp, by simp [byteWrites], ⟨hbuckets.1, ?_⟩, by simp [byteData, byteWrites]⟩
    intro slot bucket hget
    have hm := hbuckets.2 bucket (List.mem_of_getElem? hget)
    simp [hm, indexedAddresses]

private theorem append_untouched_spec (data : NativeData)
    (row : Spike.engine.Address × Spike.engine.Cell) (pending : NativePending)
    (buckets : Buckets) (index : bucketIndex pending buckets pending.val.length)
    (room : data.val.length < Usize.max)
    : WP.spec (Spike.engine.append_untouched data row pending buckets)
        (fun next =>
          byteData next
          = byteData data
            ++ [(byteAddr row.1, byteCell row.2)].filter
                (keep ((byteWrites pending.val).map Prod.fst))) := by
  obtain ⟨a, c⟩ := row
  unfold Spike.engine.append_untouched
  apply WP.spec_bind (bucket_for_spec a)
  intro slot ⟨hslot, hs⟩
  have hb : slot.val < buckets.val.length := index.1 ▸ hs
  rw [alloc.vec.Vec.index_slice_index]
  apply WP.spec_bind (alloc.vec.Vec.index_usize_spec buckets slot hb)
  intro bucket hget
  have hpos : buckets.val[slot.val]? = some bucket := by rw [List.getElem?_eq_getElem hb, ← hget]
  have h := index.2 _ _ hpos
  apply WP.spec_bind (bucket_contains_spec pending bucket a h.1)
  intro found hfound
  have hmem : a ∈ indexedAddresses pending bucket.val ↔
      byteAddr a ∈ (byteWrites pending.val).map Prod.fst := by
    rw [h.2 a, List.take_length, byteWrites_keys]
    exact ⟨fun ha => List.mem_map.mpr ⟨a, ha.1, rfl⟩, fun ha => by
      obtain ⟨b, hm, he⟩ := List.mem_map.mp ha
      exact ⟨byteAddr_inj he ▸ hm, hslot.symm⟩⟩
  by_cases hm : byteAddr a ∈ (byteWrites pending.val).map Prod.fst
  · have ht : found = true := hfound.trans (decide_eq_true (hmem.mpr hm))
    simp [ht, hm, keep]
  · have hf : found = false := hfound.trans (decide_eq_false (fun he => hm (hmem.mp he)))
    simp only [hf, Bool.false_eq_true, ite_false, clone_address, clone_cell, bind_ok]
    apply WP.spec_bind (alloc.vec.Vec.push_spec data (a, c) room)
    intro next hnext
    simp [hnext, byteData, hm, keep]

private theorem byteData_length (data : NativeData)
    : (byteData data).length = data.val.length :=
  List.length_map _

private theorem publish_batch_spec (data : NativeData) (pending : NativePending)
    (version : U64) (capacity : data.val.length + pending.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.publish_batch data pending version)
        (fun result =>
          match result with
          | none => True
          | some next =>
              byteData next
              = publish (byteData data) version.val (byteWrites pending.val)) := by
  let predicate := keep (V := List U8) ((byteWrites pending.val).map Prod.fst)
  have hone : (1#usize : Usize).val = 1 := rfl
  have hmax := alloc.vec.Vec.len_ineq data
  unfold Spike.engine.publish_batch
  apply WP.spec_bind (stage_batch_spec pending version)
  rintro (_ | ⟨puts, buckets⟩) h
  · simp
  · obtain ⟨hn, index, hputs⟩ := h
    simp only [List.take_length] at hn hputs
    have he := publish_distinct (byteData data) version.val (byteWrites pending.val) hn
    rw [← hputs] at he
    apply WP.spec_bind (Pₘ := fun next =>
      byteData next = byteData puts ++ (byteData data).filter predicate)
    swap
    · intro next hnext
      simpa only [WP.spec_ok] using hnext.trans he.symm
    unfold Spike.engine.publish_batch_loop
    apply loop.spec_decr_nat
      (fun (p : NativeData × NativeData × Usize) => data.val.length - p.2.2.val)
      (fun p => p.1 = data ∧ p.2.2.val ≤ data.val.length
        ∧ p.2.1.val.length ≤ pending.val.length + p.2.2.val
        ∧ byteData p.2.1 ++ ((byteData data).drop p.2.2.val).filter predicate =
          byteData puts ++ (byteData data).filter predicate)
      _ _ _
    · rintro ⟨old, next, i⟩ ⟨hold, hi, hlen, hacc⟩
      dsimp only at hold hi hlen hacc ⊢
      subst old
      unfold Spike.engine.publish_batch_loop.body
      by_cases go : i < alloc.vec.Vec.len data
      · have hd : i.val < data.val.length := go
        have hroom : next.val.length < Usize.max := by omega
        simp only [go, ite_true, alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec data i hd)
        rintro ⟨a, c⟩ hrow
        apply WP.spec_bind (append_untouched_spec next (a, c) pending buckets index hroom)
        intro updated hu
        apply WP.spec_bind (Usize.add_spec (by omega))
        intro j hj
        have hj' : j.val = i.val + 1 := by omega
        simp only [WP.spec_ok]
        refine ⟨⟨trivial, by omega, ?_, ?_⟩, by omega⟩
        · have hlen' := congrArg List.length hu
          have hf := List.length_filter_le predicate [(byteAddr a, byteCell c)]
          simp only [List.length_append, byteData_length] at hlen'
          simp only [List.length_singleton] at hf
          change updated.val.length = next.val.length + ([(byteAddr a, byteCell c)].filter predicate).length at hlen'
          omega
        · have hsplit : (byteData data).drop i.val =
              [(byteAddr a, byteCell c)] ++ (byteData data).drop j.val := by
            rw [hj']
            simp only [byteData, ← List.map_drop, List.drop_eq_getElem_cons hd, ← hrow,
              List.map_cons, List.singleton_append]
          rw [hsplit, List.filter_append, ← List.append_assoc] at hacc
          rw [hu]
          exact hacc
      · have hstop : ¬i.val < data.val.length := go
        have hdrop := List.drop_eq_nil_of_le
          (by rw [byteData_length]; omega : (byteData data).length ≤ i.val)
        simpa [go, hdrop] using hacc
    · have hlen := congrArg List.length hputs
      have hf := List.length_filterMap_le (stampedPut version.val) (byteWrites pending.val)
      have hlenw : (byteWrites pending.val).length = pending.val.length := List.length_map _
      rw [hlenw] at hf
      rw [byteData_length] at hlen
      exact ⟨rfl, by simp, by change puts.val.length ≤ pending.val.length + 0; omega, by simp⟩

/-- Both the indexed path and the general fold implement the same ordered publication. -/
theorem publish_matches_model
    (data : Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell)
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write) (version : U64)
    (capacity : data.val.length + pending.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.publish data pending version)
        (fun next =>
          byteData next
          = publish (byteData data) version.val (byteWrites pending.val)) := by
  unfold Spike.engine.publish
  by_cases go : alloc.vec.Vec.len pending ≥ 64#usize
  · simp only [go, ite_true]
    apply WP.spec_bind (publish_batch_spec data pending version capacity)
    intro result h
    cases result with
    | none =>
        simpa only [clone_assoc, bind_ok]
          using publish_sequential_matches_model data pending version capacity
    | some next => simpa only [WP.spec_ok] using h
  · simpa only [go, ite_false, clone_assoc, bind_ok]
      using publish_sequential_matches_model data pending version capacity

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
