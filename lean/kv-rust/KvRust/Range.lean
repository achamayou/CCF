-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Keys
public import Kv.Model

import all Aeneas.Std.Core.Core

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- The negative comparison result is exactly strict lexicographic byte order. -/
theorem byteOrder_lt (a b : List U8) : byteOrder a b < 0#i8 ↔ a < b := by
  have hn : (-1)#i8 < 0#i8 := by decide
  have hp : ¬(1#i8 < 0#i8) := by decide
  induction a generalizing b with
  | nil => cases b <;> simp [byteOrder, hn]
  | cons a xs ih =>
      cases b with
      | nil => simp [byteOrder, hp]
      | cons b bs =>
          by_cases hab : a < b
          · simp [byteOrder, List.cons_lt_cons_iff, hab, hn]
          · by_cases hba : b < a
            · have hne : a ≠ b := fun eq => (lt_irrefl b) (eq ▸ hba)
              simp [byteOrder, List.cons_lt_cons_iff, hab, hba, hp, hne]
            · have heq : a = b := le_antisymm (le_of_not_gt hba) (le_of_not_gt hab)
              subst b
              simpa [byteOrder] using ih bs

/-- A nonpositive comparison result is exactly non-strict lexicographic byte order. -/
theorem byteOrder_le (a b : List U8) : byteOrder a b ≤ 0#i8 ↔ a ≤ b := by
  rw [← (not_lt (a := b) (b := a)), ← byteOrder_lt]
  have hn : (-1)#i8 < 0#i8 := by decide
  have hnl : (-1)#i8 ≤ 0#i8 := le_of_lt hn
  have hp : ¬(1#i8 < 0#i8) := by decide
  have hpl : ¬(1#i8 ≤ 0#i8) := by decide
  induction a generalizing b with
  | nil => cases b <;> simp [byteOrder, hnl, hp]
  | cons a xs ih =>
      cases b with
      | nil => simp [byteOrder, hpl, hn]
      | cons b bs =>
          by_cases hab : a < b
          · simp [byteOrder, hab, lt_asymm hab, hnl, hp]
          · by_cases hba : b < a
            · simp [byteOrder, hab, hba, hpl, hn]
            · simp [byteOrder, hab, hba, ih]

/-- Embed a byte as the Unicode code point with that unsigned value. -/
def encodeByte (b : U8) : Char := Char.ofUInt8 (UInt8.ofNat b.val)

private theorem byteChar_nat (b : U8) : (encodeByte b).toNat = b.val := by
  simp [encodeByte, Char.ofUInt8, ← Char.toNat_val,
    Nat.mod_eq_of_lt (U8.lt_succ_max b)]

private theorem byteChar_injective : Function.Injective encodeByte := by
  intro a b h
  apply UScalar.val_eq_imp
  simpa only [byteChar_nat] using congrArg Char.toNat h

/-- Embed each byte as the Unicode code point with the same unsigned number. This is not
UTF-8 decoding: every byte list, including ill-formed UTF-8, has a distinct image. -/
def encodeBytes (bytes : List U8) : String := String.ofList (bytes.map encodeByte)

/-- The encoding does not conflate any byte lists. -/
theorem encodeBytes_injective : Function.Injective encodeBytes := by
  intro a b h
  exact List.map_injective_iff.mpr byteChar_injective (String.ofList_inj.mp h)

/-- String order on the encoding is exactly unsigned lexicographic byte order. -/
theorem encodeBytes_lt (a b : List U8) : encodeBytes a < encodeBytes b ↔ a < b := by
  rw [← String.toList_lt_toList_iff]
  simp only [encodeBytes, String.toList_ofList]
  apply List.map_lt_map_iff_of_injective encodeByte _ byteChar_injective
  intro x y
  rw [Char.lt_def, UInt32.lt_iff_toNat_lt, Char.toNat_val, Char.toNat_val,
    byteChar_nat, byteChar_nat, UScalar.lt_equiv]

/-- A string encoding usable for range membership and sorting. -/
def PreservesByteOrder (encode : List U8 → String) : Prop :=
  ∀ a b, a < b ↔ encode a < encode b

/-- The concrete encoding preserves the order of all byte lists. -/
theorem encodeBytes_preservesByteOrder : PreservesByteOrder encodeBytes :=
  fun a b => (encodeBytes_lt a b).symm

/-- Compare a lower bound inclusively after projection to the model's key type. -/
theorem byteOrder_le_encoded {encode : List U8 → String}
    (order : PreservesByteOrder encode) (a b : List U8)
    : byteOrder a b ≤ 0#i8 ↔ encode a ≤ encode b := by
  rw [byteOrder_le, ← (not_lt (a := b) (b := a)), order b a, _root_.Std.not_lt]

/-- Compare an upper bound exclusively after projection to the model's key type. -/
theorem byteOrder_lt_encoded {encode : List U8 → String}
    (order : PreservesByteOrder encode) (a b : List U8)
    : byteOrder a b < 0#i8 ↔ encode a < encode b :=
  (byteOrder_lt a b).trans (order a b)

/-- Project an optional native range endpoint to the model. -/
def encodeBound (encode : List U8 → String) (bound : Option Spike.engine.Bytes)
    : Option String :=
  bound.map fun b => encode b.val

/-- Project the entries without changing their order. -/
def encodeEntries (encode : List U8 → String)
    (rows : alloc.vec.Vec (Spike.engine.Bytes × Spike.engine.Bytes))
    : Assoc String String :=
  rows.val.map fun (k, v) => (encode k.val, encode v.val)

/-- The extracted two-bound guard agrees with the model's empty-range test. -/
theorem range_empty_guard {encode : List U8 → String} (order : PreservesByteOrder encode)
    (lower upper : Spike.engine.Bytes)
    : WP.spec (Spike.engine.Bytes.compare lower upper)
        (fun cmp =>
          decide (cmp ≥ 0#i8)
          = emptyRange (encodeBound encode (some lower))
              (encodeBound encode (some upper))) := by
  apply WP.spec_mono (bytes_compare lower upper)
  intro cmp hcmp
  subst cmp
  exact Bool.decide_congr ((not_lt (a := byteOrder lower.val upper.val) (b := 0#i8)).symm.trans
    ((not_congr (byteOrder_lt_encoded order lower.val upper.val)).trans _root_.Std.not_lt))

/-- If the guard succeeds, the interval predicate rejects every key. -/
theorem inRange_of_emptyRange {lower upper : Option String}
    (empty : emptyRange lower upper = true) (key : String)
    : inRange lower upper key = false := by
  cases lower with
  | none => simp [emptyRange] at empty
  | some l =>
      cases upper with
      | none => simp [emptyRange] at empty
      | some u =>
          simp only [emptyRange, decide_eq_true_eq] at empty
          by_cases hl : l ≤ key
          · have hu : ¬key < u := _root_.Std.not_lt_of_ge (_root_.Std.le_trans empty hl)
            simp [inRange, hu]
          · simp [inRange, hl]

private abbrev Bytes := Spike.engine.Bytes
private abbrev Row := Bytes × Bytes
private abbrev Entries := alloc.vec.Vec Row

private def rowKey (encode : List U8 → String) (row : Row) : String := encode row.1.val

private theorem insertion_index_spec {encode : List U8 → String}
    (order : PreservesByteOrder encode) (entries : Entries) (key : Bytes)
    : WP.spec (Spike.engine.insertion_index entries key)
        (fun pos =>
          pos.val ≤ entries.val.length
          ∧ (∀ row ∈ entries.val.take pos.val, rowKey encode row < encode key.val)
          ∧ ∀ h : pos.val < entries.val.length,
              encode key.val ≤ rowKey encode entries.val[pos.val]) := by
  unfold Spike.engine.insertion_index Spike.engine.insertion_index_loop
  apply loop.spec_decr_nat (fun pos : Usize => entries.val.length - pos.val)
    (fun pos => pos.val ≤ entries.val.length ∧
      ∀ row ∈ entries.val.take pos.val, rowKey encode row < encode key.val) _ _ _
  · intro pos ⟨hpos, hprefix⟩
    unfold Spike.engine.insertion_index_loop.body
    have hlen : (alloc.vec.Vec.len entries).val = entries.val.length :=
      alloc.vec.Vec.len_val entries
    have hcap := alloc.vec.Vec.len_ineq entries
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : pos < alloc.vec.Vec.len entries
    · have hb : pos.val < entries.val.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec entries pos hb)
      rintro ⟨k, v⟩ hrow
      change WP.spec (do
        let cmp ← Spike.engine.Bytes.compare k key
        if cmp < 0#i8 then
          let next ← pos + 1#usize
          Result.ok (ControlFlow.cont next)
        else Result.ok (ControlFlow.done pos)) _
      apply WP.spec_bind (bytes_compare k key)
      intro cmp hcmp
      by_cases hlt : cmp < 0#i8
      · rw [ite_eq_left hlt]
        apply WP.spec_bind (Usize.add_spec (x := pos) (y := 1#usize) (by omega))
        intro next hnext
        have hn : next.val = pos.val + 1 := by omega
        have hk := (byteOrder_lt_encoded order k.val key.val).mp (hcmp ▸ hlt)
        rw [WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        intro row hr
        rw [hn, List.take_succ_eq_append_getElem hb, ← hrow, List.mem_append,
          List.mem_singleton] at hr
        rcases hr with hp | rfl
        · exact hprefix _ hp
        · exact hk
      · rw [ite_eq_right hlt, WP.spec_ok]
        refine ⟨hpos, hprefix, fun _ => ?_⟩
        rw [← hrow]
        exact _root_.Std.not_lt.mp (fun hk => hlt (hcmp ▸
          (byteOrder_lt_encoded order k.val key.val).mpr hk))
    · have hb : ¬pos.val < entries.val.length := by rw [← hlen]; exact h
      rw [ite_eq_right h, WP.spec_ok]
      exact ⟨hpos, hprefix, fun hy => (hb hy).elim⟩
  · simp

private theorem insertIdx_split {α : Type} (xs : List α) (i : Nat) (x : α)
    (hi : i ≤ xs.length)
    : xs.insertIdx i x = xs.take i ++ x :: xs.drop i := by
  induction xs generalizing i with
  | nil =>
      have : i = 0 := by simpa using hi
      subst i
      rfl
  | cons y ys ih =>
      cases i with
      | zero => rfl
      | succ j =>
          simp only [List.insertIdx_succ_cons, List.take_succ_cons, List.drop_succ_cons,
            List.cons_append]
          rw [ih j (by simpa using hi)]

private theorem insertIdx_sorted {α : Type} (key : α → String)
    {xs : List α} {x : α} {i : Nat}
    (sorted : xs.Pairwise (fun a b => key a ≤ key b))
    (hi : i ≤ xs.length)
    (before : ∀ a ∈ xs.take i, key a < key x)
    (atIndex : ∀ h : i < xs.length, key x ≤ key xs[i])
    : (xs.insertIdx i x).Pairwise (fun a b => key a ≤ key b) := by
  have hsplit := List.pairwise_append.mp
    (show (xs.take i ++ xs.drop i).Pairwise (fun a b => key a ≤ key b) by simpa using sorted)
  have hafter : ∀ b ∈ xs.drop i, key x ≤ key b := by
    intro b hb
    by_cases h : i < xs.length
    · have hd := List.drop_eq_getElem_cons (l := xs) h
      rw [hd] at hb
      rcases List.mem_cons.mp hb with he | ht
      · simpa only [he] using atIndex h
      · have htail := hsplit.2.1
        rw [hd] at htail
        exact _root_.Std.le_trans (atIndex h) ((List.pairwise_cons.mp htail).1 b ht)
    · rw [List.drop_eq_nil_of_le (Nat.le_of_not_gt h)] at hb
      exact (List.not_mem_nil hb).elim
  rw [insertIdx_split xs i x hi, List.pairwise_append]
  refine ⟨hsplit.1, List.pairwise_cons.mpr ⟨hafter, hsplit.2.1⟩, ?_⟩
  intro a ha b hb
  rcases List.mem_cons.mp hb with rfl | hb
  · exact _root_.Std.le_of_lt (before a ha)
  · exact hsplit.2.2 a ha b hb

private theorem insert_row {encode : List U8 → String}
    (order : PreservesByteOrder encode) (out : Entries) (row : Row)
    (hcap : out.val.length < Usize.max)
    (sorted : out.val.Pairwise (fun a b => rowKey encode a ≤ rowKey encode b))
    : WP.spec
        (do
          let pos ← Spike.engine.insertion_index out row.1
          if pos = alloc.vec.Vec.len out then
            let p ← (BuiltinClone Row).clone row
            alloc.vec.Vec.push out p
          else
            let p ← (BuiltinClone Row).clone row
            alloc.vec.Vec.insert out pos p)
        (fun result =>
          result.val.length = out.val.length + 1
          ∧ result.val.Pairwise (fun a b => rowKey encode a ≤ rowKey encode b)
          ∧ result.val.Perm (row :: out.val)) := by
  apply WP.spec_bind (insertion_index_spec order out row.1)
  intro pos ⟨hpos, hbefore, hnext⟩
  have hlen := alloc.vec.Vec.len_val out
  have hpost : ∀ result : Entries, result.val = out.val.insertIdx pos.val row →
      result.val.length = out.val.length + 1 ∧
        result.val.Pairwise (fun a b => rowKey encode a ≤ rowKey encode b) ∧
        result.val.Perm (row :: out.val) := by
    intro result hr
    rw [hr]
    exact ⟨List.length_insertIdx_of_le_length hpos row,
      insertIdx_sorted (rowKey encode) sorted hpos hbefore hnext, List.perm_insertIdx row _ hpos⟩
  by_cases heq : pos = alloc.vec.Vec.len out
  · rw [ite_eq_left heq]
    simp only [BuiltinClone, bind_ok]
    apply WP.spec_mono (alloc.vec.Vec.push_spec out row hcap)
    intro result hr
    apply hpost result
    rwa [heq, hlen, List.insertIdx_length_self]
  · rw [ite_eq_right heq]
    simp only [BuiltinClone, bind_ok]
    have hlt : pos.val < out.val.length := by
      apply Nat.lt_of_le_of_ne hpos
      intro he
      exact heq (UScalar.val_eq_imp _ _ (he.trans hlen.symm))
    exact WP.spec_mono (alloc.vec.Vec.insert_spec out pos row hlt hcap) hpost

private theorem compare_ok (a b : Bytes)
    : Spike.engine.Bytes.compare a b = .ok (byteOrder a.val b.val) := by
  have h := bytes_compare a b
  cases heq : Spike.engine.Bytes.compare a b using Result.cases with
  | ret cmp => simpa [heq] using h
  | vis _ _ => simp [heq] at h
  | div => simp [heq] at h

private def lowerAllows (encode : List U8 → String) (lower : Option Bytes) (row : Row)
    : Bool :=
  (encodeBound encode lower).all (fun l => decide (l ≤ rowKey encode row))

private def upperAllows (encode : List U8 → String) (upper : Option Bytes) (row : Row)
    : Bool :=
  (encodeBound encode upper).all (fun u => decide (rowKey encode row < u))

private def checkLower (lower : Option Bytes) (row : Row) : Result (Row × Bool) :=
  match lower with
  | none => Result.ok (row, true)
  | some l => do
      let (k, _) := row
      let cmp ← Spike.engine.Bytes.compare l k
      Result.ok (row, decide (cmp ≤ 0#i8))

private def checkUpper (upper : Option Bytes) (row : Row) : Result (Row × Bool) :=
  match upper with
  | none => Result.ok (row, true)
  | some u => do
      let (k, _) := row
      let cmp ← Spike.engine.Bytes.compare k u
      Result.ok (row, decide (cmp < 0#i8))

private theorem lower_result {encode : List U8 → String}
    (order : PreservesByteOrder encode) (lower : Option Bytes) (row : Row)
    : checkLower lower row = .ok (row, lowerAllows encode lower row) := by
  obtain ⟨k, v⟩ := row
  cases lower with
  | none => rfl
  | some l =>
      simp only [checkLower, compare_ok, bind_ok]
      exact congrArg (fun b => Result.ok ((k, v), b))
        (Bool.decide_congr (byteOrder_le_encoded order l.val k.val))

private theorem upper_result {encode : List U8 → String}
    (order : PreservesByteOrder encode) (upper : Option Bytes) (row : Row)
    : checkUpper upper row = .ok (row, upperAllows encode upper row) := by
  obtain ⟨k, v⟩ := row
  cases upper with
  | none => rfl
  | some u =>
      simp only [checkUpper, compare_ok, bind_ok]
      exact congrArg (fun b => Result.ok ((k, v), b))
        (Bool.decide_congr (byteOrder_lt_encoded order k.val u.val))

private theorem ordered_range_perm {encode : List U8 → String}
    (order : PreservesByteOrder encode) (entries : Entries) (lower upper : Option Bytes)
    : WP.spec (Spike.engine.ordered_range entries lower upper)
        (fun out =>
          out.val.Pairwise (fun a b => rowKey encode a ≤ rowKey encode b)
          ∧ out.val.Perm
              (entries.val.filter
                fun row =>
                  inRange (encodeBound encode lower) (encodeBound encode upper)
                    (rowKey encode row))) := by
  let accepts := fun row : Row => lowerAllows encode lower row && upperAllows encode upper row
  change WP.spec _ (fun out : Entries => out.val.Pairwise (fun a b => rowKey encode a ≤ rowKey encode b) ∧
    out.val.Perm (entries.val.filter accepts))
  unfold Spike.engine.ordered_range Spike.engine.ordered_range_loop
  apply loop.spec_decr_nat (fun (p : Entries × Usize) => entries.val.length - p.2.val)
    (fun (out, i) =>
      out.val.length ≤ i.val
      ∧ out.val.Pairwise (fun a b => rowKey encode a ≤ rowKey encode b)
      ∧ (out.val ++ (entries.val.drop i.val).filter accepts).Perm
          (entries.val.filter accepts))
    _ _ _
  · rintro ⟨out, i⟩ ⟨hsize, hsorted, hperm⟩
    dsimp only at hsize hsorted hperm ⊢
    unfold Spike.engine.ordered_range_loop.body
    have hlen : (alloc.vec.Vec.len entries).val = entries.val.length :=
      alloc.vec.Vec.len_val entries
    have hcap := alloc.vec.Vec.len_ineq entries
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len entries
    · have hb : i.val < entries.val.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec entries i hb)
      intro row hrow
      change WP.spec (do
        let lo ← checkLower lower row
        let hi ← checkUpper upper lo.1
        let result ← if lo.2 then
          if hi.2 then
            let pos ← Spike.engine.insertion_index out hi.1.1
            if pos = alloc.vec.Vec.len out then
              let p ← (BuiltinClone Row).clone hi.1
              alloc.vec.Vec.push out p
            else
              let p ← (BuiltinClone Row).clone hi.1
              alloc.vec.Vec.insert out pos p
          else Result.ok out
        else Result.ok out
        let j ← i + 1#usize
        Result.ok (ControlFlow.cont (result, j))) _
      simp only [lower_result order, upper_result order, bind_ok]
      have hdrop : entries.val.drop i.val = row :: entries.val.drop (i.val + 1) := by
        rw [List.drop_eq_getElem_cons hb, ← hrow]
      have hroom : out.val.length < Usize.max := by omega
      have hadd : i.val + (1#usize : Usize).val ≤ Usize.max := by omega
      have rejected (hno : ¬accepts row = true) :
          (out.val ++ (entries.val.drop (i.val + 1)).filter accepts).Perm
            (entries.val.filter accepts) := by
        simpa only [hdrop, List.filter_cons, ite_eq_right hno] using hperm
      apply WP.spec_bind (Pₘ := fun result : Entries =>
        result.val.length ≤ i.val + 1 ∧
          result.val.Pairwise (fun a b => rowKey encode a ≤ rowKey encode b) ∧
          (result.val ++ (entries.val.drop (i.val + 1)).filter accepts).Perm
            (entries.val.filter accepts))
      · by_cases hl : lowerAllows encode lower row = true
        · rw [ite_eq_left hl]
          by_cases hu : upperAllows encode upper row = true
          · rw [ite_eq_left hu]
            apply WP.spec_mono (insert_row order out row hroom hsorted)
            intro result ⟨hresult, hsort, hp⟩
            have hkeep : accepts row = true := by simp [accepts, hl, hu]
            rw [hdrop, List.filter_cons, ite_eq_left hkeep] at hperm
            exact ⟨by omega, hsort, ((hp.append_right _).trans List.perm_middle.symm).trans hperm⟩
          · rw [ite_eq_right hu, WP.spec_ok]
            exact ⟨by omega, hsorted, rejected (by simp [accepts, hu])⟩
        · rw [ite_eq_right hl, WP.spec_ok]
          exact ⟨by omega, hsorted, rejected (by simp [accepts, hl])⟩
      · intro result ⟨hresult, hsort, hp⟩
        apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) hadd)
        intro j hj
        have hj' : j.val = i.val + 1 := by omega
        rw [WP.spec_ok]
        dsimp only
        exact ⟨⟨by omega, hsort, by simpa only [hj'] using hp⟩, by omega⟩
    · have hb : entries.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      rw [ite_eq_right h, WP.spec_ok]
      exact ⟨hsorted, by simpa [List.drop_eq_nil_of_le hb] using hperm⟩
  · simp

private theorem eq_of_unique_key {K V : Type} {rows : Assoc K V}
    (unique : (rows.map Prod.fst).Nodup) {a b : K × V}
    (ha : a ∈ rows) (hb : b ∈ rows) (heq : a.1 = b.1)
    : a = b := by
  induction rows with
  | nil => simp at ha
  | cons row rows ih =>
      simp only [List.map_cons, List.nodup_cons] at unique
      rcases List.mem_cons.mp ha with rfl | ha'
      · rcases List.mem_cons.mp hb with rfl | hb'
        · rfl
        · exact (unique.1 (heq.symm ▸ List.mem_map_of_mem hb')).elim
      · rcases List.mem_cons.mp hb with rfl | hb'
        · exact (unique.1 (heq ▸ List.mem_map_of_mem ha')).elim
        · exact ih unique.2 ha' hb'

/-- The extracted ordered range returns exactly the model's half-open filter followed by
ascending key sort, on inputs whose projected keys are unique. -/
theorem ordered_range {encode : List U8 → String} (order : PreservesByteOrder encode)
    (entries : alloc.vec.Vec (Spike.engine.Bytes × Spike.engine.Bytes))
    (lower upper : Option Spike.engine.Bytes)
    (unique : ((encodeEntries encode entries).map Prod.fst).Nodup)
    : WP.spec (Spike.engine.ordered_range entries lower upper)
        (fun out =>
          encodeEntries encode out
          = ((encodeEntries encode entries).filter
              (fun (k, _) =>
                inRange (encodeBound encode lower) (encodeBound encode upper)
                  k)).mergeSort
              (fun a b => decide (a.1 ≤ b.1))) := by
  let project : Row → String × String := fun (k, v) => (encode k.val, encode v.val)
  let filtered := (encodeEntries encode entries).filter fun (k, _) =>
    inRange (encodeBound encode lower) (encodeBound encode upper) k
  let cmp : (String × String) → (String × String) → Bool := fun a b => decide (a.1 ≤ b.1)
  apply WP.spec_mono (ordered_range_perm order entries lower upper)
  intro out ⟨hsorted, hperm⟩
  change encodeEntries encode out = filtered.mergeSort cmp
  have hp : (encodeEntries encode out).Perm filtered := by
    unfold filtered encodeEntries
    rw [List.filter_map]
    exact hperm.map project
  have hsort : (encodeEntries encode out).Pairwise (fun a b => a.1 ≤ b.1) :=
    hsorted.map project (fun _ _ h => h)
  have hsort' : (filtered.mergeSort cmp).Pairwise (fun a b => a.1 ≤ b.1) := by
    apply List.Pairwise.imp (R := fun a b => cmp a b = true) (fun h => of_decide_eq_true h)
    apply List.pairwise_mergeSort
    · intro a b c hab hbc
      exact decide_eq_true (_root_.Std.le_trans (of_decide_eq_true hab) (of_decide_eq_true hbc))
    · intro a b
      rcases _root_.Std.le_total (a := a.1) (b := b.1) with h | h <;> simp [cmp, h]
  have hm := List.mergeSort_perm filtered cmp
  apply List.Perm.eq_of_pairwise _ hsort hsort' (hp.trans hm.symm)
  intro a b ha hb hab hba
  exact eq_of_unique_key unique (List.mem_of_mem_filter (hp.subset ha))
    (List.mem_of_mem_filter (hm.subset hb)) (_root_.Std.le_antisymm hab hba)

/-- Even without a uniqueness hypothesis, an empty model interval yields no extracted rows. -/
theorem ordered_range_empty {encode : List U8 → String}
    (order : PreservesByteOrder encode)
    (entries : alloc.vec.Vec (Spike.engine.Bytes × Spike.engine.Bytes))
    (lower upper : Option Spike.engine.Bytes)
    (empty : emptyRange (encodeBound encode lower) (encodeBound encode upper) = true)
    : WP.spec (Spike.engine.ordered_range entries lower upper)
        (fun out => out.val = []) := by
  apply WP.spec_mono (ordered_range_perm order entries lower upper)
  intro out ⟨_, hp⟩
  have hn : (entries.val.filter fun row =>
      inRange (encodeBound encode lower) (encodeBound encode upper) (rowKey encode row)) = [] :=
    List.filter_eq_nil_iff.mpr (fun row _ => by simp [inRange_of_emptyRange empty (rowKey encode row)])
  exact (hn ▸ hp).eq_nil

end KvRust
