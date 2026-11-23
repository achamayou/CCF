-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs
public import Kv.Model.Types

import all Aeneas.Data.List.List
import all Aeneas.Std.Core.Core
import all Init.Data.Nat.Power2.Basic

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- Digit zero marks the end of a key and never aliases an actual nibble. -/
def radixSymbol (key : List U8) (digit : Nat) : Nat :=
  match key[digit / 2]? with
  | none => 0
  | some byte => 1 + if digit % 2 = 0 then byte.val / 16 else byte.val % 16

/-- Every digit selects one of the 17 directory slots. -/
theorem radixSymbol_bound (key : List U8) (digit : Nat) : radixSymbol key digit < 17 := by
  unfold radixSymbol
  split
  · decide
  · rename_i byte _
    have hb := U8.lt_succ_max byte
    split <;> omega

/-- A real byte, including zero, never uses the terminal slot. -/
theorem radixSymbol_terminal (key : List U8) (digit : Nat)
    : radixSymbol key digit = 0 ↔ key.length ≤ digit / 2 := by
  by_cases h : digit / 2 < key.length
  · rw [radixSymbol, List.getElem?_eq_getElem h]
    simp
    omega
  · have h' : key.length ≤ digit / 2 := by omega
    simp [radixSymbol, h']

/-- Routing digits distinguish keys even when one key ends at a prefix of another. -/
theorem radixSymbol_injective : Function.Injective radixSymbol := by
  intro a b hab
  apply List.ext_getElem?
  intro i
  have hi : (2 * i) / 2 = i := by omega
  have hip : (2 * i + 1) / 2 = i := by omega
  have even : (2 * i) % 2 = 0 := by omega
  have odd : (2 * i + 1) % 2 ≠ 0 := by omega
  have lengths : a.length ≤ i ↔ b.length ≤ i := by
    rw [← hi, ← radixSymbol_terminal, ← radixSymbol_terminal, hab]
  by_cases ha : i < a.length
  · have hb : i < b.length := by omega
    have high := congrFun hab (2 * i)
    have low := congrFun hab (2 * i + 1)
    simp only [radixSymbol, hi, List.getElem?_eq_getElem ha, List.getElem?_eq_getElem hb,
      even, ite_true] at high
    simp only [radixSymbol, hip, List.getElem?_eq_getElem ha, List.getElem?_eq_getElem hb,
      odd, ite_false] at low
    rw [List.getElem?_eq_getElem ha, List.getElem?_eq_getElem hb]
    congr 1
    apply UScalar.eq_of_val_eq
    omega
  · have hb : b.length ≤ i := by omega
    simp [List.getElem?_eq_none (by omega : a.length ≤ i), List.getElem?_eq_none hb]

/-- The Rust directory selector implements the mathematical symbols for all native inputs. -/
theorem radix_symbol_matches (key : Slice U8) (digit : Usize)
    : WP.spec (Spike.radix.symbol key digit)
        (fun slot => slot.val = radixSymbol key.val digit.val) := by
  unfold Spike.radix.symbol
  apply WP.spec_bind (Usize.div_spec digit (by decide : (2#usize : Usize).val ≠ 0))
  intro index hindex
  have hat' : index.val = digit.val / 2 := hindex
  by_cases outside : Slice.len key ≤ index
  · have h : key.val.length ≤ digit.val / 2 := by
      have hn : key.val.length ≤ index.val := outside
      omega
    simp [outside, (radixSymbol_terminal key.val digit.val).mpr h]
  · have inside : index.val < key.val.length := by
      have hn : ¬key.val.length ≤ index.val := outside
      omega
    simp only [outside, ite_false]
    apply WP.spec_bind (Slice.index_usize_spec key index inside)
    intro byte hbyte
    apply WP.spec_bind (Usize.rem_spec digit (by decide : (2#usize : Usize).val ≠ 0))
    intro side hside
    have hside' : side.val = digit.val % 2 := hside
    have hselect : radixSymbol key.val digit.val =
        1 + if digit.val % 2 = 0 then byte.val / 16 else byte.val % 16 := by
      simp only [radixSymbol, ← hat', List.getElem?_eq_getElem inside, ← hbyte]
    have hcast (b : U8) : (UScalar.cast .Usize b).val = b.val := U8.cast_Usize_val_eq b
    have hsum (b : U8) : (1#usize : Usize).val + (UScalar.cast .Usize b).val ≤ Usize.max := by
      rw [hcast]
      have hb := U8.lt_succ_max b
      have hmax : 256 ≤ Usize.max := by scalar_tac
      change 1 + b.val ≤ Usize.max
      omega
    by_cases high : side = 0#usize
    · have hparity : digit.val % 2 = 0 := by
        rw [← hside', high]
        rfl
      simp only [high, ite_true, hselect, hparity]
      apply WP.spec_bind (U8.div_spec byte (by decide : (16#u8 : U8).val ≠ 0))
      intro b hb
      simp only [lift, bind_ok]
      apply WP.spec_mono (Usize.add_spec (hsum b))
      intro slot hs
      rw [hs, hcast, hb]
      rfl
    · have hparity : digit.val % 2 ≠ 0 := by
        rw [← hside']
        intro h
        apply high
        apply UScalar.eq_of_val_eq
        exact h
      simp only [high, ite_false, hselect, hparity]
      apply WP.spec_bind (U8.rem_spec byte (by decide : (16#u8 : U8).val ≠ 0))
      intro b hb
      simp only [lift, bind_ok]
      apply WP.spec_mono (Usize.add_spec (hsum b))
      intro slot hs
      rw [hs, hcast, hb]
      rfl

/-- A successful split is the earliest differing routing digit. -/
def radixSplit (a b : List U8) (split : Option Nat) : Prop :=
  match split with
  | none => a = b
  | some digit =>
      radixSymbol a digit ≠ radixSymbol b digit
      ∧ ∀ prev, prev < digit → radixSymbol a prev = radixSymbol b prev

private theorem earlier_symbols (a b : List U8) (i digit : Nat)
    (shared : ∀ j, j < i → a[j]? = b[j]?)
    (earlier : digit < 2 * i)
    : radixSymbol a digit = radixSymbol b digit := by
  unfold radixSymbol
  rw [shared _ (by omega)]

private theorem high_symbol (key : List U8) (i : Nat) (hi : i < key.length)
    : radixSymbol key (2 * i) = 1 + key[i].val / 16 := by
  have hdiv : (2 * i) / 2 = i := by omega
  have hrem : (2 * i) % 2 = 0 := by omega
  simp [radixSymbol, hdiv, hrem, List.getElem?_eq_getElem hi]

private theorem low_symbol (key : List U8) (i : Nat) (hi : i < key.length)
    : radixSymbol key (2 * i + 1) = 1 + key[i].val % 16 := by
  have hdiv : (2 * i + 1) / 2 = i := by omega
  simp [radixSymbol, hdiv, List.getElem?_eq_getElem hi]

private theorem differing_byte (a b : List U8) (i : Nat)
    (shared : ∀ j, j < i → a[j]? = b[j]?)
    (ha : i < a.length) (hb : i < b.length)
    (different : a[i] ≠ b[i])
    : radixSplit a b
        (some (if a[i].val / 16 = b[i].val / 16 then 2 * i + 1 else 2 * i)) := by
  by_cases high : a[i].val / 16 = b[i].val / 16
  · simp only [high, ite_true, radixSplit]
    refine ⟨?_, ?_⟩
    · rw [low_symbol _ _ ha, low_symbol _ _ hb]
      intro he
      apply different
      apply UScalar.eq_of_val_eq
      omega
    · intro prev hp
      by_cases earlier : prev < 2 * i
      · exact earlier_symbols a b i prev shared earlier
      · have he : prev = 2 * i := by omega
        rw [he, high_symbol _ _ ha, high_symbol _ _ hb, high]
  · simp only [high, ite_false, radixSplit]
    refine ⟨?_, fun prev => earlier_symbols a b i prev shared⟩
    rw [high_symbol _ _ ha, high_symbol _ _ hb]
    exact fun he => high (by omega)

private theorem prefix_end (a b : List U8) (i : Nat)
    (shared : ∀ j, j < i → a[j]? = b[j]?)
    (ha : i ≤ a.length) (hb : i ≤ b.length)
    (atEnd : a.length ≤ i ∨ b.length ≤ i)
    : radixSplit a b (if a.length = b.length then none else some (2 * i)) := by
  by_cases he : a.length = b.length
  · simp only [he, ite_true, radixSplit]
    apply List.ext_getElem?
    intro j
    by_cases hj : j < i
    · exact shared j hj
    · have ha' : a.length ≤ j := by omega
      have hb' : b.length ≤ j := by omega
      simp [ha', hb']
  · simp only [he, ite_false, radixSplit]
    refine ⟨?_, fun prev => earlier_symbols a b i prev shared⟩
    have hhalf : 2 * i / 2 = i := by omega
    rcases atEnd with h | h
    · have hterm := (radixSymbol_terminal a (2 * i)).mpr (by rwa [hhalf])
      have hnon : radixSymbol b (2 * i) ≠ 0 :=
        fun hz => by have := (radixSymbol_terminal b (2 * i)).mp hz; omega
      rw [hterm]
      exact Ne.symm hnon
    · have hterm := (radixSymbol_terminal b (2 * i)).mpr (by rwa [hhalf])
      have hnon : radixSymbol a (2 * i) ≠ 0 :=
        fun hz => by have := (radixSymbol_terminal a (2 * i)).mp hz; omega
      rwa [hterm]

private theorem byte_difference_spec (index : Usize) (a b : U8)
    (fits : 2 * index.val + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.byte_difference index a b)
        (fun digit =>
          digit.val
          = if a.val / 16 = b.val / 16 then 2 * index.val + 1 else 2 * index.val) := by
  unfold Spike.radix.byte_difference
  apply WP.spec_bind (U8.div_spec a (by decide : (16#u8 : U8).val ≠ 0))
  intro x hx
  apply WP.spec_bind (U8.div_spec b (by decide : (16#u8 : U8).val ≠ 0))
  intro y hy
  have htwo : (2#usize : Usize).val = 2 := rfl
  have hone : (1#usize : Usize).val = 1 := rfl
  have hscale : (2#usize : Usize).val * index.val ≤ Usize.max :=
    Nat.le_trans (Nat.le_succ _) fits
  have hx' : x.val = a.val / 16 := hx
  have hy' : y.val = b.val / 16 := hy
  by_cases same : x = y
  · have high : a.val / 16 = b.val / 16 := by rw [← hx', ← hy', same]
    simp only [same, bne_self_eq_false, Bool.false_eq_true, ite_false, high, ite_true]
    apply WP.spec_bind (Usize.mul_spec hscale)
    intro i hi
    have hi' : i.val = 2 * index.val := hi
    have hplus : i.val + (1#usize : Usize).val ≤ Usize.max := hi' ▸ fits
    simpa only [hi', hone] using Usize.add_spec hplus
  · have high : a.val / 16 ≠ b.val / 16 := by
      rw [← hx', ← hy']
      exact fun he => same (UScalar.eq_of_val_eq he)
    have test : (x != y) = true := bne_iff_ne.mpr same
    simpa only [test, ite_true, high, ite_false, htwo] using Usize.mul_spec hscale

/-- The compiled split loop finds the first differing digit, or proves both keys equal.
The bound is on the doubled byte index, not on the contents of either key. -/
theorem radix_first_difference_matches (a b : Slice U8)
    (fits : 2 * min a.val.length b.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.first_difference a b)
        (fun found => radixSplit a.val b.val (found.map UScalar.val)) := by
  let count := min a.val.length b.val.length
  unfold Spike.radix.first_difference Spike.radix.first_difference_loop
  apply loop.spec_decr_nat
    (fun i : Usize => count - i.val)
    (fun i =>
      i.val ≤ count ∧ ∀ j, j < i.val → a.val[j]? = b.val[j]?)
    _ _ _
  · intro i hi
    obtain ⟨hi, shared⟩ := hi
    have htwo : (2#usize : Usize).val = 2 := rfl
    have hone : (1#usize : Usize).val = 1 := rfl
    have hroom : 2 * i.val + 1 ≤ Usize.max := by omega
    have ha : i.val ≤ a.val.length := hi.trans (Nat.min_le_left _ _)
    have hb : i.val ≤ b.val.length := hi.trans (Nat.min_le_right _ _)
    unfold Spike.radix.first_difference_loop.body
    by_cases ga : i < Slice.len a <;> by_cases gb : i < Slice.len b
    · have hA : i.val < a.val.length := ga
      have hB : i.val < b.val.length := gb
      simp only [ga, gb, ite_true]
      apply WP.spec_bind (Slice.index_usize_spec a i hA)
      intro u hu
      apply WP.spec_bind (Slice.index_usize_spec b i hB)
      intro v hv
      by_cases he : u = v
      · simp only [he, bne_self_eq_false, Bool.false_eq_true, ite_false]
        have hcount : i.val < count := Nat.lt_min.mpr ⟨hA, hB⟩
        apply WP.spec_bind (Usize.add_spec (by omega))
        intro next hnext
        simp only [WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        intro j hj
        by_cases prev : j < i.val
        · exact shared j prev
        · have eq : j = i.val := by omega
          subst j
          rw [List.getElem?_eq_getElem hA, List.getElem?_eq_getElem hB, ← hu, ← hv, he]
      · have test : (u != v) = true := bne_iff_ne.mpr he
        simp only [test, ite_true]
        apply WP.spec_bind (byte_difference_spec i u v hroom)
        intro digit hdigit
        have hdiff : a.val[i.val] ≠ b.val[i.val] := by rwa [← hu, ← hv]
        have hs := differing_byte a.val b.val i.val shared hA hB hdiff
        simpa only [WP.spec_ok, Option.map_some, hdigit, hu, hv] using hs
    all_goals
      have ended : a.val.length ≤ i.val ∨ b.val.length ≤ i.val := by
        first
        | exact Or.inr (Nat.le_of_not_gt gb)
        | exact Or.inl (Nat.le_of_not_gt ga)
      simp only [ga, ite_true, ite_false]
      try simp only [gb, ite_false]
      have split := prefix_end a.val b.val i.val shared ha hb ended
      by_cases he : Slice.len a = Slice.len b
      · have hlen : a.val.length = b.val.length := congrArg UScalar.val he
        simpa only [he, ite_true, WP.spec_ok, hlen, Option.map_none] using split
      · have hlen : a.val.length ≠ b.val.length :=
          fun h => he (UScalar.eq_of_val_eq h)
        simp only [he, ite_false]
        apply WP.spec_bind (Usize.mul_spec (by rw [htwo]; omega))
        intro digit hdigit
        simpa only [WP.spec_ok, Option.map_some, hdigit, htwo, hlen, ite_false] using split
  · simp

/-- A finite projection of an arena root. Each directory partitions its
bindings by the selected digit; its children have strictly smaller height. -/
inductive RadixTree (dirs : List (Option Spike.radix.RadixDir))
    : Nat → U32 → List (List U8 × U32) → Prop where
  | empty (height : Nat) : RadixTree dirs height 0#u32 []
  | leaf (height : Nat) (node : U32) (key : List U8)
    (tagged : (2147483648#u32 : U32) ≤ node)
    : RadixTree dirs height node [(key, node)]
  | branch (height : Nat) (node : U32) (dir : Spike.radix.RadixDir)
    (bindings : List (List U8 × U32))
    (positive : 0 < node.val) (untagged : node < 2147483648#u32)
    (live : dirs[node.val - 1]? = some (some dir))
    (child : Nat → U32)
    (links : ∀ slot, slot < 17 → dir.children.val[slot]? = some (child slot))
    (children
      : ∀ slot,
          slot < 17
          → RadixTree dirs height (child slot)
              (bindings.filter fun row => radixSymbol row.1 dir.digit.val == slot))
    : RadixTree dirs (height + 1) node bindings

private theorem radix_tag : Spike.radix.RADIX_LEAF_TAG = 2147483648#u32 := by
  simp [Spike.radix.RADIX_LEAF_TAG]

/-- Exactly the slots holding a nonempty link appear in a directory's bitmap. -/
def RadixMask (dir : Spike.radix.RadixDir) : Prop :=
  ∀ i,
    i < 32
    → dir.mask.bv.getLsbD i
      = decide (∃ child, dir.children.val[i]? = some child ∧ child ≠ 0#u32)

theorem radix_empty_matches (digit : Usize)
    : WP.spec (Spike.radix.RadixDir.empty digit)
        (fun dir =>
          dir.digit = digit
          ∧ dir.first = 0#u32
          ∧ dir.children.val = List.replicate 17 0#u32
          ∧ RadixMask dir) := by
  unfold Spike.radix.RadixDir.empty
  simp only [WP.spec_ok, Array.repeat_val]
  refine ⟨trivial, trivial, rfl, ?_⟩
  intro i _
  have hz : (0#u32 : U32).bv = 0#32 := rfl
  simp only [hz, BitVec.getLsbD_zero, Array.repeat_val]
  symm
  apply decide_eq_false
  rintro ⟨child, hget, nz⟩
  exact nz (List.mem_replicate.mp (List.mem_of_getElem? hget)).2

/-- A directory update changes just one child and its occupancy bit. The
caller refreshes the cached first leaf before publishing the directory. -/
theorem radix_set_child_matches (dir : Spike.radix.RadixDir) (slot : Usize) (child : U32)
    (bound : slot.val < 17)
    : WP.spec (Spike.radix.RadixDir.set_child dir slot child)
        (fun next =>
          next.digit = dir.digit
          ∧ next.first = dir.first
          ∧ next.children.val = dir.children.val.set slot.val child
          ∧ ∀ i,
              i < 32
              → next.mask.bv.getLsbD i
                = if i = slot.val then child != 0#u32 else dir.mask.bv.getLsbD i) := by
  have hb : slot.val < dir.children.val.length := by
    rw [Array.length_eq]
    exact bound
  have hshift : slot.val < 32 := by omega
  have hbit (one : U32) (h : one.bv = (1#u32 : U32).bv <<< slot.val)
      (i : Nat) (hi : i < 32) : one.bv.getLsbD i = decide (i = slot.val) := by
    have hone : (1#u32 : U32).bv = 1#32 := rfl
    rw [h, hone, BitVec.getLsbD_shiftLeft, BitVec.getLsbD_one]
    by_cases eq : i = slot.val
    · subst i
      simp [hshift]
    · by_cases lt : i < slot.val
      · simp [lt, eq]
      · have hd : i - slot.val ≠ 0 := by omega
        simp [hd, eq]
  unfold Spike.radix.RadixDir.set_child
  apply WP.spec_bind (Array.index_mut_usize_spec dir.children slot hb)
  rintro ⟨_, back⟩ ⟨_, hback⟩
  by_cases zero : child = 0#u32
  · simp only [zero, ite_true]
    apply WP.spec_bind (U32.ShiftLeft_spec 1#u32 slot hshift)
    intro one h
    simp only [lift, bind_ok, WP.spec_ok, hback, Array.set_val_eq]
    refine ⟨trivial, trivial, trivial, ?_⟩
    intro i hi
    let old : BitVec 32 := dir.mask.bv
    let bit : BitVec 32 := one.bv
    change (old &&& ~~~bit).getLsbD i = _
    have hset : bit.getLsbD i = decide (i = slot.val) := hbit one h.2 i hi
    rw [BitVec.getLsbD_and, BitVec.getLsbD_not, hset]
    by_cases same : i = slot.val <;> simp [hi, same, old]
  · simp only [zero, ite_false]
    apply WP.spec_bind (U32.ShiftLeft_spec 1#u32 slot hshift)
    intro one h
    simp only [lift, bind_ok, WP.spec_ok, hback, Array.set_val_eq]
    refine ⟨trivial, trivial, trivial, ?_⟩
    intro i hi
    let old : BitVec 32 := dir.mask.bv
    let bit : BitVec 32 := one.bv
    change (old ||| bit).getLsbD i = _
    have hset : bit.getLsbD i = decide (i = slot.val) := hbit one h.2 i hi
    have nz : (child != 0#u32) = true := bne_iff_ne.mpr zero
    rw [BitVec.getLsbD_or, hset]
    by_cases same : i = slot.val <;> simp [same, nz, old]

theorem radix_set_child_preserves_mask (dir : Spike.radix.RadixDir) (slot : Usize)
    (child : U32) (bound : slot.val < 17) (mask : RadixMask dir)
    : WP.spec (Spike.radix.RadixDir.set_child dir slot child) RadixMask := by
  apply WP.spec_mono (radix_set_child_matches dir slot child bound)
  intro next ⟨_, _, hstep, hmask⟩ i hi
  rw [hmask i hi, hstep]
  by_cases same : i = slot.val
  · subst i
    have hb : slot.val < dir.children.val.length := by
      rw [Array.length_eq]
      exact bound
    rw [List.getElem?_set_self hb]
    by_cases zero : child = 0#u32
    · simp [zero]
    · have nz : (child != 0#u32) = true := bne_iff_ne.mpr zero
      have hval : child.val ≠ 0 := fun h => zero (UScalar.eq_of_val_eq h)
      simp [nz, hval]
  · rw [ite_eq_right same, List.getElem?_set_ne (Ne.symm same)]
    exact mask i hi

/-- The free list has no duplicates and names only vacant, addressable slots. -/
def RadixFree {T : Type} (slots : alloc.vec.Vec (Option T)) (free : alloc.vec.Vec Usize)
    : Prop :=
  free.val.Nodup ∧ ∀ i ∈ free.val, slots.val[i.val]? = some none

/-- Allocation preserves every live slot, including those reached from older roots. -/
theorem radix_allocate_matches {T : Type} (slots : alloc.vec.Vec (Option T))
    (free : alloc.vec.Vec Usize) (value : T)
    (vacant : RadixFree slots free)
    (room : free.val = [] → slots.val.length < Usize.max)
    : WP.spec (Spike.radix.allocate slots free value)
        (fun (i, next, left) =>
          next.val[i.val]? = some (some value)
          ∧ (∀ (j : Nat) (old : T),
              slots.val[j]? = some (some old) → next.val[j]? = some (some old))
          ∧ left.val = free.val.take (free.val.length - 1)
          ∧ i.val ≤ slots.val.length
          ∧ next.val.length ≤ slots.val.length + 1
          ∧ RadixFree next left) := by
  have hlen : (alloc.vec.Vec.len free).val = free.val.length := alloc.vec.Vec.len_val free
  have hone : (1#usize : Usize).val = 1 := rfl
  have hzero : (0#usize : Usize).val = 0 := rfl
  unfold Spike.radix.allocate
  by_cases he : alloc.vec.Vec.len free = 0#usize
  · have hempty : free.val = [] := by
      apply List.length_eq_zero_iff.mp
      exact congrArg UScalar.val he
    simp only [he, ite_true]
    apply WP.spec_bind (alloc.vec.Vec.push_spec slots (some value) (room hempty))
    intro next hnext
    simp only [WP.spec_ok, hnext, alloc.vec.Vec.len_val]
    refine ⟨?_, ?_, by simp [hempty], Nat.le_refl _, by simp, ?_⟩
    · rw [List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]
      rfl
    · intro j old hj
      have hb : j < slots.val.length := by
        by_contra hn
        simp [Nat.le_of_not_gt hn] at hj
      rwa [List.getElem?_append_left hb]
    · simp [RadixFree, hempty]
  · simp only [he, ite_false]
    have hpos : 0 < free.val.length := by
      by_contra hn
      apply he
      apply UScalar.eq_of_val_eq
      omega
    have hsub : (1#usize : Usize).val ≤ (alloc.vec.Vec.len free).val := by omega
    apply WP.spec_bind (Usize.sub_spec hsub)
    intro last hlast
    have hl : last.val = free.val.length - 1 := by omega
    have hfi : last.val < free.val.length := by omega
    simp only [alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_mut_slice_index]
    apply WP.spec_bind (alloc.vec.Vec.index_usize_spec free last hfi)
    intro index hi
    have hv := vacant.2 index (hi ▸ List.getElem_mem hfi)
    have hb : index.val < slots.val.length := by
      by_contra hn
      simp [Nat.le_of_not_gt hn] at hv
    apply WP.spec_bind (alloc.vec.Vec.index_usize_spec slots index hb)
    intro entry hent
    rw [List.getElem?_eq_getElem hb, ← hent, Option.some.injEq] at hv
    rw [hv]
    simp only [core.option.Option.is_none, massert, Option.isNone_none, ite_true, bind_ok]
    apply WP.spec_bind (alloc.vec.Vec.resize_spec core.clone.CloneUsize free last 0#usize rfl)
    intro left hleft
    apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec slots index hb)
    rintro ⟨_, back⟩ ⟨_, hback⟩
    change WP.spec (Result.ok (index, back (some value), left)) _
    simp only [WP.spec_ok, hback, alloc.vec.Vec.set_val_eq]
    have hprefix : left.val = free.val.take (free.val.length - 1) := by
      rw [hleft, hl]
      simp [List.resize, Nat.sub_eq_zero_of_le (Nat.sub_le free.val.length 1)]
    refine ⟨List.getElem?_set_self hb, ?_, hprefix, by omega,
      by simp, ?_⟩
    · intro j old hj
      have different : index.val ≠ j := by
        intro same
        rw [← same, List.getElem?_eq_getElem hb, ← hent, hv] at hj
        cases hj
      rwa [List.getElem?_set_ne different]
    · have hsplit : free.val = left.val ++ [index] := by
        rw [hprefix, ← hl, hi, ← List.take_succ_eq_append_getElem hfi]
        have hf : last.val + 1 = free.val.length := by omega
        simp [hf]
      have hn := vacant.1
      rw [hsplit, List.nodup_append] at hn
      refine ⟨hn.1, ?_⟩
      intro i him
      have hn' : i ≠ index := hn.2.2 i him index (by simp)
      have hne : index.val ≠ i.val := fun eq => hn' (UScalar.eq_of_val_eq eq.symm)
      have hmem : i ∈ free.val := by rw [hsplit]; exact List.mem_append_left _ him
      have hval := vacant.2 i hmem
      change (slots.set index (some value)).val[i.val]? = some none
      rwa [alloc.vec.Vec.set_val_eq, List.getElem?_set_ne hne]

/-- Allocating new directories cannot invalidate an existing root whose live
slots are preserved. The new root is verified separately. -/
theorem radix_tree_preserved
    (old next : List (Option Spike.radix.RadixDir))
    (preserved : ∀ (i : Nat) dir, old[i]? = some (some dir) → next[i]? = some (some dir))
    {height : Nat} {root : U32} {bindings : List (List U8 × U32)}
    (tree : RadixTree old height root bindings)
    : RadixTree next height root bindings := by
  induction tree with
  | empty height => exact .empty height
  | leaf height node key tagged => exact .leaf height node key tagged
  | branch height node dir bindings positive untagged live child links children ih =>
      exact .branch height node dir bindings positive untagged (preserved _ _ live) child
        links ih

private theorem radix_link_matches (index : Usize) (leaf : Bool)
    (bounded : index.val < 2147483647)
    : WP.spec (Spike.radix.link_at index leaf)
        (fun link =>
          link.val = index.val + 1 + if leaf then 2147483648 else 0) := by
  have nativeBound : index < 2147483647#usize := bounded
  unfold Spike.radix.link_at
  simp only [massert, nativeBound, ite_true, bind_ok, radix_tag]
  have hmax : U32.max = 4294967295 := by scalar_tac
  apply WP.spec_bind (UScalar.cast_inBounds_spec .U32 index (by scalar_tac))
  intro slot hslot
  have hone : (1#u32 : U32).val = 1 := rfl
  have hplus : slot.val + (1#u32 : U32).val ≤ U32.max := by omega
  apply WP.spec_bind (U32.add_spec hplus)
  intro raw hraw
  cases leaf
  · simp [hraw, hslot, hone]
  · simp only [ite_true]
    have htag : (2147483648#u32 : U32).val = 2147483648 := rfl
    apply WP.spec_mono (U32.add_spec (x := 2147483648#u32) (y := raw) (by omega))
    intro link hlink
    omega

/-- The first occupied slot in digit order, or zero if all slots are empty. -/
def radixFirst (dir : Spike.radix.RadixDir) : U32 :=
  (dir.children.val.find? (· != 0#u32)).getD 0#u32

theorem radix_first_child_matches (dir : Spike.radix.RadixDir)
    : WP.spec (Spike.radix.RadixDir.first_child dir) (· = radixFirst dir) := by
  have size : dir.children.val.length = 17 := Array.length_eq dir.children
  have fanout : Spike.radix.RADIX_FANOUT = 17#usize := by simp [Spike.radix.RADIX_FANOUT]
  have hone : (1#usize : Usize).val = 1 := rfl
  have hmax : 17 ≤ Usize.max := by scalar_tac
  unfold Spike.radix.RadixDir.first_child Spike.radix.RadixDir.first_child_loop
  apply loop.spec_decr_nat (fun (i : Usize) => 17 - i.val)
    (fun i => i.val ≤ 17
      ∧ ((dir.children.val.drop i.val).find? (· != 0#u32)).getD 0#u32 = radixFirst dir)
    _ _ _
  · intro i ⟨hi, same⟩
    unfold Spike.radix.RadixDir.first_child_loop.body
    rw [fanout]
    by_cases go : i < 17#usize
    · have hpos : i.val < 17 := go
      have hb : i.val < dir.children.val.length := by omega
      simp only [go, ite_true]
      apply WP.spec_bind (Array.index_usize_spec dir.children i hb)
      intro child hc
      rw [List.drop_eq_getElem_cons hb, ← hc, List.find?_cons] at same
      by_cases zero : child = 0#u32
      · have test : (child != 0#u32) = false := by simp [zero]
        simp only [test, Bool.false_eq_true, ite_false] at same ⊢
        apply WP.spec_bind (Usize.add_spec (by omega))
        intro j hj
        have hstep : j.val = i.val + 1 := by omega
        simp only [WP.spec_ok]
        exact ⟨⟨by omega, by simpa only [hstep] using same⟩, by omega⟩
      · have test : (child != 0#u32) = true := bne_iff_ne.mpr zero
        simpa only [test, ite_true, Option.getD_some, WP.spec_ok] using same
    · have hstop : ¬i.val < 17 := go
      have hd : dir.children.val.length ≤ i.val := by omega
      simpa [go, List.drop_eq_nil_of_le hd] using same
  · simp [radixFirst]

private theorem radix_directory_matches (dirs : Slice (Option Spike.radix.RadixDir))
    (node : U32) (dir : Spike.radix.RadixDir) (positive : 0 < node.val)
    (live : dirs.val[node.val - 1]? = some (some dir))
    : WP.spec (Spike.radix.directory dirs node) (· = dir) := by
  unfold Spike.radix.directory
  have hone : (1#u32 : U32).val = 1 := rfl
  have hsub : (1#u32 : U32).val ≤ node.val := by omega
  apply WP.spec_bind (U32.sub_spec hsub)
  intro idx hidx
  simp only [lift, bind_ok]
  let i := UScalar.cast .Usize idx
  have hi : i.val = node.val - 1 := by
    rw [U32.cast_Usize_val_eq, hidx.1, hone]
  have hd : i.val < dirs.val.length := by
    by_contra hn
    have hl : dirs.val.length ≤ node.val - 1 := by omega
    simp [hl] at live
  apply WP.spec_bind (Slice.index_usize_spec dirs i hd)
  intro got hgot
  rw [← hi, List.getElem?_eq_getElem hd, ← hgot, Option.some.injEq] at live
  simp [live]

private abbrev DirArena := alloc.vec.Vec (Option Spike.radix.RadixDir)

/-- All previously live directory slots still hold the same directory. -/
def preservesSlots (old next : alloc.vec.Vec (Option Spike.radix.RadixDir)) : Prop :=
  ∀ (i : Nat) dir, old.val[i]? = some (some dir) → next.val[i]? = some (some dir)

private theorem radix_first_mem (dir : Spike.radix.RadixDir) (nz : radixFirst dir ≠ 0#u32)
    : radixFirst dir ∈ dir.children.val := by
  unfold radixFirst at nz ⊢
  cases h : dir.children.val.find? (· != 0#u32) with
  | none => simp [h] at nz
  | some child => exact List.mem_of_find?_eq_some h

private theorem radix_add_directory_matches (dirs : DirArena) (free : alloc.vec.Vec Usize)
    (dir : Spike.radix.RadixDir) (vacant : RadixFree dirs free)
    (room : dirs.val.length < 2147483647)
    (nonempty : radixFirst dir ≠ 0#u32)
    (live
      : radixFirst dir < 2147483648#u32
        → ∃ child, dirs.val[(radixFirst dir).val - 1]? = some (some child))
    : WP.spec (Spike.radix.add_directory dirs free dir)
        (fun (root, next, left) =>
          0 < root.val
          ∧ root.val < 2147483648
          ∧ (∃ published,
              next.val[root.val - 1]? = some (some published)
              ∧ published.digit = dir.digit
              ∧ published.children = dir.children
              ∧ published.mask = dir.mask)
          ∧ preservesSlots dirs next
          ∧ next.val.length ≤ dirs.val.length + 1
          ∧ RadixFree next left) := by
  unfold Spike.radix.add_directory
  apply WP.spec_bind (radix_first_child_matches dir)
  intro first hf
  subst first
  have nz : (radixFirst dir != 0#u32) = true := bne_iff_ne.mpr nonempty
  simp only [nz, massert, ite_true, bind_ok, radix_tag]
  apply WP.spec_bind (Pₘ := fun (_ : U32) => True)
  · by_cases tagged : 2147483648#u32 ≤ radixFirst dir
    · simp [tagged]
    · simp only [tagged, ite_false]
      have lower : radixFirst dir < 2147483648#u32 := lt_of_not_ge tagged
      obtain ⟨target, ht⟩ := live lower
      have positive : 0 < (radixFirst dir).val := by
        by_contra hn
        apply nonempty
        apply UScalar.eq_of_val_eq
        change (radixFirst dir).val = 0
        omega
      have hs : (alloc.vec.Vec.deref dirs).val[(radixFirst dir).val - 1]? = some (some target) := by
        simpa [alloc.vec.Vec.deref] using ht
      apply WP.spec_bind
        (radix_directory_matches (alloc.vec.Vec.deref dirs) (radixFirst dir) target
          positive hs)
      simp
  · intro cached _
    let updated : Spike.radix.RadixDir := {dir with first := cached}
    have cap : dirs.val.length < Usize.max := by
      have h : 2147483647 ≤ Usize.max := by scalar_tac
      omega
    apply WP.spec_bind (radix_allocate_matches dirs free updated vacant (fun _ => cap))
    rintro ⟨i, next, left⟩ ⟨hnew, hprev, _, hi, hlen, hfree⟩
    apply WP.spec_bind (radix_link_matches i false (by omega))
    intro root hroot
    simp only [Bool.false_eq_true, ite_false, Nat.add_zero] at hroot
    simp only [WP.spec_ok]
    refine ⟨by omega, by omega, ⟨updated, ?_, rfl, rfl, rfl⟩, hprev, hlen, hfree⟩
    have hidx : root.val - 1 = i.val := by omega
    rwa [hidx]

/-- Any directory link names a live slot. Leaf and empty links do not read
the directory arena. -/
def RadixDirLive (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) (link : U32)
    : Prop :=
  link ≠ 0#u32 → link < 2147483648#u32 → ∃ dir, dirs.val[link.val - 1]? = some (some dir)

private theorem radix_live_preserved {old next : DirArena}
    (keep : preservesSlots old next) {link : U32} (live : RadixDirLive old link)
    : RadixDirLive next link := by
  intro nz tagged
  obtain ⟨dir, hdir⟩ := live nz tagged
  exact ⟨dir, keep _ _ hdir⟩

private theorem radix_first_nonzero (dir : Spike.radix.RadixDir)
    (existsChild : ∃ child ∈ dir.children.val, child ≠ 0#u32)
    : radixFirst dir ≠ 0#u32 := by
  obtain ⟨child, hm, hz⟩ := existsChild
  unfold radixFirst
  cases h : dir.children.val.find? (· != 0#u32) with
  | none =>
      have empty := List.find?_eq_none.mp h child hm
      simp [bne_iff_ne.mpr hz] at empty
  | some first =>
      have set := List.find?_some h
      simpa using bne_iff_ne.mp set

/-- A prepared parent names live directories and has a surviving sibling. -/
def SafeParent (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) (parent : U32)
    (slot : Usize)
    : Prop :=
  0 < parent.val
  ∧ slot.val < 17
  ∧ ∃ dir,
      dirs.val[parent.val - 1]? = some (some dir)
      ∧ (∀ child ∈ dir.children.val, RadixDirLive dirs child)
      ∧ ∃ (sibling : Nat) (child : U32),
          sibling ≠ slot.val ∧ dir.children.val[sibling]? = some child ∧ child ≠ 0#u32

private theorem radix_safe_parent_preserved {old next : DirArena}
    (keep : preservesSlots old next) {parent : U32} {slot : Usize}
    (safe : SafeParent old parent slot)
    : SafeParent next parent slot := by
  obtain ⟨pos, bound, dir, live, children, sibling⟩ := safe
  exact ⟨pos, bound, dir, keep _ _ live, fun child hm => radix_live_preserved keep (children child hm),
    sibling⟩

private theorem radix_copy_parent_step (dirs : DirArena) (free : alloc.vec.Vec Usize)
    (parent : U32) (slot : Usize) (child : U32)
    (vacant : RadixFree dirs free) (room : dirs.val.length < 2147483647)
    (safe : SafeParent dirs parent slot) (live : RadixDirLive dirs child)
    : WP.spec (Spike.radix.copy_parent dirs free parent slot child)
        (fun (root, next, left) =>
          preservesSlots dirs next
          ∧ next.val.length ≤ dirs.val.length + 1
          ∧ RadixFree next left
          ∧ RadixDirLive next root
          ∧ ∀ original,
              dirs.val[parent.val - 1]? = some (some original)
              → ∃ updated : Spike.radix.RadixDir,
                  updated.digit = original.digit
                  ∧ updated.children.val = original.children.val.set slot.val child
                  ∧ (RadixMask original → RadixMask updated)
                  ∧ ((0 < root.val
                        ∧ root < 2147483648#u32
                        ∧ ∃ published,
                            next.val[root.val - 1]? = some (some published)
                            ∧ published.digit = updated.digit
                            ∧ published.children = updated.children)
                      ∨ root = radixFirst updated ∧ updated.mask.val.isPowerOfTwo)) := by
  obtain ⟨positive, bound, dir, hdir, hchildren, sibling, survivor, other, hs, hn⟩ := safe
  unfold Spike.radix.copy_parent
  apply WP.spec_bind
    (radix_directory_matches (alloc.vec.Vec.deref dirs) parent dir positive
      (by simpa [alloc.vec.Vec.deref] using hdir))
  intro expected hd
  subst expected
  apply WP.spec_bind (radix_set_child_matches dir slot child bound)
  intro updated ⟨hdigit, _, hnew, hmask⟩
  have preservesMask (hm : RadixMask dir) : RadixMask updated := by
    intro i hi
    rw [hmask i hi, hnew]
    by_cases same : i = slot.val
    · subst i
      have hb : slot.val < dir.children.val.length := by
        rw [Array.length_eq]
        exact bound
      rw [List.getElem?_set_self hb]
      by_cases hz : child = 0#u32
      · simp [hz]
      · have nz : (child != 0#u32) = true := bne_iff_ne.mpr hz
        have hval : child.val ≠ 0 := fun h => hz (UScalar.eq_of_val_eq h)
        simp [nz, hval]
    · rw [ite_eq_right same, List.getElem?_set_ne (Ne.symm same)]
      exact hm i hi
  have children : ∀ link ∈ updated.children.val, RadixDirLive dirs link := by
    intro link hm
    rw [hnew] at hm
    obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp hm
    by_cases same : slot.val = i
    · subst i
      have hb : slot.val < dir.children.val.length := by
        rw [Array.length_eq]
        exact bound
      rw [List.getElem?_set_self hb, Option.some.injEq] at hi
      exact hi ▸ live
    · rw [List.getElem?_set_ne same] at hi
      exact hchildren link (List.mem_of_getElem? hi)
  have hsurv : updated.children.val[sibling]? = some survivor := by
    rw [hnew, List.getElem?_set_ne (Ne.symm other)]
    exact hs
  have nonempty := radix_first_nonzero updated ⟨survivor, List.mem_of_getElem? hsurv, hn⟩
  have firstLive := children _ (radix_first_mem updated nonempty)
  apply WP.spec_bind (core.num.U32.is_power_of_two.spec updated.mask)
  · intro collapse hcollapse
    cases collapse
    · simp only [Bool.false_eq_true, ite_false]
      apply WP.spec_mono (radix_add_directory_matches dirs free updated vacant room nonempty
        (firstLive nonempty))
      rintro ⟨nextLink, next, left⟩ ⟨pos, low, published, keep, hlen, avail⟩
      refine ⟨keep, hlen, avail, fun _ _ => published.imp fun _ h => h.1, ?_⟩
      intro original ho
      have same : original = dir := Option.some.inj (Option.some.inj (ho.symm.trans hdir))
      subst original
      exact ⟨updated, hdigit, hnew, preservesMask, Or.inl
        ⟨pos, low, published.imp fun _ h => ⟨h.1, h.2.1, h.2.2.1⟩⟩⟩
    · simp only [ite_true]
      apply WP.spec_bind (radix_first_child_matches updated)
      intro first he
      simp only [WP.spec_ok]
      refine ⟨fun _ _ h => h, by omega, vacant, he ▸ firstLive, ?_⟩
      intro original ho
      have same : original = dir := Option.some.inj (Option.some.inj (ho.symm.trans hdir))
      subst original
      exact ⟨updated, hdigit, hnew, preservesMask, Or.inr ⟨he, hcollapse.mp rfl⟩⟩

/-- Copy a prepared path without modifying any previously-live directory.
The caller supplies valid path entries; this theorem does not yet relate
the rebuilt root's bindings to a put or remove. -/
theorem radix_rebuild_preserves
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (free : alloc.vec.Vec Usize) (path : Slice (U32 × Usize)) (child : U32)
    (vacant : RadixFree dirs free)
    (room : dirs.val.length + path.val.length ≤ 2147483647)
    (safe : ∀ row ∈ path.val, SafeParent dirs row.1 row.2)
    (live : RadixDirLive dirs child)
    : WP.spec (Spike.radix.rebuild_path dirs free path child)
        (fun (root, next, left) =>
          preservesSlots dirs next
          ∧ next.val.length ≤ dirs.val.length + path.val.length
          ∧ RadixFree next left
          ∧ RadixDirLive next root) := by
  have hone : (1#usize : Usize).val = 1 := rfl
  have hzero : (0#usize : Usize).val = 0 := rfl
  unfold Spike.radix.rebuild_path Spike.radix.rebuild_path_loop
  apply loop.spec_decr_nat
    (fun (p : DirArena × alloc.vec.Vec Usize × U32 × Usize) => p.2.2.2.val)
    (fun (current, avail, found, i) =>
      i.val ≤ path.val.length
      ∧ current.val.length + i.val ≤ 2147483647
      ∧ current.val.length + i.val ≤ dirs.val.length + path.val.length
      ∧ preservesSlots dirs current
      ∧ RadixFree current avail
      ∧ RadixDirLive current found)
    _ _ _
  · rintro ⟨current, avail, found, i⟩ ⟨hi, cap, growth, keep, hf, hfound⟩
    unfold Spike.radix.rebuild_path_loop.body
    by_cases go : i > 0#usize
    · simp only [go, ite_true]
      have hpos : 0 < i.val := go
      apply WP.spec_bind (Usize.sub_spec (by omega : (1#usize : Usize).val ≤ i.val))
      intro j hj
      have hb : j.val < path.val.length := by omega
      apply WP.spec_bind (Slice.index_usize_spec path j hb)
      rintro ⟨link, slot⟩ hrow
      have hm : (link, slot) ∈ path.val := hrow ▸ List.getElem_mem hb
      have active := radix_safe_parent_preserved keep (safe (link, slot) hm)
      apply WP.spec_bind
        (radix_copy_parent_step current avail link slot found hf (by omega) active hfound)
      rintro ⟨root, next, left⟩ ⟨hkeep, hlen, hleft, hroot, _⟩
      change WP.spec (Result.ok (ControlFlow.cont (next, left, root, j))) _
      simp only [WP.spec_ok]
      exact ⟨⟨by omega, by omega, by omega, fun k dir hk => hkeep k dir (keep k dir hk),
        hleft, hroot⟩, by omega⟩
    · have hstop : ¬0 < i.val := go
      simp only [go, ite_false, WP.spec_ok]
      exact ⟨keep, by omega, hf, hfound⟩
  · exact ⟨Nat.le_refl _, room, Nat.le_refl _, fun _ _ h => h, vacant, live⟩

private theorem radix_tree_zero {dirs : List (Option Spike.radix.RadixDir)}
    {height : Nat} {link : U32} {bindings : List (List U8 × U32)}
    (tree : RadixTree dirs height link bindings) (zero : link = 0#u32)
    : bindings = [] := by
  cases tree with
  | empty => rfl
  | leaf _ node _ tagged =>
      rw [zero] at tagged
      exact (by decide : ¬(2147483648#u32 : U32) ≤ 0#u32) tagged |>.elim
  | branch _ node _ _ positive _ _ _ _ _ =>
      rw [zero] at positive
      exact (by decide : ¬0 < (0#u32 : U32).val) positive |>.elim

private theorem radix_mask_singleton (dir : Spike.radix.RadixDir)
    (mask : RadixMask dir) (singleton : dir.mask.val.isPowerOfTwo)
    {i j : Nat} {a b : U32}
    (ha : dir.children.val[i]? = some a) (hb : dir.children.val[j]? = some b)
    (na : a ≠ 0#u32) (nb : b ≠ 0#u32)
    : i = j := by
  have hlen : dir.children.val.length = 17 := Array.length_eq _
  have hindex (k : Nat) (x : U32) (h : dir.children.val[k]? = some x) : k < 32 := by
    by_contra hn
    have hl : dir.children.val.length ≤ k := by omega
    rw [List.getElem?_eq_none hl] at h
    cases h
  obtain ⟨power, hp⟩ := singleton
  have bitSet (k : Nat) (x : U32) (h : dir.children.val[k]? = some x) (nz : x ≠ 0#u32) :
      power = k := by
    have hb := mask k (hindex k x h)
    change dir.mask.val.testBit k = _ at hb
    rw [hp, Nat.testBit_two_pow] at hb
    exact of_decide_eq_true (hb.trans (decide_eq_true ⟨x, h, nz⟩))
  exact (bitSet i a ha na).symm.trans (bitSet j b hb nb)

/-- The prepared child links project to the specified partition of the new bindings. -/
def RadixPartition (dirs : List (Option Spike.radix.RadixDir)) (height : Nat)
    (digit : Usize) (links : List U32) (bindings : List (List U8 × U32))
    : Prop :=
  ∀ slot,
    slot < 17
    → ∃ child,
        links[slot]? = some child
        ∧ RadixTree dirs height child
            (bindings.filter fun row => radixSymbol row.1 digit.val == slot)

/-- Copy a parent with one child replaced, or collapse it when only one child remains.
Either result represents the same specified partition and preserves older slots. -/
theorem radix_copy_parent_matches (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (free : alloc.vec.Vec Usize) (parent : U32) (slot : Usize) (child : U32)
    (dir : Spike.radix.RadixDir) (height : Nat) (bindings : List (List U8 × U32))
    (vacant : RadixFree dirs free) (room : dirs.val.length < 2147483647)
    (safe : SafeParent dirs parent slot) (live : RadixDirLive dirs child)
    (prior : dirs.val[parent.val - 1]? = some (some dir)) (mask : RadixMask dir)
    (parts
      : RadixPartition dirs.val height dir.digit (dir.children.val.set slot.val child)
          bindings)
    : WP.spec (Spike.radix.copy_parent dirs free parent slot child)
        (fun (root, next, left) =>
          preservesSlots dirs next
          ∧ RadixFree next left
          ∧ next.val.length ≤ dirs.val.length + 1
          ∧ ∃ h, RadixTree next.val h root bindings) := by
  apply WP.spec_mono
    (radix_copy_parent_step dirs free parent slot child vacant room safe live)
  rintro ⟨root, next, left⟩ ⟨keep, hlen, hf, _, shape⟩
  obtain ⟨updated, digit, children, occupancy, result⟩ := shape dir prior
  refine ⟨keep, hf, hlen, ?_⟩
  have components : RadixPartition dirs.val height updated.digit updated.children.val bindings := by
    rwa [digit, children]
  rcases result with ⟨positive, low, published, hp, hd, hs⟩ | ⟨collapsed, singleton⟩
  · let choose := fun (i : Nat) => updated.children.val[i]?.getD 0#u32
    refine ⟨height + 1, .branch height root published bindings positive low hp choose ?_ ?_⟩
    · intro i hi
      obtain ⟨c, hget, tree⟩ := components i hi
      simp [hs, choose, hget]
    · intro i hi
      obtain ⟨c, hget, tree⟩ := components i hi
      rw [hd]
      simpa [choose, hget] using radix_tree_preserved dirs.val next.val keep tree
  · have hn : radixFirst updated ≠ 0#u32 := by
      obtain ⟨_, _, actual, hget, _, sibling, survivor, other, hs, nz⟩ := safe
      have same : actual = dir := Option.some.inj (Option.some.inj (hget.symm.trans prior))
      subst actual
      have hstill : updated.children.val[sibling]? = some survivor := by
        rwa [children, List.getElem?_set_ne (Ne.symm other)]
      exact radix_first_nonzero updated ⟨survivor, List.mem_of_getElem? hstill, nz⟩
    obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp (radix_first_mem updated hn)
    have hi' : i < 17 := by
      have hl : updated.children.val.length = 17 := Array.length_eq _
      by_contra hn'
      have hstop : updated.children.val.length ≤ i := by omega
      rw [List.getElem?_eq_none hstop] at hi
      cases hi
    obtain ⟨c, hc, tree⟩ := components i hi'
    have same : c = root := by rw [hi, Option.some.injEq, ← collapsed] at hc; exact hc.symm
    subst c
    have hfilter : bindings.filter (fun row => radixSymbol row.1 updated.digit.val == i) =
        bindings := by
      apply List.filter_eq_self.mpr
      intro row hm
      let j := radixSymbol row.1 updated.digit.val
      have hj : j < 17 := radixSymbol_bound _ _
      obtain ⟨target, ht, tree'⟩ := components j hj
      have targetNZ : target ≠ 0#u32 := by
        intro hz
        have impossible := radix_tree_zero tree' hz
        have present : row ∈ bindings.filter (fun e => radixSymbol e.1 updated.digit.val == j) :=
          List.mem_filter.mpr ⟨hm, by simp [j]⟩
        rw [impossible] at present
        exact List.not_mem_nil present
      have eq := radix_mask_singleton updated (occupancy mask) singleton ht hi targetNZ hn
      simp [j, eq]
    rw [hfilter] at tree
    exact ⟨height, radix_tree_preserved dirs.val next.val keep tree⟩

private theorem radix_tree_height {dirs : List (Option Spike.radix.RadixDir)}
    {height depth : Nat} {root : U32} {bindings : List (List U8 × U32)}
    (tree : RadixTree dirs height root bindings) (bound : height ≤ depth)
    : RadixTree dirs depth root bindings := by
  induction tree generalizing depth with
  | empty => exact .empty depth
  | leaf _ node key tagged => exact .leaf depth node key tagged
  | branch h node dir bindings positive low live child links trees ih =>
      cases depth with
      | zero => omega
      | succ depth =>
          exact .branch depth node dir bindings positive low live child links
            (fun i hi => ih i hi (by omega))

private theorem radix_tree_live {dirs : DirArena} {height : Nat} {node : U32}
    {bindings : List (List U8 × U32)} (tree : RadixTree dirs.val height node bindings)
    : RadixDirLive dirs node := by
  intro nz low
  cases tree with
  | empty => exact (nz rfl).elim
  | leaf _ _ _ tagged => exact (not_lt_of_ge tagged low).elim
  | branch _ _ dir _ _ _ live _ _ _ => exact ⟨dir, live⟩

/-- One step of a prepared path. The replacement subtree represents the desired
bindings for this slot, and every sibling already represents its desired partition. -/
def RadixPathStep (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (entry : U32 × Usize) (below above : List (List U8 × U32))
    : Prop :=
  SafeParent dirs entry.1 entry.2
  ∧ ∃ dir,
      dirs.val[entry.1.val - 1]? = some (some dir)
      ∧ RadixMask dir
      ∧ below = above.filter (fun row => radixSymbol row.1 dir.digit.val == entry.2.val)
      ∧ ∃ height,
          ∀ (i : Nat),
            i < 17
            → i ≠ entry.2.val
            → ∃ child,
                dir.children.val[i]? = some child
                ∧ RadixTree dirs.val height child
                    (above.filter fun row => radixSymbol row.1 dir.digit.val == i)

private theorem radix_path_step_preserved {old next : DirArena}
    (keep : preservesSlots old next) {entry : U32 × Usize}
    {below above : List (List U8 × U32)} (step : RadixPathStep old entry below above)
    : RadixPathStep next entry below above := by
  obtain ⟨safe, dir, live, mask, here, height, siblings⟩ := step
  refine ⟨radix_safe_parent_preserved keep safe, dir, keep _ _ live, mask, here, height, ?_⟩
  intro i hi other
  obtain ⟨child, link, tree⟩ := siblings i hi other
  exact ⟨child, link, radix_tree_preserved old.val next.val keep tree⟩

private theorem radix_rebuild_step_matches (dirs : DirArena) (free : alloc.vec.Vec Usize)
    (entry : U32 × Usize) (child : U32) (below above : List (List U8 × U32))
    (vacant : RadixFree dirs free) (room : dirs.val.length < 2147483647)
    (step : RadixPathStep dirs entry below above)
    (existing : ∃ height, RadixTree dirs.val height child below)
    : WP.spec (Spike.radix.copy_parent dirs free entry.1 entry.2 child)
        (fun (root, next, left) =>
          preservesSlots dirs next
          ∧ RadixFree next left
          ∧ next.val.length ≤ dirs.val.length + 1
          ∧ ∃ height, RadixTree next.val height root above) := by
  obtain ⟨safe, dir, live, mask, projection, hSiblings, siblings⟩ := step
  obtain ⟨hNew, tree⟩ := existing
  apply radix_copy_parent_matches dirs free entry.1 entry.2 child dir (max hNew hSiblings)
    above vacant room safe (radix_tree_live tree) live mask
  intro i hi
  by_cases chosen : i = entry.2.val
  · subst i
    have hb : entry.2.val < dir.children.val.length := by
      rw [Array.length_eq]
      exact hi
    rw [List.getElem?_set_self hb, ← projection]
    exact ⟨child, rfl, radix_tree_height tree (Nat.le_max_left _ _)⟩
  · rw [List.getElem?_set_ne (Ne.symm chosen)]
    obtain ⟨sibling, link, siblingTree⟩ := siblings i hi chosen
    exact ⟨sibling, link, radix_tree_height siblingTree (Nat.le_max_right _ _)⟩

/-- An extracted path rebuild preserves old roots and constructs the exact
specified bindings at the new root. `atDepth` supplies the desired projection
at each level of a path already chosen by the update. -/
theorem radix_rebuild_matches (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (free : alloc.vec.Vec Usize) (path : Slice (U32 × Usize)) (child : U32)
    (atDepth : Nat → List (List U8 × U32))
    (vacant : RadixFree dirs free)
    (room : dirs.val.length + path.val.length ≤ 2147483647)
    (steps
      : ∀ i (hi : i < path.val.length),
          RadixPathStep dirs path.val[i] (atDepth (i + 1)) (atDepth i))
    (tip : ∃ height, RadixTree dirs.val height child (atDepth path.val.length))
    : WP.spec (Spike.radix.rebuild_path dirs free path child)
        (fun (root, next, left) =>
          preservesSlots dirs next
          ∧ RadixFree next left
          ∧ ∃ height, RadixTree next.val height root (atDepth 0)) := by
  have hone : (1#usize : Usize).val = 1 := rfl
  have hzero : (0#usize : Usize).val = 0 := rfl
  unfold Spike.radix.rebuild_path Spike.radix.rebuild_path_loop
  apply loop.spec_decr_nat
    (fun (p : DirArena × alloc.vec.Vec Usize × U32 × Usize) => p.2.2.2.val)
    (fun (current, avail, found, i) =>
      i.val ≤ path.val.length ∧ current.val.length + i.val ≤ 2147483647
      ∧ preservesSlots dirs current ∧ RadixFree current avail
      ∧ ∃ h, RadixTree current.val h found (atDepth i.val))
    _ _ _
  · rintro ⟨current, avail, found, i⟩ ⟨hi, cap, keep, hf, hfound⟩
    unfold Spike.radix.rebuild_path_loop.body
    by_cases go : i > 0#usize
    · simp only [go, ite_true]
      have pos : 0 < i.val := go
      apply WP.spec_bind (Usize.sub_spec (by omega : (1#usize : Usize).val ≤ i.val))
      intro j hj
      have next : j.val + 1 = i.val := by omega
      have hb : j.val < path.val.length := by omega
      apply WP.spec_bind (Slice.index_usize_spec path j hb)
      rintro ⟨link, slot⟩ hrow
      have shape := steps j.val hb
      rw [← hrow, next] at shape
      apply WP.spec_bind
        (radix_rebuild_step_matches current avail (link, slot) found
          (atDepth i.val) (atDepth j.val) hf (by omega)
          (radix_path_step_preserved keep shape) hfound)
      rintro ⟨root, updated, left⟩ ⟨holds, hleft, growth, hroot⟩
      change WP.spec (Result.ok (ControlFlow.cont (updated, left, root, j))) _
      simp only [WP.spec_ok]
      exact ⟨⟨by omega, by omega, fun k dir hk => holds k dir (keep k dir hk), hleft, hroot⟩,
        by omega⟩
    · have hstop : ¬0 < i.val := go
      have hz : i.val = 0 := by omega
      simp only [go, ite_false, WP.spec_ok]
      exact ⟨keep, hf, hz ▸ hfound⟩
  · exact ⟨Nat.le_refl _, room, fun _ _ h => h, vacant, tip⟩

private theorem radix_find_leaf_loop_matches (dirs : Slice (Option Spike.radix.RadixDir))
    (key : Slice U8) (height : Nat) (node : U32) (bindings : List (List U8 × U32))
    (tree : RadixTree dirs.val height node bindings)
    : WP.spec (Spike.radix.find_leaf_loop dirs key node)
        (fun candidate =>
          (candidate = 0#u32 ∨ ∃ k, (k, candidate) ∈ bindings)
          ∧ ∀ leaf, (key.val, leaf) ∈ bindings → candidate = leaf) := by
  induction tree with
  | empty height =>
      unfold Spike.radix.find_leaf_loop loop Spike.radix.find_leaf_loop.body
      simp
  | leaf height node leafKey tagged =>
      have nz : node ≠ 0#u32 := by
        intro h
        subst node
        exact (by decide : ¬(2147483648#u32 : U32) ≤ 0#u32) tagged
      unfold Spike.radix.find_leaf_loop loop Spike.radix.find_leaf_loop.body
      have htest : (node != 0#u32) = true := bne_iff_ne.mpr nz
      simp only [htest, ite_true, radix_tag, not_lt_of_ge tagged, ite_false, bind_ok, WP.spec_ok]
      exact ⟨
        Or.inr ⟨leafKey, by simp⟩,
        fun leaf h => congrArg Prod.snd (List.mem_singleton.mp h).symm
      ⟩
  | branch height node dir bindings positive untagged live childAt links children ih =>
      have nz : node ≠ 0#u32 := fun h => by subst node; contradiction
      have test : (node != 0#u32) = true := bne_iff_ne.mpr nz
      let chosen := radixSymbol key.val dir.digit.val
      have chosenBound := radixSymbol_bound key.val dir.digit.val
      have step : WP.spec (Spike.radix.find_leaf_loop.body dirs key node)
          (fun out => out = .cont (childAt chosen)) := by
        unfold Spike.radix.find_leaf_loop.body
        simp only [test, ite_true, radix_tag, untagged]
        apply WP.spec_bind (radix_directory_matches dirs node dir positive live)
        intro actual he
        subst actual
        apply WP.spec_bind (radix_symbol_matches key dir.digit)
        intro slot hs
        have hb : slot.val < dir.children.val.length := by
          rw [Array.length_eq, hs]
          exact chosenBound
        apply WP.spec_bind (Array.index_usize_spec dir.children slot hb)
        intro child hchild
        have hget := links chosen chosenBound
        change slot.val = chosen at hs
        rw [← hs, List.getElem?_eq_getElem hb, ← hchild, Option.some.injEq] at hget
        simp only [WP.spec_ok, hs, hget]
      unfold Spike.radix.find_leaf_loop loop
      apply WP.spec_bind step
      intro out hout
      subst out
      have next := ih chosen chosenBound
      apply WP.spec_mono next
      intro candidate ⟨valid, found⟩
      constructor
      · rcases valid with h | ⟨k, hk⟩
        · exact Or.inl h
        · exact Or.inr ⟨k, (List.mem_filter.mp hk).1⟩
      · intro leaf h
        exact found leaf (List.mem_filter.mpr ⟨h, by simp [chosen]⟩)

/-- On a live finite radix tree, the extracted point lookup never visits a
missing directory. A key in the projection routes to its leaf, and any
nonempty candidate belongs to that projection. A nonmatching leaf is a miss. -/
theorem radix_find_leaf_matches (dirs : Slice (Option Spike.radix.RadixDir))
    (key : Slice U8) (height : Nat) (node : U32) (bindings : List (List U8 × U32))
    (tree : RadixTree dirs.val height node bindings)
    : WP.spec (Spike.radix.find_leaf dirs node key)
        (fun candidate =>
          (candidate = 0#u32 ∨ ∃ k, (k, candidate) ∈ bindings)
          ∧ ∀ leaf, (key.val, leaf) ∈ bindings → candidate = leaf) :=
  radix_find_leaf_loop_matches dirs key height node bindings tree

/-- Decode the leaf's one-based row index without interpreting directories as leaves. -/
def radixRow {V : Type} (rows : List (Option (Spike.radix.RadixRow V))) (leaf : U32)
    : Option (Spike.radix.RadixRow V) :=
  (rows[leaf.val - 2147483648 - 1]?).join

private theorem radix_row_at_matches {V : Type}
    (rows : Slice (Option (Spike.radix.RadixRow V))) (leaf : U32)
    (row : Spike.radix.RadixRow V) (tagged : 2147483648 < leaf.val)
    (live : radixRow rows.val leaf = some row)
    : WP.spec (Spike.radix.row_at rows leaf) (· = row) := by
  unfold Spike.radix.row_at radixRow at *
  rw [radix_tag]
  have htag : (2147483648#u32 : U32).val = 2147483648 := rfl
  apply WP.spec_bind (U32.sub_spec (by omega : (2147483648#u32 : U32).val ≤ leaf.val))
  intro taggedIndex ht
  have hone : (1#u32 : U32).val = 1 := rfl
  apply WP.spec_bind (U32.sub_spec (by omega : (1#u32 : U32).val ≤ taggedIndex.val))
  intro rawIndex hr
  simp only [lift, bind_ok]
  let index := UScalar.cast .Usize rawIndex
  have hi : index.val = leaf.val - 2147483648 - 1 := by
    rw [U32.cast_Usize_val_eq, hr.1, ht.1, htag, hone]
  have bd : index.val < rows.val.length := by
    by_contra hn
    have hl : rows.val.length ≤ leaf.val - 2147483648 - 1 := by omega
    simp [hl] at live
  apply WP.spec_bind (Slice.index_usize_spec rows index bd)
  intro got hgot
  have eq : got = some row := by
    rwa [← hi, List.getElem?_eq_getElem bd, ← hgot, Option.join_some] at live
  simp [eq]

private theorem radix_check_leaf_spec {V : Type}
    (rows : Slice (Option (Spike.radix.RadixRow V))) (leaf : U32) (key : Slice U8)
    (row : Spike.radix.RadixRow V) (tagged : 2147483648 < leaf.val)
    (live : radixRow rows.val leaf = some row)
    : WP.spec (Spike.radix.check_leaf rows leaf key)
        (fun got =>
          got = if row.key.val = key.val then some row.value else none) := by
  unfold Spike.radix.check_leaf
  apply WP.spec_bind (radix_row_at_matches rows leaf row tagged live)
  intro found eq
  subst found
  apply WP.spec_bind (core.slice.cmp.PartialEqSlice.eq_homo_spec core.cmp.PartialEqU8
    row.key key (fun a b => by simp))
  intro equal heq
  by_cases same : row.key.val = key.val <;> simp [heq, Slice.eq_iff, same]

private theorem find_binding (bindings : List (List U8 × U32)) (key : List U8)
    : match Kv.Model.find bindings key with
      | none => ∀ leaf, (key, leaf) ∉ bindings
      | some leaf => (key, leaf) ∈ bindings := by
  induction bindings with
  | nil => simp [Kv.Model.find]
  | cons p tail ih =>
      obtain ⟨k, leaf⟩ := p
      by_cases he : k = key
      · simp [Kv.Model.find, he]
      · simp only [Kv.Model.find, he, ite_false]
        cases h : Kv.Model.find tail key with
        | none =>
            rw [h] at ih
            intro other hm
            rcases List.mem_cons.mp hm with same | rest
            · exact he (congrArg Prod.fst same).symm
            · exact ih other rest
        | some hit =>
            rw [h] at ih
            exact List.mem_cons_of_mem _ ih

/-- Borrowed lookup implements association-list lookup on the projected keys
and reads the corresponding value, including misses at unrelated leaves. -/
theorem radix_get_matches {V : Type} (dirs : Slice (Option Spike.radix.RadixDir))
    (rows : Slice (Option (Spike.radix.RadixRow V))) (key : Slice U8)
    (height : Nat) (root : U32) (bindings : List (List U8 × U32))
    (tree : RadixTree dirs.val height root bindings)
    (valid
      : ∀ entry ∈ bindings,
          2147483648 < entry.2.val
          ∧ ∃ row, radixRow rows.val entry.2 = some row ∧ row.key.val = entry.1)
    : WP.spec (Spike.radix.get dirs rows root key)
        (fun got =>
          got
          = (Kv.Model.find bindings key.val).bind
              fun leaf =>
                (radixRow rows.val leaf).map Spike.radix.RadixRow.value) := by
  unfold Spike.radix.get
  apply WP.spec_bind (radix_find_leaf_matches dirs key height root bindings tree)
  intro leaf ⟨belongs, lookup⟩
  have hb := find_binding bindings key.val
  cases hf : Kv.Model.find bindings key.val with
  | none =>
      simp only [hf] at hb
      by_cases zero : leaf = 0#u32
      · simp [zero]
      · obtain ⟨k, hk⟩ := belongs.resolve_left zero
        obtain ⟨tagged, row, live, hkrow⟩ := valid (k, leaf) hk
        have diff : row.key.val ≠ key.val := by
          intro he
          exact hb leaf (by rwa [← he, hkrow])
        simp only [zero, ite_false, Option.bind_none]
        simpa only [diff, ite_false] using radix_check_leaf_spec rows leaf key row tagged live
  | some wanted =>
      simp only [hf] at hb
      have equal := lookup wanted hb
      subst leaf
      obtain ⟨tagged, row, live, hk⟩ := valid (key.val, wanted) hb
      have zero : wanted ≠ 0#u32 := by
        intro hz
        subst wanted
        exact (by decide : ¬2147483648 < (0#u32 : U32).val) tagged
      simp only [zero, ite_false, Option.bind_some, live, Option.map_some]
      simpa only [hk, ite_true]
        using radix_check_leaf_spec rows wanted key row tagged live

private abbrev Bindings := List (List U8 × U32)
private abbrev Path := List (U32 × Usize)

/-- The route records the exact parent slots followed for a key, with the
projection at each visited root. -/
inductive RadixWalk (dirs : List (Option Spike.radix.RadixDir)) (key : List U8)
    (cutoff : Option Usize)
    : U32 → List (List U8 × U32) → U32 → List (List U8 × U32) → List (U32 × Usize)
      → Prop where
  | empty : RadixWalk dirs key cutoff 0#u32 [] 0#u32 [] []
  | leaf (node : U32) (stored : List U8) (tagged : (2147483648#u32 : U32) ≤ node)
    : RadixWalk dirs key cutoff node [(stored, node)] node [(stored, node)] []
  | stop (height : Nat) (node : U32) (dir : Spike.radix.RadixDir)
    (bindings : List (List U8 × U32)) (limit : Usize)
    (isCut : cutoff = some limit) (after : limit ≤ dir.digit)
    (positive : 0 < node.val) (untagged : node < 2147483648#u32)
    (live : dirs[node.val - 1]? = some (some dir))
    (tree : RadixTree dirs height node bindings)
    : RadixWalk dirs key cutoff node bindings node bindings []
  | branch (node : U32) (dir : Spike.radix.RadixDir) (bindings : List (List U8 × U32))
    (slot : Usize) (child leaf : U32) (tail : List (U32 × Usize))
    (tip : List (List U8 × U32)) (height : Nat)
    (positive : 0 < node.val)
    (untagged : node < 2147483648#u32)
    (live : dirs[node.val - 1]? = some (some dir))
    (before : ∀ limit, cutoff = some limit → dir.digit < limit)
    (which : slot.val = radixSymbol key dir.digit.val)
    (chosen : dir.children.val[slot.val]? = some child)
    (partition : RadixPartition dirs height dir.digit dir.children.val bindings)
    (walk
      : RadixWalk dirs key cutoff child
          (bindings.filter (fun row => radixSymbol row.1 dir.digit.val == slot.val)) leaf
          tip tail)
    : RadixWalk dirs key cutoff node bindings leaf tip ((node, slot) :: tail)

private theorem radix_record_walk (dirs : Slice (Option Spike.radix.RadixDir))
    (key : Slice U8) (height : Nat) (root : U32) (bindings : Bindings)
    (tree : RadixTree dirs.val height root bindings)
    (cutoff : Option Usize)
    (initial : alloc.vec.Vec (U32 × Usize))
    (room : initial.val.length + height ≤ Usize.max)
    : WP.spec (Spike.radix.record_path_loop dirs initial key cutoff root)
        (fun (leaf, path) =>
          ∃ (suffix : Path) (tip : Bindings),
            path.val = initial.val ++ suffix
            ∧ suffix.length ≤ height
            ∧ RadixWalk dirs.val key.val cutoff root bindings leaf tip suffix) := by
  induction tree generalizing initial with
  | empty height =>
      unfold Spike.radix.record_path_loop loop Spike.radix.record_path_loop.body
      simp only [bne_self_eq_false, Bool.false_eq_true, ite_false, bind_ok, WP.spec_ok]
      exact ⟨[], [], by simp, by simp, .empty⟩
  | leaf height node stored tagged =>
      have nz : node ≠ 0#u32 := by
        intro h
        subst node
        exact (by decide : ¬(2147483648#u32 : U32) ≤ 0#u32) tagged
      unfold Spike.radix.record_path_loop loop Spike.radix.record_path_loop.body
      simp only [bne_iff_ne.mpr nz, ite_true, radix_tag, not_lt_of_ge tagged, ite_false, bind_ok,
        WP.spec_ok]
      exact ⟨[], [(stored, node)], by simp, by simp, .leaf node stored tagged⟩
  | branch h node dir bindings positive small live choose links trees ih =>
      have nz : node ≠ 0#u32 := fun h => by subst node; contradiction
      have cap : initial.val.length < Usize.max := by omega
      have tree : RadixTree dirs.val (h + 1) node bindings :=
        .branch h node dir bindings positive small live choose links trees
      by_cases stop : ∃ limit, cutoff = some limit ∧ limit ≤ dir.digit
      · obtain ⟨limit, eq, atLimit⟩ := stop
        subst cutoff
        unfold Spike.radix.record_path_loop loop
        apply WP.spec_bind
          (Pₘ := fun out => out = ControlFlow.done (α := _ × _ × U32) (node, initial))
        · unfold Spike.radix.record_path_loop.body
          simp only [bne_iff_ne.mpr nz, ite_true, radix_tag, small]
          apply WP.spec_bind (radix_directory_matches dirs node dir positive live)
          intro actual he
          subst actual
          simp [atLimit]
        · intro out he
          subst out
          simp only [WP.spec_ok]
          exact ⟨[], bindings, by simp, by simp,
            .stop (h + 1) node dir bindings limit rfl atLimit positive small live tree⟩
      have before : ∀ limit, cutoff = some limit → dir.digit < limit :=
        fun limit eq => lt_of_not_ge (fun hr => stop ⟨limit, eq, hr⟩)
      have step : WP.spec (Spike.radix.record_path_loop.body dirs key initial cutoff node)
          (fun out =>
            ∃ slot path,
              slot.val = radixSymbol key.val dir.digit.val ∧ slot.val < 17
              ∧ path.val = initial.val ++ [(node, slot)]
              ∧ out = .cont (path, cutoff, choose slot.val)) := by
        unfold Spike.radix.record_path_loop.body
        simp only [bne_iff_ne.mpr nz, ite_true, radix_tag, small]
        apply WP.spec_bind (radix_directory_matches dirs node dir positive live)
        intro actual hdir
        subst actual
        cases eq : cutoff
        all_goals first
          | apply WP.spec_bind (radix_symbol_matches key dir.digit)
          | rename_i limit
            have notLimit := not_le_of_gt (before limit eq)
            simp only [notLimit, ite_false]
            apply WP.spec_bind (radix_symbol_matches key dir.digit)
        all_goals
          intro slot which
          have bound : slot.val < 17 := which ▸ radixSymbol_bound _ _
          have hb : slot.val < dir.children.val.length := by
            rw [Array.length_eq]
            exact bound
          apply WP.spec_bind (alloc.vec.Vec.push_spec initial (node, slot) cap)
          intro next hnext
          apply WP.spec_bind (Array.index_usize_spec dir.children slot hb)
          intro child hc
          have hlink := links slot.val bound
          rw [List.getElem?_eq_getElem hb, ← hc, Option.some.injEq] at hlink
          simp only [WP.spec_ok]
          exact ⟨slot, next, which, bound, hnext, by rw [hlink]⟩
      unfold Spike.radix.record_path_loop loop
      apply WP.spec_bind step
      rintro out ⟨slot, path, which, bound, hp, he⟩
      subst out
      have hroom : path.val.length + h ≤ Usize.max := by
        rw [hp, List.length_append, List.length_singleton]
        omega
      apply WP.spec_mono (ih slot.val bound path hroom)
      rintro ⟨leaf, full⟩ ⟨suffix, tip, hfull, hheight, route⟩
      refine ⟨(node, slot) :: suffix, tip, ?_, by simp; omega, ?_⟩
      · rw [hfull, hp, List.append_assoc, List.singleton_append]
      · exact .branch node dir bindings slot (choose slot.val) leaf suffix tip h positive small
          live before which (links _ bound) (fun j hj => ⟨choose j, links j hj, trees j hj⟩)
          route

private theorem radix_record_matches (dirs : Slice (Option Spike.radix.RadixDir))
    (initial : alloc.vec.Vec (U32 × Usize)) (root : U32) (key : Slice U8)
    (cutoff : Option Usize)
    (height : Nat) (bindings : Bindings) (room : height ≤ Usize.max)
    (tree : RadixTree dirs.val height root bindings)
    : WP.spec (Spike.radix.record_path dirs initial root key cutoff)
        (fun (leaf, path) =>
          ∃ tip,
            path.val.length ≤ height
            ∧ RadixWalk dirs.val key.val cutoff root bindings leaf tip path.val) := by
  unfold Spike.radix.record_path
  apply WP.spec_bind
    (alloc.vec.Vec.resize_spec (BuiltinClone (U32 × Usize)) initial 0#usize
      (0#u32, 0#usize) rfl)
  intro empty he
  have hempty : empty.val = [] := by simpa [List.resize] using he
  apply WP.spec_mono
    (radix_record_walk dirs key height root bindings tree cutoff empty
      (by simp [hempty, room]))
  rintro ⟨leaf, path⟩ ⟨suffix, tip, hpath, hn, hw⟩
  simp only [hempty, List.nil_append] at hpath
  exact ⟨tip, hpath ▸ hn, hpath ▸ hw⟩

/-- A published directory has consistent occupancy and a sibling for any
child being removed. -/
def RadixDirectoryInvariant (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) : Prop :=
  ∀ (node : U32) (dir : Spike.radix.RadixDir),
    0 < node.val
    → dirs.val[node.val - 1]? = some (some dir)
    → RadixMask dir ∧ ∀ (slot : Usize), slot.val < 17 → SafeParent dirs node slot

private theorem radix_walk_tip {dirs : List (Option Spike.radix.RadixDir)} {key : List U8}
    {root leaf : U32} {bindings tip : Bindings} {path : Path}
    (walk : RadixWalk dirs key none root bindings leaf tip path)
    : (leaf = 0#u32 ∧ tip = []) ∨ ∃ stored, tip = [(stored, leaf)] ∧ leaf ≠ 0#u32 := by
  induction walk with
  | empty => exact Or.inl ⟨rfl, rfl⟩
  | leaf node stored tagged =>
      refine Or.inr ⟨stored, rfl, ?_⟩
      intro hz
      subst node
      exact (by decide : ¬(2147483648#u32 : U32) ≤ 0#u32) tagged
  | stop _ _ _ _ _ isCut => cases isCut
  | branch _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ ih => exact ih

private theorem radix_walk_membership {dirs : List (Option Spike.radix.RadixDir)}
    {key : List U8} {cutoff : Option Usize} {root leaf : U32}
    {bindings tip : Bindings} {path : Path}
    (walk : RadixWalk dirs key cutoff root bindings leaf tip path)
    : (∀ row ∈ tip, row ∈ bindings)
      ∧ (∀ link, (key, link) ∈ bindings → (key, link) ∈ tip) := by
  induction walk with
  | empty => simp
  | leaf _ _ _ => exact ⟨fun _ h => h, fun _ h => h⟩
  | stop => exact ⟨fun _ h => h, fun _ h => h⟩
  | branch node dir bindings slot child leaf tail tip height positive _ live _ which chosen part _ ih
    =>
      exact ⟨
        fun row h => (List.mem_filter.mp (ih.1 row h)).1,
        fun link h => ih.2 link (List.mem_filter.mpr ⟨h, by simp [which]⟩)
      ⟩

private theorem erase_partition (bindings : Bindings) (key : List U8) (digit : Usize)
    (slot : Nat)
    : (Kv.Model.erase bindings key).filter
        (fun row => radixSymbol row.1 digit.val == slot)
      = if slot = radixSymbol key digit.val then
          Kv.Model.erase
            (bindings.filter (fun row => radixSymbol row.1 digit.val == slot)) key
        else
          bindings.filter (fun row => radixSymbol row.1 digit.val == slot) := by
  by_cases chosen : slot = radixSymbol key digit.val
  · simp only [chosen, ite_true, Kv.Model.erase, List.filter_filter]
    congr 1
    funext row
    rw [Bool.and_comm]
  · simp only [chosen, ite_false, Kv.Model.erase, List.filter_filter]
    apply List.filter_congr
    intro row _
    by_cases eq : row.1 = key
    · simp [eq, Ne.symm chosen]
    · simp [eq]

private def radixEdit (bindings : Bindings) (key : List U8) (replacement : Option U32)
    : Bindings :=
  match replacement with
  | none => Kv.Model.erase bindings key
  | some leaf => Kv.Model.set bindings key leaf

private theorem edit_partition (bindings : Bindings) (key : List U8)
    (replacement : Option U32) (digit : Usize) (slot : Nat)
    : (radixEdit bindings key replacement).filter
        (fun row => radixSymbol row.1 digit.val == slot)
      = if slot = radixSymbol key digit.val then
          radixEdit (bindings.filter (fun row => radixSymbol row.1 digit.val == slot)) key
            replacement
        else
          bindings.filter (fun row => radixSymbol row.1 digit.val == slot) := by
  cases replacement with
  | none => exact erase_partition bindings key digit slot
  | some leaf =>
      simp only [radixEdit, Kv.Model.set, List.filter_cons, erase_partition]
      by_cases chosen : slot = radixSymbol key digit.val
      · simp [chosen]
      · simp [chosen, Ne.symm chosen]

private theorem radix_walk_edit_plan (dirs : DirArena) (key : List U8)
    (replacement : Option U32) {cutoff : Option Usize} {root leaf : U32}
    {bindings tip : Bindings} {path : Path}
    (walk : RadixWalk dirs.val key cutoff root bindings leaf tip path)
    (invariant : RadixDirectoryInvariant dirs)
    : ∃ target : Nat → Bindings,
        target 0 = radixEdit bindings key replacement
        ∧ target path.length = radixEdit tip key replacement
        ∧ ∀ i (hi : i < path.length),
            RadixPathStep dirs path[i] (target (i + 1)) (target i) := by
  induction walk with
  | empty => exact ⟨fun _ => radixEdit [] key replacement, rfl, rfl, by simp⟩
  | leaf node stored _ =>
      exact ⟨fun _ => radixEdit [(stored, node)] key replacement, rfl, rfl, by simp⟩
  | stop _ _ _ bindings =>
      exact ⟨fun _ => radixEdit bindings key replacement, rfl, rfl, by simp⟩
  | branch node dir bindings slot child leaf tail tip height positive _ live _ which chosen partition walk ih
    =>
      obtain ⟨after, hhead, htip, hsteps⟩ := ih
      let target : Nat → Bindings
        | 0 => radixEdit bindings key replacement
        | i + 1 => after i
      refine ⟨target, rfl, htip, ?_⟩
      intro i hi
      cases i with
      | succ i =>
          have hbound : i < tail.length := by simpa [List.length_cons] using hi
          exact hsteps i hbound
      | zero =>
          have hb : slot.val < 17 := which ▸ radixSymbol_bound _ _
          have rule := invariant node dir positive live
          refine ⟨rule.2 slot hb, dir, live, rule.1, ?_, height, ?_⟩
          · change after 0 = ((radixEdit bindings key replacement).filter
              (fun row => radixSymbol row.1 dir.digit.val == slot.val))
            rw [hhead, edit_partition, ite_eq_left which]
          · intro j hj neq
            change ∃ child, dir.children.val[j]? = some child ∧
              RadixTree dirs.val height child ((radixEdit bindings key replacement).filter
                (fun row => radixSymbol row.1 dir.digit.val == j))
            rw [edit_partition, ite_eq_right (which ▸ neq)]
            exact partition j hj

private theorem erase_absent (bindings : Bindings) (key : List U8)
    (absent : ∀ link, (key, link) ∉ bindings)
    : Kv.Model.erase bindings key = bindings := by
  apply List.filter_eq_self.mpr
  intro ⟨stored, link⟩ hm
  have he : stored ≠ key := fun eq => absent link (eq ▸ hm)
  simp [he]

/-- The extracted deletion implements model erasure and leaves earlier roots
intact, when starting from the stated valid tree, rows, and free list. -/
theorem radix_remove_matches {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) (free : alloc.vec.Vec Usize)
    (rows : Slice (Option (Spike.radix.RadixRow V)))
    (scratch : alloc.vec.Vec (U32 × Usize)) (root : U32) (key : Slice U8) (height : Nat)
    (bindings : List (List U8 × U32)) (tree : RadixTree dirs.val height root bindings)
    (valid
      : ∀ entry ∈ bindings,
          2147483648 < entry.2.val
          ∧ ∃ row, radixRow rows.val entry.2 = some row ∧ row.key.val = entry.1)
    (vacant : RadixFree dirs free) (invariant : RadixDirectoryInvariant dirs)
    (room : dirs.val.length + height ≤ 2147483647)
    : WP.spec (Spike.radix.remove dirs free rows scratch root key)
        (fun (next, arena, avail, _) =>
          preservesSlots dirs arena
          ∧ RadixFree arena avail
          ∧ ∃ h, RadixTree arena.val h next (Kv.Model.erase bindings key.val)) := by
  unfold Spike.radix.remove
  have hmax : 2147483647 ≤ Usize.max := by scalar_tac
  apply WP.spec_bind
    (radix_record_matches (alloc.vec.Vec.deref dirs) scratch root key none height bindings
      (by omega) (by simpa [alloc.vec.Vec.deref] using tree))
  rintro ⟨leaf, path⟩ ⟨tip, depth, trace⟩
  change WP.spec
    (if leaf = 0#u32 then Result.ok (root, dirs, free, path)
    else do
      let v ← Spike.radix.check_leaf rows leaf key
      if core.option.Option.is_none v then Result.ok (root, dirs, free, path)
      else
        let (new, arena, avail) ← Spike.radix.rebuild_path dirs free (alloc.vec.Vec.deref path) 0#u32
        Result.ok (new, arena, avail, path)) _
  have walk : RadixWalk dirs.val key.val none root bindings leaf tip path.val := by
    simpa [alloc.vec.Vec.deref] using trace
  have mem := radix_walk_membership walk
  have reflexive : preservesSlots dirs dirs := fun _ _ h => h
  rcases radix_walk_tip walk with ⟨zero, ht⟩ | ⟨stored, ht, nz⟩
  · have he := erase_absent bindings key.val (fun link h => by
      have impossible := mem.2 link h
      rw [ht] at impossible
      exact List.not_mem_nil impossible)
    simp only [zero, ite_true, WP.spec_ok, he]
    exact ⟨reflexive, vacant, height, tree⟩
  · simp only [nz, ite_false]
    have present : (stored, leaf) ∈ tip := by simp [ht]
    obtain ⟨tagged, row, hrow, hk⟩ := valid (stored, leaf) (mem.1 _ present)
    apply WP.spec_bind (radix_check_leaf_spec rows leaf key row tagged hrow)
    intro output hout
    by_cases same : stored = key.val
    · have eq : output = some row.value := by simpa [hk, same] using hout
      simp only [eq, core.option.Option.is_none, Option.isNone_some, Bool.false_eq_true, ite_false]
      obtain ⟨target, head, tail, steps⟩ := radix_walk_edit_plan dirs key.val none walk invariant
      have tipEmpty : target path.val.length = [] := by
        simp [tail, ht, radixEdit, Kv.Model.erase, same]
      let input := alloc.vec.Vec.deref path
      have lengthEq : input.val.length = path.val.length := by simp [input, alloc.vec.Vec.deref]
      apply WP.spec_bind
        (radix_rebuild_matches dirs free input 0#u32 target vacant (by omega)
          (fun i hi => by
            have hb : i < path.val.length := by omega
            simpa [input, alloc.vec.Vec.deref] using steps i hb)
          (by rw [lengthEq, tipEmpty]; exact ⟨0, .empty 0⟩))
      rintro ⟨new, arena, avail⟩ ⟨keep, hf, hd⟩
      change WP.spec (Result.ok (new, arena, avail, path)) _
      simp only [WP.spec_ok]
      change preservesSlots dirs arena ∧ RadixFree arena avail ∧
        (∃ h, RadixTree arena.val h new (radixEdit bindings key.val none))
      rw [← head]
      exact ⟨keep, hf, hd⟩
    · have eq : output = none := by simpa [hk, same] using hout
      have he := erase_absent bindings key.val (fun link h => by
        have here := mem.2 link h
        rw [ht] at here
        exact same (congrArg Prod.fst (List.mem_singleton.mp here)).symm)
      simp only [eq, core.option.Option.is_none, Option.isNone_none, ite_true, WP.spec_ok, he]
      exact ⟨reflexive, vacant, height, tree⟩

/-- A cached representative is a leaf of the given directory's projection. -/
def RadixRepresentatives (dirs : List (Option Spike.radix.RadixDir)) : Prop :=
  ∀ height node bindings dir,
    RadixTree dirs height node bindings
    → 0 < node.val
    → node < 2147483648#u32
    → dirs[node.val - 1]? = some (some dir)
    → ∃ key, (key, dir.first) ∈ bindings

private inductive RepRoute (dirs : List (Option Spike.radix.RadixDir)) (key : List U8)
    : U32 → Bindings → (List U8 × U32) → Prop where
  | leaf (node : U32) (stored : List U8) (tagged : (2147483648#u32 : U32) ≤ node)
    : RepRoute dirs key node [(stored, node)] (stored, node)
  | missing (node : U32) (dir : Spike.radix.RadixDir) (bindings : Bindings)
    (row : List U8 × U32) (live : dirs[node.val - 1]? = some (some dir))
    (absent : dir.children.val[radixSymbol key dir.digit.val]? = some 0#u32)
    (member : row ∈ bindings)
    : RepRoute dirs key node bindings row
  | descend (node : U32) (dir : Spike.radix.RadixDir) (bindings : Bindings)
    (row : List U8 × U32) (child : U32) (live : dirs[node.val - 1]? = some (some dir))
    (chosen : dir.children.val[radixSymbol key dir.digit.val]? = some child)
    (route
      : RepRoute dirs key child
          (bindings.filter
            fun entry =>
              radixSymbol entry.1 dir.digit.val == radixSymbol key dir.digit.val)
          row)
    : RepRoute dirs key node bindings row

private theorem rep_member {dirs : List (Option Spike.radix.RadixDir)} {key : List U8}
    {node : U32} {bindings : Bindings} {row : List U8 × U32}
    (rep : RepRoute dirs key node bindings row)
    : row ∈ bindings := by
  induction rep with
  | leaf => exact List.mem_cons_self
  | missing _ _ _ _ _ _ member => exact member
  | descend _ _ _ _ _ _ _ _ ih => exact (List.mem_filter.mp ih).1

private theorem radix_representative_matches (dirs : Slice (Option Spike.radix.RadixDir))
    (key : Slice U8) (height : Nat) (root : U32) (bindings : Bindings)
    (tree : RadixTree dirs.val height root bindings)
    (valid : RadixRepresentatives dirs.val) (nonempty : root ≠ 0#u32)
    : WP.spec (Spike.radix.representative dirs root key)
        (fun leaf =>
          (∃ stored, RepRoute dirs.val key.val root bindings (stored, leaf))
          ∧ ∀ expected, (key.val, expected) ∈ bindings → leaf = expected) := by
  unfold Spike.radix.representative
  induction tree with
  | empty _ => exact (nonempty rfl).elim
  | leaf _ node stored tagged =>
      unfold Spike.radix.representative_loop loop Spike.radix.representative_loop.body
      simp only [radix_tag, not_lt_of_ge tagged, ite_false, bind_ok, WP.spec_ok]
      exact ⟨⟨stored, .leaf node stored tagged⟩, fun expected hm =>
        congrArg Prod.snd (List.mem_singleton.mp hm).symm⟩
  | branch h node dir bindings pos low existsDir child links subtrees ih =>
      let slot := radixSymbol key.val dir.digit.val
      have bound : slot < 17 := radixSymbol_bound _ _
      have step
          : WP.spec (Spike.radix.representative_loop.body dirs key node)
              (fun out =>
                out
                = if child slot = 0#u32 then
                    ControlFlow.done dir.first
                  else
                    .cont (child slot)) := by
        unfold Spike.radix.representative_loop.body
        simp only [radix_tag, low, ite_true]
        apply WP.spec_bind (radix_directory_matches dirs node dir pos existsDir)
        intro actual he
        subst actual
        apply WP.spec_bind (radix_symbol_matches key dir.digit)
        intro i hi
        change i.val = slot at hi
        have hb : i.val < dir.children.val.length := by
          rw [Array.length_eq, hi]; exact bound
        apply WP.spec_bind (Array.index_usize_spec dir.children i hb)
        intro picked hp
        have hs := links slot bound
        rw [← hi, List.getElem?_eq_getElem hb, ← hp, Option.some.injEq] at hs
        rw [hs, hi]
        by_cases empty : child slot = 0#u32 <;> simp [empty]
      unfold Spike.radix.representative_loop loop
      apply WP.spec_bind step
      intro out hout
      subst out
      by_cases zero : child slot = 0#u32
      · simp only [zero, ite_true, WP.spec_ok]
        have rep := valid (h + 1) node bindings dir
          (.branch h node dir bindings pos low existsDir child links subtrees) pos low existsDir
        obtain ⟨stored, hr⟩ := rep
        have absent : dir.children.val[slot]? = some 0#u32 := zero ▸ links slot bound
        refine ⟨⟨stored, .missing node dir bindings (stored, dir.first) existsDir absent hr⟩, ?_⟩
        intro expected present
        have selected : (key.val, expected) ∈
            bindings.filter (fun row => radixSymbol row.1 dir.digit.val == slot) :=
          List.mem_filter.mpr ⟨present, by simp [slot]⟩
        rw [radix_tree_zero (subtrees slot bound) zero] at selected
        exact (List.not_mem_nil selected).elim
      · simp only [zero, ite_false]
        apply WP.spec_mono (ih slot bound zero)
        intro leaf ⟨⟨stored, belongs⟩, eq⟩
        exact ⟨⟨stored, .descend node dir bindings (stored, leaf) (child slot) existsDir
            (links slot bound) belongs⟩,
          fun expected present => eq expected (List.mem_filter.mpr ⟨present, by simp [slot]⟩)⟩

private theorem representative_at_cut {dirs : List (Option Spike.radix.RadixDir)}
    {key : List U8} {limit : Usize}
    {root stem : U32} {bindings tip : Bindings} {path : Path}
    (walk : RadixWalk dirs key (some limit) root bindings stem tip path)
    (stored : List U8) (leaf : U32)
    (rep : RepRoute dirs key root bindings (stored, leaf))
    (shared : ∀ i, i < limit.val → radixSymbol stored i = radixSymbol key i)
    : RepRoute dirs key stem tip (stored, leaf) := by
  induction walk with
  | empty => exact rep
  | leaf => exact rep
  | stop => exact rep
  | branch node dir bindings slot child stem tail tip height pos low live before which chosen part _ ih
    =>
      have bound : slot.val < 17 := which ▸ radixSymbol_bound _ _
      have hroute : (stored, leaf) ∈ bindings.filter
          (fun row => radixSymbol row.1 dir.digit.val == slot.val) := by
        refine List.mem_filter.mpr ⟨rep_member rep, ?_⟩
        have hd : dir.digit.val < limit.val := before limit rfl
        simp [which, shared _ hd]
      have occupied : child ≠ 0#u32 := by
        intro zero
        obtain ⟨actual, ha, tree⟩ := part slot.val bound
        have he := Option.some.inj (ha.symm.trans chosen)
        subst actual
        rw [radix_tree_zero tree zero] at hroute
        exact List.not_mem_nil hroute
      cases rep with
      | leaf _ _ tagged => exact (not_lt_of_ge tagged low).elim
      | missing _ current _ _ currentLive vacant _ =>
          have same := Option.some.inj (Option.some.inj (currentLive.symm.trans live))
          subst current
          rw [← which, chosen, Option.some.injEq] at vacant
          exact (occupied vacant).elim
      | descend _ current _ _ next currentLive hslot recurse =>
          have same := Option.some.inj (Option.some.inj (currentLive.symm.trans live))
          subst current
          rw [← which, chosen, Option.some.injEq] at hslot
          subst next
          apply ih
          simpa only [which] using recurse

/-- Before a directory's split digit, the keys stored under it share their
routing digits. The projection must name actual row keys. -/
def RadixCompressed (dirs : List (Option Spike.radix.RadixDir))
    (leafKey : U32 → Option (List U8))
    : Prop :=
  ∀ height node bindings dir,
    RadixTree dirs height node bindings
    → 0 < node.val
    → node < 2147483648#u32
    → dirs[node.val - 1]? = some (some dir)
    → (∀ row ∈ bindings, leafKey row.2 = some row.1)
    → ∀ a ∈ bindings,
      ∀ b ∈ bindings, ∀ i, i < dir.digit.val → radixSymbol a.1 i = radixSymbol b.1 i

private inductive InsertStem (dirs : List (Option Spike.radix.RadixDir))
    (key : List U8) (limit : Usize) (oldSlot : Nat)
    : U32 → Bindings → Prop where
  | extend (height : Nat) (node : U32) (bindings : Bindings) (dir : Spike.radix.RadixDir)
    (pos : 0 < node.val) (low : node < 2147483648#u32)
    (lookup : dirs[node.val - 1]? = some (some dir))
    (atLimit : dir.digit = limit)
    (missing : dir.children.val[radixSymbol key limit.val]? = some 0#u32)
    (partition : RadixPartition dirs height dir.digit dir.children.val bindings)
    : InsertStem dirs key limit oldSlot node bindings
  | wrap (height : Nat) (node : U32) (bindings : Bindings)
    (tree : RadixTree dirs height node bindings) (nonzero : node ≠ 0#u32)
    (later
      : node < 2147483648#u32
        → ∃ dir, dirs[node.val - 1]? = some (some dir) ∧ limit < dir.digit)
    (common : ∀ row ∈ bindings, radixSymbol row.1 limit.val = oldSlot)
    : InsertStem dirs key limit oldSlot node bindings

private theorem classifies_stem {dirs : List (Option Spike.radix.RadixDir)}
    {key : List U8} {limit : Usize} {leafKey : U32 → Option (List U8)}
    {root stem : U32} {bindings tip : Bindings} {path : Path}
    (walk : RadixWalk dirs key (some limit) root bindings stem tip path)
    (stored : List U8) (leaf : U32)
    (rep : RepRoute dirs key stem tip (stored, leaf))
    (diff : radixSymbol stored limit.val ≠ radixSymbol key limit.val)
    (compressed : RadixCompressed dirs leafKey)
    (keys : ∀ row ∈ bindings, leafKey row.2 = some row.1)
    : InsertStem dirs key limit (radixSymbol stored limit.val) stem tip := by
  induction walk with
  | empty => exact (List.not_mem_nil (rep_member rep)).elim
  | leaf node k tagged =>
      refine .wrap 0 node [(k, node)] (.leaf 0 node k tagged) ?_
        (fun low => (not_lt_of_ge tagged low).elim) ?_
      · intro zero
        subst node
        exact (by decide : ¬(2147483648#u32 : U32) ≤ 0#u32) tagged
      · have hk := congrArg Prod.fst (List.mem_singleton.mp (rep_member rep))
        intro row hm
        rw [List.mem_singleton.mp hm, ← hk]
  | stop height node dir bindings bound which after yes low live tree =>
      have sameLimit : bound = limit := Option.some.inj which.symm
      subst bound
      by_cases equal : dir.digit = limit
      · cases tree with
        | empty => cases (by decide : ¬0 < (0#u32 : U32).val) yes
        | leaf _ _ _ tagged => exact (not_lt_of_ge tagged low).elim
        | branch h _ actual _ positive small directory choose links subtrees =>
            have he := Option.some.inj (Option.some.inj (directory.symm.trans live))
            subst actual
            have missing : dir.children.val[radixSymbol key limit.val]? = some 0#u32 := by
              cases rep with
              | leaf _ _ tagged => exact (not_lt_of_ge tagged low).elim
              | missing _ current _ _ active vacant hm =>
                  have he := Option.some.inj (Option.some.inj (active.symm.trans live))
                  subst current
                  simpa only [equal] using vacant
              | descend _ current _ _ next active slot branch =>
                  have he := Option.some.inj (Option.some.inj (active.symm.trans live))
                  subst current
                  have member := (List.mem_filter.mp (rep_member branch)).2
                  exact (diff (by simpa [equal] using member)).elim
            exact .extend h node bindings dir yes low live equal missing
              (fun i hi => ⟨choose i, links i hi, subtrees i hi⟩)
      · have earlier : limit < dir.digit := lt_of_le_of_ne after (Ne.symm equal)
        have nz : node ≠ 0#u32 := fun zero => by subst node; contradiction
        exact .wrap height node bindings tree nz (fun _ => ⟨dir, live, earlier⟩)
          (fun row hm => compressed height node bindings dir tree yes low live keys row hm
            (stored, leaf) (rep_member rep) _ earlier)
  | branch _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ ih =>
      exact ih rep (fun row hm => keys row (List.mem_filter.mp hm).1)

private theorem radix_prepare_fresh {V : Type}
    (dirs : Slice (Option Spike.radix.RadixDir))
    (rows : Slice (Option (Spike.radix.RadixRow V))) (path : alloc.vec.Vec (U32 × Usize))
    (root : U32) (key : Slice U8) (height : Nat) (bindings : Bindings)
    (tree : RadixTree dirs.val height root bindings)
    (reps : RadixRepresentatives dirs.val)
    (compressed
      : RadixCompressed dirs.val
          (fun leaf =>
            (radixRow rows.val leaf).map (fun row => row.key.val)))
    (absent : ∀ leaf, (key.val, leaf) ∉ bindings) (nz : root ≠ 0#u32)
    (valid
      : ∀ entry ∈ bindings,
          2147483648 < entry.2.val
          ∧ ∃ row, radixRow rows.val entry.2 = some row ∧ row.key.val = entry.1)
    (room : height ≤ Usize.max) (keyRoom : 2 * key.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.prepare_insert dirs rows path root key)
        (fun ((stem, result), recorded) =>
          ∃ (split : Spike.radix.InsertionSplit) (tip : Bindings),
            result = some split
            ∧ recorded.val.length ≤ height
            ∧ split.new_slot.val = radixSymbol key.val split.digit.val
            ∧ split.old_slot.val < 17
            ∧ split.old_slot.val ≠ split.new_slot.val
            ∧ RadixWalk dirs.val key.val (some split.digit) root bindings stem tip
                recorded.val
            ∧ InsertStem dirs.val key.val split.digit split.old_slot.val stem tip) := by
  unfold Spike.radix.prepare_insert
  apply WP.spec_bind
    (radix_representative_matches dirs key height root bindings tree reps nz)
  intro leaf ⟨⟨stored, rep⟩, _⟩
  have member := rep_member rep
  obtain ⟨tagged, row, live, same⟩ := valid (stored, leaf) member
  apply WP.spec_bind (radix_row_at_matches rows leaf row tagged live)
  intro old hrow
  subst old
  have fit : 2 * min row.key.val.length key.val.length + 1 ≤ Usize.max := by
    have := Nat.min_le_right row.key.val.length key.val.length
    omega
  apply WP.spec_bind (radix_first_difference_matches row.key key fit)
  intro found hsplit
  cases found with
  | none =>
      change row.key.val = key.val at hsplit
      have eq : stored = key.val := same.symm.trans hsplit
      exact (absent leaf (eq ▸ member)).elim
  | some digit =>
      have first : radixSplit stored key.val (some digit.val) := by
        simpa only [same, Option.map_some] using hsplit
      apply WP.spec_bind
        (radix_record_matches dirs path root key (some digit) height bindings room tree)
      rintro ⟨stem, recorded⟩ ⟨tip, length, walk⟩
      have cut := representative_at_cut walk stored leaf rep first.2
      have source :=
        classifies_stem walk stored leaf cut first.1 compressed
          (fun entry hm => by
            obtain ⟨_, value, hr, hk⟩ := valid entry hm
            simp [hr, hk])
      change WP.spec (do
        let old ← Spike.radix.symbol row.key digit
        let new ← Spike.radix.symbol key digit
        Result.ok ((stem, some ({digit, old_slot := old, new_slot := new}
          : Spike.radix.InsertionSplit)), recorded)) _
      apply WP.spec_bind (radix_symbol_matches row.key digit)
      intro old ho
      apply WP.spec_bind (radix_symbol_matches key digit)
      intro new hn
      have oldBound : old.val < 17 := ho ▸ radixSymbol_bound _ _
      have oldSlot : old.val = radixSymbol stored digit.val := by
        simpa only [same] using ho
      have different : old.val ≠ new.val := by rw [oldSlot, hn]; exact first.1
      simp only [WP.spec_ok]
      exact ⟨_, tip, rfl, length, hn, oldBound, different, walk, oldSlot ▸ source⟩

private theorem radix_split_directory_matches (dirs : Slice (Option Spike.radix.RadixDir))
    (stem : U32) (split : Spike.radix.InsertionSplit) (key : List U8) (tip : Bindings)
    (oldBound : split.old_slot.val < 17)
    (newSlot : split.new_slot.val = radixSymbol key split.digit.val)
    (different : split.old_slot.val ≠ split.new_slot.val)
    (source : InsertStem dirs.val key split.digit split.old_slot.val stem tip)
    : WP.spec (Spike.radix.split_directory dirs stem split)
        (fun dir =>
          dir.digit = split.digit
          ∧ dir.children.val[split.new_slot.val]? = some 0#u32
          ∧ ∃ height, RadixPartition dirs.val height dir.digit dir.children.val tip) := by
  unfold Spike.radix.split_directory
  rw [radix_tag]
  cases source with
  | extend h _ _ prior pos low lookup eq vacant parts =>
      rw [ite_eq_left low]
      apply WP.spec_bind (radix_directory_matches dirs stem prior pos lookup)
      intro actual he
      subst actual
      simp only [eq, ite_true, WP.spec_ok]
      exact ⟨trivial, newSlot ▸ vacant, h, eq ▸ parts⟩
  | wrap h _ _ oldTree nz later common =>
      have build
          : WP.spec
              (do
                let empty ← Spike.radix.RadixDir.empty split.digit
                Spike.radix.RadixDir.set_child empty split.old_slot stem)
              (fun dir =>
                dir.digit = split.digit
                ∧ dir.children.val[split.new_slot.val]? = some 0#u32
                ∧ ∃ height,
                    RadixPartition dirs.val height dir.digit dir.children.val tip) := by
        apply WP.spec_bind (radix_empty_matches split.digit)
        intro empty ⟨hd, _, zero, _⟩
        apply WP.spec_mono (radix_set_child_matches empty split.old_slot stem oldBound)
        intro dir ⟨same, _, children, _⟩
        have digit : dir.digit = split.digit := same.trans hd
        have pointers :=
          children.trans (congrArg (fun xs => List.set xs split.old_slot.val stem) zero)
        have newBound : split.new_slot.val < 17 := newSlot ▸ radixSymbol_bound _ _
        refine ⟨digit, ?_, h, ?_⟩
        · rw [pointers, List.getElem?_set_ne different]
          rw [List.getElem?_replicate]
          simp [newBound]
        · intro slot bound
          have room : slot < (List.replicate 17 (0#u32 : U32)).length := by
            simpa using bound
          rw [pointers, digit]
          by_cases old : split.old_slot.val = slot
          · subst slot
            rw [List.getElem?_set_self room]
            have allRows : tip.filter
                (fun row => radixSymbol row.1 split.digit.val == split.old_slot.val) = tip :=
              List.filter_eq_self.mpr (fun row hm => by simp [common row hm])
            rw [allRows]
            exact ⟨stem, rfl, oldTree⟩
          · rw [List.getElem?_set_ne old]
            have noneRows : tip.filter
                (fun row => radixSymbol row.1 split.digit.val == slot) = [] := by
              apply List.filter_eq_nil_iff.mpr
              intro row hm
              simp [common row hm, old]
            rw [noneRows]
            exact ⟨0#u32, by rw [List.getElem?_replicate]; simp [bound], .empty h⟩
      by_cases low : stem < 2147483648#u32
      · obtain ⟨prior, lookup, before⟩ := later low
        have pos : 0 < stem.val := by
          by_contra nope
          apply nz
          apply UScalar.eq_of_val_eq
          change stem.val = 0
          omega
        rw [ite_eq_left low]
        apply WP.spec_bind (radix_directory_matches dirs stem prior pos lookup)
        intro actual he
        subst actual
        rw [ite_eq_right (Ne.symm (ne_of_lt before))]
        exact build
      · rw [ite_eq_right low]
        exact build

private theorem radix_insert_tip (dirs : DirArena) (free : alloc.vec.Vec Usize)
    (stem leaf : U32) (split : Spike.radix.InsertionSplit) (key : List U8)
    (tip : Bindings) (oldBound : split.old_slot.val < 17)
    (newSlot : split.new_slot.val = radixSymbol key split.digit.val)
    (different : split.old_slot.val ≠ split.new_slot.val)
    (source : InsertStem dirs.val key split.digit split.old_slot.val stem tip)
    (tagged : (2147483648#u32 : U32) ≤ leaf) (available : RadixFree dirs free)
    (room : dirs.val.length < 2147483647)
    : WP.spec
        (do
          let dir ← Spike.radix.split_directory (alloc.vec.Vec.deref dirs) stem split
          let updated ← Spike.radix.RadixDir.set_child dir split.new_slot leaf
          let (root, next, avail) ← Spike.radix.add_directory dirs free updated
          Result.ok (next, avail, root))
        (fun (next, avail, root) =>
          preservesSlots dirs next
          ∧ RadixFree next avail
          ∧ next.val.length ≤ dirs.val.length + 1
          ∧ ∃ h, RadixTree next.val h root (Kv.Model.set tip key leaf)) := by
  have hs : InsertStem (alloc.vec.Vec.deref dirs).val key split.digit
      split.old_slot.val stem tip := by simpa [alloc.vec.Vec.deref] using source
  apply WP.spec_bind
    (radix_split_directory_matches (alloc.vec.Vec.deref dirs) stem split key
      tip oldBound newSlot different hs)
  intro dir ⟨hd, vacant, height, parts⟩
  have bound : split.new_slot.val < 17 := newSlot ▸ radixSymbol_bound _ _
  have hNew : radixSymbol key dir.digit.val = split.new_slot.val := by rw [hd, newSlot]
  obtain ⟨old, hOld, sub⟩ := parts split.new_slot.val bound
  have oldEmpty : old = 0#u32 := Option.some.inj (hOld.symm.trans vacant)
  have noRows := radix_tree_zero sub oldEmpty
  apply WP.spec_bind (radix_set_child_matches dir split.new_slot leaf bound)
  intro updated ⟨he, _, hc, _⟩
  have part : RadixPartition dirs.val height updated.digit updated.children.val
      (Kv.Model.set tip key leaf) := by
    intro slot hi
    have hb : slot < dir.children.val.length := by rw [Array.length_eq]; exact hi
    rw [hc, he]
    change ∃ child, (dir.children.val.set split.new_slot.val leaf)[slot]? = some child ∧
      RadixTree dirs.val height child
        ((radixEdit tip key (some leaf)).filter (fun row => radixSymbol row.1 dir.digit.val == slot))
    rw [edit_partition, hNew]
    by_cases chosen : slot = split.new_slot.val
    · subst slot
      rw [ite_eq_left rfl, List.getElem?_set_self hb, noRows]
      exact ⟨leaf, rfl, .leaf height leaf key tagged⟩
    · rw [ite_eq_right chosen, List.getElem?_set_ne (Ne.symm chosen)]
      simpa [alloc.vec.Vec.deref] using parts slot hi
  have hpos : leaf ≠ 0#u32 := by
    intro hz
    rw [hz] at tagged
    exact (by decide : ¬(2147483648#u32 : U32) ≤ 0#u32) tagged
  have hAt : updated.children.val[split.new_slot.val]? = some leaf := by
    rw [hc, List.getElem?_set_self]
    rw [Array.length_eq]; exact bound
  have nonempty := radix_first_nonzero updated ⟨leaf, List.mem_of_getElem? hAt, hpos⟩
  have firstLive : RadixDirLive dirs (radixFirst updated) := by
    obtain ⟨slot, hslot⟩ := List.mem_iff_getElem?.mp (radix_first_mem updated nonempty)
    have hlen : updated.children.val.length = 17 := Array.length_eq _
    have hs : slot < 17 := by
      by_contra tooBig
      have hbad : updated.children.val.length ≤ slot := by omega
      rw [List.getElem?_eq_none hbad] at hslot
      cases hslot
    obtain ⟨child, hchild, tree⟩ := part slot hs
    have eq := Option.some.inj (hchild.symm.trans hslot)
    exact eq ▸ radix_tree_live tree
  apply WP.spec_bind
    (radix_add_directory_matches dirs free updated available room nonempty
      (firstLive nonempty))
  rintro ⟨root, next, avail⟩ ⟨pos, low, ⟨published, hroot, digit, directory, _⟩, keep, growth, valid⟩
  change WP.spec (Result.ok (next, avail, root)) _
  simp only [WP.spec_ok]
  let select := fun (i : Nat) => updated.children.val[i]?.getD 0#u32
  refine ⟨
    keep,
    valid,
    growth,
    height + 1,
    .branch height root published _ pos low hroot select ?_ ?_
  ⟩
  · intro i hi
    obtain ⟨c, get, _⟩ := part i hi
    simp [directory, select, get]
  · intro i hi
    obtain ⟨c, get, tree⟩ := part i hi
    rw [digit]
    simpa [select, get] using radix_tree_preserved dirs.val next.val keep tree

private theorem radix_prepare_existing {V : Type}
    (dirs : Slice (Option Spike.radix.RadixDir))
    (rows : Slice (Option (Spike.radix.RadixRow V))) (path : alloc.vec.Vec (U32 × Usize))
    (root leaf : U32) (key : Slice U8) (height : Nat) (bindings : Bindings)
    (tree : RadixTree dirs.val height root bindings)
    (reps : RadixRepresentatives dirs.val) (present : (key.val, leaf) ∈ bindings)
    (nz : root ≠ 0#u32) (old : Spike.radix.RadixRow V) (tagged : 2147483648 < leaf.val)
    (live : radixRow rows.val leaf = some old) (same : old.key.val = key.val)
    (room : height ≤ Usize.max) (keyRoom : 2 * key.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.prepare_insert dirs rows path root key)
        (fun ((stem, split), recorded) =>
          stem = leaf
          ∧ split = none
          ∧ recorded.val.length ≤ height
          ∧ RadixWalk dirs.val key.val none root bindings leaf [(key.val, leaf)]
              recorded.val) := by
  unfold Spike.radix.prepare_insert
  apply WP.spec_bind
    (radix_representative_matches dirs key height root bindings tree reps nz)
  intro rep ⟨_, chosen⟩
  have hrep := chosen leaf present
  subst rep
  apply WP.spec_bind (radix_row_at_matches rows leaf old tagged live)
  intro previous he
  subst previous
  apply WP.spec_bind
    (radix_first_difference_matches old.key key (by rwa [same, Nat.min_self]))
  intro difference hd
  cases difference with
  | some digit =>
      exfalso
      exact hd.1 (by rw [same])
  | none =>
      apply WP.spec_bind
        (radix_record_matches dirs path root key none height bindings room tree)
      rintro ⟨stem, recorded⟩ ⟨tip, depth, route⟩
      have hm := (radix_walk_membership route).2 leaf present
      rcases radix_walk_tip route with ⟨_, empty⟩ | ⟨stored, ht, _⟩
      · rw [empty] at hm
        exact (List.not_mem_nil hm).elim
      · have hc : (key.val, leaf) = (stored, stem) := List.mem_singleton.mp (ht ▸ hm)
        have hs : stem = leaf := (congrArg Prod.snd hc).symm
        have htip : tip = [(key.val, leaf)] := ht.trans (congrArg List.singleton hc.symm)
        have hroute
            : RadixWalk dirs.val key.val none root bindings leaf [(key.val, leaf)]
                recorded.val := by
          simpa only [hs, htip] using route
        change WP.spec (Result.ok ((stem, none), recorded)) _
        simp only [WP.spec_ok]
        exact ⟨hs, trivial, depth, hroute⟩

/-- Replacing an existing binding in the native radix produces the same ordered
association-list projection and preserves the directories and rows of prior roots. -/
theorem radix_put_existing_matches {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) (freeDirs : alloc.vec.Vec Usize)
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow V)))
    (freeRows : alloc.vec.Vec Usize) (scratch : alloc.vec.Vec (U32 × Usize)) (root : U32)
    (row : Spike.radix.RadixRow V) (height : Nat) (bindings : List (List U8 × U32))
    (oldLeaf : U32) (tree : RadixTree dirs.val height root bindings)
    (present : (row.key.val, oldLeaf) ∈ bindings) (old : Spike.radix.RadixRow V)
    (tagged : 2147483648 < oldLeaf.val) (live : radixRow rows.val oldLeaf = some old)
    (same : old.key.val = row.key.val) (reps : RadixRepresentatives dirs.val)
    (invariant : RadixDirectoryInvariant dirs) (availableDirs : RadixFree dirs freeDirs)
    (availableRows : RadixFree rows freeRows)
    (dirRoom : dirs.val.length + height ≤ 2147483647)
    (rowRoom : rows.val.length < 2147483647)
    (keyRoom : 2 * row.key.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.put dirs freeDirs rows freeRows scratch root row)
        (fun (after, arena, avail, values, unused, _) =>
          preservesSlots dirs arena
          ∧ RadixFree arena avail
          ∧ RadixFree values unused
          ∧ (∀ (i : Nat) previous,
              rows.val[i]? = some (some previous) → values.val[i]? = some (some previous))
          ∧ ∃ height leaf,
              2147483648 < leaf.val
              ∧ radixRow values.val leaf = some row
              ∧ RadixTree arena.val height after
                  (Kv.Model.set bindings row.key.val leaf)) := by
  have nz : root ≠ 0#u32 := by
    intro zero
    have hb := radix_tree_zero tree zero
    rw [hb] at present
    exact List.not_mem_nil present
  have hmax : 2147483647 ≤ Usize.max := by scalar_tac
  unfold Spike.radix.put
  simp only [nz, ite_false]
  let ds := alloc.vec.Vec.deref dirs
  let rs := alloc.vec.Vec.deref rows
  have hTree : RadixTree ds.val height root bindings := by simpa [ds, alloc.vec.Vec.deref] using tree
  have hReps : RadixRepresentatives ds.val := by simpa [ds, alloc.vec.Vec.deref] using reps
  have hrow : radixRow rs.val oldLeaf = some old := by simpa [rs, alloc.vec.Vec.deref] using live
  apply WP.spec_bind
    (radix_prepare_existing ds rs scratch root oldLeaf row.key height bindings
      hTree hReps present nz old tagged hrow same (by omega) keyRoom)
  rintro ⟨⟨stem, split⟩, path⟩ ⟨_, none, depth, visit⟩
  subst split
  have walk
      : RadixWalk dirs.val row.key.val none root bindings oldLeaf [(row.key.val, oldLeaf)]
          path.val := by
    simpa [ds, alloc.vec.Vec.deref] using visit
  apply WP.spec_bind
    (radix_allocate_matches rows freeRows row availableRows (fun _ => by omega))
  rintro ⟨i, values, unused⟩ ⟨value, kept, _, eligible, _, free⟩
  apply WP.spec_bind (radix_link_matches i true (by omega))
  intro leaf hleaf
  have hlink : leaf.val = i.val + 1 + 2147483648 := by simpa using hleaf
  have htag : 2147483648 < leaf.val := by omega
  have hnew : radixRow values.val leaf = some row := by
    have hi : leaf.val - 2147483648 - 1 = i.val := by omega
    simp [radixRow, hi, value]
  obtain ⟨target, head, tail, steps⟩ := radix_walk_edit_plan dirs row.key.val (some leaf) walk invariant
  have hTip : target path.val.length = [(row.key.val, leaf)] := by
    simp [tail, radixEdit, Kv.Model.set, Kv.Model.erase]
  let input := alloc.vec.Vec.deref path
  have lengthEq : input.val.length = path.val.length := by simp [input, alloc.vec.Vec.deref]
  simp only [bind_ok]
  apply WP.spec_bind
    (radix_rebuild_matches dirs freeDirs input leaf target availableDirs
      (by omega)
      (fun j hj => by
        have hi : j < path.val.length := by omega
        simpa [input, alloc.vec.Vec.deref] using steps j hi)
      (by
        rw [lengthEq, hTip]
        exact ⟨0, .leaf 0 leaf row.key.val (by exact Nat.le_of_lt htag)⟩))
  rintro ⟨new, arena, available⟩ ⟨keep, hdr, shape⟩
  change WP.spec (Result.ok (new, arena, available, values, unused, path)) _
  simp only [WP.spec_ok]
  obtain ⟨h, hshape⟩ := shape
  rw [head] at hshape
  exact ⟨keep, hdr, free, kept, h, leaf, htag, hnew, hshape⟩

/-- Inserting into an empty radix creates a single live leaf and no directories. -/
theorem radix_put_empty_matches {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) (freeDirs : alloc.vec.Vec Usize)
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow V)))
    (freeRows : alloc.vec.Vec Usize) (scratch : alloc.vec.Vec (U32 × Usize))
    (row : Spike.radix.RadixRow V) (available : RadixFree rows freeRows)
    (room : rows.val.length < 2147483647)
    : WP.spec (Spike.radix.put dirs freeDirs rows freeRows scratch 0#u32 row)
        (fun (leaf, arena, avail, values, unused, path) =>
          arena = dirs
          ∧ avail = freeDirs
          ∧ path = scratch
          ∧ RadixFree values unused
          ∧ (∀ (i : Nat) previous,
              rows.val[i]? = some (some previous) → values.val[i]? = some (some previous))
          ∧ 2147483648 < leaf.val
          ∧ radixRow values.val leaf = some row
          ∧ RadixTree arena.val 0 leaf [(row.key.val, leaf)]) := by
  have hmax : 2147483647 ≤ Usize.max := by scalar_tac
  unfold Spike.radix.put
  simp only [ite_true]
  apply WP.spec_bind
    (radix_allocate_matches rows freeRows row available (fun _ => by omega))
  rintro ⟨i, values, unused⟩ ⟨value, kept, _, eligible, _, free⟩
  apply WP.spec_bind (radix_link_matches i true (by omega))
  intro leaf hleaf
  have hlink : leaf.val = i.val + 1 + 2147483648 := by simpa using hleaf
  have htag : 2147483648 < leaf.val := by omega
  have hnew : radixRow values.val leaf = some row := by
    have hi : leaf.val - 2147483648 - 1 = i.val := by omega
    simp [radixRow, hi, value]
  simp only [WP.spec_ok]
  exact ⟨trivial, trivial, trivial, free, kept, htag, hnew,
    .leaf 0 leaf row.key.val (Nat.le_of_lt htag)⟩

/-- Inserting a fresh key into a nonempty compressed root creates exactly
the model binding and preserves all previously live directory and row slots. -/
theorem radix_put_fresh_matches {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) (freeDirs : alloc.vec.Vec Usize)
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow V)))
    (freeRows : alloc.vec.Vec Usize) (scratch : alloc.vec.Vec (U32 × Usize)) (root : U32)
    (row : Spike.radix.RadixRow V) (height : Nat) (bindings : List (List U8 × U32))
    (tree : RadixTree dirs.val height root bindings) (nz : root ≠ 0#u32)
    (absent : ∀ leaf, (row.key.val, leaf) ∉ bindings)
    (valid
      : ∀ entry ∈ bindings,
          2147483648 < entry.2.val
          ∧ ∃ value, radixRow rows.val entry.2 = some value ∧ value.key.val = entry.1)
    (reps : RadixRepresentatives dirs.val)
    (compressed
      : RadixCompressed dirs.val
          (fun leaf =>
            (radixRow rows.val leaf).map (fun row => row.key.val)))
    (invariant : RadixDirectoryInvariant dirs) (availableDirs : RadixFree dirs freeDirs)
    (availableRows : RadixFree rows freeRows)
    (dirRoom : dirs.val.length + height + 1 ≤ 2147483647)
    (rowRoom : rows.val.length < 2147483647)
    (keyRoom : 2 * row.key.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.put dirs freeDirs rows freeRows scratch root row)
        (fun (after, arena, avail, values, unused, _) =>
          preservesSlots dirs arena
          ∧ RadixFree arena avail
          ∧ RadixFree values unused
          ∧ (∀ (i : Nat) previous,
              rows.val[i]? = some (some previous) → values.val[i]? = some (some previous))
          ∧ ∃ height leaf,
              2147483648 < leaf.val
              ∧ radixRow values.val leaf = some row
              ∧ RadixTree arena.val height after
                  (Kv.Model.set bindings row.key.val leaf)) := by
  have hmax : 2147483647 ≤ Usize.max := by scalar_tac
  unfold Spike.radix.put
  simp only [nz, ite_false]
  let ds := alloc.vec.Vec.deref dirs
  let rs := alloc.vec.Vec.deref rows
  have hTree : RadixTree ds.val height root bindings := by simpa [ds, alloc.vec.Vec.deref] using tree
  have hReps : RadixRepresentatives ds.val := by simpa [ds, alloc.vec.Vec.deref] using reps
  have hCompressed : RadixCompressed ds.val (fun leaf =>
      (radixRow rs.val leaf).map (fun row => row.key.val)) := by
    simpa [ds, rs, alloc.vec.Vec.deref] using compressed
  have hRows : ∀ entry ∈ bindings, 2147483648 < entry.2.val ∧
      ∃ value, radixRow rs.val entry.2 = some value ∧ value.key.val = entry.1 := by
    simpa [rs, alloc.vec.Vec.deref] using valid
  apply WP.spec_bind
    (radix_prepare_fresh ds rs scratch root row.key height bindings
      hTree hReps hCompressed absent nz hRows (by omega) keyRoom)
  rintro ⟨⟨stem, found⟩, path⟩ ⟨split, tip, eq, depth, newSlot, oldBound, different, visit, source⟩
  subst found
  have walk
      : RadixWalk dirs.val row.key.val (some split.digit) root bindings stem tip
          path.val := by
    simpa [ds, alloc.vec.Vec.deref] using visit
  have hSource
      : InsertStem dirs.val row.key.val split.digit split.old_slot.val stem tip := by
    simpa [ds, alloc.vec.Vec.deref] using source
  apply WP.spec_bind
    (radix_allocate_matches rows freeRows row availableRows (fun _ => by omega))
  rintro ⟨i, values, unused⟩ ⟨value, kept, _, eligible, _, free⟩
  apply WP.spec_bind (radix_link_matches i true (by omega))
  intro leaf hleaf
  have hlink : leaf.val = i.val + 1 + 2147483648 := by simpa using hleaf
  have htag : 2147483648 < leaf.val := by omega
  have hnew : radixRow values.val leaf = some row := by
    have hi : leaf.val - 2147483648 - 1 = i.val := by omega
    simp [radixRow, hi, value]
  obtain ⟨target, head, tail, steps⟩ := radix_walk_edit_plan dirs row.key.val (some leaf) walk invariant
  have publishTip := radix_insert_tip dirs freeDirs stem leaf split row.key.val tip oldBound
    newSlot different hSource (Nat.le_of_lt htag) availableDirs (by omega)
  apply WP.spec_bind publishTip
  rintro ⟨newDirs, freeNext, child⟩ ⟨keeps, nextFree, growth, subtree⟩
  let input := alloc.vec.Vec.deref path
  have lengthEq : input.val.length = path.val.length := by simp [input, alloc.vec.Vec.deref]
  apply WP.spec_bind
    (radix_rebuild_matches newDirs freeNext input child target nextFree
      (by omega)
      (fun j hj => by
        have hi : j < path.val.length := by omega
        simpa [input, alloc.vec.Vec.deref]
          using radix_path_step_preserved keeps (steps j hi))
      (by rw [lengthEq, tail]; exact subtree))
  rintro ⟨new, arena, available⟩ ⟨keep, hdr, shape⟩
  change WP.spec (Result.ok (new, arena, available, values, unused, path)) _
  simp only [WP.spec_ok]
  obtain ⟨h, hshape⟩ := shape
  rw [head] at hshape
  exact ⟨fun j dir present => keep j dir (keeps j dir present), hdr, free, kept,
    h, leaf, htag, hnew, hshape⟩

end KvRust
