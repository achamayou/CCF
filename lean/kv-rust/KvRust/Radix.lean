-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs
public import KvRust.Keys
public import Kv.Model.Types

import all Aeneas.Data.List.List
import all Aeneas.Std.Core.Core
import all Init.Data.Nat.Power2.Basic

@[expose] public section

namespace KvRust

open Aeneas.Std

private theorem key_borrow_val (key : alloc.vec.Vec U8)
    : (alloc.vec.Vec.deref key).val = key.val := by simp [alloc.vec.Vec.deref]

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

private theorem radixSymbol_cons_shift (head : U8) (tail : List U8) (digit : Nat)
    : radixSymbol (head :: tail) (digit + 2) = radixSymbol tail digit := by
  have index : (digit + 2) / 2 = digit / 2 + 1 := by omega
  have parity : (digit + 2) % 2 = digit % 2 := by omega
  simp [radixSymbol, index, parity, List.getElem?_cons_succ]

/-- At the first differing routing digit, slot order agrees with unsigned byte order. -/
theorem radix_first_symbol_lt (a b : List U8) (digit : Nat)
    (same : ∀ i < digit, radixSymbol a i = radixSymbol b i)
    (lower : radixSymbol a digit < radixSymbol b digit)
    : byteOrder a b = (-1)#i8 := by
  induction a generalizing b digit with
  | nil =>
      cases b with
      | nil => exact (Nat.lt_irrefl _ lower).elim
      | cons b tail => rfl
  | cons a xs ih =>
      cases b with
      | nil => simp [radixSymbol] at lower
      | cons b ys =>
          have high (x : U8) (tail : List U8) : radixSymbol (x :: tail) 0 = 1 + x.val / 16 := rfl
          have low (x : U8) (tail : List U8) : radixSymbol (x :: tail) 1 = 1 + x.val % 16 := rfl
          have cmp (lt : a.val < b.val) : byteOrder (a :: xs) (b :: ys) = (-1)#i8 := by
            have smaller : a < b := lt
            simp [byteOrder, smaller]
          by_cases first : digit = 0
          · subst digit
            rw [high, high] at lower
            exact cmp (by omega)
          · have hEq := same 0 (by omega)
            rw [high, high] at hEq
            by_cases second : digit = 1
            · subst digit
              rw [low, low] at lower
              exact cmp (by omega)
            · have lEq := same 1 (by omega)
              rw [low, low] at lEq
              have byteEq : a = b := UScalar.eq_of_val_eq (by omega)
              subst b
              let rest := digit - 2
              have shifted : rest + 2 = digit := by dsimp [rest]; omega
              have sameTail : ∀ i < rest, radixSymbol xs i = radixSymbol ys i := by
                intro i hi
                have eq := same (i + 2) (by omega)
                simpa only [radixSymbol_cons_shift] using eq
              have lowerTail : radixSymbol xs rest < radixSymbol ys rest := by
                simpa only [← shifted, radixSymbol_cons_shift] using lower
              simpa [byteOrder] using ih ys rest sameTail lowerTail

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

private theorem radix_updated_mask (dir next : Spike.radix.RadixDir) (slot : Usize)
    (child : U32) (bound : slot.val < 17) (mask : RadixMask dir)
    (hstep : next.children.val = dir.children.val.set slot.val child)
    (hmask
      : ∀ i,
          i < 32
          → next.mask.bv.getLsbD i
            = if i = slot.val then child != 0#u32 else dir.mask.bv.getLsbD i)
    : RadixMask next := by
  intro i hi
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

theorem radix_set_child_preserves_mask (dir : Spike.radix.RadixDir) (slot : Usize)
    (child : U32) (bound : slot.val < 17) (mask : RadixMask dir)
    : WP.spec (Spike.radix.RadixDir.set_child dir slot child) RadixMask := by
  apply WP.spec_mono (radix_set_child_matches dir slot child bound)
  intro next ⟨_, _, hstep, hmask⟩
  exact radix_updated_mask dir next slot child bound mask hstep hmask

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
          ∧ RadixFree next left
          ∧ ∀ (j : Nat), j ≠ i.val → next.val[j]? = slots.val[j]?) := by
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
    refine ⟨?_, ?_, by simp [hempty], Nat.le_refl _, by simp, ?_, ?_⟩
    · rw [List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]
      rfl
    · intro j old hj
      have hb : j < slots.val.length := by
        by_contra hn
        simp [Nat.le_of_not_gt hn] at hj
      rwa [List.getElem?_append_left hb]
    · simp [RadixFree, hempty]
    · intro j different
      change j ≠ slots.val.length at different
      by_cases inside : j < slots.val.length
      · exact List.getElem?_append_left inside
      · have beyond : (slots.val ++ [some value]).length ≤ j := by
          simp only [List.length_append, List.length_singleton]
          omega
        rw [List.getElem?_eq_none beyond, List.getElem?_eq_none (Nat.le_of_not_gt inside)]
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
    refine ⟨List.getElem?_set_self hb, ?_, hprefix, by omega, by simp, ?_, ?_⟩
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
    · exact fun _ different => List.getElem?_set_ne (Ne.symm different)

/-- Recycling clears exactly the selected slot and adds it to the free list.
The caller establishes liveness separately. -/
theorem radix_recycle_slot_matches {T : Type} (slots : alloc.vec.Vec (Option T))
    (free : alloc.vec.Vec Usize) (index : Usize) (old : T)
    (live : slots.val[index.val]? = some (some old)) (vacant : RadixFree slots free)
    (room : free.val.length < Usize.max)
    : WP.spec (Spike.radix.recycle_slot slots free index)
        (fun (removed, next, avail) =>
          removed = old
          ∧ next.val[index.val]? = some none
          ∧ avail.val = free.val ++ [index]
          ∧ RadixFree next avail
          ∧ ∀ j : Nat, j ≠ index.val → next.val[j]? = slots.val[j]?) := by
  have hb : index.val < slots.val.length := by
    by_contra hn
    simp [Nat.le_of_not_gt hn] at live
  have notFree : index ∉ free.val := by
    intro hm
    have bad := vacant.2 index hm
    rw [live] at bad
    cases bad
  unfold Spike.radix.recycle_slot
  rw [alloc.vec.Vec.index_mut_slice_index]
  apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec slots index hb)
  rintro ⟨entry, back⟩ ⟨he, hback⟩
  rw [List.getElem?_eq_getElem hb, ← he, Option.some.injEq] at live
  subst entry
  simp only [core.option.Option.take]
  apply WP.spec_bind (alloc.vec.Vec.push_spec free index room)
  intro avail appended
  simp only [WP.spec_ok, hback, alloc.vec.Vec.set_val_eq]
  refine ⟨trivial, List.getElem?_set_self hb, appended, ?_, ?_⟩
  · rw [RadixFree, appended]
    constructor
    · rw [List.nodup_append]
      refine ⟨vacant.1, List.nodup_singleton _, ?_⟩
      intro i hi j hj same
      exact notFree ((same.trans (List.mem_singleton.mp hj)) ▸ hi)
    · intro i hi
      rcases List.mem_append.mp hi with previous | newest
      · have hne : index.val ≠ i.val :=
          fun eq => notFree (UScalar.eq_of_val_eq eq ▸ previous)
        rw [alloc.vec.Vec.set_val_eq, List.getElem?_set_ne hne]
        exact vacant.2 i previous
      · have eq := List.mem_singleton.mp newest
        subst i
        rw [alloc.vec.Vec.set_val_eq]
        exact List.getElem?_set_self hb
  · exact fun _ different => List.getElem?_set_ne (Ne.symm different)

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

/-- A newly published directory has a finite projection drawn from this update. -/
def RadixAdds (old next : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (allowed : Usize → List (List U8 × U32) → Prop)
    : Prop :=
  ∀ (i : Nat) dir,
    next.val[i]? = some (some dir)
    → old.val[i]? ≠ some (some dir)
    → ∃ (root : U32) (height : Nat) (bindings : List (List U8 × U32)),
        root.val = i + 1
        ∧ root < 2147483648#u32
        ∧ RadixTree next.val height root bindings
        ∧ allowed dir.digit bindings

/-- Keys below one compressed directory agree on every preceding routing digit. -/
def RadixPrefix (digit : Usize) (bindings : List (List U8 × U32)) : Prop :=
  ∀ a ∈ bindings,
  ∀ b ∈ bindings, ∀ i, i < digit.val → radixSymbol a.1 i = radixSymbol b.1 i

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
    → RadixPrefix dir.digit bindings

/-- Each live directory has a finite witness with actual leaf keys and a
uniform compressed prefix. Binding order is deliberately not part of this invariant. -/
def RadixKnowledge (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (keyOf : U32 → Option (List U8))
    : Prop :=
  ∀ (index : Nat) dir,
    dirs.val[index]? = some (some dir)
    → ∃ (root : U32) (height : Nat) (bindings : List (List U8 × U32)),
        root.val = index + 1
        ∧ root < 2147483648#u32
        ∧ RadixTree dirs.val height root bindings
        ∧ (∀ row ∈ bindings, keyOf row.2 = some row.1)
        ∧ RadixPrefix dir.digit bindings

private def KnowsRows (keyOf : U32 → Option (List U8)) (digit : Usize)
    (bindings : List (List U8 × U32))
    : Prop :=
  (∀ row ∈ bindings, keyOf row.2 = some row.1) ∧ RadixPrefix digit bindings

/-- Slot preservation retains the previous forest; provenance establishes
compression only for directories that this mutation allocates. -/
theorem radix_knowledge_extend
    (dirs next : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (keyOf newKeyOf : U32 → Option (List U8))
    (known : RadixKnowledge dirs keyOf) (kept : preservesSlots dirs next)
    (keysKept : ∀ leaf key, keyOf leaf = some key → newKeyOf leaf = some key)
    (added
      : RadixAdds dirs next
          (fun digit bindings =>
            (∀ row ∈ bindings, newKeyOf row.2 = some row.1) ∧ RadixPrefix digit bindings))
    : RadixKnowledge next newKeyOf := by
  intro index dir live
  by_cases earlier : dirs.val[index]? = some (some dir)
  · obtain ⟨root, h, bs, idx, low, tree, actual, uniform⟩ := known index dir earlier
    exact ⟨root, h, bs, idx, low, radix_tree_preserved dirs.val next.val kept tree,
      fun row hm => keysKept _ _ (actual row hm), uniform⟩
  · exact added index dir live earlier

private theorem radix_adds_chain {a b c : DirArena}
    {allowed : Usize → List (List U8 × U32) → Prop}
    (before : RadixAdds a b allowed) (after : RadixAdds b c allowed)
    (keep : preservesSlots b c)
    : RadixAdds a c allowed := by
  intro index dir live new
  by_cases present : b.val[index]? = some (some dir)
  · obtain ⟨root, h, bs, hi, low, tree, ok⟩ := before index dir present new
    exact ⟨root, h, bs, hi, low, radix_tree_preserved b.val c.val keep tree, ok⟩
  · exact after index dir live present

private theorem radix_first_mem (dir : Spike.radix.RadixDir) (nz : radixFirst dir ≠ 0#u32)
    : radixFirst dir ∈ dir.children.val := by
  unfold radixFirst at nz ⊢
  cases h : dir.children.val.find? (· != 0#u32) with
  | none => simp [h] at nz
  | some child => exact List.mem_of_find?_eq_some h

/-- The cache agrees with the first occupied child, following that child's
cache only when the child is itself a directory. -/
def RadixFirstCache (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (dir : Spike.radix.RadixDir)
    : Prop :=
  radixFirst dir ≠ 0#u32
  ∧ if (2147483648#u32 : U32) ≤ radixFirst dir then
      dir.first = radixFirst dir
    else
      ∃ child,
        dirs.val[(radixFirst dir).val - 1]? = some (some child) ∧ dir.first = child.first

private theorem radix_cache_preserved {dirs next : DirArena}
    (keep : preservesSlots dirs next) {dir : Spike.radix.RadixDir}
    (cache : RadixFirstCache dirs dir)
    : RadixFirstCache next dir := by
  refine ⟨cache.1, ?_⟩
  by_cases tagged : (2147483648#u32 : U32) ≤ radixFirst dir
  · simpa only [tagged, ite_true] using cache.2
  · have h := cache.2
    rw [ite_eq_right tagged] at h ⊢
    obtain ⟨d, hd, first⟩ := h
    exact ⟨d, keep _ _ hd, first⟩

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
              ∧ published.mask = dir.mask
              ∧ RadixFirstCache next published)
          ∧ preservesSlots dirs next
          ∧ next.val.length ≤ dirs.val.length + 1
          ∧ RadixFree next left
          ∧ ∀ (j : Nat), j ≠ root.val - 1 → next.val[j]? = dirs.val[j]?) := by
  unfold Spike.radix.add_directory
  apply WP.spec_bind (radix_first_child_matches dir)
  intro first hf
  subst first
  have nz : (radixFirst dir != 0#u32) = true := bne_iff_ne.mpr nonempty
  simp only [nz, massert, ite_true, bind_ok, radix_tag]
  apply WP.spec_bind (Pₘ := fun cached => RadixFirstCache dirs {dir with first := cached})
  · by_cases tagged : 2147483648#u32 ≤ radixFirst dir
    · simp only [tagged, ite_true, WP.spec_ok]
      refine ⟨nonempty, ?_⟩
      change (if (2147483648#u32 : U32) ≤ radixFirst dir then radixFirst dir = radixFirst dir
        else ∃ child, dirs.val[(radixFirst dir).val - 1]? = some (some child) ∧
          radixFirst dir = child.first)
      simp only [tagged, ite_true]
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
      intro d hd
      subst d
      simp only [WP.spec_ok]
      refine ⟨nonempty, ?_⟩
      change (if (2147483648#u32 : U32) ≤ radixFirst dir then target.first = radixFirst dir
        else ∃ child, dirs.val[(radixFirst dir).val - 1]? = some (some child) ∧
          target.first = child.first)
      rw [ite_eq_right tagged]
      exact ⟨target, ht, rfl⟩
  · intro cached hCache
    let updated : Spike.radix.RadixDir := {dir with first := cached}
    have cap : dirs.val.length < Usize.max := by
      have h : 2147483647 ≤ Usize.max := by scalar_tac
      omega
    apply WP.spec_bind (radix_allocate_matches dirs free updated vacant (fun _ => cap))
    rintro ⟨i, next, left⟩ ⟨hnew, hprev, _, hi, hlen, hfree, unchanged⟩
    apply WP.spec_bind (radix_link_matches i false (by omega))
    intro root hroot
    simp only [Bool.false_eq_true, ite_false, Nat.add_zero] at hroot
    simp only [WP.spec_ok]
    have hidx : root.val - 1 = i.val := by omega
    rw [hidx]
    exact ⟨by omega, by omega, ⟨updated, hnew, rfl, rfl, rfl, radix_cache_preserved hprev hCache⟩,
      hprev, hlen, hfree, unchanged⟩

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

/-- A directory slot contains a nonempty link. -/
def Occupied (dir : Spike.radix.RadixDir) (slot : Nat) : Prop :=
  ∃ link, dir.children.val[slot]? = some link ∧ link ≠ 0#u32

private theorem occupied_bound (dir : Spike.radix.RadixDir) (slot : Nat)
    (occupied : Occupied dir slot)
    : slot < 17 := by
  have hlen : dir.children.val.length = 17 := Array.length_eq _
  obtain ⟨child, hc, _⟩ := occupied
  by_contra outside
  rw [List.getElem?_eq_none (by omega : dir.children.val.length ≤ slot)] at hc
  cases hc

private theorem radix_multi_slot (dir : Spike.radix.RadixDir) (mask : RadixMask dir)
    (nonempty : radixFirst dir ≠ 0#u32) (multi : ¬dir.mask.val.isPowerOfTwo)
    : ∃ i j, i ≠ j ∧ Occupied dir i ∧ Occupied dir j := by
  obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp (radix_first_mem dir nonempty)
  have occupied : Occupied dir i := ⟨radixFirst dir, hi, nonempty⟩
  refine ⟨i, ?_⟩
  by_contra noOther
  apply multi
  refine ⟨i, ?_⟩
  apply Nat.eq_of_testBit_eq
  intro j
  rw [Nat.testBit_two_pow]
  by_cases equal : i = j
  · subst j
    have set := mask i (Nat.lt_trans (occupied_bound dir i occupied) (by decide))
    change dir.mask.val.testBit i = _ at set
    rw [set, decide_eq_true (show ∃ link, dir.children.val[i]? = some link ∧ link ≠ 0#u32
      from occupied)]
    simp
  · have absent : ¬Occupied dir j := fun hj => noOther ⟨j, equal, occupied, hj⟩
    by_cases inside : j < 32
    · have bit := mask j inside
      change dir.mask.val.testBit j = _ at bit
      rw [bit, decide_eq_false (show ¬ ∃ link, dir.children.val[j]? = some link ∧ link ≠ 0#u32
        from absent)]
      simp [equal]
    · let bits : BitVec 32 := dir.mask.bv
      change bits.getLsbD j = decide (i = j)
      rw [BitVec.getLsbD_of_ge _ _ (Nat.le_of_not_gt inside)]
      simp [equal]

/-- A published directory has correct occupancy, live directory children, and
at least two occupied slots. Unused arena slots make no promises. -/
def RadixDirectoryInvariant (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) : Prop :=
  ∀ (i : Nat) (dir : Spike.radix.RadixDir),
    dirs.val[i]? = some (some dir)
    → RadixMask dir
      ∧ (∀ child ∈ dir.children.val, RadixDirLive dirs child)
      ∧ RadixFirstCache dirs dir
      ∧ ∃ a b, a ≠ b ∧ Occupied dir a ∧ Occupied dir b

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

private theorem radix_safe_parent_of_invariant {dirs : DirArena}
    (invariant : RadixDirectoryInvariant dirs) (node : U32) (dir : Spike.radix.RadixDir)
    (positive : 0 < node.val) (live : dirs.val[node.val - 1]? = some (some dir))
    : RadixMask dir ∧ ∀ slot : Usize, slot.val < 17 → SafeParent dirs node slot := by
  obtain ⟨mask, children, _, a, b, distinct, ha, hb⟩ := invariant _ _ live
  refine ⟨mask, fun slot h => ⟨positive, h, dir, live, children, ?_⟩⟩
  by_cases selected : a = slot.val
  · obtain ⟨child, hc, hn⟩ := hb
    exact ⟨b, child, fun eq => distinct (selected.trans eq.symm), hc, hn⟩
  · obtain ⟨child, hc, hn⟩ := ha
    exact ⟨a, child, selected, hc, hn⟩

private theorem radix_extend_invariant {dirs next : DirArena}
    (invariant : RadixDirectoryInvariant dirs) (keep : preservesSlots dirs next)
    (index : Nat) (dir : Spike.radix.RadixDir)
    (entry : next.val[index]? = some (some dir))
    (unchanged : ∀ j, j ≠ index → next.val[j]? = dirs.val[j]?) (mask : RadixMask dir)
    (children : ∀ child ∈ dir.children.val, RadixDirLive dirs child)
    (cache : RadixFirstCache next dir)
    (occupied : ∃ a b, a ≠ b ∧ Occupied dir a ∧ Occupied dir b)
    : RadixDirectoryInvariant next := by
  intro j current hj
  by_cases same : j = index
  · subst j
    rw [entry, Option.some.injEq, Option.some.injEq] at hj
    subst current
    exact ⟨mask, fun child h => radix_live_preserved keep (children child h), cache, occupied⟩
  · rw [unchanged j same] at hj
    obtain ⟨hm, hs, hc, ho⟩ := invariant j current hj
    exact ⟨hm, fun child h => radix_live_preserved keep (hs child h),
      radix_cache_preserved keep hc, ho⟩

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
          ∧ (RadixDirectoryInvariant dirs → RadixDirectoryInvariant next)
          ∧ ∀ original,
              dirs.val[parent.val - 1]? = some (some original)
              → ∃ updated : Spike.radix.RadixDir,
                  updated.digit = original.digit
                  ∧ updated.children.val = original.children.val.set slot.val child
                  ∧ (RadixMask original → RadixMask updated)
                  ∧ ((0 < root.val
                        ∧ root < 2147483648#u32
                        ∧ (∃ published,
                            next.val[root.val - 1]? = some (some published)
                            ∧ published.digit = updated.digit
                            ∧ published.children = updated.children)
                        ∧ (∀ j : Nat, j ≠ root.val - 1 → next.val[j]? = dirs.val[j]?))
                      ∨ root = radixFirst updated
                        ∧ updated.mask.val.isPowerOfTwo
                        ∧ next = dirs)) := by
  obtain ⟨positive, bound, dir, hdir, hchildren, sibling, survivor, other, hs, hn⟩ := safe
  unfold Spike.radix.copy_parent
  apply WP.spec_bind
    (radix_directory_matches (alloc.vec.Vec.deref dirs) parent dir positive
      (by simpa [alloc.vec.Vec.deref] using hdir))
  intro expected hd
  subst expected
  apply WP.spec_bind (radix_set_child_matches dir slot child bound)
  intro updated ⟨hdigit, _, hnew, hmask⟩
  have preservesMask (hm : RadixMask dir) : RadixMask updated :=
    radix_updated_mask dir updated slot child bound hm hnew hmask
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
      rintro ⟨nextLink, next, left⟩ ⟨pos, low, published, keep, hlen, avail, untouched⟩
      refine ⟨keep, hlen, avail, fun _ _ => published.imp fun _ h => h.1, ?_, ?_⟩
      · intro invariant
        obtain ⟨actual, hAt, _, childEq, maskEq, cache⟩ := published
        have hm := preservesMask ((invariant _ _ hdir).1)
        have notPower : ¬updated.mask.val.isPowerOfTwo := fun h => by
          have invalid := hcollapse.mpr h
          contradiction
        apply radix_extend_invariant invariant keep (nextLink.val - 1) actual hAt untouched
        · intro i hi
          simpa only [childEq, maskEq] using hm i hi
        · simpa only [childEq] using children
        · exact cache
        · obtain ⟨a, b, different, ha, hb⟩ := radix_multi_slot updated hm nonempty notPower
          exact ⟨a, b, different, by simpa only [Occupied, childEq] using ha,
            by simpa only [Occupied, childEq] using hb⟩
      intro original ho
      have same : original = dir := Option.some.inj (Option.some.inj (ho.symm.trans hdir))
      subst original
      exact ⟨updated, hdigit, hnew, preservesMask, Or.inl
        ⟨pos, low, published.imp (fun _ h => ⟨h.1, h.2.1, h.2.2.1⟩), untouched⟩⟩
    · simp only [ite_true]
      apply WP.spec_bind (radix_first_child_matches updated)
      intro first he
      simp only [WP.spec_ok]
      refine ⟨fun _ _ h => h, by omega, vacant, he ▸ firstLive, id, ?_⟩
      intro original ho
      have same : original = dir := Option.some.inj (Option.some.inj (ho.symm.trans hdir))
      subst original
      exact ⟨updated, hdigit, hnew, preservesMask, Or.inr ⟨he, hcollapse.mp rfl, trivial⟩⟩

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
      rintro ⟨root, next, left⟩ ⟨hkeep, hlen, hleft, hroot, _, _⟩
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

private theorem radix_partition_tree (dirs : List (Option Spike.radix.RadixDir))
    (node : U32) (dir : Spike.radix.RadixDir) (height : Nat)
    (bindings : List (List U8 × U32))
    (positive : 0 < node.val) (low : node < 2147483648#u32)
    (entry : dirs[node.val - 1]? = some (some dir))
    (parts : RadixPartition dirs height dir.digit dir.children.val bindings)
    : RadixTree dirs (height + 1) node bindings := by
  let pick := fun (i : Nat) => dir.children.val[i]?.getD 0#u32
  refine .branch height node dir bindings positive low entry pick ?_ ?_
  · intro i hi
    obtain ⟨child, found, _⟩ := parts i hi
    simp [pick, found]
  · intro i hi
    obtain ⟨child, found, tree⟩ := parts i hi
    simpa [pick, found] using tree

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
          ∧ (RadixDirectoryInvariant dirs → RadixDirectoryInvariant next)
          ∧ RadixAdds dirs next (fun digit rows => digit = dir.digit ∧ rows = bindings)
          ∧ ∃ h, RadixTree next.val h root bindings) := by
  apply WP.spec_mono
    (radix_copy_parent_step dirs free parent slot child vacant room safe live)
  rintro ⟨root, next, left⟩ ⟨keep, hlen, hf, _, invariant, shape⟩
  obtain ⟨updated, digit, children, occupancy, result⟩ := shape dir prior
  refine ⟨keep, hf, hlen, invariant, ?_⟩
  have components : RadixPartition dirs.val height updated.digit updated.children.val bindings := by
    rwa [digit, children]
  rcases result with ⟨positive, low, ⟨published, hp, hd, hs⟩, unchanged⟩ |
    ⟨collapsed, singleton, sameArena⟩
  · let choose := fun (i : Nat) => updated.children.val[i]?.getD 0#u32
    have newTree : RadixTree next.val (height + 1) root bindings := by
      refine .branch height root published bindings positive low hp choose ?_ ?_
      · intro i hi
        obtain ⟨c, hget, tree⟩ := components i hi
        simp [hs, choose, hget]
      · intro i hi
        obtain ⟨c, hget, tree⟩ := components i hi
        rw [hd]
        simpa [choose, hget] using radix_tree_preserved dirs.val next.val keep tree
    refine ⟨?_, height + 1, newTree⟩
    intro i current entry earlier
    have index : i = root.val - 1 := by
      by_contra hn
      exact earlier ((unchanged i hn).symm.trans entry)
    have same : current = published :=
      Option.some.inj (Option.some.inj (entry.symm.trans (by rwa [index])))
    subst current
    exact ⟨root, height + 1, bindings, by omega, low, newTree, hd.trans digit, rfl⟩
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
    refine ⟨?_, height, radix_tree_preserved dirs.val next.val keep tree⟩
    intro i current entry earlier
    exact (earlier (by simpa only [sameArena] using entry)).elim

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

/-- With no unary directories, the number of bindings is a conservative
height bound independent of the witness used for a rebuilt root. -/
theorem radix_tree_binding_bound (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (invariant : RadixDirectoryInvariant dirs)
    {height : Nat} {node : U32} {bindings : List (List U8 × U32)}
    (tree : RadixTree dirs.val height node bindings)
    : RadixTree dirs.val bindings.length node bindings
      ∧ (node ≠ 0#u32 → bindings ≠ []) := by
  induction tree with
  | empty => exact ⟨.empty 0, fun nz => (nz rfl).elim⟩
  | leaf _ node key tagged => exact ⟨.leaf 1 node key tagged, by simp⟩
  | branch height root dir bindings positive low live child links children ih =>
      obtain ⟨_, _, _, a, b, different, ha, hb⟩ := invariant _ _ live
      have hasRows (i : Nat) (occupied : Occupied dir i) :
          ∃ e ∈ bindings, radixSymbol e.1 dir.digit.val = i := by
        have bound := occupied_bound dir i occupied
        obtain ⟨link, read, nz⟩ := occupied
        have childEq := Option.some.inj ((links i bound).symm.trans read)
        have nonempty := (ih i bound).2 (childEq.symm ▸ nz)
        obtain ⟨e, mem⟩ := List.exists_mem_of_ne_nil _ nonempty
        obtain ⟨hm, digit⟩ := List.mem_filter.mp mem
        exact ⟨e, hm, beq_iff_eq.mp digit⟩
      obtain ⟨entry, present, _⟩ := hasRows a ha
      have nonempty : bindings ≠ [] := by
        intro he
        simp [he] at present
      have space : 0 < bindings.length := List.length_pos_iff.mpr nonempty
      constructor
      · suffices RadixTree dirs.val (bindings.length - 1 + 1) root bindings by
          simpa only [Nat.sub_add_cancel (by omega : 1 ≤ bindings.length)] using this
        refine .branch _ root dir bindings positive low live child links ?_
        intro i bound
        have misses : ∃ e ∈ bindings, radixSymbol e.1 dir.digit.val ≠ i := by
          by_cases eq : i = a
          · subst i
            obtain ⟨e, hm, digit⟩ := hasRows b hb
            exact ⟨e, hm, fun eq => different (eq.symm.trans digit)⟩
          · obtain ⟨e, hm, digit⟩ := hasRows a ha
            exact ⟨e, hm, fun he => eq (he.symm.trans digit)⟩
        have shorter := List.length_filter_lt_length_iff_exists.mpr
          (show ∃ e ∈ bindings, ¬(radixSymbol e.1 dir.digit.val == i) from by
            obtain ⟨e, hm, bad⟩ := misses
            exact ⟨e, hm, fun he => bad (beq_iff_eq.mp he)⟩)
        exact radix_tree_height (ih i bound).1 (by omega)
      · exact fun _ => nonempty

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
          ∧ (RadixDirectoryInvariant dirs → RadixDirectoryInvariant next)
          ∧ RadixAdds dirs next
              (fun digit rows =>
                rows = above
                ∧ ∃ dir, dirs.val[entry.1.val - 1]? = some (some dir) ∧ digit = dir.digit)
          ∧ ∃ height, RadixTree next.val height root above) := by
  obtain ⟨safe, dir, live, mask, projection, hSiblings, siblings⟩ := step
  obtain ⟨hNew, tree⟩ := existing
  have partitions : RadixPartition dirs.val (max hNew hSiblings) dir.digit
      (dir.children.val.set entry.2.val child) above := by
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
  apply WP.spec_mono
    (radix_copy_parent_matches dirs free entry.1 entry.2 child dir (max hNew hSiblings)
      above vacant room safe (radix_tree_live tree) live mask partitions)
  rintro ⟨root, next, left⟩ ⟨keep, avail, growth, inv, adds, shape⟩
  refine ⟨keep, avail, growth, inv, ?_, shape⟩
  intro i created atSlot absent
  obtain ⟨node, h, bs, hi, low, ht, hd, hb⟩ := adds i created atSlot absent
  exact ⟨node, h, bs, hi, low, ht, hb, dir, live, hd⟩

/-- Each directory allocated during a rebuild comes from a particular path step. -/
def RadixPathAdds (dirs next : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (path : List (U32 × Usize)) (atDepth : Nat → List (List U8 × U32))
    : Prop :=
  RadixAdds dirs next
    (fun digit rows =>
      ∃ (j : Nat) (bound : j < path.length) (dir : Spike.radix.RadixDir),
        dirs.val[path[j].1.val - 1]? = some (some dir)
        ∧ digit = dir.digit
        ∧ rows = atDepth j)

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
          ∧ (RadixDirectoryInvariant dirs → RadixDirectoryInvariant next)
          ∧ RadixPathAdds dirs next path.val atDepth
          ∧ next.val.length ≤ dirs.val.length + path.val.length
          ∧ ∃ height, RadixTree next.val height root (atDepth 0)) := by
  have hone : (1#usize : Usize).val = 1 := rfl
  have hzero : (0#usize : Usize).val = 0 := rfl
  unfold Spike.radix.rebuild_path Spike.radix.rebuild_path_loop
  apply loop.spec_decr_nat
    (fun (p : DirArena × alloc.vec.Vec Usize × U32 × Usize) => p.2.2.2.val)
    (fun (current, avail, found, i) =>
      i.val ≤ path.val.length ∧ current.val.length + i.val ≤ 2147483647
      ∧ preservesSlots dirs current ∧ RadixFree current avail
      ∧ (RadixDirectoryInvariant dirs → RadixDirectoryInvariant current)
      ∧ RadixPathAdds dirs current path.val atDepth
      ∧ current.val.length + i.val ≤ dirs.val.length + path.val.length
      ∧ ∃ h, RadixTree current.val h found (atDepth i.val))
    _ _ _
  · rintro ⟨current, avail, found, i⟩ ⟨hi, cap, keep, hf, hinv, had, hgrowth, hfound⟩
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
      rintro ⟨root, updated, left⟩ ⟨holds, hleft, growth, inv, adds, hroot⟩
      change WP.spec (Result.ok (ControlFlow.cont (updated, left, root, j))) _
      simp only [WP.spec_ok]
      have added : RadixPathAdds dirs updated path.val atDepth := by
        intro ix d seen missing
        by_cases already : current.val[ix]? = some (some d)
        · obtain ⟨node, h, bs, hn, low, ht, allowed⟩ := had ix d already missing
          exact ⟨node, h, bs, hn, low, radix_tree_preserved current.val updated.val holds ht, allowed⟩
        · obtain ⟨node, h, bs, hn, low, ht, rows, dir, live, digit⟩ := adds ix d seen already
          obtain ⟨_, prior, hprior, _⟩ := shape
          have eq : dir = prior :=
            Option.some.inj (Option.some.inj (live.symm.trans (keep _ _ hprior)))
          exact ⟨node, h, bs, hn, low, ht, j.val, hb, prior, by simpa only [← hrow] using hprior,
            digit.trans (congrArg Spike.radix.RadixDir.digit eq), rows⟩
      exact ⟨⟨by omega, by omega, fun k dir hk => holds k dir (keep k dir hk), hleft, inv ∘ hinv,
        added, by omega, hroot⟩,
        by omega⟩
    · have hstop : ¬0 < i.val := go
      have hz : i.val = 0 := by omega
      simp only [go, ite_false, WP.spec_ok]
      exact ⟨keep, hf, hinv, had, by omega, hz ▸ hfound⟩
  · exact ⟨Nat.le_refl _, room, fun _ _ h => h, vacant, id, fun _ _ h no => (no h).elim,
      Nat.le_refl _, tip⟩

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

/-- The actual key associated with a live leaf link. -/
def radixKeyOf {V : Type} (rows : List (Option (Spike.radix.RadixRow V))) (leaf : U32)
    : Option (List U8) :=
  (radixRow rows leaf).map (·.key.val)

private theorem radix_keys_kept {V : Type}
    (old next : List (Option (Spike.radix.RadixRow V)))
    (kept
      : ∀ (i : Nat) previous,
          old[i]? = some (some previous) → next[i]? = some (some previous))
    : ∀ leaf key, radixKeyOf old leaf = some key → radixKeyOf next leaf = some key := by
  intro leaf key actual
  unfold radixKeyOf radixRow at actual ⊢
  cases he : old[leaf.val - 2147483648 - 1]? with
  | none => simp [he] at actual
  | some entry =>
      cases entry with
      | none => simp [he] at actual
      | some row =>
          simpa [kept _ _ he] using (show row.key.val = key from by simpa [he] using actual)

/-- Decode a tagged link to its live arena row. -/
theorem radix_row_at_matches {V : Type}
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
    (alloc.vec.Vec.deref row.key) key (fun a b => by simp))
  intro equal heq
  by_cases same : row.key.val = key.val <;> simp [heq, Slice.eq_iff, key_borrow_val, same]

theorem find_binding (bindings : List (List U8 × U32)) (key : List U8)
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

private def RadixEditSource (dirs : DirArena) (key : List U8) (cutoff : Option Usize)
    (replacement : Option U32) (original tip : Bindings) (entry : U32 × Usize)
    (above : Bindings)
    : Prop :=
  ∃ (h : Nat) (dir : Spike.radix.RadixDir) (source : Bindings),
    0 < entry.1.val
    ∧ entry.1 < 2147483648#u32
    ∧ dirs.val[entry.1.val - 1]? = some (some dir)
    ∧ RadixTree dirs.val h entry.1 source
    ∧ (∀ limit, cutoff = some limit → dir.digit < limit)
    ∧ above = radixEdit source key replacement
    ∧ (∀ row ∈ tip, row ∈ source)
    ∧ ∀ row ∈ source, row ∈ original

private theorem radix_walk_edit_plan (dirs : DirArena) (key : List U8)
    (replacement : Option U32) {cutoff : Option Usize} {root leaf : U32}
    {bindings tip : Bindings} {path : Path}
    (walk : RadixWalk dirs.val key cutoff root bindings leaf tip path)
    (invariant : RadixDirectoryInvariant dirs)
    : ∃ target : Nat → Bindings,
        target 0 = radixEdit bindings key replacement
        ∧ target path.length = radixEdit tip key replacement
        ∧ (∀ i (hi : i < path.length),
            RadixPathStep dirs path[i] (target (i + 1)) (target i))
        ∧ ∀ i (hi : i < path.length),
            RadixEditSource dirs key cutoff replacement bindings tip path[i]
              (target i) := by
  induction walk with
  | empty => exact ⟨fun _ => radixEdit [] key replacement, rfl, rfl, by simp, by simp⟩
  | leaf node stored _ =>
      exact ⟨
        fun _ => radixEdit [(stored, node)] key replacement,
        rfl,
        rfl,
        by simp,
        by simp
      ⟩
  | stop _ _ _ bindings =>
      exact ⟨fun _ => radixEdit bindings key replacement, rfl, rfl, by simp, by simp⟩
  | branch node dir bindings slot child leaf tail tip height positive low live before which chosen partition walk ih
    =>
      obtain ⟨after, hhead, htip, hsteps, sources⟩ := ih
      let target : Nat → Bindings
        | 0 => radixEdit bindings key replacement
        | i + 1 => after i
      refine ⟨target, rfl, htip, ?_, ?_⟩
      · intro i hi
        cases i with
        | succ i =>
            have hbound : i < tail.length := by simpa [List.length_cons] using hi
            exact hsteps i hbound
        | zero =>
            have hb : slot.val < 17 := which ▸ radixSymbol_bound _ _
            have rule := radix_safe_parent_of_invariant invariant node dir positive live
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
      · intro i hi
        cases i with
        | zero =>
            have tree :=
              radix_partition_tree dirs.val node dir height bindings positive low live
                partition
            exact ⟨
              _,
              dir,
              bindings,
              positive,
              low,
              live,
              tree,
              before,
              rfl,
              fun row hm =>
                (List.mem_filter.mp ((radix_walk_membership walk).1 row hm)).1,
              fun _ h => h
            ⟩
        | succ i =>
            have hbound : i < tail.length := by simpa [List.length_cons] using hi
            obtain ⟨h, d, bs, pos, small, found, tree, cut, edited, kept, hs⟩ :=
              sources i hbound
            exact ⟨h, d, bs, pos, small, found, tree, cut, edited, kept,
              fun row hm => (List.mem_filter.mp (hs row hm)).1⟩

theorem erase_absent (bindings : List (List U8 × U32)) (key : List U8)
    (absent : ∀ link, (key, link) ∉ bindings)
    : Kv.Model.erase bindings key = bindings := by
  apply List.filter_eq_self.mpr
  intro ⟨stored, link⟩ hm
  have he : stored ≠ key := fun eq => absent link (eq ▸ hm)
  simp [he]

private theorem radix_edit_member (bindings : Bindings) (key : List U8)
    (replacement : Option U32) (entry : List U8 × U32)
    (present : entry ∈ radixEdit bindings key replacement)
    : entry ∈ bindings ∨ ∃ leaf, replacement = some leaf ∧ entry = (key, leaf) := by
  cases replacement with
  | none => exact Or.inl (List.mem_filter.mp present).1
  | some leaf =>
      rcases List.mem_cons.mp present with new | old
      · exact Or.inr ⟨leaf, rfl, new⟩
      · exact Or.inl (List.mem_filter.mp old).1

private theorem radix_edit_keys (keyOf newKeyOf : U32 → Option (List U8))
    (bindings : Bindings) (key : List U8) (replacement : Option U32)
    (keys : ∀ row ∈ bindings, keyOf row.2 = some row.1)
    (old : ∀ leaf key, keyOf leaf = some key → newKeyOf leaf = some key)
    (fresh : ∀ leaf, replacement = some leaf → newKeyOf leaf = some key)
    : ∀ row ∈ radixEdit bindings key replacement, newKeyOf row.2 = some row.1 := by
  intro row hm
  rcases radix_edit_member bindings key replacement row hm with oldRow | ⟨leaf, hr, rfl⟩
  · exact old _ _ (keys row oldRow)
  · exact fresh leaf hr

private theorem radix_edit_prefix (bindings : Bindings) (key : List U8)
    (replacement : Option U32) (digit : Usize) (uniform : RadixPrefix digit bindings)
    (agrees
      : ∀ leaf,
          replacement = some leaf
          → ∀ row ∈ bindings,
              ∀ i, i < digit.val → radixSymbol key i = radixSymbol row.1 i)
    : RadixPrefix digit (radixEdit bindings key replacement) := by
  intro a ha b hb i hi
  rcases radix_edit_member bindings key replacement a ha with oldA | ⟨leafA, eqA, rfl⟩
  · rcases radix_edit_member bindings key replacement b hb with oldB | ⟨leafB, eqB, rfl⟩
    · exact uniform a oldA b oldB i hi
    · exact (agrees leafB eqB a oldA i hi).symm
  · rcases radix_edit_member bindings key replacement b hb with oldB | ⟨leafB, eqB, rfl⟩
    · exact agrees leafA eqA b oldB i hi
    · rfl

private theorem radix_path_adds_knowledge (dirs base next : DirArena)
    (keyOf newKeyOf : U32 → Option (List U8)) (key : List U8)
    (cutoff : Option Usize) (replacement : Option U32) (bindings tip : Bindings)
    (path : Path) (target : Nat → Bindings)
    (kept : preservesSlots dirs base)
    (sources
      : ∀ i (hi : i < path.length),
          RadixEditSource dirs key cutoff replacement bindings tip path[i] (target i))
    (added : RadixPathAdds base next path target)
    (compressed : RadixCompressed dirs.val keyOf)
    (keys : ∀ row ∈ bindings, keyOf row.2 = some row.1)
    (keysKept : ∀ leaf k, keyOf leaf = some k → newKeyOf leaf = some k)
    (keyAdded : ∀ leaf, replacement = some leaf → newKeyOf leaf = some key)
    (guide
      : ∀ leaf,
          replacement = some leaf
          → ∃ row ∈ tip,
              ∀ i,
                (∀ limit, cutoff = some limit → i < limit.val)
                → radixSymbol key i = radixSymbol row.1 i)
    : RadixAdds base next (KnowsRows newKeyOf) := by
  intro ix dir live absent
  obtain ⟨root, height, bs, index, low, tree, j, hbound, prior, hdir, digit, after⟩ :=
    added ix dir live absent
  obtain ⟨h, original, before, pos, tagged, atSlot, oldTree, cut, edited, contains, subset⟩ :=
    sources j hbound
  have same : prior = original := Option.some.inj (Option.some.inj (hdir.symm.trans (kept _ _ atSlot)))
  subst prior
  refine ⟨root, height, bs, index, low, tree, ?_⟩
  simp only [digit, after, edited]
  have actual : ∀ row ∈ before, keyOf row.2 = some row.1 := fun row hm => keys row (subset row hm)
  refine ⟨radix_edit_keys keyOf newKeyOf before key replacement actual keysKept keyAdded,
    radix_edit_prefix before key replacement original.digit
      (compressed h _ before original oldTree pos tagged atSlot actual) ?_⟩
  intro leaf eq row hm i hi
  obtain ⟨representative, ht, shared⟩ := guide leaf eq
  have hcond : ∀ limit, cutoff = some limit → i < limit.val := by
    intro limit he
    exact Nat.lt_trans hi (cut limit he)
  exact (shared i hcond).trans
    (compressed h _ before original oldTree pos tagged atSlot actual _ (contains _ ht) row
      hm i hi)

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
    (compressed : RadixCompressed dirs.val (radixKeyOf rows.val))
    (room : dirs.val.length + height ≤ 2147483647)
    : WP.spec (Spike.radix.remove dirs free rows scratch root key)
        (fun (next, arena, avail, _) =>
          preservesSlots dirs arena
          ∧ RadixFree arena avail
          ∧ RadixDirectoryInvariant arena
          ∧ (RadixKnowledge dirs (radixKeyOf rows.val)
              → RadixKnowledge arena (radixKeyOf rows.val))
          ∧ arena.val.length ≤ dirs.val.length + height
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
    exact ⟨reflexive, vacant, invariant, id, by omega, height, tree⟩
  · simp only [nz, ite_false]
    have present : (stored, leaf) ∈ tip := by simp [ht]
    obtain ⟨tagged, row, hrow, hk⟩ := valid (stored, leaf) (mem.1 _ present)
    apply WP.spec_bind (radix_check_leaf_spec rows leaf key row tagged hrow)
    intro output hout
    by_cases same : stored = key.val
    · have eq : output = some row.value := by simpa [hk, same] using hout
      simp only [eq, core.option.Option.is_none, Option.isNone_some, Bool.false_eq_true, ite_false]
      obtain ⟨target, head, tail, steps, sources⟩ := radix_walk_edit_plan dirs key.val none walk invariant
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
      rintro ⟨new, arena, avail⟩ ⟨keep, hf, inv, added, growth, hd⟩
      change WP.spec (Result.ok (new, arena, avail, path)) _
      simp only [WP.spec_ok]
      change preservesSlots dirs arena ∧ RadixFree arena avail ∧ RadixDirectoryInvariant arena ∧
        (RadixKnowledge dirs (radixKeyOf rows.val) → RadixKnowledge arena (radixKeyOf rows.val)) ∧
        arena.val.length ≤ dirs.val.length + height ∧
        (∃ h, RadixTree arena.val h new (radixEdit bindings key.val none))
      rw [← head]
      refine ⟨keep, hf, inv invariant, ?_, by omega, hd⟩
      intro known
      apply radix_knowledge_extend dirs arena _ _ known keep (fun _ _ h => h)
      apply radix_path_adds_knowledge dirs dirs arena _ _ key.val none none bindings tip path.val target
        reflexive sources (by simpa [input, alloc.vec.Vec.deref] using added) compressed
      · intro e hm
        obtain ⟨_, r, live, sameKey⟩ := valid e hm
        simp [radixKeyOf, live, sameKey]
      · exact fun _ _ h => h
      · simp
      · simp
    · have eq : output = none := by simpa [hk, same] using hout
      have he := erase_absent bindings key.val (fun link h => by
        have here := mem.2 link h
        rw [ht] at here
        exact same (congrArg Prod.fst (List.mem_singleton.mp here)).symm)
      simp only [eq, core.option.Option.is_none, Option.isNone_none, ite_true, WP.spec_ok, he]
      exact ⟨reflexive, vacant, invariant, id, by omega, height, tree⟩

/-- A cached representative is a leaf of the given directory's projection. -/
def RadixRepresentatives (dirs : List (Option Spike.radix.RadixDir)) : Prop :=
  ∀ height node bindings dir,
    RadixTree dirs height node bindings
    → 0 < node.val
    → node < 2147483648#u32
    → dirs[node.val - 1]? = some (some dir)
    → ∃ key, (key, dir.first) ∈ bindings

private theorem radix_cached_rep {dirs : DirArena}
    (invariant : RadixDirectoryInvariant dirs) {height : Nat} {root : U32}
    {bindings : Bindings} (tree : RadixTree dirs.val height root bindings)
    : if root = 0#u32 then
        True
      else if (2147483648#u32 : U32) ≤ root then
        ∃ key, (key, root) ∈ bindings
      else
        ∃ d,
          dirs.val[root.val - 1]? = some (some d) ∧ ∃ key, (key, d.first) ∈ bindings := by
  induction tree with
  | empty => simp
  | leaf _ node stored tag =>
      have nz : node ≠ 0#u32 := by
        intro hz
        subst node
        exact (by decide : ¬(2147483648#u32 : U32) ≤ 0#u32) tag
      simp [nz, tag]
  | branch height node dir bindings positive low live children links trees ih =>
      have nz : node ≠ 0#u32 := fun hz => by subst node; contradiction
      simp only [nz, ite_false, not_le_of_gt low]
      refine ⟨dir, live, ?_⟩
      have health := (invariant _ _ live).2.2.1
      obtain ⟨slot, atSlot⟩ := List.mem_iff_getElem?.mp (radix_first_mem dir health.1)
      have bound : slot < 17 := occupied_bound dir slot ⟨_, atSlot, health.1⟩
      have hchild : children slot = radixFirst dir :=
        Option.some.inj ((links slot bound).symm.trans atSlot)
      have first := ih slot bound
      rw [hchild, ite_eq_right health.1] at first
      by_cases tag : (2147483648#u32 : U32) ≤ radixFirst dir
      · rw [ite_eq_left tag] at first
        obtain ⟨k, hk⟩ := first
        have eq := health.2
        rw [ite_eq_left tag] at eq
        exact ⟨k, eq.symm ▸ (List.mem_filter.mp hk).1⟩
      · rw [ite_eq_right tag] at first
        obtain ⟨child, hDir, k, hk⟩ := first
        have hc := health.2
        rw [ite_eq_right tag] at hc
        obtain ⟨cached, hCache, eq⟩ := hc
        have same : cached = child :=
          Option.some.inj (Option.some.inj (hCache.symm.trans hDir))
        subst cached
        exact ⟨k, eq.symm ▸ (List.mem_filter.mp hk).1⟩

/-- The preserved first-child caches select real leaves of every finite projected root. -/
theorem radix_representatives_of_invariant
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (invariant : RadixDirectoryInvariant dirs)
    : RadixRepresentatives dirs.val := by
  intro height node bindings dir tree positive low lookup
  have nz : node ≠ 0#u32 := fun hz => by subst node; contradiction
  have h := radix_cached_rep invariant tree
  simp only [nz, ite_false, not_le_of_gt low] at h
  obtain ⟨d, live, chosen⟩ := h
  have same : d = dir := Option.some.inj (Option.some.inj (live.symm.trans lookup))
  exact same ▸ chosen

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

private theorem radix_tip_shared {dirs : List (Option Spike.radix.RadixDir)}
    {key : List U8} {digit : Usize} {keyOf : U32 → Option (List U8)}
    {root stem : U32} {bindings tip : Bindings} {path : Path}
    (walk : RadixWalk dirs key (some digit) root bindings stem tip path)
    (stored : List U8) (leaf : U32) (chosen : (stored, leaf) ∈ tip)
    (compressed : RadixCompressed dirs keyOf)
    (actual : ∀ e ∈ bindings, keyOf e.2 = some e.1)
    : ∀ entry ∈ tip,
        ∀ i, i < digit.val → radixSymbol stored i = radixSymbol entry.1 i := by
  induction walk with
  | empty => simp
  | leaf _ k _ =>
      have h : stored = k := congrArg Prod.fst (List.mem_singleton.mp chosen)
      intro entry he i hi
      rw [List.mem_singleton.mp he, h]
  | stop h node dir bs limit atCut later positive small live tree =>
      have sameCut : limit = digit := Option.some.inj atCut.symm
      subst limit
      exact fun entry he i hi => compressed h node bs dir tree positive small live
        actual (stored, leaf) chosen entry he i (Nat.lt_of_lt_of_le hi later)
  | branch _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ ih =>
      exact ih chosen (fun e hm => actual e (List.mem_filter.mp hm).1)

private theorem radix_prepare_fresh {V : Type}
    (dirs : Slice (Option Spike.radix.RadixDir))
    (rows : Slice (Option (Spike.radix.RadixRow V))) (path : alloc.vec.Vec (U32 × Usize))
    (root : U32) (key : Slice U8) (height : Nat) (bindings : Bindings)
    (tree : RadixTree dirs.val height root bindings)
    (reps : RadixRepresentatives dirs.val)
    (compressed : RadixCompressed dirs.val (radixKeyOf rows.val))
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
            ∧ InsertStem dirs.val key.val split.digit split.old_slot.val stem tip
            ∧ (∀ entry ∈ tip, entry ∈ bindings)
            ∧ (∃ guide ∈ tip,
                ∀ i, i < split.digit.val → radixSymbol key.val i = radixSymbol guide.1 i)
            ∧ ∀ entry ∈ tip,
                ∀ i,
                  i < split.digit.val
                  → radixSymbol key.val i = radixSymbol entry.1 i) := by
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
  apply WP.spec_bind
    (radix_first_difference_matches (alloc.vec.Vec.deref row.key) key
      (by simpa only [key_borrow_val] using fit))
  intro found hsplit
  simp only [key_borrow_val] at hsplit
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
      have actual : ∀ entry ∈ bindings, radixKeyOf rows.val entry.2 = some entry.1 := by
        intro entry hm
        obtain ⟨_, value, hr, hk⟩ := valid entry hm
        simp [radixKeyOf, hr, hk]
      have source :=
        classifies_stem walk stored leaf cut first.1 compressed actual
      have subset := (radix_walk_membership walk).1
      have agree : ∀ entry ∈ tip,
          ∀ i, i < digit.val → radixSymbol key.val i = radixSymbol entry.1 i := by
        have shared (i : Nat) (hi : i < digit.val) : radixSymbol key.val i = radixSymbol stored i :=
          (first.2 i hi).symm
        have stemUniform := radix_tip_shared walk stored leaf (rep_member cut) compressed actual
        exact fun entry hm i hi => (shared i hi).trans (stemUniform entry hm i hi)
      change WP.spec (do
        let old ← Spike.radix.symbol (alloc.vec.Vec.deref row.key) digit
        let new ← Spike.radix.symbol key digit
        Result.ok ((stem, some ({digit, old_slot := old, new_slot := new}
          : Spike.radix.InsertionSplit)), recorded)) _
      apply WP.spec_bind (radix_symbol_matches (alloc.vec.Vec.deref row.key) digit)
      intro old ho
      apply WP.spec_bind (radix_symbol_matches key digit)
      intro new hn
      have oldBound : old.val < 17 := ho ▸ radixSymbol_bound _ _
      have oldSlot : old.val = radixSymbol stored digit.val := by
        simpa only [key_borrow_val, same] using ho
      have different : old.val ≠ new.val := by rw [oldSlot, hn]; exact first.1
      simp only [WP.spec_ok]
      exact ⟨_, tip, rfl, length, hn, oldBound, different, walk, oldSlot ▸ source, subset,
        ⟨(stored, leaf), rep_member cut, fun i hi => (first.2 i hi).symm⟩, agree⟩

private theorem radix_split_directory_matches (dirs : Slice (Option Spike.radix.RadixDir))
    (stem : U32) (split : Spike.radix.InsertionSplit) (key : List U8) (tip : Bindings)
    (oldBound : split.old_slot.val < 17)
    (newSlot : split.new_slot.val = radixSymbol key split.digit.val)
    (different : split.old_slot.val ≠ split.new_slot.val)
    (source : InsertStem dirs.val key split.digit split.old_slot.val stem tip)
    (health
      : ∀ (i : Nat) d,
          dirs.val[i]? = some (some d) → RadixMask d ∧ ∃ slot, Occupied d slot)
    : WP.spec (Spike.radix.split_directory dirs stem split)
        (fun dir =>
          dir.digit = split.digit
          ∧ dir.children.val[split.new_slot.val]? = some 0#u32
          ∧ RadixMask dir
          ∧ (∃ slot, Occupied dir slot)
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
      have valid := health _ _ lookup
      exact ⟨trivial, newSlot ▸ vacant, valid.1, valid.2, h, eq ▸ parts⟩
  | wrap h _ _ oldTree nz later common =>
      have build
          : WP.spec
              (do
                let empty ← Spike.radix.RadixDir.empty split.digit
                Spike.radix.RadixDir.set_child empty split.old_slot stem)
              (fun dir =>
                dir.digit = split.digit
                ∧ dir.children.val[split.new_slot.val]? = some 0#u32
                ∧ RadixMask dir ∧ (∃ slot, Occupied dir slot)
                ∧ ∃ height,
                    RadixPartition dirs.val height dir.digit dir.children.val tip) := by
        apply WP.spec_bind (radix_empty_matches split.digit)
        intro empty ⟨hd, _, zero, hm⟩
        apply WP.spec_mono (radix_set_child_matches empty split.old_slot stem oldBound)
        intro dir ⟨same, _, children, mask⟩
        have digit : dir.digit = split.digit := same.trans hd
        have pointers :=
          children.trans (congrArg (fun xs => List.set xs split.old_slot.val stem) zero)
        have newBound : split.new_slot.val < 17 := newSlot ▸ radixSymbol_bound _ _
        refine ⟨digit, ?_, radix_updated_mask empty dir split.old_slot stem oldBound hm children mask,
          ⟨split.old_slot.val, stem, ?_, nz⟩, h, ?_⟩
        · rw [pointers, List.getElem?_set_ne different]
          rw [List.getElem?_replicate]
          simp [newBound]
        · rw [pointers, List.getElem?_set_self (by simpa using oldBound)]
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
    (invariant : RadixDirectoryInvariant dirs)
    (room : dirs.val.length < 2147483647)
    : WP.spec
        (do
          let dir ← Spike.radix.split_directory (alloc.vec.Vec.deref dirs) stem split
          let updated ← Spike.radix.RadixDir.set_child dir split.new_slot leaf
          let (root, next, avail) ← Spike.radix.add_directory dirs free updated
          Result.ok (next, avail, root, (none : Option U32)))
        (fun (next, avail, root, replaced) =>
          replaced = none
          ∧ preservesSlots dirs next
          ∧ RadixFree next avail
          ∧ next.val.length ≤ dirs.val.length + 1
          ∧ RadixDirectoryInvariant next
          ∧ RadixAdds dirs next
              (fun digit rows =>
                digit = split.digit ∧ rows = Kv.Model.set tip key leaf)
          ∧ ∃ h, RadixTree next.val h root (Kv.Model.set tip key leaf)) := by
  have hs : InsertStem (alloc.vec.Vec.deref dirs).val key split.digit
      split.old_slot.val stem tip := by simpa [alloc.vec.Vec.deref] using source
  apply WP.spec_bind
    (radix_split_directory_matches (alloc.vec.Vec.deref dirs) stem split key tip oldBound
      newSlot different hs
      (fun i d h => by
        have atSlot : dirs.val[i]? = some (some d) := by simpa [alloc.vec.Vec.deref] using h
        obtain ⟨hm, _, _, a, _, _, ha, _⟩ := invariant i d atSlot
        exact ⟨hm, a, ha⟩))
  intro dir ⟨hd, vacant, mask, ⟨sibling, siblingLink, hsibling, siblingNZ⟩, height, parts⟩
  have bound : split.new_slot.val < 17 := newSlot ▸ radixSymbol_bound _ _
  have hNew : radixSymbol key dir.digit.val = split.new_slot.val := by rw [hd, newSlot]
  obtain ⟨old, hOld, sub⟩ := parts split.new_slot.val bound
  have oldEmpty : old = 0#u32 := Option.some.inj (hOld.symm.trans vacant)
  have noRows := radix_tree_zero sub oldEmpty
  apply WP.spec_bind (radix_set_child_matches dir split.new_slot leaf bound)
  intro updated ⟨he, _, hc, hmask⟩
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
  have childLive : ∀ child ∈ updated.children.val, RadixDirLive dirs child := by
    intro child hp
    obtain ⟨slot, hslot⟩ := List.mem_iff_getElem?.mp hp
    have hlen : updated.children.val.length = 17 := Array.length_eq _
    have hs : slot < 17 := by
      by_contra tooBig
      have hbad : updated.children.val.length ≤ slot := by omega
      rw [List.getElem?_eq_none hbad] at hslot
      cases hslot
    obtain ⟨link, hchild, tree⟩ := part slot hs
    have eq := Option.some.inj (hchild.symm.trans hslot)
    exact eq ▸ radix_tree_live tree
  have firstLive := childLive _ (radix_first_mem updated nonempty)
  apply WP.spec_bind
    (radix_add_directory_matches dirs free updated available room nonempty
      (firstLive nonempty))
  rintro ⟨root, next, avail⟩
    ⟨pos, low, ⟨published, hroot, digit, directory, bitmap, cache⟩, keep, growth, valid, unchanged⟩
  change WP.spec (Result.ok (next, avail, root, none)) _
  simp only [WP.spec_ok]
  have pubParts : RadixPartition next.val height published.digit published.children.val
      (Kv.Model.set tip key leaf) := by
    intro i hi
    obtain ⟨c, get, tree⟩ := part i hi
    exact ⟨c, by simpa only [directory] using get, by
      simpa only [digit] using radix_tree_preserved dirs.val next.val keep tree⟩
  have newTree := radix_partition_tree next.val root published height (Kv.Model.set tip key leaf)
    pos low hroot pubParts
  refine ⟨trivial, keep, valid, growth, ?_, ?_, height + 1, newTree⟩
  · apply radix_extend_invariant invariant keep _ published hroot unchanged
    · intro i hi
      simpa only [directory, bitmap] using radix_updated_mask dir updated split.new_slot leaf
        bound mask hc hmask i hi
    · simpa only [directory] using childLive
    · exact cache
    · have differentSlot : split.new_slot.val ≠ sibling := by
        intro equal
        rw [← equal, vacant, Option.some.injEq] at hsibling
        exact siblingNZ hsibling.symm
      refine ⟨split.new_slot.val, sibling, differentSlot, ⟨leaf, ?_, hpos⟩,
        ⟨siblingLink, ?_, siblingNZ⟩⟩
      · simpa only [directory] using hAt
      · rw [directory, hc, List.getElem?_set_ne differentSlot]
        exact hsibling
  · intro i actual live absent
    have hi : i = root.val - 1 := by
      by_contra different
      exact absent ((unchanged i different).symm.trans live)
    have same : actual = published :=
      Option.some.inj (Option.some.inj (live.symm.trans (by rwa [hi])))
    subst actual
    exact ⟨root, height + 1, Kv.Model.set tip key leaf, by omega, low, newTree,
      digit.trans (he.trans hd), rfl⟩

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
    (radix_first_difference_matches (alloc.vec.Vec.deref old.key) key
      (by simpa [alloc.vec.Vec.deref, same] using keyRoom))
  intro difference hd
  cases difference with
  | some digit =>
      exfalso
      exact hd.1 (by rw [key_borrow_val, same])
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
    (same : old.key.val = row.key.val)
    (compressed : RadixCompressed dirs.val (radixKeyOf rows.val))
    (keys : ∀ e ∈ bindings, radixKeyOf rows.val e.2 = some e.1)
    (invariant : RadixDirectoryInvariant dirs) (availableDirs : RadixFree dirs freeDirs)
    (availableRows : RadixFree rows freeRows)
    (dirRoom : dirs.val.length + height ≤ 2147483647)
    (rowRoom : rows.val.length < 2147483647)
    (keyRoom : 2 * row.key.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.put dirs freeDirs rows freeRows scratch root row)
        (fun ((after, leaf, replaced), arena, avail, values, unused, _) =>
          preservesSlots dirs arena
          ∧ RadixFree arena avail
          ∧ RadixDirectoryInvariant arena
          ∧ (RadixKnowledge dirs (radixKeyOf rows.val)
              → RadixKnowledge arena (radixKeyOf values.val))
          ∧ RadixFree values unused
          ∧ (∀ (i : Nat) previous,
              rows.val[i]? = some (some previous) → values.val[i]? = some (some previous))
          ∧ replaced = some oldLeaf
          ∧ ∃ height,
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
  have hReps : RadixRepresentatives ds.val := by
    simpa [ds, alloc.vec.Vec.deref]
      using radix_representatives_of_invariant dirs invariant
  have hrow : radixRow rs.val oldLeaf = some old := by simpa [rs, alloc.vec.Vec.deref] using live
  apply WP.spec_bind
    (radix_prepare_existing ds rs scratch root oldLeaf (alloc.vec.Vec.deref row.key)
      height bindings hTree hReps (by simpa only [key_borrow_val] using present) nz old
      tagged hrow (by simpa only [key_borrow_val] using same) (by omega)
      (by simpa only [key_borrow_val] using keyRoom))
  rintro ⟨⟨stem, split⟩, path⟩ ⟨stemEq, none, depth, visit⟩
  subst split stem
  have walk
      : RadixWalk dirs.val row.key.val none root bindings oldLeaf [(row.key.val, oldLeaf)]
          path.val := by
    simpa [ds, alloc.vec.Vec.deref] using visit
  apply WP.spec_bind
    (radix_allocate_matches rows freeRows row availableRows (fun _ => by omega))
  rintro ⟨i, values, unused⟩ ⟨value, kept, _, eligible, _, free, _⟩
  apply WP.spec_bind (radix_link_matches i true (by omega))
  intro leaf hleaf
  have hlink : leaf.val = i.val + 1 + 2147483648 := by simpa using hleaf
  have htag : 2147483648 < leaf.val := by omega
  have hnew : radixRow values.val leaf = some row := by
    have hi : leaf.val - 2147483648 - 1 = i.val := by omega
    simp [radixRow, hi, value]
  obtain ⟨target, head, tail, steps, sources⟩ :=
    radix_walk_edit_plan dirs row.key.val (some leaf) walk invariant
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
  rintro ⟨new, arena, available⟩ ⟨keep, hdr, inv, adds, _, shape⟩
  change WP.spec (Result.ok ((new, leaf, some oldLeaf), arena, available, values, unused, path)) _
  simp only [WP.spec_ok]
  obtain ⟨h, hshape⟩ := shape
  rw [head] at hshape
  refine ⟨keep, hdr, inv invariant, ?_, free, kept, trivial, h, htag, hnew, hshape⟩
  intro known
  have keysKept := radix_keys_kept rows.val values.val kept
  apply radix_knowledge_extend dirs arena _ _ known keep keysKept
  apply radix_path_adds_knowledge dirs dirs arena _ _ row.key.val none (some leaf)
    bindings [(row.key.val, oldLeaf)] path.val target (fun _ _ h => h) sources
    (by simpa [input, alloc.vec.Vec.deref] using adds) compressed keys keysKept
  · intro q eq
    have sameLeaf : q = leaf := (Option.some.inj eq).symm
    simp [sameLeaf, radixKeyOf, hnew]
  · intro _ _
    exact ⟨(row.key.val, oldLeaf), List.mem_cons_self, fun _ _ => rfl⟩

/-- Inserting into an empty radix creates a single live leaf and no directories. -/
theorem radix_put_empty_matches {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) (freeDirs : alloc.vec.Vec Usize)
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow V)))
    (freeRows : alloc.vec.Vec Usize) (scratch : alloc.vec.Vec (U32 × Usize))
    (row : Spike.radix.RadixRow V) (available : RadixFree rows freeRows)
    (room : rows.val.length < 2147483647)
    : WP.spec (Spike.radix.put dirs freeDirs rows freeRows scratch 0#u32 row)
        (fun ((next, leaf, replaced), arena, avail, values, unused, path) =>
          arena = dirs
          ∧ avail = freeDirs
          ∧ path = scratch
          ∧ RadixFree values unused
          ∧ (∀ (i : Nat) previous,
              rows.val[i]? = some (some previous) → values.val[i]? = some (some previous))
          ∧ 2147483648 < leaf.val
          ∧ radixRow values.val leaf = some row
          ∧ replaced = none
          ∧ RadixTree arena.val 0 next [(row.key.val, leaf)]) := by
  have hmax : 2147483647 ≤ Usize.max := by scalar_tac
  unfold Spike.radix.put
  simp only [ite_true]
  apply WP.spec_bind
    (radix_allocate_matches rows freeRows row available (fun _ => by omega))
  rintro ⟨i, values, unused⟩ ⟨value, kept, _, eligible, _, free, _⟩
  apply WP.spec_bind (radix_link_matches i true (by omega))
  intro leaf hleaf
  have hlink : leaf.val = i.val + 1 + 2147483648 := by simpa using hleaf
  have htag : 2147483648 < leaf.val := by omega
  have hnew : radixRow values.val leaf = some row := by
    have hi : leaf.val - 2147483648 - 1 = i.val := by omega
    simp [radixRow, hi, value]
  simp only [WP.spec_ok]
  exact ⟨trivial, trivial, trivial, free, kept, htag, hnew, trivial,
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
    (compressed : RadixCompressed dirs.val (radixKeyOf rows.val))
    (invariant : RadixDirectoryInvariant dirs) (availableDirs : RadixFree dirs freeDirs)
    (availableRows : RadixFree rows freeRows)
    (dirRoom : dirs.val.length + height + 1 ≤ 2147483647)
    (rowRoom : rows.val.length < 2147483647)
    (keyRoom : 2 * row.key.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.put dirs freeDirs rows freeRows scratch root row)
        (fun ((after, leaf, replaced), arena, avail, values, unused, _) =>
          preservesSlots dirs arena
          ∧ RadixFree arena avail
          ∧ RadixDirectoryInvariant arena
          ∧ (RadixKnowledge dirs (radixKeyOf rows.val)
              → RadixKnowledge arena (radixKeyOf values.val))
          ∧ RadixFree values unused
          ∧ (∀ (i : Nat) previous,
              rows.val[i]? = some (some previous) → values.val[i]? = some (some previous))
          ∧ replaced = none
          ∧ ∃ height,
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
  have hReps : RadixRepresentatives ds.val := by
    simpa [ds, alloc.vec.Vec.deref]
      using radix_representatives_of_invariant dirs invariant
  have hCompressed : RadixCompressed ds.val (radixKeyOf rs.val) := by
    simpa [ds, rs, alloc.vec.Vec.deref] using compressed
  have hRows : ∀ entry ∈ bindings, 2147483648 < entry.2.val ∧
      ∃ value, radixRow rs.val entry.2 = some value ∧ value.key.val = entry.1 := by
    simpa [rs, alloc.vec.Vec.deref] using valid
  apply WP.spec_bind
    (radix_prepare_fresh ds rs scratch root (alloc.vec.Vec.deref row.key) height bindings
      hTree hReps hCompressed (by simpa only [key_borrow_val] using absent) nz hRows
      (by omega) (by simpa only [key_borrow_val] using keyRoom))
  rintro ⟨⟨stem, found⟩, path⟩
    ⟨split, tip, eq, depth, newSlot, oldBound, different, visit, source, subset, guide, common⟩
  subst found
  simp only [key_borrow_val] at newSlot guide common
  have walk
      : RadixWalk dirs.val row.key.val (some split.digit) root bindings stem tip
          path.val := by
    simpa [ds, alloc.vec.Vec.deref] using visit
  have hSource
      : InsertStem dirs.val row.key.val split.digit split.old_slot.val stem tip := by
    simpa [ds, alloc.vec.Vec.deref] using source
  apply WP.spec_bind
    (radix_allocate_matches rows freeRows row availableRows (fun _ => by omega))
  rintro ⟨i, values, unused⟩ ⟨value, kept, _, eligible, _, free, _⟩
  apply WP.spec_bind (radix_link_matches i true (by omega))
  intro leaf hleaf
  have hlink : leaf.val = i.val + 1 + 2147483648 := by simpa using hleaf
  have htag : 2147483648 < leaf.val := by omega
  have hnew : radixRow values.val leaf = some row := by
    have hi : leaf.val - 2147483648 - 1 = i.val := by omega
    simp [radixRow, hi, value]
  obtain ⟨target, head, tail, steps, sources⟩ :=
    radix_walk_edit_plan dirs row.key.val (some leaf) walk invariant
  have publishTip := radix_insert_tip dirs freeDirs stem leaf split row.key.val tip oldBound
    newSlot different hSource (Nat.le_of_lt htag) availableDirs invariant (by omega)
  apply WP.spec_bind publishTip
  rintro ⟨newDirs, freeNext, child, replaced⟩
    ⟨hr, keeps, nextFree, growth, invTip, addedTip, subtree⟩
  subst replaced
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
  rintro ⟨new, arena, available⟩ ⟨keep, hdr, inv, adds, _, shape⟩
  change WP.spec (Result.ok ((new, leaf, none), arena, available, values, unused, path)) _
  simp only [WP.spec_ok]
  obtain ⟨h, hshape⟩ := shape
  rw [head] at hshape
  have keyBefore : ∀ e ∈ bindings, radixKeyOf rows.val e.2 = some e.1 := by
    intro e hm
    obtain ⟨_, item, old, eq⟩ := valid e hm
    simp [radixKeyOf, old, eq]
  have keysKept := radix_keys_kept rows.val values.val kept
  have keyAdded : ∀ q, (some leaf : Option U32) = some q →
      radixKeyOf values.val q = some row.key.val := by
    intro q eq
    have sameLeaf : q = leaf := (Option.some.inj eq).symm
    simp [sameLeaf, radixKeyOf, hnew]
  refine ⟨fun j dir present => keep j dir (keeps j dir present), hdr, inv invTip, ?_,
    free, kept, trivial, h, htag, hnew, hshape⟩
  intro known
  have routeAddition : RadixAdds newDirs arena (KnowsRows (radixKeyOf values.val)) := by
    apply radix_path_adds_knowledge dirs newDirs arena _ _ row.key.val (some split.digit)
      (some leaf) bindings tip path.val target keeps sources
      (by simpa [input, alloc.vec.Vec.deref] using adds)
      compressed keyBefore keysKept keyAdded
    intro _ _
    obtain ⟨e, hm, shared⟩ := guide
    exact ⟨e, hm, fun i hi => shared i (hi split.digit rfl)⟩
  have tipAddition : RadixAdds dirs newDirs (KnowsRows (radixKeyOf values.val)) := by
    intro ix d live absent
    obtain ⟨node, height, bs, index, low, newTree, digit, outcome⟩ := addedTip ix d live absent
    refine ⟨node, height, bs, index, low, newTree, ?_⟩
    rw [digit, outcome]
    have original : ∀ e ∈ tip, radixKeyOf rows.val e.2 = some e.1 :=
      fun e hm => keyBefore e (subset e hm)
    have uniform : RadixPrefix split.digit tip := by
      intro a ha b hb i hi
      exact (common a ha i hi).symm.trans (common b hb i hi)
    exact ⟨radix_edit_keys _ _ tip row.key.val (some leaf) original keysKept keyAdded,
      radix_edit_prefix tip row.key.val (some leaf) split.digit uniform (fun _ _ => common)⟩
  have mid := radix_knowledge_extend dirs newDirs _ _ known keeps keysKept tipAddition
  exact radix_knowledge_extend newDirs arena _ _ mid keep (fun _ _ h => h) routeAddition

/-- All projected leaf links refer to live rows bearing the projected keys. -/
def RadixRows {V : Type} (rows : List (Option (Spike.radix.RadixRow V)))
    (bindings : List (List U8 × U32))
    : Prop :=
  ∀ entry ∈ bindings,
    2147483648 < entry.2.val
    ∧ ∃ row, radixRow rows entry.2 = some row ∧ row.key.val = entry.1

/-- The actual values, in the order required by the model, not directory traversal order. -/
def radixBindings {V : Type} (rows : List (Option (Spike.radix.RadixRow V)))
    (bindings : List (List U8 × U32))
    : List (List U8 × V) :=
  bindings.filterMap
    fun (key, leaf) => (radixRow rows leaf).map (fun row => (key, row.value))

private theorem radix_project_find {V : Type}
    (rows : List (Option (Spike.radix.RadixRow V))) (bindings : Bindings) (key : List U8)
    (valid : RadixRows rows bindings)
    : Kv.Model.find (radixBindings rows bindings) key
      = (Kv.Model.find bindings key).bind
          fun leaf =>
            (radixRow rows leaf).map Spike.radix.RadixRow.value := by
  induction bindings with
  | nil => rfl
  | cons p tail ih =>
      obtain ⟨stored, leaf⟩ := p
      obtain ⟨_, row, live, _⟩ := valid (stored, leaf) List.mem_cons_self
      have ht := ih (fun x hm => valid x (List.mem_cons_of_mem _ hm))
      have cons : radixBindings rows ((stored, leaf) :: tail) =
          (stored, row.value) :: radixBindings rows tail := by
        simp [radixBindings, live]
      rw [cons]
      by_cases hz : stored = key
      · simp [Kv.Model.find, hz, live]
      · simpa only [Kv.Model.find, hz, ite_false] using ht

/-- The native get is exactly lookup on the projected byte keys and their real values. -/
theorem radix_get_refines {V : Type} (dirs : Slice (Option Spike.radix.RadixDir))
    (rows : Slice (Option (Spike.radix.RadixRow V))) (key : Slice U8)
    (height : Nat) (root : U32) (bindings : List (List U8 × U32))
    (tree : RadixTree dirs.val height root bindings) (valid : RadixRows rows.val bindings)
    : WP.spec (Spike.radix.get dirs rows root key)
        (· = Kv.Model.find (radixBindings rows.val bindings) key.val) := by
  rw [radix_project_find rows.val bindings key.val valid]
  exact radix_get_matches dirs rows key height root bindings tree valid

/-- Preserving live arena slots preserves the decoded value of a retained leaf. -/
theorem radix_old_row {V : Type}
    (old next : List (Option (Spike.radix.RadixRow V)))
    (kept : ∀ (i : Nat) row, old[i]? = some (some row) → next[i]? = some (some row))
    (leaf : U32) (row : Spike.radix.RadixRow V) (live : radixRow old leaf = some row)
    : radixRow next leaf = some row := by
  unfold radixRow at live ⊢
  cases he : old[leaf.val - 2147483648 - 1]? with
  | none => simp [he] at live
  | some entry =>
      have eq : entry = some row := by simpa [he] using live
      rw [eq] at he
      rw [kept _ _ he, Option.join_some]

private theorem radix_old_projection {V : Type}
    (old next : List (Option (Spike.radix.RadixRow V)))
    (kept : ∀ (i : Nat) row, old[i]? = some (some row) → next[i]? = some (some row))
    (bindings : Bindings) (valid : RadixRows old bindings)
    : RadixRows next bindings
      ∧ radixBindings next bindings = radixBindings old bindings := by
  constructor
  · intro entry hm
    obtain ⟨tagged, row, live, hk⟩ := valid entry hm
    exact ⟨tagged, row, radix_old_row old next kept _ _ live, hk⟩
  · unfold radixBindings
    apply List.filterMap_congr
    intro entry hm
    obtain ⟨_, row, live, _⟩ := valid entry hm
    have after := radix_old_row old next kept _ _ live
    obtain ⟨key, leaf⟩ := entry
    simp [after, live]

/-- Projecting the retained rows commutes with erasing by key. -/
theorem radix_project_erase {V : Type} (rows : List (Option (Spike.radix.RadixRow V)))
    (bindings : List (List U8 × U32)) (key : List U8)
    : radixBindings rows (Kv.Model.erase bindings key)
      = Kv.Model.erase (radixBindings rows bindings) key := by
  induction bindings with
  | nil => rfl
  | cons p tail ih =>
      obtain ⟨stored, leaf⟩ := p
      by_cases same : stored = key <;> cases href : radixRow rows leaf <;>
        simp [Kv.Model.erase, radixBindings, same, href] at ih ⊢ <;> exact ih

/-- Retained roots keep the same bindings even when subsequent writes reuse free slots. -/
theorem radix_preserves_roots {V : Type}
    (dirs nextDirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (rows nextRows : alloc.vec.Vec (Option (Spike.radix.RadixRow V)))
    (keepDirs : preservesSlots dirs nextDirs)
    (keepRows
      : ∀ (i : Nat) row,
          rows.val[i]? = some (some row) → nextRows.val[i]? = some (some row))
    (height : Nat) (root : U32) (bindings : List (List U8 × U32))
    (tree : RadixTree dirs.val height root bindings) (valid : RadixRows rows.val bindings)
    : RadixTree nextDirs.val height root bindings
      ∧ RadixRows nextRows.val bindings
      ∧ radixBindings nextRows.val bindings = radixBindings rows.val bindings :=
  ⟨
    radix_tree_preserved dirs.val nextDirs.val keepDirs tree,
    radix_old_projection rows.val nextRows.val keepRows bindings valid
  ⟩

private theorem radix_rows_erase {V : Type}
    (rows : List (Option (Spike.radix.RadixRow V))) (bindings : Bindings) (key : List U8)
    (valid : RadixRows rows bindings)
    : RadixRows rows (Kv.Model.erase bindings key) :=
  fun entry hm => valid entry (List.mem_filter.mp hm).1

private theorem radix_project_set {V : Type}
    (old next : List (Option (Spike.radix.RadixRow V)))
    (kept : ∀ (i : Nat) row, old[i]? = some (some row) → next[i]? = some (some row))
    (bindings : Bindings) (leaf : U32) (row : Spike.radix.RadixRow V)
    (valid : RadixRows old bindings) (tagged : 2147483648 < leaf.val)
    (inserted : radixRow next leaf = some row)
    : RadixRows next (Kv.Model.set bindings row.key.val leaf)
      ∧ radixBindings next (Kv.Model.set bindings row.key.val leaf)
        = Kv.Model.set (radixBindings old bindings) row.key.val row.value := by
  obtain ⟨available, same⟩ := radix_old_projection old next kept bindings valid
  constructor
  · intro entry hm
    rcases List.mem_cons.mp hm with he | inherited
    · subst entry
      exact ⟨tagged, row, inserted, rfl⟩
    · exact radix_rows_erase next bindings row.key.val available entry inherited
  · have prepend : radixBindings next (Kv.Model.set bindings row.key.val leaf) =
        (row.key.val, row.value) :: radixBindings next (Kv.Model.erase bindings row.key.val) := by
      simp [Kv.Model.set, radixBindings, inserted]
    rw [prepend, radix_project_erase, same]
    rfl

/-- Delete the key from the ordered value projection, leaving every retained directory intact. -/
theorem radix_remove_refines {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) (free : alloc.vec.Vec Usize)
    (rows : Slice (Option (Spike.radix.RadixRow V)))
    (scratch : alloc.vec.Vec (U32 × Usize)) (root : U32) (key : Slice U8) (height : Nat)
    (bindings : List (List U8 × U32)) (tree : RadixTree dirs.val height root bindings)
    (valid : RadixRows rows.val bindings) (vacant : RadixFree dirs free)
    (invariant : RadixDirectoryInvariant dirs)
    (compressed : RadixCompressed dirs.val (radixKeyOf rows.val))
    (room : dirs.val.length + height ≤ 2147483647)
    : WP.spec (Spike.radix.remove dirs free rows scratch root key)
        (fun (next, arena, avail, _) =>
          preservesSlots dirs arena
          ∧ RadixFree arena avail
          ∧ RadixDirectoryInvariant arena
          ∧ (RadixKnowledge dirs (radixKeyOf rows.val)
              → RadixKnowledge arena (radixKeyOf rows.val))
          ∧ arena.val.length ≤ dirs.val.length + height
          ∧ ∃ h,
              RadixTree arena.val h next (Kv.Model.erase bindings key.val)
              ∧ RadixRows rows.val (Kv.Model.erase bindings key.val)
              ∧ radixBindings rows.val (Kv.Model.erase bindings key.val)
                = Kv.Model.erase (radixBindings rows.val bindings) key.val) := by
  apply WP.spec_mono (radix_remove_matches dirs free rows scratch root key height bindings
    tree valid vacant invariant compressed room)
  rintro ⟨next, arena, avail, _⟩ ⟨keep, avail, invariant, knows, growth, h, tree⟩
  exact ⟨keep, avail, invariant, knows, growth, h, tree,
    radix_rows_erase rows.val bindings key.val valid, radix_project_erase rows.val bindings key.val⟩

/-- Every case of native put refines the same ordered association-list update.
The bounds reserve room for the path copy and the optional new split directory. -/
theorem radix_put_refines {V : Type} (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (freeDirs : alloc.vec.Vec Usize)
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow V)))
    (freeRows : alloc.vec.Vec Usize) (scratch : alloc.vec.Vec (U32 × Usize)) (root : U32)
    (row : Spike.radix.RadixRow V) (height : Nat) (bindings : List (List U8 × U32))
    (tree : RadixTree dirs.val height root bindings) (valid : RadixRows rows.val bindings)
    (compressed : RadixCompressed dirs.val (radixKeyOf rows.val))
    (invariant : RadixDirectoryInvariant dirs) (availableDirs : RadixFree dirs freeDirs)
    (availableRows : RadixFree rows freeRows)
    (dirRoom : dirs.val.length + height + 1 ≤ 2147483647)
    (rowRoom : rows.val.length < 2147483647)
    (keyRoom : 2 * row.key.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.put dirs freeDirs rows freeRows scratch root row)
        (fun ((next, leaf, replaced), arena, avail, values, unused, _) =>
          preservesSlots dirs arena
          ∧ RadixFree arena avail
          ∧ RadixDirectoryInvariant arena
          ∧ (RadixKnowledge dirs (radixKeyOf rows.val)
              → RadixKnowledge arena (radixKeyOf values.val))
          ∧ RadixFree values unused
          ∧ (∀ (i : Nat) previous,
              rows.val[i]? = some (some previous) → values.val[i]? = some (some previous))
          ∧ replaced = Kv.Model.find bindings row.key.val
          ∧ radixRow values.val leaf = some row
          ∧ ∃ h,
              RadixTree arena.val h next (Kv.Model.set bindings row.key.val leaf)
              ∧ RadixRows values.val (Kv.Model.set bindings row.key.val leaf)
              ∧ radixBindings values.val (Kv.Model.set bindings row.key.val leaf)
                = Kv.Model.set (radixBindings rows.val bindings) row.key.val
                    row.value) := by
  by_cases zero : root = 0#u32
  · have empty := radix_tree_zero tree zero
    subst bindings root
    apply WP.spec_mono (radix_put_empty_matches dirs freeDirs rows freeRows scratch row
      availableRows rowRoom)
    rintro ⟨⟨next, leaf, replaced⟩, arena, avail, values, unused, _⟩
      ⟨hd, hf, _, vacant, kept, tagged, inserted, hr, ht⟩
    subst arena avail
    have hp := radix_project_set rows.val values.val kept [] leaf row valid tagged inserted
    exact ⟨fun _ _ h => h, availableDirs, invariant,
      (fun h => radix_knowledge_extend dirs dirs _ _ h (fun _ _ hk => hk)
        (radix_keys_kept rows.val values.val kept) (fun _ _ live absent => (absent live).elim)),
      vacant, kept, hr, inserted, 0, ht, hp.1, hp.2⟩
  · have h := find_binding bindings row.key.val
    cases hf : Kv.Model.find bindings row.key.val with
    | none =>
        have absent : ∀ leaf, (row.key.val, leaf) ∉ bindings := by simpa only [hf] using h
        apply WP.spec_mono
          (radix_put_fresh_matches dirs freeDirs rows freeRows scratch root row height
            bindings tree zero absent valid compressed invariant availableDirs
            availableRows dirRoom rowRoom keyRoom)
        rintro ⟨⟨next, leaf, replaced⟩, arena, avail, values, unused, _⟩
          ⟨keep, av, inv, knows, vacant, kept, hr, h, tag, ins, ht⟩
        exact ⟨
          keep,
          av,
          inv,
          knows,
          vacant,
          kept,
          hr,
          ins,
          h,
          ht,
          radix_project_set rows.val values.val kept bindings leaf row valid tag ins
        ⟩
    | some leaf =>
        have present : (row.key.val, leaf) ∈ bindings := by simpa only [hf] using h
        obtain ⟨tagged, old, live, same⟩ := valid (row.key.val, leaf) present
        apply WP.spec_mono
          (radix_put_existing_matches dirs freeDirs rows freeRows scratch root row height
            bindings leaf tree present old tagged live same compressed
            (fun e hm => by
              obtain ⟨_, r, hr, hk⟩ := valid e hm
              simp [radixKeyOf, hr, hk])
            invariant availableDirs availableRows
            (by omega)
            rowRoom keyRoom)
        rintro ⟨⟨next, added, replaced⟩, arena, avail, values, unused, _⟩
          ⟨keep, av, inv, knows, vacant, kept, hr, h, tag, ins, ht⟩
        exact ⟨
          keep,
          av,
          inv,
          knows,
          vacant,
          kept,
          hr,
          ins,
          h,
          ht,
          radix_project_set rows.val values.val kept bindings added row valid tag ins
        ⟩

/-- A finite radix has a unique set of key/link bindings once the keys of its
live rows are fixed. The model may impose a separate observation order. -/
theorem radix_projection_membership (dirs : List (Option Spike.radix.RadixDir))
    (keyOf : U32 → Option (List U8)) (root : U32)
    (h₁ h₂ : Nat) (a b : List (List U8 × U32))
    (t₁ : RadixTree dirs h₁ root a) (t₂ : RadixTree dirs h₂ root b)
    (keys₁ : ∀ row ∈ a, keyOf row.2 = some row.1)
    (keys₂ : ∀ row ∈ b, keyOf row.2 = some row.1)
    : ∀ row, row ∈ a ↔ row ∈ b := by
  induction t₁ generalizing h₂ b with
  | empty =>
      rw [radix_tree_zero t₂ rfl]
      intro row
      rfl
  | leaf _ node key tagged =>
      cases t₂ with
      | empty => exact (by decide : ¬(2147483648#u32 : U32) ≤ 0#u32) tagged |>.elim
      | leaf _ _ stored _ =>
          have hkey := keys₁ (key, node) List.mem_cons_self
          have hstored := keys₂ (stored, node) List.mem_cons_self
          have same : key = stored := Option.some.inj (hkey.symm.trans hstored)
          subst stored
          simp
      | branch _ _ _ _ _ low _ _ _ _ => exact (not_lt_of_ge tagged low).elim
  | branch h node dir rows pos low live choose lookup subtrees ih =>
      cases t₂ with
      | empty => exact (by decide : ¬0 < (0#u32 : U32).val) pos |>.elim
      | leaf _ _ _ tag => exact (not_lt_of_ge tag low).elim
      | branch depth _ other bs _ _ hdir choose' lookup' subtrees' =>
          have same : other = dir :=
            Option.some.inj (Option.some.inj (hdir.symm.trans live))
          subst other
          intro row
          let slot := radixSymbol row.1 dir.digit.val
          have bound : slot < 17 := radixSymbol_bound _ _
          have hc : choose' slot = choose slot :=
            Option.some.inj ((lookup' slot bound).symm.trans (lookup slot bound))
          have t := subtrees' slot bound
          rw [hc] at t
          have hm := ih slot bound depth _ t
            (fun entry h => keys₁ entry (List.mem_filter.mp h).1)
            (fun entry h => keys₂ entry (List.mem_filter.mp h).1) row
          simpa [slot] using hm

theorem radix_empty_knowledge (keyOf : U32 → Option (List U8))
    : RadixKnowledge (alloc.vec.Vec.new _) keyOf := by
  intro i d h
  simp at h

theorem radix_compressed_of_knowledge (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (keyOf : U32 → Option (List U8)) (known : RadixKnowledge dirs keyOf)
    : RadixCompressed dirs.val keyOf := by
  intro height root bindings dir tree pos low live keys a ha b hb i hi
  obtain ⟨node, h, bs, idx, _, witness, actual, uniform⟩ := known _ _ live
  have same : node = root := UScalar.eq_of_val_eq (by omega)
  subst node
  have mem := radix_projection_membership dirs.val keyOf root height h bindings bs
    tree witness keys actual
  exact uniform a ((mem a).mp ha) b ((mem b).mp hb) i hi

private theorem radix_group_slots {α : Type} (rows : List α) (slot : α → Nat) (n : Nat)
    : List.Perm ((List.range n).flatMap fun i => rows.filter (fun row => slot row == i))
        (rows.filter (fun row => decide (slot row < n))) := by
  induction n with
  | zero => simp
  | succ n ih =>
      rw [List.range_succ, List.flatMap_append]
      have hsplit := List.filter_append_perm (fun row => decide (slot row < n))
        (rows.filter fun row => decide (slot row < n + 1))
      have before :
          (rows.filter (fun row => decide (slot row < n + 1))).filter
            (fun row => decide (slot row < n)) = rows.filter (fun row => decide (slot row < n)) := by
        rw [List.filter_filter]
        apply List.filter_congr
        intro row _
        by_cases h : slot row < n
        · simp [h, show slot row < n + 1 by omega]
        · simp [h]
      have last :
          (rows.filter (fun row => decide (slot row < n + 1))).filter
            (fun row => !decide (slot row < n)) = rows.filter (fun row => slot row == n) := by
        rw [List.filter_filter]
        apply List.filter_congr
        intro row _
        by_cases he : slot row = n
        · simp [he]
        · by_cases hlt : slot row < n
          · simp [he, hlt]
          · have hb : ¬ slot row < n + 1 := by omega
            simp [he, hb]
      rw [before, last] at hsplit
      simpa only [List.flatMap_cons, List.flatMap_nil, List.append_nil]
        using (ih.append_right (rows.filter (fun row => slot row == n))).trans hsplit

private theorem radix_push_children (stack : alloc.vec.Vec U32)
    (dir : Spike.radix.RadixDir) (room : stack.val.length + 17 ≤ Usize.max)
    : WP.spec (Spike.radix.push_children stack dir)
        (fun result =>
          result.val = stack.val ++ (dir.children.val.filter (· != 0#u32)).reverse) := by
  let live := fun (link : U32) => link != 0#u32
  let goal := stack.val ++ (dir.children.val.filter live).reverse
  have size : dir.children.val.length = 17 := Array.length_eq dir.children
  have one : (1#usize : Usize).val = 1 := rfl
  have zero : (0#usize : Usize).val = 0 := rfl
  unfold Spike.radix.push_children Spike.radix.push_children_loop
  apply loop.spec_decr_nat (fun (p : alloc.vec.Vec U32 × Usize) => p.2.val)
    (fun p => p.2.val ≤ 17 ∧ p.1.val.length + p.2.val ≤ Usize.max
      ∧ p.1.val ++ ((dir.children.val.take p.2.val).filter live).reverse = goal)
    _ _ _
  · rintro ⟨current, slot⟩ ⟨bound, cap, done⟩
    dsimp only at bound cap done ⊢
    unfold Spike.radix.push_children_loop.body
    by_cases go : slot > 0#usize
    · rw [ite_eq_left go]
      have pos : 0 < slot.val := go
      apply WP.spec_bind (Usize.sub_spec (by omega : (1#usize : Usize).val ≤ slot.val))
      intro prev hp
      have step : slot.val = prev.val + 1 := by omega
      have index : prev.val < dir.children.val.length := by omega
      apply WP.spec_bind (Array.index_usize_spec dir.children prev index)
      intro child hc
      have split : dir.children.val.take slot.val = dir.children.val.take prev.val ++ [child] := by
        rw [step, List.take_succ_eq_append_getElem index, ← hc]
      rw [split, List.filter_append, List.reverse_append, ← List.append_assoc] at done
      by_cases isZero : child = 0#u32
      · have test : (child != 0#u32) = false := by simp [isZero]
        simp only [live, List.filter_cons, List.filter_nil, test, Bool.false_eq_true, ite_false,
          List.reverse_nil, List.append_nil] at done
        simp only [test, Bool.false_eq_true, ite_false, WP.spec_ok]
        exact ⟨⟨by omega, by omega, done⟩, by omega⟩
      · have nonzero : (child != 0#u32) = true := bne_iff_ne.mpr isZero
        simp only [nonzero, ite_true]
        apply WP.spec_bind (alloc.vec.Vec.push_spec current child (by omega))
        intro next hn
        have hlength : next.val.length = current.val.length + 1 := by simp [hn]
        simp only [WP.spec_ok]
        refine ⟨⟨by omega, by omega, ?_⟩, by omega⟩
        rw [hn]
        simpa only [live, List.filter_cons, List.filter_nil, nonzero, ite_true,
          List.reverse_singleton] using done
    · have stopped : ¬ 0 < slot.val := go
      have zz : slot.val = 0 := by omega
      simp only [go, ite_false, WP.spec_ok]
      simpa [zz, goal, live] using done
  · have full : dir.children.val.take 17 = dir.children.val := List.take_of_length_le size.le
    simp [Spike.radix.RADIX_FANOUT, full, room, goal]

/-- A finite traversal of live stack entries, in pop order. A directory
reserves room to push all its child slots. -/
inductive RadixScanPlan (dirs : List (Option Spike.radix.RadixDir))
    : List U32 → Nat → List U32 → Prop where
  | done : RadixScanPlan dirs [] 0 []
  | leaf (node : U32) (rest : List U32) (fuel : Nat) (leaves : List U32)
    (tagged : (2147483648#u32 : U32) ≤ node)
    (tail : RadixScanPlan dirs rest fuel leaves)
    : RadixScanPlan dirs (node :: rest) (fuel + 1) (node :: leaves)
  | branch (node : U32) (dir : Spike.radix.RadixDir)
    (rest : List U32) (fuel : Nat) (leaves : List U32)
    (positive : 0 < node.val) (untagged : node < 2147483648#u32)
    (live : dirs[node.val - 1]? = some (some dir))
    (tail : RadixScanPlan dirs (dir.children.val.filter (· != 0#u32) ++ rest) fuel leaves)
    : RadixScanPlan dirs (node :: rest) (fuel + 17) leaves

private theorem scan_plan_unique {dirs : List (Option Spike.radix.RadixDir)}
    {stack : List U32} {f g : Nat} {xs ys : List U32}
    (first : RadixScanPlan dirs stack f xs) (second : RadixScanPlan dirs stack g ys)
    : f = g ∧ xs = ys := by
  induction first generalizing g ys with
  | done =>
      cases second
      exact ⟨rfl, rfl⟩
  | leaf node rest fuel leaves tagged _ ih =>
      cases second with
      | leaf _ _ other out _ tail =>
          obtain ⟨same, eq⟩ := ih tail
          exact ⟨congrArg (· + 1) same, congrArg (node :: ·) eq⟩
      | branch _ _ _ _ _ _ untagged _ _ =>
          exact (not_lt_of_ge tagged untagged).elim
  | branch node dir rest fuel leaves positive untagged live _ ih =>
      cases second with
      | leaf _ _ _ _ tagged _ =>
          exact (not_lt_of_ge tagged untagged).elim
      | branch _ other _ _ _ _ _ saved tail =>
          have eq := Option.some.inj (Option.some.inj (live.symm.trans saved))
          subst other
          obtain ⟨same, eq⟩ := ih tail
          exact ⟨congrArg (· + 17) same, eq⟩

private theorem scan_plan_room {dirs : List (Option Spike.radix.RadixDir)}
    {stack : List U32} {fuel : Nat} {leaves : List U32}
    (plan : RadixScanPlan dirs stack fuel leaves)
    : stack.length ≤ fuel := by
  induction plan with
  | done => simp
  | leaf _ _ _ _ _ _ ih => simpa only [List.length_cons] using Nat.succ_le_succ ih
  | branch _ _ _ _ _ _ _ _ _ ih =>
      simp only [List.length_append] at ih
      simp only [List.length_cons]
      omega

private theorem scan_plan_append {dirs : List (Option Spike.radix.RadixDir)}
    {a b : List U32} {m n : Nat} {xs ys : List U32}
    (head : RadixScanPlan dirs a m xs) (tail : RadixScanPlan dirs b n ys)
    : RadixScanPlan dirs (a ++ b) (m + n) (xs ++ ys) := by
  induction head with
  | done => simpa using tail
  | leaf node rest fuel leaves tagged _ ih =>
      simpa only [List.cons_append, Nat.add_right_comm fuel 1 n]
        using RadixScanPlan.leaf node (rest ++ b) (fuel + n) (leaves ++ ys) tagged ih
  | branch node dir rest fuel leaves positive untagged live _ ih =>
      simpa only [List.cons_append, Nat.add_right_comm fuel 17 n]
        using RadixScanPlan.branch node dir (rest ++ b) (fuel + n) (leaves ++ ys)
          positive untagged live (by simpa only [List.append_assoc] using ih)

def radixKeyLt (a b : List U8 × U32) : Prop :=
  byteOrder a.1 b.1 = (-1)#i8

private theorem scan_plan_slots (dirs : List (Option Spike.radix.RadixDir))
    (slots : List Nat) (child : Nat → U32) (bindings : Nat → Bindings)
    (sortedSlots : slots.Pairwise (· < ·)) (ordered : Prop)
    (separated
      : ordered → ∀ i j, i < j → ∀ a ∈ bindings i, ∀ b ∈ bindings j, radixKeyLt a b)
    (available
      : ∀ i ∈ slots,
          ∃ fuel rows,
            RadixScanPlan dirs ([child i].filter (· != 0#u32)) fuel (rows.map Prod.snd)
            ∧ List.Perm rows (bindings i)
            ∧ (ordered → rows.Pairwise radixKeyLt))
    : ∃ fuel rows,
        RadixScanPlan dirs ((slots.map child).filter (· != 0#u32)) fuel
          (rows.map Prod.snd)
        ∧ List.Perm rows (slots.flatMap bindings)
        ∧ (ordered → rows.Pairwise radixKeyLt) := by
  induction slots with
  | nil => exact ⟨0, [], .done, .nil, fun _ => .nil⟩
  | cons i rest ih =>
      obtain ⟨m, xs, ha, hp, sp⟩ := available i List.mem_cons_self
      obtain ⟨earlier, sortedRest⟩ := List.pairwise_cons.mp sortedSlots
      obtain ⟨n, ys, hb, hq, sq⟩ := ih sortedRest (fun j hj => available j (List.mem_cons_of_mem _ hj))
      refine ⟨m + n, xs ++ ys, ?_, ?_, ?_⟩
      · rw [List.map_append, List.map_cons, ← List.singleton_append, List.filter_append]
        exact scan_plan_append ha hb
      · exact hp.append hq
      · intro sort
        apply List.pairwise_append.mpr
        refine ⟨sp sort, sq sort, ?_⟩
        intro a ha b hb
        obtain ⟨j, hj, hb'⟩ := List.mem_flatMap.mp (hq.mem_iff.mp hb)
        exact separated sort i j (earlier j hj) a (hp.mem_iff.mp ha) b hb'

private theorem scan_plan_tree (dirs : List (Option Spike.radix.RadixDir))
    (height : Nat) (root : U32) (bindings : Bindings)
    (keyOf : U32 → Option (List U8))
    (tree : RadixTree dirs height root bindings)
    : ∃ fuel rows,
        RadixScanPlan dirs ([root].filter (· != 0#u32)) fuel (rows.map Prod.snd)
        ∧ List.Perm rows bindings
        ∧ (RadixCompressed dirs keyOf
            → (∀ e ∈ bindings, keyOf e.2 = some e.1)
            → rows.Pairwise radixKeyLt) := by
  induction tree with
  | empty =>
      exact ⟨
        0,
        [],
        by simpa using (RadixScanPlan.done (dirs := dirs)),
        .nil,
        fun _ _ => .nil
      ⟩
  | leaf _ node key tagged =>
      have nz : node ≠ 0#u32 := by
        intro hz
        subst node
        exact (by decide : ¬(2147483648#u32 : U32) ≤ 0#u32) tagged
      have test : (node != 0#u32) = true := bne_iff_ne.mpr nz
      exact ⟨
        1,
        [(key, node)],
        by
          simpa only [List.map_cons, List.map_nil, List.filter_cons, List.filter_nil,
            test, ite_true]
            using RadixScanPlan.leaf node [] 0 [] tagged (.done (dirs := dirs)),
        .refl _,
        fun _ _ => List.pairwise_singleton _ _
      ⟩
  | branch h node dir bindings positive low live child links children ih =>
      let rows :=
        fun i => bindings.filter (fun row => radixSymbol row.1 dir.digit.val == i)
      let good := RadixCompressed dirs keyOf ∧ ∀ e ∈ bindings, keyOf e.2 = some e.1
      have sorted : (List.range 17).Pairwise (· < ·) := by decide
      have separated : good → ∀ i j, i < j → ∀ a ∈ rows i, ∀ b ∈ rows j, radixKeyLt a b := by
        intro hGood i j lt a ha b hb
        have left := List.mem_filter.mp ha
        have right := List.mem_filter.mp hb
        have common := hGood.1 (h + 1) node bindings dir
          (.branch h node dir bindings positive low live child links children)
          positive low live hGood.2
        apply radix_first_symbol_lt a.1 b.1 dir.digit.val
          (common a left.1 b right.1)
        rwa [beq_iff_eq.mp left.2, beq_iff_eq.mp right.2]
      have available : ∀ i ∈ List.range 17, ∃ fuel output,
          RadixScanPlan dirs ([child i].filter (· != 0#u32)) fuel (output.map Prod.snd)
          ∧ List.Perm output (rows i) ∧ (good → output.Pairwise radixKeyLt) := by
        intro i hi
        obtain ⟨fuel, output, plan, perm, order⟩ := ih i (List.mem_range.mp hi)
        refine ⟨fuel, output, plan, perm, fun cfg => order cfg.1 ?_⟩
        intro e hm
        exact cfg.2 e (List.mem_filter.mp hm).1
      obtain ⟨fuel, leaves, plan, perm, order⟩ :=
        scan_plan_slots dirs (List.range 17) child rows sorted good separated available
      have pointers : (List.range 17).map child = dir.children.val := by
        apply List.ext_getElem?
        intro i
        by_cases inside : i < 17
        · rw [List.getElem?_map, List.getElem?_range inside, Option.map_some, links i inside]
        · have size : dir.children.val.length = 17 := Array.length_eq dir.children
          have hIndex : 17 ≤ i := Nat.le_of_not_gt inside
          rw [List.getElem?_map, List.getElem?_eq_none (by simpa using hIndex),
            List.getElem?_eq_none (size.symm ▸ hIndex)]
          rfl
      rw [pointers] at plan
      have hfilter
          : bindings.filter (fun row => decide (radixSymbol row.1 dir.digit.val < 17))
            = bindings :=
        List.filter_eq_self.mpr (fun row _ => decide_eq_true (radixSymbol_bound _ _))
      have partition :=
        radix_group_slots bindings (fun row => radixSymbol row.1 dir.digit.val) 17
      rw [hfilter] at partition
      have nz : node ≠ 0#u32 := fun hz => by subst node; contradiction
      refine ⟨
        fuel + 17,
        leaves,
        ?_,
        perm.trans partition,
        fun comp actual => order ⟨comp, actual⟩
      ⟩
      simpa only [List.filter_cons, List.filter_nil, bne_iff_ne.mpr nz, ite_true,
        List.append_nil]
        using RadixScanPlan.branch node dir [] fuel (leaves.map Prod.snd) positive low
          live (by simpa using plan)

private theorem scan_step {dirs : Slice (Option Spike.radix.RadixDir)}
    (out stack : alloc.vec.Vec U32) (node : U32) (rest : List U32)
    (hstack : stack.val.reverse = node :: rest)
    (hs : node < 2147483648#u32 → rest.length + 17 ≤ Usize.max)
    (ho : out.val.length < Usize.max)
    (live
      : node < 2147483648#u32
        → ∃ dir, 0 < node.val ∧ dirs.val[node.val - 1]? = some (some dir))
    : WP.spec (Spike.radix.scan_leaves_loop.body dirs out stack)
        (fun result =>
          ∃ next todo,
            result = .cont (next, todo)
            ∧ if node < 2147483648#u32 then
                ∃ dir,
                  dirs.val[node.val - 1]? = some (some dir)
                  ∧ next = out
                  ∧ todo.val.reverse = dir.children.val.filter (· != 0#u32) ++ rest
              else
                next.val = out.val ++ [node] ∧ todo.val.reverse = rest) := by
  have contents : stack.val = rest.reverse ++ [node] := by
    simpa only [List.reverse_reverse, List.reverse_cons]
      using congrArg List.reverse hstack
  have size : stack.val.length = rest.length + 1 := by simp [contents]
  have len : (alloc.vec.Vec.len stack).val = stack.val.length := alloc.vec.Vec.len_val _
  have one : (1#usize : Usize).val = 1 := rfl
  have go : 0#usize < alloc.vec.Vec.len stack := by
    change 0 < (alloc.vec.Vec.len stack).val
    omega
  unfold Spike.radix.scan_leaves_loop.body
  simp only [go, ite_true, alloc.vec.Vec.index_slice_index, radix_tag]
  apply WP.spec_bind
    (Usize.sub_spec (by omega : (1#usize : Usize).val ≤ (alloc.vec.Vec.len stack).val))
  intro index hi
  have atEnd : index.val = rest.length := by omega
  have bound : index.val < stack.val.length := by omega
  apply WP.spec_bind (alloc.vec.Vec.index_usize_spec stack index bound)
  intro link hlink
  have eq : link = node := by
    have last : stack.val[index.val]? = some node := by
      rw [contents, atEnd, List.getElem?_append_right (by simp)]
      simp
    rw [List.getElem?_eq_getElem bound, ← hlink, Option.some.injEq] at last
    exact last
  rw [eq]
  apply WP.spec_bind (alloc.vec.Vec.resize_spec core.clone.CloneU32 stack index 0#u32 rfl)
  intro popped hp
  have remaining : popped.val = rest.reverse := by
    have shrink : index.val ≤ stack.val.length := by omega
    rw [hp, List.resize, Nat.sub_eq_zero_of_le shrink, List.replicate_zero, List.append_nil]
    rw [contents, atEnd, List.take_append_of_le_length (by simp)]
    exact List.take_of_length_le (by simp)
  by_cases tagged : node < 2147483648#u32
  · obtain ⟨dir, pos, existsDir⟩ := live tagged
    simp only [tagged, ite_true]
    apply WP.spec_bind (radix_directory_matches dirs node dir pos existsDir)
    intro found he
    subst found
    apply WP.spec_bind (radix_push_children popped dir (by simpa [remaining] using hs tagged))
    intro next hn
    simp only [WP.spec_ok]
    exact ⟨out, next, rfl, dir, existsDir, rfl, by simp [hn, remaining]⟩
  · simp only [tagged, ite_false]
    apply WP.spec_bind (alloc.vec.Vec.push_spec out node ho)
    intro next hn
    simp only [WP.spec_ok]
    exact ⟨next, popped, rfl, hn, by simp [remaining]⟩

private theorem scan_loop_refines (dirs : Slice (Option Spike.radix.RadixDir))
    (todo : List U32) (fuel : Nat) (leaves : List U32)
    (plan : RadixScanPlan dirs.val todo fuel leaves)
    (out stack : alloc.vec.Vec U32)
    (hstack : stack.val.reverse = todo) (room : out.val.length + fuel ≤ Usize.max)
    : WP.spec (Spike.radix.scan_leaves_loop dirs out stack)
        (fun result =>
          result.val = out.val ++ leaves) := by
  induction plan generalizing out stack with
  | done =>
      have empty : stack.val = [] := by simpa using congrArg List.reverse hstack
      unfold Spike.radix.scan_leaves_loop loop Spike.radix.scan_leaves_loop.body
      have zero : ¬0#usize < alloc.vec.Vec.len stack := by
        change ¬0 < (alloc.vec.Vec.len stack).val
        simp [empty]
      simp [zero]
  | leaf node rest fuel leaves tagged tail ih =>
      have small : ¬node < 2147483648#u32 := not_lt_of_ge tagged
      unfold Spike.radix.scan_leaves_loop loop
      have step
          : WP.spec (Spike.radix.scan_leaves_loop.body dirs out stack)
              (fun result =>
                ∃ next todo,
                  result = .cont (next, todo)
                  ∧ next.val = out.val ++ [node]
                  ∧ todo.val.reverse = rest) := by
        -- No directory children are pushed in this case.
        apply WP.spec_mono
          (scan_step out stack node rest hstack
            (fun low => (small low).elim) (by omega) (fun low => (small low).elim))
        rintro r ⟨next, todo, hr, post⟩
        exact ⟨next, todo, hr, by simpa only [small, ite_false] using post⟩
      apply WP.spec_bind step
      rintro result ⟨next, todo, he, hn, ht⟩
      subst result
      apply WP.spec_mono (ih next todo ht (by simp [hn]; omega))
      intro r hr
      simp [hr, hn, List.append_assoc]
  | branch node dir rest fuel leaves positive low live tail ih =>
      have hrest := scan_plan_room tail
      have hsize : rest.length ≤ fuel := by simp only [List.length_append] at hrest; omega
      unfold Spike.radix.scan_leaves_loop loop
      apply WP.spec_bind
        (scan_step out stack node rest hstack
          (fun _ => by omega) (by omega) (fun _ => ⟨dir, positive, live⟩))
      rintro result ⟨next, todo, he, post⟩
      subst result
      rw [ite_eq_left low] at post
      obtain ⟨actual, existsDir, equal, ht⟩ := post
      have eq : actual = dir :=
        Option.some.inj (Option.some.inj (existsDir.symm.trans live))
      subst actual next
      exact ih out todo ht (by omega)

/-- With room for the traversal, the native scan visits the planned leaves in
directory order, without consulting rows outside the root. -/
theorem radix_scan_plan_matches (dirs : Slice (Option Spike.radix.RadixDir))
    (root : U32) (fuel : Nat) (leaves : List U32)
    (plan : RadixScanPlan dirs.val ([root].filter (· != 0#u32)) fuel leaves)
    (room : fuel ≤ Usize.max)
    : WP.spec (Spike.radix.scan_leaves dirs root)
        (fun result => result.val = leaves) := by
  unfold Spike.radix.scan_leaves
  by_cases zero : root = 0#u32
  · subst root
    rw [ite_eq_left rfl, WP.spec_ok]
    have empty : RadixScanPlan dirs.val [] fuel leaves := by simpa using plan
    cases empty
    rfl
  · rw [ite_eq_right zero]
    have hroom : (alloc.vec.Vec.new U32).val.length < Usize.max := by
      change 0 < Usize.max
      scalar_tac
    apply WP.spec_bind (alloc.vec.Vec.push_spec (alloc.vec.Vec.new U32) root hroom)
    intro stack hs
    have top : stack.val.reverse = ([root].filter (· != 0#u32)) := by
      simp [hs, bne_iff_ne.mpr zero]
    simpa using scan_loop_refines dirs _ fuel leaves plan (alloc.vec.Vec.new U32) stack top (by simpa using room)

/-- Every finite root admits a scan plan with exactly the projected leaf
links. The plan's fuel bounds the native stack and result vectors. -/
theorem radix_scan_plan_exists (dirs : Slice (Option Spike.radix.RadixDir))
    (height : Nat) (root : U32) (bindings : List (List U8 × U32))
    (tree : RadixTree dirs.val height root bindings)
    : ∃ fuel leaves,
        RadixScanPlan dirs.val ([root].filter (· != 0#u32)) fuel leaves
        ∧ List.Perm leaves (bindings.map Prod.snd) := by
  obtain ⟨fuel, rows, plan, perm, _⟩ :=
    scan_plan_tree dirs.val height root bindings (fun _ => none) tree
  exact ⟨fuel, rows.map Prod.snd, plan, perm.map Prod.snd⟩

/-- A compressed tree's native scan plan enumerates the real keys in strictly
increasing byte order, independently of the model's write order. -/
theorem radix_scan_lex_plan_exists {V : Type} (dirs : Slice (Option Spike.radix.RadixDir))
    (rows : Slice (Option (Spike.radix.RadixRow V))) (height : Nat) (root : U32)
    (bindings : List (List U8 × U32)) (tree : RadixTree dirs.val height root bindings)
    (valid : RadixRows rows.val bindings)
    (compressed : RadixCompressed dirs.val (radixKeyOf rows.val))
    : ∃ fuel ordered,
        RadixScanPlan dirs.val ([root].filter (· != 0#u32)) fuel (ordered.map Prod.snd)
        ∧ List.Perm ordered bindings
        ∧ ordered.Pairwise radixKeyLt := by
  obtain ⟨fuel, ordered, plan, perm, sort⟩ :=
    scan_plan_tree dirs.val height root bindings (radixKeyOf rows.val) tree
  refine ⟨fuel, ordered, plan, perm, sort compressed ?_⟩
  intro entry hm
  obtain ⟨_, row, live, key⟩ := valid entry hm
  simp [radixKeyOf, live, key]

/-- Native traversal of a compressed tree returns the exact lexicographic
projection when its ordinary scan plan fits the native bounds. -/
theorem radix_scan_leaves_lex_refines {V : Type}
    (dirs : Slice (Option Spike.radix.RadixDir))
    (rows : Slice (Option (Spike.radix.RadixRow V))) (height : Nat) (root : U32)
    (bindings : List (List U8 × U32)) (tree : RadixTree dirs.val height root bindings)
    (valid : RadixRows rows.val bindings)
    (compressed : RadixCompressed dirs.val (radixKeyOf rows.val))
    (fits
      : ∃ fuel leaves,
          RadixScanPlan dirs.val ([root].filter (· != 0#u32)) fuel leaves
          ∧ fuel ≤ Usize.max)
    : WP.spec (Spike.radix.scan_leaves dirs root)
        (fun result =>
          ∃ ordered,
            result.val = ordered.map Prod.snd
            ∧ List.Perm ordered bindings
            ∧ ordered.Pairwise radixKeyLt) := by
  obtain ⟨bounded, leaves, ordinary, room⟩ := fits
  obtain ⟨fuel, ordered, plan, perm, sort⟩ :=
    radix_scan_lex_plan_exists dirs rows height root bindings tree valid compressed
  have size := (scan_plan_unique plan ordinary).1
  exact WP.spec_mono (radix_scan_plan_matches dirs root fuel _ plan (size.symm ▸ room))
    (fun _ eq => ⟨ordered, eq, perm, sort⟩)

/-- The native traversal returns every projected leaf link with exactly its
original multiplicity. Scan order is a separate policy from traversal order. -/
theorem radix_scan_leaves_refines (dirs : Slice (Option Spike.radix.RadixDir))
    (root : U32) (bindings : List (List U8 × U32))
    (fits
      : ∃ fuel leaves,
          RadixScanPlan dirs.val ([root].filter (· != 0#u32)) fuel leaves
          ∧ fuel ≤ Usize.max
          ∧ List.Perm leaves (bindings.map Prod.snd))
    : WP.spec (Spike.radix.scan_leaves dirs root)
        (fun result => List.Perm result.val (bindings.map Prod.snd)) := by
  obtain ⟨fuel, leaves, plan, room, permutation⟩ := fits
  apply WP.spec_mono (radix_scan_plan_matches dirs root fuel leaves plan room)
  intro result h
  exact h ▸ permutation

private def keepLeaf (removed : Option U32) (leaf : U32) : Bool :=
  match removed with
  | none => true
  | some old => old != leaf

private theorem edit_order_loop_matches (order : Slice U32) (removed : Option U32)
    (out : alloc.vec.Vec U32) (count : Usize)
    (room : out.val.length + (order.val.drop count.val).length ≤ Usize.max)
    : WP.spec (Spike.radix.edit_order_loop order removed out count)
        (fun next =>
          next.val
          = out.val ++ (order.val.drop count.val).filter (keepLeaf removed)) := by
  unfold Spike.radix.edit_order_loop
  let suffix := fun i : Usize => order.val.drop i.val
  apply loop.spec_decr_nat
    (fun p : alloc.vec.Vec U32 × Usize => order.val.length - p.2.val)
    (fun (next, i) =>
      next.val.length + (suffix i).length ≤ Usize.max
      ∧ next.val ++ (suffix i).filter (keepLeaf removed)
        = out.val ++ (suffix count).filter (keepLeaf removed)) _ _ _
  · rintro ⟨next, i⟩ ⟨capacity, same⟩
    dsimp only at capacity same ⊢
    unfold Spike.radix.edit_order_loop.body
    have hlen : (Slice.len order).val = order.val.length := Slice.len_val _
    by_cases h : i < Slice.len order
    · have inside : i.val < order.val.length := by rwa [← hlen]
      rw [ite_eq_left h]
      apply WP.spec_bind (Slice.index_usize_spec order i inside)
      intro leaf hleaf
      have step : suffix i = leaf :: order.val.drop (i.val + 1) := by
        dsimp only [suffix]
        rw [List.drop_eq_getElem_cons inside, ← hleaf]
      have one : (1#usize : Usize).val = 1 := rfl
      have max := Slice.length_ineq order
      let check : Option U32 → Result Bool := fun o => match o with
          | none => Result.ok true
          | some old => Result.ok (old != leaf)
      have cond : check removed = Result.ok (keepLeaf removed leaf) := by
        cases removed <;> rfl
      change WP.spec (do
        let keep ← check removed
        let n ← if keep then alloc.vec.Vec.push next leaf else Result.ok next
        let j ← i + 1#usize
        Result.ok (ControlFlow.cont (n, j))) _
      rw [cond, bind_ok]
      have edited : WP.spec
          (if keepLeaf removed leaf then alloc.vec.Vec.push next leaf else Result.ok next)
          (fun v => v.val = next.val ++ if keepLeaf removed leaf then [leaf] else []) := by
        split
        · apply alloc.vec.Vec.push_spec
          rw [step, List.length_cons] at capacity
          omega
        · simp
      apply WP.spec_bind edited
      intro edited equality
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro j hj
      have increment : j.val = i.val + 1 := by omega
      have splitSuffix : suffix i = leaf :: suffix j := by simpa [suffix, increment] using step
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨?_, ?_⟩, by omega⟩
      · rw [splitSuffix, List.length_cons] at capacity
        rw [equality, List.length_append]
        cases keepLeaf removed leaf <;> simp <;> omega
      · rw [splitSuffix, List.filter_cons] at same
        cases keep : keepLeaf removed leaf <;>
          simpa [equality, keep, List.append_assoc] using same
    · rw [ite_eq_right h, WP.spec_ok]
      have past : order.val.length ≤ i.val := by
        rw [← hlen]
        exact Nat.le_of_not_gt h
      simpa [suffix, List.drop_eq_nil_of_le past] using same
  · exact ⟨room, rfl⟩

private theorem edit_order_matches (order : Slice U32) (removed added : Option U32)
    (room : order.val.length + added.toList.length ≤ Usize.max)
    : WP.spec (Spike.radix.edit_order order removed added)
        (fun next => next.val = added.toList ++ order.val.filter (keepLeaf removed)) := by
  unfold Spike.radix.edit_order
  have first : WP.spec
      (match added with
        | none => Result.ok (alloc.vec.Vec.new U32)
        | some leaf => alloc.vec.Vec.push (alloc.vec.Vec.new U32) leaf)
      (fun out => out.val = added.toList) := by
    cases added with
    | none => simp
    | some leaf =>
        simpa using alloc.vec.Vec.push_spec (alloc.vec.Vec.new U32) leaf (by
          change 0 < Usize.max
          scalar_tac)
  apply WP.spec_bind first
  intro out initial
  have fit : out.val.length + (order.val.drop (0#usize : Usize).val).length ≤ Usize.max := by
    simpa [initial, Nat.add_comm] using room
  simpa [initial] using edit_order_loop_matches order removed out 0#usize fit

private theorem matching_leaf_matches {V : Type}
    (dirs : Slice (Option Spike.radix.RadixDir))
    (rows : Slice (Option (Spike.radix.RadixRow V))) (root : U32) (key : Slice U8)
    (height : Nat) (bindings : Bindings) (tree : RadixTree dirs.val height root bindings)
    (valid : RadixRows rows.val bindings)
    : WP.spec (Spike.radix.matching_leaf dirs rows root key)
        (· = Kv.Model.find bindings key.val) := by
  unfold Spike.radix.matching_leaf
  apply WP.spec_bind (radix_find_leaf_matches dirs key height root bindings tree)
  intro leaf ⟨belongs, lookup⟩
  have hb := find_binding bindings key.val
  by_cases zero : leaf = 0#u32
  · rw [ite_eq_left zero, WP.spec_ok]
    cases found : Kv.Model.find bindings key.val with
    | none => rfl
    | some link =>
        have hm : (key.val, link) ∈ bindings := by simpa only [found] using hb
        have eq := lookup link hm
        have tag := (valid _ hm).1
        rw [← eq, zero] at tag
        exact ((by decide : ¬2147483648 < (0#u32 : U32).val) tag).elim
  · obtain ⟨k, hm⟩ := belongs.resolve_left zero
    obtain ⟨tag, row, live, eq⟩ := valid (k, leaf) hm
    rw [ite_eq_right zero]
    apply WP.spec_bind (radix_check_leaf_spec rows leaf key row tag live)
    intro result check
    rw [check, eq]
    cases found : Kv.Model.find bindings key.val with
    | none =>
        have diff : k ≠ key.val := by
          intro same
          subst k
          exact (show ∀ l, (key.val, l) ∉ bindings by simpa only [found] using hb) leaf hm
        simp [diff, core.option.Option.is_none]
    | some link =>
        have present : (key.val, link) ∈ bindings := by simpa only [found] using hb
        have eqLink := lookup link present
        obtain ⟨_, other, read, same⟩ := valid _ present
        rw [← eqLink, live, Option.some.injEq] at read
        subst other link
        have hk : k = key.val := eq.symm.trans same
        simp [hk, core.option.Option.is_none]

private theorem erase_order_matches {V : Type}
    (rows : List (Option (Spike.radix.RadixRow V))) (bindings : Bindings) (key : List U8)
    (valid : RadixRows rows bindings)
    (route : ∀ l, (key, l) ∈ bindings → Kv.Model.find bindings key = some l)
    : (Kv.Model.erase bindings key).map Prod.snd
      = (bindings.map Prod.snd).filter (keepLeaf (Kv.Model.find bindings key)) := by
  unfold Kv.Model.erase
  rw [List.filter_map]
  apply congrArg (List.map Prod.snd)
  apply List.filter_congr
  intro entry hm
  obtain ⟨k, l⟩ := entry
  have eq : Kv.Model.find bindings key = some l ↔ k = key := by
    constructor
    · intro h
      have bound := find_binding bindings key
      rw [h] at bound
      obtain ⟨_, a, ha, ka⟩ := valid (k, l) hm
      obtain ⟨_, b, hb, kb⟩ := valid (key, l) bound
      have same := Option.some.inj (ha.symm.trans hb)
      exact ka.symm.trans ((congrArg (fun r : Spike.radix.RadixRow V => r.key.val) same).trans kb)
    · intro h
      subst k
      exact route l hm
  change decide (k ≠ key) = keepLeaf (Kv.Model.find bindings key) l
  cases found : Kv.Model.find bindings key with
  | none =>
      have diff : k ≠ key := fun h => by simpa [found] using eq.mpr h
      simp [keepLeaf, diff]
  | some old =>
      have same : old = l ↔ k = key := by simpa only [found, Option.some.injEq] using eq
      by_cases h : k = key
      · simp [keepLeaf, h, same.mpr h]
      · have diff : old ≠ l := fun he => h (same.mp he)
        simp [keepLeaf, h, bne_iff_ne.mpr diff]

private theorem find_in_tree {V : Type} (a : Spike.radix.OrderedRadix V) (key : Slice U8)
    {height : Nat} {lookup : U32} {bindings : Bindings}
    (tree : RadixTree a.dirs.val height lookup bindings)
    (valid : RadixRows a.rows.val bindings)
    : ∀ l, (key.val, l) ∈ bindings → Kv.Model.find bindings key.val = some l := by
  have ds : RadixTree (alloc.vec.Vec.deref a.dirs).val height lookup bindings := by
    simpa [alloc.vec.Vec.deref] using tree
  have rs : RadixRows (alloc.vec.Vec.deref a.rows).val bindings := by
    simpa [alloc.vec.Vec.deref] using valid
  have route := radix_find_leaf_matches (alloc.vec.Vec.deref a.dirs) key height lookup bindings ds
  have matchKey := matching_leaf_matches (alloc.vec.Vec.deref a.dirs)
    (alloc.vec.Vec.deref a.rows) lookup key height bindings ds rs
  intro l present
  have chosen := WP.spec_mono route (fun _ h => h.2 l present)
  have matched : WP.spec (Spike.radix.matching_leaf (alloc.vec.Vec.deref a.dirs)
      (alloc.vec.Vec.deref a.rows) lookup key) (· = some l) := by
    unfold Spike.radix.matching_leaf
    apply WP.spec_bind chosen
    intro leaf hl
    subst leaf
    obtain ⟨tag, row, live, eq⟩ := rs (key.val, l) present
    have nonzero : l ≠ 0#u32 := by intro hl; subst l; contradiction
    rw [ite_eq_right nonzero]
    apply WP.spec_bind (radix_check_leaf_spec (alloc.vec.Vec.deref a.rows) l key row tag live)
    intro got hg
    simp [hg, eq, core.option.Option.is_none]
  obtain ⟨_, same, wanted⟩ := WP.spec_exists (WP.spec_and matched matchKey)
  exact wanted.symm.trans same

/-- Relation between an arena-local handle and the ordered key/leaf projection. -/
structure OrderedView {V : Type} (a : Spike.radix.OrderedRadix V)
    (root : Spike.radix.Root) (bindings : List (List U8 × U32))
    : Prop where
  witness
    : ∃ (prior : Spike.radix.OrderedRoot) (height : Nat),
        a.roots.val[root.val]? = some prior
        ∧ prior.order.val = bindings.map Prod.snd
        ∧ RadixTree a.dirs.val height prior.lookup bindings
        ∧ RadixRows a.rows.val bindings

/-- Conditions on the two arenas shared by all roots. -/
structure OrderedArenaValid {V : Type} (a : Spike.radix.OrderedRadix V) : Prop where
  freeDirs : RadixFree a.dirs a.free_dirs
  freeRows : RadixFree a.rows a.free_rows
  directories : RadixDirectoryInvariant a.dirs
  known : RadixKnowledge a.dirs (radixKeyOf a.rows.val)

/-- The selected root admits a height bound that leaves room for a path copy. -/
def OrderedRootFits {V : Type} (a : Spike.radix.OrderedRadix V) (root : Spike.radix.Root)
    (bindings : List (List U8 × U32)) (extra : Nat)
    : Prop :=
  ∃ (prior : Spike.radix.OrderedRoot) (height : Nat),
    a.roots.val[root.val]? = some prior
    ∧ RadixTree a.dirs.val height prior.lookup bindings
    ∧ a.dirs.val.length + height + extra ≤ 2147483647

private theorem ordered_index {V : Type} (a : Spike.radix.OrderedRadix V)
    (root : Spike.radix.Root) (prior : Spike.radix.OrderedRoot)
    (live : a.roots.val[root.val]? = some prior)
    : WP.spec
        (alloc.vec.Vec.index
          (core.slice.index.SliceIndexUsizeSlice Spike.radix.OrderedRoot) a.roots root)
        (· = prior) := by
  rw [alloc.vec.Vec.index_slice_index]
  have bound : root.val < a.roots.val.length := by
    by_contra hn
    simp [List.getElem?_eq_none (Nat.le_of_not_gt hn)] at live
  apply WP.spec_mono (alloc.vec.Vec.index_usize_spec a.roots root bound)
  intro found hf
  rw [List.getElem?_eq_getElem bound, ← hf, Option.some.injEq] at live
  exact live

private theorem ordered_add_root {V : Type} (a : Spike.radix.OrderedRadix V)
    (lookup : U32) (order : alloc.vec.Vec U32) (room : a.roots.val.length < Usize.max)
    : WP.spec (Spike.radix.OrderedRadix.add_root a lookup order)
        (fun (root, after) =>
          ∃ roots,
            after = { a with roots }
            ∧ root.val = a.roots.val.length
            ∧ roots.val = a.roots.val ++ [{ lookup, order }]) := by
  unfold Spike.radix.OrderedRadix.add_root
  apply WP.spec_bind (alloc.vec.Vec.push_spec a.roots _ room)
  intro roots appended
  rw [WP.spec_ok]
  exact ⟨roots, rfl, alloc.vec.Vec.len_val _, appended⟩

private theorem ordered_preserve {V : Type} (a after : Spike.radix.OrderedRadix V)
    (roots : ∃ extra, after.roots.val = a.roots.val ++ extra)
    (keepDirs : preservesSlots a.dirs after.dirs)
    (keepRows
      : ∀ (i : Nat) row,
          a.rows.val[i]? = some (some row) → after.rows.val[i]? = some (some row))
    : ∀ root bs,
        OrderedView a root bs
        → OrderedView after root bs
          ∧ radixBindings after.rows.val bs = radixBindings a.rows.val bs := by
  intro root bs ⟨prior, height, live, order, tree, valid⟩
  obtain ⟨extra, appended⟩ := roots
  have bound : root.val < a.roots.val.length := by
    by_contra hn
    simp [List.getElem?_eq_none (Nat.le_of_not_gt hn)] at live
  obtain ⟨shape, rows, same⟩ :=
    radix_preserves_roots a.dirs after.dirs a.rows after.rows keepDirs keepRows
      height prior.lookup bs tree valid
  refine ⟨⟨prior, height, ?_, order, shape, rows⟩, same⟩
  rw [appended, List.getElem?_append_left bound]
  exact live

/-- A well-formed append-only arena starts with the model's empty map. -/
theorem ordered_new_refines (V : Type)
    : WP.spec (Spike.radix.OrderedRadix.new V)
        (fun a => OrderedArenaValid a ∧ OrderedView a 0#usize []) := by
  unfold Spike.radix.OrderedRadix.new
  apply WP.spec_bind
    (alloc.vec.Vec.push_spec (alloc.vec.Vec.new _) _
      (by
        change 0 < Usize.max
        scalar_tac))
  intro roots h
  rw [WP.spec_ok]
  constructor
  · refine ⟨?_, ?_, ?_, radix_empty_knowledge _⟩
    · simp [RadixFree]
    · simp [RadixFree]
    · intro i d live
      simp at live
  · exact ⟨{ lookup := 0#u32, order := alloc.vec.Vec.new U32 }, 0,
      by simp [h], rfl, .empty 0, fun _ hm => (List.not_mem_nil hm).elim⟩

theorem ordered_get_refines {V : Type} (a : Spike.radix.OrderedRadix V)
    (root : Spike.radix.Root) (key : Slice U8) (bs : List (List U8 × U32))
    (view : OrderedView a root bs)
    : WP.spec (Spike.radix.OrderedRadix.get a root key)
        (· = Kv.Model.find (radixBindings a.rows.val bs) key.val) := by
  obtain ⟨prior, height, live, _, tree, valid⟩ := view.witness
  unfold Spike.radix.OrderedRadix.get
  apply WP.spec_bind (ordered_index a root prior live)
  intro found h
  subst found
  simpa [alloc.vec.Vec.deref]
    using radix_get_refines (alloc.vec.Vec.deref a.dirs) (alloc.vec.Vec.deref a.rows) key
      height prior.lookup bs (by simpa [alloc.vec.Vec.deref] using tree)
      (by simpa [alloc.vec.Vec.deref] using valid)

/-- The native indexed scan exposes exactly the length of the model projection. -/
theorem ordered_scan_len_refines {V : Type} (a : Spike.radix.OrderedRadix V)
    (root : Spike.radix.Root) (bs : List (List U8 × U32)) (view : OrderedView a root bs)
    : WP.spec (Spike.radix.OrderedRadix.scan_len a root)
        (fun n => n.val = (radixBindings a.rows.val bs).length) := by
  obtain ⟨prior, height, live, order, tree, valid⟩ := view.witness
  unfold Spike.radix.OrderedRadix.scan_len
  apply WP.spec_bind (ordered_index a root prior live)
  intro found he
  subst found
  rw [WP.spec_ok, alloc.vec.Vec.len_val]
  change prior.order.val.length = _
  rw [order, List.length_map]
  clear view order tree
  induction bs with
  | nil => rfl
  | cons p tail ih =>
      obtain ⟨_, row, read, _⟩ := valid p List.mem_cons_self
      simp [radixBindings, read, ih (fun e hm => valid e (List.mem_cons_of_mem _ hm))]

private theorem radix_projection_index {V : Type}
    (rows : List (Option (Spike.radix.RadixRow V))) (bs : Bindings)
    (valid : RadixRows rows bs) (i : Nat)
    : (radixBindings rows bs)[i]?
      = (bs[i]?).bind
          (fun (k, l) => (radixRow rows l).map (fun row => (k, row.value))) := by
  induction bs generalizing i with
  | nil => cases i <;> rfl
  | cons p tail ih =>
      obtain ⟨_, row, live, _⟩ := valid p List.mem_cons_self
      cases i with
      | zero => simp [radixBindings, live]
      | succ i =>
          simp only [radixBindings, List.filterMap_cons, live, Option.map_some,
            List.getElem?_cons_succ]
          exact ih (fun e hm => valid e (List.mem_cons_of_mem _ hm)) i

/-- Reading a scan position agrees with the exact ordered model row, including exhaustion. -/
theorem ordered_scan_at_refines {V : Type} (a : Spike.radix.OrderedRadix V)
    (root : Spike.radix.Root) (i : Usize) (bs : List (List U8 × U32))
    (view : OrderedView a root bs)
    : WP.spec (Spike.radix.OrderedRadix.scan_at a root i)
        (fun row =>
          row.map (fun r => (r.key.val, r.value))
          = (radixBindings a.rows.val bs)[i.val]?) := by
  obtain ⟨prior, _, live, order, _, valid⟩ := view.witness
  unfold Spike.radix.OrderedRadix.scan_at
  apply WP.spec_bind (ordered_index a root prior live)
  intro found he
  subst found
  have len : (alloc.vec.Vec.len prior.order).val = bs.length := by
    rw [alloc.vec.Vec.len_val]
    change prior.order.val.length = _
    rw [order, List.length_map]
  rw [radix_projection_index _ _ valid]
  by_cases hb : i.val < bs.length
  · have less : ¬ i ≥ alloc.vec.Vec.len prior.order := by
      change ¬ (alloc.vec.Vec.len prior.order).val ≤ i.val
      omega
    rw [ite_eq_right less, alloc.vec.Vec.index_slice_index]
    have bound : i.val < prior.order.val.length := by simpa [order] using hb
    apply WP.spec_bind (alloc.vec.Vec.index_usize_spec prior.order i bound)
    intro leaf hleaf
    let p := bs[i.val]
    have hm : p ∈ bs := List.getElem_mem hb
    obtain ⟨tag, row, read, key⟩ := valid p hm
    have same : leaf = p.2 := by simp [hleaf, order, p]
    rw [same]
    apply WP.spec_bind (radix_row_at_matches (alloc.vec.Vec.deref a.rows) p.2 row tag
      (by simpa [alloc.vec.Vec.deref] using read))
    intro got hg
    rw [WP.spec_ok, hg, List.getElem?_eq_getElem hb]
    change some (row.key.val, row.value) = (radixRow a.rows.val p.2).map (fun r => (p.1, r.value))
    rw [read, Option.map_some, key]
  · have past : i ≥ alloc.vec.Vec.len prior.order := by
      change (alloc.vec.Vec.len prior.order).val ≤ i.val
      omega
    rw [ite_eq_left past, WP.spec_ok, List.getElem?_eq_none (Nat.le_of_not_gt hb)]
    rfl

/-- Insertion refines model `set`, including scan order and all previously published roots. -/
theorem ordered_put_refines {V : Type} (a : Spike.radix.OrderedRadix V)
    (root : Spike.radix.Root) (row : Spike.radix.RadixRow V) (bs : List (List U8 × U32))
    (view : OrderedView a root bs) (good : OrderedArenaValid a)
    (dirRoom : OrderedRootFits a root bs 1)
    (rowRoom : a.rows.val.length < 2147483647)
    (keyRoom : 2 * row.key.val.length + 1 ≤ Usize.max)
    (orderRoom : bs.length < Usize.max) (rootRoom : a.roots.val.length < Usize.max)
    : WP.spec (Spike.radix.OrderedRadix.put a root row)
        (fun (next, after) =>
          OrderedArenaValid after
          ∧ (∀ r links,
              OrderedView a r links
              → OrderedView after r links
                ∧ radixBindings after.rows.val links = radixBindings a.rows.val links)
          ∧ ∃ updated,
              OrderedView after next updated
              ∧ radixBindings after.rows.val updated
                = Kv.Model.set (radixBindings a.rows.val bs) row.key.val row.value) := by
  obtain ⟨prior, _, live, priorOrder, _, valid⟩ := view.witness
  obtain ⟨bounded, height, hbound, tree, room⟩ := dirRoom
  have same := Option.some.inj (hbound.symm.trans live)
  subst bounded
  unfold Spike.radix.OrderedRadix.put
  apply WP.spec_bind (ordered_index a root prior live)
  intro found hf
  subst found
  apply WP.spec_bind (radix_put_refines a.dirs a.free_dirs a.rows a.free_rows a.path
    prior.lookup row height bs tree valid (radix_compressed_of_knowledge _ _ good.known)
    good.directories good.freeDirs good.freeRows room rowRoom keyRoom)
  rintro ⟨⟨lookup, added, removed⟩, dirs, freeDirs, rows, freeRows, path⟩
    ⟨keepDirs, vacantDirs, invariant, knowledge, vacantRows, keepRows, removedEq, _,
      newHeight, newTree, newRows, valueEq⟩
  have room : (alloc.vec.Vec.deref prior.order).val.length + (some added).toList.length
      ≤ Usize.max := by simpa [alloc.vec.Vec.deref, priorOrder, Nat.add_one_le_iff] using orderRoom
  apply WP.spec_bind
    (edit_order_matches (alloc.vec.Vec.deref prior.order) removed (some added) room)
  intro order eq
  let edited := Kv.Model.set bs row.key.val added
  have orderEq : order.val = edited.map Prod.snd := by
    have erase := erase_order_matches a.rows.val bs row.key.val valid
      (by simpa only [key_borrow_val] using find_in_tree a (alloc.vec.Vec.deref row.key) tree valid)
    rw [eq, removedEq]
    simp [edited, Kv.Model.set, alloc.vec.Vec.deref, priorOrder, erase]
  let updated : Spike.radix.OrderedRadix V :=
    { a with dirs, free_dirs := freeDirs, rows, free_rows := freeRows, path }
  change WP.spec (Spike.radix.OrderedRadix.add_root updated lookup order) _
  apply WP.spec_mono (ordered_add_root updated lookup order rootRoom)
  rintro ⟨next, after⟩ ⟨roots, ha, index, appended⟩
  subst after
  change roots.val = a.roots.val ++ [_] at appended
  refine ⟨⟨vacantDirs, vacantRows, invariant, knowledge good.known⟩,
    ordered_preserve a _ ⟨_, appended⟩ keepDirs keepRows,
    edited, ⟨{ lookup, order }, newHeight, ?_, orderEq, newTree, newRows⟩, valueEq⟩
  change roots.val[next.val]? = some { lookup, order }
  simp [index, updated, appended]

/-- Deletion refines model `erase`; an absent key retains the same root. -/
theorem ordered_remove_refines {V : Type} (a : Spike.radix.OrderedRadix V)
    (root : Spike.radix.Root) (key : Slice U8) (bs : List (List U8 × U32))
    (view : OrderedView a root bs) (good : OrderedArenaValid a)
    (dirRoom : OrderedRootFits a root bs 0)
    (rootRoom : a.roots.val.length < Usize.max)
    : WP.spec (Spike.radix.OrderedRadix.remove a root key)
        (fun (next, after) =>
          OrderedArenaValid after
          ∧ (∀ r links, OrderedView a r links → OrderedView after r links)
          ∧ after.rows = a.rows
          ∧ OrderedView after next (Kv.Model.erase bs key.val)
          ∧ radixBindings after.rows.val (Kv.Model.erase bs key.val)
            = Kv.Model.erase (radixBindings a.rows.val bs) key.val) := by
  obtain ⟨prior, _, live, priorOrder, _, valid⟩ := view.witness
  obtain ⟨bounded, height, hbound, tree, room⟩ := dirRoom
  have same := Option.some.inj (hbound.symm.trans live)
  subst bounded
  unfold Spike.radix.OrderedRadix.remove
  apply WP.spec_bind (ordered_index a root prior live)
  intro found hf
  subst found
  let dirs := alloc.vec.Vec.deref a.dirs
  let rows := alloc.vec.Vec.deref a.rows
  have tree' : RadixTree dirs.val height prior.lookup bs := by
    simpa [dirs, alloc.vec.Vec.deref] using tree
  have valid' : RadixRows rows.val bs := by simpa [rows, alloc.vec.Vec.deref] using valid
  apply WP.spec_bind
    (matching_leaf_matches dirs rows prior.lookup key height bs tree' valid')
  intro removed eq
  subst removed
  cases h : Kv.Model.find bs key.val with
  | none =>
      have hb := find_binding bs key.val
      rw [h] at hb
      have erased := erase_absent bs key.val hb
      change WP.spec (Result.ok (root, a)) _
      rw [WP.spec_ok]
      exact ⟨good, fun _ _ v => v, rfl, erased.symm ▸ view, radix_project_erase _ _ _⟩
  | some removed =>
      simp only [core.option.Option.is_none]
      have compressed : RadixCompressed a.dirs.val (radixKeyOf rows.val) := by
        simpa [rows, alloc.vec.Vec.deref]
          using radix_compressed_of_knowledge _ _ good.known
      apply WP.spec_bind
        (radix_remove_refines a.dirs a.free_dirs rows a.path prior.lookup key height
          bs tree valid' good.freeDirs good.directories compressed (by simpa using room))
      rintro ⟨lookup, dirsAfter, freeDirs, path⟩
        ⟨keepDirs, vacant, invariant, knowledge, _, newHeight, newTree, newRows, valueEq⟩
      let links := alloc.vec.Vec.deref prior.order
      have room : links.val.length + (none : Option U32).toList.length ≤ Usize.max := by
        simp
      apply WP.spec_bind (edit_order_matches links (some removed) none room)
      intro order eq
      have orderEq : order.val = (Kv.Model.erase bs key.val).map Prod.snd := by
        have erase := erase_order_matches a.rows.val bs key.val valid
          (find_in_tree a key tree valid)
        rw [h] at erase
        simpa [links, alloc.vec.Vec.deref, priorOrder, erase] using eq
      let updated : Spike.radix.OrderedRadix V := { a with dirs := dirsAfter, free_dirs := freeDirs, path }
      change WP.spec (Spike.radix.OrderedRadix.add_root updated lookup order) _
      apply WP.spec_mono (ordered_add_root updated lookup order rootRoom)
      rintro ⟨next, after⟩ ⟨roots, ha, index, appended⟩
      subst after
      change roots.val = a.roots.val ++ [_] at appended
      have knows : RadixKnowledge dirsAfter (radixKeyOf a.rows.val) := by
        simpa [rows, alloc.vec.Vec.deref]
          using knowledge (by simpa [rows, alloc.vec.Vec.deref] using good.known)
      have preserved := ordered_preserve a {updated with roots} ⟨_, appended⟩ keepDirs
        (fun _ _ hp => hp)
      refine ⟨⟨vacant, good.freeRows, invariant, knows⟩,
        fun r b hv => (preserved r b hv).1, rfl,
        ⟨{ lookup, order }, newHeight, ?_, orderEq, newTree, ?_⟩, ?_⟩
      · change roots.val[next.val]? = some { lookup, order }
        simp [index, updated, appended]
      · simpa [updated, rows, alloc.vec.Vec.deref] using newRows
      · simpa [updated, rows, alloc.vec.Vec.deref] using valueEq

end KvRust
