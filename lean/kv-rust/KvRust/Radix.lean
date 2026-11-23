-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs

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

end KvRust
