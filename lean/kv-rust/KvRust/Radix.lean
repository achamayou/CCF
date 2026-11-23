-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs
public import Kv.Model.Types

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
        subst got
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

private theorem radix_check_leaf_spec {V : Type}
    (rows : Slice (Option (Spike.radix.RadixRow V))) (leaf : U32) (key : Slice U8)
    (row : Spike.radix.RadixRow V) (tagged : 2147483648 < leaf.val)
    (live : radixRow rows.val leaf = some row)
    : WP.spec (Spike.radix.check_leaf rows leaf key)
        (fun got =>
          got = if row.key.val = key.val then some row.value else none) := by
  unfold Spike.radix.check_leaf radixRow at *
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
  rw [eq]
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

end KvRust
