-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.RadixDual
public import KvRust.RadixBatch

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- Single-arena radix view whose bindings are canonically sorted in strictly
increasing byte-key order. -/
structure SingleView {V : Type} (arena : Spike.radix.SingleRadix V)
    (root : Spike.radix.RadixRoot) (bindings : List (List U8 × U32))
    : Prop where
  lookup : ∃ height, RadixTree arena.values.dirs.val height root bindings
  values : RadixRows arena.values.rows.val bindings
  sorted : bindings.Pairwise radixKeyLt

def singleBindings {V : Type} (arena : Spike.radix.SingleRadix V)
    (bindings : List (List U8 × U32))
    : List (List U8 × V) :=
  radixBindings arena.values.rows.val bindings

theorem radix_tree_perm {dirs : List (Option Spike.radix.RadixDir)}
    {height : Nat} {root : U32} {a b : List (List U8 × U32)}
    (tree : RadixTree dirs height root a) (perm : a.Perm b)
    : RadixTree dirs height root b := by
  induction tree generalizing b with
  | empty h =>
      rw [← perm.nil_eq]
      exact .empty h
  | leaf h node key tagged =>
      rw [← perm.singleton_eq]
      exact .leaf h node key tagged
  | branch h node dir bs pos untagged live child links children ih =>
      refine .branch h node dir b pos untagged live child links ?_
      intro slot hslot
      exact ih slot hslot (perm.filter _)

theorem radix_rows_perm {V : Type} {rows : List (Option (Spike.radix.RadixRow V))}
    {a b : List (List U8 × U32)}
    (valid : RadixRows rows a) (perm : a.Perm b)
    : RadixRows rows b :=
  fun entry hm => valid entry (perm.symm.subset hm)

private theorem byteOrder_trichotomy (xs ys : List U8)
    : byteOrder xs ys = (-1)#i8 ∨ byteOrder xs ys = 0#i8 ∨ byteOrder xs ys = 1#i8 := by
  induction xs generalizing ys with
  | nil => cases ys <;> simp [byteOrder]
  | cons x xs ih =>
      cases ys with
      | nil => simp [byteOrder]
      | cons y ys =>
          simp only [byteOrder]
          by_cases hxy : x < y
          · simp [hxy]
          · by_cases hyx : y < x
            · simp [hxy, hyx]
            · simpa [hxy, hyx] using ih ys

theorem radixKeyLt_iff (a b : List U8 × U32) : radixKeyLt a b ↔ a.1 < b.1 := by
  unfold radixKeyLt
  constructor
  · intro h
    exact (byteOrder_lt a.1 b.1).mp (by rw [h]; decide)
  · intro h
    have neg := (byteOrder_lt a.1 b.1).mpr h
    rcases byteOrder_trichotomy a.1 b.1 with h1 | h0 | h2
    · exact h1
    · rw [h0] at neg; exact (show ¬ (0#i8 : I8) < 0#i8 by decide) neg |>.elim
    · rw [h2] at neg; exact (show ¬ (1#i8 : I8) < 0#i8 by decide) neg |>.elim

theorem radixKeyLt_irrefl (a : List U8 × U32) : ¬ radixKeyLt a a := by
  rw [radixKeyLt_iff]
  exact lt_irrefl a.1

theorem radixKeyLt_trans {a b c : List U8 × U32}
    (ab : radixKeyLt a b) (bc : radixKeyLt b c)
    : radixKeyLt a c := by
  rw [radixKeyLt_iff] at ab bc ⊢
  exact lt_trans ab bc

theorem radixKeyLt_perm_eq {a b : List (List U8 × U32)}
    (ha : a.Pairwise radixKeyLt) (hb : b.Pairwise radixKeyLt) (perm : a.Perm b)
    : a = b := by
  induction a generalizing b with
  | nil => exact perm.nil_eq
  | cons x xs ih =>
      cases b with
      | nil => exact (List.Perm.nil_eq perm.symm).symm
      | cons y ys =>
          obtain ⟨hx, hxs⟩ := List.pairwise_cons.mp ha
          obtain ⟨hy, hys⟩ := List.pairwise_cons.mp hb
          have hxy : x = y := by
            have hyIn : y ∈ x :: xs := perm.symm.subset List.mem_cons_self
            have hxIn : x ∈ y :: ys := perm.subset List.mem_cons_self
            rcases List.mem_cons.mp hyIn with rfl | hyXs
            · rfl
            · rcases List.mem_cons.mp hxIn with rfl | hxYs
              · rfl
              · exact (radixKeyLt_irrefl x (radixKeyLt_trans (hx y hyXs) (hy x hxYs))).elim
          subst hxy
          exact congrArg (List.cons x) (ih hxs hys (List.Perm.cons_inv perm))

/-- Insert `(key, leaf)` in strictly increasing `radixKeyLt` order, replacing any
existing entry with the same key. -/
def insertSorted (bindings : List (List U8 × U32)) (key : List U8) (leaf : U32)
    : List (List U8 × U32) :=
  match bindings with
  | [] => [(key, leaf)]
  | (k, v) :: rest =>
      if key < k then
        (key, leaf) :: (k, v) :: Kv.Model.erase rest key
      else if k < key then
        (k, v) :: insertSorted rest key leaf
      else
        (key, leaf) :: Kv.Model.erase rest key

theorem insertSorted_perm (bindings : List (List U8 × U32)) (key : List U8) (leaf : U32)
    : (insertSorted bindings key leaf).Perm (Kv.Model.set bindings key leaf) := by
  induction bindings with
  | nil => simp [insertSorted, Kv.Model.set, Kv.Model.erase]
  | cons entry rest ih =>
      obtain ⟨k, v⟩ := entry
      unfold insertSorted
      by_cases hlt : key < k
      · have hne : k ≠ key := ne_of_gt hlt
        simp [hlt, Kv.Model.set, Kv.Model.erase, hne]
      · by_cases hgt : k < key
        · have hne : k ≠ key := ne_of_lt hgt
          simp only [hlt, hgt, ite_false, ite_true]
          have hstep : Kv.Model.set ((k, v) :: rest) key leaf =
              (key, leaf) :: (k, v) :: Kv.Model.erase rest key := by
            simp [Kv.Model.set, Kv.Model.erase, hne]
          rw [hstep]
          exact (ih.cons (k, v)).trans (List.Perm.swap (key, leaf) (k, v) _)
        · have heq : k = key := le_antisymm (le_of_not_gt hlt) (le_of_not_gt hgt)
          subst heq
          simp [Kv.Model.set, Kv.Model.erase]

theorem insertSorted_pairwise {bindings : List (List U8 × U32)}
    (sorted : bindings.Pairwise radixKeyLt) (key : List U8) (leaf : U32)
    : (insertSorted bindings key leaf).Pairwise radixKeyLt := by
  induction bindings with
  | nil => simp [insertSorted]
  | cons entry rest ih =>
      obtain ⟨k, v⟩ := entry
      obtain ⟨hhead, hrest⟩ := List.pairwise_cons.mp sorted
      unfold insertSorted
      by_cases hlt : key < k
      · simp only [hlt, ite_true]
        refine List.pairwise_cons.mpr ⟨?_, List.pairwise_cons.mpr ⟨?_, hrest.filter _⟩⟩
        · intro x hx
          rcases List.mem_cons.mp hx with rfl | hx'
          · exact (radixKeyLt_iff _ _).mpr hlt
          · have hmem := (List.mem_filter.mp hx').1
            exact radixKeyLt_trans ((radixKeyLt_iff _ _).mpr hlt) (hhead x hmem)
        · intro x hx
          exact hhead x (List.mem_filter.mp hx).1
      · by_cases hgt : k < key
        · simp only [hlt, hgt, ite_false, ite_true]
          refine List.pairwise_cons.mpr ⟨?_, ih hrest⟩
          intro x hx
          have hmem := (insertSorted_perm rest key leaf).subset hx
          rcases List.mem_cons.mp hmem with rfl | hx'
          · exact (radixKeyLt_iff _ _).mpr hgt
          · exact hhead x (List.mem_filter.mp hx').1
        · have heq : k = key := le_antisymm (le_of_not_gt hlt) (le_of_not_gt hgt)
          subst heq
          simp only [lt_irrefl, ite_false]
          refine List.pairwise_cons.mpr ⟨?_, hrest.filter _⟩
          intro x hx
          have hmem := (List.mem_filter.mp hx).1
          exact (radixKeyLt_iff _ _).mpr ((radixKeyLt_iff _ _).mp (hhead x hmem))

private theorem perm_filter_split {α : Type} (xs : List α) (p : α → Bool)
    : xs.Perm (xs.filter (fun x => !p x) ++ xs.filter p) := by
  induction xs with
  | nil => simp
  | cons x xs ih =>
      cases hpx : p x with
      | false =>
          simp only [List.filter_cons, hpx, Bool.not_false, ite_true, List.cons_append]
          exact ih.cons x
      | true =>
          simp only [List.filter_cons, hpx, Bool.not_true, ite_true]
          exact (ih.cons x).trans List.perm_middle.symm

private theorem filter_range_perm {α : Type} (xs : List α) (f : α → Nat) (n : Nat)
    (bound : ∀ x ∈ xs, f x < n)
    : xs.Perm ((List.range n).flatMap fun s => xs.filter fun x => f x == s) := by
  induction n generalizing xs with
  | zero =>
      cases xs with
      | nil => simp
      | cons x _ => exact (Nat.not_lt_zero _ (bound x List.mem_cons_self)).elim
  | succ n ih =>
      rw [List.range_succ, List.flatMap_append, List.flatMap_singleton]
      have hsplit : xs.Perm
          (xs.filter (fun x => !(f x == n)) ++ xs.filter (fun x => f x == n)) :=
        perm_filter_split xs (fun x => f x == n)
      have hlt : ∀ x ∈ xs.filter (fun x => !(f x == n)), f x < n := by
        intro x hx
        obtain ⟨hm, hne⟩ := List.mem_filter.mp hx
        have hbn : f x < n + 1 := bound x hm
        have hne' : f x ≠ n := by simpa using hne
        omega
      have hsub := ih (xs.filter (fun x => !(f x == n))) hlt
      have hfiltEq : ∀ s ∈ List.range n,
          (xs.filter (fun x => !(f x == n))).filter (fun x => f x == s) =
          xs.filter (fun x => f x == s) := by
        intro s hs
        have hslt : s < n := List.mem_range.mp hs
        rw [List.filter_filter]
        apply List.filter_congr
        intro x _
        by_cases hxs : f x = s
        · have hbeq : (s == n) = false := beq_false_of_ne (by omega)
          simp [hxs, hbeq]
        · simp [hxs]
      have hflatEq :
          ((List.range n).flatMap fun s =>
              (xs.filter (fun x => !(f x == n))).filter fun x => f x == s) =
          ((List.range n).flatMap fun s => xs.filter fun x => f x == s) := by
        apply List.flatMap_congr
        intro s hs
        exact hfiltEq s hs
      rw [hflatEq] at hsub
      exact hsplit.trans (hsub.append_right _)

private theorem radix_tree_perm_unique {V : Type}
    {dirs : List (Option Spike.radix.RadixDir)}
    {rows : List (Option (Spike.radix.RadixRow V))}
    {ha hb : Nat} {root : U32} {a b : List (List U8 × U32)}
    (ta : RadixTree dirs ha root a) (tb : RadixTree dirs hb root b)
    (ra : RadixRows rows a) (rb : RadixRows rows b)
    : a.Perm b := by
  induction ta generalizing hb b with
  | empty _ =>
      cases tb with
      | empty _ => exact .nil
      | leaf _ _ _ tagged =>
          have h0 : (0#u32 : U32).val = 0 := rfl
          have : 2147483648 ≤ (0#u32 : U32).val := tagged
          omega
      | branch _ _ _ _ pos => exact (Nat.lt_irrefl 0 pos).elim
  | leaf _ node ka tagged =>
      cases tb with
      | empty _ =>
          have h0 : (0#u32 : U32).val = 0 := rfl
          have : 2147483648 ≤ (0#u32 : U32).val := tagged
          omega
      | leaf _ _ kb _ =>
          obtain ⟨_, r1, hr1, hk1⟩ := ra (ka, node) List.mem_cons_self
          obtain ⟨_, r2, hr2, hk2⟩ := rb (kb, node) List.mem_cons_self
          have hr : r1 = r2 := Option.some.inj (hr1.symm.trans hr2)
          have hk : ka = kb := hk1.symm.trans ((congrArg (fun r => r.key.val) hr).trans hk2)
          rw [hk]
      | branch _ _ _ _ _ untagged => exact (not_lt_of_ge tagged untagged).elim
  | branch _ node dir a pos untagged live child links children ih =>
      cases tb with
      | empty _ => exact (Nat.lt_irrefl 0 pos).elim
      | leaf _ _ _ tagged => exact (not_lt_of_ge tagged untagged).elim
      | branch _ _ dirB b _ _ liveB childB linksB childrenB =>
          have hdir : dir = dirB := Option.some.inj (Option.some.inj (live.symm.trans liveB))
          subst hdir
          have hslot : ∀ s ∈ List.range 17,
              (a.filter fun row => radixSymbol row.1 dir.digit.val == s).Perm
              (b.filter fun row => radixSymbol row.1 dir.digit.val == s) := by
            intro s hs
            have hlt : s < 17 := List.mem_range.mp hs
            have hc : child s = childB s :=
              Option.some.inj ((links s hlt).symm.trans (linksB s hlt))
            exact ih s hlt (hc ▸ childrenB s hlt)
              (fun e he => ra e (List.mem_filter.mp he).1)
              (fun e he => rb e (List.mem_filter.mp he).1)
          have haP := filter_range_perm a (fun row => radixSymbol row.1 dir.digit.val) 17
            (fun x _ => radixSymbol_bound x.1 dir.digit.val)
          have hbP := filter_range_perm b (fun row => radixSymbol row.1 dir.digit.val) 17
            (fun x _ => radixSymbol_bound x.1 dir.digit.val)
          have hflat : ∀ l : List Nat, (∀ s ∈ l,
              (a.filter fun row => radixSymbol row.1 dir.digit.val == s).Perm
              (b.filter fun row => radixSymbol row.1 dir.digit.val == s)) →
              (l.flatMap fun s => a.filter fun row => radixSymbol row.1 dir.digit.val == s).Perm
              (l.flatMap fun s => b.filter fun row => radixSymbol row.1 dir.digit.val == s) := by
            intro l hl
            induction l with
            | nil => exact .nil
            | cons s rest ihl =>
                simp only [List.flatMap_cons]
                exact (hl s List.mem_cons_self).append
                  (ihl (fun t ht => hl t (List.mem_cons_of_mem _ ht)))
          exact haP.trans ((hflat _ hslot).trans hbP.symm)

theorem single_view_unique {V : Type} {arena : Spike.radix.SingleRadix V}
    {root : Spike.radix.RadixRoot} {a b : List (List U8 × U32)}
    (va : SingleView arena root a) (vb : SingleView arena root b)
    : a = b := by
  obtain ⟨_, ta⟩ := va.lookup
  obtain ⟨_, tb⟩ := vb.lookup
  exact radixKeyLt_perm_eq va.sorted vb.sorted (radix_tree_perm_unique ta tb va.values vb.values)

theorem single_retains_views {V : Type} (before after : Spike.radix.SingleRadix V)
    (kept : ArenaKeeps before.values after.values)
    (root : Spike.radix.RadixRoot) (bindings : List (List U8 × U32))
    (view : SingleView before root bindings)
    : SingleView after root bindings
      ∧ singleBindings after bindings = singleBindings before bindings := by
  obtain ⟨height, tree⟩ := view.lookup
  have htree := radix_tree_preserved before.values.dirs after.values.dirs kept.dirs tree
  have hrows : RadixRows after.values.rows.val bindings := by
    intro entry hm
    obtain ⟨tag, row, saved, key⟩ := view.values entry hm
    exact ⟨tag, row, radix_old_row _ _ kept.rows _ _ saved, key⟩
  have hbind : singleBindings after bindings = singleBindings before bindings := by
    unfold singleBindings radixBindings
    apply List.filterMap_congr
    rintro ⟨k, l⟩ hm
    obtain ⟨_, row, saved, _⟩ := view.values (k, l) hm
    have hkept := radix_old_row _ _ kept.rows _ _ saved
    dsimp only
    rw [saved, hkept]
  exact ⟨⟨⟨height, htree⟩, hrows, view.sorted⟩, hbind⟩

theorem single_empty_root_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    : WP.spec (Spike.radix.SingleRadix.empty_root arena)
        (fun root => SingleView arena root []) := by
  unfold Spike.radix.SingleRadix.empty_root
  rw [WP.spec_ok]
  exact ⟨⟨0, .empty 0⟩, (fun _ h => by cases h), List.Pairwise.nil⟩

theorem single_get_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (root : Spike.radix.RadixRoot) (key : Slice U8) (bindings : List (List U8 × U32))
    (view : SingleView arena root bindings)
    : WP.spec (Spike.radix.SingleRadix.get arena root key)
        (· = Kv.Model.find (singleBindings arena bindings) key.val) := by
  obtain ⟨height, tree⟩ := view.lookup
  unfold Spike.radix.SingleRadix.get
  apply WP.spec_mono
    (radix_get_refines _ _ key height root bindings
      (by simpa [alloc.vec.Vec.deref] using tree)
      (by simpa [alloc.vec.Vec.deref] using view.values))
  intro result found
  simpa [singleBindings, alloc.vec.Vec.deref] using found

theorem single_scan_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (root : Spike.radix.RadixRoot) (bindings : List (List U8 × U32))
    (view : SingleView arena root bindings) (valid : ArenaValid arena.values)
    (room : 18 * bindings.length ≤ Usize.max)
    : WP.spec (Spike.radix.SingleRadix.scan_links arena root)
        (fun links => links.val = bindings.map Prod.snd) := by
  obtain ⟨height, tree⟩ := view.lookup
  obtain ⟨fuel, leaves, plan, hpermL⟩ :=
    radix_scan_plan_exists (alloc.vec.Vec.deref arena.values.dirs) height root bindings
      (by simpa [alloc.vec.Vec.deref] using tree)
  have hbound := radix_scan_plan_bound arena.values.dirs valid.directories
    (by simpa [alloc.vec.Vec.deref] using plan)
  have hlenL : leaves.length = bindings.length := by
    simpa [List.length_map] using hpermL.length_eq
  have comp := radix_compressed_of_knowledge arena.values.dirs _ valid.knowledge
  unfold Spike.radix.SingleRadix.scan_links
  apply WP.spec_mono
    (radix_scan_leaves_lex_refines (alloc.vec.Vec.deref arena.values.dirs)
      (alloc.vec.Vec.deref arena.values.rows) height root bindings
      (by simpa [alloc.vec.Vec.deref] using tree)
      (by simpa [alloc.vec.Vec.deref] using view.values)
      (by simpa [alloc.vec.Vec.deref] using comp)
      ⟨fuel, leaves, plan, by omega⟩)
  intro result ⟨ordered, hres, hperm, hsort⟩
  have heq : ordered = bindings := radixKeyLt_perm_eq hsort view.sorted hperm
  simpa [heq] using hres

theorem single_scan_up_to_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (root : Spike.radix.RadixRoot) (limit : Usize) (bindings : List (List U8 × U32))
    (view : SingleView arena root bindings) (valid : ArenaValid arena.values)
    (room : 18 * bindings.length ≤ Usize.max)
    : WP.spec (Spike.radix.SingleRadix.scan_links_up_to arena root limit)
        (fun links => links.val = (bindings.map Prod.snd).take limit.val) := by
  obtain ⟨height, tree⟩ := view.lookup
  obtain ⟨fuel, leaves, plan, hpermL⟩ :=
    radix_scan_plan_exists (alloc.vec.Vec.deref arena.values.dirs) height root bindings
      (by simpa [alloc.vec.Vec.deref] using tree)
  have hbound := radix_scan_plan_bound arena.values.dirs valid.directories
    (by simpa [alloc.vec.Vec.deref] using plan)
  have hlenL : leaves.length = bindings.length := by
    simpa [List.length_map] using hpermL.length_eq
  have comp := radix_compressed_of_knowledge arena.values.dirs _ valid.knowledge
  unfold Spike.radix.SingleRadix.scan_links_up_to
  apply WP.spec_mono
    (radix_scan_leaves_lex_up_to_refines (alloc.vec.Vec.deref arena.values.dirs)
      (alloc.vec.Vec.deref arena.values.rows) height root limit bindings
      (by simpa [alloc.vec.Vec.deref] using tree)
      (by simpa [alloc.vec.Vec.deref] using view.values)
      (by simpa [alloc.vec.Vec.deref] using comp)
      ⟨fuel, leaves, plan, by omega⟩)
  intro result ⟨ordered, hres, hperm, hsort⟩
  have heq : ordered = bindings := radixKeyLt_perm_eq hsort view.sorted hperm
  simpa [heq] using hres

theorem single_scan_row_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (link : U32) (row : Spike.radix.RadixRow V) (tagged : 2147483648 < link.val)
    (saved : radixRow arena.values.rows.val link = some row)
    : WP.spec (Spike.radix.SingleRadix.scan_row arena link)
        (fun out => out.1.val = row.key.val ∧ out.2 = row.value) := by
  unfold Spike.radix.SingleRadix.scan_row
  apply WP.spec_bind
    (radix_row_at_matches (alloc.vec.Vec.deref arena.values.rows) link row tagged
      (by simpa [alloc.vec.Vec.deref] using saved))
  intro found hfound
  subst found
  rw [WP.spec_ok]
  exact ⟨by simp [alloc.vec.Vec.deref], rfl⟩

/-! ### Prefix-scoped subtree descent and scan -/

private theorem has_prefix_matches (key pfx : Slice U8)
    : WP.spec (Spike.radix.has_prefix key pfx)
        (fun out => out = decide (pfx.val <+: key.val)) := by
  unfold Spike.radix.has_prefix
  have kl : (Slice.len key).val = key.val.length := Slice.len_val _
  have pl : (Slice.len pfx).val = pfx.val.length := Slice.len_val _
  by_cases hshort : Slice.len key < Slice.len pfx
  · rw [ite_eq_left hshort, WP.spec_ok]
    have hlt : key.val.length < pfx.val.length := by
      have : (Slice.len key).val < (Slice.len pfx).val := hshort
      omega
    have hno : ¬ pfx.val <+: key.val := fun h => by
      have := h.length_le; omega
    simp [hno]
  · rw [ite_eq_right hshort]
    have hge : pfx.val.length ≤ key.val.length := by
      have : ¬ (Slice.len key).val < (Slice.len pfx).val := hshort
      omega
    unfold Spike.radix.has_prefix_loop
    apply loop.spec_decr_nat (fun i : Usize => pfx.val.length - i.val)
      (fun i =>
        i.val ≤ pfx.val.length
        ∧ ∀ j, j < i.val → key.val[j]? = pfx.val[j]?)
      _ _ _
    · intro i ⟨hi, hmatch⟩
      unfold Spike.radix.has_prefix_loop.body
      have one : (1#usize : Usize).val = 1 := rfl
      by_cases run : i < Slice.len pfx
      · have hilt : i.val < pfx.val.length := by rwa [← pl]
        rw [ite_eq_left run]
        apply WP.spec_bind (Slice.index_usize_spec key i (by change i.val < key.val.length; omega))
        intro bk hbk
        apply WP.spec_bind (Slice.index_usize_spec pfx i (by change i.val < pfx.val.length; exact hilt))
        intro bp hbp
        by_cases hne : bk != bp
        · rw [ite_eq_left hne, WP.spec_ok]
          have hdiff : key.val[i.val]'(by omega) ≠ pfx.val[i.val]'hilt := by
            rw [← hbk, ← hbp]
            exact bne_iff_ne.mp hne
          have hno : ¬ pfx.val <+: key.val := by
            rintro ⟨tail, eq⟩
            have := congrArg (fun l => l[i.val]?) eq
            rw [List.getElem?_append_left hilt, List.getElem?_eq_getElem hilt,
              List.getElem?_eq_getElem (by omega)] at this
            exact hdiff (Option.some.inj this.symm)
          simp [hno]
        · rw [ite_eq_right hne]
          have heq : bk = bp := by
            by_contra h
            exact hne (bne_iff_ne.mpr h)
          have hps : pfx.val.length ≤ Usize.max := by rw [← pl]; scalar_tac
          apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
          intro next hnext
          rw [WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          intro j hj
          by_cases hji : j < i.val
          · exact hmatch j hji
          · have hjeq : j = i.val := by omega
            subst hjeq
            have hki : i.val < key.val.length := by omega
            rw [List.getElem?_eq_getElem hki, List.getElem?_eq_getElem hilt, ← hbk, ← hbp, heq]
      · have hdone : i.val = pfx.val.length := by
          have : ¬ i.val < (Slice.len pfx).val := run
          omega
        rw [ite_eq_right run, WP.spec_ok]
        have hyes : pfx.val <+: key.val := by
          refine ⟨key.val.drop pfx.val.length, ?_⟩
          apply List.ext_getElem?
          intro j
          by_cases hj : j < pfx.val.length
          · rw [List.getElem?_append_left hj, (hmatch j (by omega)).symm]
          · rw [List.getElem?_append_right (by omega), List.getElem?_drop]
            congr 1; omega
        simp [hyes]
    · have h0 : (0#usize : Usize).val = 0 := rfl
      exact ⟨by omega, fun _ h => (Nat.not_lt_zero _ (h0 ▸ h)).elim⟩

private theorem radixSymbol_prefix_iff (key pfx : List U8)
    : (∀ i, i < 2 * pfx.length → radixSymbol key i = radixSymbol pfx i)
      ↔ pfx <+: key := by
  constructor
  · intro hall
    have hlen : pfx.length ≤ key.length := by
      by_contra hlt
      have hkl : key.length < pfx.length := Nat.lt_of_not_ge hlt
      have hd := hall (2 * key.length) (by omega)
      have h0 : radixSymbol key (2 * key.length) = 0 := by
        simp [radixSymbol]
      have hpos : 0 < radixSymbol pfx (2 * key.length) := by
        simp only [radixSymbol, show 2 * key.length / 2 = key.length by omega,
          List.getElem?_eq_getElem hkl]
        split <;> omega
      omega
    refine ⟨key.drop pfx.length, ?_⟩
    apply List.ext_getElem?
    intro j
    by_cases hj : j < pfx.length
    · rw [List.getElem?_append_left hj, List.getElem?_eq_getElem hj,
        List.getElem?_eq_getElem (by omega)]
      have heven := hall (2 * j) (by omega)
      have hodd := hall (2 * j + 1) (by omega)
      simp only [radixSymbol, show 2 * j / 2 = j by omega, show (2 * j + 1) / 2 = j by omega,
        show 2 * j % 2 = 0 by omega, show (2 * j + 1) % 2 = 1 by omega, ite_true,
        show ¬ (1 = 0) by decide, ite_false, List.getElem?_eq_getElem (by omega : j < key.length),
        List.getElem?_eq_getElem hj] at heven hodd
      have hhi : (key[j]'(by omega)).val / 16 = (pfx[j]'hj).val / 16 := by omega
      have hlo : (key[j]'(by omega)).val % 16 = (pfx[j]'hj).val % 16 := by omega
      have hval : (key[j]'(by omega)).val = (pfx[j]'hj).val := by omega
      exact congrArg some (UScalar.eq_of_val_eq hval.symm)
    · rw [List.getElem?_append_right (by omega), List.getElem?_drop]
      congr 1; omega
  · rintro ⟨tail, rfl⟩ i hi
    have hdiv : i / 2 < pfx.length := by omega
    simp only [radixSymbol, List.getElem?_append_left hdiv]

private theorem sublist_filter_eq {α : Type} {p : α → Bool} {sub full : List α}
    (hsub : sub.Sublist full)
    (hmem : ∀ x ∈ full, p x = true → x ∈ sub)
    (hall : ∀ x ∈ sub, p x = true)
    (hnd : full.Nodup)
    : sub = full.filter p := by
  induction hsub with
  | slnil => simp
  | cons a hrest ih =>
      obtain ⟨haNot, hndRest⟩ := List.nodup_cons.mp hnd
      have haFalse : p a = false := by
        cases hpa : p a with
        | false => rfl
        | true =>
            have hin := hmem a List.mem_cons_self hpa
            exact (haNot (hrest.subset hin)).elim
      rw [List.filter_cons, haFalse]
      exact ih (fun x hx hpx => hmem x (List.mem_cons_of_mem _ hx) hpx) hall hndRest
  | cons_cons a hrest ih =>
      obtain ⟨haNot, hndRest⟩ := List.nodup_cons.mp hnd
      have haTrue : p a = true := hall a List.mem_cons_self
      rw [List.filter_cons, haTrue]
      apply congrArg (List.cons a)
      apply ih
      · intro x hx hpx
        have hin := hmem x (List.mem_cons_of_mem _ hx) hpx
        rcases List.mem_cons.mp hin with rfl | hin'
        · exact (haNot hx).elim
        · exact hin'
      · intro x hx
        exact hall x (List.mem_cons_of_mem _ hx)
      · exact hndRest

private theorem directory_spec (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (node : U32) (dir : Spike.radix.RadixDir)
    (hpos : 0 < node.val) (hlive : dirs.val[node.val - 1]? = some (some dir))
    : WP.spec (Spike.radix.directory (alloc.vec.Vec.deref dirs) node) (· = dir) := by
  unfold Spike.radix.directory
  have one : (1#u32 : U32).val = 1 := rfl
  apply WP.spec_bind (U32.sub_spec (x := node) (y := 1#u32) (by omega))
  intro idx hidx
  have hcast : (UScalar.cast .Usize idx).val = node.val - 1 := by
    rw [UScalar.cast_val_mod_pow_greater_numBits_eq .Usize idx
      (by
        simp only [UScalarTy.Usize_numBits_eq, UScalarTy.U32_numBits_eq]
        rcases System.Platform.numBits_eq with h | h <;> simp [h])]
    omega
  have hlen : node.val - 1 < dirs.val.length := by
    by_contra hge
    rw [List.getElem?_eq_none (by omega)] at hlive
    cases hlive
  simp only [lift, bind_ok]
  apply WP.spec_bind
    (Slice.index_usize_spec (alloc.vec.Vec.deref dirs)
      (UScalar.cast .Usize idx) (by simpa [alloc.vec.Vec.deref, hcast] using hlen))
  intro opt hopt
  have hsome : opt = some dir := by
    have := List.getElem?_eq_getElem hlen
    rw [hlive] at this
    simpa [alloc.vec.Vec.deref, hcast, hopt] using Option.some.inj this.symm
  rw [hsome, WP.spec_ok]

theorem find_prefix_subtree_refines {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow V)))
    (height : Nat) (root : U32) (pfx : Slice U8) (bindings : List (List U8 × U32))
    (tree : RadixTree dirs.val height root bindings)
    (valid : RadixRows rows.val bindings)
    (sorted : bindings.Pairwise radixKeyLt)
    (invariant : RadixDirectoryInvariant dirs)
    (compressed : RadixCompressed dirs.val (radixKeyOf rows.val))
    (prefixRoom : 2 * pfx.val.length ≤ Usize.max)
    : WP.spec
        (Spike.radix.find_prefix_subtree (alloc.vec.Vec.deref dirs)
          (alloc.vec.Vec.deref rows) root pfx)
        (fun sub =>
          ∃ h,
            RadixTree dirs.val h sub
              (bindings.filter fun row => decide (pfx.val <+: row.1))) := by
  unfold Spike.radix.find_prefix_subtree
  have pl : (Slice.len pfx).val = pfx.val.length := Slice.len_val _
  have two : (2#usize : Usize).val = 2 := rfl
  apply WP.spec_bind
    (Usize.mul_spec (x := 2#usize) (y := Slice.len pfx)
      (by rw [two, pl]; exact prefixRoom))
  intro prefixDigits hpd
  have hpdVal : prefixDigits.val = 2 * pfx.val.length := by
    rw [hpd, two, pl]
  have hnd : bindings.Nodup := by
    apply List.Pairwise.imp (fun h => ?_) sorted
    intro heq; rw [heq] at h; exact radixKeyLt_irrefl _ h
  have hLoop :
      WP.spec
        (Spike.radix.find_prefix_subtree_loop (alloc.vec.Vec.deref dirs) pfx prefixDigits root)
        (fun node =>
          ∃ h sub,
            RadixTree dirs.val h node sub
            ∧ sub.Sublist bindings
            ∧ (∀ e ∈ bindings, pfx.val <+: e.1 → e ∈ sub)
            ∧ (node ≠ 0#u32 → node < 2147483648#u32 →
                ∃ dir, dirs.val[node.val - 1]? = some (some dir) ∧ prefixDigits.val ≤ dir.digit.val)) := by
    unfold Spike.radix.find_prefix_subtree_loop
    have hInv :
        ∃ h sub,
          RadixTree dirs.val h root sub
          ∧ sub.Sublist bindings
          ∧ (∀ e ∈ bindings, pfx.val <+: e.1 → e ∈ sub) :=
      ⟨height, bindings, tree, List.Sublist.refl _, fun _ hm _ => hm⟩
    let measure (node : U32) : Nat := by
      classical
      exact if h : ∃ ht, ∃ sub, RadixTree dirs.val ht node sub then Nat.find h else 0
    apply loop.spec_decr_nat measure
      (fun node =>
        ∃ h sub,
          RadixTree dirs.val h node sub
          ∧ sub.Sublist bindings
          ∧ (∀ e ∈ bindings, pfx.val <+: e.1 → e ∈ sub))
      _ _ _
    · intro node ⟨h, sub, htree, hsub, hmem⟩
      unfold Spike.radix.find_prefix_subtree_loop.body
      by_cases hnz : node != 0#u32
      · rw [ite_eq_left hnz]
        have hnodePos : 0 < node.val := by
          have hne : node ≠ 0#u32 := bne_iff_ne.mp hnz
          have : node.val ≠ 0 := fun hz => hne (UScalar.eq_of_val_eq hz)
          omega
        by_cases hlow : node < Spike.radix.RADIX_LEAF_TAG
        · rw [ite_eq_left hlow]
          have hltTag : node < 2147483648#u32 := by simpa [Spike.radix.RADIX_LEAF_TAG] using hlow
          cases htree with
          | empty _ => exact (bne_iff_ne.mp hnz rfl).elim
          | leaf _ _ _ tagged => exact (not_lt_of_ge tagged hltTag).elim
          | branch h' _ dir _ _ _ hlive child hlinks hchildren =>
              apply WP.spec_bind (directory_spec dirs node dir hnodePos hlive)
              intro d hd; subst d
              by_cases hge : dir.digit >= prefixDigits
              · rw [ite_eq_left hge, WP.spec_ok]
                refine ⟨h' + 1, sub, .branch h' node dir sub hnodePos hltTag hlive child hlinks hchildren,
                  hsub, hmem, fun _ _ => ⟨dir, hlive, hge⟩⟩
              · rw [ite_eq_right hge]
                have hdigLt : dir.digit.val < 2 * pfx.val.length := by
                  have : ¬ prefixDigits.val ≤ dir.digit.val := hge
                  omega
                apply WP.spec_bind (radix_symbol_matches pfx dir.digit)
                intro slot hslot
                have hslotLt : slot.val < 17 := by
                  rw [hslot]; exact radixSymbol_bound pfx.val dir.digit.val
                apply WP.spec_bind
                  (Array.index_usize_spec dir.children slot (by simpa using hslotLt))
                intro next hnext
                rw [WP.spec_ok]
                have hchildEq : next = child slot.val := by
                  have hl := hlinks slot.val hslotLt
                  rw [List.getElem?_eq_getElem (by simp [hslotLt])] at hl
                  exact hnext.trans (Option.some.inj hl)
                subst hchildEq
                have htreeNext := hchildren slot.val hslotLt
                have hsubNext : (sub.filter fun row => radixSymbol row.1 dir.digit.val == slot.val).Sublist bindings :=
                  (List.filter_sublist).trans hsub
                have hmemNext : ∀ e ∈ bindings, pfx.val <+: e.1 →
                    e ∈ sub.filter fun row => radixSymbol row.1 dir.digit.val == slot.val := by
                  intro e he hpre
                  refine List.mem_filter.mpr ⟨hmem e he hpre, ?_⟩
                  have hsym := (radixSymbol_prefix_iff e.1 pfx.val).mpr hpre dir.digit.val hdigLt
                  rw [hsym, ← hslot]
                  simp
                have hdec : measure (child slot.val) < measure node := by
                  classical
                  have hexNode : ∃ ht, ∃ s, RadixTree dirs.val ht node s :=
                    ⟨h' + 1, sub, .branch h' node dir sub hnodePos hltTag hlive child hlinks hchildren⟩
                  have hexChild : ∃ ht, ∃ s, RadixTree dirs.val ht (child slot.val) s :=
                    ⟨h', _, htreeNext⟩
                  simp only [measure, dite_eq_left hexNode, dite_eq_left hexChild]
                  obtain ⟨sMin, htreeMin⟩ := Nat.find_spec hexNode
                  generalize hmEq : Nat.find hexNode = m at htreeMin
                  cases htreeMin with
                  | empty _ => exact (bne_iff_ne.mp hnz rfl).elim
                  | leaf _ _ _ tagged => exact (not_lt_of_ge tagged hltTag).elim
                  | branch m' _ dirMin _ _ _ hliveMin childMin hlinksMin hchildrenMin =>
                      have hdirSame : dirMin = dir :=
                        Option.some.inj (Option.some.inj (hliveMin.symm.trans hlive))
                      subst hdirSame
                      have hcSame : childMin slot.val = child slot.val :=
                        Option.some.inj ((hlinksMin slot.val hslotLt).symm.trans (hlinks slot.val hslotLt))
                      have hleChild : Nat.find hexChild ≤ m' :=
                        Nat.find_min' hexChild ⟨_, hcSame ▸ hchildrenMin slot.val hslotLt⟩
                      omega
                exact ⟨⟨h', _, htreeNext, hsubNext, hmemNext⟩, hdec⟩
        · rw [ite_eq_right hlow, WP.spec_ok]
          refine ⟨h, sub, htree, hsub, hmem, fun _ hlt => ?_⟩
          have : ¬ node < 2147483648#u32 := by simpa [Spike.radix.RADIX_LEAF_TAG] using hlow
          exact (this hlt).elim
      · rw [ite_eq_right hnz, WP.spec_ok]
        have hzero : node = 0#u32 := by
          by_contra hne
          exact hnz (bne_iff_ne.mpr hne)
        exact ⟨h, sub, htree, hsub, hmem, fun hne _ => (hne hzero).elim⟩
    · exact hInv
  apply WP.spec_bind hLoop
  intro node ⟨h, sub, htree, hsub, hmem, hstop⟩
  by_cases hzero : node = 0#u32
  · rw [ite_eq_left hzero, WP.spec_ok]
    subst hzero
    have hsubNil : sub = [] := by
      cases htree with
      | empty _ => rfl
      | leaf _ _ _ tagged =>
          have h0 : (0#u32 : U32).val = 0 := rfl
          have : 2147483648 ≤ (0#u32 : U32).val := tagged
          omega
      | branch _ _ _ _ pos => exact (Nat.lt_irrefl 0 pos).elim
    have hfiltNil : bindings.filter (fun row => decide (pfx.val <+: row.1)) = [] := by
      rw [List.filter_eq_nil_iff]
      intro e he hpre
      have hin := hmem e he (of_decide_eq_true hpre)
      rw [hsubNil] at hin
      cases hin
    rw [hfiltNil]
    exact ⟨0, .empty 0⟩
  · rw [ite_eq_right hzero]
    have hvalidSub : RadixRows rows.val sub := fun e he => valid e (hsub.subset he)
    have hrepSpec :
        WP.spec
          (if node < Spike.radix.RADIX_LEAF_TAG then do
              let rd ← Spike.radix.directory (alloc.vec.Vec.deref dirs) node
              Result.ok rd.first
            else Result.ok node)
          (fun rep =>
            ∃ rk, (rk, rep) ∈ sub
              ∧ (∀ e ∈ sub, (pfx.val <+: e.1) ↔ (pfx.val <+: rk))) := by
      by_cases hlow : node < Spike.radix.RADIX_LEAF_TAG
      · rw [ite_eq_left hlow]
        have hltTag : node < 2147483648#u32 := by simpa [Spike.radix.RADIX_LEAF_TAG] using hlow
        obtain ⟨dir, hlive, hdigGe⟩ := hstop hzero hltTag
        have hnodePos : 0 < node.val := by
          have : node.val ≠ 0 := fun hz => hzero (UScalar.eq_of_val_eq hz)
          omega
        apply WP.spec_bind (directory_spec dirs node dir hnodePos hlive)
        intro d hd; subst d
        rw [WP.spec_ok]
        have hrep := radix_representatives_of_invariant dirs invariant h node sub dir htree
          hnodePos hltTag hlive
        obtain ⟨rk, hrkMem⟩ := hrep
        have hkeyOf : ∀ row ∈ sub, radixKeyOf rows.val row.2 = some row.1 := by
          intro row hrow
          obtain ⟨_, r, hr, hk⟩ := hvalidSub row hrow
          simp [radixKeyOf, hr, hk]
        have hcomp := compressed h node sub dir htree hnodePos hltTag hlive hkeyOf
        refine ⟨rk, hrkMem, ?_⟩
        intro e he
        rw [← radixSymbol_prefix_iff e.1 pfx.val, ← radixSymbol_prefix_iff rk pfx.val]
        constructor <;> intro hall i hi
        · rw [← hcomp e he (rk, dir.first) hrkMem i (by omega)]
          exact hall i hi
        · rw [hcomp e he (rk, dir.first) hrkMem i (by omega)]
          exact hall i hi
      · rw [ite_eq_right hlow, WP.spec_ok]
        have hgeTag : (2147483648#u32 : U32) ≤ node := by
          have : ¬ node < 2147483648#u32 := by simpa [Spike.radix.RADIX_LEAF_TAG] using hlow
          exact le_of_not_gt this
        cases htree with
        | empty _ => exact (hzero rfl).elim
        | leaf _ _ key _ =>
            refine ⟨key, List.mem_cons_self, ?_⟩
            intro e he
            rw [List.mem_singleton.mp he]
        | branch _ _ _ _ _ untagged => exact (not_lt_of_ge hgeTag untagged).elim
    apply WP.spec_bind hrepSpec
    intro rep ⟨rk, hrkMem, hiff⟩
    obtain ⟨htag, rrow, hsaved, hkeyEq⟩ := hvalidSub (rk, rep) hrkMem
    apply WP.spec_bind
      (radix_row_at_matches (alloc.vec.Vec.deref rows) rep rrow htag
        (by simpa [alloc.vec.Vec.deref] using hsaved))
    intro rr hrr; subst rr
    apply WP.spec_bind (has_prefix_matches (alloc.vec.Vec.deref rrow.key) pfx)
    intro yes hyes
    have hyes' : yes = decide (pfx.val <+: rk) := by
      simpa [alloc.vec.Vec.deref, hkeyEq] using hyes
    cases yes with
    | true =>
        rw [ite_eq_left rfl, WP.spec_ok]
        have hrkPre : pfx.val <+: rk := of_decide_eq_true hyes'.symm
        have hfilt : sub = bindings.filter (fun row => decide (pfx.val <+: row.1)) :=
          sublist_filter_eq hsub
            (fun e he hdec => hmem e he (of_decide_eq_true hdec))
            (fun e he => decide_eq_true ((hiff e he).mpr hrkPre))
            hnd
        exact ⟨h, hfilt ▸ htree⟩
    | false =>
        rw [ite_eq_right (by decide), WP.spec_ok]
        have hrkNo : ¬ pfx.val <+: rk := of_decide_eq_false hyes'.symm
        have hfiltNil : bindings.filter (fun row => decide (pfx.val <+: row.1)) = [] := by
          rw [List.filter_eq_nil_iff]
          intro e he hdec
          have hin := hmem e he (of_decide_eq_true hdec)
          exact hrkNo ((hiff e hin).mp (of_decide_eq_true hdec))
        rw [hfiltNil]
        exact ⟨0, .empty 0⟩

theorem single_scan_prefix_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (root : Spike.radix.RadixRoot) (pfx : Slice U8) (bindings : List (List U8 × U32))
    (view : SingleView arena root bindings) (valid : ArenaValid arena.values)
    (prefixRoom : 2 * pfx.val.length ≤ Usize.max)
    (scanRoom : 18 * bindings.length ≤ Usize.max)
    : WP.spec (Spike.radix.SingleRadix.scan_prefix_links arena root pfx)
        (fun links =>
          links.val
          = (bindings.filter fun row => decide (pfx.val <+: row.1)).map Prod.snd) := by
  obtain ⟨height, tree⟩ := view.lookup
  have comp := radix_compressed_of_knowledge arena.values.dirs _ valid.knowledge
  unfold Spike.radix.SingleRadix.scan_prefix_links Spike.radix.scan_prefix_leaves
  apply WP.spec_bind
    (find_prefix_subtree_refines arena.values.dirs arena.values.rows height root pfx
      bindings tree view.values view.sorted valid.directories comp prefixRoom)
  intro sub ⟨hsub, htreeSub⟩
  let filtered := bindings.filter fun row => decide (pfx.val <+: row.1)
  have hviewSub : SingleView arena sub filtered :=
    ⟨⟨hsub, htreeSub⟩,
      fun e he => view.values e (List.mem_filter.mp he).1,
      view.sorted.filter _⟩
  have hlenLe : filtered.length ≤ bindings.length := List.length_filter_le _ _
  exact single_scan_refines arena sub filtered hviewSub valid (by omega)

end KvRust
