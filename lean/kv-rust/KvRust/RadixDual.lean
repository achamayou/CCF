-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Radix
public import KvRust.RadixAddress
public import KvRust.Range
public import KvRust.Assoc

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- Encode each live binding's stamp, keeping its leaf link and model order. -/
def dualStampBindings {V : Type}
    (rows : List (Option (Spike.radix.RadixRow (Spike.radix.Stamped V))))
    (bindings : List (List U8 × U32))
    : List (List U8 × U32) :=
  bindings.filterMap
    fun (_, leaf) =>
      (radixRow rows leaf).map fun row => (reverseStampBytes row.value.stamp, leaf)

/-- Both directory roots describe the same values. The lookup bindings are in
model order, and the stamp directory stores that order by increasing byte key. -/
structure DualView {V : Type} (arena : Spike.radix.DualRadix V)
    (root : Spike.radix.DualRoot) (bindings : List (List U8 × U32))
    : Prop where
  lookup : ∃ height, RadixTree arena.values.dirs.val height root.lookup bindings
  values : RadixRows arena.values.rows.val bindings
  order
    : ∃ (height : Nat) (keys : List (List U8 × U32)),
        RadixTree arena.order.dirs.val height root.order keys
        ∧ RadixRows arena.order.rows.val keys
        ∧ radixBindings arena.order.rows.val keys
          = dualStampBindings arena.values.rows.val bindings
        ∧ keys.Pairwise radixKeyLt
  stamps
    : ∀ a ∈ bindings,
      ∀ b ∈ bindings,
        ∀ x y,
          radixRow arena.values.rows.val a.2 = some x
          → radixRow arena.values.rows.val b.2 = some y
          → (x.value.stamp = y.value.stamp ↔ a.1 = b.1)
  issued
    : ∀ entry ∈ bindings,
        ∀ row,
          radixRow arena.values.rows.val entry.2 = some row
          → row.value.stamp.val ≤ arena.last.val

structure ArenaValid {V : Type} (arena : Spike.radix.Arena V) : Prop where
  dirs : RadixFree arena.dirs arena.free_dirs
  rows : RadixFree arena.rows arena.free_rows
  directories : RadixDirectoryInvariant arena.dirs
  knowledge : RadixKnowledge arena.dirs (radixKeyOf arena.rows.val)

structure ArenaKeeps {V : Type} (before after : Spike.radix.Arena V) : Prop where
  dirs : preservesSlots before.dirs after.dirs
  rows
    : ∀ (i : Nat) row,
        before.rows.val[i]? = some (some row) → after.rows.val[i]? = some (some row)

theorem ArenaKeeps.refl {V : Type} (arena : Spike.radix.Arena V)
    : ArenaKeeps arena arena :=
  ⟨fun _ _ h => h, fun _ _ h => h⟩

theorem ArenaKeeps.trans {V : Type} {a b c : Spike.radix.Arena V}
    (first : ArenaKeeps a b) (second : ArenaKeeps b c)
    : ArenaKeeps a c :=
  ⟨
    fun i d h => second.dirs i d (first.dirs i d h),
    fun i row h => second.rows i row (first.rows i row h)
  ⟩

def ArenaGrowth {V : Type} (before after : Spike.radix.Arena V) (dirs rows : Nat)
    : Prop :=
  after.dirs.val.length ≤ before.dirs.val.length + dirs
  ∧ after.rows.val.length ≤ before.rows.val.length + rows

theorem arena_put_refines {V : Type} (arena : Spike.radix.Arena V) (root : U32)
    (row : Spike.radix.RadixRow V) (height : Nat) (bindings : List (List U8 × U32))
    (tree : RadixTree arena.dirs.val height root bindings)
    (rows : RadixRows arena.rows.val bindings) (valid : ArenaValid arena)
    (room : arena.dirs.val.length + height + 1 ≤ 2147483647)
    (rowRoom : arena.rows.val.length < 2147483647)
    (keyRoom : 2 * row.key.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.Arena.put arena root row)
        (fun ((next, leaf, old), after) =>
          ArenaValid after
          ∧ ArenaKeeps arena after
          ∧ old = Kv.Model.find bindings row.key.val
          ∧ radixRow after.rows.val leaf = some row
          ∧ ArenaGrowth arena after (height + 1) 1
          ∧ ∃ h,
              RadixTree after.dirs.val h next (Kv.Model.set bindings row.key.val leaf)
              ∧ RadixRows after.rows.val (Kv.Model.set bindings row.key.val leaf)
              ∧ radixBindings after.rows.val (Kv.Model.set bindings row.key.val leaf)
                = Kv.Model.set (radixBindings arena.rows.val bindings) row.key.val
                    row.value) := by
  unfold Spike.radix.Arena.put
  have knows := radix_compressed_of_knowledge arena.dirs _ valid.knowledge
  apply WP.spec_bind
    (radix_put_refines arena.dirs arena.free_dirs arena.rows arena.free_rows arena.path
      root row height bindings tree rows knows valid.directories valid.dirs valid.rows
      room rowRoom keyRoom)
  rintro ⟨updates, dirs, freeDirs, values, freeRows, path⟩
    ⟨keepDirs, vacantDirs, inv, knowledge, vacantRows, keepRows, eq, ins,
      dirGrowth, rowGrowth, h, ht, hr, hp⟩
  change WP.spec (Result.ok (updates,
    ({ dirs, rows := values, free_dirs := freeDirs, free_rows := freeRows, path } : Spike.radix.Arena V))) _
  rw [WP.spec_ok]
  obtain ⟨next, leaf, old⟩ := updates
  exact ⟨
    ⟨vacantDirs, vacantRows, inv, knowledge valid.knowledge⟩,
    ⟨keepDirs, keepRows⟩,
    eq,
    ins,
    ⟨by simpa only [Nat.add_assoc] using dirGrowth, rowGrowth⟩,
    h,
    ht,
    hr,
    hp
  ⟩

theorem arena_remove_refines {V : Type} (arena : Spike.radix.Arena V) (root : U32)
    (key : Slice U8) (height : Nat) (bindings : List (List U8 × U32))
    (tree : RadixTree arena.dirs.val height root bindings)
    (rows : RadixRows arena.rows.val bindings) (valid : ArenaValid arena)
    (room : arena.dirs.val.length + height ≤ 2147483647)
    : WP.spec (Spike.radix.Arena.remove arena root key)
        (fun (next, after) =>
          ArenaValid after
          ∧ ArenaKeeps arena after
          ∧ after.rows = arena.rows
          ∧ after.dirs.val.length ≤ arena.dirs.val.length + height
          ∧ ∃ h,
              RadixTree after.dirs.val h next (Kv.Model.erase bindings key.val)
              ∧ RadixRows after.rows.val (Kv.Model.erase bindings key.val)
              ∧ radixBindings after.rows.val (Kv.Model.erase bindings key.val)
                = Kv.Model.erase (radixBindings arena.rows.val bindings) key.val) := by
  unfold Spike.radix.Arena.remove
  have knows := radix_compressed_of_knowledge arena.dirs _ valid.knowledge
  apply WP.spec_bind
    (radix_remove_refines arena.dirs arena.free_dirs (alloc.vec.Vec.deref arena.rows)
      arena.path root key height bindings tree (by simpa [alloc.vec.Vec.deref] using rows)
      valid.dirs valid.directories (by simpa [alloc.vec.Vec.deref] using knows) room)
  rintro ⟨next, dirs, free, path⟩ ⟨kept, vacant, inv, knowledge, growth, h, ht, hr, hp⟩
  change WP.spec (Result.ok (next, { arena with dirs, free_dirs := free, path })) _
  rw [WP.spec_ok]
  refine ⟨
    ⟨vacant, valid.rows, inv, ?_⟩,
    ⟨kept, fun _ _ he => he⟩,
    rfl,
    growth,
    h,
    ht,
    ?_,
    ?_
  ⟩
  · simpa [alloc.vec.Vec.deref]
      using knowledge (by simpa [alloc.vec.Vec.deref] using valid.knowledge)
  · simpa [alloc.vec.Vec.deref] using hr
  · simpa [alloc.vec.Vec.deref] using hp

/-- The value image deliberately forgets the private stamps. -/
def dualBindings {V : Type} (arena : Spike.radix.DualRadix V)
    (bindings : List (List U8 × U32))
    : List (List U8 × V) :=
  (radixBindings arena.values.rows.val bindings).map fun (key, cell) => (key, cell.value)

theorem dual_get_refines {V : Type} (arena : Spike.radix.DualRadix V)
    (root : Spike.radix.DualRoot) (key : Slice U8) (bindings : List (List U8 × U32))
    (view : DualView arena root bindings)
    : WP.spec (Spike.radix.DualRadix.get arena root key)
        (· = Kv.Model.find (dualBindings arena bindings) key.val) := by
  obtain ⟨height, tree⟩ := view.lookup
  unfold Spike.radix.DualRadix.get
  apply WP.spec_bind
    (radix_get_refines _ _ key height root.lookup bindings
      (by simpa [alloc.vec.Vec.deref] using tree)
      (by simpa [alloc.vec.Vec.deref] using view.values))
  intro result found
  have projected := find_projected (radixBindings arena.values.rows.val bindings) key.val id
    Spike.radix.Stamped.value (fun _ _ h => h)
  change Kv.Model.find (dualBindings arena bindings) key.val =
    (Kv.Model.find (radixBindings arena.values.rows.val bindings) key.val).map
      Spike.radix.Stamped.value at projected
  have resolved : result = Kv.Model.find (radixBindings arena.values.rows.val bindings) key.val := by
    simpa [alloc.vec.Vec.deref] using found
  rw [projected, ← resolved]
  cases result <;> simp

private def orderTarget (rows : List (Option (Spike.radix.RadixRow U32))) (link : U32)
    : U32 :=
  ((radixRow rows link).map Spike.radix.RadixRow.value).getD 0#u32

private theorem scan_links_remap
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow U32))) (input : alloc.vec.Vec U32)
    (live
      : ∀ link ∈ input.val,
          2147483648 < link.val ∧ ∃ row, radixRow rows.val link = some row)
    : WP.spec (Spike.radix.DualRadix.scan_links_up_to_loop rows input 0#usize)
        (fun out => out.val = input.val.map (orderTarget rows.val)) := by
  let project := orderTarget rows.val
  unfold Spike.radix.DualRadix.scan_links_up_to_loop
  apply loop.spec_decr_nat
    (fun (p : alloc.vec.Vec U32 × Usize) => input.val.length - p.2.val)
    (fun (links, i) =>
      links.val.length = input.val.length
      ∧ ∀ j : Nat,
          links.val[j]? = if j < i.val then input.val[j]?.map project else input.val[j]?)
    _ _ _
  · rintro ⟨links, i⟩ ⟨sameLen, mapping⟩
    dsimp only at sameLen mapping ⊢
    unfold Spike.radix.DualRadix.scan_links_up_to_loop.body
    have len : (alloc.vec.Vec.len links).val = input.val.length :=
      (alloc.vec.Vec.len_val links).trans sameLen
    have cap := alloc.vec.Vec.len_ineq input
    have one : (1#usize : Usize).val = 1 := rfl
    by_cases run : i < alloc.vec.Vec.len links
    · have hlt : i.val < input.val.length := by rwa [← len]
      have inside : i.val < links.val.length := sameLen ▸ hlt
      rw [ite_eq_left run, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec links i inside)
      intro leaf read
      have same : input.val[i.val]? = some leaf := by
        have h := mapping i.val
        rw [ite_eq_right (Nat.lt_irrefl _), List.getElem?_eq_getElem inside, ← read] at h
        exact h.symm
      have member : leaf ∈ input.val := List.mem_iff_getElem?.mpr ⟨_, same⟩
      obtain ⟨tag, row, saved⟩ := live leaf member
      apply WP.spec_bind (radix_row_at_matches (alloc.vec.Vec.deref rows) leaf row tag
        (by simpa [alloc.vec.Vec.deref] using saved))
      intro found eq
      subst found
      rw [alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec links i inside)
      rintro ⟨_, back⟩ ⟨_, setter⟩
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro next step
      have inc : next.val = i.val + 1 := by omega
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨?_, ?_⟩, by omega⟩
      · simp [setter, alloc.vec.Vec.set_val_eq, sameLen]
      · intro j
        rw [setter, alloc.vec.Vec.set_val_eq]
        by_cases hit : j = i.val
        · subst j
          rw [List.getElem?_set_self inside, ite_eq_left (by omega), same]
          simp [project, orderTarget, saved]
        · rw [List.getElem?_set_ne (Ne.symm hit), mapping]
          have earlier : j < next.val ↔ j < i.val := by omega
          simp only [earlier]
    · have past : input.val.length ≤ i.val := by rw [← len]; exact Nat.le_of_not_gt run
      rw [ite_eq_right run, WP.spec_ok]
      apply List.ext_getElem?
      intro j
      rw [List.getElem?_map, mapping]
      by_cases inside : j < i.val
      · simp [inside, project]
      · have hb : input.val.length ≤ j := by omega
        simp [inside, List.getElem?_eq_none hb]
  · simp

private theorem order_link_projection (rows : List (Option (Spike.radix.RadixRow U32)))
    (bindings : List (List U8 × U32)) (valid : RadixRows rows bindings)
    : (bindings.map Prod.snd).map (orderTarget rows)
      = (radixBindings rows bindings).map Prod.snd := by
  induction bindings with
  | nil => rfl
  | cons p tail ih =>
      obtain ⟨_, row, saved, _⟩ := valid p List.mem_cons_self
      have rest := ih (fun e hm => valid e (List.mem_cons_of_mem _ hm))
      simpa [orderTarget, radixBindings, saved, List.map_map]
        using congrArg (row.value :: ·) rest

private theorem stamp_links {V : Type}
    (rows : List (Option (Spike.radix.RadixRow (Spike.radix.Stamped V))))
    (bindings : List (List U8 × U32)) (valid : RadixRows rows bindings)
    : (dualStampBindings rows bindings).map Prod.snd = bindings.map Prod.snd := by
  induction bindings with
  | nil => rfl
  | cons p rest ih =>
      obtain ⟨_, row, saved, _⟩ := valid p List.mem_cons_self
      have tail := ih (fun e hm => valid e (List.mem_cons_of_mem _ hm))
      simp [dualStampBindings, saved] at tail ⊢
      exact tail

private theorem radix_rows_from_links {V : Type}
    (rows : List (Option (Spike.radix.RadixRow V))) (a b : List (List U8 × U32))
    (liveA : RadixRows rows a) (liveB : RadixRows rows b)
    (links : a.map Prod.snd = b.map Prod.snd)
    : a = b := by
  induction a generalizing b with
  | nil => cases b <;> simp_all
  | cons p tail ih =>
      cases b with
      | nil => simp at links
      | cons q next =>
          simp only [List.map_cons, List.cons.injEq] at links
          obtain ⟨_, row, read, key⟩ := liveA p List.mem_cons_self
          obtain ⟨_, row', read', key'⟩ := liveB q List.mem_cons_self
          rw [links.1, read', Option.some.injEq] at read
          have same : p = q := Prod.ext (key.symm.trans (read ▸ key')) links.1
          exact congrArg₂ List.cons same (ih next
            (fun e h => liveA e (List.mem_cons_of_mem _ h))
            (fun e h => liveB e (List.mem_cons_of_mem _ h)) links.2)

private theorem radix_key_asymm {a b : List U8 × U32}
    (ab : radixKeyLt a b) (ba : radixKeyLt b a)
    : False := by
  have ltAB : a.1 < b.1 := (byteOrder_lt _ _).mp (by
    unfold radixKeyLt at ab
    rw [ab]
    decide)
  have ltBA : b.1 < a.1 := (byteOrder_lt _ _).mp (by
    unfold radixKeyLt at ba
    rw [ba]
    decide)
  exact (lt_asymm ltAB ltBA).elim

/-- The two roots fix the ordered association list even without capacity assumptions. -/
theorem dual_view_unique {V : Type} {arena : Spike.radix.DualRadix V}
    {root : Spike.radix.DualRoot} {a b : List (List U8 × U32)}
    (va : DualView arena root a) (vb : DualView arena root b)
    : a = b := by
  obtain ⟨ha, ka, ta, ra, pa, oa⟩ := va.order
  obtain ⟨hb, kb, tb, rb, pb, ob⟩ := vb.order
  have keys (rs : List (List U8 × U32)) (live : RadixRows arena.order.rows.val rs)
      : ∀ row ∈ rs, radixKeyOf arena.order.rows.val row.2 = some row.1 := by
    intro row hm
    obtain ⟨_, item, read, same⟩ := live row hm
    simp [radixKeyOf, read, same]
  have mem := radix_projection_membership arena.order.dirs.val
    (radixKeyOf arena.order.rows.val) root.order ha hb ka kb ta tb (keys ka ra) (keys kb rb)
  have nodup (xs : List (List U8 × U32)) (ordered : xs.Pairwise radixKeyLt) : xs.Nodup := by
    change xs.Pairwise (· ≠ ·)
    apply List.Pairwise.imp _ ordered
    intro x y h eq
    subst y
    exact radix_key_asymm h h
  have perm := (List.perm_ext_iff_of_nodup (nodup ka oa) (nodup kb ob)).mpr mem
  have same := List.Perm.eq_of_pairwise (le := radixKeyLt)
    (fun _ _ _ _ ab ba => (radix_key_asymm ab ba).elim) oa ob perm
  subst kb
  apply radix_rows_from_links arena.values.rows.val a b va.values vb.values
  rw [← stamp_links _ _ va.values, ← stamp_links _ _ vb.values, ← pa, ← pb]

/-- The native stamp traversal and in-place resolution return precisely the
lookup links in model order, without sorting or copying the lookup image. -/
theorem dual_scan_up_to_refines {V : Type} (arena : Spike.radix.DualRadix V)
    (root : Spike.radix.DualRoot) (limit : Usize) (bindings : List (List U8 × U32))
    (view : DualView arena root bindings)
    (compressed : RadixCompressed arena.order.dirs.val (radixKeyOf arena.order.rows.val))
    (room
      : ∃ fuel leaves,
          RadixScanPlan arena.order.dirs.val ([root.order].filter (· != 0#u32)) fuel
            leaves
          ∧ fuel ≤ Usize.max)
    : WP.spec (Spike.radix.DualRadix.scan_links_up_to arena root limit)
        (fun links => links.val = (bindings.map Prod.snd).take limit.val) := by
  obtain ⟨height, keys, tree, valid, pairing, order⟩ := view.order
  unfold Spike.radix.DualRadix.scan_links_up_to
  apply WP.spec_bind
    (radix_scan_leaves_lex_up_to_refines (alloc.vec.Vec.deref arena.order.dirs)
      (alloc.vec.Vec.deref arena.order.rows) height root.order limit keys
      (by simpa [alloc.vec.Vec.deref] using tree)
      (by simpa [alloc.vec.Vec.deref] using valid)
      (by simpa [alloc.vec.Vec.deref] using compressed)
      (by simpa [alloc.vec.Vec.deref] using room))
  rintro links ⟨ordered, walked, perm, sorted⟩
  have unique : ordered = keys := by
    apply List.Perm.eq_of_pairwise (le := radixKeyLt) _ sorted order perm
    intro a b _ _ left right
    exact (radix_key_asymm left right).elim
  subst ordered
  have live : ∀ link ∈ links.val, 2147483648 < link.val ∧
      ∃ row, radixRow arena.order.rows.val link = some row := by
    intro link mem
    rw [walked] at mem
    obtain ⟨e, hm, linkEq⟩ := List.mem_map.mp (List.mem_of_mem_take mem)
    obtain ⟨tag, row, read, _⟩ := valid e hm
    exact linkEq ▸ ⟨tag, row, read⟩
  apply WP.spec_mono (scan_links_remap arena.order.rows links live)
  intro out remapped
  rw [remapped, walked, List.map_take, order_link_projection _ _ valid, pairing,
    stamp_links _ _ view.values]

theorem dual_scan_row_refines {V : Type} (arena : Spike.radix.DualRadix V)
    (root : Spike.radix.DualRoot) (bindings : List (List U8 × U32))
    (view : DualView arena root bindings) (entry : List U8 × U32)
    (member : entry ∈ bindings)
    : WP.spec (Spike.radix.DualRadix.scan_row arena entry.2)
        (fun (key, value) =>
          ∃ row,
            radixRow arena.values.rows.val entry.2 = some row
            ∧ key.val = entry.1
            ∧ value = row.value.value) := by
  obtain ⟨tag, row, saved, same⟩ := view.values entry member
  unfold Spike.radix.DualRadix.scan_row
  apply WP.spec_bind
    (radix_row_at_matches _ entry.2 row tag (by simpa [alloc.vec.Vec.deref] using saved))
  intro actual h
  rw [WP.spec_ok, h]
  exact ⟨row, saved, by simpa [alloc.vec.Vec.deref] using same, rfl⟩

private theorem stamp_erase {V : Type}
    (rows : List (Option (Spike.radix.RadixRow (Spike.radix.Stamped V))))
    (bindings : List (List U8 × U32)) (key : List U8) (stamp : U64)
    (valid : RadixRows rows bindings)
    (matchesStamp
      : ∀ entry ∈ bindings,
          ∀ row,
            radixRow rows entry.2 = some row → (row.value.stamp = stamp ↔ entry.1 = key))
    : dualStampBindings rows (Kv.Model.erase bindings key)
      = Kv.Model.erase (dualStampBindings rows bindings) (reverseStampBytes stamp) := by
  induction bindings with
  | nil => rfl
  | cons p tail ih =>
      obtain ⟨k, l⟩ := p
      obtain ⟨_, row, saved, _⟩ := valid (k, l) List.mem_cons_self
      have matchesKey := matchesStamp (k, l) List.mem_cons_self row saved
      have encoded : reverseStampBytes row.value.stamp = reverseStampBytes stamp ↔ k = key :=
        ⟨fun h => matchesKey.mp (reverse_stamp_bytes_inj h),
          fun h => congrArg reverseStampBytes (matchesKey.mpr h)⟩
      have rest := ih (fun e hm => valid e (List.mem_cons_of_mem _ hm))
        (fun e hm => matchesStamp e (List.mem_cons_of_mem _ hm))
      by_cases same : k = key
      · simpa [Kv.Model.erase, dualStampBindings, saved, same, encoded.mpr same] using rest
      · have diff : reverseStampBytes row.value.stamp ≠ reverseStampBytes stamp :=
          fun he => same (encoded.mp he)
        simpa [Kv.Model.erase, dualStampBindings, saved, same, diff]
          using congrArg ((reverseStampBytes row.value.stamp, l) :: ·) rest

private theorem dual_erase_value_projection {V : Type}
    (rows : List (List U8 × Spike.radix.Stamped V)) (key : List U8)
    : (Kv.Model.erase rows key).map (fun (k, v) => (k, v.value))
      = Kv.Model.erase (rows.map (fun (k, v) => (k, v.value))) key :=
  (erase_projected rows key id Spike.radix.Stamped.value (fun _ _ h => h)).symm

/-- Removal deletes the same binding from both roots, leaving all older slots live. -/
theorem dual_remove_refines {V : Type} (arena : Spike.radix.DualRadix V)
    (root : Spike.radix.DualRoot) (bindings : List (List U8 × U32)) (key : Slice U8)
    (view : DualView arena root bindings) (lookupOK : ArenaValid arena.values)
    (orderOK : ArenaValid arena.order)
    (height orderHeight : Nat) (keys : List (List U8 × U32))
    (tree : RadixTree arena.values.dirs.val height root.lookup bindings)
    (orderTree : RadixTree arena.order.dirs.val orderHeight root.order keys)
    (orderRows : RadixRows arena.order.rows.val keys)
    (pairing
      : radixBindings arena.order.rows.val keys
        = dualStampBindings arena.values.rows.val bindings)
    (orderSorted : keys.Pairwise radixKeyLt)
    (room : arena.values.dirs.val.length + height ≤ 2147483647)
    (roomOrder : arena.order.dirs.val.length + orderHeight ≤ 2147483647)
    : WP.spec (Spike.radix.DualRadix.remove arena root key)
        (fun (next, after) =>
          DualView after next (Kv.Model.erase bindings key.val)
          ∧ dualBindings after (Kv.Model.erase bindings key.val)
            = Kv.Model.erase (dualBindings arena bindings) key.val
          ∧ ArenaValid after.values
          ∧ ArenaValid after.order
          ∧ ArenaKeeps arena.values after.values
          ∧ ArenaKeeps arena.order after.order
          ∧ after.last = arena.last
          ∧ ArenaGrowth arena.values after.values height 0
          ∧ ArenaGrowth arena.order after.order orderHeight 0) := by
  unfold Spike.radix.DualRadix.remove
  have live : RadixRows (alloc.vec.Vec.deref arena.values.rows).val bindings := by
    simpa [alloc.vec.Vec.deref] using view.values
  apply WP.spec_bind
    (radix_get_matches (alloc.vec.Vec.deref arena.values.dirs)
      (alloc.vec.Vec.deref arena.values.rows) key height root.lookup bindings
      (by simpa [alloc.vec.Vec.deref] using tree)
      live)
  intro selected hs
  have resolved : selected = (Kv.Model.find bindings key.val).bind
      (fun leaf => (radixRow arena.values.rows.val leaf).map Spike.radix.RadixRow.value) := by
    simpa [alloc.vec.Vec.deref] using hs
  cases found : Kv.Model.find bindings key.val with
  | none =>
      have absent : ∀ leaf, (key.val, leaf) ∉ bindings := by
        simpa only [found] using find_binding bindings key.val
      have unchanged : Kv.Model.erase bindings key.val = bindings := by
        apply List.filter_eq_self.mpr
        rintro ⟨k, l⟩ hm
        have diff : k ≠ key.val := fun he => absent l (he ▸ hm)
        simp [diff]
      have noValue : selected = none := by simpa [found] using resolved
      rw [noValue, WP.spec_ok]
      refine ⟨unchanged.symm ▸ view, ?_, lookupOK, orderOK, .refl _, .refl _, rfl,
        ⟨Nat.le_add_right _ _, Nat.le_refl _⟩, ⟨Nat.le_add_right _ _, Nat.le_refl _⟩⟩
      rw [unchanged]
      unfold dualBindings
      rw [← dual_erase_value_projection]
      rw [← radix_project_erase arena.values.rows.val bindings key.val, unchanged]
  | some leaf =>
      have hit : (key.val, leaf) ∈ bindings := by simpa only [found] using find_binding bindings key.val
      obtain ⟨_, old, saved, _⟩ := view.values _ hit
      have eq : selected = some old.value := by simpa [found, saved] using resolved
      rw [eq]
      apply WP.spec_bind (reverse_stamp_key_refines old.value.stamp)
      intro encoded he
      let bytes := alloc.vec.Vec.deref encoded
      have keyEq : bytes.val = reverseStampBytes old.value.stamp := by
        simpa [bytes, alloc.vec.Vec.deref] using he
      apply WP.spec_bind
        (arena_remove_refines arena.order root.order bytes orderHeight keys
          orderTree orderRows orderOK roomOrder)
      rintro ⟨order, orderAfter⟩ ⟨validOrder, keepsOrder, orderFixed, orderGrowth, oh, ot, orows, op⟩
      apply WP.spec_bind
        (arena_remove_refines arena.values root.lookup key height bindings tree
          view.values lookupOK room)
      rintro ⟨value, valueAfter⟩ ⟨validValues, keepsValues, valuesUnchanged, valueGrowth, vh, vt, vrows, vp⟩
      change WP.spec (Result.ok (({ lookup := value, order } : Spike.radix.DualRoot),
        { arena with values := valueAfter, order := orderAfter })) _
      rw [WP.spec_ok]
      have paired : radixBindings orderAfter.rows.val (Kv.Model.erase keys bytes.val)
          = dualStampBindings valueAfter.rows.val (Kv.Model.erase bindings key.val) := by
        rw [op, pairing, keyEq, valuesUnchanged, stamp_erase _ _ _ _ view.values]
        intro e hm row live
        exact view.stamps e hm (key.val, leaf) hit row old live saved
      refine ⟨
        ⟨
          ⟨vh, vt⟩,
          vrows,
          ⟨oh, Kv.Model.erase keys bytes.val, ot, orows, paired, orderSorted.filter _⟩,
          ?_,
          ?_
        ⟩,
        ?_,
        validValues,
        validOrder,
        keepsValues,
        keepsOrder,
        rfl,
        ⟨valueGrowth, by rw [valuesUnchanged, Nat.add_zero]⟩,
        ⟨orderGrowth, by rw [orderFixed, Nat.add_zero]⟩
      ⟩
      · intro a ha b hb x y hx hy
        rw [valuesUnchanged] at hx hy
        exact view.stamps a (List.mem_filter.mp ha).1 b (List.mem_filter.mp hb).1 x y hx hy
      · intro e hm row hr
        rw [valuesUnchanged] at hr
        exact view.issued e (List.mem_filter.mp hm).1 row hr
      · unfold dualBindings
        rw [vp, dual_erase_value_projection]

private structure PreparedOrder (before after : Spike.radix.Arena U32)
    (root : U32) (height : Nat) (keys target : List (List U8 × U32))
    : Prop where
  valid : ArenaValid after
  kept : ArenaKeeps before after
  fixedRows : after.rows = before.rows
  growth : after.dirs.val.length ≤ before.dirs.val.length + height
  view
    : ∃ active,
        active.Sublist keys
        ∧ RadixTree after.dirs.val active.length root active
        ∧ RadixRows after.rows.val active
        ∧ radixBindings after.rows.val active = target
        ∧ active.Pairwise radixKeyLt

private theorem prepare_order_before_insert {V : Type} (arena : Spike.radix.DualRadix V)
    (root : Spike.radix.DualRoot) (values : Spike.radix.Arena (Spike.radix.Stamped V))
    (bindings keys : List (List U8 × U32)) (view : DualView arena root bindings)
    (orderOK : ArenaValid arena.order) (height : Nat)
    (tree : RadixTree arena.order.dirs.val height root.order keys)
    (rows : RadixRows arena.order.rows.val keys)
    (pairing
      : radixBindings arena.order.rows.val keys
        = dualStampBindings arena.values.rows.val bindings)
    (sorted : keys.Pairwise radixKeyLt)
    (room : arena.order.dirs.val.length + height ≤ 2147483647)
    (kept : ArenaKeeps arena.values values) (key : List U8) (old : Option U32)
    (found : old = Kv.Model.find bindings key)
    : WP.spec
        (match old with
          | none => Result.ok (values, arena.order, root.order)
          | some link => do
              let previous ← Spike.radix.row_at (alloc.vec.Vec.deref values.rows) link
              let encoded ← Spike.radix.reverse_stamp_key previous.value.stamp
              let (order, after) ←
                Spike.radix.Arena.remove arena.order root.order
                  (alloc.vec.Vec.deref encoded)
              Result.ok (values, after, order))
        (fun (same, after, order) =>
          same = values
          ∧ PreparedOrder arena.order after order height keys
              (dualStampBindings arena.values.rows.val
                (Kv.Model.erase bindings key))) := by
  cases old with
  | none =>
      have absent : ∀ leaf, (key, leaf) ∉ bindings := by
        simpa only [← found] using find_binding bindings key
      rw [erase_absent bindings key absent, WP.spec_ok]
      exact ⟨
        rfl,
        orderOK,
        .refl _,
        rfl,
        by omega,
        keys,
        List.Sublist.refl _,
        (radix_tree_binding_bound _ orderOK.directories tree).1,
        rows,
        pairing,
        sorted
      ⟩
  | some link =>
      have hit : (key, link) ∈ bindings := by
        simpa only [← found] using find_binding bindings key
      obtain ⟨tag, row, saved, _⟩ := view.values _ hit
      have retained := radix_old_row arena.values.rows.val values.rows.val kept.rows link row saved
      apply WP.spec_bind
        (radix_row_at_matches _ link row tag
          (by simpa [alloc.vec.Vec.deref] using retained))
      intro oldRow read
      subst oldRow
      apply WP.spec_bind (reverse_stamp_key_refines row.value.stamp)
      intro encoded he
      let bytes := alloc.vec.Vec.deref encoded
      have keyEq : bytes.val = reverseStampBytes row.value.stamp := by
        simpa [bytes, alloc.vec.Vec.deref] using he
      apply WP.spec_bind (arena_remove_refines arena.order root.order bytes height keys
        tree rows orderOK room)
      rintro ⟨order, after⟩ ⟨valid, preserves, fixed, growth, h, ht, hr, hp⟩
      change WP.spec (Result.ok (values, after, order)) _
      rw [WP.spec_ok]
      refine ⟨
        rfl,
        valid,
        preserves,
        fixed,
        growth,
        Kv.Model.erase keys bytes.val,
        List.filter_sublist,
        (radix_tree_binding_bound _ valid.directories ht).1,
        hr,
        ?_,
        sorted.filter _
      ⟩
      rw [hp, pairing, keyEq, stamp_erase _ _ _ _ view.values]
      intro e hm item live
      exact view.stamps e hm (key, link) hit item row live saved

private theorem stamp_projection_kept {V : Type}
    (before after : Spike.radix.Arena (Spike.radix.Stamped V))
    (kept : ArenaKeeps before after) (bindings : List (List U8 × U32))
    (valid : RadixRows before.rows.val bindings)
    : dualStampBindings after.rows.val bindings
      = dualStampBindings before.rows.val bindings := by
  unfold dualStampBindings
  apply List.filterMap_congr
  intro entry hm
  obtain ⟨_, row, saved, _⟩ := valid entry hm
  have preserved := radix_old_row _ _ kept.rows _ _ saved
  rcases entry with ⟨k, l⟩
  simp [preserved, saved]

private theorem stamp_of_order_key {V : Type} (arena : Spike.radix.DualRadix V)
    (bindings keys : List (List U8 × U32))
    (rows : RadixRows arena.order.rows.val keys)
    (pairing
      : radixBindings arena.order.rows.val keys
        = dualStampBindings arena.values.rows.val bindings)
    (entry : List U8 × U32) (member : entry ∈ keys)
    : ∃ e ∈ bindings,
        ∃ row,
          radixRow arena.values.rows.val e.2
            = some (row : Spike.radix.RadixRow (Spike.radix.Stamped V))
          ∧ entry.1 = reverseStampBytes row.value.stamp := by
  obtain ⟨_, orderRow, live, _⟩ := rows entry member
  have projected : (entry.1, orderRow.value) ∈ radixBindings arena.order.rows.val keys :=
    List.mem_filterMap.mpr ⟨entry, member, by simp [live]⟩
  rw [pairing] at projected
  obtain ⟨⟨k, leaf⟩, hm, eq⟩ := List.mem_filterMap.mp projected
  cases old : radixRow arena.values.rows.val leaf with
  | none => simp [old] at eq
  | some row =>
      have bytes := Option.some.inj (by simpa [old] using eq :
        some (reverseStampBytes row.value.stamp, leaf) = some (entry.1, orderRow.value))
      exact ⟨(k, leaf), hm, row, old, (congrArg Prod.fst bytes).symm⟩

/-- Replacing a key updates both persistent roots and puts the new binding first. -/
theorem dual_put_refines {V : Type} (arena : Spike.radix.DualRadix V)
    (root : Spike.radix.DualRoot) (bindings : List (List U8 × U32))
    (row : Spike.radix.RadixRow V) (view : DualView arena root bindings)
    (lookupOK : ArenaValid arena.values) (orderOK : ArenaValid arena.order)
    (height orderHeight : Nat) (keys : List (List U8 × U32))
    (tree : RadixTree arena.values.dirs.val height root.lookup bindings)
    (orderTree : RadixTree arena.order.dirs.val orderHeight root.order keys)
    (orderRows : RadixRows arena.order.rows.val keys)
    (pairing
      : radixBindings arena.order.rows.val keys
        = dualStampBindings arena.values.rows.val bindings)
    (orderSorted : keys.Pairwise radixKeyLt)
    (room : arena.values.dirs.val.length + height + 1 ≤ 2147483647)
    (roomOrder : arena.order.dirs.val.length + orderHeight + keys.length + 1 ≤ 2147483647)
    (valueRoom : arena.values.rows.val.length < 2147483647)
    (stampRoom : arena.order.rows.val.length < 2147483647)
    (keyRoom : 2 * row.key.val.length + 1 ≤ Usize.max)
    (counterRoom : arena.last.val < U64.max)
    : WP.spec (Spike.radix.DualRadix.put arena root row)
        (fun (next, after) =>
          ∃ leaf,
            DualView after next (Kv.Model.set bindings row.key.val leaf)
            ∧ dualBindings after (Kv.Model.set bindings row.key.val leaf)
              = Kv.Model.set (dualBindings arena bindings) row.key.val row.value
            ∧ ArenaValid after.values
            ∧ ArenaValid after.order
            ∧ ArenaKeeps arena.values after.values
            ∧ ArenaKeeps arena.order after.order
            ∧ after.last.val = arena.last.val + 1
            ∧ ArenaGrowth arena.values after.values (height + 1) 1
            ∧ ArenaGrowth arena.order after.order (orderHeight + keys.length + 1) 1) := by
  have hmax : core.num.U64.MAX.val = U64.max := by rw [U64.max_eq]; rfl
  have fits : arena.last < core.num.U64.MAX := by
    change arena.last.val < core.num.U64.MAX.val
    omega
  have one : (1#u64 : U64).val = 1 := rfl
  unfold Spike.radix.DualRadix.put
  simp only [massert, fits, ite_true, bind_ok]
  apply WP.spec_bind (U64.add_spec (x := arena.last) (y := 1#u64) (by omega))
  intro stamp hs
  have fresh : stamp.val = arena.last.val + 1 := by omega
  let written : Spike.radix.RadixRow (Spike.radix.Stamped V) :=
    {key := row.key, value := {stamp, value := row.value}}
  apply WP.spec_bind (arena_put_refines arena.values root.lookup written height bindings
    tree view.values lookupOK room valueRoom keyRoom)
  rintro ⟨⟨lookup, leaf, old⟩, values⟩
    ⟨lookupValid, keptValues, found, inserted, valueGrowth, vh, vt, vr, vp⟩
  apply WP.spec_bind
    (prepare_order_before_insert arena root values bindings keys view orderOK orderHeight
      orderTree orderRows pairing orderSorted (by omega) keptValues row.key.val old found)
  rintro ⟨sameValues, trimmed, order⟩ ⟨same, cleared⟩
  subst sameValues
  obtain ⟨active, subset, trimmedTree, trimmedRows, trimmedPairs, sorted⟩ := cleared.view
  apply WP.spec_bind (reverse_stamp_key_refines stamp)
  intro encoded he
  have len : encoded.val.length = 8 := by rw [he, reverseStampBytes, Array.length_eq]; rfl
  have trimmedRoom : trimmed.dirs.val.length + active.length + 1 ≤ 2147483647 := by
    have growth := cleared.growth
    have count := subset.length_le
    omega
  apply WP.spec_bind
    (arena_put_refines trimmed order {key := encoded, value := leaf}
      active.length active trimmedTree trimmedRows cleared.valid trimmedRoom
      (by rw [cleared.fixedRows]; exact stampRoom)
      (by rw [len]; scalar_tac))
  rintro ⟨⟨order', orderLeaf, _⟩, orderAfter⟩
    ⟨validOrder, keptOrder, _, _, orderGrowth, oh, ot, orows, op⟩
  let after : Spike.radix.DualRadix V := {values, order := orderAfter, last := stamp}
  change WP.spec (Result.ok (({lookup, order := order'} : Spike.radix.DualRoot), after)) _
  rw [WP.spec_ok]
  let remaining := Kv.Model.erase bindings row.key.val
  have remMember (e : List U8 × U32) (hm : e ∈ remaining) : e ∈ bindings :=
    (List.mem_filter.mp hm).1
  have remKey (e : List U8 × U32) (hm : e ∈ remaining) : e.1 ≠ row.key.val := by
    have ok := (List.mem_filter.mp hm).2
    simpa [bne_iff_ne] using ok
  have oldRows : RadixRows arena.values.rows.val remaining :=
    fun e hm => view.values e (remMember e hm)
  have keptRead (e : List U8 × U32) (hm : e ∈ remaining) (item)
      (read : radixRow values.rows.val e.2 = some item)
      : radixRow arena.values.rows.val e.2 = some item := by
    obtain ⟨_, previous, h, _⟩ := oldRows e hm
    have saved := radix_old_row _ _ keptValues.rows _ _ h
    rw [read, Option.some.injEq] at saved
    exact h.trans (congrArg some saved.symm)
  have isNew (e : List U8 × U32) (hm : e ∈ Kv.Model.set bindings row.key.val leaf)
      : e = (row.key.val, leaf) ∨ e ∈ remaining := List.mem_cons.mp hm
  have afterStamps : dualStampBindings values.rows.val (Kv.Model.set bindings row.key.val leaf) =
      (reverseStampBytes stamp, leaf) :: dualStampBindings arena.values.rows.val remaining := by
    have unchanged := stamp_projection_kept _ _ keptValues remaining oldRows
    change dualStampBindings values.rows.val ((row.key.val, leaf) :: remaining) = _
    have expanded : dualStampBindings values.rows.val ((row.key.val, leaf) :: remaining) =
        (reverseStampBytes stamp, leaf) :: dualStampBindings values.rows.val remaining := by
      simp [dualStampBindings, inserted, written]
    rw [expanded, unchanged]
  have unissued : Kv.Model.erase (dualStampBindings arena.values.rows.val remaining) encoded.val =
      dualStampBindings arena.values.rows.val remaining := by
    apply List.filter_eq_self.mpr
    intro p hp
    obtain ⟨e, hm, hp'⟩ := List.mem_filterMap.mp hp
    cases hr : radixRow arena.values.rows.val e.2 with
    | none => simp [hr] at hp'
    | some item =>
        have same : p = (reverseStampBytes item.value.stamp, e.2) := by simpa [hr] using hp'.symm
        have lower := view.issued e (remMember e hm) item hr
        have diff : reverseStampBytes item.value.stamp ≠ reverseStampBytes stamp := by
          intro eq
          have eq := congrArg UScalar.val (reverse_stamp_bytes_inj eq)
          omega
        simp [same, he, diff]
  have paired : radixBindings orderAfter.rows.val (Kv.Model.set active encoded.val orderLeaf) =
      dualStampBindings values.rows.val (Kv.Model.set bindings row.key.val leaf) := by
    rw [op, trimmedPairs, afterStamps]
    change (encoded.val, leaf) :: Kv.Model.erase (dualStampBindings arena.values.rows.val remaining)
      encoded.val = _
    rw [unissued, he]
  have ordered : (Kv.Model.set active encoded.val orderLeaf).Pairwise radixKeyLt := by
    apply List.pairwise_cons.mpr
    refine ⟨?_, sorted.filter _⟩
    intro entry hm
    obtain ⟨e, issued, item, read, packed⟩ :=
      stamp_of_order_key arena bindings keys orderRows pairing entry
        (subset.subset (List.mem_filter.mp hm).1)
    have lower := view.issued e issued item read
    change byteOrder encoded.val entry.1 = _
    rw [he, packed]
    exact reverse_stamp_order _ _ (by omega)
  refine ⟨leaf, ⟨⟨vh, vt⟩, vr, ⟨oh, Kv.Model.set active encoded.val orderLeaf, ot, orows,
    paired, ordered⟩, ?_, ?_⟩, ?_, lookupValid, validOrder, keptValues,
    cleared.kept.trans keptOrder, fresh, valueGrowth, ?_⟩
  · intro a ha b hb x y hx hy
    change radixRow values.rows.val a.2 = some x at hx
    change radixRow values.rows.val b.2 = some y at hy
    rcases isNew a ha with rfl | oldA <;> rcases isNew b hb with rfl | oldB
    · rw [inserted, Option.some.injEq] at hx hy
      simp [← hx, ← hy]
    · rw [inserted, Option.some.injEq] at hx
      have read := keptRead b oldB y hy
      have smaller := view.issued b (remMember b oldB) y read
      have diff : stamp ≠ y.value.stamp := by
        intro he
        have he := congrArg UScalar.val he
        omega
      simp [← hx, written, diff, Ne.symm (remKey b oldB)]
    · rw [inserted, Option.some.injEq] at hy
      have read := keptRead a oldA x hx
      have smaller := view.issued a (remMember a oldA) x read
      have diff : x.value.stamp ≠ stamp := by
        intro he
        have he := congrArg UScalar.val he
        omega
      simp [← hy, written, diff, remKey a oldA]
    · exact view.stamps a (remMember a oldA) b (remMember b oldB) x y
        (keptRead a oldA x hx) (keptRead b oldB y hy)
  · intro e hm item read
    change radixRow values.rows.val e.2 = some item at read
    change item.value.stamp.val ≤ stamp.val
    rcases isNew e hm with rfl | old
    · rw [inserted, Option.some.injEq] at read
      simp [← read, written]
    · have h := view.issued e (remMember e old) item (keptRead e old item read)
      omega
  · unfold dualBindings
    change (radixBindings values.rows.val (Kv.Model.set bindings row.key.val leaf)).map _ = _
    rw [vp]
    exact (set_projected _ row.key.val written.value id Spike.radix.Stamped.value
      (fun _ _ h => h)).symm
  · have allocated := cleared.growth
    have remaining := subset.length_le
    obtain ⟨dirs, rows⟩ := orderGrowth
    change ArenaGrowth arena.order orderAfter (orderHeight + keys.length + 1) 1
    exact ⟨by omega, by rwa [cleared.fixedRows] at rows⟩

/-- Both indices are empty at construction and satisfy the arena invariants. -/
theorem dual_new_refines (V : Type)
    : WP.spec (Spike.radix.DualRadix.new V)
        (fun arena =>
          ArenaValid arena.values
          ∧ ArenaValid arena.order
          ∧ WP.spec (Spike.radix.DualRadix.empty_root arena)
              (fun root => DualView arena root [])) := by
  have emptyValid (T : Type) :
      WP.spec (Spike.radix.Arena.new T) (fun arena =>
        ArenaValid arena ∧ arena.dirs.val = [] ∧ arena.rows.val = []) := by
    unfold Spike.radix.Arena.new
    rw [WP.spec_ok]
    refine ⟨⟨by simp [RadixFree], by simp [RadixFree], ?_, radix_empty_knowledge _⟩, rfl, rfl⟩
    intro i d live
    simp at live
  unfold Spike.radix.DualRadix.new
  apply WP.spec_bind (emptyValid (Spike.radix.Stamped V))
  intro values ⟨valueOK, _, _⟩
  apply WP.spec_bind (emptyValid U32)
  intro order ⟨orderOK, _, _⟩
  rw [WP.spec_ok]
  refine ⟨valueOK, orderOK, ?_⟩
  unfold Spike.radix.DualRadix.empty_root
  rw [WP.spec_ok]
  refine ⟨⟨0, .empty 0⟩, ?_, ⟨0, [], .empty 0, ?_, rfl, List.Pairwise.nil⟩, ?_, ?_⟩ <;>
    simp [RadixRows]

/-- Every previously retained root pair still describes exactly the same ordered
values after publication of a new pair. -/
theorem dual_retains_views {V : Type} (before after : Spike.radix.DualRadix V)
    (values : ArenaKeeps before.values after.values)
    (order : ArenaKeeps before.order after.order)
    (clock : before.last.val ≤ after.last.val) (root : Spike.radix.DualRoot)
    (bindings : List (List U8 × U32)) (view : DualView before root bindings)
    : DualView after root bindings
      ∧ dualBindings after bindings = dualBindings before bindings := by
  obtain ⟨vh, vt⟩ := view.lookup
  obtain ⟨oh, keys, ot, orows, pairs, sorted⟩ := view.order
  obtain ⟨lookup, lookupRows, lookupValues⟩ :=
    radix_preserves_roots _ _ _ _ values.dirs values.rows vh root.lookup bindings vt view.values
  obtain ⟨chronology, orderRows, orderValues⟩ :=
    radix_preserves_roots _ _ _ _ order.dirs order.rows oh root.order keys ot orows
  have stamps := stamp_projection_kept _ _ values bindings view.values
  have keptRead (e : List U8 × U32) (hm : e ∈ bindings) (row)
      (read : radixRow after.values.rows.val e.2 = some row)
      : radixRow before.values.rows.val e.2 = some row := by
    obtain ⟨_, original, old, _⟩ := view.values e hm
    have same := Option.some.inj ((radix_old_row _ _ values.rows _ _ old).symm.trans read)
    exact old.trans (congrArg some same)
  constructor
  · refine ⟨⟨vh, lookup⟩, lookupRows,
      ⟨oh, keys, chronology, orderRows, orderValues.trans (pairs.trans stamps.symm), sorted⟩,
      ?_, ?_⟩
    · intro a ha b hb x y hx hy
      exact view.stamps a ha b hb x y (keptRead a ha x hx) (keptRead b hb y hy)
    · intro e hm row read
      exact (view.issued e hm row (keptRead e hm row read)).trans clock
  · simp [dualBindings, lookupValues]

end KvRust
