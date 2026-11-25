-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Radix

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- For a nonempty link, count incoming references from pins and directory slots.
Directories awaiting retirement still contribute their outgoing references. -/
def radixReferences (dirs : List (Option CcfKv.radix.RadixDir)) (pins : List U32)
    (target : U32)
    : Nat :=
  (pins ++ (dirs.filterMap id).flatMap (·.children.val)).count target

private theorem count_zero_iff (n : U32) : n = 0#u32 ↔ n.val = 0 :=
  ⟨fun h => h ▸ rfl, fun h => UScalar.eq_of_val_eq h⟩

/-- Adding an owner increments the exact multiplicity of the referenced link. -/
theorem retain_reference_matches (count target : U32) (owners : List U32)
    (exactCount : count.val = owners.count target) (room : count.val < U32.max)
    : WP.spec (CcfKv.radix.retain_reference count)
        (fun (first, next) =>
          first = decide (owners.count target = 0)
          ∧ next.val = (target :: owners).count target) := by
  have limit : core.num.U32.MAX.val = U32.max := by rw [U32.max_eq]; rfl
  have fits : count < core.num.U32.MAX := by
    change count.val < core.num.U32.MAX.val
    omega
  have one : (1#u32 : U32).val = 1 := rfl
  simp only [CcfKv.radix.retain_reference, massert, fits, ite_true, bind_ok]
  apply WP.spec_bind (U32.add_spec (x := count) (y := 1#u32) (by omega))
  intro next inc
  rw [WP.spec_ok]
  exact ⟨
    decide_eq_decide.mpr (by rw [count_zero_iff count, exactCount]),
    by simpa [exactCount] using inc
  ⟩

/-- Removing one owner queues this link exactly when its remaining owner count is zero. -/
theorem release_reference_matches (count target : U32) (owners : List U32)
    (exactCount : count.val = (target :: owners).count target)
    : WP.spec (CcfKv.radix.release_reference count)
        (fun (last, next) =>
          last = decide (owners.count target = 0) ∧ next.val = owners.count target) := by
  have one : (1#u32 : U32).val = 1 := rfl
  have old : count.val = owners.count target + 1 := by simpa using exactCount
  have live : (0#u32 : U32) < count := by change 0 < count.val; omega
  simp only [CcfKv.radix.release_reference, massert, live, ite_true, bind_ok]
  apply WP.spec_bind (U32.sub_spec (x := count) (y := 1#u32) (by omega))
  intro next dec
  have exactNext : next.val = owners.count target := by omega
  rw [WP.spec_ok]
  exact ⟨decide_eq_decide.mpr (by rw [count_zero_iff next, exactNext]), exactNext⟩

inductive RadixReachable (dirs : List (Option CcfKv.radix.RadixDir)) (root : U32)
    : U32 → Prop where
  | root : RadixReachable dirs root root
  | child {parent node : U32} {dir : CcfKv.radix.RadixDir}
    (prev : RadixReachable dirs root parent)
    (positive : 0 < parent.val)
    (untagged : parent < 2147483648#u32)
    (live : dirs[parent.val - 1]? = some (some dir))
    (edge : node ∈ dir.children.val)
    : RadixReachable dirs root node

private theorem radix_reach_trans {dirs : List (Option CcfKv.radix.RadixDir)}
    {root mid n : U32} (first : RadixReachable dirs root mid)
    (second : RadixReachable dirs mid n)
    : RadixReachable dirs root n := by
  induction second with
  | root => exact first
  | child _ positive untagged live edge ih => exact .child ih positive untagged live edge

/-- The zero-reference test is sufficient even with a nonempty retirement queue. -/
theorem radix_zero_unreachable (dirs : List (Option CcfKv.radix.RadixDir))
    (pins : List U32) (target root : U32) (pinned : root ∈ pins)
    (zero : radixReferences dirs pins target = 0)
    : ¬RadixReachable dirs root target := by
  intro reach
  have absent : target ∉ (pins ++ (dirs.filterMap id).flatMap (·.children.val)) := by
    intro hm
    have h := List.count_pos_iff.mpr hm
    unfold radixReferences at zero
    rw [zero] at h
    exact (Nat.not_lt_zero _) h
  apply absent
  cases reach with
  | root => exact List.mem_append_left _ pinned
  | child _ _ _ live edge =>
      have mem : some _ ∈ dirs := List.mem_iff_getElem?.mpr ⟨_, live⟩
      exact List.mem_append_right _ (List.mem_flatMap.mpr
        ⟨_, List.mem_filterMap.mpr ⟨some _, mem, rfl⟩, edge⟩)

private theorem radix_tree_keep_reachable
    (before after : List (Option CcfKv.radix.RadixDir)) {height : Nat} {root : U32}
    {bindings : List (List U8 × U32)} (tree : RadixTree before height root bindings)
    (keep
      : ∀ n,
          0 < n.val
          → RadixReachable before root n
          → after[n.val - 1]? = before[n.val - 1]?)
    : RadixTree after height root bindings := by
  induction tree with
  | empty height => exact .empty height
  | leaf height node key tagged => exact .leaf height node key tagged
  | branch height root dir bindings positive untagged live child slots kids ih =>
      refine .branch height root dir bindings positive untagged
        ((keep root positive .root).trans live) child slots ?_
      intro slot bound
      apply ih slot bound
      intro n pos h
      have atChild : RadixReachable before root (child slot) :=
        .child .root positive untagged live (List.mem_iff_getElem?.mpr ⟨slot, slots slot bound⟩)
      exact keep n pos (radix_reach_trans atChild h)

private theorem recycled_slots_eq {α : Type} (before after : List (Option α))
    (index : Nat) (old : α) (live : before[index]? = some (some old))
    (cleared : after[index]? = some none)
    (kept : ∀ i, i ≠ index → after[i]? = before[i]?)
    : after = before.set index none := by
  have bound := (List.getElem?_eq_some_iff.mp live).1
  apply List.ext_getElem?
  intro i
  by_cases eq : i = index
  · subst i
    rw [cleared, List.getElem?_set_self bound]
  · rw [kept i eq, List.getElem?_set_ne (Ne.symm eq)]

private theorem remove_one_live_slot {α : Type} (slots : List (Option α))
    (index : Nat) (old : α) (live : slots[index]? = some (some old))
    : List.Perm (((slots.set index none).filterMap id) ++ [old])
        (slots.filterMap id) := by
  induction slots generalizing index with
  | nil => simp at live
  | cons head rest ih =>
      cases index with
      | zero =>
          have eq : head = some old := Option.some.inj live
          subst head
          simp
      | succ i =>
          have h := ih i live
          cases head with
          | none => exact h
          | some owner => exact h.cons owner

private theorem recycled_directory_invariant
    (before after : alloc.vec.Vec (Option CcfKv.radix.RadixDir))
    (pins : List U32) (node : U32) (index : Usize)
    (link : node.val = index.val + 1) (zero : radixReferences before.val pins node = 0)
    (cleared : after.val[index.val]? = some none)
    (keep : ∀ i, i ≠ index.val → after.val[i]? = before.val[i]?)
    (valid : RadixDirectoryInvariant before)
    : RadixDirectoryInvariant after := by
  intro i dir live
  have different : i ≠ index.val := by
    intro same
    rw [same, cleared] at live
    cases live
  have prior : before.val[i]? = some (some dir) := (keep i different).symm.trans live
  obtain ⟨mask, children, cache, occupied⟩ := valid i dir prior
  have notChild (child : U32) (member : child ∈ dir.children.val)
      (nz : child ≠ 0#u32) : child.val - 1 ≠ index.val := by
    intro same
    have positive : 0 < child.val := by
      by_contra no
      have empty : (0#u32 : U32).val = 0 := rfl
      exact nz (UScalar.eq_of_val_eq (by omega))
    have retired : child = node := UScalar.eq_of_val_eq (by omega)
    have listed : node ∈ pins ++ (before.val.filterMap id).flatMap (·.children.val) := by
      apply List.mem_append_right
      exact List.mem_flatMap.mpr ⟨dir, List.mem_filterMap.mpr
        ⟨some dir, List.mem_iff_getElem?.mpr ⟨i, prior⟩, rfl⟩, retired ▸ member⟩
    have count := List.count_pos_iff.mpr listed
    unfold radixReferences at zero
    omega
  refine ⟨mask, ?_, ?_, occupied⟩
  · intro child member nz untagged
    obtain ⟨value, read⟩ := children child member nz untagged
    exact ⟨value, (keep _ (notChild child member nz)).trans read⟩
  · unfold RadixFirstCache at cache ⊢
    refine ⟨cache.1, ?_⟩
    by_cases tagged : (2147483648#u32 : U32) ≤ radixFirst dir
    · simpa only [tagged, ite_true] using cache.2
    · have h := cache.2
      rw [ite_eq_right tagged] at h ⊢
      obtain ⟨child, read, same⟩ := h
      exact ⟨child, (keep _ (notChild _ (radix_first_mem dir cache.1) cache.1)).trans read, same⟩

private theorem recycled_directory_knowledge
    (before after : alloc.vec.Vec (Option CcfKv.radix.RadixDir))
    (pins : List U32) (node : U32) (index : Usize)
    (link : node.val = index.val + 1) (zero : radixReferences before.val pins node = 0)
    (cleared : after.val[index.val]? = some none)
    (keep : ∀ i, i ≠ index.val → after.val[i]? = before.val[i]?)
    (keyOf : U32 → Option (List U8)) (known : RadixKnowledge before keyOf)
    : RadixKnowledge after keyOf := by
  intro i dir live
  have different : i ≠ index.val := by
    intro same
    rw [same, cleared] at live
    cases live
  obtain ⟨root, height, rows, atRoot, tagged, projection, keys, uniform⟩ :=
    known i dir ((keep i different).symm.trans live)
  have newRoot : root ≠ node := fun eq => different (by rw [eq, link] at atRoot; omega)
  have stillZero : radixReferences before.val (root :: pins) node = 0 := by
    simpa [radixReferences, newRoot] using zero
  refine ⟨root, height, rows, atRoot, tagged, ?_, keys, uniform⟩
  apply radix_tree_keep_reachable before.val after.val projection
  intro n positive reach
  apply keep
  intro overlap
  have eq : n = node := UScalar.eq_of_val_eq (by omega)
  exact radix_zero_unreachable before.val (root :: pins) node root List.mem_cons_self
    stillZero (eq ▸ reach)

/-- Retiring a zero-count directory leaves the exact projection of every
retained root intact and removes each of its child references exactly once.
Counts must separately agree with `radixReferences`. -/
theorem radix_recycle_dir_refines
    (dirs : alloc.vec.Vec (Option CcfKv.radix.RadixDir)) (free : alloc.vec.Vec Usize)
    (pins : List U32) (node : U32) (index : Usize) (dir : CcfKv.radix.RadixDir)
    (link : node.val = index.val + 1) (live : dirs.val[index.val]? = some (some dir))
    (vacant : RadixFree dirs free) (room : free.val.length < Usize.max)
    (zero : radixReferences dirs.val pins node = 0)
    : WP.spec (CcfKv.radix.recycle_slot dirs free index)
        (fun (removed, after, avail) =>
          removed = dir
          ∧ RadixFree after avail
          ∧ (RadixDirectoryInvariant dirs → RadixDirectoryInvariant after)
          ∧ (∀ keyOf, RadixKnowledge dirs keyOf → RadixKnowledge after keyOf)
          ∧ (∀ target,
              radixReferences dirs.val pins target
              = radixReferences after.val pins target + dir.children.val.count target)
          ∧ ∀ height root bindings,
              root ∈ pins
              → RadixTree dirs.val height root bindings
              → RadixTree after.val height root bindings) := by
  apply WP.spec_mono (radix_recycle_slot_matches dirs free index dir live vacant room)
  rintro ⟨removed, after, avail⟩ ⟨same, cleared, _, valid, keep⟩
  refine ⟨
    same,
    valid,
    recycled_directory_invariant dirs after pins node index link zero cleared keep,
    recycled_directory_knowledge dirs after pins node index link zero cleared keep,
    ?_,
    ?_
  ⟩
  · intro target
    have erased := recycled_slots_eq dirs.val after.val index.val dir live cleared keep
    have perm := (remove_one_live_slot dirs.val index.val dir live).flatMap_right (·.children.val)
    have count := perm.count_eq target
    rw [← erased, List.flatMap_append, List.flatMap_cons, List.flatMap_nil, List.append_nil,
      List.count_append] at count
    simp only [radixReferences, List.count_append]
    omega
  · intro height root bindings pinned tree
    apply radix_tree_keep_reachable dirs.val after.val tree
    intro n positive reach
    apply keep
    intro overlap
    have eq : n = node := UScalar.eq_of_val_eq (by omega)
    exact radix_zero_unreachable dirs.val pins node root pinned zero (eq ▸ reach)

private theorem radix_binding_reachable (dirs : List (Option CcfKv.radix.RadixDir))
    {height : Nat} {root : U32} {bindings : List (List U8 × U32)}
    (tree : RadixTree dirs height root bindings) (entry : List U8 × U32)
    (member : entry ∈ bindings)
    : RadixReachable dirs root entry.2 := by
  induction tree with
  | empty => cases member
  | leaf height node key tagged =>
      have eq := List.mem_singleton.mp member
      rw [eq]
      exact .root
  | branch height root dir bindings positive untagged live child slots kids ih =>
      let slot := radixSymbol entry.1 dir.digit.val
      have bound : slot < 17 := radixSymbol_bound _ _
      have inChild : entry ∈ bindings.filter (fun row => radixSymbol row.1 dir.digit.val == slot) :=
        List.mem_filter.mpr ⟨member, by simp [slot]⟩
      exact radix_reach_trans
        (.child .root positive untagged live
          (List.mem_iff_getElem?.mpr ⟨slot, slots slot bound⟩))
        (ih slot bound inChild)

private theorem radix_row_kept {V : Type}
    (dirs : List (Option CcfKv.radix.RadixDir))
    (before after : List (Option (CcfKv.radix.RadixRow V)))
    (pins : List U32) (node : U32) (index : Usize)
    (link : node.val = index.val + 2147483648 + 1)
    (zero : radixReferences dirs pins node = 0)
    (keep : ∀ j : Nat, j ≠ index.val → after[j]? = before[j]?)
    {height : Nat} {root : U32} {bindings : List (List U8 × U32)}
    (pinned : root ∈ pins) (tree : RadixTree dirs height root bindings)
    (entry : List U8 × U32) (member : entry ∈ bindings)
    (tagged : 2147483648 < entry.2.val)
    : radixRow after entry.2 = radixRow before entry.2 := by
  have reach := radix_binding_reachable dirs tree entry member
  have different : entry.2.val - 2147483648 - 1 ≠ index.val := by
    intro overlap
    have eq : entry.2 = node := UScalar.eq_of_val_eq (by omega)
    exact radix_zero_unreachable dirs pins node root pinned zero (eq ▸ reach)
  unfold radixRow
  rw [keep _ different]

private theorem recycled_row_knowledge {V : Type}
    (dirs : alloc.vec.Vec (Option CcfKv.radix.RadixDir))
    (before after : List (Option (CcfKv.radix.RadixRow V)))
    (pins : List U32) (node : U32) (index : Usize)
    (link : node.val = index.val + 2147483648 + 1)
    (zero : radixReferences dirs.val pins node = 0)
    (keep : ∀ j, j ≠ index.val → after[j]? = before[j]?)
    (known : RadixKnowledge dirs (radixKeyOf before))
    : RadixKnowledge dirs (radixKeyOf after) := by
  intro i dir live
  obtain ⟨root, height, rows, atRoot, tagged, projection, keys, uniform⟩ := known i dir live
  have different : root ≠ node := by
    intro same
    have below : root.val < (2147483648#u32 : U32).val := tagged
    have tag : (2147483648#u32 : U32).val = 2147483648 := rfl
    rw [same, link, tag] at below
    omega
  have stillZero : radixReferences dirs.val (root :: pins) node = 0 := by
    simpa [radixReferences, different] using zero
  refine ⟨root, height, rows, atRoot, tagged, projection, ?_, uniform⟩
  intro entry hm
  have was := keys entry hm
  have above : 2147483648 < entry.2.val := by
    by_contra no
    simp [radixKeyOf, radixRow, no] at was
  have saved := radix_row_kept dirs.val before after (root :: pins) node index link stillZero
    keep List.mem_cons_self projection entry hm above
  unfold radixKeyOf
  rw [saved]
  exact was

/-- Recycling a zero-count row preserves the values and the exact ordered
association list of every retained root, with the same arena-relative links. -/
theorem radix_recycle_row_refines {V : Type}
    (dirs : List (Option CcfKv.radix.RadixDir))
    (rows : alloc.vec.Vec (Option (CcfKv.radix.RadixRow V))) (free : alloc.vec.Vec Usize)
    (pins : List U32) (node : U32) (index : Usize) (row : CcfKv.radix.RadixRow V)
    (link : node.val = index.val + 2147483648 + 1)
    (live : rows.val[index.val]? = some (some row)) (vacant : RadixFree rows free)
    (room : free.val.length < Usize.max) (zero : radixReferences dirs pins node = 0)
    : WP.spec (CcfKv.radix.recycle_slot rows free index)
        (fun (removed, after, avail) =>
          removed = row
          ∧ RadixFree after avail
          ∧ (∀ tree,
              tree.val = dirs
              → RadixKnowledge tree (radixKeyOf rows.val)
              → RadixKnowledge tree (radixKeyOf after.val))
          ∧ ∀ height root bindings,
              root ∈ pins
              → RadixTree dirs height root bindings
              → RadixRows rows.val bindings
              → RadixRows after.val bindings
                ∧ radixBindings after.val bindings
                  = radixBindings rows.val bindings) := by
  apply WP.spec_mono (radix_recycle_slot_matches rows free index row live vacant room)
  rintro ⟨removed, after, avail⟩ ⟨same, _, _, valid, keep⟩
  refine ⟨same, valid, ?_, ?_⟩
  · intro tree eq known
    exact recycled_row_knowledge tree _ _ pins node index link (eq.symm ▸ zero) keep known
  ·
    intro height root bindings pinned tree liveRows
    have preserved : ∀ entry ∈ bindings, radixRow after.val entry.2 = radixRow rows.val entry.2 := by
      intro entry hm
      exact radix_row_kept dirs _ _ pins node index link zero keep pinned tree entry hm
        (liveRows entry hm).1
    constructor
    · intro entry hm
      rw [preserved entry hm]
      exact liveRows entry hm
    · unfold radixBindings
      apply List.filterMap_congr
      rintro ⟨key, leaf⟩ hm
      exact congrArg (Option.map (fun r : CcfKv.radix.RadixRow V => (key, r.value)))
        (preserved (key, leaf) hm)

end KvRust
