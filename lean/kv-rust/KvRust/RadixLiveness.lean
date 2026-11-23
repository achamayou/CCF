-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Radix

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- For a nonempty link, count incoming references from pins and directory slots.
Directories awaiting retirement still contribute their outgoing references. -/
def radixReferences (dirs : List (Option Spike.radix.RadixDir)) (pins : List U32)
    (target : U32)
    : Nat :=
  (pins ++ (dirs.filterMap id).flatMap (·.children.val)).count target

inductive RadixReachable (dirs : List (Option Spike.radix.RadixDir)) (root : U32)
    : U32 → Prop where
  | root : RadixReachable dirs root root
  | child {parent node : U32} {dir : Spike.radix.RadixDir}
    (prev : RadixReachable dirs root parent)
    (positive : 0 < parent.val)
    (untagged : parent < 2147483648#u32)
    (live : dirs[parent.val - 1]? = some (some dir))
    (edge : node ∈ dir.children.val)
    : RadixReachable dirs root node

private theorem radix_reach_trans {dirs : List (Option Spike.radix.RadixDir)}
    {root mid n : U32} (first : RadixReachable dirs root mid)
    (second : RadixReachable dirs mid n)
    : RadixReachable dirs root n := by
  induction second with
  | root => exact first
  | child _ positive untagged live edge ih => exact .child ih positive untagged live edge

/-- The zero-reference test is sufficient even with a nonempty retirement queue. -/
theorem radix_zero_unreachable (dirs : List (Option Spike.radix.RadixDir))
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
    (before after : List (Option Spike.radix.RadixDir)) {height : Nat} {root : U32}
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

/-- Retiring a zero-count directory leaves the exact projection of every
retained root intact. Counts must separately agree with `radixReferences`. -/
theorem radix_recycle_dir_refines
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) (free : alloc.vec.Vec Usize)
    (pins : List U32) (node : U32) (index : Usize) (dir : Spike.radix.RadixDir)
    (link : node.val = index.val + 1) (live : dirs.val[index.val]? = some (some dir))
    (vacant : RadixFree dirs free) (room : free.val.length < Usize.max)
    (zero : radixReferences dirs.val pins node = 0)
    : WP.spec (Spike.radix.recycle_slot dirs free index)
        (fun (removed, after, avail) =>
          removed = dir
          ∧ RadixFree after avail
          ∧ ∀ height root bindings,
              root ∈ pins
              → RadixTree dirs.val height root bindings
              → RadixTree after.val height root bindings) := by
  apply WP.spec_mono (radix_recycle_slot_matches dirs free index dir live vacant room)
  rintro ⟨removed, after, avail⟩ ⟨same, _, _, valid, keep⟩
  refine ⟨same, valid, ?_⟩
  intro height root bindings pinned tree
  apply radix_tree_keep_reachable dirs.val after.val tree
  intro n positive reach
  apply keep
  intro overlap
  have eq : n = node := UScalar.eq_of_val_eq (by omega)
  exact radix_zero_unreachable dirs.val pins node root pinned zero (eq ▸ reach)

private theorem radix_binding_reachable (dirs : List (Option Spike.radix.RadixDir))
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

/-- Recycling a zero-count row preserves the values and the exact ordered
association list of every retained root, with the same arena-relative links. -/
theorem radix_recycle_row_refines {V : Type}
    (dirs : List (Option Spike.radix.RadixDir))
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow V))) (free : alloc.vec.Vec Usize)
    (pins : List U32) (node : U32) (index : Usize) (row : Spike.radix.RadixRow V)
    (link : node.val = index.val + 2147483648 + 1)
    (live : rows.val[index.val]? = some (some row)) (vacant : RadixFree rows free)
    (room : free.val.length < Usize.max) (zero : radixReferences dirs pins node = 0)
    : WP.spec (Spike.radix.recycle_slot rows free index)
        (fun (removed, after, avail) =>
          removed = row
          ∧ RadixFree after avail
          ∧ ∀ height root bindings,
              root ∈ pins
              → RadixTree dirs height root bindings
              → RadixRows rows.val bindings
              → RadixRows after.val bindings
                ∧ radixBindings after.val bindings
                  = radixBindings rows.val bindings) := by
  apply WP.spec_mono (radix_recycle_slot_matches rows free index row live vacant room)
  rintro ⟨removed, after, avail⟩ ⟨same, _, _, valid, keep⟩
  refine ⟨same, valid, ?_⟩
  intro height root bindings pinned tree liveRows
  have preserved : ∀ entry ∈ bindings, radixRow after.val entry.2 = radixRow rows.val entry.2 := by
    intro entry hm
    have tag := (liveRows entry hm).1
    have different : entry.2.val - 2147483648 - 1 ≠ index.val := by
      intro overlap
      have eq : entry.2 = node := UScalar.eq_of_val_eq (by omega)
      exact radix_zero_unreachable dirs pins node root pinned zero
        (eq ▸ radix_binding_reachable dirs tree entry hm)
    unfold radixRow
    rw [keep _ different]
  constructor
  · intro entry hm
    rw [preserved entry hm]
    exact liveRows entry hm
  · unfold radixBindings
    apply List.filterMap_congr
    rintro ⟨key, leaf⟩ hm
    exact congrArg (Option.map (fun r : Spike.radix.RadixRow V => (key, r.value)))
      (preserved (key, leaf) hm)

end KvRust
