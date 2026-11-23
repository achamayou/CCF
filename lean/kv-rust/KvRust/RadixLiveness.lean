-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Radix
public import KvRust.RadixDual

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- For a nonempty link, count incoming references from pins and directory slots.
Directories awaiting retirement still contribute their outgoing references. -/
def radixReferences (dirs : List (Option Spike.radix.RadixDir)) (pins : List U32)
    (target : U32)
    : Nat :=
  (pins ++ (dirs.filterMap id).flatMap (·.children.val)).count target

private theorem count_zero_iff (n : U32) : n = 0#u32 ↔ n.val = 0 :=
  ⟨fun h => h ▸ rfl, fun h => UScalar.eq_of_val_eq h⟩

/-- Adding an owner increments the exact multiplicity of the referenced link. -/
theorem retain_reference_matches (count target : U32) (owners : List U32)
    (exactCount : count.val = owners.count target) (room : count.val < U32.max)
    : WP.spec (Spike.radix.retain_reference count)
        (fun (first, next) =>
          first = decide (owners.count target = 0)
          ∧ next.val = (target :: owners).count target) := by
  have limit : core.num.U32.MAX.val = U32.max := by rw [U32.max_eq]; rfl
  have fits : count < core.num.U32.MAX := by
    change count.val < core.num.U32.MAX.val
    omega
  have one : (1#u32 : U32).val = 1 := rfl
  simp only [Spike.radix.retain_reference, massert, fits, ite_true, bind_ok]
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
    : WP.spec (Spike.radix.release_reference count)
        (fun (last, next) =>
          last = decide (owners.count target = 0) ∧ next.val = owners.count target) := by
  have one : (1#u32 : U32).val = 1 := rfl
  have old : count.val = owners.count target + 1 := by simpa using exactCount
  have live : (0#u32 : U32) < count := by change 0 < count.val; omega
  simp only [Spike.radix.release_reference, massert, live, ite_true, bind_ok]
  apply WP.spec_bind (U32.sub_spec (x := count) (y := 1#u32) (by omega))
  intro next dec
  have exactNext : next.val = owners.count target := by omega
  rw [WP.spec_ok]
  exact ⟨decide_eq_decide.mpr (by rw [count_zero_iff next, exactNext]), exactNext⟩

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

/-- Retiring a zero-count directory leaves the exact projection of every
retained root intact and removes each of its child references exactly once.
Counts must separately agree with `radixReferences`. -/
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
          ∧ (∀ target,
              radixReferences dirs.val pins target
              = radixReferences after.val pins target + dir.children.val.count target)
          ∧ ∀ height root bindings,
              root ∈ pins
              → RadixTree dirs.val height root bindings
              → RadixTree after.val height root bindings) := by
  apply WP.spec_mono (radix_recycle_slot_matches dirs free index dir live vacant room)
  rintro ⟨removed, after, avail⟩ ⟨same, cleared, _, valid, keep⟩
  refine ⟨same, valid, ?_, ?_⟩
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

private theorem radix_row_kept {V : Type}
    (dirs : List (Option Spike.radix.RadixDir))
    (before after : List (Option (Spike.radix.RadixRow V)))
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
    exact radix_row_kept dirs _ _ pins node index link zero keep pinned tree entry hm
      (liveRows entry hm).1
  constructor
  · intro entry hm
    rw [preserved entry hm]
    exact liveRows entry hm
  · unfold radixBindings
    apply List.filterMap_congr
    rintro ⟨key, leaf⟩ hm
    exact congrArg (Option.map (fun r : Spike.radix.RadixRow V => (key, r.value)))
      (preserved (key, leaf) hm)

/-- A stamp row continues owning its value link while it is queued for retirement. -/
def dualOrderValueLinks {V : Type} (arena : Spike.radix.DualRadix V) : List U32 :=
  arena.order.rows.val.filterMap (fun entry => entry.map Spike.radix.RadixRow.value)

def dualValueReferences {V : Type} (arena : Spike.radix.DualRadix V)
    (pins : List Spike.radix.DualRoot) (node : U32)
    : Nat :=
  radixReferences arena.values.dirs.val (pins.map Spike.radix.DualRoot.lookup) node
  + (dualOrderValueLinks arena).count node

def dualOrderReferences {V : Type} (arena : Spike.radix.DualRadix V)
    (pins : List Spike.radix.DualRoot) (node : U32)
    : Nat :=
  radixReferences arena.order.dirs.val (pins.map Spike.radix.DualRoot.order) node

theorem dual_value_zero_no_order_owner {V : Type} (arena : Spike.radix.DualRadix V)
    (pins : List Spike.radix.DualRoot) (node : U32)
    (zero : dualValueReferences arena pins node = 0) (row : Spike.radix.RadixRow U32)
    (live : some row ∈ arena.order.rows.val)
    : row.value ≠ node := by
  intro same
  have listed : node ∈ dualOrderValueLinks arena :=
    List.mem_filterMap.mpr ⟨some row, live, by simp [same]⟩
  have positive := List.count_pos_iff.mpr listed
  unfold dualValueReferences at zero
  omega

def withValueRows {V : Type} (arena : Spike.radix.DualRadix V)
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow (Spike.radix.Stamped V))))
    (free : alloc.vec.Vec Usize)
    : Spike.radix.DualRadix V :=
  {arena with values := {arena.values with rows, free_rows := free}}

/-- Recycling a value leaf with no lookup or order owner preserves both views
of each pinned root. This is conditional on the retirement counter being exact. -/
theorem dual_recycle_value_refines {V : Type} (arena : Spike.radix.DualRadix V)
    (pins : List Spike.radix.DualRoot) (node : U32) (index : Usize)
    (row : Spike.radix.RadixRow (Spike.radix.Stamped V))
    (link : node.val = index.val + 2147483648 + 1)
    (live : arena.values.rows.val[index.val]? = some (some row))
    (vacant : RadixFree arena.values.rows arena.values.free_rows)
    (room : arena.values.free_rows.val.length < Usize.max)
    (zero : dualValueReferences arena pins node = 0)
    : WP.spec (Spike.radix.recycle_slot arena.values.rows arena.values.free_rows index)
        (fun (removed, after, avail) =>
          removed = row
          ∧ RadixFree after avail
          ∧ ∀ root ∈ pins,
              ∀ bindings,
                DualView arena root bindings
                → DualView (withValueRows arena after avail) root bindings
                  ∧ dualBindings (withValueRows arena after avail) bindings
                    = dualBindings arena bindings) := by
  apply WP.spec_mono (radix_recycle_slot_matches arena.values.rows arena.values.free_rows
    index row live vacant room)
  rintro ⟨removed, after, avail⟩ ⟨same, _, _, free, keep⟩
  refine ⟨same, free, ?_⟩
  intro root pin bindings view
  obtain ⟨height, lookup⟩ := view.lookup
  obtain ⟨oh, keys, order, orderedRows, paired, sorted⟩ := view.order
  have noRefs : radixReferences arena.values.dirs.val
      (pins.map Spike.radix.DualRoot.lookup) node = 0 := by
    unfold dualValueReferences at zero
    omega
  have saved (entry : List U8 × U32) (hm : entry ∈ bindings) :
      radixRow after.val entry.2 = radixRow arena.values.rows.val entry.2 :=
    radix_row_kept _ _ _ _ node index link noRefs keep (List.mem_map_of_mem pin) lookup
      entry hm (view.values entry hm).1
  have stampLinks : dualStampBindings after.val bindings
      = dualStampBindings arena.values.rows.val bindings := by
    unfold dualStampBindings
    apply List.filterMap_congr
    intro entry hm
    exact congrArg (Option.map fun r : Spike.radix.RadixRow (Spike.radix.Stamped V) =>
      (reverseStampBytes r.value.stamp, entry.2)) (saved entry hm)
  refine ⟨⟨⟨height, lookup⟩, ?_, ⟨oh, keys, order, orderedRows, ?_, sorted⟩, ?_, ?_⟩, ?_⟩
  · intro entry hm
    change 2147483648 < entry.2.val ∧ ∃ value, radixRow after.val entry.2 = some value ∧ _
    rw [saved entry hm]
    exact view.values entry hm
  · change radixBindings arena.order.rows.val keys = dualStampBindings after.val bindings
    rwa [stampLinks]
  · intro a ha b hb x y hx hy
    change radixRow after.val a.2 = some x at hx
    change radixRow after.val b.2 = some y at hy
    rw [saved a ha] at hx
    rw [saved b hb] at hy
    exact view.stamps a ha b hb x y hx hy
  · intro entry hm value read
    change radixRow after.val entry.2 = some value at read
    rw [saved entry hm] at read
    exact view.issued entry hm value read
  · unfold dualBindings
    congr 1
    change radixBindings after.val bindings = _
    unfold radixBindings
    apply List.filterMap_congr
    intro entry hm
    exact congrArg (Option.map fun r : Spike.radix.RadixRow (Spike.radix.Stamped V) =>
      (entry.1, r.value)) (saved entry hm)

def withOrderRows {V : Type} (arena : Spike.radix.DualRadix V)
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow U32)))
    (free : alloc.vec.Vec Usize)
    : Spike.radix.DualRadix V :=
  {arena with order := {arena.order with rows, free_rows := free}}

private theorem map_live_slots {α β : Type} (slots : List (Option α)) (f : α → β)
    : (slots.filterMap id).map f = slots.filterMap (fun entry => entry.map f) := by
  induction slots with
  | nil => rfl
  | cons head rest ih =>
      cases head with
      | none => exact ih
      | some x => exact congrArg (f x :: ·) ih

/-- Recycling a stamp leaf leaves all pinned views intact and releases exactly
one reference to its value row, even when other stamp rows share that value link. -/
theorem dual_recycle_order_refines {V : Type} (arena : Spike.radix.DualRadix V)
    (pins : List Spike.radix.DualRoot) (node : U32) (index : Usize)
    (row : Spike.radix.RadixRow U32) (link : node.val = index.val + 2147483648 + 1)
    (live : arena.order.rows.val[index.val]? = some (some row))
    (vacant : RadixFree arena.order.rows arena.order.free_rows)
    (room : arena.order.free_rows.val.length < Usize.max)
    (zero : dualOrderReferences arena pins node = 0)
    : WP.spec (Spike.radix.recycle_slot arena.order.rows arena.order.free_rows index)
        (fun (removed, after, avail) =>
          removed = row
          ∧ RadixFree after avail
          ∧ (∀ target,
              dualValueReferences arena pins target
              = dualValueReferences (withOrderRows arena after avail) pins target
                + [row.value].count target)
          ∧ ∀ root ∈ pins,
              ∀ bindings,
                DualView arena root bindings
                → DualView (withOrderRows arena after avail) root bindings) := by
  apply WP.spec_mono (radix_recycle_slot_matches arena.order.rows arena.order.free_rows
    index row live vacant room)
  rintro ⟨removed, after, avail⟩ ⟨same, cleared, _, free, keep⟩
  refine ⟨same, free, ?_, ?_⟩
  · have erased := recycled_slots_eq arena.order.rows.val after.val index.val row live cleared keep
    have perm := (remove_one_live_slot arena.order.rows.val index.val row live).map
      Spike.radix.RadixRow.value
    intro target
    have counts := perm.count_eq target
    simp only [← erased, List.map_append, List.map_cons, List.map_nil, map_live_slots] at counts
    change (dualOrderValueLinks (withOrderRows arena after avail) ++ [row.value]).count target
      = (dualOrderValueLinks arena).count target at counts
    rw [List.count_append] at counts
    unfold dualValueReferences
    change radixReferences arena.values.dirs.val _ _ + (dualOrderValueLinks arena).count target
      = radixReferences arena.values.dirs.val _ _
        + (dualOrderValueLinks (withOrderRows arena after avail)).count target + [row.value].count target
    omega
  · intro root pinned bindings view
    obtain ⟨height, keys, tree, oldRows, pairing, sorted⟩ := view.order
    have saved (entry : List U8 × U32) (hm : entry ∈ keys) :
        radixRow after.val entry.2 = radixRow arena.order.rows.val entry.2 :=
      radix_row_kept _ _ _ _ node index link zero keep (List.mem_map_of_mem pinned) tree
        entry hm (oldRows entry hm).1
    refine ⟨view.lookup, view.values, ⟨height, keys, tree, ?_, ?_, sorted⟩, view.stamps, view.issued⟩
    · intro entry hm
      change 2147483648 < entry.2.val ∧ ∃ value, radixRow after.val entry.2 = some value ∧ _
      rw [saved entry hm]
      exact oldRows entry hm
    · change radixBindings after.val keys = dualStampBindings arena.values.rows.val bindings
      rw [← pairing]
      unfold radixBindings
      apply List.filterMap_congr
      intro entry hm
      exact congrArg (Option.map fun r : Spike.radix.RadixRow U32 =>
        (entry.1, r.value)) (saved entry hm)

end KvRust
