-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.RadixBatch
public import KvRust.RadixDual

import all Aeneas.Data.List.List

@[expose] public section

namespace KvRust

open Aeneas.Std

private theorem staged_rows_valid {V : Type} (before : Spike.radix.Arena V)
    (after : alloc.vec.Vec (Option (Spike.radix.RadixRow V))) (free : alloc.vec.Vec Usize)
    (valid : ArenaValid before) (vacant : RadixFree after free)
    (kept
      : ∀ (i : Nat) row,
          before.rows.val[i]? = some (some row) → after.val[i]? = some (some row))
    : ArenaValid {before with rows := after, free_rows := free} := by
  refine ⟨valid.dirs, vacant, valid.directories, ?_⟩
  exact radix_knowledge_extend before.dirs before.dirs _ _ valid.knowledge (fun _ _ h => h)
    (radix_keys_kept _ _ kept) (fun _ _ live absent => (absent live).elim)

/-- Staging a pair consumes a single fresh stamp and preserves every live
directory and row in both arenas, without creating any intermediate roots. -/
theorem stage_batch_leaf_refines {V : Type} (arena : Spike.radix.DualRadix V)
    (row : Spike.radix.RadixRow V) (values : ArenaValid arena.values)
    (order : ArenaValid arena.order)
    (valueRoom : arena.values.rows.val.length < 2147483647)
    (orderRoom : arena.order.rows.val.length < 2147483647)
    (clockRoom : arena.last.val < U64.max)
    : WP.spec (Spike.radix.DualRadix.stage_batch_leaf arena row)
        (fun ((leaf, slot), after) =>
          ArenaValid after.values
          ∧ ArenaValid after.order
          ∧ ArenaKeeps arena.values after.values
          ∧ ArenaKeeps arena.order after.order
          ∧ ArenaGrowth arena.values after.values 0 1
          ∧ ArenaGrowth arena.order after.order 0 1
          ∧ after.last.val = arena.last.val + 1
          ∧ 2147483648 < leaf.val
          ∧ 2147483648 < slot.val
          ∧ radixRow after.values.rows.val leaf
            = some {key := row.key, value := {stamp := after.last, value := row.value}}
          ∧ ∃ encoded,
              encoded.val = reverseStampBytes after.last
              ∧ radixRow after.order.rows.val slot
                = some {key := encoded, value := leaf}) := by
  have limit : core.num.U64.MAX.val = U64.max := by rw [U64.max_eq]; rfl
  have fits : arena.last < core.num.U64.MAX := by
    change arena.last.val < core.num.U64.MAX.val
    omega
  have one : (1#u64 : U64).val = 1 := rfl
  have ptrRoom : 2147483647 ≤ Usize.max := by scalar_tac
  unfold Spike.radix.DualRadix.stage_batch_leaf
  simp only [massert, fits, ite_true, bind_ok]
  apply WP.spec_bind (U64.add_spec (x := arena.last) (y := 1#u64) (by omega))
  intro stamp hs
  have fresh : stamp.val = arena.last.val + 1 := by omega
  let written : Spike.radix.RadixRow (Spike.radix.Stamped V) :=
    {key := row.key, value := {stamp, value := row.value}}
  apply WP.spec_bind
    (radix_allocate_matches arena.values.rows arena.values.free_rows written
      values.rows (fun _ => by omega))
  rintro ⟨i, vr, vf⟩ ⟨vEntry, vSaved, _, iBound, vSize, vFree, _⟩
  apply WP.spec_bind (radix_link_matches i true (by omega))
  intro leaf leafLink
  have hleaf : leaf.val = i.val + 1 + 2147483648 := by simpa using leafLink
  apply WP.spec_bind (reverse_stamp_key_refines stamp)
  intro encoded bytes
  let chronology : Spike.radix.RadixRow U32 := {key := encoded, value := leaf}
  apply WP.spec_bind
    (radix_allocate_matches arena.order.rows arena.order.free_rows chronology
      order.rows (fun _ => by omega))
  rintro ⟨j, sr, sf⟩ ⟨sEntry, sSaved, _, jBound, sSize, sFree, _⟩
  apply WP.spec_bind (radix_link_matches j true (by omega))
  intro slot slotLink
  have hslot : slot.val = j.val + 1 + 2147483648 := by simpa using slotLink
  have ltag : 2147483648 < leaf.val := by omega
  have stag : 2147483648 < slot.val := by omega
  let after : Spike.radix.DualRadix V :=
    {values := {arena.values with rows := vr, free_rows := vf},
     order := {arena.order with rows := sr, free_rows := sf}, last := stamp}
  change WP.spec (Result.ok ((leaf, slot), after)) _
  rw [WP.spec_ok]
  refine ⟨staged_rows_valid arena.values vr vf values vFree vSaved,
    staged_rows_valid arena.order sr sf order sFree sSaved,
    ⟨fun _ _ h => h, vSaved⟩, ⟨fun _ _ h => h, sSaved⟩,
    ⟨Nat.le_refl _, vSize⟩, ⟨Nat.le_refl _, sSize⟩, fresh, ltag, stag, ?_,
    encoded, bytes, ?_⟩
  · have atLeaf : leaf.val - 2147483648 - 1 = i.val := by omega
    change radixRow vr.val leaf = some written
    simp [radixRow, ltag, atLeaf, vEntry]
  · have atSlot : slot.val - 2147483648 - 1 = j.val := by omega
    change radixRow sr.val slot = some chronology
    simp [radixRow, stag, atSlot, sEntry]

theorem radix_tree_perm {dirs : List (Option Spike.radix.RadixDir)}
    {height : Nat} {root : U32} {before after : List (List U8 × U32)}
    (tree : RadixTree dirs height root before) (perm : List.Perm before after)
    : RadixTree dirs height root after := by
  induction tree generalizing after with
  | empty h =>
      rw [← perm.nil_eq]
      exact .empty h
  | leaf h link key tagged =>
      rw [← perm.singleton_eq]
      exact .leaf h link key tagged
  | branch h node dir bindings positive untagged live child links children ih =>
      exact .branch h node dir after positive untagged live child links
        (fun i inside => ih i inside (perm.filter (fun row => radixSymbol row.1 dir.digit.val == i)))

/-- Staged leaves agree on the ordered mapping from stamps to value links. -/
structure BatchPairing {V : Type} (arena : Spike.radix.DualRadix V)
    (bindings stamps : List (List U8 × U32))
    : Prop where
  pairs
    : radixBindings arena.order.rows.val stamps
      = dualStampBindings arena.values.rows.val bindings
  uniqueStamp
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

structure BatchBuildRoom (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (bindings : List (List U8 × U32)) (ceiling : Nat)
    : Prop where
  depth : ∀ entry ∈ bindings, 2 * entry.1.length ≤ ceiling
  keys : ∀ entry ∈ bindings, 2 * entry.1.length + 1 ≤ Usize.max
  arena : dirs.val.length + 2 * (bindings.length * (ceiling + 1)) < 2147483647

/-- Publish both prepared indexes. Lookup routing is independent of the order
in which their common bindings must be observed. -/
theorem publish_batch_leaves_refines {V : Type} (arena : Spike.radix.DualRadix V)
    (lookup order : Slice U32) (byKey stamps bindings : List (List U8 × U32))
    (values : ArenaValid arena.values) (chronology : ArenaValid arena.order)
    (lookupRows : BatchLeaves (alloc.vec.Vec.deref arena.values.rows) lookup byKey)
    (orderRows : BatchLeaves (alloc.vec.Vec.deref arena.order.rows) order stamps)
    (keySorted : byKey.Pairwise radixKeyLt) (stampSorted : stamps.Pairwise radixKeyLt)
    (perm : List.Perm byKey bindings) (pairing : BatchPairing arena bindings stamps)
    (keyCeiling stampCeiling : Nat)
    (keyRoom : BatchBuildRoom arena.values.dirs byKey keyCeiling)
    (stampRoom : BatchBuildRoom arena.order.dirs stamps stampCeiling)
    : WP.spec (Spike.radix.DualRadix.publish_batch_leaves arena lookup order)
        (fun (root, after) =>
          DualView after root bindings
          ∧ dualBindings after bindings = dualBindings arena bindings
          ∧ ArenaValid after.values
          ∧ ArenaValid after.order
          ∧ ArenaKeeps arena.values after.values
          ∧ ArenaKeeps arena.order after.order
          ∧ after.last = arena.last) := by
  unfold Spike.radix.DualRadix.publish_batch_leaves
  apply WP.spec_bind
    (build_sorted_refines arena.values.dirs arena.values.free_dirs
      (alloc.vec.Vec.deref arena.values.rows) lookup byKey lookupRows keySorted keyCeiling
      keyRoom.depth keyRoom.keys keyRoom.arena values.dirs values.directories
      (by simpa [alloc.vec.Vec.deref] using values.knowledge))
  rintro ⟨keyRoot, keyDirs, keyFree⟩ ⟨keyKept, keyVacant, keyValid, keyKnown, keyTree, _⟩
  apply WP.spec_bind
    (build_sorted_refines arena.order.dirs arena.order.free_dirs
      (alloc.vec.Vec.deref arena.order.rows) order stamps orderRows stampSorted
      stampCeiling stampRoom.depth stampRoom.keys stampRoom.arena chronology.dirs
      chronology.directories (by simpa [alloc.vec.Vec.deref] using chronology.knowledge))
  rintro ⟨stampRoot, stampDirs, stampFree⟩ ⟨stampKept, stampVacant, stampValid, stampKnown, stampTree, _⟩
  let after := {arena with
    values := {arena.values with dirs := keyDirs, free_dirs := keyFree},
    order := {arena.order with dirs := stampDirs, free_dirs := stampFree}}
  change WP.spec (Result.ok (({lookup := keyRoot, order := stampRoot} : Spike.radix.DualRoot), after)) _
  rw [WP.spec_ok]
  have valRows : RadixRows after.values.rows.val bindings := by
    intro entry member
    have old := lookupRows.live entry (perm.mem_iff.mpr member)
    simpa [after, alloc.vec.Vec.deref] using old
  have sr : RadixRows after.order.rows.val stamps := by
    simpa [after, alloc.vec.Vec.deref] using orderRows.live
  refine ⟨
    ⟨
      ⟨byKey.length, radix_tree_perm keyTree perm⟩,
      valRows,
      ⟨stamps.length, stamps, stampTree, sr, pairing.pairs, stampSorted⟩,
      pairing.uniqueStamp,
      pairing.issued
    ⟩,
    rfl,
    ⟨keyVacant, values.rows, keyValid, ?_⟩,
    ⟨stampVacant, chronology.rows, stampValid, ?_⟩,
    ⟨keyKept, fun _ _ h => h⟩,
    ⟨stampKept, fun _ _ h => h⟩,
    rfl
  ⟩
  · simpa [after, alloc.vec.Vec.deref] using keyKnown
  · simpa [after, alloc.vec.Vec.deref] using stampKnown

private structure StagedEntry (V : Type) where
  row : Spike.radix.RadixRow V
  leaf : U32
  slot : U32
  stamp : U64

private def StagedEntry.valueBinding {V : Type} (e : StagedEntry V) : List U8 × U32 :=
  (e.row.key.val, e.leaf)

private def StagedEntry.stampBinding {V : Type} (e : StagedEntry V) : List U8 × U32 :=
  (reverseStampBytes e.stamp, e.slot)

private def StagedEntry.written {V : Type} (e : StagedEntry V)
    : Spike.radix.RadixRow (Spike.radix.Stamped V) :=
  {key := e.row.key, value := {stamp := e.stamp, value := e.row.value}}

private structure StagedBatch {V : Type} (arena : Spike.radix.DualRadix V)
    (entries : List (StagedEntry V))
    : Prop where
  lookup
    : ∀ e ∈ entries,
        2147483648 < e.leaf.val ∧ radixRow arena.values.rows.val e.leaf = some e.written
  order
    : ∀ e ∈ entries,
        2147483648 < e.slot.val
        ∧ ∃ encoded,
            encoded.val = reverseStampBytes e.stamp
            ∧ radixRow arena.order.rows.val e.slot
              = some {key := encoded, value := e.leaf}
  chronology : entries.Pairwise (fun a b => b.stamp.val < a.stamp.val)
  issued : ∀ e ∈ entries, e.stamp.val ≤ arena.last.val

private theorem StagedBatch.extend {V : Type} {before after : Spike.radix.DualRadix V}
    {entries : List (StagedEntry V)} (staged : StagedBatch before entries)
    (entry : StagedEntry V) (keys : ArenaKeeps before.values after.values)
    (stamps : ArenaKeeps before.order after.order) (newest : entry.stamp = after.last)
    (tick : after.last.val = before.last.val + 1)
    (lookup
      : 2147483648 < entry.leaf.val
        ∧ radixRow after.values.rows.val entry.leaf = some entry.written)
    (order
      : 2147483648 < entry.slot.val
        ∧ ∃ encoded,
            encoded.val = reverseStampBytes entry.stamp
            ∧ radixRow after.order.rows.val entry.slot
              = some {key := encoded, value := entry.leaf})
    : StagedBatch after (entry :: entries) := by
  refine ⟨?_, ?_, List.pairwise_cons.mpr ⟨?_, staged.chronology⟩, ?_⟩
  · intro e member
    rcases List.mem_cons.mp member with rfl | old
    · exact lookup
    · obtain ⟨tag, row⟩ := staged.lookup e old
      exact ⟨tag, radix_old_row _ _ keys.rows _ _ row⟩
  · intro e member
    rcases List.mem_cons.mp member with rfl | old
    · exact order
    · obtain ⟨tag, bytes, key, read⟩ := staged.order e old
      exact ⟨tag, bytes, key, radix_old_row _ _ stamps.rows _ _ read⟩
  · intro e old
    have issued := staged.issued e old
    rw [newest, tick]
    omega
  · intro e member
    rcases List.mem_cons.mp member with rfl | old
    · rw [newest]
    · have h := staged.issued e old
      omega

private theorem staged_value_rows {V : Type} (arena : Spike.radix.DualRadix V)
    (entries : List (StagedEntry V)) (staged : StagedBatch arena entries)
    : RadixRows arena.values.rows.val (entries.map StagedEntry.valueBinding) := by
  intro binding member
  obtain ⟨entry, present, rfl⟩ := List.mem_map.mp member
  have hit := staged.lookup entry present
  exact ⟨hit.1, entry.written, hit.2, rfl⟩

private theorem staged_stamp_rows {V : Type} (arena : Spike.radix.DualRadix V)
    (entries : List (StagedEntry V)) (staged : StagedBatch arena entries)
    : RadixRows arena.order.rows.val (entries.map StagedEntry.stampBinding) := by
  intro binding member
  obtain ⟨entry, present, rfl⟩ := List.mem_map.mp member
  obtain ⟨tag, bytes, key, read⟩ := staged.order entry present
  exact ⟨tag, {key := bytes, value := entry.leaf}, read, key⟩

private theorem staged_stamp_values {V : Type} (arena : Spike.radix.DualRadix V)
    (entries : List (StagedEntry V))
    (order
      : ∀ e ∈ entries,
          ∃ encoded,
            encoded.val = reverseStampBytes e.stamp
            ∧ radixRow arena.order.rows.val e.slot
              = some {key := encoded, value := e.leaf})
    : radixBindings arena.order.rows.val (entries.map StagedEntry.stampBinding)
      = entries.map (fun entry => (reverseStampBytes entry.stamp, entry.leaf)) := by
  induction entries with
  | nil => rfl
  | cons entry rest ih =>
      obtain ⟨encoded, bytes, read⟩ := order entry List.mem_cons_self
      have tail := ih (fun e h => order e (List.mem_cons_of_mem _ h))
      simp [radixBindings, StagedEntry.stampBinding, read] at tail ⊢
      exact tail

private theorem staged_value_stamps {V : Type} (arena : Spike.radix.DualRadix V)
    (entries : List (StagedEntry V))
    (values : ∀ e ∈ entries, radixRow arena.values.rows.val e.leaf = some e.written)
    : dualStampBindings arena.values.rows.val (entries.map StagedEntry.valueBinding)
      = entries.map (fun entry => (reverseStampBytes entry.stamp, entry.leaf)) := by
  induction entries with
  | nil => rfl
  | cons entry rest ih =>
      have read := values entry List.mem_cons_self
      have tail := ih (fun e h => values e (List.mem_cons_of_mem _ h))
      simp [dualStampBindings, StagedEntry.valueBinding, StagedEntry.written, read] at tail ⊢
      exact tail

private theorem pairwise_key_inj {α β : Type} (entries : List α) (key : α → β)
    (unique : entries.Pairwise (fun a b => key a ≠ key b))
    (a b : α) (ha : a ∈ entries) (hb : b ∈ entries) (eq : key a = key b)
    : a = b := by
  induction entries with
  | nil => cases ha
  | cons first rest ih =>
      obtain ⟨distinct, tail⟩ := List.pairwise_cons.mp unique
      rcases List.mem_cons.mp ha with rfl | oldA <;> rcases List.mem_cons.mp hb with rfl | oldB
      · rfl
      · exact (distinct b oldB eq).elim
      · exact (distinct a oldA eq.symm).elim
      · exact ih tail oldA oldB

private theorem staged_pairing {V : Type} (arena : Spike.radix.DualRadix V)
    (entries : List (StagedEntry V)) (staged : StagedBatch arena entries)
    (distinct : entries.Pairwise (fun a b => a.row.key.val ≠ b.row.key.val))
    : BatchPairing arena (entries.map StagedEntry.valueBinding)
        (entries.map StagedEntry.stampBinding) := by
  refine ⟨(staged_stamp_values arena entries (fun e h => (staged.order e h).2)).trans
      (staged_value_stamps arena entries (fun e h => (staged.lookup e h).2)).symm,
    ?_, ?_⟩
  · intro a ha b hb x y hx hy
    obtain ⟨va, ma, rfl⟩ := List.mem_map.mp ha
    obtain ⟨vb, mb, rfl⟩ := List.mem_map.mp hb
    have sameX := Option.some.inj (hx.symm.trans (staged.lookup va ma).2)
    have sameY := Option.some.inj (hy.symm.trans (staged.lookup vb mb).2)
    subst x y
    change (va.stamp = vb.stamp ↔ va.row.key.val = vb.row.key.val)
    have stamps : entries.Pairwise (fun a b => a.stamp ≠ b.stamp) := by
      apply staged.chronology.imp
      intro a b h ne
      rw [ne] at h
      exact Nat.lt_irrefl _ h
    exact ⟨fun h => congrArg (fun e => e.row.key.val) (pairwise_key_inj entries _ stamps va vb ma mb h),
      fun h => congrArg StagedEntry.stamp (pairwise_key_inj entries _ distinct va vb ma mb h)⟩
  · intro binding member row read
    obtain ⟨entry, present, rfl⟩ := List.mem_map.mp member
    have same := Option.some.inj (read.symm.trans (staged.lookup entry present).2)
    rw [same]
    exact staged.issued entry present

structure BatchStageRoom {V : Type} (arena : Spike.radix.DualRadix V) (entries : Nat)
    : Prop where
  values : arena.values.rows.val.length + entries ≤ 2147483647
  order : arena.order.rows.val.length + entries ≤ 2147483647
  clock : arena.last.val + entries ≤ U64.max

private theorem after_set_drop {T : Type} (xs : List T) (i : Nat) (x : T)
    : (xs.set i x).drop (i + 1) = xs.drop (i + 1) := by
  induction xs generalizing i with
  | nil => simp
  | cons hd tl ih =>
      cases i with
      | zero => rfl
      | succ i => exact ih i

private theorem stage_order_slot (n : Nat) (tail : List U32) (stamp : U32)
    : (List.replicate (n + 1) (0#u32) ++ tail).set n stamp
      = List.replicate n (0#u32) ++ (stamp :: tail) := by
  rw [List.replicate_succ', List.append_assoc, List.set_append_right _ _ (by simp)]
  simp

private theorem build_sorted_batch_loop_refines {V : Type}
    (arena : Spike.radix.DualRadix V)
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow V)))
    (prepared : List (Spike.radix.RadixRow V)) (source : rows.val = prepared.map some)
    (n : Usize) (size : n.val = prepared.length) (lookup order : alloc.vec.Vec U32)
    (lookupEmpty : lookup.val = []) (orderZero : order.val = List.replicate n.val 0#u32)
    (values : ArenaValid arena.values) (stamps : ArenaValid arena.order)
    (room : BatchStageRoom arena prepared.length)
    : WP.spec
        (Spike.radix.DualRadix.build_sorted_batch_loop arena rows n lookup order 0#usize)
        (fun (after, ls, os) =>
          ArenaValid after.values
          ∧ ArenaValid after.order
          ∧ ArenaKeeps arena.values after.values
          ∧ ArenaKeeps arena.order after.order
          ∧ ArenaGrowth arena.values after.values 0 prepared.length
          ∧ ArenaGrowth arena.order after.order 0 prepared.length
          ∧ after.last.val = arena.last.val + prepared.length
          ∧ ∃ entries : List (StagedEntry V),
              StagedBatch after entries
              ∧ entries.reverse.map StagedEntry.row = prepared
              ∧ ls.val = entries.reverse.map StagedEntry.leaf
              ∧ os.val = entries.map StagedEntry.slot) := by
  unfold Spike.radix.DualRadix.build_sorted_batch_loop
  apply loop.spec_decr_nat (fun (_, _, _, _, i) => n.val - (i : Usize).val)
    (fun (current, working, keys, chronology, i) =>
      i.val ≤ n.val
      ∧ working.val.length = n.val
      ∧ working.val.drop i.val = (prepared.drop i.val).map some
      ∧ ArenaValid current.values
      ∧ ArenaValid current.order
      ∧ ArenaKeeps arena.values current.values
      ∧ ArenaKeeps arena.order current.order
      ∧ ArenaGrowth arena.values current.values 0 i.val
      ∧ ArenaGrowth arena.order current.order 0 i.val
      ∧ current.last.val = arena.last.val + i.val
      ∧ ∃ entries : List (StagedEntry V),
          StagedBatch current entries
          ∧ entries.reverse.map StagedEntry.row = prepared.take i.val
          ∧ keys.val = entries.reverse.map StagedEntry.leaf
          ∧ chronology.val
            = List.replicate (n.val - i.val) 0#u32 ++ entries.map StagedEntry.slot)
    _ _ _
  · rintro ⟨current, working, keys, chronology, i⟩
      ⟨upto, rowCount, untouched, keyValid, stampValid, keyKept, stampKept, keyGrowth, stampGrowth,
        stampClock, entries, staged, doneRows, doneKeys, doneStamps⟩
    dsimp only at upto rowCount untouched keyValid stampValid keyKept stampKept keyGrowth stampGrowth stampClock staged doneRows doneKeys doneStamps ⊢
    unfold Spike.radix.DualRadix.build_sorted_batch_loop.body
    have one : (1#usize : Usize).val = 1 := rfl
    by_cases run : i < n
    · have h : i.val < n.val := run
      have inRows : i.val < working.val.length := by omega
      have inInput : i.val < prepared.length := by omega
      have limit : n.val ≤ Usize.max := by scalar_tac
      have count : entries.length = i.val := by
        have eq := congrArg List.length doneRows
        simpa [List.length_take, Nat.min_eq_left (Nat.le_of_lt inInput)] using eq
      have chronoSize : chronology.val.length = n.val := by
        rw [doneStamps, List.length_append, List.length_replicate, List.length_map, count]
        omega
      rw [ite_eq_left run, alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec working i inRows)
      rintro ⟨original, back⟩ ⟨read, setter⟩
      have alive : original = some prepared[i.val] := by
        have eq := congrArg (fun (xs : List (Option (Spike.radix.RadixRow V))) => xs[0]?) untouched
        rw [List.getElem?_drop, Nat.add_zero, List.getElem?_eq_getElem inRows, ← read,
          List.getElem?_map, List.getElem?_drop, Nat.add_zero,
          List.getElem?_eq_getElem inInput] at eq
        exact Option.some.inj eq
      rw [alive]
      simp only [core.option.Option.take]
      have valuesLimit := room.values
      have orderLimit := room.order
      have clockLimit := room.clock
      have valSlots := keyGrowth.2
      have stampSlots := stampGrowth.2
      apply WP.spec_bind (stage_batch_leaf_refines current prepared[i.val] keyValid stampValid
        (by omega) (by omega) (by omega))
      rintro ⟨⟨leaf, stamp⟩, after⟩
        ⟨keyOK, stampOK, kKept, sKept, kGrowth, sGrowth, clock, ltag, stag, value, orderLeaf⟩
      have keySize : keys.val.length = i.val := by simp [doneKeys, count]
      apply WP.spec_bind (alloc.vec.Vec.push_spec keys leaf (by omega))
      intro newKeys appended
      apply WP.spec_bind (Usize.sub_spec (x := n) (y := 1#usize) (by omega))
      intro last hl
      apply WP.spec_bind (Usize.sub_spec (x := last) (y := i) (by omega))
      intro slot hs
      have backIndex : slot.val = n.val - (i.val + 1) := by omega
      have inOrder : slot.val < chronology.val.length := by omega
      rw [alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec chronology slot inOrder)
      rintro ⟨_, newOrder⟩ ⟨_, storeStamp⟩
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro next hi
      have advanced : next.val = i.val + 1 := by omega
      let entry : StagedEntry V := {row := prepared[i.val], leaf, slot := stamp, stamp := after.last}
      change WP.spec (Result.ok (ControlFlow.cont (after, back none, newKeys, newOrder stamp, next))) _
      rw [WP.spec_ok]
      dsimp only
      have work : (back none).val = working.val.set i.val none := by
        rw [setter]
        exact alloc.vec.Vec.set_val_eq _ _ _
      have stored : (newOrder stamp).val = chronology.val.set slot.val stamp := by
        rw [storeStamp]
        exact alloc.vec.Vec.set_val_eq _ _ _
      have keyDirs := keyGrowth.1
      have orderDirs := stampGrowth.1
      have nextKeyDirs := kGrowth.1
      have nextOrderDirs := sGrowth.1
      have nextVSlots := kGrowth.2
      have nextSSlots := sGrowth.2
      refine ⟨⟨by omega, by simpa [work] using rowCount, ?_, keyOK, stampOK,
        keyKept.trans kKept, stampKept.trans sKept, ⟨by omega, by omega⟩, ⟨by omega, by omega⟩,
        by omega, entry :: entries, ?_, ?_, ?_, ?_⟩, by omega⟩
      · rw [work, advanced, after_set_drop]
        have d := congrArg (List.drop 1) untouched
        simpa [List.drop_drop, List.map_drop, Nat.add_comm] using d
      · exact staged.extend entry kKept sKept rfl clock ⟨ltag, value⟩ ⟨stag, orderLeaf⟩
      · rw [List.reverse_cons, List.map_append, doneRows, advanced,
          List.take_succ_eq_append_getElem inInput]
        rfl
      · rw [List.reverse_cons, List.map_append, ← doneKeys, appended]
        rfl
      · rw [stored, doneStamps, backIndex, advanced,
          show n.val - i.val = n.val - (i.val + 1) + 1 by omega, stage_order_slot]
        rfl
    · have ended : i.val = n.val := by
        have h : ¬ i.val < n.val := run
        omega
      rw [ite_eq_right run, WP.spec_ok]
      refine ⟨keyValid, stampValid, keyKept, stampKept, ?_, ?_, ?_, entries, staged, ?_, doneKeys, ?_⟩
      · simpa [ended, size] using keyGrowth
      · simpa [ended, size] using stampGrowth
      · simpa [ended, size] using stampClock
      · simpa [ended, size] using doneRows
      · simpa [ended] using doneStamps
  · refine ⟨by simp, by simp [source, size], by simp [source], values, stamps, .refl _, .refl _,
      ?_, ?_, by simp, [], ?_, by simp, lookupEmpty, ?_⟩
    · exact ⟨Nat.le_refl _, Nat.le_refl _⟩
    · exact ⟨Nat.le_refl _, Nat.le_refl _⟩
    · constructor <;> simp
    · simpa using orderZero

private theorem staged_values {V : Type} (arena : Spike.radix.DualRadix V)
    (entries : List (StagedEntry V))
    (read : ∀ e ∈ entries, radixRow arena.values.rows.val e.leaf = some e.written)
    : dualBindings arena (entries.map StagedEntry.valueBinding)
      = entries.map (fun entry => (entry.row.key.val, entry.row.value)) := by
  induction entries with
  | nil => rfl
  | cons entry rest ih =>
      have head := read entry List.mem_cons_self
      have tail := ih (fun e h => read e (List.mem_cons_of_mem _ h))
      simp [dualBindings, radixBindings, StagedEntry.valueBinding, StagedEntry.written, head] at tail ⊢
      exact tail

structure SortedBatchRoom {V : Type} (arena : Spike.radix.DualRadix V)
    (prepared : List (Spike.radix.RadixRow V)) (ceiling : Nat)
    : Prop where
  stage : BatchStageRoom arena prepared.length
  depth : ∀ row ∈ prepared, 2 * row.key.val.length ≤ ceiling
  keys : ∀ row ∈ prepared, 2 * row.key.val.length + 1 ≤ Usize.max
  lookup
    : arena.values.dirs.val.length + 2 * (prepared.length * (ceiling + 1)) < 2147483647
  order : arena.order.dirs.val.length + 2 * (prepared.length * 17) < 2147483647

/-- Build and publish a fresh dual-radix image from owned rows in increasing
key order. Scans observe the reverse (newest-first) write order. -/
theorem build_sorted_batch_refines {V : Type} (arena : Spike.radix.DualRadix V)
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow V)))
    (prepared : List (Spike.radix.RadixRow V)) (source : rows.val = prepared.map some)
    (ordered : prepared.Pairwise (fun a b => byteOrder a.key.val b.key.val = (-1)#i8))
    (values : ArenaValid arena.values) (stamps : ArenaValid arena.order) (ceiling : Nat)
    (room : SortedBatchRoom arena prepared ceiling)
    : WP.spec (Spike.radix.DualRadix.build_sorted_batch arena rows)
        (fun (root, after) =>
          ArenaValid after.values
          ∧ ArenaValid after.order
          ∧ ArenaKeeps arena.values after.values
          ∧ ArenaKeeps arena.order after.order
          ∧ after.last.val = arena.last.val + prepared.length
          ∧ ∃ bindings,
              DualView after root bindings
              ∧ dualBindings after bindings
                = prepared.reverse.map (fun row => (row.key.val, row.value))) := by
  unfold Spike.radix.DualRadix.build_sorted_batch
  let n := alloc.vec.Vec.len rows
  have size : n.val = prepared.length := by
    change (alloc.vec.Vec.len rows).val = prepared.length
    simp only [alloc.vec.Vec.len_val]
    change rows.val.length = prepared.length
    rw [source, List.length_map]
  apply WP.spec_bind
    (alloc.vec.Vec.resize_spec core.clone.CloneU32 (alloc.vec.Vec.new U32) n 0#u32 rfl)
  intro order resized
  have orderZero : order.val = List.replicate n.val 0#u32 := by
    simp [resized, List.resize]
  apply WP.spec_bind
    (build_sorted_batch_loop_refines arena rows prepared source n size
      (alloc.vec.Vec.with_capacity U32 n) order (by simp [alloc.vec.Vec.with_capacity])
      orderZero values stamps room.stage)
  rintro ⟨stagedArena, ls, os⟩ ⟨valueOK, orderOK, oldValues, oldStamps, valueGrowth,
    orderGrowth, clock, entries, staged, doneRows, doneKeys, doneStamps⟩
  let byKey := entries.reverse.map StagedEntry.valueBinding
  let byStamp := entries.map StagedEntry.stampBinding
  let logical := entries.map StagedEntry.valueBinding
  have lv : BatchLeaves (alloc.vec.Vec.deref stagedArena.values.rows) (alloc.vec.Vec.deref ls) byKey := by
    constructor
    · simpa [alloc.vec.Vec.deref, byKey, List.map_map, Function.comp_def,
        StagedEntry.valueBinding] using doneKeys
    · intro binding hm
      obtain ⟨entry, present, rfl⟩ := List.mem_map.mp hm
      obtain ⟨tag, read⟩ := staged.lookup entry (List.mem_reverse.mp present)
      exact ⟨tag, entry.written, by simpa [alloc.vec.Vec.deref, StagedEntry.valueBinding] using read, rfl⟩
  have sv : BatchLeaves (alloc.vec.Vec.deref stagedArena.order.rows) (alloc.vec.Vec.deref os) byStamp := by
    exact ⟨by simpa [alloc.vec.Vec.deref, byStamp, List.map_map, Function.comp_def,
        StagedEntry.stampBinding] using doneStamps,
      by simpa [alloc.vec.Vec.deref, byStamp] using staged_stamp_rows stagedArena entries staged⟩
  have keyOrder : entries.reverse.Pairwise (fun a b => byteOrder a.row.key.val b.row.key.val = (-1)#i8) := by
    rw [← doneRows, List.pairwise_map] at ordered
    exact ordered
  have keys : byKey.Pairwise radixKeyLt := by
    rw [List.pairwise_map]
    exact keyOrder
  have chronology : byStamp.Pairwise radixKeyLt := by
    rw [List.pairwise_map]
    apply staged.chronology.imp
    intro a b older
    exact reverse_stamp_order b.stamp a.stamp older
  have distinct : entries.Pairwise (fun a b => a.row.key.val ≠ b.row.key.val) := by
    have ahead : entries.reverse.Pairwise (fun a b => a.row.key.val ≠ b.row.key.val) := by
      apply keyOrder.imp
      intro a b order same
      have lt : byteOrder a.row.key.val b.row.key.val < 0#i8 := by rw [order]; decide
      exact (ne_of_lt ((byteOrder_lt _ _).mp lt)) same
    rw [List.pairwise_reverse] at ahead
    exact ahead.imp (fun h => Ne.symm h)
  have keySize : byKey.length = prepared.length := by
    simpa [byKey] using congrArg List.length doneRows
  have stampSize : byStamp.length = prepared.length := by
    simpa [byStamp] using congrArg List.length doneRows
  have inputMember (entry : List U8 × U32) (hm : entry ∈ byKey) :
      ∃ source ∈ prepared, source.key.val = entry.1 := by
    obtain ⟨e, he, same⟩ := List.mem_map.mp hm
    refine ⟨e.row, ?_, ?_⟩
    · rw [← doneRows]
      exact List.mem_map_of_mem he
    · exact congrArg Prod.fst same
  have vr : BatchBuildRoom stagedArena.values.dirs byKey ceiling := by
    refine ⟨?_, ?_, ?_⟩
    · intro entry hm
      obtain ⟨source, member, same⟩ := inputMember entry hm
      rw [← same]
      exact room.depth source member
    · intro entry hm
      obtain ⟨source, member, same⟩ := inputMember entry hm
      rw [← same]
      exact room.keys source member
    · have kept := valueGrowth.1
      have space := room.lookup
      rw [keySize]
      omega
  have stampLength (entry : List U8 × U32) (member : entry ∈ byStamp) : entry.1.length = 8 := by
    obtain ⟨stamp, _, rfl⟩ := List.mem_map.mp member
    change (reverseStampBytes stamp.stamp).length = 8
    rw [reverseStampBytes, Array.length_eq]
    rfl
  have sr : BatchBuildRoom stagedArena.order.dirs byStamp 16 := by
    refine ⟨?_, ?_, ?_⟩
    · intro entry hm
      rw [stampLength entry hm]
    · intro entry hm
      rw [stampLength entry hm]
      scalar_tac
    · have kept := orderGrowth.1
      have space := room.order
      rw [stampSize]
      omega
  have perm : List.Perm byKey logical := by
    unfold byKey logical
    exact (List.reverse_perm entries).map _
  apply WP.spec_mono
    (publish_batch_leaves_refines stagedArena _ _ byKey byStamp logical valueOK orderOK lv
      sv keys chronology perm (staged_pairing stagedArena entries staged distinct) ceiling
      16 vr sr)
  rintro ⟨root, after⟩ ⟨view, preserved, valOK, ordOK, valKept, ordKept, stamp⟩
  refine ⟨
    valOK,
    ordOK,
    oldValues.trans valKept,
    oldStamps.trans ordKept,
    ?_,
    logical,
    view,
    ?_
  ⟩
  · rw [stamp]
    exact clock
  · rw [preserved]
    unfold logical
    rw [staged_values stagedArena entries (fun e h => (staged.lookup e h).2)]
    have actual : entries.map StagedEntry.row = prepared.reverse := by
      rw [← doneRows, List.map_reverse, List.reverse_reverse]
    rw [← actual, List.map_map]
    rfl

end KvRust
