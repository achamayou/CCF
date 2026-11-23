-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.RadixLiveness

import all Aeneas.Data.List.List

@[expose] public section

namespace KvRust

open Aeneas.Std

abbrev NativeRetireQueue := Spike.retire_queue.RetireQueue

def retirementSlot (capacity head offset : Nat) : Nat :=
  if offset < capacity - head then head + offset else offset - (capacity - head)

structure RetirementQueueView (queue : NativeRetireQueue) (entries : List U32)
    : Prop where
  size : queue.len.val = entries.length
  capacity : entries.length ≤ queue.slots.val.length
  head : queue.head.val ≤ queue.slots.val.length
  wrapped : 0 < queue.slots.val.length → queue.head.val < queue.slots.val.length
  entry
    : ∀ i,
        i < entries.length
        → queue.slots.val[retirementSlot queue.slots.val.length queue.head.val i]?
          = entries[i]?

private theorem retirement_slot_bound {capacity head offset : Nat}
    (inside : head < capacity) (offsetBound : offset ≤ capacity)
    : retirementSlot capacity head offset < capacity := by
  unfold retirementSlot
  split <;> omega

private theorem retirement_slot_shift {capacity head offset : Nat}
    (inside : head < capacity) (offsetBound : offset + 1 < capacity)
    : retirementSlot capacity (retirementSlot capacity head 1) offset
      = retirementSlot capacity head (offset + 1) := by
  unfold retirementSlot
  split <;> split <;> split <;> omega

private theorem retirement_slot_matches (queue : NativeRetireQueue) (offset : Usize)
    (head : queue.head.val ≤ queue.slots.val.length)
    : WP.spec (Spike.retire_queue.RetireQueue.slot queue offset)
        (fun i =>
          i.val = retirementSlot queue.slots.val.length queue.head.val offset.val) := by
  unfold Spike.retire_queue.RetireQueue.slot
  have length : (alloc.vec.Vec.len queue.slots).val = queue.slots.val.length :=
    alloc.vec.Vec.len_val queue.slots
  have space := alloc.vec.Vec.len_ineq queue.slots
  apply WP.spec_bind
    (Usize.sub_spec (x := alloc.vec.Vec.len queue.slots) (y := queue.head) (by omega))
  intro suffix sub
  by_cases run : offset < suffix
  · have below : offset.val < suffix.val := run
    rw [ite_eq_left run]
    apply WP.spec_mono (Usize.add_spec (x := queue.head) (y := offset) (by omega))
    intro i hi
    have right : offset.val < queue.slots.val.length - queue.head.val := by omega
    simpa [retirementSlot, right] using hi
  · have beyond : suffix.val ≤ offset.val := Nat.le_of_not_gt run
    rw [ite_eq_right run]
    apply WP.spec_mono (Usize.sub_spec (x := offset) (y := suffix) beyond)
    intro i hi
    have right : ¬offset.val < queue.slots.val.length - queue.head.val := by omega
    have eq : suffix.val = queue.slots.val.length - queue.head.val := by omega
    simpa [retirementSlot, right, eq] using hi.1

theorem retirement_queue_new
    : WP.spec Spike.retire_queue.RetireQueue.new
        (fun queue => RetirementQueueView queue []) := by
  rw [Spike.retire_queue.RetireQueue.new, WP.spec_ok]
  exact ⟨rfl, by simp, by simp, by simp, by simp⟩

theorem retirement_queue_len (queue : NativeRetireQueue) (entries : List U32)
    (view : RetirementQueueView queue entries)
    : WP.spec (Spike.retire_queue.RetireQueue.impl.len queue)
        (fun n => n.val = entries.length) := by
  rw [Spike.retire_queue.RetireQueue.impl.len, WP.spec_ok]
  exact view.size

theorem retirement_queue_is_empty (queue : NativeRetireQueue) (entries : List U32)
    (view : RetirementQueueView queue entries)
    : WP.spec (Spike.retire_queue.RetireQueue.is_empty queue) (· = entries.isEmpty) := by
  rw [Spike.retire_queue.RetireQueue.is_empty, WP.spec_ok]
  have empty : queue.len = 0#usize ↔ entries = [] := by
    rw [← List.length_eq_zero_iff, ← view.size]
    exact ⟨fun h => h ▸ rfl, fun h => UScalar.eq_of_val_eq h⟩
  cases entries <;> simp_all

theorem retirement_queue_get (queue : NativeRetireQueue) (entries : List U32)
    (view : RetirementQueueView queue entries) (offset : Usize)
    : WP.spec (Spike.retire_queue.RetireQueue.get queue offset)
        (fun found => found = entries[offset.val]?) := by
  unfold Spike.retire_queue.RetireQueue.get
  have len := view.size
  have room := view.capacity
  by_cases run : offset < queue.len
  · have h : offset.val < queue.len.val := run
    have inside : offset.val < entries.length := by omega
    have head : queue.head.val < queue.slots.val.length := view.wrapped (by omega)
    rw [ite_eq_left run]
    apply WP.spec_bind (retirement_slot_matches queue offset view.head)
    intro i selected
    have valid : i.val < queue.slots.val.length := by
      rw [selected]
      exact retirement_slot_bound head (by omega)
    rw [alloc.vec.Vec.index_slice_index]
    apply WP.spec_bind (alloc.vec.Vec.index_usize_spec queue.slots i valid)
    intro link found
    rw [WP.spec_ok, found, ← List.getElem?_eq_getElem valid, selected]
    exact view.entry offset.val inside
  · have outside : entries.length ≤ offset.val := by
      have no : ¬offset.val < queue.len.val := run
      omega
    simp [run, List.getElem?_eq_none outside]

theorem retirement_queue_pop (queue : NativeRetireQueue) (entries : List U32)
    (view : RetirementQueueView queue entries)
    : WP.spec (Spike.retire_queue.RetireQueue.pop_front queue)
        (fun (item, after) =>
          item = entries.head? ∧ RetirementQueueView after entries.tail) := by
  unfold Spike.retire_queue.RetireQueue.pop_front
  have size := view.size
  have capacity := view.capacity
  have zero : (0#usize : Usize).val = 0 := rfl
  have one : (1#usize : Usize).val = 1 := rfl
  cases entries with
  | nil =>
      have empty : queue.len = 0#usize := UScalar.eq_of_val_eq size
      simpa [empty] using view
  | cons first tail =>
      have full : 0 < queue.len.val := by simp at size; omega
      have nonempty : queue.len ≠ 0#usize := fun h => by rw [h] at full; omega
      have head : queue.head.val < queue.slots.val.length := view.wrapped (by omega)
      rw [ite_eq_right nonempty, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec queue.slots queue.head head)
      intro link read
      have firstEq : link = first := by
        have eq := view.entry 0 (by simp)
        have physical : retirementSlot queue.slots.val.length queue.head.val 0 = queue.head.val := by
          unfold retirementSlot
          split <;> omega
        rw [physical, List.getElem?_eq_getElem head, ← read] at eq
        exact Option.some.inj eq
      apply WP.spec_bind (retirement_slot_matches queue 1#usize view.head)
      intro i shift
      apply WP.spec_bind (Usize.sub_spec (x := queue.len) (y := 1#usize) (by omega))
      intro len smaller
      rw [WP.spec_ok]
      have inside : i.val < queue.slots.val.length := by
        rw [shift, one]
        exact retirement_slot_bound head (by omega)
      refine ⟨congrArg some firstEq, ⟨?_, ?_, Nat.le_of_lt inside, fun _ => inside, ?_⟩⟩
      · change len.val = tail.length
        simp only [List.length_cons] at size
        omega
      · change tail.length ≤ queue.slots.val.length
        simp only [List.length_cons] at capacity
        omega
      · intro offset h
        change offset < tail.length at h
        change queue.slots.val[retirementSlot queue.slots.val.length i.val offset]? = tail[offset]?
        have within : offset + 1 < queue.slots.val.length := by
          simp only [List.length_cons] at capacity
          omega
        rw [shift, one, retirement_slot_shift head within]
        exact view.entry (offset + 1) (by simpa using Nat.succ_lt_succ h)

private theorem retirement_copy (queue : NativeRetireQueue) (entries : List U32)
    (view : RetirementQueueView queue entries) (capacity : Usize)
    : WP.spec
        (Spike.retire_queue.RetireQueue.grow_loop queue.slots queue.head queue.len
          (alloc.vec.Vec.with_capacity U32 capacity) 0#usize)
        (fun out => out.val = entries) := by
  have size := view.size
  have room := view.capacity
  have maxSize := alloc.vec.Vec.len_ineq queue.slots
  unfold Spike.retire_queue.RetireQueue.grow_loop
  apply loop.spec_decr_nat (fun (_, i) => entries.length - (i : Usize).val)
    (fun (out, i) => i.val ≤ entries.length ∧ out.val = entries.take i.val)
    _ _ _
  · rintro ⟨out, i⟩ ⟨hi, written⟩
    dsimp only at hi written ⊢
    unfold Spike.retire_queue.RetireQueue.grow_loop.body
    by_cases run : i < queue.len
    · have h : i.val < queue.len.val := run
      have within : i.val < entries.length := by omega
      have head : queue.head.val < queue.slots.val.length := view.wrapped (by omega)
      rw [ite_eq_left run]
      apply WP.spec_bind (retirement_slot_matches queue i view.head)
      intro index located
      have inside : index.val < queue.slots.val.length := by
        rw [located]
        exact retirement_slot_bound head (by omega)
      rw [alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec queue.slots index inside)
      intro item read
      have source := view.entry i.val within
      rw [← located, List.getElem?_eq_getElem inside, ← read,
        List.getElem?_eq_getElem within, Option.some.injEq] at source
      have used : out.val.length = i.val := by simp [written, Nat.min_eq_left hi]
      apply WP.spec_bind (alloc.vec.Vec.push_spec out item (by omega))
      intro next copied
      have one : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro j nextOffset
      have succ : j.val = i.val + 1 := by omega
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨by omega, ?_⟩, by omega⟩
      rw [copied, written, source, succ, List.take_succ_eq_append_getElem within]
    · have atEnd : entries.length ≤ i.val := by
        have no : ¬ i.val < queue.len.val := run
        omega
      rw [ite_eq_right run, WP.spec_ok]
      simpa [List.take_of_length_le atEnd] using written
  · simp [alloc.vec.Vec.with_capacity]

private theorem retirement_grow (queue : NativeRetireQueue) (entries : List U32)
    (view : RetirementQueueView queue entries)
    (room : 2 * queue.slots.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.retire_queue.RetireQueue.grow queue)
        (fun after =>
          RetirementQueueView after entries
          ∧ after.len.val < after.slots.val.length) := by
  unfold Spike.retire_queue.RetireQueue.grow
  have two : (2#usize : Usize).val = 2 := rfl
  have one : (1#usize : Usize).val = 1 := rfl
  have zero : (0#usize : Usize).val = 0 := rfl
  have old : (alloc.vec.Vec.len queue.slots).val = queue.slots.val.length :=
    alloc.vec.Vec.len_val queue.slots
  apply WP.spec_bind
    (Usize.mul_spec (x := 2#usize) (y := alloc.vec.Vec.len queue.slots)
      (by rw [two, old]; omega))
  intro doubled mul
  rw [two, old] at mul
  apply WP.spec_bind (Usize.add_spec (x := doubled) (y := 1#usize) (by omega))
  intro capacity increased
  have size : capacity.val = 2 * queue.slots.val.length + 1 := by omega
  have length := view.capacity
  have len := view.size
  apply WP.spec_bind (retirement_copy queue entries view capacity)
  intro copied ordered
  apply WP.spec_bind
    (alloc.vec.Vec.resize_spec core.clone.CloneU32 copied capacity 0#u32 rfl)
  intro slots resized
  have expanded : slots.val = entries ++ List.replicate (capacity.val - entries.length) 0#u32 := by
    rw [resized, ordered, List.resize, List.take_of_length_le (by omega)]
    simp
  have slotsSize : slots.val.length = capacity.val := by
    rw [expanded, List.length_append, List.length_replicate]
    omega
  rw [WP.spec_ok]
  refine ⟨
    ⟨
      len,
      by simpa [slotsSize] using (show entries.length ≤ capacity.val by omega),
      by simp,
      fun h => h,
      ?_
    ⟩,
    ?_
  ⟩
  · intro j hj
    change slots.val[retirementSlot slots.val.length (0#usize : Usize).val j]? = entries[j]?
    have direct : retirementSlot slots.val.length (0#usize : Usize).val j = j := by
      have within : j < slots.val.length := by omega
      simp [retirementSlot, zero, within]
    rw [direct, expanded, List.getElem?_append_left hj]
  · change queue.len.val < slots.val.length
    omega

private theorem retirement_slot_injective {capacity head a b : Nat}
    (inside : head < capacity) (ha : a < capacity) (hb : b < capacity)
    (same : retirementSlot capacity head a = retirementSlot capacity head b)
    : a = b := by
  unfold retirementSlot at same
  split at same <;> split at same <;> omega

theorem retirement_queue_push (queue : NativeRetireQueue) (entries : List U32)
    (view : RetirementQueueView queue entries) (link : U32)
    (room
      : queue.len.val = queue.slots.val.length
        → 2 * queue.slots.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.retire_queue.RetireQueue.push_back queue link)
        (fun after => RetirementQueueView after (entries ++ [link])) := by
  unfold Spike.retire_queue.RetireQueue.push_back
  apply WP.spec_bind (Pₘ := fun prepared : NativeRetireQueue =>
    RetirementQueueView prepared entries ∧ prepared.len.val < prepared.slots.val.length)
  · have size : (alloc.vec.Vec.len queue.slots).val = queue.slots.val.length :=
      alloc.vec.Vec.len_val queue.slots
    by_cases full : queue.len = alloc.vec.Vec.len queue.slots
    · rw [ite_eq_left full]
      exact retirement_grow queue entries view (room (by rw [full, size]))
    · rw [ite_eq_right full, WP.spec_ok]
      have notFull : queue.len.val ≠ queue.slots.val.length := fun eq =>
        full (UScalar.eq_of_val_eq (eq.trans size.symm))
      have len := view.size
      have bound := view.capacity
      exact ⟨view, by omega⟩
  · intro prepared ⟨valid, available⟩
    have len := valid.size
    have head : prepared.head.val < prepared.slots.val.length := valid.wrapped (by omega)
    apply WP.spec_bind (retirement_slot_matches prepared prepared.len valid.head)
    intro index computed
    have inside : index.val < prepared.slots.val.length := by
      rw [computed]
      exact retirement_slot_bound head (by omega)
    rw [alloc.vec.Vec.index_mut_slice_index]
    apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec prepared.slots index inside)
    rintro ⟨_, back⟩ ⟨_, update⟩
    change WP.spec (do
      let n ← prepared.len + 1#usize
      Result.ok {prepared with slots := back link, len := n}) _
    have one : (1#usize : Usize).val = 1 := rfl
    have limit := alloc.vec.Vec.len_ineq prepared.slots
    apply WP.spec_bind (Usize.add_spec (x := prepared.len) (y := 1#usize) (by omega))
    intro n newLen
    have written : (back link).val = prepared.slots.val.set index.val link := by
      rw [update]
      exact alloc.vec.Vec.set_val_eq _ _ _
    have size : (back link).val.length = prepared.slots.val.length := by simp [written]
    rw [WP.spec_ok]
    refine ⟨?_, ?_, by simpa [size] using valid.head, ?_, ?_⟩
    · change n.val = (entries ++ [link]).length
      simp only [List.length_append, List.length_singleton]
      omega
    · change (entries ++ [link]).length ≤ (back link).val.length
      simp only [size, List.length_append, List.length_singleton]
      omega
    · simpa [size] using valid.wrapped
    · intro j hj
      change (back link).val[retirementSlot (back link).val.length prepared.head.val j]? =
        (entries ++ [link])[j]?
      rw [size, written]
      by_cases prior : j < entries.length
      · have different : index.val ≠ retirementSlot prepared.slots.val.length prepared.head.val j := by
          rw [computed]
          intro same
          have eq := retirement_slot_injective head available
            (show j < prepared.slots.val.length by omega) same
          omega
        rw [List.getElem?_set_ne different, List.getElem?_append_left prior]
        exact valid.entry j prior
      · change j < (entries ++ [link]).length at hj
        have last : j = entries.length := by simp only [List.length_append, List.length_singleton] at hj; omega
        rw [last, ← len, ← computed, List.getElem?_set_self inside, len,
          List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]
        rfl

/-- Dropping an owner updates the count and appends exactly on the transition to zero. -/
theorem release_owner_schedules (count : U32) (queue : NativeRetireQueue)
    (link : U32) (owners entries : List U32)
    (exactCount : count.val = (link :: owners).count link)
    (view : RetirementQueueView queue entries)
    (room
      : owners.count link = 0
        → queue.len.val = queue.slots.val.length
        → 2 * queue.slots.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.retire_queue.release_owner count queue link)
        (fun (next, after) =>
          next.val = owners.count link
          ∧ RetirementQueueView after
              (if owners.count link = 0 then entries ++ [link] else entries)) := by
  unfold Spike.retire_queue.release_owner
  apply WP.spec_bind (release_reference_matches count link owners exactCount)
  rintro ⟨last, next⟩ ⟨test, correct⟩
  change last = decide (owners.count link = 0) at test
  change next.val = owners.count link at correct
  subst last
  by_cases zero : owners.count link = 0
  · simp only [zero, decide_true, ite_true]
    apply WP.spec_bind (retirement_queue_push queue entries view link (room zero))
    intro after valid
    rw [WP.spec_ok]
    exact ⟨by simpa only [zero] using correct, valid⟩
  · simp [zero, correct, view]

end KvRust
