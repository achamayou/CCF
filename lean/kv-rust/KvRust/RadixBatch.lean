-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Radix
public import KvRust.Range

import all Aeneas.Data.List.List

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- Every input link reads the indicated byte key and a live value row. -/
structure BatchLeaves {V : Type} (rows : Slice (Option (CcfKv.radix.RadixRow V)))
    (sorted : Slice U32) (bindings : List (List U8 × U32))
    : Prop where
  links : sorted.val = bindings.map Prod.snd
  live : RadixRows rows.val bindings

def batchKey (bindings : List (List U8 × U32)) (i : Nat) : List U8 :=
  (bindings[i]?.map Prod.fst).getD []

private theorem batch_link_at {V : Type} (rows : Slice (Option (CcfKv.radix.RadixRow V)))
    (sorted : Slice U32) (bindings : List (List U8 × U32))
    (valid : BatchLeaves rows sorted bindings) (i : Usize)
    (inside : i.val < bindings.length)
    : WP.spec (Slice.index_usize sorted i)
        (fun link =>
          link = bindings[i.val].2
          ∧ ∃ row,
              2147483648 < link.val
              ∧ radixRow rows.val link = some row
              ∧ row.key.val = batchKey bindings i.val) := by
  have fits : i.val < sorted.val.length := by simpa [valid.links] using inside
  apply WP.spec_mono (Slice.index_usize_spec sorted i fits)
  intro link read
  have old := congrArg (fun xs : List U32 => xs[i.val]?) valid.links
  rw [List.getElem?_eq_getElem fits, ← read, List.getElem?_map,
    List.getElem?_eq_getElem inside] at old
  have same : link = bindings[i.val].2 := Option.some.inj old
  obtain ⟨tag, row, live, key⟩ := valid.live _ (List.getElem_mem inside)
  exact ⟨
    same,
    row,
    by rw [same]; exact tag,
    by rwa [same],
    by simpa [batchKey, List.getElem?_eq_getElem inside] using key
  ⟩

/-- The native builder selects the earliest routing difference of a group's
first and last keys and initializes a directory with no children. -/
theorem sorted_frame_refines {V : Type} (rows : Slice (Option (CcfKv.radix.RadixRow V)))
    (sorted : Slice U32) (bindings : List (List U8 × U32))
    (valid : BatchLeaves rows sorted bindings) (begin past parent : Usize)
    (span : begin.val + 2 ≤ past.val) (inside : past.val ≤ bindings.length)
    (different : batchKey bindings begin.val ≠ batchKey bindings (past.val - 1))
    (room
      : 2
            * min (batchKey bindings begin.val).length
                (batchKey bindings (past.val - 1)).length
          + 1
        ≤ Usize.max)
    : WP.spec (CcfKv.radix.sorted_frame rows sorted begin past parent)
        (fun frame =>
          frame.cursor = begin
          ∧ frame.end = past
          ∧ frame.parent_slot = parent
          ∧ radixSplit (batchKey bindings begin.val)
              (batchKey bindings (past.val - 1)) (some frame.dir.digit.val)
          ∧ frame.dir.children.val = List.replicate 17 0#u32
          ∧ RadixMask frame.dir) := by
  unfold CcfKv.radix.sorted_frame
  apply WP.spec_bind (batch_link_at rows sorted bindings valid begin (by omega))
  intro firstLink ⟨_, firstRow, firstTag, firstLive, firstKey⟩
  apply WP.spec_bind (radix_row_at_matches rows firstLink firstRow firstTag firstLive)
  intro first sameFirst
  subst first
  have one : (1#usize : Usize).val = 1 := rfl
  apply WP.spec_bind (Usize.sub_spec (x := past) (y := 1#usize) (by omega))
  intro lastIndex previous
  have last : lastIndex.val = past.val - 1 := by omega
  apply WP.spec_bind (batch_link_at rows sorted bindings valid lastIndex (by omega))
  intro lastLink ⟨_, lastRow, lastTag, lastLive, lastKey⟩
  apply WP.spec_bind (radix_row_at_matches rows lastLink lastRow lastTag lastLive)
  intro finalRow sameLast
  subst finalRow
  have firstBytes : (alloc.vec.Vec.deref firstRow.key).val = batchKey bindings begin.val := by
    simpa [alloc.vec.Vec.deref] using firstKey
  have lastBytes : (alloc.vec.Vec.deref lastRow.key).val = batchKey bindings (past.val - 1) := by
    simpa [alloc.vec.Vec.deref, last] using lastKey
  apply WP.spec_bind
    (radix_first_difference_matches (alloc.vec.Vec.deref firstRow.key)
      (alloc.vec.Vec.deref lastRow.key) (by rwa [firstBytes, lastBytes]))
  intro digit split
  rw [firstBytes, lastBytes] at split
  cases digit with
  | none => exact (different split).elim
  | some d =>
      apply WP.spec_bind (radix_empty_matches d)
      intro dir ⟨hd, _, children, mask⟩
      rw [WP.spec_ok]
      exact ⟨rfl, rfl, rfl, hd.symm ▸ split, children, mask⟩

/-- The extracted group scanner consumes exactly a maximal run sharing the
requested routing digit, without consulting rows beyond the group's parent. -/
theorem sorted_group_end_refines {V : Type}
    (rows : Slice (Option (CcfKv.radix.RadixRow V))) (sorted : Slice U32)
    (bindings : List (List U8 × U32)) (valid : BatchLeaves rows sorted bindings)
    (begin past digit slot : Usize) (span : begin.val < past.val)
    (inside : past.val ≤ bindings.length) (space : past.val ≤ Usize.max)
    (first : radixSymbol (batchKey bindings begin.val) digit.val = slot.val)
    : WP.spec (CcfKv.radix.sorted_group_end rows sorted begin past digit slot)
        (fun next =>
          begin.val < next.val
          ∧ next.val ≤ past.val
          ∧ (∀ i,
              begin.val ≤ i
              → i < next.val
              → radixSymbol (batchKey bindings i) digit.val = slot.val)
          ∧ (next.val < past.val
              → radixSymbol (batchKey bindings next.val) digit.val ≠ slot.val)) := by
  unfold CcfKv.radix.sorted_group_end CcfKv.radix.sorted_group_end_loop
  have one : (1#usize : Usize).val = 1 := rfl
  apply WP.spec_bind (Usize.add_spec (x := begin) (y := 1#usize) (by omega))
  intro start startStep
  apply loop.spec_decr_nat (fun (i : Usize) => past.val - i.val)
    (fun i =>
      begin.val < i.val
      ∧ i.val ≤ past.val
      ∧ ∀ j,
          begin.val ≤ j
          → j < i.val
          → radixSymbol (batchKey bindings j) digit.val = slot.val)
    _ _ _
  · intro i ⟨afterBegin, untilEnd, consumed⟩
    unfold CcfKv.radix.sorted_group_end_loop.body
    by_cases run : i < past
    · have h : i.val < past.val := run
      rw [ite_eq_left run]
      apply WP.spec_bind (batch_link_at rows sorted bindings valid i (by omega))
      intro link ⟨_, row, tagged, saved, key⟩
      apply WP.spec_bind (radix_row_at_matches rows link row tagged saved)
      intro entry read
      subst entry
      apply WP.spec_bind (radix_symbol_matches (alloc.vec.Vec.deref row.key) digit)
      intro got symbolEq
      have symbolMatches : got.val = radixSymbol (batchKey bindings i.val) digit.val := by
        simpa [alloc.vec.Vec.deref, key] using symbolEq
      by_cases sameSlot : got = slot
      · simp only [sameSlot, bne_self_eq_false, Bool.false_eq_true, ite_false]
        apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
        intro next moved
        rw [WP.spec_ok]
        refine ⟨⟨by omega, by omega, ?_⟩, by omega⟩
        intro j lower upper
        by_cases earlier : j < i.val
        · exact consumed j lower earlier
        · have atBoundary : j = i.val := by omega
          rw [atBoundary, ← symbolMatches, sameSlot]
      · simp only [bne_iff_ne.mpr sameSlot, ite_true, WP.spec_ok]
        exact ⟨afterBegin, untilEnd, consumed, fun _ same =>
          sameSlot (UScalar.eq_of_val_eq (symbolMatches.trans same))⟩
    · rw [ite_eq_right run, WP.spec_ok]
      exact ⟨afterBegin, untilEnd, consumed, fun h => (run h).elim⟩
  · refine ⟨by omega, by omega, ?_⟩
    intro j lower upper
    have same : j = begin.val := by omega
    rwa [same]

private theorem symbol_mono_with_prefix (a b : List U8) (digit : Nat)
    (sorted : a ≤ b) (prefixEq : ∀ i < digit, radixSymbol a i = radixSymbol b i)
    : radixSymbol a digit ≤ radixSymbol b digit := by
  by_contra opposite
  have lt : radixSymbol b digit < radixSymbol a digit := Nat.lt_of_not_ge opposite
  have reversed := radix_first_symbol_lt b a digit (fun i h => (prefixEq i h).symm) lt
  have order : byteOrder b a < 0#i8 := by rw [reversed]; decide
  exact not_lt_of_ge sorted ((byteOrder_lt b a).mp order)

private theorem between_prefix (first inner last : List U8) (digit : Nat)
    (above : first ≤ inner) (below : inner ≤ last)
    (shared : ∀ i < digit, radixSymbol first i = radixSymbol last i)
    : ∀ i < digit,
        radixSymbol first i = radixSymbol inner i
        ∧ radixSymbol inner i = radixSymbol last i := by
  intro i
  induction i using Nat.strong_induction_on with
  | ind i earlier =>
      intro hi
      have lo := symbol_mono_with_prefix first inner i above
        (fun j hj => (earlier j hj (hj.trans hi)).1)
      have up := symbol_mono_with_prefix inner last i below
        (fun j hj => (earlier j hj (hj.trans hi)).2)
      have eq := shared i hi
      exact ⟨by omega, by omega⟩

private theorem batch_key_order (bindings : List (List U8 × U32)) (i j : Nat)
    (sorted : bindings.Pairwise radixKeyLt) (forward : i ≤ j)
    (inside : j < bindings.length)
    : batchKey bindings i ≤ batchKey bindings j := by
  by_cases same : i = j
  · simp [same]
  · have earlier : i < j := Nat.lt_of_le_of_ne forward same
    have hi : i < bindings.length := earlier.trans inside
    have pair := sorted.rel_getElem_of_lt hi inside earlier
    have hlt : byteOrder bindings[i].1 bindings[j].1 < 0#i8 := by
      unfold radixKeyLt at pair
      rw [pair]
      decide
    simpa [batchKey, List.getElem?_eq_getElem hi, List.getElem?_eq_getElem inside]
      using le_of_lt ((byteOrder_lt _ _).mp hlt)

/-- In a sorted interval, every key shares the endpoints' common prefix, and
the first differing digit splits the interval into ordered, contiguous groups. -/
theorem batch_split_partition (bindings : List (List U8 × U32)) (begin past digit : Nat)
    (sorted : bindings.Pairwise radixKeyLt) (nonempty : begin < past)
    (inside : past ≤ bindings.length)
    (split
      : radixSplit (batchKey bindings begin) (batchKey bindings (past - 1)) (some digit))
    : (∀ i,
        begin ≤ i
        → i < past
        → ∀ prev < digit,
            radixSymbol (batchKey bindings i) prev
            = radixSymbol (batchKey bindings begin) prev)
      ∧ (∀ i j,
          begin ≤ i
          → i ≤ j
          → j < past
          → radixSymbol (batchKey bindings i) digit
            ≤ radixSymbol (batchKey bindings j) digit)
      ∧ radixSymbol (batchKey bindings begin) digit
        < radixSymbol (batchKey bindings (past - 1)) digit := by
  have shared (i : Nat) (afterBegin : begin ≤ i) (beforeEnd : i < past) :
      ∀ prev < digit,
        radixSymbol (batchKey bindings i) prev = radixSymbol (batchKey bindings begin) prev := by
    have first := batch_key_order bindings begin i sorted afterBegin (by omega)
    have last := batch_key_order bindings i (past - 1) sorted (by omega) (by omega)
    intro prev earlier
    exact (between_prefix _ _ _ digit first last split.2 prev earlier).1.symm
  have digits (i j : Nat) (afterBegin : begin ≤ i) (ij : i ≤ j) (beforeEnd : j < past) :
      radixSymbol (batchKey bindings i) digit ≤ radixSymbol (batchKey bindings j) digit := by
    apply symbol_mono_with_prefix _ _ _ (batch_key_order bindings i j sorted ij (by omega))
    intro prev earlier
    exact (shared i afterBegin (by omega) prev earlier).trans
      (shared j (by omega) beforeEnd prev earlier).symm
  exact ⟨
    shared,
    digits,
    Nat.lt_of_le_of_ne (digits begin (past - 1) (by omega) (by omega) (by omega)) split.1
  ⟩

def batchInterval {α : Type} (entries : List α) (begin past : Nat) : List α :=
  (entries.take past).drop begin

theorem batch_interval_length {α : Type} (entries : List α) (begin past : Nat)
    (within : past ≤ entries.length)
    : (batchInterval entries begin past).length = past - begin := by
  simp [batchInterval, Nat.min_eq_left within]

theorem batch_interval_append {α : Type} (entries : List α) (begin middle past : Nat)
    (forward : begin ≤ middle) (within : middle ≤ past)
    : batchInterval entries begin middle ++ batchInterval entries middle past
      = batchInterval entries begin past := by
  have split := List.take_append_drop (middle - begin) ((entries.take past).drop begin)
  rw [List.take_drop, List.drop_drop, show begin + (middle - begin) = middle by omega,
    List.take_take, Nat.min_eq_left within] at split
  exact split

private theorem batch_interval_read (bindings : List (List U8 × U32)) (begin past : Nat)
    (entry : List U8 × U32) (member : entry ∈ batchInterval bindings begin past)
    : ∃ i, begin ≤ i ∧ i < past ∧ batchKey bindings i = entry.1 := by
  obtain ⟨offset, read⟩ := List.mem_iff_getElem?.mp member
  have within := (List.getElem?_eq_some_iff.mp read).1
  have upper : begin + offset < past := by
    simp only [batchInterval, List.length_drop, List.length_take] at within
    omega
  unfold batchInterval at read
  rw [List.getElem?_drop, List.getElem?_take_of_lt upper] at read
  exact ⟨begin + offset, by omega, upper, by simp [batchKey, read]⟩

/-- In a parent interval, a maximal group with no earlier occurrences is
exactly the full child partition, with the original binding order. -/
theorem batch_group_partition (bindings : List (List U8 × U32))
    (begin cursor next past digit slot : Nat)
    (starts : begin ≤ cursor) (nonempty : cursor < next) (inside : next ≤ past)
    (monotone
      : ∀ i j,
          begin ≤ i
          → i ≤ j
          → j < past
          → radixSymbol (batchKey bindings i) digit
            ≤ radixSymbol (batchKey bindings j) digit)
    (earlier
      : ∀ i, begin ≤ i → i < cursor → radixSymbol (batchKey bindings i) digit < slot)
    (accepted
      : ∀ i, cursor ≤ i → i < next → radixSymbol (batchKey bindings i) digit = slot)
    (boundary : next < past → radixSymbol (batchKey bindings next) digit ≠ slot)
    : (batchInterval bindings begin past).filter
        (fun entry => radixSymbol entry.1 digit == slot)
      = batchInterval bindings cursor next := by
  let belongs := fun entry : List U8 × U32 => radixSymbol entry.1 digit == slot
  change (batchInterval bindings begin past).filter belongs = _
  have left : (batchInterval bindings begin cursor).filter belongs = [] := by
    apply List.filter_eq_nil_iff.mpr
    intro entry hm
    obtain ⟨i, lo, hi, key⟩ := batch_interval_read bindings begin cursor entry hm
    have lower := earlier i lo hi
    simp [belongs, ← key, Nat.ne_of_lt lower]
  have middle : (batchInterval bindings cursor next).filter belongs
      = batchInterval bindings cursor next := by
    apply List.filter_eq_self.mpr
    intro entry hm
    obtain ⟨i, lo, hi, key⟩ := batch_interval_read bindings cursor next entry hm
    simp [belongs, ← key, accepted i lo hi]
  have right : (batchInterval bindings next past).filter belongs = [] := by
    apply List.filter_eq_nil_iff.mpr
    intro entry hm
    obtain ⟨i, lo, hi, key⟩ := batch_interval_read bindings next past entry hm
    have nextBound : next < past := by omega
    have current := accepted cursor (Nat.le_refl _) nonempty
    have asc := monotone cursor next starts (by omega) nextBound
    have above := monotone next i (by omega) lo hi
    have differs := boundary nextBound
    have ne : radixSymbol (batchKey bindings i) digit ≠ slot := by omega
    simp [belongs, ← key, ne]
  rw [← batch_interval_append bindings begin cursor past starts (by omega),
    ← batch_interval_append bindings cursor next past (by omega) inside,
    List.filter_append, List.filter_append, left, middle, right]
  simp

/-- A stack frame contains precisely the already completed group partitions.
The ghost cursor may lag the native cursor while a child frame is in flight. -/
structure BatchFrameView (dirs : List (Option CcfKv.radix.RadixDir))
    (bindings : List (List U8 × U32)) (frame : CcfKv.radix.BuildFrame)
    (begin doneAt : Nat)
    : Prop where
  span : begin + 2 ≤ frame.end.val
  bound : frame.end.val ≤ bindings.length
  fromBegin : begin ≤ doneAt
  toEnd : doneAt ≤ frame.end.val
  split
    : radixSplit (batchKey bindings begin) (batchKey bindings (frame.end.val - 1))
        (some frame.dir.digit.val)
  mask : RadixMask frame.dir
  children
    : RadixPartition dirs bindings.length frame.dir.digit frame.dir.children.val
        (batchInterval bindings begin doneAt)
  earlier
    : ∀ i,
        begin ≤ i
        → i < doneAt
        → doneAt < frame.end.val
        → radixSymbol (batchKey bindings i) frame.dir.digit.val
          < radixSymbol (batchKey bindings doneAt) frame.dir.digit.val

theorem BatchFrameView.preserve
    {before after : alloc.vec.Vec (Option CcfKv.radix.RadixDir)}
    {bindings : List (List U8 × U32)} {frame : CcfKv.radix.BuildFrame}
    {begin doneAt : Nat} (view : BatchFrameView before.val bindings frame begin doneAt)
    (kept : preservesSlots before after)
    : BatchFrameView after.val bindings frame begin doneAt := by
  refine ⟨view.span, view.bound, view.fromBegin, view.toEnd, view.split, view.mask, ?_, view.earlier⟩
  intro slot bound
  obtain ⟨child, read, tree⟩ := view.children slot bound
  exact ⟨child, read, radix_tree_preserved before.val after.val kept tree⟩

theorem batch_fresh_frame {V : Type} (dirs : List (Option CcfKv.radix.RadixDir))
    (rows : Slice (Option (CcfKv.radix.RadixRow V))) (sorted : Slice U32)
    (bindings : List (List U8 × U32)) (valid : BatchLeaves rows sorted bindings)
    (begin past parent : Usize) (span : begin.val + 2 ≤ past.val)
    (inside : past.val ≤ bindings.length)
    (different : batchKey bindings begin.val ≠ batchKey bindings (past.val - 1))
    (room
      : 2
            * min (batchKey bindings begin.val).length
                (batchKey bindings (past.val - 1)).length
          + 1
        ≤ Usize.max)
    : WP.spec (CcfKv.radix.sorted_frame rows sorted begin past parent)
        (fun frame =>
          frame.cursor = begin
          ∧ frame.end = past
          ∧ frame.parent_slot = parent
          ∧ BatchFrameView dirs bindings frame begin.val begin.val) := by
  apply WP.spec_mono (sorted_frame_refines rows sorted bindings valid begin past parent
    span inside different room)
  intro frame ⟨cursor, last, resume, split, empty, mask⟩
  refine ⟨cursor, last, resume, ?_⟩
  refine ⟨
    by rwa [last],
    by rwa [last],
    Nat.le_refl _,
    by rw [last]; omega,
    by simpa only [last] using split,
    mask,
    ?_,
    by omega
  ⟩
  intro slot inside
  have slice : batchInterval bindings begin.val begin.val = [] := by simp [batchInterval]
  refine ⟨0#u32, ?_, ?_⟩
  · rw [empty, List.getElem?_replicate, ite_eq_left inside]
  · simp only [slice, List.filter_nil]
    exact .empty _

/-- Attach one completed group to the prepared parent without losing sibling trees. -/
theorem batch_attach_child (dirs : List (Option CcfKv.radix.RadixDir))
    (bindings : List (List U8 × U32)) (frame : CcfKv.radix.BuildFrame)
    (begin cursor next : Nat) (slot : Usize)
    (view : BatchFrameView dirs bindings frame begin cursor)
    (sorted : bindings.Pairwise radixKeyLt) (nonempty : cursor < next)
    (inside : next ≤ frame.end.val)
    (accepted
      : ∀ i,
          cursor ≤ i
          → i < next
          → radixSymbol (batchKey bindings i) frame.dir.digit.val = slot.val)
    (boundary
      : next < frame.end.val
        → radixSymbol (batchKey bindings next) frame.dir.digit.val ≠ slot.val)
    (child : U32)
    (tree : RadixTree dirs bindings.length child (batchInterval bindings cursor next))
    : WP.spec (CcfKv.radix.RadixDir.set_child frame.dir slot child)
        (fun dir =>
          dir.digit = frame.dir.digit
          ∧ BatchFrameView dirs bindings {frame with dir} begin next) := by
  have slotEq := accepted cursor (Nat.le_refl _) nonempty
  have slotBound : slot.val < 17 := slotEq ▸ radixSymbol_bound _ _
  obtain ⟨_, monotone, _⟩ := batch_split_partition bindings begin frame.end.val frame.dir.digit.val
    sorted (by have h := view.span; omega) view.bound view.split
  have beforeGroup (i : Nat) (lo : begin ≤ i) (hi : i < cursor) :
      radixSymbol (batchKey bindings i) frame.dir.digit.val < slot.val := by
    rw [← slotEq]
    exact view.earlier i lo hi (by omega)
  have partition := batch_group_partition bindings begin cursor next next frame.dir.digit.val slot.val
    view.fromBegin nonempty (Nat.le_refl _)
    (fun i j lo order bound => monotone i j lo order (by omega))
    beforeGroup accepted (fun h => (Nat.lt_irrefl _ h).elim)
  apply WP.spec_mono (radix_set_child_matches frame.dir slot child slotBound)
  intro dir ⟨digit, _, links, bitmap⟩
  refine ⟨digit, ?_⟩
  refine ⟨
    view.span,
    view.bound,
    view.fromBegin.trans (Nat.le_of_lt nonempty),
    inside,
    by simpa only [digit] using view.split,
    radix_updated_mask frame.dir dir slot child slotBound view.mask links bitmap,
    ?_,
    ?_
  ⟩
  · intro j hj
    change ∃ root, dir.children.val[j]? = some root ∧ RadixTree dirs bindings.length root
        ((batchInterval bindings begin next).filter fun row => radixSymbol row.1 dir.digit.val == j)
    rw [digit, links]
    by_cases chosen : j = slot.val
    · subst j
      rw [List.getElem?_set_self (by rw [Array.length_eq]; exact slotBound), partition]
      exact ⟨child, rfl, tree⟩
    · rw [List.getElem?_set_ne (Ne.symm chosen)]
      have noMatch : (batchInterval bindings cursor next).filter
          (fun row => radixSymbol row.1 frame.dir.digit.val == j) = [] := by
        apply List.filter_eq_nil_iff.mpr
        intro entry member
        obtain ⟨i, lo, hi, key⟩ := batch_interval_read bindings cursor next entry member
        simp [← key, accepted i lo hi, Ne.symm chosen]
      rw [← batch_interval_append bindings begin cursor next view.fromBegin (by omega),
        List.filter_append, noMatch, List.append_nil]
      exact view.children j hj
  · intro i lo hi unread
    change radixSymbol (batchKey bindings i) dir.digit.val
        < radixSymbol (batchKey bindings next) dir.digit.val
    rw [digit]
    have source := view.fromBegin
    have fromCursor := monotone cursor next source (by omega) unread
    rw [slotEq] at fromCursor
    have strict := boundary unread
    by_cases prior : i < cursor
    · have h := beforeGroup i lo prior
      omega
    · rw [accepted i (Nat.le_of_not_gt prior) hi]
      omega

private theorem batch_interval_member {α : Type} (entries : List α) (begin past i : Nat)
    (afterBegin : begin ≤ i) (beforeEnd : i < past) (within : past ≤ entries.length)
    : entries[i]'(beforeEnd.trans_le within) ∈ batchInterval entries begin past := by
  apply List.mem_iff_getElem?.mpr
  refine ⟨i - begin, ?_⟩
  unfold batchInterval
  rw [List.getElem?_drop, show begin + (i - begin) = i by omega,
    List.getElem?_take_of_lt beforeEnd, List.getElem?_eq_getElem (beforeEnd.trans_le within)]

private theorem batch_interval_subset {α : Type} (entries : List α) (begin past : Nat)
    : batchInterval entries begin past ⊆ entries :=
  fun _ h => List.mem_of_mem_take (List.mem_of_mem_drop h)

/-- Once all groups in the interval are attached, publishing the directory
is a single allocation and preserves the existing arena. -/
theorem batch_publish_frame {V : Type}
    (dirs : alloc.vec.Vec (Option CcfKv.radix.RadixDir)) (free : alloc.vec.Vec Usize)
    (rows : Slice (Option (CcfKv.radix.RadixRow V))) (bindings : List (List U8 × U32))
    (frame : CcfKv.radix.BuildFrame) (begin : Nat)
    (view : BatchFrameView dirs.val bindings frame begin frame.end.val)
    (sorted : bindings.Pairwise radixKeyLt) (live : RadixRows rows.val bindings)
    (directories : RadixDirectoryInvariant dirs)
    (known : RadixKnowledge dirs (radixKeyOf rows.val)) (available : RadixFree dirs free)
    (room : dirs.val.length < 2147483647)
    : WP.spec (CcfKv.radix.add_directory dirs free frame.dir)
        (fun (root, after, left) =>
          preservesSlots dirs after
          ∧ RadixFree after left
          ∧ after.val.length ≤ dirs.val.length + 1
          ∧ RadixDirectoryInvariant after
          ∧ RadixKnowledge after (radixKeyOf rows.val)
          ∧ RadixTree after.val bindings.length root
              (batchInterval bindings begin frame.end.val)) := by
  let entries := batchInterval bindings begin frame.end.val
  obtain ⟨shared, _, different⟩ := batch_split_partition bindings begin frame.end.val frame.dir.digit.val
    sorted (by have h := view.span; omega) view.bound view.split
  have child (i : Nat) (lo : begin ≤ i) (hi : i < frame.end.val) :
      Occupied frame.dir (radixSymbol (batchKey bindings i) frame.dir.digit.val) := by
    have within := hi.trans_le view.bound
    let entry := bindings[i]'within
    let slot := radixSymbol (batchKey bindings i) frame.dir.digit.val
    have key : batchKey bindings i = entry.1 := by simp [batchKey, List.getElem?_eq_getElem within, entry]
    have member : entry ∈ entries := batch_interval_member bindings begin frame.end.val i lo hi view.bound
    obtain ⟨link, read, tree⟩ := view.children slot (radixSymbol_bound _ _)
    refine ⟨link, read, ?_⟩
    intro zero
    have empty := radix_tree_zero tree zero
    have hit : entry ∈ entries.filter (fun row => radixSymbol row.1 frame.dir.digit.val == slot) :=
      List.mem_filter.mpr ⟨member, by simp [slot, key]⟩
    rw [empty] at hit
    exact List.not_mem_nil hit
  have span := view.span
  have occupied : ∃ a b, a ≠ b ∧ Occupied frame.dir a ∧ Occupied frame.dir b :=
    ⟨_, _, Nat.ne_of_lt different, child begin (Nat.le_refl _) (by omega),
      child (frame.end.val - 1) (by omega) (by omega)⟩
  apply WP.spec_mono (radix_publish_partition dirs free frame.dir bindings.length entries
    view.children view.mask occupied directories available room)
  rintro ⟨root, after, left⟩ ⟨kept, vacant, growth, valid, tree, adds⟩
  have height := (radix_tree_binding_bound after valid tree).1
  have bounded : entries.length ≤ bindings.length := by
    have size := batch_interval_length bindings begin frame.end.val view.bound
    have hi := view.bound
    change entries.length = frame.end.val - begin at size
    omega
  refine ⟨kept, vacant, growth, valid, ?_, radix_tree_height height bounded⟩
  apply radix_knowledge_extend dirs after _ _ known kept (fun _ _ h => h)
  intro i published saved absent
  obtain ⟨link, h, found, whereAt, untagged, projected, digit, exactRows⟩ :=
    adds i published saved absent
  subst found
  refine ⟨link, h, entries, whereAt, untagged, projected, ?_, ?_⟩
  · intro entry member
    have belongs : entry ∈ bindings := batch_interval_subset bindings begin frame.end.val member
    obtain ⟨_, row, read, bytes⟩ := live entry belongs
    simp [radixKeyOf, read, bytes]
  · intro a ha b hb idx beforeSplit
    obtain ⟨i, ilo, ihi, ka⟩ := batch_interval_read bindings begin frame.end.val a ha
    obtain ⟨j, jlo, jhi, kb⟩ := batch_interval_read bindings begin frame.end.val b hb
    rw [digit] at beforeSplit
    rw [← ka, ← kb, shared i ilo ihi idx beforeSplit, shared j jlo jhi idx beforeSplit]

/-- The native parent stack is read in reverse. Each suspended parent records
the interval and routing slot of the one child it is waiting to attach. -/
inductive BatchSuspension (dirs : List (Option CcfKv.radix.RadixDir))
    (bindings : List (List U8 × U32))
    : List CcfKv.radix.BuildFrame → Nat → Nat → Nat → Prop where
  | top {slot : Nat} : BatchSuspension dirs bindings [] 0 bindings.length slot
  | pending (parent : CcfKv.radix.BuildFrame) (rest : List CcfKv.radix.BuildFrame)
    (begin childBegin childSlot : Nat)
    (outer
      : BatchSuspension dirs bindings rest begin parent.end.val parent.parent_slot.val)
    (view : BatchFrameView dirs bindings parent begin childBegin)
    (span : childBegin < parent.cursor.val)
    (within : parent.cursor.val ≤ parent.end.val)
    (grouped
      : ∀ i,
          childBegin ≤ i
          → i < parent.cursor.val
          → radixSymbol (batchKey bindings i) parent.dir.digit.val = childSlot)
    (boundary
      : parent.cursor.val < parent.end.val
        → radixSymbol (batchKey bindings parent.cursor.val) parent.dir.digit.val
          ≠ childSlot)
    : BatchSuspension dirs bindings (parent :: rest) childBegin parent.cursor.val
        childSlot

theorem BatchSuspension.preserve
    {before after : alloc.vec.Vec (Option CcfKv.radix.RadixDir)}
    {bindings : List (List U8 × U32)} {stack : List CcfKv.radix.BuildFrame}
    {begin past slot : Nat}
    (suspended : BatchSuspension before.val bindings stack begin past slot)
    (kept : preservesSlots before after)
    : BatchSuspension after.val bindings stack begin past slot := by
  induction suspended with
  | top => exact .top
  | pending parent rest begin childBegin childSlot outer view span within grouped boundary ih
    =>
      exact .pending parent rest begin childBegin childSlot ih (view.preserve kept)
        span within grouped boundary

private theorem batch_top {dirs : List (Option CcfKv.radix.RadixDir)}
    {bindings : List (List U8 × U32)} {begin past slot : Nat}
    (suspended : BatchSuspension dirs bindings [] begin past slot)
    : begin = 0 ∧ past = bindings.length := by
  cases suspended
  exact ⟨rfl, rfl⟩

private theorem batch_parent {dirs : List (Option CcfKv.radix.RadixDir)}
    {bindings : List (List U8 × U32)} {parent : CcfKv.radix.BuildFrame}
    {rest : List CcfKv.radix.BuildFrame} {begin past slot : Nat}
    (suspended : BatchSuspension dirs bindings (parent :: rest) begin past slot)
    : ∃ start,
        BatchSuspension dirs bindings rest start parent.end.val parent.parent_slot.val
        ∧ BatchFrameView dirs bindings parent start begin
        ∧ begin < past
        ∧ past = parent.cursor.val
        ∧ past ≤ parent.end.val
        ∧ (∀ i,
            begin ≤ i
            → i < past
            → radixSymbol (batchKey bindings i) parent.dir.digit.val = slot)
        ∧ (past < parent.end.val
            → radixSymbol (batchKey bindings past) parent.dir.digit.val ≠ slot) := by
  cases suspended with
  | pending p rest start childBegin childSlot outer view span within grouped boundary =>
      exact ⟨start, outer, view, span, rfl, within, grouped, boundary⟩

private theorem batch_interval_single (bindings : List (List U8 × U32)) (i : Nat)
    (inside : i < bindings.length)
    : batchInterval bindings i (i + 1) = [bindings[i]] := by
  have size := batch_interval_length bindings i (i + 1) (by omega)
  have member := batch_interval_member bindings i (i + 1) i (Nat.le_refl _) (by omega) (by omega)
  cases sliced : batchInterval bindings i (i + 1) with
  | nil => simp [sliced] at member
  | cons head rest =>
      rw [sliced] at size member
      have empty : rest = [] := by
        have zero : rest.length = 0 := by simp only [List.length_cons] at size; omega
        exact List.length_eq_zero_iff.mp zero
      subst rest
      simp only [List.mem_singleton] at member
      rw [member]

private theorem batch_key_limit (bindings : List (List U8 × U32)) (i ceiling : Nat)
    (inside : i < bindings.length)
    (bounded : ∀ entry ∈ bindings, 2 * entry.1.length ≤ ceiling)
    : 2 * (batchKey bindings i).length ≤ ceiling := by
  simpa [batchKey, List.getElem?_eq_getElem inside]
    using bounded _ (List.getElem_mem inside)

private theorem batch_split_limit (bindings : List (List U8 × U32))
    (begin past digit ceiling : Nat) (span : begin < past)
    (inside : past ≤ bindings.length)
    (bounded : ∀ entry ∈ bindings, 2 * entry.1.length ≤ ceiling)
    (split
      : radixSplit (batchKey bindings begin) (batchKey bindings (past - 1)) (some digit))
    : digit < ceiling := by
  by_contra tooHigh
  have first := batch_key_limit bindings begin ceiling (by omega) bounded
  have last := batch_key_limit bindings (past - 1) ceiling (by omega) bounded
  have a := (radixSymbol_terminal (batchKey bindings begin) digit).mpr (by omega)
  have b := (radixSymbol_terminal (batchKey bindings (past - 1)) digit).mpr (by omega)
  exact split.1 (a.trans b.symm)

private theorem batch_key_distinct (bindings : List (List U8 × U32)) (i j : Nat)
    (sorted : bindings.Pairwise radixKeyLt) (forward : i < j)
    (inside : j < bindings.length)
    : batchKey bindings i ≠ batchKey bindings j := by
  have hi := forward.trans inside
  have ordered := sorted.rel_getElem_of_lt hi inside forward
  have lt : byteOrder bindings[i].1 bindings[j].1 < 0#i8 := by
    unfold radixKeyLt at ordered
    rw [ordered]
    decide
  simpa [batchKey, List.getElem?_eq_getElem hi, List.getElem?_eq_getElem inside]
    using ne_of_lt ((byteOrder_lt _ _).mp lt)

private theorem batch_nested_split (bindings : List (List U8 × U32))
    (begin past digit first last split slot : Nat) (sorted : bindings.Pairwise radixKeyLt)
    (span : begin < past) (inside : past ≤ bindings.length)
    (parent
      : radixSplit (batchKey bindings begin) (batchKey bindings (past - 1)) (some digit))
    (firstIn : begin ≤ first) (lastIn : last < past) (forward : first ≤ last)
    (a : radixSymbol (batchKey bindings first) digit = slot)
    (b : radixSymbol (batchKey bindings last) digit = slot)
    (child : radixSplit (batchKey bindings first) (batchKey bindings last) (some split))
    : digit < split := by
  obtain ⟨common, _, _⟩ := batch_split_partition bindings begin past digit sorted span inside parent
  by_contra no
  apply child.1
  by_cases earlier : split < digit
  · exact (common first firstIn (by omega) split earlier).trans
      (common last (by omega) lastIn split earlier).symm
  · have atSplit : split = digit := by omega
    rw [atSplit, a, b]

private def frameWork (ceiling : Nat) (frame : CcfKv.radix.BuildFrame) : Nat :=
  (frame.end.val - frame.cursor.val) * (ceiling - frame.dir.digit.val + 1)

private def batchWork (ceiling : Nat) (parents : List CcfKv.radix.BuildFrame)
    (frame : CcfKv.radix.BuildFrame)
    : Nat :=
  2 * ((parents.map (frameWork ceiling)).sum + frameWork ceiling frame) + parents.length

private theorem batch_work_pop (ceiling : Nat) (rest : List CcfKv.radix.BuildFrame)
    (parent frame : CcfKv.radix.BuildFrame) (dir : CcfKv.radix.RadixDir)
    (finished : frame.cursor = frame.end) (same : dir.digit = parent.dir.digit)
    : batchWork ceiling (rest ++ [parent]) frame
      = batchWork ceiling rest {parent with dir} + 1 := by
  simp [batchWork, frameWork, finished, same]
  omega

private theorem batch_work_child (ceiling : Nat) (parents : List CcfKv.radix.BuildFrame)
    (frame child : CcfKv.radix.BuildFrame) (next : Usize)
    (bounds : frame.cursor.val < next.val ∧ next.val ≤ frame.end.val)
    (starts : child.cursor = frame.cursor) (ends : child.end = next)
    (nested : frame.dir.digit.val < child.dir.digit.val)
    (depth : child.dir.digit.val ≤ ceiling)
    : batchWork ceiling (parents ++ [{frame with cursor := next}]) child
      < batchWork ceiling parents frame := by
  let work := ceiling - frame.dir.digit.val + 1
  let inner := ceiling - child.dir.digit.val + 1
  have diff : inner < work := by dsimp [inner, work]; omega
  have positive : 0 < next.val - frame.cursor.val := by omega
  have shrunk := Nat.mul_lt_mul_of_pos_left diff positive
  have split : frame.end.val - frame.cursor.val =
      (frame.end.val - next.val) + (next.val - frame.cursor.val) := by omega
  unfold batchWork
  simp only [List.map_append, List.map_cons, List.map_nil, List.sum_append, List.sum_cons,
    List.sum_nil, Nat.add_zero, List.length_append, List.length_singleton]
  unfold frameWork
  simp only [starts, ends, split, Nat.add_mul]
  change 2 * ((parents.map (frameWork ceiling)).sum + (frame.end.val - next.val) * work
      + (next.val - frame.cursor.val) * inner) + (parents.length + 1) <
    2 * ((parents.map (frameWork ceiling)).sum + ((frame.end.val - next.val) * work
      + (next.val - frame.cursor.val) * work)) + parents.length
  omega

private theorem batch_work_leaf (ceiling : Nat) (parents : List CcfKv.radix.BuildFrame)
    (frame : CcfKv.radix.BuildFrame) (next : Usize) (dir : CcfKv.radix.RadixDir)
    (bounds : frame.cursor.val < next.val ∧ next.val ≤ frame.end.val)
    (same : dir.digit = frame.dir.digit)
    : batchWork ceiling parents {frame with cursor := next, dir}
      < batchWork ceiling parents frame := by
  let work := ceiling - frame.dir.digit.val + 1
  have positive : 0 < work := Nat.zero_lt_succ _
  have smaller : frame.end.val - next.val < frame.end.val - frame.cursor.val := by omega
  have shrunk := Nat.mul_lt_mul_of_pos_right smaller positive
  change 2 * ((parents.map (frameWork ceiling)).sum +
      (frame.end.val - next.val) * (ceiling - dir.digit.val + 1)) + parents.length <
    2 * ((parents.map (frameWork ceiling)).sum + (frame.end.val - frame.cursor.val) * work) +
      parents.length
  rw [same]
  change 2 * ((parents.map (frameWork ceiling)).sum + (frame.end.val - next.val) * work) +
      parents.length <
    2 * ((parents.map (frameWork ceiling)).sum + (frame.end.val - frame.cursor.val) * work) +
      parents.length
  omega

private theorem BatchFrameView.withCursor {dirs : List (Option CcfKv.radix.RadixDir)}
    {bindings : List (List U8 × U32)} {frame : CcfKv.radix.BuildFrame}
    {begin doneAt : Nat} (view : BatchFrameView dirs bindings frame begin doneAt)
    (cursor : Usize)
    : BatchFrameView dirs bindings {frame with cursor} begin doneAt :=
  ⟨
    view.span,
    view.bound,
    view.fromBegin,
    view.toEnd,
    view.split,
    view.mask,
    view.children,
    view.earlier
  ⟩

private theorem batch_key_room (bindings : List (List U8 × U32)) (i j : Nat)
    (inside : i < bindings.length)
    (bounded : ∀ entry ∈ bindings, 2 * entry.1.length + 1 ≤ Usize.max)
    : 2 * min (batchKey bindings i).length (batchKey bindings j).length + 1
      ≤ Usize.max := by
  have limit : 2 * (batchKey bindings i).length + 1 ≤ Usize.max := by
    simpa [batchKey, List.getElem?_eq_getElem inside]
      using bounded _ (List.getElem_mem inside)
  have minimum := Nat.min_le_left (batchKey bindings i).length (batchKey bindings j).length
  omega

private abbrev BuildDirs := alloc.vec.Vec (Option CcfKv.radix.RadixDir)

private theorem build_sorted_loop_refines {V : Type} (original dirs : BuildDirs)
    (free : alloc.vec.Vec Usize) (rows : Slice (Option (CcfKv.radix.RadixRow V)))
    (sorted : Slice U32) (bindings : List (List U8 × U32))
    (input : BatchLeaves rows sorted bindings) (ordered : bindings.Pairwise radixKeyLt)
    (ceiling : Nat) (bounded : ∀ entry ∈ bindings, 2 * entry.1.length ≤ ceiling)
    (keyRoom : ∀ entry ∈ bindings, 2 * entry.1.length + 1 ≤ Usize.max)
    (parents : alloc.vec.Vec CcfKv.radix.BuildFrame) (frame : CcfKv.radix.BuildFrame)
    (ready
      : ∃ begin,
          BatchFrameView dirs.val bindings frame begin frame.cursor.val
          ∧ BatchSuspension dirs.val bindings parents.val.reverse begin frame.end.val
              frame.parent_slot.val)
    (room : dirs.val.length + batchWork ceiling parents.val frame < 2147483647)
    (kept : preservesSlots original dirs) (available : RadixFree dirs free)
    (valid : RadixDirectoryInvariant dirs)
    (known : RadixKnowledge dirs (radixKeyOf rows.val))
    : WP.spec (CcfKv.radix.build_sorted_loop dirs free rows sorted parents frame)
        (fun (root, after, left) =>
          preservesSlots original after
          ∧ RadixFree after left
          ∧ RadixDirectoryInvariant after
          ∧ RadixKnowledge after (radixKeyOf rows.val)
          ∧ RadixTree after.val bindings.length root bindings
          ∧ after.val.length
            ≤ dirs.val.length + batchWork ceiling parents.val frame + 1) := by
  unfold CcfKv.radix.build_sorted_loop
  apply loop.spec_decr_nat
    (fun (_, _, ps, current) => batchWork ceiling ps.val current)
    (fun (arena, vacant, ps, current) =>
      preservesSlots original arena
      ∧ RadixFree arena vacant
      ∧ RadixDirectoryInvariant arena
      ∧ RadixKnowledge arena (radixKeyOf rows.val)
      ∧ arena.val.length + batchWork ceiling ps.val current
          ≤ dirs.val.length + batchWork ceiling parents.val frame
      ∧ ∃ begin,
          BatchFrameView arena.val bindings current begin current.cursor.val
          ∧ BatchSuspension arena.val bindings ps.val.reverse begin current.end.val
              current.parent_slot.val)
    _ _ _
  · rintro ⟨arena, vacant, ps, current⟩ ⟨retained, freeSlots, invariant, knowledge, capacity,
      begin, view, stack⟩
    dsimp only at retained freeSlots invariant knowledge capacity view stack ⊢
    unfold CcfKv.radix.build_sorted_loop.body
    have one : (1#usize : Usize).val = 1 := rfl
    by_cases finished : current.cursor = current.end
    · rw [ite_eq_left finished]
      have complete : BatchFrameView arena.val bindings current begin current.end.val := by
        rwa [← finished]
      apply WP.spec_bind
        (batch_publish_frame arena vacant rows bindings current begin
          complete ordered input.live invariant knowledge freeSlots (by omega))
      rintro ⟨root, after, left⟩ ⟨saved, validFree, growth, directories, prefixes, tree⟩
      have owner := stack.preserve saved
      have allKept : preservesSlots original after := fun j d h => saved j d (retained j d h)
      have emptyTest : alloc.vec.Vec.is_empty ps = .ok (decide (ps.val = [])) := by
        change Result.ok (decide (ps.val.length = 0)) = _
        exact congrArg Result.ok (decide_eq_decide.mpr List.length_eq_zero_iff)
      simp only [emptyTest, bind_ok, decide_eq_true_eq]
      change WP.spec (if ps.val = [] then Result.ok (ControlFlow.done (root, after, left))
        else do
          let i ← alloc.vec.Vec.len ps - 1#usize
          let parent ← alloc.vec.Vec.index
            (core.slice.index.SliceIndexUsizeSlice CcfKv.radix.BuildFrame) ps i
          let tail ← alloc.vec.Vec.resize CcfKv.radix.BuildFrame.Insts.CoreCloneClone ps i current
          let dir ← CcfKv.radix.RadixDir.set_child parent.dir current.parent_slot root
          Result.ok (ControlFlow.cont (after, left, tail, {parent with dir}))) _
      by_cases empty : ps.val = []
      · rw [ite_eq_left empty, WP.spec_ok]
        have rootStack : BatchSuspension after.val bindings [] begin current.end.val current.parent_slot.val := by
          simpa [empty] using owner
        obtain ⟨first, last⟩ := batch_top rootStack
        exact ⟨
          allKept,
          validFree,
          directories,
          prefixes,
          by simp [batchInterval, first, last] at tree; exact tree,
          Nat.le_trans growth
            (Nat.add_le_add_right (Nat.le_trans (Nat.le_add_right _ _) capacity) 1)
        ⟩
      · rw [ite_eq_right empty]
        obtain nil | ⟨rest, parent, split⟩ := List.eq_nil_or_concat ps.val
        · exact (empty nil).elim
        have frames : ps.val = rest ++ [parent] := by simpa using split
        have top : BatchSuspension after.val bindings (parent :: rest.reverse) begin current.end.val
            current.parent_slot.val := by
          simpa [frames, List.reverse_append] using owner
        obtain ⟨parentBegin, scope, parentView, group, resume, within, sameSlot, boundary⟩ :=
          batch_parent top
        have len : (alloc.vec.Vec.len ps).val = rest.length + 1 := by
          simp only [alloc.vec.Vec.len_val]
          change ps.val.length = rest.length + 1
          rw [frames, List.length_append, List.length_singleton]
        apply WP.spec_bind
          (Usize.sub_spec (x := alloc.vec.Vec.len ps) (y := 1#usize) (by omega))
        intro i moved
        have position : i.val = rest.length := by omega
        have inStack : i.val < ps.val.length := by simp [frames, position]
        rw [alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec ps i inStack)
        intro raw read
        have same : raw = parent := by
          have last : ps.val[i.val]? = some parent := by
            rw [position, frames, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]
            rfl
          rw [List.getElem?_eq_getElem inStack, ← read, Option.some.injEq] at last
          exact last
        rw [same]
        apply WP.spec_bind
          (alloc.vec.Vec.resize_spec CcfKv.radix.BuildFrame.Insts.CoreCloneClone ps i
            current rfl)
        intro tail resized
        have tailEq : tail.val = rest := by
          have shrunk : i.val ≤ ps.val.length := Nat.le_of_lt inStack
          rw [resized, List.resize, Nat.sub_eq_zero_of_le shrunk, List.replicate_zero, List.append_nil,
            frames, position, List.take_append_of_le_length (Nat.le_refl _), List.take_length]
          simp
        apply WP.spec_bind
          (batch_attach_child after.val bindings parent parentBegin begin current.end.val
            current.parent_slot parentView ordered group within sameSlot boundary root
            tree)
        intro dir ⟨digit, completed⟩
        rw [WP.spec_ok]
        dsimp only
        have delta := batch_work_pop ceiling rest parent current dir finished digit
        rw [← frames, ← tailEq] at delta
        refine ⟨
          ⟨allKept, validFree, directories, prefixes, by omega, parentBegin, ?_, ?_⟩,
          by omega
        ⟩
        · exact resume ▸ completed
        · exact tailEq.symm ▸ scope
    · rw [ite_eq_right finished]
      have endBound := view.toEnd
      have inGroup : current.cursor.val < current.end.val := by
        have ne : current.cursor.val ≠ current.end.val := fun h =>
          finished (UScalar.eq_of_val_eq h)
        omega
      have inside := inGroup.trans_le view.bound
      apply WP.spec_bind (batch_link_at rows sorted bindings input current.cursor inside)
      intro leaf ⟨leafLink, entry, tag, live, key⟩
      apply WP.spec_bind (radix_row_at_matches rows leaf entry tag live)
      intro value same
      subst value
      apply WP.spec_bind
        (radix_symbol_matches (alloc.vec.Vec.deref entry.key) current.dir.digit)
      intro slot found
      have correct : radixSymbol (batchKey bindings current.cursor.val) current.dir.digit.val = slot.val := by
        simpa [alloc.vec.Vec.deref, key] using found.symm
      have endFits : current.end.val ≤ Usize.max := by scalar_tac
      apply WP.spec_bind
        (sorted_group_end_refines rows sorted bindings input current.cursor
          current.end current.dir.digit slot inGroup view.bound endFits correct)
      intro next ⟨group, within, accepted, boundary⟩
      apply WP.spec_bind (Usize.add_spec (x := current.cursor) (y := 1#usize) (by omega))
      intro following step
      have follows : following.val = current.cursor.val + 1 := by omega
      by_cases single : next = following
      · rw [ite_eq_left single]
        have tree : RadixTree arena.val bindings.length leaf (batchInterval bindings current.cursor.val next.val) := by
          have n : next.val = current.cursor.val + 1 := by rw [single, follows]
          rw [n, batch_interval_single bindings current.cursor.val inside, leafLink]
          exact .leaf _ _ _ (by rw [← leafLink]; exact Nat.le_of_lt tag)
        apply WP.spec_bind (batch_attach_child arena.val bindings current begin current.cursor.val
          next.val slot view ordered group within accepted boundary leaf tree)
        intro dir ⟨digit, attached⟩
        rw [WP.spec_ok]
        dsimp only
        have smaller := batch_work_leaf ceiling ps.val current next dir ⟨group, within⟩ digit
        exact ⟨⟨retained, freeSlots, invariant, knowledge, by omega, begin,
          attached.withCursor next, stack⟩, smaller⟩
      · rw [ite_eq_right single]
        have two : current.cursor.val + 2 ≤ next.val := by
          have ne : next.val ≠ following.val := fun h => single (UScalar.eq_of_val_eq h)
          omega
        have fits : ps.val.length < Usize.max := by
          have h : ps.val.length ≤ batchWork ceiling ps.val current := by
            unfold batchWork
            omega
          have platform : 2147483647 ≤ Usize.max := by scalar_tac
          omega
        apply WP.spec_bind (alloc.vec.Vec.push_spec ps {current with cursor := next} fits)
        intro parents' pushed
        have bounds : next.val ≤ bindings.length := within.trans view.bound
        have distinct := batch_key_distinct bindings current.cursor.val (next.val - 1) ordered
          (by omega) (by omega)
        apply WP.spec_bind (batch_fresh_frame arena.val rows sorted bindings input current.cursor next
          slot two bounds distinct (batch_key_room bindings _ _ inside keyRoom))
        intro child ⟨atStart, atEnd, parentSlot, childView⟩
        rw [WP.spec_ok]
        dsimp only
        have refined := childView.split
        rw [atEnd] at refined
        have whole := view.span
        have below := batch_split_limit bindings current.cursor.val next.val child.dir.digit.val
          ceiling group bounds bounded refined
        have nested := batch_nested_split bindings begin current.end.val current.dir.digit.val
          current.cursor.val (next.val - 1) child.dir.digit.val slot.val ordered (by omega)
          view.bound view.split view.fromBegin (by omega) (by omega) correct
          (accepted (next.val - 1) (by omega) (by omega)) refined
        have smaller := batch_work_child ceiling ps.val current child next ⟨group, within⟩
          atStart atEnd nested (Nat.le_of_lt below)
        rw [← pushed] at smaller
        have suspended : BatchSuspension arena.val bindings parents'.val.reverse
            current.cursor.val child.end.val child.parent_slot.val := by
          rw [pushed, List.reverse_append, atEnd, parentSlot]
          exact .pending {current with cursor := next} ps.val.reverse begin current.cursor.val
            slot.val stack (view.withCursor next) group within accepted boundary
        refine ⟨⟨retained, freeSlots, invariant, knowledge, by omega, current.cursor.val, ?_,
          suspended⟩, smaller⟩
        rwa [atStart]
  · exact ⟨kept, available, valid, known, Nat.le_refl _, ready⟩

/-- The extracted sorted builder constructs precisely the supplied live
bindings without changing the directories reachable from prior roots.
The numerical bound reserves room for the explicit-stack schedule and its
directory allocations. -/
theorem build_sorted_refines {V : Type}
    (dirs : alloc.vec.Vec (Option CcfKv.radix.RadixDir)) (free : alloc.vec.Vec Usize)
    (rows : Slice (Option (CcfKv.radix.RadixRow V))) (sorted : Slice U32)
    (bindings : List (List U8 × U32)) (input : BatchLeaves rows sorted bindings)
    (ordered : bindings.Pairwise radixKeyLt) (ceiling : Nat)
    (bounded : ∀ entry ∈ bindings, 2 * entry.1.length ≤ ceiling)
    (keyRoom : ∀ entry ∈ bindings, 2 * entry.1.length + 1 ≤ Usize.max)
    (room : dirs.val.length + 2 * (bindings.length * (ceiling + 1)) < 2147483647)
    (available : RadixFree dirs free) (valid : RadixDirectoryInvariant dirs)
    (known : RadixKnowledge dirs (radixKeyOf rows.val))
    : WP.spec (CcfKv.radix.build_sorted dirs free rows sorted)
        (fun (root, after, left) =>
          preservesSlots dirs after
          ∧ RadixFree after left
          ∧ RadixDirectoryInvariant after
          ∧ RadixKnowledge after (radixKeyOf rows.val)
          ∧ RadixTree after.val bindings.length root bindings
          ∧ after.val.length
            ≤ dirs.val.length + 2 * (bindings.length * (ceiling + 1)) + 1) := by
  unfold CcfKv.radix.build_sorted
  let past := Slice.len sorted
  have size : past.val = bindings.length := by
    change (Slice.len sorted).val = bindings.length
    rw [Slice.len_val]
    change sorted.val.length = bindings.length
    rw [input.links, List.length_map]
  have zero : (0#usize : Usize).val = 0 := rfl
  have one : (1#usize : Usize).val = 1 := rfl
  have keep : preservesSlots dirs dirs := fun _ _ h => h
  by_cases empty : past = 0#usize
  · rw [ite_eq_left empty, WP.spec_ok]
    have none : bindings = [] := by apply List.length_eq_zero_iff.mp; rw [← size, empty, zero]
    exact ⟨keep, available, valid, known, by rw [none]; exact .empty _, by omega⟩
  · rw [ite_eq_right empty]
    by_cases single : past = 1#usize
    · rw [ite_eq_left single]
      have count : bindings.length = 1 := by rw [← size, single, one]
      cases bindings with
      | nil => simp at count
      | cons entry rest =>
          have tail : rest = [] := by simpa using count
          subst rest
          apply WP.spec_bind (batch_link_at rows sorted [entry] input 0#usize (by simp))
          intro link ⟨same, row, tag, _, _⟩
          rw [WP.spec_ok]
          refine ⟨keep, available, valid, known, ?_, by omega⟩
          change link = entry.2 at same
          rw [same]
          exact .leaf _ _ _ (by rw [← same]; exact Nat.le_of_lt tag)
    · rw [ite_eq_right single]
      have nonzero : past.val ≠ 0 := fun eq => empty (UScalar.eq_of_val_eq eq)
      have multiple : past.val ≠ 1 := fun eq => single (UScalar.eq_of_val_eq eq)
      have span : 2 ≤ past.val := by omega
      have different := batch_key_distinct bindings 0 (past.val - 1) ordered (by omega) (by omega)
      apply WP.spec_bind (batch_fresh_frame dirs.val rows sorted bindings input 0#usize past 0#usize
        (by omega) (by omega) different (batch_key_room bindings _ _ (by omega) keyRoom))
      intro frame ⟨start, last, _, current⟩
      let stack := alloc.vec.Vec.new CcfKv.radix.BuildFrame
      have ready : ∃ begin, BatchFrameView dirs.val bindings frame begin frame.cursor.val
          ∧ BatchSuspension dirs.val bindings stack.val.reverse begin frame.end.val frame.parent_slot.val := by
        refine ⟨0, ?_, ?_⟩
        · simpa only [start, zero] using current
        · rw [last, size]
          exact .top
      have workLe : batchWork ceiling stack.val frame ≤ 2 * (bindings.length * (ceiling + 1)) := by
        have scale := Nat.mul_le_mul_left bindings.length
          (show ceiling - frame.dir.digit.val + 1 ≤ ceiling + 1 by omega)
        have emptyStack : stack.val = [] := rfl
        simp only [batchWork, frameWork, emptyStack, List.map_nil, List.sum_nil, List.length_nil,
          Nat.zero_add, Nat.add_zero, start, last, size, zero, Nat.sub_zero]
        change 2 * (bindings.length * (ceiling - frame.dir.digit.val + 1)) ≤ _
        omega
      have space : dirs.val.length + batchWork ceiling stack.val frame < 2147483647 := by omega
      apply WP.spec_mono
        (build_sorted_loop_refines dirs dirs free rows sorted bindings input ordered ceiling
          bounded keyRoom stack frame ready space keep available valid known)
      rintro ⟨root, after, left⟩ ⟨h1, h2, h3, h4, h5, hlen⟩
      exact ⟨h1, h2, h3, h4, h5, by omega⟩

end KvRust
