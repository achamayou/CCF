-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties
public import KvRust.Assoc

@[expose] public section

namespace KvRust

open Kv.Model Kv.Properties

theorem lookup_eq_some_iff_mem {K V : Type} [DecidableEq K]
    (rows : Assoc K V) (unique : Unique rows) (key : K) (value : V)
    : find rows key = some value ↔ (key, value) ∈ rows := by
  induction rows with
  | nil => simp [find]
  | cons row rest ih =>
      obtain ⟨k, v⟩ := row
      obtain ⟨absent, tail⟩ := List.nodup_cons.mp unique
      by_cases same : k = key
      · subst k
        have missing : (key, value) ∉ rest :=
          fun hm => absent (List.mem_map.mpr ⟨(key, value), hm, rfl⟩)
        simp [find, missing, eq_comm]
      · have diff : (key, value) ≠ (k, v) := fun h => same (congrArg Prod.fst h).symm
        simpa [find, same, diff] using ih tail

theorem entry_eq_of_unique_key {K V : Type} [DecidableEq K] {rows : Assoc K V}
    (unique : Unique rows) {a b : K × V} (ha : a ∈ rows) (hb : b ∈ rows)
    (same : a.1 = b.1)
    : a = b := by
  obtain ⟨ka, va⟩ := a
  obtain ⟨kb, vb⟩ := b
  dsimp only at same
  subst kb
  have left := (lookup_eq_some_iff_mem rows unique ka va).mpr ha
  have right := (lookup_eq_some_iff_mem rows unique ka vb).mpr hb
  rw [left] at right
  rw [Option.some.inj right]

theorem unique_of_perm {K V : Type} {a b : Assoc K V} (perm : a.Perm b)
    (unique : Unique a)
    : Unique b :=
  (perm.map Prod.fst).nodup_iff.mp unique

theorem lookup_perm {K V : Type} [DecidableEq K] {a b : Assoc K V} (perm : a.Perm b)
    (unique : Unique a) (key : K)
    : find a key = find b key := by
  have other := unique_of_perm perm unique
  have member (value : V) : find a key = some value ↔ find b key = some value :=
    (lookup_eq_some_iff_mem a unique key value).trans
      (perm.mem_iff.trans (lookup_eq_some_iff_mem b other key value).symm)
  cases found : find a key with
  | some value => exact (member value).mp found |>.symm
  | none =>
      cases hb : find b key with
      | none => rfl
      | some value => simp [found] at member; exact (member value hb).elim

theorem perm_of_lookup {K V : Type} [DecidableEq K] {a b : Assoc K V}
    (ha : Unique a) (hb : Unique b) (same : ∀ key, find a key = find b key)
    : a.Perm b := by
  apply (List.perm_ext_iff_of_nodup (ha.of_map Prod.fst) (hb.of_map Prod.fst)).mpr
  rintro ⟨key, value⟩
  rw [← lookup_eq_some_iff_mem a ha, ← lookup_eq_some_iff_mem b hb, same]

theorem set_perm {K V : Type} [DecidableEq K] {a b : Assoc K V}
    (h : a.Perm b) (key : K) (value : V)
    : (Kv.Model.set a key value).Perm (Kv.Model.set b key value) :=
  (h.filter _).cons _

private theorem unique_erase {K V : Type} [DecidableEq K] (rows : Assoc K V) (key : K)
    (unique : Unique rows)
    : Unique (erase rows key) :=
  (List.filter_sublist.map Prod.fst).nodup unique

private theorem unique_set {K V : Type} [DecidableEq K] (rows : Assoc K V) (key : K)
    (value : V) (unique : Unique rows)
    : Unique (Kv.Model.set rows key value) := by
  apply List.nodup_cons.mpr
  refine ⟨?_, unique_erase rows key unique⟩
  intro present
  obtain ⟨row, member, same⟩ := List.mem_map.mp present
  exact (bne_iff_ne.mp (List.mem_filter.mp member).2) same

/-- Publishing a permutation preserves the complete versioned bindings, not only values. -/
theorem publication_perm {M K V : Type} [DecidableEq M] [DecidableEq K] {a b : DB M K V}
    {xs ys : Writes M K V} (version : Nat) (same : a.Perm b) (writes : xs.Perm ys)
    (baseUnique : Unique a) (writesUnique : Unique xs)
    : (publish a version xs).Perm (publish b version ys) := by
  apply perm_of_lookup (Kv.Properties.publish_unique a version xs baseUnique)
    (Kv.Properties.publish_unique b version ys (unique_of_perm same baseUnique))
  intro key
  rw [Kv.Properties.publish_lookup, Kv.Properties.publish_lookup, lookup_perm same baseUnique,
    lookup_perm writes writesUnique]

/-- Relate complete committed frames without requiring their tables to use
the same association-list order. Metadata still compares exactly by map. -/
structure FrameOrderEq (a b : Frame) : Prop where
  version : a.version = b.version
  data : a.data.Perm b.data
  revisions : ∀ map, find a.revisions map = find b.revisions map
  births : ∀ map, find a.births map = find b.births map

private def mapRows {M K V : Type} [DecidableEq M] (rows : Assoc (Addr M K) V) (m : M)
    : Assoc K V :=
  rows.filterMap fun (a, v) => if a.1 = m then some (a.2, v) else none

private theorem unique_map_rows {M K V : Type} [DecidableEq M]
    (rows : Assoc (Addr M K) V) (m : M) (unique : Unique rows)
    : Unique (mapRows rows m) := by
  induction rows with
  | nil => simp [Kv.Properties.Unique, mapRows]
  | cons row rest ih =>
      obtain ⟨⟨table, key⟩, value⟩ := row
      obtain ⟨absent, tail⟩ := List.nodup_cons.mp unique
      by_cases same : table = m
      · subst table
        simp only [Kv.Properties.Unique, mapRows, List.filterMap_cons, ite_true, List.map_cons,
          List.nodup_cons]
        refine ⟨?_, ih tail⟩
        intro present
        obtain ⟨⟨k, v⟩, hm, hk⟩ := List.mem_map.mp present
        dsimp only at hk
        subst k
        obtain ⟨⟨⟨table, k⟩, original⟩, old, found⟩ := List.mem_filterMap.mp hm
        by_cases onMap : table = m
        · subst table
          simp at found
          obtain ⟨rfl, _⟩ := found
          exact absent (List.mem_map.mpr ⟨_, old, rfl⟩)
        · simp [onMap] at found
      · simpa only [Kv.Properties.Unique, mapRows, List.filterMap_cons, same, ite_false]
          using ih tail

/-- Filtering a database by map preserves unique keys within that map. -/
theorem unique_image {M K V : Type} [DecidableEq M] (db : DB M K V) (m : M)
    (unique : Unique db)
    : Unique (image db m) :=
  unique_map_rows db m unique

private theorem values_unique {K V : Type} [DecidableEq K] (base : Assoc K V)
    (writes : Assoc K (Option V)) (unique : Unique base)
    : Unique (writeValues base writes) := by
  induction writes with
  | nil => exact unique
  | cons row rest ih =>
      obtain ⟨key, value⟩ := row
      cases value with
      | none => exact unique_erase _ key ih
      | some value => exact unique_set _ key value ih

private theorem values_lookup {K V : Type} [DecidableEq K] (base : Assoc K V)
    (writes : Assoc K (Option V)) (key : K)
    : find (writeValues base writes) key = (find writes key).getD (find base key) := by
  induction writes with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨k, value⟩ := row
      cases value with
      | none =>
          change find (erase (writeValues base rest) k) key =
            (find ((k, none) :: rest) key).getD (find base key)
          rw [find_erase_key, ih]
          by_cases same : key = k <;> simp [find, same, eq_comm]
      | some value =>
          change find (Kv.Model.set (writeValues base rest) k value) key =
            (find ((k, some value) :: rest) key).getD (find base key)
          rw [find_set_key, ih]
          by_cases same : key = k <;> simp [find, same, eq_comm]

/-- Staging cannot introduce duplicate keys into a scan of a unique image. -/
theorem unique_scan {M K V : Type} [DecidableEq M] [DecidableEq K]
    (db : DB M K V) (writes : Writes M K V) (m : M) (unique : Unique (image db m))
    : Unique (scanAt db writes m) := by
  apply values_unique
  unfold Kv.Properties.Unique
  rw [List.map_map]
  change ((image db m).map Prod.fst).Nodup
  exact unique

theorem scan_perm {M K V : Type} [DecidableEq M] [DecidableEq K]
    {a b : DB M K V} {xs ys : Writes M K V} (m : M)
    (same : (image a m).Perm (image b m)) (writes : xs.Perm ys)
    (baseUnique : Unique (image a m)) (writesUnique : Unique xs)
    : (scanAt a xs m).Perm (scanAt b ys m) := by
  apply perm_of_lookup (unique_scan a xs m baseUnique)
    (unique_scan b ys m (unique_of_perm same baseUnique))
  intro key
  let project : K × Cell V → K × V := fun (k, cell) => (k, cell.value)
  have base : ((image a m).map project).Perm ((image b m).map project) := same.map _
  have unique : Unique ((image a m).map project) := by
    unfold Kv.Properties.Unique
    rw [List.map_map]
    change ((image a m).map Prod.fst).Nodup
    exact baseUnique
  have filtered : (mapRows xs m).Perm (mapRows ys m) := writes.filterMap _
  change find (writeValues ((image a m).map project) (mapRows xs m)) key =
    find (writeValues ((image b m).map project) (mapRows ys m)) key
  rw [values_lookup, values_lookup,
    show find (mapRows xs m) key = find (mapRows ys m) key from
      lookup_perm filtered (unique_map_rows xs m writesUnique) key,
    lookup_perm base unique]

def removeEntry (m : String) (ws : Pending) (row : String × String) : Pending :=
  Kv.Model.set ws (m, row.1) none

private theorem removal_lookup (m : String) (entries : Assoc String String)
    (writes : Pending) (key : Addr String String)
    : find (entries.foldl (removeEntry m) writes) key
      = if entries.any (fun row => decide (key = (m, row.1))) then
          some none
        else
          find writes key := by
  induction entries generalizing writes with
  | nil => rfl
  | cons row rest ih =>
      simp only [List.foldl_cons, List.any_cons]
      rw [ih, removeEntry, find_set_key]
      change (if rest.any (fun r => decide (key = (m, r.1))) then some none
        else if key = (m, row.1) then some none else find writes key) =
        (if decide (key = (m, row.1)) || rest.any (fun r => decide (key = (m, r.1))) then some none
          else find writes key)
      by_cases same : key = (m, row.1) <;>
        cases rest.any (fun r => decide (key = (m, r.1))) <;> simp [same]

private theorem removal_unique (m : String) (entries : Assoc String String)
    (writes : Pending) (unique : Unique writes)
    : Unique (entries.foldl (removeEntry m) writes) := by
  induction entries generalizing writes with
  | nil => exact unique
  | cons row rest ih => exact ih _ (unique_set writes (m, row.1) none unique)

theorem clear_entries_perm (m : String) {a b : Assoc String String} {x y : Pending}
    (visible : a.Perm b) (writes : x.Perm y) (unique : Unique x)
    : (a.foldl (removeEntry m) x).Perm (b.foldl (removeEntry m) y) := by
  apply perm_of_lookup (removal_unique m a x unique)
    (removal_unique m b y (unique_of_perm writes unique))
  intro key
  rw [removal_lookup, removal_lookup, visible.any_eq, lookup_perm writes unique]

/-- Point dependencies agree exactly; whole-map dependencies retain both the
value and previous-write version of every cell, but not their order. -/
inductive DependencyOrderEq {M K V : Type} : Dependency M K V → Dependency M K V → Prop
  | key (address : Addr M K) (expected : Option (Cell V))
    : DependencyOrderEq (.key address expected) (.key address expected)
  | map (table : M) {a b : Assoc K (Cell V)} (perm : a.Perm b)
    : DependencyOrderEq (.map table a) (.map table b)

/-- The permutation-based dependency predicate used by the relaxed contract. -/
def holdsByContents {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V)
    : Dependency M K V → Bool
  | .key address expected => decide (find db address = expected)
  | .map table expected => decide ((image db table).Perm expected)

theorem dependency_order_eq {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]
    {a b : DB M K V} {x y : Dependency M K V}
    (base : a.Perm b) (unique : Unique a) (deps : DependencyOrderEq x y)
    : holdsByContents a x = holdsByContents b y := by
  cases deps with
  | key address expected => simp only [holdsByContents, lookup_perm base unique]
  | map table same =>
      have imagePerm : (image a table).Perm (image b table) := base.filterMap _
      simp only [holdsByContents]
      apply decide_eq_decide.mpr
      exact ⟨fun h => imagePerm.symm.trans (h.trans same), fun h => imagePerm.trans (h.trans same.symm)⟩

private def rowsBefore (db : Data) (cut : Nat) : Data :=
  db.filter (fun row => decide (row.2.version ≤ cut))

private theorem old_rows_publish (db : Data) (writes : Pending) (cut version : Nat)
    (newer : cut < version)
    : (rowsBefore (publish db version writes) cut).Sublist (rowsBefore db cut) := by
  have erase_sublist (rows : Data) (key : Addr String String) :
      (rowsBefore (erase rows key) cut).Sublist (rowsBefore rows cut) :=
    List.filter_sublist.filter _
  induction writes with
  | nil => exact List.Sublist.refl _
  | cons row rest ih =>
      obtain ⟨key, value⟩ := row
      cases value with
      | none => exact (erase_sublist (publish db version rest) key).trans ih
      | some value =>
          change (rowsBefore (Kv.Model.set (publish db version rest) key {value, version}) cut).Sublist _
          simpa [rowsBefore, Kv.Model.set, Nat.not_le_of_lt newer]
            using (erase_sublist (publish db version rest) key).trans ih

private theorem history_member_version {frames : List Frame} {latest : Nat}
    (shape : Kv.Properties.History frames latest) (frame : Frame)
    (member : frame ∈ frames)
    : frame.version ≤ latest := by
  induction shape with
  | zero =>
      rw [List.mem_singleton.mp member]
  | succ f n fs version _ _ ih =>
      rcases List.mem_cons.mp member with rfl | old
      · exact Nat.le_of_eq version
      · exact Nat.le_trans (ih old) (Nat.le_succ n)

private theorem history_head_present {frames : List Frame} {latest : Nat}
    (shape : Kv.Properties.History frames latest)
    : frames.head?.getD {} ∈ frames ∧ (frames.head?.getD {}).version = latest := by
  cases shape with
  | zero => simp
  | succ f n fs version _ _ => simp [version]

private theorem history_old_rows_ordered {frames : List Frame} {latest : Nat}
    (shape : Kv.Properties.History frames latest) (old current : Frame)
    (older : old ∈ frames) (newer : current ∈ frames)
    (ordered : old.version ≤ current.version)
    : (rowsBefore current.data old.version).Sublist
        (rowsBefore old.data old.version) := by
  induction shape generalizing old current with
  | zero =>
      obtain rfl := List.mem_singleton.mp older
      obtain rfl := List.mem_singleton.mp newer
      exact List.Sublist.refl _
  | succ head n rest version publication tail ih =>
      rcases List.mem_cons.mp newer with rfl | newTail
      · rcases List.mem_cons.mp older with rfl | oldTail
        · exact List.Sublist.refl _
        · obtain ⟨previous, previousVersion⟩ := history_head_present tail
          have oldVersion := history_member_version tail old oldTail
          obtain ⟨writes, applied⟩ := publication
          rw [applied]
          exact (old_rows_publish _ writes old.version (n + 1) (by omega)).trans
            (ih _ _ oldTail previous (by omega))
      · rcases List.mem_cons.mp older with rfl | oldTail
        · have limited := history_member_version tail current newTail
          omega
        · exact ih _ _ oldTail newTail ordered

private theorem image_rows_before (db : Data) (m : String) (cut : Nat)
    : image (rowsBefore db cut) m
      = (image db m).filter (fun row => decide (row.2.version ≤ cut)) := by
  induction db with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨⟨table, key⟩, cell⟩ := row
      by_cases here : table = m <;> by_cases prior : cell.version ≤ cut <;>
        simp [image, rowsBefore, here, prior] at ih ⊢ <;> exact ih

/-- In a single ordinary publication history, two cuts with the same versioned
map contents also have the same ordering of those cells. This does not apply
to imported or independently constructed histories. -/
theorem same_branch_image_order {frames : List Frame} {latest : Nat}
    (shape : Kv.Properties.History frames latest) (old current : Frame)
    (older : old ∈ frames) (newer : current ∈ frames)
    (ordered : old.version ≤ current.version) (m : String)
    (same : (image old.data m).Perm (image current.data m))
    (bounded : ∀ row ∈ image old.data m, row.2.version ≤ old.version)
    : image old.data m = image current.data m := by
  have sub := (history_old_rows_ordered shape old current older newer ordered).filterMap
    (fun (a, v) => if a.1 = m then some (a.2, v) else none)
  change (image (rowsBefore current.data old.version) m).Sublist
    (image (rowsBefore old.data old.version) m) at sub
  rw [image_rows_before, image_rows_before] at sub
  have keepOld : (image old.data m).filter (fun row => decide (row.2.version ≤ old.version)) =
      image old.data m :=
    List.filter_eq_self.mpr fun row present => decide_eq_true (bounded row present)
  have keepCurrent : (image current.data m).filter (fun row => decide (row.2.version ≤ old.version)) =
      image current.data m :=
    List.filter_eq_self.mpr fun row present => decide_eq_true (bounded row (same.symm.subset present))
  rw [keepCurrent, keepOld] at sub
  exact (sub.eq_of_length same.length_eq.symm).symm

/-- An ordinary whole-map dependency names the contents of a surviving cut.
Point dependencies need no such witness because their check does not use order. -/
def DependencyHasOrigin (frames : List Frame) (current : Frame)
    : Dependency String String String → Prop
  | .key _ _ => True
  | .map m expected =>
      ∃ old ∈ frames,
        old.version ≤ current.version
        ∧ expected = image old.data m
        ∧ ∀ row ∈ expected, row.2.version ≤ old.version

private theorem holds_in_history {frames : List Frame} {latest : Nat}
    (shape : Kv.Properties.History frames latest) (current : Frame)
    (present : current ∈ frames) (dependency : Dependency String String String)
    (origin : DependencyHasOrigin frames current dependency)
    : dependency.holds current.data = holdsByContents current.data dependency := by
  cases dependency with
  | key address expected => rfl
  | map table expected =>
      obtain ⟨old, older, atMost, exactImage, bounded⟩ := origin
      subst expected
      simp only [Dependency.holds, holdsByContents]
      apply decide_eq_decide.mpr
      exact ⟨fun eq => eq ▸ .rfl, fun perm =>
        (same_branch_image_order shape old current older present atMost table perm.symm bounded).symm⟩

/-- Ordinary OCC can use the existing ordered comparison as an implementation
of content equality, without sorting or changing the committed-version check. -/
theorem validates_by_contents {frames : List Frame} {latest : Nat}
    (shape : Kv.Properties.History frames latest) (current model : Frame)
    (present : current ∈ frames) (same : FrameOrderEq current model)
    (unique : Unique current.data)
    {a b : List (Dependency String String String)}
    (related : List.Forall₂ DependencyOrderEq a b)
    (origins : ∀ dep ∈ a, DependencyHasOrigin frames current dep)
    : validates current.data a = b.all (holdsByContents model.data) := by
  induction related with
  | nil => rfl
  | @cons x y xs ys dep rest ih =>
      have h := holds_in_history shape current present x (origins x List.mem_cons_self)
      simp only [validates, List.all_cons] at ih ⊢
      rw [h, dependency_order_eq same.data unique dep,
        ih (fun d hd => origins d (List.mem_cons_of_mem _ hd))]

theorem mergeSort_keys_ordered (rows : Assoc String String)
    : (rows.mergeSort (fun a b => decide (a.1 ≤ b.1))).Pairwise
        (fun a b => a.1 ≤ b.1) := by
  apply List.Pairwise.imp (R := fun (a b : String × String) => decide (a.1 ≤ b.1) = true)
    of_decide_eq_true
  apply List.pairwise_mergeSort
  · intro a b c ab bc
    exact decide_eq_true (_root_.Std.le_trans (of_decide_eq_true ab) (of_decide_eq_true bc))
  · intro a b
    rcases _root_.Std.le_total (a := a.1) (b := b.1) with h | h <;> simp [h]

/-- Explicitly byte-sorted observations still compare in exact order. -/
theorem sorted_range_eq {a b : Assoc String String} (perm : a.Perm b) (unique : Unique a)
    (lower upper : Option String)
    : let cmp : (String × String) → (String × String) → Bool :=
        fun a b => decide (a.1 ≤ b.1)
      ((a.filter (fun row => inRange lower upper row.1)).mergeSort cmp)
      = ((b.filter (fun row => inRange lower upper row.1)).mergeSort cmp) := by
  dsimp only
  let lhs := a.filter (fun row => inRange lower upper row.1)
  let rhs := b.filter (fun row => inRange lower upper row.1)
  let cmp : (String × String) → (String × String) → Bool := fun a b => decide (a.1 ≤ b.1)
  have hp := (List.mergeSort_perm lhs cmp).trans
    ((perm.filter _).trans (List.mergeSort_perm rhs cmp).symm)
  apply List.Perm.eq_of_pairwise _ (mergeSort_keys_ordered lhs) (mergeSort_keys_ordered rhs) hp
  intro left right hl hr ab ba
  exact entry_eq_of_unique_key unique
    (List.mem_of_mem_filter ((List.mergeSort_perm lhs cmp).subset hl))
    (perm.symm.subset (List.mem_of_mem_filter ((List.mergeSort_perm rhs cmp).subset hr)))
    (_root_.Std.le_antisymm ab ba)

end KvRust
