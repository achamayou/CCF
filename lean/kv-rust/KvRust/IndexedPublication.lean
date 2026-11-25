-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.IndexedImage

@[expose] public section

namespace KvRust

open Aeneas.Std

local instance : DecidableEq Spike.engine.Address :=
  fun a b => decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

abbrev IndexWrite := Spike.engine.Address × Spike.engine.Write

def applyIndexedWrite (version : U64) (row : IndexWrite) (data : CellRows) : CellRows :=
  match row.2 with
  | .Put value => Kv.Model.set data row.1 {value, version}
  | .Remove => Kv.Model.erase data row.1

def indexedCellData (rows : CellRows) : Kv.Model.DB (List U8) (List U8) (List U8) :=
  rows.map fun (a, c) => (byteAddr a, byteCell c)

theorem indexed_fold_projects (rows : CellRows) (writes : List IndexWrite) (version : U64)
    : indexedCellData (writes.foldr (applyIndexedWrite version) rows)
      = Kv.Model.publish (indexedCellData rows) version.val (byteWrites writes) := by
  induction writes with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨a, w⟩ := row
      cases w with
      | Put value =>
          change _ = Kv.Model.set (Kv.Model.publish (indexedCellData rows) version.val
            (byteWrites rest)) (byteAddr a) (byteCell {value, version})
          rw [← ih]
          exact (set_projected _ a {value, version} byteAddr byteCell
            (fun _ _ h => byteAddr_inj h)).symm
      | Remove =>
          change _ = Kv.Model.erase (Kv.Model.publish (indexedCellData rows) version.val
            (byteWrites rest)) (byteAddr a)
          rw [← ih]
          exact (erase_projected _ a byteAddr byteCell (fun _ _ h => byteAddr_inj h)).symm

abbrev CellIndex := Spike.kv_index.AddressIndex Spike.engine.Cell

def IndexKeyRoom (row : IndexWrite) : Prop :=
  2 * (8 + row.1.map.val.length + row.1.key.val.length) + 1 ≤ Usize.max

private def untouchedCells (writes : List IndexWrite) (data : CellRows) : CellRows :=
  writes.foldr (fun row rest => Kv.Model.erase rest row.1) data

private theorem indexed_fold_suffix (rows : CellRows) (writes : List IndexWrite)
    (version : U64)
    : writes.foldr (applyIndexedWrite version) rows
      = writes.foldr (applyIndexedWrite version) [] ++ untouchedCells writes rows := by
  induction writes with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨addr, write⟩ := row
      cases write <;>
        simp only [List.foldr_cons, applyIndexedWrite, ih, untouchedCells,
          Kv.Model.set, Kv.Model.erase, List.filter_append, List.cons_append]

private theorem untouched_cells_spec (writes : List IndexWrite) (rows : CellRows)
    (entry : Spike.engine.Address × Spike.engine.Cell)
    (member : entry ∈ untouchedCells writes rows)
    : entry ∈ rows ∧ entry.1 ∉ writes.map Prod.fst := by
  induction writes with
  | nil => exact ⟨member, List.not_mem_nil⟩
  | cons row rest ih =>
      obtain ⟨kept, different⟩ := List.mem_filter.mp member
      obtain ⟨before, notWritten⟩ := ih kept
      have ne : entry.1 ≠ row.1 := bne_iff_ne.mp different
      exact ⟨before, by simpa [List.mem_cons, ne] using notWritten⟩

theorem indexed_fold_cover (rows : CellRows) (writes : List IndexWrite) (version : U64)
    (covers : ∀ entry ∈ rows, entry.1 ∈ writes.map Prod.fst)
    : writes.foldr (applyIndexedWrite version) rows
      = writes.foldr (applyIndexedWrite version) [] := by
  have cleared : untouchedCells writes rows = [] := by
    cases h : untouchedCells writes rows with
    | nil => rfl
    | cons entry rest =>
        have hm : entry ∈ untouchedCells writes rows := h.symm ▸ List.mem_cons_self
        have ⟨old, absent⟩ := untouched_cells_spec writes rows entry hm
        exact (absent (covers entry old)).elim
  simp [indexed_fold_suffix rows writes version, cleared]

/-- Conservative headroom for every edit in the batch on the single-radix arena. -/
structure IndexBatchRoom (index : CellIndex) (peak writes : Nat) : Prop where
  lookup : index.values.dirs.val.length + writes * (peak + 1) ≤ 2147483647
  values : index.values.rows.val.length + writes ≤ 2147483647

theorem IndexBatchRoom.shrink {index : CellIndex} {peak smaller writes : Nat}
    (room : IndexBatchRoom index peak writes) (fits : smaller ≤ peak)
    : IndexBatchRoom index smaller writes := by
  refine ⟨?_, room.values⟩
  have bound := Nat.mul_le_mul_left writes (show smaller + 1 ≤ peak + 1 by omega)
  have total := room.lookup
  omega

private theorem applyIndexedWrite_perm (version : U64) (row : IndexWrite)
    {a b : CellRows} (perm : a.Perm b)
    : (applyIndexedWrite version row a).Perm (applyIndexedWrite version row b) := by
  obtain ⟨addr, w⟩ := row
  cases w with
  | Put val => exact (perm.filter _).cons (addr, {value := val, version})
  | Remove => exact perm.filter _

private theorem indexed_fold_perm (version : U64) (writes : List IndexWrite)
    {a b : CellRows} (perm : a.Perm b)
    : (writes.foldr (applyIndexedWrite version) a).Perm
        (writes.foldr (applyIndexedWrite version) b) := by
  induction writes with
  | nil => exact perm
  | cons row rest ih => exact applyIndexedWrite_perm version row ih

private def Covers (rows : CellRows) (pending : List IndexWrite) : Prop :=
  ∀ entry ∈ rows, entry.1 ∈ pending.map Prod.fst

private theorem publication_compare (index : CellIndex) (root : Spike.radix.RadixRoot)
    (rows : CellRows) (pending : alloc.vec.Vec IndexWrite)
    (count : Usize) (links : alloc.vec.Vec U32)
    (rowsSize : rows.length = count.val) (pendingSize : pending.val.length = count.val)
    (linksSize : links.val.length = count.val)
    (load
      : ∀ (i : Nat) link,
          links.val[i]? = some link
          → ∃ entry,
              rows[i]? = some entry
              ∧ WP.spec (Spike.kv_index.AddressIndex.scan_row index link) (· = entry))
    : WP.spec (Spike.engine.publication_base_loop index root pending count links 0#usize)
        (fun base =>
          base = root ∨ (IndexView index base [] ∧ Covers rows pending.val)) := by
  unfold Spike.engine.publication_base_loop
  apply loop.spec_decr_nat (fun (i : Usize) => count.val - i.val)
    (fun i => ∀ j, j < i.val →
      rows[j]?.map Prod.fst = pending.val[count.val - 1 - j]?.map Prod.fst)
    _ _ _
  · intro i same
    unfold Spike.engine.publication_base_loop.body
    by_cases run : i < count
    · have h : i.val < count.val := run
      have inside : i.val < links.val.length := by omega
      have one : (1#usize : Usize).val = 1 := rfl
      rw [ite_eq_left run, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec links i inside)
      intro leaf read
      obtain ⟨entry, loaded, get⟩ := load i.val leaf
        ((List.getElem?_eq_getElem inside).trans (congrArg some read.symm))
      apply WP.spec_bind get
      rintro ⟨address, cell⟩ eq
      subst entry
      change WP.spec (do
        let i1 ← count - 1#usize
        let i2 ← i1 - i
        let row ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice IndexWrite) pending i2
        let agrees ← Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey.same address row.1
        if agrees then
          let j ← i + 1#usize
          Result.ok (ControlFlow.cont j)
        else Result.ok (ControlFlow.done root)) _
      apply WP.spec_bind (Usize.sub_spec (x := count) (y := 1#usize) (by omega))
      intro c1 hc1
      apply WP.spec_bind (Usize.sub_spec (x := c1) (y := i) (by omega))
      intro revIdx hrevIdx
      have hrevVal : revIdx.val = count.val - 1 - i.val := by omega
      have staged : revIdx.val < pending.val.length := by omega
      rw [alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending revIdx staged)
      intro write saved
      have incoming : pending.val[count.val - 1 - i.val]? = some write := by
        rw [← hrevVal, List.getElem?_eq_getElem staged, ← saved]
      simp only [compare_address, bind_ok, decide_eq_true_eq]
      by_cases equal : address = write.1
      · rw [ite_eq_left equal]
        have room : count.val ≤ Usize.max := by scalar_tac
        apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
        intro j advance
        rw [WP.spec_ok]
        refine ⟨?_, by omega⟩
        intro n earlier
        by_cases earlierThan : n < i.val
        · exact same n earlierThan
        · have atEnd : n = i.val := by omega
          rw [atEnd, loaded, incoming]
          simp [equal]
      · rw [ite_eq_right equal, WP.spec_ok]
        exact Or.inl rfl
    · rw [ite_eq_right run]
      apply WP.spec_bind (index_empty_root_refines index)
      intro fresh empty
      rw [WP.spec_ok]
      refine Or.inr ⟨empty, ?_⟩
      intro entry present
      obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp present
      have bound := (List.getElem?_eq_some_iff.mp hj).1
      have off : count.val ≤ i.val := Nat.le_of_not_gt run
      have found := same j (by omega)
      rw [hj, ← List.getElem?_map] at found
      exact List.mem_iff_getElem?.mpr ⟨count.val - 1 - j, found.symm⟩
  · simp

/-- The fast path starts from empty only after matching every original address. -/
theorem publication_base_refines (index : CellIndex) (root : Spike.radix.RadixRoot)
    (rows : CellRows)
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write)
    (view : IndexView index root rows) (valid : IndexValid index)
    (space : IndexBatchRoom index (rows.length + pending.val.length) pending.val.length)
    : WP.spec (Spike.engine.publication_base index root pending)
        (fun base =>
          base = root
          ∨ (IndexView index base []
              ∧ ∀ entry ∈ rows, entry.1 ∈ pending.val.map Prod.fst)) := by
  unfold Spike.engine.publication_base
  let count := alloc.vec.Vec.len pending
  have size : count.val = pending.val.length := alloc.vec.Vec.len_val _
  have threshold : (256#usize : Usize).val = 256 := rfl
  have max : core.num.Usize.MAX.val = Usize.max := rfl
  by_cases small : count < 256#usize
  · rw [ite_eq_left small, WP.spec_ok]
    exact Or.inl rfl
  · rw [ite_eq_right small]
    by_cases full : count = core.num.Usize.MAX
    · rw [ite_eq_left full, WP.spec_ok]
      exact Or.inl rfl
    · rw [ite_eq_right full]
      have one : (1#usize : Usize).val = 1 := rfl
      have nmax : count.val < Usize.max := by
        have upper : count.val ≤ Usize.max := by scalar_tac
        have different : count.val ≠ Usize.max := fun eq =>
          full (UScalar.eq_of_val_eq (eq.trans max.symm))
        omega
      apply WP.spec_bind (Usize.add_spec (x := count) (y := 1#usize) (by omega))
      intro limit increased
      have enough : 18 * rows.length ≤ Usize.max := by
        have large : (256#usize : Usize).val ≤ count.val := Nat.le_of_not_gt small
        have slots := space.lookup
        have cap : 2147483647 ≤ Usize.max := by scalar_tac
        have bound := Nat.mul_le_mul_right (rows.length + pending.val.length + 1)
          (show 18 ≤ pending.val.length by omega)
        omega
      apply WP.spec_bind (index_scan_up_to_refines index root limit rows view valid enough)
      intro links ⟨scanSize, load⟩
      change WP.spec (if alloc.vec.Vec.len links != count then Result.ok root
        else Spike.engine.publication_base_loop index root pending count links 0#usize) _
      have actual : (alloc.vec.Vec.len links).val = links.val.length := alloc.vec.Vec.len_val _
      by_cases sameSize : alloc.vec.Vec.len links = count
      · have checked : links.val.length = count.val := by rw [← actual, sameSize]
        have complete : rows.length = count.val := by
          rw [checked, Nat.min_def] at scanSize
          split at scanSize <;> omega
        rw [ite_eq_right (show ¬ (alloc.vec.Vec.len links != count) = true from by simp [sameSize])]
        exact publication_compare index root rows pending count links complete size.symm checked load
      · have diff : (alloc.vec.Vec.len links != count) = true := bne_iff_ne.mpr sameSize
        rw [diff, ite_eq_left (show true = true from rfl), WP.spec_ok]
        exact Or.inl rfl

private theorem indexed_row_refines (index : CellIndex) (root : Spike.radix.RadixRoot)
    (rows : CellRows) (write : IndexWrite) (version : U64)
    (view : IndexView index root rows) (valid : IndexValid index)
    (keyRoom : IndexKeyRoom write) (space : IndexBatchRoom index rows.length 1)
    : WP.spec (Spike.engine.publish_indexed_row index root write version)
        (fun (next, after) =>
          (∃ out,
            IndexView after next out ∧ out.Perm (applyIndexedWrite version write rows))
          ∧ IndexValid after
          ∧ IndexKeeps index after
          ∧ IndexGrowth index after (rows.length + 1) 1) := by
  obtain ⟨address, action⟩ := write
  have lookup := space.lookup
  have values := space.values
  have key : 2 * (8 + address.map.val.length + address.key.val.length) + 1 ≤ Usize.max :=
    keyRoom
  simp only [Nat.one_mul] at lookup
  cases action with
  | Put value =>
      simp only [Spike.engine.publish_indexed_row, clone_address, clone_bytes, bind_ok,
        applyIndexedWrite]
      exact index_put_refines index root rows view address {value, version} valid
        (by omega) (by omega) key
  | Remove =>
      simp only [Spike.engine.publish_indexed_row, applyIndexedWrite]
      apply WP.spec_mono
        (index_remove_refines index root rows view address valid (by omega) (by omega))
      rintro ⟨next, after⟩ ⟨updated, good, kept, ⟨ld, lv⟩⟩
      dsimp only
      exact ⟨
        ⟨Kv.Model.erase rows address, updated, .refl _⟩,
        good,
        kept,
        ⟨by omega, by omega⟩
      ⟩

private theorem indexed_write_length (version : U64) (row : IndexWrite) (data : CellRows)
    : (applyIndexedWrite version row data).length ≤ data.length + 1 := by
  obtain ⟨a, w⟩ := row
  have erased : (Kv.Model.erase data a).length ≤ data.length := List.length_filter_le _ _
  cases w <;> simp only [applyIndexedWrite, Kv.Model.set, List.length_cons] <;> omega

/-- Extracted publication implements the fold up to permutation and retains every prior root. -/
theorem indexed_publication_refines (index : CellIndex) (root : Spike.radix.RadixRoot)
    (rows : CellRows)
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write) (version : U64)
    (view : IndexView index root rows) (valid : IndexValid index)
    (space : IndexBatchRoom index (rows.length + pending.val.length) pending.val.length)
    (addresses : ∀ row ∈ pending.val, IndexKeyRoom row)
    : WP.spec (Spike.engine.publish_indexed index root pending version)
        (fun (next, after) =>
          (∃ out,
            IndexView after next out
            ∧ out.Perm (pending.val.foldr (applyIndexedWrite version) rows))
          ∧ IndexValid after
          ∧ IndexKeeps index after
          ∧ IndexGrowth index after
              (pending.val.length * (rows.length + pending.val.length + 1))
              pending.val.length) := by
  let total := pending.val.length
  let peak := rows.length + total
  let lookupCost := peak + 1
  let expected := pending.val.foldr (applyIndexedWrite version) rows
  change WP.spec _ (fun (next, after) =>
    (∃ out, IndexView after next out ∧ out.Perm expected)
    ∧ IndexValid after ∧ IndexKeeps index after
    ∧ IndexGrowth index after (total * lookupCost) total)
  unfold Spike.engine.publish_indexed Spike.engine.publish_indexed_loop
  apply loop.spec_decr_nat (fun (_, _, i) => (i : Usize).val)
    (fun (arena, cut, i) =>
      i.val ≤ total
      ∧ IndexValid arena
      ∧ IndexKeeps index arena
      ∧ IndexGrowth index arena ((total - i.val) * lookupCost) (total - i.val)
      ∧ ∃ current : CellRows,
          IndexView arena cut current
          ∧ current.length + i.val ≤ peak
          ∧ ((pending.val.take i.val).foldr (applyIndexedWrite version) current).Perm
              expected)
    _ _ _
  · rintro ⟨arena, cut, i⟩ ⟨hi, good, kept, growth, current, related, size, remaining⟩
    dsimp only at hi good kept growth related size remaining ⊢
    unfold Spike.engine.publish_indexed_loop.body
    have one : (1#usize : Usize).val = 1 := rfl
    by_cases run : (0#usize : Usize) < i
    · have positive : 0 < i.val := run
      rw [ite_eq_left run]
      apply WP.spec_bind (Usize.sub_spec (x := i) (y := 1#usize) (by omega))
      intro j hj
      have step : i.val = j.val + 1 := by omega
      have bound : j.val < pending.val.length := by change j.val < total; omega
      rw [alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending j bound)
      intro row read
      have keys : IndexKeyRoom row := addresses row (read ▸ List.getElem_mem _)
      have used : total - j.val = (total - i.val).succ := by omega
      have split (cost : Nat) :
          (total - i.val) * cost + cost ≤ total * cost := by
        rw [← Nat.succ_mul, ← used]
        exact Nat.mul_le_mul_right _ (Nat.sub_le _ _)
      obtain ⟨ld, lv⟩ := growth
      have lookupStep := split lookupCost
      have ⟨pl, pv⟩ : IndexBatchRoom index peak total := space
      have smaller : current.length ≤ peak := by omega
      have lstep : current.length + 1 ≤ lookupCost := by dsimp [lookupCost]; omega
      change index.values.dirs.val.length + total * lookupCost ≤ 2147483647 at pl
      have nextRoom : IndexBatchRoom arena current.length 1 :=
        ⟨by simp only [Nat.one_mul]; omega, by omega⟩
      apply WP.spec_bind (indexed_row_refines arena cut current row version related good keys nextRoom)
      rintro ⟨next, after⟩ ⟨⟨nextRows, nextView, nextPerm⟩, nextValid, nextKeeps, ⟨dl, vl⟩⟩
      change WP.spec (Result.ok (ControlFlow.cont (after, next, j))) _
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨by omega, nextValid, kept.trans nextKeeps, ?_,
        nextRows, nextView, ?_, ?_⟩, by omega⟩
      · rw [used, Nat.succ_mul]
        exact ⟨by omega, by omega⟩
      · have len := indexed_write_length version row current
        have hlenEq := nextPerm.length_eq
        omega
      · rw [step, List.take_succ_eq_append_getElem bound, ← read, List.foldr_append] at remaining
        exact (indexed_fold_perm version (pending.val.take j.val) nextPerm).trans remaining
    · have zero : i.val = 0 := by
        have notPositive : ¬ 0 < i.val := run
        omega
      rw [ite_eq_right run, WP.spec_ok]
      rw [zero, Nat.sub_zero] at growth
      simp only [zero, List.take_zero, List.foldr_nil] at remaining
      exact ⟨⟨current, related, remaining⟩, good, kept, growth⟩
  · have length : (alloc.vec.Vec.len pending).val = total := alloc.vec.Vec.len_val pending
    simp only [length, Nat.sub_self, Nat.zero_mul, Nat.le_refl, true_and]
    exact ⟨valid, .refl _, ⟨Nat.le_refl _, Nat.le_refl _⟩, rows, view, Nat.le_refl _,
      by simp [total, expected]⟩

theorem indexed_publish_selected (index : CellIndex) (root base : Spike.radix.RadixRoot)
    (rows : CellRows)
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write) (version : U64)
    (view : IndexView index root rows) (valid : IndexValid index)
    (space : IndexBatchRoom index (rows.length + pending.val.length) pending.val.length)
    (addresses : ∀ row ∈ pending.val, IndexKeyRoom row)
    (chosen
      : base = root
        ∨ (IndexView index base [] ∧ ∀ entry ∈ rows, entry.1 ∈ pending.val.map Prod.fst))
    : WP.spec (Spike.engine.publish_indexed index base pending version)
        (fun (next, after) =>
          (∃ out,
            IndexView after next out
            ∧ out.Perm (pending.val.foldr (applyIndexedWrite version) rows))
          ∧ IndexValid after
          ∧ IndexKeeps index after) := by
  rcases chosen with rfl | ⟨empty, covers⟩
  · apply WP.spec_mono (indexed_publication_refines index base rows pending version
      view valid space addresses)
    rintro ⟨_, _⟩ ⟨refined, good, kept, _⟩
    exact ⟨refined, good, kept⟩
  · rw [indexed_fold_cover rows pending.val version covers]
    have fits : IndexBatchRoom index (([] : CellRows).length + pending.val.length) pending.val.length :=
      space.shrink (by simp)
    apply WP.spec_mono (indexed_publication_refines index base [] pending version
      empty valid fits addresses)
    rintro ⟨_, _⟩ ⟨refined, good, kept, _⟩
    exact ⟨refined, good, kept⟩

end KvRust
