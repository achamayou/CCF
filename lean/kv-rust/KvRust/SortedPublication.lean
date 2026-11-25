-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.IndexedPublication
public import KvRust.RadixDualBatch

@[expose] public section

namespace KvRust

open Aeneas.Std

local instance batchAddressEquality : DecidableEq Spike.engine.Address :=
  fun a b => decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

abbrev BatchRow := Spike.radix.RadixRow (Spike.kv_index.Binding Spike.engine.Cell)

private def sourceRow (version : U64) (entry : IndexWrite) :=
  (
    packedAddress entry.1,
    match entry.2 with
    | .Put value =>
        some
          ({ address := entry.1, value := {value, version} }
            : Spike.kv_index.Binding Spike.engine.Cell)
    | .Remove => none
  )

private def batchImage (row : BatchRow) := (row.key.val, some row.value)

private theorem byte_order_of_lt {a b : List U8} (lt : a < b)
    : byteOrder a b = (-1)#i8 := by
  have neg := (byteOrder_lt a b).mpr lt
  induction a generalizing b with
  | nil => cases b <;> simp [byteOrder] at neg ⊢
  | cons a rest ih =>
      cases b with
      | nil => simp [byteOrder] at neg
      | cons b tail =>
          simp only [byteOrder] at neg ⊢
          by_cases hab : a < b
          · simp [hab]
          simp only [ite_eq_right hab] at neg ⊢
          by_cases hba : b < a
          · simp only [ite_eq_left hba] at neg
            have impossible : ¬ (1#i8 : I8) < 0#i8 := by decide
            exact (impossible neg).elim
          · rw [ite_eq_right hba]
            rw [ite_eq_right hba] at neg
            exact ih ((byteOrder_lt _ _).mp neg) neg

private theorem byte_order_prefix (common a b : List U8)
    : byteOrder (common ++ a) (common ++ b) = byteOrder a b := by
  induction common with
  | nil => rfl
  | cons p rest ih => simpa [byteOrder] using ih

private theorem batch_image_fold (version : U64) (writes : List IndexWrite)
    (batch : List BatchRow)
    (matching : batch.map batchImage = writes.map (sourceRow version))
    (sorted : writes.Pairwise (fun a b => packedAddress b.1 < packedAddress a.1))
    : batch.map (fun row => (row.key.val, row.value))
      = packedBindings (writes.foldr (applyIndexedWrite version) []) := by
  induction writes generalizing batch with
  | nil =>
      have empty : batch = [] := List.map_eq_nil_iff.mp matching
      simp [empty, packedBindings]
  | cons w rest ih =>
      cases batch with
      | nil => simp at matching
      | cons row more =>
          obtain ⟨head, tail⟩ := List.cons.inj matching
          obtain ⟨earlier, ordered⟩ := List.pairwise_cons.mp sorted
          let after := rest.foldr (applyIndexedWrite version) []
          have related := ih more tail ordered
          obtain ⟨a, write⟩ := w
          cases write with
          | Remove =>
              have bad := congrArg Prod.snd head
              simp [sourceRow, batchImage] at bad
          | Put value =>
              have sameKey : row.key.val = packedAddress a := congrArg Prod.fst head
              have sameValue : row.value = {address := a, value := {value, version}} :=
                Option.some.inj (congrArg Prod.snd head)
              have notOverwritten : ∀ cell ∈ after, cell.1 ≠ a := by
                intro cell hm equal
                have present : (packedAddress cell.1,
                      ({address := cell.1, value := cell.2} :
                        Spike.kv_index.Binding Spike.engine.Cell)) ∈
                    more.map (fun row => (row.key.val, row.value)) := by
                  rw [related]
                  exact List.mem_map_of_mem hm
                obtain ⟨entry, he, binding⟩ := List.mem_map.mp present
                have mapped := List.mem_map_of_mem (f := batchImage) he
                rw [tail] at mapped
                obtain ⟨write, hw, key⟩ := List.mem_map.mp mapped
                have strict := earlier write hw
                have eq : packedAddress write.1 = packedAddress a :=
                  (congrArg Prod.fst key).trans ((congrArg Prod.fst binding).trans (congrArg packedAddress equal))
                exact (lt_irrefl _ (eq ▸ strict))
              have erased : Kv.Model.erase after a = after := by
                unfold Kv.Model.erase
                apply List.filter_eq_self.mpr
                intro cell hm
                exact bne_iff_ne.mpr (notOverwritten cell hm)
              change (row.key.val, row.value) :: _ =
                packedBindings ((a, {value, version}) :: Kv.Model.erase after a)
              rw [sameKey, sameValue, erased]
              exact congrArg (List.cons _) related

private theorem single_map_increasing_refines (a b : Spike.engine.Address)
    : WP.spec (Spike.engine.single_map_increasing a b)
        (fun yes => yes = true → packedAddress a < packedAddress b) := by
  simp only [Spike.engine.single_map_increasing, bytes_same, bind_ok]
  by_cases hm : a.map.val = b.map.val
  · simp only [hm, decide_true, ite_true]
    apply WP.spec_bind (bytes_compare a.key b.key)
    intro cmp comparison
    rw [WP.spec_ok]
    intro yes
    have order : byteOrder a.key.val b.key.val = (-1)#i8 := by
      simpa [comparison] using yes
    apply (byteOrder_lt _ _).mp
    unfold packedAddress addressBytes
    rw [hm, byte_order_prefix, order]
    decide
  · simp [hm]

private structure PreparedRows (version : U64) (writes : List IndexWrite)
    (batch : alloc.vec.Vec (Option BatchRow)) (rows : List BatchRow)
    : Prop where
  owned : batch.val = rows.map some
  exactImage : rows.map batchImage = writes.reverse.map (sourceRow version)
  newestFirst : writes.Pairwise (fun a b => packedAddress b.1 < packedAddress a.1)
  shallow : ∀ row ∈ rows, row.key.val.length ≤ 56

private def Prepared (version : U64) (writes : List IndexWrite)
    (batch : alloc.vec.Vec (Option BatchRow))
    : Prop :=
  ∃ rows, PreparedRows version writes batch rows

private theorem prepared_push (version : U64) (writes : List IndexWrite)
    (a : Spike.engine.Address) (value : Spike.engine.Bytes)
    (batch next : alloc.vec.Vec (Option BatchRow)) (row : BatchRow)
    (before : Prepared version writes batch)
    (step : next.val = batch.val ++ [some row])
    (ordered
      : ((a, Spike.engine.Write.Put value) :: writes).Pairwise
          (fun a b => packedAddress b.1 < packedAddress a.1))
    (key : row.key.val = packedAddress a)
    (payload : row.value = {address := a, value := {value, version}})
    (small : row.key.val.length ≤ 56)
    : Prepared version ((a, .Put value) :: writes) next := by
  obtain ⟨rows, owned, image, _, depth⟩ := before
  refine ⟨rows ++ [row], ?_, ?_, ordered, ?_⟩
  · rw [step, owned, List.map_append]
    rfl
  · rw [List.reverse_cons, List.map_append, List.map_append, image]
    simp [batchImage, sourceRow, key, payload]
  · intro entry hm
    rcases List.mem_append.mp hm with hm | hm
    · exact depth entry hm
    · rwa [List.mem_singleton.mp hm]

private theorem prepared_length {version : U64} {writes : List IndexWrite}
    {batch : alloc.vec.Vec (Option BatchRow)} {rows : List BatchRow}
    (p : PreparedRows version writes batch rows)
    : batch.val.length = writes.length ∧ rows.length = writes.length := by
  have size := congrArg List.length p.exactImage
  simp only [List.length_map, List.length_reverse] at size
  exact ⟨by rw [p.owned, List.length_map, size], size⟩

private theorem prepare_sorted_batch_refines
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write) (version : U64)
    (addresses : ∀ row ∈ pending.val, IndexKeyRoom row)
    : WP.spec (Spike.engine.prepare_sorted_batch pending version)
        (fun result =>
          ∀ batch, result = some batch → Prepared version pending.val batch) := by
  unfold Spike.engine.prepare_sorted_batch Spike.engine.prepare_sorted_batch_loop
  let len := alloc.vec.Vec.len pending
  have lenEq : len.val = pending.val.length := alloc.vec.Vec.len_val _
  change WP.spec (loop (fun (batch, i) =>
    Spike.engine.prepare_sorted_batch_loop.body pending version len batch i)
    (alloc.vec.Vec.with_capacity (Option BatchRow) len, len)) _
  apply loop.spec_decr_nat (fun (_, i) => (i : Usize).val)
    (fun (batch, i) => i.val ≤ len.val ∧ Prepared version (pending.val.drop i.val) batch)
    _ _ _
  · rintro ⟨batch, i⟩ ⟨within, ready⟩
    dsimp only at within ready ⊢
    unfold Spike.engine.prepare_sorted_batch_loop.body
    by_cases run : (0#usize : Usize) < i
    · have hpos : 0 < i.val := run
      have one : (1#usize : Usize).val = 1 := rfl
      rw [ite_eq_left run]
      apply WP.spec_bind (Usize.sub_spec (x := i) (y := 1#usize) (by omega))
      intro j sub
      have hj : j.val < pending.val.length := by omega
      rw [alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending j hj)
      rintro ⟨a, write⟩ read
      change WP.spec (if i < len then _ else _) _
      have following : j.val + 1 = i.val := by omega
      have dropNext : pending.val.drop j.val = (a, write) :: pending.val.drop i.val := by
        rw [List.drop_eq_getElem_cons hj, ← read, following]
      obtain ⟨prepared, preparedInfo⟩ := ready
      have room := addresses (a, write) (read ▸ List.getElem_mem hj)
      have fits : 8 + a.map.val.length + a.key.val.length ≤ Usize.max := by
        unfold IndexKeyRoom at room
        dsimp only at room
        omega
      have pushRoom : batch.val.length < Usize.max := by
        have size := (prepared_length preparedInfo).1
        rw [List.length_drop, ← lenEq] at size
        have capacity := alloc.vec.Vec.len_ineq pending
        omega
      have orderBefore := preparedInfo.newestFirst
      have appendOrder (newest : ∀ entry ∈ pending.val.drop i.val,
          packedAddress entry.1 < packedAddress a) :
          ((a, write) :: pending.val.drop i.val).Pairwise
            (fun x y => packedAddress y.1 < packedAddress x.1) :=
        List.pairwise_cons.mpr ⟨newest, orderBefore⟩
      have noPrevious (h : ¬ i < len) : pending.val.drop i.val = [] := by
        have ni : ¬ i.val < len.val := h
        exact List.drop_eq_nil_of_le (by omega)
      by_cases hasPrevious : i < len
      case' pos =>
        rw [ite_eq_left hasPrevious, alloc.vec.Vec.index_slice_index]
        have hi : i.val < pending.val.length := lenEq ▸ hasPrevious
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending i hi)
        rintro ⟨pa, pw⟩ readPrev
        change WP.spec (do
          let check ← Spike.engine.single_map_increasing pa a
          if check then _ else _) _
        apply WP.spec_bind (single_map_increasing_refines pa a)
        intro check passed
        cases check
        case false => simp
        case' true =>
          simp only [ite_true]
          have previous : pending.val.drop i.val = (pa, pw) :: pending.val.drop (i.val + 1) := by
            rw [List.drop_eq_getElem_cons hi, ← readPrev]
          have newest (entry : IndexWrite) (present : entry ∈ pending.val.drop i.val) :
              packedAddress entry.1 < packedAddress a := by
            have step := passed rfl
            rw [previous] at present orderBefore
            rcases List.mem_cons.mp present with rfl | inTail
            · exact step
            · exact lt_trans ((List.pairwise_cons.mp orderBefore).1 entry inTail) step
          have ordered := appendOrder newest
      case' neg =>
        rw [ite_eq_right hasPrevious]
        have ordered := appendOrder (fun entry present => by simp [noPrevious hasPrevious] at present)
      all_goals
        cases write with
        | Remove => simp
        | Put value =>
            simp only [clone_address, clone_bytes, bind_ok]
            apply WP.spec_bind (index_batch_row_refines a
              ({value, version} : Spike.engine.Cell) fits)
            intro row ⟨key, payload, _⟩
            have rowLen : (alloc.vec.Vec.len row.key).val = row.key.val.length :=
              alloc.vec.Vec.len_val _
            by_cases big : 56#usize < alloc.vec.Vec.len row.key
            · simp [big]
            · rw [ite_eq_right big]
              apply WP.spec_bind (alloc.vec.Vec.push_spec batch (some row) pushRoom)
              intro next pushed
              rw [WP.spec_ok]
              change (j.val ≤ len.val ∧ Prepared version (pending.val.drop j.val) next)
                ∧ j.val < i.val
              refine ⟨⟨by omega, ?_⟩, by omega⟩
              rw [dropNext]
              have nbig : ¬ (56#usize : Usize).val < (alloc.vec.Vec.len row.key).val := big
              exact prepared_push version _ a value batch next row ⟨prepared, preparedInfo⟩
                pushed ordered key payload (by scalar_tac)
    · rw [ite_eq_right run, WP.spec_ok]
      intro out eq
      cases eq
      have notPositive : ¬ 0 < i.val := run
      have zero : i.val = 0 := by omega
      simpa only [zero, List.drop_zero] using ready
  · refine ⟨Nat.le_refl _, [], ?_, ?_, ?_, ?_⟩
    · simp [alloc.vec.Vec.with_capacity]
    · simp [lenEq]
    · simp [lenEq]
    · simp

private theorem sorted_batch_publishes (index : CellIndex) (valid : IndexValid index)
    (pending : List IndexWrite) (version : U64)
    (batch : alloc.vec.Vec (Option BatchRow)) (prepared : Prepared version pending batch)
    (large : 256 ≤ pending.length)
    (peak : Nat) (peakSize : pending.length ≤ peak)
    (space : IndexBatchRoom index peak pending.length)
    : WP.spec (Spike.kv_index.AddressIndex.build_sorted_batch index batch)
        (fun (root, after) =>
          (∃ out,
            IndexView after root out
            ∧ out.Perm (pending.foldr (applyIndexedWrite version) []))
          ∧ IndexValid after
          ∧ IndexKeeps index after) := by
  obtain ⟨rows, info⟩ := prepared
  have size := (prepared_length info).2
  have sameKeys : rows.map (fun row => row.key.val) =
      pending.reverse.map (fun w => packedAddress w.1) := by
    simpa [List.map_map, Function.comp_def, batchImage, sourceRow]
      using congrArg (List.map Prod.fst) info.exactImage
  have backwards : pending.reverse.Pairwise (fun a b => packedAddress a.1 < packedAddress b.1) :=
    List.pairwise_reverse.mpr info.newestFirst
  have ordered : rows.Pairwise (fun a b => a.key.val < b.key.val) := by
    have keys : (pending.reverse.map (fun w => packedAddress w.1)).Pairwise (· < ·) :=
      List.pairwise_map.mpr backwards
    rw [← sameKeys, List.pairwise_map] at keys
    exact keys
  have hDepth : ∀ row ∈ rows, 2 * row.key.val.length ≤ 112 := by
    intro row member
    have small := info.shallow row member
    omega
  have hKeys : ∀ row ∈ rows, 2 * row.key.val.length + 1 ≤ Usize.max := by
    intro row member
    have small := info.shallow row member
    have width := Usize.max_succ_eq_pow
    rcases System.Platform.numBits_eq with h | h <;> simp [h] at width <;> omega
  have hDirRoom : index.values.dirs.val.length + 2 * (rows.length * (112 + 1)) < 2147483647 := by
    rw [size]
    have strict := Nat.mul_lt_mul_of_pos_left (show 226 < peak + 1 by omega)
      (show 0 < pending.length by omega)
    have bound := space.lookup
    omega
  have hRowRoom : index.values.rows.val.length + rows.length ≤ 2147483647 := by
    rw [size]; exact space.values
  unfold Spike.kv_index.AddressIndex.build_sorted_batch
  apply WP.spec_bind
    (single_build_sorted_batch_refines index batch rows valid info.owned ordered 112
      hDepth hKeys hDirRoom hRowRoom)
  rintro ⟨root, after⟩ ⟨valueValid, valueKeeps, links, view, bindings⟩
  change WP.spec (Result.ok (root, after)) _
  rw [WP.spec_ok]
  have reverseImage : rows.reverse.map batchImage = pending.map (sourceRow version) := by
    simpa only [List.map_reverse, List.reverse_reverse]
      using congrArg List.reverse info.exactImage
  have hRevFold := batch_image_fold version pending rows.reverse reverseImage info.newestFirst
  let out : CellRows := (pending.foldr (applyIndexedWrite version) []).reverse
  have hPacked : singleBindings after links = packedBindings out := by
    rw [bindings]
    have hrev := congrArg List.reverse hRevFold
    simpa only [List.map_reverse, List.reverse_reverse, packedBindings, out] using hrev
  exact ⟨⟨out, ⟨links, view, hPacked⟩, List.reverse_perm _⟩, valueValid, valueKeeps⟩

theorem sorted_publication_refines (index : CellIndex) (root base : Spike.radix.RadixRoot)
    (rows : CellRows)
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write) (version : U64)
    (view : IndexView index root rows) (valid : IndexValid index)
    (space : IndexBatchRoom index (rows.length + pending.val.length) pending.val.length)
    (addresses : ∀ row ∈ pending.val, IndexKeyRoom row)
    (chosen
      : base = root
        ∨ (IndexView index base [] ∧ ∀ entry ∈ rows, entry.1 ∈ pending.val.map Prod.fst))
    : WP.spec (Spike.engine.publish_selected index base pending version)
        (fun (next, after) =>
          (∃ out,
            IndexView after next out
            ∧ out.Perm (pending.val.foldr (applyIndexedWrite version) rows))
          ∧ IndexValid after
          ∧ IndexKeeps index after) := by
  have fallback := indexed_publish_selected index root base rows pending version
    view valid space addresses chosen
  unfold Spike.engine.publish_selected Spike.radix.RadixRoot.is_empty
  by_cases emptyBase : base = 0#u32
  · subst emptyBase
    simp only [decide_true, bind_ok, ite_true]
    by_cases large : 256#usize ≤ alloc.vec.Vec.len pending
    · rw [ite_eq_left large]
      apply WP.spec_bind (prepare_sorted_batch_refines pending version addresses)
      intro result prep
      cases result with
      | none => exact fallback
      | some batch =>
          have empty : IndexView index 0#u32 [] := by
            simpa [Spike.kv_index.AddressIndex.empty_root,
              Spike.radix.SingleRadix.empty_root, WP.spec_ok]
              using index_empty_root_refines index
          have cover : ∀ entry ∈ rows, entry.1 ∈ pending.val.map Prod.fst := by
            rcases chosen with same | covered
            · have noRows := index_view_unique view (same ▸ empty)
              simp [noRows]
            · exact covered.2
          rw [indexed_fold_cover rows pending.val version cover]
          have minSize : 256 ≤ pending.val.length := by simpa using large
          exact sorted_batch_publishes index valid pending.val version batch
            (prep batch rfl) minSize _ (by omega) space
    · simpa only [ite_eq_right large] using fallback
  · simpa only [emptyBase, decide_false, bind_ok, Bool.false_eq_true, ite_false] using fallback

end KvRust
