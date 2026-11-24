-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.RadixDual
public import KvRust.Publication

@[expose] public section

namespace KvRust

open Aeneas.Std

def packedAddress (address : Spike.engine.Address) : List U8 :=
  addressBytes address.map.val address.key.val

theorem packed_address_injective : Function.Injective packedAddress := by
  intro a b same
  have fits (bytes : Spike.engine.Bytes) : bytes.val.length < 2 ^ 64 := by
    have bound := alloc.vec.Vec.len_ineq bytes
    have width := Usize.max_succ_eq_pow
    rcases System.Platform.numBits_eq with h | h <;> simp [h] at width <;> omega
  have eq := address_bytes_injective a.map.val b.map.val a.key.val b.key.val
    (fits a.map) (fits b.map) same
  exact byteAddr_inj (Prod.ext eq.1 eq.2)

def packedBindings {V : Type} (rows : List (Spike.engine.Address × V))
    : List (List U8 × Spike.kv_index.Binding V) :=
  rows.map fun (a, v) => (packedAddress a, { address := a, value := v })

/-- The native root implements the original ordered address/value list. -/
structure IndexView {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot) (rows : List (Spike.engine.Address × V))
    : Prop where
  witness
    : ∃ links, DualView index root links ∧ dualBindings index links = packedBindings rows

theorem index_view_unique {V : Type} {index : Spike.kv_index.AddressIndex V}
    {root : Spike.radix.DualRoot} {a b : List (Spike.engine.Address × V)}
    (va : IndexView index root a) (vb : IndexView index root b)
    : a = b := by
  obtain ⟨la, ha, pa⟩ := va.witness
  obtain ⟨lb, hb, pb⟩ := vb.witness
  obtain rfl := dual_view_unique ha hb
  have payload := congrArg (List.map fun row : List U8 × Spike.kv_index.Binding V =>
    (row.2.address, row.2.value)) (pa.symm.trans pb)
  simpa [packedBindings, List.map_map, Function.comp_def] using payload

noncomputable def indexRows {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot)
    : List (Spike.engine.Address × V) := by
  classical
  exact if h : ∃ rows, IndexView index root rows then Classical.choose h else []

theorem index_rows_eq {V : Type} {index : Spike.kv_index.AddressIndex V}
    {root : Spike.radix.DualRoot} {rows : List (Spike.engine.Address × V)}
    (h : IndexView index root rows)
    : indexRows index root = rows := by
  unfold indexRows
  rw [dite_eq_left ⟨rows, h⟩]
  exact index_view_unique (Classical.choose_spec _) h

theorem index_rows_view {V : Type} {index : Spike.kv_index.AddressIndex V}
    {root : Spike.radix.DualRoot} (live : ∃ rows, IndexView index root rows)
    : IndexView index root (indexRows index root) := by
  obtain ⟨rows, view⟩ := live
  rwa [index_rows_eq view]

def IndexValid {V : Type} (index : Spike.kv_index.AddressIndex V) : Prop :=
  ArenaValid index.values ∧ ArenaValid index.order

def IndexKeeps {V : Type} (before after : Spike.kv_index.AddressIndex V) : Prop :=
  ArenaKeeps before.values after.values
  ∧ ArenaKeeps before.order after.order
  ∧ before.last.val ≤ after.last.val

theorem IndexKeeps.refl {V : Type} (index : Spike.kv_index.AddressIndex V)
    : IndexKeeps index index :=
  ⟨.refl _, .refl _, Nat.le_refl _⟩

theorem IndexKeeps.trans {V : Type} {a b c : Spike.kv_index.AddressIndex V}
    (ab : IndexKeeps a b) (bc : IndexKeeps b c)
    : IndexKeeps a c :=
  ⟨ab.1.trans bc.1, ab.2.1.trans bc.2.1, Nat.le_trans ab.2.2 bc.2.2⟩

theorem index_keeps_view {V : Type} {old next : Spike.kv_index.AddressIndex V}
    (kept : IndexKeeps old next) (root : Spike.radix.DualRoot)
    (rows : List (Spike.engine.Address × V)) (view : IndexView old root rows)
    : IndexView next root rows := by
  obtain ⟨links, dual, projection⟩ := view.witness
  obtain ⟨after, same⟩ := dual_retains_views old next kept.1 kept.2.1 kept.2.2 root links dual
  exact ⟨links, after, same.trans projection⟩

theorem index_new_refines (V : Type)
    : WP.spec (Spike.kv_index.AddressIndex.new V)
        (fun index =>
          IndexValid index
          ∧ WP.spec (Spike.kv_index.AddressIndex.empty_root index)
              (fun root => IndexView index root [])) := by
  unfold Spike.kv_index.AddressIndex.new Spike.kv_index.AddressIndex.empty_root
  apply WP.spec_bind (dual_new_refines (Spike.kv_index.Binding V))
  intro index ⟨validValues, validOrder, empty⟩
  rw [WP.spec_ok]
  refine ⟨⟨validValues, validOrder⟩, ?_⟩
  exact WP.spec_mono empty (fun _ view => ⟨[], view, rfl⟩)

theorem index_empty_root_refines {V : Type} (index : Spike.kv_index.AddressIndex V)
    : WP.spec (Spike.kv_index.AddressIndex.empty_root index)
        (fun root => IndexView index root []) := by
  unfold Spike.kv_index.AddressIndex.empty_root Spike.radix.DualRadix.empty_root
  rw [WP.spec_ok]
  refine ⟨[], ⟨⟨0, .empty 0⟩, ?_, ⟨0, [], .empty 0, ?_, rfl, List.Pairwise.nil⟩,
    ?_, ?_⟩, rfl⟩ <;> simp [RadixRows]

private theorem address_key_matches (a : Spike.engine.Address)
    (capacity : 8 + a.map.val.length + a.key.val.length ≤ Usize.max)
    : WP.spec
        (Spike.radix.address_key (alloc.vec.Vec.deref a.map) (alloc.vec.Vec.deref a.key))
        (fun out => out.val = packedAddress a) := by
  apply WP.spec_mono
    (native_address_key _ _ (by simpa [alloc.vec.Vec.deref] using capacity))
  intro out bytes
  simpa [alloc.vec.Vec.deref, packedAddress] using bytes

theorem index_batch_row_refines {V : Type} (address : Spike.engine.Address) (value : V)
    (capacity : 8 + address.map.val.length + address.key.val.length ≤ Usize.max)
    : WP.spec (Spike.kv_index.AddressIndex.batch_row address value)
        (fun row =>
          row.key.val = packedAddress address
          ∧ row.value = {address, value}
          ∧ row.key.val.length
            = 8 + address.map.val.length + address.key.val.length) := by
  simp only [Spike.kv_index.AddressIndex.batch_row, Spike.engine.Bytes.as_slice, bind_ok]
  apply WP.spec_bind (address_key_matches address capacity)
  intro key encoded
  rw [WP.spec_ok]
  refine ⟨encoded, rfl, ?_⟩
  rw [encoded, packedAddress, addressBytes, List.length_append, List.length_append]
  simp [addressPrefix, BitVec.toLEBytes_length]

local instance nativeAddressEq : DecidableEq Spike.engine.Address :=
  fun a b => decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

theorem index_get_refines {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot) (rows : List (Spike.engine.Address × V))
    (view : IndexView index root rows) (address : Spike.engine.Address)
    (capacity : 8 + address.map.val.length + address.key.val.length ≤ Usize.max)
    : WP.spec (Spike.kv_index.AddressIndex.get index root address)
        (· = Kv.Model.find rows address) := by
  obtain ⟨links, related, projection⟩ := view.witness
  simp only [Spike.kv_index.AddressIndex.get, Spike.engine.Bytes.as_slice, bind_ok]
  apply WP.spec_bind (address_key_matches address capacity)
  intro encoded same
  apply WP.spec_bind
    (dual_get_refines index root (alloc.vec.Vec.deref encoded) links related)
  intro found he
  have lookup :
      found = (Kv.Model.find rows address).map
        (fun v => ({ address, value := v } : Spike.kv_index.Binding V)) := by
    rw [projection, show (alloc.vec.Vec.deref encoded).val = packedAddress address from by
      simpa [alloc.vec.Vec.deref] using same] at he
    exact he.trans
      (find_projected_with_key rows address packedAddress
        (fun a v => ({ address := a, value := v } : Spike.kv_index.Binding V)) packed_address_injective)
  rw [lookup]
  cases Kv.Model.find rows address <;> simp

private theorem packed_erase {V : Type} (rows : List (Spike.engine.Address × V))
    (address : Spike.engine.Address)
    : Kv.Model.erase (packedBindings rows) (packedAddress address)
      = packedBindings (Kv.Model.erase rows address) := by
  unfold packedBindings Kv.Model.erase
  rw [List.filter_map]
  have equivalent (p : Spike.engine.Address × V) :
      @bne (List U8) instBEqOfDecidableEq (packedAddress p.1) (packedAddress address)
        = (p.1 != address) := by
    by_cases same : p.1 = address
    · simp [same]
    · have diff : packedAddress p.1 ≠ packedAddress address :=
        fun eq => same (packed_address_injective eq)
      simp [bne, diff, same]
  let project : Spike.engine.Address × V → List U8 × Spike.kv_index.Binding V :=
    fun (a, v) => (packedAddress a, { address := a, value := v })
  have filtered : rows.filter
      ((fun p => @bne (List U8) instBEqOfDecidableEq p.1 (packedAddress address)) ∘ project)
      = rows.filter (fun p => p.1 != address) := by
    apply List.filter_congr
    rintro ⟨a, v⟩ _
    exact equivalent (a, v)
  exact congrArg (List.map project) filtered

private theorem packed_set {V : Type} (rows : List (Spike.engine.Address × V))
    (address : Spike.engine.Address) (value : V)
    : Kv.Model.set (packedBindings rows) (packedAddress address)
        ({address, value} : Spike.kv_index.Binding V)
      = packedBindings (Kv.Model.set rows address value) := by
  rw [Kv.Model.set, packed_erase]
  rfl

private theorem radix_filter_map_length {V W : Type}
    (values : List (Option (Spike.radix.RadixRow V))) (links : List (List U8 × U32))
    (live : RadixRows values links) (f : (List U8 × U32) → Spike.radix.RadixRow V → W)
    : (links.filterMap fun e => (radixRow values e.2).map (f e)).length
      = links.length := by
  induction links with
  | nil => rfl
  | cons binding tail ih =>
      obtain ⟨k, l⟩ := binding
      obtain ⟨_, row, saved, _⟩ := live (k, l) List.mem_cons_self
      have h := ih (fun e hm => live e (List.mem_cons_of_mem _ hm))
      simp [saved, h]

private theorem index_link_count {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot) (rows : List (Spike.engine.Address × V))
    (links : List (List U8 × U32)) (view : DualView index root links)
    (projection : dualBindings index links = packedBindings rows)
    : links.length = rows.length := by
  have len := congrArg List.length projection
  have size : (radixBindings index.values.rows.val links).length = links.length :=
    radix_filter_map_length _ _ view.values (fun e row => (e.1, row.value))
  simpa only [dualBindings, packedBindings, List.length_map, size] using len

private theorem index_order_count {V : Type} (index : Spike.kv_index.AddressIndex V)
    (links keys : List (List U8 × U32)) (view : RadixRows index.values.rows.val links)
    (live : RadixRows index.order.rows.val keys)
    (pairing
      : radixBindings index.order.rows.val keys
        = dualStampBindings index.values.rows.val links)
    : keys.length = links.length := by
  have len := congrArg List.length pairing
  have size : (radixBindings index.order.rows.val keys).length = keys.length :=
    radix_filter_map_length _ _ live (fun e row => (e.1, row.value))
  have stamps : (dualStampBindings index.values.rows.val links).length = links.length :=
    radix_filter_map_length _ _ view (fun e row => (reverseStampBytes row.value.stamp, e.2))
  simpa only [size, stamps] using len

def IndexGrowth {V : Type} (before after : Spike.kv_index.AddressIndex V)
    (lookupDirs orderDirs writes : Nat)
    : Prop :=
  ArenaGrowth before.values after.values lookupDirs writes
  ∧ ArenaGrowth before.order after.order orderDirs writes
  ∧ after.last.val ≤ before.last.val + writes

theorem index_put_refines {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot) (rows : List (Spike.engine.Address × V))
    (related : IndexView index root rows)
    (address : Spike.engine.Address) (value : V)
    (valid : IndexValid index)
    (lookupRoom : index.values.dirs.val.length + rows.length + 1 ≤ 2147483647)
    (orderRoom : index.order.dirs.val.length + 2 * rows.length + 1 ≤ 2147483647)
    (valueRoom : index.values.rows.val.length < 2147483647)
    (stampRoom : index.order.rows.val.length < 2147483647)
    (keyRoom : 2 * (8 + address.map.val.length + address.key.val.length) + 1 ≤ Usize.max)
    (counterRoom : index.last.val < U64.max)
    : WP.spec (Spike.kv_index.AddressIndex.put index root address value)
        (fun (next, after) =>
          IndexView after next (Kv.Model.set rows address value)
          ∧ IndexValid after
          ∧ IndexKeeps index after
          ∧ IndexGrowth index after (rows.length + 1) (2 * rows.length + 1) 1) := by
  obtain ⟨links, view, projection⟩ := related.witness
  obtain ⟨h, tree⟩ := view.lookup
  obtain ⟨oh, keys, order, live, pairing, sorted⟩ := view.order
  have count := index_link_count index root rows links view projection
  have orderCount := index_order_count index links keys view.values live pairing
  have lookup := (radix_tree_binding_bound _ valid.1.directories tree).1
  have orderTree := (radix_tree_binding_bound _ valid.2.directories order).1
  unfold Spike.kv_index.AddressIndex.put
  apply WP.spec_bind (index_batch_row_refines address value (by omega))
  rintro ⟨encoded, binding⟩ ⟨he, hb, len⟩
  dsimp only at he hb len
  subst binding
  apply WP.spec_bind
    (dual_put_refines index root links
      {key := encoded, value := {address, value}} view valid.1 valid.2 _ _ keys
      lookup orderTree live pairing sorted (by omega) (by omega)
      valueRoom stampRoom (by simpa [len] using keyRoom) counterRoom)
  rintro ⟨next, after⟩ ⟨leaf, refined, hp, hv, ho, kv, ko, clock, vg, og⟩
  change WP.spec (Result.ok (next, after)) _
  rw [WP.spec_ok]
  refine ⟨⟨Kv.Model.set links encoded.val leaf, refined, ?_⟩, ⟨hv, ho⟩, ⟨kv, ko, ?_⟩, ?_⟩
  · rw [hp, projection, he, packed_set]
  · rw [clock]
    exact Nat.le_succ _
  · refine ⟨count ▸ vg, ?_, Nat.le_of_eq clock⟩
    simpa only [orderCount, count, Nat.two_mul] using og

theorem index_remove_refines {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot) (rows : List (Spike.engine.Address × V))
    (related : IndexView index root rows)
    (address : Spike.engine.Address) (valid : IndexValid index)
    (lookupRoom : index.values.dirs.val.length + rows.length ≤ 2147483647)
    (orderRoom : index.order.dirs.val.length + rows.length ≤ 2147483647)
    (capacity : 8 + address.map.val.length + address.key.val.length ≤ Usize.max)
    : WP.spec (Spike.kv_index.AddressIndex.remove index root address)
        (fun (next, after) =>
          IndexView after next (Kv.Model.erase rows address)
          ∧ IndexValid after
          ∧ IndexKeeps index after
          ∧ IndexGrowth index after rows.length rows.length 0) := by
  obtain ⟨links, view, projection⟩ := related.witness
  obtain ⟨h, tree⟩ := view.lookup
  obtain ⟨oh, keys, order, live, pairing, sorted⟩ := view.order
  have count := index_link_count index root rows links view projection
  have orderCount := index_order_count index links keys view.values live pairing
  have lookup := (radix_tree_binding_bound _ valid.1.directories tree).1
  have orderTree := (radix_tree_binding_bound _ valid.2.directories order).1
  simp only [Spike.kv_index.AddressIndex.remove, Spike.engine.Bytes.as_slice, bind_ok]
  apply WP.spec_bind (address_key_matches address capacity)
  intro encoded he
  apply WP.spec_bind
    (dual_remove_refines index root links (alloc.vec.Vec.deref encoded) view valid.1
      valid.2 _ _ keys lookup orderTree live pairing sorted (by omega) (by omega))
  rintro ⟨next, after⟩ ⟨refined, hp, hv, ho, kv, ko, clock, vg, og⟩
  change WP.spec (Result.ok (next, after)) _
  rw [WP.spec_ok]
  refine ⟨
    ⟨Kv.Model.erase links (alloc.vec.Vec.deref encoded).val, refined, ?_⟩,
    ⟨hv, ho⟩,
    ⟨kv, ko, by rw [clock]⟩,
    ⟨count ▸ vg, (orderCount.trans count) ▸ og, by rw [clock, Nat.add_zero]⟩
  ⟩
  rw [hp, projection, show (alloc.vec.Vec.deref encoded).val = packedAddress address from by
    simpa [alloc.vec.Vec.deref] using he, packed_erase]

/- The scan result contains links only; each actual Rust row read is related
to the pair at the same position of the original association list. -/
theorem index_scan_up_to_refines {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot) (limit : Usize) (rows : List (Spike.engine.Address × V))
    (view : IndexView index root rows) (valid : IndexValid index)
    (room : 18 * rows.length ≤ Usize.max)
    : WP.spec (Spike.kv_index.AddressIndex.scan_links_up_to index root limit)
        (fun links =>
          links.val.length = min limit.val rows.length
          ∧ ∀ (i : Nat) link,
              links.val[i]? = some link
              → ∃ entry,
                  rows[i]? = some entry
                  ∧ WP.spec (Spike.kv_index.AddressIndex.scan_row index link)
                      (· = entry)) := by
  obtain ⟨bindings, related, projection⟩ := view.witness
  have size := index_link_count index root rows bindings related projection
  obtain ⟨height, keys, tree, live, pairing, _⟩ := related.order
  have orderedCount := index_order_count index bindings keys related.values live pairing
  let dirs := alloc.vec.Vec.deref index.order.dirs
  obtain ⟨fuel, leaves, plan, perm⟩ :=
    radix_scan_plan_exists dirs height root.order keys
      (by simpa [dirs, alloc.vec.Vec.deref] using tree)
  have count : leaves.length = keys.length := by simpa using perm.length_eq
  have bound := radix_scan_plan_bound index.order.dirs valid.2.directories
    (by simpa [dirs, alloc.vec.Vec.deref] using plan)
  unfold Spike.kv_index.AddressIndex.scan_links_up_to
  apply WP.spec_mono
    (dual_scan_up_to_refines index root limit bindings related
      (radix_compressed_of_knowledge _ _ valid.2.knowledge)
      ⟨fuel, leaves, by simpa [dirs, alloc.vec.Vec.deref] using plan, by omega⟩)
  intro links scanned
  have sizePrefix : links.val.length = min limit.val rows.length := by
    simp [scanned, size]
  refine ⟨sizePrefix, ?_⟩
  intro i link selected
  have insideLimit : i < limit.val := by
    have inside := (List.getElem?_eq_some_iff.mp selected).1
    omega
  rw [scanned, List.getElem?_take_of_lt insideLimit, List.getElem?_map] at selected
  cases atLink : bindings[i]? with
  | none => simp [atLink] at selected
  | some entry =>
      have points : entry.2 = link := by simpa [atLink] using selected
      subst link
      have inBindings := List.mem_iff_getElem?.mpr ⟨i, atLink⟩
      have inside : i < rows.length := by
        by_contra outside
        rw [← size] at outside
        simp [List.getElem?_eq_none (Nat.le_of_not_gt outside)] at atLink
      obtain ⟨_, savedRow, saved, _⟩ := related.values entry inBindings
      have loaded := congrArg (fun items : List (List U8 × Spike.kv_index.Binding V) =>
        items[i]?) projection
      rw [dualBindings, packedBindings, List.getElem?_map, List.getElem?_map,
        radix_projection_index _ _ related.values, atLink, List.getElem?_eq_getElem inside] at loaded
      have payload : savedRow.value.value = {address := rows[i].1, value := rows[i].2} := by
        simpa [saved] using congrArg (Option.map Prod.snd) loaded
      refine ⟨rows[i], List.getElem?_eq_getElem inside, ?_⟩
      unfold Spike.kv_index.AddressIndex.scan_row
      apply WP.spec_bind
        (dual_scan_row_refines index root bindings related entry inBindings)
      rintro ⟨key, value⟩ ⟨row, original, _, read⟩
      have same : row = savedRow := Option.some.inj (original.symm.trans saved)
      subst row
      change WP.spec (Result.ok (value.address, value.value)) _
      rw [WP.spec_ok, read, payload]

theorem index_scan_refines {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot) (rows : List (Spike.engine.Address × V))
    (view : IndexView index root rows) (valid : IndexValid index)
    (room : 18 * rows.length ≤ Usize.max)
    : WP.spec (Spike.kv_index.AddressIndex.scan_links index root)
        (fun links =>
          links.val.length = rows.length
          ∧ ∀ (i : Nat) link,
              links.val[i]? = some link
              → ∃ entry,
                  rows[i]? = some entry
                  ∧ WP.spec (Spike.kv_index.AddressIndex.scan_row index link)
                      (· = entry)) := by
  change WP.spec (Spike.kv_index.AddressIndex.scan_links_up_to index root core.num.Usize.MAX) _
  apply WP.spec_mono
    (index_scan_up_to_refines index root core.num.Usize.MAX rows view valid room)
  intro links ⟨count, read⟩
  have enough : rows.length ≤ core.num.Usize.MAX.val := by
    change rows.length ≤ Usize.max
    omega
  exact ⟨count.trans (Nat.min_eq_right enough), read⟩

end KvRust
