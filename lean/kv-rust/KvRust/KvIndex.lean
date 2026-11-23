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

def IndexValid {V : Type} (index : Spike.kv_index.AddressIndex V) : Prop :=
  ArenaValid index.values ∧ ArenaValid index.order

def IndexKeeps {V : Type} (before after : Spike.kv_index.AddressIndex V) : Prop :=
  ArenaKeeps before.values after.values
  ∧ ArenaKeeps before.order after.order
  ∧ before.last.val ≤ after.last.val

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

private theorem address_key_matches (a : Spike.engine.Address)
    (capacity : 8 + a.map.val.length + a.key.val.length ≤ Usize.max)
    : WP.spec
        (Spike.radix.address_key (alloc.vec.Vec.deref a.map) (alloc.vec.Vec.deref a.key))
        (fun out => out.val = packedAddress a) := by
  apply WP.spec_mono
    (native_address_key _ _ (by simpa [alloc.vec.Vec.deref] using capacity))
  intro out bytes
  simpa [alloc.vec.Vec.deref, packedAddress] using bytes

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

/- The separate bounds reserve space for path copies in both indices.
The capacity theorems do not assume that a native operation has already succeeded. -/
def IndexLookupRoom {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot) (links : List (List U8 × U32)) (extra : Nat)
    : Prop :=
  ∃ height,
    RadixTree index.values.dirs.val height root.lookup links
    ∧ index.values.dirs.val.length + height + extra ≤ 2147483647

def IndexOrderRoom {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot) (links : List (List U8 × U32)) (rebuild : Bool)
    : Prop :=
  ∃ (height : Nat) (keys : List (List U8 × U32)),
    RadixTree index.order.dirs.val height root.order keys
    ∧ RadixRows index.order.rows.val keys
    ∧ radixBindings index.order.rows.val keys
      = dualStampBindings index.values.rows.val links
    ∧ keys.Pairwise radixKeyLt
    ∧ index.order.dirs.val.length + height + (if rebuild then keys.length + 1 else 0)
      ≤ 2147483647

theorem index_put_refines {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot) (rows : List (Spike.engine.Address × V))
    (links : List (List U8 × U32)) (view : DualView index root links)
    (projection : dualBindings index links = packedBindings rows)
    (address : Spike.engine.Address) (value : V)
    (valid : IndexValid index) (lookup : IndexLookupRoom index root links 1)
    (order : IndexOrderRoom index root links true)
    (valueRoom : index.values.rows.val.length < 2147483647)
    (stampRoom : index.order.rows.val.length < 2147483647)
    (keyRoom : 2 * (8 + address.map.val.length + address.key.val.length) + 1 ≤ Usize.max)
    (counterRoom : index.last.val < U64.max)
    : WP.spec (Spike.kv_index.AddressIndex.put index root address value)
        (fun (next, after) =>
          IndexView after next (Kv.Model.set rows address value)
          ∧ IndexValid after
          ∧ IndexKeeps index after) := by
  simp only [Spike.kv_index.AddressIndex.put, Spike.engine.Bytes.as_slice, bind_ok]
  apply WP.spec_bind (address_key_matches address (by omega))
  intro encoded he
  have len : encoded.val.length = 8 + address.map.val.length + address.key.val.length := by
    rw [he, packedAddress, addressBytes, List.length_append, List.length_append]
    simp [addressPrefix, BitVec.toLEBytes_length]
  have orderRoom :
      ∃ (height : Nat) (keys : List (List U8 × U32)),
        RadixTree index.order.dirs.val height root.order keys
        ∧ RadixRows index.order.rows.val keys
        ∧ radixBindings index.order.rows.val keys = dualStampBindings index.values.rows.val links
        ∧ keys.Pairwise radixKeyLt
        ∧ index.order.dirs.val.length + height + keys.length + 1 ≤ 2147483647 := by
    simpa [IndexOrderRoom, Nat.add_assoc] using order
  apply WP.spec_bind
    (dual_put_refines index root links
      {key := encoded, value := {address, value}} view valid.1 valid.2 lookup orderRoom
      valueRoom stampRoom (by simpa [len] using keyRoom) counterRoom)
  rintro ⟨next, after⟩ ⟨leaf, refined, hp, hv, ho, kv, ko, clock⟩
  change WP.spec (Result.ok (next, after)) _
  rw [WP.spec_ok]
  refine ⟨⟨Kv.Model.set links encoded.val leaf, refined, ?_⟩, ⟨hv, ho⟩, kv, ko, ?_⟩
  · rw [hp, projection, he, packed_set]
  · change index.last.val ≤ after.last.val
    rw [clock]
    exact Nat.le_succ _

theorem index_remove_refines {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot) (rows : List (Spike.engine.Address × V))
    (links : List (List U8 × U32)) (view : DualView index root links)
    (projection : dualBindings index links = packedBindings rows)
    (address : Spike.engine.Address) (valid : IndexValid index)
    (lookup : IndexLookupRoom index root links 0)
    (order : IndexOrderRoom index root links false)
    (capacity : 8 + address.map.val.length + address.key.val.length ≤ Usize.max)
    : WP.spec (Spike.kv_index.AddressIndex.remove index root address)
        (fun (next, after) =>
          IndexView after next (Kv.Model.erase rows address)
          ∧ IndexValid after
          ∧ IndexKeeps index after) := by
  simp only [Spike.kv_index.AddressIndex.remove, Spike.engine.Bytes.as_slice, bind_ok]
  apply WP.spec_bind (address_key_matches address capacity)
  intro encoded he
  have orderRoom :
      ∃ (height : Nat) (keys : List (List U8 × U32)),
        RadixTree index.order.dirs.val height root.order keys
        ∧ RadixRows index.order.rows.val keys
        ∧ radixBindings index.order.rows.val keys = dualStampBindings index.values.rows.val links
        ∧ keys.Pairwise radixKeyLt ∧ index.order.dirs.val.length + height ≤ 2147483647 := by
    simpa [IndexOrderRoom] using order
  apply WP.spec_bind
    (dual_remove_refines index root links (alloc.vec.Vec.deref encoded)
      view valid.1 valid.2 (by simpa [IndexLookupRoom] using lookup) orderRoom)
  rintro ⟨next, after⟩ ⟨refined, hp, hv, ho, kv, ko, clock⟩
  change WP.spec (Result.ok (next, after)) _
  rw [WP.spec_ok]
  refine ⟨
    ⟨Kv.Model.erase links (alloc.vec.Vec.deref encoded).val, refined, ?_⟩,
    ⟨hv, ho⟩,
    kv,
    ko,
    by rw [clock]
  ⟩
  rw [hp, projection, show (alloc.vec.Vec.deref encoded).val = packedAddress address from by
    simpa [alloc.vec.Vec.deref] using he, packed_erase]

private theorem radix_image_length {V : Type}
    (values : List (Option (Spike.radix.RadixRow V))) (bindings : List (List U8 × U32))
    (live : RadixRows values bindings)
    : (radixBindings values bindings).length = bindings.length := by
  induction bindings with
  | nil => rfl
  | cons binding tail ih =>
      obtain ⟨_, row, saved, _⟩ := live binding List.mem_cons_self
      have h := ih (fun e hm => live e (List.mem_cons_of_mem _ hm))
      simp [radixBindings, saved] at h ⊢
      exact h

/- The scan result contains links only; each actual Rust row read is related
to the pair at the same position of the original association list. -/
theorem index_scan_refines {V : Type} (index : Spike.kv_index.AddressIndex V)
    (root : Spike.radix.DualRoot) (rows : List (Spike.engine.Address × V))
    (view : IndexView index root rows) (valid : IndexValid index)
    (room
      : ∃ fuel leaves,
          RadixScanPlan index.order.dirs.val ([root.order].filter (· != 0#u32)) fuel
            leaves
          ∧ fuel ≤ Usize.max)
    : WP.spec (Spike.kv_index.AddressIndex.scan_links index root)
        (fun links =>
          links.val.length = rows.length
          ∧ ∀ (i : Nat) link,
              links.val[i]? = some link
              → ∃ entry,
                  rows[i]? = some entry
                  ∧ WP.spec (Spike.kv_index.AddressIndex.scan_row index link)
                      (· = entry)) := by
  obtain ⟨bindings, related, projection⟩ := view.witness
  unfold Spike.kv_index.AddressIndex.scan_links
  apply WP.spec_mono (dual_scan_refines index root bindings related
    (radix_compressed_of_knowledge _ _ valid.2.knowledge) room)
  intro links scanned
  have size : bindings.length = rows.length := by
    have len := congrArg List.length projection
    simpa [dualBindings, packedBindings, radix_image_length _ _ related.values] using len
  refine ⟨by simpa [scanned] using size, ?_⟩
  intro i link selected
  rw [scanned, List.getElem?_map] at selected
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

end KvRust
