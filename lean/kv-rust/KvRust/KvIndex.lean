-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.RadixSingleReclaim
public import KvRust.Publication

@[expose] public section

namespace KvRust

open Aeneas.Std

def packedAddress (address : CcfKv.engine.Address) : List U8 :=
  addressBytes address.map.val address.key.val

theorem packed_address_injective : Function.Injective packedAddress := by
  intro a b same
  have fits (bytes : CcfKv.engine.Bytes) : bytes.val.length < 2 ^ 64 := by
    have bound := alloc.vec.Vec.len_ineq bytes
    have width := Usize.max_succ_eq_pow
    rcases System.Platform.numBits_eq with h | h <;> simp [h] at width <;> omega
  have eq := address_bytes_injective a.map.val b.map.val a.key.val b.key.val
    (fits a.map) (fits b.map) same
  exact byteAddr_inj (Prod.ext eq.1 eq.2)

def packedBindings {V : Type} (rows : List (CcfKv.engine.Address × V))
    : List (List U8 × CcfKv.kv_index.Binding V) :=
  rows.map fun (a, v) => (packedAddress a, { address := a, value := v })

/-- The native single-radix root implements the sorted address/value list. -/
structure IndexView {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (root : CcfKv.radix.RadixRoot) (rows : List (CcfKv.engine.Address × V))
    : Prop where
  witness
    : ∃ links,
        SingleView index root links ∧ singleBindings index links = packedBindings rows

theorem index_view_sorted {V : Type} {index : CcfKv.kv_index.AddressIndex V}
    {root : CcfKv.radix.RadixRoot} {rows : List (CcfKv.engine.Address × V)}
    (view : IndexView index root rows)
    : rows.Pairwise (fun a b => packedAddress a.1 < packedAddress b.1) := by
  obtain ⟨links, sv, proj⟩ := view.witness
  have hkeys : (singleBindings index links).map Prod.fst = links.map Prod.fst := by
    unfold singleBindings radixBindings
    have hvalid := sv.values
    clear proj sv
    induction links with
    | nil => rfl
    | cons e rest ih =>
        obtain ⟨_, row, saved, _⟩ := hvalid e List.mem_cons_self
        have htail := ih (fun x hx => hvalid x (List.mem_cons_of_mem _ hx))
        simp [saved, htail]
  have hpacked : rows.map (fun r => packedAddress r.1) = links.map Prod.fst := by
    have := congrArg (List.map Prod.fst) proj
    simpa [packedBindings, List.map_map, Function.comp_def, hkeys] using this.symm
  have hlinkKeys : (links.map Prod.fst).Pairwise (· < ·) := by
    rw [List.pairwise_map]
    exact sv.sorted.imp (fun h => (radixKeyLt_iff _ _).mp h)
  rw [← hpacked, List.pairwise_map] at hlinkKeys
  exact hlinkKeys

theorem index_view_unique {V : Type} {index : CcfKv.kv_index.AddressIndex V}
    {root : CcfKv.radix.RadixRoot} {a b : List (CcfKv.engine.Address × V)}
    (va : IndexView index root a) (vb : IndexView index root b)
    : a = b := by
  obtain ⟨la, ha, pa⟩ := va.witness
  obtain ⟨lb, hb, pb⟩ := vb.witness
  obtain rfl := single_view_unique ha hb
  have payload := congrArg (List.map fun row : List U8 × CcfKv.kv_index.Binding V =>
    (row.2.address, row.2.value)) (pa.symm.trans pb)
  simpa [packedBindings, List.map_map, Function.comp_def] using payload

noncomputable def indexRows {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (root : CcfKv.radix.RadixRoot)
    : List (CcfKv.engine.Address × V) := by
  classical
  exact if h : ∃ rows, IndexView index root rows then Classical.choose h else []

theorem index_rows_eq {V : Type} {index : CcfKv.kv_index.AddressIndex V}
    {root : CcfKv.radix.RadixRoot} {rows : List (CcfKv.engine.Address × V)}
    (h : IndexView index root rows)
    : indexRows index root = rows := by
  unfold indexRows
  rw [dite_eq_left ⟨rows, h⟩]
  exact index_view_unique (Classical.choose_spec _) h

theorem index_rows_view {V : Type} {index : CcfKv.kv_index.AddressIndex V}
    {root : CcfKv.radix.RadixRoot} (live : ∃ rows, IndexView index root rows)
    : IndexView index root (indexRows index root) := by
  obtain ⟨rows, view⟩ := live
  rwa [index_rows_eq view]

def IndexValid {V : Type} (index : CcfKv.kv_index.AddressIndex V) : Prop :=
  ArenaValid index.values

def IndexLiveness {V : Type} (index : CcfKv.kv_index.AddressIndex V) (pins : List U32)
    : Prop :=
  SingleLiveness index pins

def IndexPreservesPins {V : Type} (before after : CcfKv.kv_index.AddressIndex V)
    (pins : List U32)
    : Prop :=
  SinglePreservesPins before after pins

def IndexKeeps {V : Type} (before after : CcfKv.kv_index.AddressIndex V) : Prop :=
  ArenaKeeps before.values after.values

theorem IndexKeeps.refl {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    : IndexKeeps index index :=
  ArenaKeeps.refl _

theorem IndexKeeps.trans {V : Type} {a b c : CcfKv.kv_index.AddressIndex V}
    (ab : IndexKeeps a b) (bc : IndexKeeps b c)
    : IndexKeeps a c :=
  ArenaKeeps.trans ab bc

theorem IndexPreservesPins.refl {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (pins : List U32)
    : IndexPreservesPins index index pins :=
  SinglePreservesPins.refl index pins

theorem IndexPreservesPins.trans {V : Type} {a b c : CcfKv.kv_index.AddressIndex V}
    {pins : List U32} (ab : IndexPreservesPins a b pins)
    (bc : IndexPreservesPins b c pins)
    : IndexPreservesPins a c pins :=
  SinglePreservesPins.trans ab bc

theorem IndexPreservesPins.mono {V : Type} {a b : CcfKv.kv_index.AddressIndex V}
    {p1 p2 : List U32} (h : IndexPreservesPins a b p2) (hsub : ∀ r ∈ p1, r ∈ p2)
    : IndexPreservesPins a b p1 :=
  fun r hr bs hv => h r (hsub r hr) bs hv

theorem index_preserves_pins_of_keeps {V : Type}
    {before after : CcfKv.kv_index.AddressIndex V} {pins : List U32}
    (kept : IndexKeeps before after)
    : IndexPreservesPins before after pins :=
  single_preserves_pins_of_arena_keeps kept

theorem index_preserves_pins_view {V : Type} {old next : CcfKv.kv_index.AddressIndex V}
    {pins : List U32} (kept : IndexPreservesPins old next pins)
    (root : CcfKv.radix.RadixRoot) (rows : List (CcfKv.engine.Address × V))
    (hpin : root = 0#u32 ∨ root ∈ pins) (view : IndexView old root rows)
    : IndexView next root rows := by
  rcases hpin with rfl | hmem
  · have hrows : rows = [] :=
      index_view_unique view
        ⟨
          [],
          by
            simpa [CcfKv.radix.SingleRadix.empty_root, WP.spec_ok]
              using single_empty_root_refines old,
          rfl
        ⟩
    subst hrows
    exact ⟨
      [],
      by
        simpa [CcfKv.radix.SingleRadix.empty_root, WP.spec_ok]
          using single_empty_root_refines next,
      rfl
    ⟩
  · obtain ⟨links, single, projection⟩ := view.witness
    obtain ⟨after, same⟩ := kept root hmem links single
    exact ⟨links, after, same.trans projection⟩

theorem index_keeps_view {V : Type} {old next : CcfKv.kv_index.AddressIndex V}
    (kept : IndexKeeps old next) (root : CcfKv.radix.RadixRoot)
    (rows : List (CcfKv.engine.Address × V)) (view : IndexView old root rows)
    : IndexView next root rows := by
  obtain ⟨links, single, projection⟩ := view.witness
  obtain ⟨after, same⟩ := single_retains_views old next kept root links single
  exact ⟨links, after, same.trans projection⟩

theorem index_new_refines (V : Type)
    : WP.spec (CcfKv.kv_index.AddressIndex.new V)
        (fun index =>
          IndexLiveness index []
          ∧ WP.spec (CcfKv.kv_index.AddressIndex.empty_root index)
              (fun root => root = 0#u32 ∧ IndexView index root [])) := by
  unfold CcfKv.kv_index.AddressIndex.new CcfKv.kv_index.AddressIndex.empty_root
  apply WP.spec_bind (single_new_refines (CcfKv.kv_index.Binding V))
  intro index ⟨liveValues, empty⟩
  rw [WP.spec_ok]
  refine ⟨liveValues, ?_⟩
  unfold CcfKv.radix.SingleRadix.empty_root at empty ⊢
  rw [WP.spec_ok] at empty ⊢
  exact ⟨rfl, ⟨[], empty, rfl⟩⟩

theorem index_retain_root_refines {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (pins : List U32) (root : CcfKv.radix.RadixRoot)
    (live : IndexLiveness index pins)
    (rootRef
      : root ≠ 0#u32
        → SingleLinkLive index.values.dirs.val index.values.rows.val root
          ∧ radixReferences index.values.dirs.val pins root > 0)
    (room : root ≠ 0#u32 → radixReferences index.values.dirs.val pins root < U32.max)
    : WP.spec (CcfKv.kv_index.AddressIndex.retain_root index root)
        (fun after =>
          after.values = index.values
          ∧ IndexLiveness after (if root = 0#u32 then pins else root :: pins)) := by
  unfold CcfKv.kv_index.AddressIndex.retain_root
  apply WP.spec_bind
    (single_retain_root_refines index pins root live
      (fun h => (rootRef h).1) (fun h => (rootRef h).2) room)
  intro after h
  rw [WP.spec_ok]
  exact h

theorem index_release_root_refines {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (pins : List U32) (root : CcfKv.radix.RadixRoot)
    (live : IndexLiveness index (if root = 0#u32 then pins else root :: pins))
    (queueRoom
      : 2 * (index.values.dirs.val.length + index.values.rows.val.length) + 1 ≤ Usize.max)
    : WP.spec (CcfKv.kv_index.AddressIndex.release_root index root)
        (fun after =>
          after.values = index.values ∧ IndexLiveness after pins) := by
  unfold CcfKv.kv_index.AddressIndex.release_root
  apply WP.spec_bind (single_release_root_refines index pins root live queueRoom)
  intro after h
  rw [WP.spec_ok]
  exact h

theorem index_retire_budget_refines {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (pins : List U32) (budget : Usize)
    (live : IndexLiveness index pins)
    (queueRoom
      : 2 * (index.values.dirs.val.length + index.values.rows.val.length) + 1 ≤ Usize.max)
    : WP.spec (CcfKv.kv_index.AddressIndex.retire_budget index budget)
        (fun (_, after) =>
          IndexLiveness after pins
          ∧ IndexPreservesPins index after pins
          ∧ after.values.dirs.val.length = index.values.dirs.val.length
          ∧ after.values.rows.val.length = index.values.rows.val.length) := by
  unfold CcfKv.kv_index.AddressIndex.retire_budget
  apply WP.spec_bind (single_retire_budget_refines index budget pins live queueRoom)
  rintro ⟨n, after⟩ h
  change WP.spec (Result.ok (n, after)) _
  rw [WP.spec_ok]
  exact h

theorem index_empty_root_refines {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    : WP.spec (CcfKv.kv_index.AddressIndex.empty_root index)
        (fun root => root = 0#u32 ∧ IndexView index root []) := by
  unfold CcfKv.kv_index.AddressIndex.empty_root CcfKv.radix.SingleRadix.empty_root
  rw [WP.spec_ok]
  exact ⟨
    rfl,
    ⟨
      [],
      by
        simpa [CcfKv.radix.SingleRadix.empty_root, WP.spec_ok]
          using single_empty_root_refines index,
      rfl
    ⟩
  ⟩

private theorem address_key_matches (a : CcfKv.engine.Address)
    (capacity : 8 + a.map.val.length + a.key.val.length ≤ Usize.max)
    : WP.spec
        (CcfKv.radix.address_key (alloc.vec.Vec.deref a.map) (alloc.vec.Vec.deref a.key))
        (fun out => out.val = packedAddress a) := by
  apply WP.spec_mono
    (native_address_key _ _ (by simpa [alloc.vec.Vec.deref] using capacity))
  intro out bytes
  simpa [alloc.vec.Vec.deref, packedAddress] using bytes

theorem index_batch_row_refines {V : Type} (address : CcfKv.engine.Address) (value : V)
    (capacity : 8 + address.map.val.length + address.key.val.length ≤ Usize.max)
    : WP.spec (CcfKv.kv_index.AddressIndex.batch_row address value)
        (fun row =>
          row.key.val = packedAddress address
          ∧ row.value = {address, value}
          ∧ row.key.val.length
            = 8 + address.map.val.length + address.key.val.length) := by
  simp only [CcfKv.kv_index.AddressIndex.batch_row, CcfKv.engine.Bytes.as_slice, bind_ok]
  apply WP.spec_bind (address_key_matches address capacity)
  intro key encoded
  rw [WP.spec_ok]
  refine ⟨encoded, rfl, ?_⟩
  rw [encoded, packedAddress, addressBytes, List.length_append, List.length_append]
  simp [addressPrefix, BitVec.toLEBytes_length]

local instance nativeAddressEq : DecidableEq CcfKv.engine.Address :=
  fun a b => decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

theorem index_get_refines {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (root : CcfKv.radix.RadixRoot) (rows : List (CcfKv.engine.Address × V))
    (view : IndexView index root rows) (address : CcfKv.engine.Address)
    (capacity : 8 + address.map.val.length + address.key.val.length ≤ Usize.max)
    : WP.spec (CcfKv.kv_index.AddressIndex.get index root address)
        (· = Kv.Model.find rows address) := by
  obtain ⟨links, related, projection⟩ := view.witness
  simp only [CcfKv.kv_index.AddressIndex.get, CcfKv.engine.Bytes.as_slice, bind_ok]
  apply WP.spec_bind (address_key_matches address capacity)
  intro encoded same
  apply WP.spec_bind
    (single_get_refines index root (alloc.vec.Vec.deref encoded) links related)
  intro found he
  have lookup :
      found = (Kv.Model.find rows address).map
        (fun v => ({ address, value := v } : CcfKv.kv_index.Binding V)) := by
    rw [projection, show (alloc.vec.Vec.deref encoded).val = packedAddress address from by
      simpa [alloc.vec.Vec.deref] using same] at he
    exact he.trans
      (find_projected_with_key rows address packedAddress
        (fun a v => ({ address := a, value := v } : CcfKv.kv_index.Binding V)) packed_address_injective)
  rw [lookup]
  cases Kv.Model.find rows address <;> simp

private theorem packed_erase {V : Type} (rows : List (CcfKv.engine.Address × V))
    (address : CcfKv.engine.Address)
    : Kv.Model.erase (packedBindings rows) (packedAddress address)
      = packedBindings (Kv.Model.erase rows address) := by
  unfold packedBindings Kv.Model.erase
  rw [List.filter_map]
  have equivalent (p : CcfKv.engine.Address × V) :
      @bne (List U8) instBEqOfDecidableEq (packedAddress p.1) (packedAddress address)
        = (p.1 != address) := by
    by_cases same : p.1 = address
    · simp [same]
    · have diff : packedAddress p.1 ≠ packedAddress address :=
        fun eq => same (packed_address_injective eq)
      simp [bne, diff, same]
  let project : CcfKv.engine.Address × V → List U8 × CcfKv.kv_index.Binding V :=
    fun (a, v) => (packedAddress a, { address := a, value := v })
  have filtered : rows.filter
      ((fun p => @bne (List U8) instBEqOfDecidableEq p.1 (packedAddress address)) ∘ project)
      = rows.filter (fun p => p.1 != address) := by
    apply List.filter_congr
    rintro ⟨a, v⟩ _
    exact equivalent (a, v)
  exact congrArg (List.map project) filtered

private theorem packed_set {V : Type} (rows : List (CcfKv.engine.Address × V))
    (address : CcfKv.engine.Address) (value : V)
    : Kv.Model.set (packedBindings rows) (packedAddress address)
        ({address, value} : CcfKv.kv_index.Binding V)
      = packedBindings (Kv.Model.set rows address value) := by
  rw [Kv.Model.set, packed_erase]
  rfl

private theorem radix_filter_map_length {V W : Type}
    (values : List (Option (CcfKv.radix.RadixRow V))) (links : List (List U8 × U32))
    (live : RadixRows values links) (f : (List U8 × U32) → CcfKv.radix.RadixRow V → W)
    : (links.filterMap fun e => (radixRow values e.2).map (f e)).length
      = links.length := by
  induction links with
  | nil => rfl
  | cons binding tail ih =>
      obtain ⟨k, l⟩ := binding
      obtain ⟨_, row, saved, _⟩ := live (k, l) List.mem_cons_self
      have h := ih (fun e hm => live e (List.mem_cons_of_mem _ hm))
      simp [saved, h]

private theorem index_link_count {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (root : CcfKv.radix.RadixRoot) (rows : List (CcfKv.engine.Address × V))
    (links : List (List U8 × U32)) (view : SingleView index root links)
    (projection : singleBindings index links = packedBindings rows)
    : links.length = rows.length := by
  have len := congrArg List.length projection
  have size : (radixBindings index.values.rows.val links).length = links.length :=
    radix_filter_map_length _ _ view.values (fun e row => (e.1, row.value))
  simpa only [singleBindings, packedBindings, List.length_map, size] using len

def IndexGrowth {V : Type} (before after : CcfKv.kv_index.AddressIndex V)
    (lookupDirs writes : Nat)
    : Prop :=
  ArenaGrowth before.values after.values lookupDirs writes

theorem index_put_refines {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (root : CcfKv.radix.RadixRoot) (rows : List (CcfKv.engine.Address × V))
    (pins : List U32)
    (related : IndexView index root rows)
    (address : CcfKv.engine.Address) (value : V)
    (live : IndexLiveness index pins)
    (rootRef
      : root ≠ 0#u32
        → SingleLinkLive index.values.dirs.val index.values.rows.val root
          ∧ radixReferences index.values.dirs.val pins root > 0)
    (lookupRoom : index.values.dirs.val.length + rows.length + 1 ≤ 2147483647)
    (valueRoom : index.values.rows.val.length < 2147483647)
    (keyRoom : 2 * (8 + address.map.val.length + address.key.val.length) + 1 ≤ Usize.max)
    (refRoom
      : pins.length + 17 * (index.values.dirs.val.length + rows.length + 2) + 1 ≤ U32.max)
    : WP.spec (CcfKv.kv_index.AddressIndex.put index root address value)
        (fun (next, after) =>
          (∃ out, IndexView after next out ∧ out.Perm (Kv.Model.set rows address value))
          ∧ IndexLiveness after (if next = 0#u32 then pins else next :: pins)
          ∧ IndexKeeps index after
          ∧ IndexGrowth index after (rows.length + 1) 1) := by
  obtain ⟨links, view, projection⟩ := related.witness
  have count := index_link_count index root rows links view projection
  unfold CcfKv.kv_index.AddressIndex.put
  apply WP.spec_bind (index_batch_row_refines address value (by omega))
  rintro ⟨encoded, binding⟩ ⟨he, hb, len⟩
  dsimp only at he hb len
  subst binding
  apply WP.spec_bind
    (single_put_refines index root {key := encoded, value := {address, value}} links pins
      view live rootRef (by omega) valueRoom (by simpa [len] using keyRoom) (by omega))
  rintro ⟨next, after⟩ ⟨lAfter, kAfter, gAfter, sorted, sv, hperm⟩
  change WP.spec (Result.ok (next, after)) _
  rw [WP.spec_ok]
  let out : List (CcfKv.engine.Address × V) :=
    (singleBindings after sorted).map fun (_, b) => (b.address, b.value)
  have hPackedPerm : (singleBindings after sorted).Perm
      (packedBindings (Kv.Model.set rows address value)) := by
    rw [projection, he, packed_set] at hperm
    exact hperm
  have hPackedEq : singleBindings after sorted = packedBindings out := by
    have hkeyEq : ∀ e ∈ singleBindings after sorted, e.1 = packedAddress e.2.address := by
      intro e he
      have hm := hPackedPerm.subset he
      obtain ⟨⟨a, v⟩, _, hpair⟩ := List.mem_map.mp hm
      have hfst : packedAddress a = e.1 := congrArg Prod.fst hpair
      have hsnd : ({ address := a, value := v } : CcfKv.kv_index.Binding V) = e.2 :=
        congrArg Prod.snd hpair
      rw [← hfst, ← hsnd]
    unfold packedBindings out
    rw [List.map_map]
    conv_lhs => rw [← List.map_id (singleBindings after sorted)]
    apply List.map_congr_left
    rintro ⟨k, ⟨a, v⟩⟩ hm
    have hk := hkeyEq (k, ⟨a, v⟩) hm
    dsimp only at hk ⊢
    rw [hk]
    rfl
  have hOutPerm : out.Perm (Kv.Model.set rows address value) := by
    have hmap := hPackedPerm.map (fun e : List U8 × CcfKv.kv_index.Binding V => (e.2.address, e.2.value))
    simpa [out, packedBindings, List.map_map, Function.comp_def, Prod.mk.eta] using hmap
  exact ⟨⟨out, ⟨sorted, sv, hPackedEq⟩, hOutPerm⟩, lAfter, kAfter, count ▸ gAfter⟩

theorem index_remove_refines {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (root : CcfKv.radix.RadixRoot) (rows : List (CcfKv.engine.Address × V))
    (pins : List U32)
    (related : IndexView index root rows)
    (address : CcfKv.engine.Address) (live : IndexLiveness index pins)
    (rootRef
      : root ≠ 0#u32
        → SingleLinkLive index.values.dirs.val index.values.rows.val root
          ∧ radixReferences index.values.dirs.val pins root > 0)
    (lookupRoom : index.values.dirs.val.length + rows.length ≤ 2147483647)
    (capacity : 8 + address.map.val.length + address.key.val.length ≤ Usize.max)
    (refRoom
      : pins.length + 17 * (index.values.dirs.val.length + rows.length + 1) + 1 ≤ U32.max)
    : WP.spec (CcfKv.kv_index.AddressIndex.remove index root address)
        (fun (next, after) =>
          IndexView after next (Kv.Model.erase rows address)
          ∧ IndexLiveness after (if next = 0#u32 then pins else next :: pins)
          ∧ IndexKeeps index after
          ∧ IndexGrowth index after rows.length 0) := by
  obtain ⟨links, view, projection⟩ := related.witness
  have count := index_link_count index root rows links view projection
  simp only [CcfKv.kv_index.AddressIndex.remove, CcfKv.engine.Bytes.as_slice, bind_ok]
  apply WP.spec_bind (address_key_matches address capacity)
  intro encoded he
  apply WP.spec_bind
    (single_remove_refines index root (alloc.vec.Vec.deref encoded) links pins view live
      rootRef (by omega) (by omega))
  rintro ⟨next, after⟩ ⟨lAfter, kAfter, gAfter, sv, hp⟩
  change WP.spec (Result.ok (next, after)) _
  rw [WP.spec_ok]
  refine ⟨⟨Kv.Model.erase links (alloc.vec.Vec.deref encoded).val, sv, ?_⟩,
    lAfter, kAfter, count ▸ gAfter⟩
  rw [hp, projection, show (alloc.vec.Vec.deref encoded).val = packedAddress address from by
    simpa [alloc.vec.Vec.deref] using he, packed_erase]

theorem index_scan_up_to_refines {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (root : CcfKv.radix.RadixRoot) (limit : Usize)
    (rows : List (CcfKv.engine.Address × V)) (view : IndexView index root rows)
    (valid : IndexValid index) (room : 18 * rows.length ≤ Usize.max)
    : WP.spec (CcfKv.kv_index.AddressIndex.scan_links_up_to index root limit)
        (fun links =>
          links.val.length = min limit.val rows.length
          ∧ ∀ (i : Nat) link,
              links.val[i]? = some link
              → ∃ entry,
                  rows[i]? = some entry
                  ∧ WP.spec (CcfKv.kv_index.AddressIndex.scan_row index link)
                      (· = entry)) := by
  obtain ⟨bindings, related, projection⟩ := view.witness
  have size := index_link_count index root rows bindings related projection
  unfold CcfKv.kv_index.AddressIndex.scan_links_up_to
  apply WP.spec_mono
    (single_scan_up_to_refines index root limit bindings related valid (by omega))
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
      obtain ⟨htag, savedRow, saved, _⟩ := related.values entry inBindings
      have loaded := congrArg (fun items : List (List U8 × CcfKv.kv_index.Binding V) =>
        items[i]?) projection
      rw [singleBindings, packedBindings, List.getElem?_map,
        radix_projection_index _ _ related.values, atLink, List.getElem?_eq_getElem inside] at loaded
      have payload : savedRow.value = {address := rows[i].1, value := rows[i].2} := by
        simpa [saved] using congrArg (Option.map Prod.snd) loaded
      refine ⟨rows[i], List.getElem?_eq_getElem inside, ?_⟩
      unfold CcfKv.kv_index.AddressIndex.scan_row
      apply WP.spec_bind (single_scan_row_refines index entry.2 savedRow htag saved)
      rintro ⟨_, b⟩ ⟨_, hb⟩
      dsimp only at hb
      change WP.spec (Result.ok (b.address, b.value)) _
      rw [WP.spec_ok, hb, payload]

theorem index_scan_refines {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (root : CcfKv.radix.RadixRoot) (rows : List (CcfKv.engine.Address × V))
    (view : IndexView index root rows) (valid : IndexValid index)
    (room : 18 * rows.length ≤ Usize.max)
    : WP.spec (CcfKv.kv_index.AddressIndex.scan_links index root)
        (fun links =>
          links.val.length = rows.length
          ∧ ∀ (i : Nat) link,
              links.val[i]? = some link
              → ∃ entry,
                  rows[i]? = some entry
                  ∧ WP.spec (CcfKv.kv_index.AddressIndex.scan_row index link)
                      (· = entry)) := by
  obtain ⟨bindings, related, projection⟩ := view.witness
  have size := index_link_count index root rows bindings related projection
  unfold CcfKv.kv_index.AddressIndex.scan_links
  apply WP.spec_mono (single_scan_refines index root bindings related valid (by omega))
  intro links scanned
  have hlen : links.val.length = rows.length := by simp [scanned, size]
  refine ⟨hlen, ?_⟩
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
      obtain ⟨htag, savedRow, saved, _⟩ := related.values entry inBindings
      have loaded := congrArg (fun items : List (List U8 × CcfKv.kv_index.Binding V) =>
        items[i]?) projection
      rw [singleBindings, packedBindings, List.getElem?_map,
        radix_projection_index _ _ related.values, atLink, List.getElem?_eq_getElem inside] at loaded
      have payload : savedRow.value = {address := rows[i].1, value := rows[i].2} := by
        simpa [saved] using congrArg (Option.map Prod.snd) loaded
      refine ⟨rows[i], List.getElem?_eq_getElem inside, ?_⟩
      unfold CcfKv.kv_index.AddressIndex.scan_row
      apply WP.spec_bind (single_scan_row_refines index entry.2 savedRow htag saved)
      rintro ⟨_, b⟩ ⟨_, hb⟩
      dsimp only at hb
      change WP.spec (Result.ok (b.address, b.value)) _
      rw [WP.spec_ok, hb, payload]

/-- Map-prefix scan visits only the entries of `map`, in exact sorted order. -/
theorem index_scan_map_refines {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (root : CcfKv.radix.RadixRoot) (rows : List (CcfKv.engine.Address × V))
    (map : CcfKv.engine.Bytes)
    (view : IndexView index root rows) (valid : IndexValid index)
    (mapRoom : 2 * (8 + map.val.length) ≤ Usize.max)
    (room : 18 * rows.length ≤ Usize.max)
    : WP.spec (CcfKv.kv_index.AddressIndex.scan_map_links index root map)
        (fun links =>
          let selected := rows.filter fun r => decide (r.1.map.val = map.val)
          links.val.length = selected.length
          ∧ ∀ (i : Nat) link,
              links.val[i]? = some link
              → ∃ entry,
                  selected[i]? = some entry
                  ∧ WP.spec (CcfKv.kv_index.AddressIndex.scan_row index link)
                      (· = entry)) := by
  obtain ⟨bindings, related, projection⟩ := view.witness
  have size := index_link_count index root rows bindings related projection
  simp only [CcfKv.kv_index.AddressIndex.scan_map_links, CcfKv.engine.Bytes.as_slice, bind_ok]
  apply WP.spec_bind
    (native_map_prefix (alloc.vec.Vec.deref map)
      (by
        simpa [alloc.vec.Vec.deref] using (show 8 + map.val.length ≤ Usize.max by omega)))
  intro pfx hpfx
  have hpfxVal : pfx.val = mapPrefixBytes map.val := by simpa [alloc.vec.Vec.deref] using hpfx
  have hpfxLen : pfx.val.length = 8 + map.val.length := by
    rw [hpfxVal, mapPrefixBytes, List.length_append]
    simp [addressPrefix, BitVec.toLEBytes_length]
  apply WP.spec_mono
    (single_scan_prefix_refines index root (alloc.vec.Vec.deref pfx) bindings related
      valid (by simpa [alloc.vec.Vec.deref, hpfxLen] using mapRoom) (by omega))
  intro links scanned
  let pfxB := mapPrefixBytes map.val
  let filtBindings := bindings.filter fun row => decide (pfxB <+: row.1)
  let selected := rows.filter fun r => decide (r.1.map.val = map.val)
  have hscanEq : links.val = filtBindings.map Prod.snd := by
    simpa [alloc.vec.Vec.deref, hpfxVal, filtBindings, pfxB] using scanned
  have hProjFilt : singleBindings index filtBindings = packedBindings selected := by
    have hsbFilt :
        singleBindings index filtBindings
        = (singleBindings index bindings).filter fun row => decide (pfxB <+: row.1) := by
      unfold singleBindings radixBindings filtBindings
      have hvalid := related.values
      clear projection related size hscanEq scanned
      induction bindings with
      | nil => rfl
      | cons e rest ih =>
          obtain ⟨_, r, hr, _⟩ := hvalid e List.mem_cons_self
          have htail := ih (fun x hx => hvalid x (List.mem_cons_of_mem _ hx))
          by_cases hp : pfxB <+: e.1 <;> simp [hr, hp, htail]
    rw [hsbFilt, projection]
    unfold packedBindings selected
    rw [List.filter_map]
    apply congrArg (List.map _)
    apply List.filter_congr
    rintro ⟨a, v⟩ _
    have fits (b : CcfKv.engine.Bytes) : b.val.length < 2 ^ 64 := by
      have bound := alloc.vec.Vec.len_ineq b
      have width := Usize.max_succ_eq_pow
      rcases System.Platform.numBits_eq with h | h <;> simp [h] at width <;> omega
    exact decide_eq_decide.mpr
      (map_prefix_iff map.val a.map.val a.key.val (fits map) (fits a.map))
  have hFiltRows : RadixRows index.values.rows.val filtBindings :=
    fun e he => related.values e (List.mem_filter.mp he).1
  have hFiltLen : filtBindings.length = selected.length := by
    have len := congrArg List.length hProjFilt
    have hs : (radixBindings index.values.rows.val filtBindings).length = filtBindings.length :=
      radix_filter_map_length _ _ hFiltRows (fun e row => (e.1, row.value))
    simpa only [singleBindings, packedBindings, List.length_map, hs] using len
  refine ⟨?_, ?_⟩
  · rw [hscanEq, List.length_map, hFiltLen]
  intro i link sel
  rw [hscanEq, List.getElem?_map] at sel
  cases atLink : filtBindings[i]? with
  | none => simp [atLink] at sel
  | some entry =>
      have points : entry.2 = link := by simpa [atLink] using sel
      subst link
      have inFilt := List.mem_iff_getElem?.mpr ⟨i, atLink⟩
      have inside : i < selected.length := by
        by_contra outside
        rw [← hFiltLen] at outside
        simp [List.getElem?_eq_none (Nat.le_of_not_gt outside)] at atLink
      obtain ⟨htag, savedRow, saved, _⟩ := hFiltRows entry inFilt
      have loaded := congrArg (fun items : List (List U8 × CcfKv.kv_index.Binding V) =>
        items[i]?) hProjFilt
      rw [singleBindings, packedBindings, List.getElem?_map,
        radix_projection_index _ _ hFiltRows, atLink, List.getElem?_eq_getElem inside] at loaded
      have payload : savedRow.value = {address := selected[i].1, value := selected[i].2} := by
        simpa [saved] using congrArg (Option.map Prod.snd) loaded
      refine ⟨selected[i], List.getElem?_eq_getElem inside, ?_⟩
      unfold CcfKv.kv_index.AddressIndex.scan_row
      apply WP.spec_bind (single_scan_row_refines index entry.2 savedRow htag saved)
      rintro ⟨_, b⟩ ⟨_, hb⟩
      dsimp only at hb
      change WP.spec (Result.ok (b.address, b.value)) _
      rw [WP.spec_ok, hb, payload]

end KvRust
